//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction
#![allow(clippy::doc_link_with_quotes, clippy::arithmetic_side_effects)]

use eyre::eyre;
use iroha_config::wasm::Configuration;
use iroha_data_model::{account::AccountId, prelude::*, validator, ValidationFail};
use iroha_logger::{debug, error};
// NOTE: Using error_span so that span info is logged on every event
use iroha_logger::{error_span as wasm_log_span, prelude::tracing::Span, Level as LogLevel};
use iroha_wasm_codec::{self as codec, WasmUsize};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use crate::{
    smartcontracts::{Execute, ValidQuery as _},
    wsv::WorldStateView,
};

pub mod export {
    //! Module functions names exported from wasm to iroha

    /// Exported function to allocate memory
    pub const WASM_ALLOC_FN: &str = "_iroha_wasm_alloc";
    /// Exported function to deallocate memory
    pub const WASM_DEALLOC_FN: &str = "_iroha_wasm_dealloc";
    /// Name of the exported memory
    pub const WASM_MEMORY_NAME: &str = "memory";
    /// Name of the exported entry for smart contract (or trigger) execution
    pub const WASM_MAIN_FN_NAME: &str = "_iroha_wasm_main";
}

pub mod import {
    //! Module functions names imported from iroha to wasm

    /// Name of the linked wasm module
    pub const MODULE_NAME: &str = "iroha";
    /// Name of the imported function to execute instructions
    pub const EXECUTE_ISI_FN_NAME: &str = "execute_instruction";
    /// Name of the imported function to execute queries
    pub const EXECUTE_QUERY_FN_NAME: &str = "execute_query";
    /// Name of the imported function to query trigger authority
    pub const QUERY_AUTHORITY_FN_NAME: &str = "query_authority";
    /// Name of the imported function to query event that triggered the smart contract execution
    pub const QUERY_TRIGGERING_EVENT_FN_NAME: &str = "query_triggering_event";
    /// Name of the imported function to query operation that is to be verified
    pub const QUERY_OPERATION_TO_VALIDATE_FN_NAME: &str = "query_operation_to_validate";
    /// Name of the imported function to query max log level on host
    pub const QUERY_MAX_LOG_LEVEL: &str = "query_max_log_level";
    /// Name of the imported function to debug print objects
    pub const DBG_FN_NAME: &str = "dbg";
    /// Name of the imported function to log objects
    pub const LOG_FN_NAME: &str = "log";
}

/// `WebAssembly` execution error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Engine or linker could not be created
    #[error("Runtime initialization failure")]
    Initialization(#[source] eyre::Report),
    /// Module could not be loaded from bytes
    #[error("Failed to load module")]
    ModuleLoading(#[source] eyre::Report),
    /// Module could not be instantiated
    #[error("Module instantiation failure")]
    Instantiation(#[from] InstantiationError),
    /// Export error
    #[error("Export error")]
    Export(#[from] ExportError),
    /// Call to the function exported from module failed
    #[error("Exported function call failed")]
    ExportFnCall(#[from] ExportFnCallError),
    /// Error during decoding object with length prefix
    #[error("Failed to decode object from bytes with length prefix")]
    Decode(#[source] eyre::Report),
}

/// Instantiation error
#[derive(Debug, thiserror::Error)]
pub enum InstantiationError {
    /// [`wasmtime::Linker::instantiate`] failed
    #[error("Linker failed to instantiate module")]
    Linker(#[from] eyre::Report),
    /// Export which should always be present is missing
    #[error("Mandatory export error")]
    MandatoryExport(#[from] ExportError),
}

/// Export error
#[derive(Debug, Copy, Clone, thiserror::Error)]
#[error("Failed to export `{export_name}`")]
pub struct ExportError {
    /// Name of the failed export
    pub export_name: &'static str,
    /// Error kind
    #[source]
    pub export_error_kind: ExportErrorKind,
}

/// Export error kind
#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum ExportErrorKind {
    /// Named export not found
    #[error("Not found")]
    NotFound,
    /// Export expected to be a memory, but it's not
    #[error("Not a memory")]
    NotAMemory,
    /// Export expected to be a function, but it's not
    #[error("Not a function")]
    NotAFunction,
    /// Export has a wrong signature
    #[error("Wrong signature, expected `{0} -> {1}`")]
    WrongSignature(&'static str, &'static str),
}

impl ExportError {
    fn not_found(export_name: &'static str) -> Self {
        Self {
            export_name,
            export_error_kind: ExportErrorKind::NotFound,
        }
    }

    fn not_a_memory(export_name: &'static str) -> Self {
        Self {
            export_name,
            export_error_kind: ExportErrorKind::NotAMemory,
        }
    }

    fn not_a_function(export_name: &'static str) -> Self {
        Self {
            export_name,
            export_error_kind: ExportErrorKind::NotAFunction,
        }
    }

    fn wrong_signature<P, R>(export_name: &'static str) -> Self {
        Self {
            export_name,
            export_error_kind: ExportErrorKind::WrongSignature(
                std::any::type_name::<P>(),
                std::any::type_name::<R>(),
            ),
        }
    }
}

/// Exported function call error
#[derive(Debug, thiserror::Error)]
pub enum ExportFnCallError {
    /// Failed to execute something on the host side
    #[error("Failed to execute operation on host")]
    HostExecution(#[source] eyre::Report),
    /// Stack overflow, heap overflow or other limits exceeded
    #[error("Execution limits exceeded")]
    ExecutionLimitsExceeded(#[source] eyre::Report),
    /// Other kind of trap
    #[error("Other")]
    Other(#[source] eyre::Report),
}

impl From<Trap> for ExportFnCallError {
    fn from(trap: Trap) -> Self {
        use wasmtime::TrapCode::*;

        match trap.trap_code() {
            Some(code) => match code {
                StackOverflow | MemoryOutOfBounds | TableOutOfBounds | IndirectCallToNull => {
                    Self::ExecutionLimitsExceeded(trap.into())
                }
                _ => Self::Other(trap.into()),
            },
            None => Self::HostExecution(trap.into()),
        }
    }
}

/// [`Result`] type for this module
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Create [`Engine`] with a predefined configuration.
///
/// # Panics
///
/// Panics if something is wrong with the configuration.
/// Configuration is hardcoded and tested, so this function should never panic.
pub fn create_engine() -> Engine {
    create_config()
        .and_then(|config| {
            Engine::new(&config).map_err(|err| Error::Initialization(eyre!(Box::new(err))))
        })
        .expect("Failed to create WASM engine with a predefined configuration. This is a bug")
}

/// Create [`Module`] from bytes.
///
/// # Errors
///
/// See [`Module::new`]
///
// TODO: Probably we can do some checks here such as searching for entrypoint function
pub fn load_module(engine: &Engine, bytes: impl AsRef<[u8]>) -> Result<wasmtime::Module> {
    Module::new(engine, bytes).map_err(|err| Error::ModuleLoading(eyre!(Box::new(err))))
}

fn create_config() -> Result<Config> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .cache_config_load_default()
        .map_err(|err| Error::Initialization(eyre!(Box::new(err))))?;
    Ok(config)
}

#[derive(Clone)]
struct Validator {
    /// Number of instructions in the smartcontract
    instruction_count: u64,
    /// Max allowed number of instructions in the smartcontract
    max_instruction_count: u64,
}

impl Validator {
    /// Checks if number of instructions in wasm smartcontract exceeds maximum
    ///
    /// # Errors
    ///
    /// If number of instructions exceeds maximum
    #[inline]
    pub fn check_instruction_limits(&mut self) -> Result<(), ValidationFail> {
        self.instruction_count += 1;

        if self.instruction_count > self.max_instruction_count {
            return Err(ValidationFail::TooComplex);
        }

        Ok(())
    }
}

struct State<'wrld> {
    account_id: AccountId,
    /// Ensures smartcontract adheres to limits
    validator: Option<Validator>,
    store_limits: StoreLimits,
    wsv: &'wrld mut WorldStateView,
    /// Event for triggers
    triggering_event: Option<Event>,
    /// Operation to pass to a runtime validator
    operation_to_validate: Option<validator::NeedsValidationBox>,
    /// Span inside of which all logs are recorded for this smart contract
    log_span: Span,
}

impl<'wrld> State<'wrld> {
    fn new(
        wsv: &'wrld mut WorldStateView,
        account_id: AccountId,
        config: Configuration,
        log_span: Span,
    ) -> Self {
        Self {
            wsv,
            account_id,
            validator: None,
            triggering_event: None,
            operation_to_validate: None,

            store_limits: StoreLimitsBuilder::new()
                .memory_size((*config.max_memory()).try_into().expect(
                    "config.max_memory is a u32 so this can't fail on any supported platform",
                ))
                .instances(1)
                .memories(1)
                .tables(1)
                .build(),
            log_span,
        }
    }

    fn with_validator(mut self, max_instruction_count: u64) -> Self {
        let validator = Validator {
            instruction_count: 0,
            max_instruction_count,
        };

        self.validator = Some(validator);
        self
    }

    fn with_triggering_event(mut self, event: Event) -> Self {
        self.triggering_event = Some(event);
        self
    }

    fn with_operation_to_validate(mut self, operation: &validator::NeedsValidationBox) -> Self {
        self.operation_to_validate = Some(operation.clone());
        self
    }
}

/// `WebAssembly` virtual machine
pub struct Runtime<'wrld> {
    engine: Engine,
    linker: Linker<State<'wrld>>,
    config: Configuration,
}

impl<'wrld> Runtime<'wrld> {
    fn create_store(&self, state: State<'wrld>) -> Store<State<'wrld>> {
        let mut store = Store::new(&self.engine, state);

        store.limiter(|stat| &mut stat.store_limits);
        store
            .add_fuel(*self.config.fuel_limit())
            .expect("Wasm Runtime config is malformed, this is a bug");

        store
    }

    fn create_smart_contract(
        &self,
        store: &mut Store<State<'wrld>>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<wasmtime::Instance> {
        let module = load_module(&self.engine, bytes)?;
        self.instantiate_module(&module, store).map_err(Into::into)
    }

    /// Execute `query` on host
    #[allow(clippy::needless_pass_by_value)]
    #[codec::wrap]
    fn execute_query(query: QueryBox, state: &mut State) -> Result<Value, ValidationFail> {
        iroha_logger::debug!(%query, "Executing");

        let wsv: &mut WorldStateView = state.wsv;
        let called_from_validator = state.operation_to_validate.is_some();
        if called_from_validator {
            // NOTE: Validator has already validated the query
        } else {
            // NOTE: Smart contract (not validator) is trying to execute the query, validate it first
            // TODO: Validation should be skipped when executing smart contract.
            // There should be two steps validation and execution. First smart contract
            // is validated and then it's executed. Here it's validating in both steps.
            // Add a flag indicating whether smart contract is being validated or executed
            wsv.validator_view()
                .clone() // Cloning validator is a cheap operation
                .validate(wsv, &state.account_id, query.clone())?
        }

        query.execute(wsv).map_err(Into::into)
    }

    /// Execute `instruction` on host
    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut State,
    ) -> Result<(), ValidationFail> {
        debug!(%instruction, "Executing");

        let State {
            wsv,
            account_id,
            validator,
            operation_to_validate,
            ..
        } = state;

        let called_from_validator = operation_to_validate.is_some();
        if called_from_validator {
            // NOTE: Validator has already validated the isi, don't validate again
            instruction.execute(account_id, wsv).map_err(Into::into)
        } else {
            // NOTE: Smart contract (not validator) is trying to execute the isi, validate it first
            if let Some(validator) = validator {
                validator.check_instruction_limits()?;
            }
            // TODO: Validation should be skipped when executing smart contract.
            // There should be two steps validation and execution. First smart contract
            // is validated and then it's executed. Here it's validating in both steps.
            // Add a flag indicating whether smart contract is being validated or executed
            wsv.validator_view()
                .clone() // Cloning validator is a cheap operation
                .validate(wsv, account_id, instruction)
        }
    }

    #[codec::wrap]
    fn query_authority(state: &State) -> AccountId {
        state.account_id.clone()
    }

    #[codec::wrap]
    fn query_triggering_event(state: &State) -> Option<Event> {
        state.triggering_event.clone()
    }

    #[codec::wrap]
    fn query_operation_to_validate(state: &State) -> NeedsValidationBox {
        state
            .operation_to_validate
            .as_ref()
            .expect("`query_operation_to_validate()` called outside of validator")
            .clone()
    }

    fn query_max_log_level() -> u32 {
        iroha_logger::layer::max_log_level() as u32
    }

    /// Log the given string at the given log level
    ///
    /// # Errors
    ///
    /// If log level or string decoding fails
    #[codec::wrap]
    fn log((log_level, msg): (u8, String), state: &State) -> Result<(), Trap> {
        const TARGET: &str = "WASM";

        let _span = state.log_span.enter();
        match LogLevel::from_repr(log_level)
            .ok_or_else(|| Trap::new(format!("{log_level}: not a valid log level")))?
        {
            LogLevel::TRACE => {
                iroha_logger::trace!(target: TARGET, msg);
            }
            LogLevel::DEBUG => {
                iroha_logger::debug!(target: TARGET, msg);
            }
            LogLevel::INFO => {
                iroha_logger::info!(target: TARGET, msg);
            }
            LogLevel::WARN => {
                iroha_logger::warn!(target: TARGET, msg);
            }
            LogLevel::ERROR => {
                iroha_logger::error!(target: TARGET, msg);
            }
        }
        Ok(())
    }

    /// Host-defined function which prints the given string. When this function
    /// is called, the module serializes the string to linear memory and
    /// provides offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided
    /// allocation
    ///
    /// # Errors
    ///
    /// If string decoding fails
    #[allow(clippy::print_stdout, clippy::needless_pass_by_value)]
    #[codec::wrap]
    fn dbg(msg: String) {
        println!("{msg}");
    }

    fn create_linker(engine: &Engine) -> Result<Linker<State<'wrld>>> {
        let mut linker = Linker::new(engine);

        linker
            .func_wrap(
                import::MODULE_NAME,
                import::EXECUTE_ISI_FN_NAME,
                Self::execute_instruction,
            )
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::EXECUTE_QUERY_FN_NAME,
                    Self::execute_query,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::QUERY_AUTHORITY_FN_NAME,
                    Self::query_authority,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::QUERY_TRIGGERING_EVENT_FN_NAME,
                    Self::query_triggering_event,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::QUERY_OPERATION_TO_VALIDATE_FN_NAME,
                    Self::query_operation_to_validate,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::QUERY_MAX_LOG_LEVEL,
                    Self::query_max_log_level,
                )
            })
            .and_then(|l| l.func_wrap(import::MODULE_NAME, import::LOG_FN_NAME, Self::log))
            .and_then(|l| l.func_wrap(import::MODULE_NAME, import::DBG_FN_NAME, Self::dbg))
            .map_err(|err| Error::Initialization(eyre!(Box::new(err))))?;

        Ok(linker)
    }

    fn get_memory(caller: &mut impl GetExport) -> Result<wasmtime::Memory, ExportError> {
        caller
            .get_export(export::WASM_MEMORY_NAME)
            .ok_or_else(|| ExportError::not_found(export::WASM_MEMORY_NAME))?
            .into_memory()
            .ok_or_else(|| ExportError::not_a_memory(export::WASM_MEMORY_NAME))
    }

    fn get_alloc_fn(
        caller: &mut Caller<State>,
    ) -> Result<TypedFunc<WasmUsize, WasmUsize>, ExportError> {
        caller
            .get_export(export::WASM_ALLOC_FN)
            .ok_or_else(|| ExportError::not_found(export::WASM_ALLOC_FN))?
            .into_func()
            .ok_or_else(|| ExportError::not_a_function(export::WASM_ALLOC_FN))?
            .typed::<WasmUsize, WasmUsize, _>(caller)
            .map_err(|_error| {
                ExportError::wrong_signature::<WasmUsize, WasmUsize>(export::WASM_ALLOC_FN)
            })
    }

    fn get_typed_func<P: wasmtime::WasmParams, R: wasmtime::WasmResults>(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<State>,
        func_name: &'static str,
    ) -> Result<wasmtime::TypedFunc<P, R>, ExportError> {
        instance
            .get_func(&mut store, func_name)
            .ok_or_else(|| ExportError::not_found(func_name))?
            .typed::<P, R, _>(&mut store)
            .map_err(|_error| ExportError::wrong_signature::<P, R>(func_name))
    }

    /// Validates that the given smartcontract is eligible for execution
    ///
    /// # Errors
    ///
    /// - if instructions failed to validate, but queries are permitted
    /// - if instruction limits are not obeyed
    /// - if execution of the smartcontract fails (check ['execute'])
    pub fn validate(
        &mut self,
        wsv: &mut WorldStateView,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
        max_instruction_count: u64,
    ) -> Result<()> {
        let span = wasm_log_span!("Smart contract validation", %account_id);
        let state =
            State::new(wsv, account_id, self.config, span).with_validator(max_instruction_count);

        self.execute_smart_contract_with_state(bytes, state)
    }

    /// Executes the given wasm trigger module
    ///
    /// # Errors
    ///
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute_trigger_module(
        &mut self,
        wsv: &mut WorldStateView,
        id: &TriggerId,
        account_id: AccountId,
        module: &wasmtime::Module,
        event: Event,
    ) -> Result<()> {
        let span = wasm_log_span!("Trigger execution", %id, %account_id);
        let state = State::new(wsv, account_id, self.config, span).with_triggering_event(event);

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        Self::execute_main_with_store(&instance, &mut store)
    }

    /// Execute the given module of runtime validator
    ///
    /// # Errors
    ///
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute_validator_module(
        &self,
        wsv: &mut WorldStateView,
        authority: &<Account as Identifiable>::Id,
        module: &wasmtime::Module,
        operation: &validator::NeedsValidationBox,
    ) -> Result<validator::Result> {
        let span = wasm_log_span!("Runtime validation");
        let state = State::new(wsv, authority.clone(), self.config, span)
            .with_operation_to_validate(operation);

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let validate_fn = Self::get_typed_func(&instance, &mut store, export::WASM_MAIN_FN_NAME)?;

        // NOTE: This function takes ownership of the pointer
        let offset = validate_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let memory = Self::get_memory(&mut (&instance, &mut store))?;
        let dealloc_fn = Self::get_typed_func(&instance, &mut store, export::WASM_DEALLOC_FN)?;
        codec::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
            .map_err(|err| Error::Decode(err.into()))
    }

    /// Executes the given wasm smartcontract
    ///
    /// # Errors
    ///
    /// - if unable to construct wasm module or instance of wasm module
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute(
        &mut self,
        wsv: &mut WorldStateView,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<()> {
        let span = wasm_log_span!("Smart contract execution", %account_id);
        let state = State::new(wsv, account_id, self.config, span);

        self.execute_smart_contract_with_state(bytes, state)
    }

    fn execute_smart_contract_with_state(
        &mut self,
        bytes: impl AsRef<[u8]>,
        state: State,
    ) -> Result<()> {
        let mut store = self.create_store(state);
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        Self::execute_main_with_store(&smart_contract, &mut store)
    }

    fn execute_main_with_store(
        instance: &wasmtime::Instance,
        store: &mut wasmtime::Store<State>,
    ) -> Result<()> {
        let main_fn = Self::get_typed_func(instance, store, export::WASM_MAIN_FN_NAME)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(store, ())
            .map_err(ExportFnCallError::from)
            .map_err(Into::into)
    }

    fn instantiate_module(
        &self,
        module: &wasmtime::Module,
        mut store: &mut wasmtime::Store<State<'wrld>>,
    ) -> Result<wasmtime::Instance, InstantiationError> {
        let instance = self
            .linker
            .instantiate(&mut store, module)
            .map_err(|err| InstantiationError::Linker(eyre!(Box::new(err))))?;

        // Check mandatory exports
        let _ = Self::get_memory(&mut (&instance, &mut store))?;
        let _ =
            Self::get_typed_func::<WasmUsize, WasmUsize>(&instance, store, export::WASM_ALLOC_FN)?;
        let _ = Self::get_typed_func::<(WasmUsize, WasmUsize), ()>(
            &instance,
            store,
            export::WASM_DEALLOC_FN,
        )?;

        Ok(instance)
    }
}

/// `Runtime` builder
#[derive(Default)]
pub struct RuntimeBuilder {
    engine: Option<Engine>,
    config: Option<Configuration>,
}

impl RuntimeBuilder {
    /// Creates a new `RuntimeBuilder`
    pub fn new() -> Self {
        Self {
            engine: None,
            config: None,
        }
    }

    /// Sets the [`Engine`] to be used by the [`Runtime`]
    #[must_use]
    pub fn with_engine(mut self, engine: Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Sets the [`Configuration`] to be used by the [`Runtime`]
    #[must_use]
    pub fn with_configuration(mut self, config: Configuration) -> Self {
        self.config = Some(config);
        self
    }

    /// Builds the [`Runtime`]
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build<'wrld>(self) -> Result<Runtime<'wrld>> {
        let engine = self.engine.unwrap_or_else(create_engine);
        let linker = Runtime::create_linker(&engine)?;
        Ok(Runtime {
            engine,
            linker,
            config: self.config.unwrap_or_else(|| Configuration::default()),
        })
    }
}

/// Helper trait to make a function generic over `get_export()` fn from `wasmtime` crate
trait GetExport {
    fn get_export(&mut self, name: &str) -> Option<wasmtime::Extern>;
}

#[allow(clippy::single_char_lifetime_names)]
impl<T> GetExport for Caller<'_, T> {
    fn get_export(&mut self, name: &str) -> Option<wasmtime::Extern> {
        Self::get_export(self, name)
    }
}

impl<C: wasmtime::AsContextMut> GetExport for (&wasmtime::Instance, C) {
    fn get_export(&mut self, name: &str) -> Option<wasmtime::Extern> {
        wasmtime::Instance::get_export(self.0, &mut self.1, name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use iroha_crypto::KeyPair;
    use parity_scale_codec::Encode;

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _, PeersIds, World};

    fn world_with_test_account(account_id: &AccountId) -> World {
        let domain_id = account_id.domain_id.clone();
        let (public_key, _) = KeyPair::generate().unwrap().into();
        let account = Account::new(account_id.clone(), [public_key]).build(account_id);
        let mut domain = Domain::new(domain_id).build(account_id);
        assert!(domain.add_account(account).is_none());

        World::with([domain], PeersIds::new())
    }

    fn memory_and_alloc(isi_hex: &str) -> String {
        format!(
            r#"
            ;; Embed ISI into WASM binary memory
            (memory (export "{memory_name}") 1)
            (data (i32.const 0) "{isi_hex}")

            ;; Variable which tracks total allocated size
            (global $mem_size (mut i32) i32.const {isi_len})

            ;; Export mock allocator to host. This allocator never frees!
            (func (export "{alloc_fn_name}") (param $size i32) (result i32)
                global.get $mem_size

                (global.set $mem_size
                    (i32.add (global.get $mem_size) (local.get $size))))

            ;; Export mock deallocator to host. This allocator does nothing!
            (func (export "{dealloc_fn_name}") (param $size i32) (param $len i32)
                nop)
            "#,
            memory_name = export::WASM_MEMORY_NAME,
            alloc_fn_name = export::WASM_ALLOC_FN,
            dealloc_fn_name = export::WASM_DEALLOC_FN,
            isi_len = isi_hex.len() / 3,
            isi_hex = isi_hex,
        )
    }

    fn encode_hex<T: Encode>(isi: T) -> String {
        let isi_bytes = isi.encode();

        let mut isi_hex = String::with_capacity(3 * isi_bytes.len());
        for (i, c) in hex::encode(isi_bytes).chars().enumerate() {
            if i % 2 == 0 {
                isi_hex.push('\\');
            }

            isi_hex.push(c);
        }

        isi_hex
    }

    #[test]
    fn execute_instruction_exported() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&account_id), kura);

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(InstructionBox::from(register_isi))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32) (result i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return values
                    drop))
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            execute_fn_name = import::EXECUTE_ISI_FN_NAME,
            memory_and_alloc = memory_and_alloc(&isi_hex),
            isi_len = isi_hex.len() / 3,
        );
        let mut runtime = RuntimeBuilder::new().build()?;
        runtime
            .execute(&mut wsv, account_id, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn execute_query_exported() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&account_id), kura);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(account_id.clone())));

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32) (result i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return values
                    drop))
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            execute_fn_name = import::EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = RuntimeBuilder::new().build()?;
        runtime
            .execute(&mut wsv, account_id, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn instruction_limit_reached() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();

        let mut wsv = WorldStateView::new(world_with_test_account(&account_id), kura);

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(InstructionBox::from(register_isi))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi1_end}))
                    (call $exec_fn (i32.const {isi1_end}) (i32.const {isi2_end}))))
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            execute_fn_name = import::EXECUTE_ISI_FN_NAME,
            // Store two instructions into adjacent memory and execute them
            memory_and_alloc = memory_and_alloc(&isi_hex.repeat(2)),
            isi1_end = isi_hex.len() / 3,
            isi2_end = 2 * isi_hex.len() / 3,
        );

        let mut runtime = RuntimeBuilder::new().build()?;
        let res = runtime.validate(&mut wsv, account_id, wat, 1);

        if let Error::ExportFnCall(ExportFnCallError::Other(report)) =
            res.expect_err("Execution should fail")
        {
            assert!(report
                .to_string()
                .starts_with("Number of instructions exceeds maximum(1)"));
        }

        Ok(())
    }

    #[test]
    fn instructions_not_allowed() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&account_id), kura);

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(InstructionBox::from(register_isi))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32))
                )

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))
                )
            )
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            execute_fn_name = import::EXECUTE_ISI_FN_NAME,
            memory_and_alloc = memory_and_alloc(&isi_hex),
            isi_len = isi_hex.len() / 3,
        );

        let mut runtime = RuntimeBuilder::new().build()?;
        let res = runtime.validate(&mut wsv, account_id, wat, 1);

        if let Error::ExportFnCall(ExportFnCallError::HostExecution(report)) =
            res.expect_err("Execution should fail")
        {
            assert!(report
                .to_string()
                .starts_with("Transaction rejected due to insufficient authorisation"));
        }

        Ok(())
    }

    #[test]
    fn queries_not_allowed() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&account_id), kura);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(account_id.clone())));

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32) (result i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return value
                    drop))
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            execute_fn_name = import::EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = RuntimeBuilder::new().build()?;
        let res = runtime.validate(&mut wsv, account_id, wat, 1);

        if let Error::ExportFnCall(ExportFnCallError::HostExecution(report)) =
            res.expect_err("Execution should fail")
        {
            assert!(report.to_string().starts_with("All operations are denied"));
        }

        Ok(())
    }
}
