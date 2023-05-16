//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction
#![allow(clippy::expect_used, clippy::doc_link_with_quotes)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]

use eyre::{eyre, WrapErr};
use iroha_config::{
    base::proxy::Builder,
    wasm::{Configuration, ConfigurationProxy},
};
use iroha_data_model::{prelude::*, validator};
// NOTE: Using error_span so that span info is logged on every event
use iroha_logger::{error_span as wasm_log_span, prelude::tracing::Span, Level as LogLevel};
use parity_scale_codec::{DecodeAll, Encode};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use crate::{
    smartcontracts::{Execute, ValidQuery as _},
    wsv::WorldStateView,
};

type WasmUsize = u32;

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
    #[error("Runtime initialization failure: {0}")]
    Initialization(#[source] eyre::Report),
    /// Module could not be compiled or instantiated
    #[error("Module instantiation failure: {0}")]
    Instantiation(#[source] eyre::Report),
    /// Expected named export not found in module
    #[error("Named export not found: {0}")]
    ExportNotFound(#[source] eyre::Report),
    /// Call to the function exported from module failed
    ///
    /// In Wasmtime v0.33, can also mean that max linear memory was
    /// consumed
    #[error("Exported function call failed: {0}")]
    ExportFnCall(#[from] Trap),
    /// Error during decoding object with length prefix
    #[error("Failed to decode object from bytes with length prefix: {0}")]
    Decode(#[source] eyre::Report),
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
    Module::new(engine, bytes).map_err(|err| Error::Instantiation(eyre!(Box::new(err))))
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
    pub fn check_instruction_limits(&mut self) -> Result<(), Trap> {
        self.instruction_count += 1;

        if self.instruction_count > self.max_instruction_count {
            return Err(Trap::new(format!(
                "Number of instructions exceeds maximum({})",
                self.max_instruction_count
            )));
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
                .memory_size(config.max_memory.try_into().expect(
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
    fn create_store(&self, state: State<'wrld>) -> Result<Store<State<'wrld>>> {
        let mut store = Store::new(&self.engine, state);

        store.limiter(|stat| &mut stat.store_limits);
        store
            .add_fuel(self.config.fuel_limit)
            .map_err(|err| Error::Instantiation(eyre!(Box::new(err))))?;

        Ok(store)
    }

    fn create_smart_contract(
        &self,
        store: &mut Store<State<'wrld>>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<wasmtime::Instance> {
        load_module(&self.engine, bytes).and_then(|module| {
            self.linker
                .instantiate(store, &module)
                .map_err(|err| Error::Instantiation(eyre!(Box::new(err))))
        })
    }

    /// Host defined function which executes query. When calling this function, module
    /// serializes query to linear memory and provides offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided allocation
    /// but it does transfer ownership of the result to the caller
    ///
    /// # Errors
    ///
    /// If decoding or execution of the query fails
    fn execute_query(
        mut caller: Caller<State>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<WasmUsize, Trap> {
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let memory = Self::get_memory(&mut caller)?;

        let query: QueryBox = Self::decode_from_memory(&memory, &caller, offset, len)?;
        iroha_logger::debug!(%query, "Executing");

        let State {
            wsv,
            account_id,
            operation_to_validate,
            ..
        } = caller.data_mut();

        let called_from_validator = operation_to_validate.is_some();
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
                .validate(wsv, account_id, query.clone())
                .map_err(|error| NotPermittedFail {
                    reason: error.to_string(),
                })
                .map_err(TransactionRejectionReason::NotPermitted)
                .map_err(|err| Trap::new(err.to_string()))?;
        }

        let res_bytes = Self::encode_with_length_prefix(
            &query.execute(wsv).map_err(|e| Trap::new(e.to_string()))?,
        )?;

        let res_offset =
            Self::encode_bytes_into_memory(&res_bytes, &memory, &alloc_fn, &mut caller)?;

        Ok(res_offset)
    }

    /// Host defined function which executes ISI. When calling this function, module
    /// serializes ISI to linear memory and provides offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided allocation
    /// but it does transfer ownership of the result to the caller
    ///
    /// # Errors
    ///
    /// If decoding or execution of the ISI fails
    fn execute_instruction(
        mut caller: Caller<State>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;

        let isi: InstructionBox = Self::decode_from_memory(&memory, &caller, offset, len)?;
        iroha_logger::debug!(%isi, "Executing");

        let State {
            wsv,
            account_id,
            validator,
            operation_to_validate,
            ..
        } = caller.data_mut();

        let called_from_validator = operation_to_validate.is_some();
        if called_from_validator {
            // NOTE: Validator has already validated the isi, don't validate again
            isi.execute(account_id, wsv)
                .map_err(|error| Trap::new(error.to_string()))
        } else {
            // NOTE: Smart contract (not validator) is trying to execute the isi, validate it first
            if let Some(validator) = validator {
                validator
                    .check_instruction_limits()
                    .map_err(|error| Trap::new(error.to_string()))?;
            }
            // TODO: Validation should be skipped when executing smart contract.
            // There should be two steps validation and execution. First smart contract
            // is validated and then it's executed. Here it's validating in both steps.
            // Add a flag indicating whether smart contract is being validated or executed
            wsv.validator_view()
                .clone() // Cloning validator is a cheap operation
                .validate(wsv, account_id, isi)
                .map_err(|error| NotPermittedFail {
                    reason: error.to_string(),
                })
                .map_err(|err| Trap::new(err.to_string()))
        }
    }

    fn query_authority(mut caller: Caller<State>) -> Result<WasmUsize, Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let state = caller.data();
        let authority = &state.account_id;

        let bytes = Self::encode_with_length_prefix(authority)?;
        let authority_offset =
            Self::encode_bytes_into_memory(&bytes, &memory, &alloc_fn, &mut caller)?;
        Ok(authority_offset)
    }

    fn query_triggering_event(mut caller: Caller<State>) -> Result<WasmUsize, Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let state = caller.data();
        let event = state
            .triggering_event
            .as_ref()
            .ok_or_else(|| Trap::new("There is no triggering event".to_owned()))?;

        let bytes = Self::encode_with_length_prefix(event)?;
        let event_offset = Self::encode_bytes_into_memory(&bytes, &memory, &alloc_fn, &mut caller)?;
        Ok(event_offset)
    }

    fn query_operation_to_validate(mut caller: Caller<State>) -> Result<WasmUsize, Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let state = caller.data();
        let operation = state
            .operation_to_validate
            .as_ref()
            .ok_or_else(|| Trap::new("There is no operation to validate".to_owned()))?;

        let bytes = Self::encode_with_length_prefix(operation)?;
        let operation_offset =
            Self::encode_bytes_into_memory(&bytes, &memory, &alloc_fn, &mut caller)?;
        Ok(operation_offset)
    }

    fn query_max_log_level() -> u32 {
        iroha_logger::layer::max_log_level() as u32
    }

    /// Log the given string at the given log level. When this function
    /// is called, the module serializes the string to linear memory and
    /// provides log level, offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided
    /// allocation
    ///
    /// # Errors
    ///
    /// If log level or string decoding fails
    fn log(
        mut caller: Caller<State>,
        log_level: u32,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<(), Trap> {
        const TARGET: &str = "WASM";

        let error_msg = || Trap::new(format!("{log_level}: not a valid log level"));
        let Ok(log_level) = log_level.try_into() else {
          return Err(error_msg());
        };

        let memory = Self::get_memory(&mut caller)?;
        let msg: String = Self::decode_from_memory(&memory, &caller, offset, len)?;

        let _span = caller.data().log_span.enter();
        match LogLevel::from_repr(log_level).ok_or_else(error_msg)? {
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
    #[allow(clippy::print_stdout)]
    fn dbg(mut caller: Caller<State>, offset: WasmUsize, len: WasmUsize) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let s: String = Self::decode_from_memory(&memory, &caller, offset, len)?;
        println!("{s}");
        Ok(())
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

    fn get_alloc_fn(caller: &mut Caller<State>) -> Result<TypedFunc<WasmUsize, WasmUsize>, Trap> {
        caller
            .get_export(export::WASM_ALLOC_FN)
            .ok_or_else(|| Trap::new(format!("{}: export not found", export::WASM_ALLOC_FN)))?
            .into_func()
            .ok_or_else(|| Trap::new(format!("{}: not a function", export::WASM_ALLOC_FN)))?
            .typed::<WasmUsize, WasmUsize, _>(caller)
            .map_err(|_error| {
                Trap::new(format!("{}: unexpected declaration", export::WASM_ALLOC_FN))
            })
    }

    fn get_memory(caller: &mut impl GetExport) -> Result<wasmtime::Memory, Trap> {
        caller
            .get_export(export::WASM_MEMORY_NAME)
            .ok_or_else(|| Trap::new(format!("{}: export not found", export::WASM_MEMORY_NAME)))?
            .into_memory()
            .ok_or_else(|| Trap::new(format!("{}: not a memory", export::WASM_MEMORY_NAME)))
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

        let mut store = self.create_store(state)?;
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
    ) -> Result<validator::Verdict> {
        let span = wasm_log_span!("Runtime validation");
        let state = State::new(wsv, authority.clone(), self.config, span)
            .with_operation_to_validate(operation);

        let mut store = self.create_store(state)?;
        let instance = self.instantiate_module(module, &mut store)?;

        let validate_fn = instance
            .get_typed_func::<_, WasmUsize, _>(&mut store, export::WASM_MAIN_FN_NAME)
            .map_err(|err| Error::ExportNotFound(eyre!(Box::new(err))))?;

        // NOTE: This function takes ownership of the pointer
        let offset = validate_fn
            .call(&mut store, ())
            .map_err(Error::ExportFnCall)?;

        let memory = Self::get_memory(&mut (&instance, &mut store))?;
        let dealloc_fn = Self::get_dealloc_fn(&instance, &mut store)?;
        Self::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
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
        let mut store = self.create_store(state)?;
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        Self::execute_main_with_store(&smart_contract, &mut store)
    }

    fn execute_main_with_store(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<State>,
    ) -> Result<()> {
        let main_fn = instance
            .get_typed_func(&mut store, export::WASM_MAIN_FN_NAME)
            .map_err(|err| Error::ExportNotFound(eyre!(Box::new(err))))?;

        // NOTE: This function takes ownership of the pointer
        main_fn.call(store, ()).map_err(Error::ExportFnCall)
    }

    fn instantiate_module(
        &self,
        module: &wasmtime::Module,
        store: &mut wasmtime::Store<State<'wrld>>,
    ) -> Result<wasmtime::Instance> {
        self.linker
            .instantiate(store, module)
            .map_err(|err| Error::Instantiation(eyre!(Box::new(err))))
    }

    fn get_dealloc_fn(
        instance: &wasmtime::Instance,
        store: &mut wasmtime::Store<State>,
    ) -> Result<wasmtime::TypedFunc<(WasmUsize, WasmUsize), ()>> {
        instance
            .get_typed_func(store, export::WASM_DEALLOC_FN)
            .map_err(|err| Error::ExportNotFound(eyre!(Box::new(err))))
    }

    /// Decode object from the given `memory` at the given `offset` with the given `len`
    ///
    /// # Warning
    ///
    /// This method does not take ownership of the pointer.
    fn decode_from_memory<C: wasmtime::AsContext, T: DecodeAll>(
        memory: &wasmtime::Memory,
        context: &C,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<T, Trap> {
        // Accessing memory as a byte slice to avoid the use of unsafe
        let mem_range = offset as usize..(offset + len) as usize;
        let mut bytes = &memory.data(context)[mem_range];
        T::decode_all(&mut bytes).map_err(|error| Trap::new(error.to_string()))
    }

    /// Decode the object from a given pointer where first element is the size of the object
    /// following it. This can be considered a custom encoding format.
    ///
    /// # Warning
    ///
    /// This method takes ownership of the given pointer.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn decode_with_length_prefix_from_memory<
        C: wasmtime::AsContextMut,
        T: DecodeAll + std::fmt::Debug,
    >(
        memory: &wasmtime::Memory,
        dealloc_fn: &wasmtime::TypedFunc<(WasmUsize, WasmUsize), ()>,
        mut context: &mut C,
        offset: WasmUsize,
    ) -> Result<T> {
        const U32_TO_USIZE_ERROR_MES: &str = "`u32` should always fit in `usize`";

        let len_size_bytes: u32 = core::mem::size_of::<WasmUsize>()
            .try_into()
            .map_err(|err| Error::Decode(eyre!("Can't convert `usize` to `u32`: {err}")))?;
        let len = u32::from_le_bytes(
            memory.data(&mut context)[offset as usize..(offset + len_size_bytes) as usize]
                .try_into()
                .expect("Prefix length size(bytes) incorrect"),
        );

        let bytes = &memory.data_mut(&mut context)[offset.try_into().expect(U32_TO_USIZE_ERROR_MES)
            ..(offset + len).try_into().expect(U32_TO_USIZE_ERROR_MES)];

        let obj =
            T::decode_all(&mut &bytes[len_size_bytes.try_into().expect(U32_TO_USIZE_ERROR_MES)..])
                .map_err(|err| Error::Decode(err.into()))?;

        dealloc_fn
            .call(&mut context, (offset, len))
            .map_err(Error::ExportFnCall)?;
        Ok(obj)
    }

    /// Encode `bytes` to the given `memory` with the given `alloc_fn` and `context`
    ///
    /// Return the offset of the encoded object
    fn encode_bytes_into_memory(
        bytes: &[u8],
        memory: &wasmtime::Memory,
        alloc_fn: &wasmtime::TypedFunc<WasmUsize, WasmUsize>,
        mut context: impl wasmtime::AsContextMut,
    ) -> Result<WasmUsize, Trap> {
        let mut encode = || -> eyre::Result<WasmUsize> {
            bytes
                .len()
                .try_into()
                .wrap_err("Bytes length is too big and can't be represented as `WasmUsize`")
                .and_then(|len| alloc_fn.call(&mut context, len).map_err(Into::into))
                .and_then(|offset| {
                    let offset_usize = offset
                        .try_into()
                        .wrap_err("Offset is too big and can't be represented as `usize`")?;
                    memory.write(&mut context, offset_usize, bytes)?;

                    Ok(offset)
                })
        };
        encode().map_err(|error| Trap::new(error.to_string()))
    }

    /// Encode the given object but also add it's length in front of it. This can be considered
    /// a custom encoding format
    ///
    /// Usually, to retrieve the encoded object both pointer and the length of the allocation
    /// are provided. However, due to the lack of support for multivalue return values in stable
    /// `WebAssembly` it's not possible to return two values from a wasm function without some
    /// shenanignas. In those cases, only one value is sent which is pointer to the allocation
    /// with the first element being the length of the encoded object following it.
    fn encode_with_length_prefix<T: Encode>(obj: &T) -> Result<Vec<u8>, Trap> {
        let len_size_bytes = core::mem::size_of::<WasmUsize>();

        let mut r = Vec::with_capacity(len_size_bytes + obj.size_hint());

        // Reserve space for length
        r.resize(len_size_bytes, 0);
        obj.encode_to(&mut r);

        // Store length as byte array in front of encoding
        let len = &WasmUsize::try_from(r.len()).map_err(|e| Trap::new(e.to_string()))?;
        r[..len_size_bytes].copy_from_slice(&len.to_le_bytes());

        Ok(r)
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
            config: self.config.unwrap_or_else(|| {
                ConfigurationProxy::default()
                    .build()
                    .expect("Error building WASM Runtime configuration from proxy. This is a bug")
            }),
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
            "#,
            memory_name = export::WASM_MEMORY_NAME,
            alloc_fn_name = export::WASM_ALLOC_FN,
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
                    (func $exec_fn (param i32 i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))))
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

        if let Error::ExportFnCall(trap) = res.expect_err("Execution should fail") {
            assert!(trap
                .display_reason()
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

        if let Error::ExportFnCall(trap) = res.expect_err("Execution should fail") {
            assert!(trap
                .display_reason()
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

        if let Error::ExportFnCall(trap) = res.expect_err("Execution should fail") {
            assert!(trap
                .display_reason()
                .to_string()
                .starts_with("All operations are denied"));
        }

        Ok(())
    }
}
