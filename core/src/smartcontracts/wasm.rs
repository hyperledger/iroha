//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction
#![allow(clippy::doc_link_with_quotes, clippy::arithmetic_side_effects)]

use error::*;
use eyre::eyre;
use import::{
    ExecuteOperations as _, GetAuthority as _, GetOperationsToValidate as _,
    SetPermissionTokenSchema as _,
};
use iroha_config::{
    base::proxy::Builder,
    wasm::{Configuration, ConfigurationProxy},
};
use iroha_data_model::{
    account::AccountId,
    isi::InstructionBox,
    permission::PermissionTokenSchema,
    prelude::*,
    validator::{self, MigrationResult},
    Level as LogLevel, ValidationFail,
};
use iroha_logger::debug;
// NOTE: Using error_span so that span info is logged on every event
use iroha_logger::{error_span as wasm_log_span, prelude::tracing::Span};
use iroha_wasm_codec::{self as codec, WasmUsize};
use state::{Wsv as _, WsvMut as _};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use super::query::LazyValue;
use crate::{
    smartcontracts::{Execute, ValidQuery as _},
    wsv::WorldStateView,
};

mod export {
    //! Module functions names exported from wasm to iroha

    /// Exported function to allocate memory
    pub const WASM_ALLOC_FN: &str = "_iroha_wasm_alloc";
    /// Exported function to deallocate memory
    pub const WASM_DEALLOC_FN: &str = "_iroha_wasm_dealloc";
    /// Name of the exported memory
    pub const WASM_MEMORY_NAME: &str = "memory";
    /// Name of the exported entry for smart contract or trigger execution
    pub const WASM_MAIN_FN_NAME: &str = "_iroha_wasm_main";
    /// Name of the exported entry for validator to validate transaction
    pub const VALIDATOR_VALIDATE_TRANSACTION_FN_NAME: &str =
        "_iroha_validator_validate_transaction";
    /// Name of the exported entry for validator to validate instruction
    pub const VALIDATOR_VALIDATE_INSTRUCTION_FN_NAME: &str =
        "_iroha_validator_validate_instruction";
    /// Name of the exported entry for validator to validate query
    pub const VALIDATOR_VALIDATE_QUERY_FN_NAME: &str = "_iroha_validator_validate_query";
    /// Name of the exported entry for validator to perform migration
    pub const VALIDATOR_MIGRATE_FN_NAME: &str = "_iroha_validator_migrate";
}

mod import {
    //! Module functions names imported from iroha to wasm and related traits

    use super::*;

    /// Name of the linked wasm module
    pub const MODULE_NAME: &str = "iroha";
    /// Name of the imported function to execute instructions
    pub const EXECUTE_ISI_FN_NAME: &str = "execute_instruction";
    /// Name of the imported function to execute queries
    pub const EXECUTE_QUERY_FN_NAME: &str = "execute_query";
    /// Name of the imported function to query trigger authority
    pub const GET_AUTHORITY_FN_NAME: &str = "get_authority";
    /// Name of the imported function to query event that triggered the smart contract execution
    pub const GET_TRIGGERING_EVENT_FN_NAME: &str = "get_triggering_event";
    /// Name of the imported function to get transaction that is to be verified
    pub const GET_TRANSACTION_TO_VALIDATE_FN_NAME: &str = "get_transaction_to_validate";
    /// Name of the imported function to get instruction that is to be verified
    pub const GET_INSTRUCTION_TO_VALIDATE_FN_NAME: &str = "get_instruction_to_validate";
    /// Name of the imported function to get query that is to be verified
    pub const GET_QUERY_TO_VALIDATE_FN_NAME: &str = "get_query_to_validate";
    /// Name of the imported function to debug print objects
    pub const DBG_FN_NAME: &str = "dbg";
    /// Name of the imported function to log objects
    pub const LOG_FN_NAME: &str = "log";
    /// Name of the imported function to set new [`PermissionTokenSchema`]
    pub const SET_PERMISSION_TOKEN_SCHEMA_FN_NAME: &str = "set_permission_token_schema";

    pub trait ExecuteOperations<S> {
        /// Execute `query` on host
        #[codec::wrap_trait_fn]
        fn execute_query(query: QueryBox, state: &S) -> Result<Value, ValidationFail>;

        /// Execute `instruction` on host
        #[codec::wrap_trait_fn]
        fn execute_instruction(
            instruction: InstructionBox,
            state: &mut S,
        ) -> Result<(), ValidationFail>;
    }

    pub trait GetAuthority<S> {
        #[codec::wrap_trait_fn]
        fn get_authority(state: &S) -> AccountId;
    }

    pub trait GetOperationsToValidate<S> {
        #[codec::wrap_trait_fn]
        fn get_transaction_to_validate(state: &S) -> VersionedSignedTransaction;

        #[codec::wrap_trait_fn]
        fn get_instruction_to_validate(state: &S) -> InstructionBox;

        #[codec::wrap_trait_fn]
        fn get_query_to_validate(state: &S) -> QueryBox;
    }

    pub trait SetPermissionTokenSchema<S> {
        #[codec::wrap_trait_fn]
        fn set_permission_token_schema(schema: PermissionTokenSchema, state: &mut S);
    }
}

pub mod error {
    //! Error types for [`wasm`](super) and their impls

    use wasmtime::Trap;

    /// `WebAssembly` execution error type
    #[derive(Debug, thiserror::Error, displaydoc::Display)]
    pub enum Error {
        /// Runtime initialization failure
        Initialization(#[source] eyre::Report),
        /// Failed to load module
        ModuleLoading(#[source] eyre::Report),
        /// Module could not be instantiated
        Instantiation(#[from] InstantiationError),
        /// Export error
        Export(#[from] ExportError),
        /// Call to the function exported from module failed
        ExportFnCall(#[from] ExportFnCallError),
        /// Failed to decode object from bytes with length prefix
        Decode(#[source] eyre::Report),
    }

    /// Instantiation error
    #[derive(Debug, thiserror::Error, displaydoc::Display)]
    #[ignore_extra_doc_attributes]
    pub enum InstantiationError {
        /// Linker failed to instantiate module
        ///
        /// [`wasmtime::Linker::instantiate`] failed
        Linker(#[from] eyre::Report),
        /// Export which should always be present is missing
        MandatoryExport(#[from] ExportError),
    }

    /// Failed to export `{export_name}`
    #[derive(Debug, Copy, Clone, thiserror::Error, displaydoc::Display)]
    pub struct ExportError {
        /// Name of the failed export
        pub export_name: &'static str,
        /// Error kind
        #[source]
        pub export_error_kind: ExportErrorKind,
    }

    /// Export error kind
    #[derive(Debug, Copy, Clone, thiserror::Error, displaydoc::Display)]
    pub enum ExportErrorKind {
        /// Named export not found
        NotFound,
        /// Export expected to be a memory, but it's not
        NotAMemory,
        /// Export expected to be a function, but it's not
        NotAFunction,
        /// Export has a wrong signature, expected `{0} -> {1}`
        WrongSignature(&'static str, &'static str),
    }

    impl ExportError {
        /// Create [`ExportError`] of [`NotFound`](ExportErrorKind::NotFound) kind
        pub fn not_found(export_name: &'static str) -> Self {
            Self {
                export_name,
                export_error_kind: ExportErrorKind::NotFound,
            }
        }

        /// Create [`ExportError`] of [`NotAMemory`](ExportErrorKind::NotAMemory) kind
        pub fn not_a_memory(export_name: &'static str) -> Self {
            Self {
                export_name,
                export_error_kind: ExportErrorKind::NotAMemory,
            }
        }

        /// Create [`ExportError`] of [`NotAFunction`](ExportErrorKind::NotAFunction) kind
        pub fn not_a_function(export_name: &'static str) -> Self {
            Self {
                export_name,
                export_error_kind: ExportErrorKind::NotAFunction,
            }
        }

        /// Create [`ExportError`] of [`WrongSignature`](ExportErrorKind::WrongSignature) kind
        pub fn wrong_signature<P, R>(export_name: &'static str) -> Self {
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
    #[derive(Debug, thiserror::Error, displaydoc::Display)]
    pub enum ExportFnCallError {
        /// Failed to execute operation on host
        HostExecution(#[source] eyre::Report),
        /// Execution limits exceeded
        ExecutionLimitsExceeded(#[source] eyre::Report),
        /// Other kind of trap
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
}

/// [`Result`] type for this module
pub type Result<T, E = Error> = core::result::Result<T, E>;

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

fn create_config() -> Result<Config> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .cache_config_load_default()
        .map_err(|err| Error::Initialization(eyre!(Box::new(err))))?;
    Ok(config)
}

/// Limits checker for smartcontracts.
#[derive(Copy, Clone)]
struct LimitsValidator {
    /// Number of instructions in the smartcontract
    instruction_count: u64,
    /// Max allowed number of instructions in the smartcontract
    max_instruction_count: u64,
}

impl LimitsValidator {
    /// Create new [`LimitsValidator`]
    pub fn new(max_instruction_count: u64) -> Self {
        Self {
            instruction_count: 0,
            max_instruction_count,
        }
    }

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

pub mod state {
    //! All supported states for [`Runtime`](super::Runtime)

    use super::*;

    /// Construct [`StoreLimits`] from [`Configuration`]
    ///
    /// # Panics
    ///
    /// Panics if failed to convert `u32` into `usize` which should not happen
    /// on any supported platform
    pub fn store_limits_from_config(config: &Configuration) -> StoreLimits {
        StoreLimitsBuilder::new()
            .memory_size(
                config.max_memory.try_into().expect(
                    "config.max_memory is a u32 so this can't fail on any supported platform",
                ),
            )
            .instances(1)
            .memories(1)
            .tables(1)
            .build()
    }

    /// Common data for states
    pub struct Common<'wrld> {
        pub(super) authority: AccountId,
        pub(super) store_limits: StoreLimits,
        pub(super) wsv: &'wrld mut WorldStateView,
        /// Span inside of which all logs are recorded for this smart contract
        pub(super) log_span: Span,
    }

    impl<'wrld> Common<'wrld> {
        /// Create new [`Common`]
        pub fn new(
            wsv: &'wrld mut WorldStateView,
            authority: AccountId,
            config: Configuration,
            log_span: Span,
        ) -> Self {
            Self {
                wsv,
                authority,
                store_limits: store_limits_from_config(&config),
                log_span,
            }
        }
    }

    /// Trait to get span for logs.
    ///
    /// Used to implement [`log()`](Runtime::log) export.
    pub trait LogSpan {
        /// Get log span
        fn log_span(&self) -> &Span;
    }

    /// Trait to get mutable reference to limits
    ///
    /// Used to implement [`Runtime::create_store()`].
    pub trait LimitsMut {
        /// Get mutable reference to store limits
        fn limits_mut(&mut self) -> &mut StoreLimits;
    }

    /// Trait to get authority account id
    pub trait Authority {
        /// Get authority account id
        fn authority(&self) -> &AccountId;
    }

    /// Trait to get an immutable reference to [`WorldStateView`]
    pub trait Wsv {
        /// Get immutable [`WorldStateView`]
        fn wsv(&self) -> &WorldStateView;
    }

    /// Trait to get mutable reference to [`WorldStateView`]
    pub trait WsvMut {
        /// Get mutable [`WorldStateView`]
        fn wsv_mut(&mut self) -> &mut WorldStateView;
    }

    /// Smart Contract execution state
    pub struct SmartContract<'wrld> {
        pub(super) common: Common<'wrld>,
        /// Should be set for smart contract validation only.
        pub(super) limits_validator: Option<LimitsValidator>,
    }

    impl LogSpan for SmartContract<'_> {
        fn log_span(&self) -> &Span {
            &self.common.log_span
        }
    }

    impl LimitsMut for SmartContract<'_> {
        fn limits_mut(&mut self) -> &mut StoreLimits {
            &mut self.common.store_limits
        }
    }

    impl Authority for SmartContract<'_> {
        fn authority(&self) -> &AccountId {
            &self.common.authority
        }
    }

    impl Wsv for SmartContract<'_> {
        fn wsv(&self) -> &WorldStateView {
            self.common.wsv
        }
    }

    impl WsvMut for SmartContract<'_> {
        fn wsv_mut(&mut self) -> &mut WorldStateView {
            self.common.wsv
        }
    }

    /// Trigger execution state
    pub struct Trigger<'wrld> {
        pub(super) common: Common<'wrld>,
        /// Event which activated this trigger
        pub(super) triggering_event: Event,
    }

    impl LogSpan for Trigger<'_> {
        fn log_span(&self) -> &Span {
            &self.common.log_span
        }
    }

    impl LimitsMut for Trigger<'_> {
        fn limits_mut(&mut self) -> &mut StoreLimits {
            &mut self.common.store_limits
        }
    }

    impl Authority for Trigger<'_> {
        fn authority(&self) -> &AccountId {
            &self.common.authority
        }
    }

    impl Wsv for Trigger<'_> {
        fn wsv(&self) -> &WorldStateView {
            self.common.wsv
        }
    }

    impl WsvMut for Trigger<'_> {
        fn wsv_mut(&mut self) -> &mut WorldStateView {
            self.common.wsv
        }
    }

    pub mod validator {
        //! States related to *Validator* execution.

        use super::*;

        /// Struct to encapsulate common state for `validate_transaction()` and
        /// `validate_instruction()` entrypoints.
        ///
        /// *Mut* means that [`WorldStateView`] will be mutated.
        pub struct ValidateMut<'wrld, T> {
            pub(in super::super) common: Common<'wrld>,
            pub(in super::super) to_validate: T,
        }

        impl<T> LogSpan for ValidateMut<'_, T> {
            fn log_span(&self) -> &Span {
                &self.common.log_span
            }
        }

        impl<T> LimitsMut for ValidateMut<'_, T> {
            fn limits_mut(&mut self) -> &mut StoreLimits {
                &mut self.common.store_limits
            }
        }

        impl<T> Authority for ValidateMut<'_, T> {
            fn authority(&self) -> &AccountId {
                &self.common.authority
            }
        }

        impl<T> Wsv for ValidateMut<'_, T> {
            fn wsv(&self) -> &WorldStateView {
                self.common.wsv
            }
        }

        impl<T> WsvMut for ValidateMut<'_, T> {
            fn wsv_mut(&mut self) -> &mut WorldStateView {
                self.common.wsv
            }
        }

        /// State for executing `validate_transaction()` entrypoint of validator
        pub type ValidateTransaction<'wrld> = ValidateMut<'wrld, VersionedSignedTransaction>;

        /// State for executing `validate_instruction()` entrypoint of validator
        pub type ValidateInstruction<'wrld> = ValidateMut<'wrld, InstructionBox>;

        /// State for executing `validate_query()` entrypoint of validator
        ///
        /// Does not implement [`WsvMut`] because it contains immutable reference to
        /// [`WorldStateView`] since it shouldn't be changed during *query* validation.
        pub struct ValidateQuery<'wrld> {
            pub(in super::super) authority: AccountId,
            pub(in super::super) store_limits: StoreLimits,
            pub(in super::super) wsv: &'wrld WorldStateView,
            pub(in super::super) log_span: Span,
            pub(in super::super) query: QueryBox,
        }

        impl LogSpan for ValidateQuery<'_> {
            fn log_span(&self) -> &Span {
                &self.log_span
            }
        }

        impl LimitsMut for ValidateQuery<'_> {
            fn limits_mut(&mut self) -> &mut StoreLimits {
                &mut self.store_limits
            }
        }

        impl Authority for ValidateQuery<'_> {
            fn authority(&self) -> &AccountId {
                &self.authority
            }
        }

        impl Wsv for ValidateQuery<'_> {
            fn wsv(&self) -> &WorldStateView {
                self.wsv
            }
        }

        /// State for executing `migrate()` entrypoint of validator
        pub struct Migrate<'wrld>(pub(in super::super) Common<'wrld>);

        impl LimitsMut for Migrate<'_> {
            fn limits_mut(&mut self) -> &mut StoreLimits {
                &mut self.0.store_limits
            }
        }

        impl LogSpan for Migrate<'_> {
            fn log_span(&self) -> &Span {
                &self.0.log_span
            }
        }

        impl Authority for Migrate<'_> {
            fn authority(&self) -> &AccountId {
                &self.0.authority
            }
        }

        impl Wsv for Migrate<'_> {
            fn wsv(&self) -> &WorldStateView {
                self.0.wsv
            }
        }

        impl WsvMut for Migrate<'_> {
            fn wsv_mut(&mut self) -> &mut WorldStateView {
                self.0.wsv
            }
        }
    }
}

/// `WebAssembly` virtual machine generic over state
pub struct Runtime<S> {
    engine: Engine,
    linker: Linker<S>,
    config: Configuration,
}

impl<S> Runtime<S> {
    fn get_memory(caller: &mut impl GetExport) -> Result<wasmtime::Memory, ExportError> {
        caller
            .get_export(export::WASM_MEMORY_NAME)
            .ok_or_else(|| ExportError::not_found(export::WASM_MEMORY_NAME))?
            .into_memory()
            .ok_or_else(|| ExportError::not_a_memory(export::WASM_MEMORY_NAME))
    }

    fn get_alloc_fn(
        caller: &mut Caller<S>,
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

    fn execute_main_with_store(
        instance: &wasmtime::Instance,
        store: &mut wasmtime::Store<S>,
    ) -> Result<()> {
        let main_fn = Self::get_typed_func(instance, store, export::WASM_MAIN_FN_NAME)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(store, ())
            .map_err(ExportFnCallError::from)
            .map_err(Into::into)
    }

    fn get_typed_func<P: wasmtime::WasmParams, R: wasmtime::WasmResults>(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<S>,
        func_name: &'static str,
    ) -> Result<wasmtime::TypedFunc<P, R>, ExportError> {
        instance
            .get_func(&mut store, func_name)
            .ok_or_else(|| ExportError::not_found(func_name))?
            .typed::<P, R, _>(&mut store)
            .map_err(|_error| ExportError::wrong_signature::<P, R>(func_name))
    }

    fn create_smart_contract(
        &self,
        store: &mut Store<S>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<wasmtime::Instance> {
        let module = load_module(&self.engine, bytes)?;
        self.instantiate_module(&module, store).map_err(Into::into)
    }

    fn instantiate_module(
        &self,
        module: &wasmtime::Module,
        mut store: &mut wasmtime::Store<S>,
    ) -> Result<wasmtime::Instance, InstantiationError> {
        let instance = self
            .linker
            .instantiate(&mut store, module)
            .map_err(|err| InstantiationError::Linker(eyre!(Box::new(err))))?;

        Self::check_mandatory_exports(&instance, store)?;

        Ok(instance)
    }

    fn check_mandatory_exports(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<S>,
    ) -> Result<(), InstantiationError> {
        let _ = Self::get_memory(&mut (instance, &mut store))?;
        let _ =
            Self::get_typed_func::<WasmUsize, WasmUsize>(instance, store, export::WASM_ALLOC_FN)?;
        let _ = Self::get_typed_func::<(WasmUsize, WasmUsize), ()>(
            instance,
            store,
            export::WASM_DEALLOC_FN,
        )?;

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
    #[codec::wrap(state = "S")]
    fn dbg(msg: String) {
        println!("{msg}");
    }
}

impl<S: state::LogSpan> Runtime<S> {
    /// Log the given string at the given log level
    ///
    /// # Errors
    ///
    /// If log level or string decoding fails
    #[codec::wrap]
    pub fn log((log_level, msg): (u8, String), state: &S) -> Result<(), Trap> {
        const TARGET: &str = "WASM";

        let _span = state.log_span().enter();
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
}

impl<S: state::LimitsMut> Runtime<S> {
    fn create_store(&self, state: S) -> Store<S> {
        let mut store = Store::new(&self.engine, state);

        store.limiter(|s| s.limits_mut());
        store
            .add_fuel(self.config.fuel_limit)
            .expect("Wasm Runtime config is malformed, this is a bug");

        store
    }

    fn execute_validator_validate_internal(
        &self,
        module: &wasmtime::Module,
        state: S,
        validate_fn_name: &'static str,
    ) -> Result<validator::Result> {
        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let validate_fn = Self::get_typed_func(&instance, &mut store, validate_fn_name)?;

        // NOTE: This function takes ownership of the pointer
        let offset = validate_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let memory =
            Self::get_memory(&mut (&instance, &mut store)).expect("Checked at instantiation step");
        let dealloc_fn = Self::get_typed_func(&instance, &mut store, export::WASM_DEALLOC_FN)
            .expect("Checked at instantiation step");
        codec::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
            .map_err(|err| Error::Decode(err.into()))
    }
}

#[allow(clippy::needless_pass_by_value)]
impl<S: state::Authority + state::Wsv + state::WsvMut> Runtime<S> {
    fn default_execute_query(query: QueryBox, state: &S) -> Result<Value, ValidationFail> {
        iroha_logger::debug!(%query, "Executing");

        let wsv = state.wsv();

        // NOTE: Smart contract (not validator) is trying to execute the query, validate it first
        // TODO: Validation should be skipped when executing smart contract.
        // There should be two steps validation and execution. First smart contract
        // is validated and then it's executed. Here it's validating in both steps.
        // Add a flag indicating whether smart contract is being validated or executed
        wsv.validator()
            .validate_query(wsv, state.authority(), query.clone())?;

        query
            .execute(wsv)
            .map(|lazy_value| match lazy_value {
                LazyValue::Value(value) => value,
                LazyValue::Iter(iter) => Value::Vec(iter.collect()),
            })
            .map_err(Into::into)
    }

    fn default_execute_instruction(
        instruction: InstructionBox,
        state: &mut S,
    ) -> Result<(), ValidationFail> {
        debug!(%instruction, "Executing");

        // TODO: Validation should be skipped when executing smart contract.
        // There should be two steps validation and execution. First smart contract
        // is validated and then it's executed. Here it's validating in both steps.
        // Add a flag indicating whether smart contract is being validated or executed
        let authority = state.authority().clone();
        let wsv = state.wsv_mut();
        wsv.validator()
                .clone() // Cloning validator is a cheap operation
                .validate_instruction(wsv, &authority, instruction)
    }
}

impl<S: state::Authority> import::GetAuthority<S> for Runtime<S> {
    #[codec::wrap]
    fn get_authority(state: &S) -> AccountId {
        state.authority().clone()
    }
}

impl<'wrld> Runtime<state::SmartContract<'wrld>> {
    /// Executes the given wasm smartcontract
    ///
    /// # Errors
    ///
    /// - if unable to construct wasm module or instance of wasm module
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute(
        &mut self,
        wsv: &'wrld mut WorldStateView,
        authority: AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<()> {
        let span = wasm_log_span!("Smart contract execution", %authority);
        let state = state::SmartContract {
            common: state::Common::new(wsv, authority, self.config, span),
            limits_validator: None,
        };

        self.execute_smart_contract_with_state(bytes, state)
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
        wsv: &'wrld mut WorldStateView,
        authority: AccountId,
        bytes: impl AsRef<[u8]>,
        max_instruction_count: u64,
    ) -> Result<()> {
        let span = wasm_log_span!("Smart contract validation", %authority);
        let state = state::SmartContract {
            common: state::Common::new(wsv, authority, self.config, span),
            limits_validator: Some(LimitsValidator::new(max_instruction_count)),
        };

        self.execute_smart_contract_with_state(bytes, state)
    }

    fn execute_smart_contract_with_state(
        &mut self,
        bytes: impl AsRef<[u8]>,
        state: state::SmartContract<'wrld>,
    ) -> Result<()> {
        let mut store = self.create_store(state);
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        Self::execute_main_with_store(&smart_contract, &mut store)
    }
}

impl<'wrld> import::ExecuteOperations<state::SmartContract<'wrld>>
    for Runtime<state::SmartContract<'wrld>>
{
    #[codec::wrap]
    fn execute_query(
        query: QueryBox,
        state: &state::SmartContract<'wrld>,
    ) -> Result<Value, ValidationFail> {
        Self::default_execute_query(query, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut state::SmartContract<'wrld>,
    ) -> Result<(), ValidationFail> {
        if let Some(limits_validator) = state.limits_validator.as_mut() {
            limits_validator.check_instruction_limits()?;
        }

        Self::default_execute_instruction(instruction, state)
    }
}

impl<'wrld> Runtime<state::Trigger<'wrld>> {
    /// Executes the given wasm trigger module
    ///
    /// # Errors
    ///
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute_trigger_module(
        &mut self,
        wsv: &'wrld mut WorldStateView,
        id: &TriggerId,
        authority: AccountId,
        module: &wasmtime::Module,
        event: Event,
    ) -> Result<()> {
        let span = wasm_log_span!("Trigger execution", %id, %authority);
        let state = state::Trigger {
            common: state::Common::new(wsv, authority, self.config, span),
            triggering_event: event,
        };

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        Self::execute_main_with_store(&instance, &mut store)
    }

    #[codec::wrap]
    fn get_triggering_event(state: &state::Trigger) -> Event {
        state.triggering_event.clone()
    }
}

impl<'wrld> import::ExecuteOperations<state::Trigger<'wrld>> for Runtime<state::Trigger<'wrld>> {
    #[codec::wrap]
    fn execute_query(
        query: QueryBox,
        state: &state::Trigger<'wrld>,
    ) -> Result<Value, ValidationFail> {
        Self::default_execute_query(query, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut state::Trigger<'wrld>,
    ) -> Result<(), ValidationFail> {
        Self::default_execute_instruction(instruction, state)
    }
}

/// Marker trait to auto-implement [`import::ExecuteOperations`] for a concrete
/// *Validator* [`Runtime`].
///
/// *Mut* means that [`WorldStateView`] will be mutated.
trait ExecuteOperationsAsValidatorMut<S> {}

impl<R, S> import::ExecuteOperations<S> for R
where
    R: ExecuteOperationsAsValidatorMut<S>,
    S: state::Wsv + state::WsvMut + state::Authority,
{
    #[codec::wrap]
    fn execute_query(query: QueryBox, state: &S) -> Result<Value, ValidationFail> {
        debug!(%query, "Executing as validator");

        query
            .execute(state.wsv())
            .map(|lazy_value| match lazy_value {
                LazyValue::Value(value) => value,
                LazyValue::Iter(iter) => Value::Vec(iter.collect()),
            })
            .map_err(Into::into)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut S,
    ) -> Result<(), ValidationFail> {
        debug!(%instruction, "Executing as validator");

        instruction
            .execute(&state.authority().clone(), state.wsv_mut())
            .map_err(Into::into)
    }
}

/// Marker trait to auto-implement [`import::SetPermissionTokenSchema`] for a concrete [`Runtime`].
///
/// Useful because in *Validator* exist more entrypoints than just `migrate()` which is the
/// only entrypoint allowed to execute operations on permission tokens.
trait FakeSetPermissionTokenSchema<S> {
    /// Entrypoint function name for panic message
    const ENTRYPOINT_FN_NAME: &'static str;
}

impl<R, S> import::SetPermissionTokenSchema<S> for R
where
    R: FakeSetPermissionTokenSchema<S>,
{
    #[codec::wrap]
    fn set_permission_token_schema(_schema: PermissionTokenSchema, _state: &mut S) {
        panic!(
            "Validator `{}()` entrypoint should not set permission token schema",
            Self::ENTRYPOINT_FN_NAME
        )
    }
}

impl<'wrld> Runtime<state::validator::ValidateTransaction<'wrld>> {
    /// Execute `validate_transaction()` entrypoint of the given module of runtime validator
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`validator::Result`]
    pub fn execute_validator_validate_transaction(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &<Account as Identifiable>::Id,
        module: &wasmtime::Module,
        transaction: VersionedSignedTransaction,
    ) -> Result<validator::Result> {
        let span = wasm_log_span!("Running `validate_transaction()`");

        self.execute_validator_validate_internal(
            module,
            state::validator::ValidateTransaction {
                common: state::Common::new(wsv, authority.clone(), self.config, span),
                to_validate: transaction,
            },
            export::VALIDATOR_VALIDATE_TRANSACTION_FN_NAME,
        )
    }
}

impl<'wrld> ExecuteOperationsAsValidatorMut<state::validator::ValidateTransaction<'wrld>>
    for Runtime<state::validator::ValidateTransaction<'wrld>>
{
}

impl<'wrld> import::GetOperationsToValidate<state::validator::ValidateTransaction<'wrld>>
    for Runtime<state::validator::ValidateTransaction<'wrld>>
{
    #[codec::wrap]
    fn get_transaction_to_validate(
        state: &state::validator::ValidateTransaction<'wrld>,
    ) -> VersionedSignedTransaction {
        state.to_validate.clone()
    }

    #[codec::wrap]
    fn get_instruction_to_validate(
        _state: &state::validator::ValidateTransaction<'wrld>,
    ) -> InstructionBox {
        panic!("Validator `validate_transaction()` entrypoint should not query instruction to validate")
    }

    #[codec::wrap]
    fn get_query_to_validate(_state: &state::validator::ValidateTransaction<'wrld>) -> QueryBox {
        panic!("Validator `validate_transaction()` entrypoint should not query query to validate")
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::validator::ValidateTransaction<'wrld>>
    for Runtime<state::validator::ValidateTransaction<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_transaction";
}

impl<'wrld> Runtime<state::validator::ValidateInstruction<'wrld>> {
    /// Execute `validate_instruction()` entrypoint of the given module of runtime validator
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`validator::Result`]
    pub fn execute_validator_validate_instruction(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &<Account as Identifiable>::Id,
        module: &wasmtime::Module,
        instruction: InstructionBox,
    ) -> Result<validator::Result> {
        let span = wasm_log_span!("Running `validate_instruction()`");

        self.execute_validator_validate_internal(
            module,
            state::validator::ValidateInstruction {
                common: state::Common::new(wsv, authority.clone(), self.config, span),
                to_validate: instruction,
            },
            export::VALIDATOR_VALIDATE_INSTRUCTION_FN_NAME,
        )
    }
}

impl<'wrld> ExecuteOperationsAsValidatorMut<state::validator::ValidateInstruction<'wrld>>
    for Runtime<state::validator::ValidateInstruction<'wrld>>
{
}

impl<'wrld> import::GetOperationsToValidate<state::validator::ValidateInstruction<'wrld>>
    for Runtime<state::validator::ValidateInstruction<'wrld>>
{
    #[codec::wrap]
    fn get_transaction_to_validate(
        _state: &state::validator::ValidateInstruction<'wrld>,
    ) -> VersionedSignedTransaction {
        panic!("Validator `validate_instruction()` entrypoint should not query transaction to validate")
    }

    #[codec::wrap]
    fn get_instruction_to_validate(
        state: &state::validator::ValidateInstruction<'wrld>,
    ) -> InstructionBox {
        state.to_validate.clone()
    }

    #[codec::wrap]
    fn get_query_to_validate(_state: &state::validator::ValidateInstruction<'wrld>) -> QueryBox {
        panic!("Validator `validate_instruction()` entrypoint should not query query to validate")
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::validator::ValidateInstruction<'wrld>>
    for Runtime<state::validator::ValidateInstruction<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_instruction";
}

impl<'wrld> Runtime<state::validator::ValidateQuery<'wrld>> {
    /// Execute `validate_query()` entrypoint of the given module of runtime validator
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`validator::Result`]
    pub fn execute_validator_validate_query(
        &self,
        wsv: &'wrld WorldStateView,
        authority: &<Account as Identifiable>::Id,
        module: &wasmtime::Module,
        query: QueryBox,
    ) -> Result<validator::Result> {
        let span = wasm_log_span!("Running `validate_query()`");

        self.execute_validator_validate_internal(
            module,
            state::validator::ValidateQuery {
                wsv,
                authority: authority.clone(),
                store_limits: state::store_limits_from_config(&self.config),
                log_span: span,
                query,
            },
            export::VALIDATOR_VALIDATE_QUERY_FN_NAME,
        )
    }
}

impl<'wrld> import::ExecuteOperations<state::validator::ValidateQuery<'wrld>>
    for Runtime<state::validator::ValidateQuery<'wrld>>
{
    #[codec::wrap]
    fn execute_query(
        query: QueryBox,
        state: &state::validator::ValidateQuery<'wrld>,
    ) -> Result<Value, ValidationFail> {
        debug!(%query, "Executing as validator");

        query
            .execute(state.wsv())
            .map(|lazy_value| match lazy_value {
                LazyValue::Value(value) => value,
                LazyValue::Iter(iter) => Value::Vec(iter.collect()),
            })
            .map_err(Into::into)
    }

    #[codec::wrap]
    fn execute_instruction(
        _instruction: InstructionBox,
        _state: &mut state::validator::ValidateQuery<'wrld>,
    ) -> Result<(), ValidationFail> {
        panic!("Validator `validate_query()` entrypoint should not execute instructions")
    }
}

impl<'wrld> import::GetOperationsToValidate<state::validator::ValidateQuery<'wrld>>
    for Runtime<state::validator::ValidateQuery<'wrld>>
{
    #[codec::wrap]
    fn get_transaction_to_validate(
        _state: &state::validator::ValidateQuery<'wrld>,
    ) -> VersionedSignedTransaction {
        panic!("Validator `validate_query()` entrypoint should not query transaction to validate")
    }

    #[codec::wrap]
    fn get_instruction_to_validate(
        _state: &state::validator::ValidateQuery<'wrld>,
    ) -> InstructionBox {
        panic!("Validator `validate_query()` entrypoint should not query instruction to validate")
    }

    #[codec::wrap]
    fn get_query_to_validate(state: &state::validator::ValidateQuery<'wrld>) -> QueryBox {
        state.query.clone()
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::validator::ValidateQuery<'wrld>>
    for Runtime<state::validator::ValidateQuery<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_query";
}

impl<'wrld> Runtime<state::validator::Migrate<'wrld>> {
    /// Execute `migrate()` entrypoint of *Validator*
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if failed to get export function for `migrate()`
    /// - if failed to call export function
    /// - if failed to decode [`MigrationResult`]
    pub fn execute_validator_migration(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &<Account as Identifiable>::Id,
        module: &wasmtime::Module,
    ) -> Result<MigrationResult> {
        let span = wasm_log_span!("Running migration");
        let state = state::validator::Migrate(state::Common::new(
            wsv,
            authority.clone(),
            self.config,
            span,
        ));

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let migrate_fn =
            Self::get_typed_func(&instance, &mut store, export::VALIDATOR_MIGRATE_FN_NAME)?;

        let offset = migrate_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let memory =
            Self::get_memory(&mut (&instance, &mut store)).expect("Checked at instantiation step");
        let dealloc_fn = Self::get_typed_func(&instance, &mut store, export::WASM_DEALLOC_FN)
            .expect("Checked at instantiation step");
        codec::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
            .map_err(|err| Error::Decode(err.into()))
    }
}

impl<'wrld> ExecuteOperationsAsValidatorMut<state::validator::Migrate<'wrld>>
    for Runtime<state::validator::Migrate<'wrld>>
{
}

/// Fake implementation of [`import::GetOperationsToValidate`].
///
/// This is needed because `migrate()` entrypoint exists in the same binary as
/// `validate_*()` entrypoints.
///
/// # Panics
///
/// Panics with error message if called, because it should never be called from
/// `migrate()` entrypoint.
impl<'wrld> import::GetOperationsToValidate<state::validator::Migrate<'wrld>>
    for Runtime<state::validator::Migrate<'wrld>>
{
    #[codec::wrap]
    fn get_transaction_to_validate(
        _state: &state::validator::Migrate<'wrld>,
    ) -> VersionedSignedTransaction {
        panic!("Validator `migrate()` entrypoint should not query transaction to validate")
    }

    #[codec::wrap]
    fn get_instruction_to_validate(_state: &state::validator::Migrate<'wrld>) -> InstructionBox {
        panic!("Validator `migrate()` entrypoint should not query instruction to validate")
    }

    #[codec::wrap]
    fn get_query_to_validate(_state: &state::validator::Migrate<'wrld>) -> QueryBox {
        panic!("Validator `migrate()` entrypoint should not query query to validate")
    }
}

impl<'wrld> import::SetPermissionTokenSchema<state::validator::Migrate<'wrld>>
    for Runtime<state::validator::Migrate<'wrld>>
{
    #[codec::wrap]
    fn set_permission_token_schema(
        schema: PermissionTokenSchema,
        state: &mut state::validator::Migrate<'wrld>,
    ) {
        debug!(%schema, "Setting permission token schema");

        state.wsv_mut().set_permission_token_schema(schema)
    }
}

/// `Runtime` builder
#[derive(Default)]
pub struct RuntimeBuilder<S> {
    engine: Option<Engine>,
    config: Option<Configuration>,
    linker: Option<Linker<S>>,
}

impl<S> RuntimeBuilder<S> {
    /// Creates a new [`RuntimeBuilder`]
    pub fn new() -> Self {
        Self {
            engine: None,
            config: None,
            linker: None,
        }
    }

    /// Sets the [`Engine`] to be used by the [`Runtime`]
    #[must_use]
    #[inline]
    pub fn with_engine(mut self, engine: Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Sets the [`Configuration`] to be used by the [`Runtime`]
    #[must_use]
    #[inline]
    pub fn with_configuration(mut self, config: Configuration) -> Self {
        self.config = Some(config);
        self
    }

    /// Finalizes the builder and creates a [`Runtime`].
    ///
    /// This is private and is used by `build()` methods from more specialized builders.
    fn finalize(
        self,
        create_linker: impl FnOnce(&Engine) -> Result<Linker<S>>,
    ) -> Result<Runtime<S>> {
        let engine = self.engine.unwrap_or_else(create_engine);
        let linker = self.linker.map_or_else(|| create_linker(&engine), Ok)?;
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

macro_rules! create_imports {
    (
        $linker:ident,
        $(import:: $name:ident => $fn_path:path),* $(,)?
    ) => {
        $linker.func_wrap(
                import::MODULE_NAME,
                import::LOG_FN_NAME,
                Runtime::log,
            )
            .and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::DBG_FN_NAME,
                    Runtime::dbg,
                )
            })
            $(.and_then(|l| {
                l.func_wrap(
                    import::MODULE_NAME,
                    import::$name,
                    $fn_path,
                )
            }))*
            .map_err(|err| Error::Initialization(eyre!(Box::new(err))))
    };
}

impl<'wrld> RuntimeBuilder<state::SmartContract<'wrld>> {
    /// Builds the [`Runtime`] for *Smart Contract* execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::SmartContract<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::SmartContract<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::SmartContract<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::<state::SmartContract<'_>>::get_authority,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::Trigger<'wrld>> {
    /// Builds the [`Runtime`] for *Trigger* execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::Trigger<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::Trigger<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::Trigger<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::<state::Trigger<'_>>::get_authority,
                import::GET_TRIGGERING_EVENT_FN_NAME => Runtime::get_triggering_event,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::validator::ValidateTransaction<'wrld>> {
    /// Builds the [`Runtime`] for *Validator* `validate_transaction()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::validator::ValidateTransaction<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::validator::ValidateTransaction<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::validator::ValidateTransaction<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::<state::validator::ValidateTransaction<'_>>::get_authority,
                import::GET_TRANSACTION_TO_VALIDATE_FN_NAME => Runtime::get_transaction_to_validate,
                import::GET_INSTRUCTION_TO_VALIDATE_FN_NAME => Runtime::get_instruction_to_validate,
                import::GET_QUERY_TO_VALIDATE_FN_NAME => Runtime::get_query_to_validate,
                import::SET_PERMISSION_TOKEN_SCHEMA_FN_NAME => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::validator::ValidateInstruction<'wrld>> {
    /// Builds the [`Runtime`] for *Validator* `validate_instruction()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::validator::ValidateInstruction<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::validator::ValidateInstruction<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::validator::ValidateInstruction<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::<state::validator::ValidateInstruction<'_>>::get_authority,
                import::GET_TRANSACTION_TO_VALIDATE_FN_NAME => Runtime::get_transaction_to_validate,
                import::GET_INSTRUCTION_TO_VALIDATE_FN_NAME => Runtime::get_instruction_to_validate,
                import::GET_QUERY_TO_VALIDATE_FN_NAME => Runtime::get_query_to_validate,
                import::SET_PERMISSION_TOKEN_SCHEMA_FN_NAME => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::validator::ValidateQuery<'wrld>> {
    /// Builds the [`Runtime`] for *Validator* `validate_query()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::validator::ValidateQuery<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::validator::ValidateQuery<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::validator::ValidateQuery<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::<state::validator::ValidateQuery<'_>>::get_authority,
                import::GET_TRANSACTION_TO_VALIDATE_FN_NAME => Runtime::get_transaction_to_validate,
                import::GET_INSTRUCTION_TO_VALIDATE_FN_NAME => Runtime::get_instruction_to_validate,
                import::GET_QUERY_TO_VALIDATE_FN_NAME => Runtime::get_query_to_validate,
                import::SET_PERMISSION_TOKEN_SCHEMA_FN_NAME => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::validator::Migrate<'wrld>> {
    /// Builds the [`Runtime`] to execute `permission_tokens()` entrypoint of *Validator*
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::validator::Migrate<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                import::EXECUTE_ISI_FN_NAME => Runtime::<state::validator::Migrate<'_>>::execute_instruction,
                import::EXECUTE_QUERY_FN_NAME => Runtime::<state::validator::Migrate<'_>>::execute_query,
                import::GET_AUTHORITY_FN_NAME => Runtime::get_authority,
                import::GET_TRANSACTION_TO_VALIDATE_FN_NAME => Runtime::get_transaction_to_validate,
                import::GET_INSTRUCTION_TO_VALIDATE_FN_NAME => Runtime::get_instruction_to_validate,
                import::GET_QUERY_TO_VALIDATE_FN_NAME => Runtime::get_query_to_validate,
                import::SET_PERMISSION_TOKEN_SCHEMA_FN_NAME => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

/// Helper trait to make a function generic over `get_export()` fn from `wasmtime` crate
trait GetExport {
    fn get_export(&mut self, name: &str) -> Option<wasmtime::Extern>;
}

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

    fn world_with_test_account(authority: &AccountId) -> World {
        let domain_id = authority.domain_id.clone();
        let (public_key, _) = KeyPair::generate().unwrap().into();
        let account = Account::new(authority.clone(), [public_key]).build(authority);
        let mut domain = Domain::new(domain_id).build(authority);
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
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_authority, []));
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
        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        runtime
            .execute(&mut wsv, authority, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn execute_query_exported() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(authority.clone())));

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

        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        runtime
            .execute(&mut wsv, authority, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn instruction_limit_reached() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();

        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_authority, []));
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

        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        let res = runtime.validate(&mut wsv, authority, wat, 1);

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
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = RegisterBox::new(Account::new(new_authority, []));
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

        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        let res = runtime.validate(&mut wsv, authority, wat, 1);

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
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(authority.clone())));

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

        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        let res = runtime.validate(&mut wsv, authority, wat, 1);

        if let Error::ExportFnCall(ExportFnCallError::HostExecution(report)) =
            res.expect_err("Execution should fail")
        {
            assert!(report.to_string().starts_with("All operations are denied"));
        }

        Ok(())
    }

    #[test]
    fn trigger_related_func_is_not_linked_for_smart_contract() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(authority.clone())));

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{get_triggering_event_fn_name}"
                    (func $exec_fn (param) (result i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param)
                    (call $exec_fn)

                    ;; No use of return values
                    drop))
            "#,
            main_fn_name = export::WASM_MAIN_FN_NAME,
            get_triggering_event_fn_name = import::GET_TRIGGERING_EVENT_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
        );

        let mut runtime = RuntimeBuilder::<state::SmartContract>::new().build()?;
        let err = runtime
            .execute(&mut wsv, authority, wat)
            .expect_err("Execution should fail");

        assert!(matches!(
            err,
            Error::Instantiation(InstantiationError::Linker(_))
        ));

        Ok(())
    }
}
