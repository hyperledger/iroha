//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction

use error::*;
use import::traits::{
    ExecuteOperations as _, GetExecutorPayloads as _, SetPermissionTokenSchema as _,
};
use iroha_config::{
    base::proxy::Builder,
    wasm::{Configuration, ConfigurationProxy},
};
use iroha_data_model::{
    account::AccountId,
    executor::{self, MigrationResult},
    isi::InstructionBox,
    permission::PermissionTokenSchema,
    prelude::*,
    query::{QueryBox, QueryId, QueryRequest, QueryWithParameters},
    smart_contract::{
        payloads::{self, Validate},
        SmartContractQueryRequest,
    },
    BatchedResponse, Level as LogLevel, ValidationFail,
};
use iroha_logger::debug;
// NOTE: Using error_span so that span info is logged on every event
use iroha_logger::{error_span as wasm_log_span, prelude::tracing::Span};
use iroha_wasm_codec::{self as codec, WasmUsize};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc,
};

use crate::{
    query::store::LiveQueryStoreHandle,
    smartcontracts::{wasm::state::ValidateQueryOperation, Execute},
    wsv::WorldStateView,
    ValidQuery as _,
};

/// Name of the exported memory
const WASM_MEMORY: &str = "memory";
const WASM_MODULE: &str = "iroha";

mod export {
    pub const EXECUTE_ISI: &str = "execute_instruction";
    pub const EXECUTE_QUERY: &str = "execute_query";
    pub const GET_SMART_CONTRACT_PAYLOAD: &str = "get_smart_contract_payload";
    pub const GET_TRIGGER_PAYLOAD: &str = "get_trigger_payload";
    pub const GET_MIGRATE_PAYLOAD: &str = "get_migrate_payload";
    pub const GET_VALIDATE_TRANSACTION_PAYLOAD: &str = "get_validate_transaction_payload";
    pub const GET_VALIDATE_INSTRUCTION_PAYLOAD: &str = "get_validate_instruction_payload";
    pub const GET_VALIDATE_QUERY_PAYLOAD: &str = "get_validate_query_payload";
    pub const SET_PERMISSION_TOKEN_SCHEMA: &str = "set_permission_token_schema";

    pub const DBG: &str = "dbg";
    pub const LOG: &str = "log";
}

mod import {
    pub const SMART_CONTRACT_MAIN: &str = "_iroha_smart_contract_main";
    pub const SMART_CONTRACT_ALLOC: &str = "_iroha_smart_contract_alloc";
    pub const SMART_CONTRACT_DEALLOC: &str = "_iroha_smart_contract_dealloc";

    pub const TRIGGER_MAIN: &str = "_iroha_trigger_main";

    pub const EXECUTOR_VALIDATE_TRANSACTION: &str = "_iroha_executor_validate_transaction";
    pub const EXECUTOR_VALIDATE_INSTRUCTION: &str = "_iroha_executor_validate_instruction";
    pub const EXECUTOR_VALIDATE_QUERY: &str = "_iroha_executor_validate_query";
    pub const EXECUTOR_MIGRATE: &str = "_iroha_executor_migrate";

    pub mod traits {
        //! Traits which some [Runtime]s should implement to import functions from Iroha to WASM

        use iroha_data_model::{query::QueryBox, smart_contract::payloads::Validate};

        use super::super::*;

        pub trait ExecuteOperations<S> {
            /// Execute `query` on host
            #[codec::wrap_trait_fn]
            fn execute_query(
                query_request: SmartContractQueryRequest,
                state: &mut S,
            ) -> Result<BatchedResponse<Value>, ValidationFail>;

            /// Execute `instruction` on host
            #[codec::wrap_trait_fn]
            fn execute_instruction(
                instruction: InstructionBox,
                state: &mut S,
            ) -> Result<(), ValidationFail>;
        }

        pub trait GetExecutorPayloads<S> {
            #[codec::wrap_trait_fn]
            fn get_migrate_payload(state: &S) -> payloads::Migrate;

            #[codec::wrap_trait_fn]
            fn get_validate_transaction_payload(state: &S) -> Validate<SignedTransaction>;

            #[codec::wrap_trait_fn]
            fn get_validate_instruction_payload(state: &S) -> Validate<InstructionBox>;

            #[codec::wrap_trait_fn]
            fn get_validate_query_payload(state: &S) -> Validate<QueryBox>;
        }

        pub trait SetPermissionTokenSchema<S> {
            #[codec::wrap_trait_fn]
            fn set_permission_token_schema(schema: PermissionTokenSchema, state: &mut S);
        }
    }
}

pub mod error {
    //! Error types for [`wasm`](super) and their impls

    use wasmtime::{Error as WasmtimeError, Trap};

    /// `WebAssembly` execution error type
    #[derive(Debug, thiserror::Error, displaydoc::Display)]
    #[ignore_extra_doc_attributes]
    pub enum Error {
        /// Runtime initialization failure
        Initialization(#[source] WasmtimeError),
        /// Runtime finalization failure.
        ///
        /// Currently only [`crate::query::store::Error`] might fail in this case.
        /// [`From`] is not implemented to force users to explicitly wrap this error.
        Finalization(#[source] crate::query::store::Error),
        /// Failed to load module
        ModuleLoading(#[source] WasmtimeError),
        /// Module could not be instantiated
        Instantiation(#[from] InstantiationError),
        /// Export error
        Export(#[from] ExportError),
        /// Call to the function exported from module failed
        ExportFnCall(#[from] ExportFnCallError),
        /// Failed to decode object from bytes with length prefix
        Decode(#[source] WasmtimeError),
    }

    /// Instantiation error
    #[derive(Debug, thiserror::Error, displaydoc::Display)]
    #[ignore_extra_doc_attributes]
    pub enum InstantiationError {
        /// Linker failed to instantiate module
        ///
        /// [`wasmtime::Linker::instantiate`] failed
        Linker(#[from] WasmtimeError),
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
        HostExecution(#[source] wasmtime::Error),
        /// Execution limits exceeded
        ExecutionLimitsExceeded(#[source] wasmtime::Error),
        /// Other kind of trap
        Other(#[source] wasmtime::Error),
    }

    impl From<wasmtime::Error> for ExportFnCallError {
        fn from(err: wasmtime::Error) -> Self {
            match err.downcast_ref() {
                Some(&trap) => match trap {
                    Trap::StackOverflow
                    | Trap::MemoryOutOfBounds
                    | Trap::TableOutOfBounds
                    | Trap::IndirectCallToNull
                    | Trap::OutOfFuel
                    | Trap::Interrupt => Self::ExecutionLimitsExceeded(err),
                    _ => Self::Other(err),
                },
                None => Self::HostExecution(err),
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
    Module::new(engine, bytes).map_err(Error::ModuleLoading)
}

/// Create [`Engine`] with a predefined configuration.
///
/// # Panics
///
/// Panics if something is wrong with the configuration.
/// Configuration is hardcoded and tested, so this function should never panic.
pub fn create_engine() -> Engine {
    create_config()
        .and_then(|config| Engine::new(&config).map_err(Error::Initialization))
        .expect("Failed to create WASM engine with a predefined configuration. This is a bug")
}

fn create_config() -> Result<Config> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .cache_config_load_default()
        .map_err(Error::Initialization)?;
    #[cfg(feature = "profiling")]
    {
        config.profiler(wasmtime::ProfilingStrategy::PerfMap);
    }
    Ok(config)
}

/// Remove all executed queries from the query storage.
fn forget_all_executed_queries(
    query_handle: &LiveQueryStoreHandle,
    executed_queries: impl IntoIterator<Item = QueryId>,
) -> Result<()> {
    for query_id in executed_queries {
        let _ = query_handle
            .drop_query(query_id)
            .map_err(Error::Finalization)?;
    }
    Ok(())
}

/// Limits checker for smartcontracts.
#[derive(Copy, Clone)]
struct LimitsExecutor {
    /// Number of instructions in the smartcontract
    instruction_count: u64,
    /// Max allowed number of instructions in the smartcontract
    max_instruction_count: u64,
}

impl LimitsExecutor {
    /// Create new [`LimitsExecutor`]
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

    use derive_more::Constructor;
    use indexmap::IndexSet;

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

    /// State for most common operations.
    /// Generic over borrowed [`WorldStateView`] type and specific executable state.
    pub struct CommonState<W, S> {
        pub(super) authority: AccountId,
        pub(super) store_limits: StoreLimits,
        /// Span inside of which all logs are recorded for this smart contract
        pub(super) log_span: Span,
        pub(super) executed_queries: IndexSet<QueryId>,
        /// Borrowed [`WorldStateView`] kind
        pub(super) wsv: W,
        /// Concrete state for specific executable
        pub(super) specific_state: S,
    }

    impl<W, S> CommonState<W, S> {
        /// Create new [`OrdinaryState`]
        pub fn new(
            authority: AccountId,
            config: Configuration,
            log_span: Span,
            wsv: W,
            specific_state: S,
        ) -> Self {
            Self {
                authority,
                store_limits: store_limits_from_config(&config),
                log_span,
                executed_queries: IndexSet::new(),
                wsv,
                specific_state,
            }
        }

        /// Take executed queries leaving an empty set
        pub fn take_executed_queries(&mut self) -> IndexSet<QueryId> {
            std::mem::take(&mut self.executed_queries)
        }
    }

    /// Trait to validate queries and instructions before execution.
    pub trait ValidateQueryOperation {
        /// Validate `query`.
        ///
        /// # Errors
        ///
        /// Returns error if query validation failed.
        fn validate_query(
            &self,
            authority: &AccountId,
            query: QueryBox,
        ) -> Result<(), ValidationFail>;
    }

    pub mod wsv {
        //! Strongly typed kinds of borrowed [`WorldStateView`]

        use super::*;

        /// Const reference to [`WorldStateView`].
        pub struct WithConst<'wrld>(pub(in super::super) &'wrld WorldStateView);

        /// Mutable reference to [`WorldStateView`].
        pub struct WithMut<'wrld>(pub(in super::super) &'wrld mut WorldStateView);

        /// Trait to get immutable [`WorldStateView`]
        ///
        /// Exists to write generic code for [`WithWsv`] and [`WithMutWsv`.
        pub trait Wsv {
            /// Get immutable [`WorldStateView`]
            fn wsv(&self) -> &WorldStateView;
        }

        impl Wsv for WithConst<'_> {
            fn wsv(&self) -> &WorldStateView {
                self.0
            }
        }

        impl Wsv for WithMut<'_> {
            fn wsv(&self) -> &WorldStateView {
                self.0
            }
        }
    }

    pub mod specific {
        //! States for concrete executable entrypoints.

        use super::*;

        /// Smart Contract execution state
        #[derive(Copy, Clone)]
        pub struct SmartContract {
            pub(in super::super) limits_executor: Option<LimitsExecutor>,
        }

        impl SmartContract {
            /// Create new [`SmartContract`]
            pub(in super::super) fn new(limits_executor: Option<LimitsExecutor>) -> Self {
                Self { limits_executor }
            }
        }

        /// Trigger execution state
        #[derive(Constructor)]
        pub struct Trigger {
            /// Event which activated this trigger
            pub(in super::super) triggering_event: Event,
        }

        pub mod executor {
            //! States related to *Executor* execution.

            use super::*;

            /// Struct to encapsulate common state kinds for `validate_*` entrypoints
            #[derive(Constructor)]
            pub struct Validate<T> {
                pub(in super::super::super::super) to_validate: T,
            }

            /// State kind for executing `validate_transaction()` entrypoint of executor
            pub type ValidateTransaction = Validate<SignedTransaction>;

            /// State kind for executing `validate_query()` entrypoint of executor
            pub type ValidateQuery = Validate<QueryBox>;

            /// State kind for executing `validate_instruction()` entrypoint of executor
            pub type ValidateInstruction = Validate<InstructionBox>;

            /// State kind for executing `migrate()` entrypoint of executor
            #[derive(Copy, Clone)]
            pub struct Migrate;
        }
    }

    /// State for smart contract execution
    pub type SmartContract<'wrld> = CommonState<wsv::WithMut<'wrld>, specific::SmartContract>;

    /// State for trigger execution
    pub type Trigger<'wrld> = CommonState<wsv::WithMut<'wrld>, specific::Trigger>;

    impl ValidateQueryOperation for SmartContract<'_> {
        fn validate_query(
            &self,
            authority: &AccountId,
            query: QueryBox,
        ) -> Result<(), ValidationFail> {
            let wsv: &WorldStateView = self.wsv.0;
            wsv.executor().validate_query(wsv, authority, query)
        }
    }

    impl ValidateQueryOperation for Trigger<'_> {
        fn validate_query(
            &self,
            authority: &AccountId,
            query: QueryBox,
        ) -> Result<(), ValidationFail> {
            let wsv: &WorldStateView = self.wsv.0;
            wsv.executor().validate_query(wsv, authority, query)
        }
    }

    pub mod executor {
        //! States for different executor entrypoints

        use super::*;

        /// State for executing `validate_transaction()` entrypoint
        pub type ValidateTransaction<'wrld> =
            CommonState<wsv::WithMut<'wrld>, specific::executor::ValidateTransaction>;

        /// State for executing `validate_query()` entrypoint
        pub type ValidateQuery<'wrld> =
            CommonState<wsv::WithConst<'wrld>, specific::executor::ValidateQuery>;

        /// State for executing `validate_instruction()` entrypoint
        pub type ValidateInstruction<'wrld> =
            CommonState<wsv::WithMut<'wrld>, specific::executor::ValidateInstruction>;

        /// State for executing `migrate()` entrypoint
        pub type Migrate<'wrld> = CommonState<wsv::WithMut<'wrld>, specific::executor::Migrate>;

        macro_rules! impl_blank_validate_operations {
            ($($t:ident),+ $(,)?) => { $(
                impl ValidateQueryOperation for $t <'_> {
                    fn validate_query(
                        &self,
                        _authority: &AccountId,
                        _query: QueryBox,
                    ) -> Result<(), ValidationFail> {
                        Ok(())
                    }
                }
            )+ };
        }

        impl_blank_validate_operations!(
            ValidateTransaction,
            ValidateInstruction,
            ValidateQuery,
            Migrate,
        );
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
            .get_export(WASM_MEMORY)
            .ok_or_else(|| ExportError::not_found(WASM_MEMORY))?
            .into_memory()
            .ok_or_else(|| ExportError::not_a_memory(WASM_MEMORY))
    }

    fn get_alloc_fn(
        caller: &mut Caller<S>,
    ) -> Result<TypedFunc<WasmUsize, WasmUsize>, ExportError> {
        caller
            .get_export(import::SMART_CONTRACT_ALLOC)
            .ok_or_else(|| ExportError::not_found(import::SMART_CONTRACT_ALLOC))?
            .into_func()
            .ok_or_else(|| ExportError::not_a_function(import::SMART_CONTRACT_ALLOC))?
            .typed::<WasmUsize, WasmUsize>(caller)
            .map_err(|_error| {
                ExportError::wrong_signature::<WasmUsize, WasmUsize>(import::SMART_CONTRACT_ALLOC)
            })
    }

    fn get_typed_func<P: wasmtime::WasmParams, R: wasmtime::WasmResults>(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<S>,
        func_name: &'static str,
    ) -> Result<wasmtime::TypedFunc<P, R>, ExportError> {
        instance
            .get_func(&mut store, func_name)
            .ok_or_else(|| ExportError::not_found(func_name))?
            .typed::<P, R>(&mut store)
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
            .map_err(InstantiationError::Linker)?;

        Self::check_mandatory_exports(&instance, store)?;

        Ok(instance)
    }

    fn check_mandatory_exports(
        instance: &wasmtime::Instance,
        mut store: &mut wasmtime::Store<S>,
    ) -> Result<(), InstantiationError> {
        let _ = Self::get_memory(&mut (instance, &mut store))?;
        let _ = Self::get_typed_func::<WasmUsize, WasmUsize>(
            instance,
            store,
            import::SMART_CONTRACT_ALLOC,
        )?;
        let _ = Self::get_typed_func::<(WasmUsize, WasmUsize), ()>(
            instance,
            store,
            import::SMART_CONTRACT_DEALLOC,
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
    #[allow(clippy::needless_pass_by_value)]
    #[codec::wrap(state = "S")]
    fn dbg(msg: String) {
        println!("{msg}");
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}: not a valid log level")]
struct LogError(u8);

/// It's required by `#[codec::wrap]` to parse well
type WasmtimeError = wasmtime::Error;

impl<W, S> Runtime<state::CommonState<W, S>> {
    /// Log the given string at the given log level
    ///
    /// # Errors
    ///
    /// If log level or string decoding fails
    #[codec::wrap]
    pub fn log(
        (log_level, msg): (u8, String),
        state: &state::CommonState<W, S>,
    ) -> Result<(), WasmtimeError> {
        const TARGET: &str = "WASM";

        let _span = state.log_span.enter();
        match LogLevel::from_repr(log_level)
            .ok_or(LogError(log_level))
            .map_err(wasmtime::Error::from)?
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

    fn create_store(&self, state: state::CommonState<W, S>) -> Store<state::CommonState<W, S>> {
        let mut store = Store::new(&self.engine, state);

        store.limiter(|s| &mut s.store_limits);
        store
            .set_fuel(self.config.fuel_limit)
            .expect("Wasm Runtime config is malformed, this is a bug");

        store
    }
}

impl<W: state::wsv::Wsv, S> Runtime<state::CommonState<W, S>> {
    fn execute_executor_validate_internal(
        &self,
        module: &wasmtime::Module,
        state: state::CommonState<W, S>,
        validate_fn_name: &'static str,
    ) -> Result<executor::Result> {
        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let validate_fn = Self::get_typed_func(&instance, &mut store, validate_fn_name)?;

        // NOTE: This function takes ownership of the pointer
        let offset = validate_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let memory =
            Self::get_memory(&mut (&instance, &mut store)).expect("Checked at instantiation step");
        let dealloc_fn =
            Self::get_typed_func(&instance, &mut store, import::SMART_CONTRACT_DEALLOC)
                .expect("Checked at instantiation step");
        let validation_res =
            codec::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
                .map_err(Error::Decode)?;

        let mut state = store.into_data();
        let executed_queries = state.take_executed_queries();
        forget_all_executed_queries(state.wsv.wsv().query_handle(), executed_queries)?;
        Ok(validation_res)
    }
}

impl<W, S> Runtime<state::CommonState<W, S>>
where
    W: state::wsv::Wsv,
    state::CommonState<W, S>: state::ValidateQueryOperation,
{
    fn default_execute_query(
        query_request: SmartContractQueryRequest,
        state: &mut state::CommonState<W, S>,
    ) -> Result<BatchedResponse<Value>, ValidationFail> {
        iroha_logger::debug!(%query_request, "Executing");

        match query_request.0 {
            QueryRequest::Query(QueryWithParameters {
                query,
                sorting,
                pagination,
                fetch_size,
            }) => {
                let batched = {
                    let wsv = &state.wsv.wsv();
                    state.validate_query(&state.authority, query.clone())?;
                    let output = query.execute(wsv)?;

                    wsv.query_handle()
                        .handle_query_output(output, &sorting, pagination, fetch_size)
                }?;
                match &batched {
                    BatchedResponse::V1(batched) => {
                        if let Some(query_id) = &batched.cursor.query_id {
                            state.executed_queries.insert(query_id.clone());
                        }
                    }
                }
                Ok(batched)
            }
            QueryRequest::Cursor(cursor) => {
                // In a normal situation we already have this `query_id` stored,
                // so that's a protection from malicious smart contract
                if let Some(query_id) = &cursor.query_id {
                    state.executed_queries.insert(query_id.clone());
                }
                state.wsv.wsv().query_handle().handle_query_cursor(cursor)
            }
        }
        .map_err(Into::into)
    }
}

impl<'wrld, S> Runtime<state::CommonState<state::wsv::WithMut<'wrld>, S>> {
    fn default_execute_instruction(
        instruction: InstructionBox,
        state: &mut state::CommonState<state::wsv::WithMut<'wrld>, S>,
    ) -> Result<(), ValidationFail> {
        debug!(%instruction, "Executing");

        // TODO: Validation should be skipped when executing smart contract.
        // There should be two steps validation and execution. First smart contract
        // is validated and then it's executed. Here it's validating in both steps.
        // Add a flag indicating whether smart contract is being validated or executed
        let authority = state.authority.clone();
        let wsv: &mut WorldStateView = state.wsv.0;
        wsv.executor()
                .clone() // Cloning executor is a cheap operation
                .validate_instruction(wsv, &authority, instruction)
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
        let state = state::SmartContract::new(
            authority,
            self.config,
            span,
            state::wsv::WithMut(wsv),
            state::specific::SmartContract::new(None),
        );

        self.execute_smart_contract_with_state(bytes, state)
    }

    /// Validates that the given smartcontract is eligible for execution
    ///
    /// # Errors
    ///
    /// - if instructions failed to validate, but queries are permitted
    /// - if instruction limits are not obeyed
    /// - if execution of the smartcontract fails (check [`Self::execute`])
    pub fn validate(
        &mut self,
        wsv: &'wrld mut WorldStateView,
        authority: AccountId,
        bytes: impl AsRef<[u8]>,
        max_instruction_count: u64,
    ) -> Result<()> {
        let span = wasm_log_span!("Smart contract validation", %authority);
        let state = state::SmartContract::new(
            authority,
            self.config,
            span,
            state::wsv::WithMut(wsv),
            state::specific::SmartContract::new(Some(LimitsExecutor::new(max_instruction_count))),
        );

        self.execute_smart_contract_with_state(bytes, state)
    }

    fn execute_smart_contract_with_state(
        &mut self,
        bytes: impl AsRef<[u8]>,
        state: state::SmartContract<'wrld>,
    ) -> Result<()> {
        let mut store = self.create_store(state);
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        let main_fn =
            Self::get_typed_func(&smart_contract, &mut store, import::SMART_CONTRACT_MAIN)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;
        let mut state = store.into_data();
        let executed_queries = state.take_executed_queries();
        forget_all_executed_queries(state.wsv.0.query_handle(), executed_queries)
    }

    #[codec::wrap]
    fn get_smart_contract_payload(state: &state::SmartContract) -> payloads::SmartContract {
        payloads::SmartContract {
            owner: state.authority.clone(),
        }
    }
}

impl<'wrld> import::traits::ExecuteOperations<state::SmartContract<'wrld>>
    for Runtime<state::SmartContract<'wrld>>
{
    #[codec::wrap]
    fn execute_query(
        query_request: SmartContractQueryRequest,
        state: &mut state::SmartContract<'wrld>,
    ) -> Result<BatchedResponse<Value>, ValidationFail> {
        Self::default_execute_query(query_request, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut state::SmartContract<'wrld>,
    ) -> Result<(), ValidationFail> {
        if let Some(limits_executor) = state.specific_state.limits_executor.as_mut() {
            limits_executor.check_instruction_limits()?;
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
        let state = state::Trigger::new(
            authority,
            self.config,
            span,
            state::wsv::WithMut(wsv),
            state::specific::Trigger::new(event),
        );

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let main_fn = Self::get_typed_func(&instance, &mut store, import::TRIGGER_MAIN)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let mut state = store.into_data();
        let executed_queries = state.take_executed_queries();
        forget_all_executed_queries(state.wsv.0.query_handle(), executed_queries)
    }

    #[codec::wrap]
    fn get_trigger_payload(state: &state::Trigger) -> payloads::Trigger {
        payloads::Trigger {
            owner: state.authority.clone(),
            event: state.specific_state.triggering_event.clone(),
        }
    }
}

impl<'wrld> import::traits::ExecuteOperations<state::Trigger<'wrld>>
    for Runtime<state::Trigger<'wrld>>
{
    #[codec::wrap]
    fn execute_query(
        query_request: SmartContractQueryRequest,
        state: &mut state::Trigger<'wrld>,
    ) -> Result<BatchedResponse<Value>, ValidationFail> {
        Self::default_execute_query(query_request, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut state::Trigger<'wrld>,
    ) -> Result<(), ValidationFail> {
        Self::default_execute_instruction(instruction, state)
    }
}

/// Marker trait to auto-implement [`import_traits::ExecuteOperations`] for a concrete
/// *Executor* [`Runtime`].
///
/// *Mut* means that [`WorldStateView`] will be mutated.
trait ExecuteOperationsAsExecutorMut<S> {}

impl<'wrld, R, S>
    import::traits::ExecuteOperations<state::CommonState<state::wsv::WithMut<'wrld>, S>> for R
where
    R: ExecuteOperationsAsExecutorMut<state::CommonState<state::wsv::WithMut<'wrld>, S>>,
    state::CommonState<state::wsv::WithMut<'wrld>, S>: state::ValidateQueryOperation,
{
    #[codec::wrap]
    fn execute_query(
        query_request: SmartContractQueryRequest,
        state: &mut state::CommonState<state::wsv::WithMut<'wrld>, S>,
    ) -> Result<BatchedResponse<Value>, ValidationFail> {
        debug!(%query_request, "Executing as executor");

        Runtime::default_execute_query(query_request, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        instruction: InstructionBox,
        state: &mut state::CommonState<state::wsv::WithMut<'wrld>, S>,
    ) -> Result<(), ValidationFail> {
        debug!(%instruction, "Executing as executor");

        instruction
            .execute(&state.authority.clone(), state.wsv.0)
            .map_err(Into::into)
    }
}

/// Marker trait to auto-implement [`import_traits::SetPermissionTokenSchema`] for a concrete [`Runtime`].
///
/// Useful because *Executor* exposes more entrypoints than just `migrate()` which is the
/// only entrypoint allowed to execute operations on permission tokens.
trait FakeSetPermissionTokenSchema<S> {
    /// Entrypoint function name for panic message
    const ENTRYPOINT_FN_NAME: &'static str;
}

impl<R, S> import::traits::SetPermissionTokenSchema<S> for R
where
    R: FakeSetPermissionTokenSchema<S>,
{
    #[codec::wrap]
    fn set_permission_token_schema(_schema: PermissionTokenSchema, _state: &mut S) {
        panic!(
            "Executor `{}()` entrypoint should not set permission token schema",
            Self::ENTRYPOINT_FN_NAME
        )
    }
}

impl<'wrld> Runtime<state::executor::ValidateTransaction<'wrld>> {
    /// Execute `validate_transaction()` entrypoint of the given module of runtime executor
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`executor::Result`]
    pub fn execute_executor_validate_transaction(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &AccountId,
        module: &wasmtime::Module,
        transaction: SignedTransaction,
    ) -> Result<executor::Result> {
        let span = wasm_log_span!("Running `validate_transaction()`");

        self.execute_executor_validate_internal(
            module,
            state::executor::ValidateTransaction::new(
                authority.clone(),
                self.config,
                span,
                state::wsv::WithMut(wsv),
                state::specific::executor::ValidateTransaction::new(transaction),
            ),
            import::EXECUTOR_VALIDATE_TRANSACTION,
        )
    }
}

impl<'wrld> ExecuteOperationsAsExecutorMut<state::executor::ValidateTransaction<'wrld>>
    for Runtime<state::executor::ValidateTransaction<'wrld>>
{
}

impl<'wrld> import::traits::GetExecutorPayloads<state::executor::ValidateTransaction<'wrld>>
    for Runtime<state::executor::ValidateTransaction<'wrld>>
{
    #[codec::wrap]
    fn get_migrate_payload(
        _state: &state::executor::ValidateTransaction<'wrld>,
    ) -> payloads::Migrate {
        panic!("Executor `validate_transaction()` entrypoint should not query payload for `migrate()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_transaction_payload(
        state: &state::executor::ValidateTransaction<'wrld>,
    ) -> Validate<SignedTransaction> {
        Validate {
            authority: state.authority.clone(),
            block_height: state.wsv.0.height(),
            target: state.specific_state.to_validate.clone(),
        }
    }

    #[codec::wrap]
    fn get_validate_instruction_payload(
        _state: &state::executor::ValidateTransaction<'wrld>,
    ) -> Validate<InstructionBox> {
        panic!("Executor `validate_transaction()` entrypoint should not query payload for `validate_instruction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_query_payload(
        _state: &state::executor::ValidateTransaction<'wrld>,
    ) -> Validate<QueryBox> {
        panic!("Executor `validate_transaction()` entrypoint should not query payload for `validate_query()` entrypoint")
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::executor::ValidateTransaction<'wrld>>
    for Runtime<state::executor::ValidateTransaction<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_transaction";
}

impl<'wrld> Runtime<state::executor::ValidateInstruction<'wrld>> {
    /// Execute `validate_instruction()` entrypoint of the given module of runtime executor
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`executor::Result`]
    pub fn execute_executor_validate_instruction(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &AccountId,
        module: &wasmtime::Module,
        instruction: InstructionBox,
    ) -> Result<executor::Result> {
        let span = wasm_log_span!("Running `validate_instruction()`");

        self.execute_executor_validate_internal(
            module,
            state::executor::ValidateInstruction::new(
                authority.clone(),
                self.config,
                span,
                state::wsv::WithMut(wsv),
                state::specific::executor::ValidateInstruction::new(instruction),
            ),
            import::EXECUTOR_VALIDATE_INSTRUCTION,
        )
    }
}

impl<'wrld> ExecuteOperationsAsExecutorMut<state::executor::ValidateInstruction<'wrld>>
    for Runtime<state::executor::ValidateInstruction<'wrld>>
{
}

impl<'wrld> import::traits::GetExecutorPayloads<state::executor::ValidateInstruction<'wrld>>
    for Runtime<state::executor::ValidateInstruction<'wrld>>
{
    #[codec::wrap]
    fn get_migrate_payload(
        _state: &state::executor::ValidateInstruction<'wrld>,
    ) -> payloads::Migrate {
        panic!("Executor `validate_instruction()` entrypoint should not query payload for `migrate()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_transaction_payload(
        _state: &state::executor::ValidateInstruction<'wrld>,
    ) -> Validate<SignedTransaction> {
        panic!("Executor `validate_instruction()` entrypoint should not query payload for `validate_transaction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_instruction_payload(
        state: &state::executor::ValidateInstruction<'wrld>,
    ) -> Validate<InstructionBox> {
        Validate {
            authority: state.authority.clone(),
            block_height: state.wsv.0.height(),
            target: state.specific_state.to_validate.clone(),
        }
    }

    #[codec::wrap]
    fn get_validate_query_payload(
        _state: &state::executor::ValidateInstruction<'wrld>,
    ) -> Validate<QueryBox> {
        panic!("Executor `validate_instruction()` entrypoint should not query payload for `validate_query()` entrypoint")
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::executor::ValidateInstruction<'wrld>>
    for Runtime<state::executor::ValidateInstruction<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_instruction";
}

impl<'wrld> Runtime<state::executor::ValidateQuery<'wrld>> {
    /// Execute `validate_query()` entrypoint of the given module of runtime executor
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if unable to find expected function export
    /// - if the execution of the smartcontract fails
    /// - if unable to decode [`executor::Result`]
    pub fn execute_executor_validate_query(
        &self,
        wsv: &'wrld WorldStateView,
        authority: &AccountId,
        module: &wasmtime::Module,
        query: QueryBox,
    ) -> Result<executor::Result> {
        let span = wasm_log_span!("Running `validate_query()`");

        self.execute_executor_validate_internal(
            module,
            state::executor::ValidateQuery::new(
                authority.clone(),
                self.config,
                span,
                state::wsv::WithConst(wsv),
                state::specific::executor::ValidateQuery::new(query),
            ),
            import::EXECUTOR_VALIDATE_QUERY,
        )
    }
}

impl<'wrld> import::traits::ExecuteOperations<state::executor::ValidateQuery<'wrld>>
    for Runtime<state::executor::ValidateQuery<'wrld>>
{
    #[codec::wrap]
    fn execute_query(
        query_request: SmartContractQueryRequest,
        state: &mut state::executor::ValidateQuery<'wrld>,
    ) -> Result<BatchedResponse<Value>, ValidationFail> {
        debug!(%query_request, "Executing as executor");

        Runtime::default_execute_query(query_request, state)
    }

    #[codec::wrap]
    fn execute_instruction(
        _instruction: InstructionBox,
        _state: &mut state::executor::ValidateQuery<'wrld>,
    ) -> Result<(), ValidationFail> {
        panic!("Executor `validate_query()` entrypoint should not execute instructions")
    }
}

impl<'wrld> import::traits::GetExecutorPayloads<state::executor::ValidateQuery<'wrld>>
    for Runtime<state::executor::ValidateQuery<'wrld>>
{
    #[codec::wrap]
    fn get_migrate_payload(_state: &state::executor::ValidateQuery<'wrld>) -> payloads::Migrate {
        panic!("Executor `validate_query()` entrypoint should not query payload for `migrate()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_transaction_payload(
        _state: &state::executor::ValidateQuery<'wrld>,
    ) -> Validate<SignedTransaction> {
        panic!("Executor `validate_query()` entrypoint should not query payload for `validate_transaction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_instruction_payload(
        _state: &state::executor::ValidateQuery<'wrld>,
    ) -> Validate<InstructionBox> {
        panic!("Executor `validate_query()` entrypoint should not query payload for `validate_instruction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_query_payload(
        state: &state::executor::ValidateQuery<'wrld>,
    ) -> Validate<QueryBox> {
        Validate {
            authority: state.authority.clone(),
            block_height: state.wsv.0.height(),
            target: state.specific_state.to_validate.clone(),
        }
    }
}

impl<'wrld> FakeSetPermissionTokenSchema<state::executor::ValidateQuery<'wrld>>
    for Runtime<state::executor::ValidateQuery<'wrld>>
{
    const ENTRYPOINT_FN_NAME: &'static str = "validate_query";
}

impl<'wrld> Runtime<state::executor::Migrate<'wrld>> {
    /// Execute `migrate()` entrypoint of *Executor*
    ///
    /// # Errors
    ///
    /// - if failed to instantiate provided `module`
    /// - if failed to get export function for `migrate()`
    /// - if failed to call export function
    /// - if failed to decode [`MigrationResult`]
    pub fn execute_executor_migration(
        &self,
        wsv: &'wrld mut WorldStateView,
        authority: &AccountId,
        module: &wasmtime::Module,
    ) -> Result<MigrationResult> {
        let span = wasm_log_span!("Running migration");
        let state = state::executor::Migrate::new(
            authority.clone(),
            self.config,
            span,
            state::wsv::WithMut(wsv),
            state::specific::executor::Migrate,
        );

        let mut store = self.create_store(state);
        let instance = self.instantiate_module(module, &mut store)?;

        let migrate_fn = Self::get_typed_func(&instance, &mut store, import::EXECUTOR_MIGRATE)?;

        let offset = migrate_fn
            .call(&mut store, ())
            .map_err(ExportFnCallError::from)?;

        let memory =
            Self::get_memory(&mut (&instance, &mut store)).expect("Checked at instantiation step");
        let dealloc_fn =
            Self::get_typed_func(&instance, &mut store, import::SMART_CONTRACT_DEALLOC)
                .expect("Checked at instantiation step");
        codec::decode_with_length_prefix_from_memory(&memory, &dealloc_fn, &mut store, offset)
            .map_err(Error::Decode)
    }
}

impl<'wrld> ExecuteOperationsAsExecutorMut<state::executor::Migrate<'wrld>>
    for Runtime<state::executor::Migrate<'wrld>>
{
}

/// Fake implementation of [`import_traits::GetValidationPayloads`].
///
/// This is needed because `migrate()` entrypoint exists in the same binary as
/// `validate_*()` entrypoints.
///
/// # Panics
///
/// Panics with error message if called, because it should never be called from
/// `migrate()` entrypoint.
impl<'wrld> import::traits::GetExecutorPayloads<state::executor::Migrate<'wrld>>
    for Runtime<state::executor::Migrate<'wrld>>
{
    #[codec::wrap]
    fn get_migrate_payload(state: &state::executor::Migrate<'wrld>) -> payloads::Migrate {
        payloads::Migrate {
            block_height: state.wsv.0.height(),
        }
    }

    #[codec::wrap]
    fn get_validate_transaction_payload(
        _state: &state::executor::Migrate<'wrld>,
    ) -> Validate<SignedTransaction> {
        panic!("Executor `migrate()` entrypoint should not query payload for `validate_transaction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_instruction_payload(
        _state: &state::executor::Migrate<'wrld>,
    ) -> Validate<InstructionBox> {
        panic!("Executor `migrate()` entrypoint should not query payload for `validate_instruction()` entrypoint")
    }

    #[codec::wrap]
    fn get_validate_query_payload(_state: &state::executor::Migrate<'wrld>) -> Validate<QueryBox> {
        panic!("Executor `migrate()` entrypoint should not query payload for `validate_query()` entrypoint")
    }
}

impl<'wrld> import::traits::SetPermissionTokenSchema<state::executor::Migrate<'wrld>>
    for Runtime<state::executor::Migrate<'wrld>>
{
    #[codec::wrap]
    fn set_permission_token_schema(
        schema: PermissionTokenSchema,
        state: &mut state::executor::Migrate<'wrld>,
    ) {
        debug!(%schema, "Setting permission token schema");

        state.wsv.0.set_permission_token_schema(schema)
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
        $(export::$name:ident => $fn_path:path),* $(,)?
    ) => {
        $linker.func_wrap(
                WASM_MODULE,
                export::LOG,
                Runtime::log,
            )
            .and_then(|l| {
                l.func_wrap(
                    WASM_MODULE,
                    export::DBG,
                    Runtime::dbg,
                )
            })
            $(.and_then(|l| {
                l.func_wrap(
                    WASM_MODULE,
                    export::$name,
                    $fn_path,
                )
            }))*
            .map_err(Error::Initialization)
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
                export::EXECUTE_ISI => Runtime::<state::SmartContract<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::SmartContract<'_>>::execute_query,
                export::GET_SMART_CONTRACT_PAYLOAD => Runtime::get_smart_contract_payload,
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
                export::EXECUTE_ISI => Runtime::<state::Trigger<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::Trigger<'_>>::execute_query,
                export::GET_TRIGGER_PAYLOAD => Runtime::get_trigger_payload,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::executor::ValidateTransaction<'wrld>> {
    /// Builds the [`Runtime`] for *Executor* `validate_transaction()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::executor::ValidateTransaction<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                export::EXECUTE_ISI => Runtime::<state::executor::ValidateTransaction<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::executor::ValidateTransaction<'_>>::execute_query,
                export::GET_MIGRATE_PAYLOAD => Runtime::get_migrate_payload,
                export::GET_VALIDATE_TRANSACTION_PAYLOAD => Runtime::get_validate_transaction_payload,
                export::GET_VALIDATE_INSTRUCTION_PAYLOAD => Runtime::get_validate_instruction_payload,
                export::GET_VALIDATE_QUERY_PAYLOAD => Runtime::get_validate_query_payload,
                export::SET_PERMISSION_TOKEN_SCHEMA => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::executor::ValidateInstruction<'wrld>> {
    /// Builds the [`Runtime`] for *Executor* `validate_instruction()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::executor::ValidateInstruction<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                export::EXECUTE_ISI => Runtime::<state::executor::ValidateInstruction<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::executor::ValidateInstruction<'_>>::execute_query,
                export::GET_MIGRATE_PAYLOAD => Runtime::get_migrate_payload,
                export::GET_VALIDATE_TRANSACTION_PAYLOAD => Runtime::get_validate_transaction_payload,
                export::GET_VALIDATE_INSTRUCTION_PAYLOAD => Runtime::get_validate_instruction_payload,
                export::GET_VALIDATE_QUERY_PAYLOAD => Runtime::get_validate_query_payload,
                export::SET_PERMISSION_TOKEN_SCHEMA => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::executor::ValidateQuery<'wrld>> {
    /// Builds the [`Runtime`] for *Executor* `validate_query()` execution
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::executor::ValidateQuery<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                export::EXECUTE_ISI => Runtime::<state::executor::ValidateQuery<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::executor::ValidateQuery<'_>>::execute_query,
                export::GET_MIGRATE_PAYLOAD => Runtime::get_migrate_payload,
                export::GET_VALIDATE_TRANSACTION_PAYLOAD => Runtime::get_validate_transaction_payload,
                export::GET_VALIDATE_INSTRUCTION_PAYLOAD => Runtime::get_validate_instruction_payload,
                export::GET_VALIDATE_QUERY_PAYLOAD => Runtime::get_validate_query_payload,
                export::SET_PERMISSION_TOKEN_SCHEMA => Runtime::set_permission_token_schema,
            )?;
            Ok(linker)
        })
    }
}

impl<'wrld> RuntimeBuilder<state::executor::Migrate<'wrld>> {
    /// Builds the [`Runtime`] to execute `permission_tokens()` entrypoint of *Executor*
    ///
    /// # Errors
    ///
    /// Fails if failed to create default linker.
    pub fn build(self) -> Result<Runtime<state::executor::Migrate<'wrld>>> {
        self.finalize(|engine| {
            let mut linker = Linker::new(engine);

            create_imports!(linker,
                export::EXECUTE_ISI => Runtime::<state::executor::Migrate<'_>>::execute_instruction,
                export::EXECUTE_QUERY => Runtime::<state::executor::Migrate<'_>>::execute_query,
                export::GET_MIGRATE_PAYLOAD => Runtime::get_migrate_payload,
                export::GET_VALIDATE_TRANSACTION_PAYLOAD => Runtime::get_validate_transaction_payload,
                export::GET_VALIDATE_INSTRUCTION_PAYLOAD => Runtime::get_validate_instruction_payload,
                export::GET_VALIDATE_QUERY_PAYLOAD => Runtime::get_validate_query_payload,
                export::SET_PERMISSION_TOKEN_SCHEMA => Runtime::set_permission_token_schema,
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
    use std::str::FromStr as _;

    use iroha_crypto::KeyPair;
    use iroha_data_model::query::{sorting::Sorting, Pagination};
    use parity_scale_codec::Encode;
    use tokio::test;

    use super::*;
    use crate::{
        kura::Kura, query::store::LiveQueryStore, smartcontracts::isi::Registrable as _, PeersIds,
        World,
    };

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
            memory_name = WASM_MEMORY,
            alloc_fn_name = import::SMART_CONTRACT_ALLOC,
            dealloc_fn_name = import::SMART_CONTRACT_DEALLOC,
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
    async fn execute_instruction_exported() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = Register::account(Account::new(new_authority, []));
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
            main_fn_name = import::SMART_CONTRACT_MAIN,
            execute_fn_name = export::EXECUTE_ISI,
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
    async fn execute_query_exported() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);
        let query_hex = encode_hex(SmartContractQueryRequest::query(
            QueryBox::from(FindAccountById::new(authority.clone())),
            Sorting::default(),
            Pagination::default(),
            FetchSize::default(),
        ));

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
            main_fn_name = import::SMART_CONTRACT_MAIN,
            execute_fn_name = export::EXECUTE_QUERY,
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
    async fn instruction_limit_reached() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();

        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = Register::account(Account::new(new_authority, []));
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
            main_fn_name = import::SMART_CONTRACT_MAIN,
            execute_fn_name = export::EXECUTE_ISI,
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
    async fn instructions_not_allowed() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);

        let isi_hex = {
            let new_authority = AccountId::from_str("mad_hatter@wonderland").expect("Valid");
            let register_isi = Register::account(Account::new(new_authority, []));
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
            main_fn_name = import::SMART_CONTRACT_MAIN,
            execute_fn_name = export::EXECUTE_ISI,
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
    async fn queries_not_allowed() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);
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
            main_fn_name = import::SMART_CONTRACT_MAIN,
            execute_fn_name = export::EXECUTE_QUERY,
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
    async fn trigger_related_func_is_not_linked_for_smart_contract() -> Result<(), Error> {
        let authority = AccountId::from_str("alice@wonderland").expect("Valid");
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let mut wsv = WorldStateView::new(world_with_test_account(&authority), kura, query_handle);
        let query_hex = encode_hex(QueryBox::from(FindAccountById::new(authority.clone())));

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{get_trigger_payload_fn_name}"
                    (func $exec_fn (param) (result i32)))

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param)
                    (call $exec_fn)

                    ;; No use of return values
                    drop))
            "#,
            main_fn_name = import::SMART_CONTRACT_MAIN,
            get_trigger_payload_fn_name = export::GET_TRIGGER_PAYLOAD,
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
