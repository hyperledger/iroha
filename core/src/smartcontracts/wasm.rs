//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction
#![allow(clippy::expect_used, clippy::doc_link_with_quotes)]
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]

use anyhow::anyhow;
use eyre::Context;
use iroha_config::wasm::Configuration;
use iroha_data_model::{permission, prelude::*, ParseError};
use parity_scale_codec::{Decode, Encode};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use super::{permissions::judge::InstructionJudgeArc, Evaluate};
use crate::{
    smartcontracts::{
        permissions::{check_instruction_permissions, prelude::*},
        Execute, ValidQuery,
    },
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
    /// Name of the exported entry for runtime validator execution
    pub const WASM_VALIDATOR_MAIN_FN_NAME: &str = "_iroha_validator_main";
}

pub mod import {
    //! Module functions names imported from iroha to wasm

    /// Name of the imported function to execute instructions
    pub const EXECUTE_ISI_FN_NAME: &str = "execute_instruction";
    /// Name of the imported function to execute queries
    pub const EXECUTE_QUERY_FN_NAME: &str = "execute_query";
    /// Name of the imported function to query trigger authority
    pub const QUERY_AUTHORITY_FN_NAME: &str = "query_authority";
    /// Name of the imported function to query event that triggered the smart contract execution
    pub const QUERY_TRIGGERING_EVENT_FN_NAME: &str = "query_triggering_event";
    /// Name of the imported function to query operation
    /// that needs to be validated with permission validator
    pub const QUERY_OPERATION_TO_VALIDATE_FN_NAME: &str = "query_operation_to_validate";
    /// Name of the imported function to evaluate the expression on the host side
    pub const EVALUATE_ON_HOST_FN_NAME: &str = "evaluate_on_host";
    /// Name of the imported function to debug print objects
    pub const DBG_FN_NAME: &str = "dbg";
}

/// `WebAssembly` execution error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Engine or linker could not be created
    #[error("Runtime initialization failure: {0}")]
    Initialization(#[source] anyhow::Error),
    /// Module could not be compiled or instantiated
    #[error("Module instantiation failure: {0}")]
    Instantiation(#[source] anyhow::Error),
    /// Expected named export not found in module
    #[error("Named export not found: {0}")]
    ExportNotFound(#[source] anyhow::Error),
    /// Call to the function exported from module failed
    ///
    /// In Wasmtime v0.33, can also mean that max linear memory was
    /// consumed
    #[error("Exported function call failed: {0}")]
    ExportFnCall(#[from] Trap),
    /// Parse Error
    #[error("Failed to Parse valid name: {0}")]
    Parse(#[source] ParseError),
    /// Error during decoding object with length prefix
    #[error("Failed to decode object from bytes with length prefix: {0}")]
    DecodeWithPrefix(#[source] anyhow::Error),
    /// Some other error happened
    #[error(transparent)]
    Other(eyre::Error),
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}

struct Validator<'wrld> {
    /// Number of instructions in the smartcontract
    instruction_count: u64,
    /// Max allowed number of instructions in the smartcontract
    max_instruction_count: u64,
    /// If this particular instruction is allowed
    instruction_judge: InstructionJudgeArc,
    /// If this particular query is allowed
    query_judge: QueryJudgeArc,
    /// Current [`WorldStateView`]
    wsv: &'wrld WorldStateView,
}

impl Validator<'_> {
    /// Checks if number of instructions in wasm smartcontract exceeds maximum
    ///
    /// # Errors
    ///
    /// If number of instructions exceeds maximum
    #[inline]
    fn check_instruction_len(&mut self) -> Result<(), Trap> {
        self.instruction_count += 1;

        if self.instruction_count > self.max_instruction_count {
            return Err(Trap::new(format!(
                "Number of instructions exceeds maximum({})",
                self.max_instruction_count
            )));
        }

        Ok(())
    }

    fn validate_instruction(
        &mut self,
        account_id: &AccountId,
        instruction: &Instruction,
    ) -> Result<(), Trap> {
        self.check_instruction_len()?;

        check_instruction_permissions(
            account_id,
            instruction,
            self.instruction_judge.as_ref(),
            self.query_judge.as_ref(),
            self.wsv,
        )
        .map_err(|error| Trap::new(error.to_string()))
    }

    fn validate_query(&self, account_id: &AccountId, query: &QueryBox) -> Result<(), Trap> {
        self.query_judge
            .judge(account_id, query, self.wsv)
            .map_err(Trap::new)
    }
}

struct State<'wrld> {
    account_id: AccountId,
    /// Ensures smartcontract adheres to limits
    validator: Option<Validator<'wrld>>,
    store_limits: StoreLimits,
    wsv: &'wrld WorldStateView,
    /// Event for triggers
    triggering_event: Option<Event>,
    /// Operation to pass to a runtime permission validator
    operation_to_validate: Option<permission::validator::NeedsPermissionBox>,
}

impl<'wrld> State<'wrld> {
    fn new(wsv: &'wrld WorldStateView, account_id: AccountId, config: Configuration) -> Self {
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
        }
    }

    fn with_validator(
        mut self,
        max_instruction_count: u64,
        instruction_judge: InstructionJudgeArc,
        query_judge: QueryJudgeArc,
    ) -> Self {
        let validator = Validator {
            instruction_count: 0,
            max_instruction_count,
            instruction_judge,
            query_judge,
            wsv: self.wsv,
        };

        self.validator = Some(validator);
        self
    }

    fn with_triggering_event(mut self, event: Event) -> Self {
        self.triggering_event = Some(event);
        self
    }

    fn with_operation_to_validate(
        mut self,
        operation: permission::validator::NeedsPermissionBox,
    ) -> Self {
        self.operation_to_validate = Some(operation);
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
    /// `Runtime` constructor with default configuration.
    ///
    /// # Errors
    ///
    /// If unable to construct runtime
    pub fn new() -> Result<Self, Error> {
        let engine = Self::create_engine()?;
        let config = Configuration::default();

        let linker = Self::create_linker(&engine)?;

        Ok(Self {
            engine,
            linker,
            config,
        })
    }

    /// `Runtime` constructor.
    ///
    /// # Errors
    ///
    /// See [`Runtime::new`]
    pub fn from_configuration(config: Configuration) -> Result<Self, Error> {
        Ok(Self {
            config,
            ..Runtime::new()?
        })
    }

    fn create_config() -> Config {
        let mut config = Config::new();
        config.consume_fuel(true);
        //config.cache_config_load_default();
        config
    }

    fn create_engine() -> Result<Engine, Error> {
        Engine::new(&Self::create_config()).map_err(Error::Initialization)
    }

    fn create_store(&self, state: State<'wrld>) -> Result<Store<State<'wrld>>, Error> {
        let mut store = Store::new(&self.engine, state);

        store.limiter(|stat| &mut stat.store_limits);
        store
            .add_fuel(self.config.fuel_limit)
            .map_err(Error::Instantiation)?;

        Ok(store)
    }

    fn create_smart_contract(
        &self,
        store: &mut Store<State<'wrld>>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<wasmtime::Instance, Error> {
        Module::new(&self.engine, bytes)
            .and_then(|module| self.linker.instantiate(store, &module))
            .map_err(Error::Instantiation)
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

        let query = Self::decode_from_memory(&memory, &caller, offset, len)?;

        if let Some(validator) = &caller.data().validator {
            validator
                .validate_query(&caller.data().account_id, &query)
                .map_err(|error| Trap::new(error.to_string()))?;
        }

        let res_bytes = Self::encode_with_length_prefix(
            &query
                .execute(caller.data().wsv)
                .map_err(|e| Trap::new(e.to_string()))?,
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

        let instruction = Self::decode_from_memory(&memory, &caller, offset, len)?;

        let account_id = caller.data().account_id.clone();
        if let Some(validator) = &mut caller.data_mut().validator {
            validator
                .validate_instruction(&account_id, &instruction)
                .map_err(|error| Trap::new(error.to_string()))?;
        }

        instruction
            .execute(account_id, caller.data().wsv)
            .map_err(|error| Trap::new(error.to_string()))?;

        Ok(())
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

    fn evaluate_on_host(
        mut caller: Caller<State>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<WasmUsize, Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let expression: ExpressionBox = Self::decode_from_memory(&memory, &caller, offset, len)?;
        let value = expression
            .evaluate(
                caller.data().wsv,
                &iroha_data_model::expression::Context::new(),
            )
            .map_err(|err| Trap::new(format!("Failure during expression evaluation: {err}")))?;

        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let bytes = Self::encode_with_length_prefix(&value)?;
        let value_offset = Self::encode_bytes_into_memory(&bytes, &memory, &alloc_fn, &mut caller)?;
        Ok(value_offset)
    }

    /// Host defined function which prints given string. When calling
    /// this function, module serializes ISI to linear memory and
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

    fn create_linker(engine: &Engine) -> Result<Linker<State<'wrld>>, Error> {
        let mut linker = Linker::new(engine);

        linker
            .func_wrap(
                "iroha",
                import::EXECUTE_ISI_FN_NAME,
                Self::execute_instruction,
            )
            .and_then(|l| l.func_wrap("iroha", import::EXECUTE_QUERY_FN_NAME, Self::execute_query))
            .and_then(|l| {
                l.func_wrap(
                    "iroha",
                    import::QUERY_AUTHORITY_FN_NAME,
                    Self::query_authority,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    "iroha",
                    import::QUERY_TRIGGERING_EVENT_FN_NAME,
                    Self::query_triggering_event,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    "iroha",
                    import::QUERY_OPERATION_TO_VALIDATE_FN_NAME,
                    Self::query_operation_to_validate,
                )
            })
            .and_then(|l| {
                l.func_wrap(
                    "iroha",
                    import::EVALUATE_ON_HOST_FN_NAME,
                    Self::evaluate_on_host,
                )
            })
            .and_then(|l| l.func_wrap("iroha", import::DBG_FN_NAME, Self::dbg))
            .map_err(Error::Initialization)?;

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
        wsv: &WorldStateView,
        account_id: &AccountId,
        bytes: impl AsRef<[u8]>,
        max_instruction_count: u64,
        instruction_judge: InstructionJudgeArc,
        query_judge: QueryJudgeArc,
    ) -> Result<(), Error> {
        let state = State::new(wsv, account_id.clone(), self.config).with_validator(
            max_instruction_count,
            instruction_judge,
            query_judge,
        );

        self.execute_main_with_state(bytes, state)
    }

    /// Executes the given wasm trigger
    ///
    /// # Errors
    ///
    /// - if unable to construct wasm module or instance of wasm module
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    pub fn execute_trigger(
        &mut self,
        wsv: &WorldStateView,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
        event: Event,
    ) -> Result<(), Error> {
        let state = State::new(wsv, account_id, self.config).with_triggering_event(event);
        self.execute_main_with_state(bytes, state)
    }

    /// Execute the given wasm runtime permission validator
    ///
    /// # Errors
    ///
    /// - if unable to construct wasm module or instance of wasm module
    /// - if unable to find expected main function export
    /// - if the execution of the smartcontract fails
    #[allow(unsafe_code)]
    pub fn execute_permission_validator(
        &mut self,
        wsv: &WorldStateView,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
        operation: permission::validator::NeedsPermissionBox,
    ) -> Result<permission::validator::Verdict, Error> {
        let state = State::new(wsv, account_id, self.config).with_operation_to_validate(operation);
        let mut store = self.create_store(state)?;
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        let validate_fn = smart_contract
            .get_typed_func::<_, WasmUsize, _>(&mut store, export::WASM_VALIDATOR_MAIN_FN_NAME)
            .map_err(Error::ExportNotFound)?;

        // NOTE: This function takes ownership of the pointer
        let offset = validate_fn
            .call(&mut store, ())
            .map_err(Error::ExportFnCall)?;

        let memory = Self::get_memory(&mut (&smart_contract, &mut store))?;
        let dealloc_fn = smart_contract
            .get_typed_func(&mut store, export::WASM_DEALLOC_FN)
            .map_err(Error::ExportNotFound)?;
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
        wsv: &WorldStateView,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let state = State::new(wsv, account_id, self.config);
        self.execute_main_with_state(bytes, state)
    }

    fn execute_main_with_state(
        &mut self,
        bytes: impl AsRef<[u8]>,
        state: State,
    ) -> Result<(), Error> {
        let mut store = self.create_store(state)?;
        let smart_contract = self.create_smart_contract(&mut store, bytes)?;

        let main_fn = smart_contract
            .get_typed_func(&mut store, export::WASM_MAIN_FN_NAME)
            .map_err(Error::ExportNotFound)?;

        // NOTE: This function takes ownership of the pointer
        main_fn.call(&mut store, ()).map_err(Error::ExportFnCall)
    }

    /// Decode object from the given `memory` at the given `offset` with the given `len`
    ///
    /// # Warning
    ///
    /// This method does not take ownership of the pointer.
    fn decode_from_memory<C: wasmtime::AsContext, T: Decode>(
        memory: &wasmtime::Memory,
        context: &C,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<T, Trap> {
        // Accessing memory as a byte slice to avoid the use of unsafe
        let mem_range = offset as usize..(offset + len) as usize;
        let mut bytes = &memory.data(context)[mem_range];
        T::decode(&mut bytes).map_err(|error| Trap::new(error.to_string()))
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
        T: Decode + std::fmt::Debug,
    >(
        memory: &wasmtime::Memory,
        dealloc_fn: &wasmtime::TypedFunc<(WasmUsize, WasmUsize), ()>,
        mut context: &mut C,
        offset: WasmUsize,
    ) -> Result<T, Error> {
        const U32_TO_USIZE_ERROR_MES: &str = "`u32` should always fit in `usize`";

        let len_size_bytes: u32 = core::mem::size_of::<WasmUsize>()
            .try_into()
            .map_err(|err| {
                Error::DecodeWithPrefix(anyhow!("Can't convert `usize` to `u32`: {err}"))
            })?;
        let len = u32::from_le_bytes(
            memory.data(&mut context)[offset as usize..(offset + len_size_bytes) as usize]
                .try_into()
                .expect("Prefix length size(bytes) incorrect"),
        );

        let bytes = &memory.data_mut(&mut context)[offset.try_into().expect(U32_TO_USIZE_ERROR_MES)
            ..(offset + len).try_into().expect(U32_TO_USIZE_ERROR_MES)];

        let obj =
            T::decode(&mut &bytes[len_size_bytes.try_into().expect(U32_TO_USIZE_ERROR_MES)..])
                .map_err(|err| Error::DecodeWithPrefix(err.into()))?;

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

/// Helper trait to make a function generic over `get_export()` fn from `wasmtime` crate
trait GetExport {
    fn get_export(&mut self, name: &str) -> Option<wasmtime::Extern>;
}

#[allow(clippy::single_char_lifetime_names)]
impl<'a, T> GetExport for Caller<'a, T> {
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

    use std::{str::FromStr as _, sync::Arc};

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{
        smartcontracts::permissions::judge::{AllowAll, DenyAll},
        PeersIds, World,
    };

    fn world_with_test_account(account_id: AccountId) -> World {
        let domain_id = account_id.domain_id.clone();
        let (public_key, _) = KeyPair::generate().unwrap().into();
        let account = Account::new(account_id, [public_key]).build();
        let mut domain = Domain::new(domain_id).build();
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
        let account_id = AccountId::from_str("alice@wonderland")?;
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland")?;
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(Instruction::Register(register_isi))
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
        let mut runtime = Runtime::new()?;
        runtime
            .execute(&wsv, account_id, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn execute_query_exported() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland")?;
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let query_hex = {
            let find_acc_query = FindAccountById::new(account_id.clone());
            encode_hex(QueryBox::FindAccountById(find_acc_query))
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
            execute_fn_name = import::EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        runtime
            .execute(&wsv, account_id, wat)
            .expect("Execution failed");

        Ok(())
    }

    #[test]
    fn instruction_limit_reached() -> Result<(), Error> {
        let account_id = AccountId::from_str("alice@wonderland")?;
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland")?;
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(Instruction::Register(register_isi))
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

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(
            &wsv,
            &account_id,
            wat,
            1,
            Arc::new(AllowAll::new()),
            Arc::new(AllowAll::new()),
        );

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
        let account_id = AccountId::from_str("alice@wonderland")?;
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::from_str("mad_hatter@wonderland")?;
            let register_isi = RegisterBox::new(Account::new(new_account_id, []));
            encode_hex(Instruction::Register(register_isi))
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

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(
            &wsv,
            &account_id,
            wat,
            1,
            Arc::new(DenyAll::new()),
            Arc::new(AllowAll::new()),
        );

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
        let account_id = AccountId::from_str("alice@wonderland")?;
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let query_hex = {
            let find_acc_query = FindAccountById::new(account_id.clone());
            encode_hex(QueryBox::FindAccountById(find_acc_query))
        };

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

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(
            &wsv,
            &account_id,
            wat,
            1,
            Arc::new(AllowAll::new()),
            Arc::new(DenyAll::new()),
        );

        if let Error::ExportFnCall(trap) = res.expect_err("Execution should fail") {
            assert!(trap
                .display_reason()
                .to_string()
                .starts_with("All operations are denied"));
        }

        Ok(())
    }
}
