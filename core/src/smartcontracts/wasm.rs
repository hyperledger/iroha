//! This module contains logic related to executing smartcontracts via
//! `WebAssembly` VM Smartcontracts can be written in Rust, compiled
//! to wasm format and submitted in a transaction
#![allow(clippy::expect_used)]

use std::sync::Arc;

use config::Configuration;
use eyre::WrapErr;
use iroha_data_model::{prelude::*, ParseError};
use iroha_logger::prelude::*;
use parity_scale_codec::{Decode, Encode};
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
};

use super::permissions::IsInstructionAllowedBoxed;
use crate::{
    smartcontracts::{
        permissions::{check_instruction_permissions, IsQueryAllowedBoxed},
        Execute, ValidQuery,
    },
    wsv::{WorldStateView, WorldTrait},
};

type WasmUsize = u32;

/// Exported function to allocate memory
pub const WASM_ALLOC_FN: &str = "_iroha_wasm_alloc";
/// Name of the exported memory
pub const WASM_MEMORY_NAME: &str = "memory";
/// Name of the exported entry to smartcontract execution
pub const WASM_MAIN_FN_NAME: &str = "_iroha_wasm_main";
/// Name of the imported function to execute instructions
pub const EXECUTE_ISI_FN_NAME: &str = "execute_instruction";
/// Name of the imported function to execute queries
pub const EXECUTE_QUERY_FN_NAME: &str = "execute_query";
/// Name of the imported function to debug print object
pub const DBG_FN_NAME: &str = "dbg";

/// `WebAssembly` execution error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Engine or linker could not be created
    #[error("Runtime initialization failure")]
    Initialization(#[source] anyhow::Error),
    /// Module could not be compiled or instantiated
    #[error("Module instantiation failure")]
    Instantiation(#[source] anyhow::Error),
    /// Expected named export not found in module
    #[error("Named export not found")]
    ExportNotFound(#[source] anyhow::Error),
    /// Call to the function exported from module failed
    ///
    /// In Wasmtime v0.33, can also mean that max linear memory was
    /// consumed
    #[error("Exported function call failed")]
    ExportFnCall(#[from] Trap),
    /// Parse Error
    #[error("Failed to Parse valid name")]
    Parse(#[source] ParseError),
    /// Some other error happened
    #[error(transparent)]
    Other(eyre::Error),
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Self::Parse(err)
    }
}

struct Validator<'wrld, W: WorldTrait> {
    /// Number of instructions in the smartcontract
    instruction_count: u64,
    /// Max allowed number of instructions in the smartcontract
    max_instruction_count: u64,
    /// If this particular instruction is allowed
    is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
    /// If this particular query is allowed
    is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
    /// Current [`WorldStateview`]
    wsv: &'wrld WorldStateView<W>,
}

impl<W: WorldTrait> Validator<'_, W> {
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
            &self.is_instruction_allowed,
            &self.is_query_allowed,
            self.wsv,
        )
        .map_err(|error| Trap::new(error.to_string()))
    }

    fn validate_query(&self, account_id: &AccountId, query: &QueryBox) -> Result<(), Trap> {
        self.is_query_allowed
            .check(account_id, query, self.wsv)
            .map_err(Trap::new)
    }
}

struct State<'wrld, W: WorldTrait> {
    account_id: AccountId,
    /// Ensures smartcontract adheres to limits
    validator: Option<Validator<'wrld, W>>,
    store_limits: StoreLimits,
    wsv: &'wrld WorldStateView<W>,
}

impl<'wrld, W: WorldTrait> State<'wrld, W> {
    fn new(wsv: &'wrld WorldStateView<W>, account_id: AccountId, config: Configuration) -> Self {
        Self {
            wsv,
            account_id,
            validator: None,

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
        is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
    ) -> Self {
        let validator = Validator {
            instruction_count: 0,
            max_instruction_count,
            is_instruction_allowed,
            is_query_allowed,
            wsv: self.wsv,
        };

        self.validator = Some(validator);
        self
    }
}

/// `WebAssembly` virtual machine
pub struct Runtime<'wrld, W: WorldTrait> {
    engine: Engine,
    linker: Linker<State<'wrld, W>>,
    config: Configuration,
}

impl<'wrld, W: WorldTrait> Runtime<'wrld, W> {
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
        for (i, byte) in WasmUsize::try_from(r.len())
            .map_err(|e| Trap::new(e.to_string()))?
            .to_le_bytes()
            .into_iter()
            .enumerate()
        {
            r[i] = byte;
        }

        Ok(r)
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
        mut caller: Caller<State<W>>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<WasmUsize, Trap> {
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let query_mem_range = offset as usize..(offset + len) as usize;
        let mut query_bytes = &memory.data(&caller)[query_mem_range];
        let query =
            QueryBox::decode(&mut query_bytes).map_err(|error| Trap::new(error.to_string()))?;

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

        let res_bytes_len: WasmUsize = {
            let res_bytes_len: Result<WasmUsize, _> = res_bytes.len().try_into();
            res_bytes_len.map_err(|error| Trap::new(error.to_string()))?
        };

        let res_offset = {
            let res_offset = alloc_fn
                .call(&mut caller, res_bytes_len)
                .map_err(|e| Trap::new(e.to_string()))?;

            memory
                .write(&mut caller, res_offset as usize, &res_bytes)
                .map_err(|error| Trap::new(error.to_string()))?;

            res_offset
        };

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
        mut caller: Caller<State<W>>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let isi_mem_range = offset as usize..(offset + len) as usize;
        let mut isi_bytes = &memory.data(&caller)[isi_mem_range];
        let instruction =
            Instruction::decode(&mut isi_bytes).map_err(|error| Trap::new(error.to_string()))?;

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
    fn dbg(mut caller: Caller<State<W>>, offset: WasmUsize, len: WasmUsize) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;
        let string_mem_range = offset as usize..(offset + len) as usize;
        let mut string_bytes = &memory.data(&caller)[string_mem_range];
        let s = String::decode(&mut string_bytes).map_err(|error| Trap::new(error.to_string()))?;
        println!("{s}");
        Ok(())
    }

    fn create_linker(engine: &Engine) -> Result<Linker<State<'wrld, W>>, Error> {
        let mut linker = Linker::new(engine);

        linker
            .func_wrap("iroha", EXECUTE_ISI_FN_NAME, Self::execute_instruction)
            .and_then(|l| l.func_wrap("iroha", EXECUTE_QUERY_FN_NAME, Self::execute_query))
            .map_err(Error::Initialization)?;

        linker
            .func_wrap("iroha", DBG_FN_NAME, Self::dbg)
            .map_err(Error::Initialization)?;

        Ok(linker)
    }

    fn get_alloc_fn(
        caller: &mut Caller<State<W>>,
    ) -> Result<TypedFunc<WasmUsize, WasmUsize>, Trap> {
        caller
            .get_export(WASM_ALLOC_FN)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_ALLOC_FN)))?
            .into_func()
            .ok_or_else(|| Trap::new(format!("{}: not a function", WASM_ALLOC_FN)))?
            .typed::<WasmUsize, WasmUsize, _>(caller)
            .map_err(|_error| Trap::new(format!("{}: unexpected declaration", WASM_ALLOC_FN)))
    }

    fn get_memory(caller: &mut Caller<State<W>>) -> Result<wasmtime::Memory, Trap> {
        caller
            .get_export(WASM_MEMORY_NAME)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_MEMORY_NAME)))?
            .into_memory()
            .ok_or_else(|| Trap::new(format!("{}: not a memory", WASM_MEMORY_NAME)))
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
        wsv: &WorldStateView<W>,
        account_id: &AccountId,
        bytes: impl AsRef<[u8]>,
        max_instruction_count: u64,
        is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
    ) -> Result<(), Error> {
        let state = State::new(wsv, account_id.clone(), self.config).with_validator(
            max_instruction_count,
            is_instruction_allowed,
            is_query_allowed,
        );

        self.execute_with_state(account_id, bytes, state)
    }

    /// Executes the given wasm smartcontract
    ///
    /// # Errors
    ///
    /// - if unable to construct wasm module or instance of wasm module
    /// - if unable to add fuel limit
    /// - if unable to find expected exports(main, memory, allocator)
    /// - if the execution of the smartcontract fails
    pub fn execute(
        &mut self,
        wsv: &WorldStateView<W>,
        account_id: &AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let state = State::new(wsv, account_id.clone(), self.config);
        self.execute_with_state(account_id, bytes, state)
    }

    fn execute_with_state(
        &mut self,
        account_id: &AccountId,
        bytes: impl AsRef<[u8]>,
        state: State<W>,
    ) -> Result<(), Error> {
        let account_bytes = account_id.encode();

        let module = Module::new(&self.engine, bytes).map_err(Error::Instantiation)?;
        let mut store = Store::new(&self.engine, state);
        store.limiter(|stat| &mut stat.store_limits);

        store
            .add_fuel(self.config.fuel_limit)
            .map_err(Error::Instantiation)?;

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(Error::Instantiation)?;
        let alloc_fn = instance
            .get_typed_func::<WasmUsize, WasmUsize, _>(&mut store, WASM_ALLOC_FN)
            .map_err(Error::ExportNotFound)?;

        let memory = instance
            .get_memory(&mut store, WASM_MEMORY_NAME)
            .ok_or_else(|| {
                Error::ExportNotFound(anyhow::Error::msg(format!(
                    "{}: export not found or not a memory",
                    WASM_MEMORY_NAME
                )))
            })?;

        let account_bytes_len = account_bytes
            .len()
            .try_into()
            .wrap_err(format!(
                "Encoded account ID has size larger than {}::MAX",
                std::any::type_name::<WasmUsize>()
            ))
            .map_err(Error::Other)?;

        let account_offset = {
            let acc_offset = alloc_fn
                .call(&mut store, account_bytes_len)
                .map_err(Error::ExportFnCall)?;

            memory
                .write(&mut store, acc_offset as usize, &account_bytes)
                .map_err(|error| Trap::new(error.to_string()))?;

            acc_offset
        };

        let main_fn = instance
            .get_typed_func::<(WasmUsize, WasmUsize), (), _>(&mut store, WASM_MAIN_FN_NAME)
            .map_err(Error::ExportNotFound)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(&mut store, (account_offset, account_bytes_len))
            .map_err(Error::ExportFnCall)?;

        Ok(())
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use serde::{Deserialize, Serialize};

    const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;
    const DEFAULT_MAX_MEMORY: u32 = 500 * 2_u32.pow(20); // 500 MiB

    /// [`WebAssembly Runtime`](super::Runtime) configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configurable)]
    #[config(env_prefix = "WASM_")]
    #[serde(rename_all = "UPPERCASE", default)]
    pub struct Configuration {
        /// Every WASM instruction costs approximately 1 unit of fuel. See
        /// [`wasmtime` reference](https://docs.rs/wasmtime/0.29.0/wasmtime/struct.Store.html#method.add_fuel)
        pub fuel_limit: u64,

        /// Maximum amount of linear memory a given smartcontract can allocate
        pub max_memory: u32,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                fuel_limit: DEFAULT_FUEL_LIMIT,
                max_memory: DEFAULT_MAX_MEMORY,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{
        smartcontracts::permissions::{AllowAll, DenyAll},
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
            memory_name = WASM_MEMORY_NAME,
            alloc_fn_name = WASM_ALLOC_FN,
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
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))))
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_ISI_FN_NAME,
            memory_and_alloc = memory_and_alloc(&isi_hex),
            isi_len = isi_hex.len() / 3,
        );
        let mut runtime = Runtime::new()?;
        assert!(runtime.execute(&wsv, &account_id, wat).is_ok());

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
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return values
                    drop))
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        assert!(runtime.execute(&wsv, &account_id, wat).is_ok());

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
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_ISI_FN_NAME,
            // Store two instructions into adjacent memory and execute them
            memory_and_alloc = memory_and_alloc(&isi_hex.repeat(2)),
            isi1_end = isi_hex.len() / 3,
            isi2_end = 2 * isi_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(&wsv, &account_id, wat, 1, AllowAll::new(), AllowAll::new());

        assert!(res.is_err());
        if let Error::ExportFnCall(trap) = res.unwrap_err() {
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
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_ISI_FN_NAME,
            memory_and_alloc = memory_and_alloc(&isi_hex),
            isi_len = isi_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(&wsv, &account_id, wat, 1, DenyAll::new(), AllowAll::new());

        assert!(res.is_err());
        if let Error::ExportFnCall(trap) = res.unwrap_err() {
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
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        let res = runtime.validate(&wsv, &account_id, wat, 1, AllowAll::new(), DenyAll::new());

        assert!(res.is_err());
        if let Error::ExportFnCall(trap) = res.unwrap_err() {
            assert!(trap
                .display_reason()
                .to_string()
                .starts_with("All operations are denied"));
        }

        Ok(())
    }
}
