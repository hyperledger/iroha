//! This module contains logic related to executing smartcontracts via `WebAssembly` VM
//! Smartcontracts can be written in Rust, compiled to wasm format and submitted in a transaction

use eyre::WrapErr;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use parity_scale_codec::{Decode, Encode};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, Trap, TypedFunc};

use crate::{
    smartcontracts::{Execute, ValidQuery},
    wsv::{WorldStateView, WorldTrait},
};

const WASM_ALLOC_FN: &str = "alloc";
const WASM_MEMORY_NAME: &str = "memory";
const WASM_MAIN_FN_NAME: &str = "main";
const EXECUTE_ISI_FN_NAME: &str = "execute_isi";
const EXECUTE_QUERY_FN_NAME: &str = "execute_query";

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
    /// Call to function exported from module failed
    #[error("Exported function call failed")]
    ExportFnCall(#[source] Trap),
    /// Some other error happened
    #[error(transparent)]
    Other(eyre::Error),
}

struct State<'wsv_life, W: WorldTrait> {
    wsv: &'wsv_life WorldStateView<W>,
    account_id: AccountId,

    /// Number of instructions in the smartcontract
    instruction_count: u64,
}

impl<'wsv_life, W: WorldTrait> State<'wsv_life, W> {
    fn new(wsv: &'wsv_life WorldStateView<W>, account_id: AccountId) -> Self {
        Self {
            wsv,
            account_id,
            instruction_count: 0,
        }
    }
}

/// `WebAssembly` virtual machine
pub struct Runtime<'wsv_life, W: WorldTrait> {
    engine: Engine,
    linker: Linker<State<'wsv_life, W>>,
}

impl<'wsv_life, W: WorldTrait> Runtime<'wsv_life, W> {
    /// Every WASM instruction costs approximately 1 unit of fuel. See
    /// [`wasmtime` reference](https://docs.rs/wasmtime/0.29.0/wasmtime/struct.Store.html#method.add_fuel)
    const FUEL_LIMIT: u64 = 10_000;

    fn create_config() -> Config {
        let mut config = Config::new();
        config.consume_fuel(true);
        //config.cache_config_load_default();
        config
    }

    fn create_engine(config: &Config) -> Result<Engine, Error> {
        Engine::new(config).map_err(Error::Initialization)
    }

    /// Host defined function which executes query. When calling this function, module
    /// serializes query to linear memory and provides offset and length as parameters
    ///
    /// # Errors
    ///
    /// If decoding or execution of the query fails
    fn execute_query(
        mut caller: Caller<State<W>>,
        offset: u32,
        len: u32,
    ) -> Result<(u32, u32), Trap> {
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let query_mem_range = offset as usize..(offset + len) as usize;
        let mut query_bytes = &memory.data(&caller)[query_mem_range];
        let query =
            QueryBox::decode(&mut query_bytes).map_err(|error| Trap::new(error.to_string()))?;

        let res_bytes = query
            .execute(caller.data().wsv)
            .map_err(|e| Trap::new(e.to_string()))?
            .encode();

        let res_bytes_len: u32 = {
            let res_bytes_len: Result<u32, _> = res_bytes.len().try_into();
            res_bytes_len.map_err(|error| Trap::new(error.to_string()))?
        };

        let res_offset = {
            let res_offset = alloc_fn
                .call(&mut caller, res_bytes_len)
                .map_err(|e| Trap::new(e.to_string()))?;

            let res_mem_range = res_offset as usize..res_offset as usize + res_bytes.len();
            memory.data_mut(&mut caller)[res_mem_range].copy_from_slice(&res_bytes[..]);

            res_offset
        };

        Ok((res_offset, res_bytes_len))
    }

    /// Host defined function which executes ISI. When calling this function, module
    /// serializes ISI to linear memory and provides offset and length as parameters
    ///
    /// # Errors
    ///
    /// If decoding or execution of the ISI fails
    fn execute_isi(mut caller: Caller<State<W>>, offset: u32, len: u32) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let isi_mem_range = offset as usize..(offset + len) as usize;
        let mut isi_bytes = &memory.data(&caller)[isi_mem_range];
        let instruction =
            Instruction::decode(&mut isi_bytes).map_err(|error| Trap::new(error.to_string()))?;

        instruction
            .execute(caller.data().account_id.clone(), caller.data().wsv)
            .map_err(|error| Trap::new(error.to_string()))?;

        caller.data_mut().instruction_count += 1;

        Ok(())
    }

    fn create_linker(engine: &Engine) -> Result<Linker<State<'wsv_life, W>>, Error> {
        let mut linker = Linker::new(engine);

        linker
            .func_wrap("iroha", EXECUTE_ISI_FN_NAME, Self::execute_isi)
            .map_err(Error::Initialization)?;

        linker
            .func_wrap("iroha", EXECUTE_QUERY_FN_NAME, Self::execute_query)
            .map_err(Error::Initialization)?;

        Ok(linker)
    }

    fn get_alloc_fn(caller: &mut Caller<State<W>>) -> Result<TypedFunc<u32, u32>, Trap> {
        caller
            .get_export(WASM_ALLOC_FN)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_ALLOC_FN)))?
            .into_func()
            .ok_or_else(|| Trap::new(format!("{}: not a function", WASM_ALLOC_FN)))?
            .typed::<u32, u32, _>(caller)
            .map_err(|_error| Trap::new(format!("{}: unexpected declaration", WASM_ALLOC_FN)))
    }

    fn get_memory(caller: &mut Caller<State<W>>) -> Result<wasmtime::Memory, Trap> {
        caller
            .get_export(WASM_MEMORY_NAME)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_MEMORY_NAME)))?
            .into_memory()
            .ok_or_else(|| Trap::new(format!("{}: not a memory", WASM_MEMORY_NAME)))
    }

    /// `Runtime` constructor
    ///
    /// # Errors
    ///
    /// If unable to construct runtime
    pub fn new() -> Result<Self, Error> {
        let config = Self::create_config();
        let engine = Self::create_engine(&config)?;
        let linker = Self::create_linker(&engine)?;

        Ok(Self { engine, linker })
    }

    /// Executes the given wasm smartcontract
    ///
    /// # Errors
    ///
    /// If unable to construct wasm module or instance of wasm module, if unable to add fuel limit,
    /// if unable to find expected exports(main, memory, allocator) or if the execution of the
    /// smartcontract fails
    pub fn execute(
        &mut self,
        wsv: &WorldStateView<W>,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let account_bytes = account_id.encode();

        let module = Module::new(&self.engine, bytes).map_err(Error::Instantiation)?;
        let mut store = Store::new(&self.engine, State::new(wsv, account_id));
        store
            .add_fuel(Self::FUEL_LIMIT)
            .map_err(Error::Instantiation)?;

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(Error::Instantiation)?;
        let alloc_fn = instance
            .get_typed_func::<u32, u32, _>(&mut store, WASM_ALLOC_FN)
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
            .wrap_err("Scale encoded account ID has size larger than u32::MAX")
            .map_err(Error::Other)?;

        let account_offset = {
            let acc_offset = alloc_fn
                .call(&mut store, account_bytes_len)
                .map_err(Error::ExportFnCall)?;

            let acc_mem_range = acc_offset as usize..acc_offset as usize + account_bytes.len();
            memory.data_mut(&mut store)[acc_mem_range].copy_from_slice(&account_bytes[..]);

            acc_offset
        };

        let main = instance
            .get_typed_func::<(u32, u32), (), _>(&mut store, WASM_MAIN_FN_NAME)
            .map_err(Error::ExportNotFound)?;

        main.call(&mut store, (account_offset, account_bytes_len))
            .map_err(Error::ExportFnCall)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{DomainsMap, PeersIds, World};

    fn world_with_test_account(account_id: AccountId) -> World {
        let domain_id = account_id.domain_id.clone();
        let public_key = KeyPair::generate().unwrap().public_key;
        let account = Account::with_signatory(account_id, public_key);
        let domain = Domain::with_accounts(domain_id.name.as_ref(), std::iter::once(account));

        let domains = DomainsMap::new();
        domains.insert(domain_id, domain);
        World::with(domains, PeersIds::new())
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
                    (i32.add (global.get $mem_size) (local.get $size))
                )
            )
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
        let account_id = AccountId::test("alice", "wonderland");
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::test("mad_hatter", "wonderland");
            let register_isi = RegisterBox::new(NewAccount::new(new_account_id));
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
        runtime.execute(&wsv, account_id, wat)?;

        Ok(())
    }

    #[test]
    fn execute_query_exported() -> Result<(), Error> {
        let account_id = AccountId::test("alice", "wonderland");
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
                    (func $exec_fn (param i32 i32) (result i32 i32))
                )

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return values
                    drop drop
                )
            )
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        runtime.execute(&wsv, account_id, wat)?;

        Ok(())
    }
}
