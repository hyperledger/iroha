//! Module for wasm-related configuration and structs.
#![allow(clippy::std_instead_of_core, clippy::arithmetic)]
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use serde::{Deserialize, Serialize};

const DEFAULT_FUEL_LIMIT: u64 = 1_000_000;
const DEFAULT_MAX_MEMORY: u32 = 500 * 2_u32.pow(20); // 500 MiB

/// `WebAssembly Runtime` configuration.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Documented, Proxy, LoadFromEnv,
)]
#[config(env_prefix = "WASM_")]
#[serde(rename_all = "UPPERCASE", default)]
pub struct Configuration {
    /// The fuel limit determines the maximum number of instructions that can be executed during the execution of a smart contract.
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
