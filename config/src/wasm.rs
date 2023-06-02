//! Module for wasm-related configuration and structs.
#![allow(clippy::std_instead_of_core, clippy::arithmetic_side_effects)]
use iroha_config_base::{Configuration, Documented};
use serde::{Deserialize, Serialize};

/// `WebAssembly Runtime` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Documented, Configuration)]
#[serde(try_from = "ConfigurationBuilder")]
#[config(env_prefix = "WASM_")]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// The fuel limit determines the maximum number of instructions that can be executed within a smart contract.
    /// Every WASM instruction costs approximately 1 unit of fuel. See
    /// [`wasmtime` reference](https://docs.rs/wasmtime/0.29.0/wasmtime/struct.Store.html#method.add_fuel)
    #[config(default = "23_000_000")]
    fuel_limit: u64,
    /// Maximum amount of linear memory a given smart contract can allocate.
    #[config(default = "500 * 2_u32.pow(20)")] // 500 MiB
    max_memory: u32,
}
