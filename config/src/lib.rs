//! Aggregate configuration for different iroha's modules.

pub use iroha_config_base as base;

pub mod block_sync;
pub mod client;
pub mod genesis;
pub mod iroha;
pub mod kura;
pub mod logger;
pub mod network;
pub mod queue;
pub mod sumeragi;
pub mod telemetry;
pub mod torii;
pub mod wasm;
pub mod wsv;
