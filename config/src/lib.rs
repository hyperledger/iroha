//! Aggregate configuration for different Iroha modules.
pub use iroha_config_base as base;

pub mod block_sync;
pub mod client;
pub mod client_api;
pub mod genesis;
pub mod iroha;
pub mod kura;
pub mod live_query_store;
pub mod logger;
pub mod network;
pub mod path;
pub mod queue;
pub mod snapshot;
pub mod sumeragi;
pub mod telemetry;
pub mod torii;
pub mod wasm;
pub mod wsv;
