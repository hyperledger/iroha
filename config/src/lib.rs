//! Aggregate configuration for different Iroha modules.

pub use iroha_config_base as base;
use serde::{Deserialize, Serialize};

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

/// Json config for getting configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum GetConfiguration {
    /// Getting docs of specific field
    ///
    /// Top-level fields must be enclosed in an array (of strings). This array
    /// provides the fully qualified path to the fields.
    ///
    /// # Examples
    ///
    /// To get the top-level configuration docs for `iroha_core::Torii`
    /// `curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["torii"]} ' -i`
    ///
    /// To get the documentation on the [`Logger::config::Configuration.max_log_level`]
    /// `curl -X GET -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"Docs" : ["logger", "max_log_level"]}' -i`
    Docs(Vec<String>),
    /// Get the original Value of the full configuration.
    Value,
}

/// Message acceptable for `POST` requests to the configuration endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, Copy)]
pub enum PostConfiguration {
    /// Change the maximum logging level of logger.
    ///
    /// # Examples
    ///
    /// To silence all logging events that aren't `ERROR`s
    /// `curl -X POST -H 'content-type: application/json' http://127.0.0.1:8080/configuration -d '{"LogLevel": "ERROR"}' -i`
    LogLevel(logger::Level),
}
