//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
pub mod config;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;
mod query_builder;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use url::Url;

    use crate::{
        config::{
            Config, DEFAULT_ADD_TRANSACTION_NONCE, DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            DEFAULT_TRANSACTION_TIME_TO_LIVE,
        },
        crypto::KeyPair,
        data_model::ChainId,
    };

    /// Get sample client configuration.
    pub fn get_client_config(chain_id: ChainId, key_pair: KeyPair, torii_api_url: Url) -> Config {
        Config {
            chain_id,
            key_pair,
            torii_api_url,
            account_id: "alice@wonderland"
                .parse()
                .expect("This account ID should be valid"),
            basic_auth: None,
            transaction_ttl: DEFAULT_TRANSACTION_TIME_TO_LIVE,
            transaction_status_timeout: DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            transaction_add_nonce: DEFAULT_ADD_TRANSACTION_NONCE,
        }
    }
}

pub use iroha_crypto as crypto;
pub use iroha_data_model as data_model;
