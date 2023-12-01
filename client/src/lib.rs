//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use crate::{
        config::{torii::DEFAULT_API_ADDR, Configuration, ConfigurationProxy},
        crypto::KeyPair,
    };

    /// Get sample client configuration.
    pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
        let (public_key, private_key) = key_pair.clone().into();
        ConfigurationProxy {
            public_key: Some(public_key),
            private_key: Some(private_key),
            account_id: Some(
                "alice@wonderland"
                    .parse()
                    .expect("This account ID should be valid"),
            ),
            torii_api_url: Some(
                format!("http://{DEFAULT_API_ADDR}")
                    .parse()
                    .expect("Should be a valid url"),
            ),
            ..ConfigurationProxy::default()
        }
        .build()
        .expect("Client config should build as all required fields were provided")
    }
}

pub mod config {
    //! Module for client-related configuration and structs

    pub use iroha_config::{client::*, path, torii::uri as torii};
}

pub use iroha_crypto as crypto;
pub use iroha_data_model as data_model;
