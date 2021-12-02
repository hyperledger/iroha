//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
/// Module with iroha client config
pub mod config;
pub use config::Configuration;
mod http_client;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use iroha_crypto::KeyPair;
    use iroha_data_model::uri;

    use super::Configuration;
    /// Get sample client configuration.
    pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
        let (public_key, private_key) = key_pair.clone().into();
        Configuration {
            public_key,
            private_key,
            account_id: iroha_data_model::prelude::AccountId {
                name: "alice".to_owned(),
                domain_name: "wonderland".to_owned(),
            },
            torii_api_url: uri::DEFAULT_API_URL.to_owned(),
            ..Configuration::default()
        }
    }
}
