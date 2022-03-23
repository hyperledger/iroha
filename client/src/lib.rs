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
    #[allow(clippy::expect_used)]
    pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
        let (public_key, private_key) = key_pair.clone().into();
        Configuration {
            public_key,
            private_key,
            account_id: "alice@wonderland".parse().expect("Should not fail."),
            torii_api_url: iroha_data_model::small::SmallStr::from_str(uri::DEFAULT_API_URL),
            ..Configuration::default()
        }
    }
}
