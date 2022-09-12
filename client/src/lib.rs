//! Crate contains iroha client which talks to iroha network via http

pub use iroha_config::client::Configuration;

/// Module with iroha client itself
pub mod client;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use iroha_config::torii::uri;
    use iroha_crypto::KeyPair;

    use super::Configuration;

    /// Get sample client configuration.
    #[allow(clippy::expect_used)]
    pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
        let (public_key, private_key) = key_pair.clone().into();
        Configuration {
            public_key,
            private_key,
            account_id: "alice@wonderland".parse().expect("Should not fail."),
            torii_api_url: iroha_primitives::small::SmallStr::from_str(uri::DEFAULT_API_URL),
            ..Configuration::default()
        }
    }
}
