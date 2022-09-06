//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use iroha_config::{
        base::proxy::Builder,
        client::{Configuration, ConfigurationProxy},
        torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_TELEMETRY_URL},
    };
    use iroha_crypto::KeyPair;
    use iroha_primitives::small::SmallStr;

    /// Get sample client configuration.
    #[allow(clippy::expect_used)]
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
            torii_api_url: Some(SmallStr::from_str(DEFAULT_API_URL)),
            torii_telemetry_url: Some(SmallStr::from_str(DEFAULT_TORII_TELEMETRY_URL)),
            ..ConfigurationProxy::default()
        }
        .build()
        .expect("Client config should build as all required fields were provided")
    }
}
