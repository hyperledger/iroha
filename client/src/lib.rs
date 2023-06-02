//! Crate contains iroha client which talks to iroha network via http

/// Module with iroha client itself
pub mod client;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use iroha_config::{
        client::{Configuration, ConfigurationBuilder},
        torii::Configuration as ToriiConfig,
    };
    use iroha_crypto::KeyPair;

    /// Get sample client configuration.
    #[allow(clippy::expect_used)]
    pub fn get_client_config(key_pair: &KeyPair) -> Configuration {
        let (public_key, private_key) = key_pair.clone().into();
        let mut config = ConfigurationBuilder::default();

        config.set_public_key(public_key);
        config.set_private_key(private_key);
        config.set_account_id("alice@wonderland".parse().unwrap());
        config.set_torii_api_url(
            format!("http://{}", ToriiConfig::DEFAULT_API_URL())
                .parse()
                .unwrap(),
        );
        config.set_torii_telemetry_url(
            format!("http://{}", ToriiConfig::DEFAULT_TELEMETRY_URL())
                .parse()
                .unwrap(),
        );

        config.build().expect("Infallible")
    }
}
