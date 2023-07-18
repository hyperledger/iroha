//! Crate contains iroha client which talks to iroha network via http
#![deny(
    clippy::pedantic,
    clippy::correctness,
    clippy::style,
    clippy::suspicious,
    clippy::perf,
    clippy::unwrap_used,
    clippy::todo,
    clippy::dbg_macro,
    clippy::unused_peekable,
    clippy::empty_line_after_outer_attr,
    clippy::derive_partial_eq_without_eq,
    missing_docs,
    variant_size_differences,
    unused_tuple_struct_fields,
    explicit_outlives_requirements,
    non_ascii_idents,
    unreachable_pub
)]
#![allow(clippy::implicit_return, clippy::wildcard_imports)]

/// Module with iroha client itself
pub mod client;
/// Module with general communication primitives like an HTTP request builder.
pub mod http;
mod http_default;

/// Module containing sample configurations for tests and benchmarks.
pub mod samples {
    use iroha_config::{
        client::{Configuration, ConfigurationProxy},
        torii::{uri::DEFAULT_API_ADDR, DEFAULT_TORII_TELEMETRY_ADDR},
    };
    use iroha_crypto::KeyPair;

    /// Get sample client configuration.
    #[must_use]
    #[inline]
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
            torii_telemetry_url: Some(
                format!("http://{DEFAULT_TORII_TELEMETRY_ADDR}")
                    .parse()
                    .expect("Should be a valid url"),
            ),
            ..ConfigurationProxy::default()
        }
        .build()
            .expect("Client config should build as all required fields were provided")
    }
}
