//! Crate contains client which talks to Iroha network via http

pub mod client;
pub mod config;
pub mod http;
mod http_default;
pub mod query;

pub mod samples {
    //! Module containing sample configurations for tests and benchmarks.

    use eyre::Result;
    use iroha_telemetry::metrics::Status;
    use url::Url;

    use crate::{
        client::{Client, StatusResponseHandler},
        config::{
            Config, DEFAULT_TRANSACTION_NONCE, DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            DEFAULT_TRANSACTION_TIME_TO_LIVE,
        },
        crypto::KeyPair,
        data_model::ChainId,
        http_default::DefaultRequestBuilder,
    };

    /// Get sample client configuration.
    pub fn get_client_config(chain_id: ChainId, key_pair: KeyPair, torii_api_url: Url) -> Config {
        let account_id = format!("{}@wonderland", key_pair.public_key())
            .parse()
            .expect("should be valid");
        Config {
            chain: chain_id,
            key_pair,
            torii_api_url,
            account: account_id,
            basic_auth: None,
            transaction_ttl: DEFAULT_TRANSACTION_TIME_TO_LIVE,
            transaction_status_timeout: DEFAULT_TRANSACTION_STATUS_TIMEOUT,
            transaction_add_nonce: DEFAULT_TRANSACTION_NONCE,
        }
    }

    /// Gets network status seen from the peer in json format
    ///
    /// # Errors
    /// Fails if sending request or decoding fails
    pub fn get_status_json(client: &Client) -> Result<Status> {
        let req = client.prepare_status_request::<DefaultRequestBuilder>();
        let resp = req.build()?.send()?;
        StatusResponseHandler::handle(&resp)
    }
}

pub use iroha_crypto as crypto;
pub use iroha_data_model as data_model;
