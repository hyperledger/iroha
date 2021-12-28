use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config::derive::Configurable;
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::{prelude::*, transaction};
use iroha_logger::Configuration as LoggerConfiguration;
use serde::{Deserialize, Serialize};

const DEFAULT_TORII_TELEMETRY_URL: &str = "127.0.0.1:8180";
const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;
const DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_ADD_TRANSACTION_NONCE: bool = false;

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
// TODO: design macro to load config from env.
#[derive(Clone, Deserialize, Serialize, Debug, Configurable)]
#[serde(rename_all = "UPPERCASE")]
#[serde(default)]
#[config(env_prefix = "IROHA_")]
pub struct Configuration {
    /// Public key of the user account.
    #[config(serde_as_str)]
    pub public_key: PublicKey,
    /// Private key of the user account.
    pub private_key: PrivateKey,
    /// User account id.
    pub account_id: AccountId,
    /// Torii URL.
    pub torii_api_url: String,
    /// Status URL.
    pub torii_telemetry_url: String,
    /// Proposed transaction TTL in milliseconds.
    pub transaction_time_to_live_ms: u64,
    /// Transaction status wait timeout in milliseconds.
    pub transaction_status_timeout_ms: u64,
    /// Maximum number of instructions per transaction
    pub max_instruction_number: u64,
    /// If `true` add nonce, which make different hashes for transactions which occur repeatedly and simultaneously
    pub add_transaction_nonce: bool,
    /// `Logger` configuration.
    #[config(inner)]
    pub logger_configuration: LoggerConfiguration,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            public_key: PublicKey::default(),
            private_key: PrivateKey::default(),
            account_id: AccountId::test("", ""),
            torii_api_url: uri::DEFAULT_API_URL.to_owned(),
            torii_telemetry_url: DEFAULT_TORII_TELEMETRY_URL.to_owned(),
            transaction_time_to_live_ms: DEFAULT_TRANSACTION_TIME_TO_LIVE_MS,
            transaction_status_timeout_ms: DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS,
            max_instruction_number: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
            add_transaction_nonce: DEFAULT_ADD_TRANSACTION_NONCE,
            logger_configuration: LoggerConfiguration::default(),
        }
    }
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    ///
    /// # Panics
    /// If configuration file present, but has incorrect format.
    ///
    /// # Errors
    /// If system  fails to find a file or read it's content.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Configuration> {
        let file = File::open(path).wrap_err("Failed to open the config file")?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")
    }
}
