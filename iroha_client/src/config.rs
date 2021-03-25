use std::{env, fmt::Debug, fs::File, io::BufReader, path::Path};

use iroha_crypto::{PrivateKey, PublicKey};
use iroha_dsl::prelude::*;
use iroha_error::{Error, Result, WrapErr};
use iroha_logger::config::LoggerConfiguration;
use serde::Deserialize;

const TORII_API_URL: &str = "TORII_API_URL";
const IROHA_PUBLIC_KEY: &str = "IROHA_PUBLIC_KEY";
const IROHA_PRIVATE_KEY: &str = "IROHA_PRIVATE_KEY";
const TRANSACTION_TIME_TO_LIVE_MS: &str = "TRANSACTION_TIME_TO_LIVE_MS";
const TRANSACTION_STATUS_TIMEOUT: &str = "TRANSACTION_STATUS_TIMEOUT";
const MAX_INSTRUCTION_NUMBER: &str = "MAX_INSTRUCTION_NUMBER";
const ACCOUNT_ID: &str = "IROHA_CLIENT_ACCOUNT_ID";
const DEFAULT_TORII_API_URL: &str = "127.0.0.1:8080";
const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;
const DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS: u64 = 3000;
const DEFAULT_MAX_INSTRUCTION_NUMBER: usize = 4096;

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
// TODO: design macro to load config from env.
#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Public key of the user account.
    pub public_key: PublicKey,
    /// Private key of the user account.
    pub private_key: PrivateKey,
    /// User account id.
    pub account_id: AccountId,
    /// Torii URL.
    #[serde(default = "default_torii_api_url")]
    pub torii_api_url: String,
    /// Proposed transaction TTL in milliseconds.
    #[serde(default = "default_transaction_time_to_live_ms")]
    pub transaction_time_to_live_ms: u64,
    /// `Logger` configuration.
    pub logger_configuration: LoggerConfiguration,
    /// Transaction status wait timeout in milliseconds.
    #[serde(default = "default_transaction_status_timeout_ms")]
    pub transaction_status_timeout_ms: u64,
    /// Maximum number of instructions per transaction
    #[serde(default = "default_max_instruction_number")]
    pub max_instruction_number: usize,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Configuration> {
        let file = File::open(path).wrap_err("Failed to open a file")?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")
    }

    /// Load environment variables and replace predefined parameters with these variables
    /// values.
    ///
    /// # Errors
    /// Fails if parsing environment fails
    pub fn load_environment(&mut self) -> Result<()> {
        self.logger_configuration
            .load_environment()
            .map_err(Error::msg)?;
        if let Ok(torii_api_url) = env::var(TORII_API_URL) {
            self.torii_api_url = torii_api_url;
        }
        if let Ok(public_key) = env::var(IROHA_PUBLIC_KEY) {
            self.public_key = serde_json::from_value(serde_json::json!(public_key))
                .wrap_err("Failed to parse Public Key")?;
        }
        if let Ok(private_key) = env::var(IROHA_PRIVATE_KEY) {
            self.private_key =
                serde_json::from_str(&private_key).wrap_err("Failed to parse Private Key")?;
        }
        if let Ok(proposed_transaction_ttl_ms) = env::var(TRANSACTION_TIME_TO_LIVE_MS) {
            self.transaction_time_to_live_ms =
                serde_json::from_str(&proposed_transaction_ttl_ms)
                    .wrap_err("Failed to parse proposed transaction ttl")?;
        }
        if let Ok(transaction_status_timeout_ms) = env::var(TRANSACTION_STATUS_TIMEOUT) {
            self.transaction_status_timeout_ms =
                serde_json::from_str(&transaction_status_timeout_ms)
                    .wrap_err("Failed to parse transaction status timeout")?;
        }
        if let Ok(account_id) = env::var(ACCOUNT_ID) {
            self.account_id =
                serde_json::from_str(&account_id).wrap_err("Failed to parse account id")?;
        }
        if let Ok(max_instruction_number) = env::var(MAX_INSTRUCTION_NUMBER) {
            self.max_instruction_number = max_instruction_number
                .parse::<usize>()
                .wrap_err("Failed to parse maximum number of instructions per transaction")?;
        }
        Ok(())
    }
}

fn default_torii_api_url() -> String {
    DEFAULT_TORII_API_URL.to_string()
}

const fn default_transaction_time_to_live_ms() -> u64 {
    DEFAULT_TRANSACTION_TIME_TO_LIVE_MS
}

const fn default_transaction_status_timeout_ms() -> u64 {
    DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS
}

const fn default_max_instruction_number() -> usize {
    DEFAULT_MAX_INSTRUCTION_NUMBER
}
