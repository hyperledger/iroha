//! Module for client-related configuration and structs
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use core::str::FromStr;

use derive_more::Display;
use eyre::{eyre, Result};
use iroha_config_base::derive::{Documented, LoadFromEnv, Proxy};
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, transaction};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};

const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;
const DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_ADD_TRANSACTION_NONCE: bool = false;

/// Wrapper over `SmallStr` to provide basic auth login checking
#[derive(Debug, Display, Clone, Serialize)]
pub struct WebLogin(SmallStr);

impl WebLogin {
    /// Construct new `WebLogin`
    ///
    /// # Errors
    /// Fails if `login` contains `:` character
    pub fn new(login: &str) -> Result<Self> {
        Self::from_str(login)
    }
}

impl FromStr for WebLogin {
    type Err = eyre::ErrReport;
    fn from_str(login: &str) -> Result<Self> {
        if login.contains(':') {
            return Err(eyre!("WebLogin cannot contain the `:` character"));
        }

        Ok(Self(SmallStr::from_str(login)))
    }
}

/// Deserializing `WebLogin` with `FromStr` implementation
impl<'de> Deserialize<'de> for WebLogin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Basic Authentication credentials
#[derive(Clone, Deserialize, Serialize, Debug, Documented)]
pub struct BasicAuth {
    /// Login for Basic Authentication
    pub web_login: WebLogin,
    /// Password for Basic Authentication
    pub password: SmallStr,
}

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
#[derive(Debug, Clone, Deserialize, Serialize, Proxy, LoadFromEnv, Documented)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_")]
pub struct Configuration {
    /// Public key of the user account.
    #[config(serde_as_str)]
    pub public_key: PublicKey,
    /// Private key of the user account.
    pub private_key: PrivateKey,
    /// User account id.
    pub account_id: AccountId,
    /// Basic Authentication credentials
    pub basic_auth: Option<BasicAuth>,
    /// Torii URL.
    pub torii_api_url: SmallStr,
    /// Status URL.
    pub torii_telemetry_url: SmallStr,
    /// Proposed transaction TTL in milliseconds.
    pub transaction_time_to_live_ms: u64,
    /// Transaction status wait timeout in milliseconds.
    pub transaction_status_timeout_ms: u64,
    /// The limits to which transactions must adhere to
    pub transaction_limits: TransactionLimits,
    /// If `true` add nonce, which make different hashes for transactions which occur repeatedly and simultaneously
    pub add_transaction_nonce: bool,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            public_key: None,
            private_key: None,
            account_id: None,
            basic_auth: Some(None),
            torii_api_url: None,
            torii_telemetry_url: None,
            transaction_time_to_live_ms: Some(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS),
            transaction_status_timeout_ms: Some(DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS),
            transaction_limits: Some(TransactionLimits {
                max_instruction_number: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
                max_wasm_size_bytes: transaction::DEFAULT_MAX_WASM_SIZE_BYTES,
            }),
            add_transaction_nonce: Some(DEFAULT_ADD_TRANSACTION_NONCE),
        }
    }
}
