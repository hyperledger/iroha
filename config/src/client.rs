//! Module for client-related configuration and structs
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]
use core::str::FromStr;

use derive_more::Display;
use eyre::{Result, WrapErr};
use iroha_config_base::derive::{Documented, Error as ConfigError, LoadFromEnv, Proxy};
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, transaction};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};

const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;
const DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_ADD_TRANSACTION_NONCE: bool = false;

/// Wrapper over `SmallStr` to provide basic auth login checking
#[derive(Debug, Display, Clone, Serialize, PartialEq, Eq)]
pub struct WebLogin(SmallStr);

impl WebLogin {
    /// Construct new [`Self`]
    ///
    /// # Errors
    /// Fails if `login` contains `:` character, which is the binary representation of the '\0'.
    pub fn new(login: &str) -> Result<Self> {
        Self::from_str(login)
    }
}

impl FromStr for WebLogin {
    type Err = eyre::ErrReport;
    fn from_str(login: &str) -> Result<Self> {
        if login.contains(':') {
            eyre::bail!("The `:` character, in `{login}` is not allowed");
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
#[derive(Clone, Deserialize, Serialize, Debug, Documented, PartialEq, Eq)]
pub struct BasicAuth {
    /// Login for Basic Authentication
    pub web_login: WebLogin,
    /// Password for Basic Authentication
    pub password: SmallStr,
}

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
#[derive(Debug, Clone, Deserialize, Serialize, Proxy, LoadFromEnv, Documented, PartialEq, Eq)]
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

// TODO: explain why these values were chosen.
const TTL_TOO_SMALL_THRESHOLD: u64 = 500;
const WASM_SIZE_TOO_SMALL_THRESHOLD: u64 = 2_u64.pow(10); // 1 KiB

impl ConfigurationProxy {
    /// Finalise Iroha client config proxy by checking that certain fields identify reasonable limits or
    /// are well formatted.
    ///
    /// # Errors
    /// - If the [`self.transaction_time_to_live_ms`] or [`self.transaction_limits.max_wasm_size_bytes`] fields were too small
    /// - If the [`self.transaction_status_timeout_ms`] field was smaller than [`self.transaction_time_to_live_ms`]
    /// - If the [`self.torii_api_url`] or [`self.torii_telemetry_url`] were malformed or had the wrong protocol
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn finish(&mut self) -> Result<()> {
        if let Some(tx_ttl) = self.transaction_time_to_live_ms {
            // Really small TTL would be detrimental to performance
            if tx_ttl < TTL_TOO_SMALL_THRESHOLD {
                eyre::bail!(
                    ConfigError::ProxyBuildError("`TRANSACTION_TIME_TO_LIVE_MS`, network throughput may be compromised for values less than {TTL_TOO_SMALL_THRESHOLD}".to_owned())
                );
            }
            // Timeouts bigger than transaction TTL don't make sense as then transaction would be discarded before this timeout
            if let Some(timeout) = self.transaction_status_timeout_ms {
                if timeout > tx_ttl {
                    eyre::bail!(ConfigError::ProxyBuildError("`TRANSACTION_STATUS_TIMEOUT_MS`: {timeout} bigger than `TRANSACTION_TIME_TO_LIVE_MS`: {self.transaction_status_timeout_ms}. Consider making it smaller".to_owned()));
                }
            }
        }
        if let Some(tx_limits) = self.transaction_limits {
            if tx_limits.max_wasm_size_bytes < WASM_SIZE_TOO_SMALL_THRESHOLD {
                eyre::bail!(ConfigError::ProxyBuildError("`TRANSACTION_LIMITS` parameter's `max_wasm_size` field too small at {tx_limits.max_wasm_size_bytes}. Consider making it bigger than {WASM_SIZE_TOO_SMALL_THRESHOLD}".to_owned()));
            }
        }
        if let Some(api_url) = &self.torii_api_url {
            let api_url = api_url.clone().to_string();
            let split_api_url = api_url.split("://").collect::<Vec<_>>();
            if split_api_url.len() != 2 {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "`TORII_API_URL` string: `{api_url}` should provide a connection protocol"
                        .to_owned()
                ));
            }
            // TODO: this is neither robust, nor useful. This should be enforced as a `FromStr` implementation.
            if split_api_url[0] != "http" {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "`TORII_API_URL` string: `{api_url}` only supports the `HTTP` protocol currently".to_owned()
                ));
            }
        }
        if let Some(telemetry_url) = &self.torii_telemetry_url {
            let telemetry_url = telemetry_url.clone().to_string();
            let split_telemetry_url = telemetry_url.split("://").collect::<Vec<_>>();
            if split_telemetry_url.len() != 2 {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "`TORII_TELEMETRY_URL` string: `{telemetry_url}` should provide a connection protocol".to_owned()
                ));
            }
            if split_telemetry_url[0] != "http" {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "`TORII_TELEMETRY_URL` string: `{telemetry_url}` only supports HTTP".to_owned()
                ));
            }
            if split_telemetry_url[1].split(':').count() != 2 {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "`TORII_TELEMETRY_URL` string: `{telemetry_url}` should provide a connection port, e.g. `http://127.0.0.1:8180`".to_owned()
                ));
            }
        }
        Ok(())
    }

    /// The wrapper around the client `ConfigurationProxy` that performs
    /// finalisation prior to building `Configuration`. Just like
    /// Iroha peer config, its `<Self as iroha_config_base::proxy::Builder>::build()`
    /// method should never be used directly, as only this wrapper ensures final
    /// coherence and fails if there are any issues.
    ///
    /// # Errors
    /// - Finalisation fails
    /// - Building fails, e.g. any of the inner fields had a `None` value when that
    /// is not allowed by the defaults.
    pub fn build(mut self) -> Result<Configuration> {
        self.finish()?;
        <Self as iroha_config_base::proxy::Builder>::build(self)
            .wrap_err("Failed to build `Configuration` from `ConfigurationProxy`")
    }
}

#[cfg(test)]
mod tests {
    use iroha_config_base::proxy::LoadFromDisk;
    use iroha_crypto::KeyGenConfiguration;
    use proptest::prelude::*;

    use super::*;
    use crate::torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_TELEMETRY_URL};

    const CONFIGURATION_PATH: &str = "../configs/client_cli/config.json";

    prop_compose! {
        // TODO: make tests to check generated key validity
        #[allow(clippy::expect_used)]
        fn arb_keys_from_seed()
            (seed in prop::collection::vec(any::<u8>(), 33..64)) -> (PublicKey, PrivateKey) {
                let (public_key, private_key) = KeyPair::generate_with_configuration(KeyGenConfiguration::default().use_seed(seed)).expect("Seed was invalid").into();
                (public_key, private_key)
            }
    }

    prop_compose! {
        #[allow(clippy::expect_used)]
        fn arb_keys_with_option()
            (keys in arb_keys_from_seed())
            ((a, b) in (prop::option::of(Just(keys.0)), prop::option::of(Just(keys.1))))
            -> (Option<PublicKey>, Option<PrivateKey>) {
                (a, b)
            }
    }

    #[allow(clippy::expect_used)]
    fn placeholder_account() -> <Account as Identifiable>::Id {
        AccountId::from_str("alice@wonderland").expect("Invalid account Id ")
    }

    prop_compose! {
        fn arb_proxy()
            (
                (public_key, private_key) in arb_keys_with_option(),
                account_id in prop::option::of(Just(placeholder_account())),
                basic_auth in prop::option::of(Just(None)),
                torii_api_url in prop::option::of(Just(SmallStr::from_str(DEFAULT_API_URL))),
                torii_telemetry_url in prop::option::of(Just(SmallStr::from_str(DEFAULT_TORII_TELEMETRY_URL))),
                transaction_time_to_live_ms in prop::option::of(Just(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS)),
                transaction_status_timeout_ms in prop::option::of(Just(DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS)),
                transaction_limits in prop::option::of(Just(TransactionLimits {
                    max_instruction_number: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
                    max_wasm_size_bytes: transaction::DEFAULT_MAX_WASM_SIZE_BYTES,
                })),
                add_transaction_nonce in prop::option::of(Just(DEFAULT_ADD_TRANSACTION_NONCE)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { public_key, private_key, account_id, basic_auth, torii_api_url, torii_telemetry_url, transaction_time_to_live_ms, transaction_status_timeout_ms, transaction_limits, add_transaction_nonce }
        }
    }

    proptest! {
        #[test]
        #[allow(clippy::expect_used, clippy::unwrap_used)]
        fn client_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            if cfg.is_ok() {
                let example_cfg = ConfigurationProxy::from_path(CONFIGURATION_PATH)
                    .expect("Failed to read example config file").build().expect("Failed to build example Iroha config");
                let arb_cfg = cfg.unwrap();
                // Skipping keys and `basic_auth` check as they're different from the file
                assert_eq!(arb_cfg.torii_api_url, example_cfg.torii_api_url);
                assert_eq!(arb_cfg.torii_telemetry_url, example_cfg.torii_telemetry_url);
                assert_eq!(arb_cfg.account_id, example_cfg.account_id);
                assert_eq!(arb_cfg.transaction_time_to_live_ms, example_cfg.transaction_time_to_live_ms);
                assert_eq!(arb_cfg.transaction_status_timeout_ms, example_cfg.transaction_status_timeout_ms);
                assert_eq!(arb_cfg.transaction_limits, example_cfg.transaction_limits);
                assert_eq!(arb_cfg.add_transaction_nonce, example_cfg.add_transaction_nonce);
            }
        }
    }
}
