//! Module for client-related configuration and structs
use core::str::FromStr;
use std::num::NonZeroU64;

use derive_more::Display;
use eyre::{Result, WrapErr};
use iroha_config_base::derive::{Error as ConfigError, Proxy};
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, transaction::TransactionLimits};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::wsv::default::DEFAULT_TRANSACTION_LIMITS;

#[allow(unsafe_code)]
const DEFAULT_TRANSACTION_TIME_TO_LIVE_MS: NonZeroU64 =
    unsafe { NonZeroU64::new_unchecked(100_000) };
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
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct BasicAuth {
    /// Login for Basic Authentication
    pub web_login: WebLogin,
    /// Password for Basic Authentication
    pub password: SmallStr,
}

/// `Configuration` provides an ability to define client parameters such as `TORII_URL`.
#[derive(Debug, Clone, Deserialize, Serialize, Proxy, PartialEq, Eq)]
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
    pub torii_api_url: Url,
    /// Proposed transaction TTL in milliseconds.
    pub transaction_time_to_live_ms: Option<NonZeroU64>,
    /// Transaction status wait timeout in milliseconds.
    pub transaction_status_timeout_ms: u64,
    /// The limits to which transactions must adhere to
    // NOTE: If you want this functionality, implement it in the app manually
    #[deprecated(
        note = "This parameter is not used and takes no effect and will be removed in future releases. \
        If you want this functionality, implement it in the app manually."
    )]
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
            transaction_time_to_live_ms: Some(Some(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS)),
            transaction_status_timeout_ms: Some(DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS),
            transaction_limits: Some(DEFAULT_TRANSACTION_LIMITS),
            add_transaction_nonce: Some(DEFAULT_ADD_TRANSACTION_NONCE),
        }
    }
}

// TODO: explain why these values were chosen.
const TTL_TOO_SMALL_THRESHOLD: u64 = 500;

impl ConfigurationProxy {
    /// Finalise Iroha client config proxy by checking that certain fields identify reasonable limits or
    /// are well formatted.
    ///
    /// # Errors
    /// - If the [`self.transaction_time_to_live_ms`] field is too small
    /// - If the [`self.transaction_status_timeout_ms`] field is smaller than [`self.transaction_time_to_live_ms`]
    /// - If the [`self.torii_api_url`] is malformed or had the wrong protocol
    pub fn finish(&mut self) -> Result<()> {
        if let Some(Some(tx_ttl)) = self.transaction_time_to_live_ms {
            // Really small TTL would be detrimental to performance
            if u64::from(tx_ttl) < TTL_TOO_SMALL_THRESHOLD {
                eyre::bail!(ConfigError::InsaneValue {
                    field: "TRANSACTION_TIME_TO_LIVE_MS",
                    value: tx_ttl.to_string(),
                    message: format!(", because if it's smaller than {TTL_TOO_SMALL_THRESHOLD}, Iroha wouldn't be able to produce blocks on time.")
                });
            }
            // Timeouts bigger than transaction TTL don't make sense as then transaction would be discarded before this timeout
            if let Some(timeout) = self.transaction_status_timeout_ms {
                if timeout > tx_ttl.into() {
                    eyre::bail!(ConfigError::InsaneValue {
                        field: "TRANSACTION_STATUS_TIMEOUT_MS",
                        value: timeout.to_string(),
                        message: format!(", because it should be smaller than `TRANSACTION_TIME_TO_LIVE_MS`, which is {tx_ttl}")
                    })
                }
            }
        }
        if let Some(api_url) = &self.torii_api_url {
            if api_url.scheme() != "http" {
                eyre::bail!(ConfigError::InsaneValue {
                    field: "TORII_API_URL",
                    value: api_url.to_string(),
                    message: ", because we only support HTTP".to_owned(),
                });
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
    use crate::torii::uri::DEFAULT_API_ADDR;

    const CONFIGURATION_PATH: &str = "../configs/client/config.json";

    prop_compose! {
        // TODO: make tests to check generated key validity
        fn arb_keys_from_seed()
            (seed in prop::collection::vec(any::<u8>(), 33..64)) -> (PublicKey, PrivateKey) {
                let (public_key, private_key) = KeyPair::generate_with_configuration(KeyGenConfiguration::default().use_seed(seed)).expect("Seed was invalid").into();
                (public_key, private_key)
            }
    }

    prop_compose! {
        fn arb_keys_with_option()
            (keys in arb_keys_from_seed())
            ((a, b) in (prop::option::of(Just(keys.0)), prop::option::of(Just(keys.1))))
            -> (Option<PublicKey>, Option<PrivateKey>) {
                (a, b)
            }
    }

    fn placeholder_account() -> AccountId {
        AccountId::from_str("alice@wonderland").expect("Invalid account Id ")
    }

    prop_compose! {
        fn arb_proxy()
            (
                (public_key, private_key) in arb_keys_with_option(),
                account_id in prop::option::of(Just(placeholder_account())),
                basic_auth in prop::option::of(Just(None)),
                torii_api_url in prop::option::of(Just(format!("http://{DEFAULT_API_ADDR}").parse().unwrap())),
                transaction_time_to_live_ms in prop::option::of(Just(Some(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS))),
                transaction_status_timeout_ms in prop::option::of(Just(DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS)),
                transaction_limits in prop::option::of(Just(DEFAULT_TRANSACTION_LIMITS)),
                add_transaction_nonce in prop::option::of(Just(DEFAULT_ADD_TRANSACTION_NONCE)),
            )
            -> ConfigurationProxy {
            ConfigurationProxy { public_key, private_key, account_id, basic_auth, torii_api_url, transaction_time_to_live_ms, transaction_status_timeout_ms, transaction_limits, add_transaction_nonce }
        }
    }

    proptest! {
        #[test]
        fn client_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            if cfg.is_ok() {
                let example_cfg = ConfigurationProxy::from_path(CONFIGURATION_PATH).build().expect("Failed to build example Iroha config. \
                                                                                                    This probably means that some of the fields of the `CONFIGURATION PATH` \
                                                                                                    JSON were not updated properly with new changes.");
                let arb_cfg = cfg.expect("Config generated by proptest was checked to be ok by the surrounding if clause");
                // Skipping keys and `basic_auth` check as they're different from the file
                assert_eq!(arb_cfg.torii_api_url, example_cfg.torii_api_url);
                assert_eq!(arb_cfg.account_id, example_cfg.account_id);
                assert_eq!(arb_cfg.transaction_time_to_live_ms, example_cfg.transaction_time_to_live_ms);
                assert_eq!(arb_cfg.transaction_status_timeout_ms, example_cfg.transaction_status_timeout_ms);
                #[allow(deprecated)] // For testing purposes only
                {
                    assert_eq!(arb_cfg.transaction_limits, example_cfg.transaction_limits);
                }
                assert_eq!(arb_cfg.add_transaction_nonce, example_cfg.add_transaction_nonce);
            }
        }
    }
}
