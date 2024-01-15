//! Module for client-related configuration and structs
use core::str::FromStr;
use std::{num::NonZeroU64, time::Duration};

use derive_more::Display;
use eyre::{Result, WrapErr};
use iroha_config::base::{UserDuration, UserField};
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, ChainId};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use url::Url;

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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Configuration {
    /// Unique id of the blockchain. Used for simple replay attack protection.
    pub chain_id: ChainId,
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
    /// If `true` add nonce, which make different hashes for transactions which occur repeatedly and simultaneously
    pub add_transaction_nonce: bool,
}

mod user_layers {
    use iroha_config::base::{Complete, CompleteResult, Merge, UserDuration, UserField};
    use iroha_crypto::{PrivateKey, PublicKey};
    use iroha_data_model::account::AccountId;
    use serde::{Deserialize, Deserializer};
    use url::Url;

    use crate::config::BasicAuth;

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    pub struct Root {
        pub account: Account,
        pub api: Api,
        pub transaction: Transaction,
    }

    impl Complete for Root {
        type Output = super::Config;

        fn complete(self) -> CompleteResult<Self::Output> {
            // TODO: tx timeout should be smaller than ttl
            todo!()
        }
    }

    impl Merge for Root {
        fn merge(&mut self, other: Self) {
            todo!()
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    pub struct Api {
        pub torii_url: UserField<OnlyHttpUrl>,
        pub basic_auth: UserField<BasicAuth>,
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    pub struct Account {
        pub id: UserField<AccountId>,
        pub public_key: UserField<PublicKey>,
        pub private_key: UserField<PrivateKey>,
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields, default)]
    pub struct Transaction {
        pub time_to_live: UserField<UserDuration>,
        pub status_timeout: UserField<UserDuration>,
        pub add_nonce: UserField<bool>,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct OnlyHttpUrl(Url);

    impl<'de> Deserialize<'de> for OnlyHttpUrl {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let url = Url::deserialize(deserializer)?;
            if url.scheme() == "http" {
                Err(serde::de::Error::custom("only HTTP is supported"))
            } else {
                Ok(Self(url))
            }
        }
    }
}

pub struct Config {
    pub account_id: AccountId,
    pub key_pair: KeyPair,
    pub basic_auth: Option<BasicAuth>,
    pub torii_api_url: Url,
    pub transaction_ttl: Duration,
    pub transaction_status_timeout: Duration,
    pub transaction_add_nonce: bool,
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            chain_id: None,
            public_key: None,
            private_key: None,
            account_id: None,
            basic_auth: Some(None),
            torii_api_url: None,
            transaction_time_to_live_ms: Some(Some(DEFAULT_TRANSACTION_TIME_TO_LIVE_MS)),
            transaction_status_timeout_ms: Some(DEFAULT_TRANSACTION_STATUS_TIMEOUT_MS),
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
