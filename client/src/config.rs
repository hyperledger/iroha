//! Module for client-related configuration and structs

// FIXME
#![allow(unused, missing_docs)]

use core::str::FromStr;
use std::{num::NonZeroU64, time::Duration};

use derive_more::Display;
use eyre::Result;
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, ChainId};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use url::Url;

#[allow(unsafe_code)]
pub const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(100);
pub const DEFAULT_TRANSACTION_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_ADD_TRANSACTION_NONCE: bool = false;

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

pub mod user_layer {
    use iroha_config::base::{Complete, CompleteResult, Merge, UserDuration, UserField};
    use iroha_crypto::{PrivateKey, PublicKey};
    use iroha_data_model::{account::AccountId, ChainId};
    use serde::{Deserialize, Deserializer};
    use url::Url;

    use crate::config::BasicAuth;

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    pub struct Root {
        pub chain_id: UserField<ChainId>,
        pub account: Account,
        pub api: Api,
        pub transaction: Transaction,
    }

    impl Complete for Root {
        type Output = super::Config;

        fn complete(self) -> CompleteResult<Self::Output> {
            // TODO
            // # Errors
            // - If the [`self.transaction_time_to_live_ms`] field is too small
            // - If the [`self.transaction_status_timeout_ms`] field is smaller than [`self.transaction_time_to_live_ms`]
            // - If the [`self.torii_api_url`] is malformed or had the wrong protocol
            todo!()
        }
    }

    impl Merge for Root {
        fn merge(&mut self, other: Self) {
            todo!()
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    pub struct Api {
        pub torii_url: UserField<OnlyHttpUrl>,
        pub basic_auth: UserField<BasicAuth>,
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    pub struct Account {
        pub id: UserField<AccountId>,
        pub public_key: UserField<PublicKey>,
        pub private_key: UserField<PrivateKey>,
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default)]
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
    pub chain_id: ChainId,
    pub account_id: AccountId,
    pub key_pair: KeyPair,
    pub basic_auth: Option<BasicAuth>,
    pub torii_api_url: Url,
    pub transaction_ttl: Duration,
    pub transaction_status_timeout: Duration,
    pub transaction_add_nonce: bool,
}
