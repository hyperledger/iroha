//! Module for client-related configuration and structs

// FIXME
#![allow(unused, missing_docs)]

use core::str::FromStr;
use std::{num::NonZeroU64, time::Duration};

use derive_more::Display;
use eyre::Result;
pub use iroha_config::base;
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
    use std::{fs::File, io::Read, path::Path, time::Duration};

    use eyre::{eyre, Context, Report};
    use iroha_config::base::{
        Emitter, ErrorsCollection, FromEnvDefaultFallback, Merge, MissingFieldError, UnwrapPartial,
        UnwrapPartialResult, UserDuration, UserField,
    };
    use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
    use iroha_data_model::{account::AccountId, ChainId};
    use serde::{Deserialize, Deserializer};
    use url::Url;

    use crate::config::BasicAuth;

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default, Merge)]
    #[serde(deny_unknown_fields, default)]
    pub struct RootPartial {
        pub chain_id: UserField<ChainId>,
        pub account: AccountPartial,
        pub api: ApiPartial,
        pub transaction: TransactionPartial,
    }

    impl RootPartial {
        pub fn new() -> Self {
            // TODO: gen with macro
            Default::default()
        }

        pub fn from_toml(path: impl AsRef<Path>) -> eyre::Result<Self> {
            let contents = {
                let mut contents = String::new();
                File::open(path.as_ref())
                    .wrap_err_with(|| {
                        eyre!("cannot open file at location `{}`", path.as_ref().display())
                    })?
                    .read_to_string(&mut contents)?;
                contents
            };
            let layer: Self = toml::from_str(&contents).wrap_err("failed to parse toml")?;
            Ok(layer)
        }

        pub fn merge(mut self, other: Self) -> Self {
            Merge::merge(&mut self, other);
            self
        }
    }

    // FIXME: should config be read from ENV?
    impl FromEnvDefaultFallback for RootPartial {}

    #[derive(Clone, Debug)]
    pub struct RootFull {
        pub chain_id: ChainId,
        pub account: AccountFull,
        pub api: ApiFull,
        pub transaction: TransactionFull,
    }

    impl UnwrapPartial for RootPartial {
        type Output = RootFull;

        fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
            let mut emitter = Emitter::new();

            if self.chain_id.is_none() {
                emitter.emit_missing_field("chain_id");
            }
            let account = emitter.try_unwrap_partial(self.account);
            let api = emitter.try_unwrap_partial(self.api);
            let transaction = emitter.try_unwrap_partial(self.transaction);

            emitter.finish()?;

            Ok(RootFull {
                chain_id: self.chain_id.get().unwrap(),
                account: account.unwrap(),
                api: api.unwrap(),
                transaction: transaction.unwrap(),
            })
        }
    }

    impl RootFull {
        pub fn parse(self) -> Result<super::Config, ErrorsCollection<Report>> {
            let Self {
                chain_id,
                account:
                    AccountFull {
                        id: account_id,
                        public_key,
                        private_key,
                    },
                transaction:
                    TransactionFull {
                        time_to_live: tx_ttl,
                        status_timeout: tx_timeout,
                        add_nonce: tx_add_nonce,
                    },
                api:
                    ApiFull {
                        torii_url,
                        basic_auth,
                    },
            } = self;

            let mut emitter = Emitter::new();

            // TODO: validate if TTL is too small?

            if tx_timeout > tx_ttl {
                // TODO:
                //      would be nice to provide a nice report with spans in the input
                //      pointing out source data in provided config files
                // FIXME: explain why it should be smaller
                emitter.emit(eyre!(
                    "transaction status timeout should be smaller than its time-to-live"
                ))
            }

            let key_pair = KeyPair::new(public_key, private_key)
                .wrap_err("failed to construct a key pair")
                .map_or_else(
                    |err| {
                        emitter.emit(err);
                        None
                    },
                    Some,
                );

            emitter.finish()?;

            Ok(super::Config {
                chain_id,
                account_id,
                key_pair: key_pair.unwrap(),
                torii_api_url: torii_url.0,
                basic_auth,
                transaction_ttl: tx_ttl,
                transaction_status_timeout: tx_timeout,
                transaction_add_nonce: tx_add_nonce,
            })
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default, Merge)]
    #[serde(deny_unknown_fields, default)]
    pub struct ApiPartial {
        pub torii_url: UserField<OnlyHttpUrl>,
        pub basic_auth: UserField<BasicAuth>,
    }

    #[derive(Debug, Clone)]
    pub struct ApiFull {
        pub torii_url: OnlyHttpUrl,
        pub basic_auth: Option<BasicAuth>,
    }

    impl UnwrapPartial for ApiPartial {
        type Output = ApiFull;

        fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
            Ok(ApiFull {
                torii_url: self
                    .torii_url
                    .get()
                    .ok_or_else(|| MissingFieldError::new("api.torii_url"))?,
                basic_auth: self.basic_auth.get(),
            })
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default, Merge)]
    #[serde(deny_unknown_fields, default)]
    pub struct AccountPartial {
        pub id: UserField<AccountId>,
        pub public_key: UserField<PublicKey>,
        pub private_key: UserField<PrivateKey>,
    }

    #[derive(Debug, Clone)]
    pub struct AccountFull {
        pub id: AccountId,
        pub public_key: PublicKey,
        pub private_key: PrivateKey,
    }

    impl UnwrapPartial for AccountPartial {
        type Output = AccountFull;

        fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
            let mut emitter = Emitter::new();

            if self.id.is_none() {
                emitter.emit_missing_field("account.id");
            }
            if self.public_key.is_none() {
                emitter.emit_missing_field("account.public_key");
            }
            if self.private_key.is_none() {
                emitter.emit_missing_field("account.private_key");
            }

            emitter.finish()?;

            Ok(AccountFull {
                id: self.id.get().unwrap(),
                public_key: self.public_key.get().unwrap(),
                private_key: self.private_key.get().unwrap(),
            })
        }
    }

    #[derive(Debug, Clone, Deserialize, Eq, PartialEq, Default, Merge)]
    #[serde(deny_unknown_fields, default)]
    pub struct TransactionPartial {
        pub time_to_live: UserField<UserDuration>,
        pub status_timeout: UserField<UserDuration>,
        pub add_nonce: UserField<bool>,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct TransactionFull {
        pub time_to_live: Duration,
        pub status_timeout: Duration,
        pub add_nonce: bool,
    }

    impl UnwrapPartial for TransactionPartial {
        type Output = TransactionFull;

        fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
            Ok(TransactionFull {
                time_to_live: self
                    .time_to_live
                    .get()
                    .map_or(super::DEFAULT_TRANSACTION_TIME_TO_LIVE, UserDuration::get),
                status_timeout: self
                    .status_timeout
                    .get()
                    .map_or(super::DEFAULT_TRANSACTION_STATUS_TIMEOUT, UserDuration::get),
                add_nonce: self
                    .add_nonce
                    .get()
                    .unwrap_or(super::DEFAULT_ADD_TRANSACTION_NONCE),
            })
        }
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
                Ok(Self(url))
            } else {
                Err(serde::de::Error::custom("only HTTP scheme is supported"))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub chain_id: ChainId,
    pub account_id: AccountId,
    pub key_pair: KeyPair,
    pub basic_auth: Option<BasicAuth>,
    // FIXME: or use `OnlyHttpUrl` here?
    pub torii_api_url: Url,
    pub transaction_ttl: Duration,
    pub transaction_status_timeout: Duration,
    pub transaction_add_nonce: bool,
}
