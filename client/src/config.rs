//! Module for client-related configuration and structs

// FIXME
#![allow(unused, missing_docs)]

use core::str::FromStr;
use std::{num::NonZeroU64, path::Path, time::Duration};

use derive_more::Display;
use eyre::Result;
pub use iroha_config::base;
use iroha_config::base::UnwrapPartial;
use iroha_crypto::prelude::*;
use iroha_data_model::{prelude::*, ChainId};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::user_layer::RootPartial;

pub mod user_layer;

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

impl Config {
    /// Loads configuration from a file
    ///
    /// # Errors
    /// - unable to load config from a TOML file
    /// - unable to validate loaded config
    pub fn load(path: impl AsRef<Path>) -> std::result::Result<Self, eyre::Report> {
        let config = RootPartial::from_toml(path)?;
        let config = config.unwrap_partial()?.parse()?;
        Ok(config)
    }
}
