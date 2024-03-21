//! Module for client-related configuration and structs

use core::str::FromStr;
use std::{path::Path, time::Duration};

use derive_more::Display;
use eyre::Result;
use iroha_config::{
    base,
    base::{FromEnv, StdEnv, UnwrapPartial},
};
use iroha_crypto::KeyPair;
use iroha_data_model::{prelude::*, ChainId};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use url::Url;

use crate::config::user::RootPartial;

mod user;

#[allow(missing_docs)]
pub const DEFAULT_TRANSACTION_TIME_TO_LIVE: Duration = Duration::from_secs(100);
#[allow(missing_docs)]
pub const DEFAULT_TRANSACTION_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
#[allow(missing_docs)]
pub const DEFAULT_TRANSACTION_NONCE: bool = false;

/// Valid web auth login string. See [`WebLogin::from_str`]
#[derive(Debug, Display, Clone, PartialEq, Eq, DeserializeFromStr, SerializeDisplay)]
pub struct WebLogin(SmallStr);

impl FromStr for WebLogin {
    type Err = eyre::ErrReport;

    /// Validates that the string is a valid web login
    ///
    /// # Errors
    /// Fails if `login` contains `:` character, which is the binary representation of the '\0'.
    fn from_str(login: &str) -> Result<Self> {
        if login.contains(':') {
            eyre::bail!("The `:` character, in `{login}` is not allowed");
        }

        Ok(Self(SmallStr::from_str(login)))
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

/// Complete client configuration
#[derive(Clone, Debug, Serialize)]
#[allow(missing_docs)]
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
    /// - the config is invalid
    pub fn load(path: impl AsRef<Path>) -> std::result::Result<Self, eyre::Report> {
        let config = RootPartial::from_toml(path)?;
        let config = config.merge(RootPartial::from_env(&StdEnv)?);
        Ok(config.unwrap_partial()?.parse()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_login_ok() {
        let _ok = WebLogin::from_str("alice").expect("input is valid");
    }

    #[test]
    fn web_login_bad() {
        let _err = WebLogin::from_str("alice:wonderland").expect_err("input has `:`");
    }

    #[test]
    fn parse_full_toml_config() {
        let _: RootPartial = toml::toml! {
            chain_id = "00000000-0000-0000-0000-000000000000"
            torii_url = "http://127.0.0.1:8080/"

            [basic_auth]
            web_login = "mad_hatter"
            password = "ilovetea"

            [account]
            domain_id = "wonderland"
            public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            private_key = "802640CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"

            [transaction]
            time_to_live = 100_000
            status_timeout = 100_000
            nonce = false
        }.try_into().unwrap();
    }
}
