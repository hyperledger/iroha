//! Module for client-related configuration and structs

use core::str::FromStr;
use std::{path::Path, time::Duration};

use derive_more::Display;
use error_stack::ResultExt;
use eyre::Result;
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use iroha_primitives::small::SmallStr;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use url::Url;

use crate::{
    crypto::KeyPair,
    data_model::{prelude::*, ChainId},
};

mod user;

pub use user::Root as UserConfig;

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
    pub chain: ChainId,
    pub account: AccountId,
    pub key_pair: KeyPair,
    pub basic_auth: Option<BasicAuth>,
    pub torii_api_url: Url,
    pub transaction_ttl: Duration,
    pub transaction_status_timeout: Duration,
    pub transaction_add_nonce: bool,
}

/// An error type for [`Config::load`]
#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Failed to load configuration")]
pub struct LoadError;

impl Config {
    /// Loads configuration from a file
    ///
    /// # Errors
    /// - unable to load config from a TOML file
    /// - the config is invalid
    pub fn load(path: impl AsRef<Path>) -> error_stack::Result<Self, LoadError> {
        let toml = TomlSource::from_file(path).change_context(LoadError)?;
        let config = ConfigReader::new()
            .with_toml_source(toml)
            .read_and_complete::<user::Root>()
            .change_context(LoadError)?
            .parse()
            .change_context(LoadError)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use assertables::{assert_contains, assert_contains_as_result};
    use iroha_config_base::env::MockEnv;

    use super::*;

    #[test]
    fn web_login_ok() {
        let _ok: WebLogin = "alice".parse().expect("input is valid");
    }

    #[test]
    fn web_login_bad() {
        let _err = "alice:wonderland"
            .parse::<WebLogin>()
            .expect_err("input has `:`");
    }

    fn config_sample() -> toml::Table {
        toml::toml! {
            chain = "00000000-0000-0000-0000-000000000000"
            torii_url = "http://127.0.0.1:8080/"

            [basic_auth]
            web_login = "mad_hatter"
            password = "ilovetea"

            [account]
            domain = "wonderland"
            public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
            private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"

            [transaction]
            time_to_live_ms = 100_000
            status_timeout_ms = 100_000
            nonce = false
        }
    }

    #[test]
    fn parse_full_toml_config() {
        ConfigReader::new()
            .with_toml_source(TomlSource::inline(config_sample()))
            .read_and_complete::<user::Root>()
            .unwrap();
    }

    #[test]
    fn torii_url_scheme_support() {
        fn with_scheme(scheme: &str) -> error_stack::Result<Config, user::ParseError> {
            ConfigReader::new()
                .with_toml_source(TomlSource::inline(config_sample()))
                .with_env(MockEnv::from([(
                    "TORII_URL",
                    format!("{scheme}://127.0.0.1:8080"),
                )]))
                .read_and_complete::<user::Root>()
                .unwrap()
                .parse()
        }

        let _ = with_scheme("http").expect("should be fine");
        let _ = with_scheme("https").expect("should be fine");
        let _ = with_scheme("ws").expect_err("not supported");
    }

    #[test]
    fn torii_url_ensure_trailing_slash() {
        let config = ConfigReader::new()
            .with_toml_source(TomlSource::inline(config_sample()))
            .with_env(MockEnv::from([("TORII_URL", "http://127.0.0.1/peer-1")]))
            .read_and_complete::<user::Root>()
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!(config.torii_api_url.as_str(), "http://127.0.0.1/peer-1/");
    }

    #[test]
    fn invalid_toml_file_is_handled_properly() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"not a valid toml").unwrap();

        let err = Config::load(file.path()).expect_err("should fail on toml parsing");

        assert_contains!(
            format!("{err:#?}"),
            "Error while deserializing file contents as TOML"
        );
    }
}
