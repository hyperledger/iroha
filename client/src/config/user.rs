//! User configuration view.

mod boilerplate;

use std::{fs::File, io::Read, path::Path, str::FromStr, time::Duration};

pub use boilerplate::*;
use eyre::{eyre, Context, Report};
use iroha_config::base::{Emitter, ErrorsCollection};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::prelude::{AccountId, ChainId, DomainId};
use merge::Merge;
use serde_with::DeserializeFromStr;
use url::Url;

use crate::config::BasicAuth;

impl RootPartial {
    /// Reads the partial layer from TOML
    ///
    /// # Errors
    /// - File not found
    /// - Not valid TOML or content
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

    /// Merge other into self
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        Merge::merge(&mut self, other);
        self
    }
}

/// Root of the user configuration
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct Root {
    pub chain_id: ChainId,
    pub torii_url: OnlyHttpUrl,
    pub basic_auth: Option<BasicAuth>,
    pub account: Account,
    pub transaction: Transaction,
}

impl Root {
    /// Validates user configuration for semantic errors and constructs a complete
    /// [`super::Config`].
    ///
    /// # Errors
    /// If a set of validity errors occurs.
    pub fn parse(self) -> Result<super::Config, ErrorsCollection<Report>> {
        let Self {
            chain_id,
            torii_url,
            basic_auth,
            account:
                Account {
                    domian_id,
                    public_key,
                    private_key,
                },
            transaction:
                Transaction {
                    time_to_live: tx_ttl,
                    status_timeout: tx_timeout,
                    nonce: tx_add_nonce,
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

        let account_id = AccountId::new(domian_id, public_key.clone());

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

#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct Account {
    pub domian_id: DomainId,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)]
pub struct Transaction {
    pub time_to_live: Duration,
    pub status_timeout: Duration,
    pub nonce: bool,
}

/// A [`Url`] that might only have HTTP scheme inside
#[derive(Debug, Clone, Eq, PartialEq, DeserializeFromStr)]
pub struct OnlyHttpUrl(Url);

impl FromStr for OnlyHttpUrl {
    type Err = ParseHttpUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::from_str(s)?;
        if url.scheme() == "http" {
            Ok(Self(url))
        } else {
            Err(ParseHttpUrlError::NotHttp {
                found: url.scheme().to_owned(),
            })
        }
    }
}

/// Possible errors that might occur for [`FromStr::from_str`] for [`OnlyHttpUrl`].
#[derive(Debug, thiserror::Error)]
pub enum ParseHttpUrlError {
    /// Unable to parse the url
    #[error(transparent)]
    Parse(#[from] url::ParseError),
    /// Parsed fine, but doesn't contain HTTP
    #[error("expected `http` scheme, found: `{found}`")]
    NotHttp {
        /// What scheme was actually found
        found: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iroha_config::base::{FromEnv as _, TestEnv};

    use super::*;

    #[test]
    fn parses_all_envs() {
        let env = TestEnv::new().set("TORII_URL", "http://localhost:8080");

        let _layer = RootPartial::from_env(&env).expect("should not fail since env is valid");

        assert_eq!(env.unvisited(), HashSet::new())
    }

    #[test]
    fn non_http_url_error() {
        let error = "https://localhost:1123"
            .parse::<OnlyHttpUrl>()
            .expect_err("should not allow https");

        assert_eq!(format!("{error}"), "expected `http` scheme, found: `https`");
    }
}
