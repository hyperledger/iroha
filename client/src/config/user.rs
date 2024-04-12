//! User configuration view.

use std::str::FromStr;

use error_stack::{Report, ResultExt};
use iroha_config_base::{
    util::{Emitter, EmitterResultExt, HumanDuration},
    ReadConfig, WithOrigin,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::prelude::{AccountId, ChainId, DomainId};
use serde_with::DeserializeFromStr;
use url::Url;

use crate::config::BasicAuth;

/// Root of the user configuration
#[derive(Clone, Debug, ReadConfig)]
#[allow(missing_docs)]
pub struct Root {
    pub chain_id: ChainId,
    #[config(env = "TORII_URL")]
    pub torii_url: OnlyHttpUrl,
    pub basic_auth: Option<BasicAuth>,
    #[config(nested)]
    pub account: Account,
    #[config(nested)]
    pub transaction: Transaction,
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Transaction status timeout should be smaller than its time-to-live")]
    TxTimeoutVsTtl,
    #[error("Failed to construct a key pair from provided public and private keys")]
    KeyPair,
}

impl Root {
    /// Validates user configuration for semantic errors and constructs a complete
    /// [`super::Config`].
    ///
    /// # Errors
    /// If a set of validity errors occurs.
    pub fn parse(self) -> error_stack::Result<super::Config, ParseError> {
        let Self {
            chain_id,
            torii_url,
            basic_auth,
            account:
                Account {
                    domain_id,
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

        if tx_timeout.value() > tx_ttl.value() {
            emitter.emit(
                Report::new(ParseError::TxTimeoutVsTtl)
                    .attach_printable(format!("{}: {:?}", tx_timeout.origin(), tx_timeout.value()))
                    .attach_printable(format!("{}: {:?}", tx_ttl.origin(), tx_ttl.value()))
                    // FIXME: is this correct?
                    .attach_printable("Note: it doesn't make sense to set the timeout longer than the possible transaction lifetime"),
            )
        }

        let (public_key, public_key_origin) = public_key.into_tuple();
        let (private_key, private_key_origin) = private_key.into_tuple();
        let account_id = AccountId::new(domain_id, public_key.clone());
        let key_pair = KeyPair::new(public_key, private_key)
            .change_context(ParseError::KeyPair)
            .attach_printable_lazy(|| format!("got public key from: {public_key_origin}"))
            .attach_printable_lazy(|| format!("got private key from: {private_key_origin}"))
            .ok_or_emit(&mut emitter);

        emitter.into_result()?;

        Ok(super::Config {
            chain_id,
            account_id,
            key_pair: key_pair.unwrap(),
            torii_api_url: torii_url.0,
            basic_auth,
            transaction_ttl: tx_ttl.into_value().get(),
            transaction_status_timeout: tx_timeout.into_value().get(),
            transaction_add_nonce: tx_add_nonce,
        })
    }
}

#[derive(Debug, Clone, ReadConfig)]
#[allow(missing_docs)]
pub struct Account {
    pub domain_id: DomainId,
    pub public_key: WithOrigin<PublicKey>,
    pub private_key: WithOrigin<PrivateKey>,
}

#[derive(Debug, Clone, ReadConfig)]
#[allow(missing_docs)]
pub struct Transaction {
    #[config(default = "super::DEFAULT_TRANSACTION_TIME_TO_LIVE.into()")]
    pub time_to_live: WithOrigin<HumanDuration>,
    #[config(default = "super::DEFAULT_TRANSACTION_STATUS_TIMEOUT.into()")]
    pub status_timeout: WithOrigin<HumanDuration>,
    #[config(default = "super::DEFAULT_TRANSACTION_NONCE")]
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

    use iroha_config_base::{env::MockEnv, read::ConfigReader};

    use super::*;

    #[test]
    fn parses_all_envs() {
        let env = MockEnv::from([("TORII_URL", "http://localhost:8080")]);

        let _ = ConfigReader::new()
            .with_env(env.clone())
            .read_and_complete::<Root>()
            .expect_err("there are missing fields, but that of no concern");

        assert_eq!(env.unvisited(), HashSet::new());
        assert_eq!(env.unknown(), HashSet::new());
    }

    #[test]
    fn non_http_url_error() {
        let error = "https://localhost:1123"
            .parse::<OnlyHttpUrl>()
            .expect_err("should not allow https");

        assert_eq!(format!("{error}"), "expected `http` scheme, found: `https`");
    }
}
