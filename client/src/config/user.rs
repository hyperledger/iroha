//! User configuration view.

use error_stack::{Report, ResultExt};
use iroha_config_base::{
    attach::ConfigValueAndOrigin,
    util::{Emitter, EmitterResultExt, HumanDuration},
    ReadConfig, WithOrigin,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::prelude::{AccountId, ChainId, DomainId};
use url::Url;

use crate::config::BasicAuth;

/// Root of the user configuration
#[derive(Clone, Debug, ReadConfig)]
#[allow(missing_docs)]
pub struct Root {
    pub chain_id: ChainId,
    #[config(env = "TORII_URL")]
    pub torii_url: WithOrigin<Url>,
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
    #[error("Unsupported URL scheme: `{scheme}`")]
    UnsupportedUrlScheme { scheme: String },
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
                    .attach_printable(tx_timeout.clone().into_attachment())
                    .attach_printable(tx_ttl.clone().into_attachment())
                    // FIXME: is this correct?
                    .attach_printable("Note: it doesn't make sense to set the timeout longer than the possible transaction lifetime"),
            )
        }

        match torii_url.value().scheme() {
            "http" | "https" => {}
            scheme => emitter.emit(
                Report::new(ParseError::UnsupportedUrlScheme {
                    scheme: scheme.to_string(),
                })
                .attach_printable(torii_url.clone().into_attachment())
                .attach_printable("Note: only `http` and `https` protocols are supported"),
            ),
        }

        let (public_key, public_key_origin) = public_key.into_tuple();
        let (private_key, private_key_origin) = private_key.into_tuple();
        let account_id = AccountId::new(domain_id, public_key.clone());
        let key_pair = KeyPair::new(public_key, private_key)
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", public_key_origin))
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", private_key_origin))
            .change_context(ParseError::KeyPair)
            .ok_or_emit(&mut emitter);

        emitter.into_result()?;

        Ok(super::Config {
            chain_id,
            account_id,
            key_pair: key_pair.unwrap(),
            torii_api_url: torii_url.into_value(),
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
}
