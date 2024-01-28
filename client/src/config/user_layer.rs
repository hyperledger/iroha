use std::{io::Read, time::Duration};

use eyre::{eyre, Context, Report};
use iroha_config::base::{Emitter, ErrorsCollection, FromEnvDefaultFallback, Merge, UnwrapPartial};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{account::AccountId, ChainId};
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::config::BasicAuth;

mod boilerplate;
pub use boilerplate::*;

#[derive(Clone, Debug)]
pub struct Root {
    pub chain_id: ChainId,
    pub account: Account,
    pub api: Api,
    pub transaction: Transaction,
}

impl Root {
    pub fn parse(self) -> Result<super::Config, ErrorsCollection<Report>> {
        let Self {
            chain_id,
            account:
                Account {
                    id: account_id,
                    public_key,
                    private_key,
                },
            transaction:
                Transaction {
                    time_to_live: tx_ttl,
                    status_timeout: tx_timeout,
                    add_nonce: tx_add_nonce,
                },
            api: Api {
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

#[derive(Debug, Clone)]
pub struct Api {
    pub torii_url: OnlyHttpUrl,
    pub basic_auth: Option<BasicAuth>,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub id: AccountId,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

#[derive(Debug, Clone, Copy)]
pub struct Transaction {
    pub time_to_live: Duration,
    pub status_timeout: Duration,
    pub add_nonce: bool,
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
