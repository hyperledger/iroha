//! Module with genesis configuration logic.
use std::path::PathBuf;

use eyre::{eyre, Context, Report};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_genesis::RawGenesisBlock;
use serde::{Deserialize, Serialize};

use crate::{
    Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvDefaultFallback,
    FromEnvResult, ParseEnvResult, ReadEnv,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UserLayer {
    pub public_key: Option<PublicKey>,
    pub private_key: Option<PrivateKey>,
    pub file: Option<PathBuf>,
}

#[derive(Debug)]
pub enum Config {
    /// The peer can only observe the genesis block
    Partial {
        /// Genesis account public key
        public_key: PublicKey,
    },
    /// The peer is responsible for submitting the genesis block
    Full {
        /// Genesis account key pair
        key_pair: KeyPair,
        /// Raw genesis block
        raw_block: RawGenesisBlock,
    },
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Config> {
        let public_key = self
            .public_key
            .ok_or_else(|| CompleteError::missing_field("public_key"))?;

        match (self.private_key, self.file) {
            (None, None) => Ok(Config::Partial { public_key }),
            (Some(private_key), Some(path)) => {
                let raw_block = RawGenesisBlock::from_path(&path)
                    .map_err(|report| GenesisConfigError::File { path, report })
                    .wrap_err("FIXME don't know how to wrap error here")
                    .map_err(CompleteError::Custom)?;

                Ok(Config::Full {
                    key_pair: KeyPair::new(public_key, private_key)
                        .map_err(GenesisConfigError::from)
                        .wrap_err("FIXME")
                        .map_err(CompleteError::Custom)?,
                    raw_block,
                })
            }
            _ => Err(GenesisConfigError::Inconsistent)
                .wrap_err("FIXME")
                .map_err(CompleteError::Custom)?,
        }
    }
}

impl FromEnv for UserLayer {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let public_key = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "GENESIS_PUBLIC_KEY",
            "genesis.public_key",
        )
        .into();
        let private_key = super::iroha::private_key_from_env(
            &mut emitter,
            env,
            "GENESIS_PRIVATE_KEY",
            "genesis.private_key",
        )
        .into();
        let file =
            ParseEnvResult::parse_simple(&mut emitter, env, "GENESIS_FILE", "genesis.file").into();

        emitter.finish()?;

        Ok(Self {
            public_key,
            private_key,
            file,
        })
    }
}

/// Error which might occur during [`Configuration::parse()`]
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum GenesisConfigError {
    /// `genesis.file` and `genesis.private_key` should be set together
    Inconsistent,
    /// invalid genesis key pair
    KeyPair(#[from] iroha_crypto::error::Error),
    /// cannot read the genesis block from file "`{path}`"
    File {
        /// Original error report
        #[source]
        report: Report,
        /// Path to the file
        path: PathBuf,
    },
}
