//! Module with genesis configuration logic.
use std::{ops::Deref, path::PathBuf};

use eyre::{eyre, Context, Report};
use iroha_config_base::{
    Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvDefaultFallback,
    FromEnvResult, Merge, ParseEnvResult, ReadEnv, UserField,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_genesis::RawGenesisBlock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct UserLayer {
    pub public_key: UserField<PublicKey>,
    pub private_key: UserField<PrivateKey>,
    #[serde(default)]
    pub file: UserField<PathBuf>,
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
        /// Path to the [`RawGenesisBlock`]
        file: PathBuf,
    },
}

impl Complete for UserLayer {
    type Output = Config;

    fn complete(self) -> CompleteResult<Config> {
        let public_key = self
            .public_key
            .get()
            .ok_or_else(|| CompleteError::missing_field("genesis.public_key"))?;

        match (self.private_key.get(), self.file.get()) {
            (None, None) => Ok(Config::Partial { public_key }),
            (Some(private_key), Some(file)) => Ok(Config::Full {
                key_pair: KeyPair::new(public_key, private_key)
                    .map_err(GenesisConfigError::from)
                    .wrap_err("FIXME")
                    .map_err(CompleteError::Custom)?,
                file,
            }),
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

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum GenesisConfigError {
    /// `genesis.file` and `genesis.private_key` should be set together
    Inconsistent,
    /// failed to construct the genesis's keypair using `genesis.public_key` and `genesis.private_key` configuration parameters
    KeyPair(#[from] iroha_crypto::error::Error),
}
