//! Module with genesis configuration logic.
use std::path::PathBuf;

use eyre::Report;
use iroha_config_base::derive::{view, Proxy};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_genesis::RawGenesisBlock;
use serde::{Deserialize, Serialize};

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration of the genesis block and the process of its submission.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize,  Proxy)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_GENESIS_")]
    pub struct Configuration {
        /// The public key of the genesis account, should be supplied to all peers.
        #[config(serde_as_str)]
        pub public_key: PublicKey,
        /// The private key of the genesis account, only needed for the peer that submits the genesis block.
        #[view(ignore)]
        pub private_key: Option<PrivateKey>,
        /// Path to the genesis file
        #[config(serde_as_str)]
        pub file: Option<PathBuf>
    }
}

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            public_key: None,
            private_key: Some(None),
            file: None,
        }
    }
}

/// Parsed variant of the user-provided [`Configuration`]
// TODO: incorporate this struct into the final, parsed configuration
//       https://github.com/hyperledger/iroha/issues/3500
pub enum ParsedConfiguration {
    /// The peer can only observe the genesis block
    Default {
        /// Genesis account public key
        public_key: PublicKey,
    },
    /// The peer is responsible for submitting the genesis block
    Submit {
        /// Genesis account key pair
        key_pair: KeyPair,
        /// Raw genesis block
        raw_block: RawGenesisBlock,
    },
}

impl Configuration {
    /// Parses user configuration into a stronger-typed structure [`ParsedConfiguration`]
    ///
    /// # Errors
    /// See [`ParseError`]
    pub fn parse(self, submit: bool) -> Result<ParsedConfiguration, ParseError> {
        match (self.private_key, self.file, submit) {
            (None, None, false) => Ok(ParsedConfiguration::Default {
                public_key: self.public_key,
            }),
            (Some(private_key), Some(path), true) => {
                let raw_block = RawGenesisBlock::from_path(&path)
                    .map_err(|report| ParseError::File { path, report })?;

                Ok(ParsedConfiguration::Submit {
                    key_pair: KeyPair::new(self.public_key, private_key)?,
                    raw_block,
                })
            }
            _ => Err(ParseError::InvalidParametersCombination),
        }
    }
}

/// Error which might occur during [`Configuration::parse()`]
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum ParseError {
    /// `genesis.private_key` and `genesis.file` should be set for the peer that submits the genesis
    InvalidParametersCombination,
    /// Genesis key pair is invalid
    InvalidKeyPair(#[from] iroha_crypto::error::Error),
    /// Cannot read the genesis block from file `{path}`
    File {
        /// Original error report
        #[source]
        report: Report,
        /// Path to the file
        path: PathBuf,
    },
}

#[cfg(test)]
pub mod tests {
    use iroha_crypto::KeyPair;
    use proptest::prelude::*;

    use super::*;

    /// Key-pair used by default for test purposes
    fn placeholder_keypair() -> KeyPair {
        let public_key = "ed01204CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF"
            .parse()
            .expect("Public key not in multihash format");
        let private_key = PrivateKey::from_hex(
            iroha_crypto::Algorithm::Ed25519,
            "D748E18CE60CB30DEA3E73C9019B7AF45A8D465E3D71BCC9A5EF99A008205E534CFFD0EE429B1BDD36B3910EC570852B8BB63F18750341772FB46BC856C5CAAF"
        ).expect("Private key not hex encoded");

        KeyPair::new(public_key, private_key).expect("Key pair mismatch")
    }

    #[allow(clippy::option_option)]
    fn arb_keys() -> BoxedStrategy<(Option<PublicKey>, Option<Option<PrivateKey>>)> {
        let (pub_key, _) = placeholder_keypair().into();
        (
            prop::option::of(Just(pub_key)),
            prop::option::of(Just(None)),
        )
            .boxed()
    }

    prop_compose! {
        pub fn arb_proxy()
            (
                (public_key, private_key) in arb_keys(),
                file in prop::option::of(Just(None))
            )
            -> ConfigurationProxy {
            ConfigurationProxy { public_key, private_key, file }
        }
    }
}
