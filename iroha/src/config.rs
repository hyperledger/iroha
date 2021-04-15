//! This module contains `Configuration` structure and related implementation.
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use iroha_config::derive::Configurable;
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::prelude::*;
use iroha_error::{Result, WrapErr};
use iroha_logger::config::LoggerConfiguration;
use serde::{Deserialize, Serialize};

use crate::{
    block_sync::config::BlockSyncConfiguration,
    genesis::config::GenesisConfiguration,
    kura::config::KuraConfiguration,
    queue::config::QueueConfiguration,
    sumeragi::config::{SumeragiConfiguration, TrustedPeers},
    torii::config::ToriiConfiguration,
    wsv::config::Configuration as WorldStateViewConfiguration,
};

/// Configuration parameters container.
#[derive(Clone, Default, Deserialize, Serialize, Debug, Configurable)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_")]
pub struct Configuration {
    /// Public key of this peer.
    #[config(serde_as_str)]
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// `Kura` related configuration.
    #[config(inner)]
    pub kura_configuration: KuraConfiguration,
    /// `Sumeragi` related configuration.
    #[config(inner)]
    pub sumeragi_configuration: SumeragiConfiguration,
    /// `Torii` related configuration.
    #[config(inner)]
    pub torii_configuration: ToriiConfiguration,
    /// `BlockSynchronizer` configuration.
    #[config(inner)]
    pub block_sync_configuration: BlockSyncConfiguration,
    /// `Queue` configuration.
    #[config(inner)]
    pub queue_configuration: QueueConfiguration,
    /// `Logger` configuration.
    #[config(inner)]
    pub logger_configuration: LoggerConfiguration,
    /// Configuration for `GenesisBlock`.
    #[config(inner)]
    pub genesis_configuration: GenesisConfiguration,
    /// Configuration for [`WorldStateView`](crate::wsv::WorldStateView).
    #[serde(default)]
    #[config(inner)]
    pub wsv_configuration: WorldStateViewConfiguration,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Configuration> {
        let file = File::open(path).wrap_err("Failed to open a file")?;
        let reader = BufReader::new(file);
        let mut configuration: Configuration =
            serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")?;
        configuration.sumeragi_configuration.key_pair = KeyPair {
            public_key: configuration.public_key.clone(),
            private_key: configuration.private_key.clone(),
        };
        configuration.sumeragi_configuration.peer_id = PeerId::new(
            &configuration.torii_configuration.torii_p2p_url,
            &configuration.public_key,
        );
        Ok(configuration)
    }

    /// Loads configuration from environment
    /// # Errors
    /// Fails if fails to deserialize configuration from env variables
    pub async fn load_environment(&mut self) -> Result<()> {
        iroha_config::Configurable::load_environment(self).await?;
        self.sumeragi_configuration.key_pair = KeyPair {
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
        };
        self.sumeragi_configuration.peer_id = PeerId::new(
            &self.torii_configuration.torii_p2p_url,
            &self.public_key.clone(),
        );
        Ok(())
    }

    /// Load trusted peers variables from a json *pretty* formatted file.
    ///
    /// # Errors
    /// Fails if can not load [`TrustedPeers`] from `path`.
    pub fn load_trusted_peers_from_path<P: AsRef<Path> + Debug>(&mut self, path: P) -> Result<()> {
        self.sumeragi_configuration.trusted_peers = TrustedPeers::from_path(&path)?;
        Ok(())
    }

    /// Add genesis block path to config
    pub fn add_genesis_block_path(&mut self, path: &str) {
        self.genesis_configuration.genesis_block_path = Some(path.to_owned());
    }

    /// Gets `public_key` and `private_key` configuration parameters.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key.clone(), self.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::collections::BTreeSet;

    use super::*;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";
    const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";

    #[test]
    fn parse_example_json() -> Result<()> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .wrap_err("Failed to read configuration from example config")?;
        assert_eq!(
            "127.0.0.1:1337",
            configuration.torii_configuration.torii_p2p_url
        );
        assert_eq!(1000, configuration.sumeragi_configuration.block_time_ms);
        Ok(())
    }

    #[test]
    fn parse_example_trusted_peers_json() -> Result<(), String> {
        let mut configuration = Configuration::from_path(CONFIGURATION_PATH)
            .map_err(|e| format!("Failed to read configuration from example config: {}", e))?;
        configuration
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .map_err(|e| {
                format!(
                    "Failed to read trusted peers parameters from example config: {}",
                    e
                )
            })?;
        let public_key = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
            )
            .expect("Failed to decode"),
        };
        let expected_trusted_peers: BTreeSet<PeerId> = vec![
            PeerId {
                address: "127.0.0.1:1337".to_string(),
                public_key: public_key.clone(),
            },
            PeerId {
                address: "localhost:1338".to_string(),
                public_key: public_key.clone(),
            },
            PeerId {
                address: "195.162.0.1:23".to_string(),
                public_key: public_key.clone(),
            },
            PeerId {
                address: "195.162.0.1:24".to_string(),
                public_key,
            },
        ]
        .into_iter()
        .collect();
        assert_eq!(1000, configuration.sumeragi_configuration.block_time_ms);
        assert_eq!(
            expected_trusted_peers,
            configuration.sumeragi_configuration.trusted_peers.peers
        );
        Ok(())
    }

    #[test]
    fn parse_trusted_peers_success() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address":"localhost:1338", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address": "195.162.0.1:23", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}]"#;
        let public_key = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
            )
            .expect("Failed to decode"),
        };
        let expected_trusted_peers = vec![
            PeerId {
                address: "127.0.0.1:1337".to_string(),
                public_key: public_key.clone(),
            },
            PeerId {
                address: "localhost:1338".to_string(),
                public_key: public_key.clone(),
            },
            PeerId {
                address: "195.162.0.1:23".to_string(),
                public_key,
            },
        ];
        let result: Vec<PeerId> =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers.");
        assert_eq!(expected_trusted_peers, result);
    }
}
