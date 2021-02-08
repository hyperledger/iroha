//! This module contains `Configuration` structure and related implementation.
use crate::{
    block_sync::config::BlockSyncConfiguration, genesis::config::GenesisConfiguration,
    init::config::InitConfiguration, kura::config::KuraConfiguration,
    queue::config::QueueConfiguration, sumeragi::config::SumeragiConfiguration,
    torii::config::ToriiConfiguration,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::prelude::*;
use iroha_logger::config::LoggerConfiguration;
use serde::Deserialize;
use std::{env, fmt::Debug, fs::File, io::BufReader, path::Path};

const IROHA_PUBLIC_KEY: &str = "IROHA_PUBLIC_KEY";
const IROHA_PRIVATE_KEY: &str = "IROHA_PRIVATE_KEY";

/// Configuration parameters container.
#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Configuration {
    /// Public key of this peer.
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// `Kura` related configuration.
    pub kura_configuration: KuraConfiguration,
    /// `Sumeragi` related configuration.
    pub sumeragi_configuration: SumeragiConfiguration,
    /// `Torii` related configuration.
    pub torii_configuration: ToriiConfiguration,
    /// `BlockSynchronizer` configuration.
    pub block_sync_configuration: BlockSyncConfiguration,
    /// `Queue` configuration.
    pub queue_configuration: QueueConfiguration,
    /// `Logger` configuration.
    pub logger_configuration: LoggerConfiguration,
    /// Configuration for initial setup.
    pub init_configuration: InitConfiguration,
    /// Configuration for `GenesisBlock`.
    pub genesis_configuration: GenesisConfiguration,
}

impl Configuration {
    /// This method will build `Configuration` from a json *pretty* formatted file (without `:` in
    /// key names).
    /// # Panics
    /// This method will panic if configuration file presented, but has incorrect scheme or format.
    /// # Errors
    /// This method will return error if system will fail to find a file or read it's content.
    pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<Configuration, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open a file: {}", e))?;
        let reader = BufReader::new(file);
        let mut configuration: Configuration = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to deserialize json from reader: {}", e))?;
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

    /// Load environment variables and replace existing parameters with these variables values.
    pub fn load_environment(&mut self) -> Result<(), String> {
        self.torii_configuration.load_environment()?;
        self.kura_configuration.load_environment()?;
        self.sumeragi_configuration.load_environment()?;
        self.block_sync_configuration.load_environment()?;
        self.queue_configuration.load_environment()?;
        self.logger_configuration.load_environment()?;
        self.init_configuration.load_environment()?;
        self.genesis_configuration.load_environment()?;
        if let Ok(public_key) = env::var(IROHA_PUBLIC_KEY) {
            self.public_key = serde_json::from_value(serde_json::json!(public_key))
                .map_err(|e| format!("Failed to parse Public Key: {}", e))?;
        }
        if let Ok(private_key) = env::var(IROHA_PRIVATE_KEY) {
            self.private_key = serde_json::from_str(&private_key)
                .map_err(|e| format!("Failed to parse Private Key: {}", e))?;
        }
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

    /// Add genesis block path to config
    pub fn add_genesis_block_path(&mut self, path: &str) {
        self.genesis_configuration.genesis_block_path = Some(path.to_string());
    }

    /// Gets `public_key` and `private_key` configuration parameters.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key.clone(), self.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const CONFIGURATION_PATH: &str = "tests/test_config.json";

    #[test]
    fn parse_example_json() -> Result<(), String> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .map_err(|e| format!("Failed to read configuration from example config: {}", e))?;
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
        assert_eq!(
            "127.0.0.1:1337",
            configuration.torii_configuration.torii_p2p_url
        );
        assert_eq!(1000, configuration.sumeragi_configuration.block_time_ms);
        assert_eq!(
            expected_trusted_peers,
            configuration.sumeragi_configuration.trusted_peers
        );
        Ok(())
    }

    #[test]
    fn parse_trusted_peers_success() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address":"localhost:1338", "public_key": "ed207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address": "195.162.0.1:23", "public_key": "ed207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}]"#;
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
