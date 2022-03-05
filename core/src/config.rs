//! This module contains [`Configuration`] structure and related implementation.
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config::derive::Configurable;
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::prelude::*;
use iroha_logger::Configuration as LoggerConfiguration;
use serde::{Deserialize, Serialize};

use crate::{
    block_sync::config::BlockSyncConfiguration, genesis::config::GenesisConfiguration,
    kura::config::KuraConfiguration, queue::Configuration as QueueConfiguration,
    sumeragi::config::SumeragiConfiguration, torii::config::ToriiConfiguration,
    wsv::config::Configuration as WorldStateViewConfiguration,
};

/// Configuration parameters container.
#[derive(Clone, Deserialize, Serialize, Debug, Configurable, Default)]
#[serde(default)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_")]
pub struct Configuration {
    /// Public key of this peer.
    #[config(serde_as_str)]
    pub public_key: PublicKey,
    /// Private key of this peer.
    pub private_key: PrivateKey,
    /// Disable coloring of the backtrace and error report on panic.
    pub disable_panic_terminal_colors: bool,
    /// `Kura` related configuration.
    #[config(inner)]
    pub kura: KuraConfiguration,
    /// `Sumeragi` related configuration.
    #[config(inner)]
    pub sumeragi: SumeragiConfiguration,
    /// `Torii` related configuration.
    #[config(inner)]
    pub torii: ToriiConfiguration,
    /// `BlockSynchronizer` configuration.
    #[config(inner)]
    pub block_sync: BlockSyncConfiguration,
    /// `Queue` configuration.
    #[config(inner)]
    pub queue: QueueConfiguration,
    /// `Logger` configuration.
    #[config(inner)]
    pub logger: LoggerConfiguration,
    /// Configuration for `GenesisBlock`.
    #[config(inner)]
    pub genesis: GenesisConfiguration,
    /// Configuration for [`WorldStateView`](crate::wsv::WorldStateView).
    #[config(inner)]
    pub wsv: WorldStateViewConfiguration,
    #[cfg(feature = "telemetry")]
    /// Configuration for telemetry
    #[config(inner)]
    pub telemetry: iroha_telemetry::Configuration,
    /// Network configuration
    #[config(inner)]
    pub network: NetworkConfiguration,
}

/// Network Configuration parameters container.
#[derive(Clone, Copy, Deserialize, Serialize, Debug, Configurable, PartialEq, Eq)]
#[serde(default)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_NETWORK_")]
pub struct NetworkConfiguration {
    /// Actor mailbox size
    pub mailbox: usize,
}

const DEFAULT_MAILBOX_SIZE: usize = 100;

impl Default for NetworkConfiguration {
    fn default() -> Self {
        Self {
            mailbox: DEFAULT_MAILBOX_SIZE,
        }
    }
}

impl Configuration {
    /// Construct [`Self`] from a path-like object.
    ///
    /// # Errors
    /// - File not found.
    /// - File found, but peer configuration parsing failed.
    /// - Length of the array in raw json representation is different
    /// to the lenght of the array in
    /// [`self.sumeragi.trusted_peers.peers`], most likely due to two
    /// (or more) peers having the same public key.
    pub fn from_path<P: AsRef<Path> + Debug + Clone>(path: P) -> Result<Configuration> {
        let file = File::open(path.clone())
            .wrap_err(format!("Failed to open the config file {:?}", path))?;
        let reader = BufReader::new(file);
        let mut configuration: Configuration = serde_json::from_reader(reader).wrap_err(
            format!("Failed to parse {:?} as Iroha peer configuration.", path),
        )?;
        configuration.finalize();
        Ok(configuration)
    }

    fn finalize(&mut self) {
        self.sumeragi.key_pair = self.key_pair().into();
        self.sumeragi.peer_id = PeerId::new(&self.torii.p2p_addr, &self.public_key.clone());
    }

    /// Loads configuration from environment
    ///
    /// # Errors
    /// If Configuration deserialize fails:
    /// - Configuration `TrustedPeers` contains entries with duplicate public keys
    pub fn load_environment(&mut self) -> Result<()> {
        iroha_config::Configurable::load_environment(self)?;
        self.finalize();
        Ok(())
    }

    /// Get `public_key` and `private_key` configuration parameters.
    pub fn key_pair(&self) -> (PublicKey, PrivateKey) {
        (self.public_key.clone(), self.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::collections::HashSet;

    use super::*;
    use crate::sumeragi::config::TrustedPeers;

    const CONFIGURATION_PATH: &str = "../configs/peer/config.json";

    #[test]
    fn parse_example_json() -> Result<()> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .wrap_err("Failed to read configuration from example config")?;
        assert_eq!("127.0.0.1:1337", configuration.torii.p2p_addr);
        assert_eq!(1000, configuration.sumeragi.block_time_ms);
        Ok(())
    }

    #[test]
    fn parse_example_trusted_peers_json() -> Result<(), String> {
        let configuration = Configuration::from_path(CONFIGURATION_PATH)
            .map_err(|e| format!("Failed to read configuration from example config: {}", e))?;
        let public_key1 = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
            )
            .expect("Failed to decode"),
        };
        let public_key2 = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "CC25624D62896D3A0BFD8940F928DC2ABF27CC57CEFEB442AA96D9081AAE58A1",
            )
            .expect("Failed to decode"),
        };
        let public_key3 = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "FACA9E8AA83225CB4D16D67F27DD4F93FC30FFA11ADC1F5C88FD5495ECC91020",
            )
            .expect("Failed to decode"),
        };
        let public_key4 = PublicKey {
            digest_function: iroha_crypto::ED_25519.to_string(),
            payload: hex::decode(
                "8E351A70B6A603ED285D666B8D689B680865913BA03CE29FB7D13A166C4E7F1F",
            )
            .expect("Failed to decode"),
        };
        let expected_trusted_peers = vec![
            PeerId {
                address: "127.0.0.1:1337".to_owned(),
                public_key: public_key1,
            },
            PeerId {
                address: "127.0.0.1:1338".to_owned(),
                public_key: public_key2,
            },
            PeerId {
                address: "127.0.0.1:1339".to_owned(),
                public_key: public_key3,
            },
            PeerId {
                address: "127.0.0.1:1340".to_owned(),
                public_key: public_key4,
            },
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(1000, configuration.sumeragi.block_time_ms);
        assert_eq!(
            expected_trusted_peers,
            configuration.sumeragi.trusted_peers.peers
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

    #[test]
    #[should_panic]
    fn parse_trusted_peers_fail_duplicate_peer_id() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address":"127.0.0.1:1337", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address":"localhost:1338", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}, {"address": "195.162.0.1:23", "public_key": "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"}]"#;
        let _result: TrustedPeers =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers");
    }
}
