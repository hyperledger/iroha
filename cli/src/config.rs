//! This module contains [`Configuration`] structure and related implementation.
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config::derive::Configurable;
use iroha_core::{
    block_sync::config::BlockSyncConfiguration, genesis::config::GenesisConfiguration,
    kura::config::KuraConfiguration, queue::Configuration as QueueConfiguration,
    sumeragi::config::SumeragiConfiguration,
    wsv::config::Configuration as WorldStateViewConfiguration,
};
use iroha_crypto::prelude::*;
use iroha_data_model::prelude::*;
use iroha_logger::Configuration as LoggerConfiguration;
use serde::{Deserialize, Serialize};

use super::torii::config::ToriiConfiguration;

/// Configuration parameters container.
#[derive(Debug, Clone, Deserialize, Serialize, Configurable)]
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
    /// Configuration for `WorldStateView`.
    #[config(inner)]
    pub wsv: WorldStateViewConfiguration,
    /// Network configuration
    #[config(inner)]
    pub network: NetworkConfiguration,
    /// Configuration for telemetry
    #[config(inner)]
    #[cfg(feature = "telemetry")]
    pub telemetry: iroha_telemetry::Configuration,
}

impl Default for Configuration {
    fn default() -> Self {
        let sumeragi_configuration = SumeragiConfiguration::default();
        let (public_key, private_key) = sumeragi_configuration.key_pair.clone().into();

        Self {
            public_key,
            private_key,
            disable_panic_terminal_colors: bool::default(),
            kura: KuraConfiguration::default(),
            sumeragi: sumeragi_configuration,
            torii: ToriiConfiguration::default(),
            block_sync: BlockSyncConfiguration::default(),
            queue: QueueConfiguration::default(),
            logger: LoggerConfiguration::default(),
            genesis: GenesisConfiguration::default(),
            wsv: WorldStateViewConfiguration::default(),
            network: NetworkConfiguration::default(),
            #[cfg(feature = "telemetry")]
            telemetry: iroha_telemetry::Configuration::default(),
        }
    }
}

/// Network Configuration parameters container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configurable)]
#[serde(default)]
#[serde(rename_all = "UPPERCASE")]
#[config(env_prefix = "IROHA_NETWORK_")]
pub struct NetworkConfiguration {
    /// Actor mailbox size
    pub mailbox: u32,
}

const DEFAULT_MAILBOX_SIZE: u32 = 100;

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
        self.sumeragi.key_pair = self.key_pair();
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
    pub fn key_pair(&self) -> iroha_crypto::KeyPair {
        iroha_crypto::KeyPair::new(self.public_key.clone(), self.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_core::sumeragi::config::TrustedPeers;

    use super::*;

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
    #[should_panic]
    fn parse_trusted_peers_fail_duplicate_peer_id() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed0120954c83a4220faffb2c1d23fc5225b3e7952d53acbb2a065ff30c631e5e1d6b10"}, {"address":"127.0.0.1:1337", "public_key": "ed0120954c83a4220faffb2c1d23fc5225b3e7952d53acbb2a065ff30c631e5e1d6b10"}, {"address":"localhost:1338", "public_key": "ed0120954c83a4220faffb2c1d23fc5225b3e7952d53acbb2a065ff30c631e5e1d6b10"}, {"address": "195.162.0.1:23", "public_key": "ed0120954c83a4220faffb2c1d23fc5225b3e7952d53acbb2a065ff30c631e5e1d6b10"}]"#;
        let _result: TrustedPeers =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers");
    }
}
