//! This module contains [`struct@Configuration`] structure and related implementation.
#![allow(clippy::std_instead_of_core)]
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config_base::derive::{view, Documented, LoadFromEnv, Proxy};
use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration parameters for a peer
    #[derive(Debug, Clone, Deserialize, Serialize, Proxy, LoadFromEnv, Documented)]
    #[serde(default)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_")]
    pub struct Configuration {
        /// Public key of this peer
        #[config(serde_as_str)]
        pub public_key: PublicKey,
        /// Private key of this peer
        #[view(ignore)]
        pub private_key: PrivateKey,
        /// Disable coloring of the backtrace and error report on panic
        pub disable_panic_terminal_colors: bool,
        /// `Kura` configuration
        #[config(inner)]
        pub kura: kura::Configuration,
        /// `Sumeragi` configuration
        #[config(inner)]
        #[view(into = sumeragi::ConfigurationView)]
        pub sumeragi: sumeragi::Configuration,
        /// `Torii` configuration
        #[config(inner)]
        pub torii: torii::Configuration,
        /// `BlockSynchronizer` configuration
        #[config(inner)]
        pub block_sync: block_sync::Configuration,
        /// `Queue` configuration
        #[config(inner)]
        pub queue: queue::Configuration,
        /// `Logger` configuration
        #[config(inner)]
        pub logger: logger::Configuration,
        /// `GenesisBlock` configuration
        #[config(inner)]
        #[view(into = genesis::ConfigurationView)]
        pub genesis: genesis::Configuration,
        /// `WorldStateView` configuration
        #[config(inner)]
        pub wsv: wsv::Configuration,
        /// Network configuration
        #[config(inner)]
        pub network: network::Configuration,
        /// Telemetry configuration
        #[config(inner)]
        pub telemetry: telemetry::Configuration,
    }
}

impl Default for Configuration {
    fn default() -> Self {
        let sumeragi_configuration = sumeragi::Configuration::default();
        let (public_key, private_key) = sumeragi_configuration.key_pair.clone().into();

        Self {
            public_key,
            private_key,
            disable_panic_terminal_colors: bool::default(),
            kura: kura::Configuration::default(),
            sumeragi: sumeragi_configuration,
            torii: torii::Configuration::default(),
            block_sync: block_sync::Configuration::default(),
            queue: queue::Configuration::default(),
            logger: logger::Configuration::default(),
            genesis: genesis::Configuration::default(),
            wsv: wsv::Configuration::default(),
            network: network::Configuration::default(),
            telemetry: telemetry::Configuration::default(),
        }
    }
}

impl Configuration {
    /// Construct [`struct@Self`] from a path-like object.
    ///
    /// # Errors
    /// - File not found.
    /// - File found, but peer configuration parsing failed.
    /// - The length of the array in raw JSON representation is different
    /// from the length of the array in
    /// [`self.sumeragi.trusted_peers.peers`], most likely due to two
    /// (or more) peers having the same public key.
    pub fn from_path<P: AsRef<Path> + Debug + Clone>(path: P) -> Result<Configuration> {
        let file = File::open(path.clone())
            .wrap_err(format!("Failed to open the config file {:?}", path))?;
        let reader = BufReader::new(file);
        let mut configuration: Configuration = serde_json::from_reader(reader).wrap_err(
            format!("Failed to parse {:?} as Iroha peer configuration.", path),
        )?;
        configuration.finalize()?;
        Ok(configuration)
    }

    fn finalize(&mut self) -> Result<()> {
        self.sumeragi.key_pair = KeyPair::new(self.public_key.clone(), self.private_key.clone())?;
        self.sumeragi.peer_id =
            iroha_data_model::peer::Id::new(&self.torii.p2p_addr, &self.public_key.clone());

        Ok(())
    }

    /// Load configuration from the environment
    ///
    /// # Errors
    /// Fails if Configuration deserialization fails (e.g. if `TrustedPeers` contains entries with duplicate public keys)
    pub fn load_environment(&mut self) -> Result<()> {
        <Self as iroha_config_base::proxy::LoadFromEnv>::load_environment(self)?;
        self.finalize()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;
    use crate::sumeragi::TrustedPeers;

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
