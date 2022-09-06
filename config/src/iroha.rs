//! This module contains [`struct@Configuration`] structure and related implementation.
#![allow(clippy::std_instead_of_core)]
use std::{fmt::Debug, fs::File, io::BufReader, path::Path};

use eyre::{Result, WrapErr};
use iroha_config_base::{
    derive::{view, Documented, Error as ConfigError, LoadFromEnv, Proxy},
    proxy::Builder,
};
use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration parameters for a peer
    #[derive(Debug, Clone, Deserialize, Serialize, Proxy, Documented, LoadFromEnv)]
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

impl Default for ConfigurationProxy {
    fn default() -> Self {
        Self {
            public_key: None,
            private_key: None,
            disable_panic_terminal_colors: Some(bool::default()),
            kura: Some(kura::ConfigurationProxy::default()),
            sumeragi: Some(sumeragi::ConfigurationProxy::default()),
            torii: Some(torii::ConfigurationProxy::default()),
            block_sync: Some(block_sync::ConfigurationProxy::default()),
            queue: Some(queue::ConfigurationProxy::default()),
            logger: Some(logger::ConfigurationProxy::default()),
            genesis: Some(genesis::ConfigurationProxy::default()),
            wsv: Some(wsv::ConfigurationProxy::default()),
            network: Some(network::ConfigurationProxy::default()),
            telemetry: Some(telemetry::ConfigurationProxy::default()),
        }
    }
}

impl ConfigurationProxy {
    /// Finalise Iroha config proxy by instantiating mutually equivalent fields
    /// via the uppermost Iroha config fields. Configuration fields provided in the
    /// Iroha config always overwrite those in sumeragi even in case of discrepancy,
    /// so proper care is advised.
    ///
    /// # Errors
    /// - If the relevant uppermost Iroha config fields were not provided.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn finalize(&mut self) -> Result<()> {
        if let Some(sumeragi_proxy) = &mut self.sumeragi {
            // First, iroha public/private key and sumeragi keypair are interchangeable, but
            // the user is allowed to provide only the former, and keypair is generated automatically,
            // bailing out if key_pair provided in sumeragi no matter its value
            if sumeragi_proxy.key_pair.is_some() {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "Sumeragi should not be provided with `key_pair` directly as it is instantiated via Iroha config"
                        .to_owned()))
            }
            if let (Some(public_key), Some(private_key)) = (&self.public_key, &self.private_key) {
                sumeragi_proxy.key_pair =
                    Some(KeyPair::new(public_key.clone(), private_key.clone())?);
            } else {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "Iroha public and private key not supplied, instantiating sumeragi keypair is impossible"
                        .to_owned()
                ))
            }
            // Second, torii gateway and sumeragi peer id are interchangeable too; the latter is derived from the
            // former and overwritten silently in case of difference
            if let Some(torii_proxy) = &mut self.torii {
                if sumeragi_proxy.peer_id.is_none() {
                    sumeragi_proxy.peer_id = Some(iroha_data_model::peer::Id::new(
                        &torii_proxy.p2p_addr.clone().ok_or_else(|| {
                            eyre::eyre!("Torii `p2p_addr` field has `None` value")
                        })?,
                        &self.public_key.clone().expect(
                            "Iroha `public_key` should have been initialized above at the latest",
                        ),
                    ));
                } else {
                    eyre::bail!(ConfigError::ProxyBuildError(
                        "Sumeragi should not be provided with `peer_id` directly".to_owned()
                    ))
                }
            } else {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "Torii config should have at least `p2p_addr` provided for sumeragi finalisation"
                        .to_owned()
                ))
            }
            // Finally, if trusted peers were not supplied, we can fall back to inserting itself as
            // the only trusted one
            if sumeragi_proxy.trusted_peers.is_none() {
                sumeragi_proxy.insert_self_as_trusted_peers()
            }
        }

        Ok(())
    }

    /// The wrapper around the topmost Iroha `ConfigurationProxy`
    /// that performs finalisation prior to building. For the uppermost
    /// Iroha config, its `<Self as iroha_config_base::proxy::Builder>::build()`
    /// method should never be used directly, as only this wrapper ensures final
    /// coherence.
    ///
    /// # Errors
    /// - Finalisation fails
    /// - Any of the inner fields had a `None` value when that
    /// is not allowed by the defaults.
    pub fn build(mut self) -> Result<Configuration> {
        self.finalize()?;
        <Self as Builder>::build(self)
            .wrap_err("Failed to build `Configuration` from `ConfigurationProxy`")
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
    use crate::{base::proxy::LoadFromDisk, sumeragi::TrustedPeers};

    const CONFIGURATION_PATH: &str = "../configs/peer/config.json";

    #[test]
    fn parse_example_json() -> Result<()> {
        let cfg_proxy = ConfigurationProxy::from_path(CONFIGURATION_PATH)
            .wrap_err("Failed to read configuration from example config")?;
        assert_eq!("127.0.0.1:1337", cfg_proxy.torii.unwrap().p2p_addr.unwrap());
        assert_eq!(
            10000,
            cfg_proxy.block_sync.unwrap().gossip_period_ms.unwrap()
        );
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
