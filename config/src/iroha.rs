//! This module contains [`struct@Configuration`] structure and related implementation.
#![allow(clippy::std_instead_of_core)]
use std::fmt::Debug;

use eyre::{Result, WrapErr};
use iroha_config_base::derive::{view, Documented, Error as ConfigError, LoadFromEnv, Proxy};
use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration parameters for a peer
    #[derive(Debug, Clone, Deserialize, Serialize, Proxy, Documented, LoadFromEnv, PartialEq, Eq)]
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
    pub fn finish(&mut self) -> Result<()> {
        if let Some(sumeragi_proxy) = &mut self.sumeragi {
            // First, iroha public/private key and sumeragi keypair are interchangeable, but
            // the user is allowed to provide only the former, and keypair is generated automatically,
            // bailing out if key_pair provided in sumeragi no matter its value
            if sumeragi_proxy.key_pair.is_some() {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "Sumeragi should not be provided with `key_pair` directly as it is instantiated via Iroha config. Please set the `KEY_PAIR` to `null` or omit them entirely."
                        .to_owned()))
            }
            if let (Some(public_key), Some(private_key)) = (&self.public_key, &self.private_key) {
                sumeragi_proxy.key_pair =
                    Some(KeyPair::new(public_key.clone(), private_key.clone())?);
            } else {
                eyre::bail!(ConfigError::ProxyBuildError(
                    "Iroha public and private key not supplied, instantiating `sumeragi` keypair is impossible. Please provide `PRIVATE_KEY` and `PUBLIC_KEY` variables."
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
                    // TODO: should we just warn the user that this value will be ignored?
                    eyre::bail!(ConfigError::ProxyBuildError(
                        "Sumeragi should not be provided with `peer_id` directly. It is computed from the other provided values.".to_owned()
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
    /// - Building fails, e.g. any of the inner fields had a `None` value when that
    /// is not allowed by the defaults.
    pub fn build(mut self) -> Result<Configuration> {
        self.finish()?;
        <Self as iroha_config_base::proxy::Builder>::build(self)
            .wrap_err("Failed to build `Configuration` from `ConfigurationProxy`")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use proptest::prelude::*;

    use super::*;
    use crate::{base::proxy::LoadFromDisk, sumeragi::TrustedPeers};

    const CONFIGURATION_PATH: &str = "./iroha_test_config.json";

    /// Key-pair used for proptests generation
    #[allow(clippy::expect_used)]
    pub fn placeholder_keypair() -> KeyPair {
        let public_key = "ed01201c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
            .parse()
            .expect("Public key not in mulithash format");
        let private_key = PrivateKey::from_hex(
            Algorithm::Ed25519,
            "282ed9f3cf92811c3818dbc4ae594ed59dc1a2f78e4241e31924e101d6b1fb831c61faf8fe94e253b93114240394f79a607b7fa55f9e5a41ebec74b88055768b"
        ).expect("Private key not hex encoded");

        KeyPair::new(public_key, private_key).expect("Key pair mismatch")
    }

    fn arb_keys() -> BoxedStrategy<(Option<PublicKey>, Option<PrivateKey>)> {
        let (pub_key, priv_key) = placeholder_keypair().into();
        (
            prop::option::of(Just(pub_key)),
            prop::option::of(Just(priv_key)),
        )
            .boxed()
    }

    prop_compose! {
        fn arb_proxy()(
            (public_key, private_key) in arb_keys(),
            disable_panic_terminal_colors in prop::option::of(Just(true)),
            kura in prop::option::of(kura::tests::arb_proxy()),
            sumeragi in prop::option::of(sumeragi::tests::arb_proxy()),
            torii in prop::option::of(torii::tests::arb_proxy()),
            block_sync in prop::option::of(block_sync::tests::arb_proxy()),
            queue in prop::option::of(queue::tests::arb_proxy()),
            logger in prop::option::of(logger::tests::arb_proxy()),
            genesis in prop::option::of(genesis::tests::arb_proxy()),
            wsv in prop::option::of(wsv::tests::arb_proxy()),
            network in prop::option::of(network::tests::arb_proxy()),
            telemetry in prop::option::of(telemetry::tests::arb_proxy()),
            ) -> ConfigurationProxy {
            ConfigurationProxy { public_key, private_key, disable_panic_terminal_colors, kura, sumeragi, torii, block_sync, queue,
                                 logger, genesis, wsv, network, telemetry }
        }
    }

    proptest! {
        #[test]
        fn iroha_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            let example_cfg = ConfigurationProxy::from_path(CONFIGURATION_PATH)
                .expect("Failed to read example config file").build().expect("Failed to build example Iroha config");
            if cfg.is_ok() {
                assert_eq!(cfg.unwrap(), example_cfg)
            }
        }
    }

    #[test]
    fn parse_example_json() -> Result<()> {
        let cfg_proxy = ConfigurationProxy::from_path(CONFIGURATION_PATH)
            .wrap_err("Failed to read configuration from example config")?;
        assert_eq!(
            "./storage",
            cfg_proxy.kura.unwrap().block_store_path.unwrap()
        );
        assert_eq!(
            10000,
            cfg_proxy
                .block_sync
                .expect("Block sync configuration was None")
                .gossip_period_ms
                .expect("Gossip period was None")
        );
        Ok(())
    }

    #[test]
    fn example_json_proxy_builds() -> Result<()> {
        let cfg_proxy = ConfigurationProxy::from_path(CONFIGURATION_PATH)
            .wrap_err("Failed to read configuration from example config")?;
        cfg_proxy.build()?;
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
