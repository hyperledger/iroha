//! This module contains [`struct@Configuration`] structure and related implementation.
use std::fmt::Debug;

use iroha_config_base::derive::{view, Documented, Error as ConfigError, Proxy};
use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration parameters for a peer
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Proxy, Documented)]
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
        /// SnapshotMaker configuration
        #[config(inner)]
        pub snapshot: snapshot::Configuration,
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
            snapshot: Some(snapshot::ConfigurationProxy::default()),
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
    pub fn finish(&mut self) -> Result<(), ConfigError> {
        if let Some(sumeragi_proxy) = &mut self.sumeragi {
            // First, iroha public/private key and sumeragi keypair are interchangeable, but
            // the user is allowed to provide only the former, and keypair is generated automatically,
            // bailing out if key_pair provided in sumeragi no matter its value
            if sumeragi_proxy.key_pair.is_some() {
                return Err(ConfigError::ProvidedInferredField {
                    field: "key_pair",
                    message: "Sumeragi should not be provided with `KEY_PAIR` directly. That value is computed from the other config parameters. Please set the `KEY_PAIR` to `null` or omit entirely."
                });
            }
            if let (Some(public_key), Some(private_key)) = (&self.public_key, &self.private_key) {
                sumeragi_proxy.key_pair =
                    Some(KeyPair::new(public_key.clone(), private_key.clone())?);
            } else {
                return Err(ConfigError::MissingField {
                    field: "PUBLIC_KEY and PRIVATE_KEY",
                    message: "The sumeragi keypair is not provided in the example configuration. It's done this way to ensure you don't re-use the example keys in production, and know how to generate new keys. Please have a look at \n\nhttps://hyperledger.github.io/iroha-2-docs/guide/configure/keys.html\n\nto learn more.\n\n-----",
                });
            }
            // Second, torii gateway and sumeragi peer id are interchangeable too; the latter is derived from the
            // former and overwritten silently in case of difference
            if let Some(torii_proxy) = &mut self.torii {
                if sumeragi_proxy.peer_id.is_none() {
                    sumeragi_proxy.peer_id = Some(iroha_data_model::prelude::PeerId::new(
                        &torii_proxy
                            .p2p_addr
                            .clone()
                            .ok_or(ConfigError::MissingField {
                                field: "p2p_addr",
                                message:
                                    "`p2p_addr` should not be set to `null` or `None` explicitly.",
                            })?,
                        &self.public_key.clone().expect(
                            "Iroha `public_key` should have been initialized above at the latest",
                        ),
                    ));
                } else {
                    // TODO: should we just warn the user that this value will be ignored?
                    // TODO: Consider eliminating this value from the public API.
                    return Err(ConfigError::ProvidedInferredField {
                        field: "PEER_ID",
                        message: "The `peer_id` is computed from the key and address. You should remove it from the config.",
                    });
                }
            } else {
                return Err(ConfigError::MissingField{
                    field: "p2p_addr",
                    message: "Torii config should have at least `p2p_addr` provided for sumeragi finalisation",
                });
            }

            sumeragi_proxy.insert_self_as_trusted_peers()
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
    pub fn build(mut self) -> Result<Configuration, ConfigError> {
        self.finish()?;
        <Self as iroha_config_base::proxy::Builder>::build(self)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{base::proxy::LoadFromDisk, sumeragi::TrustedPeers};

    const CONFIGURATION_PATH: &str = "./iroha_test_config.json";

    /// Key-pair used for proptests generation
    pub fn placeholder_keypair() -> KeyPair {
        let private_key = PrivateKey::from_hex(
            Algorithm::Ed25519,
            "282ED9F3CF92811C3818DBC4AE594ED59DC1A2F78E4241E31924E101D6B1FB831C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B".as_ref()
        ).expect("Private key not hex encoded");

        KeyPair::new(
            "ed01201C61FAF8FE94E253B93114240394F79A607B7FA55F9E5A41EBEC74B88055768B"
                .parse()
                .expect("Public key not in mulithash format"),
            private_key,
        )
        .expect("Key pair mismatch")
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
            snapshot in prop::option::of(snapshot::tests::arb_proxy()),
            ) -> ConfigurationProxy {
            ConfigurationProxy { public_key, private_key, disable_panic_terminal_colors, kura, sumeragi, torii, block_sync, queue,
                                 logger, genesis, wsv, network, telemetry, snapshot }
        }
    }

    proptest! {
        #[test]
        fn iroha_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            let example_cfg = ConfigurationProxy::from_path(CONFIGURATION_PATH).build().expect("Failed to build example Iroha config");
            if cfg.is_ok() {
                assert_eq!(cfg.unwrap(), example_cfg)
            }
        }
    }

    #[test]
    fn parse_example_json() {
        let cfg_proxy = ConfigurationProxy::from_path(CONFIGURATION_PATH);
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
    }

    #[test]
    fn example_json_proxy_builds() {
        ConfigurationProxy::from_path(CONFIGURATION_PATH).build().unwrap_or_else(|_| panic!("`ConfigurationProxy` specified in {CONFIGURATION_PATH} \
                                                                                          failed to build. This probably means that some of the fields there were not updated \
                                                                                          properly with new changes."));
    }

    #[test]
    #[should_panic]
    fn parse_trusted_peers_fail_duplicate_peer_id() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address":"127.0.0.1:1337", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address":"localhost:1338", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address": "195.162.0.1:23", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}]"#;
        let _result: TrustedPeers =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers");
    }
}
