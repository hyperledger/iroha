//! This module contains [`struct@Configuration`] structure and related implementation.
use core::fmt::Debug;

use iroha_config_base::{view, Configuration, Documented};
use iroha_crypto::prelude::*;
use serde::{Deserialize, Serialize};

use super::*;

// Generate `ConfigurationView` without the private key
view! {
    /// Configuration parameters for a peer
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configuration, Documented)]
    #[serde(try_from = "ConfigurationBuilder")]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "IROHA_")]
    pub struct Configuration {
        /// Public key of this peer
        #[config(serde_as_str)]
        public_key: PublicKey,
        /// Private key of this peer
        private_key: PrivateKey,
        /// Disable coloring of the backtrace and error report on panic
        #[config(default = "false")]
        disable_panic_terminal_colors: bool,
        /// `Kura` configuration
        #[config(default = "kura::Configuration::default()")]
        kura: kura::Configuration,
        /// `Sumeragi` configuration
        #[view(into = sumeragi::ConfigurationView)]
        sumeragi: sumeragi::Configuration,
        /// `Torii` configuration
        #[config(default = "torii::Configuration::default()")]
        torii: torii::Configuration,
        /// `BlockSynchronizer` configuration
        #[config(default = "block_sync::Configuration::default()")]
        block_sync: block_sync::Configuration,
        /// `Queue` configuration
        #[config(default = "queue::Configuration::default()")]
        queue: queue::Configuration,
        /// `Logger` configuration
        #[config(default = "logger::Configuration::default()")]
        logger: logger::Configuration,
        /// `GenesisBlock` configuration
        #[view(into = genesis::ConfigurationView)]
        genesis: genesis::Configuration,
        /// `WorldStateView` configuration
        #[config(default = "wsv::Configuration::default()")]
        wsv: wsv::Configuration,
        /// Network configuration
        #[config(default = "network::Configuration::default()")]
        network: network::Configuration,
        /// Telemetry configuration
        #[config(default = "telemetry::Configuration::default()")]
        telemetry: telemetry::Configuration,
    }
}

//impl ConfigurationBuilder {
//    /// Finalise Iroha config proxy by instantiating mutually equivalent fields
//    /// via the uppermost Iroha config fields. Configuration fields provided in the
//    /// Iroha config always overwrite those in sumeragi even in case of discrepancy,
//    /// so proper care is advised.
//    ///
//    /// # Errors
//    /// - If the relevant uppermost Iroha config fields were not provided.
//    pub fn finish(&mut self) -> Result<(), ConfigError> {
//        if let Some(sumeragi_proxy) = &mut self.sumeragi {
//            // First, iroha public/private key and sumeragi keypair are interchangeable, but
//            // the user is allowed to provide only the former, and keypair is generated automatically,
//            // bailing out if key_pair provided in sumeragi no matter its value
//            if sumeragi_proxy.key_pair.is_some() {
//                return Err(ConfigError::ProvidedInferredField {
//                    field: "key_pair",
//                    message: "Sumeragi should not be provided with `KEY_PAIR` directly. That value is computed from the other config parameters. Please set the `KEY_PAIR` to `null` or omit entirely."
//                });
//            }
//            if let (Some(public_key), Some(private_key)) = (&self.public_key, &self.private_key) {
//                sumeragi_proxy.set_key_pair(KeyPair::new(public_key.clone(), private_key.clone())?);
//            }
//            // Second, torii gateway and sumeragi peer id are interchangeable too; the latter is derived from the
//            // former and overwritten silently in case of difference
//            if let Some(torii_proxy) = &mut self.torii {
//                if sumeragi_proxy.peer_id.is_none() {
//                    sumeragi_proxy.peer_id = Some(iroha_data_model::prelude::PeerId::new(
//                        &torii_proxy
//                            .p2p_addr
//                            .clone()
//                            .ok_or(ConfigError::MissingField("p2p_addr"))?,
//                        &self.public_key.clone().expect(
//                            "Iroha `public_key` should have been initialized above at the latest",
//                        ),
//                    ));
//                } else {
//                    // TODO: should we just warn the user that this value will be ignored?
//                    // TODO: Consider eliminating this value from the public API.
//                    return Err(ConfigError::ProvidedInferredField {
//                        field: "PEER_ID",
//                        message: "The `peer_id` is computed from the key and address. You should remove it from the config.",
//                    });
//                }
//            } else {
//                return Err(ConfigError::MissingField{
//                    field: "p2p_addr",
//                    message: "Torii config should have at least `p2p_addr` provided for sumeragi finalisation",
//                });
//            }
//            if sumeragi_proxy.trusted_peers.is_none() {
//                // TODO: Why should self ever be in the set of trusted peers?
//                sumeragi_proxy.insert_self_as_trusted_peers()
//            }
//        }
//
//        Ok(())
//    }
//}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_data_model::peer::PeerId;
    use proptest::prelude::*;

    use super::*;
    use crate::sumeragi::OrderedSet;

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
            disable_panic_terminal_colors in prop::option::of(Just(Configuration::DEFAULT_DISABLE_PANIC_TERMINAL_COLORS())),
            kura in prop::option::of(Configuration::DEFAULT_KURA()),
            sumeragi in prop::option::of(sumeragi::tests::arb_proxy()),
            torii in prop::option::of(torii::tests::arb_proxy()),
            block_sync in prop::option::of(block_sync::tests::arb_proxy()),
            queue in prop::option::of(queue::tests::arb_proxy()),
            logger in prop::option::of(logger::tests::arb_proxy()),
            genesis in prop::option::of(genesis::tests::arb_proxy()),
            wsv in prop::option::of(wsv::tests::arb_proxy()),
            network in prop::option::of(network::tests::arb_proxy()),
            telemetry in prop::option::of(telemetry::tests::arb_proxy()),
            ) -> ConfigurationBuilder {
            ConfigurationBuilder { public_key, private_key, disable_panic_terminal_colors, kura, sumeragi, torii, block_sync, queue,
                                 logger, genesis, wsv, network, telemetry }
        }
    }

    proptest! {
        #[test]
        fn iroha_proxy_build_fails_on_none(proxy in arb_proxy()) {
            let cfg = proxy.build();
            let example_cfg = ConfigurationBuilder::from_path(CONFIGURATION_PATH).build().expect("Failed to build example Iroha config");
            if cfg.is_ok() {
                assert_eq!(cfg.unwrap(), example_cfg)
            }
        }
    }

    #[test]
    fn parse_example_json() {
        let cfg_proxy = ConfigurationBuilder::from_path(CONFIGURATION_PATH);
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
        ConfigurationBuilder::from_path(CONFIGURATION_PATH).build().unwrap_or_else(|_| panic!("`ConfigurationBuilder` specified in {CONFIGURATION_PATH} \
                                                                                          failed to build. This probably means that some of the fields there were not updated \
                                                                                          properly with new changes."));
    }

    #[test]
    #[should_panic]
    fn parse_trusted_peers_fail_duplicate_peer_id() {
        let trusted_peers_string = r#"[{"address":"127.0.0.1:1337", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address":"127.0.0.1:1337", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address":"localhost:1338", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}, {"address": "195.162.0.1:23", "public_key": "ed0120954C83A4220FAFFB2C1D23FC5225B3E7952D53ACBB2A065FF30C631E5E1D6B10"}]"#;
        let _result: OrderedSet<PeerId> =
            serde_json::from_str(trusted_peers_string).expect("Failed to parse Trusted Peers");
    }
}
