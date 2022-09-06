#![allow(clippy::restriction)]
//! This module contains the sample configurations used for testing and benchmarking throghout Iroha.
use std::{collections::HashSet, str::FromStr};

use iroha_config::{
    iroha::{Configuration, ConfigurationProxy},
    sumeragi::TrustedPeers,
    torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_P2P_ADDR, DEFAULT_TORII_TELEMETRY_URL},
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::peer::Id as PeerId;

/// Get sample trusted peers. The public key must be the same as `configuration.public_key`
///
/// # Panics
/// Never
pub fn get_trusted_peers(public_key: Option<&PublicKey>) -> HashSet<PeerId> {
    let mut trusted_peers: HashSet<PeerId> = [
        (
            "localhost:1338",
            "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c1",
        ),
        (
            "195.162.0.1:23",
            "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c2",
        ),
        (
            "195.162.0.1:24",
            "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c3",
        ),
    ]
    .iter()
    .map(|(a, k)| PeerId {
        address: (*a).to_string(),
        public_key: PublicKey::from_str(k).unwrap(),
    })
    .collect();
    if let Some(pubkey) = public_key {
        trusted_peers.insert(PeerId {
            address: DEFAULT_TORII_P2P_ADDR.to_owned(),
            public_key: pubkey.clone(),
        });
    }
    trusted_peers
}

#[allow(clippy::implicit_hasher)]
/// Get a sample Iroha configuration. Trusted peers must either be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt.
///
/// # Panics
/// when [`KeyPair`] generation fails (rare).
pub fn get_config(trusted_peers: HashSet<PeerId>, key_pair: Option<KeyPair>) -> Configuration {
    let (public_key, private_key) = match key_pair {
        Some(key_pair) => key_pair.into(),
        None => KeyPair::generate()
            .expect("Key pair generation failed")
            .into(),
    };
    iroha_logger::info!(?public_key);
    ConfigurationProxy {
        public_key: Some(public_key.clone()),
        private_key: Some(private_key.clone()),
        sumeragi: Some(iroha_config::sumeragi::ConfigurationProxy {
            key_pair: None,
            peer_id: None,
            trusted_peers: Some(TrustedPeers {
                peers: trusted_peers,
            }),
            ..iroha_config::sumeragi::ConfigurationProxy::default()
        }),
        torii: Some(iroha_config::torii::ConfigurationProxy {
            p2p_addr: Some(DEFAULT_TORII_P2P_ADDR.to_owned()),
            api_url: Some(DEFAULT_API_URL.to_owned()),
            telemetry_url: Some(DEFAULT_TORII_TELEMETRY_URL.to_owned()),
            max_transaction_size: Some(0x8000),
            ..iroha_config::torii::ConfigurationProxy::default()
        }),
        block_sync: Some(iroha_config::block_sync::ConfigurationProxy {
            block_batch_size: Some(1),
            gossip_period_ms: Some(500),
            ..iroha_config::block_sync::ConfigurationProxy::default()
        }),
        queue: Some(iroha_config::queue::ConfigurationProxy {
            maximum_transactions_in_block: Some(2),
            ..iroha_config::queue::ConfigurationProxy::default()
        }),
        genesis: Some(iroha_config::genesis::ConfigurationProxy {
            account_private_key: Some(Some(private_key)),
            account_public_key: Some(public_key),
            ..iroha_config::genesis::ConfigurationProxy::default()
        }),
        wsv: Some(iroha_config::wsv::ConfigurationProxy {
            wasm_runtime_config: Some(iroha_config::wasm::ConfigurationProxy {
                fuel_limit: Some(10_000_000),
                ..iroha_config::wasm::ConfigurationProxy::default()
            }),
            ..iroha_config::wsv::ConfigurationProxy::default()
        }),
        ..ConfigurationProxy::default()
    }
    .build()
    .expect("Iroha config should build as all required fields were provided")
}
