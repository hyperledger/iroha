#![allow(clippy::restriction)]
//! This module contains the sample configurations used for testing and benchmarking throghout Iroha.
use std::{collections::HashSet, str::FromStr};

use iroha_core::{
    block_sync::config::BlockSyncConfiguration,
    genesis::config::GenesisConfiguration,
    kura::config::KuraConfiguration,
    queue::Configuration as QueueConfiguration,
    smartcontracts::wasm::config::Configuration as WasmConfiguration,
    sumeragi::config::{SumeragiConfiguration, TrustedPeers},
    wsv::config::Configuration as WsvConfiguration,
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::peer::Id as PeerId;

use crate::{
    config::Configuration,
    torii::config::{ToriiConfiguration, DEFAULT_TORII_P2P_ADDR},
};

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
    Configuration {
        public_key: public_key.clone(),
        private_key: private_key.clone(),
        kura: KuraConfiguration {
            init_mode: iroha_core::kura::Mode::Strict,
            block_store_path: "./blocks".into(),
            ..KuraConfiguration::default()
        },
        sumeragi: SumeragiConfiguration {
            key_pair: KeyPair::new(public_key.clone(), private_key.clone())
                .expect("Key pair mismatch"),
            peer_id: PeerId::new(DEFAULT_TORII_P2P_ADDR, &public_key),
            trusted_peers: TrustedPeers {
                peers: trusted_peers,
            },
            gossip_period_ms: 500,
            ..SumeragiConfiguration::default()
        },
        torii: ToriiConfiguration {
            max_transaction_size: 0x8000,
            ..ToriiConfiguration::default()
        },
        block_sync: BlockSyncConfiguration {
            batch_size: 1,
            gossip_period_ms: 5000,
            ..BlockSyncConfiguration::default()
        },
        queue: QueueConfiguration {
            maximum_transactions_in_block: 2,
            ..QueueConfiguration::default()
        },
        genesis: GenesisConfiguration {
            account_public_key: public_key,
            account_private_key: Some(private_key),
            ..GenesisConfiguration::default()
        },
        wsv: WsvConfiguration {
            wasm_runtime_config: WasmConfiguration {
                fuel_limit: 10_000_000,
                ..WasmConfiguration::default()
            },
            ..WsvConfiguration::default()
        },
        ..Configuration::default()
    }
}
