#![allow(clippy::restriction)]
//! This module contains the sample configurations used for testing and benchmarking throghout Iroha.
use std::{collections::HashSet, path::Path, str::FromStr};

use eyre::WrapErr as _;
use iroha_config::{
    iroha::{Configuration, ConfigurationProxy},
    sumeragi::TrustedPeers,
    torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_P2P_ADDR, DEFAULT_TORII_TELEMETRY_URL},
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{peer::PeerId, prelude::*};

/// Get sample trusted peers. The public key must be the same as `configuration.public_key`
///
/// # Panics
/// Never
pub fn get_trusted_peers(public_key: Option<&PublicKey>) -> HashSet<PeerId> {
    let mut trusted_peers: HashSet<PeerId> = [
        (
            "localhost:1338",
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C1",
        ),
        (
            "195.162.0.1:23",
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C2",
        ),
        (
            "195.162.0.1:24",
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C3",
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
/// Get a sample Iroha configuration proxy. Trusted peers must be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt. Almost equivalent to the [`get_config`]
/// function, except the proxy is left unbuilt.
///
/// # Panics
/// - when [`KeyPair`] generation fails (rare case).
pub fn get_config_proxy(peers: HashSet<PeerId>, key_pair: Option<KeyPair>) -> ConfigurationProxy {
    let (public_key, private_key) = key_pair
        .unwrap_or_else(|| KeyPair::generate().expect("Key pair generation failed"))
        .into();
    iroha_logger::info!(%public_key);
    ConfigurationProxy {
        public_key: Some(public_key.clone()),
        private_key: Some(private_key.clone()),
        sumeragi: Some(iroha_config::sumeragi::ConfigurationProxy {
            max_transactions_in_block: Some(2),
            trusted_peers: Some(TrustedPeers { peers }),
            ..iroha_config::sumeragi::ConfigurationProxy::default()
        }),
        torii: Some(iroha_config::torii::ConfigurationProxy {
            p2p_addr: Some(DEFAULT_TORII_P2P_ADDR.to_owned()),
            api_url: Some(DEFAULT_API_URL.to_owned()),
            telemetry_url: Some(DEFAULT_TORII_TELEMETRY_URL.to_owned()),
            ..iroha_config::torii::ConfigurationProxy::default()
        }),
        block_sync: Some(iroha_config::block_sync::ConfigurationProxy {
            block_batch_size: Some(1),
            gossip_period_ms: Some(500),
            ..iroha_config::block_sync::ConfigurationProxy::default()
        }),
        queue: Some(iroha_config::queue::ConfigurationProxy {
            ..iroha_config::queue::ConfigurationProxy::default()
        }),
        genesis: Some(iroha_config::genesis::ConfigurationProxy {
            account_private_key: Some(Some(private_key)),
            account_public_key: Some(public_key),
        }),
        ..ConfigurationProxy::default()
    }
}

#[allow(clippy::implicit_hasher)]
/// Get a sample Iroha configuration. Trusted peers must either be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt.
///
/// # Panics
/// - when [`KeyPair`] generation fails (rare case).
pub fn get_config(trusted_peers: HashSet<PeerId>, key_pair: Option<KeyPair>) -> Configuration {
    get_config_proxy(trusted_peers, key_pair)
        .build()
        .expect("Iroha config should build as all required fields were provided")
}

/// Construct validator from path.
///
/// `relative_path` should be relative to `CARGO_MANIFEST_DIR`.
///
/// # Errors
///
/// - Failed to create temp dir for validator output
/// - Failed to build validator
/// - Failed to optimize validator
pub fn construct_validator<P>(relative_path: &P) -> color_eyre::Result<Validator>
where
    P: AsRef<Path> + ?Sized,
{
    let build_dir =
        tempfile::tempdir().wrap_err("Failed to create temp dir for runtime validator output")?;

    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path)
        .out_dir(build_dir.path())
        .build()?
        .optimize()?
        .into_bytes();

    Ok(Validator::new(WasmSmartContract::from_compiled(wasm_blob)))
}
