//! This module contains the sample configurations used for testing and benchmarking throughout Iroha.
use std::{collections::HashSet, path::Path, str::FromStr, time::Duration};

use iroha_config::{
    base::{UnwrapPartial, UserDuration},
    parameters::{
        actual::Root as Config,
        user_layer::{CliContext, RootPartial as UserConfig},
    },
};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::{peer::PeerId, prelude::*, ChainId};
use iroha_primitives::{
    addr::{socket_addr, SocketAddr},
    unique_vec::UniqueVec,
};

// FIXME: move to a global test-related place, re-use everywhere else
const DEFAULT_P2P_ADDR: SocketAddr = socket_addr!(127.0.0.1:1337);
const DEFAULT_TORII_ADDR: SocketAddr = socket_addr!(127.0.0.1:8080);

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
    .map(|(a, k)| PeerId::new(a.parse().expect("Valid"), PublicKey::from_str(k).unwrap()))
    .collect();
    if let Some(pubkey) = public_key {
        trusted_peers.insert(PeerId {
            address: DEFAULT_P2P_ADDR.clone(),
            public_key: pubkey.clone(),
        });
    }
    trusted_peers
}

#[allow(clippy::implicit_hasher)]
/// Get a sample Iroha configuration on user-layer level. Trusted peers must be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt. Almost equivalent to the [`get_config`]
/// function, except the proxy is left unbuilt.
///
/// # Panics
/// - when [`KeyPair`] generation fails (rare case).
pub fn get_user_config(
    peers: UniqueVec<PeerId>,
    chain_id: Option<ChainId>,
    key_pair: Option<KeyPair>,
) -> UserConfig {
    let chain_id = chain_id.unwrap_or_else(|| ChainId::new("0".to_owned()));

    let (public_key, private_key) = key_pair.unwrap_or_else(KeyPair::generate).into();
    iroha_logger::info!(%public_key);

    let mut config = UserConfig::new();

    config.iroha.chain_id.set(chain_id);
    config.iroha.public_key.set(public_key.clone());
    config.iroha.private_key.set(private_key.clone());
    config.iroha.p2p_address.set(DEFAULT_P2P_ADDR);
    config
        .chain_wide
        .max_transactions_in_block
        .set(2.try_into().unwrap());
    config.sumeragi.trusted_peers.peers = peers.to_vec();
    config.torii.address.set(DEFAULT_TORII_ADDR);
    config
        .network
        .max_blocks_per_gossip
        .set(1.try_into().unwrap());
    config
        .network
        .block_gossip_period
        .set(UserDuration(Duration::from_millis(500)));
    config.genesis.private_key.set(private_key);
    config.genesis.public_key.set(public_key);
    config.genesis.file.set("./genesis.json".into());

    config
}

#[allow(clippy::implicit_hasher)]
/// Get a sample Iroha configuration. Trusted peers must either be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt.
///
/// # Panics
/// - when [`KeyPair`] generation fails (rare case).
pub fn get_config(
    trusted_peers: UniqueVec<PeerId>,
    chain_id: Option<ChainId>,
    key_pair: Option<KeyPair>,
) -> Config {
    get_user_config(trusted_peers, chain_id, key_pair)
        .unwrap_partial()
        .expect("config should build as all required fields were provided")
        .parse(CliContext {
            submit_genesis: true,
        })
        .expect("config should finalize as the input is semantically valid (or there is a bug)")
}

/// Construct executor from path.
///
/// `relative_path` should be relative to `CARGO_MANIFEST_DIR`.
///
/// # Errors
///
/// - Failed to create temp dir for executor output
/// - Failed to build executor
/// - Failed to optimize executor
pub fn construct_executor<P>(relative_path: &P) -> color_eyre::Result<Executor>
where
    P: AsRef<Path> + ?Sized,
{
    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path)
        .build()?
        .optimize()?
        .into_bytes()?;

    Ok(Executor::new(WasmSmartContract::from_compiled(wasm_blob)))
}
