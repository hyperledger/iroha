//! This module contains the sample configurations used for testing and benchmarking throughout Iroha.
use std::{collections::HashSet, path::Path, str::FromStr};

use iroha_config::{
    base::toml::TomlSource,
    parameters::{actual::Root as Config, user::CliContext},
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
/// Sample Iroha configuration in an unparsed format.
///
/// [`get_config`] gives the parsed, complete version of it.
///
/// Trusted peers must either be specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt.
pub fn get_config_toml(
    peers: UniqueVec<PeerId>,
    chain_id: ChainId,
    peer_key_pair: KeyPair,
    genesis_key_pair: KeyPair,
) -> toml::Table {
    let (public_key, private_key) = peer_key_pair.clone().into_parts();
    let (genesis_public_key, genesis_private_key) = genesis_key_pair.into_parts();

    iroha_logger::info!(%public_key, "sample configuration public key");

    let mut raw = toml::Table::new();
    iroha_config::base::toml::Writer::new(&mut raw)
        .write("chain_id", chain_id)
        .write("public_key", public_key)
        .write("private_key", private_key)
        .write(["sumeragi", "trusted_peers"], peers)
        .write(["network", "address"], DEFAULT_P2P_ADDR)
        .write(["network", "block_gossip_period"], 500)
        .write(["network", "block_gossip_max_size"], 1)
        .write(["torii", "address"], DEFAULT_TORII_ADDR)
        .write(["chain_wide", "max_transactions_in_block"], 2)
        .write(["genesis", "public_key"], genesis_public_key)
        .write(["genesis", "private_key"], genesis_private_key)
        .write(["genesis", "file"], "NEVER READ ME; YOU FOUND A BUG!")
        // There is no need in persistence in tests.
        // If required to should be set explicitly not to overlap with other existing tests
        .write(["snapshot", "mode"], "disabled");

    raw
}

#[allow(clippy::implicit_hasher)]
/// Get a sample Iroha configuration. Trusted peers must either be
/// specified in this function, including the current peer. Use [`get_trusted_peers`]
/// to populate `trusted_peers` if in doubt.
pub fn get_config(
    trusted_peers: UniqueVec<PeerId>,
    chain_id: ChainId,
    peer_key_pair: KeyPair,
    genesis_key_pair: KeyPair,
) -> Config {
    Config::from_toml_source(
        TomlSource::inline(get_config_toml(
            trusted_peers,
            chain_id,
            peer_key_pair,
            genesis_key_pair,
        )),
        CliContext {
            submit_genesis: true,
        },
    )
    .expect("should be a valid config")
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
pub fn construct_executor<P>(relative_path: &P) -> eyre::Result<Executor>
where
    P: AsRef<Path> + ?Sized,
{
    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path)
        .build()?
        .optimize()?
        .into_bytes()?;

    Ok(Executor::new(WasmSmartContract::from_compiled(wasm_blob)))
}
