//! A node subscribes to the same original P2P actor that owns its outbound transport.

use super::*;
use iroha_config::{
    base::{WithOrigin, read::ConfigReader},
    parameters::user,
};
use iroha_futures::supervisor::Supervisor;
use iroha_p2p::{
    P2pIdentityKeys,
    network::message::{UpdatePeers, UpdateTopology},
};
use iroha_sumeragi::{
    crypto::{Crypto, Signer},
    message::{Vote, VoteKind, WireMessage},
    types::Signature,
};
use std::collections::HashSet;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("real P2P test runtime")
}

fn network_config(replay_root: &std::path::Path) -> iroha_config::parameters::actual::Network {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../iroha_config/iroha_test_config.toml");
    let user = ConfigReader::new()
        .without_env()
        .read_toml_with_extends(&path)
        .unwrap()
        .read_and_complete::<user::Root>()
        .unwrap();
    let mut config = user.parse().unwrap().network;
    // Bind a fresh loopback address; the production parser supplies all protocol and
    // byte-bound defaults. This test changes only local listening/dial timing settings.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().into();
    drop(listener);
    config.address = WithOrigin::inline(address);
    config.public_address = config.address.clone();
    config.connect_startup_delay = Duration::ZERO;
    config.soranet_handshake.pow.revocation_store_path = replay_root
        .join("revocations.norito")
        .to_str()
        .unwrap()
        .to_owned()
        .into();
    config
}

async fn live_network(
    key: &KeyPair,
    network_id: NetworkId,
    targets: HashSet<PeerId>,
    supervisor: &mut Supervisor,
) -> (
    IrohaNetwork,
    iroha_primitives::addr::SocketAddr,
    tempfile::TempDir,
) {
    let replay_root = tempfile::tempdir().unwrap();
    let config = network_config(replay_root.path());
    let address = config.public_address.value().clone();
    let transport = KeyPair::from_seed(vec![0xEA; 32], Algorithm::Ed25519);
    let (network, child) = IrohaNetwork::start_with_crypto_and_initial_authorities(
        P2pIdentityKeys::new(key.clone(), transport).unwrap(),
        config,
        network_id,
        None,
        None,
        None,
        targets.clone(),
        targets,
        supervisor.shutdown_signal(),
    )
    .await
    .expect("real network actor startup");
    supervisor.monitor(child);
    (network, address, replay_root)
}

fn prepared_root(chain: &Chain) -> (Arc<State>, Arc<Kura>, Prepared) {
    let kura = Kura::blank_kura_for_testing();
    let state = empty_state(&chain.chain_id, &chain.genesis, &kura);
    let prepared = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(16).0,
        genesis: Some(chain.genesis.clone()),
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    })
    .expect("authenticated original root");
    (state, kura, prepared)
}

fn inputs(
    chain: &Chain,
    dir: &std::path::Path,
    network: IrohaNetwork,
) -> StartInputs<P2pNet<IrohaNetwork>> {
    let (_, time) = TimeSource::new_mock(Duration::ZERO);
    StartInputs {
        net: Arc::new(P2pNet::new(network)),
        queue: Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        )),
        key_pair: chain.keys[0].clone(),
        beacon_signer: None,
        config: NodeConfig {
            records_dir: dir.join("records"),
            installation_log: dir.join("keys/installation.log"),
            bodies_dir: dir.join("bodies"),
            local: SumeragiLocalOverrides::default(),
            assert_fresh_key: true,
            retired_keys: Vec::new(),
        },
        observer: Arc::new(LogObserver),
        driver: DriverConfig::default(),
    }
}

#[test]
fn network_start_rejects_closed_retained_actor_before_driver_files() {
    let chain = chain(4, 200);
    let (state, kura, prepared) = prepared_root(&chain);
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let mut supervisor = Supervisor::new();
    let (unrelated, _, _replay_root) = runtime.block_on(live_network(
        &chain.keys[1],
        *state.network_id_ref(),
        HashSet::from([PeerId::new(chain.keys[0].public_key().clone())]),
        &mut supervisor,
    ));
    assert!(
        unrelated.online_peers_receiver().has_changed().is_ok(),
        "the independent actor remains live but grants no startup authority"
    );
    let result = prepared.start_on_network(
        inputs(&chain, dir.path(), IrohaNetwork::closed_for_tests()),
        16,
    );
    let files_created = ["records", "keys", "bodies"].map(|path| dir.path().join(path).exists());
    // Clean up any wrongly started original driver before the failing-before assertion.
    let error = match result {
        Ok(node) => {
            node.shutdown();
            None
        }
        Err(error) => Some(error),
    };
    supervisor.shutdown_signal().send();
    runtime
        .block_on(supervisor.start())
        .expect("normal network shutdown");
    assert!(
        matches!(error, Some(NodeError::Subscription(_))),
        "a separate live subscription actor cannot authorize a closed retained sender: {error:?}; files={files_created:?}"
    );
    assert!(!dir.path().join("records").exists());
    assert!(!dir.path().join("keys").exists());
    assert!(!dir.path().join("bodies").exists());
    assert_eq!(state.view().height(), 1);
    assert_eq!(kura.blocks_count(), 1);
}

#[test]
fn retained_live_actor_delivers_signed_native_ingress() {
    let chain = chain(4, 200);
    let (state, kura, prepared) = prepared_root(&chain);
    let instance = prepared.instance();
    let config = state
        .view()
        .world()
        .consensus_schedule()
        .ready(2)
        .unwrap()
        .height_config()
        .unwrap();
    let remote = KeyPairSigner::new(&chain.keys[1]).unwrap();
    let mut vote = Vote {
        kind: VoteKind::Prepare,
        instance,
        epoch: config.epoch.id,
        height: 2,
        view: 0,
        block_hash: Hash32([0xAB; 32]),
        result: Hash32([0xBC; 32]),
        signer: config.committee.index_of(remote.public_key()).unwrap(),
        sig: Signature([0; 96]),
    };
    vote.sig = remote.sign(&vote.preimage());
    assert!(
        prepared
            .crypto
            .verify(remote.public_key(), &vote.preimage(), &vote.sig)
    );
    let frame = Frame {
        instance,
        class: iroha_sumeragi::message::TrafficClass::Control,
        bytes: Arc::from(WireMessage::Vote(vote).encode().unwrap()),
    };
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let mut supervisor = Supervisor::new();
    let local_peer = PeerId::new(chain.keys[0].public_key().clone());
    let remote_peer = PeerId::new(chain.keys[1].public_key().clone());
    let (local, _, _local_replay_root) = runtime.block_on(live_network(
        &chain.keys[0],
        *state.network_id_ref(),
        HashSet::from([remote_peer.clone()]),
        &mut supervisor,
    ));
    let (remote_actor, remote_address, _remote_replay_root) = runtime.block_on(live_network(
        &chain.keys[1],
        *state.network_id_ref(),
        HashSet::from([local_peer.clone()]),
        &mut supervisor,
    ));
    let node = prepared
        .start_on_network(inputs(&chain, dir.path(), local.clone()), 16)
        .unwrap();
    let ingress = Arc::clone(&node.ingress);
    let sender = P2pNet::new(remote_actor.clone());
    local.update_topology(UpdateTopology(HashSet::from([remote_peer.clone()])));
    remote_actor.update_topology(UpdateTopology(HashSet::from([local_peer])));
    local.update_peers_addresses(UpdatePeers(vec![(remote_peer, remote_address)]));
    let outcome = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            for network in [&local, &remote_actor] {
                let mut peers = network.online_peers_receiver();
                while peers.borrow().is_empty() {
                    peers
                        .changed()
                        .await
                        .map_err(|_| "original peer watch closed")?;
                }
            }
            let sent = sender.send(&core_key(chain.keys[0].public_key()).unwrap(), &frame);
            if !matches!(sent, SendOutcome::Admitted) {
                return Err("live original actor refused the signed message");
            }
            while ingress.stats().delivered == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(())
        })
        .await
    });
    node.shutdown();
    supervisor.shutdown_signal().send();
    runtime
        .block_on(supervisor.start())
        .expect("normal peer network shutdown");
    outcome
        .expect("signed original frame crosses the retained actor subscription")
        .expect("live original peer admission");
    assert!(ingress.stats().delivered > 0);
    assert_eq!(
        state.view().height(),
        1,
        "one vote grants no publication authority"
    );
    assert_eq!(kura.blocks_count(), 1);
}
