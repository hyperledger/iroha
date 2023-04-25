use std::{
    collections::{HashMap, HashSet},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};

use iroha_config::iroha::Configuration;
use iroha_core::{
    block::BlockBuilder,
    kura::Kura,
    prelude::*,
    queue::Queue,
    smartcontracts::Registrable,
    sumeragi::{message::*, view_change::*, *},
};
use iroha_data_model::{block::*, prelude::*, transaction::Accept};
use iroha_genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock};
use once_cell::sync::Lazy;
use rand::{seq::IteratorRandom, SeedableRng};

#[test]
fn sumeragi_commits_and_broadcasts_genesis() {
    init_telemetry();

    let pb_hash = Arc::new(Mutex::new(None));
    let pb_hash2 = pb_hash.clone();
    /* Can't have 1 peer, then block is not sent. Can't have < 4 peers because non genesis peers get upset. */
    let (_keypairs, peer_ids, _configs, _queues, sumeragis) = set_up_network(
        4,
        Arc::new(move |packet, _peer_id, _sumeragis| {
            if let message::Message::BlockCreated(block) = packet.message {
                let vb: VersionedCommittedBlock = block.block.commit_unchecked().into();
                *pb_hash2.lock().unwrap() = Some(vb.hash());
            }
        }),
    );
    let sumeragis = sumeragis.lock().unwrap();
    let sumeragi = sumeragis.get(&peer_ids[0]).unwrap();

    for _ in 0..300 {
        if sumeragi
            .apply_wsv(WorldStateView::clone)
            .block_hashes_after_hash(None)
            .len()
            == 1
        {
            if let Some(hash) = *pb_hash.lock().unwrap() {
                assert_eq!(
                    hash,
                    sumeragi
                        .apply_wsv(WorldStateView::clone)
                        .block_hashes_after_hash(None)[0]
                );
                return;
            }
        }
        sleep_ms(100);
    }
    panic!("Sumeragi did not submit genesis.");
}

#[test]
fn sumeragi_all_peers_commit_genesis() {
    init_telemetry();

    /* Can't have 1 peer, then block is not sent. Can't have < 4 peers because non genesis peers get upset. */
    let (keypairs, peer_ids, configs, _queues, sumeragis) =
        set_up_network_with_genesis(4, false, Arc::new(move |_packet, _peer_id, _sumeragis| {}));
    let sumeragis = sumeragis.lock().unwrap();
    let sumeragi = sumeragis.get(&peer_ids[0]).unwrap();
    let other_key = keypairs[1].clone();
    let other_config = configs[1].clone();

    let genesis_block: VersionedCommittedBlock = {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(genesis_world(peer_ids.clone()), Arc::clone(&kura));

        assert_eq!(wsv.height(), 0);
        assert_eq!(wsv.latest_block_hash(), None);

        let genesis_network = GenesisNetwork::test(other_config, true).unwrap();
        let transactions = genesis_network.transactions;
        assert!(
            !transactions.is_empty(),
            "Genesis transaction set contains no valid transactions"
        );

        let block = BlockBuilder {
            transactions,
            event_recommendations: Vec::new(),
            view_change_index: 0,
            committed_with_topology: network_topology::Topology::new(peer_ids.clone()),
            key_pair: other_key,
            wsv,
        }
        .build();

        assert!(
            block.rejected_transactions.is_empty(),
            "Genesis transaction set contains invalid transactions"
        );

        block.commit_unchecked().into()
    };

    sumeragi.incoming_message(MessagePacket::new(
        ProofChain::default(),
        Message::BlockSyncUpdate(genesis_block.clone().into()),
    ));

    for _ in 0..300 {
        if sumeragi
            .apply_wsv(WorldStateView::clone)
            .block_hashes_after_hash(None)
            .len()
            == 1
        {
            assert_eq!(
                genesis_block.hash(),
                sumeragi
                    .apply_wsv(WorldStateView::clone)
                    .block_hashes_after_hash(None)[0]
            );
            return;
        }
        sleep_ms(100);
    }
    panic!("Sumeragi did not commit genesis correctly.");
}

#[test]
fn sumeragi_no_faults_commit_blocks() {
    init_telemetry();

    let (_keypairs, peer_ids, _configs, queues, sumeragis) = set_up_network(
        7,
        Arc::new(move |packet, peer_id, sumeragis| {
            let sumeragis = sumeragis.lock().unwrap();
            sumeragis.get(peer_id).unwrap().incoming_message(packet);
        }),
    );

    for block_height in 1..10 {
        {
            let mut success = false;
            let mut last_block_sync = Instant::now();
            for _ in 0..300 {
                if last_block_sync.elapsed().as_secs() > 5 {
                    let sumeragis = sumeragis.lock().unwrap();
                    let mut all_blocks = Vec::new();
                    for sumeragi in sumeragis.values() {
                        sumeragi.apply_wsv(|wsv| all_blocks.extend(wsv.all_blocks_by_value()));
                    }
                    for sumeragi in sumeragis.values() {
                        for block in &all_blocks {
                            sumeragi.incoming_message(MessagePacket::new(
                                ProofChain::default(),
                                Message::BlockSyncUpdate(block.clone().into()),
                            ));
                        }
                    }
                    last_block_sync = Instant::now();
                }

                {
                    let sumeragis = sumeragis.lock().unwrap();
                    success = true;
                    for sumeragi in sumeragis.values() {
                        if sumeragi.apply_wsv(|wsv| {
                            wsv.block_hashes_after_hash(None).len() != block_height
                        }) {
                            success = false;
                        }
                    }
                    if success {
                        break;
                    }
                }
                sleep_ms(100);
            }
            assert!(success, "Not all sumeragi instances committed the block.");
        }

        let account_id: AccountId = "alice@wonderland".parse().unwrap();
        let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().expect("Valid");
        let mint_asset = MintBox::new(
            1_u32.to_value(),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );

        let transaction =
            TransactionBuilder::new(account_id.clone(), vec![mint_asset.into()], 100_000)
                .sign(get_key_pair())
                .unwrap();
        let transaction = AcceptedTransaction::accept::<false>(
            transaction,
            &blank_config().wsv.transaction_limits,
        )
        .unwrap();

        for peer_id in &peer_ids {
            let sumeragis = sumeragis.lock().unwrap();
            let wsv = sumeragis
                .get(peer_id)
                .unwrap()
                .apply_wsv(WorldStateView::clone);
            let queue = queues.get(peer_id).unwrap();
            queue.push(transaction.clone().into(), &wsv).unwrap();
        }
    }
}

#[test]
fn sumeragi_with_faults_commit_blocks() {
    init_telemetry();

    let peer_count = 7;
    let fault_count = (peer_count - 1) / 3;
    let faulty_peers: Arc<Mutex<Vec<PeerId>>> = Arc::new(Mutex::new(Vec::new()));

    let local_faulty_peers = Arc::clone(&faulty_peers);
    let (_keypairs, peer_ids, _configs, queues, sumeragis) = set_up_network(
        peer_count,
        Arc::new(move |packet, peer_id, sumeragis| {
            if !local_faulty_peers.lock().unwrap().contains(peer_id) {
                let sumeragis = sumeragis.lock().unwrap();
                sumeragis.get(peer_id).unwrap().incoming_message(packet);
            }
        }),
    );

    for block_height in 1..5 {
        {
            let mut success = false;
            let mut last_block_sync = Instant::now();
            for _ in 0..500 {
                if last_block_sync.elapsed().as_secs() > 5 {
                    let sumeragis = sumeragis.lock().unwrap();
                    let mut all_blocks = Vec::new();
                    for (peer_id, sumeragi) in sumeragis.iter() {
                        if !faulty_peers.lock().unwrap().contains(peer_id) {
                            sumeragi.apply_wsv(|wsv| all_blocks.extend(wsv.all_blocks_by_value()));
                        }
                    }
                    for sumeragi in sumeragis.values() {
                        for block in &all_blocks {
                            sumeragi.incoming_message(MessagePacket::new(
                                ProofChain::default(),
                                Message::BlockSyncUpdate(block.clone().into()),
                            ));
                        }
                    }
                    last_block_sync = Instant::now();
                }

                {
                    let sumeragis = sumeragis.lock().unwrap();
                    let mut correct_count = 0;
                    for sumeragi in sumeragis.values() {
                        if sumeragi.apply_wsv(|wsv| {
                            wsv.block_hashes_after_hash(None).len() == block_height
                        }) {
                            correct_count += 1;
                        }
                    }
                    if correct_count + faulty_peers.lock().unwrap().len() >= peer_ids.len() {
                        success = true;
                        break;
                    }
                }
                sleep_ms(100);
            }
            assert!(success, "Not all sumeragi instances committed the block.");
        }

        {
            let rng = &mut rand::rngs::StdRng::from_entropy();
            let mut fp = faulty_peers.lock().unwrap();
            fp.clear();
            fp.extend(peer_ids.iter().cloned().choose_multiple(rng, fault_count));
        }

        let account_id: AccountId = "alice@wonderland".parse().unwrap();
        let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().expect("Valid");
        let mint_asset = MintBox::new(
            1_u32.to_value(),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );

        let transaction =
            TransactionBuilder::new(account_id.clone(), vec![mint_asset.into()], 100_000)
                .sign(get_key_pair())
                .unwrap();
        let transaction = AcceptedTransaction::accept::<false>(
            transaction,
            &blank_config().wsv.transaction_limits,
        )
        .unwrap();

        for peer_id in &peer_ids {
            if !faulty_peers.lock().unwrap().contains(peer_id) {
                let sumeragis = sumeragis.lock().unwrap();
                let wsv = sumeragis
                    .get(peer_id)
                    .unwrap()
                    .apply_wsv(WorldStateView::clone);
                let queue = queues.get(peer_id).unwrap();
                queue.push(transaction.clone().into(), &wsv).unwrap();
            }
        }
    }
}

/*  This test does not actually verify that soft forking occured. It will trigger them only. Grep the log of this test for "Soft"
to ensure soft forks are actually happening. If soft fork recovery is broken then this test will fail. */
#[test]
fn sumeragi_softfork() {
    init_telemetry();

    let should_softfork = Arc::new(Mutex::new(false));
    let local_should_softfork = Arc::clone(&should_softfork);

    let (_keypairs, peer_ids, _configs, queues, sumeragis) = set_up_network(
        7,
        Arc::new(move |packet, peer_id, sumeragis| {
            if let Message::BlockCommitted(_) = packet.message {
                let s = {
                    let mut m = local_should_softfork.lock().unwrap();
                    let s = *m;
                    *m = false;
                    s
                };
                if s {
                    sleep_ms(20000);
                }
            }

            let sumeragis = sumeragis.lock().unwrap();
            sumeragis.get(peer_id).unwrap().incoming_message(packet);
        }),
    );

    for block_height in 1..5 {
        {
            let mut success = false;
            let mut last_block_sync = Instant::now();
            for _ in 0..500 {
                if last_block_sync.elapsed().as_secs() > 5 {
                    let sumeragis = sumeragis.lock().unwrap();
                    let mut all_blocks = Vec::new();
                    for sumeragi in sumeragis.values() {
                        sumeragi.apply_wsv(|wsv| all_blocks.extend(wsv.all_blocks_by_value()));
                    }
                    for sumeragi in sumeragis.values() {
                        for block in &all_blocks {
                            sumeragi.incoming_message(MessagePacket::new(
                                ProofChain::default(),
                                Message::BlockSyncUpdate(block.clone().into()),
                            ));
                        }
                    }
                    last_block_sync = Instant::now();
                }

                {
                    let sumeragis = sumeragis.lock().unwrap();
                    let mut correct_count = 0;
                    for sumeragi in sumeragis.values() {
                        if sumeragi.apply_wsv(|wsv| {
                            wsv.block_hashes_after_hash(None).len() == block_height
                        }) {
                            correct_count += 1;
                        }
                    }
                    if correct_count == peer_ids.len() {
                        success = true;
                        break;
                    }
                }
                sleep_ms(100);
            }
            assert!(success, "Not all sumeragi instances committed the block.");
        }

        *should_softfork.lock().unwrap() = true;

        let account_id: AccountId = "alice@wonderland".parse().unwrap();
        let asset_definition_id: AssetDefinitionId = "rose#wonderland".parse().expect("Valid");
        let mint_asset = MintBox::new(
            1_u32.to_value(),
            IdBox::AssetId(AssetId::new(
                asset_definition_id.clone(),
                account_id.clone(),
            )),
        );

        let transaction =
            TransactionBuilder::new(account_id.clone(), vec![mint_asset.into()], 100_000)
                .sign(get_key_pair())
                .unwrap();
        let transaction = AcceptedTransaction::accept::<false>(
            transaction,
            &blank_config().wsv.transaction_limits,
        )
        .unwrap();

        for peer_id in &peer_ids {
            let sumeragis = sumeragis.lock().unwrap();
            let wsv = sumeragis
                .get(peer_id)
                .unwrap()
                .apply_wsv(WorldStateView::clone);
            let queue = queues.get(peer_id).unwrap();
            queue.push(transaction.clone().into(), &wsv).unwrap();
        }
    }
}

#[allow(clippy::type_complexity)]
fn set_up_network(
    peer_count: usize,
    post_proc: Arc<
        (dyn Fn(MessagePacket, &PeerId, &Arc<Mutex<HashMap<PeerId, SumeragiHandle>>>)
             + Send
             + Sync),
    >,
) -> (
    Vec<KeyPair>,
    Vec<PeerId>,
    Vec<Configuration>,
    HashMap<PeerId, Arc<Queue>>,
    Arc<Mutex<HashMap<PeerId, SumeragiHandle>>>,
) {
    set_up_network_with_genesis(peer_count, true, post_proc)
}

#[allow(clippy::needless_pass_by_value, clippy::type_complexity)]
fn set_up_network_with_genesis(
    peer_count: usize,
    commit_genesis: bool,
    post_proc: Arc<
        (dyn Fn(MessagePacket, &PeerId, &Arc<Mutex<HashMap<PeerId, SumeragiHandle>>>)
             + Send
             + Sync),
    >,
) -> (
    Vec<KeyPair>,
    Vec<PeerId>,
    Vec<Configuration>,
    HashMap<PeerId, Arc<Queue>>,
    Arc<Mutex<HashMap<PeerId, SumeragiHandle>>>,
) {
    let keypairs: Vec<KeyPair> = (0..peer_count)
        .into_iter()
        .map(|_| KeyPair::generate().unwrap())
        .collect();

    let peer_ids: Vec<PeerId> = keypairs
        .iter()
        .enumerate()
        .map(|(i, kp)| {
            PeerId::new(
                &format!("localhost:{}", i).parse().unwrap(),
                kp.public_key(),
            )
        })
        .collect();

    let sumeragis: Arc<Mutex<HashMap<PeerId, SumeragiHandle>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut queues: HashMap<PeerId, Arc<Queue>> = HashMap::new();

    let mut configs = Vec::new();

    for (index, (keypair, peer_id)) in keypairs.iter().zip(peer_ids.iter()).enumerate() {
        let mut configuration = iroha::samples::get_config_proxy(
            peer_ids.iter().cloned().collect(),
            Some(keypair.clone()),
        )
        .build()
        .unwrap();
        configuration.genesis.account_private_key = Some(GENESIS_KEY.private_key().clone());
        configuration.genesis.account_public_key = GENESIS_KEY.public_key().clone();

        configs.push(configuration.clone());

        let (events_sender, _) = tokio::sync::broadcast::channel(10000);

        let kura = Kura::blank_kura_for_testing();
        let queue = Arc::new(Queue::from_configuration(&configuration.queue));
        let wsv = WorldStateView::new(genesis_world(peer_ids.clone()), Arc::clone(&kura));

        let sumeragis_arc = Arc::clone(&sumeragis);

        let local_post_proc = Arc::clone(&post_proc);
        let sumeragi = SumeragiHandle::start_closure(SumeragiStartClosureArgs {
            configuration: &configuration.sumeragi,
            events_sender,
            wsv,
            queue: Arc::clone(&queue),
            kura,
            genesis_network: GenesisNetwork::test(
                configuration.clone(),
                index == 0 && commit_genesis,
            ),
            block_hashes: &[],
            post_procedure: Arc::new(move |packet, peer_id| {
                local_post_proc(packet, peer_id, &sumeragis_arc);
            }),
            update_topology_procedure: Arc::new(move |_network_topology| {}),
            get_connected_peers_procedure: Arc::new(HashSet::new),
        });

        sumeragis.lock().unwrap().insert(peer_id.clone(), sumeragi);
        queues.insert(peer_id.clone(), queue);
    }
    (keypairs, peer_ids, configs, queues, sumeragis)
}

fn init_telemetry() {
    iroha_logger::init(&blank_config().logger).expect("Failed to initialize telemetry");
}

fn blank_config() -> Configuration {
    iroha::samples::get_config_proxy(HashSet::new(), Some(KeyPair::generate().unwrap()))
        .build()
        .unwrap()
}

/// Get a standardised key-pair from the hard-coded literals.
///
/// # Panics
/// Programmer error. Hardcoded keys must be in proper format.
pub fn get_key_pair() -> KeyPair {
    KeyPair::new(
        PublicKey::from_str(
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
        )
        .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "9AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0".as_ref(),
        ).expect("Private key not hex encoded")
    ).expect("Key pair mismatch")
}

static GENESIS_KEY: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());

fn genesis_account(public_key: iroha_crypto::PublicKey) -> Account {
    Account::new(AccountId::genesis(), [public_key]).build(&AccountId::genesis())
}

fn genesis_world(peers: Vec<PeerId>) -> World {
    let account_public_key = GENESIS_KEY.public_key().clone();
    let mut domain = Domain::new(DomainId::genesis()).build(&AccountId::genesis());

    domain.accounts.insert(
        <Account as Identifiable>::Id::genesis(),
        genesis_account(account_public_key),
    );

    World::with(vec![domain], peers)
}

fn sleep_ms(t: u64) {
    std::thread::sleep(std::time::Duration::from_millis(t));
}

/// Trait used to differentiate a test instance of `genesis`.
pub trait TestGenesis: Sized {
    /// Construct Iroha genesis network and optionally submit genesis
    /// from the given peer.
    fn test(cfg: Configuration, submit_genesis: bool) -> Option<Self>;
}

static GENESIS_CACHE: Lazy<RawGenesisBlock> = Lazy::new(|| {
    // TODO: Fix this somehow. Probably we need to make `kagami` a library (#3253).
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    RawGenesisBlock::from_path(manifest_dir.join("../configs/peer/genesis.json"))
        .expect("Failed to deserialize genesis block from file")
});

impl TestGenesis for GenesisNetwork {
    fn test(cfg: Configuration, submit_genesis: bool) -> Option<Self> {
        let mut genesis = GENESIS_CACHE.clone();

        let rose_definition_id = <AssetDefinition as Identifiable>::Id::from_str("rose#wonderland")
            .expect("valid names");
        let alice_id =
            <Account as Identifiable>::Id::from_str("alice@wonderland").expect("valid names");

        let mint_rose_permission = PermissionToken::new(
            "can_mint_assets_with_definition"
                .parse()
                .expect("valid names"),
        )
        .with_params([(
            "asset_definition_id".parse().expect("valid names"),
            IdBox::from(rose_definition_id.clone()).into(),
        )]);
        let burn_rose_permission = PermissionToken::new(
            "can_burn_assets_with_definition"
                .parse()
                .expect("valid names"),
        )
        .with_params([(
            "asset_definition_id".parse().expect("valid names"),
            IdBox::from(rose_definition_id).into(),
        )]);
        let unregister_any_peer_permission =
            PermissionToken::new("can_unregister_any_peer".parse().expect("valid names"));
        let unregister_any_role_permission =
            PermissionToken::new("can_unregister_any_role".parse().expect("valid names"));
        let upgrade_validator_permission =
            PermissionToken::new("can_upgrade_validator".parse().expect("valid names"));

        for permission in [
            mint_rose_permission,
            burn_rose_permission,
            unregister_any_peer_permission,
            unregister_any_role_permission,
            upgrade_validator_permission,
        ] {
            genesis.transactions[0]
                .isi
                .push(GrantBox::new(permission, alice_id.clone()).into());
        }

        GenesisNetwork::from_configuration(
            submit_genesis,
            genesis,
            Some(&cfg.genesis),
            &cfg.wsv.transaction_limits,
        )
        .expect("Failed to init genesis")
    }
}
