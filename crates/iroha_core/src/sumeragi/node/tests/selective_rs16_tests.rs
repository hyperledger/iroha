//! Native sockets, real BLS and State under selective original signed-row deprivation.
//!
//! Only the test-owned authenticated receive loop drops rows. This is in-process
//! whole-node evidence, not daemon-process or deployment qualification.
//! TODO: qualify selective withholding and exact process exits in a daemon-process harness.

use super::*;
use crate::{
    IrohaNetwork, NetworkMessage,
    sumeragi::{
        certified_chain::{CertifiedBlock, CertifiedPrefix},
        driver::Worker,
        net::{Routed, SumeragiFrame, SumeragiSubscription},
    },
};
use iroha_futures::supervisor::{ShutdownSignal, Supervisor};
use iroha_p2p::{
    network::message::{UpdatePeers, UpdateTopology},
    peer::message::PeerMessage,
};
use iroha_sumeragi::{
    availability::verify_availability,
    message::{PayloadManifest, Qc, VoteKind, WireMessage},
    types::HeightConfig,
};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
    thread::JoinHandle,
};

const TARGET: u64 = 3;
const OBSERVER: usize = 4;
const WAIT: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Lifecycle {
    finished: AtomicUsize,
    failed: AtomicUsize,
}
impl Observer for Lifecycle {
    fn finished(&self) {
        self.finished.fetch_add(1, Ordering::Relaxed);
    }
    fn stopped(&self, _: Worker) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
    fn halt(&self, _: &iroha_sumeragi::api::HaltReason) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
}

struct RowObservation {
    // Original received frame retained for audit only; never issued as native body custody.
    frame: Arc<SumeragiFrame>,
    senders: BTreeSet<PeerId>,
    withheld: usize,
    passed: usize,
    repaired: usize,
}
struct Gate {
    instance: Hash32,
    width: usize,
    data: usize,
    active: bool,
    released: bool,
    captured_bytes: usize,
    rows: BTreeMap<(Hash32, u32), RowObservation>,
    manifests: BTreeMap<Hash32, PayloadManifest>,
    finality: BTreeMap<Hash32, Qc>,
}
impl Gate {
    fn new(instance: Hash32, config: &HeightConfig) -> Self {
        let layout = config.epoch.da_layout;
        assert!(layout.data_shards >= 2);
        Self {
            instance,
            width: usize::from(layout.data_shards) + usize::from(layout.parity_shards),
            data: usize::from(layout.data_shards),
            active: false,
            released: false,
            captured_bytes: 0,
            rows: BTreeMap::new(),
            manifests: BTreeMap::new(),
            finality: BTreeMap::new(),
        }
    }
    fn selected(&self, instance: Hash32, height: u64) -> bool {
        instance == self.instance && height == TARGET
    }
    fn arm(&mut self) {
        assert!(!self.active && !self.released && self.rows.is_empty());
        self.active = true;
    }
    fn release(&mut self) {
        assert!(self.active && !self.released);
        self.active = false;
        self.released = true;
    }
    fn manifest(&mut self, manifest: &PayloadManifest, crypto: &BlsCrypto) {
        if !self.selected(manifest.header.instance, manifest.header.height) {
            return;
        }
        let hash = manifest.hash(crypto);
        if let Some(original) = self.manifests.get(&hash) {
            assert_eq!(
                original, manifest,
                "original signed table changed on repair"
            );
        } else {
            assert!(self.manifests.len() < 8, "bounded one-height observation");
            self.manifests.insert(hash, manifest.clone());
        }
    }
    fn route(
        &mut self,
        message: PeerMessage<NetworkMessage>,
        ingress: &SumeragiIngress,
        crypto: &BlsCrypto,
    ) {
        assert_eq!(message.peer.id(), message.authenticated_via());
        assert!(
            message.reply_route().is_some(),
            "actual authenticated socket source"
        );
        let sender = message.authenticated_via().clone();
        let NetworkMessage::Sumeragi(frame) = &message.payload else {
            panic!("semantic Sumeragi subscription returned another message");
        };
        let decoded = WireMessage::decode(frame.bytes(), frame.bytes().len())
            .expect("canonical socket frame");
        let row_key = if let WireMessage::PayloadChunk(chunk) = &decoded {
            self.selected(chunk.instance, chunk.height)
                .then_some((chunk.block_hash, chunk.index))
        } else {
            None
        };
        if let Some(key) = row_key {
            if !self.rows.contains_key(&key) {
                assert!(self.rows.len() < 96, "bounded original row audit");
                self.captured_bytes = self
                    .captured_bytes
                    .checked_add(frame.bytes().len())
                    .unwrap();
                assert!(
                    self.captured_bytes <= 1024 * 1024,
                    "bounded original row bytes"
                );
                self.rows.insert(
                    key,
                    RowObservation {
                        frame: Arc::clone(frame),
                        senders: BTreeSet::new(),
                        withheld: 0,
                        passed: 0,
                        repaired: 0,
                    },
                );
            }
            let row = self.rows.get_mut(&key).unwrap();
            assert_eq!(
                row.frame.bytes(),
                frame.bytes(),
                "repair replaced original row bytes"
            );
            row.senders.insert(sender);
            // The same d-1 data indices may arrive from every source. Parity must
            // not complete a stripe while the exact test-owned gate is active.
            if self.active
                && !cfg!(all(test, sumeragi_core_mutation = "HC449"))
                && key.1 as usize % self.width >= self.data - 1
            {
                row.withheld += 1;
                return; // Release actual transport credits; production repair will retry.
            }
        }
        if ingress.route(message) != Routed::Delivered {
            return;
        }
        if let Some(key) = row_key {
            let row = self.rows.get_mut(&key).unwrap();
            row.passed += 1;
            if self.released {
                row.repaired += 1;
            }
        }
        match decoded {
            WireMessage::PayloadManifest(manifest) => self.manifest(&manifest, crypto),
            WireMessage::Proposal(proposal) => self.manifest(
                &PayloadManifest {
                    header: proposal.proposal.header,
                    availability: proposal.availability,
                },
                crypto,
            ),
            WireMessage::SyncResponse(response) => {
                for entry in response.blocks {
                    if self.selected(entry.manifest.header.instance, entry.manifest.header.height) {
                        self.finality
                            .insert(entry.manifest.hash(crypto), entry.commit_qc);
                    }
                    self.manifest(&entry.manifest, crypto);
                }
            }
            WireMessage::Qc(qc)
                if self.selected(qc.instance, qc.height) && qc.kind == VoteKind::Commit =>
            {
                self.finality.insert(qc.block_hash, qc);
            }
            WireMessage::Status(status) => {
                if let Some(qc) = status.committed_qc
                    && self.selected(qc.instance, qc.height)
                    && qc.kind == VoteKind::Commit
                {
                    self.finality.insert(qc.block_hash, qc);
                }
            }
            _ => {}
        }
    }
    fn partial(&self, hash: Hash32, stripes: usize) -> bool {
        self.active
            && self.manifests.contains_key(&hash)
            && self.finality.contains_key(&hash)
            && (0..stripes).all(|stripe| {
                self.rows
                    .iter()
                    .filter(|((block, index), row)| {
                        *block == hash && *index as usize / self.width == stripe && row.passed > 0
                    })
                    .count()
                    == self.data - 1
            })
            && self
                .rows
                .iter()
                .any(|((block, _), row)| *block == hash && row.withheld > 0)
    }
    fn authenticate(
        &self,
        certified: &CertifiedBlock,
        config: &HeightConfig,
        crypto: &BlsCrypto,
        peers: &BTreeSet<PeerId>,
    ) {
        let header = certified.header().unwrap();
        let hash = certified.core_hash();
        let qc = self
            .finality
            .get(&hash)
            .expect("actual original finality metadata ingress");
        assert_eq!(
            (qc.height, qc.block_hash, qc.result, qc.kind),
            (TARGET, hash, certified.result(), VoteKind::Commit)
        );
        iroha_sumeragi::crypto::Verifier::new(
            crypto,
            &self.instance,
            &config.epoch.id,
            &config.committee,
        )
        .verify_qc(qc)
        .expect("actual socket QC verifies under independent original authority");
        let manifest = self
            .manifests
            .get(&hash)
            .expect("actual original manifest ingress");
        assert_eq!(&manifest.header, header);
        let evidence = verify_availability(
            self.instance,
            config,
            header,
            manifest.availability.as_slice(),
            crypto,
        )
        .expect("actual original BLS manifest and row authorizations");
        let certificate = certified.block().commit_certificate().unwrap();
        let original: iroha_sumeragi::availability::AvailabilityFrame =
            norito::decode_canonical(certificate.availability()).unwrap();
        assert_eq!(
            original.as_slice(),
            manifest.availability.as_slice(),
            "finality binds exact original signature table"
        );
        for ((block, index), row) in &self.rows {
            if *block != hash {
                continue;
            }
            let WireMessage::PayloadChunk(chunk) =
                WireMessage::decode(row.frame.bytes(), row.frame.bytes().len()).unwrap()
            else {
                unreachable!()
            };
            assert_eq!(
                (chunk.instance, chunk.height, chunk.block_hash, chunk.index),
                (self.instance, TARGET, hash, *index)
            );
            assert!(
                row.senders.iter().all(|peer| peers.contains(peer)),
                "row source is not an original validator"
            );
            assert!(
                evidence.accepts_row(*index as usize, chunk.bytes.as_slice(), crypto),
                "captured actual row must match original signature/hash/length"
            );
        }
    }
}

fn filtered_ingress(
    subscription: SumeragiSubscription,
    ingress: Arc<SumeragiIngress>,
    gate: Arc<parking_lot::Mutex<Gate>>,
    crypto: Arc<BlsCrypto>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let SumeragiSubscription {
            mut control,
            mut proposal,
            mut bulk,
        } = subscription;
        runtime.block_on(async move {
            loop {
                let message = tokio::select! {
                    biased;
                    Some(message) = control.recv() => message,
                    Some(message) = proposal.recv() => message,
                    Some(message) = bulk.recv() => message,
                    else => break,
                };
                gate.lock().route(message, &ingress, &crypto);
            }
        });
    })
}

type LiveSockets = (
    ShutdownSignal,
    tokio::task::JoinHandle<iroha_futures::supervisor::Result<()>>,
);

struct SocketNodes {
    nodes: Vec<Validator>,
    actors: Vec<IrohaNetwork>,
    ingress: Vec<JoinHandle<()>>,
    lifecycle: Vec<Arc<Lifecycle>>,
    supervisor: Option<LiveSockets>,
    runtime: tokio::runtime::Runtime,
    directories: Vec<tempfile::TempDir>,
    gate: Arc<parking_lot::Mutex<Gate>>,
    config: HeightConfig,
    crypto: Arc<BlsCrypto>,
}
impl SocketNodes {
    fn new(root: &DataspaceChain) -> Self {
        let runtime = super::super::p2p_owner_tests::runtime();
        let mut keys = root.chain.keys.clone();
        keys.push(KeyPair::from_seed(vec![0xE9; 32], Algorithm::BlsNormal));
        let ids = keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<BTreeSet<_>>();
        let mut supervisor = Supervisor::new();
        let mut actors = Vec::new();
        let mut addresses = Vec::new();
        let mut directories = Vec::new();
        let network_id = NetworkId::from_genesis_hash(root.chain.genesis.hash());
        for key in &keys {
            let targets = ids
                .iter()
                .filter(|id| id.public_key() != key.public_key())
                .cloned()
                .collect();
            let (actor, address, directory) =
                runtime.block_on(super::super::p2p_owner_tests::live_network(
                    key,
                    network_id,
                    targets,
                    &mut supervisor,
                ));
            actors.push(actor);
            addresses.push(address);
            directories.push(directory);
        }
        // Supervision runs throughout work so an early actor exit cannot be relabelled
        // as a clean shutdown merely because its join is examined after release.
        let shutdown = supervisor.shutdown_signal();
        let supervised = runtime.spawn(supervisor.start());
        let mut prepared_nodes: Vec<(Arc<State>, Prepared)> = Vec::new();
        for _ in &keys {
            let (state, _) = root.state(None);
            let prepared = prepare(PrepareInputs {
                state: Arc::clone(&state),
                events: tokio::sync::broadcast::channel(1024).0,
                genesis: Some(root.chain.genesis.clone()),
                genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                consensus_mode: ConsensusMode::Permissioned,
            })
            .expect("exact original signed root startup");
            for (previous, _) in &prepared_nodes {
                assert!(
                    !Arc::ptr_eq(previous, &state),
                    "each original node owns separate State"
                );
                assert!(
                    !std::ptr::eq(previous.kura(), state.kura()),
                    "each original node owns separate Kura"
                );
            }
            prepared_nodes.push((state, prepared));
        }
        let config = prepared_nodes[0]
            .0
            .view()
            .world()
            .consensus_schedule()
            .ready(TARGET)
            .unwrap()
            .height_config()
            .unwrap();
        let crypto = Arc::clone(&prepared_nodes[0].1.crypto);
        let gate = Arc::new(parking_lot::Mutex::new(Gate::new(
            prepared_nodes[0].1.instance(),
            &config,
        )));
        let mut fixture = Self {
            nodes: Vec::new(),
            actors,
            ingress: Vec::new(),
            lifecycle: Vec::new(),
            supervisor: Some((shutdown, supervised)),
            runtime,
            directories,
            gate,
            config,
            crypto,
        };
        for (index, ((state, prepared), key)) in prepared_nodes.into_iter().zip(&keys).enumerate() {
            let directory = tempfile::tempdir().unwrap();
            let net = Arc::new(P2pNet::new(fixture.actors[index].clone()));
            // Same retained actor owns both directions. Subscription precedes driver
            // construction/key installation exactly as in Prepared::start_on_network.
            let subscription = net.subscribe(128).expect("original actor subscription");
            let (_, time) = TimeSource::new_mock(Duration::ZERO);
            let queue = Arc::new(Queue::test(
                iroha_config::parameters::actual::Queue::default(),
                &time,
            ));
            let observer = Arc::new(Lifecycle::default());
            let node = prepared
                .start(StartInputs {
                    net,
                    queue: Arc::clone(&queue),
                    key_pair: key.clone(),
                    beacon_signer: None,
                    config: NodeConfig {
                        records_dir: directory.path().join("records"),
                        installation_log: directory.path().join("keys/installation.log"),
                        bodies_dir: directory.path().join("bodies"),
                        local: SumeragiLocalOverrides::default(),
                        assert_fresh_key: true,
                        retired_keys: Vec::new(),
                    },
                    observer: observer.clone(),
                    driver: DriverConfig::default(),
                })
                .expect("native State/file/Kura node with original BLS key");
            let ingress = if index == OBSERVER {
                filtered_ingress(
                    subscription,
                    Arc::clone(&node.ingress),
                    Arc::clone(&fixture.gate),
                    Arc::clone(&fixture.crypto),
                )
            } else {
                spawn_ingress(subscription, Arc::clone(&node.ingress)).unwrap()
            };
            fixture.nodes.push(Validator { node, state, queue });
            fixture.ingress.push(ingress);
            fixture.lifecycle.push(observer);
            fixture.directories.push(directory);
        }
        for (index, actor) in fixture.actors.iter().enumerate() {
            let own = PeerId::new(keys[index].public_key().clone());
            actor.update_topology(UpdateTopology(
                ids.iter().filter(|id| **id != own).cloned().collect(),
            ));
            actor.update_peers_addresses(UpdatePeers(
                keys.iter()
                    .zip(&addresses)
                    .filter_map(|(key, address)| {
                        let id = PeerId::new(key.public_key().clone());
                        (id != own).then_some((id, address.clone()))
                    })
                    .collect(),
            ));
        }
        fixture.runtime.block_on(async {
            tokio::time::timeout(WAIT, async {
                for actor in &fixture.actors {
                    let mut peers = actor.online_peers_receiver();
                    while peers.borrow().len() != 4 {
                        peers.changed().await.unwrap();
                    }
                }
            })
            .await
            .expect("all five original authenticated socket actors connected");
        });
        fixture
    }
    fn stop(&mut self) {
        for validator in self.nodes.drain(..) {
            drop(validator.node.queue_wake);
            validator.node.lanes.shutdown();
            validator.node.driver.shutdown();
        }
        if let Some((shutdown, supervised)) = self.supervisor.take() {
            shutdown.send();
            self.actors.clear();
            let result = self.runtime.block_on(supervised);
            if !std::thread::panicking() {
                result
                    .expect("original socket supervisor joined")
                    .expect("all five socket actors close cleanly without premature exit");
            }
        }
        for ingress in self.ingress.drain(..) {
            let result = ingress.join();
            if !std::thread::panicking() {
                result.expect("original ingress thread joined");
            }
        }
    }
    fn finish(mut self) {
        self.stop();
        assert_eq!(self.lifecycle.len(), 5);
        for lifecycle in &self.lifecycle {
            assert_eq!(
                lifecycle.finished.load(Ordering::Relaxed),
                1,
                "exactly one orderly native node exit"
            );
            assert_eq!(
                lifecycle.failed.load(Ordering::Relaxed),
                0,
                "no failed worker or halted instance"
            );
        }
    }
}
impl Drop for SocketNodes {
    fn drop(&mut self) {
        self.stop();
    }
}

fn certified(root: &DataspaceChain, state: &State, end: u64) -> CertifiedBlock {
    let read = |height: u64| {
        state
            .kura()
            .get_block(
                usize::try_from(height).unwrap().try_into().unwrap(),
                &state.ivm_execution_budget(),
            )
            .unwrap()
            .unwrap()
    };
    let mut prefix =
        CertifiedPrefix::new(&root.chain.chain_id, *state.network_id_ref(), read(1)).unwrap();
    assert_eq!(prefix.root_scope(), root.scope);
    let mut last = None;
    for height in 2..=end {
        last = Some(prefix.push(read(height)).unwrap().into_parts().0);
    }
    last.unwrap()
}
fn assert_paid(certified: &CertifiedBlock, transaction: &SignedTransaction, fee: u64) {
    assert_eq!(certified.block().network_entrypoint_count(), 1);
    assert_eq!(
        certified.block().network_entrypoint_at(0),
        Some(&TransactionEntrypoint::External(transaction.clone()))
    );
    let (_, output) = certified.block().network_output_at(0).unwrap();
    assert!(
        output.result.0.is_ok(),
        "original paid work must execute successfully"
    );
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual original fee settlement");
    assert_eq!(
        receipt.source_id,
        *Hash::from(transaction.hash_as_entrypoint()).as_ref()
    );
    receipt
        .validate_for_network_input(
            &TransactionEntrypoint::External(transaction.clone()),
            TARGET,
        )
        .expect("fee receipt binds original signed payer, asset, cap, height and schedule");
    assert_eq!(receipt.fee_amount, Quantity::from(fee));
    assert!(matches!(
        receipt.settlement,
        iroha_data_model::block::consensus::NexusFeeSettlementV1::Burn
    ));
}

fn assert_observer_waiting(
    root: &DataspaceChain,
    fixture: &SocketNodes,
    hash: HashOf<TransactionEntrypoint>,
    paid: u64,
) {
    assert!(
        !fixture.supervisor.as_ref().unwrap().1.is_finished(),
        "original socket actor supervisor remains live"
    );
    let observer = &fixture.nodes[OBSERVER];
    assert_eq!(
        observer.state.view().height(),
        2,
        "selected original row deprivation must prevent native Apply"
    );
    assert_eq!(
        observer.state.kura().blocks_count(),
        2,
        "metadata is not durable body custody"
    );
    assert!(!observer.state.has_committed_entrypoint(hash));
    assert_eq!(
        observer
            .node
            .handle()
            .driver
            .status()
            .unwrap()
            .applied_height,
        2
    );
    root.balances(&fixture.nodes[OBSERVER..], paid);
}

#[test]
fn native_socket_selective_signed_rows_preserve_partial_delivery_and_original_paid_recovery() {
    let parent = chain(4, 200);
    let root = DataspaceChain::new(
        NetworkId::from_genesis_hash(parent.genesis.hash()),
        DataSpaceId::new((1_u64 << 40) + 39),
    );
    let fixture = SocketNodes::new(&root);
    let (warm, warm_fee) = root.submit(&fixture.nodes[..OBSERVER], "paid socket warmup");
    wait_until(
        &fixture.nodes,
        WAIT,
        "original observer paid warmup",
        || committed_everywhere(&fixture.nodes, warm),
    );
    assert_eq!(fixture.nodes[OBSERVER].state.view().height(), 2);
    root.balances(&fixture.nodes, warm_fee);
    fixture.gate.lock().arm();
    let text = "original paid transaction survives selective signed row withholding";
    let original = root.signed_work(text);
    let network = *fixture.nodes[0].state.network_id_ref();
    let accepted = AcceptedTransaction::accept(
        original.clone(),
        &network,
        Duration::from_secs(10),
        TransactionParameters::default(),
        &iroha_config::parameters::actual::Crypto::default(),
    )
    .unwrap();
    let hash = accepted.hash_as_entrypoint();
    for node in &fixture.nodes[..OBSERVER] {
        node.queue
            .push(accepted.clone(), node.state.view())
            .unwrap();
        node.node.handle().transactions_available();
    }
    wait_until(
        &fixture.nodes,
        WAIT,
        "four real validators finalize while observer lacks rows",
        || committed_everywhere(&fixture.nodes[..OBSERVER], hash),
    );
    let original_certificate = certified(&root, &fixture.nodes[0].state, TARGET);
    assert_paid(&original_certificate, &original, work_fee(text));
    let block_hash = original_certificate.core_hash();
    let shape = fixture
        .config
        .epoch
        .da_layout
        .shape(u64::from(
            original_certificate.header().unwrap().payload_len,
        ))
        .unwrap();
    wait_until(
        &fixture.nodes,
        WAIT,
        "manifest/finality plus d-1 actual rows and withheld parity",
        || {
            assert_observer_waiting(&root, &fixture, hash, warm_fee);
            fixture
                .gate
                .lock()
                .partial(block_hash, shape.stripe_count())
        },
    );
    let peers = root
        .chain
        .keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect();
    fixture.gate.lock().authenticate(
        &original_certificate,
        &fixture.config,
        &fixture.crypto,
        &peers,
    );
    // Begin only after actual target metadata, selected rows and a withheld row.
    // Use the real node's body-fetch timer, not the proposal-builder retry parameter.
    let withheld_before = fixture
        .gate
        .lock()
        .rows
        .iter()
        .filter(|((block, _), _)| *block == block_hash)
        .map(|(_, row)| row.withheld)
        .sum::<usize>();
    let retry_ms = local_params(4, &SumeragiLocalOverrides::default()).fetch_retry;
    let until = Instant::now() + Duration::from_millis(retry_ms.checked_mul(3).unwrap() + 100);
    while Instant::now() < until {
        let gate = fixture.gate.lock();
        assert!(gate.partial(block_hash, shape.stripe_count()));
        assert_observer_waiting(&root, &fixture, hash, warm_fee);
        drop(gate);
        std::thread::sleep(Duration::from_millis(20));
    }
    {
        let mut gate = fixture.gate.lock();
        let withheld_after = gate
            .rows
            .iter()
            .filter(|((block, _), _)| *block == block_hash)
            .map(|(_, row)| row.withheld)
            .sum::<usize>();
        assert!(
            withheld_after > withheld_before,
            "positive deprivation window must include an actual repeated row attempt"
        );
        let senders = gate
            .rows
            .iter()
            .filter(|((block, _), row)| *block == block_hash && row.withheld > 0)
            .flat_map(|(_, row)| row.senders.iter())
            .collect::<BTreeSet<_>>();
        assert!(
            senders.len() >= 2,
            "alternate original row holders must also be deprived"
        );
        gate.release();
    }
    wait_until(
        &fixture.nodes,
        WAIT,
        "ordinary repair of the exact original paid input",
        || committed_everywhere(&fixture.nodes, hash),
    );
    let recovered = certified(&root, &fixture.nodes[OBSERVER].state, TARGET);
    assert_eq!(recovered.header(), original_certificate.header());
    assert_eq!(recovered.result(), original_certificate.result());
    assert_eq!(recovered.block_hash(), original_certificate.block_hash());
    assert_paid(&recovered, &original, work_fee(text));
    root.balances(&fixture.nodes, warm_fee + work_fee(text));
    {
        let gate = fixture.gate.lock();
        gate.authenticate(&recovered, &fixture.config, &fixture.crypto, &peers);
        for stripe in 0..shape.stripe_count() {
            assert!(
                gate.rows
                    .iter()
                    .filter(|((block, index), row)| *block == block_hash
                        && *index as usize / gate.width == stripe
                        && row.passed > 0)
                    .count()
                    >= gate.data
            );
        }
        assert!(
            gate.rows
                .iter()
                .any(|((block, _), row)| *block == block_hash
                    && row.withheld > 0
                    && row.repaired > 0),
            "production repair must deliver an actually withheld original row"
        );
    }
    assert_idle_height_unchanged(&fixture.nodes, Duration::from_millis(250));
    fixture.finish();
}
