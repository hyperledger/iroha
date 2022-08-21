//! Fault injection for tests. Almost all structs from this module
//! should be reserved for testing, and only [`NoFault`], should be
//! used in code.

use std::sync::{mpsc, Mutex};

use iroha_primitives::must_use::MustUse;
use tracing::{span, Level};

use super::*;
use crate::{genesis::GenesisNetwork, sumeragi::tracing::instrument};

/// Fault injection for consensus tests
pub trait FaultInjection: Send + Sync + Sized + 'static {
    /// A function to skip or modify a message.
    fn faulty_message(sumeragi: &SumeragiWithFault<Self>, msg: Message) -> Option<Message>;

    /// Allows controlling Sumeragi rounds by sending `Voting` message
    /// manually.
    fn manual_rounds() -> bool {
        true
    }
}

/// Correct Sumeragi behavior without fault injection
#[derive(Copy, Clone, Debug)]
pub struct NoFault;

impl FaultInjection for NoFault {
    fn faulty_message(_: &SumeragiWithFault<Self>, msg: Message) -> Option<Message> {
        Some(msg)
    }

    fn manual_rounds() -> bool {
        false
    }
}

/// `Sumeragi` is the implementation of the consensus. This struct allows also to add fault injection for tests.
///
///
/// sumeragi_state_machine_data is a Mutex instead of a RWLock because
/// it communicates more clearly the correct use of the lock. The most
/// frequent action on this lock is the main loop writing to it. This
/// means that if anyone holds this lock they are blocking the sumeragi
/// thread. A RWLock will tempt someone to hold a read lock because
/// they think they are being smart, whilst a Mutex screams *DO NOT
/// HOLD ME*. That is why the SumeragiStateMachineData is wrapped in
/// a mutex, it's more self documenting.

pub struct SumeragiWithFault<F>
where
    F: FaultInjection,
{
    pub(crate) key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The peer id of myself.
    pub peer_id: PeerId,
    pub(crate) events_sender: EventsSender,

    pub wsv_for_public_use: Mutex<WorldStateView>,

    pub(crate) commit_time: Duration,
    pub(crate) block_time: Duration,

    pub(crate) transaction_limits: TransactionLimits,
    pub(crate) transaction_validator: TransactionValidator,
    /// Broker
    pub broker: Broker,
    /// Kura instance used for IO
    pub kura: Arc<Kura>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,

    pub(crate) fault_injection: PhantomData<F>,
    pub(crate) gossip_batch_size: u32,
    pub(crate) gossip_period: Duration,

    pub sumeragi_state_machine_data: Mutex<SumeragiStateMachineData>,
    pub current_online_peers: Mutex<Vec<PeerId>>,
    pub latest_block_hash_for_use_by_block_sync: Mutex<HashOf<VersionedCommittedBlock>>,

    pub incoming_message_sender: Mutex<mpsc::SyncSender<Message>>,
    pub incoming_message_receiver: Mutex<mpsc::Receiver<Message>>,
}

impl<F: FaultInjection> Debug for SumeragiWithFault<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

pub struct SumeragiStateMachineData {
    pub genesis_network: Option<GenesisNetwork>,
    pub latest_block_hash: HashOf<VersionedCommittedBlock>,
    pub latest_block_height: u64,
    pub current_topology: Topology,

    pub wsv: WorldStateView,

    pub transaction_cache: Vec<Option<VersionedAcceptedTransaction>>,

    pub sumeragi_thread_should_exit: bool,
}

impl<F: FaultInjection> SumeragiWithFault<F> {
    pub fn get_online_peer_keys(&self) -> Vec<PublicKey> {
        self.current_online_peers
            .lock()
            .expect("lock on online peers")
            .clone()
            .into_iter()
            .map(|peer_id| peer_id.public_key)
            .collect()
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if there is a change in WSV peers, otherwise leaves the order unchanged.
    #[allow(clippy::expect_used)]
    pub fn update_network_topology(topology: &mut Topology, wsv: &WorldStateView) {
        let wsv_peers: HashSet<_> = wsv.trusted_peers_ids().clone().into_iter().collect();
        let topology_peers: HashSet<_> = topology.sorted_peers().iter().cloned().collect();
        if topology_peers != wsv_peers {
            *topology = topology
                    .clone()
                    .into_builder()
                    .with_peers(wsv_peers)
                    .build(0)
                    .expect("The safety of changing the number of peers should have been checked at Instruction execution stage.");
        }
    }

    pub(crate) fn broadcast_msg_to<'a>(
        &self,
        msg: impl Into<Message> + Send,
        ids: impl Iterator<Item = &'a PeerId> + Send,
    ) {
        VersionedMessage::from(msg.into()).send_to_multiple(&self.broker, ids);
    }

    fn broadcast_msg(&self, msg: impl Into<Message> + Send, topology: &Topology) {
        self.broadcast_msg_to(msg, topology.sorted_peers().iter());
    }

    /// Gossip transactions to other peers.

    pub fn gossip_transactions(&self, txs: Vec<VersionedAcceptedTransaction>, topology: &Topology) {
        if txs.is_empty() {
            return;
        }

        debug!(
            peer_role = ?topology.role(&self.peer_id),
            tx_count = txs.len(),
            "Gossiping transactions"
        );

        self.broadcast_msg(TransactionGossip::new(txs), topology);
    }

    /// Connects or disconnects peers according to the current network topology.
    pub fn connect_peers(&self, topology: &Topology) {
        let peers_expected = {
            let mut res = topology.sorted_peers().to_owned();
            res.retain(|id| id.address != self.peer_id.address);
            res.shuffle(&mut rand::thread_rng());
            res
        };

        let mut connected_to_peers_by_key = self.get_online_peer_keys();

        for peer_to_be_connected in peers_expected.iter() {
            if connected_to_peers_by_key.contains(&peer_to_be_connected.public_key) {
                let index = connected_to_peers_by_key
                    .iter()
                    .position(|x| x == &peer_to_be_connected.public_key)
                    .expect("I just checked that it contains the value in the statement above.");
                connected_to_peers_by_key.remove(index);
                // By removing the connected to peers that we should be connected to,
                // all that remain are the unwelcome and to-be disconnected peers.
            } else {
                self.broker.issue_send_sync(&ConnectPeer {
                    peer: peer_to_be_connected.clone(),
                });
            }
        }

        let to_disconnect_peers = connected_to_peers_by_key;

        for peer in to_disconnect_peers {
            info!(%peer, "Disconnecting peer");
            self.broker.issue_send_sync(&DisconnectPeer(peer));
        }
    }

    fn check_peers_status(
        &self,
        this_peer_id: &PeerId,
        network_topology: &Topology,
    ) -> (Vec<PeerId>, Vec<PeerId>) {
        let online_peers = self.get_online_peer_keys();
        iroha_logger::info!(peer_count = online_peers.len(), "Peers status");

        let (online, offline): (Vec<PeerId>, Vec<PeerId>) = network_topology
            .sorted_peers()
            .iter()
            .cloned()
            .partition(|id| {
                online_peers.contains(&id.public_key) || this_peer_id.public_key == id.public_key
            });

        (online, offline)
    }

    fn try_get_online_topology(&self, network_topology: &Topology) -> Result<Topology> {
        use crate::sumeragi::network_topology::GenesisBuilder;
        let (online_peers, offline_peers) =
            self.check_peers_status(&self.peer_id, network_topology);
        let set_a_len = network_topology.min_votes_for_commit();
        if online_peers.len() < set_a_len {
            return Err(eyre!("Not enough online peers for consensus."));
        }
        let genesis_topology = if network_topology.sorted_peers().len() == 1 {
            network_topology.clone()
        } else {
            let set_a: HashSet<_> = online_peers[..set_a_len].iter().cloned().collect();
            let set_b: HashSet<_> = online_peers[set_a_len..]
                .iter()
                .cloned()
                .chain(offline_peers.into_iter())
                .collect();
            #[allow(clippy::expect_used)]
            GenesisBuilder::new()
                .with_leader(self.peer_id.clone())
                .with_set_a(set_a)
                .with_set_b(set_b)
                .build()
                .expect("Preconditions should be already checked.")
        };
        iroha_logger::info!("Waiting for active peers finished.");
        Ok(genesis_topology)
    }

    pub fn wait_for_peers(&self, network_topology: &Topology) {
        iroha_logger::info!("Waiting for active peers",);
        for i in 0..120 {
            self.connect_peers(&network_topology);

            let online_peers = self.get_online_peer_keys();

            let peer_count_required = network_topology.min_votes_for_commit();

            if online_peers.len() + 1 >= peer_count_required {
                return;
            }

            let reconnect_in_ms = 250;
            std::thread::sleep(Duration::from_millis(reconnect_in_ms));
        }
        panic!("Timed out waiting for peers to come online");
    }

    pub fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }
}

fn block_commit<F>(
    sumeragi: &SumeragiWithFault<F>,
    block: VersionedValidBlock,
    state_machine: &mut SumeragiStateMachineData,
) where
    F: FaultInjection,
{
    let block = block.commit();
    let block_hash = block.hash();

    if let Err(error) = state_machine.wsv.apply(block.clone()) {
        error!(%error);
        panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
    }

    // Update WSV copy that is public facing
    {
        let mut wsv_for_public_use_guard = sumeragi.wsv_for_public_use.lock().unwrap();
        *wsv_for_public_use_guard = WorldStateView::clone(&state_machine.wsv);
    }

    for event in Vec::<Event>::from(&block) {
        trace!(?event);
        sumeragi.events_sender.send(event);
    }

    state_machine.latest_block_height = block.header().height;
    state_machine.latest_block_hash = block.hash();

    // Push new block height information to block_sync
    *sumeragi
        .latest_block_hash_for_use_by_block_sync
        .lock()
        .expect("lock on latest_block_hash_for_use_by_block_sync") =
        state_machine.latest_block_hash;

    let previous_role = state_machine.current_topology.role(&sumeragi.peer_id);
    state_machine
        .current_topology
        .refresh_at_new_block(block_hash);
    info!(
        prev_peer_role = ?previous_role,
        new_peer_role = ?state_machine.current_topology.role(&sumeragi.peer_id),
        new_block_height = %state_machine.latest_block_height,
        %block_hash,
        "Committing block"
    );
    sumeragi.kura.store_block_blocking(block);
    SumeragiWithFault::<F>::update_network_topology(
        &mut state_machine.current_topology,
        &state_machine.wsv,
    );

    // Transaction Cache
    {
        let mut transaction_cache = &mut state_machine.transaction_cache;
        // We prune transactions now because now is the only time they may have been
        // invalidated by a new block being applied to the world state view.
        //
        // We also check for if the transaction has expired because we might as well.
        let mut read_index = 0;
        let mut write_index = 0;
        while read_index < transaction_cache.len() {
            if let Some(tx) = transaction_cache[read_index].take() {
                if tx.is_in_blockchain(&state_machine.wsv)
                    || tx.is_expired(sumeragi.queue.tx_time_to_live)
                {
                    read_index += 1;
                    continue;
                }
                transaction_cache[write_index] = Some(tx);
                read_index += 1;
                write_index += 1;
                continue;
            }
            read_index += 1;
        }
        transaction_cache.truncate(write_index);
    }
}

fn request_view_change<F>(
    sumeragi: &SumeragiWithFault<F>,
    state_machine_guard: &mut SumeragiStateMachineData,
    view_change_proof_chain: &mut Vec<Proof>,
    current_view_change_index: u64,
) where
    F: FaultInjection,
{
    let mut suspect_proof = Proof {
        latest_block_hash: state_machine_guard.latest_block_hash,
        view_change_index: current_view_change_index,
        signatures: Vec::new(),
    };
    suspect_proof
        .sign(sumeragi.key_pair.clone())
        .expect("must be able to perform signing");

    view_change_proof_chain.insert_proof(
        &state_machine_guard
            .current_topology
            .sorted_peers()
            .iter()
            .cloned()
            .collect(),
        state_machine_guard.current_topology.max_faults(),
        &state_machine_guard.latest_block_hash,
        &suspect_proof,
    );

    sumeragi.broadcast_msg(
        Message::ViewChangeSuggested(ViewChangeSuggested::new(view_change_proof_chain.clone())),
        &state_machine_guard.current_topology,
    );
}

#[instrument(skip(initial_latest_block, initial_block_height))]
pub fn run_sumeragi_main_loop<F>(
    sumeragi: &SumeragiWithFault<F>,
    initial_latest_block: HashOf<VersionedCommittedBlock>,
    initial_block_height: u64,
) where
    F: FaultInjection,
{
    use std::sync::mpsc::TryRecvError;

    let mut incoming_message_receiver = sumeragi
        .incoming_message_receiver
        .lock()
        .expect("lock on reciever");

    if initial_block_height != 0 && initial_latest_block != Hash::zeroed().typed() {
        // Normal startup

        let mut state_machine_guard = sumeragi
            .sumeragi_state_machine_data
            .lock()
            .expect("take lock");

        state_machine_guard.latest_block_hash = initial_latest_block;
        state_machine_guard.latest_block_height = initial_block_height;
        state_machine_guard.current_topology = Topology::builder()
            .at_block(state_machine_guard.latest_block_hash)
            .with_peers(
                state_machine_guard
                    .wsv
                    .peers()
                    .iter()
                    .map(|peer| peer.id().clone())
                    .collect(),
            )
            .build(0)
            .expect("Should be able to reconstruct topology from wsv");
    } else {
        // We need to perform a round of some form

        let maybe_genesis_network = {
            let mut state_machine_guard = sumeragi
                .sumeragi_state_machine_data
                .lock()
                .expect("take lock");
            state_machine_guard.genesis_network.take()
        };

        if let Some(genesis_network) = maybe_genesis_network {
            sumeragi_init_commit_genesis(sumeragi, genesis_network);
        } else {
            sumeragi_init_listen_for_genesis(sumeragi, &mut incoming_message_receiver);
        }
    }

    {
        let state_machine_guard = sumeragi.sumeragi_state_machine_data.lock().unwrap();
        assert!(state_machine_guard.latest_block_height >= 1);
        assert_eq!(
            state_machine_guard.latest_block_hash,
            state_machine_guard.wsv.latest_block_hash()
        );
        trace!(
            "I, {}, finished sumeragi init. My role in the next round is {:?}",
            sumeragi.peer_id.public_key,
            state_machine_guard.current_topology.role(&sumeragi.peer_id),
        );
    }

    // do normal rounds

    let mut voting_block_option = None;

    let mut block_signature_acc = Vec::new();

    let mut should_sleep = false;

    let mut has_sent_transactions = false;
    let mut sent_transaction_time = Instant::now();

    let mut last_sent_transaction_gossip_time = Instant::now();

    let mut instant_when_we_should_create_a_block = Instant::now() + sumeragi.block_time;
    let mut instant_at_which_we_should_have_committed = Instant::now();

    let mut view_change_proof_chain = Vec::new();
    let mut old_view_change_index = 0;
    let mut old_latest_block_height = 0;

    let mut last_loop_start_time = Instant::now();

    let mut maybe_incoming_message = None;
    loop {
        if should_sleep {
            let span = span!(Level::TRACE, "Sumeragi Main Thread Sleep");
            let _enter = span.enter();
            std::thread::sleep(std::time::Duration::from_micros(5000));
            should_sleep = false;
        }
        let span_for_sumeragi_cycle = span!(Level::TRACE, "Sumeragi Main Thread Cycle");
        let _enter_for_sumeragi_cycle = span_for_sumeragi_cycle.enter();

        let mut state_machine_guard = {
            let span_for_sumeragi_guard_lock = span!(
                Level::TRACE,
                "Sumeragi Main Thread Acquire state machine data lock."
            );
            let _enter_for_sumeragi_guard_lock = span_for_sumeragi_guard_lock.enter();

            let state_machine_guard = sumeragi.sumeragi_state_machine_data.lock().unwrap();
            if state_machine_guard.sumeragi_thread_should_exit {
                info!("Sumeragi Thread has Shutdown");
                return;
            }
            state_machine_guard
        };

        sumeragi.connect_peers(&state_machine_guard.current_topology);

        // Transaction Cache
        {
            // We prune expired transactions. We do not check if they are in the blockchain, it would be a waste.
            let mut read_index = 0;
            let mut write_index = 0;
            while read_index < state_machine_guard.transaction_cache.len() {
                if let Some(tx) = state_machine_guard.transaction_cache[read_index].take() {
                    if tx.is_expired(sumeragi.queue.tx_time_to_live) {
                        read_index += 1;
                        continue;
                    }
                    state_machine_guard.transaction_cache[write_index] = Some(tx);
                    read_index += 1;
                    write_index += 1;
                    continue;
                }
                read_index += 1;
            }
            state_machine_guard.transaction_cache.truncate(write_index);

            // Pull in new transactions into the cache.
            while state_machine_guard.transaction_cache.len() < sumeragi.queue.txs_in_block {
                let tx_maybe = sumeragi.queue.pop_without_seen(&state_machine_guard.wsv);
                if tx_maybe.is_none() {
                    break;
                }
                state_machine_guard.transaction_cache.push(tx_maybe);
            }
        }

        if last_sent_transaction_gossip_time.elapsed().as_secs() > 1 {
            let mut txs = Vec::new();
            for tx in state_machine_guard.transaction_cache.iter() {
                txs.push(tx.clone().unwrap());
                if txs.len() >= 10 {
                    break;
                }
            }
            if !txs.is_empty() {
                debug!(
                    peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                    tx_count = txs.len(),
                    "Gossiping transactions"
                );

                sumeragi.broadcast_msg(
                    TransactionGossip::new(txs),
                    &state_machine_guard.current_topology,
                );
                last_sent_transaction_gossip_time = Instant::now();
            }
        }

        if maybe_incoming_message.is_some() {
            panic!("If there is a message available it must be consumed within one loop cycle. A in house rule in place to stop one from implementing bugs that render a node not responding.");
        }
        maybe_incoming_message = match incoming_message_receiver.try_recv() {
            Ok(msg) => Some(msg),
            Err(recv_error) => match recv_error {
                TryRecvError::Empty => None,
                TryRecvError::Disconnected => {
                    panic!("Sumeragi message pump disconnected.")
                }
            },
        };

        if let Some(stolen_message) = maybe_incoming_message.take() {
            let peer_list = state_machine_guard
                .current_topology
                .sorted_peers()
                .iter()
                .cloned()
                .collect();

            let mut foreign_proof_chain = None;
            match stolen_message {
                Message::TransactionGossip(tx_gossip) => {
                    for transaction in tx_gossip.txs {
                        let tx_maybe = VersionedAcceptedTransaction::from_transaction(
                            transaction.into_v1(),
                            &sumeragi.transaction_limits,
                        );
                        if let Ok(tx) = tx_maybe {
                            match sumeragi.queue.push(tx, &state_machine_guard.wsv) {
                                Err((_, crate::queue::Error::InBlockchain)) | Ok(()) => {}
                                Err((_, err)) => {
                                    warn!(?err, "Failed to push to queue gossiped transaction.")
                                }
                            }
                        }
                    }
                }
                Message::ViewChangeSuggested(suggestion) => {
                    trace!("Received view change suggestion.");
                    foreign_proof_chain = Some(suggestion.proofs);
                }
                Message::TransactionForwarded(tx_forw) => {
                    foreign_proof_chain = Some(tx_forw.view_change_proofs.clone());
                    maybe_incoming_message = Some(Message::TransactionForwarded(tx_forw));
                }
                Message::BlockCreated(block_created) => {
                    foreign_proof_chain =
                        Some(block_created.block.header().view_change_proofs.clone());
                    maybe_incoming_message = Some(Message::BlockCreated(block_created));
                }
                Message::BlockSigned(block_signed) => {
                    foreign_proof_chain =
                        Some(block_signed.block.header().view_change_proofs.clone());
                    maybe_incoming_message = Some(Message::BlockSigned(block_signed));
                }
                Message::BlockCommitted(block_committed) => {
                    foreign_proof_chain =
                        Some(block_committed.block.header().view_change_proofs.clone());
                    maybe_incoming_message = Some(Message::BlockCommitted(block_committed));
                }
                other => {
                    maybe_incoming_message = Some(other);
                }
            }
            if let Some(proofs) = foreign_proof_chain {
                for proof in proofs {
                    view_change_proof_chain.insert_proof(
                        &peer_list,
                        state_machine_guard.current_topology.max_faults(),
                        &state_machine_guard.latest_block_hash,
                        &proof,
                    );
                }
            }
        }

        view_change_proof_chain.prune(&state_machine_guard.latest_block_hash);
        let current_view_change_index: u64 = view_change_proof_chain.verify_with_state(
            &state_machine_guard
                .current_topology
                .sorted_peers()
                .iter()
                .cloned()
                .collect(),
            state_machine_guard.current_topology.max_faults(),
            &state_machine_guard.latest_block_hash,
        ) as u64;

        if old_latest_block_height != state_machine_guard.latest_block_height {
            voting_block_option = None;
            block_signature_acc.clear();
            has_sent_transactions = false;
            instant_when_we_should_create_a_block = Instant::now() + sumeragi.block_time;

            old_latest_block_height = state_machine_guard.latest_block_height;
        }
        if current_view_change_index != old_view_change_index {
            state_machine_guard
                .current_topology
                .rebuild_with_new_view_change_count(current_view_change_index);

            // there has been a view change, we must reset state for the next round.

            voting_block_option = None;
            block_signature_acc.clear();
            has_sent_transactions = false;

            old_view_change_index = current_view_change_index;
            trace!("View change to attempt #{}", current_view_change_index);
        }

        if state_machine_guard.current_topology.role(&sumeragi.peer_id) != Role::Leader {
            if state_machine_guard.transaction_cache.len() > 0 && !has_sent_transactions {
                // It is assumed that we only need to send 1 tx to check liveness.
                let tx = state_machine_guard
                    .transaction_cache
                    .choose(&mut rand::thread_rng())
                    .expect("It was checked earlier that transaction cache is not empty.")
                    .clone()
                    .unwrap();
                let tx_hash = tx.hash();
                info!(
                    peer_addr = %sumeragi.peer_id.address,
                    peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                    leader_addr = %state_machine_guard.current_topology.leader().address,
                    %tx_hash,
                    "Forwarding tx to leader"
                );

                // Don't require leader to submit receipts and therefore create blocks if the tx is still waiting for more signatures.
                if let Ok(MustUse(true)) = tx.check_signature_condition(&state_machine_guard.wsv) {
                    let post = iroha_p2p::Post {
                        data: NetworkMessage::SumeragiMessage(Box::new(VersionedMessage::from(
                            Message::from(TransactionForwarded::new(
                                tx,
                                sumeragi.peer_id.clone(),
                                view_change_proof_chain.clone(),
                            )),
                        ))),
                        peer: state_machine_guard.current_topology.leader().clone(),
                    };
                    sumeragi.broker.issue_send_sync(&post);

                    has_sent_transactions = true;
                    sent_transaction_time = Instant::now();
                }
            }

            if has_sent_transactions && sent_transaction_time.elapsed() > sumeragi.pipeline_time() {
                trace!("Suspecting all peers for not producing a block with my transaction.");
                request_view_change(
                    sumeragi,
                    &mut state_machine_guard,
                    &mut view_change_proof_chain,
                    current_view_change_index,
                );
                sent_transaction_time = Instant::now();
            }
        }

        if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ObservingPeer {
            if maybe_incoming_message.is_some() {
                let incoming_message = maybe_incoming_message.take().unwrap();
                match incoming_message {
                    Message::BlockCreated(_) => {}
                    Message::BlockCommitted(block_committed) => {
                        let block = block_committed.block;

                        // TODO: An observing peer should not validate, yet we will do so
                        // in order to preserve old behaviour. This should be changed.
                        // Tracking issue : https://github.com/hyperledger/iroha/issues/2635
                        let block = block
                            .revalidate(&sumeragi.transaction_validator, &state_machine_guard.wsv);
                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event);
                        }

                        let network_topology = state_machine_guard.current_topology.clone();

                        let verified_signatures =
                            block.verified_signatures().cloned().collect::<Vec<_>>();
                        let valid_signatures = network_topology.filter_signatures_by_roles(
                            &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                            &verified_signatures,
                        );
                        let proxy_tail_signatures = network_topology
                            .filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
                        if valid_signatures.len() >= network_topology.min_votes_for_commit()
                            && proxy_tail_signatures.len() == 1
                            && state_machine_guard.latest_block_hash
                                == block.header().previous_block_hash
                        {
                            block_commit(sumeragi, block, &mut state_machine_guard);
                        }
                    }
                    _ => {
                        trace!("Observing peer not handling message {:?}", incoming_message);
                    }
                }
            } else {
                should_sleep = true;
            }
        } else if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::Leader {
            if maybe_incoming_message.is_some() {
                use crate::sumeragi::Message::TransactionForwarded;

                let msg = maybe_incoming_message.take().unwrap();
                match msg {
                    TransactionForwarded(transaction_forwarded) => {
                        let transaction_maybe = VersionedAcceptedTransaction::from_transaction(
                            transaction_forwarded.transaction.clone().into_v1(),
                            &sumeragi.transaction_limits,
                        );
                        if transaction_maybe.is_ok() {
                            let transaction = transaction_maybe.unwrap();
                            match sumeragi.queue.push(transaction, &state_machine_guard.wsv) {
                                Ok(()) => (),
                                Err((_, crate::queue::Error::InBlockchain)) | Ok(()) => (),
                                Err((_, err)) => {
                                    error!(%err, "Error while pushing transaction into queue?");
                                }
                            }
                        } else {
                            error!("Recieved transaction that did not pass transaction limits.");
                        }
                    }
                    Message::BlockCommitted(block_committed) => {
                        let block = block_committed.block;
                        let network_topology = state_machine_guard.current_topology.clone();

                        let verified_signatures =
                            block.verified_signatures().cloned().collect::<Vec<_>>();
                        let valid_signatures = network_topology.filter_signatures_by_roles(
                            &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                            &verified_signatures,
                        );
                        let proxy_tail_signatures = network_topology
                            .filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
                        if valid_signatures.len() >= network_topology.min_votes_for_commit()
                            && proxy_tail_signatures.len() == 1
                            && state_machine_guard.latest_block_hash
                                == block.header().previous_block_hash
                        {
                            block_commit(sumeragi, block, &mut state_machine_guard);
                        }
                    }
                    _ => {
                        trace!("Leader not handling message, {:?}", msg);
                    }
                }
            } else {
                should_sleep = true;
            }

            if voting_block_option.is_none() {
                if state_machine_guard.transaction_cache.len() == 0 {
                    instant_when_we_should_create_a_block = Instant::now() + sumeragi.block_time;
                    continue;
                }
                if Instant::now() > instant_when_we_should_create_a_block
                    || state_machine_guard.transaction_cache.len() >= sumeragi.queue.txs_in_block
                {
                    let transactions: Vec<VersionedAcceptedTransaction> = state_machine_guard
                        .transaction_cache
                        .iter()
                        .map(|tx| tx.clone().unwrap())
                        .collect();

                    info!("sumeragi Doing block with {} txs.", transactions.len());
                    // TODO: This should properly process triggers
                    let event_recommendations = Vec::new();

                    let block = PendingBlock::new(transactions, event_recommendations).chain(
                        state_machine_guard.latest_block_height,
                        state_machine_guard.latest_block_hash,
                        view_change_proof_chain.clone(),
                    );
                    {
                        let block = {
                            let span_for_sumeragi_leader_block_validate =
                                span!(Level::TRACE, "Sumeragi Leader Create block, validation.");
                            let _enter_for_sumeragi_leader_block_validate =
                                span_for_sumeragi_leader_block_validate.enter();

                            let block = block.validate(
                                &sumeragi.transaction_validator,
                                &state_machine_guard.wsv,
                            );
                            block
                        };

                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event);
                        }
                        let signed_block = block
                            .sign(sumeragi.key_pair.clone())
                            .expect("Sign genesis block.");

                        if !state_machine_guard.current_topology.is_consensus_required() {
                            sumeragi.broadcast_msg(
                                BlockCommitted::from(signed_block.clone()),
                                &state_machine_guard.current_topology,
                            );

                            block_commit(sumeragi, signed_block, &mut state_machine_guard);
                            has_sent_transactions = false;
                            voting_block_option = None;
                            old_view_change_index = 0;
                            view_change_proof_chain.clear();
                            continue;
                        }

                        let voting_block = VotingBlock::new(signed_block.clone());
                        let voting_block_hash = voting_block.block.hash();

                        voting_block_option = Some(voting_block);
                        sumeragi.broadcast_msg_to(
                            BlockCreated::from(signed_block.clone()),
                            state_machine_guard.current_topology.peers_set_a().iter(),
                        );
                        instant_at_which_we_should_have_committed =
                            Instant::now() + sumeragi.commit_time;
                        trace!("I, the leader, have created a block.");
                    }
                }
            } else {
                if Instant::now() > instant_at_which_we_should_have_committed {
                    trace!(
                        "Suspecting validating peers and proxy tail for not comitting the block."
                    );
                    request_view_change(
                        sumeragi,
                        &mut state_machine_guard,
                        &mut view_change_proof_chain,
                        current_view_change_index,
                    );
                    instant_at_which_we_should_have_committed += sumeragi.commit_time;
                }
            }
        } else if state_machine_guard.current_topology.role(&sumeragi.peer_id)
            == Role::ValidatingPeer
        {
            if let Some(incoming_message) = maybe_incoming_message.take() {
                match incoming_message {
                    Message::BlockCreated(block_created) => {
                        let block = block_created.block;

                        if voting_block_option.is_some() {
                            warn!("Already have block, ignoring.");
                            continue;
                        }

                        let block_view_change_index: u64 =
                            block.header().view_change_proofs.verify_with_state(
                                &state_machine_guard
                                    .current_topology
                                    .sorted_peers()
                                    .iter()
                                    .cloned()
                                    .collect(),
                                state_machine_guard.current_topology.max_faults(),
                                &state_machine_guard.latest_block_hash,
                            ) as u64;

                        if block_view_change_index != current_view_change_index {
                            warn!("Rejecting block because it is has the wrong view change index.");
                        }

                        trace!("I, a validating peer, have received a block.");

                        let block = {
                            let span_for_sumeragi_validating_peer_block_validate =
                                span!(Level::TRACE, "Sumeragi Validating Peer Validate block.");
                            let _enter_for_sumeragi_validating_peer_block_validate =
                                span_for_sumeragi_validating_peer_block_validate.enter();

                            let block = block.revalidate(
                                &sumeragi.transaction_validator,
                                &state_machine_guard.wsv,
                            );
                            block
                        };

                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event);
                        }

                        // During the genesis round we blindly take on the network topology described in
                        // the provided genesis block.
                        let block_header = block.header();
                        if block_header.is_genesis()
                            && state_machine_guard.latest_block_height == 0
                            && block_header.genesis_topology.is_some()
                        {
                            info!("Using network topology from genesis block");
                            state_machine_guard.current_topology = block_header
                                .genesis_topology
                                .clone()
                                .take()
                                .expect("We just checked that it is some");
                        }

                        if state_machine_guard
                            .current_topology
                            .filter_signatures_by_roles(
                                &[Role::Leader],
                                block.verified_signatures(),
                            )
                            .is_empty()
                        {
                            error!(
                                role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                "Rejecting Block as it is not signed by leader.",
                            );
                            continue;
                        }

                        let hash = state_machine_guard.latest_block_hash.clone();
                        let block_height = state_machine_guard.latest_block_height;
                        if let Err(e) = block.validation_check(
                            &mut state_machine_guard.wsv,
                            &hash,
                            block_height,
                            &sumeragi.transaction_limits,
                        ) {
                            warn!(%e);
                        } else {
                            let block_clone = block.clone();
                            let key_pair_clone = sumeragi.key_pair.clone();
                            let transaction_validator = sumeragi.transaction_validator.clone();
                            let signed_block = block_clone
                                .sign(key_pair_clone)
                                .expect("maybe we should handle this error");
                            {
                                let post = iroha_p2p::Post {
                                    data: NetworkMessage::SumeragiMessage(Box::new(
                                        VersionedMessage::from(Message::BlockSigned(
                                            signed_block.into(),
                                        )),
                                    )),
                                    peer: state_machine_guard.current_topology.proxy_tail().clone(),
                                };
                                sumeragi.broker.issue_send_sync(&post);
                            }
                            info!(
                                peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                block_hash = %block.hash(),
                                "Signed block candidate",
                            );
                        }

                        let voting_block = VotingBlock::new(block.clone());
                        let voting_block_hash = voting_block.block.hash();
                        voting_block_option = Some(voting_block);
                    }
                    Message::BlockCommitted(block_committed) => {
                        let block = block_committed.block;

                        let verified_signatures =
                            block.verified_signatures().cloned().collect::<Vec<_>>();
                        let valid_signatures = state_machine_guard
                            .current_topology
                            .filter_signatures_by_roles(
                                &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                                &verified_signatures,
                            );
                        if valid_signatures.len()
                            >= state_machine_guard.current_topology.min_votes_for_commit()
                            && state_machine_guard.latest_block_hash
                                == block.header().previous_block_hash
                        {
                            block_commit(sumeragi, block, &mut state_machine_guard);
                        }
                    }
                    _ => {
                        trace!("Not handling message {:?}", incoming_message);
                    }
                }
            } else {
                // if there is no message sleep
                should_sleep = true;
            }
        } else if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
            if maybe_incoming_message.is_some() {
                let incoming_message = maybe_incoming_message.take().unwrap();

                match incoming_message {
                    Message::BlockCreated(block_created) => {
                        let block = block_created.block;

                        if voting_block_option.is_some() {
                            warn!("Already have block, ignoring.");
                            continue;
                        }

                        let block_view_change_index: u64 =
                            block.header().view_change_proofs.verify_with_state(
                                &state_machine_guard
                                    .current_topology
                                    .sorted_peers()
                                    .iter()
                                    .cloned()
                                    .collect(),
                                state_machine_guard.current_topology.max_faults(),
                                &state_machine_guard.latest_block_hash,
                            ) as u64;

                        if block_view_change_index != current_view_change_index {
                            warn!("Rejecting block because it is has the wrong view change index.");
                        }

                        trace!("I, the proxy tail, have received a block.");
                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event);
                        }

                        let block_header = block.header();
                        if block.header().is_genesis() {
                            warn!("Rejecting block because it is genesis.");
                            continue;
                        }

                        if state_machine_guard
                            .current_topology
                            .filter_signatures_by_roles(
                                &[Role::Leader],
                                block.verified_signatures(),
                            )
                            .is_empty()
                        {
                            error!(
                                role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                "Rejecting Block as it is not signed by leader.",
                            );
                            continue;
                        }

                        let block = {
                            let span_for_sumeragi_proxy_tail_block_validate =
                                span!(Level::TRACE, "Sumeragi Validating Peer Validate block.");
                            let _enter_for_sumeragi_proxy_tail_block_validate =
                                span_for_sumeragi_proxy_tail_block_validate.enter();

                            let block = block.revalidate(
                                &sumeragi.transaction_validator,
                                &state_machine_guard.wsv,
                            );
                            block
                        };

                        let valid_signatures = state_machine_guard
                            .current_topology
                            .filter_signatures_by_roles(
                                &[Role::ValidatingPeer, Role::Leader],
                                block.verified_signatures(),
                            );
                        for sig in &valid_signatures {
                            block_signature_acc.push((block.hash(), sig.clone()));
                        }

                        let voting_block = VotingBlock::new(block.clone());
                        voting_block_option = Some(voting_block);

                        instant_at_which_we_should_have_committed =
                            Instant::now() + sumeragi.commit_time;
                    }
                    Message::BlockSigned(block_signed) => {
                        let block = block_signed.block;
                        let block_hash = block.hash();

                        if voting_block_option.is_some()
                            && block_hash != voting_block_option.as_ref().unwrap().block.hash()
                        {
                            error!("block signed is not relevant block");
                            continue;
                        }

                        let valid_signatures = state_machine_guard
                            .current_topology
                            .filter_signatures_by_roles(
                                &[Role::ValidatingPeer, Role::Leader],
                                block.verified_signatures(),
                            );

                        for sig in &valid_signatures {
                            block_signature_acc.push((block_hash, sig.clone()));
                        }
                    }
                    _ => {
                        trace!("Not handling message {:?}", incoming_message);
                    }
                }
            } else {
                // if there is no message sleep
                should_sleep = true;
            }

            if voting_block_option.is_some() {
                // count votes

                let validating_peers = state_machine_guard.current_topology.peers_set_a();
                let mut signatures_on_this_block = Vec::new();

                let voting_block_hash = voting_block_option.as_ref().unwrap().block.hash();
                for (block_hash, signature) in &block_signature_acc {
                    if *block_hash == voting_block_hash {
                        signatures_on_this_block.push(signature);
                    }
                }

                let mut vote_count = 0;
                let mut peer_has_voted = vec![false; validating_peers.len()];
                let mut peer_signatures = Vec::new();
                for signature in signatures_on_this_block {
                    for i in 0..validating_peers.len() {
                        if *signature.public_key() == validating_peers[i].public_key {
                            if !peer_has_voted[i] {
                                peer_has_voted[i] = true;
                                vote_count += 1;
                                peer_signatures.push(signature.clone());
                            }
                            break;
                        }
                    }
                }

                vote_count += 1; // We are also voting for this block.
                if vote_count >= state_machine_guard.current_topology.min_votes_for_commit() {
                    let mut block = voting_block_option.unwrap().block;
                    voting_block_option = None;

                    block.as_mut_v1().signatures = peer_signatures
                        .into_iter()
                        .map(SignatureOf::transmute)
                        .collect();
                    let block = block
                        .sign(sumeragi.key_pair.clone())
                        .expect("Why should signing fail?");

                    assert!(
                        block.as_v1().signatures.len()
                            >= state_machine_guard.current_topology.min_votes_for_commit()
                    );

                    info!(
                        %voting_block_hash,
                        "Block reached required number of votes",
                    );

                    sumeragi.broadcast_msg(
                        BlockCommitted::from(block.clone()),
                        &state_machine_guard.current_topology,
                    );
                    block_commit(sumeragi, block, &mut state_machine_guard);
                }
            }

            if voting_block_option.is_some()
                && Instant::now() > instant_at_which_we_should_have_committed
            {
                trace!("Suspecting validating peers for not voting for block.");
                request_view_change(
                    sumeragi,
                    &mut state_machine_guard,
                    &mut view_change_proof_chain,
                    current_view_change_index,
                );
                instant_at_which_we_should_have_committed += sumeragi.commit_time;
            }
        }
    }
}

fn sumeragi_init_commit_genesis<F>(sumeragi: &SumeragiWithFault<F>, genesis_network: GenesisNetwork)
where
    F: FaultInjection,
{
    std::thread::sleep(Duration::from_millis(250));
    let mut state_machine_guard = sumeragi
        .sumeragi_state_machine_data
        .lock()
        .expect("take lock");

    if state_machine_guard.current_topology.is_consensus_required() {
        sumeragi.wait_for_peers(&state_machine_guard.current_topology);
    }

    iroha_logger::info!("Initializing iroha using the genesis block.");

    state_machine_guard.latest_block_height = 0;
    state_machine_guard.latest_block_hash = Hash::zeroed().typed();

    let transactions = genesis_network.transactions.clone();
    // Don't start genesis round. Instead just commit the genesis block.
    if transactions.is_empty() {
        panic!("Genesis transaction set contains no valid transactions");
    } else {
        let block = PendingBlock::new(transactions, Vec::new())
            .chain_first_with_genesis_topology(state_machine_guard.current_topology.clone());

        {
            info!(block_hash = %block.hash(), "Publishing genesis block.");

            let block = block.validate(&sumeragi.transaction_validator, &state_machine_guard.wsv);

            info!(
                peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                block_hash = %block.hash(),
                "Created a block to commit.",
            );
            for event in Vec::<Event>::from(&block) {
                trace!(?event);
                sumeragi.events_sender.send(event);
            }
            let signed_block = block
                .sign(sumeragi.key_pair.clone())
                .expect("Sign genesis block.");
            {
                sumeragi.broadcast_msg(
                    BlockCommitted::from(signed_block.clone()),
                    &state_machine_guard.current_topology,
                );
                block_commit(sumeragi, signed_block, &mut state_machine_guard);
            }
        }
    }
}

fn sumeragi_init_listen_for_genesis<F>(
    sumeragi: &SumeragiWithFault<F>,
    incoming_message_receiver: &mut mpsc::Receiver<Message>,
) where
    F: FaultInjection,
{
    use std::sync::mpsc::TryRecvError;

    trace!("Start listen for genesis.");
    let mut state_machine_guard = sumeragi
        .sumeragi_state_machine_data
        .lock()
        .expect("take lock");

    if !state_machine_guard.current_topology.is_consensus_required() {
        panic!(
            "How am I supposed to receive a genesis block if I am the only peer in the network?"
        );
    }
    {
        *sumeragi
            .latest_block_hash_for_use_by_block_sync
            .lock()
            .expect("push hash to block sync for genesis") = Hash::zeroed().typed();
    }

    loop {
        sumeragi.connect_peers(&state_machine_guard.current_topology);
        std::thread::sleep(Duration::from_millis(50));

        if state_machine_guard.sumeragi_thread_should_exit {
            return;
        }

        // we must connect to peers so that our block_sync can find us the genesis block.
        match incoming_message_receiver.try_recv() {
            Ok(msg) => {
                match msg {
                    Message::BlockCommitted(block_committed) => {
                        // If we recieve a committed genesis block that is valid, use it without question.
                        let block = block_committed.block;

                        // During the genesis round we blindly take on the network topology described in
                        // the provided genesis block.
                        let block_header = block.header();
                        if block_header.is_genesis() && block_header.genesis_topology.is_some() {
                            info!("Using network topology from genesis block");
                            state_machine_guard.current_topology = block_header
                                .genesis_topology
                                .clone()
                                .take()
                                .expect("We just checked that it is some");
                        } else {
                            trace!("Received block that was not genesis.");
                            continue;
                        }

                        block_commit(sumeragi, block, &mut state_machine_guard);
                        info!("Genesis block received and committed.");
                        return;
                    }
                    _ => {
                        trace!("Not handling message, waiting genesis. : {:?}", msg);
                    }
                }
            }
            Err(recv_error) => {
                match recv_error {
                    TryRecvError::Empty => (),
                    TryRecvError::Disconnected => {
                        panic!("Sumeragi message pump disconnected.")
                    }
                };
            }
        }
    }
}
