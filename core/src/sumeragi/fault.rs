//! Fault injection for tests. Almost all structs from this module
//! should be reserved for testing, and only [`NoFault`], should be
//! used in code.

use std::sync::{mpsc, Mutex};

use iroha_primitives::must_use::MustUse;
use rand::seq::SliceRandom;
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

/// `Sumeragi` is the implementation of the consensus. This struct
/// allows also to add fault injection for tests.
///
/// TODO: paraphrase
///
/// `sumeragi_state_machine_data` is a [`Mutex`] instead of a `RWLock`
/// because it communicates more clearly the correct use of the
/// lock. The most frequent action on this lock is the main loop
/// writing to it. This means that if anyone holds this lock they are
/// blocking the sumeragi thread. A `RWLock` will tempt someone to
/// hold a read lock because they think they are being smart, whilst a
/// [`Mutex`] screams *DO NOT HOLD ME*. That is why the
/// [`SumeragiStateMachineData`] is wrapped in a mutex, it's more
/// self-documenting.
pub struct SumeragiWithFault<F>
where
    F: FaultInjection,
{
    /// The pair of keys used for communication given this Sumeragi instance.
    pub(crate) key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// An actor that sends events
    pub(crate) events_sender: EventsSender,
    /// The world state view instance that is used in public contexts
    pub wsv: Mutex<WorldStateView>,
    /// TODO: good description
    pub(crate) commit_time: Duration,
    /// TODO: good description here too.
    pub(crate) block_time: Duration,
    /// Limits that all transactions need to obey, in terms of size
    /// of WASM blob and number of instructions.
    pub(crate) transaction_limits: TransactionLimits,
    /// [`TransactionValidator`] instance that we use
    pub(crate) transaction_validator: TransactionValidator,
    /// Broker
    pub broker: Broker,
    /// Kura instance used for IO
    pub kura: Arc<Kura>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,
    /// [`PhantomData`] used to generify over [`FaultInjection`] implementations
    pub(crate) fault_injection: PhantomData<F>, // TODO: remove
    /// The size of batch that is being gossiped. Smaller size leads
    /// to longer time to synchronise, useful if you have high packet loss.
    pub(crate) gossip_batch_size: u32,
    /// The time between gossiping. More frequent gossiping shortens
    /// the time to sync, but can overload the network.
    pub(crate) gossip_period: Duration,
    /// [`PeerId`]s of the peers that are currently online.
    pub current_online_peers: Mutex<Vec<PeerId>>,
    /// Hash of the latest block
    pub latest_block_hash_for_use_by_block_sync: Mutex<HashOf<VersionedCommittedBlock>>,
    /// Incoming?? sender channel
    pub incoming_message_sender: Mutex<mpsc::SyncSender<MessagePacket>>,
    /// Incoming message receiver channel.
    pub incoming_message_receiver: Mutex<mpsc::Receiver<MessagePacket>>,
}

impl<F: FaultInjection> Debug for SumeragiWithFault<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

// TODO: In general naming things after the programming patterns is
// considered a bad practice. We need a better name.
/// Internal structure that retains the state.
pub struct SumeragiStateMachineData {
    /// The [`GenesisNetwork`] that was used to initialise the state machine.
    pub genesis_network: Option<GenesisNetwork>,
    /// The hash of the latest [`VersionedCommittedBlock`]
    pub latest_block_hash: HashOf<VersionedCommittedBlock>,
    /// Current block height
    pub latest_block_height: u64,
    /// The current network topology.
    pub current_topology: Topology,
    /// The sumeragi internal `WorldStateView`. This will probably
    /// morph into a wsv + various patches as we attempt to
    /// multithread isi execution. In the future we might also once
    /// again merge the internal wsv with the public facing one. But
    /// as of now we keep them seperate for greater flexibility when
    /// optimizing.
    pub wsv: WorldStateView,
    /// In order to *be fast*, we must minimize communication with
    /// other subsystems where we can. This way the performance of
    /// sumeragi is more dependent on the code that is internal to the
    /// subsystem.
    ///
    /// This transaction cache was therefore introduced so that only
    /// interact with the transaction queue as necessary. If this were
    /// written in C it would have just been an array of
    /// `VersionedAcceptedTransaction`, but because of Rust's RAII
    /// enforcement it has to be an array of options.  Otherwise we
    /// would need to use unsafe to implement the fast pruning on the
    /// array.
    pub transaction_cache: Vec<Option<VersionedAcceptedTransaction>>,
}

impl<F: FaultInjection> SumeragiWithFault<F> {
    /// Get the current online peers by public key.
    #[allow(clippy::expect_used)]
    pub fn get_online_peer_keys(&self) -> Vec<PublicKey> {
        self.current_online_peers
            .lock()
            .expect("lock on online peers")
            .clone()
            .into_iter()
            .map(|peer_id| peer_id.public_key)
            .collect()
    }

    /// Set the public block hash to zero, in a thread-safe manner
    #[allow(clippy::expect_used)]
    pub fn zeroize(&self) {
        *self
            .latest_block_hash_for_use_by_block_sync
            .lock()
            .expect("Poisoned Mutex") = Hash::zeroed().typed()
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if there is a change in WSV peers, otherwise leaves the order unchanged.
    #[allow(clippy::expect_used)]
    pub fn update_network_topology(topology: &mut Topology, wsv: &WorldStateView) {
        let wsv_peers: HashSet<_> = wsv
            .trusted_peers_ids()
            .iter()
            .map(|id_ref| id_ref.clone())
            .collect();
        let topology_peers: HashSet<_> = topology.sorted_peers().iter().cloned().collect();
        if topology_peers != wsv_peers {
            *topology = topology
                    .clone()
                    .into_builder()
                    .with_peers(wsv_peers)
                    .build(0)
                .expect("The safety of changing the number of peers should have been checked at the Instruction execution stage.");
        }
    }

    /// Send a sumeragi packet over the network to the specified `peer`.
    /// # Errors
    /// Fails if network sending fails
    #[instrument(skip(self, packet))]
    fn post_packet_to(&self, packet: MessagePacket, peer: &PeerId) {
        let post = iroha_p2p::Post {
            data: NetworkMessage::SumeragiPacket(Box::new(packet.into())),
            peer: peer.clone(),
        };
        self.broker.issue_send_sync(&post);
    }

    fn broadcast_packet_to<'peer_id>(
        &self,
        msg: MessagePacket,
        ids: impl Iterator<Item = &'peer_id PeerId> + Send,
    ) {
        for peer_id in ids {
            self.post_packet_to(msg.clone(), peer_id);
        }
    }

    fn broadcast_packet(&self, msg: MessagePacket, topology: &Topology) {
        self.broadcast_packet_to(msg, topology.sorted_peers().iter());
    }

    /// Connects or disconnects peers according to the current network topology.
    #[allow(clippy::expect_used)]
    pub fn connect_peers(&self, topology: &Topology) {
        let peers_expected = {
            let mut res = topology.sorted_peers().to_owned();
            res.retain(|id| id.address != self.peer_id.address);
            res.shuffle(&mut rand::thread_rng());
            res
        };

        let mut connected_to_peers_by_key = self.get_online_peer_keys();

        for peer_to_be_connected in &peers_expected {
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

    /// The maximum time a sumeragi round can take to produce a block when
    /// there are no faulty peers in the a set.
    pub fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }
}

#[allow(clippy::expect_used)]
fn block_commit<F>(
    sumeragi: &SumeragiWithFault<F>,
    block: VersionedValidBlock,
    state_machine: &mut SumeragiStateMachineData,
) where
    F: FaultInjection,
{
    let block = block.commit();
    let block_hash = block.hash();

    state_machine
        .wsv
        .apply(block.clone())
        .expect("Failed to apply block on WSV. This is absolutely not acceptable.");
    // Update WSV copy that is public facing
    {
        let mut wsv_for_public_use_guard = sumeragi
            .wsv
            .lock()
            .expect("WSV mutex in `block_commit` poisoned");
        *wsv_for_public_use_guard = state_machine.wsv.clone();
    }

    for event in Vec::<Event>::from(&block) {
        trace!(?event);
        sumeragi
            .events_sender
            .send(event)
            .map_err(|e| error!(%e, "Some events failed to be sent"))
            .unwrap_or(0);
        // Essentially log and ignore.
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
    state_machine
        .current_topology
        .update_network_topology(&state_machine.wsv);

    // Transaction Cache
    cache_transaction(state_machine, sumeragi)
}

fn cache_transaction<F: FaultInjection>(
    state_machine: &mut SumeragiStateMachineData,
    sumeragi: &SumeragiWithFault<F>,
) {
    let transaction_cache = &mut state_machine.transaction_cache;
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

#[allow(clippy::expect_used)]
fn request_view_change<F>(
    sumeragi: &SumeragiWithFault<F>,
    state_machine: &mut SumeragiStateMachineData,
    view_change_proof_chain: &mut Vec<Proof>,
    current_view_change_index: u64,
) where
    F: FaultInjection,
{
    let suspect_proof = {
        let mut proof = Proof {
            latest_block_hash: state_machine.latest_block_hash,
            view_change_index: current_view_change_index,
            signatures: Vec::new(),
        };
        proof
            .sign(sumeragi.key_pair.clone())
            .expect("Suspect proof must be able to perform signing");
        proof
    };

    let _ = view_change_proof_chain.insert_proof(
        &state_machine
            .current_topology
            .sorted_peers()
            .iter()
            .cloned()
            .collect(),
        state_machine.current_topology.max_faults(),
        &state_machine.latest_block_hash,
        &suspect_proof,
    );

    sumeragi.broadcast_packet(
        MessagePacket::new(
            view_change_proof_chain.clone(),
            Message::ViewChangeSuggested,
        ),
        &state_machine.current_topology,
    );
}

#[instrument(skip(sumeragi, state_machine_guard))]
#[allow(clippy::expect_used)]
/// Execute the main loop of [`SumeragiWithFault`]
pub fn run_sumeragi_main_loop<F>(
    sumeragi: &SumeragiWithFault<F>,
    mut state_machine_guard: SumeragiStateMachineData,
    mut shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
) where
    F: FaultInjection,
{
    let mut incoming_message_receiver = sumeragi
        .incoming_message_receiver
        .lock()
        .expect("lock on reciever");

    if state_machine_guard.latest_block_height != 0
        && state_machine_guard.latest_block_hash != Hash::zeroed().typed()
    {
        // Normal startup
        // Aka, we don't have to do anything.
    } else {
        // We don't have the genesis block.
        // We need to perform a round of some form.
        if let Some(genesis_network) = state_machine_guard.genesis_network.take() {
            sumeragi_init_commit_genesis(sumeragi, &mut state_machine_guard, genesis_network);
        } else {
            sumeragi_init_listen_for_genesis(
                sumeragi,
                &mut state_machine_guard,
                &mut incoming_message_receiver,
                &mut shutdown_receiver,
            )
            .unwrap_or_else(|err| {
                if let EarlyReturn::Disconnected = err {
                    panic!("Disconnected")
                }
            });
        }
    }

    {
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
    let mut maybe_incoming_message = None;
    loop {
        if shutdown_receiver.try_recv().is_ok() {
            info!("Sumeragi Thread is being shutdown shut down.");
            return;
        }

        if should_sleep {
            let span = span!(Level::TRACE, "Sumeragi Main Thread Sleep");
            let _enter = span.enter();
            std::thread::sleep(std::time::Duration::from_micros(5000));
            should_sleep = false;
        }
        let span_for_sumeragi_cycle = span!(Level::TRACE, "Sumeragi Main Thread Cycle");
        let _enter_for_sumeragi_cycle = span_for_sumeragi_cycle.enter();

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

        if last_sent_transaction_gossip_time.elapsed() > sumeragi.gossip_period {
            let mut txs = Vec::new();
            for tx in &state_machine_guard.transaction_cache {
                txs.push(tx.clone().expect("Failed to clone `tx`"));
                if txs.len() >= sumeragi.gossip_batch_size as usize {
                    break;
                }
            }
            if !txs.is_empty() {
                debug!(
                    peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                    tx_count = txs.len(),
                    "Gossiping transactions"
                );

                sumeragi.broadcast_packet(
                    MessagePacket::new(
                        view_change_proof_chain.clone(),
                        TransactionGossip::new(txs).into(),
                    ),
                    &state_machine_guard.current_topology,
                );
                last_sent_transaction_gossip_time = Instant::now();
            }
        }

        assert!(maybe_incoming_message.is_none(),"If there is a message available it must be consumed within one loop cycle. A in house rule in place to stop one from implementing bugs that render a node not responding.");
        maybe_incoming_message = match incoming_message_receiver.try_recv() {
            Ok(packet) => {
                let peer_list = state_machine_guard
                    .current_topology
                    .sorted_peers()
                    .iter()
                    .cloned()
                    .collect();

                for proof in packet.view_change_proofs {
                    let _ = view_change_proof_chain.insert_proof(
                        &peer_list,
                        state_machine_guard.current_topology.max_faults(),
                        &state_machine_guard.latest_block_hash,
                        &proof,
                    );
                }
                Some(packet.message)
            }
            Err(recv_error) => match recv_error {
                mpsc::TryRecvError::Empty => None,
                mpsc::TryRecvError::Disconnected => {
                    panic!("Sumeragi message pump disconnected. This is not a recoverable error.")
                }
            },
        };

        if let Some(stolen_message) = maybe_incoming_message.take() {
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
                Message::ViewChangeSuggested => {
                    trace!("Received view change suggestion.");
                }
                Message::TransactionForwarded(tx_forw) => {
                    maybe_incoming_message = Some(Message::TransactionForwarded(tx_forw));
                }
                Message::BlockCreated(block_created) => {
                    maybe_incoming_message = Some(Message::BlockCreated(block_created));
                }
                Message::BlockSigned(block_signed) => {
                    maybe_incoming_message = Some(Message::BlockSigned(block_signed));
                }
                Message::BlockCommitted(block_committed) => {
                    maybe_incoming_message = Some(Message::BlockCommitted(block_committed));
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
            if !state_machine_guard.transaction_cache.is_empty() && !has_sent_transactions {
                // It is assumed that we only need to send 1 tx to check liveness.
                let tx = state_machine_guard
                    .transaction_cache
                    .choose(&mut rand::thread_rng())
                    .expect("It was checked earlier that transaction cache is not empty.")
                    .clone()
                    .expect("It is also a non-empty variant");
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
                    sumeragi.broadcast_packet_to(
                        MessagePacket::new(
                            view_change_proof_chain.clone(),
                            TransactionForwarded::new(tx).into(),
                        ),
                        [state_machine_guard.current_topology.leader()].into_iter(),
                    );
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
                let incoming_message = maybe_incoming_message
                    .take()
                    .expect("Message must have been `Some` at this point");
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
                            sumeragi.events_sender.send(event).unwrap_or(0);
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

                let msg = maybe_incoming_message.take().expect("Valid");
                match msg {
                    TransactionForwarded(transaction_forwarded) => {
                        let transaction_maybe = VersionedAcceptedTransaction::from_transaction(
                            transaction_forwarded.transaction.clone().into_v1(),
                            &sumeragi.transaction_limits,
                        );
                        if transaction_maybe.is_ok() {
                            let transaction = transaction_maybe.expect("Valid");
                            match sumeragi.queue.push(transaction, &state_machine_guard.wsv) {
                                Err((_, crate::queue::Error::InBlockchain)) | Ok(_) => (),
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
                if state_machine_guard.transaction_cache.is_empty() {
                    instant_when_we_should_create_a_block = Instant::now() + sumeragi.block_time;
                    continue;
                }
                if Instant::now() > instant_when_we_should_create_a_block
                    || state_machine_guard.transaction_cache.len() >= sumeragi.queue.txs_in_block
                {
                    let transactions: Vec<VersionedAcceptedTransaction> = state_machine_guard
                        .transaction_cache
                        .iter()
                        .map(|tx| tx.clone().expect("Is Some"))
                        .collect();

                    info!("sumeragi Doing block with {} txs.", transactions.len());
                    // TODO: This should properly process triggers
                    let event_recommendations = Vec::new();

                    let block = PendingBlock::new(transactions, event_recommendations).chain(
                        state_machine_guard.latest_block_height,
                        state_machine_guard.latest_block_hash,
                    );
                    {
                        let block = {
                            let span_for_sumeragi_leader_block_validate =
                                span!(Level::TRACE, "Sumeragi Leader Create block, validation.");
                            let _enter_for_sumeragi_leader_block_validate =
                                span_for_sumeragi_leader_block_validate.enter();

                            block
                                .validate(&sumeragi.transaction_validator, &state_machine_guard.wsv)
                        };

                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event).unwrap_or(0);
                        }
                        let signed_block = block
                            .sign(sumeragi.key_pair.clone())
                            .expect("Sign genesis block.");

                        if !state_machine_guard.current_topology.is_consensus_required() {
                            sumeragi.broadcast_packet(
                                MessagePacket::new(
                                    view_change_proof_chain.clone(),
                                    BlockCommitted::from(signed_block.clone()).into(),
                                ),
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

                        voting_block_option = Some(voting_block);
                        sumeragi.broadcast_packet_to(
                            MessagePacket::new(
                                view_change_proof_chain.clone(),
                                BlockCreated::from(signed_block.clone()).into(),
                            ),
                            state_machine_guard.current_topology.peers_set_a().iter(),
                        );
                        instant_at_which_we_should_have_committed =
                            Instant::now() + sumeragi.commit_time;
                        trace!("I, the leader, have created a block.");
                    }
                }
            } else if Instant::now() > instant_at_which_we_should_have_committed {
                trace!("Suspecting validating peers and proxy tail for not comitting the block.");
                request_view_change(
                    sumeragi,
                    &mut state_machine_guard,
                    &mut view_change_proof_chain,
                    current_view_change_index,
                );
                instant_at_which_we_should_have_committed += sumeragi.commit_time;
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

                        trace!("I, a validating peer, have received a block.");

                        let block = {
                            let span_for_sumeragi_validating_peer_block_validate =
                                span!(Level::TRACE, "Sumeragi Validating Peer Validate block.");
                            let _enter_for_sumeragi_validating_peer_block_validate =
                                span_for_sumeragi_validating_peer_block_validate.enter();

                            block.revalidate(
                                &sumeragi.transaction_validator,
                                &state_machine_guard.wsv,
                            )
                        };

                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event).unwrap_or(0);
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

                        let hash = state_machine_guard.latest_block_hash;
                        let block_height = state_machine_guard.latest_block_height;
                        if let Err(e) = block.validation_check(
                            &state_machine_guard.wsv,
                            &hash,
                            block_height,
                            &sumeragi.transaction_limits,
                        ) {
                            warn!(%e);
                        } else {
                            let block_clone = block.clone();
                            let key_pair_clone = sumeragi.key_pair.clone();
                            let signed_block = block_clone
                                .sign(key_pair_clone)
                                .expect("maybe we should handle this error");

                            sumeragi.broadcast_packet_to(
                                MessagePacket::new(
                                    view_change_proof_chain.clone(),
                                    Message::BlockSigned(signed_block.into()).into(),
                                ),
                                [state_machine_guard.current_topology.proxy_tail()].into_iter(),
                            );
                            info!(
                                peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                block_hash = %block.hash(),
                                "Signed block candidate",
                            );
                        }

                        let voting_block = VotingBlock::new(block.clone());
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
                let incoming_message = maybe_incoming_message.take().expect(
                    "Incoming message is some in this `if` block. This is a hardware error.",
                );

                match incoming_message {
                    Message::BlockCreated(block_created) => {
                        let block = block_created.block;

                        if voting_block_option.is_some() {
                            warn!("Already have block, ignoring.");
                            continue;
                        }

                        trace!("I, the proxy tail, have received a block.");
                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            sumeragi.events_sender.send(event).unwrap_or(0);
                        }

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

                            block.revalidate(
                                &sumeragi.transaction_validator,
                                &state_machine_guard.wsv,
                            )
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
                            && block_hash
                                != voting_block_option
                                    .as_ref()
                                    .expect("Voting block is `Some`")
                                    .block
                                    .hash()
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
                // if there is no message — sleep
                should_sleep = true;
            }

            if voting_block_option.is_some() {
                // count votes

                let validating_peers = state_machine_guard.current_topology.peers_set_a();
                let mut signatures_on_this_block = Vec::new();

                let voting_block_hash = voting_block_option
                    .as_ref()
                    .expect("Vptomg block option is `Some`")
                    .block
                    .hash();
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
                    let mut block = voting_block_option
                        .expect("Voting block should have been `Some`")
                        .block;
                    voting_block_option = None;

                    block.as_mut_v1().signatures = peer_signatures
                        .into_iter()
                        .map(SignatureOf::transmute)
                        .collect();
                    let block = block
                        .sign(sumeragi.key_pair.clone())
                        .expect("Signing can only fail if the Key-Pair failed. This is mainly caused by hardware failure");

                    assert!(
                        block.as_v1().signatures.len()
                            >= state_machine_guard.current_topology.min_votes_for_commit()
                    );

                    info!(
                        %voting_block_hash,
                        "Block reached required number of votes",
                    );

                    sumeragi.broadcast_packet(
                        MessagePacket::new(
                            view_change_proof_chain.clone(),
                            BlockCommitted::from(block.clone()).into(),
                        ),
                        &state_machine_guard.current_topology,
                    );
                    block_commit(sumeragi, block, &mut state_machine_guard);
                }

                if Instant::now() > instant_at_which_we_should_have_committed {
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
}

#[allow(clippy::expect_used)]
fn sumeragi_init_commit_genesis<F>(
    sumeragi: &SumeragiWithFault<F>,
    state_machine_guard: &mut SumeragiStateMachineData,
    genesis_network: GenesisNetwork,
) where
    F: FaultInjection,
{
    std::thread::sleep(Duration::from_millis(250));

    iroha_logger::info!("Initializing iroha using the genesis block.");

    assert_eq!(state_machine_guard.latest_block_height, 0);
    assert_eq!(
        state_machine_guard.latest_block_hash,
        Hash::zeroed().typed()
    );

    let transactions = genesis_network.transactions;
    // Don't start genesis round. Instead just commit the genesis block.
    assert!(
        !transactions.is_empty(),
        "Genesis transaction set contains no valid transactions"
    );
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
            sumeragi.events_sender.send(event).unwrap_or(0);
        }
        let signed_block = block
            .sign(sumeragi.key_pair.clone())
            .expect("Sign genesis block.");
        {
            sumeragi.broadcast_packet(
                MessagePacket::new(
                    Vec::new(),
                    BlockCommitted::from(signed_block.clone()).into(),
                ),
                &state_machine_guard.current_topology,
            );
            block_commit(sumeragi, signed_block, state_machine_guard);
        }
    }
}

pub enum EarlyReturn {
    GenesisBlockReceivedAndCommitted,
    ShutdownMessageReceived,
    Disconnected,
}

fn early_return(
    shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), EarlyReturn> {
    if shutdown_receiver.try_recv().is_ok() {
        info!("Sumeragi Thread is being shutdown shut down.");
        Err(EarlyReturn::ShutdownMessageReceived)
    } else {
        Ok(())
    }
}

#[allow(clippy::expect_used, clippy::panic)]
fn sumeragi_init_listen_for_genesis<F>(
    sumeragi: &SumeragiWithFault<F>,
    state_machine_guard: &mut SumeragiStateMachineData,
    incoming_message_receiver: &mut mpsc::Receiver<MessagePacket>,
    shutdown_receiver: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), EarlyReturn>
where
    F: FaultInjection,
{
    trace!("Start listen for genesis.");
    assert!(
        state_machine_guard.current_topology.is_consensus_required(),
        "Only peer in network, yet required to receive genesis topology. This is a configuration error."
    );
    sumeragi.zeroize();
    loop {
        sumeragi.connect_peers(&state_machine_guard.current_topology);
        std::thread::sleep(Duration::from_millis(50));
        early_return(shutdown_receiver)?;
        // we must connect to peers so that our block_sync can find us the genesis block.
        match incoming_message_receiver.try_recv() {
            Ok(packet) => match packet.message {
                Message::BlockCommitted(block_committed) => {
                    // If we recieve a committed genesis block that is valid, use it without question.
                    // During the genesis round we blindly take on the network topology described in
                    // the provided genesis block.
                    let block_header = block_committed.block.header();
                    if block_header.is_genesis() && block_header.genesis_topology.is_some() {
                        info!("Using network topology from genesis block");
                        state_machine_guard.current_topology = block_header
                            .genesis_topology
                            .clone()
                            .take()
                            .expect("We just checked that it is some");
                        block_commit(sumeragi, block_committed.block, state_machine_guard);
                        info!("Genesis block received and committed.");
                        return Err(EarlyReturn::GenesisBlockReceivedAndCommitted);
                    }
                    debug!("Received block that was not genesis.");
                }
                msg => {
                    trace!(?msg, "Not handling message, waiting genesis.");
                }
            },
            Err(mpsc::TryRecvError::Disconnected) => return Err(EarlyReturn::Disconnected),
            _ => (),
        }
    }
}
