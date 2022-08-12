//! Fault injection for tests. Almost all structs from this module
//! should be reserved for testing, and only [`NoFault`], should be
//! used in code.

use iroha_primitives::must_use::MustUse;

use super::*;
use std::sync::{mpsc, Mutex};

use crate::genesis::GenesisNetwork;

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
    /// This field is used to count votes when the peer is a proxy tail role.
    pub(crate) votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    pub(crate) events_sender: EventsSender,
    pub(crate) wsv: std::sync::Mutex<WorldStateView>,

    /// This field is used to count votes for a view change.
    pub(crate) votes_for_view_change: HashMap<HashOf<Proof>, Proof>,

    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    /// And time at which this transaction was sent to the leader by this peer.
    pub(crate) txs_awaiting_receipts: HashMap<HashOf<VersionedSignedTransaction>, Instant>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in `CreatedBlock`.
    pub(crate) txs_awaiting_created_block: HashSet<HashOf<VersionedSignedTransaction>>,

    pub(crate) commit_time: Duration,
    pub(crate) tx_receipt_time: Duration,
    pub(crate) block_time: Duration,
    pub(crate) block_height: u64,
    /// Hashes of invalidated blocks
    pub invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    pub(crate) transaction_limits: TransactionLimits,
    pub(crate) transaction_validator: TransactionValidator,
    pub(crate) telemetry_started: bool,
    /// Broker
    pub broker: Broker,
    /// Kura instance used for IO
    pub kura: Arc<Kura>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,
    /// Buffer capacity of actor's MPSC channel
    pub actor_channel_capacity: u32,
    pub(crate) fault_injection: PhantomData<F>,
    pub(crate) gossip_batch_size: u32,
    pub(crate) gossip_period: Duration,

    pub sumeragi_state_machine_data: Mutex<SumeragiStateMachineData>,
    pub current_online_peers_by_public_key: Mutex<Vec<PublicKey>>,

    pub incoming_message_sender: Mutex<mpsc::Sender<Message>>,
    pub incoming_message_receiver: Mutex<mpsc::Receiver<Message>>,
}

pub struct SumeragiStateMachineData {
    pub genesis_network: Option<GenesisNetwork>,
    pub latest_block_hash: HashOf<VersionedCommittedBlock>,
    pub latest_block_height: u64,
    pub current_topology: Topology,

    pub sumeragi_thread_should_exit: bool,
}

impl<F: FaultInjection> SumeragiWithFault<F> {
    pub fn get_online_peer_keys(&self) -> Vec<PublicKey> {
        self.current_online_peers_by_public_key
            .lock()
            .expect("lock on online peer keys")
            .clone()
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
                    .build()
                    // TODO: Check it during instruction execution.
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
        trace!("Connecting peers...");
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

    /// If `suggested_chain` of view change proofs is bigger than the the current one - replace the current one.
    pub fn update_view_changes(
        &self,
        suggested_chain: view_change::ProofChain,
        topology: Topology,
        latest_block_hash: &HashOf<VersionedCommittedBlock>,
    ) -> Topology {
        #[allow(clippy::expect_used)]
        if suggested_chain.len() > topology.view_change_proofs().len()
            && suggested_chain.verify_with_state(
                &topology.sorted_peers().iter().cloned().collect(),
                topology.max_faults(),
                latest_block_hash,
            )
        {
            info!(
                prev_view_changes_count = topology.view_change_proofs().len(),
                new_view_changes_count = suggested_chain.len(),
                latest_block = ?latest_block_hash,
                "Swapping view change proof chain."
            );
            topology
                .clone()
                .into_builder()
                .with_view_changes(suggested_chain)
                .build()
                .expect("When only changing view changes it should not fail.")
        } else {
            topology
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

            let online_peers = self.current_online_peers_by_public_key.lock().unwrap();

            let peer_count_required = network_topology.min_votes_for_commit();

            if online_peers.len() + 1 >= peer_count_required {
                return;
            }

            let reconnect_in_ms = 250;
            std::thread::sleep(Duration::from_millis(reconnect_in_ms));
        }
        panic!("Timed out waiting for peers to come online");
    }
}

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

    let mut voting_block_option: Option<VotingBlock> = None;

    {
        let mut state_machine_guard = sumeragi
            .sumeragi_state_machine_data
            .lock()
            .expect("take lock");
        if initial_block_height != 0 && initial_latest_block != Hash::zeroed().typed() {
            // Normal startup
            state_machine_guard.latest_block_hash = initial_latest_block;
            state_machine_guard.latest_block_height = initial_block_height;
            state_machine_guard
                .current_topology
                .apply_block(initial_latest_block);
        } else if !state_machine_guard.current_topology.is_consensus_required() {
            let genesis_network = state_machine_guard.genesis_network.take().unwrap();
            iroha_logger::debug!("Starting commit genesis. Since consensus is not required.");

            iroha_logger::info!("Initializing iroha using the genesis block.");

            state_machine_guard.current_topology = sumeragi
                .try_get_online_topology(&state_machine_guard.current_topology)
                .expect("enough peers to pass genesis");

            assert!(!state_machine_guard.current_topology.is_consensus_required());

            println!("Genesis being submitted by {}", sumeragi.peer_id.public_key);
            println!("Online peers are {:?}", sumeragi.get_online_peer_keys());

            state_machine_guard.latest_block_height = 0;

            assert_eq!(
                state_machine_guard.current_topology.role(&sumeragi.peer_id),
                Role::Leader
            );
            let transactions = genesis_network.transactions.clone();
            {
                // Don't start genesis round. Instead just commit the genesis block.
                if transactions.is_empty() {
                    panic!("Genesis transactions set contains no valid transactions");
                } else {
                    let mut wsv_guard = sumeragi.wsv.lock().unwrap();
                    let block = PendingBlock::new(transactions, Vec::new())
                        .chain_first_with_genesis_topology(
                            state_machine_guard.current_topology.clone(),
                        );

                    {
                        info!(block_hash = %block.hash(), "Publishing genesis block.");

                        let block = block.validate(&sumeragi.transaction_validator, &wsv_guard);

                        info!(
                            peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                            block_hash = %block.hash(),
                            "Created a block",
                        );
                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            drop(sumeragi.events_sender.send(event));
                        }
                        let signed_block = block
                            .sign(sumeragi.key_pair.clone())
                            .expect("Sign genesis block.");
                        {
                            {
                                /*
                                TODO: purge the unneeded of these
                                self.invalidated_blocks_hashes.clear();
                                self.txs_awaiting_created_block.clear();
                                self.txs_awaiting_receipts.clear();
                                self.votes_for_view_change.clear();
                                */

                                sumeragi.broadcast_msg(
                                    BlockCommitted::from(signed_block.clone()),
                                    &state_machine_guard.current_topology,
                                );

                                let block = signed_block.commit();
                                let block_hash = block.hash();

                                if let Err(error) = wsv_guard.apply(block.clone()) {
                                    panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                }

                                for event in Vec::<Event>::from(&block) {
                                    trace!(?event);
                                    drop(sumeragi.events_sender.send(event));
                                }

                                state_machine_guard.latest_block_height = block.header().height;
                                state_machine_guard.latest_block_hash = block.hash();

                                let previous_role =
                                    state_machine_guard.current_topology.role(&sumeragi.peer_id);
                                state_machine_guard.current_topology.apply_block(block_hash);
                                info!(
                                    prev_peer_role = ?previous_role,
                                    new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                    new_block_height = %state_machine_guard.latest_block_height,
                                    %block_hash,
                                    "Committing block"
                                );
                                sumeragi.kura.store_block_blocking(block);
                                SumeragiWithFault::<F>::update_network_topology(
                                    &mut state_machine_guard.current_topology,
                                    &wsv_guard,
                                );
                            }
                        }
                    }
                }
            }
        } else {
            if let Some(genesis_network) = state_machine_guard.genesis_network.take() {
                // Submit genesis
                {
                    iroha_logger::debug!("Starting submit genesis");

                    sumeragi.wait_for_peers(&state_machine_guard.current_topology);

                    iroha_logger::info!("Initializing iroha using the genesis block.");

                    state_machine_guard.current_topology = sumeragi
                        .try_get_online_topology(&state_machine_guard.current_topology)
                        .expect("enough peers to pass genesis");

                    println!("Genesis being submitted by {}", sumeragi.peer_id.public_key);
                    println!("Online peers are {:?}", sumeragi.get_online_peer_keys());

                    state_machine_guard.latest_block_height = 0;

                    let genesis_topology = &state_machine_guard.current_topology;
                    assert_eq!(genesis_topology.role(&sumeragi.peer_id), Role::Leader);
                    let transactions = genesis_network.transactions.clone();
                    {
                        // Start genesis round
                        if transactions.is_empty() {
                            panic!("Genesis transactions set contains no valid transactions");
                        } else {
                            let mut wsv_guard = sumeragi.wsv.lock().unwrap();
                            let block = PendingBlock::new(transactions, Vec::new())
                                .chain_first_with_genesis_topology(genesis_topology.clone());

                            {
                                info!(block_hash = %block.hash(), "Publishing genesis block.");

                                let block =
                                    block.validate(&sumeragi.transaction_validator, &wsv_guard);

                                info!(
                                    peer_role = ?genesis_topology.role(&sumeragi.peer_id),
                                    block_hash = %block.hash(),
                                    "Created a block",
                                );
                                for event in Vec::<Event>::from(&block) {
                                    trace!(?event);
                                    drop(sumeragi.events_sender.send(event));
                                }
                                let signed_block = block
                                    .sign(sumeragi.key_pair.clone())
                                    .expect("Sign genesis block.");

                                let voting_block = VotingBlock::new(signed_block.clone());
                                let voting_block_hash = voting_block.block.hash();

                                voting_block_option = Some(voting_block);
                                sumeragi.broadcast_msg(
                                    BlockCreated::from(signed_block.clone()),
                                    genesis_topology,
                                );

                                {
                                    // view change proof
                                    let proof = view_change::Proof::commit_timeout(
                                        voting_block_hash,
                                        genesis_topology.view_change_proofs().latest_hash(),
                                        *genesis_topology.at_block(),
                                        sumeragi.key_pair.clone(),
                                    )
                                    .expect("Failed to sign CommitTimeout");
                                    // TODO: Commit timeout causes viewchange
                                }
                            }
                        }
                    }
                }
            } else {
                sumeragi.wait_for_peers(&state_machine_guard.current_topology);
            }

            {
                // now do the genesis *round*.
                {
                    while voting_block_option.is_none() {
                        println!("no voting block");

                        match incoming_message_receiver.try_recv() {
                            Ok(msg) => {
                                match msg {
                                    Message::BlockCommitted(block_committed) => {
                                        // If we recieve a committed genesis block that is valid, use it without question.
                                        let block = block_committed.block;

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
                                        } else {
                                            continue;
                                        }

                                        let network_topology =
                                            state_machine_guard.current_topology.clone();

                                        let verified_signatures = block
                                            .verified_signatures()
                                            .cloned()
                                            .collect::<Vec<_>>();
                                        let valid_signatures = network_topology
                                            .filter_signatures_by_roles(
                                                &[
                                                    Role::ValidatingPeer,
                                                    Role::Leader,
                                                    Role::ProxyTail,
                                                ],
                                                &verified_signatures,
                                            );
                                        let proxy_tail_signatures = network_topology
                                            .filter_signatures_by_roles(
                                                &[Role::ProxyTail],
                                                &verified_signatures,
                                            );
                                        if valid_signatures.len()
                                            >= network_topology.min_votes_for_commit()
                                            && proxy_tail_signatures.len() == 1
                                            && state_machine_guard.latest_block_hash
                                                == block.header().previous_block_hash
                                        {
                                            {
                                                /*
                                                TODO: purge the unneeded of these
                                                self.invalidated_blocks_hashes.clear();
                                                self.txs_awaiting_created_block.clear();
                                                self.txs_awaiting_receipts.clear();
                                                self.votes_for_view_change.clear();
                                                */

                                                let block = block.commit();
                                                let block_hash = block.hash();

                                                let mut wsv_guard = sumeragi.wsv.lock().unwrap();

                                                if let Err(error) = wsv_guard.apply(block.clone()) {
                                                    panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                                }

                                                for event in Vec::<Event>::from(&block) {
                                                    trace!(?event);
                                                    drop(sumeragi.events_sender.send(event));
                                                }

                                                state_machine_guard.latest_block_height =
                                                    block.header().height;
                                                state_machine_guard.latest_block_hash =
                                                    block.hash();

                                                let previous_role = state_machine_guard
                                                    .current_topology
                                                    .role(&sumeragi.peer_id);
                                                state_machine_guard
                                                    .current_topology
                                                    .apply_block(block_hash);
                                                info!(
                                                    prev_peer_role = ?previous_role,
                                                    new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                                    new_block_height = %state_machine_guard.latest_block_height,
                                                    %block_hash,
                                                    "Committing block"
                                                );
                                                sumeragi.kura.store_block_blocking(block);
                                                SumeragiWithFault::<F>::update_network_topology(
                                                    &mut state_machine_guard.current_topology,
                                                    &wsv_guard,
                                                );
                                                voting_block_option = None;
                                                println!("We missed the genesis but have been given the genesis block.");
                                                break;
                                            }
                                        }
                                    }
                                    Message::BlockCreated(block_created) => {
                                        let block = block_created.block;

                                        let mut wsv_guard =
                                            sumeragi.wsv.lock().expect("lock on wsv");

                                        for event in Vec::<Event>::from(&block) {
                                            trace!(?event);
                                            drop(sumeragi.events_sender.send(event));
                                        }
                                        state_machine_guard.current_topology = sumeragi
                                            .update_view_changes(
                                                block.header().view_change_proofs.clone(),
                                                state_machine_guard.current_topology.clone(),
                                                &state_machine_guard.latest_block_hash,
                                            );

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
                                        let network_topology =
                                            &state_machine_guard.current_topology;

                                        // sumeragi.txs_awaiting_created_block.clear(); TODO: Figure out what this is for
                                        if network_topology.role(&sumeragi.peer_id)
                                            == Role::ValidatingPeer
                                        {
                                            if let Err(e) = block.validation_check(
                                                &mut wsv_guard,
                                                &state_machine_guard.latest_block_hash,
                                                &state_machine_guard
                                                    .current_topology
                                                    .view_change_proofs()
                                                    .latest_hash(),
                                                state_machine_guard.latest_block_height,
                                                &sumeragi.transaction_limits,
                                            ) {
                                                warn!(%e)
                                            } else {
                                                let block_clone = block.clone();
                                                let key_pair_clone = sumeragi.key_pair.clone();
                                                let transaction_validator =
                                                    sumeragi.transaction_validator.clone();
                                                let signed_block = block_clone
                                                    .revalidate(&transaction_validator, &wsv_guard)
                                                    .sign(key_pair_clone)
                                                    .expect("maybe we should handle this error");
                                                {
                                                    let post = iroha_p2p::Post {
                                                        data: NetworkMessage::SumeragiMessage(
                                                            Box::new(VersionedMessage::from(
                                                                Message::BlockSigned(
                                                                    signed_block.into(),
                                                                ),
                                                            )),
                                                        ),
                                                        peer: network_topology.proxy_tail().clone(),
                                                    };
                                                    sumeragi.broker.issue_send_sync(&post);
                                                }
                                                info!(
                                                    peer_role = ?network_topology.role(&sumeragi.peer_id),
                                                    block_hash = %block.hash(),
                                                    "Signed block candidate",
                                                );
                                                println!("Signed block and sent to proxy tail.");
                                            }
                                            //TODO: send to set b so they can observe
                                        }
                                        let voting_block = VotingBlock::new(block.clone());
                                        let voting_block_hash = voting_block.block.hash();
                                        voting_block_option = Some(voting_block);

                                        // TODO: Do commit countdown.
                                    }
                                    _ => {
                                        println!("Not handling message {:?}", msg);
                                    }
                                }
                            }
                            Err(recv_error) => {
                                match recv_error {
                                    TryRecvError::Empty => {
                                        std::thread::sleep(Duration::from_millis(100));
                                    }
                                    TryRecvError::Disconnected => {
                                        panic!("Sumeragi message pump disconnected.")
                                    }
                                };
                            }
                        }
                    }
                }

                // We have a voting block
                if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
                    let validating_peers = state_machine_guard.current_topology.peers_set_a();
                    let mut peer_signatures = vec![None; validating_peers.len()];
                    let voting_block = voting_block_option.take().expect("take voting block");
                    let voting_block_hash = voting_block.block.hash();
                    loop {
                        if state_machine_guard.latest_block_height > 1 {
                            break;
                        }
                        if state_machine_guard.sumeragi_thread_should_exit {
                            info!("Sumeragi Thread has Shutdown");
                            return;
                        }
                        match incoming_message_receiver.try_recv() {
                            Ok(msg) => match msg {
                                Message::BlockSigned(block_signed) => {
                                    let block = block_signed.block;

                                    // I don't think we update the topology here. That ship has sailed.

                                    let network_topology = &state_machine_guard.current_topology;

                                    let block_hash = block.hash();

                                    if block_hash != voting_block_hash {
                                        error!("Block hash does not match voting block hash.");
                                    }

                                    let valid_signatures = network_topology
                                        .filter_signatures_by_roles(
                                            &[Role::ValidatingPeer, Role::Leader],
                                            block.verified_signatures(),
                                        );

                                    let mut number_of_votes = 0;
                                    for i in 0..validating_peers.len() {
                                        for sig in &valid_signatures {
                                            if *sig.public_key() == validating_peers[i].public_key {
                                                peer_signatures[i] = Some(sig.clone());
                                            }
                                        }

                                        if peer_signatures[i].is_some() {
                                            number_of_votes += 1;
                                        }
                                    }

                                    info!(
                                        %block_hash,
                                        number_of_votes = number_of_votes,
                                        required_number_of_votes = network_topology.min_votes_for_commit() - 1,
                                        "Received a vote for block",
                                    );

                                    if number_of_votes < network_topology.min_votes_for_commit() - 1
                                    {
                                        continue;
                                    }

                                    let mut signatures: Vec<SignatureOf<VersionedValidBlock>> =
                                        peer_signatures.into_iter().filter_map(|x| x).collect();
                                    let mut block = voting_block.block;
                                    block.as_mut_v1().signatures = signatures
                                        .into_iter()
                                        .map(SignatureOf::transmute)
                                        .collect();
                                    let block = block
                                        .sign(sumeragi.key_pair.clone())
                                        .expect("Why should signing fail?");

                                    assert!(
                                        block.as_v1().signatures.len()
                                            >= network_topology.min_votes_for_commit()
                                    );

                                    info!(
                                        %voting_block_hash,
                                        "Block reached required number of votes",
                                    );

                                    sumeragi.broadcast_msg_to(
                                        BlockCommitted::from(block.clone()),
                                        network_topology
                                            .validating_peers()
                                            .iter()
                                            .chain([network_topology.leader()])
                                            .chain(network_topology.peers_set_b()),
                                    );
                                    {
                                        /*
                                        TODO: purge the unneeded of these
                                        self.invalidated_blocks_hashes.clear();
                                        self.txs_awaiting_created_block.clear();
                                        self.txs_awaiting_receipts.clear();
                                        self.votes_for_view_change.clear();
                                        */

                                        let block = block.commit();
                                        let block_hash = block.hash();

                                        let mut wsv_guard = sumeragi.wsv.lock().unwrap();
                                        if let Err(error) = wsv_guard.apply(block.clone()) {
                                            panic!("Failed to apply block on WSV. This is not a recoverable state.");
                                        }

                                        for event in Vec::<Event>::from(&block) {
                                            trace!(?event);
                                            drop(sumeragi.events_sender.send(event));
                                        }

                                        state_machine_guard.latest_block_height =
                                            block.header().height;
                                        state_machine_guard.latest_block_hash = block.hash();

                                        let previous_role = state_machine_guard
                                            .current_topology
                                            .role(&sumeragi.peer_id);
                                        state_machine_guard
                                            .current_topology
                                            .apply_block(block_hash);
                                        info!(
                                            prev_peer_role = ?previous_role,
                                            new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                            new_block_height = %state_machine_guard.latest_block_height,
                                            %block_hash,
                                            "Committing block"
                                        );
                                        sumeragi.kura.store_block_blocking(block);
                                        SumeragiWithFault::<F>::update_network_topology(
                                            &mut state_machine_guard.current_topology,
                                            &wsv_guard,
                                        );
                                    }
                                    break;
                                }
                                _ => {
                                    println!("Not handling message {:?}", msg);
                                }
                            },
                            Err(recv_error) => {
                                match recv_error {
                                    TryRecvError::Empty => {
                                        std::thread::sleep(Duration::from_millis(100));
                                    }
                                    TryRecvError::Disconnected => {
                                        panic!("Sumeragi message pump disconnected.")
                                    }
                                };
                            }
                        }
                    }
                } else {
                    loop {
                        if state_machine_guard.latest_block_height > 1 {
                            break;
                        }
                        if state_machine_guard.sumeragi_thread_should_exit {
                            info!("Sumeragi Thread has Shutdown");
                            return;
                        }
                        match incoming_message_receiver.try_recv() {
                            Ok(msg) => match msg {
                                Message::BlockCommitted(block_committed) => {
                                    let block = block_committed.block;
                                    let network_topology =
                                        state_machine_guard.current_topology.clone();

                                    let verified_signatures =
                                        block.verified_signatures().cloned().collect::<Vec<_>>();
                                    let valid_signatures = network_topology
                                        .filter_signatures_by_roles(
                                            &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                                            &verified_signatures,
                                        );
                                    let proxy_tail_signatures = network_topology
                                        .filter_signatures_by_roles(
                                            &[Role::ProxyTail],
                                            &verified_signatures,
                                        );
                                    if valid_signatures.len()
                                        >= network_topology.min_votes_for_commit()
                                        && proxy_tail_signatures.len() == 1
                                        && state_machine_guard.latest_block_hash
                                            == block.header().previous_block_hash
                                    {
                                        {
                                            /*
                                            TODO: purge the unneeded of these
                                            self.invalidated_blocks_hashes.clear();
                                            self.txs_awaiting_created_block.clear();
                                            self.txs_awaiting_receipts.clear();
                                            self.votes_for_view_change.clear();
                                            */

                                            let block = block.commit();
                                            let block_hash = block.hash();

                                            let mut wsv_guard = sumeragi.wsv.lock().unwrap();
                                            if let Err(error) = wsv_guard.apply(block.clone()) {
                                                panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                            }

                                            for event in Vec::<Event>::from(&block) {
                                                trace!(?event);
                                                drop(sumeragi.events_sender.send(event));
                                            }

                                            state_machine_guard.latest_block_height =
                                                block.header().height;
                                            state_machine_guard.latest_block_hash = block.hash();

                                            let previous_role = state_machine_guard
                                                .current_topology
                                                .role(&sumeragi.peer_id);
                                            state_machine_guard
                                                .current_topology
                                                .apply_block(block_hash);
                                            info!(
                                                prev_peer_role = ?previous_role,
                                                new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                                new_block_height = %state_machine_guard.latest_block_height,
                                                %block_hash,
                                                "Committing block"
                                            );
                                            sumeragi.kura.store_block_blocking(block);
                                            SumeragiWithFault::<F>::update_network_topology(
                                                &mut state_machine_guard.current_topology,
                                                &wsv_guard,
                                            );
                                        }
                                        break;
                                    }
                                }
                                _ => {
                                    println!("Not handling message {:?}", msg);
                                }
                            },
                            Err(recv_error) => {
                                match recv_error {
                                    TryRecvError::Empty => {
                                        std::thread::sleep(Duration::from_millis(100));
                                    }
                                    TryRecvError::Disconnected => {
                                        panic!("Sumeragi message pump disconnected.")
                                    }
                                };
                            }
                        }
                    }
                }
            }
        }
    }

    {
        let mut state_machine_guard = sumeragi.sumeragi_state_machine_data.lock().unwrap();
        assert!(state_machine_guard.latest_block_height >= 1);
        println!(
            "I, {}, got to the end. My role in the first round is {:?}",
            sumeragi.peer_id.public_key,
            state_machine_guard.current_topology.role(&sumeragi.peer_id),
        );
        voting_block_option = None;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    {
        // do normal rounds

        let mut voting_block_option = None;

        let mut block_signature_acc = Vec::new();

        let mut should_sleep = false;

        let mut has_sent_transactions = false; // temporary, should be replaced with reciepts

        let mut maybe_incoming_message = None;
        loop {
            if should_sleep {
                std::thread::sleep(std::time::Duration::from_millis(50));
                should_sleep = false;
            }
            let mut state_machine_guard = sumeragi.sumeragi_state_machine_data.lock().unwrap();
            if state_machine_guard.sumeragi_thread_should_exit {
                info!("Sumeragi Thread has Shutdown");
                return;
            }

            sumeragi.connect_peers(&state_machine_guard.current_topology);

            let mut wsv_guard = sumeragi.wsv.lock().unwrap();

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

            if state_machine_guard.current_topology.role(&sumeragi.peer_id) != Role::Leader {
                let transactions = sumeragi.queue.get_transactions_for_block(&wsv_guard);
                if transactions.len() > 0 && !has_sent_transactions {
                    // If already sent tx and awaiting receipt or created block, then quit.
                    // if !self.txs_awaiting_receipts.is_empty() || !self.txs_awaiting_created_block.is_empty() {
                    //     return;
                    // }
                    // It is assumed that we only need to send 1 tx to check liveness.
                    let tx = transactions
                        .choose(&mut rand::thread_rng())
                        .expect("It was checked earlier that transactions are not empty.")
                        .clone();
                    let tx_hash = tx.hash();
                    info!(
                        peer_addr = %sumeragi.peer_id.address,
                        peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                        leader_addr = %state_machine_guard.current_topology.leader().address,
                        %tx_hash,
                        "Forwarding tx to leader"
                    );

                    // Don't require leader to submit receipts and therefore create blocks if the tx is still waiting for more signatures.
                    if let Ok(MustUse(true)) = tx.check_signature_condition(&wsv_guard) {
                        // self.txs_awaiting_receipts.insert(tx.hash(), Instant::now());
                    }
                    /*
                                            let no_tx_receipt = view_change::Proof::no_transaction_receipt_received(
                                                self.latest_view_change_hash(),
                                                *self.latest_block_hash(),
                                                self.key_pair.clone(),
                                            )
                                            .expect("Failed to put first signature.");

                                            ctx.notify(
                                                CheckReceiptTimeout {
                                                    tx_hash,
                                                    proof: no_tx_receipt,
                                                },
                                                self.tx_receipt_time,
                                            );
                    */

                    let post = iroha_p2p::Post {
                        data: NetworkMessage::SumeragiMessage(Box::new(VersionedMessage::from(
                            Message::from(TransactionForwarded::new(tx, sumeragi.peer_id.clone())),
                        ))),
                        peer: state_machine_guard.current_topology.leader().clone(),
                    };
                    sumeragi.broker.issue_send_sync(&post);

                    has_sent_transactions = true; // temporary
                                                  /*
                                                  println!(
                                                      "I, {}, a non leader, have sent a transaction to the leader.",
                                                      sumeragi.peer_id.public_key
                                                  );*/
                }
            }

            if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ObservingPeer {
                if maybe_incoming_message.is_some() {
                    let incoming_message = maybe_incoming_message.take().unwrap();
                    match incoming_message {
                        Message::BlockCreated(_) => {}
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
                                .filter_signatures_by_roles(
                                    &[Role::ProxyTail],
                                    &verified_signatures,
                                );
                            if valid_signatures.len() >= network_topology.min_votes_for_commit()
                                && proxy_tail_signatures.len() == 1
                                && state_machine_guard.latest_block_hash
                                    == block.header().previous_block_hash
                            {
                                {
                                    /*
                                    TODO: purge the unneeded of these
                                    self.invalidated_blocks_hashes.clear();
                                    self.txs_awaiting_created_block.clear();
                                    self.txs_awaiting_receipts.clear();
                                    self.votes_for_view_change.clear();
                                     */

                                    let block = block.commit();
                                    let block_hash = block.hash();

                                    if let Err(error) = wsv_guard.apply(block.clone()) {
                                        panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                    }

                                    for event in Vec::<Event>::from(&block) {
                                        trace!(?event);
                                        drop(sumeragi.events_sender.send(event));
                                    }

                                    state_machine_guard.latest_block_height = block.header().height;
                                    state_machine_guard.latest_block_hash = block.hash();

                                    let previous_role = state_machine_guard
                                        .current_topology
                                        .role(&sumeragi.peer_id);
                                    state_machine_guard.current_topology.apply_block(block_hash);
                                    info!(
                                        prev_peer_role = ?previous_role,
                                        new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                        new_block_height = %state_machine_guard.latest_block_height,
                                        %block_hash,
                                        "Committing block"
                                    );
                                    sumeragi.kura.store_block_blocking(block);
                                    SumeragiWithFault::<F>::update_network_topology(
                                        &mut state_machine_guard.current_topology,
                                        &wsv_guard,
                                    );
                                    has_sent_transactions = false;
                                    voting_block_option = None;
                                    println!(
                                        "Observing peer has committed a valid block it was given."
                                    );
                                }
                            }
                        }
                        _ => {
                            println!("Observing peer not handling message {:?}", incoming_message);
                        }
                    }
                } else {
                    should_sleep = true;
                }
                continue;
            }

            if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::Leader {
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
                                match sumeragi.queue.push(transaction, &wsv_guard) {
                                    Ok(()) => (),
                                    Err((_, crate::queue::Error::InBlockchain)) | Ok(()) => (),
                                    Err((_, err)) => {
                                        error!(%err, "Error while pushing transaction into queue?");
                                    }
                                }
                            } else {
                                error!(
                                    "Recieved transaction that did not pass transaction limits."
                                );
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
                                .filter_signatures_by_roles(
                                    &[Role::ProxyTail],
                                    &verified_signatures,
                                );
                            if valid_signatures.len() >= network_topology.min_votes_for_commit()
                                && proxy_tail_signatures.len() == 1
                                && state_machine_guard.latest_block_hash
                                    == block.header().previous_block_hash
                            {
                                {
                                    /*
                                    TODO: purge the unneeded of these
                                    self.invalidated_blocks_hashes.clear();
                                    self.txs_awaiting_created_block.clear();
                                    self.txs_awaiting_receipts.clear();
                                    self.votes_for_view_change.clear();
                                     */

                                    let block = block.commit();
                                    let block_hash = block.hash();

                                    if let Err(error) = wsv_guard.apply(block.clone()) {
                                        panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                    }

                                    for event in Vec::<Event>::from(&block) {
                                        trace!(?event);
                                        drop(sumeragi.events_sender.send(event));
                                    }

                                    state_machine_guard.latest_block_height = block.header().height;
                                    state_machine_guard.latest_block_hash = block.hash();

                                    let previous_role = state_machine_guard
                                        .current_topology
                                        .role(&sumeragi.peer_id);
                                    state_machine_guard.current_topology.apply_block(block_hash);
                                    info!(
                                        prev_peer_role = ?previous_role,
                                        new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                        new_block_height = %state_machine_guard.latest_block_height,
                                        %block_hash,
                                        "Committing block"
                                    );
                                    sumeragi.kura.store_block_blocking(block);
                                    SumeragiWithFault::<F>::update_network_topology(
                                        &mut state_machine_guard.current_topology,
                                        &wsv_guard,
                                    );
                                    has_sent_transactions = false;
                                    voting_block_option = None;
                                    println!("Leader has committed the block.");
                                }
                            }
                        }
                        _ => println!("Leader not handling message, {:?}", msg),
                    }
                } else {
                    should_sleep = true;
                }

                if voting_block_option.is_none() {
                    let transactions = sumeragi.queue.get_transactions_for_block(&wsv_guard);
                    if transactions.len() == 0 {
                        continue;
                    }
                    println!(
                        "I, {}, have transactions to make a block with.",
                        sumeragi.peer_id.public_key
                    );
                    // TODO: This should properly process triggers
                    let event_recommendations = Vec::new();

                    let block = PendingBlock::new(transactions, event_recommendations).chain(
                        state_machine_guard.latest_block_height,
                        state_machine_guard.latest_block_hash,
                        ViewChangeProofs::empty(), // self.view_change_proofs().clone(),
                        Vec::new(),                //self.invalidated_blocks_hashes.clone(),
                    );
                    {
                        let block = block.validate(&sumeragi.transaction_validator, &wsv_guard);

                        for event in Vec::<Event>::from(&block) {
                            trace!(?event);
                            drop(sumeragi.events_sender.send(event));
                        }
                        let signed_block = block
                            .sign(sumeragi.key_pair.clone())
                            .expect("Sign genesis block.");

                        if !state_machine_guard.current_topology.is_consensus_required() {
                            /*
                            TODO: purge the unneeded of these
                            self.invalidated_blocks_hashes.clear();
                            self.txs_awaiting_created_block.clear();
                            self.txs_awaiting_receipts.clear();
                            self.votes_for_view_change.clear();
                             */

                            sumeragi.broadcast_msg(
                                BlockCommitted::from(signed_block.clone()),
                                &state_machine_guard.current_topology,
                            );

                            let block = signed_block.commit();
                            let block_hash = block.hash();

                            if let Err(error) = wsv_guard.apply(block.clone()) {
                                panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                            }

                            for event in Vec::<Event>::from(&block) {
                                trace!(?event);
                                drop(sumeragi.events_sender.send(event));
                            }

                            state_machine_guard.latest_block_height = block.header().height;
                            state_machine_guard.latest_block_hash = block.hash();

                            let previous_role =
                                state_machine_guard.current_topology.role(&sumeragi.peer_id);
                            state_machine_guard.current_topology.apply_block(block_hash);
                            info!(
                                prev_peer_role = ?previous_role,
                                new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                new_block_height = %state_machine_guard.latest_block_height,
                                %block_hash,
                                "Committing block"
                            );
                            sumeragi.kura.store_block_blocking(block);
                            SumeragiWithFault::<F>::update_network_topology(
                                &mut state_machine_guard.current_topology,
                                &wsv_guard,
                            );
                            has_sent_transactions = false;
                            voting_block_option = None;
                            continue;
                        }

                        let voting_block = VotingBlock::new(signed_block.clone());
                        let voting_block_hash = voting_block.block.hash();

                        voting_block_option = Some(voting_block);
                        sumeragi.broadcast_msg(
                            BlockCreated::from(signed_block.clone()),
                            &state_machine_guard.current_topology,
                        );

                        {
                            // view change proof
                            let proof = view_change::Proof::commit_timeout(
                                voting_block_hash,
                                state_machine_guard
                                    .current_topology
                                    .view_change_proofs()
                                    .latest_hash(),
                                *state_machine_guard.current_topology.at_block(),
                                sumeragi.key_pair.clone(),
                            )
                            .expect("Failed to sign CommitTimeout");
                            // TODO: Commit timeout causes viewchange
                        }
                        println!(
                            "I, {}, the leader, have created a block.",
                            sumeragi.peer_id.public_key
                        );
                    }
                }

                continue;
            }
            if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ValidatingPeer
            {
                if maybe_incoming_message.is_some() {
                    let incoming_message = maybe_incoming_message.take().unwrap();

                    println!(
                        "I, {}, a validating peer, have recieved a message.",
                        sumeragi.peer_id.public_key
                    );

                    match incoming_message {
                        Message::BlockCreated(block_created) => {
                            let block = block_created.block;

                            if voting_block_option.is_some() {
                                eprintln!("Already have block, ignoring.");
                                continue;
                            }

                            for event in Vec::<Event>::from(&block) {
                                trace!(?event);
                                drop(sumeragi.events_sender.send(event));
                            }
                            state_machine_guard.current_topology = sumeragi.update_view_changes(
                                block.header().view_change_proofs.clone(),
                                state_machine_guard.current_topology.clone(),
                                &state_machine_guard.latest_block_hash,
                            );

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
                                eprintln!("Rejecting Block as it is not signed by leader.");
                                continue;
                            }
                            let network_topology = &state_machine_guard.current_topology;

                            // sumeragi.txs_awaiting_created_block.clear(); TODO: Figure out what this is for
                            if let Err(e) = block.validation_check(
                                &mut wsv_guard,
                                &state_machine_guard.latest_block_hash,
                                &state_machine_guard
                                    .current_topology
                                    .view_change_proofs()
                                    .latest_hash(),
                                state_machine_guard.latest_block_height,
                                &sumeragi.transaction_limits,
                            ) {
                                warn!(%e);
                                println!("Block validation failed, {:?}", e);
                            } else {
                                let block_clone = block.clone();
                                let key_pair_clone = sumeragi.key_pair.clone();
                                let transaction_validator = sumeragi.transaction_validator.clone();
                                let signed_block = block_clone
                                    .revalidate(&transaction_validator, &wsv_guard)
                                    .sign(key_pair_clone)
                                    .expect("maybe we should handle this error");
                                {
                                    let post = iroha_p2p::Post {
                                        data: NetworkMessage::SumeragiMessage(Box::new(
                                            VersionedMessage::from(Message::BlockSigned(
                                                signed_block.into(),
                                            )),
                                        )),
                                        peer: network_topology.proxy_tail().clone(),
                                    };
                                    sumeragi.broker.issue_send_sync(&post);
                                }
                                info!(
                                    peer_role = ?network_topology.role(&sumeragi.peer_id),
                                    block_hash = %block.hash(),
                                    "Signed block candidate",
                                );
                                println!("Signed block and sent to proxy tail.");
                            }
                            //TODO: send to set b so they can observe

                            let voting_block = VotingBlock::new(block.clone());
                            let voting_block_hash = voting_block.block.hash();
                            voting_block_option = Some(voting_block);

                            // TODO: Do commit countdown.
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
                                .filter_signatures_by_roles(
                                    &[Role::ProxyTail],
                                    &verified_signatures,
                                );
                            if valid_signatures.len() >= network_topology.min_votes_for_commit()
                                && proxy_tail_signatures.len() == 1
                                && state_machine_guard.latest_block_hash
                                    == block.header().previous_block_hash
                            {
                                {
                                    /*
                                    TODO: purge the unneeded of these
                                    self.invalidated_blocks_hashes.clear();
                                    self.txs_awaiting_created_block.clear();
                                    self.txs_awaiting_receipts.clear();
                                    self.votes_for_view_change.clear();
                                     */

                                    let block = block.commit();
                                    let block_hash = block.hash();

                                    if let Err(error) = wsv_guard.apply(block.clone()) {
                                        panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                                    }

                                    for event in Vec::<Event>::from(&block) {
                                        trace!(?event);
                                        drop(sumeragi.events_sender.send(event));
                                    }

                                    state_machine_guard.latest_block_height = block.header().height;
                                    state_machine_guard.latest_block_hash = block.hash();

                                    let previous_role = state_machine_guard
                                        .current_topology
                                        .role(&sumeragi.peer_id);
                                    state_machine_guard.current_topology.apply_block(block_hash);
                                    info!(
                                        prev_peer_role = ?previous_role,
                                        new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                        new_block_height = %state_machine_guard.latest_block_height,
                                        %block_hash,
                                        "Committing block"
                                    );
                                    sumeragi.kura.store_block_blocking(block);
                                    SumeragiWithFault::<F>::update_network_topology(
                                        &mut state_machine_guard.current_topology,
                                        &wsv_guard,
                                    );
                                    has_sent_transactions = false;
                                    voting_block_option = None;
                                    println!("ValidatingPeer has committed the block.");
                                }
                            }
                        }
                        _ => {
                            println!("Not handling message {:?}", incoming_message);
                        }
                    }
                } else {
                    // if there is no message sleep
                    should_sleep = true;
                }
                continue;
            }
            if state_machine_guard.current_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
                if maybe_incoming_message.is_some() {
                    let incoming_message = maybe_incoming_message.take().unwrap();

                    println!(
                        "I, {}, the proxy tail, have recieved a message.",
                        sumeragi.peer_id.public_key
                    );

                    match incoming_message {
                        Message::BlockCreated(block_created) => {
                            let block = block_created.block;

                            if voting_block_option.is_some() {
                                eprintln!("Already have block, ignoring.");
                                continue;
                            }

                            for event in Vec::<Event>::from(&block) {
                                trace!(?event);
                                drop(sumeragi.events_sender.send(event));
                            }
                            state_machine_guard.current_topology = sumeragi.update_view_changes(
                                block.header().view_change_proofs.clone(),
                                state_machine_guard.current_topology.clone(),
                                &state_machine_guard.latest_block_hash,
                            );

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
                            let network_topology = &state_machine_guard.current_topology;

                            let valid_signatures = network_topology.filter_signatures_by_roles(
                                &[Role::ValidatingPeer, Role::Leader],
                                block.verified_signatures(),
                            );

                            for sig in &valid_signatures {
                                block_signature_acc.push((block.hash(), sig.clone()));
                            }
                            // sumeragi.txs_awaiting_created_block.clear(); TODO: Figure out what this is for

                            let voting_block = VotingBlock::new(block.clone());
                            let voting_block_hash = voting_block.block.hash();
                            voting_block_option = Some(voting_block);

                            // TODO: Do commit countdown.
                        }
                        Message::BlockSigned(block_signed) => {
                            println!("block signed message");
                            let block = block_signed.block;
                            let block_hash = block.hash();

                            if voting_block_option.is_some()
                                && block_hash != voting_block_option.as_ref().unwrap().block.hash()
                            {
                                println!("block signed is not relevant block");
                                continue;
                            }

                            // I don't think we update the topology here. That ship has sailed.

                            let network_topology = &state_machine_guard.current_topology;

                            let valid_signatures = network_topology.filter_signatures_by_roles(
                                &[Role::ValidatingPeer, Role::Leader],
                                block.verified_signatures(),
                            );

                            for sig in &valid_signatures {
                                block_signature_acc.push((block_hash, sig.clone()));
                            }
                        }
                        _ => {
                            println!("Not handling message {:?}", incoming_message);
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
                        println!("Block passes!");
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

                        sumeragi.broadcast_msg_to(
                            BlockCommitted::from(block.clone()),
                            state_machine_guard
                                .current_topology
                                .validating_peers()
                                .iter()
                                .chain([state_machine_guard.current_topology.leader()])
                                .chain(state_machine_guard.current_topology.peers_set_b()),
                        );
                        {
                            /*
                            TODO: purge the unneeded of these
                            self.invalidated_blocks_hashes.clear();
                            self.txs_awaiting_created_block.clear();
                            self.txs_awaiting_receipts.clear();
                            self.votes_for_view_change.clear();
                             */

                            let block = block.commit();
                            let block_hash = block.hash();

                            if let Err(error) = wsv_guard.apply(block.clone()) {
                                panic!("Failed to apply block on WSV. This is absolutely not acceptable.");
                            }

                            for event in Vec::<Event>::from(&block) {
                                trace!(?event);
                                drop(sumeragi.events_sender.send(event));
                            }

                            state_machine_guard.latest_block_height = block.header().height;
                            state_machine_guard.latest_block_hash = block.hash();

                            let previous_role =
                                state_machine_guard.current_topology.role(&sumeragi.peer_id);
                            state_machine_guard.current_topology.apply_block(block_hash);
                            info!(
                                prev_peer_role = ?previous_role,
                                new_peer_role = ?state_machine_guard.current_topology.role(&sumeragi.peer_id),
                                new_block_height = %state_machine_guard.latest_block_height,
                                %block_hash,
                                "Committing block"
                            );
                            sumeragi.kura.store_block_blocking(block);
                            SumeragiWithFault::<F>::update_network_topology(
                                &mut state_machine_guard.current_topology,
                                &wsv_guard,
                            );
                            has_sent_transactions = false;
                            voting_block_option = None;
                            block_signature_acc.clear();
                        }
                    }
                }

                continue;
            }
        }
    }
}

impl<F: FaultInjection> Debug for SumeragiWithFault<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            // .field("network_topology", &self.topology) TODO FIX
            .field("peer_id", &self.peer_id)
            //.field("voting_block", &self.voting_block)
            .finish()
    }
}
