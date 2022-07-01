//! Fault injection for tests. Almost all structs from this module
//! should be reserved for testing, and only [`NoFault`], should be
//! used in code.

use iroha_config::sumeragi::Configuration;
use iroha_primitives::must_use::MustUse;

use iroha_config::sumeragi::Configuration as SumeragiConfiguration;
use super::*;
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
pub struct SumeragiWithFault<F>
where
    F: FaultInjection,
{
    pub(crate) key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The current topology of the peer to peer network.
    pub topology: Topology,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    pub(crate) voting_block: Option<VotingBlock>,
    /// This field is used to count votes when the peer is a proxy tail role.
    pub(crate) votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    pub(crate) events_sender: EventsSender,
    pub(crate) wsv: std::sync::Mutex<WorldStateView>,

    /// This field is used to count votes for a view change.
    pub(crate) votes_for_view_change: HashMap<HashOf<Proof>, Proof>,

    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    /// And time at which this transaction was sent to the leader by this peer.
    pub(crate) txs_awaiting_receipts: HashMap<HashOf<VersionedTransaction>, Instant>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in `CreatedBlock`.
    pub(crate) txs_awaiting_created_block: HashSet<HashOf<VersionedTransaction>>,

    pub(crate) commit_time: Duration,
    pub(crate) tx_receipt_time: Duration,
    pub(crate) block_time: Duration,
    pub(crate) block_height: u64,
    /// Hashes of invalidated blocks
    pub invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    pub(crate) transaction_limits: TransactionLimits,
    pub(crate) transaction_validator: TransactionValidator,
    pub(crate) telemetry_started: bool,
    /// Genesis network
    pub genesis_network: Option<GenesisNetwork>,
    /// Broker
    pub broker: Broker,
    /// Kura instance used for IO
    pub kura: Arc<Kura>,
    /// [`iroha_p2p::Network`] actor address
    // pub network: Addr<IrohaNetwork>,
    /// Buffer capacity of actor's MPSC channel
    pub actor_channel_capacity: u32,
    pub(crate) fault_injection: PhantomData<F>,
    pub(crate) gossip_batch_size: u32,
    pub(crate) gossip_period: Duration,
}

impl<F: FaultInjection> SumeragiWithFault<F> {
    fn from_configuration(
        configuration: &Configuration,
        events_sender: EventsSender,
        wsv: WorldStateView,
        transaction_validator: TransactionValidator,
        telemetry_started: bool,
        genesis_network: Option<GenesisNetwork>,
        queue: Arc<Queue>,
        broker: Broker,
        kura: Arc<Kura>,
        // network: Addr<IrohaNetwork>,
    ) -> Result<Self> {
        let network_topology = Topology::builder()
            .at_block(EmptyChainHash::default().into())
            .with_peers(configuration.trusted_peers.peers.clone())
            .build()?;

        Ok(Self {
            key_pair: configuration.key_pair.clone(),
            topology: network_topology,
            peer_id: configuration.peer_id.clone(),
            voting_block: None,
            votes_for_blocks: BTreeMap::new(),
            events_sender,
            wsv: std::sync::Mutex::new(wsv),
            txs_awaiting_receipts: HashMap::new(),
            txs_awaiting_created_block: HashSet::new(),
            votes_for_view_change: HashMap::new(),
            commit_time: Duration::from_millis(configuration.commit_time_limit_ms),
            tx_receipt_time: Duration::from_millis(configuration.tx_receipt_time_limit_ms),
            block_time: Duration::from_millis(configuration.block_time_ms),
            block_height: 0,
            invalidated_blocks_hashes: Vec::new(),
            telemetry_started,
            transaction_limits: configuration.transaction_limits,
            transaction_validator,
            genesis_network,
            queue,
            broker,
            kura,
            // network,
            actor_channel_capacity: configuration.actor_channel_capacity,
            fault_injection: PhantomData,
            gossip_batch_size: configuration.gossip_batch_size,
            gossip_period: Duration::from_millis(configuration.gossip_period_ms),
        })
    }

    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block: HashOf<VersionedCommittedBlock>, block_height: u64) {
        self.block_height = block_height;
        self.topology.apply_block(latest_block);
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if there is a change in WSV peers, otherwise leaves the order unchanged.
    #[allow(clippy::expect_used)]
    pub fn update_network_topology(&mut self) {
        let wsv_peers: HashSet<_> = self
            .wsv
            .lock()
            .unwrap()
            .trusted_peers_ids()
            .clone()
            .into_iter()
            .collect();
        let topology_peers: HashSet<_> = self.topology.sorted_peers().iter().cloned().collect();
        if topology_peers != wsv_peers {
            self.topology = self.topology
                .clone()
                .into_builder()
                .with_peers(wsv_peers)
                .build()
                // TODO: Check it during instruction execution.
                .expect("The safety of changing the number of peers should have been checked at Instruction execution stage.");
        }
    }

    /// Returns `true` if some block is in discussion, `false` otherwise.
    pub fn voting_in_progress(&self) -> bool {
        self.voting_block.is_some()
    }

    /// Latest block hash as seen by sumeragi.
    pub fn latest_block_hash(&self) -> &HashOf<VersionedCommittedBlock> {
        self.topology.at_block()
    }

    /// Number of view changes.
    /// Where a view change is a change in topology made if there was some consensus misfunction during round (faulty peers).
    pub fn number_of_view_changes(&self) -> u64 {
        self.topology.view_change_proofs().len() as u64
    }

    /// The proofs of view changes that happened after the last block was committed.
    pub fn view_change_proofs(&self) -> &ViewChangeProofs {
        self.topology.view_change_proofs()
    }

    /// The hash of the latest view change.
    pub fn latest_view_change_hash(&self) -> HashOf<Proof> {
        self.view_change_proofs().latest_hash()
    }

    /// Get peers as a hash set of their ids.
    pub fn peers(&self) -> HashSet<PeerId> {
        self.topology.sorted_peers().iter().cloned().collect()
    }

    /// Assumes this peer is a leader and starts the round with the given `genesis_topology`.
    ///
    /// # Errors
    /// Can fail if:
    /// * transactions are empty
    /// * peer is not leader
    /// * there are already some blocks in blockchain

    #[log(skip(self, transactions, genesis_topology))]
    pub fn start_genesis_round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        genesis_topology: Topology,
    ) -> Result<()> {
        if transactions.is_empty() {
            Err(eyre!(
                "Genesis transactions set contains no valid transactions"
            ))
        } else if genesis_topology.leader() != &self.peer_id {
            Err(eyre!(
                "Incorrect network topology this peer should be {:?} but is {:?}",
                Role::Leader,
                genesis_topology.role(&self.peer_id)
            ))
        } else if self.block_height > 0 {
            Err(eyre!(
                "Block height should be 0 for genesis round. But it is: {}",
                self.block_height
            ))
        } else {
            self.validate_and_publish_created_block(
                PendingBlock::new(transactions, Vec::new())
                    .chain_first_with_genesis_topology(genesis_topology),
            )
        }
    }

    /// The leader of each round just uses the transactions they have at hand to create a block.
    ///
    /// # Errors
    /// Can fail during signing of block

    pub fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        event_recommendations: Vec<Event>,
    ) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        if Role::Leader == self.topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions, event_recommendations).chain(
                self.block_height,
                *self.latest_block_hash(),
                self.view_change_proofs().clone(),
                self.invalidated_blocks_hashes.clone(),
            );
            self.validate_and_publish_created_block(block)?;
        } else {
            self.forward_txs_to_leader(&transactions);
        }
        Ok(())
    }

    pub(crate) fn broadcast_msg_to<'a>(
        &self,
        msg: impl Into<Message> + Send,
        ids: impl Iterator<Item = &'a PeerId> + Send,
    ) {
        VersionedMessage::from(msg.into()).send_to_multiple(&self.broker, ids);
    }

    /// Forwards transactions to the leader and waits for receipts.
    /// In consensus it is used to check the liveness of a leader.

    #[allow(clippy::expect_used)]
    pub fn forward_txs_to_leader(&mut self, txs: &[VersionedAcceptedTransaction]) {
        // If already sent tx and awaiting receipt or created block, then quit.
        if !self.txs_awaiting_receipts.is_empty() || !self.txs_awaiting_created_block.is_empty() {
            return;
        }

        // It is assumed that we only need to send 1 tx to check liveness.
        let tx = txs
            .choose(&mut rand::thread_rng())
            .expect("It was checked earlier that transactions are not empty.")
            .clone();
        let tx_hash = tx.hash();
        info!(
            peer_addr = %self.peer_id.address,
            peer_role = ?self.topology.role(&self.peer_id),
            leader_addr = %self.topology.leader().address,
            %tx_hash,
            "Forwarding tx to leader"
        );
        // Don't require leader to submit receipts and therefore create blocks if the tx is still waiting for more signatures.
        if let Ok(MustUse(true)) = tx.check_signature_condition(&self.wsv.lock().unwrap()) {
            self.txs_awaiting_receipts.insert(tx.hash(), Instant::now());
        }
        let no_tx_receipt = view_change::Proof::no_transaction_receipt_received(
            self.latest_view_change_hash(),
            *self.latest_block_hash(),
            self.key_pair.clone(),
        )
        .expect("Failed to put first signature.");

        /*
            TODO: REPLACE
            ctx.notify(
                CheckReceiptTimeout {
                    tx_hash,
                    proof: no_tx_receipt,
                },
                self.tx_receipt_time,
        );
            */

        VersionedMessage::from(Message::from(TransactionForwarded::new(
            tx,
            self.peer_id.clone(),
        )))
        .send_to(&self.broker, self.topology.leader());
    }

    /// Returns:
    /// `true` - if new votes were added
    /// `false` - otherwise
    ///
    /// And the actual Proof as it is contained in `votes_for_view_change` with merged votes.
    pub(crate) fn merge_view_change_votes(&mut self, proof: Proof) -> (bool, Proof) {
        match self.votes_for_view_change.entry(proof.hash()) {
            Entry::Occupied(mut occupied) => {
                let proof_votes = occupied.get_mut();
                let count = proof_votes.signatures().len();
                proof_votes.merge_signatures(proof.signatures().clone());

                if proof_votes.signatures().len() > count {
                    (true, proof_votes.clone())
                } else {
                    (false, proof_votes.clone())
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(proof.clone());
                (true, proof)
            }
        }
    }

    fn vote_for_view_change(&mut self, proof: Proof) {
        if !proof.has_same_state(self.latest_block_hash(), &self.latest_view_change_hash()) {
            return;
        }
        let (count_increased, merged_proof) = self.merge_view_change_votes(proof.clone());
        if count_increased {
            self.broadcast_msg(ViewChangeSuggested::new(
                proof,
                self.view_change_proofs().clone(),
            ));
            if merged_proof.verify(&self.peers(), self.topology.max_faults()) {
                let invalidated_block_hash = match merged_proof.reason() {
                    view_change::Reason::CommitTimeout(reason) => Some(reason.hash),
                    view_change::Reason::NoTransactionReceiptReceived(_)
                    | view_change::Reason::BlockCreationTimeout(_) => None,
                };
                self.change_view(merged_proof.clone(), invalidated_block_hash);
            }
        }
    }

    fn broadcast_msg(&self, msg: impl Into<Message> + Send) {
        let msg = VersionedMessage::from(msg.into());
        msg.send_to_multiple(&self.broker, self.topology.sorted_peers());
    }

    /// Gossip transactions to other peers.

    pub fn gossip_transactions(&mut self, txs: Vec<VersionedAcceptedTransaction>) {
        if txs.is_empty() {
            return;
        }

        debug!(
            peer_role = ?self.topology.role(&self.peer_id),
            tx_count = txs.len(),
            "Gossiping transactions"
        );

        self.broadcast_msg(TransactionGossip::new(txs));
    }

    /// Should be called by a leader to start the consensus round with `BlockCreated` message.
    ///
    /// # Errors
    /// Can fail signing block

    pub fn validate_and_publish_created_block(&mut self, block: ChainedBlock) -> Result<()> {
        info!(block_hash = %block.hash(), "Validating block");

        let block = block.validate(&self.transaction_validator, &self.wsv.lock().unwrap());
        let network_topology = self.network_topology_current_or_genesis(block.header());

        info!(
            peer_role = ?network_topology.role(&self.peer_id),
            block_hash = %block.hash(),
            "Created a block",
        );
        for event in Vec::<Event>::from(&block) {
            trace!(?event);
            send_event(&self.events_sender, event);
        }
        let signed_block = block.sign(self.key_pair.clone())?;
        if !network_topology.is_consensus_required() {
            self.broadcast_msg_to(
                BlockCommitted::from(signed_block.clone()),
                network_topology
                    .validating_peers()
                    .iter()
                    .chain([network_topology.leader()])
                    .chain(network_topology.peers_set_b()),
            );
            self.commit_block(signed_block);
            return Ok(());
        }

        let voting_block = VotingBlock::new(signed_block.clone());
        let voting_block_hash = voting_block.block.hash();

        self.voting_block = Some(voting_block);
        self.broadcast_msg(BlockCreated::from(signed_block.clone()));
        self.start_commit_countdown(
            voting_block_hash,
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
        );
        Ok(())
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.

    #[log(skip(self, voting_block_hash))]
    #[allow(clippy::expect_used)]
    pub fn start_commit_countdown(
        &self,
        voting_block_hash: HashOf<VersionedValidBlock>,
        latest_block: HashOf<VersionedCommittedBlock>,
        latest_view_change: HashOf<Proof>,
    ) {
        let proof = view_change::Proof::commit_timeout(
            voting_block_hash,
            latest_view_change,
            latest_block,
            self.key_pair.clone(),
        )
        .expect("Failed to sign CommitTimeout");
        /*
            TODO: REPLACE
            ctx.notify(
                CheckCommitTimeout {
                    block_hash: voting_block_hash,
                    proof,
                },
                self.commit_time,
        )
            */
    }

    /// Commits `ValidBlock` and changes the state of the `Sumeragi` and its `NetworkTopology`.
    #[log(skip(self, block))]

    pub fn commit_block(&mut self, block: VersionedValidBlock) {
        self.invalidated_blocks_hashes.clear();
        self.txs_awaiting_created_block.clear();
        self.txs_awaiting_receipts.clear();
        self.votes_for_view_change.clear();
        self.block_height = block.header().height;

        let block = block.commit();
        let block_hash = block.hash();

        if let Err(error) = self.wsv.lock().unwrap().apply(block.clone()) {
            warn!(?error, %block_hash, "Failed to apply block on WSV");
        }

        for event in Vec::<Event>::from(&block) {
            trace!(?event);
            send_event(&self.events_sender, event);
        }

        let previous_role = self.topology.role(&self.peer_id);
        self.topology.apply_block(block_hash);
        info!(
            prev_peer_role = ?previous_role,
            new_peer_role = ?self.topology.role(&self.peer_id),
            new_block_height = %self.block_height,
            %block_hash,
            "Committing block"
        );
        self.voting_block = None;
        self.votes_for_blocks.clear();
        self.kura.store_block_async(block);
        self.update_network_topology();
    }

    pub(crate) fn change_view(
        &mut self,
        proof: view_change::Proof,
        invalidated_block_hash: Option<HashOf<VersionedValidBlock>>,
    ) {
        self.txs_awaiting_created_block.clear();
        self.txs_awaiting_receipts.clear();
        self.votes_for_view_change.clear();
        let previous_role = self.topology.role(&self.peer_id);
        if let Some(hash) = invalidated_block_hash {
            self.invalidated_blocks_hashes.push(hash)
        }
        self.topology.apply_view_change(proof.clone());
        self.wsv
            .lock()
            .unwrap()
            .metrics
            .view_changes
            .set(self.number_of_view_changes());
        self.voting_block = None;
        error!(
            peer_addr = %self.peer_id.address,
            prev_peer_role = ?previous_role,
            new_peer_role = ?self.topology.role(&self.peer_id),
            block_hash = %self.latest_block_hash(),
            view_changes_count = %self.number_of_view_changes(),
            view_change_hash = %proof.hash(),
            reason = %proof.reason(),
            "Changing view at block",
        );
    }

    /// If this peer is a leader in this round.
    pub fn is_leader(&self) -> bool {
        self.topology.role(&self.peer_id) == Role::Leader
    }

    /// Role
    pub fn role(&self) -> Role {
        self.topology.role(&self.peer_id)
    }

    /// Returns current network topology or genesis specific one, if the `block` is a genesis block.
    pub fn network_topology_current_or_genesis(&self, header: &BlockHeader) -> Topology {
        if header.is_genesis() && self.block_height == 0 {
            if let Some(genesis_topology) = &header.genesis_topology {
                info!("Using network topology from genesis block");
                return genesis_topology.clone();
            }
        }

        self.topology.clone()
    }

    /// Connects or disconnects peers according to the current network topology.
    pub fn connect_peers(&self) {
        trace!("Connecting peers...");
        let peers_expected = {
            let mut res = self.topology.sorted_peers().to_owned();
            res.retain(|id| id.address != self.peer_id.address);
            res.shuffle(&mut rand::thread_rng());
            res
        };

        /*
        TODO: REPLACE
        #[allow(clippy::expect_used)]
        let peers_online = self
            .network
            .send(iroha_p2p::network::GetConnectedPeers)

            .expect("Failed to get connected peers from the network")
        .peers;
         */
        let peers_online = HashSet::new();

        for peer_to_be_connected in peers_expected
            .iter()
            .filter(|id| !peers_online.contains(&id.public_key))
        {
            info!(%peer_to_be_connected.address, "Connecting peer");
            self.broker.issue_send_sync(&ConnectPeer {
                address: peer_to_be_connected.address.clone(),
            })
        }
        for peer_to_be_disconnected in
            peers_online.difference(&peers_expected.into_iter().map(|id| id.public_key).collect())
        {
            info!(%peer_to_be_disconnected, "Disconnecting peer");
            self.broker
                .issue_send_sync(&DisconnectPeer(peer_to_be_disconnected.clone()))
        }
    }

    /// If `suggested_chain` of view change proofs is bigger than the the current one - replace the current one.
    pub fn update_view_changes(&mut self, suggested_chain: view_change::ProofChain) {
        #[allow(clippy::expect_used)]
        if suggested_chain.len() > self.topology.view_change_proofs().len()
            && suggested_chain.verify_with_state(
                &self.peers(),
                self.topology.max_faults(),
                self.latest_block_hash(),
            )
        {
            info!(
                prev_view_changes_count = self.topology.view_change_proofs().len(),
                new_view_changes_count = suggested_chain.len(),
                latest_block = ?self.latest_block_hash(),
                "Swapping view change proof chain."
            );
            self.topology = self
                .topology
                .clone()
                .into_builder()
                .with_view_changes(suggested_chain)
                .build()
                .expect("When only changing view changes it should not fail.")
        }
    }

    pub fn get_network_topology(&self, header: &BlockHeader) -> Topology {
        self.network_topology_current_or_genesis(&header)
    }
}

pub fn run_sumeragi_main_loop<F>(
    sumeragi: &SumeragiWithFault<F>,
    initial_latest_block: HashOf<VersionedCommittedBlock>,
    initial_block_height: u64,
) where
    F: FaultInjection,
{
    // TODO INIT

    loop {
        println!("Sumeragi is running");
        std::thread::sleep(Duration::from_secs(1));
    }
}

impl<F: FaultInjection> Debug for SumeragiWithFault<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            .field("network_topology", &self.topology)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}
