//! Fault injection for tests. Almost all structs from this module
//! should be reserved for testing, and only [`NoFault`], should be
//! used in code.

use super::{config::SumeragiConfiguration, *};

/// Fault injection for consensus tests
pub trait FaultInjection: Send + Sync + Sized + 'static {
    /// A function to skip or modify a message.
    fn faulty_message<G, K, W>(
        sumeragi: &SumeragiWithFault<G, K, W, Self>,
        msg: Message,
    ) -> Option<Message>
    where
        G: GenesisNetworkTrait,
        K: KuraTrait,
        W: WorldTrait;

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
    fn faulty_message<G, K, W>(
        _: &SumeragiWithFault<G, K, W, Self>,
        msg: Message,
    ) -> Option<Message>
    where
        G: GenesisNetworkTrait,
        K: KuraTrait,
        W: WorldTrait,
    {
        Some(msg)
    }

    fn manual_rounds() -> bool {
        false
    }
}

/// `Sumeragi` is the implementation of the consensus. This struct allows also to add fault injection for tests.
pub struct SumeragiWithFault<G, K, W, F>
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    W: WorldTrait,
    F: FaultInjection,
{
    pub(crate) key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue<W>>,
    /// The current topology of the peer to peer network.
    pub topology: Topology,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    pub(crate) voting_block: Option<VotingBlock>,
    /// This field is used to count votes when the peer is a proxy tail role.
    pub(crate) votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    pub(crate) events_sender: EventsSender,
    pub(crate) wsv: Arc<WorldStateView<W>>,

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
    pub(crate) transaction_validator: TransactionValidator<W>,
    pub(crate) telemetry_started: bool,
    /// Genesis network
    pub genesis_network: Option<G>,
    /// Broker
    pub broker: Broker,
    /// [`Kura`](crate::kura) actor address
    pub kura: AlwaysAddr<K>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,
    /// Mailbox size
    pub mailbox: u32,
    pub(crate) fault_injection: PhantomData<F>,
    pub(crate) gossip_batch_size: u32,
    pub(crate) gossip_period: Duration,
}

impl<G: GenesisNetworkTrait, K: KuraTrait<World = W>, W: WorldTrait, F: FaultInjection>
    SumeragiTrait for SumeragiWithFault<G, K, W, F>
{
    type GenesisNetwork = G;
    type Kura = K;
    type World = W;

    fn from_configuration(
        configuration: &SumeragiConfiguration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<W>>,
        transaction_validator: TransactionValidator<W>,
        telemetry_started: bool,
        genesis_network: Option<G>,
        queue: Arc<Queue<W>>,
        broker: Broker,
        kura: AlwaysAddr<K>,
        network: Addr<IrohaNetwork>,
    ) -> Result<Self> {
        let network_topology = Topology::builder()
            .at_block(EmptyChainHash::default().into())
            .reshuffle_after(configuration.n_topology_shifts_before_reshuffle)
            .with_peers(configuration.trusted_peers.peers.clone())
            .build()?;

        Ok(Self {
            key_pair: configuration.key_pair.clone(),
            topology: network_topology,
            peer_id: configuration.peer_id.clone(),
            voting_block: None,
            votes_for_blocks: BTreeMap::new(),
            events_sender,
            wsv,
            txs_awaiting_receipts: HashMap::new(),
            txs_awaiting_created_block: HashSet::new(),
            votes_for_view_change: HashMap::new(),
            commit_time: Duration::from_millis(configuration.commit_time_ms),
            tx_receipt_time: Duration::from_millis(configuration.tx_receipt_time_ms),
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
            network,
            mailbox: configuration.mailbox,
            fault_injection: PhantomData,
            gossip_batch_size: configuration.gossip_batch_size,
            gossip_period: Duration::from_millis(configuration.gossip_period_ms),
        })
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Actor
    for SumeragiWithFault<G, K, W, F>
{
    fn mailbox_capacity(&self) -> u32 {
        self.mailbox
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<Init, _>(ctx);
        self.broker.subscribe::<Message, _>(ctx);
        self.broker.subscribe::<CommitBlock, _>(ctx);
        self.broker.subscribe::<NetworkMessage, _>(ctx);
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<InvalidatedBlockHashes> for SumeragiWithFault<G, K, W, F>
{
    type Result = Vec<HashOf<VersionedValidBlock>>;

    async fn handle(&mut self, InvalidatedBlockHashes: InvalidatedBlockHashes) -> Self::Result {
        self.invalidated_blocks_hashes.clone()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> ContextHandler<Message>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, msg: Message) {
        trace!(peer_role=?self.topology.role(&self.peer_id), ?msg);
        if let Err(error) = msg.handle(self, ctx).await {
            error!(%error, "Failed to handle message");
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    ContextHandler<RetrieveTransactions> for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(
        &mut self,
        ctx: &mut Context<Self>,
        RetrieveTransactions: RetrieveTransactions,
    ) {
        if self.voting_in_progress().await {
            return;
        }
        let txs = self.queue.get_transactions_for_block();
        // TODO: This should properly process triggers
        let event_recommendations = Vec::new();
        if let Err(error) = self.round(txs, event_recommendations, ctx).await {
            error!(%error, "Round failed");
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<Gossip>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, Gossip: Gossip) {
        // Select N random transactions and gossip them.
        // This is done for peer not to DOS themselves under high tx load.
        let txs = self.queue.n_random_transactions(self.gossip_batch_size);
        self.gossip_transactions(txs).await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<ConnectPeers>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, ConnectPeers: ConnectPeers) {
        self.connect_peers().await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<UpdateTelemetry> for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, UpdateTelemetry: UpdateTelemetry) {
        let block_hash = self.topology.at_block();
        let finalized_height = self.block_height.saturating_sub(1);
        #[allow(clippy::cast_possible_truncation)]
        let finalized_hash = self
            .kura
            .send(GetBlockHash {
                height: finalized_height as usize,
            })
            .await;
        let finalized_hash = finalized_hash.as_ref().unwrap_or(block_hash);
        iroha_logger::telemetry!(
            msg = "system.interval",
            peers = self.topology.sorted_peers().len().saturating_sub(1),
            txcount = self.queue.tx_len(),
            height = self.block_height,
            best = %block_hash,
            finalized_height = finalized_height,
            finalized_hash = %finalized_hash
        );
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<GetNetworkTopology> for SumeragiWithFault<G, K, W, F>
{
    type Result = Topology;

    async fn handle(&mut self, GetNetworkTopology(header): GetNetworkTopology) -> Self::Result {
        self.network_topology_current_or_genesis(&header)
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<CurrentNetworkTopology> for SumeragiWithFault<G, K, W, F>
{
    type Result = Topology;

    async fn handle(&mut self, CurrentNetworkTopology: CurrentNetworkTopology) -> Self::Result {
        self.topology.clone()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<CommitBlock>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, CommitBlock(block): CommitBlock) {
        self.commit_block(block).await
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<CheckReceiptTimeout> for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, receipt_timeout: CheckReceiptTimeout) {
        if self
            .txs_awaiting_receipts
            .contains_key(&receipt_timeout.tx_hash)
        {
            self.vote_for_view_change(receipt_timeout.proof).await;
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<CheckCreationTimeout> for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, creation_timeout: CheckCreationTimeout) {
        if self
            .txs_awaiting_created_block
            .contains(&creation_timeout.tx_hash)
        {
            self.vote_for_view_change(creation_timeout.proof).await;
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    Handler<CheckCommitTimeout> for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, commit_timeout: CheckCommitTimeout) {
        if Some(commit_timeout.block_hash)
            == self.voting_block.as_ref().map(|block| block.block.hash())
        {
            self.vote_for_view_change(commit_timeout.proof).await;
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<IsLeader>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = bool;

    async fn handle(&mut self, IsLeader: IsLeader) -> Self::Result {
        self.is_leader()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<GetLeader>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = PeerId;

    async fn handle(&mut self, GetLeader: GetLeader) -> Self::Result {
        self.topology.leader().clone()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<NetworkMessage>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, msg: NetworkMessage) -> Self::Result {
        use NetworkMessage::*;

        match msg {
            SumeragiMessage(data) => self.broker.issue_send(data.into_v1()).await,
            BlockSync(data) => self.broker.issue_send(data.into_v1()).await,
            Health => {}
        }
    }
}

impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>
    SumeragiWithFault<G, K, W, F>
{
    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block: HashOf<VersionedCommittedBlock>, block_height: u64) {
        self.block_height = block_height;
        self.topology.apply_block(latest_block);
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if there is a change in WSV peers, otherwise leaves the order unchanged.
    #[allow(clippy::expect_used)]
    pub async fn update_network_topology(&mut self) {
        let wsv_peers: HashSet<_> = self.wsv.trusted_peers_ids().clone().into_iter().collect();
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
    pub async fn voting_in_progress(&self) -> bool {
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
    #[iroha_futures::telemetry_future]
    #[log(skip(self, transactions, genesis_topology, ctx))]
    pub async fn start_genesis_round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        genesis_topology: Topology,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        if transactions.is_empty() {
            Err(eyre!("Genesis transactions set is empty."))
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
                ctx,
            )
            .await
        }
    }

    /// The leader of each round just uses the transactions they have at hand to create a block.
    ///
    /// # Errors
    /// Can fail during signing of block
    #[iroha_futures::telemetry_future]
    pub async fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        event_recommendations: Vec<Event>,
        ctx: &mut Context<Self>,
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
            self.validate_and_publish_created_block(block, ctx).await?;
        } else {
            self.forward_txs_to_leader(&transactions, ctx).await;
        }
        Ok(())
    }

    pub(crate) async fn broadcast_msg_to(
        &self,
        msg: impl Into<Message> + Send,
        ids: impl Iterator<Item = &PeerId> + Send,
    ) {
        VersionedMessage::from(msg.into())
            .send_to_multiple(&self.broker, ids)
            .await;
    }

    /// Forwards transactions to the leader and waits for receipts.
    /// In consensus it is used to check the liveness of a leader.
    #[iroha_futures::telemetry_future]
    #[allow(clippy::expect_used)]
    pub async fn forward_txs_to_leader(
        &mut self,
        txs: &[VersionedAcceptedTransaction],
        ctx: &mut Context<Self>,
    ) {
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
        if let Ok(true) = tx.check_signature_condition(&self.wsv) {
            self.txs_awaiting_receipts.insert(tx.hash(), Instant::now());
        }
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

        VersionedMessage::from(Message::from(TransactionForwarded::new(
            tx,
            self.peer_id.clone(),
        )))
        .send_to(&self.broker, self.topology.leader())
        .await;
    }

    /// Returns:
    /// `true` - if new votes were added
    /// `false` - otherwise
    ///
    /// And the actual Proof as it is contained in `votes_for_view_change` with merged votes.
    pub(crate) async fn merge_view_change_votes(&mut self, proof: Proof) -> (bool, Proof) {
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

    async fn vote_for_view_change(&mut self, proof: Proof) {
        if !proof.has_same_state(self.latest_block_hash(), &self.latest_view_change_hash()) {
            return;
        }
        let (count_increased, merged_proof) = self.merge_view_change_votes(proof.clone()).await;
        if count_increased {
            self.broadcast_msg(ViewChangeSuggested::new(
                proof,
                self.view_change_proofs().clone(),
            ))
            .await;
            if merged_proof.verify(&self.peers(), self.topology.max_faults()) {
                let invalidated_block_hash = match merged_proof.reason() {
                    view_change::Reason::CommitTimeout(reason) => Some(reason.hash),
                    view_change::Reason::NoTransactionReceiptReceived(_)
                    | view_change::Reason::BlockCreationTimeout(_) => None,
                };
                self.change_view(merged_proof.clone(), invalidated_block_hash)
                    .await;
            }
        }
    }

    async fn broadcast_msg(&self, msg: impl Into<Message> + Send) {
        let msg = VersionedMessage::from(msg.into());
        msg.send_to_multiple(&self.broker, self.topology.sorted_peers())
            .await;
    }

    /// Gossip transactions to other peers.
    #[iroha_futures::telemetry_future]
    pub async fn gossip_transactions(&mut self, txs: Vec<VersionedAcceptedTransaction>) {
        if txs.is_empty() {
            return;
        }

        debug!(
            peer_role = ?self.topology.role(&self.peer_id),
            tx_count = txs.len(),
            "Gossiping transactions"
        );

        self.broadcast_msg(TransactionGossip::new(txs)).await;
    }

    /// Should be called by a leader to start the consensus round with `BlockCreated` message.
    ///
    /// # Errors
    /// Can fail signing block
    #[iroha_futures::telemetry_future]
    pub async fn validate_and_publish_created_block(
        &mut self,
        block: ChainedBlock,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        info!(block_hash = %block.hash(), "Validating block");

        let block = block.validate(&self.transaction_validator);
        let network_topology = self.network_topology_current_or_genesis(block.header());

        info!(
            peer_role = ?network_topology.role(&self.peer_id),
            block_hash = %block.hash(),
            "Created a block",
        );
        for event in Vec::<Event>::from(&block) {
            trace!(?event);
            drop(self.events_sender.send(event));
        }
        let signed_block = block.sign(self.key_pair.clone())?;
        if !network_topology.is_consensus_required() {
            self.commit_block(signed_block).await;
            return Ok(());
        }

        let voting_block = VotingBlock::new(signed_block.clone());
        let voting_block_hash = voting_block.block.hash();

        self.voting_block = Some(voting_block);
        self.broadcast_msg(BlockCreated::from(signed_block.clone()))
            .await;
        self.start_commit_countdown(
            voting_block_hash,
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
            ctx,
        )
        .await;
        Ok(())
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.
    #[iroha_futures::telemetry_future]
    #[log(skip(self, voting_block_hash))]
    #[allow(clippy::expect_used)]
    pub async fn start_commit_countdown(
        &self,
        voting_block_hash: HashOf<VersionedValidBlock>,
        latest_block: HashOf<VersionedCommittedBlock>,
        latest_view_change: HashOf<Proof>,
        ctx: &mut Context<Self>,
    ) {
        let proof = view_change::Proof::commit_timeout(
            voting_block_hash,
            latest_view_change,
            latest_block,
            self.key_pair.clone(),
        )
        .expect("Failed to sign CommitTimeout");
        ctx.notify(
            CheckCommitTimeout {
                block_hash: voting_block_hash,
                proof,
            },
            self.commit_time,
        )
    }

    /// Commits `ValidBlock` and changes the state of the `Sumeragi` and its `NetworkTopology`.
    #[log(skip(self, block))]
    #[iroha_futures::telemetry_future]
    pub async fn commit_block(&mut self, block: VersionedValidBlock) {
        self.invalidated_blocks_hashes.clear();
        self.txs_awaiting_created_block.clear();
        self.txs_awaiting_receipts.clear();
        self.votes_for_view_change.clear();
        self.block_height = block.header().height;

        let block = block.commit();
        let block_hash = block.hash();

        for event in Vec::<Event>::from(&block) {
            trace!(?event);
            drop(self.events_sender.send(event));
        }

        if let Err(error) = self.wsv.apply(block.clone()).await {
            warn!(%error, %block_hash, "Failed to apply block on WSV");
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
        self.broker.issue_send(StoreBlock(block)).await;
        self.update_network_topology().await;
    }

    #[iroha_futures::telemetry_future]
    pub(crate) async fn change_view(
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
    pub async fn connect_peers(&self) {
        trace!("Connecting peers...");
        let peers_expected = {
            let mut res = self.topology.sorted_peers().to_owned();
            res.retain(|id| id.address != self.peer_id.address);
            res.shuffle(&mut rand::thread_rng());
            res
        };

        #[allow(clippy::expect_used)]
        let peers_online = self
            .network
            .send(iroha_p2p::network::GetConnectedPeers)
            .await
            .expect("Failed to get connected peers from the network")
            .peers;

        for peer_to_be_connected in peers_expected
            .iter()
            .filter(|id| !peers_online.contains(&id.public_key))
        {
            info!(%peer_to_be_connected.address, "Connecting peer");
            self.broker
                .issue_send(ConnectPeer {
                    address: peer_to_be_connected.address.clone(),
                })
                .await
        }
        for peer_to_be_disconnected in
            peers_online.difference(&peers_expected.into_iter().map(|id| id.public_key).collect())
        {
            info!(%peer_to_be_disconnected, "Disconnecting peer");
            self.broker
                .issue_send(DisconnectPeer(peer_to_be_disconnected.clone()))
                .await
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
}

impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Debug
    for SumeragiWithFault<G, K, W, F>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key())
            .field("network_topology", &self.topology)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> ContextHandler<Init>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, Init { last_block, height }: Init) {
        info!("Starting Sumeragi");
        self.connect_peers().await;

        if height != 0 && last_block != Hash::zeroed().typed() {
            self.init(last_block, height);
        } else if let Some(genesis_network) = self.genesis_network.take() {
            let addr = self.network.clone();
            if let Err(error) = genesis_network.submit_transactions(self, addr, ctx).await {
                error!(%error, "Failed to submit genesis transactions")
            }
        }
        self.update_network_topology().await;
        ctx.notify_every::<ConnectPeers>(PEERS_CONNECT_INTERVAL);
        if !F::manual_rounds() {
            ctx.notify_every::<RetrieveTransactions>(TX_RETRIEVAL_INTERVAL);
        }
        ctx.notify_every::<Gossip>(self.gossip_period);
        if self.telemetry_started {
            ctx.notify_every::<UpdateTelemetry>(TELEMETRY_INTERVAL);
        }
    }
}
