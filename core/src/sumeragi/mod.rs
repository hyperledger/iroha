//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::{eyre, Result};
use iroha_actor::{broker::*, prelude::*, Context};
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_p2p::{ConnectPeer, DisconnectPeer};
use network_topology::{Role, Topology};
use rand::prelude::SliceRandom;

pub mod network_topology;
pub mod view_change;

use self::{
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::{BlockHeader, ChainedBlock, EmptyChainHash, VersionedPendingBlock},
    event::EventsSender,
    genesis::GenesisNetworkTrait,
    kura::{GetBlockHash, KuraTrait, StoreBlock},
    prelude::*,
    queue::Queue,
    smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed},
    wsv::WorldTrait,
    IrohaNetwork, NetworkMessage, VersionedValidBlock,
};

trait Consensus {
    fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedPendingBlock>;
}

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

    /// Allows controlling Sumeragi rounds by sending `Voting` message manually.
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

/// Message reminder for retrieving transactions.
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct RetrieveTransactions;

/// Message reminder for gossip.
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct Gossip;

/// Message reminder for peer (re/dis)connection.
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct ConnectPeers;

/// Message reminder for telemetry updates.
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct UpdateTelemetry;

/// Message reminder for initialization of sumeragi
#[derive(Debug, Clone, Copy, iroha_actor::Message)]
pub struct Init {
    /// Latest block hash
    pub last_block: HashOf<VersionedCommittedBlock>,
    /// Height of merkle tree
    pub height: u64,
}

/// Get network topology
#[derive(Debug, Clone, iroha_actor::Message)]
#[message(result = "Topology")]
pub struct GetNetworkTopology(pub BlockHeader);

/// Current network topology
#[derive(Debug, Copy, Clone, iroha_actor::Message)]
#[message(result = "Topology")]
pub struct CurrentNetworkTopology;

/// Commit block
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CommitBlock(pub VersionedValidBlock);

/// Get invalidated blocks's hashes
#[derive(Debug, Clone, Copy, iroha_actor::Message)]
#[message(result = "Vec<HashOf<VersionedValidBlock>>")]
pub struct InvalidatedBlockHashes;

/// Reminder to check if commit timeout happened.
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CheckCommitTimeout {
    block_hash: HashOf<VersionedValidBlock>,
    proof: Proof,
}

/// Reminder to check if block creation timeout happened.
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CheckCreationTimeout {
    tx_hash: HashOf<VersionedTransaction>,
    proof: Proof,
}

/// Reminder to check if transaction receipt timeout happened.
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CheckReceiptTimeout {
    tx_hash: HashOf<VersionedTransaction>,
    proof: Proof,
}

/// `Sumeragi` is the implementation of the consensus.
pub type Sumeragi<G, K, W> = SumeragiWithFault<G, K, W, NoFault>;

/// `Sumeragi` is the implementation of the consensus. This struct allows also to add fault injection for tests.
pub struct SumeragiWithFault<G, K, W, F>
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    W: WorldTrait,
    F: FaultInjection,
{
    key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The current topology of the peer to peer network.
    pub topology: Topology,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    voting_block: Option<VotingBlock>,
    /// This field is used to count votes when the peer is a proxy tail role.
    votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    events_sender: EventsSender,
    wsv: Arc<WorldStateView<W>>,

    /// This field is used to count votes for a view change.
    votes_for_view_change: HashMap<HashOf<Proof>, Proof>,

    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    /// And time at which this transaction was sent to the leader by this peer.
    txs_awaiting_receipts: HashMap<HashOf<VersionedTransaction>, Instant>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in CreatedBlock.
    txs_awaiting_created_block: HashSet<HashOf<VersionedTransaction>>,

    commit_time: Duration,
    tx_receipt_time: Duration,
    block_time: Duration,
    block_height: u64,
    /// Hashes of invalidated blocks
    pub invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
    is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
    telemetry_started: bool,
    max_instruction_number: u64,
    /// Genesis network
    pub genesis_network: Option<G>,
    /// Broker
    pub broker: Broker,
    /// [`Kura`](crate::kura) actor address
    pub kura: AlwaysAddr<K>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,
    /// Mailbox size
    pub mailbox: usize,
    fault_injection: PhantomData<F>,
    gossip_batch_size: usize,
    gossip_period: Duration,
}

/// Generic sumeragi trait
pub trait SumeragiTrait:
    Actor
    + ContextHandler<Message, Result = ()>
    + ContextHandler<Init, Result = ()>
    + ContextHandler<CommitBlock, Result = ()>
    + ContextHandler<GetNetworkTopology, Result = Topology>
    + ContextHandler<IsLeader, Result = bool>
    + ContextHandler<GetLeader, Result = PeerId>
    + ContextHandler<NetworkMessage, Result = ()>
    + ContextHandler<RetrieveTransactions, Result = ()>
    + Handler<Gossip, Result = ()>
    + Debug
{
    /// Genesis for sending genesis txs
    type GenesisNetwork: GenesisNetworkTrait;
    /// Data storage
    type Kura: KuraTrait<World = Self::World>;
    /// World for updating WSV after block commitment
    type World: WorldTrait;

    /// Construct [`Sumeragi`].
    ///
    /// # Errors
    /// Can fail during initing network topology
    #[allow(clippy::too_many_arguments)]
    fn from_configuration(
        configuration: &config::SumeragiConfiguration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<Self::World>>,
        is_instruction_allowed: IsInstructionAllowedBoxed<Self::World>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<Self::World>>,
        telemetry_started: bool,
        genesis_network: Option<Self::GenesisNetwork>,
        queue: Arc<Queue>,
        broker: Broker,
        kura: AlwaysAddr<Self::Kura>,
        network: Addr<IrohaNetwork>,
    ) -> Result<Self>;
}

impl<G: GenesisNetworkTrait, K: KuraTrait<World = W>, W: WorldTrait, F: FaultInjection>
    SumeragiTrait for SumeragiWithFault<G, K, W, F>
{
    type GenesisNetwork = G;
    type Kura = K;
    type World = W;

    fn from_configuration(
        configuration: &config::SumeragiConfiguration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<W>>,
        is_instruction_allowed: IsInstructionAllowedBoxed<W>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
        telemetry_started: bool,
        genesis_network: Option<G>,
        queue: Arc<Queue>,
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
            is_instruction_allowed: Arc::new(is_instruction_allowed),
            is_query_allowed,
            telemetry_started,
            max_instruction_number: configuration.max_instruction_number,
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

/// The interval at which sumeragi checks if there are tx in the `queue`.
/// And will create a block if is leader and the voting is not already in progress.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(200);
/// The interval of peers (re/dis)connection.
pub const PEERS_CONNECT_INTERVAL: Duration = Duration::from_secs(1);
/// The interval of telemetry updates.
pub const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Actor
    for SumeragiWithFault<G, K, W, F>
{
    fn mailbox_capacity(&self) -> usize {
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
            error!(%error, "Handle message failed");
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
        let txs = self.queue.get_transactions_for_block(&*self.wsv);
        if let Err(error) = self.round(txs, ctx).await {
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
        let txs = self
            .queue
            .n_random_transactions(&*self.wsv, self.gossip_batch_size);
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
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> ContextHandler<Init>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = ();
    async fn handle(&mut self, ctx: &mut Context<Self>, Init { last_block, height }: Init) {
        info!("Starting Sumeragi");
        self.connect_peers().await;

        if height != 0 && *last_block != Hash([0; 32]) {
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

/// Returns if peer is leader
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "bool")]
pub struct IsLeader;

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection> Handler<IsLeader>
    for SumeragiWithFault<G, K, W, F>
{
    type Result = bool;
    async fn handle(&mut self, IsLeader: IsLeader) -> Self::Result {
        self.is_leader()
    }
}

/// Gets leader from sumeragi
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "PeerId")]
pub struct GetLeader;

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
    #[log(skip(self, transactions, genesis_topology))]
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
                PendingBlock::new(transactions).chain_first_with_genesis_topology(genesis_topology),
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
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        if Role::Leader == self.topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions).chain(
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

    async fn broadcast_msg_to(
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
            .expect("It was checked earlier that transactions are not empty.");
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

        VersionedMessage::from(Message::from(TransactionForwarded::new(tx, &self.peer_id)))
            .send_to(&self.broker, self.topology.leader())
            .await;
    }

    /// Returns:
    /// `true` - if new votes were added
    /// `false` - otherwise
    ///
    /// And the actual Proof as it is contained in `votes_for_view_change` with merged votes.
    async fn merge_view_change_votes(&mut self, proof: Proof) -> (bool, Proof) {
        match self.votes_for_view_change.entry(proof.hash()) {
            Entry::Occupied(mut occupied) => {
                let proof_votes = occupied.get_mut();
                let count = proof_votes.signatures().len();
                proof_votes.merge_signatures(&proof);
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
                proof.clone(),
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
        let block = block.validate(
            &*self.wsv,
            &self.is_instruction_allowed,
            &self.is_query_allowed,
        );
        let network_topology = self.network_topology_current_or_genesis(block.header());
        info!(
            peer_role = ?network_topology.role(&self.peer_id),
            block_hash = %block.hash(),
            "Created a block",
        );
        for event in Vec::<Event>::from(&block) {
            info!(?event);
            drop(self.events_sender.send(event));
        }
        if !network_topology.is_consensus_required() {
            self.commit_block(block).await;
            return Ok(());
        }

        let voting_block = VotingBlock::new(block.clone());
        self.voting_block = Some(voting_block.clone());
        self.broadcast_msg(BlockCreated::from(block.sign(self.key_pair.clone())?))
            .await;
        self.start_commit_countdown(
            voting_block.clone(),
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
            ctx,
        )
        .await;
        Ok(())
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.
    #[iroha_futures::telemetry_future]
    #[log(skip(self, voting_block))]
    #[allow(clippy::expect_used)]
    pub async fn start_commit_countdown(
        &self,
        voting_block: VotingBlock,
        latest_block: HashOf<VersionedCommittedBlock>,
        latest_view_change: HashOf<Proof>,
        ctx: &mut Context<Self>,
    ) {
        let voting_block_hash = voting_block.block.hash();
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
            info!(?event);
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
    async fn change_view(
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
            iroha_logger::info!(
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
            .field("public_key", &self.key_pair.public_key)
            .field("network_topology", &self.topology)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}

/// Structure represents a block that is currently in discussion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VotingBlock {
    /// At what time has this peer voted for this block
    pub voted_at: Duration,
    /// Valid Block
    pub block: VersionedValidBlock,
}

impl VotingBlock {
    /// Constructs new `VotingBlock.`
    #[allow(clippy::expect_used)]
    pub fn new(block: VersionedValidBlock) -> VotingBlock {
        VotingBlock {
            voted_at: current_time(),
            block,
        }
    }
}

/// Contains message structures for p2p communication during consensus.
pub mod message {
    #![allow(clippy::module_name_repetitions)]

    use std::{sync::Arc, time::Duration};

    use eyre::{Result, WrapErr};
    use futures::{prelude::*, stream::FuturesUnordered};
    use iroha_actor::broker::Broker;
    use iroha_crypto::{HashOf, KeyPair, SignatureOf};
    use iroha_data_model::prelude::*;
    use iroha_logger::prelude::*;
    use iroha_macro::*;
    use iroha_p2p::Post;
    use iroha_schema::IntoSchema;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use tokio::task;

    use super::{view_change, CheckCreationTimeout, FaultInjection, SumeragiWithFault};
    use crate::{
        genesis::GenesisNetworkTrait,
        kura::KuraTrait,
        queue,
        sumeragi::{NetworkMessage, Role, Sumeragi, Topology, VotingBlock},
        wsv::WorldTrait,
        VersionedAcceptedTransaction, VersionedValidBlock,
    };

    declare_versioned_with_scale!(VersionedMessage 1..2, Debug, Clone, iroha_macro::FromVariant, iroha_actor::Message);

    impl VersionedMessage {
        /// Converts from `&VersionedMessage` to V1 reference
        pub const fn as_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Converts from `&mut VersionedMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedMessage` to V1
        pub fn into_v1(self) -> Message {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Send this message over the network to the specified `peer`.
        /// # Errors
        /// Fails if network sending fails
        #[iroha_futures::telemetry_future]
        #[iroha_logger::log(skip(self))]
        pub async fn send_to(self, broker: &Broker, peer: &PeerId) {
            let post = Post {
                data: NetworkMessage::SumeragiMessage(Box::new(self)),
                peer: peer.clone(),
            };
            broker.issue_send(post).await;
        }

        /// Send this message over the network to multiple `peers`.
        /// # Errors
        /// Fails if network sending fails
        pub async fn send_to_multiple<'a, I>(self, broker: &Broker, peers: I)
        where
            I: IntoIterator<Item = &'a PeerId> + Send,
        {
            let futures = peers
                .into_iter()
                .map(|peer| self.clone().send_to(broker, peer))
                .collect::<FuturesUnordered<_>>()
                .collect::<()>();

            futures.await;
        }

        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            self,
            sumeragi: &mut Sumeragi<G, K, W>,
            ctx: &mut iroha_actor::Context<Sumeragi<G, K, W>>,
        ) -> Result<()> {
            self.into_v1().handle(sumeragi, ctx).await
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Debug, Clone, Decode, Encode, FromVariant, iroha_actor::Message)]
    pub enum Message {
        /// Is sent by leader to all validating peers, when a new block is created.
        BlockCreated(BlockCreated),
        /// Is sent by validating peers to proxy tail and observing peers when they have signed this block.
        BlockSigned(BlockSigned),
        /// Is sent by proxy tail to validating peers and to leader, when the block is committed.
        BlockCommitted(BlockCommitted),
        /// Receipt of receiving tx from peer. Sent by a leader.
        TransactionReceived(TransactionReceipt),
        /// Tx forwarded from client by a peer to a leader.
        TransactionForwarded(TransactionForwarded),
        /// View change is suggested due to some faulty peer or general fault in consensus.
        ViewChangeSuggested(ViewChangeSuggested),
        /// Is sent by all peers during gossiping.
        TransactionGossip(TransactionGossip),
    }

    impl Message {
        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        #[iroha_logger::log(skip(self, sumeragi))]
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
            ctx: &mut iroha_actor::Context<SumeragiWithFault<G, K, W, F>>,
        ) -> Result<()> {
            let message = if let Some(message) = F::faulty_message(sumeragi, self) {
                message
            } else {
                return Ok(());
            };
            match message {
                Message::BlockCreated(block_created) => block_created.handle(sumeragi, ctx).await,
                Message::BlockSigned(block_signed) => block_signed.handle(sumeragi).await,
                Message::BlockCommitted(block_committed) => block_committed.handle(sumeragi).await,
                Message::TransactionReceived(transaction_receipt) => {
                    transaction_receipt.handle(sumeragi, ctx).await
                }
                Message::TransactionForwarded(transaction_forwarded) => {
                    transaction_forwarded.handle(sumeragi).await
                }
                Message::ViewChangeSuggested(view_change_suggested) => {
                    view_change_suggested.handle(sumeragi).await
                }
                Message::TransactionGossip(transaction_gossip) => {
                    transaction_gossip.handle(sumeragi).await
                }
            }
        }
    }

    /// `ViewChangeSuggested` message structure.
    #[derive(Debug, Clone, Decode, Encode)]
    pub struct ViewChangeSuggested {
        /// Proof of view change. As part of this message handling, all peers which agree with view change should sign it.
        pub proof: view_change::Proof,
        /// Chain
        pub chain: view_change::ProofChain,
    }

    impl ViewChangeSuggested {
        /// Constructor.
        pub fn new(
            proof: view_change::Proof,
            chain: view_change::ProofChain,
        ) -> ViewChangeSuggested {
            Self { proof, chain }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail during signing.
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            &self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ) -> Result<()> {
            use view_change::Reason::*;
            sumeragi.update_view_changes(self.chain.clone());
            if !self.proof.has_same_state(
                sumeragi.latest_block_hash(),
                &sumeragi.latest_view_change_hash(),
            ) {
                return Ok(());
            }
            let (_, merged_proof) = sumeragi.merge_view_change_votes(self.proof.clone()).await;
            if merged_proof.verify(&sumeragi.peers(), sumeragi.topology.max_faults()) {
                let invalidated_block_hash = match merged_proof.reason() {
                    CommitTimeout(reason) => Some(reason.hash),
                    NoTransactionReceiptReceived(_) | BlockCreationTimeout(_) => None,
                };
                sumeragi
                    .change_view(merged_proof.clone(), invalidated_block_hash)
                    .await;
            }
            Ok(())
        }
    }

    /// `BlockCreated` message structure.
    #[derive(Debug, Clone, Decode, Encode)]
    #[non_exhaustive]
    pub struct BlockCreated {
        /// The corresponding block.
        pub block: VersionedValidBlock,
    }

    impl BlockCreated {
        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            &self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
            ctx: &mut iroha_actor::Context<SumeragiWithFault<G, K, W, F>>,
        ) -> Result<()> {
            // There should be only one block in discussion during a round.
            if sumeragi.voting_block.is_some() {
                return Ok(());
            }

            for event in Vec::<Event>::from(&self.block) {
                iroha_logger::info!(?event);
                drop(sumeragi.events_sender.send(event));
            }
            sumeragi.update_view_changes(self.block.header().view_change_proofs.clone());
            let network_topology =
                sumeragi.network_topology_current_or_genesis(self.block.header());
            if network_topology
                .filter_signatures_by_roles(&[Role::Leader], self.block.verified_signatures())
                .is_empty()
            {
                iroha_logger::error!(
                    role = ?sumeragi.topology.role(&sumeragi.peer_id),
                    "Rejecting Block as it is not signed by leader.",
                );
                return Ok(());
            }
            sumeragi.txs_awaiting_created_block.clear();
            if network_topology.role(&sumeragi.peer_id) == Role::ValidatingPeer
                && self.block.validation_check(
                    &sumeragi.wsv,
                    sumeragi.latest_block_hash(),
                    &sumeragi.latest_view_change_hash(),
                    sumeragi.block_height,
                    sumeragi.max_instruction_number,
                )
            {
                let block_clone = self.block.clone();
                let wsv_clone = Arc::clone(&sumeragi.wsv);
                let is_instruction_allowed_clone = Arc::clone(&sumeragi.is_instruction_allowed);
                let is_query_allowed_clone = Arc::clone(&sumeragi.is_query_allowed);
                let key_pair_clone = sumeragi.key_pair.clone();
                let signed_block = task::spawn_blocking(move || -> Result<BlockSigned> {
                    block_clone
                        .revalidate(
                            &*wsv_clone,
                            &*is_instruction_allowed_clone,
                            &*is_query_allowed_clone,
                        )
                        .sign(key_pair_clone)
                        .map(Into::into)
                })
                .await??;
                VersionedMessage::from(Message::BlockSigned(signed_block))
                    .send_to(&sumeragi.broker, network_topology.proxy_tail())
                    .await;
                iroha_logger::info!(
                    peer_role = ?network_topology.role(&sumeragi.peer_id),
                    block_hash = %self.block.hash(),
                    "Signed block candidate",
                );
                //TODO: send to set b so they can observe
            }
            let voting_block = VotingBlock::new(self.block.clone());
            sumeragi.voting_block = Some(voting_block.clone());
            sumeragi
                .start_commit_countdown(
                    voting_block,
                    *sumeragi.latest_block_hash(),
                    sumeragi.latest_view_change_hash(),
                    ctx,
                )
                .await;
            Ok(())
        }
    }

    impl From<VersionedValidBlock> for BlockCreated {
        fn from(block: VersionedValidBlock) -> Self {
            Self { block }
        }
    }

    /// `BlockSigned` message structure.
    #[derive(Debug, Clone, Decode, Encode)]
    #[non_exhaustive]
    pub struct BlockSigned {
        /// The corresponding block.
        pub block: VersionedValidBlock,
    }

    impl BlockSigned {
        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            &self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ) -> Result<()> {
            sumeragi.update_view_changes(self.block.header().view_change_proofs.clone());
            let network_topology =
                sumeragi.network_topology_current_or_genesis(self.block.header());
            if Role::ProxyTail != network_topology.role(&sumeragi.peer_id) {
                return Ok(());
            }
            let block_hash = self.block.hash();
            let entry = sumeragi
                .votes_for_blocks
                .entry(block_hash)
                .or_insert_with(|| self.block.clone());
            entry.as_mut_v1().signatures.extend(
                self.block
                    .verified_signatures()
                    .cloned()
                    .map(SignatureOf::transmute),
            );
            let valid_signatures = network_topology.filter_signatures_by_roles(
                &[Role::ValidatingPeer, Role::Leader],
                entry.verified_signatures(),
            );

            iroha_logger::info!(
                peer_role = ?network_topology.role(&sumeragi.peer_id),
                %block_hash,
                valid_signatures_count = valid_signatures.len(),
                required_signatures_count = network_topology.min_votes_for_commit() - 1,
                "Received a vote for block",
            );

            if valid_signatures.len() < network_topology.min_votes_for_commit() - 1 {
                return Ok(());
            }

            let signatures = valid_signatures
                .into_iter()
                .map(SignatureOf::transmute)
                .collect();
            let mut block = entry.clone();
            block.as_mut_v1().signatures = signatures;
            let block = block.sign(sumeragi.key_pair.clone())?;

            iroha_logger::info!(
                peer_role = ?network_topology.role(&sumeragi.peer_id),
                %block_hash,
                "Block reached required number of votes",
            );

            sumeragi
                .broadcast_msg_to(
                    BlockCommitted::from(block.clone()),
                    network_topology
                        .validating_peers()
                        .iter()
                        .chain(std::iter::once(network_topology.leader()))
                        .chain(network_topology.peers_set_b()),
                )
                .await;
            sumeragi.votes_for_blocks.clear();
            sumeragi.commit_block(block).await;

            Ok(())
        }
    }

    impl From<VersionedValidBlock> for BlockSigned {
        fn from(block: VersionedValidBlock) -> Self {
            Self { block }
        }
    }

    /// `BlockCommitted` message structure.
    #[derive(Debug, Clone, Decode, Encode)]
    #[non_exhaustive]
    pub struct BlockCommitted {
        /// The corresponding block.
        pub block: VersionedValidBlock,
    }

    impl BlockCommitted {
        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Actually infallible
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            &self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ) -> Result<()> {
            let network_topology =
                sumeragi.network_topology_current_or_genesis(self.block.header());
            #[allow(clippy::expect_used)]
            let network_topology = network_topology
                .into_builder()
                .with_view_changes(self.block.header().view_change_proofs.clone())
                .build()
                .expect("When only changing view changes it should not fail.");
            let verified_signatures = self
                .block
                .verified_signatures()
                .cloned()
                .collect::<Vec<_>>();
            let valid_signatures = network_topology.filter_signatures_by_roles(
                &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                &verified_signatures,
            );
            let proxy_tail_signatures = network_topology
                .filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
            if valid_signatures.len() >= network_topology.min_votes_for_commit()
                && proxy_tail_signatures.len() == 1
                && sumeragi.latest_block_hash() == &self.block.header().previous_block_hash
            {
                let mut block = self.block.clone();
                block.as_mut_v1().signatures.clear();
                block
                    .as_mut_v1()
                    .signatures
                    .extend(valid_signatures.into_iter().map(SignatureOf::transmute));
                sumeragi.commit_block(block).await;
            }
            Ok(())
        }
    }

    impl From<VersionedValidBlock> for BlockCommitted {
        fn from(block: VersionedValidBlock) -> Self {
            Self { block }
        }
    }

    /// `Message` structure describing a transaction that is forwarded from a client by a peer to the leader.
    #[derive(Debug, Clone, Decode, Encode)]
    #[non_exhaustive]
    pub struct TransactionForwarded {
        /// Transaction that is forwarded from a client by a peer to the leader
        pub transaction: VersionedAcceptedTransaction,
        /// `PeerId` of the peer that forwarded this transaction to a leader.
        pub peer: PeerId,
    }

    impl TransactionForwarded {
        /// Constructs `TransactionForwarded` message.
        pub fn new(
            transaction: &VersionedAcceptedTransaction,
            peer: &PeerId,
        ) -> TransactionForwarded {
            TransactionForwarded {
                transaction: transaction.clone(),
                peer: peer.clone(),
            }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing transaction
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ) -> Result<()> {
            match sumeragi
                .queue
                .push(self.transaction.clone(), &*sumeragi.wsv)
            {
                Ok(()) if sumeragi.is_leader() => {
                    VersionedMessage::from(Message::TransactionReceived(TransactionReceipt::new(
                        &self.transaction,
                        &sumeragi.key_pair,
                    )?))
                    .send_to(&sumeragi.broker, &self.peer)
                    .await;
                    Ok(())
                }
                Err((_, queue::Error::InBlockchain)) | Ok(()) => Ok(()),
                Err((_, err)) => Err(err.into()),
            }
        }
    }

    /// Message for gossiping batches of transactions.
    #[derive(Decode, Encode, Debug, Clone)]
    pub struct TransactionGossip {
        txs: Vec<VersionedAcceptedTransaction>,
    }

    impl TransactionGossip {
        /// Constructor.
        pub fn new(txs: Vec<VersionedAcceptedTransaction>) -> Self {
            Self { txs }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail during signing.
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ) -> Result<()> {
            for tx in self.txs {
                match sumeragi.queue.push(tx, &*sumeragi.wsv) {
                    Err((_, queue::Error::InBlockchain)) | Ok(()) => {}
                    Err((_, err)) => {
                        iroha_logger::warn!(?err, "Failed to push into queue gossiped transaction.")
                    }
                }
            }
            Ok(())
        }
    }

    /// `Message` structure describing a receipt sent by the leader to the peer it got this transaction from.
    #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
    #[non_exhaustive]
    pub struct TransactionReceipt {
        /// The hash of the transaction that the leader received.
        pub hash: HashOf<VersionedTransaction>,
        /// The time at which the leader claims to have received this transaction.
        pub received_at: Duration,
        /// The signature of the leader.
        pub signature: SignatureOf<VersionedTransaction>,
    }

    impl TransactionReceipt {
        /// Constructs a new receipt.
        ///
        /// # Errors
        /// Can fail creating new signature
        #[allow(clippy::expect_used, clippy::unwrap_in_result)]
        pub fn new(
            transaction: &VersionedAcceptedTransaction,
            key_pair: &KeyPair,
        ) -> Result<TransactionReceipt> {
            let hash = transaction.hash();
            let signature = SignatureOf::from_hash(key_pair.clone(), &hash)?;
            Ok(TransactionReceipt {
                hash,
                received_at: current_time(),
                signature,
            })
        }

        /// Checks that this `TransactionReceipt` is valid.
        pub fn is_valid(&self, network_topology: &Topology) -> bool {
            network_topology
                .verify_signature_with_role(&self.signature, Role::Leader, &self.hash)
                .is_ok()
        }

        /// Checks if the block should have been already created by the `Leader`.
        pub fn is_block_should_be_created(&self, block_time: Duration) -> bool {
            (current_time() - self.received_at) >= block_time
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        #[iroha_futures::telemetry_future]
        pub async fn handle<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
            F: FaultInjection,
        >(
            &self,
            sumeragi: &mut SumeragiWithFault<G, K, W, F>,
            ctx: &mut iroha_actor::Context<SumeragiWithFault<G, K, W, F>>,
        ) -> Result<()> {
            let now = current_time();

            // Implausible time in the future, means that the leader lies
            if sumeragi.topology.role(&sumeragi.peer_id) == Role::Leader
                || self.received_at > now
                || !self.is_valid(&sumeragi.topology)
                || !sumeragi.txs_awaiting_receipts.contains_key(&self.hash)
            {
                return Ok(());
            }

            sumeragi.txs_awaiting_receipts.remove(&self.hash);
            let tx_hash = self.hash;
            let block_creation_timeout = view_change::Proof::block_creation_timeout(
                sumeragi.latest_view_change_hash(),
                *sumeragi.latest_block_hash(),
                sumeragi.key_pair.clone(),
            )
            .wrap_err("Failed to put first signature.")?;
            sumeragi.txs_awaiting_created_block.insert(tx_hash);

            // Suspect leader if the block was not yet created
            ctx.notify(
                CheckCreationTimeout {
                    tx_hash,
                    proof: block_creation_timeout,
                },
                sumeragi.block_time,
            );
            Ok(())
        }
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use std::{collections::HashSet, fmt::Debug, fs::File, io::BufReader, path::Path};

    use eyre::{Result, WrapErr};
    use iroha_config::derive::Configurable;
    use iroha_crypto::prelude::*;
    use iroha_data_model::prelude::*;
    use serde::{Deserialize, Serialize};

    const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
    const DEFAULT_COMMIT_TIME_MS: u64 = 2000;
    const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 500;
    const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    const DEFAULT_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE: u64 = 1;
    const DEFAULT_MAILBOX_SIZE: usize = 100;
    const DEFAULT_GOSSIP_PERIOD_MS: u64 = 1000;
    const DEFAULT_GOSSIP_BATCH_SIZE: usize = 500;

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Configurable)]
    #[serde(default)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "SUMERAGI_")]
    pub struct SumeragiConfiguration {
        /// Key pair of private and public keys.
        #[serde(skip)]
        pub key_pair: KeyPair,
        /// Current Peer Identification.
        pub peer_id: PeerId,
        /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        pub block_time_ms: u64,
        /// Optional list of predefined trusted peers.
        pub trusted_peers: TrustedPeers,
        /// Amount of time Peer waits for CommitMessage from the proxy tail.
        pub commit_time_ms: u64,
        /// Amount of time Peer waits for TxReceipt from the leader.
        pub tx_receipt_time_ms: u64,
        /// After N view changes topology will change tactic from shifting by one, to reshuffle.
        pub n_topology_shifts_before_reshuffle: u64,
        /// Maximum instruction number per transaction
        pub max_instruction_number: u64,
        /// Mailbox size
        pub mailbox: usize,
        /// Maximum number of transactions in tx gossip batch message. While configuring this, attention should be payed to `p2p` max message size.
        pub gossip_batch_size: usize,
        /// Period in milliseconds for pending transaction gossiping between peers.
        pub gossip_period_ms: u64,
    }

    impl Default for SumeragiConfiguration {
        fn default() -> Self {
            Self {
                key_pair: KeyPair::default(),
                trusted_peers: default_empty_trusted_peers(),
                peer_id: default_peer_id(),
                block_time_ms: DEFAULT_BLOCK_TIME_MS,
                commit_time_ms: DEFAULT_COMMIT_TIME_MS,
                tx_receipt_time_ms: DEFAULT_TX_RECEIPT_TIME_MS,
                n_topology_shifts_before_reshuffle: DEFAULT_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE,
                max_instruction_number: DEFAULT_MAX_INSTRUCTION_NUMBER,
                mailbox: DEFAULT_MAILBOX_SIZE,
                gossip_batch_size: DEFAULT_GOSSIP_BATCH_SIZE,
                gossip_period_ms: DEFAULT_GOSSIP_PERIOD_MS,
            }
        }
    }

    impl SumeragiConfiguration {
        /// Set `trusted_peers` configuration parameter - will overwrite the existing one.
        pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
            self.trusted_peers.peers = trusted_peers.into_iter().collect();
        }

        /// Time estimation from receiving a transaction to storing it in a block on all peers for the "sunny day" scenario.
        pub const fn pipeline_time_ms(&self) -> u64 {
            self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
        }
    }

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(transparent)]
    pub struct TrustedPeers {
        /// Optional list of predefined trusted peers.
        pub peers: HashSet<PeerId>,
    }

    impl TrustedPeers {
        /// Load trusted peers variables from a json *pretty* formatted file.
        ///
        /// # Errors
        /// Fails if there is no file or if file is not valid json
        pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<TrustedPeers> {
            let file = File::open(&path)
                .wrap_err_with(|| format!("Failed to open trusted peers file {:?}", &path))?;
            let reader = BufReader::new(file);
            let trusted_peers: HashSet<PeerId> = serde_json::from_reader(reader)
                .wrap_err("Failed to deserialize json from reader")?;
            Ok(TrustedPeers {
                peers: trusted_peers,
            })
        }
    }

    fn default_peer_id() -> PeerId {
        PeerId {
            address: "".to_owned(),
            public_key: PublicKey::default(),
        }
    }

    // Allowed because `HashSet::new()` is not const yet.
    fn default_empty_trusted_peers() -> TrustedPeers {
        TrustedPeers {
            peers: HashSet::new(),
        }
    }
}
