//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use std::{
    collections::{BTreeMap, HashSet},
    fmt::{self, Debug, Formatter},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::{DashMap, DashSet};
use eyre::{eyre, Result};
use futures::{future, prelude::*, stream::futures_unordered::FuturesUnordered};
use iroha_actor::{broker::*, prelude::*};
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::{
    current_time, events::Event, peer::Id as PeerId, transaction::VersionedTransaction,
};
use iroha_logger::Instrument;
use iroha_p2p::ConnectPeer;
use network_topology::{Role, Topology};
use rand::prelude::SliceRandom;
use tokio::{sync::RwLock, task, time};

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

/// Message to send to sumeragi. It will call `update_network_topology` method on it.
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct UpdateNetworkTopology;

/// Message reminder for voting
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct Voting;

/// Message reminder for gossip
#[derive(Debug, Clone, Copy, Default, iroha_actor::Message)]
pub struct Gossip;

/// Message reminder for peer (re)connection.
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

/// Get sorted peers
#[derive(Debug, Clone, Copy, iroha_actor::Message)]
#[message(result = "Vec<PeerId>")]
pub struct GetSortedPeers;

/// Get network topology
#[derive(Debug, Clone, iroha_actor::Message)]
#[message(result = "Topology")]
pub struct GetNetworkTopology(pub BlockHeader);

/// Commit block
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CommitBlock(pub VersionedValidBlock);

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi<G, K, W>
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    W: WorldTrait,
{
    key_pair: KeyPair,
    /// Address of queue
    pub queue: Arc<Queue>,
    /// The current topology of the peer to peer network.
    pub topology: Topology,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    voting_block: Arc<RwLock<Option<VotingBlock>>>,
    /// This field is used to count votes when the peer is a proxy tail role.
    votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    events_sender: EventsSender,
    wsv: Arc<WorldStateView<W>>,
    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    /// And time at which this transaction was sent to the leader by this peer.
    txs_awaiting_receipts: Arc<DashMap<HashOf<VersionedTransaction>, Instant>>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in CreatedBlock.
    txs_awaiting_created_block: Arc<DashSet<HashOf<VersionedTransaction>>>,
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
    /// [`Kura`] actor address
    pub kura: AlwaysAddr<K>,
    /// [`iroha_p2p::Network`] actor address
    pub network: Addr<IrohaNetwork>,
    /// Mailbox size
    pub mailbox: usize,
}

/// Generic sumeragi trait
pub trait SumeragiTrait:
    Actor
    + ContextHandler<UpdateNetworkTopology, Result = ()>
    + ContextHandler<Message, Result = ()>
    + ContextHandler<Init, Result = ()>
    + ContextHandler<CommitBlock, Result = ()>
    + ContextHandler<GetNetworkTopology, Result = Topology>
    + ContextHandler<GetSortedPeers, Result = Vec<PeerId>>
    + ContextHandler<IsLeader, Result = bool>
    + ContextHandler<GetLeader, Result = PeerId>
    + ContextHandler<NetworkMessage, Result = ()>
    + Handler<Gossip, Result = ()>
    + Debug
{
    /// Genesis for sending genesis txs
    type GenesisNetwork: GenesisNetworkTrait;
    /// Data storage
    type Kura: KuraTrait<World = Self::World>;
    /// World for updating WSV after block commitment
    type World: WorldTrait;

    /// Default `Sumeragi` constructor.
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
        //TODO: separate initialization from construction and do not return Result in `new`
    ) -> Result<Self>;
}

impl<G: GenesisNetworkTrait, K: KuraTrait<World = W>, W: WorldTrait> SumeragiTrait
    for Sumeragi<G, K, W>
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
        if configuration.trusted_peers.peers.is_empty() {
            return Err(eyre::eyre!(
                "There must be at least one trusted peer in the network."
            ));
        }
        let network_topology = Topology::builder()
            .at_block(EmptyChainHash::default().into())
            .with_max_faults(configuration.max_faulty_peers())
            .reshuffle_after(configuration.n_topology_shifts_before_reshuffle)
            .with_peers(configuration.trusted_peers.peers.clone())
            .build()?;
        Ok(Self {
            key_pair: configuration.key_pair.clone(),
            topology: network_topology,
            peer_id: configuration.peer_id.clone(),
            voting_block: Arc::new(RwLock::new(None)),
            votes_for_blocks: BTreeMap::new(),
            events_sender,
            wsv,
            txs_awaiting_receipts: Arc::new(DashMap::new()),
            txs_awaiting_created_block: Arc::new(DashSet::new()),
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
        })
    }
}

/// The interval at which sumeragi checks if there are tx in the `queue`.
/// And will create a block if is leader and the voting is not already in progress.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(200);
/// The interval at which sumeragi forwards txs from `queue` to other peers.
pub const TX_GOSSIP_INTERVAL: Duration = Duration::from_millis(100);
/// The interval of peers (re)connection.
pub const PEERS_CONNECT_INTERVAL: Duration = Duration::from_secs(1);
/// The interval of telemetry updates.
pub const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Actor for Sumeragi<G, K, W> {
    fn mailbox_capacity(&self) -> usize {
        self.mailbox
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<Init, _>(ctx);
        self.broker.subscribe::<UpdateNetworkTopology, _>(ctx);
        self.broker.subscribe::<Message, _>(ctx);
        self.broker.subscribe::<CommitBlock, _>(ctx);
        self.broker.subscribe::<NetworkMessage, _>(ctx);
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<UpdateNetworkTopology>
    for Sumeragi<G, K, W>
{
    type Result = ();
    async fn handle(&mut self, UpdateNetworkTopology: UpdateNetworkTopology) {
        self.update_network_topology().await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<Message> for Sumeragi<G, K, W> {
    type Result = ();
    async fn handle(&mut self, message: Message) {
        iroha_logger::trace!(role=?self.topology.role(&self.peer_id), msg=?message);
        if let Err(error) = message.handle(&mut self).await {
            iroha_logger::error!(%error, "Handle message failed");
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<Voting> for Sumeragi<G, K, W> {
    type Result = ();
    async fn handle(&mut self, Voting: Voting) {
        if self.voting_in_progress().await {
            return;
        }
        let txs = self.queue.get_transactions_for_block(&*self.wsv);
        if let Err(error) = self.round(txs).await {
            iroha_logger::error!(%error, "Round failed");
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<Gossip> for Sumeragi<G, K, W> {
    type Result = ();
    async fn handle(&mut self, Gossip: Gossip) {
        let txs = self.queue.all_transactions(&*self.wsv);
        self.gossip_transactions(&txs[..]).await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<ConnectPeers>
    for Sumeragi<G, K, W>
{
    type Result = ();
    async fn handle(&mut self, ConnectPeers: ConnectPeers) {
        self.connect_peers().await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<UpdateTelemetry>
    for Sumeragi<G, K, W>
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
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> ContextHandler<Init>
    for Sumeragi<G, K, W>
{
    type Result = ();
    async fn handle(&mut self, ctx: &mut Context<Self>, Init { last_block, height }: Init) {
        iroha_logger::info!("Starting Sumeragi");
        self.connect_peers().await;

        if height != 0 && *last_block != Hash([0; 32]) {
            self.init(last_block, height);
        } else if let Some(genesis_network) = self.genesis_network.take() {
            let addr = self.network.clone();
            if let Err(err) = genesis_network.submit_transactions(&mut self, addr).await {
                iroha_logger::error!(%err, "Failed to submit genesis transactions")
            }
        }
        self.update_network_topology().await;
        ctx.notify_every::<ConnectPeers>(PEERS_CONNECT_INTERVAL);
        ctx.notify_every::<Voting>(TX_RETRIEVAL_INTERVAL);
        ctx.notify_every::<Gossip>(TX_GOSSIP_INTERVAL);
        if self.telemetry_started {
            ctx.notify_every::<UpdateTelemetry>(TELEMETRY_INTERVAL);
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<GetSortedPeers>
    for Sumeragi<G, K, W>
{
    type Result = Vec<PeerId>;
    async fn handle(&mut self, GetSortedPeers: GetSortedPeers) -> Vec<PeerId> {
        self.topology.sorted_peers().to_vec()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<GetNetworkTopology>
    for Sumeragi<G, K, W>
{
    type Result = Topology;
    async fn handle(&mut self, GetNetworkTopology(header): GetNetworkTopology) -> Topology {
        self.network_topology_current_or_genesis(&header)
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<CommitBlock>
    for Sumeragi<G, K, W>
{
    type Result = ();
    async fn handle(&mut self, CommitBlock(block): CommitBlock) {
        self.commit_block(block).await
    }
}

/// Returns if peer is leader
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "bool")]
pub struct IsLeader;

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<IsLeader> for Sumeragi<G, K, W> {
    type Result = bool;
    async fn handle(&mut self, IsLeader: IsLeader) -> bool {
        self.is_leader()
    }
}

/// Gets leader from sumeragi
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "PeerId")]
pub struct GetLeader;

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<GetLeader> for Sumeragi<G, K, W> {
    type Result = PeerId;
    async fn handle(&mut self, GetLeader: GetLeader) -> PeerId {
        self.topology.leader().clone()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Handler<NetworkMessage>
    for Sumeragi<G, K, W>
{
    type Result = ();

    async fn handle(&mut self, msg: NetworkMessage) -> Self::Result {
        use NetworkMessage::*;

        match msg {
            SumeragiMessage(data) => self.broker.issue_send(data.into_inner_v1()).await,
            BlockSync(data) => self.broker.issue_send(data.into_inner_v1()).await,
            Health => {}
        }
    }
}

impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Sumeragi<G, K, W> {
    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block: HashOf<VersionedCommittedBlock>, block_height: u64) {
        self.block_height = block_height;
        self.topology.apply_block(latest_block);
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if the new peers were added, otherwise leaves the order unchanged.
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
        self.voting_block.read().await.is_some()
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
    #[iroha_logger::log(skip(self, transactions, genesis_topology))]
    pub async fn start_genesis_round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        genesis_topology: Topology,
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
            )
            .await
        }
    }

    /// The leader of each round just uses the transactions they have at hand to create a block.
    ///
    /// # Errors
    /// Can fail during signing of block
    #[iroha_futures::telemetry_future]
    pub async fn round(&mut self, transactions: Vec<VersionedAcceptedTransaction>) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        if let Role::Leader = self.topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions).chain(
                self.block_height,
                *self.latest_block_hash(),
                self.view_change_proofs().clone(),
                self.invalidated_blocks_hashes.clone(),
            );
            self.validate_and_publish_created_block(block).await?;
        } else {
            self.forward_txs_to_leader(&transactions).await;
        }
        Ok(())
    }

    async fn broadcast_msg_to(
        &self,
        msg: impl Into<Message> + Send,
        ids: impl Iterator<Item = &PeerId> + Send,
    ) {
        let msg = VersionedMessage::from(msg.into());
        ids.map(|id| msg.clone().send_to(&self.broker, id))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await
    }

    /// Forwards transactions to the leader and waits for receipts.
    #[iroha_futures::telemetry_future]
    pub async fn forward_txs_to_leader(&mut self, txs: &[VersionedAcceptedTransaction]) {
        let mut send_futures = Vec::new();
        for tx in txs {
            let tx_hash = tx.hash();
            if self.txs_awaiting_receipts.contains_key(&tx_hash) {
                // This peer has already sent this tx to leader and is waiting for a receipt.
                // Without this `if` depending on the round time, the peers might DOS themselves.
                continue;
            }
            iroha_logger::info!(
                "{:?} - {} - Forwarding tx to leader({}). Transaction hash: {}",
                self.topology.role(&self.peer_id),
                self.peer_id.address,
                self.topology.leader().address,
                tx_hash,
            );
            send_futures.push(
                VersionedMessage::from(Message::from(TransactionForwarded::new(tx, &self.peer_id)))
                    .send_to(&self.broker, self.topology.leader()),
            );
            // Don't require leader to submit receipts and therefore create blocks if the tx is still waiting for more signatures.
            #[allow(clippy::expect_used)]
            if let Ok(true) = tx.check_signature_condition(&self.wsv) {
                self.txs_awaiting_receipts.insert(tx.hash(), Instant::now());
            }
            let txs_awaiting_receipts = Arc::clone(&self.txs_awaiting_receipts);
            #[allow(clippy::expect_used)]
            let no_tx_receipt = view_change::Proof::no_transaction_receipt_received(
                tx_hash,
                self.latest_view_change_hash(),
                *self.latest_block_hash(),
                self.key_pair.clone(),
            )
            .expect("Failed to put first signature.");

            let recipient_peers = self.topology.sorted_peers().to_vec();
            let peer_id = self.peer_id.clone();
            let tx_receipt_time = self.tx_receipt_time;
            let broker = self.broker.clone();
            task::spawn(
                async move {
                    time::sleep(tx_receipt_time).await;
                    if txs_awaiting_receipts.contains_key(&tx_hash) {
                        iroha_logger::warn!(
                            "Transaction receipt timeout detected! Transaction hash: {}",
                            tx_hash
                        );
                        let mut send_futures = Vec::new();
                        for peer in &recipient_peers {
                            if *peer != peer_id {
                                send_futures.push(
                                    VersionedMessage::from(Message::ViewChangeSuggested(
                                        no_tx_receipt.clone().into(),
                                    ))
                                    .send_to(&broker, peer),
                                );
                            }
                        }
                        future::join_all(send_futures).await;
                    }
                }
                .in_current_span(),
            );
        }
        future::join_all(send_futures).await;
    }

    async fn broadcast_msg(&self, msg: impl Into<Message> + Send) {
        let msg = VersionedMessage::from(msg.into());
        self.topology
            .sorted_peers()
            .iter()
            .map(|peer| msg.clone().send_to(&self.broker, peer))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await
    }

    async fn broadcast_msgs(&self, msgs: impl IntoIterator<Item = impl Into<Message>> + Send) {
        let msgs = msgs
            .into_iter()
            .map(Into::into)
            .map(VersionedMessage::from)
            .collect::<Vec<_>>();
        let peers = self.topology.sorted_peers();
        peers
            .iter()
            .flat_map(|peer| msgs.clone().into_iter().map(move |msg| (peer, msg)))
            .map(|(peer, msg)| msg.send_to(&self.broker, peer))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await;
    }

    /// Gossip transactions to other peers.
    #[iroha_futures::telemetry_future]
    pub async fn gossip_transactions(&mut self, txs: &[VersionedAcceptedTransaction]) {
        if txs.is_empty() {
            return;
        }

        iroha_logger::debug!(
            role = ?self.topology.role(&self.peer_id),
            "Gossiping transactions. Number of transactions to forward: {}",
            txs.len(),
        );

        self.broadcast_msgs(
            txs.iter()
                .map(|tx| TransactionForwarded::new(tx, &self.peer_id)),
        )
        .await;
    }

    /// Should be called by a leader to start the consensus round with `BlockCreated` message.
    ///
    /// # Errors
    /// Can fail signing block
    #[iroha_futures::telemetry_future]
    pub async fn validate_and_publish_created_block(&mut self, block: ChainedBlock) -> Result<()> {
        let block = block.validate(
            &*self.wsv,
            &self.is_instruction_allowed,
            &self.is_query_allowed,
        );
        let network_topology = self.network_topology_current_or_genesis(block.header());
        iroha_logger::info!(
            role = ?network_topology.role(&self.peer_id),
            hash = %block.hash(),
            "Created a block",
        );
        for event in Vec::<Event>::from(&block) {
            iroha_logger::info!(?event, "Event happened");
            drop(self.events_sender.send(event));
        }
        if !network_topology.is_consensus_required() {
            self.commit_block(block).await;
            return Ok(());
        }

        let voting_block = VotingBlock::new(block.clone());
        *self.voting_block.write().await = Some(voting_block.clone());
        self.broadcast_msg(BlockCreated::from(block.sign(self.key_pair.clone())?))
            .await;
        self.start_commit_countdown(
            voting_block.clone(),
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
        )
        .await;
        Ok(())
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.
    #[iroha_futures::telemetry_future]
    #[iroha_logger::log(skip(self, voting_block))]
    pub async fn start_commit_countdown(
        &self,
        voting_block: VotingBlock,
        latest_block: HashOf<VersionedCommittedBlock>,
        latest_view_change: HashOf<Proof>,
    ) {
        let old_voting_block = voting_block;
        let voting_block = Arc::clone(&self.voting_block);
        let key_pair = self.key_pair.clone();
        let recipient_peers = self.topology.sorted_peers().to_vec();
        let peer_id = self.peer_id.clone();
        let commit_time = self.commit_time;
        let broker = self.broker.clone();
        task::spawn(
            async move {
                time::sleep(commit_time).await;
                let voting_block = if let Some(voting_block) = voting_block.write().await.clone() {
                    voting_block
                } else {
                    return;
                };

                // If the block was not yet committed send commit timeout to other peers to initiate view change.
                if voting_block.block.hash() != old_voting_block.block.hash() {
                    return;
                }

                iroha_logger::warn!(
                    "Block commit timeout detected! Voting block hash: {}",
                    voting_block.block.hash()
                );
                #[allow(clippy::expect_used)]
                let message = VersionedMessage::from(Message::ViewChangeSuggested(
                    view_change::Proof::commit_timeout(
                        voting_block.block.hash(),
                        latest_view_change,
                        latest_block,
                        key_pair.clone(),
                    )
                    .expect("Failed to sign CommitTimeout")
                    .into(),
                ));
                let mut send_futures = Vec::new();
                for peer in &recipient_peers {
                    if *peer != peer_id {
                        send_futures.push(message.clone().send_to(&broker, peer));
                    }
                }
                future::join_all(send_futures).await;
            }
            .in_current_span(),
        );
    }

    /// Commits `ValidBlock` and changes the state of the `Sumeragi` and its `NetworkTopology`.
    #[iroha_logger::log(skip(self, block))]
    #[iroha_futures::telemetry_future]
    pub async fn commit_block(&mut self, block: VersionedValidBlock) {
        self.invalidated_blocks_hashes.clear();
        self.txs_awaiting_created_block.clear();
        self.txs_awaiting_receipts.clear();
        self.block_height = block.header().height;

        let block = block.commit();
        let block_hash = block.hash();

        for event in Vec::<Event>::from(&block) {
            iroha_logger::info!(?event, "Event happened");
            drop(self.events_sender.send(event));
        }

        self.broker.issue_send(StoreBlock(block)).await;

        let previous_role = self.topology.role(&self.peer_id);
        self.topology.apply_block(block_hash);
        iroha_logger::info!(
            "{:?} - Commiting block with hash {}. New role: {:?}. New height: {}",
            previous_role,
            block_hash,
            self.topology.role(&self.peer_id),
            self.block_height,
        );
        *self.voting_block.write().await = None;
        self.votes_for_blocks.clear();
    }

    #[iroha_futures::telemetry_future]
    async fn change_view(
        &mut self,
        proof: view_change::Proof,
        invalidated_block_hash: Option<HashOf<VersionedValidBlock>>,
    ) {
        self.txs_awaiting_created_block.clear();
        self.txs_awaiting_receipts.clear();
        let previous_role = self.topology.role(&self.peer_id);
        if let Some(invalidated_block_hash) = invalidated_block_hash {
            self.invalidated_blocks_hashes.push(invalidated_block_hash)
        }
        self.topology.apply_view_change(proof.clone());
        *self.voting_block.write().await = None;
        iroha_logger::info!(
            "{} - {:?} - Changing view at block with hash {}. New role: {:?}. Number of view changes (including this): {}. Reason for a view change: {}",
            self.peer_id.address,
            previous_role,
            self.latest_block_hash(),
            self.topology.role(&self.peer_id),
            self.number_of_view_changes(),
            proof.reason()
        );
    }

    /// If this peer is a leader in this round.
    pub fn is_leader(&self) -> bool {
        self.topology.role(&self.peer_id) == Role::Leader
    }

    /// Returns current network topology or genesis specific one, if the `block` is a genesis block.
    pub fn network_topology_current_or_genesis(&self, header: &BlockHeader) -> Topology {
        if header.is_genesis() && self.block_height == 0 {
            if let Some(genesis_topology) = &header.genesis_topology {
                iroha_logger::info!("Using network topology from genesis block.");
                return genesis_topology.clone();
            }
        }

        self.topology.clone()
    }

    /// Connects all peers from current network topology.
    pub async fn connect_peers(&self) {
        iroha_logger::debug!("Connecting peers...");
        let mut peers = self.topology.sorted_peers().to_owned();
        let self_address = self.peer_id.address.clone();

        #[allow(clippy::expect_used)]
        let peers_online = self
            .network
            .send(iroha_p2p::network::GetConnectedPeers)
            .await
            .expect("Could not get connected peers from Network!")
            .peers;

        {
            let mut rng = rand::thread_rng();
            peers.shuffle(&mut rng);
        }
        for peer in peers {
            if peer.address == self_address || peers_online.contains(&peer.public_key) {
                continue;
            }
            iroha_logger::info!("Connecting {}", &peer.address);
            let connect = ConnectPeer { id: peer.clone() };
            self.broker.issue_send(connect).await;
        }
    }
}

impl<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait> Debug for Sumeragi<G, K, W> {
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

    use std::{
        collections::HashSet,
        sync::Arc,
        time::{Duration, Instant},
    };

    use eyre::{Result, WrapErr};
    use iroha_actor::broker::Broker;
    use iroha_crypto::{HashOf, KeyPair, SignatureOf};
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_logger::Instrument;
    use iroha_p2p::Post;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use tokio::{task, time};

    use super::view_change;
    use crate::{
        genesis::GenesisNetworkTrait,
        kura::KuraTrait,
        queue,
        sumeragi::{NetworkMessage, Role, Sumeragi, Topology, VotingBlock},
        wsv::WorldTrait,
        VersionedAcceptedTransaction, VersionedValidBlock,
    };

    declare_versioned_with_scale!(VersionedMessage 1..2, Debug, Clone, iroha_derive::FromVariant, iroha_actor::Message);

    impl VersionedMessage {
        /// Same as [`as_v1`](`VersionedMessage::as_v1()`) but also does conversion
        pub const fn as_inner_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// Same as [`as_inner_v1`](`VersionedMessage::as_inner_v1()`) but returns mutable reference
        pub fn as_mut_inner_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// Same as [`into_v1`](`VersionedMessage::into_v1()`) but also does conversion
        pub fn into_inner_v1(self) -> Message {
            match self {
                Self::V1(v1) => v1.0,
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
                id: peer.clone(),
            };
            broker.issue_send(post).await;
        }

        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        #[iroha_futures::telemetry_future]
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
            self.into_inner_v1().handle(sumeragi).await
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage", derive = "Debug, Clone")]
    #[derive(Io, Decode, Encode, Debug, Clone, FromVariant, iroha_actor::Message)]
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
    }

    impl Message {
        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        #[iroha_logger::log(skip(self, sumeragi))]
        #[iroha_futures::telemetry_future]
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
            match self {
                Message::BlockCreated(block_created) => block_created.handle(sumeragi).await,
                Message::BlockSigned(block_signed) => block_signed.handle(sumeragi).await,
                Message::BlockCommitted(block_committed) => block_committed.handle(sumeragi).await,
                Message::TransactionReceived(transaction_receipt) => {
                    transaction_receipt.handle(sumeragi).await
                }
                Message::TransactionForwarded(transaction_forwarded) => {
                    transaction_forwarded.handle(sumeragi).await
                }
                Message::ViewChangeSuggested(view_change_suggested) => {
                    view_change_suggested.handle(sumeragi).await
                }
            }
        }
    }

    /// `ViewChangeSuggested` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct ViewChangeSuggested {
        /// Proof of view change. As part of this message handling, all peers which agree with view change should sign it.
        pub proof: view_change::Proof,
    }

    impl ViewChangeSuggested {
        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail during signing.
        #[iroha_futures::telemetry_future]
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
            use view_change::Reason::*;

            if !self.proof.has_same_state(
                sumeragi.latest_block_hash(),
                &sumeragi.latest_view_change_hash(),
            ) {
                return Ok(());
            }
            let (should_vote, invalidated_block_hash) = match self.proof.reason() {
                CommitTimeout(reason) => (
                    Self::is_commit_timeout(reason, sumeragi).await,
                    Some(reason.hash),
                ),
                NoTransactionReceiptReceived(reason) => (
                    Self::is_no_transaction_receipt_received(reason, sumeragi).await,
                    None,
                ),
                BlockCreationTimeout(reason) => (
                    Self::is_block_creation_timeout(reason, sumeragi).await,
                    None,
                ),
            };
            let already_voted = self
                .proof
                .signatures()
                .contains(&sumeragi.key_pair.public_key);
            let view_change_suggested = if should_vote && !already_voted {
                let view_change_suggested = self.clone().sign(sumeragi.key_pair.clone())?;
                let peers = sumeragi.peers();
                let view_change_suggested_cloned = view_change_suggested.clone();
                // Sending message in parallel as it can block peer and during consensus whole blockchain.
                let broker = sumeragi.broker.clone();
                task::spawn(async move {
                    view_change_suggested_cloned
                        .send_to_all(&broker, peers)
                        .await
                });
                view_change_suggested
            } else {
                self.clone()
            };
            if view_change_suggested
                .proof
                .verify(&sumeragi.peers(), sumeragi.topology.max_faults())
            {
                sumeragi
                    .change_view(view_change_suggested.proof, invalidated_block_hash)
                    .await;
            }
            Ok(())
        }

        async fn is_commit_timeout<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            reason: &view_change::CommitTimeout,
            sumeragi: &Sumeragi<G, K, W>,
        ) -> bool {
            let voting_block = sumeragi.voting_block.read().await.clone();
            voting_block.map_or(false, |voting_block| {
                voting_block.block.hash() == reason.hash
                    && (current_time() - voting_block.voted_at) >= sumeragi.commit_time
            })
        }

        async fn is_block_creation_timeout<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            reason: &view_change::BlockCreationTimeout,
            sumeragi: &Sumeragi<G, K, W>,
        ) -> bool {
            reason.transaction_receipt.is_valid(&sumeragi.topology)
                && reason.transaction_receipt.is_block_should_be_created(sumeragi.block_time)
                // Block is not yet created
                && sumeragi.voting_block.write().await.is_none()
        }

        async fn is_no_transaction_receipt_received<
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        >(
            reason: &view_change::NoTransactionReceiptReceived,
            sumeragi: &Sumeragi<G, K, W>,
        ) -> bool {
            let current_time = Instant::now();
            // Due to the fact that transactions are all the time gossiped -
            // if the leader is not sending a receipt for some transaction every peer will know it.
            // And therefore will have it in `transactions_awaiting_receipts`.
            // If it doesn't have it then either this peer is faulty or the one sending this message is faulty.
            let sent_at = if let Some(sent_at) =
                sumeragi.txs_awaiting_receipts.get(&reason.transaction_hash)
            {
                sent_at.to_owned()
            } else {
                return false;
            };

            current_time.duration_since(sent_at) >= sumeragi.tx_receipt_time
        }

        fn sign(self, key_pair: KeyPair) -> Result<Self> {
            self.proof.sign(key_pair).map(|proof| Self { proof })
        }

        async fn send_to_all(&self, broker: &Broker, peers: HashSet<PeerId>) {
            let view_change_suggested =
                VersionedMessage::from(Message::ViewChangeSuggested(self.clone()));
            futures::future::join_all(
                peers
                    .iter()
                    .map(|peer| view_change_suggested.clone().send_to(broker, peer)),
            )
            .await;
        }
    }

    impl From<view_change::Proof> for ViewChangeSuggested {
        fn from(proof: view_change::Proof) -> Self {
            ViewChangeSuggested { proof }
        }
    }

    /// `BlockCreated` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    #[non_exhaustive]
    pub struct BlockCreated {
        /// The corresponding block.
        pub block: VersionedValidBlock,
    }

    impl BlockCreated {
        fn update_view_changes<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) {
            let leader_view_changes = self.block.header().view_change_proofs.clone();
            #[allow(clippy::expect_used)]
            if leader_view_changes.len() > sumeragi.topology.view_change_proofs().len()
                && leader_view_changes.verify_with_state(
                    &sumeragi.peers(),
                    sumeragi.topology.max_faults(),
                    sumeragi.latest_block_hash(),
                )
            {
                iroha_logger::info!("Updating number of view changes on BlockCreated from leader. Number of view changes {} -> {}", sumeragi.topology.view_change_proofs().len(), leader_view_changes.len());
                sumeragi.topology = sumeragi
                    .topology
                    .clone()
                    .into_builder()
                    .with_view_changes(leader_view_changes)
                    .build()
                    .expect("When only changing view changes it should not fail.")
            }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        #[iroha_futures::telemetry_future]
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
            // There should be only one block in discussion during a round.
            if sumeragi.voting_block.read().await.is_some() {
                return Ok(());
            }

            for event in Vec::<Event>::from(&self.block) {
                iroha_logger::info!(?event, "Event happened");
                drop(sumeragi.events_sender.send(event));
            }
            self.update_view_changes(sumeragi);
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
                    role = ?network_topology.role(&sumeragi.peer_id),
                    "Signed block candidate with hash {}.",
                    self.block.hash(),
                );
                //TODO: send to set b so they can observe
            }
            let voting_block = VotingBlock::new(self.block.clone());
            *sumeragi.voting_block.write().await = Some(voting_block.clone());
            sumeragi
                .start_commit_countdown(
                    voting_block,
                    *sumeragi.latest_block_hash(),
                    sumeragi.latest_view_change_hash(),
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
    #[derive(Io, Decode, Encode, Debug, Clone)]
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
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
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
            entry.as_mut_inner_v1().signatures.extend(
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
                role = ?network_topology.role(&sumeragi.peer_id),
                "Received a vote for block with hash {}. Now it has {} signatures out of {} required (not counting ProxyTail signature).",
                block_hash,
                valid_signatures.len(),
                network_topology.min_votes_for_commit() - 1,
            );

            if valid_signatures.len() < network_topology.min_votes_for_commit() as usize - 1 {
                return Ok(());
            }

            let signatures = valid_signatures
                .into_iter()
                .map(SignatureOf::transmute)
                .collect();
            let mut block = entry.clone();
            block.as_mut_inner_v1().signatures = signatures;
            let block = block.sign(sumeragi.key_pair.clone())?;

            iroha_logger::info!(
                role = ?network_topology.role(&sumeragi.peer_id),
                "Block reached required number of votes. Block hash {}.",
                block_hash,
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
    #[derive(Io, Decode, Encode, Debug, Clone)]
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
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
        ) -> Result<()> {
            let network_topology =
                sumeragi.network_topology_current_or_genesis(self.block.header());
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
            if valid_signatures.len() >= network_topology.min_votes_for_commit() as usize
                && proxy_tail_signatures.len() == 1
                && sumeragi.latest_block_hash() == &self.block.header().previous_block_hash
            {
                let mut block = self.block.clone();
                block.as_mut_inner_v1().signatures.clear();
                block
                    .as_mut_inner_v1()
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
    #[derive(Io, Decode, Encode, Debug, Clone)]
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
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            self,
            sumeragi: &mut Sumeragi<G, K, W>,
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
                Err((tx, err)) => Err(err).wrap_err_with(|| {
                    format!("Failed to push tx with hash {} in queue", tx.hash())
                }),
            }
        }
    }

    /// `Message` structure describing a receipt sent by the leader to the peer it got this transaction from.
    #[derive(Io, Decode, Encode, Debug, Clone)]
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
        pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait>(
            &self,
            sumeragi: &mut Sumeragi<G, K, W>,
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
            let block_time = sumeragi.block_time;
            let transactions_awaiting_created_block =
                Arc::clone(&sumeragi.txs_awaiting_created_block);
            let tx_hash = self.hash;
            let block_creation_timeout = view_change::Proof::block_creation_timeout(
                self.clone(),
                sumeragi.latest_view_change_hash(),
                *sumeragi.latest_block_hash(),
                sumeragi.key_pair.clone(),
            )
            .wrap_err("Failed to put first signature.")?;
            transactions_awaiting_created_block.insert(tx_hash);
            let recipient_peers = sumeragi.topology.sorted_peers().to_vec();
            let broker = sumeragi.broker.clone();

            // Suspect leader if the block was not yet created
            task::spawn(
                async move {
                    time::sleep(block_time).await;
                    if !transactions_awaiting_created_block.contains(&tx_hash) {
                        return;
                    }

                    iroha_logger::warn!("Block creation timeout detected!");
                    let block_creation_timeout_message = VersionedMessage::from(
                        Message::ViewChangeSuggested(block_creation_timeout.into()),
                    );
                    futures::future::join_all(recipient_peers.iter().map(|peer| {
                        block_creation_timeout_message
                            .clone()
                            .send_to(&broker, peer)
                    }))
                    .await;
                }
                .in_current_span(),
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
    const DEFAULT_COMMIT_TIME_MS: u64 = 1000;
    const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 200;
    const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);
    const DEFAULT_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE: u64 = 1;
    const DEFAULT_MAILBOX_SIZE: usize = 100;

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Clone, Debug, Deserialize, Serialize, Configurable, PartialEq, Eq)]
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
            }
        }
    }

    impl SumeragiConfiguration {
        /// Set `trusted_peers` configuration parameter - will overwrite the existing one.
        pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
            self.trusted_peers.peers = trusted_peers.into_iter().collect();
        }

        /// Calculate `max_faulty_peers` configuration parameter as per (f-1)/3.
        pub fn max_faulty_peers(&self) -> u32 {
            #![allow(clippy::integer_division, clippy::cast_possible_truncation)]
            (self.trusted_peers.peers.len() as u32 - 1) / 3
        }

        /// Time estimation from receiving a transaction to storing it in a block on all peers for the "sunny day" scenario.
        pub const fn pipeline_time_ms(&self) -> u64 {
            self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
        }
    }

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Default, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
