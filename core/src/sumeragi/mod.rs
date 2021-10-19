//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{self, Debug, Formatter},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use eyre::{eyre, Context as EyreContext, Result};
use futures::{prelude::*, stream::futures_unordered::FuturesUnordered};
use iroha_actor::{broker::*, prelude::*};
use iroha_crypto::{HashOf, KeyPair, SignatureOf};
use iroha_data_model::{events::Event, peer::Id as PeerId, transaction::VersionedTransaction};
use iroha_p2p::ConnectPeer;
use network_topology::{Role, Topology};
use tokio::task;

pub mod network_topology;
pub mod view_change;

pub use config::Configuration;

use self::{
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::{BlockHeader, ChainedBlock, EmptyChainHash, VersionedPendingBlock},
    event::EventsSender,
    genesis::GenesisNetworkTrait,
    kura::StoreBlock,
    prelude::*,
    queue::{self, Queue},
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

/// Remainder message of timeout of block commit
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CommitTimeout {
    /// Previous voting block
    pub old_block: VotingBlock,
    /// last committed block
    pub last_block: HashOf<VersionedCommittedBlock>,
    /// Last proof of view change
    pub last_view_change: HashOf<Proof>,
}

/// Remainder message of timeout of receiving receipt for transaction
#[derive(Debug, Clone, Copy, iroha_actor::Message)]
pub struct TxReceiptTimeout(pub HashOf<VersionedTransaction>);

/// Remainder message of timeout of creating block
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct BlockCreationTimeout(pub TransactionReceipt);

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi<G, W>
where
    G: GenesisNetworkTrait,
    W: WorldTrait,
{
    key_pair: KeyPair,
    /// Queue
    pub queue: Arc<Queue>,
    /// network topology
    pub topology: Topology,
    /// Peer id
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    voting_block: Option<VotingBlock>,
    /// This field is used to count votes when the peer is a proxy tail role.
    votes_for_blocks: BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
    events_sender: EventsSender,
    /// World state view
    pub wsv: Arc<WorldStateView<W>>,
    txs_awaiting_receipts: HashMap<HashOf<VersionedTransaction>, Instant>,
    txs_awaiting_created_block: HashSet<HashOf<VersionedTransaction>>,
    commit_time: Duration,
    tx_receipt_time: Duration,
    block_time: Duration,
    block_height: u64,
    /// Invalidated blocks' hashes
    pub invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    is_instruction_allowed: Arc<IsInstructionAllowedBoxed<W>>,
    is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
    max_instruction_number: u64,
    /// Genesis network
    pub genesis_network: Option<G>,
    /// Broker
    pub broker: Broker,
    /// Network address
    pub network: Addr<IrohaNetwork>,
    mailbox: usize,
}

/// Generic sumeragi trait
pub trait SumeragiTrait:
    Actor
    + ContextHandler<UpdateNetworkTopology, Result = ()>
    + ContextHandler<Init, Result = ()>
    + ContextHandler<CommitBlock, Result = ()>
    + ContextHandler<GetNetworkTopology, Result = Topology>
    + ContextHandler<GetSortedPeers, Result = Vec<PeerId>>
    + ContextHandler<IsLeader, Result = bool>
    + ContextHandler<GetLeader, Result = PeerId>
    + ContextHandler<NetworkMessage, Result = ()>
    + ContextHandler<CommitTimeout, Result = ()>
    + ContextHandler<TxReceiptTimeout, Result = ()>
    + ContextHandler<BlockCreationTimeout, Result = ()>
    + ContextHandler<Gossip, Result = ()>
    + Debug
{
    /// Genesis for sending genesis txs
    type GenesisNetwork: GenesisNetworkTrait;
    /// World for updating WSV after block commitment
    type World: WorldTrait;

    /// Default `Sumeragi` constructor.
    ///
    /// # Errors
    /// Can fail during initing network topology
    #[allow(clippy::too_many_arguments)]
    fn from_configuration(
        configuration: &Configuration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<Self::World>>,
        is_instruction_allowed: IsInstructionAllowedBoxed<Self::World>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<Self::World>>,
        genesis_network: Option<Self::GenesisNetwork>,
        queue: Arc<Queue>,
        broker: Broker,
        network: Addr<IrohaNetwork>,
        //TODO: separate initialization from construction and do not return Result in `new`
    ) -> Result<Self>;
}

impl<G: GenesisNetworkTrait, W: WorldTrait> SumeragiTrait for Sumeragi<G, W> {
    type GenesisNetwork = G;
    type World = W;

    fn from_configuration(
        configuration: &Configuration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<W>>,
        is_instruction_allowed: IsInstructionAllowedBoxed<W>,
        is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
        genesis_network: Option<G>,
        queue: Arc<Queue>,
        broker: Broker,
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
            voting_block: None,
            votes_for_blocks: BTreeMap::new(),
            events_sender,
            wsv,
            txs_awaiting_receipts: HashMap::new(),
            txs_awaiting_created_block: HashSet::new(),
            commit_time: Duration::from_millis(configuration.commit_time_ms),
            tx_receipt_time: Duration::from_millis(configuration.tx_receipt_time_ms),
            block_time: Duration::from_millis(configuration.block_time_ms),
            block_height: 0,
            invalidated_blocks_hashes: Vec::new(),
            is_instruction_allowed: Arc::new(is_instruction_allowed),
            is_query_allowed,
            max_instruction_number: configuration.max_instruction_number,
            genesis_network,
            queue,
            broker,
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

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Actor for Sumeragi<G, W> {
    fn mailbox_capacity(&self) -> usize {
        self.mailbox
    }

    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<Init, _>(ctx);
        self.broker.subscribe::<UpdateNetworkTopology, _>(ctx);
        self.broker.subscribe::<CommitBlock, _>(ctx);
        self.broker.subscribe::<NetworkMessage, _>(ctx);
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<CommitTimeout> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(
        &mut self,
        CommitTimeout {
            old_block,
            last_block,
            last_view_change,
        }: CommitTimeout,
    ) {
        let hash = match &self.voting_block {
            Some(new) => {
                let hash = new.block.hash();
                if old_block.block.hash() != hash {
                    return;
                }
                hash
            }
            None => return,
        };

        iroha_logger::warn!(voting_block = %hash, "Block commit timeout detected!");

        #[allow(clippy::expect_used)]
        let msg = view_change::Proof::commit_timeout(
            hash,
            last_view_change,
            last_block,
            self.key_pair.clone(),
        )
        .expect("Failed to sign CommitTimeout");
        self.broadcast_msg(ViewChangeSuggested::from(msg)).await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<TxReceiptTimeout> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, TxReceiptTimeout(hash): TxReceiptTimeout) {
        if !self.txs_awaiting_receipts.contains_key(&hash) {
            return;
        }

        iroha_logger::warn!(tx = %hash, "Transaction receipt timeout detected!");

        #[allow(clippy::expect_used)]
        let no_tx_receipt = view_change::Proof::no_transaction_receipt_received(
            hash,
            self.latest_view_change_hash(),
            *self.latest_block_hash(),
            self.key_pair.clone(),
        )
        .expect("Failed to put first signature.");

        self.broadcast_msg(ViewChangeSuggested::from(no_tx_receipt))
            .await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<BlockCreationTimeout> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, BlockCreationTimeout(receipt): BlockCreationTimeout) {
        if !self.txs_awaiting_created_block.contains(&receipt.hash) {
            return;
        }

        iroha_logger::warn!(tx = %receipt.hash, "Block creation timeout detected!");

        #[allow(clippy::expect_used)]
        let block_creation_timeout = view_change::Proof::block_creation_timeout(
            receipt,
            self.latest_view_change_hash(),
            *self.latest_block_hash(),
            self.key_pair.clone(),
        )
        .expect("Failed to put first signature.");

        self.broadcast_msg(ViewChangeSuggested::from(block_creation_timeout))
            .await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<UpdateNetworkTopology> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, UpdateNetworkTopology: UpdateNetworkTopology) {
        self.update_network_topology().await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> ContextHandler<Voting> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, ctx: &mut Context<Self>, Voting: Voting) {
        if self.voting_in_progress().await {
            return;
        }
        let txs = self.queue.get_transactions_for_block(&*self.wsv);
        if let Err(error) = self.round(ctx, txs).await {
            iroha_logger::error!(%error, "Round failed");
        }
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<Gossip> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, Gossip: Gossip) {
        let txs = self.queue.all_transactions(&*self.wsv);
        self.gossip_transactions(&txs[..]).await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<ConnectPeers> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, ConnectPeers: ConnectPeers) {
        self.connect_peers().await;
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> ContextHandler<Init> for Sumeragi<G, W> {
    type Result = ();
    async fn handle(&mut self, ctx: &mut Context<Self>, Init { last_block, height }: Init) {
        iroha_logger::info!("Starting Sumeragi");
        self.connect_peers().await;

        if height != 0 && *last_block != Hash([0; 32]) {
            self.init(last_block, height);
        } else if let Some(genesis_network) = self.genesis_network.take() {
            let addr = self.network.clone();
            if let Err(err) = genesis_network
                .submit_transactions(&mut self, ctx, addr)
                .await
            {
                iroha_logger::error!(%err, "Failed to submit genesis transactions")
            }
        }
        self.update_network_topology().await;
        ctx.notify_every::<ConnectPeers>(PEERS_CONNECT_INTERVAL);
        ctx.notify_every::<Voting>(TX_RETRIEVAL_INTERVAL);
        ctx.notify_every::<Gossip>(TX_GOSSIP_INTERVAL);
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<GetSortedPeers> for Sumeragi<G, W> {
    type Result = Vec<PeerId>;
    async fn handle(&mut self, GetSortedPeers: GetSortedPeers) -> Vec<PeerId> {
        self.topology.sorted_peers().to_vec()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<GetNetworkTopology> for Sumeragi<G, W> {
    type Result = Topology;
    async fn handle(&mut self, GetNetworkTopology(header): GetNetworkTopology) -> Topology {
        self.network_topology_current_or_genesis(&header)
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<CommitBlock> for Sumeragi<G, W> {
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
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<IsLeader> for Sumeragi<G, W> {
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
impl<G: GenesisNetworkTrait, W: WorldTrait> Handler<GetLeader> for Sumeragi<G, W> {
    type Result = PeerId;
    async fn handle(&mut self, GetLeader: GetLeader) -> PeerId {
        self.topology.leader().clone()
    }
}

#[async_trait::async_trait]
impl<G: GenesisNetworkTrait, W: WorldTrait> ContextHandler<NetworkMessage> for Sumeragi<G, W> {
    type Result = ();

    async fn handle(&mut self, ctx: &mut Context<Self>, msg: NetworkMessage) -> Self::Result {
        use NetworkMessage::*;

        match msg {
            SumeragiMessage(msg) => {
                let msg = msg.into_inner_v1();
                iroha_logger::trace!(role=?self.topology.role(&self.peer_id), ?msg);
                if let Err(error) = self.handle_msg(msg, ctx).await {
                    iroha_logger::error!(%error, "Handle message failed");
                }
            }
            BlockSync(data) => self.broker.issue_send(data.into_inner_v1()).await,
            Health => {}
        }
    }
}

impl<G: GenesisNetworkTrait, W: WorldTrait> Sumeragi<G, W> {
    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block: HashOf<VersionedCommittedBlock>, block_height: u64) {
        self.block_height = block_height;
        self.topology.apply_block(latest_block);
    }

    #[allow(clippy::expect_used)]
    fn update_view_changes(&mut self, header: &BlockHeader) -> Topology {
        let proof = header.view_change_proofs.clone();
        if proof.len() > self.topology.view_change_proofs().len()
            && proof.verify_with_state(
                &self.peers(),
                self.topology.max_faults(),
                self.latest_block_hash(),
            )
        {
            iroha_logger::info!("Updating number of view changes on BlockCreated from leader. Number of view changes {} -> {}", self.topology.view_change_proofs().len(), proof.len());
            self.topology = self
                .topology
                .clone()
                .into_builder()
                .with_view_changes(proof)
                .build()
                .expect("When only changing view changes it should not fail.")
        }

        self.network_topology_current_or_genesis(header)
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
    pub async fn voting_in_progress(&mut self) -> bool {
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
    #[iroha_logger::log(skip(self, transactions, genesis_topology))]
    pub async fn start_genesis_round<S: SumeragiTrait>(
        &mut self,
        ctx: &mut Context<S>,
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
                ctx,
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
    pub async fn round<S: SumeragiTrait>(
        &mut self,
        ctx: &mut Context<S>,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Result<()> {
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
            self.validate_and_publish_created_block(ctx, block).await?;
        } else {
            self.forward_txs_to_leader(ctx, &transactions).await;
        }
        Ok(())
    }

    async fn send_msg(&self, msg: impl Into<Message> + Send, peer: PeerId) {
        let msg = VersionedMessage::from(msg.into());
        let post = iroha_p2p::Post {
            data: NetworkMessage::SumeragiMessage(Box::new(msg)),
            id: peer.clone(),
        };
        self.broker.issue_send(post).await;
    }

    async fn broadcast_msg_to(
        &self,
        msg: impl Into<Message> + Send,
        ids: impl Iterator<Item = &PeerId> + Send,
    ) {
        let msg = msg.into();
        ids.cloned()
            .map(|id| self.send_msg(msg.clone(), id))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await
    }

    /// Returns true if block can be send for discussion
    fn check_block(&self, block: &VersionedValidBlock) -> bool {
        block.validation_check(
            &self.wsv,
            self.latest_block_hash(),
            &self.latest_view_change_hash(),
            self.block_height,
            self.max_instruction_number,
        )
    }

    async fn revalidate_and_sign(&self, block: VersionedValidBlock) -> Result<BlockSigned> {
        let wsv_clone = Arc::clone(&self.wsv);
        let is_instruction_allowed_clone = Arc::clone(&self.is_instruction_allowed);
        let is_query_allowed_clone = Arc::clone(&self.is_query_allowed);
        let key_pair_clone = self.key_pair.clone();
        task::spawn_blocking(move || -> Result<BlockSigned> {
            block
                .revalidate(
                    &*wsv_clone,
                    &*is_instruction_allowed_clone,
                    &*is_query_allowed_clone,
                )
                .sign(key_pair_clone)
                .map(Into::into)
        })
        .await?
    }

    async fn handle_block_create<S: SumeragiTrait>(
        &mut self,
        BlockCreated { block }: BlockCreated,
        ctx: &mut Context<S>,
    ) -> Result<()> {
        // There should be only one block in discussion during a round.
        if self.voting_block.is_some() {
            return Ok(());
        }

        for event in Vec::<Event>::from(&block) {
            iroha_logger::info!(?event, "Event happened");
            drop(self.events_sender.send(event));
        }

        let network_topology = self.update_view_changes(block.header());
        if !network_topology.is_signed_by_leader(block.verified_signatures()) {
            iroha_logger::error!(
                role = ?self.topology.role(&self.peer_id),
                "Rejecting Block as it is not signed by leader.",
            );
            return Ok(());
        }

        self.txs_awaiting_created_block.clear();

        if network_topology.role(&self.peer_id) == Role::ValidatingPeer && self.check_block(&block)
        {
            let signed = self.revalidate_and_sign(block.clone()).await?;
            let hash = signed.block.hash();
            self.send_msg(signed, network_topology.proxy_tail().clone())
                .await;
            iroha_logger::info!(
                role = ?network_topology.role(&self.peer_id),
                %hash,
                "Signed block candidate.",
            );
            //TODO: send to set b so they can observe
        }

        let block = VotingBlock::new(block);
        self.voting_block = Some(block.clone());
        self.start_commit_countdown(
            ctx,
            block,
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
        )
        .await;
        Ok(())
    }

    async fn get_voting_block<'a, 'b>(
        votes: &'a mut BTreeMap<HashOf<VersionedValidBlock>, VersionedValidBlock>,
        block: VersionedValidBlock,
        network: &'b network_topology::Topology,
    ) -> &'a mut VersionedValidBlock {
        use std::collections::btree_map::Entry;

        let block = block.remove_invalid_signatures(network);

        match votes.entry(block.hash()) {
            Entry::Vacant(ent) => ent.insert(block),
            Entry::Occupied(ent) => {
                let ent = ent.into_mut();
                ent.as_mut_inner_v1().signatures.extend(
                    block
                        .into_inner_v1()
                        .signatures
                        .into_iter()
                        .map(SignatureOf::transmute),
                );
                ent
            }
        }
    }

    async fn handle_block_signed(&mut self, BlockSigned { block }: BlockSigned) -> Result<()> {
        let network_topology = self.network_topology_current_or_genesis(block.header());
        if Role::ProxyTail != network_topology.role(&self.peer_id) {
            return Ok(());
        }
        let block =
            Self::get_voting_block(&mut self.votes_for_blocks, block, &network_topology).await;
        let hash = block.hash();
        let valid_signatures = network_topology
            .filter_signatures_by_roles(&[Role::ValidatingPeer, Role::Leader], block.signatures());

        iroha_logger::info!(
            role = ?network_topology.role(&self.peer_id),
            block = %hash,
            "Received a vote for block. Now it has {} signatures out of {} required (not counting ProxyTail signature).",
            valid_signatures.len(),
            network_topology.min_votes_for_commit() - 1,
        );

        if valid_signatures.len() < network_topology.min_votes_for_commit() as usize - 1 {
            return Ok(());
        }

        let block = block.clone().sign(self.key_pair.clone())?;

        iroha_logger::info!(
            role = ?network_topology.role(&self.peer_id),
            block = %hash,
            "Block reached required number of votes",
        );

        self.broadcast_msg_to(
            BlockCommitted::from(block.clone()),
            network_topology
                .validating_peers()
                .iter()
                .chain(std::iter::once(network_topology.leader()))
                .chain(network_topology.peers_set_b()),
        )
        .await;
        self.votes_for_blocks.clear();
        self.commit_block(block.clone()).await;

        Ok(())
    }

    async fn handle_block_committed(&mut self, BlockCommitted { block }: BlockCommitted) {
        let network_topology = self.network_topology_current_or_genesis(block.header());
        let block = block.remove_invalid_signatures(&network_topology);

        let proxy_tail_signatures = network_topology
            .filter_signatures_by_roles(&[Role::ProxyTail], block.verified_signatures());
        if block.n_signatures() >= network_topology.min_votes_for_commit() as usize
            && proxy_tail_signatures.len() == 1
            && self.latest_block_hash() == &block.header().previous_block_hash
        {
            self.commit_block(block).await;
        }
    }

    async fn handle_tx_received<S: SumeragiTrait>(
        &mut self,
        ctx: &mut Context<S>,
        receipt: TransactionReceipt,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .wrap_err("Failed to get System Time.")?;

        // Implausible time in the future, means that the leader lies
        if self.topology.role(&self.peer_id) == Role::Leader
            || receipt.received_at > now
            || !receipt.is_valid(&self.topology)
            || !self.txs_awaiting_receipts.contains_key(&receipt.hash)
        {
            return Ok(());
        }

        self.txs_awaiting_receipts.remove(&receipt.hash);
        self.txs_awaiting_created_block.insert(receipt.hash);
        ctx.notify_later(BlockCreationTimeout(receipt), self.block_time);
        Ok(())
    }

    async fn handle_view_change(&mut self, view_change: ViewChangeSuggested) -> Result<()> {
        use view_change::Reason::*;

        if !view_change
            .proof
            .has_same_state(self.latest_block_hash(), &self.latest_view_change_hash())
        {
            return Ok(());
        }
        let (should_vote, invalidated_block_hash) = match view_change.proof.reason() {
            CommitTimeout(reason) => (
                ViewChangeSuggested::is_commit_timeout(reason, self).await,
                Some(reason.hash),
            ),
            NoTransactionReceiptReceived(reason) => (
                ViewChangeSuggested::is_no_transaction_receipt_received(reason, self).await,
                None,
            ),
            BlockCreationTimeout(reason) => (
                ViewChangeSuggested::is_block_creation_timeout(reason, self).await,
                None,
            ),
        };
        let already_voted = view_change
            .proof
            .signatures()
            .contains(&self.key_pair.public_key);
        let view_change = if should_vote && !already_voted {
            let view_change = view_change.sign(self.key_pair.clone())?;
            self.broadcast_msg(view_change.clone()).await;
            view_change
        } else {
            view_change.clone()
        };

        if view_change
            .proof
            .verify(&self.peers(), self.topology.max_faults())
        {
            self.change_view(view_change.proof, invalidated_block_hash)
                .await;
        }
        Ok(())
    }

    /// Handles this message as part of `Sumeragi` consensus.
    /// # Errors
    /// Fails if message handling fails
    pub async fn handle_msg<S: SumeragiTrait>(
        &mut self,
        msg: Message,
        ctx: &mut Context<S>,
    ) -> Result<()> {
        match msg {
            Message::BlockCreated(msg) => self.handle_block_create(msg, ctx).await,
            Message::BlockSigned(msg) => self.handle_block_signed(msg).await,
            Message::BlockCommitted(msg) => {
                self.handle_block_committed(msg).await;
                Ok(())
            }
            Message::TransactionReceived(msg) => self.handle_tx_received(ctx, msg).await,
            Message::TransactionForwarded(TransactionForwarded { transaction, peer }) => {
                match self.queue.push(transaction.clone(), &*self.wsv) {
                    Ok(()) if self.is_leader() => {
                        let receipt = TransactionReceipt::new(&transaction, &self.key_pair)?;
                        self.send_msg(receipt, peer).await;
                        Ok(())
                    }
                    Err((_, queue::Error::InBlockchain)) | Ok(()) => Ok(()),
                    Err((tx, err)) => Err(err).wrap_err_with(|| {
                        format!("Failed to push tx with hash {} in queue", tx.hash())
                    }),
                }
            }
            Message::ViewChangeSuggested(msg) => self.handle_view_change(msg).await,
        }
    }

    /// Forwards transactions to the leader and waits for receipts.
    #[iroha_futures::telemetry_future]
    pub async fn forward_txs_to_leader<S: SumeragiTrait>(
        &mut self,
        ctx: &mut Context<S>,
        txs: &[VersionedAcceptedTransaction],
    ) {
        let mut to_forward = Vec::new();

        for tx in txs {
            let hash = tx.hash();
            if self.txs_awaiting_receipts.contains_key(&hash) {
                continue;
            }
            iroha_logger::info!(
                role=?self.topology.role(&self.peer_id),
                addr=%self.peer_id.address,
                leader=%self.topology.leader().address,
                tx=%hash,
                "Forwarding tx to leader",
            );
            if let Ok(true) = tx.check_signature_condition(&self.wsv) {
                self.txs_awaiting_receipts.insert(hash, Instant::now());
            }
            ctx.notify_later(TxReceiptTimeout(hash), self.tx_receipt_time);
            to_forward.push(TransactionForwarded::new(tx, &self.peer_id));
        }

        to_forward
            .into_iter()
            .map(|tx| self.send_msg(tx, self.topology.leader().clone()))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await
    }

    async fn broadcast_msg(&self, msg: impl Into<Message> + Send) {
        let msg = msg.into();
        self.topology
            .sorted_peers()
            .iter()
            .cloned()
            .map(|peer| self.send_msg(msg.clone(), peer))
            .collect::<FuturesUnordered<_>>()
            .collect::<()>()
            .await
    }

    async fn broadcast_msgs(&self, msgs: impl IntoIterator<Item = impl Into<Message>> + Send) {
        let msgs = msgs.into_iter().map(Into::into).collect::<Vec<_>>();
        let peers = self.topology.sorted_peers();
        peers
            .iter()
            .flat_map(|peer| msgs.clone().into_iter().map(move |msg| (peer, msg)))
            .map(|(peer, msg)| self.send_msg(msg, peer.clone()))
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
    pub async fn validate_and_publish_created_block<S: SumeragiTrait>(
        &mut self,
        ctx: &mut Context<S>,
        block: ChainedBlock,
    ) -> Result<()> {
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
        self.voting_block = Some(voting_block.clone());
        self.broadcast_msg(BlockCreated::from(block.sign(self.key_pair.clone())?))
            .await;
        self.start_commit_countdown(
            ctx,
            voting_block,
            *self.latest_block_hash(),
            self.latest_view_change_hash(),
        )
        .await;
        Ok(())
    }

    /// Starts countdown for a period in which the `old_block` should be committed.
    #[iroha_futures::telemetry_future]
    #[iroha_logger::log(skip(self, old_block))]
    pub async fn start_commit_countdown<S: SumeragiTrait>(
        &self,
        ctx: &mut Context<S>,
        old_block: VotingBlock,
        last_block: HashOf<VersionedCommittedBlock>,
        last_view_change: HashOf<Proof>,
    ) {
        let msg = CommitTimeout {
            old_block,
            last_block,
            last_view_change,
        };
        ctx.notify_later(msg, self.commit_time);
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
        self.voting_block = None;
        self.votes_for_blocks.clear();
    }

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
        self.voting_block = None;
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
        let peers = self.topology.sorted_peers().to_owned();
        let self_address = self.peer_id.address.clone();

        #[allow(clippy::expect_used)]
        let peers_online = self
            .network
            .send(iroha_p2p::network::GetConnectedPeers)
            .await
            .expect("Could not get connected peers from Network!")
            .peers;

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

impl<G: GenesisNetworkTrait, W: WorldTrait> Debug for Sumeragi<G, W> {
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
            voted_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time."),
            block,
        }
    }
}

/// Contains message structures for p2p communication during consensus.
pub mod message {
    #![allow(clippy::module_name_repetitions)]

    use std::time::{Duration, Instant, SystemTime};

    use eyre::Result;
    use iroha_crypto::{HashOf, KeyPair, SignatureOf};
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use super::view_change;
    use crate::{
        genesis::GenesisNetworkTrait,
        sumeragi::{Role, Sumeragi, Topology},
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

    /// `ViewChangeSuggested` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct ViewChangeSuggested {
        /// Proof of view change. As part of this message handling, all peers which agree with view change should sign it.
        pub proof: view_change::Proof,
    }

    impl ViewChangeSuggested {
        /// Checks whether block commit timeout should be triggered by this time
        pub async fn is_commit_timeout<G: GenesisNetworkTrait, W: WorldTrait>(
            reason: &view_change::CommitTimeout,
            sumeragi: &Sumeragi<G, W>,
        ) -> bool {
            let voting_block = sumeragi.voting_block.clone();
            #[allow(clippy::expect_used)]
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.");
            voting_block.map_or(false, |voting_block| {
                voting_block.block.hash() == reason.hash
                    && (current_time - voting_block.voted_at) >= sumeragi.commit_time
            })
        }

        /// Checks whether block creation timeout should be triggered by this time
        pub async fn is_block_creation_timeout<G: GenesisNetworkTrait, W: WorldTrait>(
            reason: &view_change::BlockCreationTimeout,
            sumeragi: &Sumeragi<G, W>,
        ) -> bool {
            reason.transaction_receipt.is_valid(&sumeragi.topology)
                && reason.transaction_receipt.is_block_should_be_created(sumeragi.block_time)
                // Block is not yet created
                && sumeragi.voting_block.is_none()
        }

        /// Checks whether transaction receipt should be received by this time
        pub async fn is_no_transaction_receipt_received<G: GenesisNetworkTrait, W: WorldTrait>(
            reason: &view_change::NoTransactionReceiptReceived,
            sumeragi: &Sumeragi<G, W>,
        ) -> bool {
            let current_time = Instant::now();
            // Due to the fact that transactions are all the time gossiped -
            // if the leader is not sending a receipt for some transaction every peer will know it.
            // And therefore will have it in `transactions_awaiting_receipts`.
            // If it doesn't have it then either this peer is faulty or the one sending this message is faulty.
            let sent_at = if let Some(sent_at) =
                sumeragi.txs_awaiting_receipts.get(&reason.transaction_hash)
            {
                *sent_at
            } else {
                return false;
            };

            current_time.duration_since(sent_at) >= sumeragi.tx_receipt_time
        }

        /// Tries to sign
        /// # Errors
        /// Fails due to signing
        pub fn sign(self, key_pair: KeyPair) -> Result<Self> {
            self.proof.sign(key_pair).map(|proof| Self { proof })
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
                received_at: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time."),
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
            #[allow(clippy::expect_used)]
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.");
            (current_time - self.received_at) >= block_time
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
    #[derive(Clone, Debug, Deserialize, Serialize, Configurable)]
    #[serde(default)]
    #[serde(rename_all = "UPPERCASE")]
    #[config(env_prefix = "SUMERAGI_")]
    pub struct Configuration {
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

    impl Default for Configuration {
        fn default() -> Self {
            Self {
                key_pair: KeyPair::default(),
                trusted_peers: TrustedPeers::default(),
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

    impl Configuration {
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
    #[derive(Default, Clone, Debug, Deserialize, Serialize)]
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
}
