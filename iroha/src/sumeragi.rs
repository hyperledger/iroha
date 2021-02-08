//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use self::message::*;
use crate::{
    block::{ChainedBlock, PendingBlock},
    event::EventsSender,
    permissions::PermissionsValidatorBox,
    prelude::*,
};
use async_std::sync::RwLock;
use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::prelude::*;
use iroha_derive::*;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    iter,
    sync::Arc,
    time::{Duration, SystemTime},
};

trait Consensus {
    fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Option<PendingBlock>;
}

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi {
    key_pair: KeyPair,
    /// The current topology of the peer to peer network.
    pub network_topology: InitializedNetworkTopology,
    /// The peer id of myself.
    pub peer_id: PeerId,
    /// The block in discussion this round, received from a leader.
    voting_block: Arc<RwLock<Option<VotingBlock>>>,
    /// This field is used to count votes when the peer is a proxy tail role.
    votes_for_blocks: BTreeMap<Hash, ValidBlock>,
    blocks_sender: Arc<RwLock<ValidBlockSender>>,
    events_sender: EventsSender,
    transactions_sender: TransactionSender,
    world_state_view: Arc<RwLock<WorldStateView>>,
    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    transactions_awaiting_receipts: Arc<RwLock<BTreeSet<Hash>>>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in CreatedBlock.
    transactions_awaiting_created_block: Arc<RwLock<BTreeSet<Hash>>>,
    commit_time: Duration,
    tx_receipt_time: Duration,
    block_time: Duration,
    //TODO: Think about moving `latest_block_hash` to `NetworkTopology` or get it from wsv so there is no controversy
    latest_block_hash: Hash,
    block_height: u64,
    /// Number of view changes after the previous block was committed
    number_of_view_changes: u32,
    invalidated_blocks_hashes: Vec<Hash>,
    permissions_validator: PermissionsValidatorBox,
}

impl Sumeragi {
    /// Default `Sumeragi` constructor.
    pub fn from_configuration(
        configuration: &config::SumeragiConfiguration,
        blocks_sender: Arc<RwLock<ValidBlockSender>>,
        events_sender: EventsSender,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transactions_sender: TransactionSender,
        permissions_validator: PermissionsValidatorBox,
        //TODO: separate initialization from construction and do not return Result in `new`
    ) -> Result<Self, String> {
        Ok(Self {
            key_pair: configuration.key_pair.clone(),
            network_topology: NetworkTopology::new(
                &configuration.trusted_peers,
                None,
                configuration.max_faulty_peers,
            )
            .init()?,
            peer_id: configuration.peer_id.clone(),
            voting_block: Arc::new(RwLock::new(None)),
            votes_for_blocks: BTreeMap::new(),
            blocks_sender,
            events_sender,
            world_state_view,
            transactions_awaiting_receipts: Arc::new(RwLock::new(BTreeSet::new())),
            transactions_awaiting_created_block: Arc::new(RwLock::new(BTreeSet::new())),
            commit_time: Duration::from_millis(configuration.commit_time_ms),
            transactions_sender,
            tx_receipt_time: Duration::from_millis(configuration.tx_receipt_time_ms),
            block_time: Duration::from_millis(configuration.block_time_ms),
            latest_block_hash: Hash([0u8; 32]),
            block_height: 0,
            number_of_view_changes: 0,
            invalidated_blocks_hashes: Vec::new(),
            permissions_validator,
        })
    }

    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block_hash: Hash, block_height: u64) {
        self.block_height = block_height;
        self.latest_block_hash = latest_block_hash;
        self.network_topology.sort_peers(Some(latest_block_hash));
    }

    /// Updates network topology by taking the actual list of peers from `WorldStateView`.
    /// Updates it only if the new peers were added, otherwise leaves the order unchanged.
    pub async fn update_network_topology(&mut self) {
        let wsv_peers = self
            .world_state_view
            .read()
            .await
            .read_world()
            .trusted_peers_ids
            .clone();
        self.network_topology
            .update(wsv_peers, self.latest_block_hash);
    }

    /// Returns `true` if some block is in discussion, `false` otherwise.
    pub async fn voting_in_progress(&self) -> bool {
        self.voting_block.write().await.is_some()
    }

    /// Assumes this peer is a leader and starts the round with the given `genesis_topology`.
    pub async fn start_genesis_round(
        &mut self,
        transactions: Vec<AcceptedTransaction>,
        genesis_topology: InitializedNetworkTopology,
    ) -> Result<(), String> {
        if transactions.is_empty() {
            Err("Genesis transactions set is empty.".to_string())
        } else if genesis_topology.leader() != &self.peer_id {
            Err(format!(
                "Incorrect network topology this peer should be {:?} but is {:?}",
                Role::Leader,
                genesis_topology.role(&self.peer_id)
            ))
        } else if self.block_height > 0 {
            Err(format!(
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

    /// the leader of each round just uses the transactions they have at hand to create a block
    pub async fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Result<(), String> {
        if transactions.is_empty() {
            return Ok(());
        }
        if let Role::Leader = self.network_topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions).chain(
                self.block_height,
                self.latest_block_hash,
                self.number_of_view_changes,
                self.invalidated_blocks_hashes.clone(),
            );
            self.validate_and_publish_created_block(block).await
        } else {
            //Sends transactions to leader
            log::info!(
                "{:?} - Forwarding transactions to leader. Number of transactions to forward: {}",
                self.network_topology.role(&self.peer_id),
                transactions.len(),
            );
            let mut send_futures = Vec::new();
            for transaction in &transactions {
                send_futures.push(
                    Message::TransactionForwarded(TransactionForwarded {
                        transaction: transaction.clone(),
                        peer: self.peer_id.clone(),
                    })
                    .send_to(self.network_topology.leader()),
                );
                let _ = self
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .insert(transaction.hash());
                let transactions_awaiting_receipts = self.transactions_awaiting_receipts.clone();
                let mut no_tx_receipt = NoTransactionReceiptReceived::new(
                    &transaction,
                    self.network_topology.leader().clone(),
                );
                let role = self.network_topology.role(&self.peer_id);
                if role == Role::ValidatingPeer || role == Role::ProxyTail {
                    no_tx_receipt = no_tx_receipt
                        .sign(&self.key_pair)
                        .expect("Failed to put first signature.");
                }
                let recipient_peers = self.network_topology.sorted_peers.clone();
                let transaction_hash = transaction.hash();
                let peer_id = self.peer_id.clone();
                let tx_receipt_time = self.tx_receipt_time;
                let _ = async_std::task::spawn(async move {
                    async_std::task::sleep(tx_receipt_time).await;
                    if transactions_awaiting_receipts
                        .write()
                        .await
                        .contains(&transaction_hash)
                    {
                        let mut send_futures = Vec::new();
                        for peer in &recipient_peers {
                            if *peer != peer_id {
                                send_futures.push(
                                    Message::NoTransactionReceiptReceived(no_tx_receipt.clone())
                                        .send_to(peer),
                                );
                            }
                        }
                        let results = futures::future::join_all(send_futures).await;
                        results
                            .iter()
                            .filter(|result| result.is_err())
                            .for_each(|error_result| {
                                log::error!(
                                    "Failed to send NoTransactionReceiptReceived message to peers: {:?}",
                                    error_result
                                )
                            });
                    }
                });
            }
            let results = futures::future::join_all(send_futures).await;
            results
                .iter()
                .filter(|result| result.is_err())
                .for_each(|error_result| {
                    log::error!(
                        "Failed to send transactions to the leader: {:?}",
                        error_result
                    )
                });
            Ok(())
        }
    }

    /// Should be called by a leader to start the consensus round with `BlockCreated` message.
    pub async fn validate_and_publish_created_block(
        &mut self,
        block: ChainedBlock,
    ) -> Result<(), String> {
        let wsv = self.world_state_view.clone();
        let block = block.validate(&*wsv.read().await, &self.permissions_validator);
        let network_topology = self.network_topology_current_or_genesis(&block);
        log::info!(
            "{:?} - Created a block with hash {}.",
            network_topology.role(&self.peer_id),
            block.hash(),
        );
        for event in Vec::<Event>::from(&block.clone()) {
            self.events_sender.send(event).await;
        }
        if !network_topology.is_consensus_required() {
            self.commit_block(block).await;
            Ok(())
        } else {
            *self.voting_block.write().await = Some(VotingBlock::new(block.clone()));
            let message = Message::BlockCreated(block.clone().sign(&self.key_pair)?.into());
            let recipient_peers = network_topology.sorted_peers.clone();
            let mut send_futures = Vec::new();
            for peer in &recipient_peers {
                if self.peer_id != *peer {
                    send_futures.push(message.clone().send_to(peer));
                }
            }
            let results = futures::future::join_all(send_futures).await;
            results
                .iter()
                .filter(|result| result.is_err())
                .for_each(|error_result| {
                    log::error!("Failed to send BlockCreated messages: {:?}", error_result)
                });
            Ok(())
        }
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.
    #[log]
    pub async fn start_commit_countdown(&self, voting_block: VotingBlock) {
        let old_voting_block = voting_block;
        let voting_block = self.voting_block.clone();
        let key_pair = self.key_pair.clone();
        let recipient_peers = self.network_topology.sorted_peers.clone();
        let peer_id = self.peer_id.clone();
        let commit_time = self.commit_time;
        let _ = async_std::task::spawn(async move {
            async_std::task::sleep(commit_time).await;
            if let Some(voting_block) = voting_block.write().await.clone() {
                // If the block was not yet committed send commit timeout to other peers to initiate view change.
                if voting_block.block.hash() == old_voting_block.block.hash() {
                    let message = Message::CommitTimeout(
                        CommitTimeout::new(voting_block)
                            .sign(&key_pair)
                            .expect("Failed to sign CommitTimeout"),
                    );
                    let mut send_futures = Vec::new();
                    for peer in &recipient_peers {
                        if *peer != peer_id {
                            send_futures.push(message.clone().send_to(peer));
                        }
                    }
                    let results = futures::future::join_all(send_futures).await;
                    results
                        .iter()
                        .filter(|result| result.is_err())
                        .for_each(|error_result| {
                            log::error!("Failed to send CommitTimeout messages: {:?}", error_result)
                        });
                }
            }
        });
    }

    /// Commits `ValidBlock` and changes the state of the `Sumeragi` and its `NetworkTopology`.
    #[log]
    pub async fn commit_block(&mut self, block: ValidBlock) {
        let block_hash = block.hash();
        self.latest_block_hash = block_hash;
        self.invalidated_blocks_hashes.clear();
        self.transactions_awaiting_created_block
            .write()
            .await
            .clear();
        self.transactions_awaiting_receipts.write().await.clear();
        self.block_height = block.header.height;
        for event in Vec::<Event>::from(&block.clone().commit()) {
            self.events_sender.send(event).await;
        }
        self.blocks_sender.write().await.send(block).await;
        let previous_role = self.network_topology.role(&self.peer_id);
        self.network_topology
            .sort_peers(Some(self.latest_block_hash));
        log::info!(
            "{:?} - Commiting block with hash {}. New role: {:?}. New height: {}",
            previous_role,
            block_hash,
            self.network_topology.role(&self.peer_id),
            self.block_height,
        );
        *self.voting_block.write().await = None;
        self.number_of_view_changes = 0;
    }

    async fn change_view(&mut self) {
        self.transactions_awaiting_created_block
            .write()
            .await
            .clear();
        self.transactions_awaiting_receipts.write().await.clear();
        let previous_role = self.network_topology.role(&self.peer_id);
        self.network_topology.shift_peers_by_one();
        *self.voting_block.write().await = None;
        self.number_of_view_changes += 1;
        log::info!(
            "{:?} - Changing view at block with hash {}. New role: {:?}. Number of view changes (including this): {}",
            previous_role,
            self.latest_block_hash,
            self.network_topology.role(&self.peer_id),
            self.number_of_view_changes,
        );
    }

    /// If this peer is a leader in this round.
    pub fn is_leader(&self) -> bool {
        self.network_topology.role(&self.peer_id) == Role::Leader
    }

    /// Returns current network topology or genesis specific one, if the `block` is a genesis block.
    pub fn network_topology_current_or_genesis(
        &self,
        block: &ValidBlock,
    ) -> InitializedNetworkTopology {
        if block.header.is_genesis() && self.block_height == 0 {
            if let Some(genesis_topology) = block.header.genesis_topology.clone() {
                log::info!("Using network topology from genesis block.");
                genesis_topology
            } else {
                self.network_topology.clone()
            }
        } else {
            self.network_topology.clone()
        }
    }
}

impl Debug for Sumeragi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.key_pair.public_key)
            .field("network_topology", &self.network_topology)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}

/// Uninitialized `NetworkTopology`, use only for construction.
/// Call `init` to get `InitializedNetworkTopology` and access all other methods.
#[derive(Debug)]
pub struct NetworkTopology {
    peers: BTreeSet<PeerId>,
    max_faults: u32,
    block_hash: Option<Hash>,
}

impl NetworkTopology {
    /// Constructs a new `NetworkTopology` instance.
    pub fn new(
        peers: &BTreeSet<PeerId>,
        block_hash: Option<Hash>,
        max_faults: u32,
    ) -> NetworkTopology {
        NetworkTopology {
            peers: peers.clone(),
            max_faults,
            block_hash,
        }
    }

    /// Initializes network topology.
    pub fn init(self) -> Result<InitializedNetworkTopology, String> {
        let min_peers = 3 * self.max_faults + 1;
        if self.peers.len() >= min_peers as usize {
            let mut topology = InitializedNetworkTopology {
                sorted_peers: self.peers.into_iter().collect(),
                max_faults: self.max_faults,
            };
            topology.sort_peers(self.block_hash);
            Ok(topology)
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * self.max_faults + 1, self.peers.len()))
        }
    }
}

/// Represents a topology of peers, defining a `role` for each peer based on the previous block hash.
#[derive(Debug, Clone, Encode, Decode)]
pub struct InitializedNetworkTopology {
    /// Current order of peers. The roles of peers are defined based on this order.
    pub sorted_peers: Vec<PeerId>,
    /// Maximum faulty peers in a network.
    pub max_faults: u32,
}

impl InitializedNetworkTopology {
    /// Construct `InitializedNetworkTopology` from predefined peer roles.
    pub fn from_roles(
        leader: PeerId,
        validating_peers: Vec<PeerId>,
        proxy_tail: PeerId,
        observing_peers: Vec<PeerId>,
        max_faults: u32,
    ) -> Result<Self, String> {
        let validating_peers_required_len = 2 * max_faults - 1;
        if validating_peers.len() != validating_peers_required_len as usize {
            return Err(format!(
                "Expected {} validating peers, found {}.",
                validating_peers_required_len,
                validating_peers.len()
            ));
        }
        let observing_peers_min_len = max_faults as usize;
        if observing_peers.len() < observing_peers_min_len {
            return Err(format!(
                "Expected at least {} observing peers, found {}.",
                observing_peers_min_len,
                observing_peers.len()
            ));
        }
        Ok(Self {
            sorted_peers: iter::once(leader)
                .chain(validating_peers.into_iter())
                .chain(iter::once(proxy_tail))
                .chain(observing_peers.into_iter())
                .collect(),
            max_faults,
        })
    }

    /// Updates it only if the new peers were added, otherwise leaves the order unchanged.
    pub fn update(&mut self, peers: BTreeSet<PeerId>, latest_block_hash: Hash) {
        let current_peers: BTreeSet<_> = self.sorted_peers.iter().cloned().collect();
        let peers: BTreeSet<_> = peers.into_iter().collect();
        if peers != current_peers {
            self.sorted_peers = peers.iter().cloned().collect();
            self.sort_peers(Some(latest_block_hash));
        }
    }

    /// Answers if the consensus stage is required with the current number of peers.
    pub fn is_consensus_required(&self) -> bool {
        self.sorted_peers.len() > 1
    }

    /// The minimum number of signatures needed to commit a block
    pub fn min_votes_for_commit(&self) -> u32 {
        2 * self.max_faults + 1
    }

    /// The minimum number of signatures needed to perform a view change (change leader, proxy, etc.)
    pub fn min_votes_for_view_change(&self) -> u32 {
        self.max_faults + 1
    }

    /// Peers of set A. They participate in the consensus.
    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers as usize]
    }

    /// Peers of set B. The watch the consensus process.
    pub fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1) as usize..]
    }

    /// The leader of the current round.
    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    /// The proxy tail of the current round.
    pub fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    /// The peers that validate the block in discussion this round and vote for it to be accepted by the blockchain.
    pub fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    /// Sortes peers based on the `block_hash`.
    pub fn sort_peers(&mut self, block_hash: Option<Hash>) {
        self.sorted_peers
            .sort_by(|p1, p2| p1.address.cmp(&p2.address));
        if let Some(block_hash) = block_hash {
            let Hash(bytes) = block_hash;
            let mut rng = StdRng::from_seed(bytes);
            self.sorted_peers.shuffle(&mut rng);
        }
    }

    /// Shifts `sorted_peers` by one to the right.
    pub fn shift_peers_by_one(&mut self) {
        let last_element = self
            .sorted_peers
            .pop()
            .expect("No elements found in sorted peers.");
        self.sorted_peers.insert(0, last_element);
    }

    /// Shifts `sorted_peers` by `n` to the right.
    pub fn shift_peers_by_n(&mut self, n: u32) {
        for _ in 0..n {
            self.shift_peers_by_one();
        }
    }

    /// Get role of the peer by its id.
    pub fn role(&self, peer_id: &PeerId) -> Role {
        if self.leader() == peer_id {
            Role::Leader
        } else if self.proxy_tail() == peer_id {
            Role::ProxyTail
        } else if self.validating_peers().contains(peer_id) {
            Role::ValidatingPeer
        } else {
            Role::ObservingPeer
        }
    }

    /// Verifies that this `message` was signed by the `signature` of a peer with specified `role`.
    pub fn verify_signature_with_role(
        &self,
        signature: Signature,
        role: Role,
        message_payload: &[u8],
    ) -> Result<(), String> {
        if role
            .peers(&self)
            .iter()
            .any(|peer| peer.public_key == signature.public_key)
        {
            Ok(())
        } else {
            Err(format!("No {:?} with this public key exists.", role))
        }
        .and(signature.verify(message_payload))
    }

    /// Returns signatures of the peers with the specified `roles` from all `signatures`.
    pub fn filter_signatures_by_roles(
        &self,
        roles: &[Role],
        signatures: &[Signature],
    ) -> Vec<Signature> {
        let roles: BTreeSet<Role> = roles.iter().cloned().collect();
        let public_keys: Vec<_> = roles
            .iter()
            .flat_map(|role| role.peers(self))
            .map(|peer| peer.public_key)
            .collect();
        signatures
            .iter()
            .filter(|signature| public_keys.contains(&signature.public_key))
            .cloned()
            .collect()
    }
}

/// Possible Peer's roles in consensus.
#[derive(Copy, Clone, Debug, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub enum Role {
    /// Leader.
    Leader,
    /// Validating Peer.
    ValidatingPeer,
    /// Observing Peer.
    ObservingPeer,
    /// Proxy Tail.
    ProxyTail,
}

impl Role {
    /// Returns peers that have this `Role` in this voting round.
    pub fn peers(&self, network_topology: &InitializedNetworkTopology) -> Vec<PeerId> {
        match self {
            Role::Leader => vec![network_topology.leader().clone()],
            Role::ValidatingPeer => network_topology.validating_peers().to_vec(),
            Role::ObservingPeer => network_topology.peers_set_b().to_vec(),
            Role::ProxyTail => vec![network_topology.proxy_tail().clone()],
        }
    }
}

/// Structure represents a block that is currently in discussion.
#[derive(Debug, Clone)]
pub struct VotingBlock {
    /// At what time has this peer voted for this block
    pub voted_at: Duration,
    /// Valid Block
    pub block: ValidBlock,
}

impl VotingBlock {
    /// Constructs new VotingBlock.
    pub fn new(block: ValidBlock) -> VotingBlock {
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
    use crate::{
        block::ValidBlock,
        sumeragi::{InitializedNetworkTopology, Role, Sumeragi, VotingBlock},
        torii::uri,
        tx::AcceptedTransaction,
    };
    use iroha_crypto::{Hash, KeyPair, Signature, Signatures};
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_network::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use std::time::{Duration, SystemTime};

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub enum Message {
        /// Is sent by leader to all validating peers, when a new block is created.
        BlockCreated(BlockCreated),
        /// Is sent by validating peers to proxy tail and observing peers when they have signed this block.
        BlockSigned(BlockSigned),
        /// Is sent by proxy tail to validating peers and to leader, when the block is committed.
        BlockCommitted(BlockCommitted),
        /// Is sent when the node votes to change view due to commit timeout.
        CommitTimeout(CommitTimeout),
        /// Receipt of receiving tx from peer. Sent by a leader.
        TransactionReceived(TransactionReceipt),
        /// Tx forwarded from client by a peer to a leader.
        TransactionForwarded(TransactionForwarded),
        /// Message to other peers that this peer did not receive receipt from leader for a forwarded tx.
        NoTransactionReceiptReceived(NoTransactionReceiptReceived),
        /// Message to other peers that the block was not created in `block_time` by the leader after receiving a transaction.
        BlockCreationTimeout(BlockCreationTimeout),
    }

    impl Message {
        /// Send this message over the network to the specified `peer`.
        #[log]
        pub async fn send_to(self, peer: &PeerId) -> Result<(), String> {
            match Network::send_request_to(
                &peer.address,
                Request::new(uri::CONSENSUS_URI.to_string(), self.into()),
            )
            .await?
            {
                Response::Ok(_) => Ok(()),
                Response::InternalError => Err(format!(
                    "Failed to send message - Internal Error on peer: {:?}",
                    peer
                )),
            }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        #[log]
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            match self {
                Message::BlockCreated(block_created) => block_created.handle(sumeragi).await,
                Message::BlockSigned(block_signed) => block_signed.handle(sumeragi).await,
                Message::BlockCommitted(block_committed) => block_committed.handle(sumeragi).await,
                Message::CommitTimeout(change_view) => change_view.handle(sumeragi).await,
                Message::TransactionReceived(transaction_receipt) => {
                    transaction_receipt.handle(sumeragi).await
                }
                Message::TransactionForwarded(transaction_forwarded) => {
                    transaction_forwarded.handle(sumeragi).await
                }
                Message::NoTransactionReceiptReceived(no_transaction_receipt_received) => {
                    no_transaction_receipt_received.handle(sumeragi).await
                }
                Message::BlockCreationTimeout(block_creation_timeout) => {
                    block_creation_timeout.handle(sumeragi).await
                }
            }
        }
    }

    /// `BlockCreated` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct BlockCreated {
        /// The corresponding block.
        pub block: ValidBlock,
    }

    impl BlockCreated {
        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let network_topology = sumeragi.network_topology_current_or_genesis(&self.block);
            if network_topology
                .filter_signatures_by_roles(&[Role::Leader], &self.block.verified_signatures())
                .is_empty()
            {
                log::error!(
                    "{:?} - Rejecting Block as it is not signed by leader.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                );
                return Ok(());
            }
            sumeragi
                .transactions_awaiting_created_block
                .write()
                .await
                .clear();
            for event in Vec::<Event>::from(&self.block.clone()) {
                sumeragi.events_sender.send(event).await;
            }
            match network_topology.role(&sumeragi.peer_id) {
                Role::ValidatingPeer => {
                    if !self.block.is_empty()
                        && sumeragi.latest_block_hash == self.block.header.previous_block_hash
                        && sumeragi.number_of_view_changes
                            == self.block.header.number_of_view_changes
                        && sumeragi.block_height + 1 == self.block.header.height
                    {
                        let wsv = sumeragi.world_state_view.read().await;
                        if let Err(e) = Message::BlockSigned(
                            self.block
                                .clone()
                                .revalidate(&*wsv, &sumeragi.permissions_validator)
                                .sign(&sumeragi.key_pair)?
                                .into(),
                        )
                        .send_to(network_topology.proxy_tail())
                        .await
                        {
                            log::error!(
                                "Failed to send BlockSigned message to the proxy tail: {:?}",
                                e
                            );
                        } else {
                            log::info!(
                                "{:?} - Signed block candidate with hash {}.",
                                network_topology.role(&sumeragi.peer_id),
                                self.block.hash(),
                            );
                        }
                        //TODO: send to set b so they can observe
                    }
                    let voting_block = VotingBlock::new(self.block.clone());
                    *sumeragi.voting_block.write().await = Some(voting_block.clone());
                    sumeragi.start_commit_countdown(voting_block.clone()).await;
                }
                Role::ProxyTail => {
                    if sumeragi.voting_block.write().await.is_none() {
                        *sumeragi.voting_block.write().await =
                            Some(VotingBlock::new(self.block.clone()))
                    }
                }
                Role::ObservingPeer => {
                    *sumeragi.voting_block.write().await =
                        Some(VotingBlock::new(self.block.clone()));
                }
                _ => (),
            }
            Ok(())
        }
    }

    impl From<ValidBlock> for BlockCreated {
        fn from(block: ValidBlock) -> Self {
            Self { block }
        }
    }

    /// `BlockSigned` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct BlockSigned {
        /// The corresponding block.
        pub block: ValidBlock,
    }

    impl BlockSigned {
        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let network_topology = sumeragi.network_topology_current_or_genesis(&self.block);
            if let Role::ProxyTail = network_topology.role(&sumeragi.peer_id) {
                let block_hash = self.block.hash();
                let entry = sumeragi
                    .votes_for_blocks
                    .entry(block_hash)
                    .or_insert_with(|| self.block.clone());
                entry.signatures.append(&self.block.verified_signatures());
                let valid_signatures = network_topology.filter_signatures_by_roles(
                    &[Role::ValidatingPeer, Role::Leader],
                    &entry.verified_signatures(),
                );
                log::info!(
                    "{:?} - Recieved a vote for block with hash {}. Now it has {} signatures out of {} required (not counting ProxyTail signature).",
                    network_topology.role(&sumeragi.peer_id),
                    block_hash,
                    valid_signatures.len(),
                    network_topology.min_votes_for_commit() - 1,
                );
                if valid_signatures.len() >= network_topology.min_votes_for_commit() as usize - 1 {
                    let mut signatures = Signatures::default();
                    signatures.append(&valid_signatures);
                    let mut block = entry.clone();
                    block.signatures = signatures;
                    let block = block.sign(&sumeragi.key_pair)?;
                    log::info!(
                        "{:?} - Block reached required number of votes. Block hash {}.",
                        network_topology.role(&sumeragi.peer_id),
                        block_hash,
                    );
                    let message = Message::BlockCommitted(block.clone().into());
                    let mut send_futures = Vec::new();
                    for peer in network_topology.validating_peers() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    send_futures.push(message.clone().send_to(network_topology.leader()));
                    for peer in network_topology.peers_set_b() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    let results = futures::future::join_all(send_futures).await;
                    results
                        .iter()
                        .filter(|result| result.is_err())
                        .for_each(|error_result| {
                            log::error!(
                                "Failed to send BlockCommitted messages: {:?}",
                                error_result
                            )
                        });
                    sumeragi.votes_for_blocks.clear();
                    sumeragi.commit_block(block).await;
                }
            }
            Ok(())
        }
    }

    impl From<ValidBlock> for BlockSigned {
        fn from(block: ValidBlock) -> Self {
            Self { block }
        }
    }

    /// `BlockCommitted` message structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct BlockCommitted {
        /// The corresponding block.
        pub block: ValidBlock,
    }

    impl BlockCommitted {
        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let network_topology = sumeragi.network_topology_current_or_genesis(&self.block);
            let verified_signatures = self.block.verified_signatures();
            let valid_signatures = network_topology.filter_signatures_by_roles(
                &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                &verified_signatures,
            );
            let proxy_tail_signatures = network_topology
                .filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
            if valid_signatures.len() >= network_topology.min_votes_for_commit() as usize
                && proxy_tail_signatures.len() == 1
                && sumeragi.latest_block_hash == self.block.header.previous_block_hash
            {
                let mut block = self.block.clone();
                block.signatures.clear();
                block.signatures.append(&valid_signatures);
                sumeragi.commit_block(block).await;
            }
            Ok(())
        }
    }

    impl From<ValidBlock> for BlockCommitted {
        fn from(block: ValidBlock) -> Self {
            Self { block }
        }
    }

    /// Message structure showing a `transaction_receipt` from a leader as a proof that peer did not create a block
    /// in `block_time` after receiving this transaction.
    /// Peers validate the receipt, and sign the message to vote for changing the view.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct BlockCreationTimeout {
        /// A proof of the leader receiving and accepting a transaction.
        pub transaction_receipt: TransactionReceipt,
        /// Signatures of the peers who voted for changing the leader.
        pub signatures: Signatures,
    }

    impl BlockCreationTimeout {
        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the leader does not produce a block
        /// after receiving transaction in `block_time`.
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<BlockCreationTimeout, String> {
            let signature = Signature::new(
                key_pair.clone(),
                &Vec::<u8>::from(self.transaction_receipt.clone()),
            )?;
            self.signatures.add(signature);
            Ok(self)
        }

        /// Signatures that are verified with the `transaction_receipt` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures
                .verified(&Vec::<u8>::from(self.transaction_receipt.clone()))
        }

        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let role = sumeragi.network_topology.role(&sumeragi.peer_id);
            let tx_receipt = self.transaction_receipt.clone();
            if tx_receipt.is_valid(&sumeragi.network_topology)
                && tx_receipt.is_block_should_be_created(sumeragi.block_time)
                && (role == Role::ValidatingPeer || role == Role::ProxyTail)
                // Block is not yet created
                && sumeragi.voting_block.write().await.is_none()
                && !self.signatures.contains(&sumeragi.key_pair.public_key)
            {
                let block_creation_timeout_message = Message::BlockCreationTimeout(
                    self.clone()
                        .sign(&sumeragi.key_pair)
                        .expect("Failed to sign."),
                );
                let _ = futures::future::join_all(
                    sumeragi
                        .network_topology
                        .sorted_peers
                        .iter()
                        .map(|peer| block_creation_timeout_message.clone().send_to(peer)),
                )
                .await;
            }
            if sumeragi
                .network_topology
                .filter_signatures_by_roles(
                    &[Role::ProxyTail, Role::ValidatingPeer],
                    &self.verified_signatures(),
                )
                .len()
                >= sumeragi.network_topology.min_votes_for_view_change() as usize
            {
                log::info!(
                    "{:?} - Block creation timeout verified by voting. Previous block hash: {}.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                    sumeragi.latest_block_hash,
                );
                sumeragi.change_view().await;
            }
            Ok(())
        }
    }

    impl From<TransactionReceipt> for BlockCreationTimeout {
        fn from(transaction_receipt: TransactionReceipt) -> Self {
            BlockCreationTimeout {
                transaction_receipt,
                signatures: Signatures::default(),
            }
        }
    }

    /// Message structure describing a failed attempt to forward transaction to a leader.
    /// Peers sign it if they are not able to get a TxReceipt from a leader after sending the specified transaction.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct NoTransactionReceiptReceived {
        /// Transaction for which there was no `TransactionReceipt`.
        pub transaction: AcceptedTransaction,
        /// Signatures of the peers who voted for changing the leader.
        pub signatures: Signatures,
        /// The id of the leader, to determine that peer topologies are synchronized.
        pub leader_id: PeerId,
    }

    impl NoTransactionReceiptReceived {
        /// Constructs a new `NoTransactionReceiptReceived` message with no signatures.
        pub fn new(
            transaction: &AcceptedTransaction,
            leader_id: PeerId,
        ) -> NoTransactionReceiptReceived {
            NoTransactionReceiptReceived {
                transaction: transaction.clone(),
                signatures: Signatures::default(),
                leader_id,
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the leader refuses to accept this transaction.
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<NoTransactionReceiptReceived, String> {
            let signature =
                Signature::new(key_pair.clone(), &Vec::<u8>::from(self.transaction.clone()))?;
            self.signatures.add(signature);
            Ok(self)
        }

        /// Signatures that are verified with the `transaction` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures
                .verified(&Vec::<u8>::from(self.transaction.clone()))
        }

        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            if self.leader_id != *sumeragi.network_topology.leader() {
                return Ok(());
            }
            if sumeragi
                .network_topology
                .filter_signatures_by_roles(
                    &[Role::ProxyTail, Role::ValidatingPeer],
                    &self.verified_signatures(),
                )
                .len()
                >= sumeragi.network_topology.min_votes_for_view_change() as usize
            {
                log::info!(
                    "{:?} - Faulty leader not sending tx receipts verified by voting. Previous block hash: {}.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                    sumeragi.latest_block_hash,
                );
                sumeragi.change_view().await;
                return Ok(());
            }
            let role = sumeragi.network_topology.role(&sumeragi.peer_id);
            if (role == Role::ValidatingPeer || role == Role::ProxyTail)
                && !self.signatures.contains(&sumeragi.key_pair.public_key)
            {
                let _result = Message::TransactionForwarded(TransactionForwarded {
                    transaction: self.transaction.clone(),
                    peer: sumeragi.peer_id.clone(),
                })
                .send_to(sumeragi.network_topology.leader())
                .await;
                let _ = sumeragi
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .insert(self.transaction.hash());
                let pending_forwarded_tx_hashes = sumeragi.transactions_awaiting_receipts.clone();
                let recipient_peers = sumeragi.network_topology.sorted_peers.clone();
                let tx_receipt_time = sumeragi.tx_receipt_time;
                let no_tx_receipt = self
                    .clone()
                    .sign(&sumeragi.key_pair)
                    .expect("Failed to sign.");
                let _ = async_std::task::spawn(async move {
                    async_std::task::sleep(tx_receipt_time).await;
                    if pending_forwarded_tx_hashes
                        .write()
                        .await
                        .contains(&no_tx_receipt.transaction.hash())
                    {
                        let mut send_futures = Vec::new();
                        for peer in &recipient_peers {
                            send_futures.push(
                                Message::NoTransactionReceiptReceived(no_tx_receipt.clone())
                                    .send_to(peer),
                            );
                        }
                        let _ = futures::future::join_all(send_futures).await;
                    }
                });
            }
            Ok(())
        }
    }

    /// Message structure describing a transaction that is forwarded from a client by a peer to the leader.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct TransactionForwarded {
        /// Transaction that is forwarded from a client by a peer to the leader
        pub transaction: AcceptedTransaction,
        /// `PeerId` of the peer that forwarded this transaction to a leader.
        pub peer: PeerId,
    }

    impl TransactionForwarded {
        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let _result = Message::TransactionReceived(TransactionReceipt::new(
                &self.transaction,
                &sumeragi.key_pair,
            )?)
            .send_to(&self.peer)
            .await;
            sumeragi
                .transactions_sender
                .send(self.transaction.clone())
                .await;
            Ok(())
        }
    }

    /// Message structure describing a receipt sent by the leader to the peer it got this transaction from.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct TransactionReceipt {
        /// The hash of the transaction that the leader received.
        pub transaction_hash: Hash,
        /// The time at which the leader claims to have received this transaction.
        pub received_at: Duration,
        /// The signature of the leader.
        pub signature: Signature,
    }

    impl TransactionReceipt {
        /// Constructs a new receipt.
        pub fn new(
            transaction: &AcceptedTransaction,
            key_pair: &KeyPair,
        ) -> Result<TransactionReceipt, String> {
            let transaction_hash = transaction.hash();
            Ok(TransactionReceipt {
                transaction_hash,
                received_at: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time."),
                signature: Signature::new(key_pair.clone(), transaction_hash.as_ref())?,
            })
        }

        /// Checks that this `TransactionReceipt` is valid.
        pub fn is_valid(&self, network_topology: &InitializedNetworkTopology) -> bool {
            network_topology
                .verify_signature_with_role(
                    self.signature.clone(),
                    Role::Leader,
                    self.transaction_hash.as_ref(),
                )
                .is_ok()
        }

        /// Checks if the block should have been already created by the `Leader`.
        pub fn is_block_should_be_created(&self, block_time: Duration) -> bool {
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.");
            (current_time - self.received_at) >= block_time
        }

        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            // Implausible time in the future, means that the leader lies
            if sumeragi.network_topology.role(&sumeragi.peer_id) != Role::Leader
                && self.received_at
                    <= SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("Failed to get System Time.")
                && self.is_valid(&sumeragi.network_topology)
                && sumeragi
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .contains(&self.transaction_hash)
            {
                let _ = sumeragi
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .remove(&self.transaction_hash);
                let block_time = sumeragi.block_time;
                let transactions_awaiting_created_block =
                    sumeragi.transactions_awaiting_created_block.clone();
                let tx_hash = self.transaction_hash;
                let role = sumeragi.network_topology.role(&sumeragi.peer_id);
                let mut block_creation_timeout: BlockCreationTimeout = self.clone().into();
                if role == Role::ValidatingPeer || role == Role::ProxyTail {
                    block_creation_timeout = block_creation_timeout
                        .sign(&sumeragi.key_pair)
                        .expect("Failed to put first signature.");
                }
                let _ = transactions_awaiting_created_block
                    .write()
                    .await
                    .insert(tx_hash);
                let recipient_peers = sumeragi.network_topology.sorted_peers.clone();
                let _ = async_std::task::spawn(async move {
                    async_std::task::sleep(block_time).await;
                    // Suspect leader if the block was not yet created
                    if transactions_awaiting_created_block
                        .write()
                        .await
                        .contains(&tx_hash)
                    {
                        let block_creation_timeout_message =
                            Message::BlockCreationTimeout(block_creation_timeout);
                        let _ = futures::future::join_all(
                            recipient_peers
                                .iter()
                                .map(|peer| block_creation_timeout_message.clone().send_to(peer)),
                        )
                        .await;
                    }
                });
            }
            Ok(())
        }
    }

    /// Message structure describing a request to other peers to change view because of the commit timeout.
    /// Peers vote on this view change by signing and forwarding this structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub struct CommitTimeout {
        /// The hash of the block in discussion in this round.
        pub voting_block_hash: Hash,
        /// The signatures of the peers who vote to for a view change.
        pub signatures: Signatures,
    }

    impl CommitTimeout {
        /// Constructs a new commit timeout message with no signatures.
        pub fn new(voting_block: VotingBlock) -> CommitTimeout {
            CommitTimeout {
                voting_block_hash: voting_block.block.hash(),
                signatures: Signatures::default(),
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the proxy tail does not send commit message in `commit_time`.
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<CommitTimeout, String> {
            let signature = Signature::new(key_pair.clone(), self.voting_block_hash.as_ref())?;
            self.signatures.add(signature);
            Ok(self)
        }

        /// Signatures that are verified with the `voting_block_hash` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures.verified(self.voting_block_hash.as_ref())
        }

        /// Handles this message as part of `Sumeragi` consensus.
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<(), String> {
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.");
            let role = sumeragi.network_topology.role(&sumeragi.peer_id);
            if role == Role::ValidatingPeer || role == Role::Leader {
                let voting_block = sumeragi.voting_block.read().await.clone();
                if let Some(voting_block) = voting_block {
                    if voting_block.block.hash() == self.voting_block_hash
                        && (current_time - voting_block.voted_at) >= sumeragi.commit_time
                        && !self.signatures.contains(&sumeragi.key_pair.public_key)
                    {
                        let message = Message::CommitTimeout(
                            self.clone()
                                .sign(&sumeragi.key_pair)
                                .expect("Failed to sign."),
                        );
                        let mut send_futures = Vec::new();
                        for peer in &sumeragi.network_topology.sorted_peers {
                            send_futures.push(message.clone().send_to(peer));
                        }
                        let results = futures::future::join_all(send_futures).await;
                        results
                            .iter()
                            .filter(|result| result.is_err())
                            .for_each(|error_result| {
                                log::error!(
                                    "Failed to send CommitTimeout messages: {:?}",
                                    error_result
                                )
                            });
                    }
                }
            }
            if sumeragi
                .network_topology
                .filter_signatures_by_roles(
                    &[Role::Leader, Role::ValidatingPeer],
                    &self.verified_signatures(),
                )
                .len()
                >= sumeragi.network_topology.min_votes_for_view_change() as usize
            {
                sumeragi
                    .invalidated_blocks_hashes
                    .push(self.voting_block_hash);
                log::info!(
                    "{:?} - Block commit timeout verified by voting. Previous block hash: {}.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                    sumeragi.latest_block_hash,
                );
                sumeragi.change_view().await;
            }
            Ok(())
        }
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_crypto::prelude::*;
    use iroha_data_model::prelude::*;
    use serde::Deserialize;
    use std::{collections::BTreeSet, env};

    const BLOCK_TIME_MS: &str = "BLOCK_TIME_MS";
    const TRUSTED_PEERS: &str = "IROHA_TRUSTED_PEERS";
    const MAX_FAULTY_PEERS: &str = "MAX_FAULTY_PEERS";
    const COMMIT_TIME_MS: &str = "COMMIT_TIME_MS";
    const TX_RECEIPT_TIME_MS: &str = "TX_RECEIPT_TIME_MS";
    const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
    const DEFAULT_MAX_FAULTY_PEERS: u32 = 0;
    const DEFAULT_COMMIT_TIME_MS: u64 = 1000;
    const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 200;

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all = "UPPERCASE")]
    pub struct SumeragiConfiguration {
        /// Key pair of private and public keys.
        #[serde(skip)]
        pub key_pair: KeyPair,
        /// Current Peer Identification.
        #[serde(default = "default_peer_id")]
        pub peer_id: PeerId,
        /// Amount of time peer waits for the `CreatedBlock` message after getting a `TransactionReceipt`
        #[serde(default = "default_block_time_ms")]
        pub block_time_ms: u64,
        /// Optional list of predefined trusted peers.
        #[serde(default)]
        pub trusted_peers: BTreeSet<PeerId>,
        /// Maximum amount of peers to fail and do not compromise the consensus.
        #[serde(default = "default_max_faulty_peers")]
        pub max_faulty_peers: u32,
        /// Amount of time Peer waits for CommitMessage from the proxy tail.
        #[serde(default = "default_commit_time_ms")]
        pub commit_time_ms: u64,
        /// Amount of time Peer waits for TxReceipt from the leader.
        #[serde(default = "default_tx_receipt_time_ms")]
        pub tx_receipt_time_ms: u64,
    }

    impl SumeragiConfiguration {
        /// Load environment variables and replace predefined parameters with these variables
        /// values.
        pub fn load_environment(&mut self) -> Result<(), String> {
            if let Ok(block_time_ms) = env::var(BLOCK_TIME_MS) {
                self.block_time_ms = block_time_ms
                    .parse()
                    .map_err(|e| format!("Failed to parse Block Build Time: {}", e))?;
            }
            if let Ok(trusted_peers) = env::var(TRUSTED_PEERS) {
                self.trusted_peers = serde_json::from_str(&trusted_peers)
                    .map_err(|e| format!("Failed to parse Trusted Peers: {}", e))?;
            }
            if let Ok(max_faulty_peers) = env::var(MAX_FAULTY_PEERS) {
                self.max_faulty_peers = max_faulty_peers
                    .parse()
                    .map_err(|e| format!("Failed to parse Max Faulty Peers: {}", e))?;
            }
            if let Ok(commit_time_ms) = env::var(COMMIT_TIME_MS) {
                self.commit_time_ms = commit_time_ms
                    .parse()
                    .map_err(|e| format!("Failed to parse Commit Time Ms: {}", e))?;
            }
            if let Ok(tx_receipt_time_ms) = env::var(TX_RECEIPT_TIME_MS) {
                self.tx_receipt_time_ms = tx_receipt_time_ms
                    .parse()
                    .map_err(|e| format!("Failed to parse Tx Receipt Time Ms: {}", e))?;
            }
            Ok(())
        }

        /// Set `trusted_peers` configuration parameter - will overwrite the existing one.
        pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
            self.trusted_peers = trusted_peers.into_iter().collect();
        }

        /// Set `max_faulty_peers` configuration parameter - will overwrite the existing one.
        pub fn max_faulty_peers(&mut self, max_faulty_peers: u32) {
            self.max_faulty_peers = max_faulty_peers;
        }

        /// Time estimation from receiving a transaction to storing it in a block on all peers.
        pub fn pipeline_time_ms(&self) -> u64 {
            self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
        }
    }

    fn default_peer_id() -> PeerId {
        PeerId {
            address: "".to_string(),
            public_key: PublicKey::default(),
        }
    }

    fn default_block_time_ms() -> u64 {
        DEFAULT_BLOCK_TIME_MS
    }

    fn default_max_faulty_peers() -> u32 {
        DEFAULT_MAX_FAULTY_PEERS
    }

    fn default_commit_time_ms() -> u64 {
        DEFAULT_COMMIT_TIME_MS
    }

    fn default_tx_receipt_time_ms() -> u64 {
        DEFAULT_TX_RECEIPT_TIME_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[cfg(feature = "network-mock")]
    use {
        crate::{
            config::Configuration, init, maintenance::System, queue::Queue, torii::Torii,
            tx::Accept,
        },
        async_std::{prelude::*, sync, task},
        std::time::Duration,
    };

    #[cfg(feature = "network-mock")]
    const CONFIG_PATH: &str = "config.json";
    #[cfg(feature = "network-mock")]
    const BLOCK_TIME_MS: u64 = 1000;
    #[cfg(feature = "network-mock")]
    const COMMIT_TIME_MS: u64 = 1000;
    #[cfg(feature = "network-mock")]
    const TX_RECEIPT_TIME_MS: u64 = 200;
    #[cfg(feature = "network-mock")]
    const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let listen_address = "127.0.0.1".to_string();
        let this_peer: BTreeSet<PeerId> = vec![PeerId {
            address: listen_address,
            public_key: key_pair.public_key,
        }]
        .into_iter()
        .collect();
        let _network_topology = NetworkTopology::new(&this_peer, None, 3)
            .init()
            .expect("Failed to create topology.");
    }

    #[test]
    fn different_order() {
        let peers: BTreeSet<PeerId> = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7881".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
        ]
        .into_iter()
        .collect();
        let network_topology1 = NetworkTopology::new(&peers, Some(Hash([1u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        let network_topology2 = NetworkTopology::new(&peers, Some(Hash([2u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        assert_ne!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[test]
    fn same_order() {
        let peers: BTreeSet<PeerId> = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7881".to_string(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
        ]
        .into_iter()
        .collect();
        let network_topology1 = NetworkTopology::new(&peers, Some(Hash([1u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        let network_topology2 = NetworkTopology::new(&peers, Some(Hash([1u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        assert_eq!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn all_peers_commit_block() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut block_counters = Vec::new();
        let root_key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            addresses.push((
                format!("127.0.0.1:{}", 7878 + i * 2),
                format!("127.0.0.1:{}", 7878 + i * 2 + 1),
            ));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        config.init_configuration.root_public_key = root_key_pair.public_key.clone();
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
                init::domains(&config),
                ids_set.clone(),
            ))));
            let (p2p_address, api_address) = &addresses[i];
            config.torii_configuration.torii_p2p_url = p2p_address.clone();
            config.torii_configuration.torii_api_url = api_address.clone();
            let mut config = config.clone();
            config.sumeragi_configuration.key_pair = keys[i].clone();
            config.sumeragi_configuration.peer_id = ids[i].clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.sumeragi_configuration.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::from_configuration(
                    &config.sumeragi_configuration,
                    Arc::new(RwLock::new(block_sender)),
                    events_sender.clone(),
                    wsv.clone(),
                    transactions_sender,
                    AllowAll.into(),
                )
                .expect("Failed to create Sumeragi."),
            ));
            let queue = Arc::new(RwLock::new(Queue::from_configuration(
                &config.queue_configuration,
            )));
            let mut torii = Torii::from_configuration(
                &config.torii_configuration,
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            let _ = task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            sumeragi.write().await.init(Hash([0u8; 32]), 0);
            peers.push(sumeragi.clone());
            let _ = task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let _result = message.handle(&mut *sumeragi.write().await).await;
                }
            });
            let block_counter = block_counters[i].clone();
            let _ = task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
        }
        async_std::task::sleep(Duration::from_millis(2000)).await;
        // First peer is a leader in this particular case.
        let leader = peers
            .iter()
            .find(|peer| {
                async_std::task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![Transaction::new(
                vec![],
                AccountId::new("root", "global"),
                TRANSACTION_TIME_TO_LIVE_MS,
            )
            .sign(&root_key_pair)
            .expect("Failed to sign.")
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(2000)).await;
        for block_counter in block_counters {
            assert_eq!(*block_counter.write().await, 1);
        }
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn change_view_on_commit_timeout() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut block_counters = Vec::new();
        let root_key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            addresses.push((
                format!("127.0.0.1:{}", 7878 + n_peers * 2 + i * 2),
                format!("127.0.0.1:{}", 7878 + n_peers * 2 + i * 2 + 1),
            ));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        config.init_configuration.root_public_key = root_key_pair.public_key.clone();
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
                init::domains(&config),
                ids_set.clone(),
            ))));
            let (p2p_address, api_address) = &addresses[i];
            config.torii_configuration.torii_p2p_url = p2p_address.clone();
            config.torii_configuration.torii_api_url = api_address.clone();
            let mut config = config.clone();
            config.sumeragi_configuration.key_pair = keys[i].clone();
            config.sumeragi_configuration.peer_id = ids[i].clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.sumeragi_configuration.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::from_configuration(
                    &config.sumeragi_configuration,
                    Arc::new(RwLock::new(block_sender)),
                    events_sender.clone(),
                    wsv.clone(),
                    transactions_sender,
                    AllowAll.into(),
                )
                .expect("Failed to create Sumeragi."),
            ));
            let queue = Arc::new(RwLock::new(Queue::from_configuration(
                &config.queue_configuration,
            )));
            let mut torii = Torii::from_configuration(
                &config.torii_configuration,
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            let _ = task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            sumeragi.write().await.init(Hash([0u8; 32]), 0);
            peers.push(sumeragi.clone());
            let _ = task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate faulty proxy tail
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
                        if let Message::BlockSigned(..) = message {
                            continue;
                        }
                    }
                    let _result = message.handle(&mut *sumeragi).await;
                }
            });
            let block_counter = block_counters[i].clone();
            let _ = task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
        }
        async_std::task::sleep(Duration::from_millis(2000)).await;
        // First peer is a leader in this particular case.
        let leader = peers
            .iter()
            .find(|peer| {
                async_std::task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![Transaction::new(
                vec![],
                AccountId::new("root", "global"),
                TRANSACTION_TIME_TO_LIVE_MS,
            )
            .sign(&root_key_pair)
            .expect("Failed to sign.")
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        network_topology.shift_peers_by_one();
        let order_after_change = network_topology.sorted_peers;
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(
                peer.write().await.network_topology.sorted_peers,
                order_after_change
            );
            assert_eq!(peer.write().await.invalidated_blocks_hashes.len(), 1);
        }
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn change_view_on_tx_receipt_timeout() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut block_counters = Vec::new();
        let root_key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            addresses.push((
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 2 + i * 2),
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 2 + i * 2 + 1),
            ));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        config.init_configuration.root_public_key = root_key_pair.public_key.clone();
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
                init::domains(&config),
                ids_set.clone(),
            ))));
            let (p2p_address, api_address) = &addresses[i];
            config.torii_configuration.torii_p2p_url = p2p_address.clone();
            config.torii_configuration.torii_api_url = api_address.clone();
            let mut config = config.clone();
            config.sumeragi_configuration.key_pair = keys[i].clone();
            config.sumeragi_configuration.peer_id = ids[i].clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.sumeragi_configuration.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::from_configuration(
                    &config.sumeragi_configuration,
                    Arc::new(RwLock::new(block_sender)),
                    events_sender.clone(),
                    wsv.clone(),
                    transactions_sender,
                    AllowAll.into(),
                )
                .expect("Failed to create Sumeragi."),
            ));
            let queue = Arc::new(RwLock::new(Queue::from_configuration(
                &config.queue_configuration,
            )));
            let mut torii = Torii::from_configuration(
                &config.torii_configuration,
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            let _ = task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            sumeragi.write().await.init(Hash([0u8; 32]), 0);
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            let _ = task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi_arc_clone.write().await;
                    // Simulate faulty leader
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::Leader {
                        if let Message::TransactionForwarded(..) = message {
                            continue;
                        }
                    }
                    let _result = message.handle(&mut *sumeragi).await;
                }
            });
            let block_counter = block_counters[i].clone();
            let _ = task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
            let sumeragi_arc_clone = sumeragi.clone();
            let _ = task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    if let Err(e) = sumeragi_arc_clone
                        .write()
                        .await
                        .round(vec![transaction])
                        .await
                    {
                        eprintln!("{}", e);
                    }
                }
            });
        }
        async_std::task::sleep(Duration::from_millis(2000)).await;
        let peer = peers
            .iter()
            .find(|peer| {
                async_std::task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) != Role::Leader
                })
            })
            .expect("Failed to find a non-leader peer.");
        peer.write()
            .await
            .round(vec![Transaction::new(
                vec![],
                AccountId::new("root", "global"),
                TRANSACTION_TIME_TO_LIVE_MS,
            )
            .sign(&root_key_pair)
            .expect("Failed to sign.")
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        network_topology.shift_peers_by_one();
        let order_after_change = network_topology.sorted_peers;
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(
                peer.write().await.network_topology.sorted_peers,
                order_after_change
            );
        }
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn change_view_on_block_creation_timeout() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut block_counters = Vec::new();
        let root_key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            addresses.push((
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 3 + i * 2),
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 3 + i * 2 + 1),
            ));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        config.init_configuration.root_public_key = root_key_pair.public_key.clone();
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
                init::domains(&config),
                ids_set.clone(),
            ))));
            let (p2p_address, api_address) = &addresses[i];
            config.torii_configuration.torii_p2p_url = p2p_address.clone();
            config.torii_configuration.torii_api_url = api_address.clone();
            let mut config = config.clone();
            config.sumeragi_configuration.key_pair = keys[i].clone();
            config.sumeragi_configuration.peer_id = ids[i].clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.sumeragi_configuration.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::from_configuration(
                    &config.sumeragi_configuration,
                    Arc::new(RwLock::new(block_sender)),
                    events_sender.clone(),
                    wsv.clone(),
                    transactions_sender,
                    AllowAll.into(),
                )
                .expect("Failed to create Sumeragi."),
            ));
            let queue = Arc::new(RwLock::new(Queue::from_configuration(
                &config.queue_configuration,
            )));
            let mut torii = Torii::from_configuration(
                &config.torii_configuration,
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            let _ = task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            sumeragi.write().await.init(Hash([0u8; 32]), 0);
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            let _ = task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    // Simulate faulty leader as if it does not send `BlockCreated` messages
                    if let Message::BlockCreated(..) = message {
                        continue;
                    }
                    let _result = message.handle(&mut *sumeragi_arc_clone.write().await).await;
                }
            });
            let block_counter = block_counters[i].clone();
            let _ = task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
            let sumeragi_arc_clone = sumeragi.clone();
            let _ = task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    if let Err(e) = sumeragi_arc_clone
                        .write()
                        .await
                        .round(vec![transaction])
                        .await
                    {
                        log::error!("{}", e);
                    }
                }
            });
        }
        async_std::task::sleep(Duration::from_millis(2000)).await;
        let peer = peers
            .iter()
            .find(|peer| {
                async_std::task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) != Role::Leader
                })
            })
            .expect("Failed to find a non-leader peer.");
        peer.write()
            .await
            .round(vec![Transaction::new(
                vec![],
                AccountId::new("root", "global"),
                TRANSACTION_TIME_TO_LIVE_MS,
            )
            .sign(&root_key_pair)
            .expect("Failed to sign.")
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        network_topology.shift_peers_by_one();
        let order_after_change = network_topology.sorted_peers;
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(
                peer.write().await.network_topology.sorted_peers,
                order_after_change
            );
        }
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn not_enough_votes() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut addresses = Vec::new();
        let mut block_counters = Vec::new();
        let root_key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            addresses.push((
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 4 + i * 2),
                format!("127.0.0.1:{}", 7878 + n_peers * 2 * 4 + i * 2 + 1),
            ));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        config.init_configuration.root_public_key = root_key_pair.public_key.clone();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
            let wsv = Arc::new(RwLock::new(WorldStateView::new(World::with(
                init::domains(&config),
                ids_set,
            ))));
            let (p2p_address, api_address) = &addresses[i];
            config.torii_configuration.torii_p2p_url = p2p_address.clone();
            config.torii_configuration.torii_api_url = api_address.clone();
            let mut config = config.clone();
            config.sumeragi_configuration.key_pair = keys[i].clone();
            config.sumeragi_configuration.peer_id = ids[i].clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.sumeragi_configuration.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::from_configuration(
                    &config.sumeragi_configuration,
                    Arc::new(RwLock::new(block_sender)),
                    events_sender.clone(),
                    wsv.clone(),
                    transactions_sender,
                    AllowAll.into(),
                )
                .expect("Failed to create Sumeragi."),
            ));
            let queue = Arc::new(RwLock::new(Queue::from_configuration(
                &config.queue_configuration,
            )));
            let mut torii = Torii::from_configuration(
                &config.torii_configuration,
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            let _ = task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            sumeragi.write().await.init(Hash([0u8; 32]), 0);
            peers.push(sumeragi.clone());
            let _ = task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate leader producing empty blocks
                    if let Message::BlockCreated(block_created) = message {
                        let mut block_created = block_created.clone();
                        block_created.block.transactions = Vec::new();
                        let _result = Message::BlockCreated(block_created)
                            .handle(&mut *sumeragi)
                            .await;
                    } else {
                        let _result = message.handle(&mut *sumeragi).await;
                    }
                }
            });
            let block_counter = block_counters[i].clone();
            let _ = task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
        }
        async_std::task::sleep(Duration::from_millis(2000)).await;
        let leader = peers
            .iter()
            .find(|peer| {
                async_std::task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![Transaction::new(
                vec![],
                AccountId::new("root", "global"),
                TRANSACTION_TIME_TO_LIVE_MS,
            )
            .sign(&root_key_pair)
            .expect("Failed to sign.")
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let ids: BTreeSet<PeerId> = ids.into_iter().collect();
        let mut network_topology = NetworkTopology::new(&ids, Some(Hash([0u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        network_topology.shift_peers_by_one();
        let order_after_change = network_topology.sorted_peers;
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(
                peer.write().await.network_topology.sorted_peers,
                order_after_change
            );
            assert_eq!(peer.write().await.invalidated_blocks_hashes.len(), 1);
        }
    }
}
