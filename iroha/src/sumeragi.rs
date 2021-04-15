//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

#![allow(clippy::missing_inline_in_public_items)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    iter,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_std::{sync::RwLock, task};
use futures::future;
use iroha_crypto::{Hash, KeyPair};
use iroha_data_model::prelude::*;
use iroha_error::{error, Result};
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

use self::message::*;
use crate::{
    block::{ChainedBlock, VersionedPendingBlock},
    event::EventsSender,
    permissions::PermissionsValidatorBox,
    prelude::*,
    VersionedValidBlock,
};

trait Consensus {
    fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedPendingBlock>;
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
    votes_for_blocks: BTreeMap<Hash, VersionedValidBlock>,
    blocks_sender: ValidBlockSender,
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
    //TODO: Move latest_block_hash and block_height into `State` struct and get NetworkTopology as a function of state.
    latest_block_hash: Hash,
    block_height: u64,
    /// Number of view changes after the previous block was committed
    number_of_view_changes: u32,
    invalidated_blocks_hashes: Vec<Hash>,
    permissions_validator: PermissionsValidatorBox,
    n_topology_shifts_before_reshuffle: u32,
    max_instruction_number: usize,
}

impl Sumeragi {
    /// Default `Sumeragi` constructor.
    ///
    /// # Errors
    /// Can fail during initing network topology
    pub fn from_configuration(
        configuration: &config::SumeragiConfiguration,
        blocks_sender: ValidBlockSender,
        events_sender: EventsSender,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transactions_sender: TransactionSender,
        permissions_validator: PermissionsValidatorBox,
        //TODO: separate initialization from construction and do not return Result in `new`
    ) -> Result<Self> {
        Ok(Self {
            key_pair: configuration.key_pair.clone(),
            network_topology: NetworkTopology::new(
                &configuration.trusted_peers.peers,
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
            latest_block_hash: Hash([0_u8; 32]),
            block_height: 0,
            number_of_view_changes: 0,
            invalidated_blocks_hashes: Vec::new(),
            permissions_validator,
            n_topology_shifts_before_reshuffle: configuration.n_topology_shifts_before_reshuffle,
            max_instruction_number: configuration.max_instruction_number,
        })
    }

    /// Initializes sumeragi with the `latest_block_hash` and `block_height` after Kura loads the blocks.
    pub fn init(&mut self, latest_block_hash: Hash, block_height: u64) {
        self.block_height = block_height;
        self.latest_block_hash = latest_block_hash;
        self.network_topology
            .sort_peers_by_hash(Some(latest_block_hash));
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
            .update(&wsv_peers, self.latest_block_hash);
    }

    /// Returns `true` if some block is in discussion, `false` otherwise.
    pub async fn voting_in_progress(&self) -> bool {
        self.voting_block.write().await.is_some()
    }

    /// Assumes this peer is a leader and starts the round with the given `genesis_topology`.
    ///
    /// # Errors
    /// Can fail if:
    /// * transactions are empty
    /// * peer is not leader
    /// * there are already some blocks in blockchain
    pub async fn start_genesis_round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
        genesis_topology: InitializedNetworkTopology,
    ) -> Result<()> {
        if transactions.is_empty() {
            Err(error!("Genesis transactions set is empty."))
        } else if genesis_topology.leader() != &self.peer_id {
            Err(error!(
                "Incorrect network topology this peer should be {:?} but is {:?}",
                Role::Leader,
                genesis_topology.role(&self.peer_id)
            ))
        } else if self.block_height > 0 {
            Err(error!(
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
    pub async fn round(&mut self, transactions: Vec<VersionedAcceptedTransaction>) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }
        self.gossip_transactions(&transactions).await;
        if let Role::Leader = self.network_topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions).chain(
                self.block_height,
                self.latest_block_hash,
                self.number_of_view_changes,
                self.invalidated_blocks_hashes.clone(),
            );
            self.validate_and_publish_created_block(block).await
        } else {
            self.forward_transactions_to_leader(&transactions).await;
            Ok(())
        }
    }

    /// Forwards transactions to the leader and waits for receipts.
    pub async fn forward_transactions_to_leader(
        &mut self,
        transactions: &[VersionedAcceptedTransaction],
    ) {
        iroha_logger::info!(
            "{:?} - {} - Forwarding transactions to leader({}). Number of transactions to forward: {}",
            self.network_topology.role(&self.peer_id),
            self.peer_id.address,
            self.network_topology.leader().address,
            transactions.len(),
        );
        let mut send_futures = Vec::new();
        for transaction in transactions {
            send_futures.push(
                VersionedMessage::from(Message::from(TransactionForwarded::new(
                    transaction,
                    &self.peer_id,
                )))
                .send_to(self.network_topology.leader()),
            );
            // Don't require leader to submit receipts and therefore create blocks if the transaction is still waiting for more signatures.
            if let Ok(true) =
                transaction.check_signature_condition(&*self.world_state_view.read().await)
            {
                let _ = self
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .insert(transaction.hash());
            }
            let transactions_awaiting_receipts = Arc::clone(&self.transactions_awaiting_receipts);
            let mut no_tx_receipt = NoTransactionReceiptReceived::new(
                transaction,
                self.network_topology.leader().clone(),
                self.latest_block_hash,
                self.number_of_view_changes,
            );
            let role = self.network_topology.role(&self.peer_id);
            #[allow(clippy::expect_used)]
            if role == Role::ValidatingPeer || role == Role::ProxyTail {
                no_tx_receipt = no_tx_receipt
                    .sign(&self.key_pair)
                    .expect("Failed to put first signature.");
            }
            let recipient_peers = self.network_topology.sorted_peers.clone();
            let transaction_hash = transaction.hash();
            let peer_id = self.peer_id.clone();
            let tx_receipt_time = self.tx_receipt_time;
            drop(task::spawn(async move {
                task::sleep(tx_receipt_time).await;
                if transactions_awaiting_receipts
                    .write()
                    .await
                    .contains(&transaction_hash)
                {
                    let mut send_futures = Vec::new();
                    for peer in &recipient_peers {
                        if *peer != peer_id {
                            send_futures.push(
                                VersionedMessage::from(Message::NoTransactionReceiptReceived(
                                    no_tx_receipt.clone(),
                                ))
                                .send_to(peer),
                            );
                        }
                    }
                    future::join_all(send_futures)
                        .await
                        .into_iter()
                        .filter_map(Result::err)
                        .for_each(|error| {
                            iroha_logger::error!(
                                "Failed to send NoTransactionReceiptReceived message to peers: {:?}",
                                error
                            )
                        });
                }
            }));
        }
        future::join_all(send_futures)
            .await
            .into_iter()
            .filter_map(Result::err)
            .for_each(|error| {
                iroha_logger::error!("Failed to send transactions to the leader: {:?}", error)
            });
    }

    /// Gossip transactions to other peers.
    pub async fn gossip_transactions(&mut self, transactions: &[VersionedAcceptedTransaction]) {
        iroha_logger::debug!(
            "{:?} - Gossiping transactions. Number of transactions to forward: {}",
            self.network_topology.role(&self.peer_id),
            transactions.len(),
        );
        let leader = self.network_topology.leader().clone();
        let this_peer = self.peer_id.clone();
        let peers = self.network_topology.sorted_peers.clone();
        let transactions = transactions.to_vec();
        let mut send_futures = Vec::new();
        // TODO: send transactions in batch not to crowd message channels.
        for peer in &peers {
            for transaction in &transactions {
                if peer != &leader && peer != &this_peer {
                    let message = VersionedMessage::from(Message::from(TransactionForwarded::new(
                        transaction,
                        &this_peer,
                    )));
                    send_futures.push(message.send_to(peer));
                }
            }
        }
        let results = future::join_all(send_futures).await;
        results
            .into_iter()
            .filter_map(Result::err)
            .for_each(|error| iroha_logger::error!("Failed to gossip transactions: {:?}", error));
    }

    /// Should be called by a leader to start the consensus round with `BlockCreated` message.
    ///
    /// # Errors
    /// Can fail signing block
    pub async fn validate_and_publish_created_block(&mut self, block: ChainedBlock) -> Result<()> {
        let wsv = Arc::clone(&self.world_state_view);
        let block = block.validate(&*wsv.read().await, &self.permissions_validator);
        let network_topology = self.network_topology_current_or_genesis(&block);
        iroha_logger::info!(
            "{:?} - Created a block with hash {}.",
            network_topology.role(&self.peer_id),
            block.hash(),
        );
        for event in Vec::<Event>::from(&block.clone()) {
            self.events_sender.send(event).await;
        }
        if !network_topology.is_consensus_required() {
            self.commit_block(block).await;
            return Ok(());
        }

        let voting_block = VotingBlock::new(block.clone());
        *self.voting_block.write().await = Some(voting_block.clone());
        let message = VersionedMessage::from(Message::BlockCreated(
            block.clone().sign(&self.key_pair)?.into(),
        ));
        let recipient_peers = network_topology.sorted_peers.clone();
        let this_peer = self.peer_id.clone();
        let mut send_futures = Vec::new();
        for peer in &recipient_peers {
            if this_peer != *peer {
                send_futures.push(message.clone().send_to(peer));
            }
        }
        let results = futures::future::join_all(send_futures).await;
        results
            .into_iter()
            .filter_map(Result::err)
            .for_each(|error_result| {
                iroha_logger::error!(
                    "Failed to send BlockCreated messages from {}: {:?}",
                    this_peer.address,
                    error_result
                )
            });
        self.start_commit_countdown(
            voting_block.clone(),
            self.latest_block_hash,
            self.number_of_view_changes,
        )
        .await;
        Ok(())
    }

    /// Starts countdown for a period in which the `voting_block` should be committed.
    #[iroha_logger::log(skip(self, voting_block))]
    pub async fn start_commit_countdown(
        &self,
        voting_block: VotingBlock,
        latest_block_hash: Hash,
        number_of_view_changes: u32,
    ) {
        let old_voting_block = voting_block;
        let voting_block = Arc::clone(&self.voting_block);
        let key_pair = self.key_pair.clone();
        let recipient_peers = self.network_topology.sorted_peers.clone();
        let peer_id = self.peer_id.clone();
        let commit_time = self.commit_time;
        drop(task::spawn(async move {
            task::sleep(commit_time).await;
            let voting_block = if let Some(voting_block) = voting_block.write().await.clone() {
                voting_block
            } else {
                return;
            };

            // If the block was not yet committed send commit timeout to other peers to initiate view change.
            if voting_block.block.hash() != old_voting_block.block.hash() {
                return;
            }

            #[allow(clippy::expect_used)]
            let message = VersionedMessage::from(Message::CommitTimeout(
                CommitTimeout::new(&voting_block, latest_block_hash, number_of_view_changes)
                    .sign(&key_pair)
                    .expect("Failed to sign CommitTimeout"),
            ));
            let mut send_futures = Vec::new();
            for peer in &recipient_peers {
                if *peer != peer_id {
                    send_futures.push(message.clone().send_to(peer));
                }
            }
            future::join_all(send_futures)
                .await
                .into_iter()
                .filter_map(Result::err)
                .for_each(|error| {
                    iroha_logger::error!("Failed to send CommitTimeout messages: {:?}", error)
                });
        }));
    }

    /// Commits `ValidBlock` and changes the state of the `Sumeragi` and its `NetworkTopology`.
    #[iroha_logger::log(skip(self, block))]
    pub async fn commit_block(&mut self, block: VersionedValidBlock) {
        let block_hash = block.hash();
        self.latest_block_hash = block_hash;
        self.invalidated_blocks_hashes.clear();
        self.transactions_awaiting_created_block
            .write()
            .await
            .clear();
        self.transactions_awaiting_receipts.write().await.clear();
        self.block_height = block.header().height;

        for event in Vec::<Event>::from(&block.clone().commit()) {
            self.events_sender.send(event).await;
        }

        self.blocks_sender.send(block).await;

        let previous_role = self.network_topology.role(&self.peer_id);
        self.network_topology
            .sort_peers_by_hash(Some(self.latest_block_hash));
        iroha_logger::info!(
            "{:?} - Commiting block with hash {}. New role: {:?}. New height: {}",
            previous_role,
            block_hash,
            self.network_topology.role(&self.peer_id),
            self.block_height,
        );
        *self.voting_block.write().await = None;
        self.number_of_view_changes = 0;
        self.votes_for_blocks.clear();
    }

    async fn change_view(&mut self) {
        self.transactions_awaiting_created_block
            .write()
            .await
            .clear();
        self.transactions_awaiting_receipts.write().await.clear();
        let previous_role = self.network_topology.role(&self.peer_id);
        if self.number_of_view_changes < self.n_topology_shifts_before_reshuffle {
            self.network_topology.shift_peers_by_one();
        } else {
            self.network_topology.sort_peers_by_hash_and_counter(
                Some(self.latest_block_hash),
                self.number_of_view_changes,
            )
        }
        *self.voting_block.write().await = None;
        self.number_of_view_changes += 1;
        iroha_logger::info!(
            "{} - {:?} - Changing view at block with hash {}. New role: {:?}. Number of view changes (including this): {}",
            self.peer_id.address,
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
        block: &VersionedValidBlock,
    ) -> InitializedNetworkTopology {
        if block.header().is_genesis() && self.block_height == 0 {
            if let Some(genesis_topology) = block.header().genesis_topology.clone() {
                iroha_logger::info!("Using network topology from genesis block.");
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
    ///
    /// # Errors
    /// Can fail if consensus criteria is not meet:
    /// `len(peers) >= 3 * max_faulty_peers + 1`
    pub fn init(self) -> Result<InitializedNetworkTopology> {
        let min_peers = 3 * self.max_faults + 1;
        if self.peers.len() >= min_peers as usize {
            let mut topology = InitializedNetworkTopology {
                sorted_peers: self.peers.into_iter().collect(),
                max_faults: self.max_faults,
            };
            topology.sort_peers_by_hash(self.block_hash);
            Ok(topology)
        } else {
            Err(error!(
                "Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}",
                3 * self.max_faults + 1,
                self.peers.len(),
            ))
        }
    }
}

/// Represents a topology of peers, defining a `role` for each peer based on the previous block hash.
#[derive(Debug, Clone, Encode, Decode)]
pub struct InitializedNetworkTopology {
    /// Current order of peers. The roles of peers are defined based on this order.
    sorted_peers: Vec<PeerId>,
    /// Maximum faulty peers in a network.
    max_faults: u32,
}

impl InitializedNetworkTopology {
    /// Construct `InitializedNetworkTopology` from predefined peer roles.
    ///
    /// # Errors
    /// Can fail if role conditions are not meet
    pub fn from_roles(
        leader: PeerId,
        validating_peers: Vec<PeerId>,
        proxy_tail: PeerId,
        observing_peers: Vec<PeerId>,
        max_faults: u32,
    ) -> Result<Self> {
        let validating_peers_required_len = 2 * max_faults - 1;
        if validating_peers.len() != validating_peers_required_len as usize {
            return Err(error!(
                "Expected {} validating peers, found {}.",
                validating_peers_required_len,
                validating_peers.len()
            ));
        }
        let observing_peers_min_len = max_faults as usize;
        if observing_peers.len() < observing_peers_min_len {
            return Err(error!(
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
    pub fn update(&mut self, peers: &BTreeSet<PeerId>, latest_block_hash: Hash) {
        let current_peers: BTreeSet<_> = self.sorted_peers.iter().cloned().collect();
        if peers != &current_peers {
            self.sorted_peers = peers.iter().cloned().collect();
            self.sort_peers_by_hash(Some(latest_block_hash));
        }
    }

    /// Answers if the consensus stage is required with the current number of peers.
    pub fn is_consensus_required(&self) -> bool {
        self.sorted_peers.len() > 1
    }

    /// The minimum number of signatures needed to commit a block
    pub const fn min_votes_for_commit(&self) -> u32 {
        2 * self.max_faults + 1
    }

    /// The minimum number of signatures needed to perform a view change (change leader, proxy, etc.)
    pub const fn min_votes_for_view_change(&self) -> u32 {
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
    #[allow(clippy::expect_used)]
    pub fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    /// The proxy tail of the current round.
    #[allow(clippy::expect_used)]
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

    /// Sorts peers based on the `hash`.
    pub fn sort_peers_by_hash(&mut self, hash: Option<Hash>) {
        self.sort_peers_by_hash_and_counter(hash, 0)
    }

    /// Sorts peers based on the `hash` and `counter` combined as a seed.
    pub fn sort_peers_by_hash_and_counter(&mut self, hash: Option<Hash>, counter: u32) {
        self.sorted_peers
            .sort_by(|p1, p2| p1.address.cmp(&p2.address));
        let mut bytes: Vec<u8> = counter.to_le_bytes().to_vec();
        if let Some(Hash(hash)) = hash {
            bytes.append(hash.to_vec().as_mut());
        }
        let Hash(bytes) = Hash::new(&bytes);
        let mut rng = StdRng::from_seed(bytes);
        self.sorted_peers.shuffle(&mut rng);
    }

    /// Shifts `sorted_peers` by one to the right.
    #[allow(clippy::expect_used)]
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
    ///
    /// # Errors
    /// Fails if there are no such peer with this key and if signature verification fails
    pub fn verify_signature_with_role(
        &self,
        signature: &Signature,
        role: Role,
        message_payload: &[u8],
    ) -> Result<()> {
        if role
            .peers(self)
            .iter()
            .any(|peer| peer.public_key == signature.public_key)
        {
            Ok(())
        } else {
            Err(error!("No {:?} with this public key exists.", role))
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

    /// Get sorted peers.
    pub fn sorted_peers(&self) -> &[PeerId] {
        self.sorted_peers.as_slice()
    }

    /// Get max faulty peers limit.
    pub const fn max_faults(&self) -> u32 {
        self.max_faults
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
    pub fn peers(self, network_topology: &InitializedNetworkTopology) -> Vec<PeerId> {
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

    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use async_std::task;
    use iroha_crypto::{Hash, KeyPair, Signature, Signatures};
    use iroha_data_model::prelude::*;
    use iroha_derive::*;
    use iroha_error::{error, Result, WrapErr};
    use iroha_network::prelude::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use crate::{
        sumeragi::{InitializedNetworkTopology, Role, Sumeragi, VotingBlock},
        torii::uri,
        VersionedAcceptedTransaction, VersionedValidBlock,
    };

    declare_versioned_with_scale!(VersionedMessage 1..2);

    impl VersionedMessage {
        /// Same as [`as_v1`] but also does conversion
        pub const fn as_inner_v1(&self) -> &Message {
            match self {
                Self::V1(v1) => &v1.0,
            }
        }

        /// Same as [`as_inner_v1`] but returns mutable reference
        pub fn as_mut_inner_v1(&mut self) -> &mut Message {
            match self {
                Self::V1(v1) => &mut v1.0,
            }
        }

        /// Same as [`into_v1`] but also does conversion
        #[allow(clippy::missing_const_for_fn)]
        pub fn into_inner_v1(self) -> Message {
            match self {
                Self::V1(v1) => v1.0,
            }
        }

        /// Send this message over the network to the specified `peer`.
        /// # Errors
        /// Fails if network sending fails
        #[iroha_logger::log(skip(self))]
        pub async fn send_to(self, peer: &PeerId) -> Result<()> {
            match Network::send_request_to(
                &peer.address,
                Request::new(uri::CONSENSUS_URI, self.encode_versioned()?),
            )
            .await
            .wrap_err_with(|| format!("Failed to send to peer {} with error", peer.address))?
            {
                Response::Ok(_) => Ok(()),
                Response::InternalError => Err(error!(
                    "Failed to send message - Internal Error on peer: {:?}",
                    peer
                )),
            }
        }

        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            self.as_inner_v1().handle(sumeragi).await
        }
    }

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[version_with_scale(n = 1, versioned = "VersionedMessage")]
    #[derive(Io, Decode, Encode, Debug, Clone, FromVariant)]
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
        /// Handles this message as part of `Sumeragi` consensus.
        /// # Errors
        /// Fails if message handling fails
        #[iroha_logger::log(skip(self, sumeragi))]
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
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
    #[non_exhaustive]
    pub struct BlockCreated {
        /// The corresponding block.
        pub block: VersionedValidBlock,
    }

    impl BlockCreated {
        /// # Errors
        /// Asserts specific instruction number of instruction constraint
        pub fn check_instruction_len(&self, max_instruction_number: usize) -> Result<()> {
            self.block.check_instruction_len(max_instruction_number)
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            // There should be only one block in discussion during a round.
            if sumeragi.voting_block.write().await.is_some() {
                return Ok(());
            }
            for event in Vec::<Event>::from(&self.block.clone()) {
                sumeragi.events_sender.send(event).await;
            }
            let network_topology = sumeragi.network_topology_current_or_genesis(&self.block);
            if network_topology
                .filter_signatures_by_roles(&[Role::Leader], &self.block.verified_signatures())
                .is_empty()
            {
                iroha_logger::error!(
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
            match network_topology.role(&sumeragi.peer_id) {
                Role::ValidatingPeer => {
                    if self.block.validation_check(
                        &*sumeragi.world_state_view.read().await,
                        sumeragi.latest_block_hash,
                        sumeragi.number_of_view_changes,
                        sumeragi.block_height,
                        sumeragi.max_instruction_number,
                    ) {
                        let wsv = sumeragi.world_state_view.read().await;
                        if let Err(e) = VersionedMessage::from(Message::BlockSigned(
                            self.block
                                .clone()
                                .revalidate(&*wsv, &sumeragi.permissions_validator)
                                .sign(&sumeragi.key_pair)?
                                .into(),
                        ))
                        .send_to(network_topology.proxy_tail())
                        .await
                        {
                            iroha_logger::error!(
                                "Failed to send BlockSigned message to the proxy tail: {:?}",
                                e
                            );
                        } else {
                            iroha_logger::info!(
                                "{:?} - Signed block candidate with hash {}.",
                                network_topology.role(&sumeragi.peer_id),
                                self.block.hash(),
                            );
                        }
                        //TODO: send to set b so they can observe
                    }
                    let voting_block = VotingBlock::new(self.block.clone());
                    *sumeragi.voting_block.write().await = Some(voting_block.clone());
                    sumeragi
                        .start_commit_countdown(
                            voting_block.clone(),
                            sumeragi.latest_block_hash,
                            sumeragi.number_of_view_changes,
                        )
                        .await;
                }
                Role::ProxyTail => {
                    let voting_block = VotingBlock::new(self.block.clone());
                    *sumeragi.voting_block.write().await = Some(voting_block.clone());
                    sumeragi
                        .start_commit_countdown(
                            voting_block.clone(),
                            sumeragi.latest_block_hash,
                            sumeragi.number_of_view_changes,
                        )
                        .await;
                }
                Role::ObservingPeer => {
                    *sumeragi.voting_block.write().await =
                        Some(VotingBlock::new(self.block.clone()));
                }
                Role::Leader => (),
            }
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
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            let network_topology = sumeragi.network_topology_current_or_genesis(&self.block);
            if let Role::ProxyTail = network_topology.role(&sumeragi.peer_id) {
                let block_hash = self.block.hash();
                let entry = sumeragi
                    .votes_for_blocks
                    .entry(block_hash)
                    .or_insert_with(|| self.block.clone());
                entry
                    .as_mut_inner_v1()
                    .signatures
                    .append(&self.block.verified_signatures());
                let valid_signatures = network_topology.filter_signatures_by_roles(
                    &[Role::ValidatingPeer, Role::Leader],
                    &entry.verified_signatures(),
                );
                iroha_logger::info!(
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
                    block.as_mut_inner_v1().signatures = signatures;
                    let block = block.sign(&sumeragi.key_pair)?;
                    iroha_logger::info!(
                        "{:?} - Block reached required number of votes. Block hash {}.",
                        network_topology.role(&sumeragi.peer_id),
                        block_hash,
                    );
                    let message =
                        VersionedMessage::from(Message::BlockCommitted(block.clone().into()));
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
                            iroha_logger::error!(
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
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
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
                && sumeragi.latest_block_hash == self.block.header().previous_block_hash
            {
                let mut block = self.block.clone();
                block.as_mut_inner_v1().signatures.clear();
                block.as_mut_inner_v1().signatures.append(&valid_signatures);
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

    /// `Message` structure showing a `transaction_receipt` from a leader as a proof that peer did not create a block
    /// in `block_time` after receiving this transaction.
    /// Peers validate the receipt, and sign the message to vote for changing the view.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    #[non_exhaustive]
    pub struct BlockCreationTimeout {
        /// A proof of the leader receiving and accepting a transaction.
        pub transaction_receipt: TransactionReceipt,
        /// Signatures of the peers who voted for changing the leader.
        pub signatures: Signatures,
        /// The block hash of the latest committed block.
        pub latest_block_hash: Hash,
        /// Number of view changes since the last commit.
        pub number_of_view_changes: u32,
    }

    impl BlockCreationTimeout {
        /// Construct `BlockCreationTimeout` message.
        pub fn new(
            transaction_receipt: TransactionReceipt,
            latest_block_hash: Hash,
            number_of_view_changes: u32,
        ) -> Self {
            BlockCreationTimeout {
                transaction_receipt,
                signatures: Signatures::default(),
                latest_block_hash,
                number_of_view_changes,
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the leader does not produce a block
        /// after receiving transaction in `block_time`.
        ///
        /// # Errors
        /// Can fail during creation of signature
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<BlockCreationTimeout> {
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

        fn has_same_state(&self, sumeragi: &Sumeragi) -> bool {
            sumeragi.number_of_view_changes == self.number_of_view_changes
                && sumeragi.latest_block_hash == self.latest_block_hash
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of created block
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            if !self.has_same_state(sumeragi) {
                return Ok(());
            }
            let role = sumeragi.network_topology.role(&sumeragi.peer_id);
            let tx_receipt = self.transaction_receipt.clone();
            if tx_receipt.is_valid(&sumeragi.network_topology)
                && tx_receipt.is_block_should_be_created(sumeragi.block_time)
                && (role == Role::ValidatingPeer || role == Role::ProxyTail)
                // Block is not yet created
                && sumeragi.voting_block.write().await.is_none()
                && !self.signatures.contains(&sumeragi.key_pair.public_key)
            {
                let block_creation_timeout_message =
                    VersionedMessage::from(Message::BlockCreationTimeout(
                        self.clone()
                            .sign(&sumeragi.key_pair)
                            .wrap_err("Failed to sign.")?,
                    ));
                drop(
                    futures::future::join_all(
                        sumeragi
                            .network_topology
                            .sorted_peers
                            .iter()
                            .map(|peer| block_creation_timeout_message.clone().send_to(peer)),
                    )
                    .await,
                );
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
                iroha_logger::info!(
                    "{:?} - Block creation timeout verified by voting. Previous block hash: {}.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                    sumeragi.latest_block_hash,
                );
                sumeragi.change_view().await;
            }
            Ok(())
        }
    }

    /// `Message` structure describing a failed attempt to forward transaction to a leader.
    /// Peers sign it if they are not able to get a `TxReceipt` from a leader after sending the specified transaction.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    #[non_exhaustive]
    pub struct NoTransactionReceiptReceived {
        /// Transaction for which there was no `TransactionReceipt`.
        pub transaction: VersionedAcceptedTransaction,
        /// Signatures of the peers who voted for changing the leader.
        pub signatures: Signatures,
        /// The id of the leader, to determine that peer topologies are synchronized.
        pub leader_id: PeerId,
        /// The block hash of the latest committed block.
        pub latest_block_hash: Hash,
        /// Number of view changes since the last commit.
        pub number_of_view_changes: u32,
    }

    impl NoTransactionReceiptReceived {
        /// Constructs a new `NoTransactionReceiptReceived` message with no signatures.
        pub fn new(
            transaction: &VersionedAcceptedTransaction,
            leader_id: PeerId,
            latest_block_hash: Hash,
            number_of_view_changes: u32,
        ) -> NoTransactionReceiptReceived {
            NoTransactionReceiptReceived {
                transaction: transaction.clone(),
                signatures: Signatures::default(),
                leader_id,
                latest_block_hash,
                number_of_view_changes,
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the leader refuses to accept this transaction.
        ///
        /// # Errors
        /// Can fail creating new signature
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<NoTransactionReceiptReceived> {
            let signature = Signature::new(
                key_pair.clone(),
                &Vec::<u8>::from(self.transaction.as_inner_v1().clone()),
            )?;
            self.signatures.add(signature);
            Ok(self)
        }

        /// Signatures that are verified with the `transaction` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures
                .verified(&Vec::<u8>::from(self.transaction.as_inner_v1().clone()))
        }

        fn has_same_state(&self, sumeragi: &Sumeragi) -> bool {
            sumeragi.number_of_view_changes == self.number_of_view_changes
                && sumeragi.latest_block_hash == self.latest_block_hash
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail while signing message
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            if !self.has_same_state(sumeragi) {
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
                iroha_logger::info!(
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
                let _result =
                    VersionedMessage::from(Message::TransactionForwarded(TransactionForwarded {
                        transaction: self.transaction.clone(),
                        peer: sumeragi.peer_id.clone(),
                    }))
                    .send_to(sumeragi.network_topology.leader())
                    .await;
                let _ = sumeragi
                    .transactions_awaiting_receipts
                    .write()
                    .await
                    .insert(self.transaction.hash());
                let pending_forwarded_tx_hashes =
                    Arc::clone(&sumeragi.transactions_awaiting_receipts);
                let recipient_peers = sumeragi.network_topology.sorted_peers.clone();
                let tx_receipt_time = sumeragi.tx_receipt_time;
                let no_tx_receipt = self
                    .clone()
                    .sign(&sumeragi.key_pair)
                    .wrap_err("Failed to sign.")?;
                drop(task::spawn(async move {
                    task::sleep(tx_receipt_time).await;
                    if pending_forwarded_tx_hashes
                        .write()
                        .await
                        .contains(&no_tx_receipt.transaction.hash())
                    {
                        let mut send_futures = Vec::new();
                        for peer in &recipient_peers {
                            send_futures.push(
                                VersionedMessage::from(Message::NoTransactionReceiptReceived(
                                    no_tx_receipt.clone(),
                                ))
                                .send_to(peer),
                            );
                        }
                        drop(futures::future::join_all(send_futures).await);
                    }
                }));
            }
            Ok(())
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
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            if sumeragi.is_leader() {
                if let Err(err) = VersionedMessage::from(Message::TransactionReceived(
                    TransactionReceipt::new(&self.transaction, &sumeragi.key_pair)?,
                ))
                .send_to(&self.peer)
                .await
                {
                    iroha_logger::error!(
                        "{:?} - Failed to send a transaction receipt to peer {}: {}",
                        sumeragi.network_topology.role(&sumeragi.peer_id),
                        self.peer.address,
                        err
                    )
                }
            }
            sumeragi
                .transactions_sender
                .send(self.transaction.clone())
                .await;
            Ok(())
        }
    }

    /// `Message` structure describing a receipt sent by the leader to the peer it got this transaction from.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    #[non_exhaustive]
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
        ///
        /// # Errors
        /// Can fail creating new signature
        #[allow(clippy::expect_used, clippy::unwrap_in_result)]
        pub fn new(
            transaction: &VersionedAcceptedTransaction,
            key_pair: &KeyPair,
        ) -> Result<TransactionReceipt> {
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
                    &self.signature,
                    Role::Leader,
                    self.transaction_hash.as_ref(),
                )
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

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail due to signing of block
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            // Implausible time in the future, means that the leader lies
            #[allow(clippy::expect_used)]
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
                    Arc::clone(&sumeragi.transactions_awaiting_created_block);
                let tx_hash = self.transaction_hash;
                let role = sumeragi.network_topology.role(&sumeragi.peer_id);
                let mut block_creation_timeout = BlockCreationTimeout::new(
                    self.clone(),
                    sumeragi.latest_block_hash,
                    sumeragi.number_of_view_changes,
                );
                if role == Role::ValidatingPeer || role == Role::ProxyTail {
                    block_creation_timeout = block_creation_timeout
                        .sign(&sumeragi.key_pair)
                        .wrap_err("Failed to put first signature.")?;
                }
                let _ = transactions_awaiting_created_block
                    .write()
                    .await
                    .insert(tx_hash);
                let recipient_peers = sumeragi.network_topology.sorted_peers.clone();
                drop(task::spawn(async move {
                    task::sleep(block_time).await;
                    // Suspect leader if the block was not yet created
                    if transactions_awaiting_created_block
                        .write()
                        .await
                        .contains(&tx_hash)
                    {
                        let block_creation_timeout_message = VersionedMessage::from(
                            Message::BlockCreationTimeout(block_creation_timeout),
                        );
                        drop(
                            futures::future::join_all(
                                recipient_peers.iter().map(|peer| {
                                    block_creation_timeout_message.clone().send_to(peer)
                                }),
                            )
                            .await,
                        );
                    }
                }));
            }
            Ok(())
        }
    }

    /// `Message` structure describing a request to other peers to change view because of the commit timeout.
    /// Peers vote on this view change by signing and forwarding this structure.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    #[non_exhaustive]
    pub struct CommitTimeout {
        /// The hash of the block in discussion in this round.
        pub voting_block_hash: Hash,
        /// The signatures of the peers who vote to for a view change.
        pub signatures: Signatures,
        /// The block hash of the latest committed block.
        pub latest_block_hash: Hash,
        /// Number of view changes since the last commit.
        pub number_of_view_changes: u32,
    }

    impl CommitTimeout {
        /// Constructs a new commit timeout message with no signatures.
        pub fn new(
            voting_block: &VotingBlock,
            latest_block_hash: Hash,
            number_of_view_changes: u32,
        ) -> CommitTimeout {
            CommitTimeout {
                voting_block_hash: voting_block.block.hash(),
                signatures: Signatures::default(),
                latest_block_hash,
                number_of_view_changes,
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the proxy tail does not send commit message in `commit_time`.
        ///
        /// # Errors
        /// Can fail creating new signature
        pub fn sign(mut self, key_pair: &KeyPair) -> Result<CommitTimeout> {
            let signature = Signature::new(key_pair.clone(), self.voting_block_hash.as_ref())?;
            self.signatures.add(signature);
            Ok(self)
        }

        /// Signatures that are verified with the `voting_block_hash` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures.verified(self.voting_block_hash.as_ref())
        }

        fn has_same_state(&self, sumeragi: &Sumeragi) -> bool {
            sumeragi.number_of_view_changes == self.number_of_view_changes
                && sumeragi.latest_block_hash == self.latest_block_hash
        }

        /// Handles this message as part of `Sumeragi` consensus.
        ///
        /// # Errors
        /// Can fail creating new signature
        pub async fn handle(&self, sumeragi: &mut Sumeragi) -> Result<()> {
            if !self.has_same_state(sumeragi) {
                return Ok(());
            }
            if sumeragi
                .network_topology
                .filter_signatures_by_roles(
                    &[Role::Leader, Role::ValidatingPeer, Role::ProxyTail],
                    &self.verified_signatures(),
                )
                .len()
                >= sumeragi.network_topology.min_votes_for_view_change() as usize
                && sumeragi
                    .voting_block
                    .read()
                    .await
                    .clone()
                    .map(|block| block.block.hash())
                    == Some(self.voting_block_hash)
            {
                sumeragi
                    .invalidated_blocks_hashes
                    .push(self.voting_block_hash);
                iroha_logger::info!(
                    "{:?} - Block commit timeout verified by voting. Previous block hash: {}.",
                    sumeragi.network_topology.role(&sumeragi.peer_id),
                    sumeragi.latest_block_hash,
                );
                sumeragi.change_view().await;
            } else {
                let role = sumeragi.network_topology.role(&sumeragi.peer_id);
                if role != Role::ObservingPeer {
                    let voting_block = sumeragi.voting_block.read().await.clone();
                    if let Some(voting_block) = voting_block {
                        #[allow(clippy::expect_used)]
                        let current_time = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .expect("Failed to get System Time.");
                        if voting_block.block.hash() == self.voting_block_hash
                            && (current_time - voting_block.voted_at) >= sumeragi.commit_time
                            && !self.signatures.contains(&sumeragi.key_pair.public_key)
                        {
                            let message = VersionedMessage::from(Message::CommitTimeout(
                                self.clone()
                                    .sign(&sumeragi.key_pair)
                                    .wrap_err("Failed to sign.")?,
                            ));
                            let sorted_peers = sumeragi.network_topology.sorted_peers.clone();
                            drop(task::spawn(async move {
                                let mut send_futures = Vec::new();
                                for peer in &sorted_peers {
                                    send_futures.push(message.clone().send_to(peer));
                                }
                                let results = futures::future::join_all(send_futures).await;
                                results
                                    .into_iter()
                                    .filter_map(Result::err)
                                    .for_each(|error| {
                                        iroha_logger::error!(
                                            "Failed to send CommitTimeout messages: {:?}",
                                            error
                                        )
                                    });
                            }));
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use std::{collections::BTreeSet, fmt::Debug, fs::File, io::BufReader, path::Path};

    use iroha_config::derive::Configurable;
    use iroha_crypto::prelude::*;
    use iroha_data_model::prelude::*;
    use iroha_error::{Result, WrapErr};
    use serde::{Deserialize, Serialize};

    const DEFAULT_BLOCK_TIME_MS: u64 = 1000;
    const DEFAULT_MAX_FAULTY_PEERS: u32 = 0;
    const DEFAULT_COMMIT_TIME_MS: u64 = 1000;
    const DEFAULT_TX_RECEIPT_TIME_MS: u64 = 200;
    const DEFAULT_MAX_INSTRUCTION_NUMBER: usize = 2_usize.pow(12);
    const DEFAULT_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE: u32 = 1;

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Clone, Debug, Deserialize, Serialize, Configurable)]
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
        /// Maximum amount of peers to fail and do not compromise the consensus.
        pub max_faulty_peers: u32,
        /// Amount of time Peer waits for CommitMessage from the proxy tail.
        pub commit_time_ms: u64,
        /// Amount of time Peer waits for TxReceipt from the leader.
        pub tx_receipt_time_ms: u64,
        /// After N view changes topology will change tactic from shifting by one, to reshuffle.
        pub n_topology_shifts_before_reshuffle: u32,
        /// Maximum instruction number per transaction
        pub max_instruction_number: usize,
    }

    impl Default for SumeragiConfiguration {
        fn default() -> Self {
            Self {
                key_pair: KeyPair::default(),
                trusted_peers: default_empty_trusted_peers(),
                peer_id: default_peer_id(),
                block_time_ms: DEFAULT_BLOCK_TIME_MS,
                max_faulty_peers: DEFAULT_MAX_FAULTY_PEERS,
                commit_time_ms: DEFAULT_COMMIT_TIME_MS,
                tx_receipt_time_ms: DEFAULT_TX_RECEIPT_TIME_MS,
                n_topology_shifts_before_reshuffle: DEFAULT_N_TOPOLOGY_SHIFTS_BEFORE_RESHUFFLE,
                max_instruction_number: DEFAULT_MAX_INSTRUCTION_NUMBER,
            }
        }
    }

    impl SumeragiConfiguration {
        /// Set `trusted_peers` configuration parameter - will overwrite the existing one.
        pub fn trusted_peers(&mut self, trusted_peers: Vec<PeerId>) {
            self.trusted_peers.peers = trusted_peers.into_iter().collect();
        }

        /// Set `max_faulty_peers` configuration parameter - will overwrite the existing one.
        pub fn max_faulty_peers(&mut self, max_faulty_peers: u32) {
            self.max_faulty_peers = max_faulty_peers;
        }

        /// Time estimation from receiving a transaction to storing it in a block on all peers.
        #[allow(clippy::integer_arithmetic)]
        pub const fn pipeline_time_ms(&self) -> u64 {
            self.tx_receipt_time_ms + self.block_time_ms + self.commit_time_ms
        }
    }

    /// `SumeragiConfiguration` provides an ability to define parameters such as `BLOCK_TIME_MS`
    /// and list of `TRUSTED_PEERS`.
    #[derive(Default, Clone, Debug, Deserialize, Serialize)]
    #[serde(rename_all = "UPPERCASE")]
    #[serde(transparent)]
    #[allow(clippy::exhaustive_structs)]
    pub struct TrustedPeers {
        /// Optional list of predefined trusted peers.
        pub peers: BTreeSet<PeerId>,
    }

    impl TrustedPeers {
        /// Load trusted peers variables from a json *pretty* formatted file.
        ///
        /// # Errors
        /// Fails if there is no file or if file is not valid json
        pub fn from_path<P: AsRef<Path> + Debug>(path: P) -> Result<TrustedPeers> {
            let file = File::open(path).wrap_err("Failed to open a file")?;
            let reader = BufReader::new(file);
            let trusted_peers: BTreeSet<PeerId> = serde_json::from_reader(reader)
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

    // Allowed because `BTreeSet::new()` is not const yet.
    #[allow(clippy::missing_const_for_fn)]
    fn default_empty_trusted_peers() -> TrustedPeers {
        TrustedPeers {
            peers: BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::collections::BTreeSet;

    #[cfg(feature = "network-mock")]
    use {
        crate::{config::Configuration, maintenance::System, queue::Queue, torii::Torii},
        async_std::{prelude::*, sync, task},
        network::*,
        std::time::Duration,
    };

    use super::*;

    #[cfg(feature = "network-mock")]
    mod network {
        pub const CONFIG_PATH: &str = "config.json";
        pub const TRUSTED_PEERS_PATH: &str = "tests/test_trusted_peers.json";
        pub const BLOCK_TIME_MS: u64 = 1000;
        pub const COMMIT_TIME_MS: u64 = 1000;
        pub const TX_RECEIPT_TIME_MS: u64 = 200;
        pub const TRANSACTION_TIME_TO_LIVE_MS: u64 = 100_000;

        pub fn get_free_address() -> String {
            format!(
                "127.0.0.1:{}",
                unique_port::get_unique_free_port().expect("Failed to get free port")
            )
        }
    }

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let listen_address = "127.0.0.1".to_owned();
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

    #[cfg(feature = "network-mock")]
    pub fn world_with_test_domains(public_key: PublicKey) -> World {
        let mut domains = BTreeMap::new();
        let mut domain = Domain::new("global");
        let account_id = AccountId::new("root", "global");
        let mut account = Account::new(account_id.clone());
        account.signatories.push(public_key);
        let _ = domain.accounts.insert(account_id, account);
        let _ = domains.insert("global".to_owned(), domain);
        World::with(domains, BTreeSet::new())
    }

    fn topology_test_peers() -> BTreeSet<PeerId> {
        vec![
            PeerId {
                address: "127.0.0.1:7878".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7879".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7880".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
            PeerId {
                address: "127.0.0.1:7881".to_owned(),
                public_key: KeyPair::generate()
                    .expect("Failed to generate KeyPair.")
                    .public_key,
            },
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn different_order() {
        let peers = topology_test_peers();
        let network_topology1 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        let network_topology2 = NetworkTopology::new(&peers, Some(Hash([2_u8; 32])), 1)
            .init()
            .expect("Failed to construct topology");
        assert_ne!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[test]
    fn same_order() {
        let peers = topology_test_peers();
        let network_topology1 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        let network_topology2 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        assert_eq!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[test]
    fn same_order_by_hash_and_counter() {
        let peers = topology_test_peers();
        let mut network_topology1 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        let mut network_topology2 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        network_topology1.sort_peers_by_hash_and_counter(Some(Hash([2_u8; 32])), 1);
        network_topology2.sort_peers_by_hash_and_counter(Some(Hash([2_u8; 32])), 1);
        assert_eq!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[test]
    fn different_order_by_hash_and_counter() {
        let peers = topology_test_peers();
        let mut network_topology1 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        let mut network_topology2 = NetworkTopology::new(&peers, Some(Hash([1_u8; 32])), 1)
            .init()
            .expect("Failed to initialize topology");
        network_topology1.sort_peers_by_hash_and_counter(Some(Hash([2_u8; 32])), 1);
        network_topology2.sort_peers_by_hash_and_counter(Some(Hash([2_u8; 32])), 2);
        assert_ne!(
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
            addresses.push((get_free_address(), get_free_address()));
            let (p2p_address, _) = &addresses[i];
            let peer_id = PeerId {
                address: p2p_address.clone(),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0_usize)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        iroha_logger::init(config.logger_configuration);
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(world_with_test_domains(
                root_key_pair.public_key.clone(),
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
                    block_sender,
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
                config.torii_configuration.clone(),
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            drop(task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            }));
            sumeragi.write().await.init(Hash([0_u8; 32]), 0);
            peers.push(sumeragi.clone());
            drop(task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let _result = message.handle(&mut *sumeragi.write().await).await;
                }
            }));
            let block_counter = block_counters[i].clone();
            drop(task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            }));
        }
        task::sleep(Duration::from_millis(2000)).await;
        // First peer is a leader in this particular case.
        let leader = peers
            .iter()
            .find(|peer| {
                task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![VersionedAcceptedTransaction::from_transaction(
                Transaction::new(
                    vec![],
                    AccountId::new("root", "global"),
                    TRANSACTION_TIME_TO_LIVE_MS,
                )
                .sign(&root_key_pair)
                .expect("Failed to sign transaction."),
                4096,
            )
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        task::sleep(Duration::from_millis(2000)).await;
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
            addresses.push((get_free_address(), get_free_address()));
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
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        iroha_logger::init(config.logger_configuration);
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(world_with_test_domains(
                root_key_pair.public_key.clone(),
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
                    block_sender,
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
                config.torii_configuration.clone(),
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            drop(task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            }));
            sumeragi.write().await.init(Hash([0_u8; 32]), 0);
            peers.push(sumeragi.clone());
            drop(task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate faulty proxy tail
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
                        if let Message::BlockSigned(..) = message.as_inner_v1() {
                            continue;
                        }
                    }
                    let _result = message.handle(&mut *sumeragi).await;
                }
            }));
            let block_counter = block_counters[i].clone();
            drop(task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            }));
        }
        task::sleep(Duration::from_millis(2000)).await;
        // First peer is a leader in this particular case.
        let leader = peers
            .iter()
            .find(|peer| {
                task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![VersionedAcceptedTransaction::from_transaction(
                Transaction::new(
                    vec![],
                    AccountId::new("root", "global"),
                    TRANSACTION_TIME_TO_LIVE_MS,
                )
                .sign(&root_key_pair)
                .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0_u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0_u8; 32])), 1)
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
            addresses.push((get_free_address(), get_free_address()));
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
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        iroha_logger::init(config.logger_configuration);
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(world_with_test_domains(
                root_key_pair.public_key.clone(),
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
                    block_sender,
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
                config.torii_configuration.clone(),
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            drop(task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            }));
            sumeragi.write().await.init(Hash([0_u8; 32]), 0);
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            drop(task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi_arc_clone.write().await;
                    // Simulate faulty leader
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::Leader {
                        if let Message::TransactionForwarded(..) = message.as_inner_v1() {
                            continue;
                        }
                    }
                    let _result = message.handle(&mut *sumeragi).await;
                }
            }));
            let block_counter = block_counters[i].clone();
            drop(task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            }));
            let sumeragi_arc_clone = sumeragi.clone();
            drop(task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    if sumeragi_arc_clone.read().await.is_leader() {
                        if let Err(e) = sumeragi_arc_clone
                            .write()
                            .await
                            .round(vec![transaction])
                            .await
                        {
                            iroha_logger::error!("{}", e);
                        }
                    }
                    task::sleep(Duration::from_millis(500)).await;
                }
            }));
        }
        task::sleep(Duration::from_millis(2000)).await;
        let peer = peers
            .iter()
            .find(|peer| {
                task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) != Role::Leader
                })
            })
            .expect("Failed to find a non-leader peer.");
        peer.write()
            .await
            .round(vec![VersionedAcceptedTransaction::from_transaction(
                Transaction::new(
                    vec![],
                    AccountId::new("root", "global"),
                    TRANSACTION_TIME_TO_LIVE_MS,
                )
                .sign(&root_key_pair)
                .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0_u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0_u8; 32])), 1)
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
            addresses.push((get_free_address(), get_free_address()));
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
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        iroha_logger::init(config.logger_configuration);
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        let ids_set: BTreeSet<PeerId> = ids.clone().into_iter().collect();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(world_with_test_domains(
                root_key_pair.public_key.clone(),
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
                    block_sender,
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
                config.torii_configuration.clone(),
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            drop(task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            }));
            sumeragi.write().await.init(Hash([0_u8; 32]), 0);
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            drop(task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    // Simulate faulty leader as if it does not send `BlockCreated` messages
                    if let Message::BlockCreated(..) = message.as_inner_v1() {
                        continue;
                    }
                    let _result = message.handle(&mut *sumeragi_arc_clone.write().await).await;
                }
            }));
            let block_counter = block_counters[i].clone();
            drop(task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            }));
            let sumeragi_arc_clone = sumeragi.clone();
            drop(task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    if sumeragi_arc_clone.read().await.is_leader() {
                        if let Err(e) = sumeragi_arc_clone
                            .write()
                            .await
                            .round(vec![transaction])
                            .await
                        {
                            iroha_logger::error!("{}", e);
                        }
                    }
                    task::sleep(Duration::from_millis(500)).await;
                }
            }));
        }
        task::sleep(Duration::from_millis(2000)).await;
        let peer = peers
            .iter()
            .find(|peer| {
                task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) != Role::Leader
                })
            })
            .expect("Failed to find a non-leader peer.");
        peer.write()
            .await
            .round(vec![VersionedAcceptedTransaction::from_transaction(
                Transaction::new(
                    vec![],
                    AccountId::new("root", "global"),
                    TRANSACTION_TIME_TO_LIVE_MS,
                )
                .sign(&root_key_pair)
                .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0_u8);
        }
        let mut network_topology = NetworkTopology::new(&ids_set, Some(Hash([0_u8; 32])), 1)
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
            addresses.push((get_free_address(), get_free_address()));
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
        config
            .load_trusted_peers_from_path(TRUSTED_PEERS_PATH)
            .expect("Failed to load trusted peers.");
        iroha_logger::init(config.logger_configuration);
        config.sumeragi_configuration.commit_time_ms = COMMIT_TIME_MS;
        config.sumeragi_configuration.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.sumeragi_configuration.block_time_ms = BLOCK_TIME_MS;
        config.sumeragi_configuration.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (sumeragi_message_sender, mut sumeragi_message_receiver) = sync::channel(100);
            let (block_sync_message_sender, _) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (events_sender, events_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(world_with_test_domains(
                root_key_pair.public_key.clone(),
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
                    block_sender,
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
                config.torii_configuration.clone(),
                wsv.clone(),
                tx,
                sumeragi_message_sender,
                block_sync_message_sender,
                System::new(&config),
                queue,
                sumeragi.clone(),
                (events_sender.clone(), events_receiver),
            );
            drop(task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            }));
            sumeragi.write().await.init(Hash([0_u8; 32]), 0);
            peers.push(sumeragi.clone());
            drop(task::spawn(async move {
                while let Some(message) = sumeragi_message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate leader producing empty blocks
                    if let Message::BlockCreated(ref block_created) = message.as_inner_v1() {
                        let mut block_created = block_created.clone();
                        block_created.block.as_mut_inner_v1().transactions = Vec::new();
                        let _result = Message::BlockCreated(block_created)
                            .handle(&mut *sumeragi)
                            .await;
                    } else {
                        let _result = message.handle(&mut *sumeragi).await;
                    }
                }
            }));
            let block_counter = block_counters[i].clone();
            drop(task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            }));
        }
        task::sleep(Duration::from_millis(2000)).await;
        let leader = peers
            .iter()
            .find(|peer| {
                task::block_on(async {
                    let peer = peer.write().await;
                    peer.network_topology.role(&peer.peer_id) == Role::Leader
                })
            })
            .expect("Failed to find a leader.");
        leader
            .write()
            .await
            .round(vec![VersionedAcceptedTransaction::from_transaction(
                Transaction::new(
                    vec![],
                    AccountId::new("root", "global"),
                    TRANSACTION_TIME_TO_LIVE_MS,
                )
                .sign(&root_key_pair)
                .expect("Failed to sign."),
                4096,
            )
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        task::sleep(Duration::from_millis(
            config.sumeragi_configuration.pipeline_time_ms() + 2000,
        ))
        .await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0_u8);
        }
        let ids: BTreeSet<PeerId> = ids.into_iter().collect();
        let mut network_topology = NetworkTopology::new(&ids, Some(Hash([0_u8; 32])), 1)
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
