//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use self::message::*;
use crate::{
    block::{PendingBlock, SignedBlock},
    config::Configuration,
    crypto::{Hash, KeyPair, Signatures},
    peer::PeerId,
    prelude::*,
};
use async_std::sync::RwLock;
use iroha_derive::*;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::{self, Debug, Formatter},
    sync::Arc,
    time::{Duration, SystemTime},
};

trait Consensus {
    fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Option<PendingBlock>;
}

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi {
    key_pair: KeyPair,
    network_topology: InitializedNetworkTopology,
    peer_id: PeerId,
    /// The block in discussion this round.
    voting_block: Arc<RwLock<Option<VotingBlock>>>,
    blocks_sender: Arc<RwLock<ValidBlockSender>>,
    transactions_sender: TransactionSender,
    world_state_view: Arc<RwLock<WorldStateView>>,
    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt.
    transactions_awaiting_receipts: Arc<RwLock<BTreeSet<Hash>>>,
    /// Hashes of the transactions that were accepted by the leader and are waiting to be stored in CreatedBlock.
    transactions_awaiting_created_block: Arc<RwLock<BTreeSet<Hash>>>,
    commit_time: Duration,
    tx_receipt_time: Duration,
    block_time: Duration,
    latest_block_hash: Hash,
    block_height: u64,
}

impl Sumeragi {
    /// Default `Sumeragi` constructor.
    pub fn new(
        config: Configuration,
        blocks_sender: Arc<RwLock<ValidBlockSender>>,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transactions_sender: TransactionSender,
        latest_block_hash: Hash,
        block_height: u64,
        //TODO: separate initialization from construction and do not return Result in `new`
    ) -> Result<Self, String> {
        Ok(Self {
            key_pair: KeyPair {
                public_key: config.public_key,
                private_key: config.private_key,
            },
            network_topology: NetworkTopology::new(
                &config.trusted_peers,
                Some(latest_block_hash),
                config.max_faulty_peers,
            )
            .init()?,
            peer_id: PeerId::new(&config.torii_url, &config.public_key),
            voting_block: Arc::new(RwLock::new(None)),
            blocks_sender,
            world_state_view,
            transactions_awaiting_receipts: Arc::new(RwLock::new(BTreeSet::new())),
            transactions_awaiting_created_block: Arc::new(RwLock::new(BTreeSet::new())),
            commit_time: Duration::from_millis(config.commit_time_ms),
            transactions_sender,
            tx_receipt_time: Duration::from_millis(config.tx_receipt_time_ms),
            block_time: Duration::from_millis(config.block_time_ms),
            latest_block_hash,
            block_height,
        })
    }

    /// Returns `true` if some block is in discussion, `false` otherwise.
    pub async fn voting_in_progress(&self) -> bool {
        self.voting_block.write().await.is_some()
    }

    /// the leader of each round just uses the transactions they have at hand to create a block
    pub async fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Result<(), String> {
        if transactions.is_empty() {
            return Ok(());
        }
        if let Role::Leader = self.network_topology.role(&self.peer_id) {
            let block = PendingBlock::new(transactions)
                .chain(self.block_height, self.latest_block_hash)
                .sign(&self.key_pair)?;
            if !self.network_topology.is_consensus_required() {
                self.commit_block(block).await;
                Ok(())
            } else {
                *self.voting_block.write().await = Some(VotingBlock::new(block.clone()));
                let message = Message::BlockCreated(block.clone());
                let recipient_peers = self.network_topology.sorted_peers.clone();
                let mut send_futures = Vec::new();
                for peer in &recipient_peers {
                    if self.peer_id != *peer {
                        send_futures.push(message.clone().send_to(peer));
                    }
                }
                send_futures.push(message.clone().send_to(self.network_topology.proxy_tail()));
                let results = futures::future::join_all(send_futures).await;
                results
                    .iter()
                    .filter(|result| result.is_err())
                    .for_each(|error_result| {
                        eprintln!("Failed to send messages: {:?}", error_result)
                    });
                Ok(())
            }
        } else {
            //Sends transactions to leader
            let mut send_futures = Vec::new();
            for transaction in &transactions {
                send_futures.push(
                    Message::TransactionForwarded(TransactionForwarded {
                        transaction: transaction.clone(),
                        peer: self.peer_id.clone(),
                    })
                    .send_to(self.network_topology.leader()),
                );
                self.transactions_awaiting_receipts
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
                    no_tx_receipt
                        .sign(&self.key_pair)
                        .expect("Failed to put first signature.");
                }
                let recipient_peers = self.network_topology.sorted_peers.clone();
                let transaction_hash = transaction.hash();
                let peer_id = self.peer_id.clone();
                let tx_receipt_time = self.tx_receipt_time;
                async_std::task::spawn(async move {
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
                                eprintln!(
                                    "Failed to send transactions to the leader: {:?}",
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
                    eprintln!(
                        "Failed to send transactions to the leader: {:?}",
                        error_result
                    )
                });
            Ok(())
        }
    }

    /// This method is used to handle messages from other peers.
    #[log]
    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: move handlers to `Message`
        match message {
            Message::BlockCreated(block) => self.handle_block_created(block).await?,
            Message::BlockSigned(block) => self.handle_block_signed(block).await?,
            Message::BlockCommitted(block) => self.handle_block_committed(block).await?,
            Message::CommitTimeout(change_view) => self.handle_commit_timeout(change_view).await?,
            Message::TransactionReceived(tx_receipt) => {
                self.handle_transaction_received(tx_receipt).await?
            }
            Message::TransactionForwarded(forwarded_tx) => {
                self.handle_transaction_forwarded(forwarded_tx).await?
            }
            Message::NoTransactionReceiptReceived(no_tx_receipt) => {
                self.handle_no_transaction_receipt(no_tx_receipt).await?
            }
            Message::BlockCreationTimeout(block_creation_timeout) => {
                self.handle_block_creation_timeout(block_creation_timeout)
                    .await?
            }
        }
        Ok(())
    }

    #[log]
    async fn handle_block_creation_timeout(
        &mut self,
        mut block_creation_timeout: BlockCreationTimeout,
    ) -> Result<(), String> {
        if self.network_topology.leader().public_key
            != block_creation_timeout
                .transaction_receipt
                .signature
                .public_key
        {
            return Ok(());
        }
        let role = self.network_topology.role(&self.peer_id);
        let tx_receipt = block_creation_timeout.transaction_receipt.clone();
        if tx_receipt.is_valid(&self.network_topology)
            && tx_receipt.is_block_should_be_created(self.block_time)
            && (role == Role::ValidatingPeer || role == Role::ProxyTail)
            // Block is not yet created
            && self.voting_block.write().await.is_none()
            && !block_creation_timeout.signatures.contains(&self.key_pair.public_key)
        {
            block_creation_timeout
                .sign(&self.key_pair)
                .expect("Failed to sign.");
            let block_creation_timeout_message =
                Message::BlockCreationTimeout(block_creation_timeout.clone());
            futures::future::join_all(
                self.network_topology
                    .sorted_peers
                    .iter()
                    .map(|peer| block_creation_timeout_message.clone().send_to(peer)),
            )
            .await;
        }
        if self
            .network_topology
            .filter_signatures_by_roles(
                &[Role::ProxyTail, Role::ValidatingPeer],
                &block_creation_timeout.verified_signatures(),
            )
            .len()
            >= self.network_topology.min_votes_for_view_change()
        {
            self.change_view().await;
        }
        Ok(())
    }

    #[log]
    async fn start_commit_countdown(&self, voting_block: VotingBlock) {
        let old_voting_block = voting_block;
        let voting_block = self.voting_block.clone();
        let key_pair = self.key_pair.clone();
        let recipient_peers = self.network_topology.sorted_peers.clone();
        let peer_id = self.peer_id.clone();
        let commit_time = self.commit_time;
        async_std::task::spawn(async move {
            async_std::task::sleep(commit_time).await;
            if let Some(voting_block) = voting_block.write().await.clone() {
                // If the block was not yet committed send commit timeout to other peers to initiate view change.
                if voting_block.block.hash() == old_voting_block.block.hash() {
                    let mut commit_timeout = CommitTimeout::new(voting_block);
                    if let Err(e) = commit_timeout.sign(&key_pair) {
                        eprintln!("Failed to sign CommitTimeout: {:?}", e);
                    }
                    let message = Message::CommitTimeout(commit_timeout.clone());
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
                            eprintln!("Failed to send messages: {:?}", error_result)
                        });
                }
            }
        });
    }

    #[log]
    async fn handle_no_transaction_receipt(
        &mut self,
        no_tx_receipt: NoTransactionReceiptReceived,
    ) -> Result<(), String> {
        if no_tx_receipt.leader_id != *self.network_topology.leader() {
            return Ok(());
        }
        if self
            .network_topology
            .filter_signatures_by_roles(
                &[Role::ProxyTail, Role::ValidatingPeer],
                &no_tx_receipt.verified_signatures(),
            )
            .len()
            >= self.network_topology.min_votes_for_view_change()
        {
            self.change_view().await;
            return Ok(());
        }
        let role = self.network_topology.role(&self.peer_id);
        if role == Role::ValidatingPeer || role == Role::ProxyTail {
            let mut no_tx_receipt = no_tx_receipt.clone();
            if !no_tx_receipt.signatures.contains(&self.key_pair.public_key) {
                no_tx_receipt.sign(&self.key_pair).expect("Failed to sign.");
                let _result = Message::TransactionForwarded(TransactionForwarded {
                    transaction: no_tx_receipt.transaction.clone(),
                    peer: self.peer_id.clone(),
                })
                .send_to(self.network_topology.leader())
                .await;
                self.transactions_awaiting_receipts
                    .write()
                    .await
                    .insert(no_tx_receipt.transaction.hash());
                let pending_forwarded_tx_hashes = self.transactions_awaiting_receipts.clone();
                let recipient_peers = self.network_topology.sorted_peers.clone();
                let tx_receipt_time = self.tx_receipt_time;
                async_std::task::spawn(async move {
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
                        futures::future::join_all(send_futures).await;
                    }
                });
            }
        }
        Ok(())
    }

    #[log]
    async fn handle_transaction_forwarded(
        &mut self,
        forwarded_tx: TransactionForwarded,
    ) -> Result<(), String> {
        let _result = Message::TransactionReceived(TransactionReceipt::new(
            &forwarded_tx.transaction,
            &self.key_pair,
        )?)
        .send_to(&forwarded_tx.peer)
        .await;
        self.transactions_sender
            .send(forwarded_tx.transaction.clone())
            .await;
        Ok(())
    }

    #[log]
    async fn handle_transaction_received(
        &mut self,
        tx_receipt: TransactionReceipt,
    ) -> Result<(), String> {
        // Implausible time in the future, means that the leader lies
        if self.network_topology.role(&self.peer_id) != Role::Leader
            && tx_receipt.received_at
                <= SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
            && tx_receipt.is_valid(&self.network_topology)
            && self
                .transactions_awaiting_receipts
                .write()
                .await
                .contains(&tx_receipt.transaction_hash)
        {
            self.transactions_awaiting_receipts
                .write()
                .await
                .remove(&tx_receipt.transaction_hash);
            let block_time = self.block_time;
            let transactions_awaiting_created_block =
                self.transactions_awaiting_created_block.clone();
            let tx_hash = tx_receipt.transaction_hash;
            let role = self.network_topology.role(&self.peer_id);
            let mut block_creation_timeout = BlockCreationTimeout::new(&tx_receipt);
            if role == Role::ValidatingPeer || role == Role::ProxyTail {
                block_creation_timeout
                    .sign(&self.key_pair)
                    .expect("Failed to put first signature.");
            }
            transactions_awaiting_created_block
                .write()
                .await
                .insert(tx_hash);
            let recipient_peers = self.network_topology.sorted_peers.clone();
            async_std::task::spawn(async move {
                async_std::task::sleep(block_time).await;
                // Suspect leader if the block was not yet created
                if transactions_awaiting_created_block
                    .write()
                    .await
                    .contains(&tx_hash)
                {
                    let block_creation_timeout_message =
                        Message::BlockCreationTimeout(block_creation_timeout);
                    futures::future::join_all(
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

    #[log]
    async fn handle_block_created(&mut self, block: SignedBlock) -> Result<(), String> {
        if self
            .network_topology
            .filter_signatures_by_roles(&[Role::Leader], &block.verified_signatures())
            .is_empty()
        {
            return Ok(());
        }
        self.transactions_awaiting_created_block
            .write()
            .await
            .clear();
        match self.network_topology.role(&self.peer_id) {
            Role::ValidatingPeer => {
                if !block.transactions.is_empty() {
                    if let Err(e) = Message::BlockSigned(block.clone().sign(&self.key_pair)?)
                        .send_to(self.network_topology.proxy_tail())
                        .await
                    {
                        eprintln!(
                            "Failed to send BlockSigned message to the proxy tail: {:?}",
                            e
                        );
                    }
                    //TODO: send to set b so they can observe
                }
                let voting_block = VotingBlock::new(block);
                *self.voting_block.write().await = Some(voting_block.clone());
                self.start_commit_countdown(voting_block.clone()).await;
            }
            Role::ProxyTail => {
                if self.voting_block.write().await.is_none() {
                    *self.voting_block.write().await = Some(VotingBlock::new(block))
                }
            }
            Role::ObservingPeer => {
                *self.voting_block.write().await = Some(VotingBlock::new(block));
            }
            _ => (),
        }
        Ok(())
    }

    #[log]
    async fn handle_block_signed(&mut self, block: SignedBlock) -> Result<(), String> {
        if let Role::ProxyTail = self.network_topology.role(&self.peer_id) {
            let voting_block = self.voting_block.write().await.clone();
            match voting_block {
                Some(mut voting_block) => {
                    voting_block
                        .block
                        .signatures
                        .append(&block.verified_signatures());
                    *self.voting_block.write().await = Some(voting_block);
                }
                None => *self.voting_block.write().await = Some(VotingBlock::new(block)),
            };
            let voting_block = self.voting_block.write().await.clone();
            if let Some(VotingBlock { block, .. }) = voting_block {
                let valid_signatures = self.network_topology.filter_signatures_by_roles(
                    &[Role::ValidatingPeer, Role::Leader],
                    &block.verified_signatures(),
                );
                if valid_signatures.len() >= self.network_topology.min_votes_for_commit() - 1 {
                    let mut signatures = Signatures::default();
                    signatures.append(&valid_signatures);
                    let mut block = block.clone();
                    block.signatures = signatures;
                    let block = block.sign(&self.key_pair)?;
                    let message = Message::BlockCommitted(block.clone());
                    let mut send_futures = Vec::new();
                    for peer in self.network_topology.validating_peers() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    send_futures.push(message.clone().send_to(self.network_topology.leader()));
                    for peer in self.network_topology.peers_set_b() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    let results = futures::future::join_all(send_futures).await;
                    results
                        .iter()
                        .filter(|result| result.is_err())
                        .for_each(|error_result| {
                            eprintln!("Failed to send messages: {:?}", error_result)
                        });
                    self.commit_block(block).await;
                }
            }
        }
        Ok(())
    }

    #[log]
    async fn handle_block_committed(&mut self, mut block: SignedBlock) -> Result<(), String> {
        let voting_block = self.voting_block.write().await.clone();
        if let Some(voting_block) = voting_block {
            let verified_signatures = block.verified_signatures();
            let valid_signatures = self.network_topology.filter_signatures_by_roles(
                &[Role::ValidatingPeer, Role::Leader, Role::ProxyTail],
                &verified_signatures,
            );
            let proxy_tail_signatures = self
                .network_topology
                .filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
            if valid_signatures.len() >= self.network_topology.min_votes_for_commit()
                && proxy_tail_signatures.len() == 1
                && voting_block.block.hash() == block.hash()
            {
                block.signatures.clear();
                block.signatures.append(&valid_signatures);
                self.commit_block(block).await;
            }
        }
        Ok(())
    }

    #[log]
    async fn handle_commit_timeout(&mut self, commit_timeout: CommitTimeout) -> Result<(), String> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get System Time.");
        let mut commit_timeout = commit_timeout.clone();
        let role = self.network_topology.role(&self.peer_id);
        if role == Role::ValidatingPeer || role == Role::Leader {
            let voting_block = self.voting_block.write().await.clone();
            if let Some(voting_block) = voting_block {
                if voting_block.block.hash() == commit_timeout.voting_block_hash
                    && (current_time - voting_block.voted_at) >= self.commit_time
                    && !commit_timeout
                        .signatures
                        .contains(&self.key_pair.public_key)
                {
                    commit_timeout
                        .sign(&self.key_pair)
                        .expect("Failed to sign.");
                    let message = Message::CommitTimeout(commit_timeout.clone());
                    let mut send_futures = Vec::new();
                    for peer in &self.network_topology.sorted_peers {
                        if *peer != self.peer_id {
                            send_futures.push(message.clone().send_to(peer));
                        }
                    }
                    let results = futures::future::join_all(send_futures).await;
                    results
                        .iter()
                        .filter(|result| result.is_err())
                        .for_each(|error_result| {
                            eprintln!("Failed to send messages: {:?}", error_result)
                        });
                }
            }
        }
        if self
            .network_topology
            .filter_signatures_by_roles(
                &[Role::Leader, Role::ValidatingPeer],
                &commit_timeout.verified_signatures(),
            )
            .len()
            >= self.network_topology.min_votes_for_view_change()
        {
            //TODO: store invalidated block hashes
            self.change_view().await;
        }
        Ok(())
    }

    async fn commit_block(&mut self, block: SignedBlock) {
        let block = block
            .validate(&*self.world_state_view.read().await)
            .expect("Failed to validate the block.");
        self.latest_block_hash = block.hash();
        self.block_height = block.header.height;
        self.blocks_sender.write().await.send(block).await;
        self.network_topology
            .sort_peers(Some(self.latest_block_hash));
        *self.voting_block.write().await = None;
    }

    async fn change_view(&mut self) {
        self.network_topology.shift_peers_by_one();
        *self.voting_block.write().await = None;
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
pub struct NetworkTopology {
    peers: Vec<PeerId>,
    max_faults: usize,
    block_hash: Option<Hash>,
}

impl NetworkTopology {
    /// Constructs a new `NetworkTopology` instance.
    pub fn new(peers: &[PeerId], block_hash: Option<Hash>, max_faults: usize) -> NetworkTopology {
        NetworkTopology {
            peers: peers.to_vec(),
            max_faults,
            block_hash,
        }
    }

    /// Initializes network topology.
    pub fn init(self) -> Result<InitializedNetworkTopology, String> {
        let min_peers = 3 * self.max_faults + 1;
        if self.peers.len() >= min_peers {
            let mut topology = InitializedNetworkTopology {
                sorted_peers: self.peers,
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
#[derive(Debug)]
pub struct InitializedNetworkTopology {
    /// Current order of peers. The roles of peers are defined based on this order.
    pub sorted_peers: Vec<PeerId>,
    max_faults: usize,
}

impl InitializedNetworkTopology {
    /// Answers if the consensus stage is required with the current number of peers.
    pub fn is_consensus_required(&self) -> bool {
        self.sorted_peers.len() > 1
    }

    /// The minimum number of signatures needed to commit a block
    pub fn min_votes_for_commit(&self) -> usize {
        2 * self.max_faults + 1
    }

    /// The minimum number of signatures needed to perform a view change (change leader, proxy, etc.)
    pub fn min_votes_for_view_change(&self) -> usize {
        self.max_faults + 1
    }

    /// Peers of set A. They participate in the consensus.
    pub fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers]
    }

    /// Peers of set B. The watch the consensus process.
    pub fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1)..]
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
            let mut rng = StdRng::from_seed(block_hash);
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
        let roles: HashSet<Role> = roles.iter().cloned().collect();
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
#[derive(Eq, PartialEq, Debug, Hash, Clone)]
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
    /// Signed Block
    pub block: SignedBlock,
}

impl VotingBlock {
    /// Constructs new VotingBlock.
    pub fn new(block: SignedBlock) -> VotingBlock {
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
        block::SignedBlock,
        crypto::{Hash, KeyPair, Signature, Signatures},
        peer::PeerId,
        sumeragi::{InitializedNetworkTopology, Role, VotingBlock},
        torii::uri,
        tx::AcceptedTransaction,
    };
    use iroha_derive::*;
    use iroha_network::prelude::*;
    use parity_scale_codec::{Decode, Encode};
    use std::time::{Duration, SystemTime};

    /// Message's variants that are used by peers to communicate in the process of consensus.
    #[derive(Io, Decode, Encode, Debug, Clone)]
    pub enum Message {
        /// Is sent by leader to all validating peers, when a new block is created.
        BlockCreated(SignedBlock),
        /// Is sent by validating peers to proxy tail and observing peers when they have signed this block.
        BlockSigned(SignedBlock),
        /// Is sent by proxy tail to validating peers and to leader, when the block is committed.
        BlockCommitted(SignedBlock),
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
        /// Constructs a new `BlockCreationTimeout` message with no signatures.
        pub fn new(transaction_receipt: &TransactionReceipt) -> BlockCreationTimeout {
            BlockCreationTimeout {
                transaction_receipt: transaction_receipt.clone(),
                signatures: Signatures::default(),
            }
        }

        /// Signs this message with the peer's public and private key.
        /// This way peers vote for changing the view, if the leader does not produce a block
        /// after receiving transaction in `block_time`.
        pub fn sign(&mut self, key_pair: &KeyPair) -> Result<(), String> {
            let signature = Signature::new(
                key_pair.clone(),
                &Vec::<u8>::from(self.transaction_receipt.clone()),
            )?;
            self.signatures.add(signature);
            Ok(())
        }

        /// Signatures that are verified with the `transaction_receipt` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures
                .verified(&Vec::<u8>::from(self.transaction_receipt.clone()))
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
        pub fn sign(&mut self, key_pair: &KeyPair) -> Result<(), String> {
            let signature =
                Signature::new(key_pair.clone(), &Vec::<u8>::from(self.transaction.clone()))?;
            self.signatures.add(signature);
            Ok(())
        }

        /// Signatures that are verified with the `transaction` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures
                .verified(&Vec::<u8>::from(self.transaction.clone()))
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
                signature: Signature::new(key_pair.clone(), &transaction_hash)?,
            })
        }

        /// Checks that this `TransactionReceipt` is valid.
        pub fn is_valid(&self, network_topology: &InitializedNetworkTopology) -> bool {
            network_topology
                .verify_signature_with_role(
                    self.signature.clone(),
                    Role::Leader,
                    &self.transaction_hash,
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
        pub fn sign(&mut self, key_pair: &KeyPair) -> Result<(), String> {
            let signature = Signature::new(key_pair.clone(), &self.voting_block_hash)?;
            self.signatures.add(signature);
            Ok(())
        }

        /// Signatures that are verified with the `voting_block_hash` bytes as `payload`.
        pub fn verified_signatures(&self) -> Vec<Signature> {
            self.signatures.verified(&self.voting_block_hash)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account, config, crypto, torii::Torii};
    use async_std::{prelude::*, sync, task};
    use std::time::Duration;

    const CONFIG_PATH: &str = "config.json";
    const BLOCK_TIME_MS: u64 = 1000;
    const COMMIT_TIME_MS: u64 = 1000;
    const TX_RECEIPT_TIME_MS: u64 = 200;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
        let listen_address = "127.0.0.1".to_string();
        let this_peer = PeerId {
            address: listen_address,
            public_key: key_pair.public_key,
        };
        let network_topology = NetworkTopology::new(&[this_peer.clone()], None, 3)
            .init()
            .expect("Failed to create topology.");
    }

    #[test]
    fn different_order() {
        let peers = vec![
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
        ];
        let network_topology1 = NetworkTopology::new(&peers, Some([1u8; 32]), 1)
            .init()
            .expect("Failed to construct topology");
        let network_topology2 = NetworkTopology::new(&peers, Some([2u8; 32]), 1)
            .init()
            .expect("Failed to construct topology");
        assert_ne!(
            network_topology1.sorted_peers,
            network_topology2.sorted_peers
        );
    }

    #[test]
    fn same_order() {
        let peers = vec![
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
        ];
        let network_topology1 = NetworkTopology::new(&peers, Some([1u8; 32]), 1)
            .init()
            .expect("Failed to initialize topology");
        let network_topology2 = NetworkTopology::new(&peers, Some([1u8; 32]), 1)
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
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + i),
                public_key: key_pair.public_key.clone(),
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.commit_time_ms = COMMIT_TIME_MS;
        config.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.block_time_ms = BLOCK_TIME_MS;
        config.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &ids,
            ))));
            let mut torii = Torii::new(ids[i].address.as_str(), wsv.clone(), tx, message_sender);
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let mut config = config.clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.torii_url = ids[i].address.clone();
            config.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    config,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transactions_sender,
                    [0u8; 32],
                    0,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let _result = sumeragi.write().await.handle_message(message).await;
                }
            });
            let block_counter = block_counters[i].clone();
            task::spawn(async move {
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
            .round(vec![RequestedTransaction::new(
                vec![],
                account::Id::new("entity", "domain"),
            )
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
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers + i),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.commit_time_ms = COMMIT_TIME_MS;
        config.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.block_time_ms = BLOCK_TIME_MS;
        config.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &ids,
            ))));
            let mut torii = Torii::new(ids[i].address.as_str(), wsv.clone(), tx, message_sender);
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let mut config = config.clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.torii_url = ids[i].address.clone();
            config.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    config,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transactions_sender,
                    [0u8; 32],
                    0,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate faulty proxy tail
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::ProxyTail {
                        if let Message::BlockSigned(..) = message {
                            continue;
                        }
                    }
                    let _result = sumeragi.handle_message(message).await;
                }
            });
            let block_counter = block_counters[i].clone();
            task::spawn(async move {
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
            .round(vec![RequestedTransaction::new(
                vec![],
                account::Id::new("entity", "domain"),
            )
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(config.pipeline_time_ms() + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids, Some([0u8; 32]), 1)
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
    async fn change_view_on_tx_receipt_timeout() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers * 2 + i),
                public_key: key_pair.public_key.clone(),
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.commit_time_ms = COMMIT_TIME_MS;
        config.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.block_time_ms = BLOCK_TIME_MS;
        config.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &ids,
            ))));
            let mut torii = Torii::new(
                ids[i].address.as_str(),
                wsv.clone(),
                transactions_sender.clone(),
                message_sender,
            );
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let mut config = config.clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.torii_url = ids[i].address.clone();
            config.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    config,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transactions_sender,
                    [0u8; 32],
                    0,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let mut sumeragi = sumeragi_arc_clone.write().await;
                    // Simulate faulty leader
                    if sumeragi.network_topology.role(&sumeragi.peer_id) == Role::Leader {
                        if let Message::TransactionForwarded(..) = message {
                            continue;
                        }
                    }
                    let _result = sumeragi.handle_message(message).await;
                }
            });
            let block_counter = block_counters[i].clone();
            task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
            let sumeragi_arc_clone = sumeragi.clone();
            task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    sumeragi_arc_clone
                        .write()
                        .await
                        .round(vec![transaction])
                        .await;
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
            .round(vec![RequestedTransaction::new(
                vec![],
                account::Id::new("entity", "domain"),
            )
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(config.pipeline_time_ms() + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids, Some([0u8; 32]), 1)
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
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers * 3 + i),
                public_key: key_pair.public_key.clone(),
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.commit_time_ms = COMMIT_TIME_MS;
        config.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.block_time_ms = BLOCK_TIME_MS;
        config.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transactions_sender, mut transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &ids,
            ))));
            let mut torii = Torii::new(
                ids[i].address.as_str(),
                wsv.clone(),
                transactions_sender.clone(),
                message_sender,
            );
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let mut config = config.clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.torii_url = ids[i].address.clone();
            config.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    config,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transactions_sender,
                    [0u8; 32],
                    0,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    // Simulate faulty leader as if it does not send `BlockCreated` messages
                    if let Message::BlockCreated(..) = message {
                        continue;
                    }
                    let _result = sumeragi_arc_clone
                        .write()
                        .await
                        .handle_message(message)
                        .await;
                }
            });
            let block_counter = block_counters[i].clone();
            task::spawn(async move {
                while let Some(_block) = block_receiver.next().await {
                    *block_counter.write().await += 1;
                }
            });
            let sumeragi_arc_clone = sumeragi.clone();
            task::spawn(async move {
                while let Some(transaction) = transactions_receiver.next().await {
                    sumeragi_arc_clone
                        .write()
                        .await
                        .round(vec![transaction])
                        .await;
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
            .round(vec![RequestedTransaction::new(
                vec![],
                account::Id::new("entity", "domain"),
            )
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(config.pipeline_time_ms() + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids, Some([0u8; 32]), 1)
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
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let key_pair = KeyPair::generate().expect("Failed to generate KeyPair.");
            keys.push(key_pair.clone());
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers * 4 + i),
                public_key: key_pair.public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        let mut config =
            Configuration::from_path(CONFIG_PATH).expect("Failed to get configuration.");
        config.commit_time_ms = COMMIT_TIME_MS;
        config.tx_receipt_time_ms = TX_RECEIPT_TIME_MS;
        config.block_time_ms = BLOCK_TIME_MS;
        config.max_faulty_peers(max_faults);
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transactions_sender, _transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &ids,
            ))));
            let mut torii = Torii::new(ids[i].address.as_str(), wsv.clone(), tx, message_sender);
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let mut config = config.clone();
            config.private_key = keys[i].private_key.clone();
            config.public_key = ids[i].public_key.clone();
            config.torii_url = ids[i].address.clone();
            config.trusted_peers(ids.clone());
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    config,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transactions_sender,
                    [0u8; 32],
                    0,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate leader producing empty blocks
                    if let Message::BlockCreated(block) = message {
                        let mut block = block.clone();
                        block.transactions = Vec::new();
                        let _result = sumeragi.handle_message(Message::BlockCreated(block)).await;
                    } else {
                        let _result = sumeragi.handle_message(message).await;
                    }
                }
            });
            let block_counter = block_counters[i].clone();
            task::spawn(async move {
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
            .round(vec![RequestedTransaction::new(
                vec![],
                account::Id::new("entity", "domain"),
            )
            .accept()
            .expect("Failed to accept tx.")])
            .await
            .expect("Round failed.");
        async_std::task::sleep(Duration::from_millis(config.pipeline_time_ms() + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut network_topology = NetworkTopology::new(&ids, Some([0u8; 32]), 1)
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
}
