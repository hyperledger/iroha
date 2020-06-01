//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use crate::{
    block::{PendingBlock, SignedBlock},
    crypto::Hash,
    peer::PeerId,
    prelude::*,
    torii::uri,
};
use async_std::sync::RwLock;
use iroha_derive::*;
use iroha_network::{Network, Request, Response};
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    sync::Arc,
    time::{Duration, SystemTime},
};

trait Consensus {
    fn round(&mut self, transactions: Vec<AcceptedTransaction>) -> Option<PendingBlock>;
}

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
}

impl Message {
    #[log]
    async fn send_to(self, peer: &PeerId) -> Result<(), String> {
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

/// Message structure describing a failed attempt to forward transaction to a leader.
/// Peers sign it if they are not able to get a TxReceipt from a leader after sending the specified transaction.
#[derive(Io, Decode, Encode, Debug, Clone)]
pub struct NoTransactionReceiptReceived {
    transaction: AcceptedTransaction,
    signatures: BTreeMap<PublicKey, Signature>,
}

impl NoTransactionReceiptReceived {
    /// Constructs a new `NoTransactionReceiptReceived` message with no signatures.
    pub fn new(transaction: &AcceptedTransaction) -> NoTransactionReceiptReceived {
        NoTransactionReceiptReceived {
            transaction: transaction.clone(),
            signatures: BTreeMap::new(),
        }
    }

    /// Signes this failed attempt with the peer's public and private key.
    /// This way peers vote for changing the view, if the leader refuses to accept this transaction.
    pub fn sign(&mut self, public_key: &PublicKey, private_key: &PrivateKey) -> Result<(), String> {
        let payload: Vec<u8> = self.transaction.clone().into();
        if self.signatures.contains_key(public_key) {
            Err("Already signed by these keys.".to_string())
        } else {
            self.signatures.insert(
                *public_key,
                Signature::new(*public_key, &payload, private_key)?,
            );
            Ok(())
        }
    }
}

/// Message structure describing a transaction that is forwarded from a client by a peer to the leader.
#[derive(Io, Decode, Encode, Debug, Clone)]
pub struct TransactionForwarded {
    transaction: AcceptedTransaction,
    peer: PeerId,
}

/// Message structure describing a receipt sent by the leader to the peer it got this transaction from.
#[derive(Io, Decode, Encode, Debug, Clone)]
pub struct TransactionReceipt {
    transaction_hash: Hash,
    received_at: Duration,
    signature: Signature,
}

impl TransactionReceipt {
    /// Constructs a new receipt
    pub fn new(
        transaction: &AcceptedTransaction,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<TransactionReceipt, String> {
        let transaction_hash = transaction.hash();
        Ok(TransactionReceipt {
            transaction_hash,
            received_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time."),
            signature: Signature::new(*public_key, &transaction_hash, private_key)?,
        })
    }
}

/// Message structure describing a request to other peers to change view because of the commit timeout.
/// Peers vote on this view change by signing and forwarding this structure.
#[derive(Io, Decode, Encode, Debug, Clone)]
pub struct CommitTimeout {
    voting_block_hash: Hash,
    signatures: BTreeMap<PublicKey, Signature>,
}

impl CommitTimeout {
    /// Constructs a new commit timeout message with no signatures.
    pub fn new(voting_block: VotingBlock) -> CommitTimeout {
        CommitTimeout {
            voting_block_hash: voting_block.block.hash(),
            signatures: BTreeMap::new(),
        }
    }

    /// Signes this request with the peer's public and private key.
    /// This way peers vote for changing the view.
    pub fn sign(&mut self, public_key: &PublicKey, private_key: &PrivateKey) -> Result<(), String> {
        if self.signatures.contains_key(public_key) {
            Err("Already signed by these keys.".to_string())
        } else {
            self.signatures.insert(
                *public_key,
                Signature::new(*public_key, &self.voting_block_hash, private_key)?,
            );
            Ok(())
        }
    }
}

/// Structure represents a block that is currently in discussion.
#[derive(Debug, Clone)]
pub struct VotingBlock {
    /// At what time has this peer voted for this block
    voted_at: Duration,
    /// Signed Block hash
    block: SignedBlock,
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

/// Possible Peer's roles in consensus.
#[derive(Eq, PartialEq, Debug, Hash)]
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

/// `Sumeragi` is the implementation of the consensus.
pub struct Sumeragi {
    public_key: PublicKey,
    private_key: PrivateKey,
    sorted_peers: Vec<PeerId>,
    max_faults: usize,
    peer_id: PeerId,
    /// PendingBlock in discussion this round
    voting_block: Arc<RwLock<Option<VotingBlock>>>,
    blocks_sender: Arc<RwLock<ValidBlockSender>>,
    transaction_sender: TransactionSender,
    world_state_view: Arc<RwLock<WorldStateView>>,
    /// Hashes of the transactions that were forwarded to a leader, but not yet confirmed with a receipt
    pending_forwarded_tx_hashes: Arc<RwLock<BTreeSet<Hash>>>,
    commit_time: Duration,
    tx_receipt_time: Duration,
}

impl Sumeragi {
    /// Default `Sumeragi` constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        private_key: PrivateKey,
        peers: &[PeerId],
        peer_id: PeerId,
        max_faults: usize,
        blocks_sender: Arc<RwLock<ValidBlockSender>>,
        world_state_view: Arc<RwLock<WorldStateView>>,
        transaction_sender: TransactionSender,
        commit_time_ms: u64,
        tx_receipt_time_ms: u64,
    ) -> Result<Self, String> {
        let min_peers = 3 * max_faults + 1;
        if peers.len() >= min_peers {
            //TODO: get previous block hash from kura
            let mut sorted_peers = peers.to_vec();
            Self::sort_peers(&mut sorted_peers, None);
            Ok(Self {
                public_key: peer_id.public_key,
                private_key,
                sorted_peers,
                max_faults,
                peer_id,
                voting_block: Arc::new(RwLock::new(None)),
                blocks_sender,
                world_state_view,
                pending_forwarded_tx_hashes: Arc::new(RwLock::new(BTreeSet::new())),
                commit_time: Duration::from_millis(commit_time_ms),
                transaction_sender,
                tx_receipt_time: Duration::from_millis(tx_receipt_time_ms),
            })
        } else {
            Err(format!("Not enough peers to be Byzantine fault tolerant. Expected a least {} peers, got {}", 3 * max_faults + 1, peers.len()))
        }
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
        if let Role::Leader = self.role() {
            let block = PendingBlock::new(transactions)
                //TODO: actually chain block?
                .chain_first()
                .sign(&self.public_key, &self.private_key)?;
            let minimum_quorum_of_peers = 2;
            if self.sorted_peers.len() < minimum_quorum_of_peers {
                let block = block.validate(&*self.world_state_view.read().await)?;
                self.blocks_sender.write().await.send(block).await;
                Ok(())
            } else {
                *self.voting_block.write().await = Some(VotingBlock::new(block.clone()));
                let message = Message::BlockCreated(block.clone());
                let mut send_futures = Vec::new();
                for peer in self.validating_peers() {
                    send_futures.push(message.clone().send_to(peer));
                }
                send_futures.push(message.clone().send_to(self.proxy_tail()));
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
                    .send_to(self.leader()),
                );
                self.pending_forwarded_tx_hashes
                    .write()
                    .await
                    .insert(transaction.hash());
                let pending_forwarded_tx_hashes = self.pending_forwarded_tx_hashes.clone();
                let mut no_tx_receipt = NoTransactionReceiptReceived::new(&transaction);
                if self.role() == Role::ValidatingPeer || self.role() == Role::ProxyTail {
                    no_tx_receipt
                        .sign(&self.public_key, &self.private_key)
                        .expect("Failed to put first signature.");
                }
                let recipient_peers = self.sorted_peers.clone();
                let transaction_hash = transaction.hash();
                let peer_id = self.peer_id.clone();
                let tx_receipt_time = self.tx_receipt_time;
                async_std::task::spawn(async move {
                    async_std::task::sleep(tx_receipt_time).await;
                    if pending_forwarded_tx_hashes
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

    /// This method is used to sort list of peers.
    pub fn sort_peers(peers: &mut Vec<PeerId>, block_hash: Option<Hash>) {
        peers.sort_by(|p1, p2| p1.address.cmp(&p2.address));
        if let Some(block_hash) = block_hash {
            let mut rng = StdRng::from_seed(block_hash);
            peers.shuffle(&mut rng);
        }
    }

    /// This method is used to handle messages from other peers.
    #[log]
    pub async fn handle_message(&mut self, message: Message) -> Result<(), String> {
        //TODO: check that the messages come from the right peers (check roles, keys)
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
        }
        Ok(())
    }

    #[log]
    async fn start_commit_countdown(&self, voting_block: VotingBlock) {
        let old_voting_block = voting_block;
        let voting_block = self.voting_block.clone();
        let public_key = self.public_key;
        let private_key = self.private_key;
        let recipient_peers = self.sorted_peers.clone();
        let peer_id = self.peer_id.clone();
        let commit_time = self.commit_time;
        async_std::task::spawn(async move {
            async_std::task::sleep(commit_time).await;
            if let Some(voting_block) = voting_block.write().await.clone() {
                // If the block was not yet committed send commit timeout to other peers to initiate view change.
                if voting_block.block.hash() == old_voting_block.block.hash() {
                    let mut commit_timeout = CommitTimeout::new(voting_block);
                    if let Err(e) = commit_timeout.sign(&public_key, &private_key) {
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
        let minimum_votes = self.max_faults + 1;
        // TODO: check that signatures are from proxy tail and validating peers, ignore other signatures
        if no_tx_receipt.signatures.len() >= minimum_votes {
            self.change_view().await;
            return Ok(());
        }
        if self.role() == Role::ValidatingPeer || self.role() == Role::ProxyTail {
            let mut no_tx_receipt = no_tx_receipt.clone();
            if no_tx_receipt
                .sign(&self.public_key, &self.private_key)
                .is_ok()
            {
                let _result = Message::TransactionForwarded(TransactionForwarded {
                    transaction: no_tx_receipt.transaction.clone(),
                    peer: self.peer_id.clone(),
                })
                .send_to(self.leader())
                .await;
                self.pending_forwarded_tx_hashes
                    .write()
                    .await
                    .insert(no_tx_receipt.transaction.hash());
                let pending_forwarded_tx_hashes = self.pending_forwarded_tx_hashes.clone();
                let recipient_peers = self.sorted_peers.clone();
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
            &self.public_key,
            &self.private_key,
        )?)
        .send_to(&forwarded_tx.peer)
        .await;
        self.transaction_sender
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
        if self.role() != Role::Leader
            && tx_receipt.received_at
                <= SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
        {
            self.pending_forwarded_tx_hashes
                .write()
                .await
                .remove(&tx_receipt.transaction_hash);
        }
        Ok(())
    }

    #[log]
    async fn handle_block_created(&mut self, block: SignedBlock) -> Result<(), String> {
        match self.role() {
            Role::ValidatingPeer => {
                if let Err(e) =
                    Message::BlockSigned(block.clone().sign(&self.public_key, &self.private_key)?)
                        .send_to(self.proxy_tail())
                        .await
                {
                    eprintln!(
                        "Failed to send BlockSigned message to the proxy tail: {:?}",
                        e
                    );
                }
                let voting_block = VotingBlock::new(block);
                *self.voting_block.write().await = Some(voting_block.clone());
                self.start_commit_countdown(voting_block.clone()).await;
                //TODO: send to set b so they can observe
            }
            Role::ProxyTail => {
                if self.voting_block.write().await.is_none() {
                    *self.voting_block.write().await = Some(VotingBlock::new(block));
                }
            }
            _ => (),
        }
        Ok(())
    }

    #[log]
    async fn handle_block_signed(&mut self, block: SignedBlock) -> Result<(), String> {
        if let Role::ProxyTail = self.role() {
            let voting_block = self.voting_block.write().await.clone();
            match voting_block {
                Some(voting_block) => {
                    // TODO: verify signatures
                    let mut voting_block = voting_block.clone();
                    for signature in block.signatures {
                        if !voting_block.block.signatures.contains(&signature) {
                            voting_block.block.signatures.push(signature)
                        }
                    }
                    *self.voting_block.write().await = Some(voting_block);
                }
                None => *self.voting_block.write().await = Some(VotingBlock::new(block)),
            };
            let voting_block = self.voting_block.write().await.clone();
            if let Some(VotingBlock { block, .. }) = voting_block {
                if block.signatures.len() >= 2 * self.max_faults {
                    let block = block.sign(&self.public_key, &self.private_key)?;
                    let message = Message::BlockCommitted(block.clone());
                    let mut send_futures = Vec::new();
                    for peer in self.validating_peers() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    send_futures.push(message.clone().send_to(self.leader()));
                    for peer in self.peers_set_b() {
                        send_futures.push(message.clone().send_to(peer));
                    }
                    let results = futures::future::join_all(send_futures).await;
                    results
                        .iter()
                        .filter(|result| result.is_err())
                        .for_each(|error_result| {
                            eprintln!("Failed to send messages: {:?}", error_result)
                        });
                    let block = block.validate(&*self.world_state_view.read().await)?;
                    let hash = block.hash();
                    self.blocks_sender.write().await.send(block).await;
                    self.next_round(hash).await;
                }
            }
        }
        Ok(())
    }

    #[log]
    async fn handle_block_committed(&mut self, block: SignedBlock) -> Result<(), String> {
        //TODO: check if the block is the same as pending
        let block = block.validate(&*self.world_state_view.read().await)?;
        let hash = block.hash();
        self.blocks_sender.write().await.send(block).await;
        self.next_round(hash).await;
        Ok(())
    }

    #[log]
    async fn handle_commit_timeout(&mut self, commit_timeout: CommitTimeout) -> Result<(), String> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get System Time.");
        let mut commit_timeout = commit_timeout.clone();
        if self.role() == Role::ValidatingPeer || self.role() == Role::Leader {
            let voting_block = self.voting_block.write().await.clone();
            if let Some(voting_block) = voting_block {
                if voting_block.block.hash() == commit_timeout.voting_block_hash
                    && (current_time - voting_block.voted_at) >= self.commit_time
                {
                    let sign_result = commit_timeout.sign(&self.public_key, &self.private_key);
                    if sign_result.is_ok() {
                        let message = Message::CommitTimeout(commit_timeout.clone());
                        let mut send_futures = Vec::new();
                        for peer in &self.sorted_peers {
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
        }
        let minimum_votes = self.max_faults + 1;
        // TODO: check that signatures are from leader and validating peers, ignore other signatures
        if commit_timeout.signatures.len() >= minimum_votes {
            //TODO: store invalidated block hashes
            self.change_view().await;
        }
        Ok(())
    }

    async fn next_round(&mut self, prev_block_hash: Hash) {
        Self::sort_peers(&mut self.sorted_peers, Some(prev_block_hash));
        *self.voting_block.write().await = None;
    }

    async fn change_view(&mut self) {
        let last_element = self
            .sorted_peers
            .pop()
            .expect("No elements found in sorted peers.");
        self.sorted_peers.insert(0, last_element);
        *self.voting_block.write().await = None;
    }

    fn peers_set_a(&self) -> &[PeerId] {
        let n_a_peers = 2 * self.max_faults + 1;
        &self.sorted_peers[..n_a_peers]
    }

    fn peers_set_b(&self) -> &[PeerId] {
        &self.sorted_peers[(2 * self.max_faults + 1)..]
    }

    fn leader(&self) -> &PeerId {
        self.peers_set_a()
            .first()
            .expect("Failed to get first peer.")
    }

    fn proxy_tail(&self) -> &PeerId {
        self.peers_set_a().last().expect("Failed to get last peer.")
    }

    fn validating_peers(&self) -> &[PeerId] {
        let a_set = self.peers_set_a();
        if a_set.len() > 1 {
            &a_set[1..(a_set.len() - 1)]
        } else {
            &[]
        }
    }

    fn role(&self) -> Role {
        if *self.leader() == self.peer_id {
            Role::Leader
        } else if *self.proxy_tail() == self.peer_id {
            Role::ProxyTail
        } else if self.validating_peers().contains(&self.peer_id) {
            Role::ValidatingPeer
        } else {
            Role::ObservingPeer
        }
    }
}

impl Debug for Sumeragi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sumeragi")
            .field("public_key", &self.public_key)
            .field("sorted_peers", &self.sorted_peers)
            .field("max_faults", &self.max_faults)
            .field("peer_id", &self.peer_id)
            .field("voting_block", &self.voting_block)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account, config, crypto, torii::Torii};
    use async_std::{prelude::*, sync, task};
    use std::time::Duration;

    #[test]
    #[should_panic]
    fn not_enough_peers() {
        let (blocks_sender, _blocks_receiver) = sync::channel(100);
        let (transaction_sender, _transaction_receiver) = sync::channel(100);
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let listen_address = "127.0.0.1".to_string();
        let this_peer = PeerId {
            address: listen_address.clone(),
            public_key,
        };
        Sumeragi::new(
            private_key,
            &[this_peer.clone()],
            this_peer.clone(),
            3,
            Arc::new(RwLock::new(blocks_sender)),
            Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                this_peer.clone(),
                &vec![this_peer],
            )))),
            transaction_sender,
            config::DEFAULT_COMMIT_TIME_MS,
            config::DEFAULT_TX_RECEIPT_TIME_MS,
        )
        .expect("Failed to create Sumeragi.");
    }

    #[test]
    fn different_order() {
        let mut peers1 = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: [1u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: [2u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: [3u8; 32],
            },
        ];
        Sumeragi::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::sort_peers(&mut peers2, Some([2u8; 32]));
        assert_ne!(peers1, peers2);
    }

    #[test]
    fn same_order() {
        let mut peers1 = vec![
            PeerId {
                address: "127.0.0.1:7878".to_string(),
                public_key: [1u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7879".to_string(),
                public_key: [2u8; 32],
            },
            PeerId {
                address: "127.0.0.1:7880".to_string(),
                public_key: [3u8; 32],
            },
        ];
        Sumeragi::sort_peers(&mut peers1, Some([1u8; 32]));
        let mut peers2 = peers1.clone();
        Sumeragi::sort_peers(&mut peers2, Some([1u8; 32]));
        assert_eq!(peers1, peers2);
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
            let (public_key, private_key) =
                crypto::generate_key_pair().expect("Failed to generate key pair.");
            keys.push((public_key, private_key));
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + i),
                public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (transaction_sender, _transactions_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: [0; 32],
                },
                &ids,
            ))));
            let mut torii = Torii::new(ids[i].address.as_str(), wsv.clone(), tx, message_sender);
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    keys[i].1,
                    &ids,
                    ids[i].clone(),
                    max_faults,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transaction_sender,
                    config::DEFAULT_COMMIT_TIME_MS,
                    config::DEFAULT_TX_RECEIPT_TIME_MS,
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
        let leader = peers.first().expect("Failed to get first peer.");
        assert_eq!(leader.write().await.role(), Role::Leader);
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
            let (public_key, private_key) =
                crypto::generate_key_pair().expect("Failed to generate key pair.");
            keys.push((public_key, private_key));
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers + i),
                public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (tx, _rx) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transaction_sender, _transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: [0; 32],
                },
                &ids,
            ))));
            let mut torii = Torii::new(ids[i].address.as_str(), wsv.clone(), tx, message_sender);
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    keys[i].1,
                    &ids,
                    ids[i].clone(),
                    max_faults,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transaction_sender,
                    config::DEFAULT_COMMIT_TIME_MS,
                    config::DEFAULT_TX_RECEIPT_TIME_MS,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let mut sumeragi = sumeragi.write().await;
                    // Simulate faulty proxy tail
                    if sumeragi.role() == Role::ProxyTail {
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
        let leader = peers.first().expect("Failed to get first peer.");
        assert_eq!(leader.write().await.role(), Role::Leader);
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
        async_std::task::sleep(Duration::from_millis(config::DEFAULT_COMMIT_TIME_MS + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as there was a commit timeout for current block
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut order_after_change = ids.clone();
        Sumeragi::sort_peers(&mut ids, None);
        let last_peer = order_after_change.pop().expect("Expected at least 1 peer.");
        order_after_change.insert(0, last_peer);
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(peer.write().await.sorted_peers, order_after_change);
        }
    }

    #[cfg(feature = "network-mock")]
    #[async_std::test]
    async fn change_view_on_tx_receipt() {
        let n_peers = 10;
        let max_faults = 1;
        let mut keys = Vec::new();
        let mut ids = Vec::new();
        let mut block_counters = Vec::new();
        for i in 0..n_peers {
            let (public_key, private_key) =
                crypto::generate_key_pair().expect("Failed to generate key pair.");
            keys.push((public_key, private_key));
            let peer_id = PeerId {
                address: format!("127.0.0.1:{}", 7878 + n_peers * 2 + i),
                public_key,
            };
            ids.push(peer_id);
            block_counters.push(Arc::new(RwLock::new(0)));
        }
        let mut peers = Vec::new();
        for i in 0..n_peers {
            let (block_sender, mut block_receiver) = sync::channel(100);
            let (message_sender, mut message_receiver) = sync::channel(100);
            let (transaction_sender, mut transactions_receiver) = sync::channel(100);
            let wsv = Arc::new(RwLock::new(WorldStateView::new(Peer::new(
                PeerId {
                    address: "127.0.0.1:7878".to_string(),
                    public_key: [0; 32],
                },
                &ids,
            ))));
            let mut torii = Torii::new(
                ids[i].address.as_str(),
                wsv.clone(),
                transaction_sender.clone(),
                message_sender,
            );
            task::spawn(async move {
                torii.start().await.expect("Torii failed.");
            });
            let sumeragi = Arc::new(RwLock::new(
                Sumeragi::new(
                    keys[i].1,
                    &ids,
                    ids[i].clone(),
                    max_faults,
                    Arc::new(RwLock::new(block_sender)),
                    wsv,
                    transaction_sender,
                    config::DEFAULT_COMMIT_TIME_MS,
                    config::DEFAULT_TX_RECEIPT_TIME_MS,
                )
                .expect("Failed to create Sumeragi."),
            ));
            peers.push(sumeragi.clone());
            let sumeragi_arc_clone = sumeragi.clone();
            task::spawn(async move {
                while let Some(message) = message_receiver.next().await {
                    let mut sumeragi = sumeragi_arc_clone.write().await;
                    // Simulate faulty proxy tail
                    if sumeragi.role() == Role::Leader {
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
        // Second peer is not a leader in this particular case.
        let peer = peers.get(2).expect("Failed to get second peer.");
        assert_ne!(peer.write().await.role(), Role::Leader);
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
        async_std::task::sleep(Duration::from_millis(config::DEFAULT_COMMIT_TIME_MS + 2000)).await;
        for block_counter in block_counters {
            // No blocks are committed as the leader failed to send tx receipt
            assert_eq!(*block_counter.write().await, 0u8);
        }
        let mut order_after_change = ids.clone();
        Sumeragi::sort_peers(&mut ids, None);
        let last_peer = order_after_change.pop().expect("Expected at least 1 peer.");
        order_after_change.insert(0, last_peer);
        // All peer should perform a view change
        for peer in peers {
            assert_eq!(peer.write().await.sorted_peers, order_after_change);
        }
    }
}
