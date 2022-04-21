//! Contains message structures for p2p communication during consensus.
#![allow(clippy::module_name_repetitions)]

use std::time::Duration;

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

use super::{
    fault::{FaultInjection, SumeragiWithFault},
    view_change::{self, Proof},
};
use crate::{
    block::BlockHeader,
    genesis::GenesisNetworkTrait,
    kura::KuraTrait,
    queue,
    sumeragi::{NetworkMessage, Role, Sumeragi, Topology, VotingBlock},
    wsv::WorldTrait,
    VersionedAcceptedTransaction, VersionedCommittedBlock, VersionedValidBlock,
};

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

/// Message reminder for initialization of [`Sumeragi`]
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
    pub(crate) block_hash: HashOf<VersionedValidBlock>,
    pub(crate) proof: Proof,
}

/// Reminder to check if block creation timeout happened.
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CheckCreationTimeout {
    pub(crate) tx_hash: HashOf<VersionedTransaction>,
    pub(crate) proof: Proof,
}

/// Reminder to check if transaction receipt timeout happened.
#[derive(Debug, Clone, iroha_actor::Message)]
pub struct CheckReceiptTimeout {
    pub(crate) tx_hash: HashOf<VersionedTransaction>,
    pub(crate) proof: Proof,
}

/// `true` if current peer is the leader in the current topology.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "bool")]
pub struct IsLeader;

/// Get [`PeerId`] of leader in current topology.
#[derive(Clone, Copy, Debug, iroha_actor::Message)]
#[message(result = "PeerId")]
pub struct GetLeader;

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
    #[log(skip(self))]
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
    pub async fn send_to_multiple<'itm, I>(self, broker: &Broker, peers: I)
    where
        I: IntoIterator<Item = &'itm PeerId> + Send,
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
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
    #[log(skip(self, sumeragi, ctx))]
    #[iroha_futures::telemetry_future]
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
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
    pub const fn new(
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        &self,
        sumeragi: &mut SumeragiWithFault<G, K, W, F>,
        ctx: &mut iroha_actor::Context<SumeragiWithFault<G, K, W, F>>,
    ) -> Result<()> {
        // There should be only one block in discussion during a round.
        if sumeragi.voting_block.is_some() {
            return Ok(());
        }

        for event in Vec::<Event>::from(&self.block) {
            trace!(?event);
            drop(sumeragi.events_sender.send(event));
        }
        sumeragi.update_view_changes(self.block.header().view_change_proofs.clone());
        let network_topology = sumeragi.network_topology_current_or_genesis(self.block.header());
        if network_topology
            .filter_signatures_by_roles(&[Role::Leader], self.block.verified_signatures())
            .is_empty()
        {
            error!(
                role = ?sumeragi.topology.role(&sumeragi.peer_id),
                "Rejecting Block as it is not signed by leader.",
            );
            return Ok(());
        }
        sumeragi.txs_awaiting_created_block.clear();
        if network_topology.role(&sumeragi.peer_id) == Role::ValidatingPeer {
            if let Err(e) = self.block.validation_check(
                &sumeragi.wsv,
                sumeragi.latest_block_hash(),
                &sumeragi.latest_view_change_hash(),
                sumeragi.block_height,
                &sumeragi.transaction_limits,
            ) {
                warn!(%e)
            } else {
                let block_clone = self.block.clone();
                let key_pair_clone = sumeragi.key_pair.clone();
                let transaction_validator = sumeragi.transaction_validator.clone();
                let signed_block = task::spawn_blocking(move || -> Result<BlockSigned> {
                    block_clone
                        .revalidate(&transaction_validator)
                        .sign(key_pair_clone)
                        .map(Into::into)
                })
                .await??;
                VersionedMessage::from(Message::BlockSigned(signed_block))
                    .send_to(&sumeragi.broker, network_topology.proxy_tail())
                    .await;
                info!(
                    peer_role = ?network_topology.role(&sumeragi.peer_id),
                    block_hash = %self.block.hash(),
                    "Signed block candidate",
                );
            }
            //TODO: send to set b so they can observe
        }
        let voting_block = VotingBlock::new(self.block.clone());
        let voting_block_hash = voting_block.block.hash();
        sumeragi.voting_block = Some(voting_block);

        sumeragi
            .start_commit_countdown(
                voting_block_hash,
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        &self,
        sumeragi: &mut SumeragiWithFault<G, K, W, F>,
    ) -> Result<()> {
        sumeragi.update_view_changes(self.block.header().view_change_proofs.clone());
        let network_topology = sumeragi.network_topology_current_or_genesis(self.block.header());
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

        info!(
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

        info!(
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        &self,
        sumeragi: &mut SumeragiWithFault<G, K, W, F>,
    ) -> Result<()> {
        let network_topology = sumeragi.network_topology_current_or_genesis(self.block.header());
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
        let proxy_tail_signatures =
            network_topology.filter_signatures_by_roles(&[Role::ProxyTail], &verified_signatures);
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
    pub transaction: VersionedTransaction,
    /// `PeerId` of the peer that forwarded this transaction to a leader.
    pub peer: PeerId,
}

impl TransactionForwarded {
    /// Constructs `TransactionForwarded` message.
    pub fn new(transaction: VersionedAcceptedTransaction, peer: PeerId) -> TransactionForwarded {
        TransactionForwarded {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            transaction: transaction.into(),
            peer,
        }
    }

    /// Handles this message as part of `Sumeragi` consensus.
    ///
    /// # Errors
    /// Can fail due to signing transaction
    #[iroha_futures::telemetry_future]
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        self,
        sumeragi: &mut SumeragiWithFault<G, K, W, F>,
    ) -> Result<()> {
        let transaction = VersionedAcceptedTransaction::from_transaction(
            self.transaction.clone().into_v1(),
            &sumeragi.transaction_limits,
        )?;
        match sumeragi.queue.push(transaction) {
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
    txs: Vec<VersionedTransaction>,
}

impl TransactionGossip {
    /// Constructor.
    pub fn new(txs: Vec<VersionedAcceptedTransaction>) -> Self {
        Self {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            txs: txs.into_iter().map(Into::into).collect(),
        }
    }

    /// Handles this message as part of `Sumeragi` consensus.
    ///
    /// # Errors
    /// Can fail during signing.
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
        self,
        sumeragi: &mut SumeragiWithFault<G, K, W, F>,
    ) -> Result<()> {
        for transaction in self.txs {
            let tx = VersionedAcceptedTransaction::from_transaction(
                transaction.into_v1(),
                &sumeragi.transaction_limits,
            )?;
            match sumeragi.queue.push(tx) {
                Err((_, queue::Error::InBlockchain)) | Ok(()) => {}
                Err((_, err)) => {
                    warn!(?err, "Failed to push into queue gossiped transaction.")
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
        transaction: &VersionedTransaction,
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
    pub async fn handle<G: GenesisNetworkTrait, K: KuraTrait, W: WorldTrait, F: FaultInjection>(
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
