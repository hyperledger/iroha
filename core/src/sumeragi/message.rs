//! Contains message structures for p2p communication during consensus.
#![allow(clippy::module_name_repetitions)]
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
#![allow(clippy::significant_drop_in_scrutinee)]

use std::time::Duration;

use eyre::{Result, WrapErr};
use futures::{prelude::*, stream::FuturesUnordered};
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
    view_change::{self, Proof, ProofChain},
};
use crate::{
    block::BlockHeader,
    genesis::GenesisNetworkTrait,
    queue, send_event,
    sumeragi::{NetworkMessage, Role, Sumeragi, Topology, VotingBlock},
    VersionedAcceptedTransaction, VersionedCommittedBlock, VersionedValidBlock,
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
    #[log(skip(self, broker))]
    pub fn send_to(self, broker: &iroha_actor::broker::Broker, peer: &PeerId) {
        let post = Post {
            data: NetworkMessage::SumeragiMessage(Box::new(self)),
            peer: peer.clone(),
        };
        broker.issue_send_sync(&post);
    }

    /// Send this message over the network to multiple `peers`.
    /// # Errors
    /// Fails if network sending fails
    pub fn send_to_multiple<'itm, I>(self, broker: &iroha_actor::broker::Broker, peers: I)
    where
        I: IntoIterator<Item = &'itm PeerId> + Send,
    {
        for peer_id in peers.into_iter() {
            self.clone().send_to(broker, peer_id);
        }
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
    /// Tx forwarded from client by a peer to a leader.
    TransactionForwarded(TransactionForwarded),
    /// View change is suggested due to some faulty peer or general fault in consensus.
    ViewChangeSuggested(ViewChangeSuggested),
    /// Is sent by all peers during gossiping.
    TransactionGossip(TransactionGossip),
}

/// `ViewChangeSuggested` message structure.
#[derive(Debug, Clone, Decode, Encode)]
pub struct ViewChangeSuggested {
    /// Proof of view change. As part of this message handling, all peers which agree with view change should sign it.
    pub proofs: Vec<view_change::Proof>,
}

impl ViewChangeSuggested {
    /// Constructor.
    pub const fn new(proofs: Vec<view_change::Proof>) -> ViewChangeSuggested {
        Self { proofs }
    }
}

/// `BlockCreated` message structure.
#[derive(Debug, Clone, Decode, Encode)]
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
#[derive(Debug, Clone, Decode, Encode)]
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
#[derive(Debug, Clone, Decode, Encode)]
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
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct TransactionForwarded {
    /// Transaction that is forwarded from a client by a peer to the leader
    pub transaction: VersionedTransaction,
    /// `PeerId` of the peer that forwarded this transaction to a leader.
    pub peer: PeerId,
    pub view_change_proofs: Vec<Proof>,
}

impl TransactionForwarded {
    /// Constructs `TransactionForwarded` message.
    pub fn new(
        transaction: VersionedAcceptedTransaction,
        peer: PeerId,
        view_change_proofs: Vec<Proof>,
    ) -> TransactionForwarded {
        TransactionForwarded {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            transaction: transaction.into(),
            peer,
            view_change_proofs,
        }
    }
}

/// Message for gossiping batches of transactions.
#[derive(Decode, Encode, Debug, Clone)]
pub struct TransactionGossip {
    pub txs: Vec<VersionedTransaction>,
}

impl TransactionGossip {
    #![allow(clippy::unused_async)]
    /// Constructor.
    pub fn new(txs: Vec<VersionedAcceptedTransaction>) -> Self {
        Self {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            txs: txs.into_iter().map(Into::into).collect(),
        }
    }
}
