//! Contains message structures for p2p communication during consensus.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::module_name_repetitions
)]

use iroha_data_model::prelude::*;
use iroha_macro::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use super::view_change;
use crate::{VersionedAcceptedTransaction, VersionedValidBlock};

declare_versioned_with_scale!(VersionedPacket 1..2, Debug, Clone, iroha_macro::FromVariant, iroha_actor::Message);

impl VersionedPacket {
    /// Convert `&`[`Self`] to V1 reference
    pub const fn as_v1(&self) -> &MessagePacket {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert `&mut` [`Self`] to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut MessagePacket {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Perform the conversion from [`Self`] to V1
    pub fn into_v1(self) -> MessagePacket {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

/// Helper structure, wrapping messages and view change proofs.
#[version_with_scale(n = 1, versioned = "VersionedPacket")]
#[derive(Debug, Clone, Decode, Encode, iroha_actor::Message)]
pub struct MessagePacket {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    pub view_change_proofs: Vec<view_change::Proof>,
    /// Actual Sumeragi message in this packet.
    pub message: Message,
}

impl MessagePacket {
    /// Construct [`Self`]
    pub fn new(view_change_proofs: Vec<view_change::Proof>, message: Message) -> Self {
        Self {
            view_change_proofs,
            message,
        }
    }
}

/// Message's variants that are used by peers to communicate in the process of consensus.
#[derive(Debug, Clone, Decode, Encode, FromVariant)]
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
    ViewChangeSuggested,
    /// Is sent by all peers during gossiping.
    TransactionGossip(TransactionGossip),
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
    pub transaction: VersionedSignedTransaction,
}

impl TransactionForwarded {
    /// Constructs `TransactionForwarded` message.
    pub fn new(transaction: VersionedAcceptedTransaction) -> TransactionForwarded {
        TransactionForwarded {
            // Converting into non-accepted transaction because it's not possible
            // to guarantee that the sending peer checked transaction limits
            transaction: transaction.into(),
        }
    }
}

/// Message for gossiping batches of transactions.
#[derive(Decode, Encode, Debug, Clone)]
pub struct TransactionGossip {
    /// Batch of transactions.
    pub txs: Vec<VersionedSignedTransaction>,
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
