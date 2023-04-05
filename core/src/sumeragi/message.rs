//! Contains message structures for p2p communication during consensus.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::module_name_repetitions
)]

use iroha_crypto::{HashOf, SignaturesOf};
use iroha_data_model::{
    block::{Block, BlockPayload},
    prelude::*,
};
use iroha_macro::*;
use iroha_version::prelude::*;
use parity_scale_codec::{Decode, Encode};

use super::view_change;
use crate::block::{CommittedBlock, ValidBlock};

declare_versioned_with_scale!(VersionedPacket 1..2, Debug, Clone, iroha_macro::FromVariant);

/// Helper structure, wrapping messages and view change proofs.
#[version_with_scale(n = 1, versioned = "VersionedPacket")]
#[derive(Debug, Clone, Decode, Encode)]
pub struct MessagePacket {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    pub view_change_proofs: view_change::ProofChain,
    /// Actual Sumeragi message in this packet.
    pub message: Message,
}

impl MessagePacket {
    /// Construct [`Self`]
    pub fn new(view_change_proofs: view_change::ProofChain, message: impl Into<Message>) -> Self {
        Self {
            view_change_proofs,
            message: message.into(),
        }
    }
}

/// Message's variants that are used by peers to communicate in the process of consensus.
#[derive(Debug, Clone, Decode, Encode, FromVariant)]
pub enum Message {
    /// This message is sent by leader to all validating peers, when a new block is created.
    BlockCreated(BlockCreated),
    /// This message is sent by validating peers to proxy tail and observing peers when they have signed this block.
    BlockSigned(BlockSigned),
    /// This message is sent by proxy tail to validating peers and to leader, when the block is committed.
    BlockCommitted(BlockCommitted),
    /// This message is sent by `BlockSync` when new block is received
    BlockSyncUpdate(BlockSyncUpdate),
    /// View change is suggested due to some faulty peer or general fault in consensus.
    ViewChangeSuggested,
}

/// `BlockCreated` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockCreated {
    /// The corresponding block.
    pub block: VersionedSignedBlock,
}

impl From<VersionedSignedBlock> for BlockCreated {
    fn from(block: VersionedSignedBlock) -> Self {
        Self { block }
    }
}

/// `BlockSigned` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockSigned {
    /// Hash of the block being signed.
    pub hash: HashOf<BlockPayload>,
    /// Set of signatures.
    pub signatures: SignaturesOf<BlockPayload>,
}

impl From<ValidBlock> for BlockSigned {
    fn from(block: ValidBlock) -> Self {
        let VersionedSignedBlock::V1(block) = block.into();

        Self {
            hash: block.hash(),
            signatures: block.signatures,
        }
    }
}

/// `BlockCommitted` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockCommitted {
    /// Hash of the block being signed.
    pub hash: HashOf<BlockPayload>,
    /// Set of signatures.
    pub signatures: SignaturesOf<BlockPayload>,
}

impl From<CommittedBlock> for BlockCommitted {
    fn from(block: CommittedBlock) -> Self {
        let VersionedSignedBlock::V1(block) = block.into();

        Self {
            hash: block.hash(),
            signatures: block.signatures,
        }
    }
}

/// `BlockSyncUpdate` message structure
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockSyncUpdate {
    /// The corresponding block.
    pub block: VersionedSignedBlock,
}
