//! Contains message structures for p2p communication during consensus.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::module_name_repetitions
)]

use iroha_crypto::{HashOf, SignaturesOf};
use iroha_data_model::block::{BlockPayload, VersionedSignedBlock};
use iroha_macro::*;
use parity_scale_codec::{Decode, Encode};

use super::view_change;
use crate::block::{CommittedBlock, ValidBlock};

/// Helper structure, wrapping messages and view change proofs.
#[derive(Debug, Clone, Decode, Encode)]
pub struct MessagePacket {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    pub view_change_proofs: view_change::ProofChain,
    /// Actual Sumeragi message in this packet.
    pub message: Option<Message>,
}

impl MessagePacket {
    /// Construct [`Self`]
    pub fn new(view_change_proofs: view_change::ProofChain, message: Option<Message>) -> Self {
        Self {
            view_change_proofs,
            message,
        }
    }
}

#[allow(clippy::enum_variant_names)]
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
}

/// Specialization of `MessagePacket`
pub struct ControlFlowMessage {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    pub view_change_proofs: view_change::ProofChain,
}

impl From<ControlFlowMessage> for MessagePacket {
    fn from(m: ControlFlowMessage) -> MessagePacket {
        MessagePacket {
            view_change_proofs: m.view_change_proofs,
            message: None,
        }
    }
}

/// `BlockCreated` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockCreated {
    /// The corresponding block.
    pub block: VersionedSignedBlock,
}

impl From<ValidBlock> for BlockCreated {
    fn from(block: ValidBlock) -> Self {
        Self {
            block: block.into(),
        }
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
        let block_hash = block.payload().hash();
        let VersionedSignedBlock::V1(block) = block.into();

        Self {
            hash: block_hash,
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
        let block_hash = block.payload().hash();
        let VersionedSignedBlock::V1(block) = block.into();

        Self {
            hash: block_hash,
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

impl From<VersionedSignedBlock> for BlockSyncUpdate {
    fn from(block: VersionedSignedBlock) -> Self {
        Self { block }
    }
}
