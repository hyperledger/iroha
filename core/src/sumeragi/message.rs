//! Contains message structures for p2p communication during consensus.
use iroha_data_model::block::{BlockSignature, SignedBlock};
use iroha_macro::*;
use parity_scale_codec::{Decode, Encode};

use super::view_change;
use crate::block::{CommittedBlock, ValidBlock};

#[allow(clippy::enum_variant_names)]
/// Message's variants that are used by peers to communicate in the process of consensus.
#[derive(Debug, Clone, Decode, Encode, FromVariant)]
pub enum BlockMessage {
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
#[derive(Debug, Clone, Decode, Encode)]
pub struct ControlFlowMessage {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    pub view_change_proofs: view_change::ProofChain,
}

impl ControlFlowMessage {
    /// Helper function to construct a `ControlFlowMessage`
    pub fn new(view_change_proofs: view_change::ProofChain) -> ControlFlowMessage {
        ControlFlowMessage { view_change_proofs }
    }
}

/// `BlockCreated` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockCreated {
    /// The corresponding block.
    pub block: SignedBlock,
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
    /// Set of signatures.
    pub signatures: Vec<BlockSignature>,
}

impl From<&ValidBlock> for BlockSigned {
    fn from(block: &ValidBlock) -> Self {
        Self {
            signatures: block.as_ref().signatures().cloned().collect(),
        }
    }
}

/// `BlockCommitted` message structure.
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockCommitted {
    /// Set of signatures.
    pub signatures: Vec<BlockSignature>,
}

impl From<&CommittedBlock> for BlockCommitted {
    fn from(block: &CommittedBlock) -> Self {
        Self {
            signatures: block.as_ref().signatures().cloned().collect(),
        }
    }
}

/// `BlockSyncUpdate` message structure
#[derive(Debug, Clone, Decode, Encode)]
#[non_exhaustive]
pub struct BlockSyncUpdate {
    /// The corresponding block.
    pub block: SignedBlock,
}

impl From<SignedBlock> for BlockSyncUpdate {
    fn from(block: SignedBlock) -> Self {
        Self { block }
    }
}
