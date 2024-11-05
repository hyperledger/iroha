//! Contains message structures for p2p communication during consensus.
use iroha_crypto::HashOf;
use iroha_data_model::block::{BlockHeader, BlockSignature, SignedBlock};
use iroha_macro::*;
use parity_scale_codec::{Decode, Encode};

use super::view_change;
use crate::block::{CommittedBlock, NewBlock, ValidBlock};

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

/// Specialization of [`BlockMessage`]
#[derive(Debug, Clone, Decode, Encode)]
pub enum ControlFlowMessage {
    /// Proof of view change. As part of this message handling, all
    /// peers which agree with view change should sign it.
    ViewChangeProof(view_change::SignedViewChangeProof),
}

/// `BlockCreated` message structure.
#[derive(Debug, Clone, Decode, Encode)]
pub struct BlockCreated {
    /// The corresponding block.
    pub block: SignedBlock,
}

impl From<&NewBlock> for BlockCreated {
    fn from(block: &NewBlock) -> Self {
        Self {
            // TODO: Redundant clone
            block: block.clone().into(),
        }
    }
}

impl From<&SignedBlock> for BlockCreated {
    fn from(block: &SignedBlock) -> Self {
        Self {
            // TODO: Redundant clone
            block: block.clone(),
        }
    }
}

/// `BlockSigned` message structure.
#[derive(Debug, Clone, Decode, Encode)]
pub struct BlockSigned {
    /// Hash of the block being signed.
    pub hash: HashOf<BlockHeader>,
    /// Signature of the block
    pub signature: BlockSignature,
}

impl From<&ValidBlock> for BlockSigned {
    fn from(block: &ValidBlock) -> Self {
        Self {
            hash: block.as_ref().hash(),
            signature: block
                .as_ref()
                .signatures()
                .last()
                .cloned()
                .expect("INTERNAL BUG: Block must have at least one signature"),
        }
    }
}

/// `BlockCommitted` message structure.
#[derive(Debug, Clone, Encode)]
pub struct BlockCommitted {
    /// Hash of the block being signed.
    pub hash: HashOf<BlockHeader>,
    /// Set of signatures.
    pub signatures: Vec<BlockSignature>,
}

impl From<&CommittedBlock> for BlockCommitted {
    fn from(block: &CommittedBlock) -> Self {
        Self {
            hash: block.as_ref().hash(),
            signatures: block.as_ref().signatures().cloned().collect(),
        }
    }
}

/// `BlockSyncUpdate` message structure
#[derive(Debug, Clone, Decode, Encode)]
pub struct BlockSyncUpdate {
    /// The corresponding block.
    pub block: SignedBlock,
}

impl From<&SignedBlock> for BlockSyncUpdate {
    fn from(block: &SignedBlock) -> Self {
        // TODO: Redundant clone
        Self {
            block: block.clone(),
        }
    }
}

mod candidate {
    use indexmap::IndexSet;
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode)]
    struct BlockCommittedCandidate {
        /// Hash of the block being signed.
        pub hash: HashOf<BlockHeader>,
        /// Set of signatures.
        pub signatures: Vec<BlockSignature>,
    }

    impl BlockCommittedCandidate {
        fn validate(self) -> Result<BlockCommitted, &'static str> {
            self.validate_signatures()?;

            Ok(BlockCommitted {
                hash: self.hash,
                signatures: self.signatures,
            })
        }

        fn validate_signatures(&self) -> Result<(), &'static str> {
            if self.signatures.is_empty() {
                return Err("No signatures in block");
            }

            self.signatures
                .iter()
                .map(|signature| &signature.0)
                .try_fold(IndexSet::new(), |mut acc, elem| {
                    if !acc.insert(elem) {
                        return Err("Duplicate signature");
                    }

                    Ok(acc)
                })?;

            Ok(())
        }
    }

    impl Decode for BlockCommitted {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            BlockCommittedCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
}
