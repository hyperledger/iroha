//! This module contains `Block` structures for each state, it's transitions, implementations and related traits
//! implementations.

use crate::{crypto, prelude::*};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
/// Blocks lifecycle starts from "Pending" state which is represented by `PendingBlock` struct.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct PendingBlock {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<AcceptedTransaction>,
}

impl PendingBlock {
    /// Create a new `PendingBlock` from transactions.
    pub fn new(transactions: Vec<AcceptedTransaction>) -> PendingBlock {
        PendingBlock {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            transactions,
        }
    }

    /// Chain block with the existing blockchain.
    pub fn chain(self, height: u64, previous_block_hash: Hash) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height,
                previous_block_hash,
                // TODO: get actual merkle tree hash
                merkle_root_hash: [0u8; 32],
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first(self) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 0,
                previous_block_hash: [0u8; 32],
                merkle_root_hash: [0u8; 32],
            },
        }
    }
}

/// When `PendingBlock` chained with a blockchain it becomes `ChainedBlock`
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ChainedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<AcceptedTransaction>,
}

/// Header of the block. The hash should be taken from its byte representation.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct BlockHeader {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: Hash,
    /// Hash of merkle tree root of the tree of transactions hashes.
    pub merkle_root_hash: Hash,
}

impl BlockHeader {
    /// Calculate hash of the current block header.
    pub fn hash(&self) -> Hash {
        crypto::hash(self.into())
    }
}

impl ChainedBlock {
    /// Sign block by the given key pair.
    pub fn sign(
        self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<SignedBlock, String> {
        let signature_payload: Vec<u8> = self.hash().to_vec();
        let mut transactions = Vec::new();
        for transaction in self.transactions {
            transactions.push(transaction.sign(public_key, private_key)?);
        }
        Ok(SignedBlock {
            header: self.header,
            transactions,
            signatures: vec![Signature::new(
                *public_key,
                &signature_payload,
                private_key,
            )?],
        })
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// When a `ChainedBlock` is created by a peer or received for a vote it can be signed by the peer
/// changing it's type to a `SignedBlock`. Block can be signed several times by different peers.
//TODO[@humb1t:RH2-8]: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
//signatures placed outside of the payload - should we store them?
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct SignedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<SignedTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: Vec<Signature>,
}

impl SignedBlock {
    /// Add additional signature to the already signed block.
    pub fn sign(
        mut self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Result<SignedBlock, String> {
        let signature_payload: Vec<u8> = self.hash().to_vec();
        self.signatures.push(Signature::new(
            *public_key,
            &signature_payload,
            private_key,
        )?);
        Ok(SignedBlock {
            header: self.header,
            transactions: self.transactions,
            signatures: self.signatures,
        })
    }

    /// Validate block transactions against current state of the world.
    pub fn validate(self, world_state_view: &WorldStateView) -> Result<ValidBlock, String> {
        let mut world_state_view = world_state_view.clone();
        Ok(ValidBlock {
            header: self.header,
            signatures: self.signatures,
            transactions: self
                .transactions
                .into_iter()
                .map(|transaction| transaction.validate(&mut world_state_view))
                .filter_map(Result::ok)
                .collect(),
        })
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// After full validation `SignedBlock` can transform into `ValidBlock`.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ValidBlock {
    /// Header
    pub header: BlockHeader,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<ValidTransaction>,
    /// Signatures of peers which approved this block
    pub signatures: Vec<Signature>,
}

impl ValidBlock {
    /// Commit block to the store.
    //TODO: pass block store and block sender as parameters?
    pub fn commit(self) -> CommittedBlock {
        CommittedBlock {
            header: self.header,
            transactions: self.transactions,
            signatures: self.signatures,
        }
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// When Kura receives `ValidBlock`, the block is stored and
/// then sent to later stage of the pipeline as `CommitedBlock`.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct CommittedBlock {
    /// Header
    pub header: BlockHeader,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<ValidTransaction>,
    /// Signatures of peers which approved this block
    pub signatures: Vec<Signature>,
}

impl CommittedBlock {
    /// Calculate hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{BlockHeader, ValidBlock};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                height: 0,
                previous_block_hash: [0u8; 32],
                merkle_root_hash: [0u8; 32],
            },
            transactions: vec![],
            signatures: vec![],
        };
        let commited_block = valid_block.clone().commit();
        assert_eq!(valid_block.hash(), commited_block.hash())
    }
}
