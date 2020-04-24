use crate::{crypto, prelude::*};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
//TODO[@humb1t:RH2-8]: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
//signatures placed outside of the payload - should we store them?
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct Block {
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<Transaction>,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: Option<Hash>,
    /// Signatures of peers which approved this block
    pub signatures: Vec<Signature>,
}

impl Block {
    pub fn builder(transactions: Vec<Transaction>) -> BlockBuilder {
        BlockBuilder {
            transactions,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            ..Default::default()
        }
    }

    pub fn hash(&self) -> Hash {
        crypto::hash(self.into())
    }
}

#[derive(Default)]
pub struct BlockBuilder {
    pub height: Option<u64>,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub previous_block_hash: Option<Hash>,
    pub rejected_transactions_hashes: Vec<Hash>,
}

impl BlockBuilder {
    pub fn height(mut self, height: u64) -> Self {
        self.height = Option::Some(height);
        self
    }

    pub fn build(self) -> Block {
        Block {
            height: self.height.unwrap_or(0),
            timestamp: self.timestamp,
            transactions: self.transactions,
            previous_block_hash: self.previous_block_hash,
            signatures: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_hash() {
        let block = Block {
            height: 0,
            timestamp: 1,
            transactions: Vec::new(),
            previous_block_hash: None,
            signatures: vec![],
        };

        assert_ne!(block.hash(), [0; 32]);
    }
}
