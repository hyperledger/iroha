use crate::{kura::Kura, prelude::*};
use std::time::SystemTime;

/// Chain of `Blocks`.
pub struct Blockchain {
    blocks: Vec<Block>,
    kura: Kura,
}

impl Blockchain {
    pub fn new(kura: Kura) -> Self {
        Blockchain {
            kura,
            //TODO: we should fill blockchain with already stored blocks.
            blocks: Vec::new(),
        }
    }

    pub async fn accept(&mut self, transactions: Vec<Transaction>) {
        let mut block = Block::builder(transactions).build();
        if !self.blocks.is_empty() {
            let last_block_index = self.blocks.len() - 1;
            block.height = last_block_index as u64 + 1;
            block.previous_block_hash = Some(self.blocks.as_mut_slice()[last_block_index].hash());
        }
        self.kura
            .store(&block)
            .await
            .expect("Failed to store block into Kura.");
        self.blocks.push(block);
    }

    pub fn last(&self) -> &Block {
        &self.blocks[..]
            .last()
            .expect("Failed to extract last block.")
    }
}

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
//TODO[@humb1t:RH2-8]: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
//signatures placed outside of the payload - should we store them?
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    /// rejected transactions hashes — array of transaction hashes, which did not pass stateful
    /// validation step; this field is optional.
    pub rejected_transactions_hashes: Option<Vec<Hash>>,
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
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };

        let bytes: Vec<u8> = self.into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

#[derive(Default)]
pub struct BlockBuilder {
    pub height: Option<u64>,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub previous_block_hash: Option<Hash>,
    pub rejected_transactions_hashes: Option<Vec<Hash>>,
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
            rejected_transactions_hashes: self.rejected_transactions_hashes,
        }
    }
}

impl std::convert::From<&Block> for Vec<u8> {
    fn from(block: &Block) -> Self {
        bincode::serialize(block).expect("Failed to serialize block.")
    }
}

impl std::convert::From<Vec<u8>> for Block {
    fn from(bytes: Vec<u8>) -> Self {
        bincode::deserialize(&bytes).expect("Failed to deserialize block.")
    }
}

#[test]
fn block_hash() {
    let block = Block {
        height: 0,
        timestamp: 1,
        transactions: Vec::new(),
        previous_block_hash: None,
        rejected_transactions_hashes: None,
    };

    assert_ne!(block.hash(), [0; 32]);
}
