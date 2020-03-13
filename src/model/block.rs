use crate::model::{crypto::Hash, tx::Transaction};

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
//TODO[@humb1t:RH2-8]: based on https://iroha.readthedocs.io/en/latest/concepts_architecture/glossary.html#block
//signatures placed outside of the payload - should we store them?
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Block {
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u64,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<Transaction>,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: Hash,
    /// rejected transactions hashes — array of transaction hashes, which did not pass stateful
    /// validation step; this field is optional.
    pub rejected_transactions_hashes: Option<Vec<Hash>>,
}

impl Block {
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
        previous_block_hash: [0; 32],
        rejected_transactions_hashes: None,
    };

    assert_ne!(block.hash(), [0; 32]);
}
