//! This module contains [`BlockValue`] and [`BlockHeaderValue`] structures, their implementation and related traits and
//! instructions implementations.
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use core::cmp::Ordering;

use derive_more::Display;
use iroha_crypto::{Hash, HashOf, MerkleTree};
use iroha_ffi::FfiType;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    events::Event,
    ffi::declare_item,
    transaction::{
        VersionedRejectedTransaction, VersionedSignedTransaction, VersionedValidTransaction,
    },
};

declare_item! {
    /// Block header
    #[derive(
        Debug, Clone, Display, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, FfiType, IntoSchema,
    )]
    #[display(fmt = "Block №{height} (hash: {transactions_hash});")]
    pub struct BlockHeaderValue {
        /// Unix time (in milliseconds) of block forming by a peer.
        pub timestamp: u128,
        /// a number of blocks in the chain up to the block.
        pub height: u64,
        /// Hash of a previous block in the chain.
        /// Is an array of zeros for the first block.
        pub previous_block_hash: Hash,
        /// Hash of merkle tree root of the tree of valid transactions' hashes.
        pub transactions_hash: HashOf<MerkleTree<VersionedSignedTransaction>>,
        /// Hash of merkle tree root of the tree of rejected transactions' hashes.
        pub rejected_transactions_hash: HashOf<MerkleTree<VersionedSignedTransaction>>,
        /// Hashes of the blocks that were rejected by consensus.
        pub invalidated_blocks_hashes: Vec<Hash>,
        /// Hash of the most recent block
        pub current_block_hash: Hash,
    }
}

impl PartialOrd for BlockHeaderValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockHeaderValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

/// Representation of block on blockchain
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema,
)]
#[display(fmt = "({})", header)]
pub struct BlockValue {
    /// Header
    pub header: BlockHeaderValue,
    /// Array of transactions
    pub transactions: Vec<VersionedValidTransaction>,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Event recommendations
    pub event_recommendations: Vec<Event>,
}

impl PartialOrd for BlockValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.header.cmp(&other.header)
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{BlockHeaderValue, BlockValue};
}
