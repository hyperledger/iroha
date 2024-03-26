//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{fmt::Display, time::Duration};

use derive_more::Display;
use getset::Getters;
use iroha_crypto::{HashOf, MerkleTree};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_primitives::unique_vec::UniqueVec;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{peer, transaction::prelude::*};

#[model]
pub mod model {
    use super::*;

    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[cfg_attr(
        feature = "std",
        display(fmt = "Block №{height} (hash: {});", "HashOf::new(&self)")
    )]
    #[cfg_attr(not(feature = "std"), display(fmt = "Block №{height}"))]
    #[getset(get = "pub")]
    #[allow(missing_docs)]
    #[ffi_type]
    pub struct BlockHeader {
        /// Number of blocks in the chain including this block.
        pub height: u64,
        /// Hash of the previous block in the chain.
        pub prev_block_hash: Option<HashOf<Block>>,
        /// Hash of merkle tree root of transactions' hashes.
        pub transactions_hash: HashOf<MerkleTree<SignedTransaction>>,
        /// Value of view change index. Used to resolve soft forks.
        pub view_change_index: u64,
        /// Creation timestamp (unix time in milliseconds).
        #[getset(skip)]
        pub creation_time_ms: u64,
    }

    /// Block
    #[version_with_scale(version = 1, versioned_alias = "Block")]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Serialize, IntoSchema,
    )]
    #[cfg_attr(not(feature = "std"), display(fmt = "Block"))]
    #[cfg_attr(feature = "std", display(fmt = "{}", "self.hash()"))]
    #[ffi_type]
    pub struct BlockV1 {
        /// Block header
        pub header: BlockHeader,
        /// Topology of the network at the time of block commit.
        pub commit_topology: UniqueVec<peer::PeerId>,
        /// Collection of all transactions store in the block
        pub transactions: Vec<CommittedTransaction>,
    }
}

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
declare_versioned!(Block 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
declare_versioned!(Block 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, IntoSchema);

impl BlockHeader {
    /// Checks if it's a header of a genesis block.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub const fn is_genesis(&self) -> bool {
        self.height == 1
    }

    /// Creation timestamp
    pub fn creation_time(&self) -> Duration {
        Duration::from_millis(self.creation_time_ms)
    }
}

impl BlockV1 {
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<Block> {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::HashOf::new(self).into())
    }
}

impl Block {
    /// Block header
    #[inline]
    pub fn header(&self) -> &BlockHeader {
        let Block::V1(block) = self;
        &block.header
    }

    /// Block commit topology
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub fn commit_topology(&self) -> &UniqueVec<peer::PeerId> {
        let Block::V1(block) = self;
        &block.commit_topology
    }

    /// Block transactions
    #[inline]
    pub fn transactions(&self) -> impl ExactSizeIterator<Item = &CommittedTransaction> {
        let Block::V1(block) = self;
        block.transactions.iter()
    }

    /// Calculate block hash
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }
}

mod candidate {
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct BlockCandidate {
        header: BlockHeader,
        commit_topology: UniqueVec<peer::PeerId>,
        transactions: Vec<CommittedTransaction>,
    }

    impl BlockCandidate {
        fn validate(self) -> Result<BlockV1, &'static str> {
            self.validate_header()?;

            if self.transactions.is_empty() {
                return Err("Block is empty");
            }

            Ok(BlockV1 {
                header: self.header,
                commit_topology: self.commit_topology,
                transactions: self.transactions,
            })
        }

        fn validate_header(&self) -> Result<(), &'static str> {
            let actual_txs_hash = self.header.transactions_hash;

            let expected_txs_hash = self
                .transactions
                .iter()
                .map(|value| value.as_ref().hash())
                .collect::<MerkleTree<_>>()
                .hash()
                .unwrap();

            if expected_txs_hash != actual_txs_hash {
                return Err("Transactions' hash incorrect. Expected: {expected_txs_hash:?}, actual: {actual_txs_hash:?}");
            }
            // TODO: Validate Event recommendations somehow?

            Ok(())
        }
    }

    impl Decode for BlockV1 {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            BlockCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
    impl<'de> Deserialize<'de> for BlockV1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            BlockCandidate::deserialize(deserializer)?
                .validate()
                .map_err(D::Error::custom)
        }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Block::V1(block) = self;
        block.fmt(f)
    }
}

#[cfg(feature = "http")]
pub mod stream {
    //! Blocks for streaming API.

    use derive_more::Constructor;
    use iroha_schema::IntoSchema;
    use parity_scale_codec::{Decode, Encode};

    pub use self::model::*;
    use super::*;

    #[model]
    pub mod model {
        use core::num::NonZeroU64;

        use super::*;

        /// Request sent to subscribe to blocks stream starting from the given height.
        #[derive(Debug, Clone, Copy, Constructor, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct BlockSubscriptionRequest(pub NonZeroU64);

        /// Message sent by the stream producer containing block.
        #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct BlockMessage(pub Block);
    }

    impl From<BlockMessage> for Block {
        fn from(source: BlockMessage) -> Self {
            source.0
        }
    }

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{BlockMessage, BlockSubscriptionRequest};
    }
}

pub mod error {
    //! Module containing errors that can occur during instruction evaluation

    pub use self::model::*;
    use super::*;

    #[model]
    pub mod model {
        use super::*;

        /// The reason for rejecting a transaction with new blocks.
        #[derive(
            Debug,
            Display,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            iroha_macro::FromVariant,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "Block was rejected during consensus")]
        #[serde(untagged)] // Unaffected by #3330 as it's a unit variant
        #[repr(transparent)]
        #[ffi_type]
        pub enum BlockRejectionReason {
            /// Block was rejected during consensus.
            ConsensusBlockRejection,
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for BlockRejectionReason {}
}
