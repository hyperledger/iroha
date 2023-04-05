//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{cmp::Ordering, fmt::Display};

use derive_more::Display;
use getset::Getters;
use iroha_crypto::{HashOf, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
pub use model::*;
use parity_scale_codec::{Decode, Encode, Input};
use serde::{Deserialize, Serialize};

use crate::{events::prelude::*, peer, transaction::prelude::*};

/// Trait for basic block operations
pub trait Block {
    /// Calculate block hash
    #[cfg(feature = "std")]
    fn hash(&self) -> HashOf<BlockPayload> {
        HashOf::new(self.header()).transmute()
    }
    /// Return block header
    fn header(&self) -> &BlockHeader {
        &self.payload().header
    }

    /// Return block payload
    fn payload(&self) -> &BlockPayload;
    /// Return block signatures
    fn signatures(&self) -> &SignaturesOf<BlockPayload>;
}

#[model]
pub mod model {
    use super::*;
    use crate::transaction::error::TransactionRejectionReason;

    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
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
    // TODO: Do we need both BlockPayload and BlockHeader?
    // If yes, what data goes into which structure?
    pub struct BlockHeader {
        /// Number of blocks in the chain including this block.
        pub height: u64,
        /// Creation timestamp (unix time in milliseconds).
        pub timestamp_ms: u128,
        /// Hash of the previous block in the chain.
        pub previous_block_hash: Option<HashOf<BlockPayload>>,
        /// Hash of merkle tree root of valid transactions' hashes.
        pub transactions_hash: Option<HashOf<MerkleTree<TransactionPayload>>>,
        /// Hash of merkle tree root of rejected transactions' hashes.
        pub rejected_transactions_hash: Option<HashOf<MerkleTree<TransactionPayload>>>,
        /// Topology of the network at the time of block commit.
        pub commit_topology: Vec<peer::PeerId>,
        /// Value of view change index. Used to resolve soft forks.
        // NOTE: This field used to be required to rotate topology. After merging
        // https://github.com/hyperledger/iroha/pull/3250 only commit_topology is used
        #[deprecated(since = "2.0.0-pre-rc.13", note = "Will be removed in future versions")]
        pub view_change_index: u64,
        /// Estimation of consensus duration (in milliseconds).
        pub consensus_estimation_ms: u64,
    }

    #[derive(
        Debug, Display, Clone, Eq, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[display(fmt = "({header})")]
    #[getset(get = "pub")]
    #[allow(missing_docs)]
    #[ffi_type]
    pub struct BlockPayload {
        /// Block header
        pub header: BlockHeader,
        /// array of transactions, which successfully passed validation and consensus step.
        pub transactions: Vec<VersionedSignedTransaction>,
        /// Array of rejected transactions.
        pub rejected_transactions: Vec<(VersionedSignedTransaction, TransactionRejectionReason)>,
        /// Event recommendations.
        #[getset(skip)] // NOTE: Unused ATM
        pub event_recommendations: Vec<Event>,
    }

    /// Signed block
    #[version_with_scale(n = 1, versioned = "VersionedSignedBlock")]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Getters,
        Encode,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "({payload})")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct SignedBlock {
        /// Block payload
        pub payload: BlockPayload,
        /// Signatures of peers which approved this block.
        pub signatures: SignaturesOf<BlockPayload>,
    }
}

#[cfg(any(feature = "ffi-export", feature = "ffi-import"))]
declare_versioned!(VersionedSignedBlock 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi-export"), not(feature = "ffi-import")))]
declare_versioned!(VersionedSignedBlock 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, FromVariant, IntoSchema);

// TODO: Think about how should BlockPayload implement Eq, Ord, Hash?
impl PartialEq for BlockPayload {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
    }
}
impl PartialOrd for BlockPayload {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BlockPayload {
    fn cmp(&self, other: &Self) -> Ordering {
        self.header.cmp(&other.header)
    }
}
impl core::hash::Hash for BlockPayload {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.header.hash(state)
    }
}

impl BlockHeader {
    /// Checks if it's a header of a genesis block.
    #[inline]
    pub const fn is_genesis(&self) -> bool {
        self.height == 1
    }
}

impl Block for SignedBlock {
    fn payload(&self) -> &BlockPayload {
        &self.payload
    }
    fn signatures(&self) -> &SignaturesOf<BlockPayload> {
        &self.signatures
    }
}

impl Block for VersionedSignedBlock {
    fn payload(&self) -> &BlockPayload {
        let VersionedSignedBlock::V1(block) = self;
        block.payload()
    }
    fn signatures(&self) -> &SignaturesOf<BlockPayload> {
        let VersionedSignedBlock::V1(block) = self;
        block.signatures()
    }
}

mod candidate {
    use super::*;

    #[derive(Decode, Deserialize)]
    #[serde(transparent)]
    struct SignedBlockCandidate(SignedBlock);

    impl SignedBlockCandidate {
        fn validate(mut self) -> Result<SignedBlock, &'static str> {
            #[cfg(feature = "std")]
            self.validate_header()?;

            #[cfg(feature = "std")]
            if self.retain_verified_signatures().is_empty() {
                return Err("Block contains no signatures");
            }

            let payload = &self.0.payload;
            if payload.transactions.is_empty() && payload.rejected_transactions.is_empty() {
                return Err("Block is empty");
            }

            Ok(self.0)
        }

        #[cfg(feature = "std")]
        fn retain_verified_signatures(&mut self) -> Vec<&SignatureOf<BlockPayload>> {
            self.0
                .signatures
                .retain_verified_by_hash(self.0.hash())
                .collect()
        }

        #[cfg(feature = "std")]
        fn validate_header(&self) -> Result<(), &'static str> {
            let actual_txs_hash = self.0.header().transactions_hash;
            let actual_rejected_txs_hash = self.0.header().rejected_transactions_hash;

            let expected_txs_hash = self
                .0
                .payload
                .transactions
                .iter()
                .map(VersionedSignedTransaction::hash)
                .collect::<MerkleTree<_>>()
                .hash();
            let expected_rejected_txs_hash = self
                .0
                .payload
                .rejected_transactions
                .iter()
                .map(|(rejected_transaction, _)| rejected_transaction.hash())
                .collect::<MerkleTree<_>>()
                .hash();

            if expected_txs_hash != actual_txs_hash {
                return Err("Transactions' hash incorrect. Expected: {expected_txs_hash:?}, actual: {actual_txs_hash:?}");
            }
            if expected_rejected_txs_hash != actual_rejected_txs_hash {
                return Err("Rejected transactions' hash incorrect. Expected: {expected_rejected_txs_hash:?}, actual: {actual_rejected_txs_hash:?}");
            }
            // TODO: Validate Event recommendations somehow?

            Ok(())
        }
    }

    impl Decode for SignedBlock {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedBlockCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
    impl<'de> Deserialize<'de> for SignedBlock {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            SignedBlockCandidate::deserialize(deserializer)?
                .validate()
                .map_err(D::Error::custom)
        }
    }
}

impl Display for VersionedSignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let VersionedSignedBlock::V1(block) = self;
        block.fmt(f)
    }
}

#[cfg(feature = "http")]
pub mod stream {
    //! Blocks for streaming API.

    use derive_more::Constructor;
    use iroha_macro::FromVariant;
    use iroha_schema::IntoSchema;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    pub use self::model::*;
    use super::*;

    declare_versioned_with_scale!(VersionedBlockMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

    #[model]
    pub mod model {
        use super::*;

        /// Request sent to subscribe to blocks stream starting from the given height.
        #[version_with_scale(n = 1, versioned = "VersionedBlockSubscriptionRequest")]
        #[derive(Debug, Clone, Copy, Constructor, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct BlockSubscriptionRequest(pub u64);

        /// Message sent by the stream producer
        /// Block sent by the peer.
        #[version_with_scale(n = 1, versioned = "VersionedBlockMessage")]
        #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
        #[repr(transparent)]
        pub struct BlockMessage(pub VersionedSignedBlock);
    }

    impl From<BlockMessage> for VersionedSignedBlock {
        fn from(source: BlockMessage) -> Self {
            source.0
        }
    }

    declare_versioned_with_scale!(VersionedBlockSubscriptionRequest 1..2, Debug, Clone, FromVariant, IntoSchema);

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{VersionedBlockMessage, VersionedBlockSubscriptionRequest};
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::stream::prelude::*;
    pub use super::{Block, VersionedSignedBlock};
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
            Hash,
            iroha_macro::FromVariant,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "Block was rejected during consensus")]
        #[serde(untagged)]
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
