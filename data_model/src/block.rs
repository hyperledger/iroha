//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{fmt::Display, time::Duration};

use derive_more::Display;
use iroha_crypto::{HashOf, MerkleTree, SignaturesOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_primitives::unique_vec::UniqueVec;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{events::prelude::*, peer, transaction::prelude::*};

#[model]
mod model {
    use getset::{CopyGetters, Getters};

    use super::*;

    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        CopyGetters,
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
    #[allow(missing_docs)]
    #[ffi_type]
    pub struct BlockHeader {
        /// Number of blocks in the chain including this block.
        #[getset(get_copy = "pub")]
        pub height: u64,
        /// Hash of the previous block in the chain.
        #[getset(get = "pub")]
        pub previous_block_hash: Option<HashOf<SignedBlock>>,
        /// Hash of merkle tree root of transactions' hashes.
        #[getset(get = "pub")]
        pub transactions_hash: Option<HashOf<MerkleTree<SignedTransaction>>>,
        /// Creation timestamp (unix time in milliseconds).
        #[getset(skip)]
        pub timestamp_ms: u64,
        /// Value of view change index. Used to resolve soft forks.
        #[getset(skip)]
        pub view_change_index: u64,
        /// Estimation of consensus duration (in milliseconds).
        pub consensus_estimation_ms: u64,
    }

    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "({header})")]
    #[allow(missing_docs)]
    pub(crate) struct BlockPayload {
        /// Block header
        pub header: BlockHeader,
        /// Topology of the network at the time of block commit.
        pub commit_topology: UniqueVec<peer::PeerId>,
        /// array of transactions, which successfully passed validation and consensus step.
        pub transactions: Vec<TransactionValue>,
        /// Event recommendations.
        pub event_recommendations: Vec<EventBox>,
    }

    /// Signed block
    #[version_with_scale(version = 1, versioned_alias = "SignedBlock")]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Serialize, IntoSchema,
    )]
    #[cfg_attr(not(feature = "std"), display(fmt = "Signed block"))]
    #[cfg_attr(feature = "std", display(fmt = "{}", "self.hash()"))]
    #[ffi_type]
    pub struct SignedBlockV1 {
        /// Signatures of peers which approved this block.
        pub signatures: SignaturesOf<BlockPayload>,
        /// Block payload
        pub payload: BlockPayload,
    }
}

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
declare_versioned!(SignedBlock 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
declare_versioned!(SignedBlock 1..2, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, IntoSchema);

impl BlockHeader {
    /// Checks if it's a header of a genesis block.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub const fn is_genesis(&self) -> bool {
        self.height == 1
    }

    /// Creation timestamp
    pub fn timestamp(&self) -> Duration {
        Duration::from_millis(self.timestamp_ms)
    }
}

impl SignedBlockV1 {
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<SignedBlock> {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::HashOf::new(self).into())
    }
}

impl SignedBlock {
    /// Block header
    #[inline]
    pub fn header(&self) -> &BlockHeader {
        let SignedBlock::V1(block) = self;
        &block.payload.header
    }

    /// Block transactions
    #[inline]
    pub fn transactions(&self) -> impl ExactSizeIterator<Item = &TransactionValue> {
        let SignedBlock::V1(block) = self;
        block.payload.transactions.iter()
    }

    /// Topology of the network at the time of block commit.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub fn commit_topology(&self) -> &UniqueVec<peer::PeerId> {
        let SignedBlock::V1(block) = self;
        &block.payload.commit_topology
    }

    /// Signatures of peers which approved this block.
    #[inline]
    #[allow(private_interfaces)]
    pub fn signatures(&self) -> &SignaturesOf<BlockPayload> {
        let SignedBlock::V1(block) = self;
        &block.signatures
    }

    /// Calculate block hash
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }

    /// Calculate block payload [`Hash`](`iroha_crypto::HashOf`).
    #[inline]
    #[cfg(feature = "std")]
    #[cfg(feature = "transparent_api")]
    pub fn hash_of_payload(&self) -> iroha_crypto::HashOf<BlockPayload> {
        let SignedBlock::V1(block) = self;
        iroha_crypto::HashOf::new(&block.payload)
    }

    /// Add additional signatures to this block
    #[must_use]
    #[cfg(all(feature = "std", feature = "transparent_api"))]
    pub fn sign(mut self, key_pair: &iroha_crypto::KeyPair) -> Self {
        let SignedBlock::V1(block) = &mut self;
        let signature = iroha_crypto::SignatureOf::new(key_pair, &block.payload);
        block.signatures.insert(signature);
        self
    }

    /// Add additional signatures to this block
    ///
    /// # Errors
    ///
    /// If given signature doesn't match block hash
    #[cfg(feature = "transparent_api")]
    pub fn add_signature(
        &mut self,
        signature: iroha_crypto::SignatureOf<BlockPayload>,
    ) -> Result<(), iroha_crypto::error::Error> {
        let SignedBlock::V1(block) = self;
        signature.verify(&block.payload)?;

        let SignedBlock::V1(block) = self;
        block.signatures.insert(signature);

        Ok(())
    }

    /// Add additional signatures to this block
    #[cfg(feature = "transparent_api")]
    pub fn replace_signatures(
        &mut self,
        signatures: iroha_crypto::SignaturesOf<BlockPayload>,
    ) -> bool {
        #[cfg(not(feature = "std"))]
        use alloc::collections::BTreeSet;
        #[cfg(feature = "std")]
        use std::collections::BTreeSet;

        let SignedBlock::V1(block) = self;
        block.signatures = BTreeSet::new().into();

        for signature in signatures {
            if self.add_signature(signature).is_err() {
                return false;
            }
        }

        true
    }
}

mod candidate {
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct SignedBlockCandidate {
        signatures: SignaturesOf<BlockPayload>,
        payload: BlockPayload,
    }

    impl SignedBlockCandidate {
        fn validate(self) -> Result<SignedBlockV1, &'static str> {
            self.validate_signatures()?;
            self.validate_header()?;

            if self.payload.transactions.is_empty() {
                return Err("Block is empty");
            }

            Ok(SignedBlockV1 {
                payload: self.payload,
                signatures: self.signatures,
            })
        }

        fn validate_header(&self) -> Result<(), &'static str> {
            let actual_txs_hash = self.payload.header.transactions_hash;

            let expected_txs_hash = self
                .payload
                .transactions
                .iter()
                .map(|value| value.as_ref().hash())
                .collect::<MerkleTree<_>>()
                .hash();

            if expected_txs_hash != actual_txs_hash {
                return Err("Transactions' hash incorrect. Expected: {expected_txs_hash:?}, actual: {actual_txs_hash:?}");
            }
            // TODO: Validate Event recommendations somehow?

            Ok(())
        }

        fn validate_signatures(&self) -> Result<(), &'static str> {
            self.signatures
                .verify(&self.payload)
                .map_err(|_| "Transaction contains invalid signatures")
        }
    }

    impl Decode for SignedBlockV1 {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedBlockCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
    impl<'de> Deserialize<'de> for SignedBlockV1 {
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

impl Display for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let SignedBlock::V1(block) = self;
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
    mod model {
        use core::num::NonZeroU64;

        use super::*;

        /// Request sent to subscribe to blocks stream starting from the given height.
        #[derive(
            Debug, Clone, Copy, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema,
        )]
        #[repr(transparent)]
        pub struct BlockSubscriptionRequest(pub NonZeroU64);

        /// Message sent by the stream producer containing block.
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[repr(transparent)]
        pub struct BlockMessage(pub SignedBlock);
    }

    impl From<BlockMessage> for SignedBlock {
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
    mod model {
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
