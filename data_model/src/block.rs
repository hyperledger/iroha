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
#[cfg(feature = "std")]
use iroha_crypto::SignatureOf;
use iroha_crypto::{Hash, HashOf, MerkleTree, SignaturesOf};
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::{
    committed::{CommittedBlock, PartialBlockHash, VersionedCommittedBlock},
    header::BlockHeader,
};
use crate::{events::prelude::*, model, peer, transaction::prelude::*};

mod header {
    pub use self::model::*;
    use super::*;

    #[model]
    pub mod model {
        use super::*;

        /// Header of the block. The hash should be taken from its byte representation.
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
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
        #[ffi_type]
        pub struct BlockHeader {
            /// Unix time (in milliseconds) of block forming by a peer.
            pub timestamp: u128,
            /// Estimation of consensus duration in milliseconds
            pub consensus_estimation: u64,
            /// A number of blocks in the chain up to the block.
            pub height: u64,
            /// Value of view change index used to resolve soft forks
            pub view_change_index: u64,
            /// Hash of a previous block in the chain.
            /// Is an array of zeros for the first block.
            pub previous_block_hash: Option<HashOf<VersionedCommittedBlock>>,
            /// Hash of merkle tree root of the tree of valid transactions' hashes.
            pub transactions_hash: Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
            /// Hash of merkle tree root of the tree of rejected transactions' hashes.
            pub rejected_transactions_hash: Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
            /// Network topology when the block was committed.
            // TODO: Derive with getset once FFI impl is fixed
            #[getset(skip)]
            pub committed_with_topology: Vec<peer::PeerId>,
        }
    }

    impl BlockHeader {
        /// Checks if it's a header of a genesis block.
        #[inline]
        pub const fn is_genesis(&self) -> bool {
            self.height == 1
        }
        /// Serialize the header's data for hashing purposes.
        pub fn payload(&self) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend(&self.timestamp.to_le_bytes());
            data.extend(&self.consensus_estimation.to_le_bytes());
            data.extend(&self.height.to_le_bytes());
            data.extend(&self.view_change_index.to_le_bytes());
            if let Some(hash) = self.previous_block_hash.as_ref() {
                data.extend(hash.as_ref());
            }
            if let Some(hash) = self.transactions_hash.as_ref() {
                data.extend(hash.as_ref());
            }
            if let Some(hash) = self.rejected_transactions_hash.as_ref() {
                data.extend(hash.as_ref());
            }
            for id in &self.committed_with_topology {
                data.extend(id.payload());
            }
            data
        }
    }

    impl PartialOrd for BlockHeader {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for BlockHeader {
        fn cmp(&self, other: &Self) -> Ordering {
            self.timestamp.cmp(&other.timestamp)
        }
    }
}

mod committed {
    use iroha_macro::FromVariant;

    pub use self::model::*;
    use super::*;

    #[cfg(any(feature = "ffi_import", feature = "ffi_export"))]
    declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, Deserialize, Serialize, iroha_ffi::FfiType, IntoSchema);
    #[cfg(all(not(feature = "ffi_import"), not(feature = "ffi_export")))]
    declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, Deserialize, Serialize, IntoSchema);

    #[model]
    pub mod model {
        use super::*;

        /// The hash of a [`VersionedCommittedBlock`] used for signing in consensus.
        /// The normal [`Hashof<VersionedCommittedBlock>`] will change based on who
        /// has signed the block. If you want to compare the contents of a block only
        /// use this hash instead.
        #[derive(
            Debug,
            Display,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Getters,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "({internal})")]
        #[repr(transparent)]
        #[serde(transparent)]
        #[ffi_type(unsafe {robust})]
        pub struct PartialBlockHash {
            /// The hash value.
            pub internal: Hash,
        }

        /// The `CommittedBlock` struct represents a block accepted by consensus
        #[version_with_scale(n = 1, versioned = "VersionedCommittedBlock")]
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            Hash,
            Getters,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "({header})")]
        #[getset(get = "pub")]
        #[ffi_type]
        pub struct CommittedBlock {
            /// Block header
            pub header: BlockHeader,
            /// Array of rejected transactions.
            // TODO: Derive with getset once FFI impl is fixed
            #[getset(skip)]
            pub rejected_transactions: Vec<VersionedRejectedTransaction>,
            /// array of transactions, which successfully passed validation and consensus step.
            // TODO: Derive with getset once FFI impl is fixed
            #[getset(skip)]
            pub transactions: Vec<VersionedValidTransaction>,
            /// Event recommendations.
            // TODO: Derive with getset once FFI impl is fixed
            #[getset(skip)]
            pub event_recommendations: Vec<Event>,
            /// Signatures of peers which approved this block
            #[getset(skip)]
            pub signatures: SignaturesOf<Self>,
        }
    }

    impl VersionedCommittedBlock {
        /// Convert from `&VersionedCommittedBlock` to V1 reference
        #[inline]
        pub const fn as_v1(&self) -> &CommittedBlock {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Convert from `&mut VersionedCommittedBlock` to V1 mutable reference
        #[inline]
        pub fn as_mut_v1(&mut self) -> &mut CommittedBlock {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedCommittedBlock` to V1
        #[inline]
        pub fn into_v1(self) -> CommittedBlock {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Calculate the [`PartialBlockHash`] of this block.
        #[cfg(feature = "std")]
        #[inline]
        pub fn partial_hash(&self) -> PartialBlockHash {
            match self {
                Self::V1(v1) => v1.partial_hash(),
            }
        }

        /// Calculate the [`HashOf<VersionedCommittedBlock>`] for this block.
        #[cfg(feature = "std")]
        pub fn hash(&self) -> HashOf<Self> {
            match self {
                Self::V1(v1) => v1.hash().transmute(),
            }
        }

        /// Return signatures that are verified with the `hash` of this block
        #[cfg(feature = "std")]
        #[inline]
        pub fn signatures(&self) -> impl ExactSizeIterator<Item = &SignatureOf<Self>> {
            self.as_v1().signatures().map(SignatureOf::transmute_ref)
        }
    }

    impl Display for VersionedCommittedBlock {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            self.as_v1().fmt(f)
        }
    }

    impl PartialOrd for VersionedCommittedBlock {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for VersionedCommittedBlock {
        fn cmp(&self, other: &Self) -> Ordering {
            self.as_v1().cmp(other.as_v1())
        }
    }

    impl CommittedBlock {
        /// Calculate the partial hash of the current block.
        /// [`CommitedBlock`] should have the same partial hash as [`PendingBlock`].
        #[cfg(feature = "std")]
        #[inline]
        pub fn partial_hash(&self) -> PartialBlockHash {
            PartialBlockHash {
                internal: Hash::new(self.header.payload()),
            }
        }
        /// Calculate the complete hash of the block that includes signatures.
        #[cfg(feature = "std")]
        #[inline]
        pub fn hash(&self) -> HashOf<Self> {
            let mut data = Vec::new();
            data.extend(self.header.payload());
            for s in self.signatures.iter() {
                data.extend(s.key_payload());
                data.extend(s.signature_payload());
            }
            Hash::new(&data).typed()
        }

        /// Return signatures that are verified with the `hash` of this block
        #[cfg(feature = "std")]
        #[inline]
        pub fn signatures(&self) -> impl ExactSizeIterator<Item = &SignatureOf<Self>> {
            self.signatures.iter()
        }
    }

    impl PartialOrd for CommittedBlock {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for CommittedBlock {
        fn cmp(&self, other: &Self) -> Ordering {
            self.header.cmp(&other.header)
        }
    }

    #[cfg(feature = "std")]
    impl From<&CommittedBlock> for Vec<Event> {
        fn from(block: &CommittedBlock) -> Self {
            let rejected_tx = block
                .rejected_transactions
                .iter()
                .cloned()
                .map(|transaction| {
                    PipelineEvent {
                        entity_kind: PipelineEntityKind::Transaction,
                        status: PipelineStatus::Rejected(
                            transaction.as_v1().rejection_reason.clone().into(),
                        ),
                        hash: transaction.hash().into(),
                    }
                    .into()
                });
            let tx = block.transactions.iter().cloned().map(|transaction| {
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status: PipelineStatus::Committed,
                    hash: transaction.hash().into(),
                }
                .into()
            });
            let current_block = core::iter::once(
                PipelineEvent {
                    entity_kind: PipelineEntityKind::Block,
                    status: PipelineStatus::Committed,
                    hash: block.hash().into(),
                }
                .into(),
            );

            tx.chain(rejected_tx).chain(current_block).collect()
        }
    }

    #[cfg(feature = "std")]
    impl From<&VersionedCommittedBlock> for Vec<Event> {
        #[inline]
        fn from(block: &VersionedCommittedBlock) -> Self {
            block.as_v1().into()
        }
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

    impl VersionedBlockMessage {
        /// Convert from `&VersionedBlockPublisherMessage` to V1 reference
        pub const fn as_v1(&self) -> &BlockMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Convert from `&mut VersionedBlockPublisherMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut BlockMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedBlockPublisherMessage` to V1
        pub fn into_v1(self) -> BlockMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

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
        pub struct BlockMessage(pub VersionedCommittedBlock);
    }

    impl From<BlockMessage> for VersionedCommittedBlock {
        fn from(source: BlockMessage) -> Self {
            source.0
        }
    }

    declare_versioned_with_scale!(VersionedBlockSubscriptionRequest 1..2, Debug, Clone, FromVariant, IntoSchema);

    impl VersionedBlockSubscriptionRequest {
        /// Convert from `&VersionedBlockSubscriberMessage` to V1 reference
        pub const fn as_v1(&self) -> &BlockSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Convert from `&mut VersionedBlockSubscriberMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut BlockSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedBlockSubscriberMessage` to V1
        pub fn into_v1(self) -> BlockSubscriptionRequest {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{
            BlockMessage, BlockSubscriptionRequest, VersionedBlockMessage,
            VersionedBlockSubscriptionRequest,
        };
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
            Hash,
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
