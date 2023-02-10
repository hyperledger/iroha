//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{cmp::Ordering, fmt::Display, iter};

use derive_more::Display;
use iroha_crypto::{HashOf, MerkleTree, SignatureOf, SignaturesOf};
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::{
    committed::{CommittedBlock, VersionedCommittedBlock},
    header::BlockHeader,
};
use crate::{events::prelude::*, peer, transaction::prelude::*};

mod header {
    use super::*;

    /// Header of the block. The hash should be taken from its byte representation.
    #[derive(
        Debug,
        Display,
        Clone,
        Decode,
        Encode,
        IntoSchema,
        Serialize,
        Deserialize,
        PartialEq,
        Eq,
        Hash,
    )]
    #[cfg_attr(
        feature = "std",
        display(fmt = "Block №{height} (hash: {});", "HashOf::new(&self)")
    )]
    // NOTE: hash is unavailable without `std` feature
    #[cfg_attr(not(feature = "std"), display(fmt = "Block №{height}"))]
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
        pub committed_with_topology: Vec<peer::Id>,
    }

    impl BlockHeader {
        /// Checks if it's a header of a genesis block.
        #[inline]
        pub const fn is_genesis(&self) -> bool {
            self.height == 1
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
    use super::*;

    declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema, Serialize, Deserialize, PartialEq, Eq, Hash);

    /// The `CommittedBlock` struct represents a block accepted by consensus
    #[version_with_scale(n = 1, versioned = "VersionedCommittedBlock")]
    #[derive(
        Debug,
        Clone,
        Decode,
        Encode,
        IntoSchema,
        Serialize,
        Deserialize,
        PartialEq,
        Eq,
        Display,
        Hash,
    )]
    #[display(fmt = "({header})")]
    pub struct CommittedBlock {
        /// Block header
        pub header: BlockHeader,
        /// Array of rejected transactions.
        pub rejected_transactions: Vec<VersionedRejectedTransaction>,
        /// array of transactions, which successfully passed validation and consensus step.
        pub transactions: Vec<VersionedValidTransaction>,
        /// Event recommendations.
        pub event_recommendations: Vec<Event>,
        /// Signatures of peers which approved this block
        pub signatures: SignaturesOf<Self>,
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

        /// Calculate the hash of the current block.
        /// `VersionedCommitedBlock` should have the same hash as `VersionedCommitedBlock`.
        #[cfg(feature = "std")]
        #[inline]
        pub fn hash(&self) -> HashOf<Self> {
            self.as_v1().hash().transmute()
        }

        /// Returns the header of a valid block
        #[inline]
        pub const fn header(&self) -> &BlockHeader {
            &self.as_v1().header
        }

        /// Return signatures that are verified with the `hash` of this block
        #[cfg(feature = "std")]
        #[inline]
        pub fn signatures(&self) -> impl IntoIterator<Item = &SignatureOf<Self>> {
            self.as_v1()
                .signatures
                .iter()
                .map(SignatureOf::transmute_ref)
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
        /// Calculate the hash of the current block.
        /// `CommitedBlock` should have the same hash as `ValidBlock`.
        #[cfg(feature = "std")]
        #[inline]
        pub fn hash(&self) -> HashOf<Self> {
            HashOf::new(&self.header).transmute()
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
                    PipelineEvent::new(
                        PipelineEntityKind::Transaction,
                        PipelineStatus::Rejected(
                            transaction.as_v1().rejection_reason.clone().into(),
                        ),
                        transaction.hash().into(),
                    )
                    .into()
                });
            let tx = block.transactions.iter().cloned().map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityKind::Transaction,
                    PipelineStatus::Committed,
                    transaction.hash().into(),
                )
                .into()
            });
            let current_block: iter::Once<Event> = iter::once(
                PipelineEvent::new(
                    PipelineEntityKind::Block,
                    PipelineStatus::Committed,
                    block.hash().into(),
                )
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

pub mod stream {
    //! Blocks for streaming API.

    use iroha_macro::FromVariant;
    use iroha_schema::prelude::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

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

    /// Message sent by the stream producer
    /// Block sent by the peer.
    #[version_with_scale(n = 1, versioned = "VersionedBlockMessage")]
    #[derive(Debug, Clone, Decode, Encode, IntoSchema)]
    pub struct BlockMessage(pub VersionedCommittedBlock);

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

    /// Message sent by the stream consumer.
    /// Request sent to subscribe to blocks stream starting from the given height.
    #[version_with_scale(n = 1, versioned = "VersionedBlockSubscriptionRequest")]
    #[derive(Debug, Clone, Copy, Decode, Encode, IntoSchema)]
    pub struct BlockSubscriptionRequest(pub u64);

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{
            BlockMessage, BlockSubscriptionRequest, VersionedBlockMessage,
            VersionedBlockSubscriptionRequest,
        };
    }
}
