//! Pipeline events.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::num::NonZeroU64;

use iroha_crypto::HashOf;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{block::BlockHeader, transaction::SignedTransaction};

#[model]
mod model {
    use getset::{CopyGetters, Getters};

    use super::*;

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type(opaque)]
    pub enum PipelineEventBox {
        Transaction(TransactionEvent),
        Block(BlockEvent),
    }

    #[derive(
        Debug,
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
    #[ffi_type]
    #[getset(get = "pub")]
    pub struct BlockEvent {
        pub header: BlockHeader,
        pub status: BlockStatus,
    }

    #[derive(
        Debug,
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
    #[ffi_type]
    pub struct TransactionEvent {
        #[getset(get = "pub")]
        pub hash: HashOf<SignedTransaction>,
        #[getset(get_copy = "pub")]
        pub block_height: Option<NonZeroU64>,
        #[getset(get = "pub")]
        pub status: TransactionStatus,
    }

    /// Report of block's status in the pipeline
    #[derive(
        Debug,
        Clone,
        Copy,
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
    #[ffi_type(opaque)]
    pub enum BlockStatus {
        /// Block created (only emitted by the leader node)
        Created,
        /// Block was approved to participate in consensus
        Approved,
        /// Block was rejected by consensus
        Rejected(crate::block::error::BlockRejectionReason),
        /// Block has passed consensus successfully
        Committed,
        /// Changes have been reflected in the WSV
        Applied,
    }

    /// Report of transaction's status in the pipeline
    #[derive(
        Debug,
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
    #[ffi_type(opaque)]
    pub enum TransactionStatus {
        /// Transaction was received and enqueued
        Queued,
        /// Transaction was dropped(not stored in a block)
        Expired,
        /// Transaction was stored in the block as valid
        Approved,
        /// Transaction was stored in the block as invalid
        Rejected(Box<crate::transaction::error::TransactionRejectionReason>),
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub enum PipelineEventFilterBox {
        Transaction(TransactionEventFilter),
        Block(BlockEventFilter),
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        CopyGetters,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub struct BlockEventFilter {
        #[getset(get_copy = "pub")]
        pub height: Option<NonZeroU64>,
        #[getset(get = "pub")]
        pub status: Option<BlockStatus>,
    }

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    pub struct TransactionEventFilter {
        #[getset(get = "pub")]
        pub hash: Option<HashOf<SignedTransaction>>,
        pub block_height: Option<Option<NonZeroU64>>,
        #[getset(get = "pub")]
        pub status: Option<TransactionStatus>,
    }
}

impl BlockEventFilter {
    /// Construct new instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            height: None,
            status: None,
        }
    }

    /// Match only block with the given height
    #[must_use]
    pub fn for_height(mut self, height: NonZeroU64) -> Self {
        self.height = Some(height);
        self
    }

    /// Match only block with the given status
    #[must_use]
    pub fn for_status(mut self, status: BlockStatus) -> Self {
        self.status = Some(status);
        self
    }
}

impl TransactionEventFilter {
    /// Construct new instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hash: None,
            block_height: None,
            status: None,
        }
    }

    /// Match only transactions with the given block height
    #[must_use]
    pub fn for_block_height(mut self, block_height: Option<NonZeroU64>) -> Self {
        self.block_height = Some(block_height);
        self
    }

    /// Match only transactions with the given hash
    #[must_use]
    pub fn for_hash(mut self, hash: HashOf<SignedTransaction>) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Match only transactions with the given status
    #[must_use]
    pub fn for_status(mut self, status: TransactionStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Block height
    // TODO: Derive with getset
    pub fn block_height(&self) -> Option<Option<NonZeroU64>> {
        self.block_height
    }
}

#[cfg(feature = "transparent_api")]
impl TransactionEventFilter {
    fn field_matches<T: Eq>(filter: Option<&T>, event: &T) -> bool {
        filter.map_or(true, |field| field == event)
    }
}

#[cfg(feature = "transparent_api")]
impl BlockEventFilter {
    fn field_matches<T: Eq>(filter: Option<&T>, event: &T) -> bool {
        filter.map_or(true, |field| field == event)
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for PipelineEventFilterBox {
    type Event = PipelineEventBox;

    /// Check if `self` accepts the `event`.
    #[inline]
    fn matches(&self, event: &PipelineEventBox) -> bool {
        match (self, event) {
            (Self::Block(block_filter), PipelineEventBox::Block(block_event)) => [
                BlockEventFilter::field_matches(
                    block_filter.height.as_ref(),
                    &block_event.header.height,
                ),
                BlockEventFilter::field_matches(block_filter.status.as_ref(), &block_event.status),
            ]
            .into_iter()
            .all(core::convert::identity),
            (
                Self::Transaction(transaction_filter),
                PipelineEventBox::Transaction(transaction_event),
            ) => [
                TransactionEventFilter::field_matches(
                    transaction_filter.hash.as_ref(),
                    &transaction_event.hash,
                ),
                TransactionEventFilter::field_matches(
                    transaction_filter.block_height.as_ref(),
                    &transaction_event.block_height,
                ),
                TransactionEventFilter::field_matches(
                    transaction_filter.status.as_ref(),
                    &transaction_event.status,
                ),
            ]
            .into_iter()
            .all(core::convert::identity),
            _ => false,
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        BlockEvent, BlockStatus, PipelineEventBox, PipelineEventFilterBox, TransactionEvent,
        TransactionStatus,
    };
}

#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{string::ToString as _, vec, vec::Vec};

    use iroha_crypto::Hash;
    use nonzero_ext::nonzero;

    use super::{super::EventFilter, *};
    use crate::{transaction::error::TransactionRejectionReason::*, ValidationFail};

    impl BlockHeader {
        fn dummy(height: NonZeroU64) -> Self {
            Self {
                height,
                prev_block_hash: None,
                transactions_hash: HashOf::from_untyped_unchecked(Hash::prehashed(
                    [1_u8; Hash::LENGTH],
                )),
                creation_time_ms: 0,
                view_change_index: 0,
            }
        }
    }

    #[test]
    fn events_are_correctly_filtered() {
        let events = vec![
            TransactionEvent {
                hash: HashOf::from_untyped_unchecked(Hash::prehashed([0_u8; Hash::LENGTH])),
                block_height: None,
                status: TransactionStatus::Queued,
            }
            .into(),
            TransactionEvent {
                hash: HashOf::from_untyped_unchecked(Hash::prehashed([0_u8; Hash::LENGTH])),
                block_height: Some(nonzero!(3_u64)),
                status: TransactionStatus::Rejected(Box::new(Validation(
                    ValidationFail::TooComplex,
                ))),
            }
            .into(),
            TransactionEvent {
                hash: HashOf::from_untyped_unchecked(Hash::prehashed([2_u8; Hash::LENGTH])),
                block_height: None,
                status: TransactionStatus::Approved,
            }
            .into(),
            BlockEvent {
                header: BlockHeader::dummy(nonzero!(7_u64)),
                status: BlockStatus::Committed,
            }
            .into(),
        ];

        assert_eq!(
            events
                .iter()
                .filter(|&event| {
                    let filter: PipelineEventFilterBox = TransactionEventFilter::default()
                        .for_hash(HashOf::from_untyped_unchecked(Hash::prehashed(
                            [0_u8; Hash::LENGTH],
                        )))
                        .into();

                    filter.matches(event)
                })
                .cloned()
                .collect::<Vec<PipelineEventBox>>(),
            vec![
                TransactionEvent {
                    hash: HashOf::from_untyped_unchecked(Hash::prehashed([0_u8; Hash::LENGTH])),
                    block_height: None,
                    status: TransactionStatus::Queued,
                }
                .into(),
                TransactionEvent {
                    hash: HashOf::from_untyped_unchecked(Hash::prehashed([0_u8; Hash::LENGTH])),
                    block_height: Some(nonzero!(3_u64)),
                    status: TransactionStatus::Rejected(Box::new(Validation(
                        ValidationFail::TooComplex,
                    ))),
                }
                .into(),
            ],
        );

        assert_eq!(
            events
                .iter()
                .filter(|&event| {
                    let filter: PipelineEventFilterBox = BlockEventFilter::default().into();
                    filter.matches(event)
                })
                .cloned()
                .collect::<Vec<_>>(),
            vec![BlockEvent {
                status: BlockStatus::Committed,
                header: BlockHeader::dummy(nonzero!(7_u64)),
            }
            .into()],
        );
        assert_eq!(
            events
                .iter()
                .filter(|&event| {
                    let filter: PipelineEventFilterBox = TransactionEventFilter::default()
                        .for_hash(HashOf::from_untyped_unchecked(Hash::prehashed(
                            [2_u8; Hash::LENGTH],
                        )))
                        .into();

                    filter.matches(event)
                })
                .cloned()
                .collect::<Vec<PipelineEventBox>>(),
            vec![TransactionEvent {
                hash: HashOf::from_untyped_unchecked(Hash::prehashed([2_u8; Hash::LENGTH])),
                block_height: None,
                status: TransactionStatus::Approved,
            }
            .into()],
        );
    }
}
