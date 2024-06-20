//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::{fmt::Display, time::Duration};

use derive_more::Display;
use iroha_crypto::{HashOf, MerkleTree, PrivateKey, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{events::prelude::*, peer, peer::PeerId, transaction::prelude::*};

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
        #[getset(get_copy = "pub")]
        pub prev_block_hash: Option<HashOf<SignedBlock>>,
        /// Hash of merkle tree root of transactions' hashes.
        #[getset(get_copy = "pub")]
        pub transactions_hash: HashOf<MerkleTree<SignedTransaction>>,
        /// Creation timestamp (unix time in milliseconds).
        #[getset(skip)]
        pub timestamp_ms: u64,
        /// Value of view change index. Used to resolve soft forks.
        #[getset(skip)]
        pub view_change_index: u32,
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
        pub commit_topology: Vec<peer::PeerId>,
        /// array of transactions, which successfully passed validation and consensus step.
        pub transactions: Vec<CommittedTransaction>,
        /// Event recommendations.
        pub event_recommendations: Vec<EventBox>,
    }

    /// Signature of a block
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
    pub struct BlockSignature(
        /// Index of the peer in the topology
        pub u64,
        /// Payload
        pub SignatureOf<BlockPayload>,
    );

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
        pub(super) signatures: Vec<BlockSignature>,
        /// Block payload
        pub(super) payload: BlockPayload,
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
    pub const fn timestamp(&self) -> Duration {
        Duration::from_millis(self.timestamp_ms)
    }

    /// Consensus estimation
    pub const fn consensus_estimation(&self) -> Duration {
        Duration::from_millis(self.consensus_estimation_ms)
    }
}

impl BlockPayload {
    /// Create new signed block, using `key_pair` to sign `payload`
    #[cfg(feature = "transparent_api")]
    pub fn sign(self, private_key: &iroha_crypto::PrivateKey) -> SignedBlock {
        let signatures = vec![BlockSignature(0, SignatureOf::new(private_key, &self))];

        SignedBlockV1 {
            signatures,
            payload: self,
        }
        .into()
    }
}

impl SignedBlockV1 {
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<SignedBlock> {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::HashOf::new(self).into())
    }
}

impl SignedBlock {
    /// Block payload. Used for tests
    #[cfg(feature = "transparent_api")]
    pub fn payload(&self) -> &BlockPayload {
        let SignedBlock::V1(block) = self;
        &block.payload
    }

    /// Block header
    #[inline]
    pub fn header(&self) -> &BlockHeader {
        let SignedBlock::V1(block) = self;
        &block.payload.header
    }

    /// Block transactions
    #[inline]
    pub fn transactions(&self) -> impl ExactSizeIterator<Item = &CommittedTransaction> {
        let SignedBlock::V1(block) = self;
        block.payload.transactions.iter()
    }

    /// Topology of the network at the time of block commit.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub fn commit_topology(&self) -> impl ExactSizeIterator<Item = &peer::PeerId> {
        let SignedBlock::V1(block) = self;
        block.payload.commit_topology.iter()
    }

    /// Signatures of peers which approved this block.
    #[inline]
    pub fn signatures(
        &self,
    ) -> impl ExactSizeIterator<Item = &BlockSignature> + DoubleEndedIterator {
        let SignedBlock::V1(block) = self;
        block.signatures.iter()
    }

    /// Calculate block hash
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }

    /// Add signature to the block
    ///
    /// # Errors
    ///
    /// if signature is invalid
    #[cfg(feature = "transparent_api")]
    pub fn add_signature(
        &mut self,
        signature: BlockSignature,
        public_key: &iroha_crypto::PublicKey,
    ) -> Result<(), iroha_crypto::Error> {
        if self.signatures().any(|s| signature.0 == s.0) {
            return Err(iroha_crypto::Error::Signing(
                "Duplicate signature".to_owned(),
            ));
        }

        signature.1.verify(public_key, self.payload())?;

        let SignedBlock::V1(block) = self;
        block.signatures.push(signature);

        Ok(())
    }

    /// Replace signatures without verification
    #[cfg(feature = "transparent_api")]
    pub fn replace_signatures_unchecked(
        &mut self,
        signatures: Vec<BlockSignature>,
    ) -> Vec<BlockSignature> {
        let SignedBlock::V1(block) = self;
        std::mem::replace(&mut block.signatures, signatures)
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
    #[cfg(all(feature = "std", feature = "transparent_api"))]
    pub fn sign(&mut self, private_key: &iroha_crypto::PrivateKey, signatory: usize) {
        let SignedBlock::V1(block) = self;

        block.signatures.push(BlockSignature(
            signatory as u64,
            SignatureOf::new(private_key, &block.payload),
        ));
    }

    /// Creates genesis block signed with genesis private key (and not signed by any peer)
    pub fn genesis(
        genesis_transactions: Vec<SignedTransaction>,
        genesis_private_key: &PrivateKey,
        topology: Vec<PeerId>,
    ) -> SignedBlock {
        let transactions_hash = genesis_transactions
            .iter()
            .map(SignedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .expect("Tree is not empty");
        let first_transaction = &genesis_transactions[0];
        let timestamp_ms = u64::try_from(first_transaction.creation_time().as_millis())
            .expect("Must fit since Duration was created from u64 in creation_time()");
        let header = BlockHeader {
            height: 1,
            prev_block_hash: None,
            transactions_hash,
            timestamp_ms,
            view_change_index: 0,
            consensus_estimation_ms: 0,
        };
        let transactions = genesis_transactions
            .into_iter()
            .map(|transaction| CommittedTransaction {
                value: transaction,
                error: None,
            })
            .collect();
        let payload = BlockPayload {
            header,
            commit_topology: topology,
            transactions,
            event_recommendations: vec![],
        };

        let signature = BlockSignature(0, SignatureOf::new(genesis_private_key, &payload));
        SignedBlockV1 {
            signatures: vec![signature],
            payload,
        }
        .into()
    }
}

mod candidate {
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;
    #[cfg(feature = "std")]
    use std::collections::BTreeSet;

    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct SignedBlockCandidate {
        signatures: Vec<BlockSignature>,
        payload: BlockPayload,
    }

    impl SignedBlockCandidate {
        fn validate(self) -> Result<SignedBlockV1, &'static str> {
            self.validate_signatures()?;
            self.validate_header()?;

            Ok(SignedBlockV1 {
                signatures: self.signatures,
                payload: self.payload,
            })
        }

        fn validate_signatures(&self) -> Result<(), &'static str> {
            if self.signatures.is_empty() && self.payload.header.height != 1 {
                return Err("Block missing signatures");
            }

            self.signatures
                .iter()
                .map(|signature| signature.0)
                .try_fold(BTreeSet::new(), |mut acc, elem| {
                    if !acc.insert(elem) {
                        return Err("Duplicate signature in block");
                    }

                    Ok(acc)
                })?;

            Ok(())
        }

        fn validate_header(&self) -> Result<(), &'static str> {
            let actual_txs_hash = self.payload.header.transactions_hash;

            let expected_txs_hash = self
                .payload
                .transactions
                .iter()
                .map(|value| value.as_ref().hash())
                .collect::<MerkleTree<_>>()
                .hash()
                .ok_or("Block is empty")?;

            if expected_txs_hash != actual_txs_hash {
                return Err("Transactions' hash incorrect. Expected: {expected_txs_hash:?}, actual: {actual_txs_hash:?}");
            }
            // TODO: Validate Event recommendations somehow?

            Ok(())
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
