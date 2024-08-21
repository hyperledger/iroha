//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::{fmt::Display, time::Duration};

use derive_more::Display;
use iroha_crypto::{HashOf, MerkleTree, PrivateKey, Signature, SignatureOf};
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
use nonzero_ext::nonzero;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::transaction::prelude::*;

#[model]
mod model {
    use core::num::NonZeroU64;

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
        pub height: NonZeroU64,
        /// Hash of the previous block in the chain.
        #[getset(get_copy = "pub")]
        pub prev_block_hash: Option<HashOf<SignedBlock>>,
        /// Hash of merkle tree root of transactions' hashes.
        #[getset(get_copy = "pub")]
        pub transactions_hash: HashOf<MerkleTree<SignedTransaction>>,
        /// Creation timestamp (unix time in milliseconds).
        #[getset(skip)]
        pub creation_time_ms: u64,
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
        /// array of transactions, which successfully passed validation and consensus step.
        pub transactions: Vec<CommittedTransaction>,
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
    #[display(fmt = "{}", "self.hash()")]
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
        self.height.get() == 1
    }

    /// Creation timestamp
    pub const fn creation_time(&self) -> Duration {
        Duration::from_millis(self.creation_time_ms)
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
    fn hash(&self) -> iroha_crypto::HashOf<SignedBlock> {
        iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::HashOf::new(&self.payload.header).into(),
        )
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
        let SignedBlock::V1(block) = self;
        block.hash()
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
    ) -> SignedBlock {
        let transactions_hash = genesis_transactions
            .iter()
            .map(SignedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .expect("Tree is not empty");
        let first_transaction = &genesis_transactions[0];
        let creation_time_ms = u64::try_from(first_transaction.creation_time().as_millis())
            .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
        let header = BlockHeader {
            height: nonzero!(1_u64),
            prev_block_hash: None,
            transactions_hash,
            creation_time_ms,
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
            transactions,
        };

        let signature = BlockSignature(0, SignatureOf::new(genesis_private_key, &payload));
        SignedBlockV1 {
            signatures: vec![signature],
            payload,
        }
        .into()
    }
}

impl BlockSignature {
    /// Peer topology index
    pub fn index(&self) -> u64 {
        self.0
    }

    /// Signature itself
    pub fn payload(&self) -> &Signature {
        &self.1
    }
}

mod candidate {
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;
    #[cfg(feature = "std")]
    use std::collections::BTreeSet;

    use parity_scale_codec::Input;

    use super::*;
    use crate::isi::InstructionBox;

    #[derive(Decode, Deserialize)]
    struct SignedBlockCandidate {
        signatures: Vec<BlockSignature>,
        payload: BlockPayload,
    }

    impl SignedBlockCandidate {
        fn validate(self) -> Result<SignedBlockV1, &'static str> {
            self.validate_signatures()?;
            self.validate_header()?;
            if self.payload.header.height.get() == 1 {
                self.validate_genesis()?;
            }

            Ok(SignedBlockV1 {
                signatures: self.signatures,
                payload: self.payload,
            })
        }

        fn validate_genesis(&self) -> Result<(), &'static str> {
            let transactions = self.payload.transactions.as_slice();
            for transaction in transactions {
                if transaction.error.is_some() {
                    return Err("Genesis transaction must not contain errors");
                }
                let Executable::Instructions(_) = transaction.value.instructions() else {
                    return Err("Genesis transaction must contain instructions");
                };
            }

            let Some(transaction_executor) = transactions.first() else {
                return Err("Genesis block must contain at least one transaction");
            };
            let Executable::Instructions(instructions_executor) =
                transaction_executor.value.instructions()
            else {
                return Err("Genesis transaction must contain instructions");
            };
            let [InstructionBox::Upgrade(_)] = instructions_executor.as_slice() else {
                return Err(
                    "First transaction must contain single `Upgrade` instruction to set executor",
                );
            };

            if transactions.len() > 4 {
                return Err(
                    "Genesis block must have 1 to 4 transactions (executor upgrade, initial topology, parameters, other isi)",
                );
            }

            Ok(())
        }

        fn validate_signatures(&self) -> Result<(), &'static str> {
            if self.signatures.is_empty() && self.payload.header.height.get() != 1 {
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
