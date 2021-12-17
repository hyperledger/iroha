//! This module contains `Block` structures for each state, it's transitions, implementations and related traits
//! implementations.

#![allow(clippy::module_name_repetitions)]

use std::{collections::BTreeSet, iter, marker::PhantomData};

use dashmap::{mapref::one::Ref as MapRef, DashMap};
use eyre::{Context, Result};
use iroha_crypto::{HashOf, KeyPair, SignatureOf, SignaturesOf};
use iroha_data_model::{
    current_time, events::prelude::*, merkle::MerkleTree, transaction::prelude::*,
};
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

use crate::{
    prelude::*,
    smartcontracts::permissions::{IsInstructionAllowedBoxed, IsQueryAllowedBoxed},
    sumeragi::{
        network_topology::Topology,
        view_change::{Proof, ProofChain as ViewChangeProofs},
    },
    tx::VersionedAcceptedTransaction,
    wsv::WorldTrait,
};

/// The chain of the previous block hash if there is no previous block - the blockchain is empty.
#[derive(Debug, Clone, Copy)]
pub struct EmptyChainHash<T>(PhantomData<T>);

impl<T> Default for EmptyChainHash<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> From<EmptyChainHash<T>> for HashOf<T> {
    fn from(EmptyChainHash(PhantomData): EmptyChainHash<T>) -> Self {
        Self::from_hash(Hash([0_u8; 32]))
    }
}

/// Blockchain.
#[derive(Debug, Default)]
pub struct Chain {
    blocks: DashMap<u64, VersionedCommittedBlock>,
}

impl Chain {
    /// Constructor.
    #[inline]
    pub fn new() -> Self {
        Chain {
            blocks: DashMap::new(),
        }
    }

    /// Push latest block.
    pub fn push(&self, block: VersionedCommittedBlock) {
        let height = block.as_v1().header.height;
        self.blocks.insert(height, block);
    }

    /// Iterator over height and block.
    pub fn iter(&self) -> ChainIterator {
        ChainIterator::new(self)
    }

    /// Latest block reference and its height.
    pub fn latest_block(&self) -> Option<MapRef<u64, VersionedCommittedBlock>> {
        self.blocks.get(&(self.blocks.len() as u64))
    }

    /// Length of the blockchain.
    #[inline]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether blockchain is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Chain iterator
pub struct ChainIterator<'a> {
    chain: &'a Chain,
    pos_front: u64,
    pos_back: u64,
}

impl<'a> ChainIterator<'a> {
    fn new(chain: &'a Chain) -> Self {
        ChainIterator {
            chain,
            pos_front: 1,
            pos_back: chain.len() as u64,
        }
    }

    fn is_exhausted(&self) -> bool {
        self.pos_front > self.pos_back
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = MapRef<'a, u64, VersionedCommittedBlock>;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.is_exhausted() {
            let val = self.chain.blocks.get(&self.pos_front);
            self.pos_front += 1;
            return val;
        }
        None
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.pos_front += n as u64;
        self.next()
    }

    fn last(mut self) -> Option<Self::Item> {
        self.pos_front = self.chain.len() as u64;
        self.chain.blocks.get(&self.pos_front)
    }

    fn count(self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let count = (self.chain.len() as u64 - (self.pos_front - 1)) as usize;
        count
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        #[allow(clippy::cast_possible_truncation)]
        let height = (self.chain.len() as u64 - (self.pos_front - 1)) as usize;
        (height, Some(height))
    }
}

impl<'a> DoubleEndedIterator for ChainIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if !self.is_exhausted() {
            let val = self.chain.blocks.get(&self.pos_back);
            self.pos_back -= 1;
            return val;
        }
        None
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.pos_back -= n as u64;
        self.next_back()
    }
}

declare_versioned_with_scale!(VersionedPendingBlock 1..2, Debug, Clone, iroha_macro::FromVariant);

/// Transaction data is permanently recorded in files called blocks. Blocks are organized into
/// a linear sequence over time (also known as the block chain).
/// Blocks lifecycle starts from "Pending" state which is represented by `PendingBlock` struct.
#[version_with_scale(n = 1, versioned = "VersionedPendingBlock")]
#[derive(Debug, Clone, Decode, Encode)]
pub struct PendingBlock {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
}

impl PendingBlock {
    /// Create a new `PendingBlock` from transactions.
    #[inline]
    pub fn new(transactions: Vec<VersionedAcceptedTransaction>) -> PendingBlock {
        #[allow(clippy::expect_used)]
        let timestamp = current_time().as_millis();
        PendingBlock {
            timestamp,
            transactions,
        }
    }

    /// Chain block with the existing blockchain.
    pub fn chain(
        self,
        height: u64,
        previous_block_hash: HashOf<VersionedCommittedBlock>,
        view_change_proofs: ViewChangeProofs,
        invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    ) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: height + 1,
                previous_block_hash,
                transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                rejected_transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                view_change_proofs,
                invalidated_blocks_hashes,
                genesis_topology: None,
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first_with_genesis_topology(self, genesis_topology: Topology) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: EmptyChainHash::default().into(),
                transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                rejected_transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                view_change_proofs: ViewChangeProofs::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: Some(genesis_topology),
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first(self) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            header: BlockHeader {
                timestamp: self.timestamp,
                height: 1,
                previous_block_hash: EmptyChainHash::default().into(),
                transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                rejected_transactions_hash: HashOf::from_hash(Hash([0_u8; 32])),
                view_change_proofs: ViewChangeProofs::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
        }
    }
}

/// When `PendingBlock` chained with a blockchain it becomes `ChainedBlock`
#[derive(Debug, Clone, Decode, Encode)]
pub struct ChainedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
}

/// Header of the block. The hash should be taken from its byte representation.
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct BlockHeader {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// a number of blocks in the chain up to the block.
    pub height: u64,
    /// Hash of a previous block in the chain.
    /// Is an array of zeros for the first block.
    pub previous_block_hash: HashOf<VersionedCommittedBlock>,
    /// Hash of merkle tree root of the tree of valid transactions' hashes.
    pub transactions_hash: HashOf<MerkleTree<VersionedTransaction>>,
    /// Hash of merkle tree root of the tree of rejected transactions' hashes.
    pub rejected_transactions_hash: HashOf<MerkleTree<VersionedTransaction>>,
    /// Number of view changes after the previous block was committed and before this block was committed.
    pub view_change_proofs: ViewChangeProofs,
    /// Hashes of the blocks that were rejected by consensus.
    pub invalidated_blocks_hashes: Vec<HashOf<VersionedValidBlock>>,
    /// Genesis topology
    pub genesis_topology: Option<Topology>,
}

impl BlockHeader {
    /// Checks if it's a header of a genesis block.
    #[inline]
    pub const fn is_genesis(&self) -> bool {
        self.height == 1
    }
}

use std::error::Error;

impl ChainedBlock {
    /// Validate block transactions against current state of the world.
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> VersionedValidBlock {
        let mut txs = Vec::new();
        let mut rejected = Vec::new();
        for tx in self.transactions {
            match tx.validate(
                wsv,
                is_instruction_allowed,
                is_query_allowed,
                self.header.is_genesis(),
            ) {
                Ok(tx) => txs.push(tx),
                Err(tx) => {
                    iroha_logger::warn!(
                        reason = %tx.as_v1().rejection_reason,
                        caused_by = ?tx.as_v1().rejection_reason.source(),
                        "Transaction validation failed",
                    );
                    rejected.push(tx)
                }
            }
        }
        let mut header = self.header;
        header.transactions_hash = txs
            .iter()
            .map(VersionedValidTransaction::hash)
            .collect::<MerkleTree<_>>()
            .root_hash();
        header.rejected_transactions_hash = rejected
            .iter()
            .map(VersionedRejectedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .root_hash();
        ValidBlock {
            header,
            rejected_transactions: rejected,
            transactions: txs,
            signatures: BTreeSet::default(),
        }
        .into()
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }
}

declare_versioned_with_scale!(VersionedValidBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

impl VersionedValidBlock {
    /// Converts from `&VersionedValidBlock` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &ValidBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedValidBlock` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut ValidBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedValidBlock` to V1
    #[inline]
    pub fn into_v1(self) -> ValidBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Returns header of valid block
    #[inline]
    pub const fn header(&self) -> &BlockHeader {
        &self.as_v1().header
    }

    /// Commit block to the store.
    pub fn commit(self) -> VersionedCommittedBlock {
        self.into_v1().commit().into()
    }

    /// Validate block transactions against current state of the world.
    pub fn revalidate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> VersionedValidBlock {
        self.into_v1()
            .revalidate(wsv, is_instruction_allowed, is_query_allowed)
            .into()
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        self.as_v1().hash().transmute()
    }

    /// Sign this block and get [`VersionedValidBlock`](`Self`).
    /// # Errors
    /// Look at [`ValidBlock`](`ValidBlock`) for more info
    pub fn sign(self, key_pair: KeyPair) -> Result<VersionedValidBlock> {
        self.into_v1().sign(key_pair).map(Into::into)
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(
        &'_ self,
    ) -> impl Iterator<Item = &'_ SignatureOf<VersionedValidBlock>> + '_ {
        self.as_v1()
            .verified_signatures()
            .map(SignatureOf::transmute_ref)
    }

    /// Checks if there are no transactions in this block.
    pub fn is_empty(&self) -> bool {
        self.as_v1().is_empty()
    }

    /// Checks if block has transactions that are already in blockchain.
    pub fn has_committed_transactions<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        self.as_v1().has_committed_transactions(wsv)
    }

    /// # Errors
    /// Asserts specific instruction number of instruction in transaction constraint
    pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
        self.as_v1().check_instruction_len(max_instruction_len)
    }

    /// Returns true if block can be send for discussion
    pub fn validation_check<W: WorldTrait>(
        &self,
        wsv: &WorldStateView<W>,
        latest_block: &HashOf<VersionedCommittedBlock>,
        latest_view_change: &HashOf<Proof>,
        block_height: u64,
        max_instruction_number: u64,
    ) -> bool {
        !self.is_empty()
            && !self.has_committed_transactions(wsv)
            && latest_block == &self.header().previous_block_hash
            && latest_view_change == &self.header().view_change_proofs.latest_hash()
            && block_height + 1 == self.header().height
            && self.check_instruction_len(max_instruction_number).is_ok()
    }
}

/// After full validation `ChainedBlock` can transform into `ValidBlock`.
#[version_with_scale(n = 1, versioned = "VersionedValidBlock")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct ValidBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of transactions.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: BTreeSet<SignatureOf<Self>>,
}

impl ValidBlock {
    /// # Errors
    /// Asserts specific instruction number of instruction constraint
    pub fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
        self.transactions
            .iter()
            .map(|tx| tx.check_instruction_len(max_instruction_len))
            .collect::<Result<Vec<()>>>()
            .map(drop)?;
        self.rejected_transactions
            .iter()
            .map(|tx| tx.check_instruction_len(max_instruction_len))
            .collect::<Result<Vec<()>>>()
            .map(drop)?;
        Ok(())
    }

    /// Commit block to the store.
    //TODO: pass block store and block sender as parameters?
    pub fn commit(self) -> CommittedBlock {
        CommittedBlock {
            header: self.header,
            rejected_transactions: self.rejected_transactions,
            transactions: self.transactions,
            signatures: SignaturesOf::from_iter_unchecked(
                self.signatures.into_iter().map(SignatureOf::transmute),
            ),
        }
    }

    /// Validate block transactions against current state of the world.
    pub fn revalidate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        is_instruction_allowed: &IsInstructionAllowedBoxed<W>,
        is_query_allowed: &IsQueryAllowedBoxed<W>,
    ) -> ValidBlock {
        ValidBlock {
            signatures: self.signatures,
            ..ChainedBlock {
                header: self.header,
                transactions: self
                    .transactions
                    .into_iter()
                    .map(Into::into)
                    .chain(self.rejected_transactions.into_iter().map(Into::into))
                    .collect(),
            }
            .validate(wsv, is_instruction_allowed, is_query_allowed)
            .into_v1()
        }
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Sign this block and get `ValidBlock`.
    ///
    /// # Errors
    /// Fails if generating signature fails
    pub fn sign(mut self, key_pair: KeyPair) -> Result<ValidBlock> {
        self.signatures.insert(
            SignatureOf::from_hash(key_pair, &self.hash()).wrap_err("Failed to sign block")?,
        );
        Ok(self)
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&'_ self) -> impl Iterator<Item = &'_ SignatureOf<ValidBlock>> + '_ {
        let hash = self.hash();
        self.signatures
            .iter()
            .filter(move |sign| sign.verify_hash(&hash).is_ok())
    }

    /// Checks if there are no transactions in this block.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.rejected_transactions.is_empty()
    }

    /// Checks if block has transactions that are already in blockchain.
    pub fn has_committed_transactions<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.is_in_blockchain(wsv))
            || self
                .rejected_transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(wsv))
    }

    /// Creates dummy `ValidBlock`. Used in tests
    ///
    /// # Panics
    /// If generating keys or block signing fails.
    #[cfg(test)]
    #[allow(clippy::restriction)]
    pub fn new_dummy() -> Self {
        ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                height: 1,
                previous_block_hash: EmptyChainHash::default().into(),
                transactions_hash: EmptyChainHash::default().into(),
                rejected_transactions_hash: EmptyChainHash::default().into(),
                view_change_proofs: ViewChangeProofs::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
            rejected_transactions: vec![],
            transactions: vec![],
            signatures: BTreeSet::default(),
        }
        .sign(KeyPair::generate().unwrap())
        .unwrap()
    }
}

impl From<&VersionedValidBlock> for Vec<Event> {
    fn from(block: &VersionedValidBlock) -> Self {
        block.as_v1().into()
    }
}

impl From<&ValidBlock> for Vec<Event> {
    fn from(block: &ValidBlock) -> Self {
        block
            .transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Validating,
                    transaction.hash().into(),
                )
                .into()
            })
            .chain(
                block
                    .rejected_transactions
                    .iter()
                    .cloned()
                    .map(|transaction| {
                        PipelineEvent::new(
                            PipelineEntityType::Transaction,
                            PipelineStatus::Validating,
                            transaction.hash().into(),
                        )
                        .into()
                    }),
            )
            .chain(iter::once(
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    PipelineStatus::Validating,
                    block.hash().into(),
                )
                .into(),
            ))
            .collect()
    }
}

declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

impl VersionedCommittedBlock {
    /// Converts from `&VersionedCommittedBlock` to V1 reference
    pub const fn as_v1(&self) -> &CommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedCommittedBlock` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut CommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedCommittedBlock` to V1
    pub fn into_v1(self) -> CommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Calculate hash of the current block.
    /// `VersionedCommitedBlock` should have the same hash as `VersionedCommitedBlock`.
    pub fn hash(&self) -> HashOf<Self> {
        self.as_v1().hash().transmute()
    }

    /// Returns header of valid block
    pub const fn header(&self) -> &BlockHeader {
        &self.as_v1().header
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&'_ self) -> impl Iterator<Item = &'_ SignatureOf<Self>> + '_ {
        self.as_v1()
            .verified_signatures()
            .map(SignatureOf::transmute_ref)
    }
}

/// When Kura receives `ValidBlock`, the block is stored and
/// then sent to later stage of the pipeline as `CommitedBlock`.
#[version_with_scale(n = 1, versioned = "VersionedCommittedBlock")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct CommittedBlock {
    /// Header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Signatures of peers which approved this block
    pub signatures: SignaturesOf<Self>,
}

impl CommittedBlock {
    /// Calculate hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Signatures that are verified with the `hash` of this block as `payload`.
    pub fn verified_signatures(&'_ self) -> impl Iterator<Item = &'_ SignatureOf<Self>> + '_ {
        self.signatures.verified_by_hash(self.hash())
    }
}

impl From<CommittedBlock> for ValidBlock {
    fn from(
        CommittedBlock {
            header,
            rejected_transactions,
            transactions,
            signatures,
        }: CommittedBlock,
    ) -> Self {
        let signatures = signatures.into_iter().map(SignatureOf::transmute).collect();
        Self {
            header,
            rejected_transactions,
            transactions,
            signatures,
        }
    }
}

impl From<VersionedCommittedBlock> for VersionedValidBlock {
    #[inline]
    fn from(block: VersionedCommittedBlock) -> Self {
        ValidBlock::from(block.into_v1()).into()
    }
}

impl From<&VersionedCommittedBlock> for Vec<Event> {
    #[inline]
    fn from(block: &VersionedCommittedBlock) -> Self {
        block.as_v1().into()
    }
}

impl From<&CommittedBlock> for Vec<Event> {
    fn from(block: &CommittedBlock) -> Self {
        let rejected_tx = block
            .rejected_transactions
            .iter()
            .cloned()
            .map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityType::Transaction,
                    PipelineStatus::Rejected(transaction.as_v1().rejection_reason.clone().into()),
                    transaction.hash().into(),
                )
                .into()
            });
        let tx = block.transactions.iter().cloned().map(|transaction| {
            PipelineEvent::new(
                PipelineEntityType::Transaction,
                PipelineStatus::Committed,
                transaction.hash().into(),
            )
            .into()
        });
        let invalid_blocks = block
            .header
            .invalidated_blocks_hashes
            .iter()
            .copied()
            .map(|hash| {
                PipelineEvent::new(
                    PipelineEntityType::Block,
                    //TODO: store rejection reasons for blocks?
                    PipelineStatus::Rejected(PipelineRejectionReason::Block(
                        BlockRejectionReason::ConsensusBlockRejection,
                    )),
                    hash.into(),
                )
                .into()
            });
        let current_block: iter::Once<Event> = iter::once(
            PipelineEvent::new(
                PipelineEntityType::Block,
                PipelineStatus::Committed,
                block.hash().into(),
            )
            .into(),
        );

        tx.chain(rejected_tx)
            .chain(invalid_blocks)
            .chain(current_block)
            .collect()
    }
}

// TODO: Move to data_model after release
pub mod stream {
    //! Blocks for streaming API.

    use iroha_macro::FromVariant;
    use iroha_schema::prelude::*;
    use iroha_version::prelude::*;
    use parity_scale_codec::{Decode, Encode};

    use crate::block::VersionedCommittedBlock;

    declare_versioned_with_scale!(VersionedBlockPublisherMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

    impl VersionedBlockPublisherMessage {
        /// Converts from `&VersionedBlockPublisherMessage` to V1 reference
        pub const fn as_v1(&self) -> &BlockPublisherMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Converts from `&mut VersionedBlockPublisherMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut BlockPublisherMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedBlockPublisherMessage` to V1
        pub fn into_v1(self) -> BlockPublisherMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    /// Message sent by the stream producer
    #[version_with_scale(n = 1, versioned = "VersionedBlockPublisherMessage")]
    #[derive(Debug, Clone, Decode, Encode, FromVariant, IntoSchema)]
    #[allow(clippy::large_enum_variant)]
    pub enum BlockPublisherMessage {
        /// Answer sent by the peer.
        /// The message means that block stream connection is initialized and will be supplying
        /// events starting with the next message.
        SubscriptionAccepted,
        /// Block sent by the peer.
        Block(VersionedCommittedBlock),
    }

    declare_versioned_with_scale!(VersionedBlockSubscriberMessage 1..2, Debug, Clone, FromVariant, IntoSchema);

    impl VersionedBlockSubscriberMessage {
        /// Converts from `&VersionedBlockSubscriberMessage` to V1 reference
        pub const fn as_v1(&self) -> &BlockSubscriberMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Converts from `&mut VersionedBlockSubscriberMessage` to V1 mutable reference
        pub fn as_mut_v1(&mut self) -> &mut BlockSubscriberMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedBlockSubscriberMessage` to V1
        pub fn into_v1(self) -> BlockSubscriberMessage {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    /// Message sent by the stream consumer
    #[version_with_scale(n = 1, versioned = "VersionedBlockSubscriberMessage")]
    #[derive(Debug, Clone, Copy, Decode, Encode, FromVariant, IntoSchema)]
    pub enum BlockSubscriberMessage {
        /// Request sent to subscribe to blocks stream starting from the given height.
        SubscriptionRequest(u64),
        /// Acknowledgment of receiving block sent from the peer.
        BlockReceived,
    }

    /// Exports common structs and enums from this module.
    pub mod prelude {
        pub use super::{
            BlockPublisherMessage, BlockSubscriberMessage, VersionedBlockPublisherMessage,
            VersionedBlockSubscriberMessage,
        };
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use super::*;

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock::new_dummy();
        let committed_block = valid_block.clone().commit();

        assert_eq!(*valid_block.hash(), *committed_block.hash())
    }

    #[test]
    pub fn chain_iter_returns_blocks_ordered() {
        const BLOCK_COUNT: usize = 10;
        let chain = Chain::new();

        let mut block = ValidBlock::new_dummy().commit();

        for i in 1..=BLOCK_COUNT {
            block.header.height = i as u64;
            chain.push(block.clone().into());
        }

        assert_eq!(
            (BLOCK_COUNT - 5..=BLOCK_COUNT)
                .map(|i| i as u64)
                .collect::<Vec<_>>(),
            chain
                .iter()
                .skip(BLOCK_COUNT - 6)
                .map(|b| *b.key())
                .collect::<Vec<_>>()
        );

        assert_eq!(BLOCK_COUNT - 2, chain.iter().skip(2).count());
        assert_eq!(3, *chain.iter().nth(2).unwrap().key());
    }

    #[test]
    pub fn chain_rev_iter_returns_blocks_ordered() {
        const BLOCK_COUNT: usize = 10;
        let chain = Chain::new();

        let mut block = ValidBlock::new_dummy().commit();

        for i in 1..=BLOCK_COUNT {
            block.header.height = i as u64;
            chain.push(block.clone().into());
        }

        assert_eq!(
            (1..=BLOCK_COUNT - 4)
                .rev()
                .map(|i| i as u64)
                .collect::<Vec<_>>(),
            chain
                .iter()
                .rev()
                .skip(BLOCK_COUNT - 6)
                .map(|b| *b.key())
                .collect::<Vec<_>>()
        );

        assert_eq!(
            (BLOCK_COUNT - 2) as u64,
            *chain.iter().nth_back(2).unwrap().key()
        );
    }
}
