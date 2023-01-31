//! This module contains `Block` structures for each state, it's
//! transitions, implementations and related traits
//! implementations. `Block`s are organised into a linear sequence
//! over time (also known as the block chain).  A Block's life-cycle
//! starts from `PendingBlock`.
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::{error::Error, iter};

use eyre::{bail, eyre, Context, Result};
use iroha_config::sumeragi::{DEFAULT_BLOCK_TIME_MS, DEFAULT_COMMIT_TIME_LIMIT_MS};
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{
    block_value::{BlockHeaderValue, BlockValue},
    current_time,
    events::prelude::*,
    transaction::prelude::*,
};
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;

use crate::{
    prelude::*,
    sumeragi::network_topology::{Role, Topology},
    tx::{TransactionValidator, VersionedAcceptedTransaction},
};

/// Default estimation of consensus duration
#[allow(clippy::integer_division)]
pub const DEFAULT_CONSENSUS_ESTIMATION_MS: u64 =
    DEFAULT_BLOCK_TIME_MS + (DEFAULT_COMMIT_TIME_LIMIT_MS / 2);

declare_versioned_with_scale!(VersionedPendingBlock 1..2, Debug, Clone, iroha_macro::FromVariant);

/// Transaction data is permanently recorded in files called
/// blocks.  This is the first stage of a `Block`s life-cycle.
#[version_with_scale(n = 1, versioned = "VersionedPendingBlock")]
#[derive(Debug, Clone, Decode, Encode)]
pub struct PendingBlock {
    /// Unix time (in milliseconds) of block forming by a peer.
    pub timestamp: u128,
    /// array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
}

// TODO: I strongly believe that we shouldn't be moving parts of a
// PendingBlock, but instead move the PendingBlock wholesale. This
// refactor could improve memory performance.

impl PendingBlock {
    /// Create a new `PendingBlock` from transactions.
    #[inline]
    pub fn new(
        transactions: Vec<VersionedAcceptedTransaction>,
        event_recommendations: Vec<Event>,
    ) -> PendingBlock {
        #[allow(clippy::expect_used)]
        let timestamp = current_time().as_millis();
        // TODO: Need to check if the `transactions` vector is empty. It shouldn't be allowed.
        PendingBlock {
            timestamp,
            transactions,
            event_recommendations,
        }
    }

    /// Chain block with the existing blockchain.
    pub fn chain(
        self,
        height: u64,
        previous_block_hash: Option<HashOf<VersionedCommittedBlock>>,
        view_change_index: u64,
    ) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            event_recommendations: self.event_recommendations,
            header: BlockHeader {
                timestamp: self.timestamp,
                consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: height + 1,
                view_change_index,
                previous_block_hash,
                transactions_hash: None,
                rejected_transactions_hash: None,
                genesis_topology: None,
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first_with_genesis_topology(self, genesis_topology: Topology) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            event_recommendations: self.event_recommendations,
            header: BlockHeader {
                timestamp: self.timestamp,
                consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: 1,
                view_change_index: 0,
                previous_block_hash: None,
                transactions_hash: None,
                rejected_transactions_hash: None,
                genesis_topology: Some(genesis_topology),
            },
        }
    }

    /// Create a new blockchain with current block as a first block.
    pub fn chain_first(self) -> ChainedBlock {
        ChainedBlock {
            transactions: self.transactions,
            event_recommendations: self.event_recommendations,
            header: BlockHeader {
                timestamp: self.timestamp,
                consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: 1,
                view_change_index: 0,
                previous_block_hash: None,
                transactions_hash: None,
                rejected_transactions_hash: None,
                genesis_topology: None,
            },
        }
    }
}

/// When `PendingBlock` chained with a blockchain it becomes `ChainedBlock`
#[derive(Debug, Clone, Decode, Encode)]
pub struct ChainedBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedAcceptedTransaction>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
}

/// Header of the block. The hash should be taken from its byte representation.
#[derive(Debug, Clone, Decode, Encode, IntoSchema, Serialize)]
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

impl ChainedBlock {
    /// Validate block transactions against the current state of the world.
    pub fn validate(
        self,
        transaction_validator: &TransactionValidator,
        wsv: &WorldStateView,
    ) -> ValidBlock {
        let mut txs = Vec::new();
        let mut rejected = Vec::new();

        let wsv = wsv.clone();
        for tx in self.transactions {
            match transaction_validator.validate(tx.into_v1(), self.header.is_genesis(), &wsv) {
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
            .hash();
        header.rejected_transactions_hash = rejected
            .iter()
            .map(VersionedRejectedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash();
        let event_recommendations = self.event_recommendations;
        // TODO: Validate Event recommendations somehow?
        ValidBlock {
            header,
            rejected_transactions: rejected,
            transactions: txs,
            event_recommendations,
        }
    }

    /// Calculate the hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }
}
/// After full validation `ChainedBlock` can transform into `ValidBlock`.
#[derive(Debug, Clone)]
pub struct ValidBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of all transactions in this block.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
}

impl ValidBlock {
    /// Calculate hash of the current block.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Sign this block and get `SignedBlock`.
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign(self, key_pair: KeyPair) -> Result<SignedBlock> {
        let signature = SignatureOf::from_hash(key_pair, &self.hash().transmute())
            .wrap_err(format!("Failed to sign block with hash {}", self.hash()))?;
        let signatures = SignaturesOf::from(signature);
        Ok(SignedBlock {
            header: self.header,
            rejected_transactions: self.rejected_transactions,
            transactions: self.transactions,
            event_recommendations: self.event_recommendations,
            signatures,
        })
    }
}

/// After receiving first signature, `ValidBlock` can transform into `SignedBlock`.
#[derive(Debug, Clone)]
pub struct SignedBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of all rejected transactions in this block.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of all valid transactions in this block.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: SignaturesOf<Self>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
}

impl SignedBlock {
    /// Commit block to the store.
    /// When calling this function, the user is responsible for the validity of the block signatures.
    /// Preference should be given to [`Self::commit`], where signature verification is built in.
    #[inline]
    pub fn commit_unchecked(self) -> CommittedBlock {
        let Self {
            header,
            rejected_transactions,
            transactions,
            event_recommendations,
            signatures,
        } = self;

        CommittedBlock {
            event_recommendations,
            header,
            rejected_transactions,
            transactions,
            signatures: signatures.transmute(),
        }
    }

    /// Verify signatures and commit block to the store.
    ///
    /// # Errors
    ///
    /// Not enough signatures
    #[inline]
    pub fn commit(mut self, topology: &Topology) -> Result<CommittedBlock, (Self, eyre::Report)> {
        let verified_signatures = self.retain_verified_signatures();

        if topology
            .filter_signatures_by_roles(
                &[
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ],
                verified_signatures,
            )
            .len()
            .lt(&topology.min_votes_for_commit())
        {
            return Err((
                self,
                eyre!("The block doesn't have enough valid signatures to be committed."),
            ));
        }

        Ok(self.commit_unchecked())
    }

    /// Calculate the hash of the current block.
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Add additional signatures for `SignedBlock`.
    ///
    /// # Errors
    /// Fails if signature generation fails
    pub fn sign(mut self, key_pair: KeyPair) -> Result<Self> {
        SignatureOf::from_hash(key_pair, &self.hash())
            .wrap_err(format!("Failed to sign block with hash {}", self.hash()))
            .map(|signature| {
                self.signatures.insert(signature);
                self
            })
    }

    /// Add additional signature for `SignedBlock`
    ///
    /// # Errors
    /// Fails if given signature doesn't match block hash
    pub fn add_signature(&mut self, signature: SignatureOf<Self>) -> Result<()> {
        signature
            .verify_hash(&self.hash())
            .map(|_| {
                self.signatures.insert(signature);
            })
            .wrap_err(format!(
                "Provided signature doesn't match block with hash {}",
                self.hash()
            ))
    }

    /// Return signatures that are verified with the `hash` of this block, removing all other
    /// signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.signatures.retain_verified_by_hash(self.hash())
    }

    /// Create dummy `ValidBlock`. Used in tests
    ///
    /// # Panics
    /// If generating keys or block signing fails.
    #[allow(clippy::restriction)]
    #[cfg(test)]
    pub fn new_dummy() -> Self {
        ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                consensus_estimation: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: 1,
                view_change_index: 0,
                previous_block_hash: None,
                transactions_hash: None,
                rejected_transactions_hash: None,
                genesis_topology: None,
            },
            rejected_transactions: Vec::new(),
            transactions: Vec::new(),
            event_recommendations: Vec::new(),
        }
        .sign(KeyPair::generate().unwrap())
        .unwrap()
    }
}

impl From<&SignedBlock> for Vec<Event> {
    fn from(block: &SignedBlock) -> Self {
        block
            .transactions
            .iter()
            .map(|transaction| -> Event {
                PipelineEvent::new(
                    PipelineEntityKind::Transaction,
                    PipelineStatus::Validating,
                    transaction.hash().into(),
                )
                .into()
            })
            .chain(block.rejected_transactions.iter().map(|transaction| {
                PipelineEvent::new(
                    PipelineEntityKind::Transaction,
                    PipelineStatus::Validating,
                    transaction.hash().into(),
                )
                .into()
            }))
            .chain([PipelineEvent::new(
                PipelineEntityKind::Block,
                PipelineStatus::Validating,
                block.hash().into(),
            )
            .into()])
            .collect()
    }
}

declare_versioned_with_scale!(VersionedCandidateBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

impl VersionedCandidateBlock {
    /// Convert from `&VersionedCandidateBlock` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &CandidateBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedCandidateBlock` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut CandidateBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Perform the conversion from `VersionedCandidateBlock` to V1
    #[inline]
    pub fn into_v1(self) -> CandidateBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Return the header of a valid block
    #[inline]
    pub const fn header(&self) -> &BlockHeader {
        &self.as_v1().header
    }

    /// Calculate the hash of the current block.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        self.as_v1().hash().transmute()
    }

    /// Return signatures that are verified with the `hash` of this block, removing all other signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.as_mut_v1()
            .retain_verified_signatures()
            .map(SignatureOf::transmute_ref)
    }

    /// Revalidate a block against the current state of the world.
    ///
    /// # Errors
    /// Forward errors from [`CandidateBlock::revalidate`]
    #[inline]
    pub fn revalidate<const IS_GENESIS: bool>(
        self,
        transaction_validator: &TransactionValidator,
        wsv: &WorldStateView,
        latest_block: Option<HashOf<VersionedCommittedBlock>>,
        block_height: u64,
    ) -> Result<SignedBlock, eyre::Report> {
        self.into_v1().revalidate::<IS_GENESIS>(
            transaction_validator,
            wsv,
            latest_block,
            block_height,
        )
    }
}

/// Revalidate the block that was sent through the network by transforming it back into [`ValidBlock`]
#[version_with_scale(n = 1, versioned = "VersionedCandidateBlock")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct CandidateBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedSignedTransaction>,
    /// Array of all transactions in this block.
    pub transactions: Vec<VersionedSignedTransaction>,
    /// Signatures of peers which approved this block.
    pub signatures: SignaturesOf<Self>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
}

impl CandidateBlock {
    /// Calculate the hash of the current block.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Return signatures that are verified with the `hash` of this block, removing all other signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.signatures.retain_verified_by_hash(self.hash())
    }

    /// Check if there are no transactions in this block.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.rejected_transactions.is_empty()
    }

    /// Check if a block has transactions that are already in the blockchain.
    pub fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
        self.transactions
            .iter()
            .any(|transaction| transaction.is_in_blockchain(wsv))
            || self
                .rejected_transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(wsv))
    }

    /// Revalidate a block against the current state of the world.
    ///
    /// # Errors
    /// - Block is empty
    /// - Block has committed transactions
    /// - There is a mismatch between candidate block height and actual blockchain height
    /// - There is a mismatch between candidate block previous block hash and actual latest block hash
    /// - Block header transaction hashes don't match with computed transaction hashes
    /// - Error during revalidation of individual transactions
    #[allow(clippy::too_many_lines)]
    pub fn revalidate<const IS_GENESIS: bool>(
        self,
        transaction_validator: &TransactionValidator,
        wsv: &WorldStateView,
        latest_block: Option<HashOf<VersionedCommittedBlock>>,
        block_height: u64,
    ) -> Result<SignedBlock, eyre::Report> {
        if self.is_empty() {
            bail!("Block is empty");
        }

        if self.has_committed_transactions(wsv) {
            bail!("Block has committed transactions");
        }

        if latest_block != self.header.previous_block_hash {
            bail!(
                "Mismatch between the actual and expected hashes of the latest block. Expected: {:?}, actual: {:?}",
                latest_block,
                &self.header.previous_block_hash
            );
        }

        if block_height + 1 != self.header.height {
            bail!(
                "Mismatch between the actual and expected heights of the block. Expected: {}, actual: {}",
                block_height + 1,
                self.header.height
            );
        }

        let wsv = wsv.clone();
        let CandidateBlock {
            header,
            rejected_transactions,
            transactions,
            signatures,
            event_recommendations,
        } = self;

        // Validate that header transactions hashes are matched with actual hashes
        transactions
            .iter()
            .map(VersionedSignedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .eq(&header.transactions_hash)
            .then_some(())
            .ok_or_else(|| {
                eyre!("The transaction hash stored in the block header does not match the actual transaction hash.")
            })?;

        rejected_transactions
            .iter()
            .map(VersionedSignedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .eq(&header.rejected_transactions_hash)
            .then_some(())
            .ok_or_else(|| eyre!("The hash of a rejected transaction stored in the block header does not match the actual hash or this transaction."))?;

        // Check that valid transactions are still valid
        let transactions = transactions
            .into_iter()
            .map(VersionedSignedTransaction::into_v1)
            .map(|tx| {
                AcceptedTransaction::from_transaction::<IS_GENESIS>(
                    tx,
                    &transaction_validator.transaction_limits,
                )
            })
            .map(|accepted_tx| {
                accepted_tx.and_then(|tx| {
                    transaction_validator
                        .validate(tx, header.is_genesis(), &wsv)
                        .map_err(|rejected_tx| rejected_tx.into_v1().rejection_reason)
                        .wrap_err("Failed to validate transaction")
                })
            })
            .try_fold(Vec::new(), |mut acc, tx| {
                tx.map(|valid_tx| {
                    acc.push(valid_tx);
                    acc
                })
            })
            .wrap_err("Error during transaction revalidation")?;

        // Check that rejected transactions are indeed rejected
        let rejected_transactions = rejected_transactions
            .into_iter()
            .map(VersionedSignedTransaction::into_v1)
            .map(|tx| {
                AcceptedTransaction::from_transaction::<IS_GENESIS>(
                    tx,
                    &transaction_validator.transaction_limits,
                )
            })
            .map(|accepted_tx| {
                accepted_tx.and_then(|tx| {
                    match transaction_validator.validate(tx, header.is_genesis(), &wsv) {
                        Err(rejected_transaction) => Ok(rejected_transaction),
                        Ok(_) => Err(eyre!("Transactions which supposed to be rejected is valid")),
                    }
                })
            })
            .try_fold(Vec::new(), |mut acc, rejected_tx| {
                rejected_tx.map(|tx| {
                    acc.push(tx);
                    acc
                })
            })
            .wrap_err("Error during transaction revalidation")?;

        Ok(SignedBlock {
            header,
            transactions,
            rejected_transactions,
            event_recommendations,
            signatures: signatures.transmute(),
        })
    }
}

impl From<SignedBlock> for CandidateBlock {
    fn from(valid_block: SignedBlock) -> Self {
        let SignedBlock {
            header,
            rejected_transactions,
            transactions,
            signatures,
            event_recommendations,
        } = valid_block;
        Self {
            header,
            rejected_transactions: rejected_transactions
                .into_iter()
                .map(VersionedSignedTransaction::from)
                .collect(),
            transactions: transactions
                .into_iter()
                .map(VersionedSignedTransaction::from)
                .collect(),
            signatures: signatures.transmute(),
            event_recommendations,
        }
    }
}

impl From<SignedBlock> for VersionedCandidateBlock {
    fn from(valid_block: SignedBlock) -> Self {
        CandidateBlock::from(valid_block).into()
    }
}

declare_versioned_with_scale!(VersionedCommittedBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema, Serialize);

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
    #[inline]
    pub fn signatures(&self) -> impl IntoIterator<Item = &SignatureOf<Self>> {
        self.as_v1()
            .signatures
            .iter()
            .map(SignatureOf::transmute_ref)
    }

    /// Convert block to [`iroha_data_model`] representation for use in e.g. queries.
    pub fn into_value(self) -> BlockValue {
        let current_block_hash = self.hash();

        let CommittedBlock {
            header,
            rejected_transactions,
            transactions,
            event_recommendations,
            ..
        } = self.into_v1();
        let BlockHeader {
            timestamp,
            height,
            previous_block_hash,
            transactions_hash,
            rejected_transactions_hash,
            ..
        } = header;

        let header_value = BlockHeaderValue {
            timestamp,
            height,
            previous_block_hash: previous_block_hash.as_deref().copied(),
            transactions_hash,
            rejected_transactions_hash,
            invalidated_blocks_hashes: Vec::new(),
            current_block_hash: Hash::from(current_block_hash),
        };

        BlockValue {
            header: header_value,
            transactions,
            rejected_transactions,
            event_recommendations,
        }
    }
}

/// The `CommittedBlock` struct represents a block accepted by consensus
#[version_with_scale(n = 1, versioned = "VersionedCommittedBlock")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema, Serialize)]
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

impl CommittedBlock {
    /// Calculate the hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }
}

impl From<CommittedBlock> for CandidateCommittedBlock {
    fn from(
        CommittedBlock {
            header,
            rejected_transactions,
            transactions,
            signatures,
            event_recommendations,
        }: CommittedBlock,
    ) -> Self {
        Self {
            header,
            rejected_transactions,
            transactions,
            event_recommendations,
            signatures: signatures.transmute(),
        }
    }
}

impl From<VersionedCommittedBlock> for VersionedCandidateCommittedBlock {
    #[inline]
    fn from(block: VersionedCommittedBlock) -> Self {
        CandidateCommittedBlock::from(block.into_v1()).into()
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
                    PipelineEntityKind::Transaction,
                    PipelineStatus::Rejected(transaction.as_v1().rejection_reason.clone().into()),
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

declare_versioned_with_scale!(VersionedCandidateCommittedBlock 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema, Serialize);

impl VersionedCandidateCommittedBlock {
    /// Convert from `&VersionedCandidateCommittedBlock` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &CandidateCommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedCandidateCommittedBlock` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut CandidateCommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedCandidateCommittedBlock` to V1
    #[inline]
    pub fn into_v1(self) -> CandidateCommittedBlock {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Calculate the hash of the current block.
    /// `VersionedCandidateCommittedBlock` should have the same hash as `VersionedCommittedBlock`.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        self.as_v1().hash().transmute()
    }

    /// Returns the header of a valid block
    #[inline]
    pub const fn header(&self) -> &BlockHeader {
        &self.as_v1().header
    }

    /// Revalidate transaction hashes, verify signatures and produce [`VersionedCommittedBlock`]
    ///
    /// # Errors
    /// - If transaction hashes don't match the hashes stored in the block header
    /// - If signatures verification fails
    pub fn revalidate(
        self,
        topology: &Topology,
    ) -> Result<VersionedCommittedBlock, (Self, eyre::Report)> {
        self.into_v1()
            .revalidate(topology)
            .map(VersionedCommittedBlock::from)
            .map_err(|err| (err.0.into(), err.1))
    }

    /// Revalidate transaction hashes and produce [`VersionedCommittedBlock`]
    ///
    /// # Errors
    /// - If transaction hashes don't match the hashes stored in the block header
    pub fn revalidate_hashes(self) -> Result<VersionedCommittedBlock, (Self, eyre::Report)> {
        self.into_v1()
            .revalidate_hashes()
            .map(VersionedCommittedBlock::from)
            .map_err(|err| (err.0.into(), err.1))
    }
}

/// Block state used to transfer accepted by consensus block through network to the other peers.
/// This block state is not entirely trusted and require hash revalidation to obtain `CommittedBlock`.
#[version_with_scale(n = 1, versioned = "VersionedCandidateCommittedBlock")]
#[derive(Debug, Clone, Decode, Encode, IntoSchema, Serialize)]
pub struct CandidateCommittedBlock {
    /// Block header
    pub header: BlockHeader,
    /// Array of rejected transactions.
    pub rejected_transactions: Vec<VersionedRejectedTransaction>,
    /// Array of transactions, which successfully passed validation and consensus step.
    pub transactions: Vec<VersionedValidTransaction>,
    /// Event recommendations.
    pub event_recommendations: Vec<Event>,
    /// Signatures of peers which approved this block
    pub signatures: SignaturesOf<Self>,
}

impl CandidateCommittedBlock {
    /// Calculate the hash of the current block.
    /// `CommitedBlock` should have the same hash as `ValidBlock`.
    #[inline]
    pub fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.header).transmute()
    }

    /// Return signatures that are verified with the `hash` of this block, removing all other signatures.
    #[inline]
    pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
        self.signatures.retain_verified_by_hash(self.hash())
    }

    /// Revalidate transaction hashes, verify signatures and produce [`CommittedBlock`]
    ///
    /// # Errors
    /// - If transaction hashes don't match the hashes stored in the block header
    /// - If signatures verification fails
    pub fn revalidate(
        mut self,
        topology: &Topology,
    ) -> Result<CommittedBlock, (Self, eyre::Report)> {
        let verified_signatures = self.retain_verified_signatures();

        if topology
            .filter_signatures_by_roles(
                &[
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ],
                verified_signatures,
            )
            .len()
            .lt(&topology.min_votes_for_commit())
        {
            return Err((
                self,
                eyre!("The block doesn't have enough valid signatures to be committed."),
            ));
        }
        self.revalidate_hashes()
    }

    /// Revalidate transaction hashes and produce [`CommittedBlock`]
    ///
    /// When calling this function, the user is responsible for the validity of the block signatures.
    /// Preference should be given to [`Self::revalidate`], where signature verification is built in.
    ///
    /// # Errors
    /// - If transaction hashes don't match the hashes stored in the block header
    pub fn revalidate_hashes(self) -> Result<CommittedBlock, (Self, eyre::Report)> {
        if self
            .transactions
            .iter()
            .map(VersionedValidTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .ne(&self.header.transactions_hash)
        {
            return Err((self, eyre!("The transaction hash stored in the block header does not match the actual transaction hash.")));
        }

        if self
            .rejected_transactions
            .iter()
            .map(VersionedRejectedTransaction::hash)
            .collect::<MerkleTree<_>>()
            .hash()
            .ne(&self.header.rejected_transactions_hash)
        {
            return Err((self, eyre!("The hash of a rejected transaction stored in the block header does not match the actual hash or this transaction.")));
        }

        Ok(CommittedBlock {
            header: self.header,
            rejected_transactions: self.rejected_transactions,
            transactions: self.transactions,
            event_recommendations: self.event_recommendations,
            signatures: self.signatures.transmute(),
        })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr;

    use iroha_data_model::prelude::*;

    use super::*;
    use crate::kura::Kura;

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = SignedBlock::new_dummy();
        let committed_block = valid_block.clone().commit_unchecked();

        assert_eq!(*valid_block.hash(), *committed_block.hash())
    }

    #[test]
    fn should_reject_due_to_repetition() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account = Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build();
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition: Instruction =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id)).into();

        // Making two transactions that have the same instruction
        let transaction_limits = TransactionLimits {
            max_instruction_number: 100,
            max_wasm_size_bytes: 0,
        };
        let transaction_validator = TransactionValidator::new(transaction_limits);
        let tx = Transaction::new(alice_id, [create_asset_definition].into(), 4000)
            .sign(alice_keys)
            .expect("Valid");
        let tx =
            crate::VersionedAcceptedTransaction::from_transaction::<false>(tx, &transaction_limits)
                .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let pending_block = PendingBlock::new(transactions, Vec::new());
        let chained_block = pending_block.chain_first();
        let valid_block = chained_block.validate(&transaction_validator, &wsv);

        // The first transaction should be confirmed
        assert_eq!(valid_block.transactions.len(), 1);

        // The second transaction should be rejected
        assert_eq!(valid_block.rejected_transactions.len(), 1);
    }
}
