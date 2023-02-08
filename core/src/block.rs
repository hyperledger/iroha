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

use std::error::Error;

use eyre::{bail, eyre, Context, Result};
use iroha_config::sumeragi::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{block::*, events::prelude::*, transaction::prelude::*};
use iroha_version::{declare_versioned_with_scale, version_with_scale};
use parity_scale_codec::{Decode, Encode};

pub use self::{
    candidate::{CandidateBlock, VersionedCandidateBlock},
    candidate_committed::{CandidateCommittedBlock, VersionedCandidateCommittedBlock},
    chained::ChainedBlock,
    pending::{PendingBlock, VersionedPendingBlock},
    signed::SignedBlock,
    valid::ValidBlock,
};
use crate::{
    prelude::*,
    sumeragi::network_topology::{Role, Topology},
    tx::TransactionValidator,
};

mod pending {
    use super::*;

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

    impl PendingBlock {
        /// Create a new `PendingBlock` from transactions.
        #[inline]
        pub fn new(
            transactions: Vec<VersionedAcceptedTransaction>,
            event_recommendations: Vec<Event>,
        ) -> Self {
            #[allow(clippy::expect_used)]
            let timestamp = crate::current_time().as_millis();
            // TODO: Need to check if the `transactions` vector is empty. It shouldn't be allowed.
            Self {
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
            committed_with_topology: Topology,
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
                    committed_with_topology: committed_with_topology.sorted_peers,
                },
            }
        }

        /// Create a new blockchain with current block as a first block.
        pub fn chain_first_with_topology(self, genesis_topology: Topology) -> ChainedBlock {
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
                    committed_with_topology: genesis_topology.sorted_peers,
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
                    committed_with_topology: Vec::new(),
                },
            }
        }
    }
}

mod chained {
    use super::*;

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

    impl ChainedBlock {
        /// Calculate the hash of the current block.

        #[inline]
        pub fn hash(&self) -> HashOf<Self> {
            HashOf::new(&self.header).transmute()
        }

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
    }
}

mod valid {
    use super::*;

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
}

/// Signed block related structures and implementations.
mod signed {
    use super::*;

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
        /// Calculate the hash of the current block.

        pub fn hash(&self) -> HashOf<Self> {
            HashOf::new(&self.header).transmute()
        }

        /// Return signatures that are verified with the `hash` of this block, removing all other
        /// signatures.

        #[inline]
        pub fn retain_verified_signatures(&mut self) -> impl Iterator<Item = &SignatureOf<Self>> {
            self.signatures.retain_verified_by_hash(self.hash())
        }

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
        pub fn commit(
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

            Ok(self.commit_unchecked())
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
                    committed_with_topology: Vec::new(),
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
                    PipelineEvent {
                        entity_kind: PipelineEntityKind::Transaction,
                        status: PipelineStatus::Validating,
                        hash: transaction.hash().into(),
                    }
                    .into()
                })
                .chain(block.rejected_transactions.iter().map(|transaction| {
                    PipelineEvent {
                        entity_kind: PipelineEntityKind::Transaction,
                        status: PipelineStatus::Validating,
                        hash: transaction.hash().into(),
                    }
                    .into()
                }))
                .chain([PipelineEvent {
                    entity_kind: PipelineEntityKind::Block,
                    status: PipelineStatus::Validating,
                    hash: block.hash().into(),
                }
                .into()])
                .collect()
        }
    }
}

mod candidate {
    use super::*;

    declare_versioned_with_scale!(VersionedCandidateBlock 1..2, Debug, Clone, iroha_macro::FromVariant);

    /// Revalidate the block that was sent through the network by transforming it back into [`ValidBlock`]
    #[version_with_scale(n = 1, versioned = "VersionedCandidateBlock")]
    #[derive(Debug, Clone, Decode, Encode)]
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
                    AcceptedTransaction::accept::<IS_GENESIS>(
                        tx,
                        &transaction_validator.transaction_limits,
                    )
                    .wrap_err("Failed to accept transaction")
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
                    AcceptedTransaction::accept::<IS_GENESIS>(
                        tx,
                        &transaction_validator.transaction_limits,
                    )
                    .wrap_err("Failed to accept transaction")
                })
                .map(|accepted_tx| {
                    accepted_tx.and_then(|tx| {
                        match transaction_validator.validate(tx, header.is_genesis(), &wsv) {
                            Err(rejected_transaction) => Ok(rejected_transaction),
                            Ok(_) => {
                                Err(eyre!("Transactions which supposed to be rejected is valid"))
                            }
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

        /// Check if a block has transactions that are already in the blockchain.
        fn has_committed_transactions(&self, wsv: &WorldStateView) -> bool {
            self.transactions
                .iter()
                .any(|transaction| transaction.is_in_blockchain(wsv))
                || self
                    .rejected_transactions
                    .iter()
                    .any(|transaction| transaction.is_in_blockchain(wsv))
        }
    }

    impl From<SignedBlock> for VersionedCandidateBlock {
        fn from(valid_block: SignedBlock) -> Self {
            CandidateBlock::from(valid_block).into()
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
}

mod candidate_committed {
    use super::*;

    declare_versioned_with_scale!(VersionedCandidateCommittedBlock 1..2, Debug, Clone, iroha_macro::FromVariant);

    /// Block state used to transfer accepted by consensus block through network to the other peers.
    /// This block state is not entirely trusted and require hash revalidation to obtain `CommittedBlock`.
    #[version_with_scale(n = 1, versioned = "VersionedCandidateCommittedBlock")]
    #[derive(Debug, Clone, Decode, Encode)]
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
        let tx = Transaction::new(alice_id, [create_asset_definition], 4000)
            .sign(alice_keys)
            .expect("Valid");
        let tx: VersionedAcceptedTransaction =
            AcceptedTransaction::accept::<false>(tx, &transaction_limits)
                .map(Into::into)
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
