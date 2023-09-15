//! This module contains [`Block`] structures for each state, it's
//! transitions, implementations and related trait implementations.
//! [`Block`]s are organised into a linear sequence over time (also known as the block chain).
#![allow(
    clippy::module_name_repetitions,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects
)]

use std::error::Error as _;

use iroha_config::sumeragi::default::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{
    block::*,
    events::prelude::*,
    peer::PeerId,
    transaction::{error::TransactionRejectionReason, prelude::*},
};
use iroha_genesis::GenesisTransaction;
use thiserror::Error;

pub use self::{chained::Chained, commit::CommittedBlock, valid::ValidBlock};
use crate::{
    prelude::*,
    sumeragi::network_topology::{SignatureVerificationError, Topology},
    tx::AcceptTransactionFail,
};

/// Error during transaction validation
#[derive(Debug, displaydoc::Display, Error)]
pub enum TransactionValidationError {
    /// Failed to accept transaction
    Accept(#[from] AcceptTransactionFail),
    /// A transaction is marked as accepted, but is actually invalid
    NotValid(#[from] TransactionRejectionReason),
    /// A transaction is marked as rejected, but is actually valid
    RejectedIsValid,
}

/// Errors occurred on block validation
#[derive(Debug, displaydoc::Display, Error)]
pub enum BlockValidationError {
    /// Block has committed transactions
    HasCommittedTransactions,
    /// Mismatch between the actual and expected hashes of the latest block. Expected: {expected:?}, actual: {actual:?}
    LatestBlockHashMismatch {
        /// Expected value
        expected: Option<HashOf<VersionedSignedBlock>>,
        /// Actual value
        actual: Option<HashOf<VersionedSignedBlock>>,
    },
    /// Mismatch between the actual and expected height of the latest block. Expected: {expected}, actual: {actual}
    LatestBlockHeightMismatch {
        /// Expected value
        expected: u64,
        /// Actual value
        actual: u64,
    },
    /// The transaction hash stored in the block header does not match the actual transaction hash
    TransactionHashMismatch,
    /// Error during transaction validation
    TransactionValidation(#[from] TransactionValidationError),
    /// Mismatch between the actual and expected topology. Expected: {expected:?}, actual: {actual:?}
    TopologyMismatch {
        /// Expected value
        expected: Vec<PeerId>,
        /// Actual value
        actual: Vec<PeerId>,
    },
    /// Error during block signatures check
    SignatureVerification(#[from] SignatureVerificationError),
    /// Received view change index is too large
    ViewChangeIndexTooLarge,
}

/// Builder for blocks
#[derive(Debug, Clone)]
pub struct BlockBuilder<B>(B);

mod pending {
    use iroha_data_model::transaction::TransactionValue;

    use super::*;

    /// First stage in the life-cycle of a [`Block`].
    /// In the beginning the block is assumed to be verified and to contain only accepted transactions.
    /// Additionally the block must retain events emitted during the execution of on-chain logic during
    /// the previous round, which might then be processed by the trigger system.
    #[derive(Debug, Clone)]
    pub struct Pending {
        /// Unix timestamp
        timestamp_ms: u64,
        /// Collection of transactions which have been accepted.
        /// Transaction will be validated when block is chained.
        transactions: Vec<AcceptedTransaction>,
        /// The topology at the time of block commit.
        commit_topology: Topology,
        /// Event recommendations for use in triggers and off-chain work
        event_recommendations: Vec<Event>,
    }

    impl BlockBuilder<Pending> {
        /// Create [`Self`]
        ///
        /// # Panics
        ///
        /// if the given list of transaction is empty
        #[inline]
        pub fn new(
            transactions: Vec<AcceptedTransaction>,
            commit_topology: Topology,
            event_recommendations: Vec<Event>,
        ) -> Self {
            assert!(!transactions.is_empty(), "Empty block created");

            Self(Pending {
                timestamp_ms: iroha_data_model::current_time()
                    .as_millis()
                    .try_into()
                    .expect("Time should fit into u64"),
                transactions,
                commit_topology,
                event_recommendations,
            })
        }

        fn make_header(
            timestamp_ms: u64,
            previous_height: u64,
            previous_block_hash: Option<HashOf<VersionedSignedBlock>>,
            view_change_index: u64,
            transactions: &[TransactionValue],
            commit_topology: Topology,
        ) -> BlockHeader {
            BlockHeader {
                timestamp_ms,
                consensus_estimation_ms: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: previous_height + 1,
                view_change_index,
                previous_block_hash,
                transactions_hash: transactions
                    .iter()
                    .map(TransactionValue::hash)
                    .collect::<MerkleTree<_>>()
                    .hash(),
                commit_topology: commit_topology.ordered_peers,
            }
        }

        fn categorize_transactions(
            transactions: Vec<AcceptedTransaction>,
            wsv: &mut WorldStateView,
        ) -> Vec<TransactionValue> {
            transactions
                .into_iter()
                .map(|tx| match wsv.transaction_validator().validate(tx, wsv) {
                    Ok(tx) => TransactionValue {
                        value: tx,
                        error: None,
                    },
                    Err((tx, error)) => {
                        iroha_logger::warn!(
                            reason = %error,
                            caused_by = ?error.source(),
                            "Transaction validation failed",
                        );
                        TransactionValue {
                            value: tx,
                            error: Some(error),
                        }
                    }
                })
                .collect()
        }

        /// Chain the block with existing blockchain.
        pub fn chain(
            self,
            view_change_index: u64,
            wsv: &mut WorldStateView,
        ) -> BlockBuilder<Chained> {
            let transactions = Self::categorize_transactions(self.0.transactions, wsv);

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    self.0.timestamp_ms,
                    wsv.height(),
                    wsv.latest_block_hash(),
                    view_change_index,
                    &transactions,
                    self.0.commit_topology,
                ),
                transactions,
                event_recommendations: self.0.event_recommendations,
            }))
        }

        /// Create a new blockchain with current block as the first block.
        pub fn chain_first(self, wsv: &mut WorldStateView) -> BlockBuilder<Chained> {
            let transactions = Self::categorize_transactions(self.0.transactions, wsv);

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    self.0.timestamp_ms,
                    0,
                    None,
                    0,
                    &transactions,
                    self.0.commit_topology,
                ),
                transactions,
                event_recommendations: self.0.event_recommendations,
            }))
        }
    }
}

mod chained {
    use super::*;

    /// When a [`Pending`] block is chained with the blockchain it becomes [`Chained`] block.
    #[derive(Debug, Clone)]
    pub struct Chained(pub(super) BlockPayload);

    impl BlockBuilder<Chained> {
        /// Sign this block and get [`SignedBlock`].
        ///
        /// # Errors
        ///
        /// Fails if signature generation fails
        pub fn sign(self, key_pair: KeyPair) -> Result<ValidBlock, iroha_crypto::error::Error> {
            let signature = SignatureOf::new(key_pair, &self.0 .0)?;

            Ok(ValidBlock(
                SignedBlock {
                    payload: self.0 .0,
                    signatures: SignaturesOf::from(signature),
                }
                .into(),
            ))
        }
    }
}

mod valid {
    use super::*;
    use crate::sumeragi::network_topology::Role;

    /// Block that was validated and accepted
    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct ValidBlock(pub(super) VersionedSignedBlock);

    impl ValidBlock {
        pub(crate) fn payload(&self) -> &BlockPayload {
            self.0.payload()
        }
        pub(crate) fn signatures(&self) -> &SignaturesOf<BlockPayload> {
            self.0.signatures()
        }

        /// Validate a block against the current state of the world.
        ///
        /// # Errors
        ///
        /// - Block is empty
        /// - There is a mismatch between candidate block height and actual blockchain height
        /// - There is a mismatch between candidate block previous block hash and actual latest block hash
        /// - Block has committed transactions
        /// - Block header transaction hashes don't match with computed transaction hashes
        /// - Error during validation of individual transactions
        /// - Topology field is incorrect
        pub fn validate(
            block: VersionedSignedBlock,
            topology: &Topology,
            wsv: &mut WorldStateView,
        ) -> Result<ValidBlock, (VersionedSignedBlock, BlockValidationError)> {
            let actual_commit_topology = &block.payload().header.commit_topology;
            let expected_commit_topology = &topology.ordered_peers;

            if actual_commit_topology != expected_commit_topology {
                let actual_commit_topology = actual_commit_topology.clone();

                return Err((
                    block,
                    BlockValidationError::TopologyMismatch {
                        expected: expected_commit_topology.clone(),
                        actual: actual_commit_topology,
                    },
                ));
            }

            if !block.payload().header.is_genesis()
                && topology
                    .filter_signatures_by_roles(&[Role::Leader], block.signatures())
                    .is_empty()
            {
                return Err((block, SignatureVerificationError::LeaderMissing.into()));
            }

            let expected_block_height = wsv.height() + 1;
            let actual_height = block.payload().header.height;

            if expected_block_height != actual_height {
                return Err((
                    block,
                    BlockValidationError::LatestBlockHeightMismatch {
                        expected: expected_block_height,
                        actual: actual_height,
                    },
                ));
            }

            let expected_previous_block_hash = wsv.latest_block_hash();
            let actual_block_hash = block.payload().header.previous_block_hash;

            if expected_previous_block_hash != actual_block_hash {
                return Err((
                    block,
                    BlockValidationError::LatestBlockHashMismatch {
                        expected: expected_previous_block_hash,
                        actual: actual_block_hash,
                    },
                ));
            }

            if block
                .payload()
                .transactions
                .iter()
                .any(|tx| wsv.has_transaction(tx.hash()))
            {
                return Err((block, BlockValidationError::HasCommittedTransactions));
            }

            if let Err(error) = Self::validate_transactions(&block, wsv) {
                return Err((block, error.into()));
            }

            let VersionedSignedBlock::V1(block) = block;
            Ok(ValidBlock(
                SignedBlock {
                    payload: block.payload,
                    signatures: block.signatures,
                }
                .into(),
            ))
        }

        fn validate_transactions(
            block: &VersionedSignedBlock,
            wsv: &mut WorldStateView,
        ) -> Result<(), TransactionValidationError> {
            let is_genesis = block.payload().header.is_genesis();

            block.payload()
                .transactions
                .iter()
                // TODO: Unnecessary clone?
                .cloned()
                .try_for_each(|TransactionValue{value, error}| {
                    let transaction_validator = wsv.transaction_validator();
                    let limits = &transaction_validator.transaction_limits;

                    if error.is_none() {
                        let tx = if is_genesis {
                            AcceptedTransaction::accept_genesis(GenesisTransaction(value))
                        } else {
                            AcceptedTransaction::accept(value, limits)?
                        };

                        transaction_validator.validate(tx, wsv).map_err(|(_tx, error)| {
                            TransactionValidationError::NotValid(error)
                        })?;
                    } else {
                        let tx = if is_genesis {
                            AcceptedTransaction::accept_genesis(GenesisTransaction(value))
                        } else {
                            AcceptedTransaction::accept(value, limits)?
                        };

                        match transaction_validator.validate(tx, wsv) {
                            Err(rejected_transaction) => Ok(rejected_transaction),
                            Ok(_) => Err(TransactionValidationError::RejectedIsValid),
                        }?;
                    }

                    Ok(())
                })
        }

        /// The manipulation of the topology relies upon all peers seeing the same signature set.
        /// Therefore we must clear the signatures and accept what the proxy tail giveth.
        ///
        /// # Errors
        ///
        /// - Not enough signatures
        /// - Not signed by proxy tail
        pub(crate) fn commit_with_signatures(
            mut self,
            topology: &Topology,
            signatures: SignaturesOf<BlockPayload>,
        ) -> Result<CommittedBlock, (Self, BlockValidationError)> {
            if topology
                .filter_signatures_by_roles(&[Role::Leader], &signatures)
                .is_empty()
            {
                return Err((self, SignatureVerificationError::LeaderMissing.into()));
            }

            if !self.signatures().is_subset(&signatures) {
                return Err((self, SignatureVerificationError::SignatureMissing.into()));
            }

            if !self.0.replace_signatures(signatures) {
                return Err((self, SignatureVerificationError::UnknownSignature.into()));
            }

            self.commit(topology)
        }

        /// Verify signatures and commit block to the store.
        ///
        /// # Errors
        ///
        /// - Not enough signatures
        /// - Not signed by proxy tail
        pub fn commit(
            self,
            topology: &Topology,
        ) -> Result<CommittedBlock, (Self, BlockValidationError)> {
            // TODO: Should the peer that serves genesis have a fixed role of ProxyTail in topology?
            if !self.payload().header.is_genesis()
                && topology.is_consensus_required().is_some()
                && topology
                    .filter_signatures_by_roles(&[Role::ProxyTail], self.signatures())
                    .is_empty()
            {
                return Err((self, SignatureVerificationError::ProxyTailMissing.into()));
            }

            #[allow(clippy::collapsible_else_if)]
            if self.payload().header.is_genesis() {
                // At genesis round we blindly take on the network topology from the genesis block.
            } else {
                let roles = [
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ];

                let votes_count = topology
                    .filter_signatures_by_roles(&roles, self.signatures())
                    .len();
                if votes_count.lt(&topology.min_votes_for_commit()) {
                    return Err((
                        self,
                        SignatureVerificationError::NotEnoughSignatures {
                            votes_count,
                            min_votes_for_commit: topology.min_votes_for_commit(),
                        }
                        .into(),
                    ));
                }
            }

            Ok(CommittedBlock(self.0))
        }

        /// Add additional signatures for [`Self`].
        ///
        /// # Errors
        ///
        /// If signature generation fails
        pub fn sign(self, key_pair: KeyPair) -> Result<Self, iroha_crypto::error::Error> {
            self.0.sign(key_pair).map(ValidBlock)
        }

        /// Add additional signature for [`Self`]
        ///
        /// # Errors
        ///
        /// If given signature doesn't match block hash
        pub fn add_signature(
            &mut self,
            signature: SignatureOf<BlockPayload>,
        ) -> Result<(), iroha_crypto::error::Error> {
            self.0.add_signature(signature)
        }

        #[cfg(test)]
        pub(crate) fn new_dummy() -> Self {
            BlockBuilder(Chained(BlockPayload {
                header: BlockHeader {
                    timestamp_ms: 0,
                    consensus_estimation_ms: DEFAULT_CONSENSUS_ESTIMATION_MS,
                    height: 1,
                    view_change_index: 0,
                    previous_block_hash: None,
                    transactions_hash: None,
                    commit_topology: Vec::new(),
                },
                transactions: Vec::new(),
                event_recommendations: Vec::new(),
            }))
            .sign(KeyPair::generate().unwrap())
            .unwrap()
        }
    }

    impl From<ValidBlock> for VersionedSignedBlock {
        fn from(source: ValidBlock) -> Self {
            source.0
        }
    }
}

mod commit {
    use super::*;

    /// Represents a block accepted by consensus.
    /// Every [`Self`] will have a different height.
    #[derive(Debug, Clone)]
    // TODO: Make it pub(super) at most
    pub struct CommittedBlock(pub(crate) VersionedSignedBlock);

    impl CommittedBlock {
        /// Calculate block hash
        pub fn hash(&self) -> HashOf<VersionedSignedBlock> {
            self.0.hash()
        }
        pub(crate) fn payload(&self) -> &BlockPayload {
            self.0.payload()
        }
        pub(crate) fn signatures(&self) -> &SignaturesOf<BlockPayload> {
            self.0.signatures()
        }
    }

    impl CommittedBlock {
        pub(crate) fn produce_events(&self) -> Vec<PipelineEvent> {
            let tx = self.payload().transactions.iter().map(|tx| {
                let status = tx.error.as_ref().map_or_else(
                    || PipelineStatus::Committed,
                    |error| PipelineStatus::Rejected(error.clone().into()),
                );

                PipelineEvent {
                    entity_kind: PipelineEntityKind::Transaction,
                    status,
                    hash: tx.payload().hash().into(),
                }
            });
            let current_block = core::iter::once(PipelineEvent {
                entity_kind: PipelineEntityKind::Block,
                status: PipelineStatus::Committed,
                hash: self.hash().into(),
            });

            tx.chain(current_block).collect()
        }
    }

    impl From<CommittedBlock> for ValidBlock {
        fn from(source: CommittedBlock) -> Self {
            ValidBlock(source.0)
        }
    }

    impl From<CommittedBlock> for VersionedSignedBlock {
        fn from(source: CommittedBlock) -> Self {
            source.0
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use iroha_data_model::prelude::*;

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock::new_dummy();
        let topology = Topology::new(Vec::new());
        let committed_block = valid_block.clone().commit(&topology).unwrap();

        assert_eq!(
            valid_block.payload().hash(),
            committed_block.payload().hash()
        )
    }

    #[test]
    fn should_reject_due_to_repetition() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id));

        // Making two transactions that have the same instruction
        let transaction_limits = &wsv.transaction_validator().transaction_limits;
        let tx = TransactionBuilder::new(alice_id)
            .with_instructions([create_asset_definition])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx = AcceptedTransaction::accept(tx, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let topology = Topology::new(Vec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain_first(&mut wsv)
            .sign(alice_keys)
            .expect("Valid");

        // The first transaction should be confirmed
        assert!(valid_block.payload().transactions[0].error.is_none());

        // The second transaction should be rejected
        assert!(valid_block.payload().transactions[1].error.is_some());
    }

    #[test]
    fn tx_order_same_in_validation_and_revalidation() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));

        // Making two transactions that have the same instruction
        let transaction_limits = &wsv.transaction_validator().transaction_limits;
        let tx = TransactionBuilder::new(alice_id.clone())
            .with_instructions([create_asset_definition])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx = AcceptedTransaction::accept(tx, transaction_limits).expect("Valid");

        let quantity: u32 = 200;
        let fail_quantity: u32 = 20;

        let fail_mint = MintBox::new(
            fail_quantity.to_value(),
            IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id.clone())),
        );

        let succeed_mint = MintBox::new(
            quantity.to_value(),
            IdBox::AssetId(AssetId::new(asset_definition_id, alice_id.clone())),
        );

        let tx0 = TransactionBuilder::new(alice_id.clone())
            .with_instructions([fail_mint])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx0 = AcceptedTransaction::accept(tx0, transaction_limits).expect("Valid");

        let tx2 = TransactionBuilder::new(alice_id)
            .with_instructions([succeed_mint])
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx2 = AcceptedTransaction::accept(tx2, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx0, tx, tx2];
        let topology = Topology::new(Vec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain_first(&mut wsv)
            .sign(alice_keys)
            .expect("Valid");

        // The first transaction should fail
        assert!(valid_block.payload().transactions[0].error.is_some());

        // The third transaction should succeed
        assert!(valid_block.payload().transactions[2].error.is_none());
    }

    #[test]
    fn failed_transactions_revert() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account =
            Account::new(alice_id.clone(), [alice_keys.public_key().clone()]).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(
            domain.add_account(account).is_none(),
            "`alice@wonderland` already exist in the blockchain"
        );
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world, kura);
        let transaction_limits = &wsv.transaction_validator().transaction_limits;

        let domain_id = DomainId::from_str("domain").expect("Valid");
        let create_domain = RegisterBox::new(Domain::new(domain_id));
        let asset_definition_id = AssetDefinitionId::from_str("coin#domain").expect("Valid");
        let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id));
        let instructions_fail: [InstructionBox; 2] = [
            create_domain.clone().into(),
            FailBox::new("Always fail").into(),
        ];
        let instructions_accept: [InstructionBox; 2] = [create_domain.into(), create_asset.into()];
        let tx_fail = TransactionBuilder::new(alice_id.clone())
            .with_instructions(instructions_fail)
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx_fail = AcceptedTransaction::accept(tx_fail, transaction_limits).expect("Valid");
        let tx_accept = TransactionBuilder::new(alice_id)
            .with_instructions(instructions_accept)
            .sign(alice_keys.clone())
            .expect("Valid");
        let tx_accept = AcceptedTransaction::accept(tx_accept, transaction_limits).expect("Valid");

        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let topology = Topology::new(Vec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain_first(&mut wsv)
            .sign(alice_keys)
            .expect("Valid");

        // The first transaction should be rejected
        assert!(
            valid_block.payload().transactions[0].error.is_some(),
            "The first transaction should be rejected, as it contains `FailBox`."
        );

        // The second transaction should be accepted
        assert!(
            valid_block.payload().transactions[1].error.is_none(),
            "The second transaction should be accepted."
        );
    }
}
