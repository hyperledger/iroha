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

use eyre::{eyre, Context, Result};
use iroha_config::sumeragi::DEFAULT_CONSENSUS_ESTIMATION_MS;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{block::*, events::prelude::*, transaction::prelude::*};
use iroha_genesis::AcceptedTransaction;

pub use self::{chained::Chained, commit::CommittedBlock, pending::Pending, valid::ValidBlock};
use crate::{
    prelude::*,
    sumeragi::network_topology::{Role, Topology},
    tx::TransactionValidator,
};

/// Buidler for blocks
#[derive(Debug, Clone)]
pub struct BlockBuilder<B>(B);

mod pending {
    use super::*;

    /// First stage in the life-cycle of a [`Block`].
    /// In the beginning the block is assumed to be verified and to contain only accepted transactions.
    /// Additionally the block must retain events emitted during the execution of on-chain logic during
    /// the previous round, which might then be processed by the trigger system.
    #[derive(Debug, Clone)]
    pub struct Pending {
        /// Unix timestamp
        timestamp_ms: u128,
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
                timestamp_ms: iroha_data_model::current_time().as_millis(),
                transactions,
                commit_topology,
                event_recommendations,
            })
        }

        fn make_header(
            timestamp_ms: u128,
            height: u64,
            previous_block_hash: Option<HashOf<BlockPayload>>,
            view_change_index: u64,
            transactions: &[VersionedSignedTransaction],
            rejected_transactions: &[(VersionedSignedTransaction, TransactionRejectionReason)],
            commit_topology: Topology,
        ) -> BlockHeader {
            BlockHeader {
                timestamp_ms,
                consensus_estimation_ms: DEFAULT_CONSENSUS_ESTIMATION_MS,
                height: height + 1,
                view_change_index,
                previous_block_hash,
                transactions_hash: transactions
                    .iter()
                    .map(VersionedSignedTransaction::hash)
                    .collect::<MerkleTree<_>>()
                    .hash(),
                rejected_transactions_hash: rejected_transactions
                    .iter()
                    .map(|(tx, _error)| tx.hash())
                    .collect::<MerkleTree<_>>()
                    .hash(),
                commit_topology: commit_topology.ordered_peers,
            }
        }

        // NOTE: Transactions are applied to WSV clone
        #[allow(clippy::needless_pass_by_value)]
        fn categorize_transactions<const IS_GENESIS: bool>(
            transactions: Vec<AcceptedTransaction>,
            transaction_validator: &TransactionValidator,
            wsv: WorldStateView,
        ) -> (
            Vec<VersionedSignedTransaction>,
            Vec<(VersionedSignedTransaction, TransactionRejectionReason)>,
        ) {
            let (mut valid, mut rejected) = (Vec::new(), Vec::new());

            for tx in transactions {
                match transaction_validator.validate::<IS_GENESIS>(tx, &wsv) {
                    Ok(tx) => valid.push(tx),
                    Err(tx) => {
                        iroha_logger::warn!(
                            reason = %tx.1,
                            caused_by = ?tx.1.source(),
                            "Transaction validation failed",
                        );
                        rejected.push(tx)
                    }
                }
            }

            (valid, rejected)
        }

        /// Chain the block with existing blockchain.
        pub fn chain(
            self,
            height: u64,
            previous_block_hash: Option<HashOf<BlockPayload>>,
            view_change_index: u64,
            transaction_validator: &TransactionValidator,
            wsv: WorldStateView,
        ) -> BlockBuilder<Chained> {
            let (transactions, rejected_transactions) = Self::categorize_transactions::<false>(
                self.0.transactions,
                transaction_validator,
                wsv,
            );

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    self.0.timestamp_ms,
                    height,
                    previous_block_hash,
                    view_change_index,
                    &transactions,
                    &rejected_transactions,
                    self.0.commit_topology,
                ),
                transactions: transactions.into_iter().map(Into::into).collect(),
                rejected_transactions: rejected_transactions.into_iter().map(Into::into).collect(),
                event_recommendations: self.0.event_recommendations,
            }))
        }

        /// Create a new blockchain with current block as the first block.
        pub fn chain_first(
            self,
            transaction_validator: &TransactionValidator,
            wsv: WorldStateView,
        ) -> BlockBuilder<Chained> {
            let (transactions, rejected_transactions) = Self::categorize_transactions::<true>(
                self.0.transactions,
                transaction_validator,
                wsv,
            );

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    self.0.timestamp_ms,
                    0,
                    None,
                    0,
                    &transactions,
                    &rejected_transactions,
                    self.0.commit_topology,
                ),
                transactions: transactions.into_iter().map(Into::into).collect(),
                rejected_transactions: rejected_transactions.into_iter().map(Into::into).collect(),
                event_recommendations: self.0.event_recommendations,
            }))
        }
    }
}

mod chained {
    use super::*;

    /// When a [`Pending`] block is chained with the blockchain it becomes [`Chained`] block.
    #[derive(Debug, Clone)]
    pub struct Chained(pub(crate) BlockPayload);

    impl BlockBuilder<Chained> {
        /// Hash of the block being built
        pub fn hash(&self) -> HashOf<BlockPayload> {
            HashOf::new(&self.0 .0.header).transmute()
        }

        /// Sign this block and get [`SignedBlock`].
        ///
        /// # Errors
        ///
        /// Fails if signature generation fails
        pub fn sign(self, key_pair: KeyPair) -> Result<ValidBlock> {
            let hash = self.hash();

            let signature = SignatureOf::from_hash(key_pair, &hash)
                .wrap_err(format!("Failed to sign block with hash {}", hash))?;
            let signatures = SignaturesOf::from(signature);
            Ok(ValidBlock(
                SignedBlock {
                    payload: self.0 .0,
                    signatures,
                }
                .into(),
            ))
        }
    }
}

mod valid {
    use eyre::bail;

    use super::*;

    /// Block that was validated and accepted
    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct ValidBlock(pub(crate) VersionedSignedBlock);

    impl Block for ValidBlock {
        fn payload(&self) -> &BlockPayload {
            self.0.payload()
        }
        fn signatures(&self) -> &SignaturesOf<BlockPayload> {
            self.0.signatures()
        }
    }

    impl ValidBlock {
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
            expected_block_height: u64,
            expected_previous_block_hash: Option<HashOf<BlockPayload>>,
            topology: &Topology,
            transaction_validator: &TransactionValidator,
            wsv: WorldStateView,
        ) -> Result<ValidBlock, (VersionedSignedBlock, eyre::Report)> {
            let actual_commit_topology = &block.header().commit_topology;
            let expected_commit_topology = &topology.ordered_peers;

            if actual_commit_topology != expected_commit_topology {
                let msg = eyre!("Block topology incorrect. Expected: {expected_commit_topology:#?}, actual: {actual_commit_topology:#?}");
                return Err((block, msg));
            }

            if !block.header().is_genesis()
                && topology
                    .filter_signatures_by_roles(&[Role::Leader], block.signatures())
                    .is_empty()
            {
                return Err((block, eyre!("Block is not signed by the leader")));
            }

            Self::validate_without_validating_topology(
                block,
                expected_block_height,
                expected_previous_block_hash,
                transaction_validator,
                wsv,
            )
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
        #[deprecated(
            since = "2.0.0-pre-rc.13",
            note = "This method exists only because some tests are failing, but it shouldn't"
        )]
        // TODO: a committed block should always contains Leader and Proxy tail signatures
        // TODO: Is it ok to not validate topology filed of the header in block_sync?
        // NOTE: Transactions are applied to WSV clone
        #[allow(clippy::needless_pass_by_value)]
        pub fn validate_without_validating_topology(
            block: VersionedSignedBlock,
            expected_block_height: u64,
            expected_previous_block_hash: Option<HashOf<BlockPayload>>,
            transaction_validator: &TransactionValidator,
            wsv: WorldStateView,
        ) -> Result<ValidBlock, (VersionedSignedBlock, eyre::Report)> {
            let actual_height = block.header().height;
            if expected_block_height != actual_height {
                return Err((block, eyre!("Mismatch between the actual and expected heights of the block. Expected: {expected_block_height}, actual: {actual_height}")));
            }
            let actual_block_hash = block.header().previous_block_hash;
            if expected_previous_block_hash != actual_block_hash {
                return Err((block, eyre!("Mismatch between the actual and expected hashes of the latest block. Expected: {expected_previous_block_hash:?}, actual: {actual_block_hash:?}")));
            }

            if let Err(error) = Self::validate_transactions(&block, transaction_validator, &wsv) {
                return Err((block, error));
            }
            if let Err(error) =
                Self::validate_rejected_transactions(&block, transaction_validator, &wsv)
            {
                return Err((block, error));
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
            transaction_validator: &TransactionValidator,
            wsv: &WorldStateView,
        ) -> Result<(), eyre::Report> {
            let committed_txns: Vec<_> = block
                .payload()
                .transactions
                .iter()
                .filter(|transaction| transaction.is_in_blockchain(wsv))
                .collect();
            if !committed_txns.is_empty() {
                bail!("Found committed transactions: {committed_txns:?}");
            }

            // Check that valid transactions are still valid
            block.payload()
                        .transactions
                        .iter()
                        // TODO: Unnecessary clone?
                        .cloned()
                        .map(|tx| {
                            let limits = &transaction_validator.transaction_limits;

                            let tx_result = if block.header().is_genesis() {
                                AcceptedTransaction::accept::<true>(tx, limits)
                            } else {
                                AcceptedTransaction::accept::<false>(tx, limits)
                            };

                            match tx_result {
                                Ok(tx) => Ok(tx),
                                Err((_tx, err)) => Err(err).wrap_err("Failed to accept transaction")
                            }
                        })
                        .map(|accepted_tx| {
                            accepted_tx.and_then(|tx| {
                                let tx_result = if block.header().is_genesis() {
                                    transaction_validator.validate::<true>(tx, wsv)
                                } else {
                                    transaction_validator.validate::<false>(tx, wsv)
                                };

                                tx_result
                                    .map_err(|tx| tx.1)
                                    .wrap_err("Failed to validate transaction")
                            })
                        })
                        .try_fold(Vec::new(), |mut acc, tx| {
                            tx.map(|valid_tx| {
                                acc.push(valid_tx);
                                acc
                            })
                        })
                        .wrap_err("Error during transaction validation")?;

            Ok(())
        }

        fn validate_rejected_transactions(
            block: &VersionedSignedBlock,
            transaction_validator: &TransactionValidator,
            wsv: &WorldStateView,
        ) -> Result<(), eyre::Report> {
            let committed_rejected_txns: Vec<_> = block
                .payload()
                .rejected_transactions
                .iter()
                .filter(|(transaction, _)| transaction.is_in_blockchain(wsv))
                .collect();

            if !committed_rejected_txns.is_empty() {
                bail!("Found committed rejected transactions: {committed_rejected_txns:?}");
            }

            // Check that rejected transactions are indeed rejected
            block.payload()
                        .rejected_transactions
                        .iter()
                        // TODO: Unnecessary clone?
                        .cloned()
                        .map(|tx| {
                            let limits = &transaction_validator.transaction_limits;

                            let tx_result = if block.header().is_genesis() {
                                AcceptedTransaction::accept::<true>(tx.0, limits)
                            } else {
                                AcceptedTransaction::accept::<false>(tx.0, limits)
                            };

                            match tx_result {
                                Ok(tx) => Ok(tx),
                                Err((_tx, err)) => Err(err).wrap_err("Failed to accept transaction")
                            }
                        })
                        .map(|accepted_tx| {
                            accepted_tx.and_then(|tx| {
                                let tx_result = if block.header().is_genesis() {
                                    transaction_validator.validate::<true>(tx, wsv)
                                } else {
                                    transaction_validator.validate::<false>(tx, wsv)
                                };

                                match tx_result {
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
                        .wrap_err("Error during transaction validation")?;

            Ok(())
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
        ) -> Result<(CommittedBlock, Vec<Event>), (Self, eyre::Report)> {
            // TODO: Should the peer that serves genesis have a fixed role of ProxyTail in topology?
            if !self.header().is_genesis()
                && topology.is_consensus_required()
                && topology
                    .filter_signatures_by_roles(&[Role::ProxyTail], self.signatures())
                    .is_empty()
            {
                return Err((self, eyre!("Block is not signed by the proxy tail")));
            }

            self.commit_without_proxy_tail_signature(topology)
        }

        /// Verify signatures and commit block to the store.
        /// The block doesn't have to be signed by the proxy tail.
        ///
        /// # Errors
        ///
        /// - Not enough signatures
        // TODO: a committed block should always contains Leader and Proxy tail signatures
        #[deprecated(
            since = "2.0.0-pre-rc.13",
            note = "This method exists only because some tests are failing, but it shouldn't"
        )]
        pub(crate) fn commit_without_proxy_tail_signature(
            self,
            topology: &Topology,
        ) -> Result<(CommittedBlock, Vec<Event>), (Self, eyre::Report)> {
            #[allow(clippy::collapsible_else_if)]
            if self.header().is_genesis() {
                // If we receive a committed genesis block that is valid, use it without question.
                // At genesis round we blindly take on the network topology from the genesis block.
            } else {
                // TODO: What is the point of filtering by all roles?
                let roles = [
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ];

                if topology
                    .filter_signatures_by_roles(&roles, self.signatures())
                    .len()
                    .lt(&topology.min_votes_for_commit())
                {
                    return Err((
                        self,
                        eyre!("The block doesn't have enough valid signatures to be committed."),
                    ));
                }
            }

            let block = CommittedBlock(self.0);
            let events = block.produce_events();

            Ok((block, events))
        }

        /// Replace signatures in this block with the given
        pub fn replace_signatures(&mut self, signatures: SignaturesOf<BlockPayload>) {
            let VersionedSignedBlock::V1(block) = &mut self.0;

            block.signatures.clear();
            for signature in signatures {
                if let Err(err) = self.add_signature(signature) {
                    // TODO: Is this something to be tolerated or should the block be rejected?
                    iroha_logger::warn!(?err, "Signature not valid");
                }
            }
        }

        #[cfg(test)]
        #[deprecated(
            since = "2.0.0-pre-rc.13",
            note = "This method exists only because some tests are failing, but it shouldn't"
        )]
        pub(crate) fn commit_unchecked(self) -> (CommittedBlock, Vec<Event>) {
            let block = CommittedBlock(self.0);
            let events = block.produce_events();

            (block, events)
        }

        /// Add additional signatures for [`Self`].
        ///
        /// # Errors
        ///
        /// If signature generation fails
        pub fn sign(self, key_pair: KeyPair) -> Result<Self> {
            Ok(ValidBlock(
                SignatureOf::from_hash(key_pair, &self.hash())
                    .wrap_err(format!("Failed to sign block with hash {}", self.hash()))
                    .map(|signature| {
                        let VersionedSignedBlock::V1(mut block) = self.0;
                        block.signatures.insert(signature);
                        VersionedSignedBlock::from(block)
                    })?,
            ))
        }

        /// Add additional signature for [`Self`]
        ///
        /// # Errors
        ///
        /// If given signature doesn't match block hash
        pub fn add_signature(&mut self, signature: SignatureOf<BlockPayload>) -> Result<()> {
            let VersionedSignedBlock::V1(block) = &mut self.0;

            signature
                .verify_hash(&block.hash())
                .map(|_| block.signatures.insert(signature))
                .wrap_err(format!(
                    "Provided signature doesn't match block with hash {}",
                    self.hash()
                ))
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
                    rejected_transactions_hash: None,
                    commit_topology: Vec::new(),
                },
                transactions: Vec::new(),
                rejected_transactions: Vec::new(),
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
    use iroha_data_model::block::Block;

    use super::*;

    /// Represents a block accepted by consensus.
    /// Every [`Self`] will have a different height.
    #[derive(Debug, Clone)]
    pub struct CommittedBlock(pub(super) VersionedSignedBlock);

    impl Block for CommittedBlock {
        fn payload(&self) -> &BlockPayload {
            self.0.payload()
        }
        fn signatures(&self) -> &SignaturesOf<BlockPayload> {
            self.0.signatures()
        }
    }

    impl CommittedBlock {
        #[deprecated(
            since = "2.0.0-pre-rc.13",
            note = "This method exists only because some tests are failing, but it shouldn't"
        )]
        pub(crate) fn commit_without_validation(
            block: VersionedSignedBlock,
        ) -> (CommittedBlock, Vec<Event>) {
            let VersionedSignedBlock::V1(block) = block;
            let block = CommittedBlock(block.into());
            let events = block.produce_events();

            (block, events)
        }
    }

    impl From<CommittedBlock> for VersionedSignedBlock {
        fn from(source: CommittedBlock) -> Self {
            let VersionedSignedBlock::V1(block) = source.0;

            SignedBlock {
                payload: block.payload,
                signatures: block.signatures,
            }
            .into()
        }
    }

    impl CommittedBlock {
        pub(super) fn produce_events(&self) -> Vec<Event> {
            let rejected_tx = self
                .payload()
                .rejected_transactions
                .iter()
                .map(|transaction| {
                    PipelineEvent {
                        entity_kind: PipelineEntityKind::Transaction,
                        status: PipelineStatus::Rejected(transaction.1.clone().into()),
                        hash: transaction.0.hash().into(),
                    }
                    .into()
                });
            let tx = self.payload().transactions.iter().map(|transaction| {
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
                    hash: self.hash().into(),
                }
                .into(),
            );

            tx.chain(rejected_tx).chain(current_block).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr;

    use iroha_data_model::{block::Block, prelude::*};

    use super::*;
    use crate::{kura::Kura, smartcontracts::isi::Registrable as _};

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let topology = Topology::new(Vec::new());
        let valid_block = ValidBlock::new_dummy();
        let committed_block = valid_block.clone().commit(&topology).expect("Valid");

        assert_eq!(valid_block.hash(), committed_block.0.hash())
    }

    #[test]
    fn should_reject_due_to_repetition() {
        // Predefined world state
        let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
        let alice_keys = KeyPair::generate().expect("Valid");
        let account = Account::new(alice_id.clone(), [alice_keys.public_key().clone()])
            .build(alice_id.clone());
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(alice_id.clone());
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world, kura);

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition: InstructionBox =
            RegisterBox::new(AssetDefinition::quantity(asset_definition_id)).into();

        // Making two transactions that have the same instruction
        let transaction_limits = TransactionLimits {
            max_instruction_number: 100,
            max_wasm_size_bytes: 0,
        };
        let transaction_validator = TransactionValidator::new(transaction_limits);
        let tx = TransactionBuilder::new(alice_id, [create_asset_definition], 4000)
            .sign(alice_keys)
            .expect("Valid");
        let tx: AcceptedTransaction = AcceptedTransaction::accept::<false>(tx, &transaction_limits)
            .map(Into::into)
            .expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let topology = Topology::new(Vec::new());
        let block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain_first(&transaction_validator, wsv);

        // The first transaction should be confirmed
        assert_eq!(block.0 .0.transactions.len(), 1);

        // The second transaction should be rejected
        assert_eq!(block.0 .0.rejected_transactions.len(), 1);
    }
}
