//! This module contains [`Block`] structures for each state. Transitions are modeled as follows:
//! 1. If a new block is constructed by the node:
//!     `BlockBuilder<Pending>` -> `BlockBuilder<Chained>` -> `ValidBlock` -> `CommittedBlock`
//! 2. If a block is received, i.e. deserialized:
//!     `SignedBlock` -> `ValidBlock` -> `CommittedBlock`
//! [`Block`]s are organised into a linear sequence over time (also known as the block chain).
use std::error::Error as _;

use iroha_config::parameters::defaults::chain_wide::CONSENSUS_ESTIMATION as DEFAULT_CONSENSUS_ESTIMATION;
use iroha_crypto::{HashOf, KeyPair, MerkleTree, SignatureOf, SignaturesOf};
use iroha_data_model::{
    block::*,
    events::prelude::*,
    peer::PeerId,
    transaction::{error::TransactionRejectionReason, prelude::*},
};
use iroha_genesis::GenesisTransaction;
use iroha_primitives::unique_vec::UniqueVec;
use thiserror::Error;

pub(crate) use self::event::WithEvents;
pub use self::{chained::Chained, commit::CommittedBlock, valid::ValidBlock};
use crate::{prelude::*, sumeragi::network_topology::Topology, tx::AcceptTransactionFail};

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
        expected: Option<HashOf<SignedBlock>>,
        /// Actual value
        actual: Option<HashOf<SignedBlock>>,
    },
    /// Mismatch between the actual and expected height of the latest block. Expected: {expected}, actual: {actual}
    LatestBlockHeightMismatch {
        /// Expected value
        expected: u64,
        /// Actual value
        actual: u64,
    },
    /// Mismatch between the actual and expected hashes of the current block. Expected: {expected:?}, actual: {actual:?}
    IncorrectHash {
        /// Expected value
        expected: HashOf<SignedBlock>,
        /// Actual value
        actual: HashOf<SignedBlock>,
    },
    /// The transaction hash stored in the block header does not match the actual transaction hash
    TransactionHashMismatch,
    /// Error during transaction validation
    TransactionValidation(#[from] TransactionValidationError),
    /// Mismatch between the actual and expected topology. Expected: {expected:?}, actual: {actual:?}
    TopologyMismatch {
        /// Expected value
        expected: UniqueVec<PeerId>,
        /// Actual value
        actual: UniqueVec<PeerId>,
    },
    /// Error during block signatures check
    SignatureVerification(#[from] SignatureVerificationError),
    /// Received view change index is too large
    ViewChangeIndexTooLarge,
}

/// Error during signature verification
#[derive(thiserror::Error, displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationError {
    /// The block doesn't have enough valid signatures to be committed (`votes_count` out of `min_votes_for_commit`)
    NotEnoughSignatures {
        /// Current number of signatures
        votes_count: usize,
        /// Minimal required number of signatures
        min_votes_for_commit: usize,
    },
    /// The block doesn't contain an expected signature. Expected signature can be leader or the current peer
    SignatureMissing,
    /// Found signature that does not correspond to block payload
    UnknownSignature,
    /// The block doesn't have proxy tail signature
    ProxyTailMissing,
    /// The block doesn't have leader signature
    LeaderMissing,
}

/// Builder for blocks
#[derive(Debug, Clone)]
pub struct BlockBuilder<B>(B);

mod pending {
    use std::time::SystemTime;

    use iroha_data_model::transaction::CommittedTransaction;

    use super::*;
    use crate::state::StateBlock;

    /// First stage in the life-cycle of a [`Block`].
    /// In the beginning the block is assumed to be verified and to contain only accepted transactions.
    /// Additionally the block must retain events emitted during the execution of on-chain logic during
    /// the previous round, which might then be processed by the trigger system.
    #[derive(Debug, Clone)]
    pub struct Pending {
        /// The topology at the time of block commit.
        commit_topology: Topology,
        /// Collection of transactions which have been accepted.
        /// Transaction will be validated when block is chained.
        transactions: Vec<AcceptedTransaction>,
        /// Event recommendations for use in triggers and off-chain work
        event_recommendations: Vec<EventBox>,
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
            event_recommendations: Vec<EventBox>,
        ) -> Self {
            assert!(!transactions.is_empty(), "Empty block created");

            Self(Pending {
                commit_topology,
                transactions,
                event_recommendations,
            })
        }

        fn make_header(
            previous_height: u64,
            prev_block_hash: Option<HashOf<SignedBlock>>,
            view_change_index: u64,
            transactions: &[CommittedTransaction],
        ) -> BlockHeader {
            BlockHeader {
                height: previous_height + 1,
                previous_block_hash: prev_block_hash,
                transactions_hash: transactions
                    .iter()
                    .map(|value| value.as_ref().hash())
                    .collect::<MerkleTree<_>>()
                    .hash(),
                timestamp_ms: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get the current system time")
                    .as_millis()
                    .try_into()
                    .expect("Time should fit into u64"),
                view_change_index,
                consensus_estimation_ms: DEFAULT_CONSENSUS_ESTIMATION
                    .as_millis()
                    .try_into()
                    .expect("Time should fit into u64"),
            }
        }

        fn categorize_transactions(
            transactions: Vec<AcceptedTransaction>,
            state_block: &mut StateBlock<'_>,
        ) -> Vec<CommittedTransaction> {
            transactions
                .into_iter()
                .map(
                    |tx| match state_block.transaction_executor().validate(tx, state_block) {
                        Ok(tx) => CommittedTransaction {
                            value: tx,
                            error: None,
                        },
                        Err((tx, error)) => {
                            iroha_logger::warn!(
                                reason = %error,
                                caused_by = ?error.source(),
                                "Transaction validation failed",
                            );
                            CommittedTransaction {
                                value: tx,
                                error: Some(error),
                            }
                        }
                    },
                )
                .collect()
        }

        /// Chain the block with existing blockchain.
        ///
        /// Upon executing this method current timestamp is stored in the block header.
        pub fn chain(
            self,
            view_change_index: u64,
            state: &mut StateBlock<'_>,
        ) -> BlockBuilder<Chained> {
            let transactions = Self::categorize_transactions(self.0.transactions, state);

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    state.height(),
                    state.latest_block_hash(),
                    view_change_index,
                    &transactions,
                ),
                transactions,
                commit_topology: self.0.commit_topology.ordered_peers,
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
        pub fn sign(self, key_pair: &KeyPair) -> WithEvents<ValidBlock> {
            let signed_block = SignedBlockV1::new(self.0 .0, key_pair);
            WithEvents::new(ValidBlock(signed_block.into()))
        }
    }
}

mod valid {
    use iroha_data_model::ChainId;

    use super::*;
    use crate::{state::StateBlock, sumeragi::network_topology::Role};

    /// Block that was validated and accepted
    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct ValidBlock(pub(super) SignedBlock);

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
        /// - Transaction in the genesis block is not signed by the genesis public key
        pub fn validate(
            block: SignedBlock,
            topology: &Topology,
            expected_chain_id: &ChainId,
            genesis_public_key: &PublicKey,
            state_block: &mut StateBlock<'_>,
        ) -> WithEvents<Result<ValidBlock, (SignedBlock, BlockValidationError)>> {
            let expected_block_height = state_block.height() + 1;
            let actual_height = block.header().height;

            if expected_block_height != actual_height {
                return WithEvents::new(Err((
                    block,
                    BlockValidationError::LatestBlockHeightMismatch {
                        expected: expected_block_height,
                        actual: actual_height,
                    },
                )));
            }

            let expected_prev_block_hash = state_block.latest_block_hash();
            let actual_prev_block_hash = block.header().previous_block_hash;

            if expected_prev_block_hash != actual_prev_block_hash {
                return WithEvents::new(Err((
                    block,
                    BlockValidationError::LatestBlockHashMismatch {
                        expected: expected_prev_block_hash,
                        actual: actual_prev_block_hash,
                    },
                )));
            }

            // NOTE: should be checked AFTER height and hash, both this issues lead to topology mismatch
            if !block.header().is_genesis() {
                let actual_commit_topology = block.commit_topology();
                let expected_commit_topology = &topology.ordered_peers;

                if actual_commit_topology != expected_commit_topology {
                    let actual_commit_topology = actual_commit_topology.clone();

                    return WithEvents::new(Err((
                        block,
                        BlockValidationError::TopologyMismatch {
                            expected: expected_commit_topology.clone(),
                            actual: actual_commit_topology,
                        },
                    )));
                }

                if topology
                    .filter_signatures_by_roles(&[Role::Leader], block.signatures())
                    .is_empty()
                {
                    return WithEvents::new(Err((
                        block,
                        SignatureVerificationError::LeaderMissing.into(),
                    )));
                }
            }

            if block
                .transactions()
                .any(|tx| state_block.has_transaction(tx.as_ref().hash()))
            {
                return WithEvents::new(Err((
                    block,
                    BlockValidationError::HasCommittedTransactions,
                )));
            }

            if let Err(error) = Self::validate_transactions(
                &block,
                expected_chain_id,
                genesis_public_key,
                state_block,
            ) {
                return WithEvents::new(Err((block, error.into())));
            }

            WithEvents::new(Ok(ValidBlock(block)))
        }

        fn validate_transactions(
            block: &SignedBlock,
            expected_chain_id: &ChainId,
            genesis_public_key: &PublicKey,
            state_block: &mut StateBlock<'_>,
        ) -> Result<(), TransactionValidationError> {
            let is_genesis = block.header().is_genesis();

            block
                .transactions()
                // TODO: Unnecessary clone?
                .cloned()
                .try_for_each(|CommittedTransaction { value, error }| {
                    let transaction_executor = state_block.transaction_executor();
                    let limits = &transaction_executor.transaction_limits;

                    let tx = if is_genesis {
                        AcceptedTransaction::accept_genesis(
                            GenesisTransaction(value),
                            expected_chain_id,
                            genesis_public_key,
                        )
                    } else {
                        AcceptedTransaction::accept(value, expected_chain_id, limits)
                    }?;

                    if error.is_some() {
                        match transaction_executor.validate(tx, state_block) {
                            Err(rejected_transaction) => Ok(rejected_transaction),
                            Ok(_) => Err(TransactionValidationError::RejectedIsValid),
                        }?;
                    } else {
                        transaction_executor
                            .validate(tx, state_block)
                            .map_err(|(_tx, error)| TransactionValidationError::NotValid(error))?;
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
        pub fn commit_with_signatures(
            mut self,
            topology: &Topology,
            signatures: SignaturesOf<BlockPayload>,
            expected_hash: HashOf<SignedBlock>,
        ) -> WithEvents<Result<CommittedBlock, (ValidBlock, BlockValidationError)>> {
            if topology
                .filter_signatures_by_roles(&[Role::Leader], &signatures)
                .is_empty()
            {
                return WithEvents::new(Err((
                    self,
                    SignatureVerificationError::LeaderMissing.into(),
                )));
            }

            if !self.as_ref().signatures().is_subset(&signatures) {
                return WithEvents::new(Err((
                    self,
                    SignatureVerificationError::SignatureMissing.into(),
                )));
            }

            if !self.0.replace_signatures(signatures) {
                return WithEvents::new(Err((
                    self,
                    SignatureVerificationError::UnknownSignature.into(),
                )));
            }

            let actual_block_hash = self.as_ref().hash();
            if actual_block_hash != expected_hash {
                let err = BlockValidationError::IncorrectHash {
                    expected: expected_hash,
                    actual: actual_block_hash,
                };

                return WithEvents::new(Err((self, err)));
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
        ) -> WithEvents<Result<CommittedBlock, (ValidBlock, BlockValidationError)>> {
            if !self.0.header().is_genesis() {
                if let Err(err) = self.verify_signatures(topology) {
                    return WithEvents::new(Err((self, err.into())));
                }
            }

            WithEvents::new(Ok(CommittedBlock(self)))
        }

        /// Add additional signatures for [`Self`].
        #[must_use]
        pub fn sign(self, key_pair: &KeyPair) -> ValidBlock {
            ValidBlock(self.0.sign(key_pair))
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
            Self::new_dummy_and_modify_payload(|_| {})
        }

        #[cfg(test)]
        pub(crate) fn new_dummy_and_modify_payload(f: impl FnOnce(&mut BlockPayload)) -> Self {
            let mut payload = BlockPayload {
                header: BlockHeader {
                    height: 2,
                    previous_block_hash: None,
                    transactions_hash: None,
                    timestamp_ms: 0,
                    view_change_index: 0,
                    consensus_estimation_ms: DEFAULT_CONSENSUS_ESTIMATION
                        .as_millis()
                        .try_into()
                        .expect("Time should fit into u64"),
                },
                transactions: Vec::new(),
                commit_topology: UniqueVec::new(),
                event_recommendations: Vec::new(),
            };
            f(&mut payload);
            BlockBuilder(Chained(payload))
                .sign(&KeyPair::random())
                .unpack(|_| {})
        }

        /// Check if block's signatures meet requirements for given topology.
        ///
        /// In order for block to be considered valid there should be at least $2f + 1$ signatures (including proxy tail and leader signature) where f is maximum number of faulty nodes.
        /// For further information please refer to the [whitepaper](docs/source/iroha_2_whitepaper.md) section 2.8 consensus.
        ///
        /// # Errors
        /// - Not enough signatures
        /// - Missing proxy tail signature
        fn verify_signatures(&self, topology: &Topology) -> Result<(), SignatureVerificationError> {
            // TODO: Should the peer that serves genesis have a fixed role of ProxyTail in topology?
            if !self.as_ref().header().is_genesis()
                && topology.is_consensus_required().is_some()
                && topology
                    .filter_signatures_by_roles(&[Role::ProxyTail], self.as_ref().signatures())
                    .is_empty()
            {
                return Err(SignatureVerificationError::ProxyTailMissing);
            }

            #[allow(clippy::collapsible_else_if)]
            if self.as_ref().header().is_genesis() {
                // At genesis round we blindly take on the network topology from the genesis block.
            } else {
                let roles = [
                    Role::ValidatingPeer,
                    Role::Leader,
                    Role::ProxyTail,
                    Role::ObservingPeer,
                ];

                let votes_count = topology
                    .filter_signatures_by_roles(&roles, self.as_ref().signatures())
                    .len();
                if votes_count < topology.min_votes_for_commit() {
                    return Err(SignatureVerificationError::NotEnoughSignatures {
                        votes_count,
                        min_votes_for_commit: topology.min_votes_for_commit(),
                    });
                }
            }

            Ok(())
        }
    }

    impl From<ValidBlock> for SignedBlock {
        fn from(source: ValidBlock) -> Self {
            source.0
        }
    }

    impl AsRef<SignedBlock> for ValidBlock {
        fn as_ref(&self) -> &SignedBlock {
            &self.0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::sumeragi::network_topology::test_peers;

        fn payload(block: &ValidBlock) -> &BlockPayload {
            let SignedBlock::V1(signed) = &block.0;
            signed.payload()
        }

        #[test]
        fn signature_verification_ok() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(7)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
            let topology = Topology::new(peers);

            let mut block = ValidBlock::new_dummy();
            let payload = payload(&block).clone();
            key_pairs
                .iter()
                .map(|key_pair| SignatureOf::new(key_pair, &payload))
                .try_for_each(|signature| block.add_signature(signature))
                .expect("Failed to add signatures");

            assert_eq!(block.verify_signatures(&topology), Ok(()));
        }

        #[test]
        fn signature_verification_consensus_not_required_ok() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(1)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0,: key_pairs_iter];
            let topology = Topology::new(peers);

            let mut block = ValidBlock::new_dummy();
            let payload = payload(&block).clone();
            key_pairs
                .iter()
                .map(|key_pair| SignatureOf::new(key_pair, &payload))
                .try_for_each(|signature| block.add_signature(signature))
                .expect("Failed to add signatures");

            assert_eq!(block.verify_signatures(&topology), Ok(()));
        }

        /// Check requirement of having at least $2f + 1$ signatures in $3f + 1$ network
        #[test]
        fn signature_verification_not_enough_signatures() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(7)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
            let topology = Topology::new(peers);

            let mut block = ValidBlock::new_dummy();
            let payload = payload(&block).clone();
            let proxy_tail_signature = SignatureOf::new(&key_pairs[4], &payload);
            block
                .add_signature(proxy_tail_signature)
                .expect("Failed to add signature");

            assert_eq!(
                block.verify_signatures(&topology),
                Err(SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 1,
                    min_votes_for_commit: topology.min_votes_for_commit(),
                })
            )
        }

        /// Check requirement of having leader signature
        #[test]
        fn signature_verification_miss_proxy_tail_signature() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(7)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
            let topology = Topology::new(peers);

            let mut block = ValidBlock::new_dummy();
            let payload = payload(&block).clone();
            key_pairs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 4) // Skip proxy tail
                .map(|(_, key_pair)| SignatureOf::new(key_pair, &payload))
                .try_for_each(|signature| block.add_signature(signature))
                .expect("Failed to add signatures");

            assert_eq!(
                block.verify_signatures(&topology),
                Err(SignatureVerificationError::ProxyTailMissing)
            )
        }
    }
}

mod commit {
    use super::*;

    /// Represents a block accepted by consensus.
    /// Every [`Self`] will have a different height.
    #[derive(Debug, Clone)]
    pub struct CommittedBlock(pub(super) ValidBlock);

    impl From<CommittedBlock> for ValidBlock {
        fn from(source: CommittedBlock) -> Self {
            ValidBlock(source.0.into())
        }
    }

    impl From<CommittedBlock> for SignedBlock {
        fn from(source: CommittedBlock) -> Self {
            source.0 .0
        }
    }

    impl AsRef<SignedBlock> for CommittedBlock {
        fn as_ref(&self) -> &SignedBlock {
            &self.0 .0
        }
    }

    #[cfg(test)]
    impl AsMut<SignedBlock> for CommittedBlock {
        fn as_mut(&mut self) -> &mut SignedBlock {
            &mut self.0 .0
        }
    }
}

mod event {
    use super::*;

    pub trait EventProducer {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox>;
    }

    #[derive(Debug)]
    #[must_use]
    pub struct WithEvents<B>(B);

    impl<B> WithEvents<B> {
        pub(super) fn new(source: B) -> Self {
            Self(source)
        }
    }

    impl<B: EventProducer, U> WithEvents<Result<B, (U, BlockValidationError)>> {
        pub fn unpack<F: Fn(PipelineEventBox)>(self, f: F) -> Result<B, (U, BlockValidationError)> {
            match self.0 {
                Ok(ok) => Ok(WithEvents(ok).unpack(f)),
                Err(err) => Err(WithEvents(err).unpack(f)),
            }
        }
    }
    impl<B: EventProducer> WithEvents<B> {
        pub fn unpack<F: Fn(PipelineEventBox)>(self, f: F) -> B {
            self.0.produce_events().for_each(f);
            self.0
        }
    }

    impl<B, E: EventProducer> WithEvents<(B, E)> {
        pub(crate) fn unpack<F: Fn(PipelineEventBox)>(self, f: F) -> (B, E) {
            self.0 .1.produce_events().for_each(f);
            self.0
        }
    }

    impl EventProducer for ValidBlock {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            let block_height = self.as_ref().header().height;

            let tx_events = self.as_ref().transactions().map(move |tx| {
                let status = tx.error.as_ref().map_or_else(
                    || TransactionStatus::Approved,
                    |error| TransactionStatus::Rejected(error.clone().into()),
                );

                TransactionEvent {
                    block_height: Some(block_height),
                    hash: tx.as_ref().hash(),
                    status,
                }
            });

            let block_event = core::iter::once(BlockEvent {
                header: self.as_ref().header().clone(),
                hash: self.as_ref().hash(),
                status: BlockStatus::Approved,
            });

            tx_events
                .map(PipelineEventBox::from)
                .chain(block_event.map(Into::into))
        }
    }

    impl EventProducer for CommittedBlock {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            let block_event = core::iter::once(BlockEvent {
                header: self.as_ref().header().clone(),
                hash: self.as_ref().hash(),
                status: BlockStatus::Committed,
            });

            block_event.map(Into::into)
        }
    }

    impl EventProducer for BlockValidationError {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            core::iter::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use iroha_crypto::SignatureVerificationFail;
    use iroha_data_model::prelude::*;
    use iroha_genesis::GENESIS_DOMAIN_ID;
    use test_samples::gen_account_in;

    use super::*;
    use crate::{
        kura::Kura, query::store::LiveQueryStore, smartcontracts::isi::Registrable as _,
        state::State, tests::test_account,
    };

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let valid_block = ValidBlock::new_dummy();
        let topology = Topology::new(UniqueVec::new());
        let committed_block = valid_block
            .clone()
            .commit(&topology)
            .unpack(|_| {})
            .unwrap();

        assert_eq!(valid_block.0.hash(), committed_block.as_ref().hash())
    }

    #[tokio::test]
    async fn should_reject_due_to_repetition() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let account = test_account(&alice_id).activate();
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));

        // Making two transactions that have the same instruction
        let transaction_limits = &state_block.transaction_executor().transaction_limits;
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([create_asset_definition])
            .sign(&alice_keypair);
        let tx = AcceptedTransaction::accept(tx, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let topology = Topology::new(UniqueVec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(&alice_keypair)
            .unpack(|_| {});

        // The first transaction should be confirmed
        assert!(valid_block
            .as_ref()
            .transactions()
            .next()
            .unwrap()
            .error
            .is_none());

        // The second transaction should be rejected
        assert!(valid_block
            .as_ref()
            .transactions()
            .nth(1)
            .unwrap()
            .error
            .is_some());
    }

    #[tokio::test]
    async fn tx_order_same_in_validation_and_revalidation() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let account = test_account(&alice_id).activate();
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(domain.add_account(account).is_none());
        let world = World::with([domain], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));

        // Making two transactions that have the same instruction
        let transaction_limits = &state_block.transaction_executor().transaction_limits;
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([create_asset_definition])
            .sign(&alice_keypair);
        let tx = AcceptedTransaction::accept(tx, &chain_id, transaction_limits).expect("Valid");

        let fail_mint = Mint::asset_numeric(
            20u32,
            AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        );

        let succeed_mint =
            Mint::asset_numeric(200u32, AssetId::new(asset_definition_id, alice_id.clone()));

        let tx0 = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([fail_mint])
            .sign(&alice_keypair);
        let tx0 = AcceptedTransaction::accept(tx0, &chain_id, transaction_limits).expect("Valid");

        let tx2 = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([succeed_mint])
            .sign(&alice_keypair);
        let tx2 = AcceptedTransaction::accept(tx2, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx0, tx, tx2];
        let topology = Topology::new(UniqueVec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(&alice_keypair)
            .unpack(|_| {});

        // The first transaction should fail
        assert!(valid_block
            .as_ref()
            .transactions()
            .next()
            .unwrap()
            .error
            .is_some());

        // The third transaction should succeed
        assert!(valid_block
            .as_ref()
            .transactions()
            .nth(2)
            .unwrap()
            .error
            .is_none());
    }

    #[tokio::test]
    async fn failed_transactions_revert() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        // Predefined world state
        let (alice_id, alice_keypair) = gen_account_in("wonderland");
        let account = test_account(&alice_id).activate();
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&alice_id);
        assert!(
            domain.add_account(account).is_none(),
            "{alice_id} already exist in the blockchain"
        );
        let world = World::with([domain], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();
        let transaction_limits = &state_block.transaction_executor().transaction_limits;

        let domain_id = DomainId::from_str("domain").expect("Valid");
        let create_domain = Register::domain(Domain::new(domain_id));
        let asset_definition_id = AssetDefinitionId::from_str("coin#domain").expect("Valid");
        let create_asset =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));
        let instructions_fail: [InstructionBox; 2] = [
            create_domain.clone().into(),
            Fail::new("Always fail".to_owned()).into(),
        ];
        let instructions_accept: [InstructionBox; 2] = [create_domain.into(), create_asset.into()];
        let tx_fail = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions(instructions_fail)
            .sign(&alice_keypair);
        let tx_fail =
            AcceptedTransaction::accept(tx_fail, &chain_id, transaction_limits).expect("Valid");
        let tx_accept = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions(instructions_accept)
            .sign(&alice_keypair);
        let tx_accept =
            AcceptedTransaction::accept(tx_accept, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let topology = Topology::new(UniqueVec::new());
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(&alice_keypair)
            .unpack(|_| {});

        // The first transaction should be rejected
        assert!(
            valid_block
                .as_ref()
                .transactions()
                .next()
                .unwrap()
                .error
                .is_some(),
            "The first transaction should be rejected, as it contains `Fail`."
        );

        // The second transaction should be accepted
        assert!(
            valid_block
                .as_ref()
                .transactions()
                .nth(1)
                .unwrap()
                .error
                .is_none(),
            "The second transaction should be accepted."
        );
    }

    #[tokio::test]
    async fn genesis_public_key_is_checked() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        // Predefined world state
        let genesis_correct_key = KeyPair::random();
        let genesis_wrong_key = KeyPair::random();
        let genesis_correct_account_id = AccountId::new(
            GENESIS_DOMAIN_ID.clone(),
            genesis_correct_key.public_key().clone(),
        );
        let genesis_wrong_account_id = AccountId::new(
            GENESIS_DOMAIN_ID.clone(),
            genesis_wrong_key.public_key().clone(),
        );
        let mut genesis_domain =
            Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_correct_account_id);
        let genesis_wrong_account = test_account(&genesis_wrong_account_id).activate();
        assert!(genesis_domain.add_account(genesis_wrong_account).is_none(),);
        let world = World::with([genesis_domain], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let isi = Log::new(
            iroha_data_model::Level::DEBUG,
            "instruction itself doesn't matter here".to_string(),
        );

        // Create genesis transaction
        // Sign with `genesis_wrong_key` as peer which has incorrect genesis key pair
        let tx = TransactionBuilder::new(chain_id.clone(), genesis_wrong_account_id.clone())
            .with_instructions([isi])
            .sign(&genesis_wrong_key);
        let tx = AcceptedTransaction::accept_genesis(
            iroha_genesis::GenesisTransaction(tx),
            &chain_id,
            genesis_wrong_key.public_key(),
        )
        .expect("Valid");

        // Create genesis block
        let transactions = vec![tx];
        let topology = Topology::new(UniqueVec::new());
        let valid_block = BlockBuilder::new(transactions, topology.clone(), Vec::new())
            .chain(0, &mut state_block)
            .sign(&KeyPair::random())
            .unpack(|_| {});

        // Validate genesis block
        // Use correct genesis key and check if transaction is rejected
        let block: SignedBlock = valid_block.into();
        let (_, error) = ValidBlock::validate(
            block,
            &topology,
            &chain_id,
            genesis_correct_key.public_key(),
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap_err();

        // The first transaction should be rejected
        assert!(matches!(
            error,
            BlockValidationError::TransactionValidation(TransactionValidationError::Accept(
                AcceptTransactionFail::SignatureVerification(SignatureVerificationFail { reason, .. })
            )) if reason == "Signature doesn't correspond to genesis public key"
        ));
    }
}
