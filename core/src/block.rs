//! This module contains [`Block`] structures for each state. Transitions are modeled as follows:
//! 1. If a new block is constructed by the node:
//!     `BlockBuilder<Pending>` -> `BlockBuilder<Chained>` -> `ValidBlock` -> `CommittedBlock`
//! 2. If a block is received, i.e. deserialized:
//!     `SignedBlock` -> `ValidBlock` -> `CommittedBlock`
//! [`Block`]s are organised into a linear sequence over time (also known as the block chain).
use std::error::Error as _;

use iroha_crypto::{HashOf, KeyPair, MerkleTree};
use iroha_data_model::{
    block::*,
    events::prelude::*,
    peer::PeerId,
    transaction::{error::TransactionRejectionReason, prelude::*},
};
use thiserror::Error;

pub(crate) use self::event::WithEvents;
pub use self::{chained::Chained, commit::CommittedBlock, valid::ValidBlock};
use crate::{prelude::*, sumeragi::network_topology::Topology, tx::AcceptTransactionFail};

/// Error during transaction validation
#[derive(Debug, displaydoc::Display, PartialEq, Eq, Error)]
pub enum TransactionValidationError {
    /// Failed to accept transaction
    Accept(#[from] AcceptTransactionFail),
    /// A transaction is marked as accepted, but is actually invalid
    NotValid(#[from] TransactionRejectionReason),
    /// A transaction is marked as rejected, but is actually valid
    RejectedIsValid,
}

/// Errors occurred on block validation
#[derive(Debug, displaydoc::Display, PartialEq, Eq, Error)]
pub enum BlockValidationError {
    /// Block has committed transactions
    HasCommittedTransactions,
    /// Mismatch between the actual and expected hashes of the previous block. Expected: {expected:?}, actual: {actual:?}
    PrevBlockHashMismatch {
        /// Expected value
        expected: Option<HashOf<SignedBlock>>,
        /// Actual value
        actual: Option<HashOf<SignedBlock>>,
    },
    /// Mismatch between the actual and expected height of the previous block. Expected: {expected}, actual: {actual}
    PrevBlockHeightMismatch {
        /// Expected value
        expected: usize,
        /// Actual value
        actual: usize,
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
    /// Genesis block hash doesn't match provided hash
    InvalidGenesisHash,
}

/// Error during signature verification
#[derive(Debug, displaydoc::Display, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignatureVerificationError {
    /// The block doesn't have enough valid signatures to be committed (`votes_count` out of `min_votes_for_commit`)
    NotEnoughSignatures {
        /// Current number of signatures
        votes_count: usize,
        /// Minimal required number of signatures
        min_votes_for_commit: usize,
    },
    /// Block was signed by the same node multiple times
    DuplicateSignatures {
        /// Index of the faulty node in the topology
        signatory: usize,
    },
    /// Block signatory doesn't correspond to any in topology
    UnknownSignatory,
    /// Block signature doesn't correspond to block payload
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
    use std::{
        num::NonZeroUsize,
        time::{Duration, SystemTime},
    };

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
            Self(Pending {
                commit_topology,
                transactions,
                event_recommendations,
            })
        }

        fn make_header(
            prev_height: usize,
            prev_block_hash: Option<HashOf<SignedBlock>>,
            view_change_index: usize,
            transactions: &[CommittedTransaction],
            consensus_estimation: Duration,
        ) -> BlockHeader {
            BlockHeader {
                height: NonZeroUsize::new(
                    prev_height
                        .checked_add(1)
                        .expect("INTERNAL BUG: Blockchain height exceeds usize::MAX"),
                )
                .expect("INTERNAL BUG: block height must not be 0")
                .try_into()
                .expect("INTERNAL BUG: Number of blocks exceeds u64::MAX"),
                prev_block_hash,
                transactions_hash: transactions
                    .iter()
                    .map(|value| value.as_ref().hash())
                    .collect::<MerkleTree<_>>()
                    .hash()
                    .expect("INTERNAL BUG: Empty block created"),
                creation_time_ms: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("INTERNAL BUG: Failed to get the current system time")
                    .as_millis()
                    .try_into()
                    .expect("Time should fit into u64"),
                view_change_index: view_change_index
                    .try_into()
                    .expect("View change index should fit into u32"),
                consensus_estimation_ms: consensus_estimation
                    .as_millis()
                    .try_into()
                    .expect("INTERNAL BUG: Time should fit into u64"),
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
            view_change_index: usize,
            state: &mut StateBlock<'_>,
        ) -> BlockBuilder<Chained> {
            let transactions = Self::categorize_transactions(self.0.transactions, state);

            BlockBuilder(Chained(BlockPayload {
                header: Self::make_header(
                    state.height(),
                    state.latest_block_hash(),
                    view_change_index,
                    &transactions,
                    state.world.parameters().sumeragi.consensus_estimation(),
                ),
                transactions,
                commit_topology: self.0.commit_topology.into_iter().collect(),
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
        pub fn sign(self, private_key: &PrivateKey) -> WithEvents<ValidBlock> {
            WithEvents::new(ValidBlock(self.0 .0.sign(private_key)))
        }
    }
}

mod valid {
    use indexmap::IndexMap;
    use iroha_data_model::{
        account::Account,
        prelude::{AccountId, Domain},
        ChainId,
    };

    use super::*;
    use crate::{smartcontracts::Registrable, state::StateBlock, sumeragi::network_topology::Role};

    /// Block that was validated and accepted
    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct ValidBlock(pub(super) SignedBlock);

    impl ValidBlock {
        fn verify_leader_signature(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            let leader_index = topology.leader_index();
            let mut block_signatures = block.signatures();

            let leader_signature = match block_signatures.next() {
                Some(BlockSignature(signatory, signature))
                    if usize::try_from(*signatory)
                        .map_err(|_err| SignatureVerificationError::LeaderMissing)?
                        == leader_index =>
                {
                    let mut additional_leader_signatures =
                        topology.filter_signatures_by_roles(&[Role::Leader], block_signatures);

                    if additional_leader_signatures.next().is_some() {
                        return Err(SignatureVerificationError::DuplicateSignatures {
                            signatory: leader_index,
                        });
                    }

                    signature
                }
                _ => {
                    return Err(SignatureVerificationError::LeaderMissing);
                }
            };

            leader_signature
                .verify(topology.leader().public_key(), block.payload())
                .map_err(|_err| SignatureVerificationError::LeaderMissing)?;
            Ok(())
        }

        fn verify_validator_signatures(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            let valid_roles: &[Role] = if topology.view_change_index() >= 1 {
                &[Role::ValidatingPeer, Role::ObservingPeer]
            } else {
                &[Role::ValidatingPeer]
            };

            topology
                .filter_signatures_by_roles(valid_roles, block.signatures())
                .try_fold(IndexMap::<usize, _>::default(), |mut acc, signature| {
                    let signatory_idx = usize::try_from(signature.0)
                        .map_err(|_err| SignatureVerificationError::UnknownSignatory)?;

                    if acc.insert(signatory_idx, signature.1.clone()).is_some() {
                        return Err(SignatureVerificationError::DuplicateSignatures {
                            signatory: signatory_idx,
                        });
                    }

                    Ok(acc)
                })?
                .into_iter()
                .try_for_each(|(signatory_idx, signature)| {
                    let signatory: &PeerId = topology
                        .as_ref()
                        .get(signatory_idx)
                        .ok_or(SignatureVerificationError::UnknownSignatory)?;

                    signature
                        .verify(signatory.public_key(), block.payload())
                        .map_err(|_err| SignatureVerificationError::UnknownSignature)?;

                    Ok(())
                })?;

            Ok(())
        }

        fn verify_no_undefined_signatures(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            if topology
                .filter_signatures_by_roles(&[Role::Undefined], block.signatures())
                .next()
                .is_some()
            {
                return Err(SignatureVerificationError::UnknownSignatory);
            }

            Ok(())
        }

        fn verify_proxy_tail_signature(
            block: &SignedBlock,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            let proxy_tail_index = topology.proxy_tail_index();
            let mut signatures = block.signatures().rev();

            let proxy_tail_signature = match signatures.next() {
                Some(BlockSignature(signatory, signature))
                    if usize::try_from(*signatory)
                        .map_err(|_err| SignatureVerificationError::ProxyTailMissing)?
                        == proxy_tail_index =>
                {
                    let mut additional_proxy_tail_signatures =
                        topology.filter_signatures_by_roles(&[Role::ProxyTail], signatures);

                    if additional_proxy_tail_signatures.next().is_some() {
                        return Err(SignatureVerificationError::DuplicateSignatures {
                            signatory: proxy_tail_index,
                        });
                    }

                    signature
                }
                _ => {
                    return Err(SignatureVerificationError::ProxyTailMissing);
                }
            };

            proxy_tail_signature
                .verify(topology.proxy_tail().public_key(), block.payload())
                .map_err(|_err| SignatureVerificationError::ProxyTailMissing)?;

            Ok(())
        }

        /// Validate a block against the current state of the world.
        ///
        /// # Errors
        ///
        /// - There is a mismatch between candidate block height and actual blockchain height
        /// - There is a mismatch between candidate block previous block hash and actual previous block hash
        /// - Block is not signed by the leader
        /// - Block has duplicate signatures
        /// - Block has unknown signatories
        /// - Block has incorrect signatures
        /// - Topology field is incorrect
        /// - Block has committed transactions
        /// - Error during validation of individual transactions
        /// - Transaction in the genesis block is not signed by the genesis public key
        pub fn validate(
            block: SignedBlock,
            topology: &Topology,
            expected_chain_id: &ChainId,
            genesis_hash: &HashOf<SignedBlock>,
            state_block: &mut StateBlock<'_>,
        ) -> WithEvents<Result<ValidBlock, (SignedBlock, BlockValidationError)>> {
            let expected_block_height = state_block
                .height()
                .checked_add(1)
                .expect("INTERNAL BUG: Block height exceeds usize::MAX");
            let actual_height = block
                .header()
                .height
                .get()
                .try_into()
                .expect("INTERNAL BUG: Block height exceeds usize::MAX");

            if expected_block_height != actual_height {
                return WithEvents::new(Err((
                    block,
                    BlockValidationError::PrevBlockHeightMismatch {
                        expected: expected_block_height,
                        actual: actual_height,
                    },
                )));
            }

            let expected_prev_block_hash = state_block.latest_block_hash();
            let actual_prev_block_hash = block.header().prev_block_hash;

            if expected_prev_block_hash != actual_prev_block_hash {
                return WithEvents::new(Err((
                    block,
                    BlockValidationError::PrevBlockHashMismatch {
                        expected: expected_prev_block_hash,
                        actual: actual_prev_block_hash,
                    },
                )));
            }

            if block.header().is_genesis() {
                // See also [SignedBlockCandidate::validate_genesis]
                if &block.hash() != genesis_hash {
                    return WithEvents::new(Err((block, BlockValidationError::InvalidGenesisHash)));
                }
                add_genesis_domain_and_account(state_block, &block)
            } else {
                if let Err(err) = Self::verify_leader_signature(&block, topology)
                    .and_then(|()| Self::verify_validator_signatures(&block, topology))
                    .and_then(|()| Self::verify_no_undefined_signatures(&block, topology))
                {
                    return WithEvents::new(Err((block, err.into())));
                }

                let actual_commit_topology = block.commit_topology().cloned().collect();
                let expected_commit_topology = topology.as_ref();

                // NOTE: checked AFTER height and hash because
                // both of them can lead to a topology mismatch
                if actual_commit_topology != expected_commit_topology {
                    return WithEvents::new(Err((
                        block,
                        BlockValidationError::TopologyMismatch {
                            expected: expected_commit_topology.to_owned(),
                            actual: actual_commit_topology,
                        },
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

            if let Err(error) = Self::validate_transactions(&block, expected_chain_id, state_block)
            {
                return WithEvents::new(Err((block, error.into())));
            }

            WithEvents::new(Ok(ValidBlock(block)))
        }

        fn validate_transactions(
            block: &SignedBlock,
            expected_chain_id: &ChainId,
            state_block: &mut StateBlock<'_>,
        ) -> Result<(), TransactionValidationError> {
            let is_genesis = block.header().is_genesis();

            block
                .transactions()
                // TODO: Unnecessary clone?
                .cloned()
                .try_for_each(|CommittedTransaction { value, error }| {
                    let transaction_executor = state_block.transaction_executor();

                    let tx = if is_genesis {
                        AcceptedTransaction::accept_genesis(value, expected_chain_id)
                    } else {
                        AcceptedTransaction::accept(
                            value,
                            expected_chain_id,
                            transaction_executor.limits,
                        )
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

        /// Add additional signature for [`Self`]
        ///
        /// # Errors
        ///
        /// If given signature doesn't match block hash
        pub fn add_signature(
            &mut self,
            signature: BlockSignature,
            topology: &Topology,
        ) -> Result<(), SignatureVerificationError> {
            let signatory_idx = usize::try_from(signature.0)
                .expect("INTERNAL BUG: Number of peers exceeds usize::MAX");
            let signatory = &topology.as_ref()[signatory_idx];

            assert_ne!(Role::Leader, topology.role(signatory));
            if topology.view_change_index() == 0 {
                assert_ne!(Role::ObservingPeer, topology.role(signatory),);
            }
            assert_ne!(Role::Undefined, topology.role(signatory));
            assert_ne!(Role::ProxyTail, topology.role(signatory));

            self.0
                .add_signature(signature, signatory.public_key())
                .map_err(|_err| SignatureVerificationError::UnknownSignature)
        }

        /// Replace block's signatures. Returns previous block signatures
        ///
        /// # Errors
        ///
        /// - Replacement signatures don't contain the leader signature
        /// - Replacement signatures contain duplicate signatures
        /// - Replacement signatures contain unknown signatories
        /// - Replacement signatures contain incorrect signatures
        pub fn replace_signatures(
            &mut self,
            signatures: Vec<BlockSignature>,
            topology: &Topology,
        ) -> WithEvents<Result<Vec<BlockSignature>, SignatureVerificationError>> {
            let prev_signatures = self.0.replace_signatures_unchecked(signatures);

            if let Err(err) = Self::verify_leader_signature(self.as_ref(), topology)
                .and_then(|()| Self::verify_validator_signatures(self.as_ref(), topology))
                .and_then(|()| Self::verify_no_undefined_signatures(self.as_ref(), topology))
            {
                self.0.replace_signatures_unchecked(prev_signatures);
                WithEvents::new(Err(err))
            } else {
                WithEvents::new(Ok(prev_signatures))
            }
        }

        /// commit block to the store.
        ///
        /// # Errors
        ///
        /// - Block has duplicate proxy tail signatures
        /// - Block is not signed by the proxy tail
        /// - Block doesn't have enough signatures
        pub fn commit(
            self,
            topology: &Topology,
        ) -> WithEvents<Result<CommittedBlock, (ValidBlock, BlockValidationError)>> {
            if !self.as_ref().header().is_genesis() {
                if let Err(err) = Self::verify_proxy_tail_signature(self.as_ref(), topology) {
                    return WithEvents::new(Err((self, err.into())));
                }

                let votes_count = self.as_ref().signatures().len();
                if votes_count < topology.min_votes_for_commit() {
                    return WithEvents::new(Err((
                        self,
                        SignatureVerificationError::NotEnoughSignatures {
                            votes_count,
                            min_votes_for_commit: topology.min_votes_for_commit(),
                        }
                        .into(),
                    )));
                }
            }

            WithEvents::new(Ok(CommittedBlock(self)))
        }

        /// Add additional signatures for [`Self`].
        pub fn sign(&mut self, key_pair: &KeyPair, topology: &Topology) {
            let signatory_idx = topology
                .position(key_pair.public_key())
                .expect("INTERNAL BUG: Node is not in topology");

            self.0.sign(key_pair.private_key(), signatory_idx);
        }

        #[cfg(test)]
        pub(crate) fn new_dummy(leader_private_key: &PrivateKey) -> Self {
            Self::new_dummy_and_modify_payload(leader_private_key, |_| {})
        }

        #[cfg(test)]
        pub(crate) fn new_dummy_and_modify_payload(
            leader_private_key: &PrivateKey,
            f: impl FnOnce(&mut BlockPayload),
        ) -> Self {
            use nonzero_ext::nonzero;

            let mut payload = BlockPayload {
                header: BlockHeader {
                    height: nonzero!(2_u64),
                    prev_block_hash: None,
                    transactions_hash: HashOf::from_untyped_unchecked(Hash::prehashed(
                        [1; Hash::LENGTH],
                    )),
                    creation_time_ms: 0,
                    view_change_index: 0,
                    consensus_estimation_ms: 4_000,
                },
                transactions: Vec::new(),
                commit_topology: Vec::new(),
                event_recommendations: Vec::new(),
            };
            f(&mut payload);
            BlockBuilder(Chained(payload))
                .sign(leader_private_key)
                .unpack(|_| {})
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

    fn add_genesis_domain_and_account(state_block: &mut StateBlock, genesis_block: &SignedBlock) {
        let genesis_account = genesis_block
            .transactions()
            .next()
            .expect("Genesis block has transactions")
            .value
            .authority();
        let genesis_public_key = genesis_account.signatory.clone();
        let (genesis_account, genesis_domain) = genesis_account_and_domain(genesis_public_key);
        state_block
            .world
            .domains
            .insert(genesis_domain.id.clone(), genesis_domain);
        state_block
            .world
            .accounts
            .insert(genesis_account.id.clone(), genesis_account);
    }

    fn genesis_account_and_domain(public_key: PublicKey) -> (Account, Domain) {
        let genesis_account_id =
            AccountId::new(iroha_genesis::GENESIS_DOMAIN_ID.clone(), public_key);
        let genesis_account = Account::new(genesis_account_id).into_account();
        let genesis_domain =
            Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_account.id);
        (genesis_account, genesis_domain)
    }

    #[cfg(test)]
    mod tests {
        use iroha_crypto::SignatureOf;

        use super::*;
        use crate::sumeragi::network_topology::test_peers;

        #[test]
        fn signature_verification_ok() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(7)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0, 1, 2, 3, 4, 5, 6: key_pairs_iter];
            let topology = Topology::new(peers);

            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let payload = block.0.payload().clone();
            key_pairs
                .iter()
                .enumerate()
                // Include only peers in validator set
                .take(topology.min_votes_for_commit())
                // Skip leader since already singed
                .skip(1)
                .filter(|(i, _)| *i != 4) // Skip proxy tail
                .map(|(i, key_pair)| {
                    BlockSignature(i as u64, SignatureOf::new(key_pair.private_key(), &payload))
                })
                .try_for_each(|signature| block.add_signature(signature, &topology))
                .expect("Failed to add signatures");

            block.sign(&key_pairs[4], &topology);

            let _ = block.commit(&topology).unpack(|_| {}).unwrap();
        }

        #[test]
        fn signature_verification_consensus_not_required_ok() {
            let key_pairs = core::iter::repeat_with(KeyPair::random)
                .take(1)
                .collect::<Vec<_>>();
            let mut key_pairs_iter = key_pairs.iter();
            let peers = test_peers![0,: key_pairs_iter];
            let topology = Topology::new(peers);

            let block = ValidBlock::new_dummy(key_pairs[0].private_key());

            assert!(block.commit(&topology).unpack(|_| {}).is_ok());
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

            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            block.sign(&key_pairs[4], &topology);

            assert_eq!(
                block.commit(&topology).unpack(|_| {}).unwrap_err().1,
                SignatureVerificationError::NotEnoughSignatures {
                    votes_count: 2,
                    min_votes_for_commit: topology.min_votes_for_commit(),
                }
                .into()
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

            let mut block = ValidBlock::new_dummy(key_pairs[0].private_key());
            let payload = block.0.payload().clone();
            key_pairs
                .iter()
                .enumerate()
                // Include only peers in validator set
                .take(topology.min_votes_for_commit())
                // Skip leader since already singed
                .skip(1)
                .filter(|(i, _)| *i != 4) // Skip proxy tail
                .map(|(i, key_pair)| {
                    BlockSignature(i as u64, SignatureOf::new(key_pair.private_key(), &payload))
                })
                .try_for_each(|signature| block.add_signature(signature, &topology))
                .expect("Failed to add signatures");

            assert_eq!(
                block.commit(&topology).unpack(|_| {}).unwrap_err().1,
                SignatureVerificationError::ProxyTailMissing.into()
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
    impl WithEvents<Result<Vec<BlockSignature>, SignatureVerificationError>> {
        pub fn unpack<F: Fn(PipelineEventBox)>(
            self,
            f: F,
        ) -> Result<Vec<BlockSignature>, SignatureVerificationError> {
            match self.0 {
                Ok(ok) => Ok(ok),
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
            // TODO:
            core::iter::empty()
        }
    }

    impl EventProducer for SignatureVerificationError {
        fn produce_events(&self) -> impl Iterator<Item = PipelineEventBox> {
            // TODO:
            core::iter::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use iroha_data_model::prelude::*;
    use iroha_genesis::GENESIS_DOMAIN_ID;
    use iroha_primitives::unique_vec::UniqueVec;
    use test_samples::gen_account_in;

    use super::*;
    use crate::{
        kura::Kura, query::store::LiveQueryStore, smartcontracts::isi::Registrable as _,
        state::State,
    };

    #[test]
    pub fn committed_and_valid_block_hashes_are_equal() {
        let peer_key_pair = KeyPair::random();
        let peer_id = PeerId::new(
            "127.0.0.1:8080".parse().unwrap(),
            peer_key_pair.public_key().clone(),
        );
        let topology = Topology::new(vec![peer_id]);
        let valid_block = ValidBlock::new_dummy(peer_key_pair.private_key());
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
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));

        // Making two transactions that have the same instruction
        let transaction_limits = state_block.transaction_executor().limits;
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([create_asset_definition])
            .sign(alice_keypair.private_key());
        let tx = AcceptedTransaction::accept(tx, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(alice_keypair.private_key())
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
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));

        // Making two transactions that have the same instruction
        let transaction_limits = state_block.transaction_executor().limits;
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([create_asset_definition])
            .sign(alice_keypair.private_key());
        let tx = AcceptedTransaction::accept(tx, &chain_id, transaction_limits).expect("Valid");

        let fail_mint = Mint::asset_numeric(
            20u32,
            AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        );

        let succeed_mint =
            Mint::asset_numeric(200u32, AssetId::new(asset_definition_id, alice_id.clone()));

        let tx0 = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([fail_mint])
            .sign(alice_keypair.private_key());
        let tx0 = AcceptedTransaction::accept(tx0, &chain_id, transaction_limits).expect("Valid");

        let tx2 = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([succeed_mint])
            .sign(alice_keypair.private_key());
        let tx2 = AcceptedTransaction::accept(tx2, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx0, tx, tx2];
        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(alice_keypair.private_key())
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
        let account = Account::new(alice_id.clone()).build(&alice_id);
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], UniqueVec::new());
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();
        let transaction_limits = state_block.transaction_executor().limits;

        let domain_id = DomainId::from_str("domain").expect("Valid");
        let create_domain = Register::domain(Domain::new(domain_id));
        let asset_definition_id = AssetDefinitionId::from_str("coin#domain").expect("Valid");
        let create_asset =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));
        let fail_isi = Unregister::domain("dummy".parse().unwrap());
        let instructions_fail: [InstructionBox; 2] =
            [create_domain.clone().into(), fail_isi.into()];
        let instructions_accept: [InstructionBox; 2] = [create_domain.into(), create_asset.into()];
        let tx_fail = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions(instructions_fail)
            .sign(alice_keypair.private_key());
        let tx_fail =
            AcceptedTransaction::accept(tx_fail, &chain_id, transaction_limits).expect("Valid");
        let tx_accept = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions(instructions_accept)
            .sign(alice_keypair.private_key());
        let tx_accept =
            AcceptedTransaction::accept(tx_accept, &chain_id, transaction_limits).expect("Valid");

        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let valid_block = BlockBuilder::new(transactions, topology, Vec::new())
            .chain(0, &mut state_block)
            .sign(alice_keypair.private_key())
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
    async fn genesis_hash_is_checked() {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        // Predefined world state
        let genesis_key = KeyPair::random();
        let genesis_account_id =
            AccountId::new(GENESIS_DOMAIN_ID.clone(), genesis_key.public_key().clone());
        let genesis_domain = Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_account_id);
        let world = World::with([genesis_domain], [], UniqueVec::new());
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
        let tx = TransactionBuilder::new(chain_id.clone(), genesis_account_id.clone())
            .with_instructions([isi])
            .sign(genesis_key.private_key());
        let tx = AcceptedTransaction(tx);

        // Create genesis block
        let transactions = vec![tx];
        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let valid_block = BlockBuilder::new(transactions, topology.clone(), Vec::new())
            .chain(0, &mut state_block)
            .sign(genesis_key.private_key())
            .unpack(|_| {});

        let genesis_wrong_hash = HashOf::from_untyped_unchecked(Hash::new([]));

        // Validate genesis block.
        // Use wrong genesis hash and check if transaction is rejected.
        let block: SignedBlock = valid_block.into();
        let (_, error) = ValidBlock::validate(
            block,
            &topology,
            &chain_id,
            &genesis_wrong_hash,
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap_err();

        // The genesis block should be rejected
        assert_eq!(error, BlockValidationError::InvalidGenesisHash)
    }
}
