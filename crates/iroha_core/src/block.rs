//! This module contains [`Block`] structures for each state. Transitions are modeled as follows:
//! 1. If a new block is constructed by the node:
//!     `BlockBuilder<Pending>` -> `BlockBuilder<Chained>` -> `ValidBlock` -> `CommittedBlock`
//! 2. If a block is received, i.e. deserialized:
//!    `SignedBlock` -> `ValidBlock` -> `CommittedBlock`
//!    [`Block`]s are organised into a linear sequence over time (also known as the block chain).
use std::{error::Error as _, time::Duration};

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
use crate::{
    prelude::*,
    state::State,
    sumeragi::{network_topology::Topology, VotingBlock},
    tx::AcceptTransactionFail,
};

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
        expected: Option<HashOf<BlockHeader>>,
        /// Actual value
        actual: Option<HashOf<BlockHeader>>,
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
    /// Invalid genesis block: {0}
    InvalidGenesis(#[from] InvalidGenesisError),
    /// Block's creation time is earlier than that of the previous block
    BlockInThePast,
    /// Block's creation time is later than the current node local time
    BlockInTheFuture,
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

/// Errors occurred on genesis block validation
#[derive(Debug, Copy, Clone, displaydoc::Display, PartialEq, Eq, Error)]
pub enum InvalidGenesisError {
    /// Genesis block must be signed with genesis private key and not signed by any peer
    InvalidSignature,
    /// Genesis transaction must be authorized by genesis account
    UnexpectedAuthority,
}

/// Builder for blocks
#[derive(Debug, Clone)]
pub struct BlockBuilder<B>(B);

mod pending {
    use std::time::SystemTime;

    use iroha_data_model::transaction::CommittedTransaction;
    use nonzero_ext::nonzero;

    use super::*;
    use crate::state::StateBlock;

    /// First stage in the life-cycle of a [`Block`].
    /// In the beginning the block is assumed to be verified and to contain only accepted transactions.
    /// Additionally the block must retain events emitted during the execution of on-chain logic during
    /// the previous round, which might then be processed by the trigger system.
    #[derive(Debug, Clone)]
    pub struct Pending {
        /// Collection of transactions which have been accepted.
        /// Transaction will be validated when block is chained.
        transactions: Vec<AcceptedTransaction>,
    }

    impl BlockBuilder<Pending> {
        const TIME_PADDING: Duration = Duration::from_millis(1);

        /// Create [`Self`]
        ///
        /// # Panics
        ///
        /// if the given list of transaction is empty
        #[inline]
        pub fn new(transactions: Vec<AcceptedTransaction>) -> Self {
            assert!(
                !transactions.is_empty(),
                "Block must contain at least 1 transaction"
            );

            Self(Pending { transactions })
        }

        /// Create new BlockPayload
        pub fn new_unverified(
            prev_block: Option<&SignedBlock>,
            view_change_index: usize,
            transactions_a: Vec<AcceptedTransaction>,
            consensus_estimation: Duration,
        ) -> BlockPayload {
            let transactions = transactions_a
                .into_iter()
                .map(|tx| CommittedTransaction {
                    value: tx.clone().into(),
                    error: None,
                })
                .collect::<Vec<_>>();
            BlockPayload {
                header: Self::make_header(
                    prev_block,
                    view_change_index,
                    &transactions,
                    consensus_estimation,
                ),
                transactions,
            }
        }

        fn make_header(
            prev_block: Option<&SignedBlock>,
            view_change_index: usize,
            transactions: &[CommittedTransaction],
        ) -> BlockHeader {
            let prev_block_time =
                prev_block.map_or(Duration::ZERO, |block| block.header().creation_time());

            let latest_txn_time = transactions
                .iter()
                .map(|tx| tx.as_ref().creation_time())
                .max()
                .expect("INTERNAL BUG: Block empty");

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();

            // NOTE: Lower time bound must always be upheld for a valid block
            // If the clock has drifted too far this block will be rejected
            let creation_time = [
                now,
                latest_txn_time + Self::TIME_PADDING,
                prev_block_time + Self::TIME_PADDING,
            ]
            .into_iter()
            .max()
            .unwrap();

            BlockHeader {
                height: prev_block.map(|block| block.header().height).map_or_else(
                    || nonzero!(1_u64),
                    |height| {
                        height
                            .checked_add(1)
                            .expect("INTERNAL BUG: Blockchain height exceeds usize::MAX")
                    },
                ),
                prev_block_hash: prev_block.map(SignedBlock::hash),
                transactions_hash: transactions
                    .iter()
                    .map(|value| value.as_ref().hash())
                    .collect::<MerkleTree<_>>()
                    .hash()
                    .expect("INTERNAL BUG: Empty block created"),
                creation_time_ms: creation_time
                    .as_millis()
                    .try_into()
                    .expect("Time should fit into u64"),
                view_change_index: view_change_index
                    .try_into()
                    .expect("View change index should fit into u32"),
            }
        }

        fn categorize_transactions(
            transactions: Vec<AcceptedTransaction>,
            state_block: &mut StateBlock<'_>,
        ) -> Vec<CommittedTransaction> {
            transactions
                .into_iter()
                .map(|tx| match state_block.validate(tx) {
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
                            error: Some(Box::new(error)),
                        }
                    }
                })
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
                    state.latest_block().as_deref(),
                    view_change_index,
                    &transactions,
                ),
                transactions,
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
        /// Sign this block as Leader and get [`SignedBlock`].
        pub fn sign(self, private_key: &PrivateKey) -> WithEvents<ValidBlock> {
            WithEvents::new(ValidBlock(self.0 .0.sign(private_key)))
        }
    }
}

mod valid {
    use std::time::SystemTime;

    use commit::CommittedBlock;
    use indexmap::IndexMap;
    use iroha_data_model::{account::AccountId, events::pipeline::PipelineEventBox, ChainId};
    use mv::storage::StorageReadOnly;

    use super::*;
    use crate::{state::StateBlock, sumeragi::network_topology::Role};

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
                .verify(topology.leader().public_key(), &block.payload().header)
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
                        .verify(signatory.public_key(), &block.payload().header)
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
                .verify(topology.proxy_tail().public_key(), &block.payload().header)
                .map_err(|_err| SignatureVerificationError::ProxyTailMissing)?;

            Ok(())
        }

        /// Validate a block against the current state of the world. Individual transaction
        /// errors will be updated.
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
            mut block: SignedBlock,
            topology: &Topology,
            expected_chain_id: &ChainId,
            genesis_account: &AccountId,
            state_block: &mut StateBlock<'_>,
        ) -> WithEvents<Result<ValidBlock, (SignedBlock, BlockValidationError)>> {
            if let Err(error) =
                Self::validate_header(&block, topology, genesis_account, state_block, false)
            {
                return WithEvents::new(Err((block, error)));
            }

            if let Err(error) = Self::validate_transactions(
                &mut block,
                expected_chain_id,
                genesis_account,
                state_block,
            ) {
                return WithEvents::new(Err((block, error.into())));
            }

            WithEvents::new(Ok(ValidBlock(block)))
        }

        /// Same as `validate` but:
        /// * Block header will be validated with read-only state
        /// * If block header is valid, `voting_block` will be released,
        ///   and transactions will be validated with write state
        pub fn validate_keep_voting_block<'state>(
            mut block: SignedBlock,
            topology: &Topology,
            expected_chain_id: &ChainId,
            genesis_account: &AccountId,
            state: &'state State,
            voting_block: &mut Option<VotingBlock>,
            soft_fork: bool,
        ) -> WithEvents<Result<(ValidBlock, StateBlock<'state>), (SignedBlock, BlockValidationError)>>
        {
            if let Err(error) =
                Self::validate_header(&block, topology, genesis_account, &state.view(), soft_fork)
            {
                return WithEvents::new(Err((block, error)));
            }

            // Release block writer before creating new one
            let _ = voting_block.take();
            let mut state_block = if soft_fork {
                state.block_and_revert()
            } else {
                state.block()
            };

            if let Err(error) = Self::validate_transactions(
                &mut block,
                expected_chain_id,
                genesis_account,
                &mut state_block,
            ) {
                return WithEvents::new(Err((block, error.into())));
            }

            WithEvents::new(Ok((ValidBlock(block), state_block)))
        }

        fn validate_header(
            block: &SignedBlock,
            topology: &Topology,
            genesis_account: &AccountId,
            state: &impl StateReadOnly,
            soft_fork: bool,
        ) -> Result<(), BlockValidationError> {
            let expected_block_height = if soft_fork {
                state.height()
            } else {
                state
                    .height()
                    .checked_add(1)
                    .expect("INTERNAL BUG: Block height exceeds usize::MAX")
            };
            let actual_height = block
                .header()
                .height
                .get()
                .try_into()
                .expect("INTERNAL BUG: Block height exceeds usize::MAX");

            if expected_block_height != actual_height {
                return Err(BlockValidationError::PrevBlockHeightMismatch {
                    expected: expected_block_height,
                    actual: actual_height,
                });
            }

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let max_clock_drift = state.world().parameters().sumeragi.max_clock_drift();
            if block.header().creation_time().saturating_sub(now) > max_clock_drift {
                return Err(BlockValidationError::BlockInTheFuture);
            }

            let expected_prev_block_hash = if soft_fork {
                state.prev_block_hash()
            } else {
                state.latest_block_hash()
            };
            let actual_prev_block_hash = block.header().prev_block_hash;

            if expected_prev_block_hash != actual_prev_block_hash {
                return Err(BlockValidationError::PrevBlockHashMismatch {
                    expected: expected_prev_block_hash,
                    actual: actual_prev_block_hash,
                });
            }

            if block.header().is_genesis() {
                check_genesis_block(block, genesis_account)?;
            } else {
                let prev_block_time = if soft_fork {
                    state.prev_block()
                } else {
                    state.latest_block()
                }
                .expect("INTERNAL BUG: Genesis not committed")
                .header()
                .creation_time();

                if block.header().creation_time() <= prev_block_time {
                    return Err(BlockValidationError::BlockInThePast);
                }

                Self::verify_leader_signature(block, topology)?;
                Self::verify_validator_signatures(block, topology)?;
                Self::verify_no_undefined_signatures(block, topology)?;
            }

            if block.transactions().any(|tx| {
                state
                    .transactions()
                    .get(&tx.as_ref().hash())
                    // In case of soft-fork transaction is check if it was added at the same height as candidate block
                    .is_some_and(|height| height.get() < expected_block_height)
            }) {
                return Err(BlockValidationError::HasCommittedTransactions);
            }

            Ok(())
        }

        fn validate_transactions(
            block: &mut SignedBlock,
            expected_chain_id: &ChainId,
            genesis_account: &AccountId,
            state_block: &mut StateBlock<'_>,
        ) -> Result<(), TransactionValidationError> {
            let is_genesis = block.header().is_genesis();

            let (max_clock_drift, tx_limits) = {
                let params = state_block.world().parameters();
                (params.sumeragi().max_clock_drift(), params.transaction)
            };

            for CommittedTransaction { value, error } in block.transactions_mut() {
                let tx = if is_genesis {
                    AcceptedTransaction::accept_genesis(
                        value.clone(),
                        expected_chain_id,
                        max_clock_drift,
                        genesis_account,
                    )
                } else {
                    AcceptedTransaction::accept(
                        value.clone(),
                        expected_chain_id,
                        max_clock_drift,
                        tx_limits,
                    )
                }?;

                *error = match state_block.validate(tx) {
                    Ok(_) => None,
                    Err((_tx, error)) => Some(Box::new(error)),
                };
            }
            Ok(())
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
            WithEvents::new(match Self::is_commit(self.as_ref(), topology) {
                Err(err) => Err((self, err)),
                Ok(()) => Ok(CommittedBlock(self)),
            })
        }

        /// Validate and commit block if possible.
        ///
        /// This method is different from calling [`ValidBlock::validate_keep_voting_block`] and [`ValidateBlock::commit`] in the following ways:
        /// - signatures are checked eagerly so voting block is kept if block doesn't have valid signatures
        ///
        /// # Errors
        /// Combinations of errors from [`ValidBlock::validate_keep_voting_block`] and [`ValidateBlock::commit`].
        #[allow(clippy::too_many_arguments)]
        pub fn commit_keep_voting_block<'state, F: Fn(PipelineEventBox)>(
            block: SignedBlock,
            topology: &Topology,
            expected_chain_id: &ChainId,
            genesis_account: &AccountId,
            state: &'state State,
            voting_block: &mut Option<VotingBlock>,
            soft_fork: bool,
            send_events: F,
        ) -> WithEvents<
            Result<(CommittedBlock, StateBlock<'state>), (SignedBlock, BlockValidationError)>,
        > {
            if let Err(err) = Self::is_commit(&block, topology) {
                return WithEvents::new(Err((block, err)));
            }

            WithEvents::new(
                Self::validate_keep_voting_block(
                    block,
                    topology,
                    expected_chain_id,
                    genesis_account,
                    state,
                    voting_block,
                    soft_fork,
                )
                .unpack(send_events)
                .map(|(block, state_block)| (CommittedBlock(block), state_block)),
            )
        }

        /// Check if block satisfy requirements to be committed
        ///
        /// # Errors
        ///
        /// - Block has duplicate proxy tail signatures
        /// - Block is not signed by the proxy tail
        /// - Block doesn't have enough signatures
        fn is_commit(block: &SignedBlock, topology: &Topology) -> Result<(), BlockValidationError> {
            if !block.header().is_genesis() {
                Self::verify_proxy_tail_signature(block, topology)?;

                let votes_count = block.signatures().len();
                if votes_count < topology.min_votes_for_commit() {
                    return Err(SignatureVerificationError::NotEnoughSignatures {
                        votes_count,
                        min_votes_for_commit: topology.min_votes_for_commit(),
                    }
                    .into());
                }
            }

            Ok(())
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
                },
                transactions: Vec::new(),
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

    // See also [SignedBlockCandidate::validate_genesis]
    fn check_genesis_block(
        block: &SignedBlock,
        genesis_account: &AccountId,
    ) -> Result<(), InvalidGenesisError> {
        let signatures = block.signatures().collect::<Vec<_>>();
        let [signature] = signatures.as_slice() else {
            return Err(InvalidGenesisError::InvalidSignature);
        };
        signature
            .1
            .verify(&genesis_account.signatory, &block.payload().header)
            .map_err(|_| InvalidGenesisError::InvalidSignature)?;

        let transactions = block.payload().transactions.as_slice();
        for transaction in transactions {
            if transaction.value.authority() != genesis_account {
                return Err(InvalidGenesisError::UnexpectedAuthority);
            }
        }
        Ok(())
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
                    BlockSignature(
                        i as u64,
                        SignatureOf::new(key_pair.private_key(), &payload.header),
                    )
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
                    BlockSignature(
                        i as u64,
                        SignatureOf::new(key_pair.private_key(), &payload.header),
                    )
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
    use crate::state::StateBlock;

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
    impl<'state, B: EventProducer, U>
        WithEvents<Result<(B, StateBlock<'state>), (U, BlockValidationError)>>
    {
        pub fn unpack<F: Fn(PipelineEventBox)>(
            self,
            f: F,
        ) -> Result<(B, StateBlock<'state>), (U, BlockValidationError)> {
            match self.0 {
                Ok((ok, state)) => Ok((WithEvents(ok).unpack(f), state)),
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
    use iroha_data_model::prelude::*;
    use iroha_genesis::GENESIS_DOMAIN_ID;
    use iroha_test_samples::gen_account_in;

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
        let domain_id = "wonderland".parse().expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction)
        };
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = "xor#wonderland".parse().expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));

        // Making two transactions that have the same instruction
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([create_asset_definition])
            .sign(alice_keypair.private_key());
        let tx =
            AcceptedTransaction::accept(tx, &chain_id, max_clock_drift, tx_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx.clone(), tx];
        let valid_block = BlockBuilder::new(transactions)
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
        let domain_id = "wonderland".parse().expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction)
        };
        let mut state_block = state.block();

        // Creating an instruction
        let asset_definition_id = "xor#wonderland"
            .parse::<AssetDefinitionId>()
            .expect("Valid");
        let create_asset_definition =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));

        // Making two transactions that have the same instruction
        let tx = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([create_asset_definition])
            .sign(alice_keypair.private_key());
        let tx =
            AcceptedTransaction::accept(tx, &chain_id, max_clock_drift, tx_limits).expect("Valid");

        let fail_mint = Mint::asset_numeric(
            20u32,
            AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        );

        let succeed_mint =
            Mint::asset_numeric(200u32, AssetId::new(asset_definition_id, alice_id.clone()));

        let tx0 = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions([fail_mint])
            .sign(alice_keypair.private_key());
        let tx0 =
            AcceptedTransaction::accept(tx0, &chain_id, max_clock_drift, tx_limits).expect("Valid");

        let tx2 = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions([succeed_mint])
            .sign(alice_keypair.private_key());
        let tx2 =
            AcceptedTransaction::accept(tx2, &chain_id, max_clock_drift, tx_limits).expect("Valid");

        // Creating a block of two identical transactions and validating it
        let transactions = vec![tx0, tx, tx2];
        let valid_block = BlockBuilder::new(transactions)
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
        let domain_id = "wonderland".parse().expect("Valid");
        let domain = Domain::new(domain_id).build(&alice_id);
        let world = World::with([domain], [account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let (max_clock_drift, tx_limits) = {
            let state_view = state.world.view();
            let params = state_view.parameters();
            (params.sumeragi().max_clock_drift(), params.transaction)
        };
        let mut state_block = state.block();

        let domain_id = "domain".parse().expect("Valid");
        let create_domain = Register::domain(Domain::new(domain_id));
        let asset_definition_id = "coin#domain".parse().expect("Valid");
        let create_asset =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id));
        let fail_isi = Unregister::domain("dummy".parse().unwrap());
        let tx_fail = TransactionBuilder::new(chain_id.clone(), alice_id.clone())
            .with_instructions::<InstructionBox>([create_domain.clone().into(), fail_isi.into()])
            .sign(alice_keypair.private_key());
        let tx_fail = AcceptedTransaction::accept(tx_fail, &chain_id, max_clock_drift, tx_limits)
            .expect("Valid");
        let tx_accept = TransactionBuilder::new(chain_id.clone(), alice_id)
            .with_instructions::<InstructionBox>([create_domain.into(), create_asset.into()])
            .sign(alice_keypair.private_key());
        let tx_accept =
            AcceptedTransaction::accept(tx_accept, &chain_id, max_clock_drift, tx_limits)
                .expect("Valid");

        // Creating a block of where first transaction must fail and second one fully executed
        let transactions = vec![tx_fail, tx_accept];
        let valid_block = BlockBuilder::new(transactions)
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
        let genesis_domain =
            Domain::new(GENESIS_DOMAIN_ID.clone()).build(&genesis_correct_account_id);
        let genesis_wrong_account =
            Account::new(genesis_wrong_account_id.clone()).build(&genesis_wrong_account_id);
        let world = World::with([genesis_domain], [genesis_wrong_account], []);
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new(world, kura, query_handle);
        let mut state_block = state.block();

        // Creating an instruction
        let isi = Log::new(
            iroha_data_model::Level::DEBUG,
            "instruction itself doesn't matter here".to_string(),
        );

        // Create genesis transaction
        // Sign with `genesis_wrong_key` as peer which has incorrect genesis key pair
        // Bypass `accept_genesis` check to allow signing with wrong key
        let tx = TransactionBuilder::new(chain_id.clone(), genesis_wrong_account_id.clone())
            .with_instructions([isi])
            .sign(genesis_wrong_key.private_key());
        let tx = AcceptedTransaction(tx);

        // Create genesis block
        let transactions = vec![tx];
        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let valid_block = BlockBuilder::new(transactions)
            .chain(0, &mut state_block)
            .sign(genesis_correct_key.private_key())
            .unpack(|_| {});

        // Validate genesis block
        // Use correct genesis key and check if transaction is rejected
        let block: SignedBlock = valid_block.into();
        let (_, error) = ValidBlock::validate(
            block,
            &topology,
            &chain_id,
            &genesis_correct_account_id,
            &mut state_block,
        )
        .unpack(|_| {})
        .unwrap_err();

        // The first transaction should be rejected
        assert_eq!(
            error,
            BlockValidationError::InvalidGenesis(InvalidGenesisError::UnexpectedAuthority)
        )
    }
}
