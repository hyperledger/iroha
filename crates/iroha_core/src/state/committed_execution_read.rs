//! Bounded local history reads authenticated by the original native State tip.

use super::*;
use iroha_data_model::query::error::QueryExecutionFail;

impl StateTransaction<'_, '_> {
    /// Authenticate a signed floor from this transaction's original execution anchor.
    /// Local source failures abandon the attempt; they cannot reject or charge its signer.
    /// The limits bound relative ancestry and actual frame bytes, never absolute chain height.
    pub(crate) fn authenticate_musubi_pin_outbox_floor(
        &mut self,
        floor: iroha_data_model::musubi::MusubiPinOutboxCheckFloorV1,
        max_work: u64,
        max_bytes: u64,
    ) -> Result<(), iroha_data_model::isi::error::InstructionExecutionError> {
        use crate::execution_attempt::ExecutionAttemptError;
        use iroha_data_model::isi::error::InstructionExecutionError as Error;
        use ivm::error::ExecutionDeferral;
        let invalid = || Error::InvariantViolation("Musubi pin-outbox Check floor differs".into());
        floor.validate().map_err(|_| invalid())?;
        let height = usize::try_from(floor.height)
            .ok()
            .and_then(NonZeroUsize::new)
            .filter(|_| floor.height < self._curr_block.height().get())
            .ok_or_else(invalid)?;
        if self
            .block_hashes
            .get(height.get() - 1)
            .map(|hash| *hash.as_ref())
            != Some(floor.block_hash)
        {
            return Err(invalid());
        }
        // This owner retains the inherited allocation scope. No per-frame reset can replenish
        // a caller's narrower budget, and the callback charges before source I/O or decode.
        let mut work_left = max_work;
        let mut bytes_left = max_bytes;
        let result = self
            .canonical_history()
            .executed_receipt(height, |work, bytes| {
                let remaining = work_left
                    .checked_sub(work)
                    .zip(bytes_left.checked_sub(bytes));
                if let Some((work, bytes)) = remaining {
                    work_left = work;
                    bytes_left = bytes;
                    Ok(())
                } else {
                    Err(ExecutionAttemptError::Deferred(
                        ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ))
                }
            });
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                let reason = match error {
                    ExecutionAttemptError::Deferred(reason) => reason,
                    ExecutionAttemptError::Rejected(_) => {
                        ExecutionDeferral::CanonicalHistoryUnavailable.into()
                    }
                };
                return Err(self
                    .attempt_error_to_instruction_error(ExecutionAttemptError::Deferred(reason)));
            }
        };
        if receipt.id() != floor.context_id {
            return Err(invalid());
        }
        Ok(())
    }
}

impl State {
    /// Read original committed execution from a consistent native State history cut.
    ///
    /// Only the hash journal and opaque execution tip are retained across I/O. The
    /// reverse ancestry walk authenticates complete execution without depending on
    /// a node's particular QC subset or scanning from genesis for a recent retry.
    /// Every source frame is admitted before I/O; target input/output work also
    /// counts. These finite read limits are not resident-graph allocation reservations.
    ///
    /// # Errors
    /// Refuses zero/exceeded limits, missing native authority, unavailable or corrupt
    /// execution ancestry, and a replaced committed journal binding.
    pub fn read_committed_execution(
        &self,
        height: NonZeroUsize,
        max_work: u64,
        max_bytes: u64,
    ) -> Result<
        crate::sumeragi::certified_chain::CommittedBlock,
        crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
    > {
        if max_work == 0 || max_bytes == 0 {
            return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ));
        }
        let (hashes, tip) = loop {
            let generation = self.state_view_generation();
            if generation % 2 != 0 {
                std::thread::yield_now();
                continue;
            }
            let hashes = self.block_hashes.view();
            let tip = *self.native_execution_tip.view().get();
            if self.state_view_generation() == generation {
                break (hashes, tip);
            }
        };
        let expected = hashes.get(height.get() - 1).copied().ok_or_else(|| {
            QueryExecutionFail::Conversion("committed execution height is unavailable".into())
        })?;
        let source =
            CanonicalHistorySource::new(&self.kura, &hashes, tip, self.ivm_execution_budget());
        let mut work_left = max_work;
        let mut bytes_left = max_bytes;
        let receipt = source.executed_receipt(height, |work, bytes| {
            work_left = work_left.checked_sub(work).ok_or(
                crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            )?;
            bytes_left = bytes_left.checked_sub(bytes).ok_or(
                crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                ),
            )?;
            Ok(())
        })?;
        let target_work = u64::try_from(
            receipt
                .block()
                .network_entrypoint_count()
                .max(receipt.block().execution_outputs().len())
                .max(1),
        )
        .map_err(|_| {
            crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            )
        })?;
        if target_work > work_left {
            return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ));
        }
        if self.block_hashes.view().get(height.get() - 1).copied() != Some(expected) {
            return Err(QueryExecutionFail::Conversion(
                "committed execution changed during authentication".into(),
            )
            .into());
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};

    fn pin_floor(
        chain: &CertifiedTestChain,
        height: u64,
    ) -> iroha_data_model::musubi::MusubiPinOutboxCheckFloorV1 {
        let block = chain.committed(height);
        iroha_data_model::musubi::MusubiPinOutboxCheckFloorV1 {
            height,
            block_hash: *block.block_hash().as_ref(),
            context_id: block.id(),
        }
    }

    #[test]
    fn native_pin_floor_relative_work_and_wire_budget_are_prepaid_exactly() {
        use ivm::error::ExecutionDeferral;
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        for _ in 0..7 {
            chain.commit(Vec::new());
        }
        let floor = pin_floor(&chain, 8);
        let bytes = chain.committed(8).block().encode_wire().unwrap().len() as u64;
        let proposal = chain.proposal(None, Vec::new());
        let mut block = chain.state().block(proposal.header());
        for (work, max_bytes, succeeds) in
            [(1, bytes, true), (0, bytes, false), (1, bytes - 1, false)]
        {
            chain.kura().reset_canonical_query_reads_for_test();
            let mut tx = block.transaction();
            let result = tx.authenticate_musubi_pin_outbox_floor(floor, work, max_bytes);
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert!(!tx.is_execution_deferred());
                assert_eq!(chain.kura().canonical_query_reads_for_test(), (1, bytes));
            } else {
                let refusal = tx.borrow_execution_deferral().unwrap();
                assert_eq!(
                    refusal.reason(),
                    ExecutionDeferral::CanonicalHistoryCapacity
                );
                assert!(refusal.allocation_refusal().is_none());
                assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
            }
        }
        let floor = pin_floor(&chain, 6);
        let bytes = (6..=8)
            .map(|height| chain.committed(height).block().encode_wire().unwrap().len() as u64)
            .sum();
        let mut tx = block.transaction();
        tx.authenticate_musubi_pin_outbox_floor(floor, 3, bytes)
            .unwrap();
    }

    #[test]
    fn native_pin_floor_preserves_inherited_decode_refusal_and_first_allocation_owner() {
        use crate::execution_attempt::ExecutionAttemptError;
        use ivm::error::ExecutionDeferral;
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let floor = pin_floor(&chain, 1);
        let proposal = chain.proposal(None, Vec::new());
        let mut block = chain.state().block(proposal.header());
        let budget = iroha_allocation::AllocationBudget::new(8);
        let occupied = budget.try_reserve_bytes(8).unwrap();
        let original = budget.try_reserve_bytes(1).unwrap_err();
        for sticky in [false, true] {
            let mut tx = block.transaction();
            if sticky {
                tx.attempt_error_to_instruction_error(ExecutionAttemptError::Deferred(
                    original.clone().into(),
                ));
            }
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
            assert!(
                norito::with_decode_limits_scope(limits, || tx
                    .authenticate_musubi_pin_outbox_floor(floor, 1, u64::MAX))
                .is_err()
            );
            let refusal = tx.borrow_execution_deferral().unwrap();
            assert_eq!(refusal.reason(), ExecutionDeferral::ActiveMemoryCapacity);
            assert_eq!(refusal.allocation_refusal(), sticky.then_some(&original));
        }
        let mut tx = block.transaction();
        tx.attempt_error_to_instruction_error(ExecutionAttemptError::Deferred(
            original.clone().into(),
        ));
        assert!(
            tx.authenticate_musubi_pin_outbox_floor(floor, 0, 0)
                .is_err()
        );
        assert_eq!(
            tx.borrow_execution_deferral().unwrap().allocation_refusal(),
            Some(&original)
        );
        drop(tx);
        let mut retry = block.transaction();
        retry
            .authenticate_musubi_pin_outbox_floor(floor, 1, u64::MAX)
            .unwrap();
        drop(occupied);
    }

    #[test]
    fn committed_execution_read_uses_recent_native_tip_under_exact_limits() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        for _ in 0..7 {
            chain.commit(Vec::new());
        }
        let original = chain.committed(8);
        let wire = original.block().encode_wire().unwrap();
        let work = u64::try_from(
            original
                .block()
                .network_entrypoint_count()
                .max(original.block().execution_outputs().len())
                .max(1),
        )
        .unwrap()
            + 1;
        assert!(
            work < chain.height(),
            "budget cannot authenticate a prefix from genesis"
        );
        let height = NonZeroUsize::new(8).unwrap();
        let bytes = u64::try_from(wire.len()).unwrap();
        let receipt = chain
            .state()
            .read_committed_execution(height, work, bytes)
            .unwrap();
        assert_eq!(receipt.block().encode_wire().unwrap(), wire);
        for (work, bytes) in [(work - 1, bytes), (work, bytes - 1), (0, bytes), (work, 0)] {
            let error = chain
                .state()
                .read_committed_execution(height, work, bytes)
                .unwrap_err();
            let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = error else {
                panic!("history allowance refusal cannot become a finalized verdict: {error:?}");
            };
            assert_eq!(
                original.reason(),
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
            );
            assert!(
                original.allocation_refusal().is_none(),
                "logical history limits have no physical release owner"
            );
        }
    }

    #[test]
    fn committed_execution_read_charges_every_reverse_ancestor_and_refuses_corruption() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        for _ in 0..3 {
            chain.commit(Vec::new());
        }
        let height = NonZeroUsize::new(2).unwrap();
        let bytes = (2..=4)
            .map(|height| {
                u64::try_from(chain.committed(height).block().encode_wire().unwrap().len()).unwrap()
            })
            .sum::<u64>();
        let block = chain.committed(2);
        let work = u64::try_from(
            block
                .block()
                .network_entrypoint_count()
                .max(block.block().execution_outputs().len())
                .max(1),
        )
        .unwrap()
            + 3;
        assert!(
            chain
                .state()
                .read_committed_execution(height, work, bytes)
                .is_ok()
        );
        let work_refusal = chain
            .state()
            .read_committed_execution(height, work - 1, bytes)
            .unwrap_err();
        {
            let crate::execution_attempt::ExecutionAttemptError::Deferred(actual) = work_refusal
            else {
                panic!("local refusal cannot become a completed verdict")
            };
            assert_eq!(
                actual.reason(),
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
            );
            assert_eq!(actual.phase(), None);
            assert!(actual.allocation_refusal().is_none());
            assert!(actual.decode_refusal().is_none());
            assert!(actual.verification_refusal().is_none());
        };
        let byte_refusal = chain
            .state()
            .read_committed_execution(height, work, bytes - 1)
            .unwrap_err();
        let crate::execution_attempt::ExecutionAttemptError::Deferred(original) = byte_refusal
        else {
            panic!("source byte refusal cannot become a finalized verdict: {byte_refusal:?}");
        };
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
        );
        assert!(original.allocation_refusal().is_none());
        chain
            .kura()
            .corrupt_canonical_body_for_testing(NonZeroUsize::new(3).unwrap())
            .unwrap();
        assert!(
            chain
                .state()
                .read_committed_execution(height, work, bytes)
                .is_err()
        );
    }

    #[test]
    fn committed_execution_read_hash_journal_cannot_replace_original_tip_authority() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let kura = Kura::blank_kura_for_testing();
        let mut state = State::new_with_chain_and_network_id_for_testing(
            World::new(),
            kura.clone(),
            crate::query::store::LiveQueryStore::start_test(),
            "sumeragi-certified-test-chain".parse().unwrap(),
            chain.network_id(),
        );
        for height in 1..=2 {
            let block = chain.committed(height).block().clone();
            kura.store_block(block.clone()).unwrap();
            state.push_block_hash_for_testing(block.hash());
        }
        assert!(
            state
                .read_committed_execution(NonZeroUsize::new(2).unwrap(), 100, 8 * 1024 * 1024)
                .is_err()
        );
    }
}
