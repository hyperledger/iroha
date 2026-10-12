//! Native certificates anchored in the captured original execution tip.
//!
//! Native source and verifier refusals retain their original local owner through every
//! State-backed read. The walk's fixed coordinates retain the original view's allocation pool.
//! TODO: original source/decoder/cryptographic nested allocations still need complete funding;
//! one charged coordinate array does not account for that separate retained graph.

use super::*;
use iroha_data_model::query::error::QueryExecutionFail;

mod execution_walk;

impl<'v, V: StateReadOnly + ?Sized> CertifiedChain<'v, V> {
    /// Read an ascending interval from this view's original execution authority.
    ///
    /// The starting parent is acquired once through the reverse native ancestry. Each
    /// following source frame is then read once and verified by the same native successor
    /// relation as [`Self::certified_from_execution`]. Only the parent and current receipt
    /// plus bounded fixed original coordinates are retained. Every yielded result matches
    /// its own original coordinate; genesis also waits for H2 to authenticate its result.
    /// The constructor and this entire lazy walk must share one source admission callback
    /// and one inherited allocation scope; returning this iterator does not retain a scope.
    ///
    /// # Errors
    /// Refuses non-State sources, reversed/out-of-view intervals, missing original execution
    /// authority, unavailable or changed ancestry, invalid certificates and resource refusal.
    /// The iterator stops after its first error and never emits a partially verified block.
    pub(crate) fn walk_from_execution<'r>(
        &'r self,
        from: NonZeroUsize,
        to: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>> + 'r,
    ) -> impl Iterator<Item = Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>>> + 'r
    {
        execution_walk::OriginalExecutionWalk::new(self, from, to, before_read)
    }

    /// Authenticate signed genesis after admitting its exact canonical source frame.
    ///
    /// Use the same admission callback and allocation scope for later certificate reads
    /// so genesis cannot escape the request's cumulative source allowance. This performs
    /// no execution authentication: native reads still require the original State tip.
    ///
    /// # Errors
    /// Refuses missing or changed canonical genesis, source/decode resource exhaustion,
    /// and genesis that does not authenticate this State's network and chain instance.
    pub fn new_with_source_admission(
        view: &'v V,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<Self, ExecutionAttemptError<QueryExecutionFail>> {
        let genesis = view.canonical_history().block_with_admission(
            NonZeroUsize::new(GENESIS_HEIGHT as usize).expect("genesis height is nonzero"),
            before_read,
        )?;
        Self::from_genesis(ChainSource::State(view), genesis).map_err(|error| {
            error.map_rejection(|error| QueryExecutionFail::Conversion(error.to_string()))
        })
    }

    /// Authenticate a local certificate through this view's original execution tip.
    ///
    /// The exact parent and target are authenticated by the reverse native hash/result
    /// chain. The parent's executed schedule then supplies the target's authority and
    /// parameters. Exact BLS quorum and signed availability checks still run; the default
    /// verifier requires the exact native BLS quorum.
    /// A recent read therefore does not repeatedly decode every block since genesis.
    /// The caller admits each source frame before I/O and retains its allocation scope
    /// across the entire operation. No fresh per-frame decode budget is installed.
    ///
    /// # Errors
    /// Refuses genesis, non-State sources, missing original tip authority, exhausted
    /// source admission, changed execution ancestry or invalid native certificates.
    pub fn certified_from_execution(
        &self,
        height: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<CertifiedBlock, ExecutionAttemptError<QueryExecutionFail>> {
        let invalid = |message: String| {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message))
        };
        let ChainSource::State(view) = &self.source else {
            return Err(invalid(
                "certificate read requires original State authority".into(),
            ));
        };
        let parent_height = height
            .get()
            .checked_sub(1)
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| invalid("genesis alone has no native CommitQC".into()))?;
        let mut parent = None;
        let mut current = None;
        view.canonical_history().visit_executed_backwards(
            parent_height,
            height,
            before_read,
            |receipt| {
                if receipt.height() == height.get() as u64 {
                    current = Some(receipt);
                } else {
                    parent = Some(receipt);
                }
                Ok(())
            },
        )?;
        let parent = parent.ok_or_else(|| invalid("authenticated parent is absent".into()))?;
        let current = current.ok_or_else(|| invalid("authenticated target is absent".into()))?;
        self.verify_executed_successor(&parent, current)
            .map_err(verification_attempt_failure)
    }

    /// Verify one target and an optional older certificate in one original-tip walk.
    ///
    /// The selector runs only after the target's parent, exact quorum and signed
    /// availability are authenticated. It may select a strictly older non-genesis
    /// height. The same captured source, source-admission callback and allocation
    /// scope cover the whole walk; the ancestry walk never restarts. The constructor's
    /// signed-genesis read remains separately admitted.
    /// An immediately preceding selection reuses the original owned parent receipt.
    ///
    /// # Errors
    /// Rejects unavailable or changed ancestry, invalid certificates, exhausted
    /// source admission, genesis selections and selections at/above the target.
    pub fn certified_with_ancestor_from_execution(
        &self,
        height: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        select: impl FnOnce(&CertifiedBlock) -> Result<Option<NonZeroUsize>, QueryExecutionFail>,
    ) -> Result<(CertifiedBlock, Option<CertifiedBlock>), ExecutionAttemptError<QueryExecutionFail>>
    {
        self.certified_with_ancestor_from_execution_into(
            height,
            before_read,
            select,
            |latest, ancestor| (latest, ancestor),
        )
    }

    /// Transfer the two completed certificates after the original ancestry walk retires.
    ///
    /// The same kernel backs the owned public reader. Its consuming destination runs only
    /// after every original source admission, selected certificate and presence check has
    /// succeeded; it introduces no graph clone, allocation, scope or authority verdict.
    #[inline(never)]
    pub(crate) fn certified_with_ancestor_from_execution_into<Output>(
        &self,
        height: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        select: impl FnOnce(&CertifiedBlock) -> Result<Option<NonZeroUsize>, QueryExecutionFail>,
        finish: impl FnOnce(CertifiedBlock, Option<CertifiedBlock>) -> Output,
    ) -> Result<Output, ExecutionAttemptError<QueryExecutionFail>> {
        let invalid = |message: &str| {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message.into()))
        };
        if height.get() == 1 {
            return Err(invalid("genesis alone has no native CommitQC"));
        }
        let ChainSource::State(view) = &self.source else {
            return Err(invalid(
                "certificate read requires original State authority",
            ));
        };
        let mut select = Some(select);
        let mut target_height = height.get() as u64;
        let mut target = None;
        let mut latest = None;
        let mut ancestor = None;
        view.canonical_history().visit_executed_backwards_until(
            NonZeroUsize::new(1).expect("genesis height is nonzero"),
            height,
            before_read,
            |receipt| {
                if let Some(current) = target.take() {
                    let certified = self
                        .verify_executed_successor(&receipt, current)
                        .map_err(verification_attempt_failure)?;
                    if let Some(select) = select.take() {
                        let selected = select(&certified)?;
                        latest = Some(certified);
                        let Some(selected) = selected else {
                            return Ok(core::ops::ControlFlow::Break(()));
                        };
                        if selected.get() <= 1 || selected >= height {
                            return Err(invalid(
                                "selected ancestor must precede the target and follow genesis",
                            ));
                        }
                        target_height = selected.get() as u64;
                    } else {
                        ancestor = Some(certified);
                        return Ok(core::ops::ControlFlow::Break(()));
                    }
                }
                if receipt.height() == target_height {
                    target = Some(receipt);
                }
                Ok(core::ops::ControlFlow::Continue(()))
            },
        )?;
        let latest = latest.ok_or_else(|| invalid("authenticated target is absent"))?;
        if select.is_none() && target_height != height.get() as u64 && ancestor.is_none() {
            return Err(invalid("authenticated selected ancestor is absent"));
        }
        Ok(finish(latest, ancestor))
    }

    fn executed_successor_authority(
        &self,
        parent: &CommittedBlock,
        current: &CommittedBlock,
    ) -> Result<(VerifiedAuthority, iroha_sumeragi::types::HeightConfig), VerificationReadError>
    {
        executed_successor_authority(parent, current)
    }

    pub(super) fn verify_executed_successor(
        &self,
        parent: &CommittedBlock,
        current: CommittedBlock,
    ) -> Result<CertifiedBlock, VerificationReadError> {
        self.verification_context()
            .verify_executed_successor(parent, current)
    }
}

// Both State-view readers and the event-only source adapter use this same successor
// relation. The context is private and comes from actual authenticated signed genesis;
// no caller-supplied committee, result, or checkpoint can construct certificate authority.
impl PrefixVerifierContext {
    pub(super) fn verify_executed_successor(
        &self,
        parent: &CommittedBlock,
        current: CommittedBlock,
    ) -> Result<CertifiedBlock, VerificationReadError> {
        let certificate = self.prepare_executed_successor(parent, &current)?;
        Ok(certificate.into_certified(current))
    }

    // The same complete certificate, availability and boundary relation can borrow
    // original admitted receipts when its consumer only needs their original QC bytes.
    fn prepare_executed_successor(
        &self,
        parent: &CommittedBlock,
        current: &CommittedBlock,
    ) -> Result<CertificateVerdict, VerificationReadError> {
        check_result_scope(parent, self.root_scope)?;
        check_result_scope(current, self.root_scope)?;
        let (authority, config) = executed_successor_authority(parent, current)?;
        let certificate = self.prepare_certificate_with_scratch_admission(
            current,
            &authority,
            Some(&config),
            None,
            &mut query_scratch_admission,
        )?;
        verify_boundary_source(current, parent, &authority)?;
        Ok(certificate)
    }
}

fn executed_successor_authority(
    parent: &CommittedBlock,
    current: &CommittedBlock,
) -> Result<(VerifiedAuthority, iroha_sumeragi::types::HeightConfig), VerificationReadError> {
    let height = current.height();
    let malformed = |reason: String| ChainReadError::Committee { height, reason };
    if !current.extends(parent) {
        return Err(ChainReadError::Discontinuous { height }.into());
    }
    parent
        .commitment()
        .schedule
        .validate_successor(&current.commitment().schedule)
        .map_err(|error| malformed(error.to_string()))?;
    let schedule::ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        return Err(malformed("parent has no authorized successor".into()).into());
    };
    let mut validation = EpochValidationScope::new();
    let config = scheduled
        .height_config_with_validation(&mut validation)
        .map_err(|error| malformed(error.to_string()))?;
    // Resource admission precedes the boolean signature relation and keeps
    // the original inherited cumulative allowance. No refusal is converted
    // to an invalid certificate or hidden in a new per-frame scope.
    let scratch = iroha_crypto::bls::consensus::ConsensusAggregateScratch::new(|bytes| {
        #[cfg(all(test, sumeragi_core_mutation = "HC13"))]
        {
            let _ = bytes;
            Ok(())
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC13")))]
        query_scratch_admission(bytes)
    })
    .map_err(VerificationReadError::Resource)?;
    let authority = VerifiedAuthority::with_crypto(
        scheduled.epoch.clone(),
        height,
        BlsCrypto::with_aggregate_scratch(scratch),
        &mut validation,
    )?;
    Ok((authority, config))
}

/// Charge the inherited request allowance before allocating verification scratch.
pub(super) fn query_scratch_admission(
    bytes: usize,
) -> Result<(), norito::core::DecodeResourceError> {
    #[cfg(all(test, sumeragi_core_mutation = "HC10"))]
    {
        let _ = bytes;
        return Ok(());
    }
    #[cfg(not(all(test, sumeragi_core_mutation = "HC10")))]
    norito::core::reserve_decode_allocation(bytes).map_err(|error| {
        error
            .decode_resource_error()
            .expect("allocation admission is a resource error")
    })
}

// Resource locality was established by the verifier's original scratch admission or
// codec producer. Do not rediscover it from the projected QueryExecutionFail.
pub(super) fn verification_attempt_failure(
    error: VerificationReadError,
) -> ExecutionAttemptError<QueryExecutionFail> {
    match error {
        VerificationReadError::Resource(error) => {
            let reason = match error {
                norito::core::DecodeResourceError::AllocationFailed { .. } => {
                    ivm::error::ExecutionDeferral::AllocationUnavailable
                }
                _ => ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
            };
            ExecutionAttemptError::Deferred(reason.into())
        }
        VerificationReadError::Deferred(original) => ExecutionAttemptError::Deferred(original),
        VerificationReadError::Source(error) => {
            ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(error.to_string()))
        }
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };

    fn pair_chain() -> CertifiedTestChain {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("genuine State-tip fixture");
        for _ in 0..4 {
            chain.commit(Vec::new());
        }
        chain
    }

    #[test]
    fn admitted_parent_pair_retains_exact_original_slots_and_refunds_on_unwind() {
        use std::alloc::Layout;

        let chain = pair_chain();
        let view = chain.state().view();
        let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
        let budget = chain.state().ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let slot_bytes = Layout::array::<CommittedBlock>(1).unwrap().size();
        let shell_bytes = iroha_data_model::block::SharedSignedBlock::allocation_layout().size();
        let original = reader
            .executed_parent_pair_with_finish(
                NonZeroUsize::new(3).unwrap(),
                |_, _| Ok(()),
                |parent, current| {
                    assert!(parent.belongs_to(&budget) && current.belongs_to(&budget));
                    assert_eq!(
                        (parent.slot_bytes(), current.slot_bytes()),
                        (slot_bytes, slot_bytes)
                    );
                    assert!(
                        parent.block().belongs_to(&budget) && current.block().belongs_to(&budget)
                    );
                    assert_eq!(
                        budget.reserved_bytes(),
                        baseline + 2 * (slot_bytes + shell_bytes),
                        "only the two exact receipt slots and their original block shells remain"
                    );
                    Ok(current.block().clone())
                },
            )
            .unwrap();
        assert_eq!(budget.reserved_bytes(), baseline + shell_bytes);
        drop(original);
        assert_eq!(budget.reserved_bytes(), baseline);

        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reader.executed_parent_pair_with_finish(
                NonZeroUsize::new(3).unwrap(),
                |_, _| Ok(()),
                |parent, current| -> Result<(), ParentServiceError> {
                    assert!(parent.belongs_to(&budget) && current.belongs_to(&budget));
                    assert_eq!(
                        budget.reserved_bytes(),
                        baseline + 2 * (slot_bytes + shell_bytes)
                    );
                    panic!("interrupt original admitted parent completion");
                },
            );
        }));
        assert!(interrupted.is_err());
        assert_eq!(budget.reserved_bytes(), baseline);
        assert!(
            reader
                .parent_service_proposal_original(
                    &chain
                        .kura()
                        .get_block(NonZeroUsize::new(5).unwrap(), &budget)
                        .unwrap()
                        .unwrap()
                )
                .is_ok(),
            "the original source and pool remain usable after unwinding"
        );
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn admitted_receipt_refusal_preserves_original_pool_source_and_exact_retry() {
        use std::alloc::Layout;

        let chain = pair_chain();
        let budget = chain.state().ivm_execution_budget();
        let block = chain
            .kura()
            .get_block(NonZeroUsize::new(3).unwrap(), &budget)
            .unwrap()
            .unwrap();
        let original = block.clone();
        let baseline = budget.reserved_bytes();
        let slot_bytes = Layout::array::<CommittedBlock>(1).unwrap().size();
        let occupied_bytes = budget
            .limit_bytes()
            .checked_sub(baseline + slot_bytes - 1)
            .unwrap();
        let occupied = budget.try_reserve_bytes(occupied_bytes).unwrap();
        let expected: ExecutionDeferred = budget.try_reserve_bytes(slot_bytes).unwrap_err().into();
        let mut validation = EpochValidationScope::new();
        let refused = AdmittedCommittedBlock::read(block.clone(), 3, &mut validation, &budget);
        let Err(ExecutionAttemptError::Deferred(actual)) = refused else {
            panic!("the exact original receipt slot must refuse before decoding")
        };
        assert_eq!(actual, expected);
        assert_eq!(budget.reserved_bytes(), baseline + occupied_bytes);
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &block, &original
        ));
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), baseline);
        let receipt = AdmittedCommittedBlock::read(block.clone(), 3, &mut validation, &budget)
            .expect("retry uses the original source and released original pool");
        assert!(receipt.belongs_to(&budget));
        assert_eq!(receipt.slot_bytes(), slot_bytes);
        assert_eq!(
            budget.reserved_bytes(),
            baseline + slot_bytes,
            "the temporary result slot retires after transfer into the original receipt"
        );
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            receipt.block(),
            &original
        ));
        let owned = receipt.into_owned();
        assert_eq!(
            budget.reserved_bytes(),
            baseline,
            "consuming the original receipt reclaims its empty backing before refund"
        );
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            owned.block(),
            &original
        ));
        assert_eq!(owned.height(), 3);
        drop(owned);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn admitted_result_slot_refusal_releases_receipt_and_retries_original_frame() {
        use std::alloc::Layout;

        let chain = pair_chain();
        let budget = chain.state().ivm_execution_budget();
        let block = chain
            .kura()
            .get_block(NonZeroUsize::new(3).unwrap(), &budget)
            .unwrap()
            .unwrap();
        let baseline = budget.reserved_bytes();
        let receipt_bytes = Layout::array::<CommittedBlock>(1).unwrap().size();
        let result_bytes = Layout::array::<CertifiedResultV1>(1).unwrap().size();
        let occupied_bytes = budget
            .limit_bytes()
            .checked_sub(baseline + receipt_bytes + result_bytes - 1)
            .unwrap();
        let occupied = budget.try_reserve_bytes(occupied_bytes).unwrap();
        let expected = budget
            .try_reserve_bytes(receipt_bytes + result_bytes)
            .unwrap_err();
        let iroha_allocation::AllocationRefusal::Capacity {
            release: expected_release,
            ..
        } = expected
        else {
            panic!("the unchanged original pool has temporary capacity occupied")
        };
        let mut validation = EpochValidationScope::new();
        let refused = AdmittedCommittedBlock::read(block.clone(), 3, &mut validation, &budget);
        let Err(ExecutionAttemptError::Deferred(actual)) = refused else {
            panic!("the complete result slot must refuse before its decoder starts")
        };
        let Some(iroha_allocation::AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = actual.allocation_refusal()
        else {
            panic!("retain the actual original result allocation refusal")
        };
        assert_eq!(*requested_bytes, result_bytes);
        assert_eq!(*reserved_bytes, baseline + occupied_bytes + receipt_bytes);
        assert_eq!(*limit_bytes, budget.limit_bytes());
        assert_eq!(
            release, &expected_release,
            "result refusal retains the original pre-reclamation release observation"
        );
        assert_eq!(
            budget.reserved_bytes(),
            baseline + occupied_bytes,
            "the still-empty receipt backing retires when its result slot refuses"
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), baseline);
        let receipt =
            AdmittedCommittedBlock::read(block.clone(), 3, &mut validation, &budget).unwrap();
        assert!(receipt.belongs_to(&budget));
        assert_eq!(budget.reserved_bytes(), baseline + receipt_bytes);
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            receipt.block(),
            &block
        ));
        drop(receipt);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    fn pair_identity<V: StateReadOnly + ?Sized>(
        reader: &CertifiedChain<'_, V>,
        target: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<(Hash32, Hash32), ParentServiceError> {
        reader
            .executed_parent_pair(target, before_read)
            .map(|(parent, current)| (parent.core_hash(), current.core_hash()))
    }

    #[test]
    fn parent_pair_completion_preserves_full_tip_walk_and_value_reader_parity() {
        let chain = pair_chain();
        let view = chain.state().view();
        let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
        let target = NonZeroUsize::new(3).unwrap();
        let mut original_charges = Vec::new();
        let (original, original_counts) = relation_counts::measure(|| {
            pair_identity(&reader, target, |work, bytes| {
                original_charges.push((work, bytes));
                Ok(())
            })
        });
        let mut completed_charges = Vec::new();
        let (completed, completed_counts) = relation_counts::measure(|| {
            reader.executed_parent_pair_with_finish(
                target,
                |work, bytes| {
                    completed_charges.push((work, bytes));
                    Ok(())
                },
                |parent, current| {
                    assert_eq!((parent.height(), current.height()), (2, 3));
                    Ok((parent.core_hash(), current.core_hash()))
                },
            )
        });
        assert_eq!(completed.unwrap(), original.unwrap());
        assert_eq!(original_counts.frames, [5, 4, 3, 2]);
        assert_eq!(completed_counts.frames, original_counts.frames);
        assert!(original_counts.qcs.is_empty() && completed_counts.qcs.is_empty());
        assert_eq!(completed_charges, original_charges);
        assert_eq!(completed_charges.len(), 4);
    }

    #[test]
    fn parent_pair_completion_preserves_each_source_refusal_without_invoking_finish() {
        let chain = pair_chain();
        let view = chain.state().view();
        let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
        let target = NonZeroUsize::new(3).unwrap();
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal: ExecutionDeferred = budget.try_reserve_bytes(1).unwrap_err().into();
        for refused_at in 0..4 {
            let mut original_reads = 0;
            let original = pair_identity(&reader, target, |_, _| {
                let index = original_reads;
                original_reads += 1;
                if index == refused_at {
                    Err(ExecutionAttemptError::Deferred(refusal.clone()))
                } else {
                    Ok(())
                }
            });
            let mut completed_reads = 0;
            let mut invoked = false;
            let (completed, counts) = relation_counts::measure(|| {
                reader.executed_parent_pair_with_finish(
                    target,
                    |_, _| {
                        let index = completed_reads;
                        completed_reads += 1;
                        if index == refused_at {
                            Err(ExecutionAttemptError::Deferred(refusal.clone()))
                        } else {
                            Ok(())
                        }
                    },
                    |_, _| {
                        invoked = true;
                        Ok(())
                    },
                )
            });
            assert_eq!(completed_reads, original_reads);
            assert_eq!(completed_reads, refused_at + 1);
            assert_eq!(counts.frames.len(), refused_at);
            assert!(counts.qcs.is_empty());
            assert!(!invoked);
            let Err(ParentServiceError::Deferred(original)) = original else {
                panic!("original source refusal")
            };
            let Err(ParentServiceError::Deferred(completed)) = completed else {
                panic!("completion source refusal")
            };
            assert_eq!(completed, original);
            assert_eq!(completed, refusal);

            let mut original_reads = 0;
            let original = pair_identity(&reader, target, |_, _| {
                let index = original_reads;
                original_reads += 1;
                if index == refused_at {
                    Err(ExecutionAttemptError::Rejected(
                        QueryExecutionFail::GasBudgetExceeded,
                    ))
                } else {
                    Ok(())
                }
            });
            let mut completed_reads = 0;
            let mut invoked = false;
            let (completed, counts) = relation_counts::measure(|| {
                reader.executed_parent_pair_with_finish(
                    target,
                    |_, _| {
                        let index = completed_reads;
                        completed_reads += 1;
                        if index == refused_at {
                            Err(ExecutionAttemptError::Rejected(
                                QueryExecutionFail::GasBudgetExceeded,
                            ))
                        } else {
                            Ok(())
                        }
                    },
                    |_, _| {
                        invoked = true;
                        Ok(())
                    },
                )
            });
            assert_eq!(completed_reads, original_reads);
            assert_eq!(completed_reads, refused_at + 1);
            assert_eq!(counts.frames.len(), refused_at);
            assert!(counts.qcs.is_empty());
            assert!(!invoked);
            let Err(ParentServiceError::Source(original)) = original else {
                panic!("original source rejection")
            };
            let Err(ParentServiceError::Source(completed)) = completed else {
                panic!("completion source rejection")
            };
            assert_eq!(original, QueryExecutionFail::GasBudgetExceeded);
            assert_eq!(completed, original);
        }
        assert_eq!(budget.reserved_bytes(), 1);
        drop(occupied);
        assert!(budget.try_reserve_bytes(1).is_ok());
    }

    #[test]
    fn parent_pair_completion_releases_receipts_after_transferring_exact_source_owner() {
        let chain = pair_chain();
        let view = chain.state().view();
        let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
        let budget = chain.state().ivm_execution_budget();
        let baseline = budget.reserved_bytes();
        let original = reader
            .executed_parent_pair_with_finish(
                NonZeroUsize::new(3).unwrap(),
                |_, _| Ok(()),
                |parent, current| {
                    assert!(parent.block().belongs_to(&budget));
                    let original = current.block().clone();
                    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                        &original,
                        current.block(),
                    ));
                    Ok(original)
                },
            )
            .unwrap();
        assert!(original.belongs_to(&budget));
        assert_eq!(
            budget.reserved_bytes(),
            baseline + iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
            "all source and receipt owners except the exact transferred current block retire"
        );
        drop(original);
        assert_eq!(budget.reserved_bytes(), baseline);
    }

    #[test]
    fn parent_proposal_completion_retries_original_decoder_refusal_and_copies_exact_qc() {
        let chain = pair_chain();
        let view = chain.state().view();
        let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
        let parent = chain
            .kura()
            .get_block(
                NonZeroUsize::new(5).unwrap(),
                &chain.state().ivm_execution_budget(),
            )
            .unwrap()
            .unwrap();
        let refused = norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
            || reader.parent_service_proposal_original(&parent),
        );
        assert!(matches!(refused, Err(ParentServiceError::Deferred(_))));
        let (original, counts) =
            relation_counts::measure(|| reader.parent_service_proposal_original(&parent).unwrap());
        assert_eq!(original, parent.commit_certificate().unwrap().commit_qc());
        assert_eq!(counts.frames, [5, 4]);
        assert_eq!(counts.qcs, [5]);
    }

    #[test]
    fn parent_service_verification_retains_original_allocation_release_owner() {
        let budget = iroha_allocation::AllocationBudget::new(1);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let expected: ExecutionDeferred = refusal.clone().into();
        let error = parent_verification_source(VerificationReadError::Deferred(refusal.into()));
        assert!(matches!(error, ParentServiceError::Deferred(actual) if actual == expected));
        assert_eq!(budget.reserved_bytes(), 1);
        drop(occupied);
        let retry = budget
            .try_reserve_bytes(1)
            .expect("the original pool admits a retry after release");
        assert_eq!(budget.reserved_bytes(), 1);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn state_certificate_maps_local_scratch_refusal_without_source_invalidity() {
        let error = VerificationReadError::Resource(
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: 17,
                limit: 16,
            },
        );
        assert_eq!(
            verification_attempt_failure(error),
            ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into()
            )
        );
    }
}

/// A local original-source refusal or an invalid consensus-carried parent proof.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ParentServiceError {
    #[error("invalid parent service proof: {0}")]
    Invalid(String),
    #[error("parent service original source is unavailable: {0}")]
    Source(QueryExecutionFail),
    #[error("parent service authentication deferred: {0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
}

/// An authenticated, proposal-bound parent participation decision.
/// Only the original State-tip reader constructs it; it has no wire constructor.
pub(crate) struct VerifiedParentService {
    proposal: HashOf<IrohaHeader>,
    height: u64,
    timestamp_ms: u64,
    signers: Vec<iroha_model_base::peer::PeerId>,
}

impl VerifiedParentService {
    pub(crate) fn require_proposal(
        &self,
        proposal: &SignedBlock,
    ) -> Result<(), ParentServiceError> {
        if self.proposal != proposal.hash()
            || self.height.checked_add(1) != Some(proposal.header().height().get())
        {
            return Err(ParentServiceError::Invalid(
                "verified participation belongs to another proposal".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn height(&self) -> u64 {
        self.height
    }

    pub(crate) fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub(crate) fn signers(&self) -> &[iroha_model_base::peer::PeerId] {
        &self.signers
    }
}

fn parent_source_failure(error: impl std::fmt::Display) -> ParentServiceError {
    ParentServiceError::Source(QueryExecutionFail::Conversion(error.to_string()))
}

fn parent_proof_decode_failure(error: norito::Error) -> ParentServiceError {
    match crate::execution_attempt::norito_decode_attempt_error(error, |error| error.to_string()) {
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            ParentServiceError::Deferred(reason)
        }
        crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
            ParentServiceError::Invalid(reason)
        }
    }
}

fn parent_source_attempt(
    error: crate::execution_attempt::ExecutionAttemptError<QueryExecutionFail>,
) -> ParentServiceError {
    match error {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
            ParentServiceError::Source(error)
        }
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            ParentServiceError::Deferred(reason)
        }
    }
}

fn parent_verification_source(error: VerificationReadError) -> ParentServiceError {
    match error {
        VerificationReadError::Resource(error) => parent_proof_decode_failure(error.into()),
        VerificationReadError::Deferred(reason) => ParentServiceError::Deferred(reason),
        error => parent_source_failure(error),
    }
}

impl<'v, V: StateReadOnly + ?Sized> CertifiedChain<'v, V> {
    /// Signed genesis source and its resource refusal remain in the same attempt.
    pub(crate) fn new_for_parent_service(view: &'v V) -> Result<Self, ParentServiceError> {
        let genesis = view
            .canonical_history()
            .block_with_admission(NonZeroUsize::new(1).expect("genesis is nonzero"), |_, _| {
                Ok(())
            })
            .map_err(parent_source_attempt)?;
        Self::from_genesis(ChainSource::State(view), genesis).map_err(|error| {
            parent_source_attempt(
                error.map_rejection(|error| QueryExecutionFail::Conversion(error.to_string())),
            )
        })
    }

    #[cfg(test)]
    fn executed_parent_pair(
        &self,
        target: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<(CommittedBlock, CommittedBlock), ParentServiceError> {
        self.executed_parent_pair_with_finish(target, before_read, |parent, current| {
            Ok((parent.into_owned(), current.into_owned()))
        })
    }

    // Retain only two small original-pool owners while the complete ancestry decoder runs.
    // Their exact backing remains charged until completion, rejection or unwinding retires it.
    fn executed_parent_pair_with_finish<Output>(
        &self,
        target: NonZeroUsize,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
        finish: impl FnOnce(
            AdmittedCommittedBlock,
            AdmittedCommittedBlock,
        ) -> Result<Output, ParentServiceError>,
    ) -> Result<Output, ParentServiceError> {
        let predecessor = target
            .get()
            .checked_sub(1)
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| ParentServiceError::Invalid("genesis has no native quorum".into()))?;
        let ChainSource::State(view) = &self.source else {
            return Err(parent_source_failure(
                "parent proof requires original State authority",
            ));
        };
        let mut parent = None;
        let mut current = None;
        view.canonical_history()
            .visit_executed_backwards_admitted_until(predecessor, target, before_read, |receipt| {
                if receipt.height() == target.get() as u64 {
                    current = Some(receipt);
                } else {
                    parent = Some(receipt);
                }
                Ok(core::ops::ControlFlow::Continue(()))
            })
            .map_err(parent_source_attempt)?;
        let parent =
            parent.ok_or_else(|| parent_source_failure("authenticated predecessor absent"))?;
        let current =
            current.ok_or_else(|| parent_source_failure("authenticated parent absent"))?;
        finish(parent, current)
    }

    /// Select one genuinely verified local certificate as a proposal input.
    /// Different valid subsets produce different next proposals; execution must
    /// authenticate the offered bytes and never reread this local certificate.
    pub(crate) fn parent_service_proposal_original(
        &self,
        parent: &SignedBlock,
    ) -> Result<Vec<u8>, ParentServiceError> {
        let height = usize::try_from(parent.header().height().get())
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| {
                ParentServiceError::Invalid("parent height is not addressable".into())
            })?;
        self.executed_parent_pair_with_finish(
            height,
            |_, _| Ok(()),
            |predecessor, original_parent| {
                self.finish_parent_service_proposal_original(parent, &predecessor, &original_parent)
            },
        )
    }

    // Full receipt verification and QC ownership begin after ancestry decoding returns.
    // The predecessor, target, certificate and protocol-bound checks retain their order.
    fn finish_parent_service_proposal_original(
        &self,
        parent: &SignedBlock,
        predecessor: &CommittedBlock,
        original_parent: &CommittedBlock,
    ) -> Result<Vec<u8>, ParentServiceError> {
        let _certificate = self
            .verification_context()
            .prepare_executed_successor(predecessor, original_parent)
            .map_err(parent_verification_source)?;
        if original_parent.block_hash() != parent.hash() {
            return Err(ParentServiceError::Invalid(
                "assembly parent differs from original executed parent".into(),
            ));
        }
        let original = original_parent
            .block()
            .commit_certificate()
            .ok_or_else(|| parent_source_failure("executed parent has no local certificate"))?
            .commit_qc();
        if original.is_empty()
            || original.len() > iroha_data_model::consensus::PARENT_SERVICE_COMMIT_QC_MAX_BYTES
        {
            return Err(ParentServiceError::Invalid(
                "parent service original exceeds the protocol bound".into(),
            ));
        }
        norito::core::reserve_decode_allocation(original.len())
            .map_err(parent_proof_decode_failure)?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(original.len()).map_err(|_| {
            ParentServiceError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        })?;
        owned.extend_from_slice(original);
        Ok(owned)
    }

    /// Authenticate the common parent participation input against the captured
    /// original execution tip. The offered QC supplies no authority or source.
    pub(crate) fn authenticate_parent_service(
        &self,
        proposal: &SignedBlock,
        before_read: impl FnMut(u64, u64) -> Result<(), ExecutionAttemptError<QueryExecutionFail>>,
    ) -> Result<Option<VerifiedParentService>, ParentServiceError> {
        proposal
            .validate_proposal_commitments()
            .map_err(|error| ParentServiceError::Invalid(error.to_string()))?;
        let height = proposal.header().height().get();
        let offered = proposal
            .npos_consensus_effects()
            .and_then(|effects| effects.parent_service_commit_qc.as_deref());
        if height <= 2 {
            if offered.is_some() {
                return Err(ParentServiceError::Invalid(
                    "genesis has no native parent service certificate".into(),
                ));
            }
            return Ok(None);
        }
        let offered = offered.ok_or_else(|| {
            ParentServiceError::Invalid("proposal omits its parent service original".into())
        })?;
        if offered.is_empty()
            || offered.len() > iroha_data_model::consensus::PARENT_SERVICE_COMMIT_QC_MAX_BYTES
        {
            return Err(ParentServiceError::Invalid(
                "parent service original exceeds the protocol bound".into(),
            ));
        }
        let target = usize::try_from(height - 1)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| {
                ParentServiceError::Invalid("parent height is not addressable".into())
            })?;
        self.executed_parent_pair_with_finish(target, before_read, |parent, current| {
            self.verify_parent_service_at(proposal, &parent, &current, offered)
        })
    }

    /// Private relation after an original-tip walk; tests retain genuine executed receipts.
    pub(super) fn verify_parent_service_at(
        &self,
        proposal: &SignedBlock,
        parent: &CommittedBlock,
        current: &CommittedBlock,
        offered: &[u8],
    ) -> Result<Option<VerifiedParentService>, ParentServiceError> {
        if proposal.header().prev_block_hash() != Some(current.block_hash()) {
            return Err(ParentServiceError::Invalid(
                "proposal does not extend the authenticated parent".into(),
            ));
        }
        let qc: Qc = norito::decode_canonical(offered).map_err(parent_proof_decode_failure)?;
        let (authority, _config) = self
            .executed_successor_authority(parent, current)
            .map_err(parent_verification_source)?;
        self.verification_context()
            .verify_commit_qc_original(current, &authority, &qc)
            .map_err(|error| ParentServiceError::Invalid(error.to_string()))?;
        verify_boundary_source(current, parent, &authority).map_err(parent_source_failure)?;
        let committee = &current.commitment().schedule.current.committee;
        let mut signers = Vec::new();
        let count = qc.signers.ones().count();
        let bytes = count
            .checked_mul(std::mem::size_of::<iroha_model_base::peer::PeerId>())
            .ok_or_else(|| ParentServiceError::Invalid("signer count overflow".into()))?;
        norito::core::reserve_decode_allocation(bytes).map_err(parent_proof_decode_failure)?;
        signers.try_reserve_exact(count).map_err(|_| {
            ParentServiceError::Deferred(
                ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
            )
        })?;
        for index in qc.signers.ones() {
            let member = usize::try_from(index)
                .ok()
                .and_then(|index| committee.get(index))
                .ok_or_else(|| {
                    ParentServiceError::Invalid("service signer outside committee".into())
                })?;
            signers.push(member.validator.clone());
        }
        Ok(Some(VerifiedParentService {
            proposal: proposal.hash(),
            height: current.height(),
            timestamp_ms: current.block_time_ms(),
            signers,
        }))
    }
}
