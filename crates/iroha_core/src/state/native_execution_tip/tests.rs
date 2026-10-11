//! Native owner, funded MV custody, deterministic history and restore assertions.
use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig};

fn chain() -> CertifiedTestChain {
    CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap()
}

#[test]
fn original_genesis_and_worker_publish_exact_tip_with_undo() {
    let mut chain = chain();
    let old_view = chain.state().view();
    let genesis = old_view.native_execution_tip().unwrap();
    let genesis_receipt = crate::sumeragi::certified_chain::committed_block(&old_view, 1).unwrap();
    assert_eq!(genesis.core_hash(), genesis_receipt.core_hash());
    assert_eq!(genesis.result(), genesis_receipt.result());
    assert_eq!(*old_view.native_execution_tip_predecessor.get(), Some(None));
    let state = Arc::clone(chain.state());
    // Release the chain borrow while retaining the actual old EBR cut through State.
    drop(old_view);
    let old_view = state.view();
    chain.commit(Vec::new());
    let view = state.view();
    let current = view.native_execution_tip().unwrap();
    let receipt = chain.committed(2);
    assert_eq!(current.height(), 2);
    assert_eq!(current.iroha_hash(), receipt.block_hash());
    assert_eq!(current.core_hash(), receipt.core_hash());
    assert_eq!(current.result(), receipt.result());
    assert_eq!(
        *view.native_execution_tip_predecessor.get(),
        Some(Some(genesis))
    );
    assert_eq!(old_view.native_execution_tip(), Some(genesis));
    assert_eq!(old_view.height(), 1);
}

#[test]
fn rejected_original_preparation_and_discard_preserve_committed_tip() {
    let mut chain = chain();
    let state = Arc::clone(chain.state());
    let before = state.view().native_execution_tip();
    let proposal = chain.proposal(None, Vec::new());
    let mut original = chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap();
    assert_eq!(
        original
            .inspect(|owner| owner.state.native_execution_tip())
            .unwrap(),
        before
    );
    assert!(original.prepare(Signers::BelowQuorum).is_err());
    assert_eq!(state.view().native_execution_tip(), before);
    drop(original);
    assert_eq!(state.view().native_execution_tip(), before);
    chain.commit(Vec::new());
    assert_eq!(state.view().native_execution_tip().unwrap().height(), 2);
}

#[test]
fn replacement_reads_exact_tip_undo_and_abandonment_restores_original_cut() {
    let mut chain = chain();
    let previous = chain.state().view().native_execution_tip();
    chain.commit(Vec::new());
    let current = chain.state().view().native_execution_tip();
    let header = chain.committed(2).block().header();
    let mut replacement = chain.state().block_and_revert(header);
    assert_eq!(replacement.native_execution_tip(), previous);
    assert_eq!(replacement.transaction().native_execution_tip(), previous);
    drop(replacement);
    assert_eq!(chain.state().view().native_execution_tip(), current);
}

#[test]
fn execution_history_admits_each_actual_source_before_read() {
    let mut chain = chain();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let view = chain.state().view();
    let mut admitted = Vec::new();
    let genesis = view
        .canonical_history()
        .executed_block(NonZeroUsize::MIN, |count, bytes| {
            admitted.push((count, bytes));
            Ok(())
        })
        .unwrap();
    assert_eq!(genesis.hash(), chain.genesis().hash());
    assert_eq!(admitted.len(), 3);
    assert!(
        admitted
            .iter()
            .all(|&(count, bytes)| count == 1 && bytes > 0)
    );
    let mut attempts = 0;
    assert!(
        view.canonical_history()
            .executed_block(NonZeroUsize::MIN, |_, _| {
                attempts += 1;
                if attempts == 2 {
                    Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                        ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
                    ))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    assert_eq!(attempts, 2);
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
    assert!(
        view.canonical_history()
            .executed_block(NonZeroUsize::MIN, |_, _| Ok(()))
            .is_err()
    );
}

fn snapshot_claim(state: &State) -> NativeExecutionTipSnapshot {
    let view = state.view();
    let claim = NativeExecutionTipSnapshot::from_original(
        *view.native_execution_tip.get(),
        *view.native_execution_tip_predecessor.get(),
    );
    norito::json::from_str(&norito::json::to_json(&claim).unwrap()).unwrap()
}

#[test]
fn restore_reauthenticates_native_current_and_undo_and_rejects_claim_substitution() {
    let mut chain = chain();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    let restore = |claim: NativeExecutionTipSnapshot| {
        claim.restore(
            &chain.state().ivm_execution_budget(),
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
    };
    let restored = restore(snapshot_claim(chain.state())).unwrap();
    assert_eq!(*restored.view().get(), view.native_execution_tip());
    assert_eq!(
        *restored.predecessor_view().get(),
        *view.native_execution_tip_predecessor.get()
    );
    let mut wrong_result = snapshot_claim(chain.state());
    wrong_result.blocks.as_mut().unwrap().result[0] ^= 1;
    assert!(restore(wrong_result).is_err());
    let mut wrong_undo = snapshot_claim(chain.state());
    wrong_undo
        .revert
        .as_mut()
        .unwrap()
        .value
        .as_mut()
        .unwrap()
        .core_hash[0] ^= 1;
    assert!(restore(wrong_undo).is_err());
    assert!(
        snapshot_claim(chain.state())
            .restore(
                &chain.state().ivm_execution_budget(),
                &"another-native-instance".parse().unwrap(),
                view.network_id(),
                &hashes,
                chain.kura(),
            )
            .is_err()
    );
}

#[test]
fn restore_rebuilds_sparse_history_checkpoints_from_verified_snapshot_prefix() {
    use crate::kura::history_checkpoints::HISTORY_CHECKPOINT_INTERVAL;

    let mut chain = chain();
    let checkpoint_height = HISTORY_CHECKPOINT_INTERVAL;
    let tip_height = checkpoint_height + 2;
    for _ in 1..tip_height {
        chain.commit(Vec::new());
    }
    let checkpoint = checkpoint_of(record(&chain.committed(checkpoint_height)));
    let target_height = checkpoint_height - 1;
    let target_hash = chain.committed(target_height).block_hash();
    let claim = snapshot_claim(chain.state());
    let view = chain.state().view();
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    let checkpoints = chain.kura().history_checkpoints();
    // A restart has the authenticated journal and decoded snapshot, but no
    // node-local checkpoints retained from the original executions.
    checkpoints.clear();
    assert!(checkpoints.candidates(1, tip_height).is_empty());
    let restored = claim
        .restore(
            &chain.state().ivm_execution_budget(),
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
        .unwrap();
    assert_eq!(*restored.view().get(), view.native_execution_tip());
    assert_eq!(
        *restored.predecessor_view().get(),
        *view.native_execution_tip_predecessor.get()
    );
    assert_eq!(checkpoints.sparse_len(), 1);
    assert_eq!(
        checkpoints.recent_len(),
        0,
        "restore retains only sparse identities"
    );
    assert!(
        checkpoints
            .candidates(1, tip_height)
            .iter()
            .copied()
            .eq([(checkpoint_height, checkpoint)])
    );

    let target = NonZeroUsize::new(usize::try_from(target_height).unwrap()).unwrap();
    let mut source_reads = 0;
    let mut visited = Vec::new();
    view.canonical_history()
        .visit_executed_backwards_from_checkpoints(
            target,
            target,
            |count, _| {
                source_reads += count;
                Ok(())
            },
            |block| {
                visited.push(block.block_hash());
                Ok(core::ops::ControlFlow::Continue(()))
            },
        )
        .unwrap();
    assert_eq!(
        source_reads, 2,
        "the restored checkpoint bounds the cold read"
    );
    assert_eq!(visited, [target_hash]);
}

#[test]
fn genesis_only_snapshot_cannot_decode_its_unsigned_result_into_authority() {
    let chain = chain();
    let view = chain.state().view();
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    assert!(
        snapshot_claim(chain.state())
            .restore(
                &chain.state().ivm_execution_budget(),
                view.chain_id(),
                view.network_id(),
                &hashes,
                chain.kura(),
            )
            .is_err()
    );
}

#[test]
fn funded_tip_admission_is_atomic_and_original_pool_bound() {
    use mv::BlockAcquisition as _;
    let initial_bytes =
        mv::cell::CellInitialization::<Option<NativeExecutionTip>>::allocation_layouts()
            .iter()
            .map(std::alloc::Layout::size)
            .sum::<usize>();
    let too_small = AllocationBudget::new(initial_bytes - 1);
    assert!(empty_cell(&too_small).is_err());
    assert_eq!(too_small.reserved_bytes(), 0);
    let budget = AllocationBudget::new(64 * 1024);
    let cell = empty_cell(&budget).unwrap();
    let before = budget.reserved_bytes();
    let successor = mv::cell::CellPublicationSuccessor::allocation_layout();
    let foreign = AllocationBudget::new(64 * 1024);
    let mut wrong_parent = foreign.try_reserve_layouts([successor]).unwrap();
    assert!(original_cell(&cell, &budget, &mut wrong_parent).is_err());
    assert_eq!(budget.reserved_bytes(), before);
    let mut parent = budget.try_reserve_layouts([successor]).unwrap();
    let mut original = original_cell(&cell, &budget, &mut parent).unwrap();
    assert_eq!(parent.remaining_bytes(), 0);
    original.initialize(mv::BlockMode::Ordinary);
    drop(original);
    assert_eq!(*cell.view().get(), None);
}

#[test]
fn snapshot_json_preserves_genesis_undo_absence_distinction() {
    let chain = chain();
    let view = chain.state().view();
    let claim = snapshot_claim(chain.state());
    assert!(claim.matches_original(view.native_execution_tip(), Some(None)));
    assert!(!claim.matches_original(view.native_execution_tip(), None));
    let empty = NativeExecutionTipSnapshot::from_original(None, None);
    let empty: NativeExecutionTipSnapshot =
        norito::json::from_str(&norito::json::to_json(&empty).unwrap()).unwrap();
    assert!(empty.matches_original(None, None));
    assert!(!empty.matches_original(None, Some(None)));
}

#[test]
fn restore_preserves_original_pool_refusal_release_and_same_source_retry() {
    // Unrelated tests may pin the process-global reclamation epoch.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::native_execution_tip::tests::restore_preserves_original_pool_refusal_release_and_same_source_retry",
    ) {
        return;
    }
    use crate::{execution_attempt::ExecutionAttemptError, state::deserialize::StateRestoreError};
    use iroha_allocation::AllocationRefusal;
    use std::task::{Context, Waker};

    let mut chain = chain();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    let refused_claim = snapshot_claim(chain.state());
    let retry_claim = snapshot_claim(chain.state());
    let pool = chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&pool);
    // The waiter is an original fixture owner, admitted before measuring request work.
    let reserved = pool.reserved_bytes();
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes().checked_sub(reserved).unwrap())
        .unwrap();
    assert!(blocker.belongs_to(&pool));
    let original = CertifiedChain::from_pinned(
        view.chain_id(),
        view.network_id(),
        &hashes,
        chain.kura(),
        &pool,
    )
    .err()
    .expect("the actual original native source must refuse its full pool");
    let ExecutionAttemptError::Deferred(original) = original else {
        panic!("fixture must obtain the original source's typed local refusal: {original:?}");
    };
    let Some(AllocationRefusal::Capacity {
        reserved_bytes,
        limit_bytes,
        release,
        ..
    }) = original.allocation_refusal()
    else {
        panic!("fixture must retain the exact original pool release: {original:?}");
    };
    assert_eq!(*reserved_bytes, pool.limit_bytes());
    assert_eq!(*limit_bytes, pool.limit_bytes());
    let release = release.clone();
    chain.kura().reset_canonical_query_reads_for_test();
    let refused = refused_claim
        .restore(
            &pool,
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
        .map_err(StateRestoreError::from);
    let occupied = pool.reserved_bytes();
    let reads = chain.kura().canonical_query_reads_for_test();
    let pending = registration.poll_wait(&release, &mut Context::from_waker(Waker::noop()));
    drop(blocker);
    let ready = registration.poll_wait(&release, &mut Context::from_waker(Waker::noop()));
    // Retire contention before any assertion, including the causal before-fix assertion.
    assert_eq!(occupied, pool.limit_bytes());
    assert_eq!(reads, (0, 0), "refused backing never reads a native body");
    assert!(pending.is_pending());
    assert!(ready.is_ready());
    let error = refused
        .err()
        .expect("full original pool must refuse restore");
    let StateRestoreError::ExecutionDeferred(actual) = error else {
        panic!(
            "native tip restore must preserve the original pool refusal as ExecutionDeferred: {error:?}"
        );
    };
    assert_eq!(
        actual, original,
        "original release and all refusal fields survive restore"
    );
    let crate::snapshot::TryReadError::StateExecutionDeferred(exported) =
        crate::snapshot::TryReadError::from(StateRestoreError::ExecutionDeferred(actual))
    else {
        panic!("the snapshot boundary must preserve the typed original refusal");
    };
    assert_eq!(exported, original);
    assert_eq!(pool.reserved_bytes(), reserved);
    let restored = retry_claim
        .restore(
            &pool,
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
        .map_err(StateRestoreError::from)
        .expect("identical native source retries after original release");
    assert_eq!(*restored.view().get(), view.native_execution_tip());
    assert_eq!(
        *restored.predecessor_view().get(),
        *view.native_execution_tip_predecessor.get()
    );
    assert!(
        pool.reserved_bytes() > reserved,
        "the restored Cell owns its original pool charge"
    );
    drop(restored);
    let retired = TipCell::allocation_layouts()
        .into_iter()
        .map(|layout| layout.size())
        .sum::<usize>();
    // The original State view still pins both retired EBR generations. Their
    // physical backing must remain charged until that reader releases its epoch.
    assert_eq!(pool.reserved_bytes(), reserved + retired);
    assert!(
        view.block_hashes()
            .iter()
            .copied()
            .eq(hashes.iter().copied())
    );
    drop(view);
    drop((chain, registration, release, exported, original));
    collect_retired_restore_owners(&pool);
}

fn collect_retired_restore_owners(pool: &AllocationBudget) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "restored native owners did not reclaim after the original readers released: {}",
            pool.reserved_bytes()
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
    assert_eq!(pool.reserved_bytes(), 0);
}

fn restore_decode_context(
    pool: &AllocationBudget,
    bytes: usize,
) -> norito::core::DecodeBudgetContext {
    norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ),
        pool,
    )
    .expect("the original fixture pool funds its cumulative decoder control")
}

#[test]
fn restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry() {
    // Unrelated tests may pin the process-global reclamation epoch.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::native_execution_tip::tests::restore_preserves_cumulative_prefix_decode_refusal_and_same_source_retry",
    ) {
        return;
    }
    use crate::{execution_attempt::ExecutionAttemptError, state::deserialize::StateRestoreError};
    let mut chain = chain();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let view = chain.state().view();
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    let refused_claim = snapshot_claim(chain.state());
    let retry_claim = snapshot_claim(chain.state());
    let pool = chain.state().ivm_execution_budget();
    let baseline = pool.reserved_bytes();
    // Calibrate only the actual canonical constructor, under its original pool and codec.
    // H3 restoration then enters walk(2, 3), so its next genuine prefix decode must refuse.
    let calibration = restore_decode_context(&pool, usize::MAX);
    calibration.with(|| {
        let _reader = CertifiedChain::from_pinned(
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
            &pool,
        )
        .expect("actual original constructor establishes its own canonical demand");
    });
    let constructor_bytes = usize::try_from(calibration.consumed_allocated_bytes()).unwrap();
    assert!(constructor_bytes > 0);
    drop(calibration);
    assert_eq!(pool.reserved_bytes(), baseline);
    let reference = restore_decode_context(&pool, constructor_bytes);
    let original = reference.with(|| {
        let reader = CertifiedChain::from_pinned(
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
            &pool,
        )
        .expect("finite allowance must complete the original constructor before prefix refusal");
        reader
            .walk(2, 3)
            .next()
            .unwrap()
            .err()
            .expect("next actual prefix decode must refuse")
    });
    let ExecutionAttemptError::Deferred(original) = original else {
        panic!("fixture must obtain a typed original prefix refusal: {original:?}");
    };
    assert_eq!(
        original.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(
        original.allocation_refusal().is_none(),
        "codec accounting has no invented pool release"
    );
    assert_eq!(
        reference.consumed_allocated_bytes(),
        u64::try_from(constructor_bytes).unwrap()
    );
    drop(reference);
    let counter = restore_decode_context(&pool, constructor_bytes);
    let reserved = pool.reserved_bytes();
    let refused = counter.with(|| {
        refused_claim
            .restore(
                &pool,
                view.chain_id(),
                view.network_id(),
                &hashes,
                chain.kura(),
            )
            .map_err(StateRestoreError::from)
    });
    assert_eq!(
        counter.consumed_allocated_bytes(),
        u64::try_from(constructor_bytes).unwrap()
    );
    assert_eq!(
        pool.reserved_bytes(),
        reserved,
        "all incomplete native graphs retire"
    );
    let error = refused
        .err()
        .expect("the actual finite prefix allowance must refuse restore");
    let StateRestoreError::ExecutionDeferred(actual) = error else {
        panic!(
            "native tip restore must preserve the cumulative prefix decode refusal as ExecutionDeferred: {error:?}"
        );
    };
    assert_eq!(actual, original);
    let restored = retry_claim
        .restore(
            &pool,
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
        .map_err(StateRestoreError::from)
        .expect("identical native prefix retries after caller decode scope");
    assert_eq!(*restored.view().get(), view.native_execution_tip());
    assert_eq!(
        *restored.predecessor_view().get(),
        *view.native_execution_tip_predecessor.get()
    );
    drop(restored);
    let retired = TipCell::allocation_layouts()
        .into_iter()
        .map(|layout| layout.size())
        .sum::<usize>();
    assert_eq!(pool.reserved_bytes(), reserved + retired);
    drop(counter);
    assert_eq!(pool.reserved_bytes(), baseline + retired);
    drop(view);
    drop((chain, actual, original));
    collect_retired_restore_owners(&pool);
}

#[test]
fn restore_keeps_corrupt_native_history_a_completed_schema_rejection() {
    use crate::state::deserialize::StateRestoreError;
    let mut chain = chain();
    chain.commit(Vec::new());
    let view = chain.state().view();
    let claim = snapshot_claim(chain.state());
    let hashes: Vec<_> = view.block_hashes().iter().copied().collect();
    let pool = chain.state().ivm_execution_budget();
    let reserved = pool.reserved_bytes();
    // This mutates real durable H2 bytes, leaving its pinned slot/hash and cached body intact.
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
    let error = claim
        .restore(
            &pool,
            view.chain_id(),
            view.network_id(),
            &hashes,
            chain.kura(),
        )
        .map_err(StateRestoreError::from)
        .err()
        .expect("corrupt native history cannot establish authority");
    let StateRestoreError::Serialization(norito::json::Error::InvalidField { field, message }) =
        error
    else {
        panic!("corrupt native history remains a completed schema rejection: {error:?}");
    };
    assert_eq!(field, "native_execution_tip");
    assert!(!message.is_empty());
    assert_eq!(pool.reserved_bytes(), reserved);
    assert_eq!(view.native_execution_tip().unwrap().height(), 2);
}
