//! Original worker backing admission, task transfer and physical release controls.

use super::*;
use std::mem::size_of;

struct NoProof;
impl FastpqProofEngine for NoProof {
    fn limits(&self) -> (ProvingLimits, ExecutionEffectVerificationLimits) {
        (
            ProvingLimits::default(),
            ExecutionEffectVerificationLimits::default(),
        )
    }

    fn prove(
        &self,
        _: &SourceExecutionEffectStatement<'_>,
        _: ExpectedExecutionEffects<'_>,
        _: &AllocationBudget,
        _: &mut AllocationReservation,
    ) -> Result<FastpqProofOutput, ProvingError> {
        panic!("an unchanged H0 source has no proof work")
    }
}

#[inline(never)]
fn original_state() -> Arc<State> {
    Arc::new(State::new_for_testing(
        crate::state::World::default(),
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    ))
}

fn original_seed(state: &State) -> crate::sumeragi::node::NativeReplaySeed {
    use iroha_config::{
        kura::{FsyncMode, InitMode},
        parameters::{actual, defaults},
    };
    let store = actual::Kura {
        init_mode: InitMode::Strict,
        store_dir: iroha_config_base::WithOrigin::inline(state.kura().store_root()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        native_context_archive_max_bytes: defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        history_checkpoint_cache_capacity: defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes: defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes: defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::kura::FASTPQ_ARTIFACT_POLICY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,
    };
    crate::sumeragi::node::NativeReplaySeed::capture(
        state,
        store,
        iroha_test_samples::ALICE_ID.clone(),
        iroha_data_model::parameter::system::ConsensusMode::Permissioned,
    )
    .unwrap()
}

#[test]
fn worker_transfer_layout_does_not_retain_inline_native_replay_state() {
    eprintln!(
        "FASTPQ worker transfer bytes={} original inline producer bytes={}",
        size_of::<WorkerProducer>(),
        size_of::<Producer>(),
    );
    assert!(
        size_of::<WorkerProducer>() < size_of::<Producer>() / 4,
        "blocking result layout {} must stay below one quarter of inline producer {}",
        size_of::<WorkerProducer>(),
        size_of::<Producer>(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_backing_capacity_retries_through_blocking_returns_and_releases_exact_slot() {
    let state = original_state();
    let budget = state.ivm_execution_budget();
    let original_limit = budget.limit_bytes();
    let bytes = size_of::<Producer>();
    let seed = original_seed(&state);
    let baseline = budget.reserved_bytes();
    assert!(baseline > 0, "original State allocations retain their pool");
    budget.set_limit_bytes(baseline + bytes);
    let competing = budget.try_reserve_bytes(bytes).unwrap();
    let source = state.kura_handle();
    let source_references = Arc::strong_count(&source);
    let mut owner = WorkerProducer::new(Arc::clone(&state), FastpqProducer::default(), Some(seed));
    let pending_seed = std::ptr::from_ref(
        owner
            .pending
            .as_ref()
            .unwrap()
            .replay_seed
            .as_ref()
            .unwrap(),
    );
    let engine: Arc<dyn FastpqProofEngine> = Arc::new(NoProof);
    let shutdown = ShutdownSignal::new();

    owner.attempt(&engine, 0, &shutdown, None);
    assert!(!owner.stopped);
    assert!(owner.retained.is_none());
    assert!(Arc::ptr_eq(&owner.pending.as_ref().unwrap().state, &state));
    assert!(matches!(
        owner.admission,
        Some(ChargedBufferError::Admission(AllocationRefusal::Capacity {
            requested_bytes, ..
        })) if requested_bytes == bytes
    ));
    assert_eq!(
        std::ptr::from_ref(
            owner
                .pending
                .as_ref()
                .unwrap()
                .replay_seed
                .as_ref()
                .unwrap()
        ),
        pending_seed,
        "capacity refusal cannot take or replace the original startup seed"
    );
    assert_eq!(Arc::strong_count(&source), source_references);
    assert!(competing.belongs_to(&budget));
    drop(competing);

    // Execute the real attempt on an ordinary blocking worker and return only
    // the original slot handle. No custom worker stack or source reconstruction.
    let worker_engine = Arc::clone(&engine);
    let worker_shutdown = shutdown.clone();
    owner = tokio::task::spawn_blocking(move || {
        owner.attempt(&worker_engine, 0, &worker_shutdown, None);
        owner
    })
    .await
    .unwrap();
    assert!(!owner.stopped);
    assert!(owner.admission.is_none());
    assert!(owner.pending.is_none());
    let retained = owner.retained.as_ref().unwrap();
    assert!(retained.belongs_to(&budget));
    assert_eq!(retained.capacity(), 1);
    let pointer = std::ptr::from_ref(&retained.as_slice()[0]) as usize;
    assert!(Arc::ptr_eq(&retained.as_slice()[0].state, &state));
    assert!(retained.as_slice()[0].replay_seed.is_some());
    assert_eq!(Arc::strong_count(&source), source_references);
    let reserved = budget.reserved_bytes();

    owner = tokio::task::spawn_blocking(move || {
        owner.attempt(&engine, 0, &shutdown, None);
        owner
    })
    .await
    .unwrap();
    assert_eq!(
        std::ptr::from_ref(&owner.retained.as_ref().unwrap().as_slice()[0]) as usize,
        pointer,
        "successive tasks retain the identical original producer allocation"
    );
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(state.committed_height(), 0);
    drop(owner);
    assert_eq!(budget.reserved_bytes(), reserved - bytes);
    assert_eq!(Arc::strong_count(&source), source_references - 1);
    budget.set_limit_bytes(original_limit);
}

#[test]
fn original_backing_fixed_bound_stops_and_prior_shutdown_preserves_pending_inputs() {
    let state = original_state();
    let budget = state.ivm_execution_budget();
    let original_limit = budget.limit_bytes();
    let bytes = size_of::<Producer>();
    budget.set_limit_bytes(bytes - 1);
    let engine: Arc<dyn FastpqProofEngine> = Arc::new(NoProof);
    let shutdown = ShutdownSignal::new();
    let mut owner = WorkerProducer::new(Arc::clone(&state), FastpqProducer::default(), None);
    owner.attempt(&engine, 0, &shutdown, None);
    assert!(owner.stopped);
    assert!(owner.retained.is_none());
    assert!(Arc::ptr_eq(&owner.pending.as_ref().unwrap().state, &state));
    assert!(matches!(
        owner.admission,
        Some(ChargedBufferError::Admission(AllocationRefusal::ExceedsLimit {
            requested_bytes, limit_bytes
        })) if requested_bytes == bytes && limit_bytes == bytes - 1
    ));
    budget.set_limit_bytes(original_limit);
    owner.attempt(&engine, 0, &shutdown, None);
    assert!(
        owner.retained.is_none(),
        "fixed-bound refusal remains terminal"
    );
    drop(owner);

    let references = Arc::strong_count(&state);
    let reserved = budget.reserved_bytes();
    let mut cancelled = WorkerProducer::new(Arc::clone(&state), FastpqProducer::default(), None);
    shutdown.send();
    cancelled.attempt(&engine, 0, &shutdown, None);
    assert!(cancelled.retained.is_none());
    assert!(cancelled.admission.is_none());
    assert!(Arc::ptr_eq(
        &cancelled.pending.as_ref().unwrap().state,
        &state
    ));
    assert_eq!(budget.reserved_bytes(), reserved);
    drop(cancelled);
    assert_eq!(Arc::strong_count(&state), references);
}

#[test]
fn original_backing_allocator_refusal_keeps_seed_and_refunds_only_unallocated_slot() {
    let state = original_state();
    let budget = state.ivm_execution_budget();
    let seed = original_seed(&state);
    let source = state.kura_handle();
    let source_references = Arc::strong_count(&source);
    let mut owner = WorkerProducer::new(Arc::clone(&state), FastpqProducer::default(), Some(seed));
    let pending_seed = std::ptr::from_ref(
        owner
            .pending
            .as_ref()
            .unwrap()
            .replay_seed
            .as_ref()
            .unwrap(),
    );
    let baseline = budget.reserved_bytes();
    let layout = std::alloc::Layout::array::<Producer>(1).unwrap();
    let engine: Arc<dyn FastpqProofEngine> = Arc::new(NoProof);
    let shutdown = ShutdownSignal::new();
    let ((), refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        owner.attempt(&engine, 0, &shutdown, None);
    });
    assert!(
        refused,
        "the actual prepaid Producer backing reaches the allocator"
    );
    assert!(!owner.stopped);
    assert!(owner.retained.is_none());
    assert!(matches!(owner.admission,
        Some(ChargedBufferError::Allocator { requested_bytes }) if requested_bytes == layout.size()
    ));
    assert_eq!(
        std::ptr::from_ref(
            owner
                .pending
                .as_ref()
                .unwrap()
                .replay_seed
                .as_ref()
                .unwrap()
        ),
        pending_seed
    );
    assert!(Arc::ptr_eq(&owner.pending.as_ref().unwrap().state, &state));
    assert_eq!(Arc::strong_count(&source), source_references);
    assert_eq!(budget.reserved_bytes(), baseline);

    owner.attempt(&engine, 0, &shutdown, None);
    assert!(owner.admission.is_none());
    assert!(owner.pending.is_none());
    let retained = owner.retained.as_ref().unwrap();
    assert!(retained.belongs_to(&budget));
    assert!(retained.as_slice()[0].replay_seed.is_some());
    assert_eq!(Arc::strong_count(&source), source_references);
    assert_eq!(budget.reserved_bytes(), baseline + layout.size());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(Arc::strong_count(&source), source_references - 1);
}
