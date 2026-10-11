use super::*;
use crate::kura::Kura;
use iroha_data_model::{block::BlockHeader, nexus::LaneConfig as LaneConfigModel};
use nonzero_ext::nonzero;
use std::{
    sync::{Arc, Barrier, mpsc},
    thread,
    time::{Duration, Instant},
};
#[test]
fn state_commit_does_not_hold_tiered_backend_while_waiting_for_state_write_lock() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::default(), kura, query));
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let _write_guard = state.state_write_lock.lock();
    let barrier = Arc::new(Barrier::new(2));
    let commit_state = Arc::clone(&state);
    let commit_barrier = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        commit_barrier.wait();
        let block = commit_state.block(header);
        block
            .commit_empty_block_for_testing()
            .expect("commit should succeed");
    });
    barrier.wait();
    let start = Instant::now();
    let mut locked_while_waiting = false;
    while start.elapsed() < Duration::from_millis(200) {
        if handle.is_finished() {
            break;
        }
        if state.tiered_backend.try_lock().is_none() {
            locked_while_waiting = true;
            break;
        }
        thread::yield_now();
    }
    assert!(
        !locked_while_waiting,
        "tiered backend locked while commit waits for state_write_lock"
    );
    drop(_write_guard);
    handle.join().expect("commit thread");
}
#[test]
fn lane_lifecycle_and_commit_do_not_deadlock_on_lock_order() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::default(), kura, query));

    let plan = iroha_data_model::nexus::LaneLifecyclePlan {
        additions: vec![LaneConfigModel {
            id: LaneId::new(1),
            alias: "beta".to_string(),
            ..LaneConfigModel::default()
        }],
        retire: Vec::new(),
    };
    let (done_tx, done_rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(3));
    let lane_state = Arc::clone(&state);
    let lane_done = done_tx.clone();
    let lane_barrier = Arc::clone(&barrier);
    let lane_handle = thread::spawn(move || {
        lane_barrier.wait();
        lane_state
            .apply_lane_lifecycle(&plan)
            .expect("lane lifecycle");
        let _ = lane_done.send(());
    });
    let commit_state = Arc::clone(&state);
    let commit_done = done_tx.clone();
    let commit_barrier = Arc::clone(&barrier);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let commit_handle = thread::spawn(move || {
        commit_barrier.wait();
        let block = commit_state.block(header);
        block.commit_empty_block_for_testing().expect("commit");
        let _ = commit_done.send(());
    });
    barrier.wait();
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first serialized operation completion");
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second serialized operation completion");
    lane_handle.join().expect("lane lifecycle thread");
    commit_handle.join().expect("commit thread");
    assert!(
        state
            .nexus_snapshot()
            .lane_catalog
            .by_alias("beta")
            .is_some(),
        "lane lifecycle should publish after serialization with commit"
    );
}
#[test]
fn lane_lifecycle_waits_for_prebuilt_runtime_without_holding_publication_fences() {
    // The channel handshakes establish ordering; the deadline only bounds a
    // deadlock under a heavily loaded test runner.
    let timeout = Duration::from_secs(30);
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::default(), kura, query));

    let plan = iroha_data_model::nexus::LaneLifecyclePlan {
        additions: vec![LaneConfigModel {
            id: LaneId::new(1),
            alias: "prebuilt-beta".to_string(),
            ..LaneConfigModel::default()
        }],
        retire: Vec::new(),
    };
    let (block_ready_tx, block_ready_rx) = mpsc::channel();
    let (commit_release_tx, commit_release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (commit_result_tx, commit_result_rx) = mpsc::channel();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let original_hash = header.hash();
    let history_before: Vec<_> = state.block_hashes.view().iter().copied().collect();
    let height_before = state.committed_height();
    let membership_height_before = state.transactions.latest_height();
    let samples_before = state.autoscale_sample_history_snapshot();
    let commit_state = Arc::clone(&state);
    let commit_done = done_tx.clone();
    let commit_handle = thread::spawn(move || {
        let block = commit_state.block(header);
        block_ready_tx
            .send(())
            .expect("notify prebuilt block is holding its overlay");
        commit_release_rx
            .recv()
            .expect("wait for the lifecycle runtime-writer probe");
        // Consuming commit abandons the original overlay on a local busy
        // refusal. Report that exact outcome before notifying completion, so a
        // valid refusal cannot masquerade as a missing lifecycle completion.
        let result = block.commit_empty_block_for_testing();
        commit_result_tx
            .send(result)
            .expect("report original consuming commit outcome");
        let _ = commit_done.send("commit");
    });
    block_ready_rx
        .recv_timeout(timeout)
        .expect("prebuilt block ready");
    let runtime_before = state.canonical_runtime.view().get().clone();
    let manifests_before = Arc::clone(&state.lane_manifests.read());
    let generation_before = state.state_view_generation();
    let (runtime_wait_tx, runtime_wait_rx) = mpsc::channel();
    let lifecycle_state = Arc::clone(&state);
    let lifecycle_done = done_tx.clone();
    let lifecycle_handle = thread::spawn(move || {
        canonical_runtime::observe_next_runtime_replacement_for_test(runtime_wait_tx);
        lifecycle_state
            .apply_lane_lifecycle(&plan)
            .expect("lane lifecycle");
        let _ = lifecycle_done.send("lifecycle");
    });
    runtime_wait_rx
        .recv_timeout(timeout)
        .expect("lifecycle reached its actual runtime-writer acquisition");
    // The original prebuilt block owns this writer, so the lifecycle cannot
    // pass this acquisition. It must leave every enclosing fence available to
    // that block's commit and must publish no partial runtime or manifest cut.
    assert!(state.state_commit_lock.try_lock().is_some());
    assert!(state.lane_lifecycle_lock.try_lock().is_some());
    assert!(state.state_write_lock.try_lock().is_some());
    assert_eq!(state.canonical_runtime.view().get(), &runtime_before);
    assert!(Arc::ptr_eq(&state.lane_manifests.read(), &manifests_before));
    assert_eq!(state.state_view_generation(), generation_before);
    assert!(
        state
            .nexus_snapshot()
            .lane_catalog
            .by_alias("prebuilt-beta")
            .is_none(),
        "catalog must remain at the captured predecessor until its writer releases"
    );
    commit_release_tx
        .send(())
        .expect("release prebuilt block commit");
    done_rx
        .recv_timeout(timeout)
        .expect("first operation completion");
    done_rx
        .recv_timeout(timeout)
        .expect("second operation completion");
    lifecycle_handle.join().expect("lane lifecycle thread");
    commit_handle.join().expect("commit thread");
    let result = commit_result_rx
        .recv_timeout(timeout)
        .expect("original consuming commit outcome");
    let history_after: Vec<_> = state.block_hashes.view().iter().copied().collect();
    match result {
        Ok(()) => {
            let mut expected_history = history_before.clone();
            expected_history.push(original_hash);
            assert_eq!(history_after, expected_history);
            assert_eq!(state.committed_height(), height_before + 1);
            assert_eq!(
                state.transactions.latest_height(),
                membership_height_before + 1
            );
            assert_eq!(state.latest_block_hash_fast(), Some(original_hash));
            let samples = state.autoscale_sample_history_snapshot();
            assert_eq!(samples.len(), samples_before.len() + 1);
            assert_eq!(samples.back().unwrap().block_hash, original_hash);
            assert_eq!(
                samples.back().unwrap().block_height,
                (height_before + 1) as u64
            );
        }
        Err(storage_transactions::TransactionsBlockError::PublicationBusy(_)) => {
            assert_eq!(history_after, history_before);
            assert_eq!(state.committed_height(), height_before);
            assert_eq!(state.transactions.latest_height(), membership_height_before);
            assert_eq!(
                state.latest_block_hash_fast(),
                history_before.last().copied()
            );
            assert_eq!(state.autoscale_sample_history_snapshot(), samples_before);
        }
        Err(other) => panic!("unexpected original consuming commit refusal: {other:?}"),
    }
    assert_eq!(state.state_view_generation() % 2, 0);
    let current = state.view();
    assert_eq!(current.height(), state.committed_height());
    assert_eq!(current.block_hashes().len(), history_after.len());
    assert!(
        state
            .nexus_snapshot()
            .lane_catalog
            .by_alias("prebuilt-beta")
            .is_some(),
        "published lane should survive prebuilt block serialization"
    );
}
#[test]
fn uncontended_prebuilt_block_publishes_its_original_history_cut() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let original_hash = header.hash();
    let block = state.block(header);
    block
        .commit_empty_block_for_testing()
        .expect("uncontended original consuming commit");
    assert_eq!(state.committed_height(), 1);
    assert_eq!(state.transactions.latest_height(), 1);
    assert_eq!(state.latest_block_hash_fast(), Some(original_hash));
    assert_eq!(
        state
            .block_hashes
            .view()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![original_hash]
    );
    let samples = state.autoscale_sample_history_snapshot();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].block_hash, original_hash);
    assert_eq!(samples[0].block_height, 1);
    let current = state.view();
    assert_eq!(current.height(), 1);
    assert_eq!(current.block_hashes().get(0), Some(&original_hash));
}

#[test]
fn transaction_and_state_views_keep_canonical_catalog_after_projection_cache_drift() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);

    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let block_catalog = block.nexus.lane_catalog.clone();
    let updated_catalog = iroha_data_model::nexus::LaneCatalog::new(
        nonzero!(2_u32),
        vec![
            LaneConfigModel::default(),
            LaneConfigModel {
                id: LaneId::new(1),
                alias: "post-block-beta".to_owned(),
                ..LaneConfigModel::default()
            },
        ],
    )
    .expect("updated lane catalog");
    {
        let mut nexus = state.nexus.write();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&updated_catalog);
        nexus.lane_catalog = updated_catalog;
    }
    assert!(
        state
            .nexus
            .read()
            .lane_catalog
            .by_alias("post-block-beta")
            .is_some()
    );
    let canonical = state.nexus_snapshot();
    assert_eq!(canonical.lane_catalog, block_catalog);
    assert!(
        canonical.lane_catalog.by_alias("post-block-beta").is_none(),
        "derived cache drift must not replace the canonical State catalog"
    );
    let tx = block.transaction();
    assert_eq!(tx.nexus.lane_catalog, block_catalog);
    assert!(
        tx.nexus.lane_catalog.by_alias("post-block-beta").is_none(),
        "transactions opened from a prebuilt block must retain their canonical catalog"
    );
}

#[test]
fn lane_lifecycle_waits_for_inflight_state_commit_lock() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = Arc::new(State::new_for_testing(World::default(), kura, query));

    let plan = iroha_data_model::nexus::LaneLifecyclePlan {
        additions: vec![LaneConfigModel {
            id: LaneId::new(1),
            alias: "serialized-beta".to_string(),
            ..LaneConfigModel::default()
        }],
        retire: Vec::new(),
    };
    let commit_guard = state.state_commit_lock.lock();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let lifecycle_state = Arc::clone(&state);
    let handle = thread::spawn(move || {
        attempt_tx
            .send(())
            .expect("notify lifecycle attempt started");
        lifecycle_state
            .apply_lane_lifecycle(&plan)
            .expect("lane lifecycle");
    });
    attempt_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("lifecycle thread started");
    thread::sleep(Duration::from_millis(50));
    assert!(
        state
            .nexus_snapshot()
            .lane_catalog
            .by_alias("serialized-beta")
            .is_none(),
        "manual lifecycle must not publish while a state commit is in progress"
    );
    drop(commit_guard);
    handle.join().expect("lane lifecycle thread");
    assert!(
        state
            .nexus_snapshot()
            .lane_catalog
            .by_alias("serialized-beta")
            .is_some(),
        "manual lifecycle should publish after the state commit lock is released"
    );
}
#[test]
fn heavy_world_commit_bench_helper_commits_accounts() {
    let kura = Kura::blank_kura_for_testing();
    let query = crate::query::store::LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query);
    let elapsed = state
        .commit_heavy_world_accounts_for_bench(nonzero!(1_u64), 16)
        .expect("heavy world bench commit");
    assert!(elapsed > Duration::ZERO);
    assert_eq!(state.view().world.accounts().iter().count(), 16);
}

#[test]
fn infallible_state_block_refuses_capacity_without_waiting_or_changing_state() {
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    state
        .ensure_da_indexes_hydrated()
        .expect("prepare the actual empty DA indexes");
    let budget = state.ivm_execution_budget();
    let retained = budget.reserved_bytes();
    let generation = state.state_view_generation();
    assert!(retained > 0, "the original State retains real pool custody");
    // Saturate available credits while preserving a policy limit large enough
    // for each request. A zero limit tests ExceedsLimit, not temporary Capacity.
    budget.set_limit_bytes(retained);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    assert!(matches!(
        state.try_block(header.clone()),
        Err(StateBlockStartError::Storage(
            StateStorageAdmissionError::World(mv::storage::AdmittedStorageError::Allocation(
                iroha_allocation::AllocationRefusal::Capacity { .. }
            ))
        ))
    ));
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(state.block(header));
    }));
    let panic = refused.expect_err("infallible block retains the genuine capacity refusal");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("capacity panic diagnostic");
    assert!(
        message.contains("Capacity"),
        "original finite admission reason is retained: {message}"
    );
    assert_eq!(budget.reserved_bytes(), retained);
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(state.committed_height(), 0);
    assert!(state.latest_block_hash_fast().is_none());
}

#[test]
fn infallible_state_block_refuses_original_writer_poison_without_waiting() {
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    state
        .ensure_da_indexes_hydrated()
        .expect("prepare the actual empty DA indexes");
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _original = state.canonical_runtime.block();
        panic!("poison the original runtime writer");
    }));
    assert!(poison.is_err());
    let generation = state.state_view_generation();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    assert!(matches!(
        state.try_block(header.clone()),
        Err(StateBlockStartError::Storage(
            StateStorageAdmissionError::World(mv::storage::AdmittedStorageError::Poisoned { .. })
        ))
    ));
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(state.block(header));
    }));
    let panic = refused.expect_err("infallible block retains original writer poison");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("poison panic diagnostic");
    assert!(
        message.contains("Poisoned"),
        "original poison reason is retained: {message}"
    );
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(state.committed_height(), 0);
    assert!(state.latest_block_hash_fast().is_none());
}
