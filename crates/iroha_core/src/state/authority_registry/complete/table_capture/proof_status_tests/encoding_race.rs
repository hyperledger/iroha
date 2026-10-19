//! Actual serializer failure must not outrank changed native or State publication owners.

use super::*;
use crate::state::authority_registry::leaf::overflow_pause::pause_next_overflow;
use std::{sync::mpsc, thread, time::Duration};

#[derive(Clone, Copy)]
enum Change {
    Stable,
    Source,
    Index,
    State,
}

fn capture_at_real_overflow(change: Change) {
    let state = state("stark/fri");
    let pool = state.ivm_execution_budget();
    let baseline = pool.reserved_bytes();
    let generation = state.state_view_generation();
    let source = state.world.proofs.try_committed_view_nonblocking().unwrap();
    let index = state
        .world
        .proofs_by_status
        .try_committed_view_nonblocking()
        .unwrap();
    let key = id("stark/fri");
    let record = source.get(&key).unwrap().clone();
    assert_eq!(index.get(&(ProofStatus::Submitted, key.clone())), Some(&()));
    let mut limits = native_test_support::limits();
    // Keep real grouping work and storage admission intact. Admit the exact key, then fail
    // the larger ProofRecord's real serializer while its original charged key remains live.
    limits.max_payload_bytes = norito::codec::encode_adaptive(&key).len();
    assert!(norito::codec::encode_adaptive(&record).len() > limits.max_payload_bytes);
    let (reached_tx, reached_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let result = thread::scope(|scope| {
        let state = &state;
        let worker = scope.spawn(move || {
            let observer = pause_next_overflow(reached_tx, resume_rx);
            let result = capture(state, limits);
            assert!(observer.observed(), "real serializer overflow was reached");
            drop(observer);
            result
        });
        reached_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("capture reached its actual serializer bound");
        assert!(
            pool.reserved_bytes() > baseline,
            "the real value encoder still retains its original funded key"
        );
        match change {
            Change::Stable => (),
            Change::Source => {
                let mut block = state.world.proofs.block();
                block.insert(key.clone(), record.clone());
                block.commit();
            }
            Change::Index => {
                let mut block = state.world.proofs_by_status.block();
                block.insert((ProofStatus::Submitted, key.clone()), ());
                block.commit();
            }
            Change::State => {
                // Retain original notification custody outside the real physical writer guards.
                let mut notice = state.state_view_publication();
                let mut commit_release = state.state_commit_lock.defer_notifications();
                let mut write_release = state.state_write_lock.defer_notifications();
                let _commit = commit_release.lock();
                let _write = write_release.lock();
                let _generation = notice.begin();
            }
        }
        assert_eq!(
            source.try_matches_current(&state.world.proofs).unwrap(),
            !matches!(change, Change::Source)
        );
        assert_eq!(
            index
                .try_matches_current(&state.world.proofs_by_status)
                .unwrap(),
            !matches!(change, Change::Index)
        );
        assert_eq!(
            state.state_view_generation(),
            generation
                + if matches!(change, Change::State) {
                    2
                } else {
                    0
                }
        );
        // Equal row bytes do not substitute for the original native publication identity.
        assert_eq!(state.world.proofs.view().get(&key), Some(&record));
        assert_eq!(
            state
                .world
                .proofs_by_status
                .view()
                .get(&(ProofStatus::Submitted, key.clone())),
            Some(&())
        );
        resume_tx
            .send(())
            .expect("release actual serializer failure");
        worker.join().expect("actual capture worker")
    });
    match change {
        Change::Stable => assert!(matches!(result, Err(LeafError::PayloadLimit))),
        _ => assert!(matches!(result, Ok(None)), "changed publication must win"),
    }
    assert_eq!(
        pool.reserved_bytes(),
        baseline,
        "failed capture refunds its actual storage"
    );
    drop(source);
    drop(index);
    let snapshot = capture(&state, native_test_support::limits())
        .unwrap()
        .expect("same State can retry without renewed authority");
    assert_eq!(snapshot.table_id(), "world.proofs");
    assert_eq!(snapshot.row_count(), 1);
    assert!(pool.reserved_bytes() > baseline);
    drop(snapshot);
    assert_eq!(
        pool.reserved_bytes(),
        baseline,
        "final snapshot owner releases storage"
    );
}

#[test]
fn stable_catalog_preserves_real_serializer_payload_limit() {
    capture_at_real_overflow(Change::Stable);
}

#[test]
fn same_value_canonical_publication_overrides_real_serializer_failure() {
    capture_at_real_overflow(Change::Source);
}

#[test]
fn same_value_derived_publication_overrides_real_serializer_failure() {
    capture_at_real_overflow(Change::Index);
}

#[test]
fn original_state_publication_overrides_real_serializer_failure() {
    capture_at_real_overflow(Change::State);
}
