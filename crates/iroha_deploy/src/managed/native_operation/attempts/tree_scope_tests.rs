//! Genuine retained rows keep fresh currentness, canonical charges and exact source retry.

use super::*;
use crate::managed::Error;

fn canonical_rows(fixture: &Fixture) {
    let mut previous = fixture.reserve();
    fixture.commit(&previous);
    for ordinal in 1..=2_u8 {
        let next = fixture
            .history()
            .unwrap()
            .reserve(
                &fixture.operation,
                Origin::Generated {
                    ordinal,
                    epoch: [ordinal; 32],
                    parent_intent: [0x73; 32],
                },
                fixture.terms.clone(),
            )
            .unwrap();
        let receipt = fixture
            .wallet
            .retire_initial_reserve_policy_unprepared(
                &previous.wallet_path(),
                &fixture.request(&previous),
            )
            .unwrap();
        retire_request(&previous, &next, &receipt).unwrap();
        let retained = fixture.retain(&next);
        commit(&next, Some(&previous), Observation::ordinary(), &retained).unwrap();
        previous = next;
    }
}

fn current(history: &History) -> (Result<()>, parse_digest_tests::Counts) {
    let counter = parse_digest_tests::Counter::begin();
    let result = history.require_current_local(None);
    (result, counter.finish())
}

#[test]
fn retained_row_tree_keeps_exact_record_counts_inventory_refusals_and_source_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    canonical_rows(&fixture);
    let history = fixture.history().unwrap();
    let (accepted, counts) = current(&history);
    accepted.unwrap();
    assert_eq!(counts.reads, 18);
    assert_eq!(counts.decoded, 13);
    assert_eq!(counts.requested, 0);
    assert_eq!(counts.computed, 0);
    assert_eq!(history.reserved_attempt_count(), 3);
    let first = &history.attempts[0];
    let authorization = first
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let observation = first
        .directory
        .read("observation.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let before = first.directory.entries(7).unwrap();
    first
        .directory
        .write_atomic("foreign.nrt", b"foreign", PublishMode::CreateNew)
        .unwrap();
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch attempt contains unknown material"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 3);
    assert_eq!(counts.decoded, 1);
    std::fs::remove_file(first.directory.path().join("foreign.nrt")).unwrap();
    std::fs::remove_file(first.directory.path().join("authorization.nrt")).unwrap();
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "original dispatch authorization was lost or changed"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 4);
    assert_eq!(counts.decoded, 1);
    first
        .directory
        .write_atomic("authorization.nrt", &authorization, PublishMode::CreateNew)
        .unwrap();
    first
        .directory
        .write_atomic("observation.nrt", b"not canonical", PublishMode::Replace)
        .unwrap();
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 5);
    assert_eq!(counts.decoded, 2);
    first
        .directory
        .write_atomic("observation.nrt", &observation, PublishMode::Replace)
        .unwrap();
    let root = history.root.as_ref().unwrap();
    let extra = root.create_child("0042").unwrap();
    drop(extra);
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "dispatch inventory changed during native operation"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 3);
    std::fs::remove_dir(root.path().join("0042")).unwrap();
    assert_eq!(first.directory.entries(7).unwrap(), before);
    let (retried, counts) = current(&history);
    retried.unwrap();
    assert_eq!(counts.reads, 18);
    assert_eq!(counts.decoded, 13);
    assert_eq!(history.reserved_attempt_count(), 3);
    assert!(
        !history.attempts[2]
            .wallet_path()
            .join("payload.json")
            .exists()
    );
    assert!(
        !history.attempts[2]
            .wallet_path()
            .join("operation.json")
            .exists()
    );
}

#[test]
fn retained_row_tree_preserves_late_active_allocation_refusal_and_exact_original_retry() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let attempt = fixture.reserve();
    let original = attempt
        .directory
        .read("authorization.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    for allocation in [0, 1] {
        let counter = parse_digest_tests::Counter::begin();
        let refused = root.read_tree_scope(|tree| {
            tree.read_scope(&attempt.directory, |reader| {
                let limits = norito::DecodeLimits::new(
                    MAX_RECORD_BYTES,
                    MAX_RECORD_BYTES,
                    MAX_RECORD_BYTES,
                    allocation,
                    32,
                );
                norito::core::with_decode_limits_scope(limits, || {
                    read_record_in_scope::<Authorization>(reader, "authorization.nrt")
                })
            })
        });
        let counts = counter.finish();
        assert!(
            matches!(&refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"),
            "{:?}",
            refused.as_ref().err()
        );
        assert_eq!(counts.reads, 1);
        assert_eq!(counts.decoded, 0);
    }
    let counter = parse_digest_tests::Counter::begin();
    let wide = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        64 * 1024 * 1024,
        32,
    );
    let restored = root
        .read_tree_scope(|tree| {
            tree.read_scope(&attempt.directory, |reader| {
                norito::core::with_decode_limits_scope(wide, || {
                    read_record_in_scope::<Authorization>(reader, "authorization.nrt")
                })
            })
        })
        .unwrap();
    let counts = counter.finish();
    assert!(restored.as_ref() == Some(&attempt.authorization));
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert_eq!(
        attempt
            .directory
            .read("authorization.nrt", MAX_RECORD_BYTES)
            .unwrap(),
        original
    );
    history.require_current_local(None).unwrap();
    assert!(!attempt.wallet_path().join("preparation.json").exists());
    assert!(!attempt.wallet_path().join("payload.json").exists());
}

#[path = "handle_tree_tests.rs"]
mod handle_tree_tests;
