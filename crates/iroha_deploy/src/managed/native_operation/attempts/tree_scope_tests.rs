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
    assert_eq!(counts.reads, 2);
    assert_eq!(counts.decoded, 13);
    assert_eq!(counts.requested, 0);
    assert_eq!(counts.computed, 0);
    assert_eq!(history.reserved_attempt_count(), 3);
    let first = &history.attempts[0];
    let authorization = metadata::test_read_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    let observation =
        metadata::test_read_component(&fixture.operation, Some(first.ordinal()), "observation.nrt")
            .unwrap()
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
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    std::fs::remove_file(first.directory.path().join("foreign.nrt")).unwrap();
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        None,
    )
    .unwrap();
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "original dispatch authorization was lost or changed"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "authorization.nrt",
        Some(&authorization),
    )
    .unwrap();
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "observation.nrt",
        Some(b"not canonical"),
    )
    .unwrap();
    let (refused, counts) = current(&history);
    assert!(
        matches!(&refused, Err(Error::Invalid(message)) if message == "invalid canonical dispatch custody record"),
        "{:?}",
        refused.as_ref().err()
    );
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 2);
    metadata::test_replace_component(
        &fixture.operation,
        Some(first.ordinal()),
        "observation.nrt",
        Some(&observation),
    )
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
    assert_eq!(counts.reads, 1);
    std::fs::remove_dir(root.path().join("0042")).unwrap();
    assert_eq!(first.directory.entries(7).unwrap(), before);
    let (retried, counts) = current(&history);
    retried.unwrap();
    assert_eq!(counts.reads, 2);
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
    let original = metadata::test_read_component(
        &fixture.operation,
        Some(attempt.ordinal()),
        "authorization.nrt",
    )
    .unwrap()
    .unwrap();
    let history = fixture.history().unwrap();
    let root = history.root.as_ref().unwrap();
    let ample = 64 * 1024 * 1024;
    // Install the owner after both native tree scopes have opened. Indexing the canonical
    // image and decoding its lazy Authorization are distinct charged stages of this read.
    let read = |allocation, decode_authorization| {
        let allocated = std::cell::Cell::new(0);
        let child_entered = std::cell::Cell::new(false);
        let counter = parse_digest_tests::Counter::begin();
        let result = root.read_tree_scope(|tree| {
            tree.read_scope(&attempt.directory, |_reader| {
                let limits = norito::DecodeLimits::new(
                    MAX_RECORD_BYTES,
                    MAX_RECORD_BYTES,
                    MAX_RECORD_BYTES,
                    allocation,
                    32,
                );
                let (result, usage) = norito::core::with_decode_limits_measured(limits, || {
                    let image = metadata::load(&fixture.operation)?;
                    if decode_authorization {
                        child_entered.set(true);
                        image.read::<Authorization>(Some(attempt.ordinal()), 0)
                    } else {
                        Ok(None)
                    }
                });
                allocated.set(usage.total_allocated_bytes());
                result
            })
        });
        (
            result,
            counter.finish(),
            allocated.get(),
            child_entered.get(),
        )
    };
    let (indexed, counts, envelope, child_entered) = read(ample, false);
    assert!(indexed.unwrap().is_none());
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 0);
    assert!(!child_entered);
    assert!(envelope > 1);

    let (restored, counts, exact, child_entered) = read(ample, true);
    assert!(restored.unwrap().as_ref() == Some(&attempt.authorization));
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert!(child_entered);
    assert!(exact > envelope);

    for allocation in [0, 1, envelope - 1, envelope, exact - 1] {
        let (refused, counts, allocated, child_entered) = read(allocation, true);
        let expected = if allocation < envelope {
            "invalid canonical operation metadata image"
        } else {
            "invalid canonical dispatch custody record"
        };
        assert!(
            matches!(&refused, Err(Error::Invalid(message)) if message == expected),
            "allocation {allocation}: {:?}",
            refused.as_ref().err()
        );
        assert_eq!(child_entered, allocation >= envelope);
        assert_eq!(counts.reads, 1);
        assert_eq!(counts.decoded, 0);
        assert!(allocated <= allocation);
        if allocation == envelope {
            assert_eq!(allocated, envelope);
        }
    }
    let (restored, counts, allocated, child_entered) = read(exact, true);
    assert!(restored.unwrap().as_ref() == Some(&attempt.authorization));
    assert_eq!(counts.reads, 1);
    assert_eq!(counts.decoded, 1);
    assert_eq!(allocated, exact);
    assert!(child_entered);
    assert_eq!(
        metadata::test_read_component(
            &fixture.operation,
            Some(attempt.ordinal()),
            "authorization.nrt"
        )
        .unwrap()
        .unwrap(),
        original
    );
    history.require_current_local(None).unwrap();
    assert!(!attempt.wallet_path().join("preparation.json").exists());
    assert!(!attempt.wallet_path().join("payload.json").exists());
}

#[path = "handle_tree_tests.rs"]
mod handle_tree_tests;
