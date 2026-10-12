//! Boundary and work-limit tests for read-only native retention selection.

use super::*;
use iroha_data_model::sccp::committee::{SccpGenerationCauseV1, SccpGenerationEndV1};

// Selection examines only lifecycle facts; this deliberately carries no key/provenance
// authority. Live callers borrow structurally validated immutable retained owners.
fn record(generation: u64) -> SccpCommitteeGenerationV1 {
    SccpCommitteeGenerationV1 {
        generation,
        committee_root: [1; 32],
        keys: Vec::new(),
        members: Vec::new(),
        cause: SccpGenerationCauseV1::Heartbeat,
        start_height: generation,
        start_timestamp_ms: 1,
        start_lc: 1,
        validity_ms: 89,
        deadline_ms: 90,
        grace_ms: 10,
        progress_cap_ms: 20,
        liable_until_lc: 100,
        dest_cleared_lc: None,
        end: Some(SccpGenerationEndV1 {
            end_height: generation,
            end_timestamp_ms: 2,
            next_committee_root: [2; 32],
            successor_validity_ms: 89,
        }),
    }
}

#[test]
fn generation_selection_uses_inclusive_shared_liability_and_preserves_current() {
    let mut value = record(1);
    for lc in [99, 100, 101, 120] {
        assert!(
            generations([&value], 2, lc, |_| PendingForgery::Clear)
                .unwrap()
                .as_slice()
                .is_empty()
        );
    }
    assert_eq!(
        generations([&value], 2, 121, |_| PendingForgery::Clear)
            .unwrap()
            .as_slice(),
        &[1]
    );
    value.dest_cleared_lc = Some(150);
    assert!(
        generations([&value], 2, 160, |_| PendingForgery::Clear)
            .unwrap()
            .as_slice()
            .is_empty()
    );
    assert_eq!(
        generations([&value], 2, 161, |_| PendingForgery::Clear)
            .unwrap()
            .as_slice(),
        &[1]
    );
    assert!(
        generations([&value], 1, u64::MAX, |_| PendingForgery::Clear)
            .unwrap()
            .as_slice()
            .is_empty()
    );
    value.dest_cleared_lc = Some(u64::MAX);
    assert!(
        generations([&value], 2, u64::MAX, |_| PendingForgery::Clear)
            .unwrap()
            .as_slice()
            .is_empty()
    );
}

#[test]
fn gaps_and_longer_predecessor_liability_do_not_hide_later_eligible_generations() {
    let mut first = record(1);
    first.liable_until_lc = 500;
    let values = [first, record(3), record(5), record(7)];
    let selected = generations(&values, 7, 121, |generation| {
        if generation == 5 {
            PendingForgery::Pending
        } else {
            PendingForgery::Clear
        }
    })
    .unwrap();
    assert_eq!(selected.as_slice(), &[3]);
}

#[test]
fn generation_deletion_count_is_eight_and_missing_forgery_custody_is_not_clear() {
    let values: Vec<_> = (1..=20).map(record).collect();
    let mut calls = 0;
    let selected = generations(&values, 20, 121, |generation| {
        calls += 1;
        if generation == 2 {
            PendingForgery::Pending
        } else {
            PendingForgery::Clear
        }
    })
    .unwrap();
    assert_eq!(selected.as_slice(), &[1, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(calls, 9);
    assert_eq!(
        generations(&values, 20, 121, |_| PendingForgery::Unavailable),
        Err(SelectionError::PendingForgeryUnavailable)
    );
    assert!(
        generations(&values, 20, 120, |_| panic!(
            "liable rows need no pending lookup"
        ))
        .unwrap()
        .as_slice()
        .is_empty()
    );
    assert_eq!(
        generations([&values[1], &values[0]], 20, 121, |_| PendingForgery::Clear),
        Err(SelectionError::NonAscending)
    );
}

#[test]
fn anchor_last_height_is_strict_and_open_or_overflowing_chunks_never_delete() {
    assert!(anchors([0], Some(4096), 1).unwrap().as_slice().is_empty());
    assert_eq!(anchors([0], Some(4097), 1).unwrap().as_slice(), &[0]);
    assert!(anchors([0], Some(4097), 0).unwrap().as_slice().is_empty());
    assert!(anchors([0], None, 1).unwrap().as_slice().is_empty());
    assert!(
        anchors([u64::MAX - 1, u64::MAX], Some(u64::MAX), u64::MAX)
            .unwrap()
            .as_slice()
            .is_empty()
    );
    assert_eq!(
        anchors(0..20, Some(100_000), 20).unwrap().as_slice(),
        &[0, 1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(
        anchors([1, 0], Some(100_000), 20),
        Err(SelectionError::NonAscending)
    );
}

#[test]
fn every_relevant_destination_must_be_strictly_past_the_deadline() {
    use DestinationProgress::{Finalized, Irrelevant, Unavailable};
    let value = record(1);
    for progress in [
        [Finalized(90), Irrelevant, Irrelevant],
        [Finalized(91), Unavailable, Irrelevant],
        [Finalized(91), Finalized(100), Finalized(89)],
    ] {
        assert!(
            clearances([&value], &progress)
                .unwrap()
                .as_slice()
                .is_empty()
        );
    }
    for progress in [[Irrelevant; 3], [Finalized(91), Finalized(100), Irrelevant]] {
        assert_eq!(clearances([&value], &progress).unwrap().as_slice(), &[1]);
    }
}

#[test]
fn clearance_counts_blocked_visits_and_never_searches_past_sixty_four_candidates() {
    use DestinationProgress::{Finalized, Irrelevant};
    let mut values: Vec<_> = (1..=66).map(record).collect();
    values[0].end = None;
    values[1].dest_cleared_lc = Some(1);
    assert_eq!(
        clearances(&values, &[Irrelevant; 3]).unwrap().as_slice(),
        &(3..=66).collect::<Vec<_>>()
    );
    let mut blocked: Vec<_> = (1..=65).map(record).collect();
    blocked[64].deadline_ms = 1;
    assert!(
        clearances(&blocked, &[Finalized(90), Irrelevant, Irrelevant])
            .unwrap()
            .as_slice()
            .is_empty()
    );
    assert_eq!(
        clearances([&values[3], &values[2]], &[Irrelevant; 3]),
        Err(SelectionError::NonAscending)
    );
}
