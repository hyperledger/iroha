//! Deterministic generation and liability-clock boundary regressions.

use super::*;

fn fixture() -> (CurrentGeneration, HeightFacts) {
    (
        CurrentGeneration {
            generation: 8,
            committee_root: [1; 32],
            start_height: 10,
            start_timestamp_ms: 100,
            start_lc: 70,
            ended: false,
        },
        HeightFacts {
            height: 20,
            timestamp_ms: 199,
            liability_clock: 150,
            committee_root: [1; 32],
            next_committee_root: [1; 32],
            boundary: false,
            parent: Some((19, 198)),
            heartbeat_ms: 100,
            validity_ms: 1000,
        },
    )
}

#[test]
fn heartbeat_is_exact_and_keeps_original_signer() {
    let (current, mut facts) = fixture();
    assert_eq!(
        plan(current, facts).unwrap(),
        GenerationPlan {
            resync: None,
            rotation: None,
            signing_generation: 8,
        }
    );
    facts.timestamp_ms = 200;
    let result = plan(current, facts).unwrap();
    let change = result.rotation.unwrap();
    assert_eq!(result.signing_generation, 8);
    assert_eq!(
        change.start,
        SccpGenerationStartV1 {
            generation: 9,
            cause: SccpGenerationCauseV1::Heartbeat,
            height: 21,
            timestamp_ms: 200,
            liability_clock: 150,
        }
    );
    assert_eq!(change.end.end_height, 20);
    assert_eq!(change.end.next_committee_root, [1; 32]);
    assert_eq!(change.end.successor_validity_ms, 1000);
    assert_eq!(
        current.start_timestamp_ms, 100,
        "no renewal of old creation facts"
    );
}

#[test]
fn key_change_wins_over_heartbeat_and_requires_boundary() {
    let (current, mut facts) = fixture();
    facts.next_committee_root = [2; 32];
    assert_eq!(plan(current, facts), Err(Degraded::InvalidHeightInputs));
    facts.boundary = true;
    facts.timestamp_ms = 200;
    let result = plan(current, facts).unwrap();
    assert_eq!(
        result.rotation.unwrap().start.cause,
        SccpGenerationCauseV1::KeyChange
    );
    assert_eq!(result.signing_generation, 8);
}

#[test]
fn resync_uses_original_parent_time_and_can_precede_key_rotation() {
    let (current, mut facts) = fixture();
    facts.committee_root = [2; 32];
    facts.next_committee_root = [2; 32];
    facts.timestamp_ms = 200;
    let result = plan(current, facts).unwrap();
    let resync = result.resync.unwrap();
    assert_eq!(resync.start.generation, 9);
    assert_eq!(resync.start.height, 20);
    assert_eq!(resync.start.cause, SccpGenerationCauseV1::Resync);
    assert_eq!(resync.end.end_height, 19);
    assert_eq!(resync.end.end_timestamp_ms, 198);
    assert_eq!(result.signing_generation, 9);
    assert!(
        result.rotation.is_none(),
        "resync resets the heartbeat start"
    );
    facts.boundary = true;
    facts.next_committee_root = [3; 32];
    let result = plan(current, facts).unwrap();
    assert_eq!(result.signing_generation, 9);
    let successor = result.rotation.unwrap();
    assert_eq!(successor.start.generation, 10);
    assert_eq!(successor.start.height, 21);
    assert_eq!(successor.end.next_committee_root, [3; 32]);
}

#[test]
fn missing_or_inconsistent_original_facts_degrade_without_changes() {
    let (mut current, mut facts) = fixture();
    current.ended = true;
    assert_eq!(
        plan(current, facts),
        Err(Degraded::InconsistentGenerationState)
    );
    current.ended = false;
    facts.committee_root = [2; 32];
    facts.next_committee_root = [2; 32];
    facts.parent = None;
    assert_eq!(plan(current, facts), Err(Degraded::MissingParentTip));
    for parent in [(18, 198), (19, 99), (19, 200)] {
        facts.parent = Some(parent);
        assert_eq!(
            plan(current, facts),
            Err(Degraded::InconsistentGenerationState)
        );
    }
    facts.parent = Some((19, 198));
    current.generation = u64::MAX;
    assert_eq!(plan(current, facts), Err(Degraded::ArithmeticOverflow));
    current.generation = 8;
    facts.liability_clock = facts.timestamp_ms + 1;
    assert_eq!(
        plan(current, facts),
        Err(Degraded::InconsistentGenerationState)
    );
}

#[test]
fn liability_clock_halt_is_capped_and_genesis_is_original_time() {
    assert_eq!(liability_clock(1, 500, None, 0, 100, 20), Ok(500));
    assert_eq!(
        liability_clock(2, 510, Some((1, 500)), 500, 100, 20),
        Ok(510)
    );
    assert_eq!(
        liability_clock(3, 10_000, Some((2, 510)), 510, 100, 20),
        Ok(630)
    );
    assert_eq!(
        liability_clock(4, 10_010, Some((3, 10_000)), 630, 100, 20),
        Ok(640)
    );
    assert_eq!(
        liability_clock(3, 600, None, 510, 100, 20),
        Err(Degraded::MissingParentTip)
    );
    for (height, time, parent, lc) in [
        (0, 5, (0, 4), 4),
        (4, 600, (2, 510), 510),
        (3, 500, (2, 510), 510),
        (3, 600, (2, 510), 511),
    ] {
        assert_eq!(
            liability_clock(height, time, Some(parent), lc, 100, 20),
            Err(Degraded::InconsistentGenerationState)
        );
    }
}
