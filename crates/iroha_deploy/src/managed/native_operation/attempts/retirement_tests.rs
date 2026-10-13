//! Real unsigned wallet receipts retain retirement across an immutable caller's own commit.

use super::*;

fn successor(fixture: &Fixture, ordinal: u8) -> Attempt {
    fixture
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
        .unwrap()
}

fn image(fixture: &Fixture) -> Vec<u8> {
    fixture
        .operation
        .read(metadata::FILE, metadata::MAX_IMAGE_BYTES)
        .unwrap()
        .to_vec()
}

fn restore(fixture: &Fixture, bytes: &[u8]) {
    fixture
        .operation
        .write_atomic(metadata::FILE, bytes, PublishMode::Replace)
        .unwrap();
}

fn require_unchanged_refusal(
    fixture: &Fixture,
    attempt: &Attempt,
    expected: &str,
    retire: impl FnOnce() -> Result<()>,
) {
    let before = image(fixture);
    let result = retire();
    assert!(
        matches!(&result, Err(crate::managed::Error::Invalid(message)) if message == expected),
        "expected {expected}, got {result:?}"
    );
    assert_eq!(image(fixture), before);
    assert!(
        metadata::test_read_attempt_component(attempt, "retired.nrt")
            .unwrap()
            .is_none()
    );
}

#[test]
fn stale_attempt_retirement_validates_fresh_commit_and_observation_against_real_receipt() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let first = fixture.reserve();
    fixture.commit(&first);
    assert!(first.commit.is_none() && first.observation.is_none());
    let next = successor(&fixture, 1);
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    let original = image(&fixture);
    let commit: Commit = metadata::load(&fixture.operation)
        .unwrap()
        .read(Some(first.ordinal()), 2)
        .unwrap()
        .unwrap();
    let request = std::fs::read(first.wallet_path().join("preparation.json")).unwrap();
    for field in ["authorization", "observation", "request", "predecessor"] {
        let mut changed = commit.clone();
        match field {
            "authorization" => changed.authorization = [0x91; 32],
            "observation" => changed.observation = [0x92; 32],
            "request" => changed.request_sha256 = "0".repeat(64),
            _ => changed.previous_retirement = Some([0x93; 32]),
        }
        metadata::test_replace_component(
            &fixture.operation,
            Some(first.ordinal()),
            "committed.nrt",
            Some(&encode(&changed, MAX_RECORD_BYTES).unwrap()),
        )
        .unwrap();
        let expected = if field == "request" {
            "retirement changed the committed wallet request"
        } else {
            "dispatch commit differs from original custody"
        };
        require_unchanged_refusal(&fixture, &first, expected, || {
            retire_request(&first, &next, &receipt)
        });
        restore(&fixture, &original);
    }
    let wrong_observation = encode(
        &Observation {
            enrollment_observed_at_unix_ms: Some(1),
        },
        MAX_RECORD_BYTES,
    )
    .unwrap();
    for changed in [None, Some(wrong_observation.as_slice())] {
        metadata::test_replace_component(
            &fixture.operation,
            Some(first.ordinal()),
            "observation.nrt",
            changed,
        )
        .unwrap();
        let expected = if changed.is_none() {
            "committed dispatch lost its original observation"
        } else {
            "dispatch observation differs from its purpose or original bounds"
        };
        require_unchanged_refusal(&fixture, &first, expected, || {
            retire_request(&first, &next, &receipt)
        });
        restore(&fixture, &original);
    }
    retire_request(&first, &next, &receipt).unwrap();
    retire_request(&first, &next, &receipt).unwrap();
    assert!(
        metadata::load(&fixture.operation)
            .unwrap()
            .read::<Commit>(Some(first.ordinal()), 2)
            .unwrap()
            .as_ref()
            == Some(&commit)
    );
    assert_eq!(
        std::fs::read(first.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn observed_commit_deletion_or_replacement_cannot_be_accepted_as_stale_retirement() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    let history = fixture.history().unwrap();
    let observed = &history.attempts[0];
    assert!(observed.commit.is_some());
    let next = successor(&fixture, 1);
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    let original = image(&fixture);
    let mut changed = observed.commit.clone().unwrap();
    changed.request_sha256 = "0".repeat(64);
    let changed = encode(&changed, MAX_RECORD_BYTES).unwrap();
    for replacement in [None, Some(changed.as_slice())] {
        metadata::test_replace_component(
            &fixture.operation,
            Some(first.ordinal()),
            "committed.nrt",
            replacement,
        )
        .unwrap();
        require_unchanged_refusal(
            &fixture,
            &first,
            "retirement commit changed before metadata publication",
            || retire_request(observed, &next, &receipt),
        );
        restore(&fixture, &original);
    }
    retire_request(observed, &next, &receipt).unwrap();
}

#[test]
fn missing_wallet_retirement_refuses_a_fresh_commit_hidden_by_a_stale_attempt() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    let next = successor(&fixture, 1);
    assert!(first.commit.is_none());
    let held = fixture.temporary.path().join("held-request");
    std::fs::rename(first.wallet_path(), &held).unwrap();
    assert!(first.directory.entries(7).unwrap().is_empty());
    require_unchanged_refusal(
        &fixture,
        &first,
        "a committed dispatch cannot infer unsigned absence from a missing wallet",
        || retire_missing(&first, &next),
    );
    std::fs::rename(&held, first.wallet_path()).unwrap();
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    retire_request(&first, &next, &receipt).unwrap();
}

#[test]
fn stale_later_commit_retirement_keeps_the_exact_predecessor_retirement_link() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let first = fixture.reserve();
    fixture.commit(&first);
    let second = successor(&fixture, 1);
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&first.wallet_path(), &fixture.request(&first))
        .unwrap();
    retire_request(&first, &second, &receipt).unwrap();
    let retained = fixture.retain(&second);
    commit(&second, Some(&first), Observation::ordinary(), &retained).unwrap();
    let third = successor(&fixture, 2);
    let receipt = fixture
        .wallet
        .retire_initial_reserve_policy_unprepared(&second.wallet_path(), &fixture.request(&second))
        .unwrap();
    assert!(second.commit.is_none());
    let original = image(&fixture);
    let retirement: Retirement = metadata::load(&fixture.operation)
        .unwrap()
        .read(Some(first.ordinal()), 3)
        .unwrap()
        .unwrap();
    for field in ["authorization", "successor", "kind", "absent"] {
        let mut changed = retirement.clone();
        match field {
            "authorization" => changed.authorization = [0x81; 32],
            "successor" => changed.successor = [0x82; 32],
            _ => changed.kind = RetirementKind::Missing,
        }
        let changed = encode(&changed, MAX_RECORD_BYTES).unwrap();
        metadata::test_replace_component(
            &fixture.operation,
            Some(first.ordinal()),
            "retired.nrt",
            (field != "absent").then_some(changed.as_slice()),
        )
        .unwrap();
        let expected = if field == "absent" {
            "dispatch predecessor was not retired"
        } else {
            "dispatch commit differs from original custody"
        };
        require_unchanged_refusal(&fixture, &second, expected, || {
            retire_request(&second, &third, &receipt)
        });
        restore(&fixture, &original);
    }
    retire_request(&second, &third, &receipt).unwrap();
    let retained = fixture.retain(&third);
    commit(&third, Some(&second), Observation::ordinary(), &retained).unwrap();
    let history = fixture.history().unwrap();
    history
        .verify_wallets(|attempt| fixture.inspect(attempt))
        .unwrap();
    assert_eq!(history.selected().unwrap().unwrap().ordinal(), 3);
}
