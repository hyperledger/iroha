//! Genuine retained-enrollment route reuse, original source refusal and active-budget equality.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    stream_token_custody::{renewal_tests::Fixture, tests::count_wallet_constructions},
};
use std::path::PathBuf;

fn assert_same(actual: &RetainedCustodyEnrollment, expected: &RetainedCustodyEnrollment) {
    assert_eq!(actual.bytes(), expected.bytes());
    assert!(actual.statement() == expected.statement());
    assert_eq!(actual.record_digest(), expected.record_digest());
    assert_eq!(actual.finalized(), expected.finalized());
}

fn retained_paths(fixture: &Fixture) -> Vec<(PathBuf, &'static str, usize)> {
    let configured_root = fixture
        .owner
        .authority
        .directory
        .open_child("configure")
        .unwrap();
    let configured = journal::required_original(&configured_root).unwrap();
    let initial = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    let initial_body = initial.dispatch().unwrap().0.path().to_owned();
    let initial = initial.into_selected().unwrap();
    let mut paths = Vec::new();
    for (body, attempt) in [
        (
            configured_root.path().to_owned(),
            configured.directory().path().to_owned(),
        ),
        (initial_body, initial.directory().path().to_owned()),
    ] {
        paths.push((body, "original.nrt", journal::MAX_ORIGINAL_BYTES));
        paths.push((attempt.clone(), "carrier.nrt", MAX_CHECKPOINT_BYTES));
        for name in ["preparation.json", "operation.json"] {
            paths.push((attempt.join("transaction"), name, 4 * 1024 * 1024));
        }
    }
    paths
}

// Test-only original independent sequence, using the unchanged canonical verifiers.
fn independent_retained_enrollment(
    owner: &ManagedStreamTokenCustody,
    policy: &SignerCustodyPolicyV1,
    interval: ManagedCustodyEnrollmentInterval,
    deadline: Instant,
) -> Result<RetainedCustodyEnrollment> {
    require_deadline(deadline)?;
    owner.authority.validate_profile()?;
    owner.validate_policy(policy)?;
    let (configured_policy, configured) = owner.retained_configuration(deadline)?;
    if configured_policy != *policy {
        return Err(invalid("retained enrollment policy differs"));
    }
    let original = owner.required_enrollment(CustodyPurpose::InitialEnroll)?;
    owner.verify_retained_enrollment(
        CustodyPurpose::InitialEnroll,
        policy,
        Some(interval),
        &configured,
        original,
        deadline,
    )
}

#[test]
fn retained_enrollment_epoch_workspace_keeps_original_source_refusal_and_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let independent = || {
        independent_retained_enrollment(&fixture.owner, &fixture.policy, fixture.initial, deadline)
    };
    let scoped = || {
        fixture
            .owner
            .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
    };
    let expected = independent().unwrap();
    let (actual, wallets) = count_wallet_constructions(scoped);
    assert_same(&actual.unwrap(), &expected);
    assert_eq!(wallets, 1);

    // Actual Configure carrier, initial body, carrier and observed wallet remain fresh reads.
    // These are original signed/paid H2/H3/H4 inputs, not a constructed proof or response.
    let paths = retained_paths(&fixture);
    for index in [1, 4, 5, 7] {
        let (path, name, maximum) = &paths[index];
        let directory = PrivateDirectory::open_exact(path).unwrap();
        let before = directory.read(name, *maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        let original_error = independent().unwrap_err().to_string();
        assert_eq!(scoped().unwrap_err().to_string(), original_error);
        directory
            .write_atomic(name, &before, PublishMode::Replace)
            .unwrap();
        assert_eq!(directory.read(name, *maximum).unwrap(), before);
        assert_same(&scoped().unwrap(), &expected);
    }

    let mut changed_interval = fixture.initial;
    changed_interval.issued_at_unix_ms += 1;
    let expected_error = independent_retained_enrollment(
        &fixture.owner,
        &fixture.policy,
        changed_interval,
        deadline,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        fixture
            .owner
            .retained_initial_enrollment(&fixture.policy, changed_interval, deadline)
            .unwrap_err()
            .to_string(),
        expected_error
    );
    let expired = Instant::now();
    assert_eq!(
        fixture
            .owner
            .retained_initial_enrollment(&fixture.policy, fixture.initial, expired)
            .unwrap_err()
            .to_string(),
        independent_retained_enrollment(&fixture.owner, &fixture.policy, fixture.initial, expired,)
            .unwrap_err()
            .to_string()
    );
    assert_same(&scoped().unwrap(), &expected);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn configuration_handoff_epoch_workspace_keeps_initial_source_refusal_and_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    // Retain only the same policy/finality tuple that survives the original Configure drop.
    let (policy, configured) = fixture.owner.retained_configuration(deadline).unwrap();
    let independent = || {
        fixture
            .owner
            .initial_prerequisite_after_configuration_with_imports(
                policy.clone(),
                configured,
                deadline,
                &mut CheckpointImports::new(&fixture.owner.authority, None),
            )
    };
    let scoped = || {
        fixture
            .owner
            .initial_prerequisite_after_configuration(policy.clone(), configured, deadline)
    };
    let expected = independent().unwrap();
    let (actual, wallets) = count_wallet_constructions(scoped);
    let actual = actual.unwrap();
    assert_eq!(actual.policy, expected.policy);
    assert_same(&actual.enrollment, &expected.enrollment);
    assert_eq!(wallets, 1);
    let paths = retained_paths(&fixture);
    for index in [4, 5, 7] {
        let (path, name, maximum) = &paths[index];
        let directory = PrivateDirectory::open_exact(path).unwrap();
        let before = directory.read(name, *maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        let original_error = independent()
            .err()
            .expect("original initial source refuses")
            .to_string();
        assert_eq!(
            scoped()
                .err()
                .expect("scoped initial source refuses")
                .to_string(),
            original_error
        );
        directory
            .write_atomic(name, &before, PublishMode::Replace)
            .unwrap();
        assert_eq!(directory.read(name, *maximum).unwrap(), before);
        let restored = scoped().unwrap();
        assert_eq!(restored.policy, expected.policy);
        assert_same(&restored.enrollment, &expected.enrollment);
    }
    // The canonical consuming handoff still reaches this route after its own fresh fences.
    let (handoff, wallets) = count_wallet_constructions(|| {
        fixture
            .owner
            .read_configuration(deadline)?
            .into_initial_prerequisite(deadline)
    });
    let handoff = handoff.unwrap();
    assert_eq!(wallets, 1);
    assert_eq!(handoff.policy, expected.policy);
    assert_same(&handoff.enrollment, &expected.enrollment);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn enrollment_epoch_workspaces_preserve_independent_finite_outer_admission() {
    use norito::core::DecodeBudgetContext;
    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let (policy, configured) = fixture.owner.retained_configuration(deadline).unwrap();
    // Each branch borrows the same canonical source bodies; only its ownership entry differs.
    let read = |handoff: bool, scoped: bool| -> Result<RetainedCustodyEnrollment> {
        if handoff {
            let result = if scoped {
                fixture.owner.initial_prerequisite_after_configuration(
                    policy.clone(),
                    configured,
                    deadline,
                )
            } else {
                fixture
                    .owner
                    .initial_prerequisite_after_configuration_with_imports(
                        policy.clone(),
                        configured,
                        deadline,
                        &mut CheckpointImports::new(&fixture.owner.authority, None),
                    )
            }?;
            assert_eq!(result.policy, policy);
            Ok(result.enrollment)
        } else if scoped {
            fixture
                .owner
                .retained_initial_enrollment(&policy, fixture.initial, deadline)
        } else {
            independent_retained_enrollment(&fixture.owner, &policy, fixture.initial, deadline)
        }
    };
    let ceiling = 256 * 1024 * 1024;
    for handoff in [false, true] {
        let warm = read(handoff, true).unwrap();
        let baseline = DecodeBudgetContext::new(limits(ceiling));
        let expected = baseline.with(|| read(handoff, false)).unwrap();
        let charge = baseline.consumed_allocated_bytes();
        assert!(charge > 0 && charge < ceiling as u64);
        let exact = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
        let actual = exact.with(|| read(handoff, true)).unwrap();
        assert_eq!(exact.consumed_allocated_bytes(), charge);
        assert_same(&actual, &expected);
        assert_same(&actual, &warm);
        assert!(!norito::core::decode_limits_active());
        for allocation in [0, 1] {
            let original_budget = DecodeBudgetContext::new(limits(allocation));
            let expected_error = original_budget
                .with(|| read(handoff, false))
                .unwrap_err()
                .to_string();
            let actual_budget = DecodeBudgetContext::new(limits(allocation));
            let actual_error = actual_budget
                .with(|| read(handoff, true))
                .unwrap_err()
                .to_string();
            assert_eq!(actual_error, expected_error);
            assert_eq!(
                actual_budget.consumed_allocated_bytes(),
                original_budget.consumed_allocated_bytes()
            );
            assert!(!norito::core::decode_limits_active());
            assert_same(&read(handoff, true).unwrap(), &warm);
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
