//! Genuine Configure/Enroll recovery sources and original active-owner admission equality.

use super::*;
use crate::managed::native_operation::test_support::UnavailablePeers;
use crate::managed::stream_token_custody::renewal_tests::Fixture;
use std::path::PathBuf;

fn recover(
    fixture: &mut Fixture,
    purpose: CustodyPurpose,
    scoped: bool,
    deadline: Instant,
) -> Result<Option<ManagedCustodyProgress>> {
    let fees = Fees::from_options(&fixture.options)?;
    if scoped {
        fixture.owner.recover_selected(
            &fixture.policy,
            &fees,
            deadline,
            purpose,
            Mode::ObserveLocal,
        )
    } else {
        // The same canonical production body with its original independent imports.
        fixture.owner.recover_selected_with_validation(
            &fixture.policy,
            &fees,
            deadline,
            purpose,
            Mode::ObserveLocal,
            None,
        )
    }
}

fn assert_same(actual: ManagedCustodyProgress, expected: &ManagedCustodyProgress) {
    assert_eq!(actual.transaction_status, expected.transaction_status);
    assert_eq!(actual.finalized, expected.finalized);
    assert!(actual.current.is_none() && expected.current.is_none());
}

fn retained_paths(
    fixture: &Fixture,
    purpose: CustodyPurpose,
) -> Vec<(PathBuf, &'static str, usize)> {
    let (body, selected) = if purpose == CustodyPurpose::Configure {
        let body = fixture
            .owner
            .authority
            .directory
            .open_child("configure")
            .unwrap();
        let selected = journal::required_original(&body).unwrap();
        (body.path().to_owned(), selected)
    } else {
        let history = BodyHistory::open(&fixture.owner, purpose).unwrap().unwrap();
        let body = history.dispatch().unwrap().0.path().to_owned();
        (body, history.into_selected().unwrap())
    };
    let attempt = selected.directory().path().to_owned();
    vec![
        (body, "original.nrt", journal::MAX_ORIGINAL_BYTES),
        (attempt.clone(), "carrier.nrt", MAX_CHECKPOINT_BYTES),
        (
            attempt.join("transaction"),
            "operation.json",
            4 * 1024 * 1024,
        ),
    ]
}

#[test]
fn configure_and_enroll_recovery_workspace_preserves_native_source_refusal_and_retry() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    for purpose in [CustodyPurpose::Configure, CustodyPurpose::InitialEnroll] {
        let expected = recover(&mut fixture, purpose, false, deadline)
            .unwrap()
            .unwrap();
        assert_eq!(expected.transaction_status, OperationStatus::Applied);
        assert_eq!(
            expected.finalized.unwrap().height,
            if purpose == CustodyPurpose::Configure {
                3
            } else {
                4
            }
        );
        assert_same(
            recover(&mut fixture, purpose, true, deadline)
                .unwrap()
                .unwrap(),
            &expected,
        );
        // These are actual paid originals, signed wallets and native certified carriers.
        for (path, name, maximum) in retained_paths(&fixture, purpose) {
            let directory = PrivateDirectory::open_exact(&path).unwrap();
            let before = directory.read(name, maximum).unwrap();
            directory
                .write_atomic(name, &[0xff], PublishMode::Replace)
                .unwrap();
            let expected_error = recover(&mut fixture, purpose, false, deadline)
                .unwrap_err()
                .to_string();
            assert_eq!(
                recover(&mut fixture, purpose, true, deadline)
                    .unwrap_err()
                    .to_string(),
                expected_error
            );
            directory
                .write_atomic(name, &before, PublishMode::Replace)
                .unwrap();
            assert_eq!(directory.read(name, maximum).unwrap(), before);
            assert_same(
                recover(&mut fixture, purpose, true, deadline)
                    .unwrap()
                    .unwrap(),
                &expected,
            );
        }
        let expired = Instant::now();
        assert!(matches!(
            recover(&mut fixture, purpose, false, expired),
            Err(crate::managed::Error::NativeDeadline)
        ));
        assert!(matches!(
            recover(&mut fixture, purpose, true, expired),
            Err(crate::managed::Error::NativeDeadline)
        ));
        assert_same(
            recover(&mut fixture, purpose, true, deadline)
                .unwrap()
                .unwrap(),
            &expected,
        );
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn warmed_recovery_workspace_keeps_exact_finite_and_refused_outer_charges() {
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
    let mut fixture = Fixture::enrolled(4_000);
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    let ceiling = 256 * 1024 * 1024;
    for purpose in [CustodyPurpose::Configure, CustodyPurpose::InitialEnroll] {
        let warm = recover(&mut fixture, purpose, true, deadline)
            .unwrap()
            .unwrap();
        let original_budget = DecodeBudgetContext::new(limits(ceiling));
        let expected = original_budget
            .with(|| recover(&mut fixture, purpose, false, deadline))
            .unwrap()
            .unwrap();
        let charge = original_budget.consumed_allocated_bytes();
        assert!(charge > 0 && charge < ceiling as u64);
        let exact_budget = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
        let actual = exact_budget
            .with(|| recover(&mut fixture, purpose, true, deadline))
            .unwrap()
            .unwrap();
        assert_eq!(exact_budget.consumed_allocated_bytes(), charge);
        assert_same(actual, &expected);
        assert_same(
            recover(&mut fixture, purpose, true, deadline)
                .unwrap()
                .unwrap(),
            &warm,
        );
        assert!(!norito::core::decode_limits_active());
        for allocation in [0, 1] {
            let original_budget = DecodeBudgetContext::new(limits(allocation));
            let expected_error = original_budget
                .with(|| recover(&mut fixture, purpose, false, deadline))
                .unwrap_err()
                .to_string();
            let scoped_budget = DecodeBudgetContext::new(limits(allocation));
            let actual_error = scoped_budget
                .with(|| recover(&mut fixture, purpose, true, deadline))
                .unwrap_err()
                .to_string();
            assert_eq!(actual_error, expected_error);
            assert_eq!(
                scoped_budget.consumed_allocated_bytes(),
                original_budget.consumed_allocated_bytes()
            );
            assert!(!norito::core::decode_limits_active());
            assert_same(
                recover(&mut fixture, purpose, true, deadline)
                    .unwrap()
                    .unwrap(),
                &warm,
            );
        }
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
