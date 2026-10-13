//! Local first-reservation capability controls; concrete native proof controls live with each owner.
use super::*;
use crate::managed::native_operation::initial_intent::PublishedInitialIntent;
use std::cell::Cell;

fn generated_with(
    fixture: &Fixture,
    fresh: impl FnMut(GeneratedPrerequisite<'_>, Instant) -> Result<Observation>,
) -> Result<()> {
    let grant = fixture
        .authorization
        .as_ref()
        .unwrap()
        .test_child(Purpose::ReservePolicy)?;
    generated(
        &fixture.operation,
        Purpose::ReservePolicy,
        fixture.semantic,
        &HistoryScope::FixedBody,
        &grant,
        fixture.deadline,
        None,
        |attempt| fixture.inspect(attempt),
        |_| Err(invalid("first reservation has no predecessor")),
        |attempt, _, _| Ok(fixture.retain(attempt)),
        fresh,
        |_| Ok(true),
    )
}

#[test]
fn first_reservation_requires_exact_native_owner_and_closes_original_after_ordinary_error() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::build_with_original(true, false);
    // This local-record fixture owns the genuine atomic Unselected image. Its canonical
    // policy bytes are sufficient semantic input without claiming a native proof.
    let bytes = encode(&fixture.policy, MAX_RECORD_BYTES).unwrap();
    let mut publication = PublishedInitialIntent::publish(
        &fixture.operation,
        bytes.to_vec(),
        MAX_RECORD_BYTES,
        "test original changed",
    )
    .unwrap();
    assert!(
        PublishedInitialIntent::publish(
            &fixture.operation,
            bytes.to_vec(),
            MAX_RECORD_BYTES,
            "test original changed"
        )
        .unwrap()
        .is_none()
    );
    let entered = Cell::new(false);
    let error = generated_with(&fixture, |prerequisite, _| {
        let first = prerequisite
            .into_first()
            .expect("sole empty generated reservation");
        first.validate(&fixture.operation, Purpose::ReservePolicy, fixture.semantic)?;
        let reopened = PrivateDirectory::open_exact(fixture.operation.path()).unwrap();
        assert!(
            first
                .validate(&reopened, Purpose::ReservePolicy, fixture.semantic)
                .is_err()
        );
        assert!(
            first
                .validate(
                    &fixture.operation,
                    Purpose::ReserveAccount(ProviderId([7; 32])),
                    fixture.semantic
                )
                .is_err()
        );
        assert!(
            first
                .validate(&fixture.operation, Purpose::ReservePolicy, [8; 32])
                .is_err()
        );
        let row = fixture
            .operation
            .open_child("attempts")
            .unwrap()
            .open_child("0001")
            .unwrap();
        let authorization =
            metadata::test_read_component(&fixture.operation, Some(1), "authorization.nrt")
                .unwrap()
                .unwrap();
        let mut changed = authorization.clone();
        changed.push(0);
        metadata::test_replace_component(
            &fixture.operation,
            Some(1),
            "authorization.nrt",
            Some(&changed),
        )
        .unwrap();
        assert!(
            first
                .validate(&fixture.operation, Purpose::ReservePolicy, fixture.semantic)
                .is_err()
        );
        metadata::test_replace_component(
            &fixture.operation,
            Some(1),
            "authorization.nrt",
            Some(&authorization),
        )
        .unwrap();
        row.write_atomic("foreign.nrt", b"unexpected", PublishMode::CreateNew)
            .unwrap();
        assert!(
            first
                .validate(&fixture.operation, Purpose::ReservePolicy, fixture.semantic)
                .is_err()
        );
        std::fs::remove_file(row.path().join("foreign.nrt")).unwrap();
        first.validate(&fixture.operation, Purpose::ReservePolicy, fixture.semantic)?;
        let owned = publication.take().unwrap();
        owned.admit(&first, Purpose::ReservePolicy, fixture.semantic, || {
            entered.set(true);
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            fixture
                .operation
                .write_atomic("original.nrt", &changed, PublishMode::Replace)
                .unwrap();
            Err(invalid("ordinary pure prerequisite error"))
        })
    })
    .unwrap_err();
    assert!(entered.get());
    assert!(
        !error
            .to_string()
            .contains("ordinary pure prerequisite error"),
        "source exit has precedence: {error}"
    );
    assert!(publication.is_none());
    assert!(
        !fixture
            .operation
            .path()
            .join("attempts/0001/transaction")
            .exists()
    );
    fixture
        .operation
        .write_atomic("original.nrt", &bytes, PublishMode::Replace)
        .unwrap();
    let calls = Cell::new(0);
    generated_with(&fixture, |prerequisite, _| {
        calls.set(calls.get() + 1);
        assert!(
            prerequisite.into_first().is_none(),
            "retained authorization is not a new reservation"
        );
        Err(invalid("canonical recovered source refusal"))
    })
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert_eq!(fixture.history().unwrap().reserved_attempt_count(), 1);
    assert!(
        !fixture
            .operation
            .path()
            .join("attempts/0001/transaction")
            .exists()
    );
}

#[test]
fn zero_request_pending_and_paid_prefixes_do_not_gain_initial_admission() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::build(true);
    // A genuine pending first reservation with zero children must use ordinary recovery.
    fixture
        .history()
        .unwrap()
        .reserve_pending(&fixture.operation, Origin::Explicit, fixture.terms.clone())
        .unwrap();
    assert!(!fixture.operation.path().join("attempts").exists());
    let calls = Cell::new(0);
    generated_with(&fixture, |prerequisite, _| {
        calls.set(calls.get() + 1);
        assert!(prerequisite.into_first().is_none());
        Err(invalid("canonical source unavailable"))
    })
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    let history = fixture.history().unwrap();
    let first = history.last().unwrap();
    assert!(!first.wallet_path().exists());
    fixture.commit(first);
    let request = std::fs::read(first.wallet_path().join("preparation.json")).unwrap();
    generated_with(&fixture, |_, _| {
        Err(invalid(
            "committed live request never needs a new prerequisite",
        ))
    })
    .unwrap();
    assert_eq!(
        std::fs::read(first.wallet_path().join("preparation.json")).unwrap(),
        request
    );
    fixture.sign(first);
    assert_eq!(
        fixture.inspect(first).unwrap().phase(),
        NativePreparationPhase::Signed
    );
    let payload = std::fs::read(first.wallet_path().join("payload.json")).unwrap();
    generated_with(&fixture, |_, _| {
        Err(invalid("paid original must not ask for initial admission"))
    })
    .unwrap();
    assert_eq!(
        std::fs::read(first.wallet_path().join("payload.json")).unwrap(),
        payload
    );
    assert!(!first.wallet_path().join("submission.json").exists());
}

#[test]
fn active_and_late_active_generated_prerequisites_keep_canonical_admission() {
    let _resources = crate::managed::native_test_guard();
    let fixture = Fixture::build(true);
    let original = fixture
        .operation
        .read("original.nrt", MAX_RECORD_BYTES)
        .unwrap();
    let calls = Cell::new(0);
    for allocation in [0, 1] {
        let limits = norito::DecodeLimits::new(
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            MAX_RECORD_BYTES,
            allocation,
            64,
        );
        let result = norito::core::with_decode_limits_scope(limits, || {
            generated_with(&fixture, |_, _| {
                calls.set(calls.get() + 1);
                Err(invalid("active refused before source"))
            })
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        assert_eq!(
            fixture
                .operation
                .read("original.nrt", MAX_RECORD_BYTES)
                .unwrap(),
            original
        );
        assert!(
            metadata::test_read_component(&fixture.operation, None, "dispatch.nrt")
                .unwrap()
                .is_none()
        );
    }
    let wide = norito::DecodeLimits::new(
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        MAX_RECORD_BYTES,
        64 * 1024 * 1024,
        64,
    );
    let budget = norito::core::DecodeBudgetContext::new(wide);
    let error = budget
        .with(|| {
            generated_with(&fixture, |prerequisite, _| {
                calls.set(calls.get() + 1);
                assert!(
                    prerequisite.into_first().is_none(),
                    "active producer retains ordinary source callback"
                );
                Err(invalid("active canonical source refused"))
            })
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("active canonical source refused"),
        "{error}"
    );
    assert_eq!(calls.get(), 1);
    assert!(budget.consumed_allocated_bytes() > 0);
    assert!(budget.consumed_allocated_bytes() <= 64 * 1024 * 1024);
    assert!(
        !fixture
            .operation
            .path()
            .join("attempts/0001/transaction")
            .exists()
    );

    let late = Fixture::build(true);
    let late_calls = Cell::new(0);
    generated_with(&late, |prerequisite, _| {
        late_calls.set(late_calls.get() + 1);
        let no_first =
            norito::core::with_decode_limits_scope(wide, || prerequisite.into_first().is_none());
        assert!(
            no_first,
            "budget installed after reservation also disables reuse"
        );
        Err(invalid("late-active canonical source remains required"))
    })
    .unwrap_err();
    assert_eq!(late_calls.get(), 1);
    assert!(
        !late
            .operation
            .path()
            .join("attempts/0001/transaction")
            .exists()
    );
}

#[test]
fn active_original_publication_keeps_the_existing_write_recipe_without_a_receipt() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let parent = PrivateDirectory::open_or_create(temporary.path().join("parent")).unwrap();
    let directory = metadata::ensure_operation(&parent, "publication").unwrap();
    // Local publication custody only: these bytes are never passed as native proof or intent.
    let original = vec![4, 5, 6];
    let limits =
        norito::DecodeLimits::new(MAX_RECORD_BYTES, MAX_RECORD_BYTES, MAX_RECORD_BYTES, 0, 64);
    assert!(
        norito::core::with_decode_limits_scope(limits, || PublishedInitialIntent::publish(
            &directory,
            original.clone(),
            MAX_RECORD_BYTES,
            "exact original changed",
        ))
        .unwrap()
        .is_none()
    );
    assert_eq!(
        directory
            .read("original.nrt", MAX_RECORD_BYTES)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    assert!(
        PublishedInitialIntent::publish(
            &directory,
            original.clone(),
            MAX_RECORD_BYTES,
            "exact original changed"
        )
        .unwrap()
        .is_none()
    );
    let error = match PublishedInitialIntent::publish(
        &directory,
        vec![7, 8, 9],
        MAX_RECORD_BYTES,
        "exact original changed",
    ) {
        Err(error) => error,
        Ok(_) => panic!("different bytes were admitted"),
    };
    assert!(error.to_string().contains("exact original changed"));
    assert_eq!(
        directory
            .read("original.nrt", MAX_RECORD_BYTES)
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    assert_eq!(
        directory.entries(2).unwrap(),
        [
            std::ffi::OsString::from(metadata::FILE),
            std::ffi::OsString::from("original.nrt")
        ]
    );
}
