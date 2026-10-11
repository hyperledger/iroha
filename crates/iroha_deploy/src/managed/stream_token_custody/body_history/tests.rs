//! Genuine native predecessor plus local custody/opaque-wallet retirement controls.
//! Local reservation counting does not claim paid execution or current signing eligibility.

use super::*;
use crate::managed::stream_token_custody::{
    bootstrap_test_support::NativeEnrollmentReads,
    renewal_tests::{Fixture, wait_until},
};
use iroha_wallet::operations::NativePreparationPhase;
use std::time::Duration;

fn ready() -> Fixture {
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    fixture
}
fn fresh_unsigned(fixture: &Fixture) -> (UnsignedEnrollment, VerifiedStreamTokenCustodyStateV1) {
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms().unwrap() + 2_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            fixture.options.deadline,
        )
        .unwrap();
    (unsigned, current)
}
fn retain_body(fixture: &Fixture) -> BodyHistory {
    let (unsigned, current) = fresh_unsigned(fixture);
    fixture.owner.bootstrap_native_body(
        &fixture.native,
        &current,
        CustodyPurpose::Renewal(2),
        unsigned,
        now_ms().unwrap() + 2_000,
        &fixture.options,
    )
}
fn retain_request(
    fixture: &Fixture,
    history: &BodyHistory,
    lifetime_ms: u64,
) -> Selected<Original> {
    let (directory, original, scope) = history.dispatch().unwrap();
    journal::explicit(
        directory,
        original,
        now_ms().unwrap() + lifetime_ms,
        &fixture.options,
        &fixture.owner.wallet().unwrap(),
        scope,
    )
    .unwrap();
    history.retained_selected(&fixture.owner).unwrap()
}
fn expiry(history: &BodyHistory) -> u64 {
    history
        .bodies
        .last()
        .unwrap()
        .reservation
        .unsigned
        .statement
        .expires_at_unix_ms
}
fn reopen(fixture: &Fixture) -> BodyHistory {
    BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap()
}

#[test]
fn completed_body_and_high_water_loss_refuse_and_scope_rechecks_outer_names() {
    let _guard = crate::managed::native_test_guard();
    let fixture = ready();
    let history = retain_body(&fixture);
    let completed_original = history
        .original()
        .unwrap()
        .expect("fixture renewal must retain a signed body before completion-loss mutation");
    assert_eq!(
        history.anchor.completed,
        Some(completed_original.digest().unwrap()),
        "fixture renewal must complete before completion-loss mutation"
    );
    let reparsed = history.read_current(&fixture.owner).unwrap();
    assert!(Arc::ptr_eq(&history.root, &reparsed.root));
    assert!(Arc::ptr_eq(
        history.body_root.as_ref().unwrap(),
        reparsed.body_root.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        &history.bodies[0].directory,
        &reparsed.bodies[0].directory
    ));
    assert_eq!(
        history.selection.digest().unwrap(),
        reparsed.selection.digest().unwrap()
    );
    drop(reparsed);
    // Ordinary crash parsing can admit Original-before-completion publication. An already
    // retained completed anchor cannot be reinterpreted as that earlier prefix.
    let completed_anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let mut regressed = history.anchor.clone();
    regressed.completed = None;
    history
        .root
        .write_atomic(
            "anchor.nrt",
            &encode(&regressed, MAX_BODY_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(history.read_current(&fixture.owner).is_err());
    history
        .root
        .write_atomic("anchor.nrt", &completed_anchor, PublishMode::Replace)
        .unwrap();
    assert!(history.read_current(&fixture.owner).is_ok());
    let (body, original, scope) = history.dispatch().unwrap();
    let wire = encode(original, journal::MAX_ORIGINAL_BYTES).unwrap();
    let root_anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let container = history.root.open_child("bodies").unwrap();
    container
        .write_atomic("unknown.nrt", b"local corruption", PublishMode::CreateNew)
        .unwrap();
    assert!(
        History::read(
            body,
            original.dispatch_purpose().unwrap(),
            original.digest().unwrap(),
            scope
        )
        .is_err()
    );
    std::fs::remove_file(container.path().join("unknown.nrt")).unwrap();
    assert!(history.read_current(&fixture.owner).is_ok());
    let selected_path = body.path().join("original.nrt");
    let held_path = fixture._temporary.path().join("held-completed-body.nrt");
    std::fs::rename(&selected_path, &held_path).unwrap();
    assert!(matches!(
        BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::RetainedMaterial
        ))
    ));
    assert!(history.read_current(&fixture.owner).is_err());
    assert!(!selected_path.exists());
    assert_eq!(
        history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        root_anchor
    );
    std::fs::rename(&held_path, &selected_path).unwrap();
    assert_eq!(
        body.read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap()
            .as_slice(),
        wire
    );
    let held_body = fixture._temporary.path().join("held-whole-body");
    std::fs::rename(body.path(), &held_body).unwrap();
    assert!(BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)).is_err());
    assert!(!body.path().exists());
    std::fs::rename(&held_body, body.path()).unwrap();
    let anchor_path = history.root.path().join("anchor.nrt");
    let held_anchor = fixture._temporary.path().join("held-anchor.nrt");
    std::fs::rename(&anchor_path, &held_anchor).unwrap();
    assert!(BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)).is_err());
    assert!(history.read_current(&fixture.owner).is_err());
    assert!(!anchor_path.exists());
    std::fs::rename(&held_anchor, &anchor_path).unwrap();
    let original = reopen(&fixture);
    assert!(original.current_history().unwrap().last().is_none());
    assert_eq!(
        original.anchor.completed,
        Some(original.original().unwrap().unwrap().digest().unwrap())
    );
}

#[test]
fn expired_request_retirement_recovers_after_actual_wallet_retirement_before_closed_record() {
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled_with_renewal_validity(4_000, 20_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let history = retain_body(&fixture);
    let old = retain_request(&fixture, &history, 3_000);
    let account = fixture.owner.wallet().unwrap();
    let request_path = old.directory().path().join("transaction");
    let request_bytes = std::fs::read(request_path.join("preparation.json")).unwrap();
    let body_bytes = history
        .dispatch()
        .unwrap()
        .0
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    wait_until(expiry(&history), Duration::from_secs(22));
    let mut turn = fixture.renewal_turn();
    let history = reopen(&fixture);
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    let mut reserved = history
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            authorization,
            fixture.options.deadline,
        )
        .unwrap();
    assert!(reserved.has_pending());
    assert!(reserved.dispatch().is_err());
    let successor = reserved.successor(0).unwrap().unwrap();
    let active = reserved.active.take().unwrap();
    let original = reserved.bodies[0].original.as_ref().unwrap();
    let pending = active
        .history
        .prepare_unsigned_closure(
            &successor,
            authorization,
            fixture.options.deadline,
            |attempt| {
                original
                    .request(
                        attempt.terms(),
                        attempt.observation()?,
                        fixture.options.deadline,
                    )?
                    .inspect(&account, &attempt.wallet_path())
            },
            |attempt| {
                original
                    .request(
                        attempt.terms(),
                        attempt.observation()?,
                        fixture.options.deadline,
                    )?
                    .retire(&account, &attempt.wallet_path())
            },
        )
        .unwrap();
    let failed = pending.finish(
        &successor,
        authorization,
        fixture.options.deadline,
        |attempt| {
            original
                .request(
                    attempt.terms(),
                    attempt.observation()?,
                    fixture.options.deadline,
                )?
                .inspect(&account, &attempt.wallet_path())
        },
        |attempt| {
            original
                .request(
                    attempt.terms(),
                    attempt.observation()?,
                    fixture.options.deadline,
                )?
                .retire(&account, &attempt.wallet_path())?;
            Err(invalid(
                "stop after real wallet retirement before closure publication",
            ))
        },
    );
    assert!(failed.is_err());
    assert_eq!(
        old.request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &request_path)
            .unwrap()
            .phase(),
        NativePreparationPhase::Retired
    );
    assert!(
        !reserved.bodies[0]
            .directory
            .path()
            .join("closed.nrt")
            .exists()
    );
    let resumed = reopen(&fixture)
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(resumed.anchor.highest, 2);
    assert_eq!(
        resumed
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        1
    );
    assert!(resumed.current_history().unwrap().last().is_none());
    assert_eq!(
        resumed.bodies[0]
            .directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body_bytes
    );
    assert_eq!(
        std::fs::read(request_path.join("preparation.json")).unwrap(),
        request_bytes
    );
    assert!(
        !request_path.join("payload.json").exists()
            && !request_path.join("operation.json").exists()
    );
    assert!(
        resumed.bodies[0]
            .directory
            .path()
            .join("closed.nrt")
            .exists()
    );
    assert_ne!(
        resumed.original().unwrap().unwrap().digest().unwrap(),
        old.digest().unwrap()
    );
    assert_eq!(fixture.native.chain.height(), 4); // Retirement itself executes no native transaction.
    // The replacement body then reaches the same paid wallet/native verifier, with the exact
    // original predecessor CAS; no synthetic completion or relaxed expiry is needed.
    let replacement = retain_request(&fixture, &resumed, 15_000);
    let mut http = crate::managed::native_operation::test_support::native_fixture::NativeReadHttp::start_config(
        &fixture.owner.authority.config, Arc::clone(fixture.native.chain.state()),
    );
    let journal::Request::Enroll(request) = replacement.request(fixture.options.deadline).unwrap()
    else {
        unreachable!()
    };
    account
        .prepare_stream_token_custody_enroll(
            &request,
            &replacement.directory().path().join("transaction"),
        )
        .unwrap();
    let signed = fixture
        .owner
        .verify_wallet(
            replacement.directory(),
            &replacement,
            fixture.options.deadline,
        )
        .unwrap();
    http.finish();
    let carrier = fixture
        .native
        .bootstrap_commit(&fixture.owner.authority, &signed);
    let finalized = crate::managed::native_operation::verify_carrier(&carrier, &signed).unwrap();
    assert_eq!(finalized.height, 5);
    replacement
        .directory()
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(&carrier).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    let retained = fixture
        .owner
        .retained_renewed_enrollment(2, &fixture.policy, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    assert_eq!(
        current
            .current()
            .unwrap()
            .record()
            .active_enrollment
            .as_deref(),
        Some(retained.bytes())
    );
    assert_eq!(
        current
            .current()
            .unwrap()
            .control()
            .active_head
            .unwrap()
            .sequence,
        2
    );
    assert_eq!(retained.finalized().height, 5);
    assert_eq!(
        reopen(&fixture)
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        2
    );
    assert_eq!(
        old.request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &request_path)
            .unwrap()
            .phase(),
        NativePreparationPhase::Retired
    );
}

#[test]
fn unused_expired_reservation_retires_without_inventing_a_wallet_or_dispatch_history() {
    let _guard = crate::managed::native_test_guard();
    let fixture = ready();
    let unsigned = fresh_unsigned(&fixture).0;
    let end = unsigned.statement.expires_at_unix_ms;
    let terms = Terms::new(now_ms().unwrap() + 2_000, &fixture.options).unwrap();
    let history = BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &terms.fees,
        &SigningTurn::Explicit(&terms),
        fixture.options.deadline,
    )
    .unwrap();
    assert!(history.has_pending());
    assert!(!history.root.path().join("bodies").exists());
    wait_until(end, Duration::from_secs(10));
    let mut turn = fixture.renewal_turn();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    let activated = history
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert!(!activated.has_pending());
    assert!(activated.original().unwrap().is_none());
    assert_eq!(
        activated.bodies[0].directory.entries(1).unwrap(),
        vec![std::ffi::OsString::from("reserved.nrt")]
    );
    let replacement = activated
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            authorization,
            fixture.options.deadline,
        )
        .unwrap()
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(
        replacement
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        0
    );
    assert!(replacement.bodies[0].unused.is_some());
    assert!(replacement.bodies[0].original.is_none());
    assert!(
        !replacement.bodies[0]
            .directory
            .path()
            .join("dispatch.nrt")
            .exists()
    );
    assert!(
        !replacement.bodies[0]
            .directory
            .path()
            .join("attempts")
            .exists()
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn signed_applied_expired_body_preserves_wire_and_recovers_missing_carrier_before_current_use_refusal()
 {
    use crate::managed::native_operation::test_support::native_fixture::NativeReadHttp;
    use crate::managed::stream_token_custody::renewal_tests::FixtureReads;
    let _guard = crate::managed::native_test_guard();
    let mut fixture = Fixture::enrolled_with_renewal_validity(4_000, 30_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let history = retain_body(&fixture);
    let old = retain_request(&fixture, &history, 15_000);
    let mut turn = fixture.renewal_turn();
    turn.authorize_retained(&fixture.owner, &reopen(&fixture), fixture.options.deadline)
        .unwrap();
    let account = fixture.owner.wallet().unwrap();
    let wallet_path = old.directory().path().join("transaction");
    let mut http = NativeReadHttp::start_config(
        &fixture.owner.authority.config,
        Arc::clone(fixture.native.chain.state()),
    );
    let journal::Request::Enroll(request) = old.request(fixture.options.deadline).unwrap() else {
        unreachable!()
    };
    account
        .prepare_stream_token_custody_enroll(&request, &wallet_path)
        .unwrap();
    let transaction = fixture
        .owner
        .verify_wallet(old.directory(), &old, fixture.options.deadline)
        .unwrap();
    http.finish();
    let wire = transaction.encode_wire_v1().unwrap();
    let body = history.bodies[0]
        .directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    assert_eq!(fixture.native.chain.commit(vec![transaction]), vec![true]);
    assert_eq!(fixture.native.chain.height(), 5);
    assert!(!old.directory().path().join("carrier.nrt").exists());
    wait_until(expiry(&history), Duration::from_secs(32));
    assert!(reopen(&fixture).preserve_paid_body(&fixture.owner).unwrap());
    let result = fixture.owner.reconcile_generated_with_reads(
        &mut turn,
        fixture.options.deadline,
        &FixtureReads {
            native: &fixture.native,
        },
    );
    assert!(matches!(
        result,
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::EnrollmentExpired
        ))
    ));
    assert!(old.directory().path().join("carrier.nrt").exists());
    let retained = fixture
        .owner
        .retained_renewed_enrollment(2, &fixture.policy, fixture.options.deadline)
        .unwrap();
    assert_eq!(retained.finalized().height, 5);
    assert_eq!(
        fixture
            .owner
            .verify_wallet(old.directory(), &old, fixture.options.deadline)
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    assert_eq!(
        history.bodies[0]
            .directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        body
    );
    assert_eq!(
        history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        anchor
    );
    assert_eq!(reopen(&fixture).anchor.highest, 1);
    assert!(!wallet_path.join("submission.json").exists());
    assert_eq!(fixture.native.chain.height(), 5);
}

#[test]
fn closed_body_count_carries_into_next_body_and_never_refunds_sixty_four_original_reservations() {
    use crate::managed::native_operation::authorization::DispatchAuthorization;
    let _guard = crate::managed::native_test_guard();
    let diagnostic = crate::managed::native_operation::deadline_diagnostics::Observer::begin();
    let fixture = ready();
    let history = retain_body(&fixture);
    let selected = retain_request(&fixture, &history, 3_000);
    wait_until(expiry(&history), Duration::from_secs(10));
    let (_, current) = fixture.current();
    diagnostic.successor();
    let mut turn = fixture.renewal_turn();
    let history = reopen(&fixture);
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let second = history
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            authorization,
            fixture.options.deadline,
        )
        .unwrap()
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(
        second
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        1
    );
    let second_body = second.dispatch().unwrap().0.path().to_owned();
    // Exercise the shared reservation/census boundary with genuine issued origins and no wallet
    // effects. These exact finite Terms remain historical reservations even if the body expires
    // during this local stress control; no callback may turn them into a paid dispatch.
    let terms = authorization
        .terms(fixture.options.deadline, Some(expiry(&second)))
        .unwrap_or_else(|error| {
            panic!(
                "cumulative reservation Terms refusal: {error:?}; after_failure_now={:?}; body_expiry={}; epoch_requested_deadline={}; epoch_signing_deadline={}",
                now_ms(),
                expiry(&second),
                authorization.lease().epoch.terms.requested_deadline_unix_ms,
                authorization.lease().epoch.terms.signing_deadline_unix_ms,
            )
        });
    let mut previous = second
        .current_history()
        .unwrap()
        .reserve(
            second.dispatch().unwrap().0,
            authorization.origin().unwrap(),
            terms.clone(),
        )
        .unwrap();
    for _ in 0..62 {
        diagnostic.replacement();
        let history = reopen(&fixture);
        let mut next_turn = fixture.renewal_turn();
        let live = next_turn
            .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
            .unwrap();
        let (directory, _, _) = history.dispatch().unwrap();
        let next = history
            .current_history()
            .unwrap()
            .reserve(directory, live.origin().unwrap(), terms.clone())
            .unwrap();
        attempts::retire_missing(&previous, &next).unwrap();
        previous = next;
    }
    diagnostic.final_checks();
    let history = reopen(&fixture);
    assert_eq!(
        history.current_history().unwrap().reserved_attempt_count(),
        63
    );
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        64
    );
    let before = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let before_names = PrivateDirectory::open_exact(&second_body)
        .unwrap()
        .open_child("attempts")
        .unwrap()
        .entries(64)
        .unwrap();
    let mut final_turn = fixture.renewal_turn();
    let live = final_turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    assert!(matches!(
        history.current_history().unwrap().reserve(
            history.dispatch().unwrap().0,
            live.origin().unwrap(),
            terms
        ),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::EpochLimit
        ))
    ));
    assert_eq!(
        history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        before
    );
    assert_eq!(
        PrivateDirectory::open_exact(&second_body)
            .unwrap()
            .open_child("attempts")
            .unwrap()
            .entries(64)
            .unwrap(),
        before_names
    );
    assert!(!second_body.join("attempts/0064").exists());
    assert_eq!(
        selected
            .request(fixture.options.deadline)
            .unwrap()
            .inspect(
                &fixture.owner.wallet().unwrap(),
                &selected.directory().path().join("transaction")
            )
            .unwrap()
            .phase(),
        NativePreparationPhase::Retired
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn paid_payload_and_signed_body_refuse_semantic_replacement_without_changing_originals() {
    use crate::managed::native_operation::test_support::native_fixture::NativeReadHttp;
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 20_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let history = retain_body(&fixture);
    let selected = retain_request(&fixture, &history, 15_000);
    let account = fixture.owner.wallet().unwrap();
    let path = selected.directory().path().join("transaction");
    let mut http = NativeReadHttp::start_config(
        &fixture.owner.authority.config,
        Arc::clone(fixture.native.chain.state()),
    );
    let journal::Request::Enroll(request) = selected.request(fixture.options.deadline).unwrap()
    else {
        unreachable!()
    };
    account
        .prepare_stream_token_custody_enroll(&request, &path)
        .unwrap();
    http.finish();
    let signed = std::fs::read(path.join("operation.json")).unwrap();
    let payload = std::fs::read(path.join("payload.json")).unwrap();
    let original = history.bodies[0]
        .directory
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    wait_until(expiry(&history), Duration::from_secs(22));
    let mut turn = fixture.renewal_turn();
    let retained = reopen(&fixture);
    let authorization = turn
        .authorize_retained(&fixture.owner, &retained, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    assert!(retained.preserve_paid_body(&fixture.owner).unwrap());
    assert!(
        retained
            .reserve_successor(
                &fixture.owner,
                fresh_unsigned(&fixture).0,
                &current,
                authorization,
                fixture.options.deadline
            )
            .is_err()
    );
    // This is a local crash-prefix control: the payload was emitted by the sole wallet owner.
    // Hiding its later signed record does not create authority or relax the retained payload.
    let held = fixture._temporary.path().join("held-signed-operation.json");
    std::fs::rename(path.join("operation.json"), &held).unwrap();
    assert_eq!(
        selected
            .request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &path)
            .unwrap()
            .phase(),
        NativePreparationPhase::PayloadRetained
    );
    let retained = reopen(&fixture);
    assert!(retained.preserve_paid_body(&fixture.owner).unwrap());
    assert!(
        retained
            .reserve_successor(
                &fixture.owner,
                fresh_unsigned(&fixture).0,
                &current,
                authorization,
                fixture.options.deadline
            )
            .is_err()
    );
    assert_eq!(std::fs::read(path.join("payload.json")).unwrap(), payload);
    assert!(!path.join("operation.json").exists());
    assert_eq!(
        history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        anchor
    );
    assert_eq!(
        history.bodies[0]
            .directory
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original
    );
    assert!(!history.root.path().join("bodies/0002").exists());
    assert!(!path.join("submission.json").exists());
    std::fs::rename(&held, path.join("operation.json")).unwrap();
    assert_eq!(std::fs::read(path.join("operation.json")).unwrap(), signed);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn same_body_retired_wallet_prefix_finishes_before_outer_terminal_closure() {
    use crate::managed::native_operation::authorization::DispatchAuthorization;
    let _guard = crate::managed::native_test_guard();
    let fixture = ready();
    let history = retain_body(&fixture);
    let first = retain_request(&fixture, &history, 3_000);
    let account = fixture.owner.wallet().unwrap();
    let request = first.request(fixture.options.deadline).unwrap();
    let mut attempt_turn = fixture.renewal_turn();
    let retained = reopen(&fixture);
    let live = attempt_turn
        .authorize_retained(&fixture.owner, &retained, fixture.options.deadline)
        .unwrap();
    let second = retained
        .current_history()
        .unwrap()
        .reserve(
            retained.dispatch().unwrap().0,
            live.origin().unwrap(),
            live.terms(fixture.options.deadline, Some(expiry(&retained)))
                .unwrap(),
        )
        .unwrap();
    // Exact crash prefix: successor is retained, predecessor's genuine wallet is retired, and
    // its shared retired.nrt has not yet been published. No second wallet exists.
    request
        .retire(&account, &first.directory().path().join("transaction"))
        .unwrap();
    assert!(!first.directory().path().join("retired.nrt").exists());
    assert!(!second.wallet_path().exists());
    wait_until(expiry(&history), Duration::from_secs(10));
    let mut body_turn = fixture.renewal_turn();
    let retained = reopen(&fixture);
    let live = body_turn
        .authorize_retained(&fixture.owner, &retained, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    let reserved = retained
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            live,
            fixture.options.deadline,
        )
        .unwrap();
    let successor = reserved.successor(0).unwrap().unwrap();
    let original = reserved.bodies[0].original.as_ref().unwrap();
    assert!(
        reserved
            .current_history()
            .unwrap()
            .verify_unsigned_closure(&successor, |attempt| {
                original
                    .request(
                        attempt.terms(),
                        attempt.observation()?,
                        fixture.options.deadline,
                    )?
                    .inspect(&account, &attempt.wallet_path())
            })
            .unwrap()
            .is_none()
    );
    assert!(!first.directory().path().join("retired.nrt").exists());
    let resumed = reserved
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(live),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert!(first.directory().path().join("retired.nrt").exists());
    assert!(
        resumed.bodies[0]
            .directory
            .path()
            .join("closed.nrt")
            .exists()
    );
    assert_eq!(
        resumed
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        2
    );
    assert!(resumed.current_history().unwrap().last().is_none());
    assert!(!second.wallet_path().exists());
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn original_before_completion_anchor_finishes_same_bytes_and_foreign_scope_refuses() {
    let _guard = crate::managed::native_test_guard();
    let fixture = ready();
    let history = retain_body(&fixture);
    let (body, original, scope) = history.dispatch().unwrap();
    assert!(
        History::read(
            body,
            original.dispatch_purpose().unwrap(),
            [0x91; 32],
            scope
        )
        .is_err()
    );
    assert!(
        History::read(
            body,
            original.dispatch_purpose().unwrap(),
            original.digest().unwrap(),
            &HistoryScope::FixedBody
        )
        .is_err()
    );
    let original_bytes = body
        .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
        .unwrap();
    let exact_anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let mut prior_anchor = history.anchor.clone();
    prior_anchor.completed = None;
    history
        .root
        .write_atomic(
            "anchor.nrt",
            &encode(&prior_anchor, MAX_BODY_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    let pending = reopen(&fixture);
    assert!(pending.dispatch().is_err());
    let mut turn = fixture.renewal_turn();
    let live = turn
        .authorize_retained(&fixture.owner, &pending, fixture.options.deadline)
        .unwrap();
    let (_, current) = fixture.current();
    let resumed = pending
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(live),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(
        resumed.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        exact_anchor
    );
    assert_eq!(
        resumed
            .dispatch()
            .unwrap()
            .0
            .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
            .unwrap(),
        original_bytes
    );
    assert!(resumed.current_history().unwrap().last().is_none());
    let mut foreign = resumed.anchor.clone();
    foreign.outer = [0x91; 32];
    resumed
        .root
        .write_atomic(
            "anchor.nrt",
            &encode(&foreign, MAX_BODY_BYTES).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)).is_err());
    assert!(!body.path().join("attempts").exists());
    resumed
        .root
        .write_atomic("anchor.nrt", &exact_anchor, PublishMode::Replace)
        .unwrap();
    assert_eq!(reopen(&fixture).anchor.highest, 1);
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn body_ordinal_and_cumulative_frame_bounds_refuse_without_wrapping_or_mutating_count() {
    assert!(body_name(0).is_err());
    assert_eq!(body_name(1).unwrap(), "0001");
    assert_eq!(body_name(64).unwrap(), "0064");
    assert!(body_name(65).is_err());
    let mut total = 0;
    add_bytes(&mut total, MAX_ALL_BODY_BYTES / 2).unwrap();
    add_bytes(&mut total, MAX_ALL_BODY_BYTES / 2).unwrap();
    assert_eq!(total, MAX_ALL_BODY_BYTES);
    assert!(add_bytes(&mut total, 1).is_err());
    assert_eq!(total, MAX_ALL_BODY_BYTES);
    assert!(add_bytes(&mut total, usize::MAX).is_err());
    assert_eq!(total, MAX_ALL_BODY_BYTES);
}

#[test]
fn expired_reserved_successor_keeps_one_claim_per_turn_and_later_fresh_turn_progresses() {
    let _guard = crate::managed::native_test_guard();
    let fixture = ready();
    let first = retain_body(&fixture);
    wait_until(expiry(&first), Duration::from_secs(10));
    let (_, current) = fixture.current();
    let mut original_turn = fixture.renewal_turn();
    let live = original_turn
        .authorize_retained(&fixture.owner, &first, fixture.options.deadline)
        .unwrap();
    let reserved = first
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            live,
            fixture.options.deadline,
        )
        .unwrap();
    assert_eq!(reserved.anchor.highest, 2);
    assert!(reserved.anchor.pending.is_some());
    assert!(!reserved.root.path().join("bodies/0002").exists());
    let exact_reservation =
        encode(reserved.anchor.pending.as_ref().unwrap(), MAX_BODY_BYTES).unwrap();
    wait_until(
        reserved
            .anchor
            .pending
            .as_ref()
            .unwrap()
            .unsigned
            .statement
            .expires_at_unix_ms,
        Duration::from_secs(10),
    );
    // A fresh invocation may complete this exact prior selection but owns only one replacement
    // claim. It may not silently issue another epoch or redraw a second target in this turn.
    let retained = reopen(&fixture);
    let mut completing_turn = fixture.renewal_turn();
    let live = completing_turn
        .authorize_retained(&fixture.owner, &retained, fixture.options.deadline)
        .unwrap();
    let completed = retained
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(live),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(completed.anchor.highest, 2);
    assert_eq!(completed.anchor.active, Some(2));
    assert!(completed.original().unwrap().is_none());
    assert_eq!(
        completed.bodies[1]
            .directory
            .read("reserved.nrt", MAX_BODY_BYTES)
            .unwrap()
            .as_slice(),
        exact_reservation
    );
    let anchor = completed.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let root_path = completed.root.path().to_owned();
    assert!(matches!(
        completed.reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            live,
            fixture.options.deadline
        ),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::ReplacementLimit
        ))
    ));
    assert_eq!(
        PrivateDirectory::open_exact(&root_path)
            .unwrap()
            .read("anchor.nrt", MAX_BODY_BYTES)
            .unwrap(),
        anchor
    );
    assert!(!root_path.join("bodies/0002/original.nrt").exists());
    assert!(!root_path.join("bodies/0002/dispatch.nrt").exists());
    assert!(!root_path.join("bodies/0003").exists());
    let retained = reopen(&fixture);
    let mut later_turn = fixture.renewal_turn();
    let live = later_turn
        .authorize_retained(&fixture.owner, &retained, fixture.options.deadline)
        .unwrap();
    let third = retained
        .reserve_successor(
            &fixture.owner,
            fresh_unsigned(&fixture).0,
            &current,
            live,
            fixture.options.deadline,
        )
        .unwrap()
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(live),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(third.anchor.highest, 3);
    assert!(third.original().unwrap().is_some());
    assert!(third.bodies[1].unused.is_some());
    assert_eq!(
        third.current_history().unwrap().cumulative_reserved_count(),
        0
    );
    assert!(third.current_history().unwrap().last().is_none());
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn first_reservation_refuses_changed_original_before_activation_and_preserves_exact_prefix() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let peers =
        crate::managed::native_operation::test_support::UnavailablePeers::start(&fixture.prepared);
    let mut turn = fixture.renewal_turn();
    let unsigned = fresh_unsigned(&fixture).0;
    let unsigned_bytes = encode(&unsigned, MAX_BODY_BYTES).unwrap();
    let (_, current) = fixture.current();
    let history = BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &Fees::from_options(&fixture.options).unwrap(),
        &SigningTurn::RenewalSelection(&turn),
        fixture.options.deadline,
    )
    .unwrap();
    assert_eq!(history.anchor.highest, 1);
    assert!(history.anchor.active.is_none());
    assert!(history.anchor.completed.is_none());
    assert!(history.bodies.is_empty());
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let reservation = encode(history.anchor.pending.as_ref().unwrap(), MAX_BODY_BYTES).unwrap();
    let reference = fixture
        .owner
        .authority
        .directory
        .read(
            reference_name(CustodyPurpose::Renewal(2)).unwrap(),
            MAX_SELECTION_BYTES,
        )
        .unwrap();
    let container = history.root.ensure_child("bodies").unwrap();
    let mut changed = reservation.clone();
    *changed.last_mut().unwrap() ^= 1;
    let body = private_parent(&container)
        .unwrap()
        .publish_private_child("0001", &[("reserved.nrt", changed.as_slice())])
        .unwrap();
    let root = Arc::clone(&history.root);
    let reads = NativeEnrollmentReads(&fixture.native);
    let error = match history.finish_pending_with_reads(
        &fixture.owner,
        &current,
        &SigningTurn::Generated(authorization),
        fixture.options.deadline,
        &reads,
    ) {
        Ok(_) => panic!("changed original reservation must refuse before activation"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("retained body reservation changed")
    );
    assert_eq!(root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(), anchor);
    assert!(!container.path().join("0001-activation.nrt").exists());
    assert!(!container.path().join("0001-unused.nrt").exists());
    assert_eq!(
        body.entries(2).unwrap(),
        vec![std::ffi::OsString::from("reserved.nrt")]
    );
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());

    body.write_atomic("reserved.nrt", &reservation, PublishMode::Replace)
        .unwrap();
    let restored = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    let completed = restored
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &reads,
        )
        .unwrap();
    assert_eq!(completed.anchor.highest, 1);
    assert_eq!(completed.anchor.active, Some(1));
    assert!(completed.anchor.pending.is_none());
    assert_eq!(
        completed.anchor.completed,
        Some(completed.original().unwrap().unwrap().digest().unwrap())
    );
    let retained = &completed.bodies[0];
    assert_eq!(
        encode(&retained.reservation.unsigned, MAX_BODY_BYTES).unwrap(),
        unsigned_bytes
    );
    assert_eq!(
        retained
            .directory
            .read("reserved.nrt", MAX_BODY_BYTES)
            .unwrap()
            .as_slice(),
        reservation
    );
    assert!(
        retained
            .activation
            .as_ref()
            .unwrap()
            .preceding_retirement
            .is_none()
    );
    assert!(retained.unused.is_none());
    assert_eq!(
        fixture
            .owner
            .authority
            .directory
            .read(
                reference_name(CustodyPurpose::Renewal(2)).unwrap(),
                MAX_SELECTION_BYTES
            )
            .unwrap(),
        reference
    );
    assert!(completed.current_history().unwrap().last().is_none());
    assert!(!retained.directory.path().join("dispatch.nrt").exists());
    assert!(!retained.directory.path().join("attempts").exists());
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn body_reads_create_wallet_only_for_observed_attempts_and_recheck_every_request() {
    use crate::managed::stream_token_custody::tests::count_wallet_constructions;

    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 20_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    // Production starts the turn before selecting a body; its original inventory is preflight.
    // Actual authorization is still issued below against the retained body and fresh checks.
    let mut turn = fixture.renewal_turn();
    // Renewal selection inspects the existing paid initial enrollment. Count that required
    // wallet separately from the new body, which has no observed wallet attempts yet.
    let ((unsigned, current), prerequisite_constructions) =
        count_wallet_constructions(|| fresh_unsigned(&fixture));
    assert_eq!(prerequisite_constructions, 1);
    let (history, constructions) = count_wallet_constructions(|| {
        fixture.owner.bootstrap_native_body(
            &fixture.native,
            &current,
            CustodyPurpose::Renewal(2),
            unsigned,
            now_ms().unwrap() + 2_000,
            &fixture.options,
        )
    });
    assert_eq!(constructions, 0);
    assert!(history.current_history().unwrap().last().is_none());
    let (read, constructions) = count_wallet_constructions(|| history.read_current(&fixture.owner));
    assert!(read.is_ok());
    assert_eq!(constructions, 0);
    drop(read);

    let first = retain_request(&fixture, &history, 3_000);
    // Keep the authenticated historical cut that selected this body. The generated helper
    // independently verifies a fresh current proof before retaining the successor request.
    wait_until(first.terms.signing_deadline_unix_ms, Duration::from_secs(4));
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let second = fixture
        .retain_generated_attempt(authorization, &history, &current)
        .unwrap_or_else(|error| {
            let failed_at = now_ms().unwrap();
            panic!(
                "generated replacement failed: {error:?}; now_unix_ms={failed_at}, body_expiry_unix_ms={}, first_request_deadline_unix_ms={}, options_remaining_ms={}, policy_expiry_unix_ms={}",
                expiry(&history),
                first.terms.signing_deadline_unix_ms,
                fixture
                    .options
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
                fixture.policy.active_until_unix_ms,
            );
        });
    assert_ne!(first.directory().path(), second.directory().path());
    let (read, constructions) = count_wallet_constructions(|| history.read_current(&fixture.owner));
    let read = read.unwrap();
    assert_eq!(constructions, 1);
    assert_eq!(read.current_history().unwrap().reserved_attempt_count(), 2);
    drop(read);

    // Both observations belong to genuine canonical wallet requests. Damage each one in turn;
    // neither a retired predecessor nor the selected successor may escape fresh inspection.
    for selected in [&first, &second] {
        let path = selected.directory().path().join("transaction");
        let bytes = std::fs::read(path.join("preparation.json")).unwrap();
        let directory = PrivateDirectory::open_exact(&path).unwrap();
        directory
            .write_atomic("preparation.json", b"invalid request", PublishMode::Replace)
            .unwrap();
        let (read, constructions) =
            count_wallet_constructions(|| history.read_current(&fixture.owner));
        assert!(read.is_err());
        assert_eq!(constructions, 1);
        assert_eq!(
            std::fs::read(path.join("preparation.json")).unwrap(),
            b"invalid request"
        );
        assert!(!path.join("payload.json").exists());
        assert!(!path.join("operation.json").exists());
        assert!(!path.join("submission.json").exists());
        directory
            .write_atomic("preparation.json", &bytes, PublishMode::Replace)
            .unwrap();
        let (read, constructions) =
            count_wallet_constructions(|| history.read_current(&fixture.owner));
        assert!(read.is_ok());
        assert_eq!(constructions, 1);
        assert_eq!(std::fs::read(path.join("preparation.json")).unwrap(), bytes);
    }
    assert_eq!(fixture.native.chain.height(), 4);
}
