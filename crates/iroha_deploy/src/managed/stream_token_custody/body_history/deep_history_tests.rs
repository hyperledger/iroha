//! Genuine finite body expiries exercise the deepest retained unsigned predecessor graph.
//! These local histories do not qualify current signing eligibility or running services.

use super::*;
use crate::managed::{
    native_operation::test_support::native_fixture::quote_instructions,
    stream_token_custody::{
        bootstrap_test_support::NativeEnrollmentReads,
        renewal_tests::{Fixture, wait_until},
    },
};
use iroha_data_model::isi::{InstructionBox, Log};
use iroha_wallet::operations::NativePreparationPhase;
use std::{path::PathBuf, time::Duration};

// This exercises history depth and custody, not a short-window signing latency target.
// All 64 bodies expire naturally: 640 seconds of expiry pacing leaves 560 seconds in
// the original finite campaign for fixture setup, native retirement, proofs and assertions.
// Focused short-expiry tests retain their own 500 ms / two-second authorizations.
const BODY_VALIDITY_MS: u64 = 10_000;
const CAMPAIGN_BUDGET: Duration = Duration::from_secs(1_200);
const BODY_EXPIRY_WAIT: Duration = Duration::from_secs(12);

struct OriginalBytes {
    body: PathBuf,
    original: zeroize::Zeroizing<Vec<u8>>,
    request: Vec<u8>,
}

struct CompletedDeepHistory {
    history: BodyHistory,
    originals: Vec<OriginalBytes>,
    original_policy: SignerCustodyPolicyV1,
    original_native:
        iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1,
    initial_carrier_path: PathBuf,
    initial_carrier: Vec<u8>,
}

fn require_full_census(history: &History) {
    let (result, census) = history.test_require_current(2 * 64);
    result.unwrap();
    assert_eq!(census.distinct_histories, 64);
    assert!(census.visits >= census.distinct_histories);
    assert!(census.visits <= 2 * 64);
}

// A genuine paid Log refreshes the certified cut when necessary. It does not mutate custody,
// set the fixture's clock, fabricate an empty block or replace any retained body checkpoint.
fn refresh_old_anchor(fixture: &mut Fixture) {
    let height = fixture.native.chain.height();
    let committed = fixture.native.chain.committed(height);
    let issued = u64::try_from(committed.block().header().creation_time().as_millis()).unwrap();
    if now_ms().unwrap().saturating_sub(issued) < fixture.policy.max_anchor_age_ms / 2 {
        return;
    }
    drop(committed);
    let log = quote_instructions(
        &fixture.native,
        &fixture.owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "deep retained custody predecessor".into(),
        ))],
    );
    assert_eq!(fixture.native.chain.commit(vec![log]), vec![true]);
    assert_eq!(fixture.native.chain.height(), height + 1);
}

#[test]
fn sixty_four_genuine_bodies_bound_retained_visits_and_refuse_oldest_material_substitution() {
    let _guard = crate::managed::native_test_guard();
    let complete_before = Instant::now() + CAMPAIGN_BUDGET;
    let fixture = Fixture::enrolled_with_policy_lifetime(4_000, BODY_VALIDITY_MS, CAMPAIGN_BUDGET);
    exercise_deep_history(fixture, complete_before);
}

// Initial enrollment completes before the retained-history exercise needs its parser scratch.
// The caller holds the native fixture guard through both phases and the fixture's drop.
#[inline(never)]
fn exercise_deep_history(mut fixture: Fixture, complete_before: Instant) {
    let completed = populate_deep_history(&mut fixture, complete_before);
    verify_deep_history(&fixture, completed);
    assert!(Instant::now() < complete_before);
}

// Each phase owns its parser scratch only while it runs. The original native handles and
// byte buffers move directly into the verification phase without reopening or copying them.
#[inline(never)]
fn populate_deep_history(fixture: &mut Fixture, complete_before: Instant) -> CompletedDeepHistory {
    let original_policy = fixture.policy.clone();
    let original_fees = Fees::from_options(&fixture.options).unwrap();
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (_, initial_current) = fixture.current();
    let original_native = initial_current.current().unwrap().record().clone();
    assert_eq!(original_native.execution_height, 4);
    assert_eq!(
        initial_current.current().unwrap().control().next_sequence,
        2
    );
    drop(initial_current);
    let initial = fixture
        .owner
        .required_enrollment(CustodyPurpose::InitialEnroll)
        .unwrap();
    let initial_carrier_path = initial.directory().path().join("carrier.nrt");
    let initial_carrier = std::fs::read(&initial_carrier_path).unwrap();
    drop(initial);
    let initial_history = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap();
    let (result, census) = initial_history
        .current_history()
        .unwrap()
        .test_require_current(1);
    result.unwrap();
    assert_eq!(census.visits, 1);
    assert_eq!(census.distinct_histories, 1);
    drop(initial_history);

    let mut retained: Option<BodyHistory> = None;
    let mut originals = Vec::with_capacity(64);
    for ordinal in 1..=64u8 {
        if let Some(history) = retained.as_ref() {
            let expiry = history
                .bodies
                .last()
                .unwrap()
                .reservation
                .unsigned
                .statement
                .expires_at_unix_ms;
            wait_until(
                expiry,
                BODY_EXPIRY_WAIT.min(complete_before.saturating_duration_since(Instant::now())),
            );
        }
        // A fresh production startup acquires its turn before opening any body history.
        // End the preceding invocation only after using its exact original expiry; the next
        // invocation retains one graph throughout reserve, finish and consuming reparse.
        drop(retained.take());
        assert!(Instant::now() < complete_before);
        assert!(now_ms().unwrap() < original_policy.active_until_unix_ms);
        // Each separate startup has its own finite I/O budget. No retained body, epoch or
        // wallet Terms are changed, and the originally configured policy remains the cap.
        fixture.options.deadline = (Instant::now() + Duration::from_secs(120)).min(complete_before);
        assert!(Fees::from_options(&fixture.options).unwrap() == original_fees);
        refresh_old_anchor(fixture);
        let mut turn = fixture.renewal_turn();
        let (checkpoint, current) = fixture.current();
        assert_eq!(current.current().unwrap().record(), &original_native);
        assert_eq!(current.current().unwrap().control().next_sequence, 2);

        let selection_started;
        let selection_finished;
        let finish_started;
        let finish_capture;
        let (history, authorization) = if ordinal > 1 {
            let previous = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
                .unwrap()
                .expect("previous startup must retain its renewal body history");
            let authorization = turn
                .authorize_retained(&fixture.owner, &previous, fixture.options.deadline)
                .unwrap();
            selection_started = Instant::now();
            let terms = Terms::new(now_ms().unwrap() + BODY_VALIDITY_MS, &fixture.options).unwrap();
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
            selection_finished = Instant::now();
            let history = previous
                .reserve_successor(
                    &fixture.owner,
                    unsigned,
                    &current,
                    authorization,
                    fixture.options.deadline,
                )
                .unwrap();
            finish_capture = finish_timing::Capture::start();
            finish_started = Instant::now();
            let history = history
                .finish_pending_with_reads(
                    &fixture.owner,
                    &current,
                    &SigningTurn::Generated(authorization),
                    fixture.options.deadline,
                    &NativeEnrollmentReads(&fixture.native),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "body {ordinal} finish failed: {error:?}; inclusive_finish_phases={:?}",
                        finish_timing::snapshot(),
                    )
                });
            (history, authorization)
        } else {
            selection_started = Instant::now();
            let terms = Terms::new(now_ms().unwrap() + BODY_VALIDITY_MS, &fixture.options).unwrap();
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
            selection_finished = Instant::now();
            let history = BodyHistory::initialize(
                &fixture.owner,
                CustodyPurpose::Renewal(2),
                unsigned,
                &original_fees,
                &SigningTurn::RenewalSelection(&turn),
                fixture.options.deadline,
            )
            .unwrap();
            let authorization = turn
                .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
                .unwrap();
            finish_capture = finish_timing::Capture::start();
            finish_started = Instant::now();
            let history = history
                .finish_pending_with_reads(
                    &fixture.owner,
                    &current,
                    &SigningTurn::Generated(authorization),
                    fixture.options.deadline,
                    &NativeEnrollmentReads(&fixture.native),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "body {ordinal} finish failed: {error:?}; inclusive_finish_phases={:?}",
                        finish_timing::snapshot(),
                    )
                });
            (history, authorization)
        };
        let finish_finished = Instant::now();
        let finish_phases = finish_capture.finish();
        assert_eq!(history.anchor.highest, ordinal);
        assert_eq!(history.bodies.len(), usize::from(ordinal));
        assert_eq!(history.anchor.active, Some(ordinal));
        assert!(!history.has_pending());
        assert!(
            history.anchor.completed.is_some() && history.original().unwrap().is_some(),
            "body {ordinal} must complete its signed Original before dispatch: selected_at_unix_ms={}, body_expiry_unix_ms={}, now_unix_ms={}, completed={}, original_present={}, inclusive_finish_phases={finish_phases:?}",
            history
                .bodies
                .last()
                .unwrap()
                .reservation
                .unsigned
                .selected_at_unix_ms,
            history
                .bodies
                .last()
                .unwrap()
                .reservation
                .unsigned
                .statement
                .expires_at_unix_ms,
            now_ms().unwrap(),
            history.anchor.completed.is_some(),
            history.original().unwrap().is_some(),
        );
        let retention_started = Instant::now();
        let selected = fixture
            .retain_generated_attempt(authorization, &history, &current)
            .unwrap_or_else(|error| {
                let failed_at = Instant::now();
                let unsigned = &history.bodies.last().unwrap().reservation.unsigned;
                panic!(
                    "generated body {ordinal} request retention failed: {error:?}; selected_at_unix_ms={}, body_expiry_unix_ms={}, now_unix_ms={}, options_remaining_ms={}, policy_expiry_unix_ms={}, selection_us={}, reservation_authorization_us={}, finish_us={}, assertions_us={}, native_retention_us={}, timed_body_work_us={}, inclusive_finish_phases={finish_phases:?}",
                    unsigned.selected_at_unix_ms,
                    unsigned.statement.expires_at_unix_ms,
                    now_ms().unwrap(),
                    fixture
                        .options
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                    original_policy.active_until_unix_ms,
                    selection_finished.duration_since(selection_started).as_micros(),
                    finish_started.duration_since(selection_finished).as_micros(),
                    finish_finished.duration_since(finish_started).as_micros(),
                    retention_started.duration_since(finish_finished).as_micros(),
                    failed_at.duration_since(retention_started).as_micros(),
                    failed_at.duration_since(selection_started).as_micros(),
                );
            });
        assert!(matches!(
            selected.attempt().origin(),
            attempts::Origin::Generated { .. }
        ));
        assert!(selected.terms.fees == original_fees);
        let wallet = selected.directory().path().join("transaction");
        assert_eq!(
            selected
                .request(fixture.options.deadline)
                .unwrap()
                .inspect(&fixture.owner.wallet().unwrap(), &wallet)
                .unwrap()
                .phase(),
            NativePreparationPhase::RequestOnly
        );
        assert!(!wallet.join("payload.json").exists());
        assert!(!wallet.join("operation.json").exists());
        assert!(!wallet.join("submission.json").exists());
        originals.push(OriginalBytes {
            body: history.dispatch().unwrap().0.path().to_owned(),
            original: history
                .dispatch()
                .unwrap()
                .0
                .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
                .unwrap(),
            request: std::fs::read(wallet.join("preparation.json")).unwrap(),
        });
        drop(selected);
        drop(turn);
        let root = Arc::clone(&history.root);
        let container = Arc::clone(history.body_root.as_ref().unwrap());
        let oldest = Arc::clone(&history.bodies[0].directory);
        let reparsed = history.reopen(&fixture.owner).unwrap();
        assert!(Arc::ptr_eq(&root, &reparsed.root));
        assert!(Arc::ptr_eq(
            &container,
            reparsed.body_root.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(&oldest, &reparsed.bodies[0].directory));
        retained = Some(reparsed);
        assert_eq!(
            retained
                .as_ref()
                .unwrap()
                .current_history()
                .unwrap()
                .cumulative_reserved_count(),
            usize::from(ordinal)
        );
        // Report only after finite request retention and this body's existing assertions.
        eprintln!("body {ordinal} inclusive_finish_phases={finish_phases:?}");
    }

    let history = retained.unwrap();
    // The final body remains unretired for the depth-limit and read-only custody assertions,
    // but its exact original interval also expires; no synthetic clock or replacement is used.
    let expiry = history
        .bodies
        .last()
        .unwrap()
        .reservation
        .unsigned
        .statement
        .expires_at_unix_ms;
    wait_until(
        expiry,
        BODY_EXPIRY_WAIT.min(complete_before.saturating_duration_since(Instant::now())),
    );
    let expired_at = now_ms().unwrap();
    assert!(
        history
            .bodies
            .iter()
            .all(|body| { body.reservation.unsigned.statement.expires_at_unix_ms <= expired_at })
    );
    assert!(Instant::now() < complete_before);
    CompletedDeepHistory {
        history,
        originals,
        original_policy,
        original_native,
        initial_carrier_path,
        initial_carrier,
    }
}

#[inline(never)]
fn verify_deep_history(fixture: &Fixture, completed: CompletedDeepHistory) {
    let CompletedDeepHistory {
        history,
        originals,
        original_policy,
        original_native,
        initial_carrier_path,
        initial_carrier,
    } = completed;
    assert_eq!(history.bodies.len(), 64);
    assert_eq!(
        history.current_history().unwrap().reserved_attempt_count(),
        1
    );
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        64
    );
    require_full_census(history.current_history().unwrap());
    let anchor = history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap();
    let (body, _, _) = history.dispatch().unwrap();
    let attempt_names = body.open_child("attempts").unwrap().entries(64).unwrap();
    let last = history.current_history().unwrap().last().unwrap();
    assert!(matches!(
        history.current_history().unwrap().reserve(
            body,
            last.origin().clone(),
            last.terms().clone()
        ),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::EpochLimit
        ))
    ));
    assert_eq!(
        history.root.read("anchor.nrt", MAX_BODY_BYTES).unwrap(),
        anchor
    );
    assert_eq!(
        body.open_child("attempts").unwrap().entries(64).unwrap(),
        attempt_names
    );
    assert!(!body.path().join("attempts/0002").exists());
    assert!(!history.root.path().join("bodies/0065").exists());

    // Exercise the oldest original through the held deepest native graph, not a newly parsed
    // substitute or a constructed scope. Restoration is test corruption cleanup only.
    let oldest = &history.bodies[0].directory;
    // Use the canonical parser with the held native graph. Positive controls around each
    // mutation keep descriptor exhaustion from masquerading as material-change refusal.
    drop(history.read_current(&fixture.owner).unwrap());
    oldest
        .write_atomic(
            "original.nrt",
            b"changed oldest original",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(
        history
            .current_history()
            .unwrap()
            .test_require_current(128)
            .0
            .is_err()
    );
    assert!(history.read_current(&fixture.owner).is_err());
    oldest
        .write_atomic("original.nrt", &originals[0].original, PublishMode::Replace)
        .unwrap();
    require_full_census(history.current_history().unwrap());
    drop(history.read_current(&fixture.owner).unwrap());
    let closure = oldest.read("closed.nrt", 64 * 1024).unwrap();
    oldest
        .write_atomic(
            "closed.nrt",
            b"changed oldest closure",
            PublishMode::Replace,
        )
        .unwrap();
    assert!(
        history
            .current_history()
            .unwrap()
            .test_require_current(128)
            .0
            .is_err()
    );
    assert!(history.read_current(&fixture.owner).is_err());
    oldest
        .write_atomic("closed.nrt", &closure, PublishMode::Replace)
        .unwrap();
    require_full_census(history.current_history().unwrap());
    drop(history.read_current(&fixture.owner).unwrap());

    let account = fixture.owner.wallet().unwrap();
    for (index, original) in originals.iter().enumerate() {
        let body = &history.bodies[index];
        assert_eq!(body.directory.path(), original.body);
        assert_eq!(
            body.directory
                .read("original.nrt", journal::MAX_ORIGINAL_BYTES)
                .unwrap(),
            original.original
        );
        let wallet = body.directory.path().join("attempts/0001/transaction");
        assert_eq!(
            std::fs::read(wallet.join("preparation.json")).unwrap(),
            original.request
        );
        assert!(!wallet.join("payload.json").exists());
        assert!(!wallet.join("operation.json").exists());
        assert!(!wallet.join("submission.json").exists());
        assert_eq!(wallet.join("retired.json").exists(), index < 63);
    }
    let selected = history.retained_selected(&fixture.owner).unwrap();
    assert_eq!(
        selected
            .request(fixture.options.deadline)
            .unwrap()
            .inspect(&account, &selected.directory().path().join("transaction"))
            .unwrap()
            .phase(),
        NativePreparationPhase::RequestOnly
    );
    assert_eq!(fixture.policy, original_policy);
    assert_eq!(
        std::fs::read(initial_carrier_path).unwrap(),
        initial_carrier
    );
    let (_, current) = fixture.current();
    assert_eq!(current.current().unwrap().record(), &original_native);
    assert_eq!(
        current
            .current()
            .unwrap()
            .control()
            .active_head
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(current.current().unwrap().control().next_sequence, 2);

    // A separate startup can also read the complete depth64 graph under the same limits.
    // Release both views first, matching production ownership rather than doubling handles.
    drop(selected);
    drop(history);
    let reopened = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .expect("the complete renewal history must survive a fresh startup");
    assert_eq!(reopened.bodies.len(), 64);
    assert_eq!(reopened.anchor.highest, 64);
    require_full_census(reopened.current_history().unwrap());
}
