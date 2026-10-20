//! Real generated enrollment refuses signing when the final source scan outlives authority.

use super::*;
use crate::managed::{
    Error,
    stream_token_custody::{
        bootstrap_test_support::NativeEnrollmentReads,
        renewal_tests::{Fixture, wait_until},
    },
};
use iroha_fs::CustodyWorkV1;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Default)]
struct Counts {
    entered: usize,
    completed: usize,
    native_walks: u64,
    signatures: usize,
}
type Hook = Box<dyn FnOnce(&BodyHistory)>;
struct State {
    hook: Option<Hook>,
    counts: Counts,
    before: CustodyWorkV1,
}
thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

// Only test-owned time, cancellation or bytes can change. The production scan still runs;
// neither this hook nor the counters can return a proof, signature or successful verdict.
pub(super) fn before_snapshot(history: &BodyHistory) {
    let hook = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let state = state.as_mut()?;
        state.counts.entered += 1;
        state.hook.take()
    });
    if let Some(hook) = hook {
        hook(history);
    }
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.before = CustodyWorkV1::current_thread();
        }
    });
}
pub(super) fn after_snapshot() {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.counts.completed += 1;
            state.counts.native_walks += CustodyWorkV1::current_thread()
                .since(state.before)
                .ancestry_walks;
        }
    });
}
pub(super) fn signed() {
    STATE.with(|state| {
        if let Some(state) = state.borrow_mut().as_mut() {
            state.counts.signatures += 1;
        }
    });
}
fn observe<T>(hook: Hook, finish: impl FnOnce() -> T) -> (T, Counts) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|state| state.replace(self.0.take()));
        }
    }
    let _restore = Restore(STATE.with(|state| {
        state.replace(Some(State {
            hook: Some(hook),
            counts: Counts::default(),
            before: CustodyWorkV1::default(),
        }))
    }));
    let result = finish();
    let counts = STATE.with(|state| state.borrow().as_ref().unwrap().counts);
    (result, counts)
}

fn run(cancelled: Arc<AtomicBool>, hook: Hook) -> (Fixture, Result<BodyHistory>, Counts) {
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let initial = fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, fixture.options.deadline)
        .unwrap();
    let mut turn = renewal::GeneratedRenewalTurn::begin(
        &fixture.owner,
        &fixture.policy,
        Fees::from_options(&fixture.options).unwrap(),
        *initial.finalized(),
        fixture.options.deadline,
        cancelled,
    )
    .unwrap();
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms().unwrap() + 8_000, &fixture.options).unwrap();
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
    let selected = BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &terms.fees,
        &SigningTurn::RenewalSelection(&turn),
        fixture.options.deadline,
    )
    .unwrap();
    let authorization = turn
        .authorize_retained(&fixture.owner, &selected, fixture.options.deadline)
        .unwrap();
    let (result, counts) = observe(hook, || {
        selected.finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
    });
    (fixture, result, counts)
}
fn completed_scan(counts: Counts, signatures: usize) {
    assert_eq!(counts.entered, 1);
    assert_eq!(counts.completed, 1);
    assert!(counts.native_walks > 0, "the genuine final native scan ran");
    assert_eq!(counts.signatures, signatures);
}
fn unsigned_on_disk(fixture: &Fixture) {
    let cold = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_eq!(cold.anchor.active, Some(1));
    assert!(cold.anchor.pending.is_none());
    assert!(cold.anchor.completed.is_none());
    assert!(cold.original().is_none());
    assert!(
        read_optional(
            &cold.bodies[0].directory,
            "original.nrt",
            journal::MAX_ORIGINAL_BYTES
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn signing_boundary_refuses_body_expiry_during_final_snapshot() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, result, counts) = run(
        Arc::new(AtomicBool::new(false)),
        Box::new(|history| {
            let expires = history.bodies[0]
                .reservation
                .unsigned
                .statement
                .expires_at_unix_ms;
            assert!(now_ms().unwrap() < expires, "body was live at the boundary");
            wait_until(expires, Duration::from_secs(10));
        }),
    );
    assert!(matches!(
        result,
        Err(Error::Bootstrap(ManagedBootstrapFailure::EnrollmentExpired))
    ));
    completed_scan(counts, 0);
    unsigned_on_disk(&fixture);
}

#[test]
fn signing_boundary_refuses_cancellation_during_final_snapshot() {
    let _resources = crate::managed::native_test_guard();
    let cancelled = Arc::new(AtomicBool::new(false));
    let changed = Arc::clone(&cancelled);
    let (fixture, result, counts) = run(
        cancelled,
        Box::new(move |_| {
            assert!(!changed.swap(true, Ordering::SeqCst));
        }),
    );
    assert!(matches!(
        result,
        Err(Error::Bootstrap(ManagedBootstrapFailure::Cancelled))
    ));
    completed_scan(counts, 0);
    unsigned_on_disk(&fixture);
}

#[test]
fn signing_boundary_live_control_publishes_one_actual_signature() {
    let _resources = crate::managed::native_test_guard();
    let (fixture, result, counts) = run(Arc::new(AtomicBool::new(false)), Box::new(|_| {}));
    let finished = result.unwrap();
    completed_scan(counts, 1);
    let digest = finished.original().unwrap().digest().unwrap();
    assert_eq!(finished.anchor.completed, Some(digest));
    let cold = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert_eq!(cold.original().unwrap().digest().unwrap(), digest);
    assert_eq!(cold.anchor.completed, Some(digest));
    assert_eq!(fixture.native.chain.height(), 4);
}

#[test]
fn signing_boundary_source_refusal_precedes_new_cancellation() {
    let _resources = crate::managed::native_test_guard();
    let cancelled = Arc::new(AtomicBool::new(false));
    let changed = Arc::clone(&cancelled);
    let saved = Rc::new(RefCell::new(None));
    let restore = Rc::clone(&saved);
    let (fixture, result, counts) = run(
        cancelled,
        Box::new(move |history| {
            let directory = Arc::clone(&history.bodies[0].directory);
            let original = directory.read("reserved.nrt", MAX_BODY_BYTES).unwrap();
            let mut replacement = original.to_vec();
            replacement[0] ^= 1;
            directory
                .write_atomic("reserved.nrt", &replacement, PublishMode::Replace)
                .unwrap();
            *restore.borrow_mut() = Some((directory, original));
            assert!(!changed.swap(true, Ordering::SeqCst));
        }),
    );
    let (directory, original) = saved.borrow_mut().take().unwrap();
    directory
        .write_atomic("reserved.nrt", &original, PublishMode::Replace)
        .unwrap();
    assert!(
        matches!(result, Err(Error::Invalid(message)) if message == "retained enrollment body material changed")
    );
    assert_eq!(counts.entered, 1);
    assert_eq!(counts.completed, 0, "the actual source scan refused");
    assert_eq!(counts.signatures, 0);
    unsigned_on_disk(&fixture);
}
