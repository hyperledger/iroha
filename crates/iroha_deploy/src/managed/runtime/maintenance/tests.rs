//! Timer and bounded-turn controls only; no fake native discovery or service authority is minted.
use super::*;
use std::sync::atomic::Ordering;

fn signed_window(utc: u64, duration: u64) -> Interval {
    Interval::new(utc, utc + duration).unwrap()
}

#[test]
fn signed_midpoint_rejects_unbounded_or_reversed_intervals_and_cannot_overflow() {
    assert!(Interval::new(5, 5).is_err());
    assert!(Interval::new(6, 5).is_err());
    assert!(Interval::new(0, u64::MAX).is_err());
    assert_eq!(
        Interval::new(u64::MAX - 100, u64::MAX - 1)
            .unwrap()
            .midpoint(),
        u64::MAX - 51
    );
    assert_eq!(Interval::new(10, 21).unwrap().midpoint(), 15);
}

#[test]
fn initial_and_refreshed_timing_share_native_discovery_ceiling_and_signed_caps() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let long = signed_window(utc, 86_400_000);
    let selected = Timing::select(utc + 86_400_000, long, long, mono, utc).unwrap();
    assert_eq!(
        selected.expiry.utc_ceiling(),
        utc + u64::try_from(DISCOVERY_FRESHNESS.as_millis()).unwrap()
    );
    assert_eq!(
        selected.next_utc,
        utc + u64::try_from((DISCOVERY_FRESHNESS / 2).as_millis()).unwrap()
    );
    assert!(!selected.due_at(mono, utc));
    assert!(selected.due_at(mono + DISCOVERY_FRESHNESS / 2, utc));
    let short = Timing::select(utc + 4_000, long, long, mono, utc).unwrap();
    assert_eq!(short.expiry.utc_ceiling(), utc + 4_000);
    assert!(short.expiry.deadline(TURN_MAXIMUM).unwrap() <= mono + Duration::from_secs(4));
}

#[test]
fn failed_refresh_retry_does_not_extend_old_expiry_or_spin_immediately() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let long = signed_window(utc, 86_400_000);
    let mut timing = Timing::select(utc + 60_000, long, long, mono, utc).unwrap();
    let original = timing.expiry;
    for offset in [0, 1_000, 2_000] {
        let now = mono + Duration::from_millis(offset);
        timing.schedule(utc + offset, now, utc + offset).unwrap();
        assert_eq!(timing.expiry, original);
        assert!(!timing.due_at(now, utc + offset));
        assert!(timing.due_at(now + RETRY_DELAY, utc + offset));
    }
}

#[test]
fn past_signed_midpoint_requests_bounded_retry_and_earlier_actual_midpoint_wins() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let advert = Interval::new(utc - 4_000, utc + 20_000).unwrap();
    let catalog = signed_window(utc, 12_000);
    let timing = Timing::select(utc + 12_000, advert, catalog, mono, utc).unwrap();
    assert_eq!(timing.next_utc, utc + 6_000);
    let past = Interval::new(utc - 20_000, utc + 5_000).unwrap();
    let timing = Timing::select(utc + 5_000, past, catalog, mono, utc).unwrap();
    assert_eq!(timing.next_utc, utc + 1_000);
    assert!(!timing.due_at(mono, utc));
}

#[test]
fn turn_deadline_cannot_outlive_old_monotonic_or_utc_observation() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let old = ReadinessExpiry::select(utc + 5_000, mono, utc).unwrap();
    let deadline = old.deadline(TURN_MAXIMUM).unwrap();
    assert!(deadline <= mono + Duration::from_secs(5));
    let turn = Budget {
        started: mono,
        timeout: deadline.duration_since(mono),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: Some(utc - 1),
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    };
    let calls = std::cell::Cell::new(0);
    assert!(matches!(
        turn.call(|_| {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Err(Failure::ObservationExpired)
    ));
    assert_eq!(calls.get(), 0);
    turn.cancelled.store(true, Ordering::Release);
    assert!(matches!(turn.check(), Err(failure) if failure == turn.progress.cancelled()));
}

#[test]
fn turn_rechecks_utc_after_an_action_before_accepting_its_result() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let turn = Budget {
        started: mono,
        timeout: Duration::from_secs(15),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: Some(utc + 1_000),
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    };
    let entered = std::cell::Cell::new(false);
    let result = turn.call(|deadline| {
        entered.set(true);
        assert!(deadline <= mono + Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(1_100));
        Ok(())
    });
    assert!(
        entered.get(),
        "the UTC regression must execute its bounded action"
    );
    assert!(matches!(result, Err(Failure::ObservationExpired)));
}

#[test]
fn refreshed_discovery_cannot_outlive_original_enrollment_after_utc_moves_backwards() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let enrollment = ReadinessExpiry::select(utc + 10_000, mono, utc).unwrap();
    let signed = signed_window(utc, 120_000);
    // Nine monotonic seconds pass but UTC returns to its original value. Native discovery
    // refresh alone would map its freshness interval past the original enrollment timer.
    let refreshed = Timing::select(
        utc + 10_000,
        signed,
        signed,
        mono + Duration::from_secs(9),
        utc,
    )
    .unwrap();
    let after_original_expiry = mono + Duration::from_secs(11);
    assert!(refreshed.expiry.current_at(after_original_expiry, utc));
    assert!(!refreshed.current_at(enrollment, after_original_expiry, utc));
    assert!(refreshed.current_at(enrollment, mono + Duration::from_secs(9), utc));
    assert!(!refreshed.current_at(enrollment, mono, utc + 10_000));
}

#[test]
fn aggregate_refresh_budget_keeps_earliest_monotonic_and_utc_bounds_independently() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    // Distinct observed clocks make the earliest monotonic and UTC limits belong to
    // different original providers. These timers alone confer no current authority.
    let monotonic_first = ReadinessExpiry::select(utc + 123_000, mono, utc + 120_000).unwrap();
    let utc_first = ReadinessExpiry::select(utc + 5_000, mono, utc - 120_000).unwrap();
    let later = ReadinessExpiry::select(utc + 40_000, mono, utc).unwrap();
    let mut budget = Budget {
        started: mono,
        timeout: TURN_MAXIMUM,
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    };
    budget
        .cap_to_expiries([later, monotonic_first, utc_first], TURN_MAXIMUM)
        .unwrap();
    assert_eq!(budget.utc_ceiling_unix_ms, Some(utc + 5_000));
    assert!(budget.started + budget.timeout <= mono + Duration::from_secs(3));
    assert!(budget.check().is_ok());
    let original = (budget.timeout, budget.utc_ceiling_unix_ms);
    budget.cap_to_expiries([later; 3], TURN_MAXIMUM).unwrap();
    assert_eq!((budget.timeout, budget.utc_ceiling_unix_ms), original);
}

#[test]
fn aggregate_refresh_expired_input_refuses_without_partially_replacing_original_caps() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let expires = ReadinessExpiry::select(utc + 200, mono, utc).unwrap();
    let current = ReadinessExpiry::select(utc + 30_000, mono, utc).unwrap();
    let mut budget = Budget {
        started: mono,
        timeout: Duration::from_secs(12),
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: Some(utc + 14_000),
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    };
    let original = (budget.timeout, budget.utc_ceiling_unix_ms);
    std::thread::sleep(Duration::from_millis(250));
    assert!(!expires.current().unwrap());
    assert!(
        budget
            .cap_to_expiries([current, expires], TURN_MAXIMUM)
            .is_err()
    );
    assert_eq!((budget.timeout, budget.utc_ceiling_unix_ms), original);
    assert!(
        budget
            .cap_to_expiries([current; 3], Duration::ZERO)
            .is_err()
    );
    assert_eq!((budget.timeout, budget.utc_ceiling_unix_ms), original);
}
