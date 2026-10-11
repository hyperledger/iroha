//! Renewal scheduling and finite-budget controls, without fabricating native authority.
use super::*;
use std::sync::atomic::Ordering;

#[test]
fn schedule_uses_inclusive_ceiling_midpoint_and_only_the_exact_next_sequence() {
    let now = now_ms().unwrap();
    let mono = Instant::now();
    let schedule = Schedule::select(1, now, now + 100_001, now + 200_000, mono, now).unwrap();
    assert!(!schedule.due_at(now + 50_000));
    assert!(schedule.due_at(now + 50_001));
    assert_eq!(schedule.sequence + 1, 2);
    assert_eq!(schedule.expiry.utc_ceiling(), now + 100_001);
    let near_limit = Schedule::select(63, now, now + 10_000, now + 20_000, mono, now).unwrap();
    assert!(near_limit.due_at(now + 5_000));
    assert_eq!(near_limit.sequence + 1, 64);
}

#[test]
fn schedule_preserves_finite_profile_and_generated_sequence_limits() {
    let now = now_ms().unwrap();
    let mono = Instant::now();
    let no_extension = Schedule::select(4, now, now + 10_000, now + 10_000, mono, now).unwrap();
    let sequence_exhausted =
        Schedule::select(64, now, now + 10_000, now + 20_000, mono, now).unwrap();
    assert!(!no_extension.due_at(now + 9_999));
    assert!(!sequence_exhausted.due_at(now + 9_999));
    for (sequence, issued, expires, provider_end) in [
        (0, now, now + 10_000, now + 20_000),
        (65, now, now + 10_000, now + 20_000),
        (1, now + 1, now + 10_000, now + 20_000),
        (1, now, now, now + 20_000),
        (1, now, now + 30_000, now + 20_000),
        (1, now, now + 10_000, u64::MAX),
        (1, now - 10_000, now - 1, now + 20_000),
    ] {
        assert!(Schedule::select(sequence, issued, expires, provider_end, mono, now).is_err());
    }
}

#[test]
fn renewal_budget_is_separate_from_startup_but_cannot_extend_original_enrollment() {
    let now = now_ms().unwrap();
    let mono = Instant::now();
    let schedule =
        Schedule::select(3, now - 20_000, now + 10_000, now + 60_000, mono, now).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Progress::default());
    let budget = schedule.budget(Arc::clone(&cancelled), progress).unwrap();
    assert!(budget.timeout <= Duration::from_secs(10));
    assert!(budget.started + budget.timeout <= mono + Duration::from_secs(10));
    assert_eq!(budget.utc_ceiling_unix_ms, Some(now + 10_000));
    assert!(budget.check().is_ok());
    cancelled.store(true, Ordering::Release);
    assert_eq!(budget.check().unwrap_err(), budget.progress.cancelled());
    assert!(
        budget
            .progress
            .cancelled()
            .message()
            .contains("custody renewal")
    );
    let long = Schedule::select(3, now, now + 360_000, now + 720_000, mono, now).unwrap();
    let budget = long
        .budget(
            Arc::new(AtomicBool::new(false)),
            Arc::new(Progress::default()),
        )
        .unwrap();
    assert!(budget.timeout <= TURN_MAXIMUM);
}

#[test]
fn aggregate_renewal_uses_unchanged_providers_earlier_expiry_without_remapping_timers() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let schedules = [
        Schedule::select(2, utc - 60_000, utc + 30_000, utc + 120_000, mono, utc).unwrap(),
        Schedule::select(1, utc - 60_000, utc + 15_000, utc + 120_000, mono, utc).unwrap(),
        Schedule::select(3, utc - 60_000, utc + 45_000, utc + 120_000, mono, utc).unwrap(),
    ];
    let originals = schedules.map(|schedule| schedule.expiry);
    let mut budget = schedules[0]
        .budget(
            Arc::new(AtomicBool::new(false)),
            Arc::new(Progress::default()),
        )
        .unwrap();
    budget.cap_to_expiries(originals, TURN_MAXIMUM).unwrap();
    assert_eq!(budget.utc_ceiling_unix_ms, Some(utc + 15_000));
    assert!(budget.started + budget.timeout <= mono + Duration::from_secs(15));
    assert_eq!(schedules.map(|schedule| schedule.expiry), originals);
    assert_eq!(schedules.map(|schedule| schedule.sequence), [2, 1, 3]);
    // The turn's own finite allowance remains independently stricter than later originals.
    let old_timeout = budget.timeout;
    budget
        .cap_to_expiries([originals[2]; 3], TURN_MAXIMUM)
        .unwrap();
    assert_eq!(budget.timeout, old_timeout);
    assert_eq!(budget.utc_ceiling_unix_ms, Some(utc + 15_000));
}

#[test]
fn backwards_utc_cannot_extend_retained_renewal_timer_across_a_fresh_observation() {
    let mono = Instant::now();
    let utc = now_ms().unwrap();
    let original_utc = utc + 300_000;
    let original = Schedule::select(
        2,
        original_utc - 60_000,
        original_utc + 10_000,
        original_utc + 120_000,
        mono - Duration::from_secs(7),
        original_utc,
    )
    .unwrap();
    // Re-observing the same signed interval after a backwards UTC movement could
    // remap it to a later monotonic end. The production cap receives the retained timer.
    let remapped = ReadinessExpiry::select(original_utc + 10_000, mono, utc).unwrap();
    assert!(remapped.current_at(mono + Duration::from_secs(5), utc));
    assert!(
        !original
            .expiry
            .current_at(mono + Duration::from_secs(5), utc)
    );
    let mut budget = Budget {
        started: mono,
        timeout: TURN_MAXIMUM,
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Progress::default()),
    };
    budget
        .cap_to_expiries([remapped, original.expiry, remapped], TURN_MAXIMUM)
        .unwrap();
    assert!(budget.started + budget.timeout <= mono + Duration::from_secs(3));
    assert_eq!(budget.utc_ceiling_unix_ms, Some(original_utc + 10_000));
    let retained = (budget.timeout, budget.utc_ceiling_unix_ms);
    budget.cap_to_expiries([remapped; 3], TURN_MAXIMUM).unwrap();
    assert_eq!((budget.timeout, budget.utc_ceiling_unix_ms), retained);
    let mut expired = Budget {
        startup_deadline_ns: None,
        utc_ceiling_unix_ms: Some(utc - 1),
        ..budget
    };
    assert!(
        expired
            .cap_to_expiries([remapped; 3], TURN_MAXIMUM)
            .is_err()
    );
    assert_eq!(expired.utc_ceiling_unix_ms, Some(utc - 1));
}
