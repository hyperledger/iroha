//! Move-only continuation identity, bounded waiting and terminal retirement.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationReservation};
use std::cell::Cell;

struct Original<'a> {
    signed: Box<[u8; 32]>,
    charge: AllocationReservation,
    dropped: &'a Cell<usize>,
}
impl Drop for Original<'_> {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
struct Failure<'a> {
    original: Original<'a>,
    deadline: Instant,
    retryable: bool,
    refusals: usize,
    retries: &'a Cell<usize>,
}
impl CheckFailure for Failure<'_> {
    fn retryable(&self) -> bool {
        self.retryable
    }
    fn deadline(&self) -> Instant {
        self.deadline
    }
}
impl<'a> BindingFailure for Failure<'a> {
    type Pending = Original<'a>;
    fn retry(mut self) -> Result<Self::Pending, Self> {
        self.retries.set(self.retries.get() + 1);
        self.refusals -= 1;
        if self.refusals == 0 {
            Ok(self.original)
        } else {
            Err(self)
        }
    }
}
fn failure<'a>(
    pool: &AllocationBudget,
    dropped: &'a Cell<usize>,
    retries: &'a Cell<usize>,
    deadline: Instant,
) -> Failure<'a> {
    Failure {
        original: Original {
            signed: Box::new([0xA9; 32]),
            charge: pool.try_reserve_bytes(32).unwrap(),
            dropped,
        },
        deadline,
        retryable: true,
        refusals: 5,
        retries,
    }
}

#[test]
fn retries_keep_exact_owner_pool_and_deadline_with_bounded_backoff() {
    let pool = AllocationBudget::new(32);
    let dropped = Cell::new(0);
    let retries = Cell::new(0);
    let now = Cell::new(Instant::now());
    let deadline = now.get() + Duration::from_secs(1);
    let original = failure(&pool, &dropped, &retries, deadline);
    let address = original.original.signed.as_ptr();
    let mut waits = 0_usize;
    let pending = complete_check_with(
        Err(original),
        Failure::retry,
        || now.get(),
        |failure, delay| {
            assert_eq!(failure.original.signed.as_ptr(), address);
            assert_eq!(*failure.original.signed, [0xA9; 32]);
            assert!(failure.original.charge.belongs_to(&pool));
            assert_eq!(pool.reserved_bytes(), 32);
            assert_eq!(failure.deadline, deadline);
            assert_eq!(dropped.get(), 0);
            assert_eq!(delay, Duration::from_millis(1 << waits));
            waits += 1;
            now.set(now.get() + delay);
        },
    )
    .unwrap_or_else(|_| panic!("original attempt should complete"));
    assert_eq!(waits, 5);
    assert_eq!(retries.get(), 5);
    assert_eq!(pending.signed.as_ptr(), address);
    assert_eq!(pool.reserved_bytes(), 32);
    assert_eq!(dropped.get(), 0);
    drop(pending);
    assert_eq!(dropped.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn terminal_failure_retains_its_owner_without_waiting_or_retrying() {
    let pool = AllocationBudget::new(32);
    let dropped = Cell::new(0);
    let retries = Cell::new(0);
    let now = Instant::now();
    let mut original = failure(&pool, &dropped, &retries, now + Duration::from_secs(1));
    original.retryable = false;
    let address = original.original.signed.as_ptr();
    let result = complete_check_with(
        Err(original),
        Failure::retry,
        || now,
        |_, _| panic!("a terminal rejection cannot wait"),
    );
    let Err(CheckTermination::Terminal(original)) = result else {
        panic!("preserve terminal rejection")
    };
    assert_eq!(original.original.signed.as_ptr(), address);
    assert_eq!(retries.get(), 0);
    assert_eq!(dropped.get(), 0);
    drop(original);
    assert_eq!(dropped.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn local_refusal_expires_at_original_deadline_without_an_extra_retry() {
    for lifetime_ms in [0, 2, 70] {
        let pool = AllocationBudget::new(32);
        let dropped = Cell::new(0);
        let retries = Cell::new(0);
        let now = Cell::new(Instant::now());
        let deadline = now.get() + Duration::from_millis(lifetime_ms);
        let mut original = failure(&pool, &dropped, &retries, deadline);
        original.refusals = usize::MAX;
        let mut waits = 0_usize;
        let result = complete_check_with(
            Err(original),
            Failure::retry,
            || now.get(),
            |failure, delay| {
                assert_eq!(failure.deadline, deadline);
                assert_eq!(pool.reserved_bytes(), 32);
                assert!(delay <= Duration::from_millis(32));
                assert!(delay <= deadline.duration_since(now.get()));
                waits += 1;
                now.set(now.get() + delay);
            },
        );
        assert!(matches!(result, Err(CheckTermination::Expired)));
        assert_eq!(now.get(), deadline);
        assert_eq!(retries.get(), waits.saturating_sub(1));
        assert_eq!(dropped.get(), 1);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn unwind_during_wait_releases_only_the_original_owner() {
    let pool = AllocationBudget::new(32);
    let dropped = Cell::new(0);
    let retries = Cell::new(0);
    let now = Instant::now();
    let original = failure(&pool, &dropped, &retries, now + Duration::from_secs(1));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = complete_check_with(
            Err(original),
            Failure::retry,
            || now,
            |failure, _| {
                assert!(failure.original.charge.belongs_to(&pool));
                assert_eq!(pool.reserved_bytes(), 32);
                panic!("service cancellation")
            },
        );
    }));
    assert!(result.is_err());
    assert_eq!(retries.get(), 0);
    assert_eq!(dropped.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn completed_failure_at_original_deadline_keeps_semantics_without_wait_or_retry() {
    let pool = AllocationBudget::new(32);
    let dropped = Cell::new(0);
    let retries = Cell::new(0);
    let deadline = Instant::now();
    let mut original = failure(&pool, &dropped, &retries, deadline);
    original.retryable = false;
    let result = complete_check_with(
        Err(original),
        Failure::retry,
        || deadline,
        |_, _| panic!("completed error cannot wait"),
    );
    let Err(CheckTermination::Terminal(original)) = result else {
        panic!("terminal classification must survive expiry");
    };
    assert_eq!(retries.get(), 0);
    assert!(original.original.charge.belongs_to(&pool));
    drop(original);
    assert_eq!(dropped.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn verification_closure_gets_the_original_owner_and_retains_a_later_terminal_outcome() {
    let pool = AllocationBudget::new(32);
    let dropped = Cell::new(0);
    let retries = Cell::new(0);
    let now = Cell::new(Instant::now());
    let deadline = now.get() + Duration::from_secs(1);
    let original = failure(&pool, &dropped, &retries, deadline);
    let address = original.original.signed.as_ptr();
    let mut verification_calls = 0;
    let mut waits = 0;
    let result: Result<(), _> = complete_check_with(
        Err(original),
        |mut original| {
            verification_calls += 1;
            assert_eq!(original.original.signed.as_ptr(), address);
            assert!(original.original.charge.belongs_to(&pool));
            original.retryable = false;
            // A completed failure returned exactly at expiry still remains terminal.
            now.set(deadline);
            Err(original)
        },
        || now.get(),
        |original, delay| {
            waits += 1;
            assert_eq!(original.deadline(), deadline);
            assert_eq!(delay, Duration::from_millis(1));
        },
    );
    let Err(CheckTermination::Terminal(original)) = result else {
        panic!("terminal verification");
    };
    assert_eq!(verification_calls, 1);
    assert_eq!(waits, 1);
    assert_eq!(
        retries.get(),
        0,
        "verification never re-enters the binding method"
    );
    assert_eq!(original.original.signed.as_ptr(), address);
    drop(original);
    assert_eq!(dropped.get(), 1);
    assert_eq!(pool.reserved_bytes(), 0);
}
