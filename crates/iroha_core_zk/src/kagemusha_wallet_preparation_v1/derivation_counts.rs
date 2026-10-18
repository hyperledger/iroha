//! Observation-only counts of native payment-path derivations.
//!
//! Each thread keeps a cumulative count in memory of every started native operation
//! derivation before Advance: planning, validation of a held plan or recovered batch, and
//! commit's independent re-derivation. The fold worker's released-fold restoration is not
//! counted. Native preparation and commit run synchronously on the calling thread, so the
//! difference of two [`KagemushaWalletDerivationCountsV1::current_thread`] readings taken
//! around one operation ([`KagemushaWalletDerivationCountsV1::observe`]) is the derivation
//! work it did.
//!
//! The counts are never serialized, persisted, signed or returned through the FFI, and no
//! wallet, verifier, admission, readiness or retry decision reads them.

use std::cell::Cell;

/// Native derivation counts (see the module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KagemushaWalletDerivationCountsV1 {
    /// Native operation derivations started before Advance.
    pub before_advance: u64,
}

impl KagemushaWalletDerivationCountsV1 {
    /// The cumulative counts of the current thread.
    #[must_use]
    pub fn current_thread() -> Self {
        Self {
            before_advance: BEFORE_ADVANCE.try_with(Cell::get).unwrap_or(0),
        }
    }

    /// Run `operation` and return its result with the derivations it started on this thread.
    #[must_use]
    pub fn observe<T>(operation: impl FnOnce() -> T) -> (T, Self) {
        let before = Self::current_thread();
        let result = operation();
        (result, Self::current_thread().since(before))
    }

    /// The work counted in `self` and not in `earlier` (saturating at zero).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            before_advance: self.before_advance.saturating_sub(earlier.before_advance),
        }
    }
}

thread_local! {
    static BEFORE_ADVANCE: Cell<u64> = const { Cell::new(0) };
}

/// Record one started derivation before Advance. Counting never fails or panics.
pub(super) fn record_before_advance() {
    let _ = BEFORE_ADVANCE.try_with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_counts_stay_on_their_thread() {
        let ((), used) = KagemushaWalletDerivationCountsV1::observe(|| {
            record_before_advance();
            let ((), elsewhere) = std::thread::spawn(|| {
                KagemushaWalletDerivationCountsV1::observe(|| {
                    record_before_advance();
                    record_before_advance();
                })
            })
            .join()
            .expect("thread");
            assert_eq!(elsewhere.before_advance, 2);
        });
        assert_eq!(used.before_advance, 1);
        let now = KagemushaWalletDerivationCountsV1::current_thread();
        assert_eq!(
            now.since(KagemushaWalletDerivationCountsV1::current_thread()),
            KagemushaWalletDerivationCountsV1::default()
        );
    }
}
