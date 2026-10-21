//! Observation-only counts of wallet proof verification work.
//!
//! Each thread keeps its own cumulative counts in memory: every started Omega lineage
//! verification, plus the `iroha_plonk` full verifications, decides and `<s(u), g>` MSMs
//! (lineage ones included). Native preparation, payment and fold verification run
//! synchronously on the calling thread, so the difference of two
//! [`KagemushaWalletVerificationCountsV1::current_thread`] readings taken around one
//! operation, fold turn or credit read ([`KagemushaWalletVerificationCountsV1::observe`]) is
//! the verification work it did.
//!
//! Fold diagnostics may return bounded, observation-only count deltas through the FFI.
//! Counts are never persisted or signed, and no wallet, verifier, admission, readiness or
//! retry decision reads them.

use std::cell::Cell;

use iroha_plonk::VerificationCounts;

/// Wallet verification work counts (see the module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KagemushaWalletVerificationCountsV1 {
    /// Omega lineage verifications started. Each one, when it completes, is one full Pallas
    /// verification plus the Pallas and Vesta accumulator decides, all counted in `proofs`.
    pub verify_lineage: u64,
    /// Every full verification, decide and generator MSM started, lineage ones included.
    pub proofs: VerificationCounts,
}

impl KagemushaWalletVerificationCountsV1 {
    /// The cumulative counts of the current thread.
    #[must_use]
    pub fn current_thread() -> Self {
        Self {
            verify_lineage: VERIFY_LINEAGE.try_with(Cell::get).unwrap_or(0),
            proofs: VerificationCounts::current_thread(),
        }
    }

    /// Run `operation` and return its result with the verification work it did on this
    /// thread.
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
            verify_lineage: self.verify_lineage.saturating_sub(earlier.verify_lineage),
            proofs: self.proofs.since(earlier.proofs),
        }
    }
}

thread_local! {
    static VERIFY_LINEAGE: Cell<u64> = const { Cell::new(0) };
}

/// Record one started Omega lineage verification. Counting never fails or panics.
pub(super) fn record_lineage() {
    let _ = VERIFY_LINEAGE.try_with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
mod tests {
    use iroha_plonk::verification_counters::record_decide;

    use super::*;

    #[test]
    fn lineage_counts_stay_on_their_thread_and_include_proof_work() {
        let ((), used) = KagemushaWalletVerificationCountsV1::observe(|| {
            record_lineage();
            record_decide();
            let ((), elsewhere) =
                std::thread::spawn(|| KagemushaWalletVerificationCountsV1::observe(record_lineage))
                    .join()
                    .expect("thread");
            assert_eq!(elsewhere.verify_lineage, 1);
            assert_eq!(elsewhere.proofs, VerificationCounts::default());
        });
        assert_eq!(used.verify_lineage, 1);
        assert_eq!(used.proofs.decides, 1);
        let now = KagemushaWalletVerificationCountsV1::current_thread();
        assert_eq!(
            now.since(KagemushaWalletVerificationCountsV1::current_thread()),
            KagemushaWalletVerificationCountsV1::default()
        );
    }
}
