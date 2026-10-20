//! Observation-only counts of verifier work.
//!
//! The counted events are full verifications ([`crate::verifier::verify_full`]
//! and its wrappers), single generator-claim decides, batched decisions, and
//! the `<s(u), g>` MSMs over the parameter generators that back each of them.
//! Every call is counted when it starts, including calls that later reject,
//! fail or are cancelled. Answers taken from a parameter owner's memo of
//! accepted work are counted separately: a reused full verification computes
//! nothing further, and a reused `<s(u), g>` replaces that MSM.
//!
//! Counting is always on. Each thread keeps its own cumulative counts in
//! memory; verification runs synchronously on the calling thread, so the
//! difference of two [`VerificationCounts::current_thread`] readings
//! ([`VerificationCounts::since`]) is the work done in between. No verifier
//! reads these values. Hosts may serialize bounded observation-only deltas for diagnostics;
//! the counters are never persisted or signed and confer no acceptance, readiness or other
//! authority.

use std::cell::Cell;

/// Verifier work counts (see the module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationCounts {
    /// Full PLONK verifications started.
    pub verify_full: u64,
    /// Single generator-claim decides started: `PendingAccumulator::decide`,
    /// `GeneratorClaim::decide` and the recursive accumulator decides.
    pub decides: u64,
    /// Batched decisions started (`batch_decide`, `batch_verify`).
    pub batches: u64,
    /// `<s(u), g>` MSMs over the parameter generators started, whether for a
    /// full verification, a decide, a recursive correction or a batch.
    pub generator_msms: u64,
    /// Generator bases of those MSMs in total (`2^k` per single MSM).
    pub generator_msm_bases: u64,
    /// Full verifications answered from the parameter owner's memo of accepted
    /// byte-identical inputs (also counted in `verify_full`).
    pub reused_verifications: u64,
    /// `<s(u), g>` values taken from the parameter owner's memo of accepted
    /// folded generators instead of an MSM (not counted in `generator_msms`).
    pub reused_generators: u64,
}

impl VerificationCounts {
    const ZERO: Self = Self {
        verify_full: 0,
        decides: 0,
        batches: 0,
        generator_msms: 0,
        generator_msm_bases: 0,
        reused_verifications: 0,
        reused_generators: 0,
    };

    /// The cumulative counts of the current thread.
    #[must_use]
    pub fn current_thread() -> Self {
        COUNTS.try_with(Cell::get).unwrap_or(Self::ZERO)
    }

    /// The work counted in `self` and not in `earlier` (field by field,
    /// saturating at zero).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            verify_full: self.verify_full.saturating_sub(earlier.verify_full),
            decides: self.decides.saturating_sub(earlier.decides),
            batches: self.batches.saturating_sub(earlier.batches),
            generator_msms: self.generator_msms.saturating_sub(earlier.generator_msms),
            generator_msm_bases: self
                .generator_msm_bases
                .saturating_sub(earlier.generator_msm_bases),
            reused_verifications: self
                .reused_verifications
                .saturating_sub(earlier.reused_verifications),
            reused_generators: self
                .reused_generators
                .saturating_sub(earlier.reused_generators),
        }
    }
}

thread_local! {
    static COUNTS: Cell<VerificationCounts> = const { Cell::new(VerificationCounts::ZERO) };
}

// Counting never fails or panics: a thread whose local storage is gone counts nothing.
fn update(change: impl FnOnce(&mut VerificationCounts)) {
    let _ = COUNTS.try_with(|cell| {
        let mut counts = cell.get();
        change(&mut counts);
        cell.set(counts);
    });
}

/// Record one started full verification.
pub(crate) fn record_verify_full() {
    update(|counts| counts.verify_full = counts.verify_full.saturating_add(1));
}

/// Record one started batched decision.
pub(crate) fn record_batch() {
    update(|counts| counts.batches = counts.batches.saturating_add(1));
}

/// Record one full verification answered from a parameter owner's memo.
pub(crate) fn record_reused_verification() {
    update(|counts| {
        counts.reused_verifications = counts.reused_verifications.saturating_add(1);
    });
}

/// Record one `<s(u), g>` value taken from a parameter owner's memo.
pub(crate) fn record_reused_generator() {
    update(|counts| counts.reused_generators = counts.reused_generators.saturating_add(1));
}

/// Record one started single generator-claim decide. Observation only, for
/// this crate and the recursive accumulator decides; it confers nothing.
pub fn record_decide() {
    update(|counts| counts.decides = counts.decides.saturating_add(1));
}

/// Record one started `<s(u), g>` MSM over `bases` parameter generators.
/// Observation only, for this crate and the recursive accumulator decides; it
/// confers nothing.
pub fn record_generator_msm(bases: usize) {
    let bases = u64::try_from(bases).unwrap_or(u64::MAX);
    update(|counts| {
        counts.generator_msms = counts.generator_msms.saturating_add(1);
        counts.generator_msm_bases = counts.generator_msm_bases.saturating_add(bases);
    });
}

#[cfg(test)]
mod tests;
