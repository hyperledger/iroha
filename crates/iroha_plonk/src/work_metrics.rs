//! Observation-only, thread-local elapsed times at native proving boundaries.
//!
//! These monotonic durations include successful, refused and cancelled calls. They are
//! nested measurements: a consumer must not add them to an enclosing operation or fold
//! duration. No prover, verifier or scheduler reads them to make a decision. The values
//! contain no witness, key, proof, identity or verdict. Hosts may expose bounded deltas as
//! diagnostics; the counters themselves remain in memory and are never signed.

use std::{
    cell::Cell,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant},
};

/// The fixed native proving boundaries measured on their calling thread.
#[derive(Clone, Copy, Debug)]
pub enum WorkPhase {
    /// Revalidation of the selected proving original by its authenticated owner.
    KeyImport,
    /// Reconstruction of the exact admitted proving key from its source-bound verifier.
    KeyRebuild,
    /// Physical circuit witness synthesis and validation under the selected key.
    Witness,
    /// The canonical proof engine, after witness synthesis and before self-verification.
    Prove,
    /// Complete acceptance of a newly produced proof, including required claim decisions
    /// and construction of its immediate native output. Restoration checks are excluded.
    SelfVerify,
    /// Wallet transition validation and durable Advance; an enclosing host scope that
    /// can contain proof verification, custody work and storage publication.
    Commit,
    /// Authenticated selected-source and durable-plan reconstruction. Includes
    /// fresh derivation and mandatory commit revalidation, not only restart.
    /// Nested in the enclosing work/commit; not physical witness synthesis.
    SourceRestore,
    /// Encode and publish the frozen Sigma capsule and exact preparation mapping.
    /// This precedes Advance and is not monetary completion or final export release.
    SigmaPublish,
}

/// Cumulative elapsed times of this thread's native proof work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkMetrics {
    /// Revalidation of the exact selected proving original.
    pub key_import: Duration,
    /// Exact admitted proving-key reconstruction.
    pub key_rebuild: Duration,
    /// Physical circuit witness synthesis and validation.
    pub witness: Duration,
    /// Canonical engine proof generation.
    pub prove: Duration,
    /// Newly produced proof acceptance, including required accumulator decisions.
    pub self_verify: Duration,
    /// Transition validation and durable Advance (not a pure storage-write timer).
    pub commit: Duration,
    /// Selected-source/plan restoration and derivation, including fresh validation.
    pub source_restore: Duration,
    /// Frozen Sigma capsule and preparation-mapping publication before Advance.
    pub sigma_publish: Duration,
}
impl WorkMetrics {
    /// Read only this calling thread's accumulated durations.
    #[must_use]
    pub fn current_thread() -> Self {
        METRICS.try_with(Cell::get).unwrap_or_default()
    }
    /// Saturating differences from an earlier reading on this same thread.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            key_import: self.key_import.saturating_sub(earlier.key_import),
            key_rebuild: self.key_rebuild.saturating_sub(earlier.key_rebuild),
            witness: self.witness.saturating_sub(earlier.witness),
            prove: self.prove.saturating_sub(earlier.prove),
            self_verify: self.self_verify.saturating_sub(earlier.self_verify),
            commit: self.commit.saturating_sub(earlier.commit),
            source_restore: self.source_restore.saturating_sub(earlier.source_restore),
            sigma_publish: self.sigma_publish.saturating_sub(earlier.sigma_publish),
        }
    }
    fn record(&mut self, phase: WorkPhase, elapsed: Duration) {
        let total = match phase {
            WorkPhase::KeyImport => &mut self.key_import,
            WorkPhase::KeyRebuild => &mut self.key_rebuild,
            WorkPhase::Witness => &mut self.witness,
            WorkPhase::Prove => &mut self.prove,
            WorkPhase::SelfVerify => &mut self.self_verify,
            WorkPhase::Commit => &mut self.commit,
            WorkPhase::SourceRestore => &mut self.source_restore,
            WorkPhase::SigmaPublish => &mut self.sigma_publish,
        };
        *total = total.saturating_add(elapsed);
    }
}
thread_local! {
    static METRICS: Cell<WorkMetrics> = const { Cell::new(WorkMetrics {
        key_import: Duration::ZERO, commit: Duration::ZERO,
        key_rebuild: Duration::ZERO, witness: Duration::ZERO,
        prove: Duration::ZERO, self_verify: Duration::ZERO,
        source_restore: Duration::ZERO, sigma_publish: Duration::ZERO,
    }) };
    static DEPTH: Cell<[u32; 8]> = const { Cell::new([0; 8]) };
}

/// A timer confined to its originating thread. Dropping it records observation even on
/// early returns or unwinding. Nested timers of the same phase are counted only once.
#[must_use]
pub struct WorkTimer {
    phase: WorkPhase,
    started: Instant,
    outermost: bool,
    thread: PhantomData<Rc<()>>,
}
impl WorkTimer {
    /// Begin an observation scope; no timer value affects its enclosed work.
    pub fn start(phase: WorkPhase) -> Self {
        let outermost = DEPTH
            .try_with(|cell| {
                let mut depth = cell.get();
                let outermost = depth[phase as usize] == 0;
                depth[phase as usize] = depth[phase as usize].saturating_add(1);
                cell.set(depth);
                outermost
            })
            .unwrap_or(false);
        Self {
            phase,
            started: Instant::now(),
            outermost,
            thread: PhantomData,
        }
    }
}
impl Drop for WorkTimer {
    fn drop(&mut self) {
        let _ = DEPTH.try_with(|cell| {
            let mut depth = cell.get();
            depth[self.phase as usize] = depth[self.phase as usize].saturating_sub(1);
            cell.set(depth);
        });
        if self.outermost {
            let elapsed = self.started.elapsed();
            let _ = METRICS.try_with(|cell| {
                let mut total = cell.get();
                total.record(self.phase, elapsed);
                cell.set(total);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_observations_stay_on_their_thread_and_survive_early_return() {
        let before = WorkMetrics::current_thread();
        std::thread::spawn(|| {
            let _timer = WorkTimer::start(WorkPhase::KeyRebuild);
        })
        .join()
        .unwrap();
        assert_eq!(WorkMetrics::current_thread(), before);
        let refused = || -> Result<(), ()> {
            let _timer = WorkTimer::start(WorkPhase::Witness);
            Err(())
        };
        assert_eq!(refused(), Err(()));
        let delta = WorkMetrics::current_thread().since(before);
        assert_eq!(delta.key_rebuild, Duration::ZERO);
        assert_eq!(delta.prove, Duration::ZERO);
        assert_eq!(delta.self_verify, Duration::ZERO);
        assert_eq!(DEPTH.with(Cell::get), [0; 8]);
    }

    #[test]
    fn nested_scopes_do_not_record_the_same_phase_twice() {
        let before = WorkMetrics::current_thread();
        let outer = WorkTimer::start(WorkPhase::SelfVerify);
        {
            let _inner = WorkTimer::start(WorkPhase::SelfVerify);
        }
        assert_eq!(WorkMetrics::current_thread(), before);
        assert_eq!(DEPTH.with(Cell::get), [0, 0, 0, 0, 1, 0, 0, 0]);
        drop(outer);
        assert_eq!(DEPTH.with(Cell::get), [0; 8]);
        assert_eq!(
            WorkMetrics::default().since(WorkMetrics::current_thread()),
            WorkMetrics::default()
        );
    }

    #[test]
    fn restoration_and_publication_have_independent_saturating_deltas() {
        let mut metrics = WorkMetrics::default();
        metrics.record(WorkPhase::SourceRestore, Duration::from_micros(7));
        metrics.record(WorkPhase::SigmaPublish, Duration::from_micros(11));
        let before = metrics;
        metrics.record(WorkPhase::SourceRestore, Duration::from_micros(3));
        metrics.record(WorkPhase::SigmaPublish, Duration::from_micros(5));
        let delta = metrics.since(before);
        assert_eq!(delta.source_restore, Duration::from_micros(3));
        assert_eq!(delta.sigma_publish, Duration::from_micros(5));
        assert_eq!(delta.commit, Duration::ZERO);
        assert_eq!(before.since(metrics), WorkMetrics::default());
    }

    #[test]
    fn restoration_and_publication_scopes_unwind_without_leaking_depth() {
        let before = WorkMetrics::current_thread();
        let restored = WorkTimer::start(WorkPhase::SourceRestore);
        let refused = || -> Result<(), ()> {
            let _nested = WorkTimer::start(WorkPhase::SourceRestore);
            let _publication = WorkTimer::start(WorkPhase::SigmaPublish);
            Err(())
        };
        assert_eq!(refused(), Err(()));
        assert_eq!(DEPTH.with(Cell::get), [0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(WorkMetrics::current_thread().source_restore, before.source_restore);
        drop(restored);
        assert_eq!(DEPTH.with(Cell::get), [0; 8]);
    }

}
