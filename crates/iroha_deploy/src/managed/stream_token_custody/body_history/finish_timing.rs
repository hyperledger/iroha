//! Opt-in numeric attribution for the existing genuine deep-history test only.
//! Nested phase totals are inclusive; they must not be added together as exclusive work.
//! Closure subphases run only inside an existing prepare/finish timer and that same capture.
//! Attempt record totals include the optional native read and, when present, its canonical
//! decoder. Decode subphases cover only `decode_record`, including its canonical re-encode;
//! absent leaves and native refusals before the callback have no decode sample. Scoped reads
//! exclude their caller's directory/tree entry and exit. Inventory subphases surround only
//! the original `entries` calls: ordinary calls include full ancestry checks, scoped calls
//! include native census work under the caller's separate entry/exit fences. No interval
//! measures wallet decoding. GraphValidate covers every full retained-graph call during the
//! capture, including calls outside prepare/finish closures. SnapshotRevalidate brackets only
//! the full snapshot entry, including its recursive walk and native entry/exit checks, without
//! recursively sampling each node. These intervals overlap and must not be added together.

use std::{cell::Cell, fmt, time::Instant};

/// Fixed numeric phase index; never retains an input, path, record, handle or authority.
#[derive(Clone, Copy, Debug)]
pub(in crate::managed) enum Phase {
    Finish,
    Reopen,
    ReadRecords,
    VerifyHistories,
    ParserWallet,
    ClosurePrepare,
    ClosureFinish,
    ClosureWallet,
    WalletRetire,
    SignRetained,
    HistoricalRead,
    ProfileEntry,
    ProfileExit,
    ClosureFullGraph,
    ClosureRetainedRead,
    ClosureLiveCheck,
    ClosureLiveClaim,
    ClosureRecordWrite,
    AttemptRecordRead,
    AttemptRecordDecode,
    AttemptScopedRecordRead,
    AttemptScopedRecordDecode,
    AttemptInventory,
    AttemptScopedInventory,
    GraphValidate,
    SnapshotRevalidate,
}
const PHASES: [Phase; 26] = [
    Phase::Finish,
    Phase::Reopen,
    Phase::ReadRecords,
    Phase::VerifyHistories,
    Phase::ParserWallet,
    Phase::ClosurePrepare,
    Phase::ClosureFinish,
    Phase::ClosureWallet,
    Phase::WalletRetire,
    Phase::SignRetained,
    Phase::HistoricalRead,
    Phase::ProfileEntry,
    Phase::ProfileExit,
    Phase::ClosureFullGraph,
    Phase::ClosureRetainedRead,
    Phase::ClosureLiveCheck,
    Phase::ClosureLiveClaim,
    Phase::ClosureRecordWrite,
    Phase::AttemptRecordRead,
    Phase::AttemptRecordDecode,
    Phase::AttemptScopedRecordRead,
    Phase::AttemptScopedRecordDecode,
    Phase::AttemptInventory,
    Phase::AttemptScopedInventory,
    Phase::GraphValidate,
    Phase::SnapshotRevalidate,
];

#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    calls: u64,
    elapsed_us: u128,
}
/// Fixed-size counters only, copied out after the measured finish returns.
#[derive(Clone, Copy, Default)]
pub(in crate::managed) struct Stats([Sample; PHASES.len()]);
impl Stats {
    /// Numeric accounting for native reader tests; no source or validation result is retained.
    pub(in crate::managed) fn sample(&self, phase: Phase) -> (u64, u128) {
        let sample = self.0[phase as usize];
        (sample.calls, sample.elapsed_us)
    }
}
impl fmt::Debug for Stats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = formatter.debug_map();
        for (phase, sample) in PHASES.iter().zip(self.0.iter()) {
            map.entry(phase, sample);
        }
        map.finish()
    }
}
thread_local! {
    static ACTIVE: Cell<Option<Stats>> = const { Cell::new(None) };
    static CLOSURE_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Single-thread test scope; unwinding removes the opt-in numeric collector.
pub(in crate::managed) struct Capture;
impl Capture {
    pub(in crate::managed) fn start() -> Self {
        ACTIVE.with(|active| {
            assert!(active.get().is_none(), "finish timer capture must not nest");
            CLOSURE_ACTIVE.set(false);
            active.set(Some(Stats::default()));
        });
        Self
    }
    pub(in crate::managed) fn finish(self) -> Stats {
        ACTIVE.with(|active| active.take().expect("finish capture is active"))
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        CLOSURE_ACTIVE.set(false);
        ACTIVE.with(|active| active.set(None));
    }
}

/// Snapshot for an existing failure report; no formatting occurs in timed code.
pub(super) fn snapshot() -> Option<Stats> {
    ACTIVE.with(Cell::get)
}

/// Records ordinary error/unwind exits as well as successful exits.
pub(in crate::managed) struct Timer {
    phase: Phase,
    started: Option<Instant>,
    previous_closure: Option<bool>,
}
pub(in crate::managed) fn phase(phase: Phase) -> Timer {
    let started = ACTIVE.with(|active| active.get().is_some().then(Instant::now));
    let previous_closure = (started.is_some()
        && matches!(phase, Phase::ClosurePrepare | Phase::ClosureFinish))
    .then(|| CLOSURE_ACTIVE.replace(true));
    Timer {
        phase,
        started,
        previous_closure,
    }
}
/// Keep native probes inert outside the original opt-in closure interval.
pub(in crate::managed) fn phase_in_closure(phase: Phase) -> Timer {
    if CLOSURE_ACTIVE.get() {
        self::phase(phase)
    } else {
        Timer {
            phase,
            started: None,
            previous_closure: None,
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let elapsed_us = started.elapsed().as_micros();
        ACTIVE.with(|active| {
            if let Some(mut totals) = active.get() {
                let sample = &mut totals.0[self.phase as usize];
                sample.calls += 1;
                sample.elapsed_us += elapsed_us;
                active.set(Some(totals));
            }
        });
        if let Some(previous) = self.previous_closure {
            CLOSURE_ACTIVE.set(previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_work_requires_both_capture_and_original_closure_guard() {
        let disabled = phase(Phase::ClosurePrepare);
        assert!(disabled.started.is_none());
        assert!(!CLOSURE_ACTIVE.get());
        assert!(phase_in_closure(Phase::ClosureFullGraph).started.is_none());
        drop(disabled);
        for measured in [Phase::GraphValidate, Phase::SnapshotRevalidate] {
            assert!(phase(measured).started.is_none());
        }

        let capture = Capture::start();
        assert!(phase_in_closure(Phase::ClosureFullGraph).started.is_none());
        {
            let _graph = phase(Phase::GraphValidate);
            drop(phase(Phase::SnapshotRevalidate));
            assert!(!CLOSURE_ACTIVE.get());
        }
        {
            let _prepare = phase(Phase::ClosurePrepare);
            let _graph = phase(Phase::GraphValidate);
            drop(phase(Phase::SnapshotRevalidate));
            drop(phase_in_closure(Phase::ClosureFullGraph));
            {
                let _finish = phase(Phase::ClosureFinish);
                drop(phase_in_closure(Phase::ClosureFullGraph));
            }
            assert!(CLOSURE_ACTIVE.get());
            drop(phase_in_closure(Phase::ClosureRetainedRead));
        }
        assert!(!CLOSURE_ACTIVE.get());
        assert!(phase_in_closure(Phase::ClosureFullGraph).started.is_none());
        let stats = capture.finish();
        assert_eq!(stats.0[Phase::ClosurePrepare as usize].calls, 1);
        assert_eq!(stats.0[Phase::ClosureFinish as usize].calls, 1);
        assert_eq!(stats.0[Phase::ClosureFullGraph as usize].calls, 2);
        assert_eq!(stats.0[Phase::ClosureRetainedRead as usize].calls, 1);
        assert_eq!(stats.sample(Phase::GraphValidate).0, 2);
        assert_eq!(stats.sample(Phase::SnapshotRevalidate).0, 2);
        assert!(snapshot().is_none());
        assert!(!CLOSURE_ACTIVE.get());
    }

    #[test]
    fn error_and_unwind_close_timers_and_clear_the_original_capture() {
        fn ordinary_error() -> Result<(), ()> {
            let _full_graph = phase(Phase::GraphValidate);
            let _snapshot = phase(Phase::SnapshotRevalidate);
            let _closure = phase(Phase::ClosurePrepare);
            let _graph = phase_in_closure(Phase::ClosureFullGraph);
            Err(())
        }
        let capture = Capture::start();
        assert_eq!(ordinary_error(), Err(()));
        assert!(!CLOSURE_ACTIVE.get());
        assert!(
            std::panic::catch_unwind(|| {
                let _full_graph = phase(Phase::GraphValidate);
                let _snapshot = phase(Phase::SnapshotRevalidate);
                let _closure = phase(Phase::ClosureFinish);
                let _check = phase_in_closure(Phase::ClosureLiveCheck);
                panic!("test-only original closure unwind");
            })
            .is_err()
        );
        assert!(!CLOSURE_ACTIVE.get());
        let stats = capture.finish();
        assert_eq!(stats.0[Phase::ClosurePrepare as usize].calls, 1);
        assert_eq!(stats.0[Phase::ClosureFinish as usize].calls, 1);
        assert_eq!(stats.0[Phase::ClosureFullGraph as usize].calls, 1);
        assert_eq!(stats.0[Phase::ClosureLiveCheck as usize].calls, 1);
        assert_eq!(stats.sample(Phase::GraphValidate).0, 2);
        assert_eq!(stats.sample(Phase::SnapshotRevalidate).0, 2);

        assert!(
            std::panic::catch_unwind(|| {
                let _capture = Capture::start();
                let _full_graph = phase(Phase::GraphValidate);
                let _snapshot = phase(Phase::SnapshotRevalidate);
                let _closure = phase(Phase::ClosurePrepare);
                let _claim = phase_in_closure(Phase::ClosureLiveClaim);
                panic!("test-only original capture unwind");
            })
            .is_err()
        );
        assert!(snapshot().is_none());
        assert!(!CLOSURE_ACTIVE.get());
        let capture = Capture::start();
        assert!(
            phase_in_closure(Phase::ClosureRecordWrite)
                .started
                .is_none()
        );
        assert!(capture.finish().0.iter().all(|sample| sample.calls == 0));
    }
}
