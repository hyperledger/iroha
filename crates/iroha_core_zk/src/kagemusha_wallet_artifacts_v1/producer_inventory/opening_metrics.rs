//! Observation-only phase timings and work counts for native wallet opening.
//!
//! An opening records the monotonic duration of each phase together with the public
//! work that phase started on its thread: signed originals opened, retained encoded
//! files opened, stored and raw bytes hashed, zstd frame decodes, descriptor decodes
//! and retained-ancestry walks. Values are public names, durations and counts only.
//! They are kept in memory, never persisted, signed or matched against a profile, and
//! no admission, readiness, error, retry or cancellation decision reads them.
//!
//! Counts are per thread because opening runs synchronously on its calling thread.
//! Work moved to another thread must add that thread's own difference explicitly:
//! the helper measures it with `attributed`, which takes it off the helper thread's
//! counts, and the opening thread counts it with `adopt`. Every lap and total of
//! that opening then counts it exactly once, wherever it ran.

use std::{
    cell::Cell,
    fmt::Write as _,
    time::{Duration, Instant},
};

/// Public opening work started on the current thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningWorkV1 {
    /// Signed originals opened for a complete bounded read or revalidation.
    pub originals_opened: u64,
    /// Retained encoded original files opened from the private carrier.
    pub stored_files_opened: u64,
    /// Encoded bytes hashed against their stored identity.
    pub stored_bytes_hashed: u64,
    /// Raw original bytes hashed by decoders, bounded original reads and
    /// compiled-profile admission.
    pub raw_bytes_hashed: u64,
    /// Single-frame zstd decodes started.
    pub zstd_decodes: u64,
    /// Canonical descriptor admission decodes started.
    pub descriptor_decodes: u64,
    /// Retained-ancestry revalidation walks started.
    pub ancestry_walks: u64,
    /// Ancestor links those walks reopened by name (one native open each).
    pub ancestry_opens: u64,
}

impl OpeningWorkV1 {
    /// This thread's cumulative counts, including filesystem custody and key admission,
    /// with work other threads did for this thread's opening and without work this
    /// thread did for another thread's opening.
    #[must_use]
    pub fn current_thread() -> Self {
        // Thread-local teardown loses only observation, never a verdict.
        let local = LOCAL.try_with(Cell::get).unwrap_or_default();
        let custody = iroha_fs::CustodyWorkV1::current_thread();
        let admission = iroha_plonk::keys::AdmissionWorkV1::current_thread();
        let (adopted, given) = MOVED.try_with(Cell::get).unwrap_or_default();
        Self {
            originals_opened: local.originals_opened,
            stored_files_opened: local.stored_files_opened,
            stored_bytes_hashed: local.stored_bytes_hashed,
            raw_bytes_hashed: local
                .raw_bytes_hashed
                .saturating_add(admission.builtin_bytes_hashed),
            zstd_decodes: local.zstd_decodes,
            descriptor_decodes: admission.descriptor_decodes,
            ancestry_walks: custody.ancestry_walks,
            ancestry_opens: custody.ancestry_opens,
        }
        .plus(adopted)
        .since(given)
    }

    /// The work counted in `self` or in `other` (field by field, saturating).
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self {
            originals_opened: self.originals_opened.saturating_add(other.originals_opened),
            stored_files_opened: self
                .stored_files_opened
                .saturating_add(other.stored_files_opened),
            stored_bytes_hashed: self
                .stored_bytes_hashed
                .saturating_add(other.stored_bytes_hashed),
            raw_bytes_hashed: self.raw_bytes_hashed.saturating_add(other.raw_bytes_hashed),
            zstd_decodes: self.zstd_decodes.saturating_add(other.zstd_decodes),
            descriptor_decodes: self
                .descriptor_decodes
                .saturating_add(other.descriptor_decodes),
            ancestry_walks: self.ancestry_walks.saturating_add(other.ancestry_walks),
            ancestry_opens: self.ancestry_opens.saturating_add(other.ancestry_opens),
        }
    }

    /// The work counted in `self` and not in `earlier` (field by field, saturating).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            originals_opened: self
                .originals_opened
                .saturating_sub(earlier.originals_opened),
            stored_files_opened: self
                .stored_files_opened
                .saturating_sub(earlier.stored_files_opened),
            stored_bytes_hashed: self
                .stored_bytes_hashed
                .saturating_sub(earlier.stored_bytes_hashed),
            raw_bytes_hashed: self
                .raw_bytes_hashed
                .saturating_sub(earlier.raw_bytes_hashed),
            zstd_decodes: self.zstd_decodes.saturating_sub(earlier.zstd_decodes),
            descriptor_decodes: self
                .descriptor_decodes
                .saturating_sub(earlier.descriptor_decodes),
            ancestry_walks: self.ancestry_walks.saturating_sub(earlier.ancestry_walks),
            ancestry_opens: self.ancestry_opens.saturating_sub(earlier.ancestry_opens),
        }
    }

    const fn fields(self) -> [(&'static str, u64); 8] {
        [
            ("originalsOpened", self.originals_opened),
            ("storedFilesOpened", self.stored_files_opened),
            ("storedBytesHashed", self.stored_bytes_hashed),
            ("rawBytesHashed", self.raw_bytes_hashed),
            ("zstdDecodes", self.zstd_decodes),
            ("descriptorDecodes", self.descriptor_decodes),
            ("ancestryWalks", self.ancestry_walks),
            ("ancestryOpens", self.ancestry_opens),
        ]
    }
}

/// Work counted by this crate; filesystem and key-admission counts live in their crates.
#[derive(Clone, Copy, Default)]
struct LocalWork {
    originals_opened: u64,
    stored_files_opened: u64,
    stored_bytes_hashed: u64,
    raw_bytes_hashed: u64,
    zstd_decodes: u64,
}

thread_local! {
    static LOCAL: Cell<LocalWork> = const {
        Cell::new(LocalWork {
            originals_opened: 0,
            stored_files_opened: 0,
            stored_bytes_hashed: 0,
            raw_bytes_hashed: 0,
            zstd_decodes: 0,
        })
    };
}

fn record(add: impl FnOnce(&mut LocalWork)) {
    let _ = LOCAL.try_with(|local| {
        let mut value = local.get();
        add(&mut value);
        local.set(value);
    });
}

const NO_WORK: OpeningWorkV1 = OpeningWorkV1 {
    originals_opened: 0,
    stored_files_opened: 0,
    stored_bytes_hashed: 0,
    raw_bytes_hashed: 0,
    zstd_decodes: 0,
    descriptor_decodes: 0,
    ancestry_walks: 0,
    ancestry_opens: 0,
};

thread_local! {
    // Work other threads did for this thread's opening (adopted), and work this
    // thread did for other threads' openings (given), so each counts on one thread.
    static MOVED: Cell<(OpeningWorkV1, OpeningWorkV1)> = const { Cell::new((NO_WORK, NO_WORK)) };
}

fn moved(update: impl FnOnce(&mut (OpeningWorkV1, OpeningWorkV1))) {
    let _ = MOVED.try_with(|cell| {
        let mut value = cell.get();
        update(&mut value);
        cell.set(value);
    });
}

/// Run `work` and take the opening work it did on this thread off this thread's
/// counts. The caller counts the returned work with `adopt` on the thread of the
/// opening it belongs to, so a task that a waiting join ran here, or that another
/// attributed task nested, still counts exactly once.
pub(super) fn attributed<R>(work: impl FnOnce() -> R) -> (R, OpeningWorkV1) {
    let start = OpeningWorkV1::current_thread();
    let result = work();
    let done = OpeningWorkV1::current_thread().since(start);
    moved(|(_, given)| *given = given.plus(done));
    (result, done)
}

/// Count `work` that other threads did for this thread's opening on this thread.
pub(super) fn adopt(work: OpeningWorkV1) {
    moved(|(adopted, _)| *adopted = adopted.plus(work));
}

/// One signed original opened for a bounded read or revalidation.
pub(super) fn record_original_opened() {
    record(|work| work.originals_opened = work.originals_opened.saturating_add(1));
}

/// One retained encoded original file opened.
pub(super) fn record_stored_file_opened() {
    record(|work| work.stored_files_opened = work.stored_files_opened.saturating_add(1));
}

/// Encoded bytes hashed by one stored reader, recorded once when it is dropped.
pub(super) fn record_stored_hashed(bytes: u64) {
    record(|work| work.stored_bytes_hashed = work.stored_bytes_hashed.saturating_add(bytes));
}

/// Raw bytes hashed by one decoder or bounded read, recorded once per original.
pub(super) fn record_raw_hashed(bytes: u64) {
    record(|work| work.raw_bytes_hashed = work.raw_bytes_hashed.saturating_add(bytes));
}

/// One single-frame zstd decode started.
pub(super) fn record_zstd_decode() {
    record(|work| work.zstd_decodes = work.zstd_decodes.saturating_add(1));
}

/// Monotonic duration and thread work of one opening phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningPhaseV1 {
    /// Monotonic wall time.
    pub elapsed: Duration,
    /// Work started on the opening thread.
    pub work: OpeningWorkV1,
}

/// Lap clock over monotonic time and this thread's work counts.
#[derive(Clone, Copy, Debug)]
pub struct OpeningClockV1 {
    at: Instant,
    work: OpeningWorkV1,
}

impl OpeningClockV1 {
    /// Start a lap now on this thread.
    #[must_use]
    pub fn start() -> Self {
        Self {
            at: Instant::now(),
            work: OpeningWorkV1::current_thread(),
        }
    }

    /// The time and work since the previous lap or start; the next lap starts now.
    pub fn lap(&mut self) -> OpeningPhaseV1 {
        let next = Self::start();
        let phase = OpeningPhaseV1 {
            elapsed: next.at.saturating_duration_since(self.at),
            work: next.work.since(self.work),
        };
        *self = next;
        phase
    }
}

/// Stage split of one complete source-graph qualification, held by its owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QualificationMetricsV1 {
    /// Installation identity, native-genesis finality and compiled-profile binding.
    pub binding: OpeningPhaseV1,
    /// The eleven sigma sources.
    pub sigma: OpeningPhaseV1,
    /// Every Q program.
    pub q: OpeningPhaseV1,
    /// Every logical operation route.
    pub routes: OpeningPhaseV1,
    /// The sole final Omega closure.
    pub omega: OpeningPhaseV1,
}

/// Schema of [`OpeningMetricsV1::to_json`].
pub const OPENING_METRICS_SCHEMA_V1: &str = "iroha.kagemusha.opening-metrics.v1";

/// Ordered named phases of one opening. Names are fixed public identifiers.
#[derive(Clone, Debug)]
pub struct OpeningMetricsV1 {
    started: OpeningClockV1,
    clock: OpeningClockV1,
    phases: Vec<(&'static str, OpeningPhaseV1)>,
}

impl OpeningMetricsV1 {
    /// Start an opening on this thread.
    #[must_use]
    pub fn start() -> Self {
        let started = OpeningClockV1::start();
        Self {
            started,
            clock: started,
            phases: Vec::new(),
        }
    }

    /// Record the time and work since the previous phase boundary as `phase`.
    pub fn lap(&mut self, phase: &'static str) {
        let value = self.clock.lap();
        self.record(phase, value);
    }

    /// Start the next phase now without recording the interval since the last boundary,
    /// for work whose own owner reports it (see [`Self::qualification`]).
    pub fn restart(&mut self) {
        self.clock = OpeningClockV1::start();
    }

    /// Record an already measured phase.
    pub fn record(&mut self, phase: &'static str, value: OpeningPhaseV1) {
        debug_assert!(
            !phase.is_empty()
                && phase
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        self.phases.push((phase, value));
    }

    /// Record a qualified owner's stage split in graph order.
    pub fn qualification(&mut self, stages: &QualificationMetricsV1) {
        for (phase, value) in [
            ("binding", stages.binding),
            ("sigma", stages.sigma),
            ("q", stages.q),
            ("routes", stages.routes),
            ("omega", stages.omega),
        ] {
            self.record(phase, value);
        }
    }

    /// Record `total`: everything since [`Self::start`], including unrecorded intervals.
    pub fn finish(&mut self) {
        let value = self.started.lap();
        self.record("total", value);
    }

    /// Recorded phases in order.
    #[must_use]
    pub fn phases(&self) -> &[(&'static str, OpeningPhaseV1)] {
        &self.phases
    }

    /// The first phase recorded under `name`.
    #[must_use]
    pub fn phase(&self, name: &str) -> Option<OpeningPhaseV1> {
        self.phases
            .iter()
            .find(|(phase, _)| *phase == name)
            .map(|(_, value)| *value)
    }

    /// One-line log record: fixed phase names, whole microseconds and counts only.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut output = format!("{{\"schema\":\"{OPENING_METRICS_SCHEMA_V1}\",\"phases\":[");
        for (index, (phase, value)) in self.phases.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let micros = u64::try_from(value.elapsed.as_micros()).unwrap_or(u64::MAX);
            let _ = write!(output, "{{\"phase\":\"{phase}\",\"micros\":{micros}");
            for (field, count) in value.work.fields() {
                let _ = write!(output, ",\"{field}\":{count}");
            }
            output.push('}');
        }
        output.push_str("]}");
        output
    }
}

#[cfg(test)]
#[path = "opening_metrics/tests.rs"]
mod tests;
