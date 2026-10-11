//! Explicit scalar observation of the unchanged original sixty-four-reservation native test.
//! No hook hashes, captures, allocates or prints without that test's installed guard. This
//! observer grants no custody, decoder admission, current authority or additional time.

use crate::managed::service_authority::profile_validation_test_support as profiles;
use iroha_crypto::Hash;
use iroha_data_model::NetworkId;
use std::{
    backtrace::Backtrace,
    cell::{Cell, RefCell},
    fmt::{self, Write as _},
    io::Write,
};

const MAX_KEYS: usize = 8;
const MAX_ERROR_TEXT_BYTES: usize = 1024;
const MAX_ERROR_CAUSES: usize = 8;

// Render directly into a fixed requested-capacity diagnostic buffer, never a full Report dump.
// Formatting refusal only ends observation; it cannot replace the original operation error.
#[derive(Debug)]
struct ErrorText {
    text: String,
    truncated: bool,
}
impl ErrorText {
    fn new() -> Self {
        Self {
            text: String::with_capacity(MAX_ERROR_TEXT_BYTES),
            truncated: false,
        }
    }
}
impl fmt::Write for ErrorText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut end = value.len().min(MAX_ERROR_TEXT_BYTES - self.text.len());
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&value[..end]);
        if end != value.len() {
            self.truncated = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}
struct RawError {
    seam: &'static str,
    class: &'static str,
    io: Option<(std::io::ErrorKind, Option<i32>)>,
    causes: usize,
    text: ErrorText,
    point: Refusal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum Phase {
    Setup,
    Successor,
    Replacements,
    FinalChecks,
}

/// Original helper call observed without retaining its native input or result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(in crate::managed) enum Stage {
    /// Original work outside the two fixture helper calls.
    Other,
    /// Original retained initial enrollment.
    RetainedInitial,
    /// Original GeneratedRenewalTurn::begin.
    Begin,
}

/// Sequential original begin work, without moving results into wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum BeginPhase {
    /// Original entry deadline/profile/policy checks.
    Entry,
    /// Original fresh Configure verification.
    Configure,
    /// Original complete renewal selection inventory.
    Inventory,
}

/// Original inventory point under the exact currently selected sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::managed) enum InventoryPhase {
    /// Original deadline before opening the sequence.
    Guard,
    /// Original fresh BodyHistory open.
    Open,
    /// Original initial prerequisite and renewal context.
    Context,
}

#[derive(Clone, Copy, Debug, Default)]
struct Snapshot {
    imports: u64,
    profiles: usize,
}
#[derive(Clone, Copy, Debug, Default)]
struct Totals {
    segments: u64,
    imports: u64,
    profiles: u64,
}

fn increment(value: &mut u64, amount: u64, anomaly: &mut bool) {
    if let Some(next) = value.checked_add(amount) {
        *value = next;
    } else {
        *anomaly = true;
    }
}
impl Totals {
    fn add(&mut self, start: Snapshot, end: Snapshot, anomaly: &mut bool) {
        increment(&mut self.segments, 1, anomaly);
        match end.imports.checked_sub(start.imports) {
            Some(delta) => increment(&mut self.imports, delta, anomaly),
            None => *anomaly = true,
        }
        match end
            .profiles
            .checked_sub(start.profiles)
            .and_then(|delta| u64::try_from(delta).ok())
        {
            Some(delta) => increment(&mut self.profiles, delta, anomaly),
            None => *anomaly = true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImportKey {
    network: [u8; 32],
    chain_hash: [u8; 32],
    byte_hash: [u8; 32],
    byte_len: usize,
}
#[derive(Clone, Copy, Debug)]
struct Miss {
    key: ImportKey,
    attempts: u64,
    by_phase: [u64; 4],
    by_stage: [u64; 3],
    first_actual_counter: usize,
    last_actual_counter: usize,
}
#[derive(Clone, Copy)]
struct Refusal {
    phase: Phase,
    replacement_iteration: u64,
    stage: Stage,
    begin_phase: Option<BeginPhase>,
    inventory: Option<(u64, InventoryPhase)>,
    totals: Snapshot,
    current_helper: Totals,
}
struct State {
    phase: Phase,
    replacement_iteration: u64,
    stage: Stage,
    begin_phase: Option<BeginPhase>,
    inventory: Option<(u64, InventoryPhase)>,
    imports: u64,
    misses: [Option<Miss>; MAX_KEYS],
    unretained_key_attempts: u64,
    phase_start: Snapshot,
    stage_start: Snapshot,
    phases: [Totals; 4],
    stages: [Totals; 3],
    counter_anomaly: bool,
    first_refusal: Option<Refusal>,
    first_raw_error: Option<RawError>,
    backtrace: Option<Backtrace>,
}
impl State {
    fn new() -> Self {
        Self {
            phase: Phase::Setup,
            replacement_iteration: 0,
            stage: Stage::Other,
            begin_phase: None,
            inventory: None,
            imports: 0,
            misses: [None; MAX_KEYS],
            unretained_key_attempts: 0,
            phase_start: Snapshot::default(),
            stage_start: Snapshot::default(),
            phases: [Totals::default(); 4],
            stages: [Totals::default(); 3],
            counter_anomaly: false,
            first_refusal: None,
            first_raw_error: None,
            backtrace: None,
        }
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            imports: self.imports,
            profiles: profiles::snapshot().unwrap_or(0),
        }
    }
    fn phase(&mut self, phase: Phase) {
        let end = self.snapshot();
        self.phases[self.phase as usize].add(self.phase_start, end, &mut self.counter_anomaly);
        self.phase = phase;
        self.phase_start = end;
        self.begin_phase = None;
        self.inventory = None;
    }
    fn miss(&mut self, key: ImportKey, actual_counter: usize) {
        increment(&mut self.imports, 1, &mut self.counter_anomaly);
        let slot = self
            .misses
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.key == key))
            .or_else(|| self.misses.iter().position(Option::is_none));
        let Some(slot) = slot else {
            increment(
                &mut self.unretained_key_attempts,
                1,
                &mut self.counter_anomaly,
            );
            return;
        };
        let entry = self.misses[slot].get_or_insert(Miss {
            key,
            attempts: 0,
            by_phase: [0; 4],
            by_stage: [0; 3],
            first_actual_counter: actual_counter,
            last_actual_counter: actual_counter,
        });
        increment(&mut entry.attempts, 1, &mut self.counter_anomaly);
        increment(
            &mut entry.by_phase[self.phase as usize],
            1,
            &mut self.counter_anomaly,
        );
        increment(
            &mut entry.by_stage[self.stage as usize],
            1,
            &mut self.counter_anomaly,
        );
        entry.last_actual_counter = actual_counter;
    }
    fn refuse(&mut self) -> bool {
        if self.first_refusal.is_some() {
            return false;
        }
        let totals = self.snapshot();
        let mut current_helper = Totals::default();
        current_helper.add(self.stage_start, totals, &mut self.counter_anomaly);
        self.first_refusal = Some(Refusal {
            phase: self.phase,
            replacement_iteration: self.replacement_iteration,
            stage: self.stage,
            begin_phase: self.begin_phase,
            inventory: self.inventory,
            totals,
            current_helper,
        });
        true
    }
    fn raw_error(
        &mut self,
        seam: &'static str,
        class: &'static str,
        io: Option<(std::io::ErrorKind, Option<i32>)>,
        causes: usize,
        text: ErrorText,
    ) {
        if self.first_raw_error.is_some() {
            return;
        }
        let totals = self.snapshot();
        let mut current_helper = Totals::default();
        current_helper.add(self.stage_start, totals, &mut self.counter_anomaly);
        self.first_raw_error = Some(RawError {
            seam,
            class,
            io,
            causes,
            text,
            point: Refusal {
                phase: self.phase,
                replacement_iteration: self.replacement_iteration,
                stage: self.stage,
                begin_phase: self.begin_phase,
                inventory: self.inventory,
                totals,
                current_helper,
            },
        });
    }
    fn dump(&self, output: &mut impl Write) -> std::io::Result<()> {
        writeln!(
            output,
            "closed64 diagnostic: cache_import_attempts={} original_profile_validations={:?} replacement_iterations_entered={} counter_anomaly={} unretained_key_attempts={}",
            self.imports,
            profiles::snapshot(),
            self.replacement_iteration,
            self.counter_anomaly,
            self.unretained_key_attempts
        )?;
        writeln!(
            output,
            "closed64 phase totals [Setup, Successor, Replacements, FinalChecks]: {:?}",
            self.phases
        )?;
        writeln!(
            output,
            "closed64 helper span totals [RetainedInitial, Begin]: {:?}",
            [
                self.stages[Stage::RetainedInitial as usize],
                self.stages[Stage::Begin as usize]
            ]
        )?;
        for (index, entry) in self.misses.iter().enumerate() {
            if let Some(entry) = entry {
                writeln!(output, "closed64 exact byte key {index}: {entry:?}")?;
            }
        }
        if let Some(r) = self.first_refusal {
            writeln!(
                output,
                "closed64 FIRST true NativeDeadline: phase={:?} replacement_iteration={} helper={:?} begin={:?} inventory={:?} total_counts={:?} current_helper_counts={:?}",
                r.phase,
                r.replacement_iteration,
                r.stage,
                r.begin_phase,
                r.inventory,
                r.totals,
                r.current_helper
            )?;
        }
        if let Some(error) = &self.first_raw_error {
            let point = error.point;
            writeln!(
                output,
                "closed64 FIRST raw error before mapping: seam={} class={} native_io={:?} causes={} truncated={} phase={:?} replacement_iteration={} helper={:?} begin={:?} inventory={:?} total_counts={:?} current_helper_counts={:?} text={:?}",
                error.seam,
                error.class,
                error.io,
                error.causes,
                error.text.truncated,
                point.phase,
                point.replacement_iteration,
                point.stage,
                point.begin_phase,
                point.inventory,
                point.totals,
                point.current_helper,
                error.text.text,
            )?;
        }
        if let Some(backtrace) = &self.backtrace {
            writeln!(
                output,
                "closed64 actual first refusal call chain:\n{backtrace}"
            )?;
        }
        Ok(())
    }
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// Read the scalar activation flag without initializing the diagnostic state or doing work.
pub(in crate::managed) fn active() -> bool {
    ACTIVE.with(Cell::get)
}
fn observe(action: impl FnOnce(&mut State)) {
    if !active() {
        return;
    }
    STATE.with(|slot| {
        if let Ok(mut selected) = slot.try_borrow_mut()
            && let Some(state) = selected.as_mut()
        {
            action(state);
        }
    });
}

/// Observe a typed failure immediately before the original retained-material conversion.
/// No owner, result or clock is retained; inactive/busy/previously observed calls do no rendering.
pub(in crate::managed) fn retained_error(error: &crate::managed::Error) {
    observe(|state| {
        if state.first_raw_error.is_some() {
            return;
        }
        use crate::managed::Error;
        let (class, io) = match error {
            Error::Io(error) => ("Io", Some((error.kind(), error.raw_os_error()))),
            Error::Invalid(_) => ("Invalid", None),
            Error::Bootstrap(_) => ("Bootstrap", None),
            Error::NativeDeadline => ("NativeDeadline", None),
            Error::NoSelection => ("NoSelection", None),
            Error::ContractCall { .. } => ("ContractCall", None),
            Error::Busy(_) => ("Busy", None),
            Error::Timeout(_) => ("Timeout", None),
            Error::WorkerFailure { .. } => ("WorkerFailure", None),
            Error::ParentDeadline => ("ParentDeadline", None),
            Error::ParentProgressDeadline { .. } => ("ParentProgressDeadline", None),
        };
        let mut text = ErrorText::new();
        let _ = write!(&mut text, "{error}");
        state.raw_error("retained material conversion", class, io, 1, text);
    });
}

/// Observe the original wallet cause before its existing fixed-label conversion.
/// Rendering is capped at 1024 UTF-8 bytes and eight causes; only the first active failure survives.
pub(in crate::managed) fn wallet_error(seam: &'static str, error: &color_eyre::eyre::Report) {
    observe(|state| {
        if state.first_raw_error.is_some() {
            return;
        }
        let mut text = ErrorText::new();
        let mut io = None;
        let mut causes = 0;
        for (index, cause) in error.chain().take(MAX_ERROR_CAUSES + 1).enumerate() {
            if index == MAX_ERROR_CAUSES {
                text.truncated = true;
                break;
            }
            causes += 1;
            if io.is_none()
                && let Some(error) = cause.downcast_ref::<std::io::Error>()
            {
                io = Some((error.kind(), error.raw_os_error()));
            }
            if !text.truncated {
                let separator = if index == 0 { "" } else { "\ncaused by: " };
                let _ = write!(&mut text, "{separator}{cause}");
            }
        }
        state.raw_error(seam, "Wallet", io, causes, text);
    });
}

/// Explicit RAII activation installed only by the original64 native control.
pub(in crate::managed) struct Observer {
    profiles: Option<profiles::Counter>,
}
impl Observer {
    /// Install bounded observation; nested or busy activation simply declines.
    pub(in crate::managed) fn begin() -> Self {
        let installed = STATE.with(|slot| {
            if let Ok(mut selected) = slot.try_borrow_mut()
                && selected.is_none()
            {
                *selected = Some(State::new());
                true
            } else {
                false
            }
        });
        let profiles = installed.then(profiles::Counter::begin);
        if installed {
            ACTIVE.with(|value| value.set(true));
        }
        Self { profiles }
    }
    /// Label existing first successor work without observing another native state.
    pub(in crate::managed) fn successor(&self) {
        if self.profiles.is_some() {
            observe(|state| state.phase(Phase::Successor));
        }
    }
    /// Record entry to one original replacement iteration with checked wide arithmetic.
    pub(in crate::managed) fn replacement(&self) {
        if self.profiles.is_some() {
            observe(|state| {
                if state.phase != Phase::Replacements {
                    state.phase(Phase::Replacements);
                }
                increment(
                    &mut state.replacement_iteration,
                    1,
                    &mut state.counter_anomaly,
                );
            });
        }
    }
    /// Label the existing final cumulative-limit and unchanged-source controls.
    pub(in crate::managed) fn final_checks(&self) {
        if self.profiles.is_some() {
            observe(|state| state.phase(Phase::FinalChecks));
        }
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        if self.profiles.is_none() {
            return;
        }
        ACTIVE.with(|value| value.set(false));
        STATE.with(|slot| {
            if let Ok(mut selected) = slot.try_borrow_mut() {
                if let Some(state) = selected.as_mut() {
                    let end = state.snapshot();
                    state.phases[state.phase as usize].add(
                        state.phase_start,
                        end,
                        &mut state.counter_anomaly,
                    );
                    // Output failure cannot replace original native refusal or test panic.
                    let _ = state.dump(&mut std::io::stderr().lock());
                }
                *selected = None;
            }
        });
        // Ordinary field Drop restores the previous existing profile counter after printing.
    }
}

/// Scalar helper span; no input, result, descriptor, decoder or clock is retained.
pub(in crate::managed) struct StageGuard {
    previous: Option<(
        Stage,
        Snapshot,
        Option<BeginPhase>,
        Option<(u64, InventoryPhase)>,
    )>,
}
impl StageGuard {
    /// Mark existing helper entry and retain only its enclosing scalar labels.
    pub(in crate::managed) fn enter(stage: Stage) -> Self {
        let mut previous = None;
        observe(|state| {
            previous = Some((
                state.stage,
                state.stage_start,
                state.begin_phase,
                state.inventory,
            ));
            state.stage = stage;
            state.stage_start = state.snapshot();
            state.begin_phase = None;
            state.inventory = None;
        });
        Self { previous }
    }
    /// Close one scalar span and label the next original helper call.
    pub(in crate::managed) fn change(&mut self, stage: Stage) {
        if self.previous.is_some() {
            observe(|state| {
                let end = state.snapshot();
                state.stages[state.stage as usize].add(
                    state.stage_start,
                    end,
                    &mut state.counter_anomaly,
                );
                state.stage = stage;
                state.stage_start = end;
                state.begin_phase = None;
                state.inventory = None;
            });
        }
    }
}
impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some((stage, start, begin, inventory)) = self.previous {
            observe(|state| {
                let end = state.snapshot();
                state.stages[state.stage as usize].add(
                    state.stage_start,
                    end,
                    &mut state.counter_anomaly,
                );
                state.stage = stage;
                state.stage_start = start;
                state.begin_phase = begin;
                state.inventory = inventory;
            });
        }
    }
}

/// Record original begin phase only when observation was explicitly installed.
pub(in crate::managed) fn begin_phase(phase: BeginPhase) {
    observe(|state| {
        state.begin_phase = Some(phase);
        state.inventory = None;
    });
}
/// Record original inventory sequence and point without changing its census.
pub(in crate::managed) fn inventory(sequence: u64, phase: InventoryPhase) {
    observe(|state| state.inventory = Some((sequence, phase)));
}
/// Observe existing cold-import counter point; no input bytes or decoder graph are retained.
pub(in crate::managed) fn import_attempt(
    bytes: &[u8],
    network: NetworkId,
    chain: &str,
    actual_counter: usize,
) {
    observe(|state| {
        // Hashing stays inside the active branch: other tests do no added hash work.
        state.miss(
            ImportKey {
                network: *network.as_bytes(),
                chain_hash: *Hash::new(chain.as_bytes()).as_ref(),
                byte_hash: *Hash::new(bytes).as_ref(),
                byte_len: bytes.len(),
            },
            actual_counter,
        );
    });
}
/// Called only AFTER original real-clock predicate has selected NativeDeadline.
pub(in crate::managed) fn deadline_refused() {
    observe(|state| {
        if state.refuse() {
            // Once, after actual refusal; no added pre-predicate clock observation.
            state.backtrace = Some(Backtrace::force_capture());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(value: u8) -> ImportKey {
        ImportKey {
            network: [1; 32],
            chain_hash: *Hash::new(b"diagnostic chain").as_ref(),
            byte_hash: *Hash::new([value]).as_ref(),
            byte_len: 1,
        }
    }
    #[test]
    fn exact_hash_keys_bound_observation_and_count_overflow_without_refusing_work() {
        let mut state = State::new();
        for value in 0..MAX_KEYS {
            state.miss(key(u8::try_from(value).unwrap()), value + 1);
        }
        state.phase = Phase::Replacements;
        state.stage = Stage::Begin;
        state.miss(key(0), 9);
        state.miss(key(8), 10);
        assert_eq!(state.imports, 10);
        assert_eq!(state.misses.iter().flatten().count(), MAX_KEYS);
        assert_eq!(state.unretained_key_attempts, 1);
        let first = state.misses[0].unwrap();
        assert_eq!(first.key, key(0));
        assert_eq!(first.attempts, 2);
        assert_eq!(first.first_actual_counter, 1);
        assert_eq!(first.last_actual_counter, 9);
        assert_eq!(first.by_phase, [1, 0, 1, 0]);
        assert_eq!(first.by_stage, [1, 0, 1]);
        assert!(!state.counter_anomaly);
        assert!(state.backtrace.is_none());
    }
    #[test]
    fn first_refusal_keeps_original_iteration_stage_and_counter_deltas() {
        let mut state = State::new();
        state.phase = Phase::Replacements;
        state.replacement_iteration = 11;
        state.stage = Stage::Begin;
        state.begin_phase = Some(BeginPhase::Inventory);
        state.inventory = Some((2, InventoryPhase::Context));
        state.stage_start.imports = 3;
        for actual in 1..=4 {
            state.miss(key(0), actual);
        }
        assert!(state.refuse());
        let original = state.first_refusal.unwrap();
        assert_eq!(original.phase, Phase::Replacements);
        assert_eq!(original.replacement_iteration, 11);
        assert_eq!(original.stage, Stage::Begin);
        assert_eq!(original.begin_phase, Some(BeginPhase::Inventory));
        assert_eq!(original.inventory, Some((2, InventoryPhase::Context)));
        assert_eq!(original.totals.imports, 4);
        assert_eq!(original.current_helper.imports, 1);
        state.phase = Phase::FinalChecks;
        state.inventory = Some((64, InventoryPhase::Guard));
        state.miss(key(1), 5);
        assert!(!state.refuse());
        assert_eq!(state.first_refusal.unwrap().replacement_iteration, 11);
        assert_eq!(state.first_refusal.unwrap().totals.imports, 4);
        // Pure observer controls do not install a diagnostic or fabricate a native refusal.
        assert!(state.backtrace.is_none());
    }
    #[test]
    fn wide_counter_exhaustion_marks_observation_incomplete_without_panicking() {
        let mut state = State::new();
        state.imports = u64::MAX;
        state.miss(key(0), 1);
        assert_eq!(state.imports, u64::MAX);
        assert!(state.counter_anomaly);
        let mut totals = Totals {
            segments: u64::MAX,
            imports: u64::MAX,
            profiles: u64::MAX,
        };
        let mut anomaly = false;
        totals.add(
            Snapshot::default(),
            Snapshot {
                imports: 1,
                profiles: 1,
            },
            &mut anomaly,
        );
        assert!(anomaly);
        assert_eq!(totals.segments, u64::MAX);
        assert_eq!(totals.imports, u64::MAX);
        assert_eq!(totals.profiles, u64::MAX);
    }
    #[test]
    fn absent_observer_preserves_original_typed_refusal_and_positive_budget() {
        use std::time::{Duration, Instant};
        assert!(!active());
        STATE.with(|state| assert!(state.borrow().is_none()));
        let mut stage = StageGuard::enter(Stage::RetainedInitial);
        stage.change(Stage::Begin);
        begin_phase(BeginPhase::Inventory);
        inventory(2, InventoryPhase::Guard);
        assert!(matches!(
            super::super::require_deadline(Instant::now()),
            Err(crate::managed::Error::NativeDeadline)
        ));
        super::super::require_deadline(Instant::now() + Duration::from_secs(60)).unwrap();
        STATE.with(|state| assert!(state.borrow().is_none()));
        assert_eq!(profiles::snapshot(), None);
        assert!(!active());
    }

    #[derive(Debug)]
    struct CountedError(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl fmt::Display for CountedError {
        fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            output.write_str("counted original cause")
        }
    }
    impl std::error::Error for CountedError {}

    #[test]
    fn inactive_raw_error_hooks_keep_state_absent_and_original_mapping() {
        use crate::managed::{Error, ManagedBootstrapFailure};
        assert!(!active());
        let displays = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let report = color_eyre::eyre::Report::new(CountedError(displays.clone()));
        let before = displays.load(std::sync::atomic::Ordering::Relaxed);
        wallet_error("wallet preparation inspection", &report);
        assert_eq!(displays.load(std::sync::atomic::Ordering::Relaxed), before);
        let mapped = super::super::require_retained_material::<()>(Err(Error::Invalid(
            "bad material".into(),
        )));
        assert!(matches!(
            mapped,
            Err(Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial))
        ));
        assert!(matches!(
            super::super::require_retained_material::<()>(Err(Error::NativeDeadline)),
            Err(Error::NativeDeadline)
        ));
        STATE.with(|slot| assert!(slot.borrow().is_none()));
        assert!(!active());
    }

    #[test]
    fn active_raw_error_keeps_first_native_class_phase_and_original_results() {
        use crate::managed::{Error, ManagedBootstrapFailure};
        let observer = Observer::begin();
        observer.replacement();
        let _stage = StageGuard::enter(Stage::Begin);
        begin_phase(BeginPhase::Inventory);
        inventory(2, InventoryPhase::Open);
        assert_eq!(
            super::super::require_retained_material(Ok(17_u32)).unwrap(),
            17
        );
        assert!(matches!(
            super::super::require_retained_material::<()>(Err(Error::NativeDeadline)),
            Err(Error::NativeDeadline)
        ));
        assert!(matches!(
            super::super::require_retained_material::<()>(Err(Error::Bootstrap(
                ManagedBootstrapFailure::TransitionPending
            ))),
            Err(Error::Bootstrap(ManagedBootstrapFailure::TransitionPending))
        ));
        STATE.with(|slot| assert!(slot.borrow().as_ref().unwrap().first_raw_error.is_none()));
        let native = std::io::Error::from_raw_os_error(24);
        let kind = native.kind();
        let mapped = super::super::require_retained_material::<()>(Err(Error::Io(native)));
        assert!(matches!(
            mapped,
            Err(Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial))
        ));
        inventory(64, InventoryPhase::Context);
        let later = super::super::require_retained_material::<()>(Err(Error::Invalid(
            "later error".into(),
        )));
        assert!(matches!(
            later,
            Err(Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial))
        ));
        STATE.with(|slot| {
            let state = slot.borrow();
            let error = state.as_ref().unwrap().first_raw_error.as_ref().unwrap();
            assert_eq!(error.seam, "retained material conversion");
            assert_eq!(error.class, "Io");
            assert_eq!(error.io, Some((kind, Some(24))));
            assert_eq!(error.point.phase, Phase::Replacements);
            assert_eq!(error.point.replacement_iteration, 1);
            assert_eq!(error.point.stage, Stage::Begin);
            assert_eq!(error.point.begin_phase, Some(BeginPhase::Inventory));
            assert_eq!(error.point.inventory, Some((2, InventoryPhase::Open)));
            assert!(error.text.text.len() <= MAX_ERROR_TEXT_BYTES);
            assert!(!error.text.truncated);
            let mut output = Vec::new();
            state.as_ref().unwrap().dump(&mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(
                "FIRST raw error before mapping: seam=retained material conversion class=Io"
            ));
            assert!(output.contains("Some(24)"));
        });
    }

    #[test]
    fn wallet_raw_error_bounds_unicode_chain_and_wins_over_outer_conversion() {
        use crate::managed::{Error, ManagedBootstrapFailure};
        let _observer = Observer::begin();
        let native = std::io::Error::from_raw_os_error(24);
        let kind = native.kind();
        let report = color_eyre::eyre::Report::from(native)
            .wrap_err("a".to_owned() + &"α".repeat(MAX_ERROR_TEXT_BYTES));
        wallet_error("wallet preparation inspection", &report);
        let mapped = super::super::require_retained_material::<()>(Err(Error::Invalid(
            "custody wallet preparation differs from original request".into(),
        )));
        assert!(matches!(
            mapped,
            Err(Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial))
        ));
        let displays = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later = color_eyre::eyre::Report::new(CountedError(displays.clone()));
        let before = displays.load(std::sync::atomic::Ordering::Relaxed);
        wallet_error("wallet signed journal verification", &later);
        assert_eq!(displays.load(std::sync::atomic::Ordering::Relaxed), before);
        STATE.with(|slot| {
            let state = slot.borrow();
            let error = state.as_ref().unwrap().first_raw_error.as_ref().unwrap();
            assert_eq!(error.seam, "wallet preparation inspection");
            assert_eq!(error.class, "Wallet");
            assert_eq!(error.io, Some((kind, Some(24))));
            assert_eq!(error.causes, 2);
            assert!(error.text.truncated);
            assert_eq!(error.text.text.len(), MAX_ERROR_TEXT_BYTES - 1);
            assert!(error.text.text.starts_with('a'));
            assert!(error.text.text.chars().skip(1).all(|value| value == 'α'));
        });
    }

    #[test]
    fn wallet_raw_error_bounds_cause_count_and_busy_observation_never_changes_result() {
        use crate::managed::{Error, ManagedBootstrapFailure};
        let _observer = Observer::begin();
        STATE.with(|slot| {
            let _held = slot.borrow_mut();
            let mapped = super::super::require_retained_material::<()>(Err(Error::Invalid(
                "busy observation".into(),
            )));
            assert!(matches!(
                mapped,
                Err(Error::Bootstrap(ManagedBootstrapFailure::RetainedMaterial))
            ));
        });
        STATE.with(|slot| assert!(slot.borrow().as_ref().unwrap().first_raw_error.is_none()));
        let mut report = color_eyre::eyre::eyre!("terminal cause");
        for _ in 0..MAX_ERROR_CAUSES + 2 {
            report = report.wrap_err("outer cause");
        }
        wallet_error("wallet signed journal verification", &report);
        STATE.with(|slot| {
            let state = slot.borrow();
            let error = state.as_ref().unwrap().first_raw_error.as_ref().unwrap();
            assert_eq!(error.seam, "wallet signed journal verification");
            assert_eq!(error.causes, MAX_ERROR_CAUSES);
            assert!(error.text.truncated);
            assert!(error.text.text.len() <= MAX_ERROR_TEXT_BYTES);
        });
    }
}
