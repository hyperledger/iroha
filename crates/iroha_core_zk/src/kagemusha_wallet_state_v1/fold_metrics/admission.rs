//! Bounded observations of existing capacity checks; never an admission authority.
use crate::kagemusha_wallet_capacity_v1::{
    KagemushaWalletRuntimeCapacityV1 as Capacity, KagemushaWalletRuntimeResourcesV1 as Resources,
};
use std::cell::Cell;

/// Maximum exact admission observations retained for one Native work row.
pub const NATIVE_ADMISSION_RECORDS_V1: usize = 8;

/// Existing capacity-check boundary. These labels never select a policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAdmissionPhaseV1 {
    /// Fresh operation before proving.
    BeforeProve,
    /// Fresh transition before committing.
    BeforeCommit,
    /// Throwaway Send proof preparation.
    Speculation,
    /// Intake storage and memory workspace admission.
    Intake,
    /// Existing intake recovery memory admission.
    IntakeMemory,
    /// Blacklist publication storage admission.
    Blacklist,
}
impl NativeAdmissionPhaseV1 {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::BeforeProve => "before_prove",
            Self::BeforeCommit => "before_commit",
            Self::Speculation => "speculation",
            Self::Intake => "intake",
            Self::IntakeMemory => "intake_memory",
            Self::Blacklist => "blacklist",
        }
    }
}

/// Result already selected by the original check or resource probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAdmissionResultV1 {
    /// Existing check passed, including its existing unknown-memory behavior.
    Passed,
    /// Existing storage check refused.
    StorageShortfall,
    /// Existing memory check refused.
    MemoryShortfall,
    /// Existing resource probe failed; no available values were obtained.
    ProbeFailed,
}
impl NativeAdmissionResultV1 {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::StorageShortfall => "storage_shortfall",
            Self::MemoryShortfall => "memory_shortfall",
            Self::ProbeFailed => "probe_failed",
        }
    }
}

/// One public resource observation; no reservation, allocation or financial authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAdmissionV1 {
    /// The existing call site.
    pub phase: NativeAdmissionPhaseV1,
    /// Analytic requirements already used by that call.
    pub required: Capacity,
    /// Original probe result, absent only when the probe failed.
    pub available: Option<Resources>,
    /// Original result, never recomputed from diagnostics.
    pub result: NativeAdmissionResultV1,
}

/// Last eight checks of one work interval, with an exact cumulative interval count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeAdmissionsV1 {
    /// All checks in the interval, including overwritten details.
    pub count: u64,
    /// Retained checks in oldest-first order, followed by empty slots.
    pub records: [Option<NativeAdmissionV1>; NATIVE_ADMISSION_RECORDS_V1],
}
#[derive(Clone, Copy)]
struct History {
    count: u64,
    records: [Option<NativeAdmissionV1>; NATIVE_ADMISSION_RECORDS_V1],
}
thread_local! {
    static HISTORY: Cell<History> = const { Cell::new(History {
        count: 0, records: [None; NATIVE_ADMISSION_RECORDS_V1],
    }) };
}

pub(super) fn count() -> u64 {
    HISTORY.try_with(|cell| cell.get().count).unwrap_or(0)
}
pub(in crate::kagemusha_wallet_state_v1) fn record(value: NativeAdmissionV1) {
    let _ = HISTORY.try_with(|cell| {
        let mut history = cell.get();
        history.records.rotate_left(1);
        history.records[NATIVE_ADMISSION_RECORDS_V1 - 1] = Some(value);
        history.count = history.count.saturating_add(1);
        cell.set(history);
    });
}
pub(super) fn since(before: u64) -> NativeAdmissionsV1 {
    HISTORY
        .try_with(|cell| {
            let history = cell.get();
            let count = history.count.saturating_sub(before);
            let kept = usize::try_from(count.min(NATIVE_ADMISSION_RECORDS_V1 as u64)).unwrap_or(0);
            let mut records = [None; NATIVE_ADMISSION_RECORDS_V1];
            records[..kept].copy_from_slice(&history.records[NATIVE_ADMISSION_RECORDS_V1 - kept..]);
            NativeAdmissionsV1 { count, records }
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_history_is_bounded_thread_local_and_preserves_unknown_memory() {
        let before = count();
        let value = NativeAdmissionV1 {
            phase: NativeAdmissionPhaseV1::BeforeProve,
            required: Capacity {
                storage_bytes: 1,
                memory_bytes: 2,
            },
            available: Some(Resources {
                storage_bytes: 3,
                memory_bytes: None,
            }),
            result: NativeAdmissionResultV1::Passed,
        };
        std::thread::spawn(move || record(value)).join().unwrap();
        assert_eq!(since(before), NativeAdmissionsV1::default());
        for _ in 0..11 {
            record(value);
        }
        let retained = since(before);
        assert_eq!(retained.count, 11);
        assert_eq!(retained.records, [Some(value); NATIVE_ADMISSION_RECORDS_V1]);
        assert_eq!(since(count()), NativeAdmissionsV1::default());
    }
}
