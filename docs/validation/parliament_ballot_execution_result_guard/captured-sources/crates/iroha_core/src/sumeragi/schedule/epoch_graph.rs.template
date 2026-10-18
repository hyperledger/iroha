//! Runtime-only custody over the shared canonical epoch graph.

pub use iroha_data_model::sumeragi_finality::{
    ConsensusSchedule, ScheduleOutcome, ScheduledConfig, ScheduledSlot, core_epoch,
};

/// The exact verified schedule and beacon fields carried by one original execution.
/// Production returns this only inside the move-only original-pool `RetainedPayload`.
/// The result commitment consumes both fields by allocation-preserving moves.
pub(crate) struct NativeExecutionInputs {
    /// Full incumbent and successor authority effects.
    pub(crate) schedule: ScheduleOutcome,
    /// Complete authenticated pulse supplied to this same original overlay, if demanded.
    pub(crate) beacon: Option<iroha_data_model::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
}
