//! Data availability ingest handlers and persistence helpers for Torii.
pub mod commitments;
#[cfg(feature = "app_api")]
mod ingest;
mod persistence;
pub mod pin_intents;
#[cfg(any(feature = "app_api", test))]
mod rs16;
mod spool;
#[cfg(feature = "app_api")]
mod taikai;
#[cfg(feature = "app_api")]
pub use ingest::{handler_get_da_manifest, handler_post_da_ingest};
use iroha_core::state::{StateReadOnly, WorldReadOnly};
use iroha_data_model::{
    account::AccountId, da::ingest::DaIngestAdmissionPolicyV1, sorafs::pin_registry::StorageClass,
};
use iroha_model_base::topology::LaneId;
pub use persistence::{DaReceiptLog, ReceiptInsertOutcome, ReplayCursorStore};
pub use spool::{DaSpoolAction, DaSpoolActionOutput, DaSpoolBatch, DaSpoolBatchReport, DaSpooler};
use std::collections::BTreeMap;
#[cfg(feature = "app_api")]
pub use taikai::spawn_anchor_worker;
#[cfg(feature = "app_api")]
pub use taikai::taikai_ingest::recover_pending_lineages as recover_pending_taikai_lineages;

/// One generation-stable view of committed DA admission policy and lane incarnations.
#[derive(Clone, Debug)]
pub struct DaIngestAdmissionSnapshot {
    policy: Option<DaIngestAdmissionPolicyV1>,
    active_incarnations: BTreeMap<LaneId, iroha_crypto::Hash>,
}
impl DaIngestAdmissionSnapshot {
    /// Return whether the snapshot authorizes an exact producer scope.
    #[must_use]
    pub(crate) fn authorizes(&self, owner: &AccountId, lane_id: LaneId, epoch: u64) -> bool {
        let Some(policy) = self.policy.as_ref() else {
            return false;
        };
        let Some(incarnation) = self.active_incarnations.get(&lane_id).copied() else {
            return false;
        };
        policy.authorizes(owner, lane_id, incarnation, epoch)
    }

    /// Return whether the snapshot retains an exact active replay window.
    #[must_use]
    pub(crate) fn retains(&self, lane_id: LaneId, epoch: u64) -> bool {
        let Some(policy) = self.policy.as_ref() else {
            return false;
        };
        let Some(lane) = policy.lane(lane_id) else {
            return false;
        };
        self.active_incarnations.get(&lane_id) == Some(&lane.lane_incarnation)
            && lane.admits_epoch(epoch)
    }

    /// Return whether the committed policy is present.
    #[must_use]
    pub(crate) const fn is_configured(&self) -> bool {
        self.policy.is_some()
    }
}

/// Capture the committed DA admission policy and active incarnations from one state view.
///
/// # Errors
///
/// Returns an error when the reserved policy payload is malformed. Absence is
/// represented explicitly and makes DA ingest fail closed without destroying
/// pre-upgrade replay evidence during startup.
pub fn committed_da_ingest_admission_snapshot(
    state: &iroha_core::state::State,
) -> Result<DaIngestAdmissionSnapshot, String> {
    let view = state.view();
    let committed_height = u64::try_from(view.height())
        .map_err(|_| "committed state height does not fit the DA admission height domain")?;
    let proposal_height = committed_height
        .checked_add(1)
        .ok_or_else(|| "DA admission proposal height overflowed".to_owned())?;
    let policy = view
        .world()
        .parameters()
        .custom()
        .get(&DaIngestAdmissionPolicyV1::parameter_id())
        .map(|custom| {
            DaIngestAdmissionPolicyV1::from_custom_parameter(custom)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "reserved DA admission parameter changed identity".to_owned())
        })
        .transpose()?;
    let active_incarnations = policy
        .as_ref()
        .map(|policy| {
            policy
                .lanes
                .iter()
                .filter_map(|lane| {
                    view.lane_incarnation_at_height(lane.lane_id, proposal_height)
                        .map(|incarnation| (lane.lane_id, incarnation))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(DaIngestAdmissionSnapshot {
        policy,
        active_incarnations,
    })
}
fn storage_class_label(class: StorageClass) -> &'static str {
    match class {
        StorageClass::Hot => "hot",
        StorageClass::Warm => "warm",
        StorageClass::Cold => "cold",
    }
}
