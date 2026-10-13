//! Same-State authorization for account-authenticated native repair chunk reads.

use crate::{
    query::{
        provider_admission::read_finalized_provider_admission_v1,
        signer_finality::verify_signer_finality_v1,
    },
    smartcontracts::ValidSingularQuery,
    state::{StateReadOnly, StateView, WorldReadOnly},
};
use iroha_data_model::{
    account::AccountId,
    permission::Permission,
    query::sorafs::prelude::FindSorafsRepairTask,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{ManifestDigest, PinStatus},
        repair_source::RepairSourceRequestV1,
    },
};
use iroha_executor_data_model::permission::sorafs::CanOperateSorafsRepair;
use mv::storage::StorageReadOnly;

/// Payload-free refusal of an invalid, stale, revoked or unauthorized repair source request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native repair source authorization rejected")]
pub struct RepairSourceAuthorizationErrorV1;

/// Authorize one chunk at a fresh durable State cut, before and after source I/O.
///
/// The caller must authenticate the canonical network request as `authority` independently.
/// The exact live lease, current worker permission, both provider admissions and approved pin
/// must remain valid. `now_unix_ms` comes from the local clock, never the request timestamp.
///
/// # Errors
/// Rejects unavailable finality, changed leases or permissions, revoked admission and expired pins.
pub fn authorize_repair_source_v1(
    view: &StateView<'_>,
    authority: &AccountId,
    request: &RepairSourceRequestV1,
    now_unix_ms: u64,
) -> Result<(), RepairSourceAuthorizationErrorV1> {
    let rejected = RepairSourceAuthorizationErrorV1;
    if now_unix_ms == 0 || !request.has_valid_shape() {
        return Err(rejected);
    }
    authorize_repair_lease_v1(
        view,
        authority,
        &RepairLeaseExpectedV1 {
            floor: request.floor,
            task_id: request.task_id,
            ticket_id: &request.ticket_id,
            manifest_digest: request.manifest_digest,
            target_provider: request.target_provider,
            task_revision: request.task_revision,
            lease_generation: request.lease_generation,
        },
        now_unix_ms,
    )?;
    read_finalized_provider_admission_v1(
        view,
        ProviderId::new(request.source_provider),
        now_unix_ms / 1000,
    )
    .map_err(|_| rejected)?
    .ok_or(rejected)?;
    Ok(())
}

/// Independently retained exact task and lease claims for bounded local or remote repair.
#[derive(Clone, Copy)]
pub struct RepairLeaseExpectedV1<'a> {
    /// Finalized native task cut retained before execution.
    pub floor: iroha_data_model::sorafs::moderation_ledger::RepairFinalizedCursorV1,
    /// Canonical task identity.
    pub task_id: [u8; 32],
    /// Canonical task ticket.
    pub ticket_id: &'a str,
    /// Manifest authorized by the task.
    pub manifest_digest: [u8; 32],
    /// Provider owning the affected replica.
    pub target_provider: [u8; 32],
    /// Exact task revision captured at admission.
    pub task_revision: u64,
    /// Exact exclusive lease generation captured at admission.
    pub lease_generation: u64,
}
/// Recheck current native authority before each replacement and before releasing quarantine.
/// Lease and pin expiry also respect the finalized block timestamp if the local clock lags.
///
/// # Errors
/// Refuses changed/expired leases, current permission or admission loss, unavailable finality,
/// foreign ancestry, and a pin that is no longer approved and retained.
pub fn authorize_repair_lease_v1(
    view: &StateView<'_>,
    authority: &AccountId,
    request: &RepairLeaseExpectedV1<'_>,
    now_unix_ms: u64,
) -> Result<(), RepairSourceAuthorizationErrorV1> {
    let rejected = RepairSourceAuthorizationErrorV1;
    if now_unix_ms == 0
        || request.ticket_id.len() > 128
        || request.ticket_id.is_empty()
        || request.floor.height == 0
        || request.task_revision == 0
        || request.lease_generation == 0
    {
        return Err(rejected);
    }
    let current_height = u64::try_from(view.height()).map_err(|_| rejected)?;
    let current_hash = view.latest_block_hash().ok_or(rejected)?;
    if request.floor.height > current_height {
        return Err(rejected);
    }
    verify_signer_finality_v1(view, current_height, *current_hash.as_ref())
        .map_err(|_| rejected)?;
    verify_signer_finality_v1(view, request.floor.height, request.floor.block_hash)
        .map_err(|_| rejected)?;
    // A lagging local clock cannot revive a lease or pin that has already expired
    // at the authenticated consensus head. Keep the local lower-bound check too.
    let finalized_unix_ms = view.authenticated_query_ledger_time_ms().ok_or(rejected)?;
    let latest_unix_ms = now_unix_ms.max(finalized_unix_ms);
    let task = FindSorafsRepairTask::new(request.ticket_id.to_owned(), None)
        .execute(view)
        .map_err(|_| rejected)?
        .task;
    let lease = task.lease.as_ref().ok_or(rejected)?;
    if (
        task.task_id,
        task.manifest_digest,
        task.provider_id,
        task.revision,
    ) != (
        request.task_id,
        request.manifest_digest,
        request.target_provider,
        request.task_revision,
    ) || task.terminal_outcome.is_some()
        || &lease.owner != authority
        || lease.generation != request.lease_generation
        || now_unix_ms < lease.acquired_at_unix_ms
        || latest_unix_ms >= lease.expires_at_unix_ms
    {
        return Err(rejected);
    }
    let world = view.world();
    let permission = Permission::from(CanOperateSorafsRepair {
        provider_id: ProviderId::new(request.target_provider),
    });
    if world.accounts().get(authority).is_none()
        || !(world.account_contains_inherent_permission(authority, &permission)
            || world
                .account_roles_iter(authority)
                .filter_map(|id| world.roles().get(id))
                .any(|role| role.permissions().any(|token| token == &permission)))
    {
        return Err(rejected);
    }
    read_finalized_provider_admission_v1(
        view,
        ProviderId::new(request.target_provider),
        now_unix_ms / 1000,
    )
    .map_err(|_| rejected)?
    .ok_or(rejected)?;
    let pin = world
        .pin_manifests()
        .get(&ManifestDigest::new(request.manifest_digest))
        .ok_or(rejected)?;
    if !matches!(pin.status, PinStatus::Approved(_))
        || pin.policy.retention_epoch <= latest_unix_ms / 1000
    {
        return Err(rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
