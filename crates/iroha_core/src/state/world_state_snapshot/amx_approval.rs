//! Borrowed exact AMX debit consent from one original certified participant World cut.

use super::*;
use iroha_data_model::{
    permission::Permissions,
    sumeragi_amx::{
        AmxDebitApprovalV1,
        approval_proof::{
            MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1, MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1,
        },
    },
};

impl State {
    /// Publish the exact relay permission under the selected participant's complete World root.
    ///
    /// The callback borrows originals from the same certified pre-tail cut and must fund any
    /// retained output from its original pool. It cannot authorize current or future execution.
    /// No broad ledger permission, role or caller-supplied predicate substitutes for the grant.
    /// # Errors
    /// Wrong root or instance, absent selected entities/direct grant, changed certified cut,
    /// missing capture, tail-modified originals, malformed input or finite resource refusal.
    pub fn with_native_amx_debit_approval_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        approval: &AmxDebitApprovalV1,
        relay: &AccountId,
        budget: &AllocationBudget,
        consume: impl FnOnce(&WorldStateSnapshotV1, &Permissions) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        let instance = tip
            .header()
            .ok_or("AMX debit approval requires a certified successor")?
            .instance
            .0;
        approval
            .validate_root(
                tip.commitment().schedule.current.network_id,
                tip.root_scope(),
                instance,
            )
            .map_err(|error| error.to_string())?;
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let permissions = amx_approval_originals(snapshot, world, approval, relay, budget)?;
            consume(snapshot, permissions)
        })
    }
}

fn amx_approval_originals<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    approval: &AmxDebitApprovalV1,
    relay: &AccountId,
    budget: &AllocationBudget,
) -> Result<&'a Permissions, String> {
    if crate::sumeragi::lanes::routing::committed_root_scope(world)
        != Some(
            iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                parent_network_id: approval.global_network,
                dataspace_id: approval.dataspace,
            },
        )
        || norito::canonical_frame_len(approval).map_err(|error| error.to_string())?
            > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
        || norito::canonical_frame_len(relay).map_err(|error| error.to_string())?
            > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
    {
        return Err("AMX debit approval differs from the selected root or finite bounds".into());
    }
    for id in [relay, approval.debited_asset.account()] {
        let account = world
            .accounts()
            .get(id)
            .ok_or("AMX debit approval account is absent")?;
        require_target(
            snapshot,
            "world.accounts",
            WorldStateElementKindV1::Table,
            Some(hash_value(id)?),
            hash_value(account)?,
        )?;
    }
    let definition = approval.debited_asset.definition();
    let asset = world
        .asset_definitions()
        .get(definition)
        .ok_or("AMX debit approval asset definition is absent")?;
    require_target(
        snapshot,
        "world.asset_definitions",
        WorldStateElementKindV1::Table,
        Some(hash_value(definition)?),
        hash_value(asset)?,
    )?;
    let permissions = world
        .account_permissions()
        .get(relay)
        .ok_or("AMX debit approval direct grant is absent")?;
    if permissions.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1
        || norito::canonical_frame_len(permissions).map_err(|error| error.to_string())?
            > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1
    {
        return Err("AMX debit approval direct permissions exceed their bound".into());
    }
    // The original pool funds the exact checked account writer's sole scratch
    // allocation. Comparisons run serially, so one live scratch suffices; the
    // owned decoder counter admits their checked cumulative work independently.
    // Neither a replacement permission nor a parsed JSON graph is constructed.
    let scratch_bytes = approval
        .permission_match_scratch_bytes()
        .map_err(|error| error.to_string())?;
    let cumulative_bytes = scratch_bytes
        .checked_mul(permissions.len())
        .ok_or("AMX debit approval comparison geometry overflow")?;
    let _scratch = budget
        .try_reserve_bytes(scratch_bytes)
        .map_err(|error| error.to_string())?;
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1,
            MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1,
            MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1,
            cumulative_bytes,
            64,
        ),
        budget,
    )
    .map_err(|error| error.to_string())?;
    let mut matched = false;
    for permission in permissions {
        if context
            .with(|| approval.matches_permission(permission))
            .map_err(|error| error.to_string())?
        {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err("AMX debit approval requires exact direct CanPrepareAmx".into());
    }
    require_target(
        snapshot,
        "world.account_permissions",
        WorldStateElementKindV1::Table,
        Some(hash_value(relay)?),
        hash_value(permissions)?,
    )?;
    Ok(permissions)
}
