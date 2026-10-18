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
        consume: impl FnOnce(&WorldStateSnapshotV1, &Permissions) -> Result<T, WorldStateSnapshotError>,
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
            .map_err(WorldStateSnapshotError::Amx)?;
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
) -> Result<&'a Permissions, WorldStateSnapshotError> {
    if crate::sumeragi::lanes::routing::read_routing_root_scope(world)
        .map_err(WorldStateSnapshotError::RootScopeRead)?
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
    require_exact_amx_permission(approval, permissions, budget)?;
    require_target(
        snapshot,
        "world.account_permissions",
        WorldStateElementKindV1::Table,
        Some(hash_value(relay)?),
        hash_value(permissions)?,
    )?;
    Ok(permissions)
}

// The original checked comparator has its own refusal boundary after source selection.
// Keeping this owner named lets controls reach it without bypassing or guessing the
// earlier root metadata reader's cumulative decoder allocations.
fn require_exact_amx_permission(
    approval: &AmxDebitApprovalV1,
    permissions: &Permissions,
    budget: &AllocationBudget,
) -> Result<(), WorldStateSnapshotError> {
    // The original pool funds the exact checked account writer's sole scratch
    // allocation. Comparisons run serially, so one live scratch suffices; the
    // owned decoder counter admits their checked cumulative work independently.
    // Neither a replacement permission nor a parsed JSON graph is constructed.
    let scratch_bytes = approval
        .permission_match_scratch_bytes()
        .map_err(WorldStateSnapshotError::Amx)?;
    let cumulative_bytes = scratch_bytes
        .checked_mul(permissions.len())
        .ok_or("AMX debit approval comparison geometry overflow")?;
    let _scratch = budget.try_reserve_bytes(scratch_bytes)?;
    let mut counters = budget.try_reserve(norito::core::DecodeBudgetContext::allocation_layout())?;
    let context = norito::core::DecodeBudgetContext::from_reservation(
        norito::DecodeLimits::new(
            MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1,
            MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1,
            MAX_AMX_DEBIT_APPROVAL_PERMISSIONS_V1,
            cumulative_bytes,
            64,
        ),
        &mut counters,
    )?;
    let mut matched = false;
    for permission in permissions {
        if context
            .with(|| approval.matches_permission(permission))
            .map_err(WorldStateSnapshotError::Amx)?
        {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err("AMX debit approval requires exact direct CanPrepareAmx".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amx_permission_scratch_and_counter_keep_original_pool_refusals() {
        use iroha_allocation::AllocationRefusal;
        let (chain, approval, signer) =
            crate::sumeragi::test_chain::native_amx_approval_route_fixture();
        let relay = AccountId::new(signer.public_key().clone());
        let capture_budget = AllocationBudget::new(32 * 1024 * 1024);
        let snapshot = chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &chain.committed(2),
                &approval,
                &relay,
                &capture_budget,
                |world, _| Ok(world.clone()),
            )
            .unwrap();
        assert_eq!(capture_budget.reserved_bytes(), 0);
        let execution = chain.state().ivm_execution_budget();
        let world = chain.state().world.try_block(&execution).unwrap();
        let scratch = approval.permission_match_scratch_bytes().unwrap();
        let control = norito::core::DecodeBudgetContext::allocation_layout().size();
        assert!(scratch > 0 && control > 0);
        for available in [0, scratch] {
            let request = AllocationBudget::new(32 * 1024 * 1024);
            let occupied = request
                .try_reserve_bytes(request.limit_bytes() - available)
                .unwrap();
            let error: WorldStateSnapshotError =
                amx_approval_originals(&snapshot, &world, &approval, &relay, &request)
                    .err()
                    .unwrap()
                    .into();
            let WorldStateSnapshotError::Allocation(AllocationRefusal::Capacity {
                requested_bytes,
                reserved_bytes,
                limit_bytes,
                ..
            }) = error
            else {
                panic!("permission request pool refusal was erased: {error}");
            };
            assert_eq!(
                requested_bytes,
                if available == 0 { scratch } else { control }
            );
            assert_eq!(reserved_bytes, request.limit_bytes());
            assert_eq!(limit_bytes, request.limit_bytes());
            drop(occupied);
            assert_eq!(request.reserved_bytes(), 0);
            amx_approval_originals(&snapshot, &world, &approval, &relay, &request).unwrap();
            assert_eq!(request.reserved_bytes(), 0);
        }
        let empty = AllocationBudget::new(0);
        let error: WorldStateSnapshotError =
            amx_approval_originals(&snapshot, &world, &approval, &relay, &empty)
                .err()
                .unwrap()
                .into();
        assert!(matches!(
            error,
            WorldStateSnapshotError::Allocation(AllocationRefusal::ExceedsLimit {
                limit_bytes: 0,
                ..
            })
        ));
        assert_eq!(empty.reserved_bytes(), 0);
    }

    #[test]
    fn amx_root_read_keeps_original_enclosing_codec_refusal_and_rejects_forged_rows() {
        let (chain, approval, signer) =
            crate::sumeragi::test_chain::native_amx_approval_route_fixture();
        let relay = AccountId::new(signer.public_key().clone());
        let request = AllocationBudget::new(32 * 1024 * 1024);
        let mut snapshot = chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &chain.committed(2),
                &approval,
                &relay,
                &request,
                |world, _| Ok(world.clone()),
            )
            .unwrap();
        let execution = chain.state().ivm_execution_budget();
        let world = chain.state().world.try_block(&execution).unwrap();
        let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        let error: WorldStateSnapshotError = outer
            .with(|| amx_approval_originals(&snapshot, &world, &approval, &relay, &request))
            .err()
            .unwrap()
            .into();
        let WorldStateSnapshotError::RootScopeRead(cause) = error else {
            panic!("the first actual root metadata read refusal was erased: {error}");
        };
        assert_eq!(
            cause.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        // The immutable-root read is first; the comparator has not acquired its
        // original request scratch or counter, and no root absence is certified.
        assert_eq!(request.reserved_bytes(), 0);
        amx_approval_originals(&snapshot, &world, &approval, &relay, &request).unwrap();
        let row = snapshot
            .entries
            .iter_mut()
            .find(|row| {
                row.field_id == "world.account_permissions"
                    && row.key_hash == Some(hash_value(&relay).unwrap())
            })
            .unwrap();
        row.value_hash = Hash::new(b"forged permission preimage");
        let error: WorldStateSnapshotError =
            amx_approval_originals(&snapshot, &world, &approval, &relay, &request)
                .err()
                .unwrap()
                .into();
        assert!(matches!(error, WorldStateSnapshotError::Invalid(_)));
        assert_eq!(request.reserved_bytes(), 0);
    }
    #[test]
    fn checked_permission_comparator_retains_its_own_original_decoder_refusal() {
        let (chain, approval, signer) =
            crate::sumeragi::test_chain::native_amx_approval_route_fixture();
        let relay = AccountId::new(signer.public_key().clone());
        let request = AllocationBudget::new(32 * 1024 * 1024);
        let execution = chain.state().ivm_execution_budget();
        let world = chain.state().world.try_block(&execution).unwrap();
        let permissions = world.account_permissions().get(&relay).unwrap();
        let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        let error = outer
            .with(|| require_exact_amx_permission(&approval, permissions, &request))
            .unwrap_err();
        let WorldStateSnapshotError::Amx(iroha_data_model::sumeragi_amx::AmxError::Resource(cause)) =
            error
        else {
            panic!("checked comparator refused without its original cause: {error}");
        };
        assert!(cause.local_refusal().is_some());
        assert_eq!(request.reserved_bytes(), 0);
        require_exact_amx_permission(&approval, permissions, &request).unwrap();
        assert_eq!(request.reserved_bytes(), 0);
    }

    #[test]
    fn absent_and_malformed_original_root_remain_terminal() {
        use iroha_data_model::parameter::{
            Parameter, custom::CustomParameter, system::consensus_metadata,
        };
        let (chain, approval, signer) =
            crate::sumeragi::test_chain::native_amx_approval_route_fixture();
        let relay = AccountId::new(signer.public_key().clone());
        let request = AllocationBudget::new(32 * 1024 * 1024);
        let snapshot = chain
            .state()
            .with_native_amx_debit_approval_snapshot_v1(
                &chain.committed(2),
                &approval,
                &relay,
                &request,
                |world, _| Ok(world.clone()),
            )
            .unwrap();
        let empty = crate::state::World::new();
        for malformed in [false, true] {
            if malformed {
                let mut parameters = empty.parameters.block();
                parameters
                    .set_parameter(Parameter::Custom(CustomParameter::new(
                        consensus_metadata::handshake_meta_id(),
                        iroha_primitives::json::Json::from_norito_value_ref(
                            &norito::json::Value::Bool(false),
                        )
                        .unwrap(),
                    )))
                    .unwrap();
                parameters.commit();
            }
            let world = empty.block();
            let error =
                amx_approval_originals(&snapshot, &world, &approval, &relay, &request).unwrap_err();
            assert!(
                matches!(error, WorldStateSnapshotError::Invalid(_)),
                "malformed or absent original is terminal: {error}"
            );
        }
    }
}
