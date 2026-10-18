//! Borrowed reserve-policy facts and one exact direct manager grant at a native World cut.

use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    permission::Permissions,
    sorafs::reserve::{
        history::{
            ReserveStateV1, STATE_LIMITS, STATE_MAX_BYTES, reserve_policy_permission,
            reserve_state_key,
        },
        proof::{
            MAX_RESERVE_POLICY_MANAGER_PERMISSIONS_V1, MAX_RESERVE_POLICY_PERMISSION_BYTES_V1,
        },
    },
};

impl State {
    /// Publish reserve-policy presence or absence with the manager's exact direct grant.
    ///
    /// Originals are borrowed from the same certified pre-tail World. No broad ledger-read
    /// permission or caller-supplied authorization predicate grants access. The callback may
    /// only produce response data and must retain its own allocation charges. Policy absence
    /// does not prove an empty reserve namespace or authorize initial policy installation.
    ///
    /// # Errors
    /// Refuses a private root, absent manager/direct grant, malformed or tail-modified
    /// originals, changed certified cut, missing original capture, or finite resource refusal.
    pub fn with_native_reserve_policy_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        manager: &AccountId,
        budget: &AllocationBudget,
        consume: impl FnOnce(&WorldStateSnapshotV1, &Permissions, Option<&Vec<u8>>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let (permissions, current) =
                reserve_policy_originals(snapshot, world, manager, budget)?;
            consume(snapshot, permissions, current).map_err(WorldStateSnapshotError::from)
        })
    }
}

fn reserve_policy_originals<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    manager: &AccountId,
    budget: &AllocationBudget,
) -> Result<(&'a Permissions, Option<&'a Vec<u8>>), String> {
    if crate::sumeragi::lanes::routing::committed_root_scope(world)
        != Some(SumeragiRootScope::Global)
    {
        return Err("Reserve policy projection requires the native Global root".into());
    }
    let account = world
        .accounts()
        .get(manager)
        .ok_or("Reserve policy manager is absent")?;
    require_target(
        snapshot,
        "world.accounts",
        WorldStateElementKindV1::Table,
        Some(hash_value(manager)?),
        hash_value(account)?,
    )?;
    let permissions = world
        .account_permissions()
        .get(manager)
        .ok_or("Reserve policy manager direct grant is absent")?;
    if permissions.len() > MAX_RESERVE_POLICY_MANAGER_PERMISSIONS_V1
        || norito::canonical_frame_len(permissions).map_err(|e| e.to_string())?
            > MAX_RESERVE_POLICY_PERMISSION_BYTES_V1
    {
        return Err("Reserve policy manager permissions exceed their bound".into());
    }
    // Fund canonical policy decoding and the exact permission token from this operation's
    // original pool. Only borrowed source values leave this helper; scratch drops here.
    let _scratch = budget
        .try_reserve_bytes(
            STATE_LIMITS
                .max_total_allocated_bytes()
                .checked_add(MAX_RESERVE_POLICY_PERMISSION_BYTES_V1)
                .ok_or("Reserve policy scratch bound overflows")?,
        )
        .map_err(|e| e.to_string())?;
    if !permissions.contains(&reserve_policy_permission()) {
        return Err(
            "Reserve policy manager requires exact direct CanSetSorafsReservePolicy".into(),
        );
    }
    require_target(
        snapshot,
        "world.account_permissions",
        WorldStateElementKindV1::Table,
        Some(hash_value(manager)?),
        hash_value(permissions)?,
    )?;
    let key = reserve_state_key();
    let current = world.smart_contract_state().get(key);
    if let Some(bytes) = current {
        if bytes.len() > STATE_MAX_BYTES {
            return Err("Reserve policy original exceeds its bound".into());
        }
        require_target(
            snapshot,
            "world.smart_contract_state",
            WorldStateElementKindV1::Table,
            Some(hash_value(key)?),
            hash_value(bytes)?,
        )?;
        ReserveStateV1::decode_frame(bytes).map_err(|e| e.to_string())?;
    } else {
        let target = (
            "world.smart_contract_state",
            WorldStateElementKindV1::Table,
            Some(hash_value(key)?),
        );
        if snapshot
            .entries
            .binary_search_by(|entry| {
                (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&target)
            })
            .is_ok()
        {
            return Err("Reserve policy absence differs from the certified original cut".into());
        }
    }
    Ok((permissions, current))
}

#[cfg(test)]
#[path = "reserve_policy/tests.rs"]
mod tests;
