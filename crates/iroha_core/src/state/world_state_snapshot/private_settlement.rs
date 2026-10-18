//! Exact public pool originals borrowed from the existing funded certified World cut.

use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    nexus::{
        PrivateSettlementPoolCutProofRefV1, PrivateSettlementPoolGovernanceProjectionV1,
        PrivateSettlementPoolKeyV1, PrivateSettlementPoolStateV1,
    },
};

impl State {
    /// Borrow the exact canonical governance/frontier rows at a selected Global World cut.
    ///
    /// This low-level native publisher grants no HTTP read permission and returns no witness,
    /// restricted governance opening or committee signing capability. A route must establish
    /// current all-ledger read authorization before invoking it: the complete hash list
    /// exposes unrelated row identities and low-entropy values. Its callback must fund any
    /// retained output from the original operation budget.
    /// # Errors
    /// Wrong root, absent rows, unavailable original cut, post-result tail substitution,
    /// mismatched typed originals, finite snapshot bound or original acquisition refusal.
    pub fn with_native_private_settlement_pool_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        key: PrivateSettlementPoolKeyV1,
        budget: &AllocationBudget,
        consume: impl FnOnce(PrivateSettlementPoolCutProofRefV1<'_>) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        if tip.root_scope() != SumeragiRootScope::Global
            || key.pool_id.is_zero()
            || key.route.dataspace_id == iroha_model_base::topology::DataSpaceId::UNIVERSAL
            || key.route.lane_incarnation == Hash::prehashed([0; Hash::LENGTH])
        {
            return Err("private pool snapshot differs from the selected Global scope".into());
        }
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let governance: &PrivateSettlementPoolGovernanceProjectionV1 = world
                .private_settlement_governance
                .get(&key)
                .ok_or("selected private pool governance is absent")?;
            let pool: &PrivateSettlementPoolStateV1 = world
                .private_settlement_pools
                .get(&key)
                .ok_or("selected private pool frontier is absent")?;
            require_target(
                snapshot,
                "world.private_settlement_governance",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key)?),
                hash_value(governance)?,
            )?;
            require_target(
                snapshot,
                "world.private_settlement_pools",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key)?),
                hash_value(pool)?,
            )?;
            if governance.route != key.route
                || governance.pool_id != key.pool_id
                || pool.route != key.route
                || pool.pool_id != key.pool_id
                || governance.governance_digest != pool.restricted_pool_policy_digest
            {
                return Err("private pool originals disagree on route, pool or governance".into());
            }
            let proof = PrivateSettlementPoolCutProofRefV1::new(snapshot, governance, pool);
            if norito::canonical_frame_len(&proof).map_err(|error| error.to_string())?
                > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
            {
                return Err(
                    "private pool snapshot exceeds the existing complete World bound".into(),
                );
            }
            consume(proof).map_err(WorldStateSnapshotError::from)
        })
    }
}

impl State {
    /// Borrow same-cut pool, native assignment and Committee-role key originals.
    ///
    /// The response contains complete World hash preimages, including unrelated rows.
    /// The caller must authorize all-ledger disclosure; selected-dataspace permissions
    /// are insufficient. Restricted asset/policy openings and witnesses stay with their owners.
    /// # Errors
    /// Any original acquisition refusal, changed pre-tail source, missing or inactive assignment,
    /// malformed key lifecycle, finite response bound or original request-budget refusal.
    pub fn with_native_private_settlement_context_v1<T>(
        &self,
        tip: &CommittedBlock,
        selectors: &iroha_data_model::nexus::PrivateSettlementContextRequestV1,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            iroha_data_model::nexus::PrivateSettlementContextsProofRefV1<'_>,
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        use iroha_data_model::nexus::{
            PrivateSettlementContextProofRefV1, PrivateSettlementContextsProofRefV1,
            private_settlement_native_route_v1,
        };
        selectors.validate().map_err(|error| error.to_string())?;
        if tip.root_scope() != SumeragiRootScope::Global || tip.header().is_none() {
            return Err("private context requires a certified Global successor".into());
        }
        let height = tip.height();
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let lanes = world.sumeragi_lanes();
            require_target(
                snapshot,
                "world.sumeragi_lanes",
                WorldStateElementKindV1::Cell,
                None,
                hash_value(lanes)?,
            )?;
            let reference_bytes = selectors
                .pools
                .len()
                .checked_mul(std::mem::size_of::<PrivateSettlementContextProofRefV1<'_>>())
                .ok_or("private context reference geometry overflow")?;
            let _references = budget
                .try_reserve_bytes(reference_bytes)
                .map_err(|error| error.to_string())?;
            let mut contexts = Vec::with_capacity(selectors.pools.len());
            for key in selectors.pools.iter().copied() {
                let governance = world
                    .private_settlement_governance
                    .get(&key)
                    .ok_or("private governance absent")?;
                let pool = world
                    .private_settlement_pools
                    .get(&key)
                    .ok_or("private pool absent")?;
                if governance.route != key.route
                    || governance.pool_id != key.pool_id
                    || pool.route != key.route
                    || pool.pool_id != key.pool_id
                    || pool.restricted_pool_policy_digest != governance.governance_digest
                {
                    return Err("private pool originals disagree".into());
                }
                governance
                    .validate_public_lineage()
                    .map_err(|error| error.to_string())?;
                for (field, value) in [
                    (
                        "world.private_settlement_governance",
                        hash_value(governance)?,
                    ),
                    ("world.private_settlement_pools", hash_value(pool)?),
                ] {
                    require_target(
                        snapshot,
                        field,
                        WorldStateElementKindV1::Table,
                        Some(hash_value(&key)?),
                        value,
                    )?;
                }
                let lane = private_settlement_native_route_v1(lanes, key.route, height)
                    .map_err(|error| error.to_string())?;
                let [first, second, third, fourth] = lane.committee.as_slice() else {
                    return Err(
                        "private context requires the exact native four-member committee".into(),
                    );
                };
                let keys = [
                    private_context_key_original(snapshot, world, &first.peer, height, budget)?,
                    private_context_key_original(snapshot, world, &second.peer, height, budget)?,
                    private_context_key_original(snapshot, world, &third.peer, height, budget)?,
                    private_context_key_original(snapshot, world, &fourth.peer, height, budget)?,
                ];

                contexts.push(PrivateSettlementContextProofRefV1::new(
                    PrivateSettlementPoolCutProofRefV1::new(snapshot, governance, pool),
                    lanes,
                    keys,
                ));
            }
            let proof = PrivateSettlementContextsProofRefV1::new(contexts);
            if norito::canonical_frame_len(&proof).map_err(|error| error.to_string())?
                > MAX_WORLD_STATE_SNAPSHOT_BYTES_V1
            {
                return Err("private contexts exceed the existing complete World bound".into());
            }
            consume(proof).map_err(WorldStateSnapshotError::from)
        })
    }
}

fn private_context_key_original<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    peer: &iroha_model_base::peer::PeerId,
    height: u64,
    budget: &AllocationBudget,
) -> Result<iroha_data_model::nexus::PrivateSettlementCommitteeKeyProofRefV1<'a>, String> {
    use iroha_data_model::{
        consensus::ConsensusKeyRole, nexus::PrivateSettlementCommitteeKeyProofRefV1,
    };
    use std::fmt::Write as _;
    struct Count(usize);
    impl std::fmt::Write for Count {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0 = self.0.checked_add(value.len()).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut count = Count(0);
    write!(count, "{}", peer.public_key()).map_err(|error| error.to_string())?;
    let _scratch = budget
        .try_reserve_bytes(count.0)
        .map_err(|error| error.to_string())?;
    let mut text = String::with_capacity(count.0);
    write!(text, "{}", peer.public_key()).map_err(|error| error.to_string())?;
    let index = world
        .consensus_keys_by_pk()
        .get(&text)
        .ok_or("private committee registry index absent")?;
    require_target(
        snapshot,
        "world.consensus_keys_by_pk",
        WorldStateElementKindV1::Table,
        Some(hash_value(&text)?),
        hash_value(index)?,
    )?;
    let original = index
        .iter()
        .filter(|id| id.role == ConsensusKeyRole::Committee)
        .filter_map(|id| world.consensus_keys().get(id).map(|record| (id, record)))
        .find(|(id, record)| {
            record.id == **id
                && &record.public_key == peer.public_key()
                && record.is_live_at(height, 0, 0)
        })
        .ok_or("private committee key is not live at the selected cut")?;
    require_target(
        snapshot,
        "world.consensus_keys",
        WorldStateElementKindV1::Table,
        Some(hash_value(original.0)?),
        hash_value(original.1)?,
    )?;
    Ok(PrivateSettlementCommitteeKeyProofRefV1::new(
        index, original.1,
    ))
}
