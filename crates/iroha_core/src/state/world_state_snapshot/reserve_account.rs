//! Borrowed native reserve partition facts before any provider service is activated.

use super::*;
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    sorafs::{
        capacity::{CapacityDeclarationRecord, ProviderId},
        pricing::{PricingScheduleRecord, ProviderCreditRecord},
        reserve::account_proof::{
            MAX_RESERVE_ACCOUNT_CAPACITY_BYTES_V1, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1,
            MAX_RESERVE_ACCOUNT_PRICING_BYTES_V1,
        },
        reserve::history::{
            ReserveStateV1, STATE_LIMITS, STATE_MAX_BYTES, decode_reserve_provider_frame,
            reserve_provider_key, reserve_state_key,
        },
    },
};

impl State {
    /// Publish original policy, provider owner and exact partition/credit/capacity facts and pricing cell.
    ///
    /// `operator` is the canonical signed-request account. This owner requires it to equal
    /// the active policy operations authority at this exact cut. No service, provider advert,
    /// admission record, broad read permission or caller eligibility predicate is consulted.
    /// The consumer may only encode response data, retaining its original allocation charges.
    /// This is no registration, collateral, credit or runtime-activation capability.
    ///
    /// # Errors
    /// Refuses private/genesis roots, missing owner/policy/accounts, another operator, stale or
    /// tail-modified originals, changed generation and finite original resource exhaustion.
    pub fn with_native_reserve_account_snapshot_v1<T>(
        &self,
        tip: &CommittedBlock,
        operator: &AccountId,
        provider: ProviderId,
        budget: &AllocationBudget,
        consume: impl FnOnce(
            &WorldStateSnapshotV1,
            &AccountId,
            &Vec<u8>,
            Option<&Vec<u8>>,
            Option<&Vec<u8>>,
            Option<&Vec<u8>>,
            &Vec<u8>,
        ) -> Result<T, String>,
    ) -> Result<T, WorldStateSnapshotError> {
        if tip.height() < 2 || provider.as_bytes() == &[0; 32] {
            return Err(
                "Reserve account projection requires a successor and nonzero provider".into(),
            );
        }
        self.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
            let originals = reserve_account_originals(
                snapshot,
                world,
                operator,
                provider,
                tip.block_time_ms(),
                tip.height(),
                budget,
            )?;
            // Authenticate the borrowed typed original before allocating its response frame.
            // Both the raw bytes and their original-pool reservation live through consume.
            let credit = originals
                .credit
                .map(|record| encode_original(record, MAX_RESERVE_ACCOUNT_CREDIT_BYTES_V1, budget))
                .transpose()?;
            let capacity = originals
                .capacity
                .map(|record| {
                    encode_original(record, MAX_RESERVE_ACCOUNT_CAPACITY_BYTES_V1, budget)
                })
                .transpose()?;
            let pricing = encode_original(
                originals.pricing,
                MAX_RESERVE_ACCOUNT_PRICING_BYTES_V1,
                budget,
            )?;
            // All materialized frames and their original-pool reservations overlap through
            // response encoding; no second scope or renewed working-set allowance is created.
            consume(
                snapshot,
                originals.owner,
                originals.policy,
                originals.current,
                credit.as_ref().map(|(bytes, _charge)| bytes),
                capacity.as_ref().map(|(bytes, _charge)| bytes),
                &pricing.0,
            )
            .map_err(WorldStateSnapshotError::from)
        })
    }
}

struct ReserveAccountOriginals<'a> {
    owner: &'a AccountId,
    policy: &'a Vec<u8>,
    current: Option<&'a Vec<u8>>,
    credit: Option<&'a ProviderCreditRecord>,
    capacity: Option<&'a CapacityDeclarationRecord>,
    pricing: &'a PricingScheduleRecord,
}

fn encode_original<T: norito::NoritoSerialize>(
    record: &T,
    maximum: usize,
    budget: &AllocationBudget,
) -> Result<(Vec<u8>, iroha_allocation::AllocationReservation), String> {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let length = norito::core::encoded_frame_len(record).map_err(|e| e.to_string())?;
    if length > maximum {
        return Err("Reserve typed original exceeds its response bound".into());
    }
    let charge = budget
        .try_reserve_bytes(length)
        .map_err(|e| e.to_string())?;
    // The bounded encoder charges its exact output allocation to the inherited codec
    // scope. The independent original pool reservation remains with that same buffer.
    let bytes = norito::core::to_bytes_bounded(record, length).map_err(|e| e.to_string())?;
    // Tuple declaration order drops the bytes before releasing their exact reservation.
    Ok((bytes, charge))
}

fn reserve_account_originals<'a>(
    snapshot: &WorldStateSnapshotV1,
    world: &'a WorldBlock<'_>,
    operator: &AccountId,
    provider: ProviderId,
    block_time_ms: u64,
    height: u64,
    budget: &AllocationBudget,
) -> Result<ReserveAccountOriginals<'a>, String> {
    if provider.as_bytes() == &[0; 32]
        || crate::sumeragi::lanes::routing::committed_root_scope(world)
            != Some(SumeragiRootScope::Global)
    {
        return Err(
            "Reserve account projection requires a nonzero provider on the Global root".into(),
        );
    }
    let owner = world
        .provider_owners()
        .get(&provider)
        .ok_or("Reserve account provider owner is absent")?;
    require_target(
        snapshot,
        "world.provider_owners",
        WorldStateElementKindV1::Table,
        Some(hash_value(&provider)?),
        hash_value(owner)?,
    )?;
    let policy = world
        .smart_contract_state()
        .get(reserve_state_key())
        .ok_or("Reserve account projection requires an active policy")?;
    if policy.is_empty() || policy.len() > STATE_MAX_BYTES {
        return Err("Reserve account policy original exceeds its bound".into());
    }
    require_target(
        snapshot,
        "world.smart_contract_state",
        WorldStateElementKindV1::Table,
        Some(hash_value(reserve_state_key())?),
        hash_value(policy)?,
    )?;

    // Fund both decoded originals and the canonical provider-key scratch before allocation.
    // The outer codec scope survives both nested decodes; neither obtains a renewed allowance.
    // Decoded graphs never escape; response originals stay borrowed from the funded overlay.
    let decoded = STATE_LIMITS
        .max_total_allocated_bytes()
        .checked_mul(2)
        .ok_or("Reserve account scratch bound overflows")?;
    let scratch = decoded
        .checked_add(STATE_MAX_BYTES)
        .ok_or("Reserve account scratch bound overflows")?;
    let _scratch = budget
        .try_reserve_bytes(scratch)
        .map_err(|e| e.to_string())?;
    let limits = norito::DecodeLimits::new(4_096, STATE_MAX_BYTES, 32_768, decoded, 64);
    norito::core::with_decode_limits_scope(limits, || {
        let state = ReserveStateV1::decode_frame(policy).map_err(|e| e.to_string())?;
        if state.policy.policy.operations_authority != *operator
            || state.policy.activated_at_unix > block_time_ms / 1_000
            || state.journal_head.last_target_block_height > height
        {
            return Err(
                "Reserve account operator or policy provenance differs from the native cut".into(),
            );
        }
        for account_id in [
            operator,
            owner,
            &state.policy.policy.custody_account,
            &state.policy.policy.treasury_account,
            &state.policy.policy.decision_authority,
        ] {
            let account = world
                .accounts()
                .get(account_id)
                .ok_or("Reserve account selected account is absent")?;
            require_target(
                snapshot,
                "world.accounts",
                WorldStateElementKindV1::Table,
                Some(hash_value(account_id)?),
                hash_value(account)?,
            )?;
        }
        let asset_id = &state.policy.policy.asset_definition;
        let asset = world
            .asset_definitions()
            .get(asset_id)
            .ok_or("Reserve account selected asset is absent")?;
        require_target(
            snapshot,
            "world.asset_definitions",
            WorldStateElementKindV1::Table,
            Some(hash_value(asset_id)?),
            hash_value(asset)?,
        )?;

        let key = reserve_provider_key(provider);
        let current = world.smart_contract_state().get(&key);
        if let Some(bytes) = current {
            if bytes.is_empty() || bytes.len() > STATE_MAX_BYTES {
                return Err("Reserve account original exceeds its bound".into());
            }
            require_target(
                snapshot,
                "world.smart_contract_state",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key)?),
                hash_value(bytes)?,
            )?;
            let account =
                decode_reserve_provider_frame(bytes, provider).map_err(|e| e.to_string())?;
            if account.terms.provider_account != *owner
                || account.updated_at_unix > block_time_ms / 1_000
            {
                return Err(
                    "Reserve account owner or timestamp differs from the native cut".into(),
                );
            }
            // The account's last-projected policy may legitimately precede an active rotation.
            // Do not normalize its digest, credit cap or balances into new authority.
        } else {
            let target = (
                "world.smart_contract_state",
                WorldStateElementKindV1::Table,
                Some(hash_value(&key)?),
            );
            if snapshot
                .entries
                .binary_search_by(|entry| {
                    (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&target)
                })
                .is_ok()
            {
                return Err(
                    "Reserve account absence differs from the certified original cut".into(),
                );
            }
        }
        let credit = world.provider_credit_ledger().get(&provider);
        if let Some(record) = credit {
            if record.provider_id != provider {
                return Err("Reserve credit original differs from selected provider".into());
            }
            require_target(
                snapshot,
                "world.provider_credit_ledger",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
                hash_value(record)?,
            )?;
        } else {
            let target = (
                "world.provider_credit_ledger",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
            );
            if snapshot
                .entries
                .binary_search_by(|entry| {
                    (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&target)
                })
                .is_ok()
            {
                return Err(
                    "Reserve credit absence differs from the certified original cut".into(),
                );
            }
        }
        let capacity = world.capacity_declarations().get(&provider);
        if let Some(record) = capacity {
            if record.provider_id != provider {
                return Err("Reserve capacity original differs from selected provider".into());
            }
            require_target(
                snapshot,
                "world.capacity_declarations",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
                hash_value(record)?,
            )?;
        } else {
            let target = (
                "world.capacity_declarations",
                WorldStateElementKindV1::Table,
                Some(hash_value(&provider)?),
            );
            if snapshot
                .entries
                .binary_search_by(|entry| {
                    (entry.field_id.as_str(), entry.kind, entry.key_hash).cmp(&target)
                })
                .is_ok()
            {
                return Err(
                    "Reserve capacity absence differs from the certified original cut".into(),
                );
            }
        }
        let pricing = world.sorafs_pricing();
        require_target(
            snapshot,
            "world.sorafs_pricing",
            WorldStateElementKindV1::Cell,
            None,
            hash_value(pricing)?,
        )?;
        // These typed originals are facts. Current eligibility and pricing arithmetic retain
        // their existing native owners; the reader neither repairs nor reinterprets them.
        Ok(ReserveAccountOriginals {
            owner,
            policy,
            current,
            credit,
            capacity,
            pricing,
        })
    })
}

#[cfg(test)]
#[path = "reserve_account/tests.rs"]
mod tests;
