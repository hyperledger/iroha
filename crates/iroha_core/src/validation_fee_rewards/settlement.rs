//! Bounded automatic materialization of funded historical staking rewards.

use super::*;
use iroha_data_model::validation_fee_rewards::{
    ValidationFeeExposureArchiveRef, ValidationFeeRewardEntitlement, allocate_page,
    validation_fee_entitlement_key,
};

/// Sole unfinished conversion; funding waits until every historical page is credited.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::RewardAllocationCursor")]
pub(super) struct RewardAllocationCursor {
    pub(super) allocation_sequence: u64,
    pub(super) validator_index: u32,
    pub(super) page_index: u64,
    pub(super) service_offset: u64,
    pub(super) credited_xor: u128,
    pub(super) next_archive: Option<ValidationFeeExposureArchiveRef>,
}

/// Credit at most one bounded exposure page. All mutations share the maintenance
/// transaction, so a refused decode, failed invariant or evidence budget rolls back.
pub(super) fn accrue_next_page(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<bool, Error> {
    let cursor_key = state_key(binding, "AllocationCursor")?;
    let Some(mut cursor) = read::<RewardAllocationCursor>(stx, &cursor_key)? else {
        return Ok(false);
    };
    let allocation: ValidationFeeRewardAllocation = read(
        stx,
        &state_key(
            binding,
            &format!("Allocation/{}", cursor.allocation_sequence),
        )?,
    )?
    .ok_or_else(|| fail("reward cursor has no funded conversion"))?;
    let (validator, service_total) = allocation
        .service_blocks
        .iter()
        .nth(
            usize::try_from(cursor.validator_index)
                .map_err(|_| fail("reward cursor index overflow"))?,
        )
        .ok_or_else(|| fail("reward cursor validator is absent"))?;
    let gross = *allocation
        .gross_shares
        .get(validator)
        .ok_or_else(|| fail("reward cursor gross funding is absent"))?;
    let reference = match &cursor.next_archive {
        Some(reference) => *reference,
        None => {
            if cursor.service_offset != 0 {
                return Err(fail("reward archive cursor lost its predecessor"));
            }
            let head = exposure::head(stx, binding, allocation.earning_period_start_ms, validator)?
                .ok_or_else(|| fail("funded historical exposure head is absent"))?;
            if head.service_total != *service_total {
                return Err(fail("funded historical exposure service differs"));
            }
            head.latest
        }
    };
    let archive = exposure::load_archive(
        stx,
        binding,
        allocation.earning_period_start_ms,
        validator,
        &reference,
    )?;
    let page = archive.page;
    let service_start = reference.service_start;
    let service_end = page
        .exposure
        .iter()
        .try_fold(service_start, |count, cohort| {
            count.checked_add(cohort.service_blocks)
        })
        .ok_or_else(|| fail("reward service cursor overflow"))?;
    if service_total.checked_sub(cursor.service_offset) != Some(service_end) {
        return Err(fail(
            "reward archive cursor does not cover the next historical interval",
        ));
    }
    let shares = allocate_page(gross, *service_total, service_start, &page).map_err(fail)?;
    let amount = shares
        .values()
        .try_fold(0u128, |sum, value| sum.checked_add(*value))
        .ok_or_else(|| fail("reward entitlement sum overflow"))?;
    cursor.credited_xor = cursor
        .credited_xor
        .checked_add(amount)
        .ok_or_else(|| fail("reward credited funding overflow"))?;
    if cursor.credited_xor > allocation.xor_minor {
        return Err(fail("automatic entitlements exceed funded XOR"));
    }
    let receipt_key = validation_fee_entitlement_key(
        binding,
        cursor.allocation_sequence,
        validator,
        page.page_index,
    )
    .map_err(fail)?;
    if stx.world.smart_contract_state.get(&receipt_key).is_some() {
        return Err(fail("historical reward page was already credited"));
    }
    let mut beneficiaries = BTreeMap::new();
    for (account, amount) in &shares {
        let original = beneficiary::ensure(stx, binding, account)?;
        beneficiaries.insert(account.clone(), original.clone());
        if *amount != 0 {
            let key = claimable_key(binding, &original)?;
            let accrued = read::<u128>(stx, &key)?
                .unwrap_or(0)
                .checked_add(*amount)
                .ok_or_else(|| fail("claim balance overflow"))?;
            write(stx, key, &accrued)?;
        }
    }
    let receipt = ValidationFeeRewardEntitlement {
        allocation_sequence: cursor.allocation_sequence,
        validator: validator.clone(),
        page_index: page.page_index,
        service_start,
        service_end,
        recorded_at_height: stx.block_height(),
        shares,
        beneficiaries,
    };
    write(stx, receipt_key, &receipt)?;
    // Retain only the bounded current-block proof source. Its monetary witness
    // is archived before the following block compacts this transient row.
    write(
        stx,
        exposure::source_key(binding, stx.block_height(), validator, page.page_index)?,
        &page,
    )?;
    cursor.service_offset = service_total
        .checked_sub(service_start)
        .ok_or_else(|| fail("reward archive service exceeds funded interval"))?;
    if let Some(previous) = archive.previous {
        if page.page_index == 0 || previous.page_index.checked_add(1) != Some(page.page_index) {
            return Err(fail("reward archive predecessor skips a historical page"));
        }
        cursor.page_index = previous.page_index;
        cursor.next_archive = Some(previous);
    } else {
        if service_start != 0 || page.page_index != 0 || cursor.service_offset != *service_total {
            return Err(fail("historical exposure does not cover validator service"));
        }
        cursor.validator_index = cursor
            .validator_index
            .checked_add(1)
            .ok_or_else(|| fail("reward validator cursor overflow"))?;
        cursor.page_index = 0;
        cursor.service_offset = 0;
        cursor.next_archive = None;
    }
    if usize::try_from(cursor.validator_index)
        .map_err(|_| fail("reward validator index overflow"))?
        == allocation.service_blocks.len()
    {
        if cursor.credited_xor != allocation.xor_minor {
            return Err(fail(
                "automatic reward allocation did not conserve funded XOR",
            ));
        }
        stx.world.smart_contract_state.remove(cursor_key);
    } else {
        write(stx, cursor_key, &cursor)?;
    }
    Ok(true)
}

/// Cool one completed-month tail after authenticating its durable original source.
/// Pending funding retains the fixed head and every archived stake interval.
fn cool_completed_month_tail(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<bool, Error> {
    use iroha_data_model::validation_fee_rewards::{
        ValidationFeeExposureArchive, ValidationFeeExposureHead,
    };
    let prefix = state_key(binding, "ExposureArchive/")?;
    let Some((key, bytes)) = stx
        .world
        .smart_contract_state
        .range(prefix.clone()..)
        .next()
        .filter(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
        .map(|(key, bytes)| (key.clone(), bytes.clone()))
    else {
        return Ok(false);
    };
    let archive: ValidationFeeExposureArchive = read(stx, &key)?
        .ok_or_else(|| fail("cooling reward tail disappeared from protected state"))?;
    let page = &archive.page;
    if page.earning_period_start_ms >= earning_month(stx.block_unix_timestamp_ms())? {
        return Ok(false);
    }
    let head_key = exposure::head_key(binding, page.earning_period_start_ms, &page.validator)?;
    let mut head: ValidationFeeExposureHead = read(stx, &head_key)?
        .ok_or_else(|| fail("cooling reward tail lacks an authenticated head"))?;
    if head.latest.recorded_at_height >= stx.block_height() {
        return Ok(false);
    }
    if !head.tail_resident
        || head.latest.page_index != page.page_index
        || head.latest.archive_hash != Hash::new(&bytes)
    {
        return Err(fail(
            "cooling reward tail differs from its authenticated head",
        ));
    }
    let original = crate::query::native_receipts::committed_reward_exposure(
        stx,
        head.latest.recorded_at_height,
        &key,
        head.latest.archive_hash,
    )
    .map_err(|error| string_attempt_instruction_error(stx, error))?;
    if original != archive {
        return Err(fail("cooling reward tail differs from original archive"));
    }
    stx.world.smart_contract_state.remove(exposure::page_key(
        binding,
        page.earning_period_start_ms,
        &page.validator,
        page.page_index,
    )?);
    stx.world.smart_contract_state.remove(key);
    head.tail_resident = false;
    write(stx, head_key, &head)?;
    Ok(true)
}

/// Retire one source head from the oldest fully funded and wallet-closed month.
/// Receipt bodies and sealed exposure remain in their original native archive.
pub(super) fn prune_completed_history(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<bool, Error> {
    let start = state_key(binding, "Service/00000000000000000000")?;
    let end = state_key(binding, "Service/99999999999999999999")?;
    let Some((key, _)) = stx.world.smart_contract_state.range(start..=end).next() else {
        return Ok(false);
    };
    let key = key.clone();
    let period = key
        .as_ref()
        .rsplit('/')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| fail("historical reward service key is malformed"))?;
    if period >= earning_month(stx.block_unix_timestamp_ms())?
        || read::<u64>(stx, &pending_key(binding, period)?)?.is_some()
    {
        return Ok(false);
    }
    if let Some(cursor) =
        read::<RewardAllocationCursor>(stx, &state_key(binding, "AllocationCursor")?)?
    {
        let allocation: ValidationFeeRewardAllocation = read(
            stx,
            &state_key(
                binding,
                &format!("Allocation/{}", cursor.allocation_sequence),
            )?,
        )?
        .ok_or_else(|| fail("reward cursor has no allocation during pruning"))?;
        if allocation.earning_period_start_ms == period {
            return Ok(false);
        }
    }
    if !crate::retail_fee::reward_history_is_closed(stx, period)? {
        return Ok(false);
    }
    // A resident tail is cooled separately after authenticating its original
    // archive. Retire only its fixed head here; never expose a partially removed
    // page/wrapper pair to restore or to a later block.
    let prefix = state_key(binding, &format!("ExposureHead/{period:020}/"))?;
    let row = stx
        .world
        .smart_contract_state
        .range(prefix.clone()..)
        .next()
        .filter(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
        .map(|(key, _)| key.clone());
    if let Some(row) = row {
        let head: iroha_data_model::validation_fee_rewards::ValidationFeeExposureHead =
            read(stx, &row)?.ok_or_else(|| fail("reward head disappeared during retirement"))?;
        if head.tail_resident {
            return Ok(false);
        }
        stx.world.smart_contract_state.remove(row);
        return Ok(true);
    }
    stx.world.smart_contract_state.remove(key);
    Ok(true)
}

/// Run after finalized service capture and before this block's transactions.
pub(crate) fn process_reward_entitlements(
    block: &mut StateBlock<'_>,
) -> Result<(), crate::state::ExecutionOutputAttemptError> {
    let mut stx = block.try_transaction()?;
    let result = (|| {
        // Funding can become inactive while its already reserved pages remain.
        // Retained custody must finish accruing those rights and retire its
        // archived receipts independently of permission to perform new swaps.
        let retained = crate::validation_fee::retained_payout_custody_binding(&stx.world)
            .map_err(|error| string_attempt_instruction_error(&stx, error))?;
        if let Some(binding) = retained {
            history::compact(&mut stx, &binding)?;
            // A sparse chain can enter a new month on every service block.
            // Match the maximum 31 new validator tails per block so cooling
            // cannot fall behind merely because the chain advances slowly.
            for _ in 0..31 {
                if !cool_completed_month_tail(&mut stx, &binding)? {
                    break;
                }
            }
            if !accrue_next_page(&mut stx, &binding)? {
                // Retire those 31 heads plus their one month service summary.
                for _ in 0..32 {
                    if !prune_completed_history(&mut stx, &binding)? {
                        break;
                    }
                }
            }
        }
        validate_pending_fee_evidence_budget(&stx)
            .map_err(|error| string_attempt_instruction_error(&stx, error))
    })();
    finish_reward_maintenance(stx, result)
}
