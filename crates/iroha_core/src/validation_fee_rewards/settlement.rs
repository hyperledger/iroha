//! Bounded automatic materialization of funded historical staking rewards.

use super::*;
use iroha_data_model::validation_fee_rewards::{
    ValidationFeeExposureArchiveRef, ValidationFeeRewardEntitlement, allocate_page,
    validation_fee_entitlement_key,
};

// A sparse chain can add 31 heads plus one summary on each block. Twice that
// arrival rate leaves bounded sweep capacity for still-outstanding months.
const HISTORY_PRUNE_VISITS_PER_BLOCK: usize = 64;

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

/// Visit one past earning month in a persistent round-robin order, retiring at
/// most one source head or its empty service summary. Delayed funding for one
/// month cannot pin completed history in other months. Receipt bodies and sealed
/// exposure remain in their original native archive.
pub(super) fn prune_completed_history(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<bool, Error> {
    let current = earning_month(stx.block_unix_timestamp_ms())?;
    let Some(last_past_instant) = current.checked_sub(1) else {
        return Ok(false);
    };
    let start = state_key(binding, "Service/00000000000000000000")?;
    let end = state_key(binding, &format!("Service/{last_past_instant:020}"))?;
    let cursor_key = state_key(binding, "HistoryPruneCursor")?;
    let cursor = read::<u64>(stx, &cursor_key)?.unwrap_or(0);
    let after = state_key(
        binding,
        &format!("Service/{:020}", cursor.saturating_add(1)),
    )?;
    let next = (after <= end)
        .then(|| {
            stx.world
                .smart_contract_state
                .range(after..=end.clone())
                .next()
        })
        .flatten()
        .or_else(|| stx.world.smart_contract_state.range(start..=end).next());
    let Some((key, _)) = next else {
        return Ok(false);
    };
    let key = key.clone();
    let period = key
        .as_ref()
        .rsplit('/')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| fail("historical reward service key is malformed"))?;
    if earning_month(period)? != period {
        return Err(fail("historical reward service month is noncanonical"));
    }
    write(stx, cursor_key, &period)?;
    if period >= current || read::<u64>(stx, &pending_key(binding, period)?)?.is_some() {
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
            accrue_next_page(&mut stx, &binding)?;
            // Keep retirement progressing even under continuous allocations.
            // A blocked visit advances the fixed cursor, so pending months do
            // not stop the bounded sweep of independently completed history.
            for _ in 0..HISTORY_PRUNE_VISITS_PER_BLOCK {
                prune_completed_history(&mut stx, &binding)?;
            }
        }
        validate_pending_fee_evidence_budget(&stx)
            .map_err(|error| string_attempt_instruction_error(&stx, error))
    })();
    finish_reward_maintenance(stx, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_pruning_round_robin_passes_blocked_month_and_preserves_cursor_on_rollback() {
        crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, _| {
            let binding = {
                let mut stx = block.transaction();
                let binding = active_bindings(&stx).unwrap().remove(0);
                let old = earning_month(stx.block_unix_timestamp_ms() - 90 * DAY_MS).unwrap();
                let newer = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
                for period in [old, newer] {
                    write(
                        &mut stx,
                        service_key(&binding, period).unwrap(),
                        &ValidationFeeServiceSnapshot {
                            earning_period_start_ms: period,
                            service_blocks: BTreeMap::new(),
                        },
                    )
                    .unwrap();
                }
                write(&mut stx, pending_key(&binding, old).unwrap(), &1_u64).unwrap();
                stx.apply();
                (binding, old, newer)
            };
            let (binding, old, newer) = binding;
            {
                let mut stx = block.transaction();
                assert!(!prune_completed_history(&mut stx, &binding).unwrap());
                assert_eq!(
                    read::<u64>(&stx, &state_key(&binding, "HistoryPruneCursor").unwrap()).unwrap(),
                    Some(old)
                );
                assert!(prune_completed_history(&mut stx, &binding).unwrap());
                assert!(
                    stx.world
                        .smart_contract_state
                        .get(&service_key(&binding, newer).unwrap())
                        .is_none()
                );
                // Dropping the failed parent batch restores both the cursor and
                // the later summary; earlier pending credit was never touched.
            }
            let mut stx = block.transaction();
            assert!(
                read::<u64>(&stx, &state_key(&binding, "HistoryPruneCursor").unwrap())
                    .unwrap()
                    .is_none()
            );
            assert!(
                stx.world
                    .smart_contract_state
                    .get(&service_key(&binding, newer).unwrap())
                    .is_some()
            );
            assert!(!prune_completed_history(&mut stx, &binding).unwrap());
            assert!(prune_completed_history(&mut stx, &binding).unwrap());
            assert_eq!(
                read::<u64>(&stx, &pending_key(&binding, old).unwrap()).unwrap(),
                Some(1)
            );
            assert!(
                stx.world
                    .smart_contract_state
                    .get(&service_key(&binding, old).unwrap())
                    .is_some()
            );
            assert!(!prune_completed_history(&mut stx, &binding).unwrap());
            assert_eq!(
                read::<u64>(&stx, &state_key(&binding, "HistoryPruneCursor").unwrap()).unwrap(),
                Some(old)
            );
        });
    }

    #[test]
    fn historical_pruning_cursor_bounds_work_across_many_independent_months() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let current = earning_month(stx.block_unix_timestamp_ms()).unwrap();
            let mut periods = Vec::new();
            let mut period = current;
            for _ in 0..256 {
                period = earning_month(period - 1).unwrap();
                periods.push(period);
                write(
                    stx,
                    service_key(&binding, period).unwrap(),
                    &ValidationFeeServiceSnapshot {
                        earning_period_start_ms: period,
                        service_blocks: BTreeMap::new(),
                    },
                )
                .unwrap();
            }
            periods.sort_unstable();
            for period in periods.iter().step_by(2) {
                write(stx, pending_key(&binding, *period).unwrap(), &1_u64).unwrap();
            }
            let mut retired = 0;
            for _ in 0..256 {
                retired += usize::from(prune_completed_history(stx, &binding).unwrap());
            }
            assert_eq!(retired, 128);
            for (index, period) in periods.iter().enumerate() {
                assert_eq!(
                    stx.world
                        .smart_contract_state
                        .get(&service_key(&binding, *period).unwrap())
                        .is_some(),
                    index % 2 == 0
                );
                if index % 2 == 0 {
                    assert_eq!(
                        read::<u64>(stx, &pending_key(&binding, *period).unwrap()).unwrap(),
                        Some(1)
                    );
                }
            }
            for _ in 0..256 {
                assert!(!prune_completed_history(stx, &binding).unwrap());
            }
        });
    }

    #[test]
    fn pruning_keeps_up_with_maximum_month_arrivals_behind_pending_funding() {
        use iroha_data_model::validation_fee_rewards::{
            ValidationFeeExposureArchiveRef, ValidationFeeExposureHead,
        };
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let mut period = earning_month(stx.block_unix_timestamp_ms()).unwrap();
            let mut months = Vec::new();
            for _ in 0..257 {
                period = earning_month(period - 1).unwrap();
                months.push(period);
            }
            months.reverse();
            let blocked = months[0];
            write(
                stx,
                service_key(&binding, blocked).unwrap(),
                &ValidationFeeServiceSnapshot {
                    earning_period_start_ms: blocked,
                    service_blocks: BTreeMap::new(),
                },
            )
            .unwrap();
            write(stx, pending_key(&binding, blocked).unwrap(), &1_u64).unwrap();
            save_state(
                stx,
                &binding,
                &ValidationFeeRewardsState {
                    pending_sbd_total: 1,
                    ..Default::default()
                },
            )
            .unwrap();
            let validators: Vec<_> = (100..131).map(super::super::tests::account).collect();
            for period in months.into_iter().skip(1) {
                write(
                    stx,
                    service_key(&binding, period).unwrap(),
                    &ValidationFeeServiceSnapshot {
                        earning_period_start_ms: period,
                        service_blocks: validators
                            .iter()
                            .cloned()
                            .map(|validator| (validator, 1))
                            .collect(),
                    },
                )
                .unwrap();
                for validator in &validators {
                    // This throughput fixture starts after successful original-
                    // archive cooling. Separate certified tests authenticate the
                    // real source and reject absent/corrupt original archives.
                    write(
                        stx,
                        exposure::head_key(&binding, period, validator).unwrap(),
                        &ValidationFeeExposureHead {
                            page_count: 1,
                            service_total: 1,
                            latest: ValidationFeeExposureArchiveRef {
                                recorded_at_height: 1,
                                page_index: 0,
                                service_start: 0,
                                archive_hash: Hash::new(period.to_le_bytes()),
                            },
                            tail_resident: false,
                        },
                    )
                    .unwrap();
                }
                let mut retired = 0;
                for _ in 0..HISTORY_PRUNE_VISITS_PER_BLOCK {
                    retired += usize::from(prune_completed_history(stx, &binding).unwrap());
                }
                assert_eq!(
                    retired, 32,
                    "31 heads plus their summary retire within the per-block budget despite pending older funding"
                );
                assert!(
                    stx.world
                        .smart_contract_state
                        .get(&service_key(&binding, period).unwrap())
                        .is_none()
                );
                let heads = state_key(&binding, "ExposureHead/").unwrap();
                assert!(
                    !stx.world
                        .smart_contract_state
                        .range(heads.clone()..)
                        .next()
                        .is_some_and(|(key, _)| key.as_ref().starts_with(heads.as_ref()))
                );
                assert_eq!(
                    read::<u64>(stx, &pending_key(&binding, blocked).unwrap()).unwrap(),
                    Some(1)
                );
                super::super::reconciliation::validate(&stx.world, &binding).unwrap();
            }

            // A month can retain more than the current committee: successive
            // committees may have served all 4,096 admitted historical roots.
            // Start after certified source cooling, as above, and require the
            // real cursor sweep to drain this finite rotation backlog while
            // preserving the older pending month. Source authentication is
            // exercised by the separate certified archive tests.
            let rotated_period =
                earning_month(earning_month(stx.block_unix_timestamp_ms()).unwrap() - 1).unwrap();
            let rotated: Vec<_> = (0
                ..iroha_data_model::validation_fee_rewards::MAX_REWARD_VALIDATORS)
                .map(|index| {
                    let mut seed = b"reward-history-rotation/".to_vec();
                    seed.extend_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
                    AccountId::new(
                        iroha_crypto::KeyPair::from_seed(seed, iroha_crypto::Algorithm::Ed25519)
                            .public_key()
                            .clone(),
                    )
                })
                .collect();
            write(
                stx,
                service_key(&binding, rotated_period).unwrap(),
                &ValidationFeeServiceSnapshot {
                    earning_period_start_ms: rotated_period,
                    service_blocks: rotated
                        .iter()
                        .cloned()
                        .map(|validator| (validator, 1))
                        .collect(),
                },
            )
            .unwrap();
            for validator in &rotated {
                write(
                    stx,
                    exposure::head_key(&binding, rotated_period, validator).unwrap(),
                    &ValidationFeeExposureHead {
                        page_count: 1,
                        service_total: 1,
                        latest: ValidationFeeExposureArchiveRef {
                            recorded_at_height: 1,
                            page_index: 0,
                            service_start: 0,
                            archive_hash: Hash::new(rotated_period.to_le_bytes()),
                        },
                        tail_resident: false,
                    },
                )
                .unwrap();
            }
            let expected_rows = rotated.len() + 1;
            let max_blocks = expected_rows.div_ceil(HISTORY_PRUNE_VISITS_PER_BLOCK / 2);
            let mut retired_total = 0;
            for batch in 0..max_blocks {
                let mut retired = 0;
                for _ in 0..HISTORY_PRUNE_VISITS_PER_BLOCK {
                    retired += usize::from(prune_completed_history(stx, &binding).unwrap());
                }
                retired_total += retired;
                assert_eq!(
                    retired,
                    (expected_rows - batch * (HISTORY_PRUNE_VISITS_PER_BLOCK / 2))
                        .min(HISTORY_PRUNE_VISITS_PER_BLOCK / 2),
                    "one preserved pending month consumes every other cursor visit"
                );
                assert_eq!(
                    read::<u64>(stx, &pending_key(&binding, blocked).unwrap()).unwrap(),
                    Some(1)
                );
            }
            assert_eq!(retired_total, expected_rows);
            assert_eq!(max_blocks, 129);
            assert!(
                stx.world
                    .smart_contract_state
                    .get(&service_key(&binding, rotated_period).unwrap())
                    .is_none()
            );
            let heads = state_key(&binding, "ExposureHead/").unwrap();
            assert!(
                !stx.world
                    .smart_contract_state
                    .range(heads.clone()..)
                    .next()
                    .is_some_and(|(key, _)| key.as_ref().starts_with(heads.as_ref()))
            );
            super::super::reconciliation::validate(&stx.world, &binding).unwrap();
        });
    }
}
