//! Restart reconciliation of compacted reward checkpoints and bounded hot receipts.
//!
//! Original receipt bodies remain in authenticated native block custody. World
//! keeps outstanding beneficiary balances, one active allocation, the last
//! uncompacted block, and one exposure tail per outstanding validator/month.

use super::*;
use iroha_data_model::validation_fee_rewards::{
    ValidationFeeExposureArchive, ValidationFeeExposureHead, ValidationFeeExposurePage,
    ValidationFeeRewardBeneficiaryAlias, ValidationFeeRewardBeneficiaryRevision,
    ValidationFeeRewardEntitlement, allocate_page, validate_exposure_archive,
    validate_exposure_page, validation_fee_beneficiary_alias_key,
    validation_fee_beneficiary_revision_key, validation_fee_entitlement_key,
};
use iroha_primitives::bigint::BigInt;

fn add(sum: u128, amount: u128) -> Result<u128, Error> {
    sum.checked_add(amount)
        .ok_or_else(|| fail("reward reconciliation amount overflow"))
}
fn cumulative(gross: u128, service: u64, total: u64) -> Result<u128, Error> {
    if total == 0 || service > total {
        return Err(fail("reward reconciliation service exceeds funded service"));
    }
    BigInt::from(gross)
        .checked_mul(&BigInt::from(service))
        .and_then(|value| value.checked_div_rem(&BigInt::from(total)))
        .map_err(|error| fail(error.to_string()))?
        .0
        .try_to_u128()
        .ok_or_else(|| fail("reward reconciliation cumulative amount overflow"))
}
fn difference(left: &BigInt, right: &BigInt) -> Result<u128, Error> {
    left.checked_sub(right)
        .map_err(|error| fail(error.to_string()))?
        .try_to_u128()
        .ok_or_else(|| fail("reward reconciliation balance is negative or oversized"))
}

/// Validate current rights against their archived checkpoint and original hot suffix.
pub(super) fn validate(
    world: &impl WorldReadOnly,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<(), ExecutionAttemptError<Error>> {
    let root = state_key(binding, "State")?;
    let prefix = root
        .as_ref()
        .strip_suffix("State")
        .ok_or_else(|| fail("invalid reward state key"))?;
    let state = read_from_world::<ValidationFeeRewardsState>(world, &root)?.unwrap_or_default();
    let checkpoint = history::checkpoint(world, binding)?;
    if checkpoint.funded.is_negative()
        || checkpoint.credited.is_negative()
        || checkpoint.paid.is_negative()
        || (checkpoint.height == 0) != checkpoint.archive_chain.is_none()
        || checkpoint.next_allocation > state.next_allocation
        || checkpoint.next_claim > state.next_claim
        || checkpoint.funded.bit_len() > 192
        || checkpoint.credited.bit_len() > 192
        || checkpoint.paid.bit_len() > 192
        || (checkpoint.height == 0
            && (checkpoint.next_allocation != 0
                || checkpoint.next_claim != 0
                || !checkpoint.funded.is_zero()
                || !checkpoint.credited.is_zero()
                || !checkpoint.paid.is_zero()))
    {
        return Err(fail("noncanonical reward history checkpoint").into());
    }
    let checkpoint_reserved = difference(&checkpoint.funded, &checkpoint.paid)?;
    let checkpoint_claimable = difference(&checkpoint.credited, &checkpoint.paid)?;
    if checkpoint_claimable > checkpoint_reserved {
        return Err(fail("compacted reward entitlements exceed funding").into());
    }
    let cursor = read_from_world::<settlement::RewardAllocationCursor>(
        world,
        &state_key(binding, "AllocationCursor")?,
    )?;
    let mut funded = checkpoint.funded.clone();
    let mut credited = checkpoint.credited.clone();
    let mut paid = checkpoint.paid.clone();
    let mut allocations = BTreeMap::<u64, ValidationFeeRewardAllocation>::new();
    let mut claims = BTreeMap::<u64, ValidationFeeRewardClaim>::new();
    let mut entitlements = Vec::<(StatePath, ValidationFeeRewardEntitlement)>::new();
    let mut services = BTreeMap::<u64, ValidationFeeServiceSnapshot>::new();
    let mut heads = BTreeMap::<StatePath, ValidationFeeExposureHead>::new();
    let mut hot_pages = BTreeMap::new();
    let mut hot_archives = BTreeMap::new();
    let mut pending_periods = BTreeSet::new();
    let mut pending_total = 0u128;
    let mut outstanding = BTreeMap::<AccountId, BigInt>::new();
    let mut checkpoint_balance_total = 0u128;
    let mut actual_claimable = BTreeMap::new();
    for (key, bytes) in world.smart_contract_state().iter() {
        let Some(leaf) = key.as_ref().strip_prefix(prefix) else {
            continue;
        };
        if leaf.starts_with("HistoryBalance/") {
            let balance: history::Balance = read_from_world(world, key)?
                .ok_or_else(|| fail("checkpoint balance disappeared"))?;
            ensure_reward_identity(&balance.beneficiary)?;
            if balance.amount == 0
                || *key != history::balance_key(binding, &balance.beneficiary)?
                || beneficiary::root_in_world(world, binding, &balance.beneficiary)?
                    != balance.beneficiary
                || beneficiary::owner_in_world(world, binding, &balance.beneficiary)?.is_none()
                || outstanding
                    .insert(balance.beneficiary, BigInt::from(balance.amount))
                    .is_some()
            {
                return Err(fail("noncanonical checkpoint beneficiary balance").into());
            }
            checkpoint_balance_total = add(checkpoint_balance_total, balance.amount)?;
        } else if leaf.starts_with("Allocation/") {
            let allocation: ValidationFeeRewardAllocation = read_from_world(world, key)?
                .ok_or_else(|| fail("reward allocation disappeared"))?;
            iroha_data_model::validation_fee_rewards::validate_allocation_bytes(&allocation)
                .map_err(fail)?;
            if *key != state_key(binding, &format!("Allocation/{}", allocation.sequence))?
                || allocation.sbd_minor == 0
                || allocation.xor_minor == 0
                || allocation.xor_minor < allocation.min_xor_minor
                || allocation.service_blocks.values().any(|count| *count == 0)
                || !allocation
                    .gross_shares
                    .keys()
                    .eq(allocation.service_blocks.keys())
                || iroha_data_model::validation_fee_rewards::allocate(
                    allocation.xor_minor,
                    &allocation.service_blocks,
                )
                .map_err(fail)?
                    != allocation.gross_shares
                || allocations.contains_key(&allocation.sequence)
            {
                return Err(fail("invalid funded reward allocation receipt").into());
            }
            if allocation.sequence >= checkpoint.next_allocation {
                history::add(&mut funded, allocation.xor_minor)?;
            }
            allocations.insert(allocation.sequence, allocation);
        } else if leaf.starts_with("Entitlement/") {
            entitlements.push((
                key.clone(),
                read_from_world(world, key)?
                    .ok_or_else(|| fail("reward entitlement disappeared"))?,
            ));
        } else if leaf.starts_with("Claim/") {
            let claim: ValidationFeeRewardClaim =
                read_from_world(world, key)?.ok_or_else(|| fail("reward claim disappeared"))?;
            if *key != state_key(binding, &format!("Claim/{}", claim.sequence))?
                || claim.xor_minor == 0
                || claim.sequence < checkpoint.next_claim
                || claim.claimed_at_height <= checkpoint.height
                || claims.insert(claim.sequence, claim).is_some()
            {
                return Err(fail("noncanonical uncheckpointed reward claim").into());
            }
        } else if leaf.starts_with("Pending/") {
            let period = leaf
                .strip_prefix("Pending/")
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| fail("invalid pending reward month"))?;
            let amount: u64 =
                read_from_world(world, key)?.ok_or_else(|| fail("pending reward disappeared"))?;
            if amount == 0
                || *key != pending_key(binding, period)?
                || !pending_periods.insert(period)
            {
                return Err(fail("noncanonical pending reward credit").into());
            }
            pending_total = add(pending_total, u128::from(amount))?;
        } else if leaf.starts_with("Service/") {
            let service: ValidationFeeServiceSnapshot =
                read_from_world(world, key)?.ok_or_else(|| fail("reward service disappeared"))?;
            if *key != service_key(binding, service.earning_period_start_ms)?
                || service.service_blocks.values().any(|count| *count == 0)
                || service.service_blocks.len()
                    > iroha_data_model::validation_fee_rewards::MAX_REWARD_VALIDATORS
                || services
                    .insert(service.earning_period_start_ms, service)
                    .is_some()
            {
                return Err(fail("noncanonical historical reward service").into());
            }
        } else if leaf.starts_with("ExposureHead/") {
            let head: ValidationFeeExposureHead = read_from_world(world, key)?
                .ok_or_else(|| fail("reward exposure head disappeared"))?;
            if head.page_count == 0
                || head.latest.page_index.checked_add(1) != Some(head.page_count)
                || head.latest.service_start >= head.service_total
                || head.latest.recorded_at_height == 0
            {
                return Err(fail("noncanonical archived reward exposure head").into());
            }
            heads.insert(key.clone(), head);
        } else if leaf.starts_with("Exposure/") {
            let page: ValidationFeeExposurePage =
                read_from_world(world, key)?.ok_or_else(|| fail("reward exposure disappeared"))?;
            validate_exposure_page(&page).map_err(fail)?;
            if *key
                != exposure::page_key(
                    binding,
                    page.earning_period_start_ms,
                    &page.validator,
                    page.page_index,
                )?
            {
                return Err(fail("noncanonical historical reward exposure key").into());
            }
            if hot_pages
                .insert(
                    (page.earning_period_start_ms, page.validator),
                    page.page_index,
                )
                .is_some()
            {
                return Err(
                    fail("multiple resident exposure pages for one validator month").into(),
                );
            }
        } else if leaf.starts_with("ExposureArchive/") {
            let archive: ValidationFeeExposureArchive = read_from_world(world, key)?
                .ok_or_else(|| fail("reward exposure archive disappeared"))?;
            validate_exposure_archive(&archive).map_err(fail)?;
            if *key
                != exposure::archive_key(
                    binding,
                    archive.page.earning_period_start_ms,
                    &archive.page.validator,
                    archive.page.page_index,
                )?
                || hot_archives
                    .insert(
                        (
                            archive.page.earning_period_start_ms,
                            archive.page.validator.clone(),
                        ),
                        (archive.page.page_index, Hash::new(bytes)),
                    )
                    .is_some()
            {
                return Err(fail("noncanonical or duplicate resident exposure archive").into());
            }
        } else if leaf.starts_with("BeneficiaryAlias/") {
            let alias: ValidationFeeRewardBeneficiaryAlias =
                read_from_world(world, key)?.ok_or_else(|| fail("reward alias disappeared"))?;
            ensure_reward_identity(&alias.account_id)?;
            ensure_reward_identity(&alias.beneficiary_id)?;
            if *key
                != validation_fee_beneficiary_alias_key(binding, &alias.account_id).map_err(fail)?
            {
                return Err(fail("noncanonical reward beneficiary alias").into());
            }
        } else if leaf.starts_with("BeneficiaryHistory/") {
            let revision: ValidationFeeRewardBeneficiaryRevision =
                read_from_world(world, key)?.ok_or_else(|| fail("reward revision disappeared"))?;
            ensure_reward_identity(&revision.account_id)?;
            ensure_reward_identity(&revision.beneficiary_id)?;
            if let Some(previous) = &revision.previous_account_id {
                ensure_reward_identity(previous)?;
            }
            if *key
                != validation_fee_beneficiary_revision_key(
                    binding,
                    &revision.beneficiary_id,
                    revision.revision,
                )
                .map_err(fail)?
            {
                return Err(fail("noncanonical reward beneficiary revision").into());
            }
        } else if leaf.starts_with("Oracle/") {
            let reference: ValidationFeeReferenceObservation =
                read_from_world(world, key)?.ok_or_else(|| fail("reward reference disappeared"))?;
            iroha_data_model::validation_fee_rewards::validate_reference_observation_bytes(
                &reference,
            )
            .map_err(fail)?;
        } else if leaf.starts_with("Claimable/") {
            let amount: u128 =
                read_from_world(world, key)?.ok_or_else(|| fail("claimable reward disappeared"))?;
            if amount == 0 {
                return Err(fail("zero claimable reward row is noncanonical").into());
            }
            actual_claimable.insert(key.clone(), amount);
        }
    }
    if checkpoint_balance_total != checkpoint_claimable
        || allocations.len() > 2
        || pending_total != state.pending_sbd_total
        || allocations
            .keys()
            .copied()
            .filter(|sequence| *sequence >= checkpoint.next_allocation)
            .ne(checkpoint.next_allocation..state.next_allocation)
        || claims
            .keys()
            .copied()
            .ne(checkpoint.next_claim..state.next_claim)
    {
        return Err(fail(
            "reward checkpoint, pending credit or receipt sequence does not reconcile",
        )
        .into());
    }
    let closed = crate::retail_fee::reward_history_closed_through(world)
        .map_err(|error| error.map_rejection(fail))?;
    let mut expected_heads = BTreeSet::new();
    for (period, service) in &services {
        for (validator, total) in &service.service_blocks {
            let head_key = exposure::head_key(binding, *period, validator)?;
            expected_heads.insert(head_key.clone());
            let required = pending_periods.contains(period)
                || closed.is_none_or(|closed| *period > closed)
                || cursor
                    .as_ref()
                    .and_then(|cursor| allocations.get(&cursor.allocation_sequence))
                    .is_some_and(|allocation| allocation.earning_period_start_ms == *period);
            let Some(head) = heads.get(&head_key) else {
                if required {
                    return Err(fail("pending funded rewards lack an exposure head").into());
                }
                continue;
            };
            if head.service_total != *total {
                return Err(fail("reward exposure head differs from historical service").into());
            }
            let page_key = exposure::page_key(binding, *period, validator, head.latest.page_index)?;
            let archive_key =
                exposure::archive_key(binding, *period, validator, head.latest.page_index)?;
            let page = read_from_world::<ValidationFeeExposurePage>(world, &page_key)?;
            let archive = read_from_world::<ValidationFeeExposureArchive>(world, &archive_key)?;
            if !head.tail_resident && (page.is_some() || archive.is_some()) {
                return Err(fail("cooled reward head retains an unexpected hot tail").into());
            }
            if let (Some(page), Some(archive)) = (page, archive) {
                validate_exposure_archive(&archive).map_err(fail)?;
                let count = page
                    .exposure
                    .iter()
                    .try_fold(0u64, |sum, cohort| sum.checked_add(cohort.service_blocks))
                    .ok_or_else(|| fail("exposure service overflow"))?;
                if archive.page != page
                    || archive.previous.as_ref().is_some_and(|previous| {
                        previous.recorded_at_height >= head.latest.recorded_at_height
                    })
                    || head.latest.service_start.checked_add(count) != Some(*total)
                    || Hash::new(
                        norito::to_bytes(&archive).map_err(|error| fail(error.to_string()))?,
                    ) != head.latest.archive_hash
                {
                    return Err(fail(
                        "hot reward tail differs from its authenticated archive head",
                    )
                    .into());
                }
            } else if head.tail_resident {
                return Err(fail("pending funded rewards lack their hot exposure tail").into());
            }
        }
    }
    if heads.keys().any(|key| !expected_heads.contains(key)) {
        return Err(fail("reward exposure head has no historical validator service").into());
    }
    for ((period, validator), page_index) in hot_pages {
        let head = heads
            .get(&exposure::head_key(binding, period, &validator)?)
            .ok_or_else(|| fail("resident reward exposure lacks an authenticated head"))?;
        if page_index != head.latest.page_index {
            return Err(fail("resident reward exposure is not the current tail").into());
        }
    }
    for ((period, validator), (page_index, hash)) in hot_archives {
        let head = heads
            .get(&exposure::head_key(binding, period, &validator)?)
            .ok_or_else(|| fail("resident reward archive lacks an authenticated head"))?;
        if page_index != head.latest.page_index || hash != head.latest.archive_hash {
            return Err(
                fail("resident reward archive is not the current authenticated tail").into(),
            );
        }
    }
    history::validate_journals(world, binding, &checkpoint)?;
    for allocation in allocations.values() {
        if services
            .get(&allocation.earning_period_start_ms)
            .is_some_and(|service| service.service_blocks != allocation.service_blocks)
        {
            return Err(fail("funded reward allocation differs from historical service").into());
        }
    }
    let mut intervals = BTreeMap::<(u64, AccountId), Vec<(u64, u64)>>::new();
    for (key, receipt) in entitlements {
        let allocation = allocations
            .get(&receipt.allocation_sequence)
            .ok_or_else(|| fail("reward entitlement lacks hot funded allocation"))?;
        let total = *allocation
            .service_blocks
            .get(&receipt.validator)
            .ok_or_else(|| fail("reward entitlement validator lacks service"))?;
        let gross = allocation.gross_shares[&receipt.validator];
        if key
            != validation_fee_entitlement_key(
                binding,
                receipt.allocation_sequence,
                &receipt.validator,
                receipt.page_index,
            )
            .map_err(fail)?
            || receipt.recorded_at_height <= checkpoint.height
            || receipt.recorded_at_height < allocation.converted_at_height
            || receipt.service_start >= receipt.service_end
            || receipt.service_end > total
            || !receipt.shares.keys().eq(receipt.beneficiaries.keys())
            || receipt.shares.is_empty()
            || receipt.shares.len()
                > iroha_data_model::validation_fee_rewards::MAX_REWARD_RECIPIENTS
        {
            return Err(fail("noncanonical uncheckpointed reward entitlement").into());
        }
        let amount = receipt
            .shares
            .values()
            .try_fold(0u128, |sum, amount| add(sum, *amount))?;
        let expected = cumulative(gross, receipt.service_end, total)?
            .checked_sub(cumulative(gross, receipt.service_start, total)?)
            .ok_or_else(|| fail("entitlement cumulative underflow"))?;
        if amount != expected {
            return Err(fail("reward entitlement does not conserve funded service share").into());
        }
        let source_key = exposure::source_key(
            binding,
            receipt.recorded_at_height,
            &receipt.validator,
            receipt.page_index,
        )?;
        let page = read_from_world::<ValidationFeeExposurePage>(world, &source_key)?
            .ok_or_else(|| fail("uncheckpointed entitlement lacks original exposure source"))?;
        if page.earning_period_start_ms != allocation.earning_period_start_ms
            || page.validator != receipt.validator
            || page.page_index != receipt.page_index
            || allocate_page(gross, total, receipt.service_start, &page).map_err(fail)?
                != receipt.shares
            || page
                .exposure
                .iter()
                .try_fold(receipt.service_start, |sum, cohort| {
                    sum.checked_add(cohort.service_blocks)
                })
                != Some(receipt.service_end)
        {
            return Err(
                fail("reward entitlement differs from original historical exposure").into(),
            );
        }
        intervals
            .entry((receipt.allocation_sequence, receipt.validator.clone()))
            .or_default()
            .push((receipt.service_start, receipt.service_end));
        for (account, amount) in &receipt.shares {
            let original = beneficiary::root_in_world(world, binding, account)?;
            if receipt.beneficiaries.get(account) != Some(&original)
                || beneficiary::owner_in_world(world, binding, &original)?.is_none()
            {
                return Err(fail("reward entitlement beneficiary history differs").into());
            }
            history::add(outstanding.entry(original).or_default(), *amount)?;
            history::add(&mut credited, *amount)?;
        }
    }
    for intervals in intervals.values_mut() {
        intervals.sort_unstable();
        if intervals.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(fail("reward entitlement intervals overlap").into());
        }
    }
    for claim in claims.values() {
        let revision_key = validation_fee_beneficiary_revision_key(
            binding,
            &claim.beneficiary_id,
            claim.beneficiary_revision,
        )
        .map_err(fail)?;
        let revision: ValidationFeeRewardBeneficiaryRevision =
            read_from_world(world, &revision_key)?
                .ok_or_else(|| fail("reward claim beneficiary revision is missing"))?;
        if revision.beneficiary_id != claim.beneficiary_id
            || revision.revision != claim.beneficiary_revision
            || revision.account_id != claim.account_id
            || revision.authorized_at_height > claim.claimed_at_height
            || beneficiary::root_in_world(world, binding, &claim.account_id)?
                != claim.beneficiary_id
        {
            return Err(fail("reward claim beneficiary revision is inconsistent").into());
        }
        let balance = outstanding
            .get_mut(&claim.beneficiary_id)
            .ok_or_else(|| fail("reward claim has no entitlement"))?;
        *balance = balance
            .checked_sub(&BigInt::from(claim.xor_minor))
            .map_err(|error| fail(error.to_string()))?;
        history::add(&mut paid, claim.xor_minor)?;
    }
    let unmaterialized = difference(&funded, &credited)?;
    if let Some(cursor) = &cursor {
        let allocation = allocations
            .get(&cursor.allocation_sequence)
            .ok_or_else(|| fail("reward cursor lacks funded allocation"))?;
        if cursor.allocation_sequence.checked_add(1) != Some(state.next_allocation) {
            return Err(fail("reward cursor is not latest funding").into());
        }
        let index = usize::try_from(cursor.validator_index)
            .map_err(|_| fail("reward cursor validator index overflow"))?;
        let (validator, total) = allocation
            .service_blocks
            .iter()
            .nth(index)
            .ok_or_else(|| fail("reward cursor validator absent"))?;
        let remaining = total
            .checked_sub(cursor.service_offset)
            .ok_or_else(|| fail("reward cursor service offset exceeds source"))?;
        let gross = allocation.gross_shares[validator];
        let expected = allocation
            .service_blocks
            .keys()
            .take(index)
            .try_fold(0u128, |sum, validator| {
                add(sum, allocation.gross_shares[validator])
            })?
            .checked_add(
                gross
                    .checked_sub(cumulative(gross, remaining, *total)?)
                    .ok_or_else(|| fail("reward cursor cumulative underflow"))?,
            )
            .ok_or_else(|| fail("reward cursor credit overflow"))?;
        if expected != cursor.credited_xor
            || allocation.xor_minor.checked_sub(expected) != Some(unmaterialized)
            || match &cursor.next_archive {
                None => cursor.service_offset != 0 || cursor.page_index != 0,
                Some(reference) => {
                    cursor.service_offset == 0
                        || reference.recorded_at_height == 0
                        || reference.page_index != cursor.page_index
                        || reference.service_start >= remaining
                }
            }
        {
            return Err(
                fail("reward allocation cursor differs from credited historical suffix").into(),
            );
        }
    } else if unmaterialized != 0 {
        return Err(fail("funded reward lacks allocation cursor").into());
    }
    let expected_claimable = outstanding
        .into_iter()
        .filter(|(_, amount)| !amount.is_zero())
        .map(|(original, amount)| {
            let amount = amount
                .try_to_u128()
                .ok_or_else(|| fail("current reward entitlement is negative or oversized"))?;
            Ok((claimable_key(binding, &original)?, amount))
        })
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    let unpaid = expected_claimable
        .values()
        .try_fold(0u128, |sum, amount| add(sum, *amount))?;
    if actual_claimable != expected_claimable
        || difference(&funded, &paid)? != state.reserved_xor
        || add(unpaid, unmaterialized)? != state.reserved_xor
    {
        return Err(fail(
            "claimable rewards do not reconcile with archived funding and hot entitlements",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation_fee_rewards::tests::{account, seed_service};
    use iroha_data_model::IntoKeyValue;

    fn fund_two_validators(
        stx: &mut StateTransaction<'_, '_>,
    ) -> ValidationFeeTreasuryPayoutBindingV1 {
        let binding = active_bindings(stx).unwrap().remove(0);
        let period = earning_month(stx.block_unix_timestamp_ms() - 31 * DAY_MS).unwrap();
        let weights = BTreeMap::from([(account(2), 2u64), (account(3), 1u64)]);
        seed_service(stx, &binding, period, &weights);
        write(stx, pending_key(&binding, period).unwrap(), &10u64).unwrap();
        save_state(
            stx,
            &binding,
            &ValidationFeeRewardsState {
                pending_sbd_total: 10,
                ..Default::default()
            },
        )
        .unwrap();
        let asset = AssetId::new(
            binding.xor_asset_id.clone(),
            binding.reward_pool_account_id.clone(),
        );
        let (_, value) = Asset::new(asset.clone(), quantity(101, 9).unwrap()).into_key_value();
        stx.world.assets.insert(asset, value);
        reserve_conversion(
            stx,
            &binding,
            &ConversionOffer {
                earning_period_start_ms: period,
                sbd_minor: 10,
                min_xor_minor: 101,
                sequence: 0,
            },
            101,
        )
        .unwrap();
        binding
    }

    #[test]
    fn funded_reward_restore_accepts_cursor_credit_and_bounded_source_pruning() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            validate(&stx.world, &binding).unwrap();
            assert!(!settlement::prune_completed_history(stx, &binding).unwrap());
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            validate(&stx.world, &binding).unwrap();
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            assert!(
                read::<settlement::RewardAllocationCursor>(
                    stx,
                    &state_key(&binding, "AllocationCursor").unwrap()
                )
                .unwrap()
                .is_none()
            );
            validate(&stx.world, &binding).unwrap();
            let allocation: ValidationFeeRewardAllocation =
                read(stx, &state_key(&binding, "Allocation/0").unwrap())
                    .unwrap()
                    .unwrap();
            let period = allocation.earning_period_start_ms;
            assert!(crate::retail_fee::reward_history_is_closed(stx, period).unwrap());
            assert!(
                !settlement::prune_completed_history(stx, &binding).unwrap(),
                "a resident tail must be authenticated and cooled before head retirement"
            );
            // Represent already authenticated cooling. The original archive
            // reader and the native cooling path have separate certified tests.
            for validator in allocation.service_blocks.keys() {
                let head_key = exposure::head_key(&binding, period, validator).unwrap();
                let mut head: ValidationFeeExposureHead = read(stx, &head_key).unwrap().unwrap();
                let page_key =
                    exposure::page_key(&binding, period, validator, head.latest.page_index)
                        .unwrap();
                let archive_key =
                    exposure::archive_key(&binding, period, validator, head.latest.page_index)
                        .unwrap();
                assert!(stx.world.smart_contract_state.remove(page_key).is_some());
                assert!(stx.world.smart_contract_state.remove(archive_key).is_some());
                head.tail_resident = false;
                write(stx, head_key, &head).unwrap();
            }
            validate(&stx.world, &binding).unwrap();
            let prefix = state_key(&binding, &format!("ExposureHead/{period:020}/")).unwrap();
            let summary = service_key(&binding, period).unwrap();
            for remaining in (0..allocation.service_blocks.len()).rev() {
                let before = stx
                    .world
                    .smart_contract_state
                    .iter()
                    .filter(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
                    .map(|(key, _)| key.clone())
                    .collect::<BTreeSet<_>>();
                assert!(settlement::prune_completed_history(stx, &binding).unwrap());
                let after = stx
                    .world
                    .smart_contract_state
                    .iter()
                    .filter(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
                    .map(|(key, _)| key.clone())
                    .collect::<BTreeSet<_>>();
                assert_eq!(after.len(), remaining);
                assert_eq!(before.difference(&after).count(), 1);
                assert!(after.is_subset(&before));
                assert!(stx.world.smart_contract_state.get(&summary).is_some());
                validate(&stx.world, &binding).unwrap();
            }
            assert!(settlement::prune_completed_history(stx, &binding).unwrap());
            assert!(stx.world.smart_contract_state.get(&summary).is_none());
            assert!(!settlement::prune_completed_history(stx, &binding).unwrap());
            validate(&stx.world, &binding).unwrap();
            assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 101);
            assert!(!settlement::accrue_next_page(stx, &binding).unwrap());
        });
    }

    #[test]
    fn restore_rejects_forged_claimable_cursor_and_entitlement_without_consuming_credit() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            let cursor_key = state_key(&binding, "AllocationCursor").unwrap();
            let cursor: settlement::RewardAllocationCursor =
                read(stx, &cursor_key).unwrap().unwrap();
            let mut forged = cursor.clone();
            forged.credited_xor = 1;
            write(stx, cursor_key.clone(), &forged).unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            let mut forged = cursor.clone();
            forged.page_index = 1;
            write(stx, cursor_key.clone(), &forged).unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            write(stx, cursor_key, &cursor).unwrap();
            settlement::accrue_next_page(stx, &binding).unwrap();
            validate(&stx.world, &binding).unwrap();
            let allocation: ValidationFeeRewardAllocation =
                read(stx, &state_key(&binding, "Allocation/0").unwrap())
                    .unwrap()
                    .unwrap();
            let validator = allocation.service_blocks.keys().next().unwrap();
            let entitlement_key =
                validation_fee_entitlement_key(&binding, 0, validator, 0).unwrap();
            let receipt: ValidationFeeRewardEntitlement =
                read(stx, &entitlement_key).unwrap().unwrap();
            let mut forged = receipt.clone();
            forged.service_start = 1;
            stx.world
                .smart_contract_state
                .insert(entitlement_key.clone(), norito::to_bytes(&forged).unwrap());
            assert!(validate(&stx.world, &binding).is_err());
            stx.world
                .smart_contract_state
                .insert(entitlement_key, norito::to_bytes(&receipt).unwrap());
            let source_key = exposure::source_key(
                &binding,
                receipt.recorded_at_height,
                &receipt.validator,
                receipt.page_index,
            )
            .unwrap();
            let original_source = stx
                .world
                .smart_contract_state
                .get(&source_key)
                .unwrap()
                .clone();
            let mut substituted: ValidationFeeExposurePage =
                norito::decode_from_bytes(&original_source).unwrap();
            substituted.earning_period_start_ms -= DAY_MS;
            let journal_key = state_key(
                &binding,
                &format!(
                    "HistoryJournal/{:020}/{}",
                    receipt.recorded_at_height,
                    hex::encode(Hash::new(source_key.as_ref().as_bytes()).as_ref()),
                ),
            )
            .unwrap();
            let original_journal = stx
                .world
                .smart_contract_state
                .remove(journal_key.clone())
                .unwrap();
            // Forge both the source and its journal hash: exact source identity,
            // beyond byte-integrity alone, must still reject this snapshot.
            write(stx, source_key.clone(), &substituted).unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            stx.world
                .smart_contract_state
                .insert(source_key, original_source);
            stx.world
                .smart_contract_state
                .insert(journal_key, original_journal);
            let credit_key = claimable_key(&binding, validator).unwrap();
            let credit: u128 = read(stx, &credit_key).unwrap().unwrap();
            write(stx, credit_key.clone(), &(credit + 1)).unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            write(stx, credit_key, &credit).unwrap();
            validate(&stx.world, &binding).unwrap();
            assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 101);
        });
    }

    #[test]
    fn restore_requires_retirement_journal_before_accepting_funded_rights() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            validate(&stx.world, &binding).unwrap();
            let prefix = state_key(&binding, "HistoryJournal/").unwrap();
            let (key, bytes) = stx
                .world
                .smart_contract_state
                .range(prefix.clone()..)
                .find(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .unwrap();
            stx.world.smart_contract_state.remove(key.clone());
            assert!(validate(&stx.world, &binding).is_err());
            stx.world.smart_contract_state.insert(key, bytes);
            validate(&stx.world, &binding).unwrap();
            assert_eq!(read_state(stx, &binding).unwrap().reserved_xor, 101);
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            validate(&stx.world, &binding).unwrap();
        });
    }

    #[test]
    fn restart_requires_complete_unfinished_sources_and_consecutive_funded_sequences() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            let mut state = read_state(stx, &binding).unwrap();
            state.next_allocation = 2;
            save_state(stx, &binding, &state).unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            state.next_allocation = 1;
            save_state(stx, &binding, &state).unwrap();
            let allocation: ValidationFeeRewardAllocation =
                read(stx, &state_key(&binding, "Allocation/0").unwrap())
                    .unwrap()
                    .unwrap();
            let validator = allocation.service_blocks.keys().next().unwrap();
            let page_key =
                exposure::page_key(&binding, allocation.earning_period_start_ms, validator, 0)
                    .unwrap();
            let page = stx
                .world
                .smart_contract_state
                .remove(page_key.clone())
                .unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            stx.world.smart_contract_state.insert(page_key, page);
            validate(&stx.world, &binding).unwrap();
        });
    }

    #[test]
    fn restart_requires_unsealed_sources_even_without_pending_funding() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            let allocation: ValidationFeeRewardAllocation =
                read(stx, &state_key(&binding, "Allocation/0").unwrap())
                    .unwrap()
                    .unwrap();
            let period = allocation.earning_period_start_ms;
            assert!(
                read::<u64>(stx, &pending_key(&binding, period).unwrap())
                    .unwrap()
                    .is_none()
            );
            assert!(
                crate::retail_fee::reward_history_closed_through(&stx.world)
                    .unwrap()
                    .is_none()
            );
            validate(&stx.world, &binding).unwrap();

            let service_key = service_key(&binding, period).unwrap();
            let service = stx
                .world
                .smart_contract_state
                .remove(service_key.clone())
                .unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            stx.world.smart_contract_state.insert(service_key, service);
            let validator = allocation.service_blocks.keys().next().unwrap();
            let page_key = exposure::page_key(&binding, period, validator, 0).unwrap();
            let page = stx
                .world
                .smart_contract_state
                .remove(page_key.clone())
                .unwrap();
            assert!(
                validate(&stx.world, &binding).is_err(),
                "an unsealed month can still receive authentic late fees"
            );
            stx.world
                .smart_contract_state
                .insert(page_key.clone(), page);
            assert!(crate::retail_fee::reward_history_is_closed(stx, period).unwrap());
            assert_eq!(
                crate::retail_fee::reward_history_closed_through(&stx.world).unwrap(),
                Some(period)
            );
            let page = stx
                .world
                .smart_contract_state
                .remove(page_key.clone())
                .unwrap();
            assert!(
                validate(&stx.world, &binding).is_err(),
                "a resident head always requires its complete hot pair"
            );
            stx.world.smart_contract_state.insert(page_key, page);
            validate(&stx.world, &binding).unwrap();
        });
    }

    #[test]
    fn compacted_outstanding_balance_requires_its_retained_beneficiary_owner() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = fund_two_validators(stx);
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            assert!(settlement::accrue_next_page(stx, &binding).unwrap());
            let checkpoint = history::Checkpoint {
                height: stx.block_height(),
                next_allocation: 1,
                next_claim: 0,
                funded: BigInt::from(101_u32),
                credited: BigInt::from(101_u32),
                paid: BigInt::default(),
                archive_chain: Some(Hash::new(b"component checkpoint original commitment")),
            };
            for beneficiary in [account(2), account(3)] {
                let amount = read::<u128>(stx, &claimable_key(&binding, &beneficiary).unwrap())
                    .unwrap()
                    .unwrap();
                write(
                    stx,
                    history::balance_key(&binding, &beneficiary).unwrap(),
                    &history::Balance {
                        beneficiary,
                        amount,
                    },
                )
                .unwrap();
            }
            // Seed the compacted representation for this restore-only corruption
            // check; certified native archive retirement is tested separately.
            write(
                stx,
                state_key(&binding, "HistoryCheckpoint").unwrap(),
                &checkpoint,
            )
            .unwrap();
            let prefix = state_key(&binding, "").unwrap();
            let retired = stx
                .world
                .smart_contract_state
                .iter()
                .filter_map(|(key, _)| {
                    let suffix = key.as_ref().strip_prefix(prefix.as_ref())?;
                    [
                        "Allocation/",
                        "Entitlement/",
                        "ExposureSource/",
                        "HistoryJournal/",
                    ]
                    .iter()
                    .any(|family| suffix.starts_with(family))
                    .then(|| key.clone())
                })
                .collect::<Vec<_>>();
            for key in retired {
                stx.world.smart_contract_state.remove(key);
            }
            validate(&stx.world, &binding).unwrap();
            let revision =
                validation_fee_beneficiary_revision_key(&binding, &account(2), 0).unwrap();
            let bytes = stx
                .world
                .smart_contract_state
                .remove(revision.clone())
                .unwrap();
            assert!(validate(&stx.world, &binding).is_err());
            stx.world.smart_contract_state.insert(revision, bytes);
            validate(&stx.world, &binding).unwrap();
            let original = account(2);
            let recovered = account(4);
            for current in [&original, &recovered] {
                if current == &recovered {
                    beneficiary::rekey_beneficiary(stx, &original, &recovered).unwrap();
                }
                let key = validation_fee_beneficiary_alias_key(&binding, current).unwrap();
                let bytes = stx.world.smart_contract_state.remove(key.clone()).unwrap();
                assert!(validate(&stx.world, &binding).is_err());
                let substituted = ValidationFeeRewardBeneficiaryAlias {
                    account_id: current.clone(),
                    beneficiary_id: account(3),
                };
                stx.world
                    .smart_contract_state
                    .insert(key.clone(), norito::to_bytes(&substituted).unwrap());
                assert!(validate(&stx.world, &binding).is_err());
                stx.world.smart_contract_state.insert(key, bytes);
                validate(&stx.world, &binding).unwrap();
            }
        });
    }

    #[test]
    fn lifetime_reward_turnover_can_exceed_current_balance_width() {
        use crate::validation_fee_rewards::tests::{
            fund_test_conversion, record_test_service, signed_claim_all,
        };

        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let period = earning_month(stx.block_unix_timestamp_ms() - 60 * DAY_MS).unwrap();
            let claimant = account(2);
            record_test_service(stx, &binding, period, &claimant, &[(2, 1)]);
            for sequence in 0..2 {
                fund_test_conversion(stx, &binding, period, u128::MAX);
                assert!(settlement::accrue_next_page(stx, &binding).unwrap());
                validate(&stx.world, &binding)
                    .expect("prior claimed turnover does not overflow live entitlement audit");
                signed_claim_all(stx, &binding, &claimant);
                let state = read_state(stx, &binding).unwrap();
                assert_eq!(state.reserved_xor, 0);
                assert_eq!(state.next_allocation, sequence + 1);
                assert_eq!(state.next_claim, sequence + 1);
                validate(&stx.world, &binding)
                    .expect("fully claimed lifetime turnover remains exactly reconcilable");
            }
            let balance = stx
                .world
                .assets
                .get(&AssetId::new(binding.xor_asset_id.clone(), claimant))
                .unwrap();
            let once = quantity(u128::MAX, 9).unwrap();
            assert_eq!(balance.as_ref(), &once.checked_add(&once).unwrap());
        });
    }

    #[test]
    fn exact_restore_arithmetic_does_not_overflow_before_division() {
        assert_eq!(
            cumulative(u128::MAX, u64::MAX, u64::MAX).unwrap(),
            u128::MAX
        );
        assert!(cumulative(1, 1, 0).is_err());
        assert!(cumulative(1, 2, 1).is_err());
        assert!(add(u128::MAX, 1).is_err());
        let mut lifetime = BigInt::from(u128::MAX);
        history::add(&mut lifetime, u128::MAX).unwrap();
        assert_eq!(
            lifetime,
            BigInt::from(u128::MAX)
                .checked_mul(&BigInt::from(2_u32))
                .unwrap()
        );
    }
}
