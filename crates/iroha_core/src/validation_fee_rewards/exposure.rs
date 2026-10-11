//! Bounded historical staking exposure captured at authenticated finalized service.

#[cfg(test)]
#[path = "exposure_archive_tests.rs"]
mod archive_tests;
#[cfg(test)]
#[path = "exposure_budget_tests.rs"]
mod budget_tests;
#[cfg(test)]
#[path = "exposure_restart_tests.rs"]
mod restart_tests;
#[cfg(test)]
#[path = "exposure_service_tests.rs"]
mod service_tests;

use super::*;
use iroha_data_model::validation_fee_rewards::{
    MAX_REWARD_EXPOSURE_BYTES, MAX_REWARD_EXPOSURE_COHORTS, MAX_REWARD_EXPOSURE_ENTRIES,
    MAX_REWARD_RECIPIENTS, MAX_REWARD_VALIDATORS, ValidationFeeExposureArchive,
    ValidationFeeExposureArchiveRef, ValidationFeeExposureHead, ValidationFeeExposurePage,
    ValidationFeeRewardExposure, validate_reward_identity,
};

/// Validate optional staking and reward recovery before creating historical obligations.
pub(crate) fn ensure_reward_identity(account: &AccountId) -> Result<(), Error> {
    validate_reward_identity(account).map_err(fail)
}

/// Admission audit before enabling funded reward service on existing stake.
pub(crate) fn ensure_existing_reward_identities(world: &impl WorldReadOnly) -> Result<(), Error> {
    for ((_, validator), row) in world.public_lane_validators().iter() {
        ensure_reward_identity(validator)?;
        ensure_reward_identity(&row.validator)?;
    }
    for ((_, validator, staker), row) in world.public_lane_stake_shares().iter() {
        ensure_reward_identity(validator)?;
        ensure_reward_identity(staker)?;
        ensure_reward_identity(&row.validator)?;
        ensure_reward_identity(&row.staker)?;
    }
    Ok(())
}

/// Parent-block bonded stake keyed by its canonical staking owner and validator.
pub(crate) type HistoricalStake = BTreeMap<(LaneId, AccountId), BTreeMap<AccountId, Quantity>>;

/// Reconstruct the exact parent post-state, including positions removed or
/// recovered by the block currently being executed. Pending unbonds are excluded:
/// scheduling an unbond stops earning at that committed block's reward boundary.
pub(crate) fn before_block(
    block: &StateBlock<'_>,
    validators: &BTreeMap<LaneId, BTreeSet<AccountId>>,
) -> Result<HistoricalStake, Error> {
    if validators.is_empty() {
        return Ok(HistoricalStake::new());
    }
    let keys: BTreeSet<_> = block
        .world
        .public_lane_stake_shares
        .iter()
        .map(|(key, _)| key)
        .chain(block.world.public_lane_stake_shares.revert_map().keys())
        .filter(|key| {
            validators
                .get(&key.0)
                .is_some_and(|accounts| accounts.contains(&key.1))
        })
        .cloned()
        .collect();
    let mut exposure = HistoricalStake::new();
    for key in keys {
        let Some(share) = block.world.public_lane_stake_shares.get_before_block(&key) else {
            continue;
        };
        if share.lane_id != key.0 || share.validator != key.1 || share.staker != key.2 {
            return Err(fail(
                "historical reward stake share has a non-canonical identity",
            ));
        }
        if !share.bonded.is_zero() {
            exposure
                .entry((key.0, key.1))
                .or_default()
                .insert(key.2, share.bonded.clone());
        }
    }
    Ok(exposure)
}

fn validator_digest(validator: &AccountId) -> String {
    hex::encode(Hash::new(validator.to_string().as_bytes()).as_ref())
}

/// Protected bounded exposure page for one validator and original earning month.
pub(super) fn page_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    page: u64,
) -> Result<StatePath, Error> {
    iroha_data_model::validation_fee_rewards::validation_fee_exposure_page_key(
        binding, period, validator, page,
    )
    .map_err(fail)
}

pub(super) fn head_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
) -> Result<StatePath, Error> {
    state_key(
        binding,
        &format!("ExposureHead/{period:020}/{}", validator_digest(validator)),
    )
}

/// Fixed-size tail reference; older pages live only in authenticated original writes.
pub(super) fn head(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
) -> Result<Option<ValidationFeeExposureHead>, Error> {
    read(stx, &head_key(binding, period, validator)?)
}

pub(super) fn archive_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    page: u64,
) -> Result<StatePath, Error> {
    iroha_data_model::validation_fee_rewards::validation_fee_exposure_archive_key(
        binding, period, validator, page,
    )
    .map_err(fail)
}

/// Retrieve the exact hot tail or its original authenticated cold projection.
pub(super) fn load_archive(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    reference: &ValidationFeeExposureArchiveRef,
) -> Result<ValidationFeeExposureArchive, Error> {
    let key = archive_key(binding, period, validator, reference.page_index)?;
    let archive = match stx.world.smart_contract_state.get(&key) {
        Some(bytes) if Hash::new(bytes) == reference.archive_hash => {
            norito::decode_canonical(bytes).map_err(|error| {
                stx.world
                    .attempt_error_to_instruction_error(norito_decode_attempt_error(
                        error,
                        |error| fail(error.to_string()),
                    ))
            })?
        }
        _ => crate::query::native_receipts::committed_reward_exposure(
            stx,
            reference.recorded_at_height,
            &key,
            reference.archive_hash,
        )
        .map_err(|error| string_attempt_instruction_error(stx, error))?,
    };
    iroha_data_model::validation_fee_rewards::validate_exposure_archive(&archive).map_err(fail)?;
    if archive.page.earning_period_start_ms != period
        || archive.page.validator != *validator
        || archive.page.page_index != reference.page_index
        || (reference.page_index == 0) != archive.previous.is_none()
        || archive.previous.as_ref().is_some_and(|previous| {
            previous.page_index.checked_add(1) != Some(reference.page_index)
                || previous.service_start >= reference.service_start
                || previous.recorded_at_height >= reference.recorded_at_height
        })
    {
        return Err(fail(
            "archived reward exposure identity or predecessor differs",
        ));
    }
    Ok(archive)
}

fn service_count(page: &ValidationFeeExposurePage) -> Result<u64, Error> {
    page.exposure.iter().try_fold(0_u64, |sum, cohort| {
        sum.checked_add(cohort.service_blocks)
            .ok_or_else(|| fail("reward exposure service count overflow"))
    })
}

fn persist_tail(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    archive: ValidationFeeExposureArchive,
    service_start: u64,
) -> Result<(), Error> {
    iroha_data_model::validation_fee_rewards::validate_exposure_archive(&archive).map_err(fail)?;
    if archive
        .previous
        .as_ref()
        .is_some_and(|previous| previous.recorded_at_height >= stx.block_height())
    {
        return Err(fail(
            "reward exposure predecessor must be an earlier committed block",
        ));
    }
    let page = &archive.page;
    let service_total = service_start
        .checked_add(service_count(page)?)
        .ok_or_else(|| fail("reward exposure total service overflow"))?;
    let bytes = norito::to_bytes(&archive).map_err(|error| fail(error.to_string()))?;
    let latest = ValidationFeeExposureArchiveRef {
        recorded_at_height: stx.block_height(),
        page_index: page.page_index,
        service_start,
        archive_hash: Hash::new(&bytes),
    };
    let head = ValidationFeeExposureHead {
        page_count: page
            .page_index
            .checked_add(1)
            .ok_or_else(|| fail("reward exposure page sequence exhausted"))?,
        service_total,
        latest,
        tail_resident: true,
    };
    write(
        stx,
        page_key(
            binding,
            page.earning_period_start_ms,
            &page.validator,
            page.page_index,
        )?,
        page,
    )?;
    stx.world.smart_contract_state.insert(
        archive_key(
            binding,
            page.earning_period_start_ms,
            &page.validator,
            page.page_index,
        )?,
        bytes,
    );
    write(
        stx,
        head_key(binding, page.earning_period_start_ms, &page.validator)?,
        &head,
    )
}

/// One block's monetary proof source. The following block retires these bounded rows.
pub(super) fn source_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    height: u64,
    validator: &AccountId,
    page: u64,
) -> Result<StatePath, Error> {
    state_key(
        binding,
        &format!(
            "ExposureSource/{height:020}/{}/{page:020}",
            validator_digest(validator)
        ),
    )
}

/// Copy each changed tail into the original native archive, independently of the
/// monetary fee corpus. At most one tail per authenticated committee signer changes.
pub(super) fn capture_archive(
    block: &StateBlock<'_>,
    witness: &mut iroha_data_model::block::consensus::ExecWitness,
) -> Result<(), String> {
    use iroha_data_model::execution_witness::REWARD_EXPOSURE_ARCHIVE_TAG_V1;
    witness
        .writes
        .retain(|write| write.key.first() != Some(&REWARD_EXPOSURE_ARCHIVE_TAG_V1));
    let mut count = 0_usize;
    let mut total_bytes = 0_usize;
    // The block undo root contains each applied transaction's touched key once,
    // in canonical order. Rolled-back transaction writes never enter this map.
    for key in block.world.smart_contract_state.revert_map().keys() {
        if !is_reserved_state_key(key) || !key.as_ref().contains("/ExposureArchive/") {
            continue;
        }
        let Some(bytes) = block.world.smart_contract_state.get(key) else {
            continue;
        };
        count += 1;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or("reward archive byte count overflow")?;
        if count > 31 || total_bytes > 4 * 1024 * 1024 {
            return Err(
                "reward archive projection exceeds the bounded committee source budget".into(),
            );
        }
        witness.writes.push(iroha_data_model::block::consensus::ExecKv {
            key: iroha_data_model::validation_fee_rewards::validation_fee_exposure_archive_witness_key(key).to_vec(),
            value: bytes.clone(),
        });
    }
    Ok(())
}

/// Bound the original-month service roster at optional validator admission.
/// Include scheduled validators and block-start registrations removed by earlier
/// sibling transactions, so later mandatory finality never discovers overflow.
pub(crate) fn ensure_validator_capacity(
    stx: &StateTransaction<'_, '_>,
    lane: LaneId,
    candidate: &AccountId,
) -> Result<(), Error> {
    let bindings = active_bindings(stx)?;
    if bindings.is_empty() {
        return Ok(());
    }
    let period = earning_month(stx.block_unix_timestamp_ms())?;
    for binding in bindings {
        if stx.staking_authority_lane(binding.validator_lane_id) != Some(lane) {
            continue;
        }
        let mut roster = service_snapshot(stx, &binding, period)?
            .service_blocks
            .into_keys()
            .collect::<BTreeSet<_>>();
        let keys = stx
            .world
            .public_lane_validators
            .iter()
            .map(|(key, _)| key.clone())
            .chain(
                stx.world
                    .public_lane_validators
                    .changed_keys_in_block()
                    .cloned(),
            )
            .filter(|key| key.0 == lane)
            .collect::<BTreeSet<_>>();
        for key in keys {
            if stx.world.public_lane_validators.get(&key).is_some()
                || stx
                    .world
                    .public_lane_validators
                    .get_before_block(&key)
                    .is_some()
            {
                roster.insert(beneficiary::root(stx, &binding, &key.1)?);
            }
        }
        roster.insert(beneficiary::root(stx, &binding, candidate)?);
        ensure_roster_bound(&roster)?;
    }
    Ok(())
}

fn ensure_roster_bound(roster: &BTreeSet<AccountId>) -> Result<(), Error> {
    if roster.len() > MAX_REWARD_VALIDATORS {
        return Err(fail(
            "earning month reached maximum distinct reward validators",
        ));
    }
    Ok(())
}

/// Append in chronological order; only adjacent identical snapshots coalesce.
/// Returning false requests a fresh page and leaves the previous page untouched.
fn append(
    page: &mut ValidationFeeExposurePage,
    stakes: &BTreeMap<AccountId, Quantity>,
) -> Result<bool, Error> {
    if stakes.is_empty()
        || stakes.values().any(Quantity::is_zero)
        || stakes.len() > MAX_REWARD_RECIPIENTS
    {
        return Err(fail(
            "reward exposure requires bounded positive eligible stakes",
        ));
    }
    for account in stakes.keys() {
        ensure_reward_identity(account)?;
    }
    if let Some(last) = page.exposure.last_mut()
        && last.stakes == *stakes
    {
        last.service_blocks = last
            .service_blocks
            .checked_add(1)
            .ok_or_else(|| fail("validator exposure service counter overflow"))?;
        return Ok(true);
    }
    let entries = page
        .exposure
        .iter()
        .try_fold(stakes.len(), |count, cohort| {
            count.checked_add(cohort.stakes.len())
        })
        .ok_or_else(|| fail("reward exposure entry count overflow"))?;
    let recipients: BTreeSet<_> = page
        .exposure
        .iter()
        .flat_map(|cohort| cohort.stakes.keys())
        .chain(stakes.keys())
        .collect();
    if page.exposure.len() >= MAX_REWARD_EXPOSURE_COHORTS
        || entries > MAX_REWARD_EXPOSURE_ENTRIES
        || recipients.len() > MAX_REWARD_RECIPIENTS
    {
        return Ok(false);
    }
    page.exposure.push(ValidationFeeRewardExposure {
        service_blocks: 1,
        stakes: stakes.clone(),
    });
    let size = norito::to_bytes(page)
        .map_err(|error| fail(error.to_string()))?
        .len();
    if size > MAX_REWARD_EXPOSURE_BYTES {
        page.exposure.pop();
        return Ok(false);
    }
    Ok(true)
}

/// Persist one service's exact distribution. Full pages roll over so mandatory
/// penalties and committee retention never depend on an optional mutation budget.
pub(super) fn record_service(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    mut stakes: BTreeMap<AccountId, Quantity>,
) -> Result<(), Error> {
    ensure_reward_identity(validator)?;
    // A retained committee member can still supply service after every bonded
    // unit was unbonded or slashed. Its zero-stake gross remains its own reward.
    if stakes.is_empty() {
        stakes.insert(validator.clone(), Quantity::one());
    }
    if let Some(head) = head(stx, binding, period, validator)? {
        let mut archive = load_archive(stx, binding, period, validator, &head.latest)?;
        if archive.page.page_index.checked_add(1) != Some(head.page_count)
            || head
                .latest
                .service_start
                .checked_add(service_count(&archive.page)?)
                != Some(head.service_total)
        {
            return Err(fail("reward exposure head differs from its current tail"));
        }
        if append(&mut archive.page, &stakes)? {
            return persist_tail(stx, binding, archive, head.latest.service_start);
        }
        // The previous block already archived the exact sealed predecessor. There
        // is never a resident array of page locations or an archive work backlog.
        if head.latest.recorded_at_height == stx.block_height() {
            return Err(fail(
                "one validator cannot roll over multiple exposure pages in one service block",
            ));
        }
        let mut page = ValidationFeeExposurePage {
            earning_period_start_ms: period,
            validator: validator.clone(),
            page_index: head.page_count,
            exposure: Vec::new(),
        };
        if !append(&mut page, &stakes)? {
            return Err(fail("single reward exposure exceeds page capacity"));
        }
        let old_page = page_key(binding, period, validator, head.latest.page_index)?;
        let old_archive = archive_key(binding, period, validator, head.latest.page_index)?;
        persist_tail(
            stx,
            binding,
            ValidationFeeExposureArchive {
                page,
                previous: Some(head.latest),
            },
            head.service_total,
        )?;
        stx.world.smart_contract_state.remove(old_page);
        stx.world.smart_contract_state.remove(old_archive);
        return Ok(());
    }
    let mut page = ValidationFeeExposurePage {
        earning_period_start_ms: period,
        validator: validator.clone(),
        page_index: 0,
        exposure: Vec::new(),
    };
    if !append(&mut page, &stakes)? {
        return Err(fail("single reward exposure exceeds page capacity"));
    }
    persist_tail(
        stx,
        binding,
        ValidationFeeExposureArchive {
            page,
            previous: None,
        },
        0,
    )
}

/// Seed a complete historical page for custody and evidence test fixtures.
#[cfg(test)]
pub(super) fn seed_page_for_testing(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    period: u64,
    validator: &AccountId,
    service_blocks: u64,
    stakes: BTreeMap<AccountId, Quantity>,
) {
    let page = ValidationFeeExposurePage {
        earning_period_start_ms: period,
        validator: validator.clone(),
        page_index: 0,
        exposure: vec![ValidationFeeRewardExposure {
            service_blocks,
            stakes,
        }],
    };
    iroha_data_model::validation_fee_rewards::validate_exposure_page(&page).unwrap();
    persist_tail(
        stx,
        binding,
        ValidationFeeExposureArchive {
            page,
            previous: None,
        },
        0,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::account::{MultisigMember, MultisigPolicy};
    use iroha_data_model::nexus::{PublicLaneStakeShare, PublicLaneUnbonding};
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    pub(super) fn multisig(seed: u32, members: u16) -> AccountId {
        AccountId::new_multisig(
            MultisigPolicy::new(
                1,
                (0..members)
                    .map(|index| {
                        let bytes = [
                            seed.to_le_bytes().as_slice(),
                            index.to_le_bytes().as_slice(),
                        ]
                        .concat();
                        MultisigMember::new(
                            iroha_crypto::KeyPair::from_seed(
                                bytes,
                                iroha_crypto::Algorithm::Ed25519,
                            )
                            .public_key()
                            .clone(),
                            1,
                        )
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn encoded_byte_capacity_rolls_over_before_entry_capacity() {
        let member_count = (1..16)
            .filter(|count| ensure_reward_identity(&multisig(0, *count)).is_ok())
            .last()
            .unwrap();
        let mut stakes = (0..MAX_REWARD_RECIPIENTS)
            .map(|index| (multisig(index as u32, member_count), Quantity::one()))
            .collect::<BTreeMap<_, _>>();
        let mut source = page();
        for index in 1..=MAX_REWARD_EXPOSURE_ENTRIES / MAX_REWARD_RECIPIENTS {
            let value: Quantity = format!("{}{}1", index, "0".repeat(150)).parse().unwrap();
            stakes.values_mut().for_each(|stake| *stake = value.clone());
            let previous = source.clone();
            if !append(&mut source, &stakes).unwrap() {
                assert_eq!(
                    source, previous,
                    "byte overflow leaves the old page unchanged"
                );
                assert!(
                    source.exposure.len() < MAX_REWARD_EXPOSURE_ENTRIES / MAX_REWARD_RECIPIENTS
                );
                iroha_data_model::validation_fee_rewards::validate_exposure_page(&source).unwrap();
                // A full tail still coalesces an unchanged stake cohort. The
                // fixed-width service counter cannot enlarge its canonical
                // encoding or move a rounding boundary to a successor page.
                let same = source.exposure.last().unwrap().stakes.clone();
                let prior_blocks = source.exposure.last().unwrap().service_blocks;
                let prior_size = norito::to_bytes(&source).unwrap().len();
                assert!(append(&mut source, &same).unwrap());
                assert_eq!(source.exposure.len(), previous.exposure.len());
                assert_eq!(
                    source.exposure.last().unwrap().service_blocks,
                    prior_blocks + 1
                );
                assert_eq!(norito::to_bytes(&source).unwrap().len(), prior_size);
                let mut successor = page();
                assert!(append(&mut successor, &stakes).unwrap());
                iroha_data_model::validation_fee_rewards::validate_exposure_page(&successor)
                    .unwrap();
                let mut oversized = source;
                oversized.exposure.extend(successor.exposure);
                assert!(norito::to_bytes(&oversized).unwrap().len() > MAX_REWARD_EXPOSURE_BYTES);
                assert!(
                    iroha_data_model::validation_fee_rewards::validate_exposure_page(&oversized)
                        .is_err()
                );
                return;
            }
        }
        panic!("maximum admitted identities and stakes must reach the byte cap first");
    }

    #[test]
    fn same_block_archive_predecessor_is_refused_before_hot_state_changes() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let period = earning_month(stx.block_unix_timestamp_ms()).unwrap();
            record_service(
                stx,
                &binding,
                period,
                &ALICE_ID,
                BTreeMap::from([(ALICE_ID.clone(), Quantity::one())]),
            )
            .unwrap();
            let original = head(stx, &binding, period, &ALICE_ID).unwrap().unwrap();
            let archive = ValidationFeeExposureArchive {
                page: ValidationFeeExposurePage {
                    earning_period_start_ms: period,
                    validator: ALICE_ID.clone(),
                    page_index: 1,
                    exposure: vec![ValidationFeeRewardExposure {
                        service_blocks: 1,
                        stakes: BTreeMap::from([(ALICE_ID.clone(), Quantity::one())]),
                    }],
                },
                previous: Some(original.latest.clone()),
            };
            assert!(persist_tail(stx, &binding, archive, original.service_total).is_err());
            assert_eq!(
                head(stx, &binding, period, &ALICE_ID).unwrap(),
                Some(original)
            );
            assert!(
                stx.world
                    .smart_contract_state
                    .get(&archive_key(&binding, period, &ALICE_ID, 1).unwrap())
                    .is_none()
            );
        });
    }

    #[test]
    fn oversized_reward_identities_are_refused_before_activation_or_recovery() {
        let oversized = multisig(99, 16);
        assert!(ensure_reward_identity(&oversized).is_err());
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            ensure_existing_reward_identities(&stx.world).unwrap();
            assert!(beneficiary::rekey_beneficiary(stx, &ALICE_ID, &oversized).is_err());
            assert!(beneficiary::rekey_beneficiary(stx, &oversized, &ALICE_ID).is_err());
            let binding = active_bindings(stx).unwrap().remove(0);
            assert_eq!(binding.invariant_error(), None);
            let mut oversized_binding = binding.clone();
            oversized_binding.reward_pool_account_id = oversized.clone();
            assert!(oversized_binding.invariant_error().is_some());
            let lane = binding.validator_lane_id;
            stx.world.public_lane_stake_shares.insert(
                (lane, ALICE_ID.clone(), oversized.clone()),
                PublicLaneStakeShare {
                    lane_id: lane,
                    validator: ALICE_ID.clone(),
                    staker: oversized,
                    bonded: Quantity::one(),
                    pending_unbonds: BTreeMap::new(),
                    metadata: Default::default(),
                },
            );
            assert!(ensure_existing_reward_identities(&stx.world).is_err());
        });
    }

    #[test]
    fn restart_rejects_oversized_unused_beneficiary_roots_and_owner_revisions() {
        use iroha_data_model::validation_fee_rewards::{
            ValidationFeeRewardBeneficiaryAlias, ValidationFeeRewardBeneficiaryRevision,
            validation_fee_beneficiary_alias_key, validation_fee_beneficiary_revision_key,
        };
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let oversized = multisig(99, 16);
            let alias_key = validation_fee_beneficiary_alias_key(&binding, &ALICE_ID).unwrap();
            write(
                stx,
                alias_key.clone(),
                &ValidationFeeRewardBeneficiaryAlias {
                    account_id: ALICE_ID.clone(),
                    beneficiary_id: oversized.clone(),
                },
            )
            .unwrap();
            assert!(reconciliation::validate(&stx.world, &binding).is_err());
            assert!(beneficiary::ensure(stx, &binding, &ALICE_ID).is_err());
            stx.world.smart_contract_state.remove(alias_key);
            let revision = ValidationFeeRewardBeneficiaryRevision {
                beneficiary_id: ALICE_ID.clone(),
                revision: 1,
                account_id: ALICE_ID.clone(),
                previous_account_id: Some(oversized),
                authorized_at_height: stx.block_height(),
            };
            write(
                stx,
                validation_fee_beneficiary_revision_key(&binding, &ALICE_ID, 1).unwrap(),
                &revision,
            )
            .unwrap();
            assert!(reconciliation::validate(&stx.world, &binding).is_err());
        });
    }

    fn page() -> ValidationFeeExposurePage {
        ValidationFeeExposurePage {
            earning_period_start_ms: 0,
            validator: ALICE_ID.clone(),
            page_index: 0,
            exposure: Vec::new(),
        }
    }

    #[test]
    fn changed_exposure_preserves_chronology_and_only_adjacent_snapshots_coalesce() {
        let mut page = page();
        let initial = BTreeMap::from([(ALICE_ID.clone(), Quantity::from(20u32))]);
        let nominated = BTreeMap::from([
            (ALICE_ID.clone(), Quantity::from(20u32)),
            (BOB_ID.clone(), Quantity::from(80u32)),
        ]);
        for stakes in [&initial, &initial, &nominated, &initial] {
            assert!(append(&mut page, stakes).unwrap());
        }
        assert_eq!(page.exposure.len(), 3);
        assert_eq!(page.exposure[0].service_blocks, 2);
        assert_eq!(page.exposure[0].stakes, initial);
        assert_eq!(page.exposure[1].stakes, nominated);
        assert_eq!(page.exposure[2].stakes, initial);
    }

    #[test]
    fn full_page_rollover_is_atomic_and_does_not_limit_future_changes() {
        let mut page = page();
        for index in 0..MAX_REWARD_EXPOSURE_COHORTS {
            if !append(
                &mut page,
                &BTreeMap::from([(ALICE_ID.clone(), Quantity::from((index + 1) as u64))]),
            )
            .unwrap()
            {
                break;
            }
        }
        let original = page.clone();
        let next = BTreeMap::from([(BOB_ID.clone(), Quantity::one())]);
        assert!(!append(&mut page, &next).unwrap());
        assert_eq!(page, original);
        let mut successor = ValidationFeeExposurePage {
            page_index: 1,
            exposure: Vec::new(),
            ..page
        };
        assert!(append(&mut successor, &next).unwrap());
        assert_eq!(successor.exposure[0].stakes, next);
    }

    #[test]
    fn rejected_zero_stake_does_not_mutate_service() {
        let mut page = page();
        let original = page.clone();
        assert!(
            append(
                &mut page,
                &BTreeMap::from([(ALICE_ID.clone(), Quantity::zero())])
            )
            .is_err()
        );
        assert_eq!(page, original);
    }

    #[test]
    fn optional_validator_registration_cannot_overfill_historical_service_roster() {
        let accounts = (0..=MAX_REWARD_VALIDATORS)
            .map(|index| {
                let key = iroha_crypto::KeyPair::try_from_seed(
                    index.to_le_bytes().to_vec(),
                    iroha_crypto::Algorithm::Ed25519,
                )
                .unwrap();
                AccountId::new(key.public_key().clone())
            })
            .collect::<Vec<_>>();
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _policy| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let period = earning_month(stx.block_unix_timestamp_ms()).unwrap();
            let snapshot = ValidationFeeServiceSnapshot {
                earning_period_start_ms: period,
                service_blocks: accounts[..MAX_REWARD_VALIDATORS]
                    .iter()
                    .cloned()
                    .map(|account| (account, 1))
                    .collect(),
            };
            write(stx, service_key(&binding, period).unwrap(), &snapshot).unwrap();
            ensure_validator_capacity(stx, LaneId::SINGLE, &accounts[0])
                .expect("re-registration of the same stable beneficiary does not grow history");
            assert!(
                ensure_validator_capacity(stx, LaneId::SINGLE, &accounts[MAX_REWARD_VALIDATORS])
                    .is_err()
            );
            assert_eq!(service_snapshot(stx, &binding, period).unwrap(), snapshot);
        });
    }

    #[test]
    fn historical_capture_survives_current_block_slash_exit_and_late_deposit() {
        use iroha_data_model::{
            Registrable,
            account::Account,
            asset::{AssetBalancePolicy, AssetDefinition},
            isi::{Mint, Register},
            nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus},
            parameter::{Parameter, system::SumeragiNposParameters},
        };
        let lane = LaneId::SINGLE;
        let make_share = |staker: AccountId, amount| PublicLaneStakeShare {
            lane_id: lane,
            validator: ALICE_ID.clone(),
            staker,
            bonded: Quantity::from(amount),
            pending_unbonds: BTreeMap::new(),
            metadata: Default::default(),
        };
        let mut validator = make_share(ALICE_ID.clone(), 20u32);
        let request_id = Hash::new("historical-unbond");
        validator.pending_unbonds.insert(
            request_id,
            PublicLaneUnbonding {
                request_id,
                amount: Quantity::from(80u32),
                release_at_ms: 50,
                slashable_through_height: 100,
                liability_release_height: 200,
            },
        );
        let world = crate::state::World::with(
            [],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&ALICE_ID),
            ],
            [],
        );
        let npos = SumeragiNposParameters::default();
        let asset = AssetId::new(npos.xor_asset_definition_id.clone(), ALICE_ID.clone());
        {
            let mut parameters = world.parameters.block();
            parameters.set_parameter(Parameter::Custom(npos.into_custom_parameter()));
            parameters.commit();
        }
        let self_key = (lane, ALICE_ID.clone(), ALICE_ID.clone());
        let nominator_key = (lane, ALICE_ID.clone(), BOB_ID.clone());
        let state = crate::state::State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        );
        {
            let mut block = state.block(iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::new(1).unwrap(),
                None,
                None,
                0,
                0,
            ));
            let mut stx = block.transaction();
            Register::asset_definition(AssetDefinition::new(
                asset.definition().clone(),
                "Reward exposure custody",
                iroha_primitives::numeric::NumericSpec::fractional(9),
                AssetBalancePolicy::Global,
                None,
            ))
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            Mint::asset_quantity(Quantity::from(130u32), asset.clone())
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.world.public_lane_validators.insert(
                (lane, ALICE_ID.clone()),
                PublicLaneValidatorRecord {
                    lane_id: lane,
                    validator: ALICE_ID.clone(),
                    peer_id: iroha_model_base::peer::PeerId::new(
                        ALICE_ID.expect_single_signatory().clone(),
                    ),
                    stake_account: ALICE_ID.clone(),
                    total_stake: Quantity::from(50u32),
                    self_stake: Quantity::from(20u32),
                    metadata: Default::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 1,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
            stx.world
                .public_lane_stake_shares
                .insert(self_key.clone(), validator.clone());
            stx.world
                .public_lane_stake_shares
                .insert(nominator_key.clone(), make_share(BOB_ID.clone(), 30u32));
            crate::smartcontracts::isi::staking::prepare_stake_custody_credit(
                &stx.world,
                lane,
                &ALICE_ID,
                &asset,
                &Quantity::from(130u32),
                &Quantity::from(130u32),
            )
            .unwrap()
            .apply(&mut stx.world);
            crate::state::validate_public_lane_stake_reserves_for_restore(&stx.world).unwrap();
            stx.apply();
            block.commit_world_overlay_for_testing().unwrap();
        }
        let mut block = state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(10).unwrap(),
            None,
            None,
            100,
            0,
        ));
        let expected = BTreeMap::from([(
            (lane, ALICE_ID.clone()),
            BTreeMap::from([
                (ALICE_ID.clone(), Quantity::from(20u32)),
                (BOB_ID.clone(), Quantity::from(30u32)),
            ]),
        )]);
        let selected = BTreeMap::from([(lane, BTreeSet::from([ALICE_ID.clone()]))]);
        assert_eq!(before_block(&block, &selected).unwrap(), expected);
        {
            let mut stx = block.transaction();
            validator.bonded = Quantity::from(1u32);
            stx.world
                .public_lane_stake_shares
                .insert(self_key, validator);
            stx.world.public_lane_stake_shares.remove(nominator_key);
            let late = crate::validation_fee_rewards::tests::account(99);
            stx.world.public_lane_stake_shares.insert(
                (lane, ALICE_ID.clone(), late.clone()),
                make_share(late, 500u32),
            );
            stx.apply();
        }
        assert_eq!(before_block(&block, &selected).unwrap(), expected);
    }
}
