//! Bounded hot reward receipts backed by the original authenticated native archive.

use super::*;
use iroha_data_model::{
    fee_evidence::{
        FeeEvidencePayloadV1 as Payload, FeeEvidenceRecordV1, MAX_FEE_EVIDENCE_RECORDS_V1,
    },
    validation_fee_rewards::ValidationFeeRewardEntitlement,
};
use iroha_primitives::bigint::BigInt;

/// Cumulative accounting at the last compacted original block.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::RewardHistoryCheckpoint")]
pub(super) struct Checkpoint {
    pub(super) height: u64,
    pub(super) next_allocation: u64,
    pub(super) next_claim: u64,
    pub(super) funded: BigInt,
    pub(super) credited: BigInt,
    pub(super) paid: BigInt,
    pub(super) archive_chain: Option<Hash>,
}

/// One outstanding original beneficiary balance at the compacted block boundary.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::RewardHistoryBalance")]
pub(super) struct Balance {
    pub(super) beneficiary: AccountId,
    pub(super) amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::validation_fee_rewards::RewardHistoryJournalEntry")]
struct JournalEntry {
    key: StatePath,
    hash: Hash,
}

fn leaf(key: &StatePath) -> Option<(&str, &str)> {
    let text = key.as_ref();
    let (contract, rest) = text.split_once("/ValidationFeeRewards/")?;
    let (custody, suffix) = rest.split_once('/')?;
    let scope_end = contract.len() + "/ValidationFeeRewards/".len() + custody.len();
    Some((&text[..scope_end], suffix))
}

fn journaled(leaf: &str) -> bool {
    [
        "Allocation/",
        "Entitlement/",
        "Claim/",
        "Attempt/",
        "ExposureSource/",
    ]
    .iter()
    .any(|prefix| leaf.starts_with(prefix))
}

/// Add one immutable receipt to this block's bounded retirement journal.
pub(super) fn journal_write(
    stx: &mut StateTransaction<'_, '_>,
    key: &StatePath,
    bytes: &[u8],
) -> Result<(), Error> {
    let Some((scope, _)) = leaf(key).filter(|(_, suffix)| journaled(suffix)) else {
        return Ok(());
    };
    let journal_key: StatePath = format!(
        "{scope}/HistoryJournal/{:020}/{}",
        stx.block_height(),
        hex::encode(Hash::new(key.as_ref().as_bytes()).as_ref()),
    )
    .parse()
    .map_err(|error| fail(format!("invalid reward journal key: {error}")))?;
    let entry = JournalEntry {
        key: key.clone(),
        hash: Hash::new(bytes),
    };
    let encoded = norito::to_bytes(&entry)
        .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if stx
        .world
        .smart_contract_state
        .get(&journal_key)
        .is_some_and(|old| old != &encoded)
    {
        return Err(fail("immutable reward journal entry was rewritten"));
    }
    stx.world.smart_contract_state.insert(journal_key, encoded);
    Ok(())
}

pub(super) fn checkpoint(
    world: &impl WorldReadOnly,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<Checkpoint, ExecutionAttemptError<Error>> {
    Ok(read_from_world(world, &state_key(binding, "HistoryCheckpoint")?)?.unwrap_or_default())
}

/// Require an exact, bounded journal for every uncheckpointed immutable receipt.
/// The only archived receipt allowed to remain hot is the active allocation.
pub(super) fn validate_journals(
    world: &impl WorldReadOnly,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    checkpoint: &Checkpoint,
) -> Result<(), ExecutionAttemptError<Error>> {
    let root = state_key(binding, "State")?;
    let prefix = root
        .as_ref()
        .strip_suffix("State")
        .ok_or_else(|| fail("invalid reward history scope"))?;
    let cursor: Option<settlement::RewardAllocationCursor> =
        read_from_world(world, &state_key(binding, "AllocationCursor")?)?;
    let mut expected = BTreeMap::new();
    let mut actual = BTreeMap::new();
    for (key, bytes) in world.smart_contract_state().iter() {
        let Some(suffix) = key.as_ref().strip_prefix(prefix) else {
            continue;
        };
        if let Some(coordinates) = suffix.strip_prefix("HistoryJournal/") {
            let height = coordinates
                .split_once('/')
                .and_then(|(height, _)| height.parse::<u64>().ok())
                .ok_or_else(|| fail("malformed reward retirement journal coordinates"))?;
            let entry: JournalEntry = read_from_world(world, key)?
                .ok_or_else(|| fail("reward retirement journal disappeared"))?;
            let canonical = state_key(
                binding,
                &format!(
                    "HistoryJournal/{height:020}/{}",
                    hex::encode(Hash::new(entry.key.as_ref().as_bytes()).as_ref())
                ),
            )?;
            if height <= checkpoint.height
                || *key != canonical
                || !entry
                    .key
                    .as_ref()
                    .strip_prefix(prefix)
                    .is_some_and(journaled)
                || actual.insert(entry.key, (height, entry.hash)).is_some()
                || actual.len() > MAX_FEE_EVIDENCE_RECORDS_V1 as usize
            {
                return Err(fail("noncanonical reward retirement journal").into());
            }
            continue;
        }
        if !journaled(suffix) {
            continue;
        }
        let (height, canonical, retained_allocation) = if suffix.starts_with("Allocation/") {
            let value: ValidationFeeRewardAllocation = read_from_world(world, key)?
                .ok_or_else(|| fail("reward allocation disappeared"))?;
            (
                value.converted_at_height,
                state_key(binding, &format!("Allocation/{}", value.sequence))?,
                value.sequence < checkpoint.next_allocation
                    && cursor
                        .as_ref()
                        .is_some_and(|cursor| cursor.allocation_sequence == value.sequence),
            )
        } else if suffix.starts_with("Entitlement/") {
            let value: ValidationFeeRewardEntitlement = read_from_world(world, key)?
                .ok_or_else(|| fail("reward entitlement disappeared"))?;
            (
                value.recorded_at_height,
                iroha_data_model::validation_fee_rewards::validation_fee_entitlement_key(
                    binding,
                    value.allocation_sequence,
                    &value.validator,
                    value.page_index,
                )
                .map_err(fail)?,
                false,
            )
        } else if suffix.starts_with("Claim/") {
            let value: ValidationFeeRewardClaim =
                read_from_world(world, key)?.ok_or_else(|| fail("reward claim disappeared"))?;
            (
                value.claimed_at_height,
                state_key(binding, &format!("Claim/{}", value.sequence))?,
                false,
            )
        } else if suffix.starts_with("Attempt/") {
            let value: ValidationFeeConversionAttempt =
                read_from_world(world, key)?.ok_or_else(|| fail("reward attempt disappeared"))?;
            (
                value.attempted_at_height,
                state_key(binding, &format!("Attempt/{}", value.attempted_at_height))?,
                false,
            )
        } else {
            let height = suffix
                .strip_prefix("ExposureSource/")
                .and_then(|coordinates| coordinates.split_once('/'))
                .and_then(|(height, _)| height.parse::<u64>().ok())
                .ok_or_else(|| fail("malformed reward exposure source coordinates"))?;
            let value: iroha_data_model::validation_fee_rewards::ValidationFeeExposurePage =
                read_from_world(world, key)?
                    .ok_or_else(|| fail("reward exposure source disappeared"))?;
            iroha_data_model::validation_fee_rewards::validate_exposure_page(&value)
                .map_err(fail)?;
            (
                height,
                exposure::source_key(binding, height, &value.validator, value.page_index)?,
                false,
            )
        };
        if height == 0 || *key != canonical {
            return Err(fail("noncanonical reward journal source coordinates").into());
        }
        if height <= checkpoint.height {
            if !retained_allocation {
                return Err(fail("compacted reward receipt remains hot").into());
            }
            continue;
        }
        if retained_allocation
            || expected
                .insert(key.clone(), (height, Hash::new(bytes)))
                .is_some()
            || expected.len() > MAX_FEE_EVIDENCE_RECORDS_V1 as usize
        {
            return Err(fail("reward journal source exceeds its bounded hot suffix").into());
        }
    }
    if expected != actual {
        return Err(fail("reward retirement journal does not exactly cover hot receipts").into());
    }
    Ok(())
}

pub(super) fn balance_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<StatePath, Error> {
    state_key(
        binding,
        &format!(
            "HistoryBalance/{}",
            hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
        ),
    )
}

pub(super) fn add(total: &mut BigInt, amount: u128) -> Result<(), Error> {
    *total = total
        .checked_add(&BigInt::from(amount))
        .map_err(|error| fail(error.to_string()))?;
    Ok(())
}

fn payload_bytes(
    record: &FeeEvidenceRecordV1,
) -> Result<Option<Vec<u8>>, ExecutionAttemptError<Error>> {
    let bytes = match &record.payload {
        Payload::RewardAllocation(value) => norito::to_bytes(value),
        Payload::RewardEntitlement(value) => norito::to_bytes(value),
        Payload::RewardClaim(value) => norito::to_bytes(value),
        Payload::RewardAttempt(value) => norito::to_bytes(value),
        Payload::RewardExposure(value) => norito::to_bytes(value),
        _ => return Ok(None),
    };
    bytes
        .map(Some)
        .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
}

/// Compact one original block only after its exact authenticated corpus can be read.
/// Archive unavailability is a local execution deferral, never an expiry or a
/// node-dependent choice to omit pruning. The transaction rolls back as a whole.
pub(super) fn compact(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
) -> Result<(), Error> {
    let prefix = state_key(binding, "HistoryJournal/")?;
    let first = stx
        .world
        .smart_contract_state
        .range(prefix.clone()..)
        .next()
        .filter(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
        .map(|(key, _)| key.clone());
    let Some(first) = first else {
        return Ok(());
    };
    let height = first
        .as_ref()
        .strip_prefix(prefix.as_ref())
        .and_then(|suffix| suffix.split('/').next())
        .and_then(|height| height.parse::<u64>().ok())
        .ok_or_else(|| fail("malformed reward history journal height"))?;
    if height >= stx.block_height() {
        return Ok(());
    }
    let block_prefix = state_key(binding, &format!("HistoryJournal/{height:020}/"))?;
    let rows = stx
        .world
        .smart_contract_state
        .range(block_prefix.clone()..)
        .take_while(|(key, _)| key.as_ref().starts_with(block_prefix.as_ref()))
        .take(MAX_FEE_EVIDENCE_RECORDS_V1 as usize + 1)
        .map(|(key, _)| {
            let entry: JournalEntry =
                read(stx, key)?.ok_or_else(|| fail("reward retirement journal disappeared"))?;
            Ok((key.clone(), entry))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if rows.len() > MAX_FEE_EVIDENCE_RECORDS_V1 as usize {
        return Err(fail(
            "reward history journal exceeds one bounded evidence block",
        ));
    }
    let mut checkpoint = checkpoint(&stx.world, binding)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if height <= checkpoint.height {
        return Err(fail("reward history journal was already compacted"));
    }
    let proof = crate::query::native_receipts::committed_fee_evidence(stx, height)
        .map_err(|error| string_attempt_instruction_error(stx, error))?;
    let mut originals = BTreeMap::new();
    let mut exposure_sources = BTreeMap::new();
    for record in &proof.records {
        if let Some(bytes) = payload_bytes(record)
            .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?
        {
            if let Payload::RewardExposure(page) = &record.payload {
                exposure_sources.insert(Hash::new(&bytes), page);
            } else {
                originals.insert(record.key.clone(), (Hash::new(&bytes), record));
            }
        }
    }
    let mut allocations = BTreeMap::new();
    let mut claims = BTreeMap::new();
    let mut entitlements = Vec::new();
    for (journal_key, entry) in &rows {
        let canonical_journal = state_key(
            binding,
            &format!(
                "HistoryJournal/{height:020}/{}",
                hex::encode(Hash::new(entry.key.as_ref().as_bytes()).as_ref())
            ),
        )?;
        let Some((source_scope, suffix)) = leaf(&entry.key).filter(|(_, suffix)| journaled(suffix))
        else {
            return Err(fail("reward journal source family differs"));
        };
        let expected_scope = leaf(&canonical_journal)
            .ok_or_else(|| fail("invalid reward journal scope"))?
            .0;
        if *journal_key != canonical_journal || source_scope != expected_scope {
            return Err(fail("reward journal coordinates or custody scope differ"));
        }
        let bytes = stx
            .world
            .smart_contract_state
            .get(&entry.key)
            .ok_or_else(|| fail("reward journal source is missing before archival retirement"))?;
        if Hash::new(bytes) != entry.hash {
            return Err(fail("reward journal source hash differs"));
        }
        if suffix.starts_with("ExposureSource/") {
            let page = exposure_sources
                .get(&entry.hash)
                .ok_or_else(|| fail("reward exposure source lacks original archived evidence"))?;
            if entry.key != exposure::source_key(binding, height, &page.validator, page.page_index)?
            {
                return Err(fail(
                    "reward exposure source differs from original coordinates",
                ));
            }
            continue;
        }
        let (hash, record) = originals
            .get(&entry.key)
            .ok_or_else(|| fail("reward receipt lacks original archived evidence"))?;
        if *hash != entry.hash {
            return Err(fail(
                "reward receipt differs from original archived evidence",
            ));
        }
        match &record.payload {
            Payload::RewardAllocation(value) => {
                allocations.insert(value.sequence, value);
            }
            Payload::RewardEntitlement(value) => entitlements.push(value),
            Payload::RewardClaim(value) => {
                claims.insert(value.sequence, value);
            }
            Payload::RewardAttempt(_) => (),
            _ => return Err(fail("unexpected archived reward journal source")),
        }
    }
    for (sequence, allocation) in allocations {
        if sequence != checkpoint.next_allocation {
            return Err(fail("compacted reward funding sequence has a gap"));
        }
        checkpoint.next_allocation = sequence
            .checked_add(1)
            .ok_or_else(|| fail("reward allocation sequence exhausted"))?;
        add(&mut checkpoint.funded, allocation.xor_minor)?;
    }
    let mut balances = BTreeMap::<AccountId, BigInt>::new();
    let mut change = |account: &AccountId, amount: u128, subtract: bool| -> Result<(), Error> {
        if !balances.contains_key(account) {
            let old: Option<Balance> = read(stx, &balance_key(binding, account)?)?;
            if old
                .as_ref()
                .is_some_and(|old| old.beneficiary != *account || old.amount == 0)
            {
                return Err(fail("noncanonical compacted reward beneficiary balance"));
            }
            balances.insert(
                account.clone(),
                BigInt::from(old.map_or(0, |old| old.amount)),
            );
        }
        let balance = balances
            .get_mut(account)
            .ok_or_else(|| fail("compacted reward balance disappeared"))?;
        *balance = if subtract {
            balance.checked_sub(&BigInt::from(amount))
        } else {
            balance.checked_add(&BigInt::from(amount))
        }
        .map_err(|error| fail(error.to_string()))?;
        Ok(())
    };
    for entitlement in entitlements {
        for (account, amount) in &entitlement.shares {
            let original = entitlement
                .beneficiaries
                .get(account)
                .ok_or_else(|| fail("archived entitlement beneficiary missing"))?;
            change(original, *amount, false)?;
            add(&mut checkpoint.credited, *amount)?;
        }
    }
    for (sequence, claim) in claims {
        if sequence != checkpoint.next_claim {
            return Err(fail("compacted reward claim sequence has a gap"));
        }
        checkpoint.next_claim = sequence
            .checked_add(1)
            .ok_or_else(|| fail("reward claim sequence exhausted"))?;
        change(&claim.beneficiary_id, claim.xor_minor, true)?;
        add(&mut checkpoint.paid, claim.xor_minor)?;
    }
    for (beneficiary, value) in balances {
        let amount = value
            .try_to_u128()
            .ok_or_else(|| fail("compacted reward balance is negative or oversized"))?;
        let key = balance_key(binding, &beneficiary)?;
        if amount == 0 {
            stx.world.smart_contract_state.remove(key);
        } else {
            write(
                stx,
                key,
                &Balance {
                    beneficiary,
                    amount,
                },
            )?;
        }
    }
    let commitment: iroha_data_model::fee_evidence::FeeEvidenceSnapshotV1 =
        norito::decode_canonical(&proof.snapshot_witness.value)
            .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
            .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?;
    if !commitment.is_valid() {
        return Err(fail("archived fee evidence commitment is incoherent"));
    }
    let root = commitment.root;
    checkpoint.archive_chain = Some(Hash::new(
        norito::to_bytes(&(checkpoint.archive_chain, height, root))
            .map_err(|error| norito_decode_attempt_error(error, |error| fail(error.to_string())))
            .map_err(|error| stx.world.attempt_error_to_instruction_error(error))?,
    ));
    checkpoint.height = height;
    write(stx, state_key(binding, "HistoryCheckpoint")?, &checkpoint)?;
    let cursor: Option<settlement::RewardAllocationCursor> =
        read(stx, &state_key(binding, "AllocationCursor")?)?;
    for (journal_key, entry) in rows {
        let keep_active_allocation = cursor.as_ref().is_some_and(|cursor| {
            state_key(
                binding,
                &format!("Allocation/{}", cursor.allocation_sequence),
            )
            .ok()
            .as_ref()
                == Some(&entry.key)
        });
        if !keep_active_allocation {
            stx.world.smart_contract_state.remove(entry.key);
        }
        stx.world.smart_contract_state.remove(journal_key);
    }
    retire_completed_allocation(stx, binding, &checkpoint, cursor.as_ref())?;
    Ok(())
}

fn retire_completed_allocation(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    checkpoint: &Checkpoint,
    cursor: Option<&settlement::RewardAllocationCursor>,
) -> Result<(), Error> {
    let prefix = state_key(binding, "Allocation/")?;
    let keys = stx
        .world
        .smart_contract_state
        .range(prefix.clone()..)
        .take_while(|(key, _)| key.as_ref().starts_with(prefix.as_ref()))
        .take(3)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    if keys.len() > 2 {
        return Err(fail("more than two hot funded reward allocations"));
    }
    for key in keys {
        let allocation: ValidationFeeRewardAllocation =
            read(stx, &key)?.ok_or_else(|| fail("hot allocation disappeared"))?;
        if allocation.sequence < checkpoint.next_allocation
            && cursor.is_none_or(|cursor| cursor.allocation_sequence != allocation.sequence)
        {
            stx.world.smart_contract_state.remove(key);
        }
    }
    Ok(())
}

/// Only this native compactor may retire an already archived immutable reward row.
pub(super) fn permits_retirement(
    stx: &StateTransaction<'_, '_>,
    key: &StatePath,
) -> Result<bool, ExecutionAttemptError<String>> {
    let Some((scope, suffix)) = leaf(key).filter(|(_, suffix)| journaled(suffix)) else {
        return Ok(false);
    };
    let checkpoint_key: StatePath = format!("{scope}/HistoryCheckpoint")
        .parse()
        .map_err(|error| format!("invalid checkpoint key: {error}"))?;
    let Some(checkpoint) = read_attempt::<Checkpoint>(stx, &checkpoint_key)
        .map_err(|error| error.map_rejection(|error| error.to_string()))?
    else {
        return Ok(false);
    };
    let Some(bytes) = stx.world.smart_contract_state.get_before_block(key) else {
        return Ok(false);
    };
    if suffix.starts_with("Allocation/") {
        let allocation: ValidationFeeRewardAllocation = norito::decode_canonical(bytes)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?;
        return Ok(allocation.sequence < checkpoint.next_allocation);
    }
    let recorded = if suffix.starts_with("Entitlement/") {
        norito::decode_canonical::<ValidationFeeRewardEntitlement>(bytes)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?
            .recorded_at_height
    } else if suffix.starts_with("Claim/") {
        norito::decode_canonical::<ValidationFeeRewardClaim>(bytes)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?
            .claimed_at_height
    } else if suffix.starts_with("Attempt/") {
        norito::decode_canonical::<ValidationFeeConversionAttempt>(bytes)
            .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?
            .attempted_at_height
    } else {
        return Ok(false);
    };
    Ok(recorded <= checkpoint.height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_journal_decode_refusal_defers_without_retiring_original_bytes() {
        crate::retail_fee_tests::fixture_block(1_793_451_600_000, |block, _| {
            let binding = {
                let mut setup = block.transaction();
                let binding = active_bindings(&setup).unwrap().remove(0);
                let height = setup.block_height() - 1;
                let key = state_key(&binding, &format!("Attempt/{height}")).unwrap();
                let source = norito::to_bytes(&ValidationFeeConversionAttempt {
                    attempted_at_height: height,
                    attempted_at_ms: setup.block_unix_timestamp_ms() - 1,
                    earning_period_start_ms: 1,
                    sbd_minor: 10,
                    min_xor_minor: 20,
                    lifecycle_seal: binding.lifecycle_seal().unwrap(),
                    reference_observations: Vec::new(),
                })
                .unwrap();
                let journal = state_key(
                    &binding,
                    &format!(
                        "HistoryJournal/{height:020}/{}",
                        hex::encode(Hash::new(key.as_ref().as_bytes()).as_ref()),
                    ),
                )
                .unwrap();
                let entry = JournalEntry {
                    key: key.clone(),
                    hash: Hash::new(&source),
                };
                setup.world.smart_contract_state.insert(key, source);
                setup
                    .world
                    .smart_contract_state
                    .insert(journal, norito::to_bytes(&entry).unwrap());
                setup.apply();
                binding
            };
            let before = block
                .world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>();
            let fragments = block.committed_fragment_count();
            let mut stx = block.transaction();
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
            let result = norito::with_decode_limits_scope(limits, || compact(&mut stx, &binding));
            let refusal = stx
                .execution_deferral()
                .expect("original journal decode resource refusal");
            assert_eq!(
                finish_reward_maintenance(stx, result),
                Err(crate::state::ExecutionOutputAttemptError::Deferred(refusal)),
            );
            assert_eq!(block.committed_fragment_count(), fragments);
            let after = block
                .world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(before, after);
            let retry = block.transaction();
            validate_journals(&retry.world, &binding, &Checkpoint::default())
                .expect("the identical journal decodes when the caller budget is restored");
        });
    }

    #[test]
    fn unavailable_original_archive_leaves_journal_and_checkpoint_intact() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let height = stx.block_height() - 1;
            let key = state_key(&binding, &format!("Attempt/{height}")).unwrap();
            let attempt = ValidationFeeConversionAttempt {
                attempted_at_height: height,
                attempted_at_ms: stx.block_unix_timestamp_ms() - 1,
                earning_period_start_ms: 1,
                sbd_minor: 10,
                min_xor_minor: 20,
                lifecycle_seal: binding.lifecycle_seal().unwrap(),
                reference_observations: Vec::new(),
            };
            let bytes = norito::to_bytes(&attempt).unwrap();
            let entry = JournalEntry {
                key: key.clone(),
                hash: Hash::new(&bytes),
            };
            let journal_key = state_key(
                &binding,
                &format!(
                    "HistoryJournal/{height:020}/{}",
                    hex::encode(Hash::new(key.as_ref().as_bytes()).as_ref())
                ),
            )
            .unwrap();
            stx.world.smart_contract_state.insert(key, bytes);
            stx.world
                .smart_contract_state
                .insert(journal_key, norito::to_bytes(&entry).unwrap());
            validate_journals(&stx.world, &binding, &Checkpoint::default()).unwrap();
            let before: BTreeMap<_, _> = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect();
            assert!(compact(stx, &binding).is_err());
            let after: BTreeMap<_, _> = stx
                .world
                .smart_contract_state
                .iter()
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect();
            assert_eq!(before, after);
            assert_eq!(
                checkpoint(&stx.world, &binding).unwrap(),
                Checkpoint::default()
            );
        });
    }

    #[test]
    fn journal_validation_requires_exact_original_height_hash_and_custody() {
        crate::retail_fee_tests::fixture(1_793_451_600_000, |stx, _| {
            let binding = active_bindings(stx).unwrap().remove(0);
            let height = stx.block_height();
            let key = state_key(&binding, &format!("Attempt/{height}")).unwrap();
            let attempt = ValidationFeeConversionAttempt {
                attempted_at_height: height,
                attempted_at_ms: stx.block_unix_timestamp_ms(),
                earning_period_start_ms: 1,
                sbd_minor: 10,
                min_xor_minor: 20,
                lifecycle_seal: binding.lifecycle_seal().unwrap(),
                reference_observations: Vec::new(),
            };
            write(stx, key.clone(), &attempt).unwrap();
            let checkpoint = Checkpoint::default();
            validate_journals(&stx.world, &binding, &checkpoint).unwrap();

            let journal_key = state_key(
                &binding,
                &format!(
                    "HistoryJournal/{height:020}/{}",
                    hex::encode(Hash::new(key.as_ref().as_bytes()).as_ref())
                ),
            )
            .unwrap();
            let original_journal = stx
                .world
                .smart_contract_state
                .remove(journal_key.clone())
                .unwrap();
            assert!(validate_journals(&stx.world, &binding, &checkpoint).is_err());
            stx.world
                .smart_contract_state
                .insert(journal_key.clone(), original_journal.clone());

            let mut changed = attempt.clone();
            changed.sbd_minor += 1;
            assert!(write(stx, key.clone(), &changed).is_err());
            assert_eq!(
                read::<ValidationFeeConversionAttempt>(stx, &key).unwrap(),
                Some(attempt)
            );
            stx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&changed).unwrap());
            assert!(validate_journals(&stx.world, &binding, &checkpoint).is_err());
            changed.sbd_minor -= 1;
            stx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&changed).unwrap());

            stx.world.smart_contract_state.remove(journal_key.clone());
            let wrong_height_key = state_key(
                &binding,
                &format!(
                    "HistoryJournal/{:020}/{}",
                    height + 1,
                    hex::encode(Hash::new(key.as_ref().as_bytes()).as_ref())
                ),
            )
            .unwrap();
            stx.world
                .smart_contract_state
                .insert(wrong_height_key.clone(), original_journal.clone());
            assert!(validate_journals(&stx.world, &binding, &checkpoint).is_err());
            stx.world.smart_contract_state.remove(wrong_height_key);
            stx.world
                .smart_contract_state
                .insert(journal_key, original_journal);

            let foreign_key: StatePath = format!(
                "sc/{}/ValidationFeeRewards/{}/Attempt/{height}",
                "ab".repeat(32),
                "cd".repeat(32)
            )
            .parse()
            .unwrap();
            let foreign = JournalEntry {
                key: foreign_key.clone(),
                hash: Hash::new(b"foreign"),
            };
            let foreign_journal = state_key(
                &binding,
                &format!(
                    "HistoryJournal/{height:020}/{}",
                    hex::encode(Hash::new(foreign_key.as_ref().as_bytes()).as_ref())
                ),
            )
            .unwrap();
            stx.world
                .smart_contract_state
                .insert(foreign_journal.clone(), norito::to_bytes(&foreign).unwrap());
            assert!(validate_journals(&stx.world, &binding, &checkpoint).is_err());
            stx.world.smart_contract_state.remove(foreign_journal);
            validate_journals(&stx.world, &binding, &checkpoint).unwrap();
        });
    }

    #[test]
    fn retirement_journal_keeps_contract_and_custody_scope() {
        let scope = format!(
            "sc/{}/ValidationFeeRewards/{}",
            "ab".repeat(32),
            "cd".repeat(32)
        );
        let key: StatePath = format!("{scope}/Entitlement/7/validator/0")
            .parse()
            .unwrap();
        assert_eq!(
            leaf(&key),
            Some((scope.as_str(), "Entitlement/7/validator/0"))
        );
        assert!(journaled(leaf(&key).unwrap().1));
        assert!(!journaled("HistoryJournal/00000000000000000007/key"));
        assert!(!journaled("Claimable/account"));
        assert!(!journaled("BeneficiaryAlias/account"));
    }

    #[test]
    fn compacted_lifetime_turnover_preserves_more_than_u128() {
        let mut checkpoint = Checkpoint {
            height: 9,
            next_allocation: 2,
            next_claim: 1,
            archive_chain: Some(Hash::new(b"original archived checkpoint")),
            ..Default::default()
        };
        add(&mut checkpoint.funded, u128::MAX).unwrap();
        add(&mut checkpoint.funded, u128::MAX).unwrap();
        checkpoint.credited = checkpoint.funded.clone();
        add(&mut checkpoint.paid, u128::MAX).unwrap();
        assert_eq!(
            checkpoint
                .funded
                .checked_sub(&checkpoint.paid)
                .unwrap()
                .try_to_u128(),
            Some(u128::MAX)
        );
        let restored: Checkpoint =
            norito::decode_canonical(&norito::to_bytes(&checkpoint).unwrap()).unwrap();
        assert_eq!(restored, checkpoint);
    }
}
