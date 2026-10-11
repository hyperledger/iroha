//! Constant-work recovery of reserved and future historical validator rewards.
use super::*;
use iroha_data_model::validation_fee_rewards::{
    ValidationFeeRewardBeneficiaryAlias as Alias,
    ValidationFeeRewardBeneficiaryRevision as Revision,
    validation_fee_beneficiary_alias_key as alias_key,
    validation_fee_beneficiary_revision_key as revision_key,
};
fn current_key(
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    original: &AccountId,
) -> Result<StatePath, Error> {
    state_key(
        binding,
        &format!(
            "BeneficiaryCurrent/{}",
            hex::encode(Hash::new(original.to_string().as_bytes()).as_ref())
        ),
    )
}
pub(super) fn root(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<AccountId, Error> {
    root_in_world(&stx.world, binding, account)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))
}
pub(super) fn root_in_world(
    world: &impl WorldReadOnly,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<AccountId, ExecutionAttemptError<Error>> {
    let key = alias_key(binding, account).map_err(fail)?;
    match read_from_world::<Alias>(world, &key)? {
        None => Ok(account.clone()),
        Some(alias) if &alias.account_id == account => Ok(alias.beneficiary_id),
        _ => Err(fail("malformed immutable reward beneficiary alias").into()),
    }
}
pub(super) fn owner(
    stx: &StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    original: &AccountId,
) -> Result<Option<Revision>, Error> {
    owner_in_world(&stx.world, binding, original)
        .map_err(|error| stx.world.attempt_error_to_instruction_error(error))
}
pub(super) fn owner_in_world(
    world: &impl WorldReadOnly,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    original: &AccountId,
) -> Result<Option<Revision>, ExecutionAttemptError<Error>> {
    let Some(revision) = read_from_world::<u64>(world, &current_key(binding, original)?)? else {
        return Ok(None);
    };
    let value = read_from_world::<Revision>(
        world,
        &revision_key(binding, original, revision).map_err(fail)?,
    )?
    .ok_or_else(|| fail("reward beneficiary owner revision is absent"))?;
    if value.beneficiary_id != *original || value.revision != revision {
        return Err(fail("reward beneficiary owner revision has mismatched identity").into());
    }
    let alias =
        read_from_world::<Alias>(world, &alias_key(binding, &value.account_id).map_err(fail)?)?
            .ok_or_else(|| fail("reward beneficiary owner alias is absent"))?;
    if alias.account_id != value.account_id || alias.beneficiary_id != *original {
        return Err(fail("reward beneficiary owner alias has mismatched identity").into());
    }
    if value.account_id != *original {
        let original_alias =
            read_from_world::<Alias>(world, &alias_key(binding, original).map_err(fail)?)?
                .ok_or_else(|| fail("original reward beneficiary alias is absent"))?;
        if original_alias.account_id != *original || original_alias.beneficiary_id != *original {
            return Err(fail("original reward beneficiary alias has mismatched identity").into());
        }
    }
    Ok(Some(value))
}
fn immutable<T: NoritoSerialize>(
    stx: &mut StateTransaction<'_, '_>,
    key: StatePath,
    value: &T,
) -> Result<(), Error> {
    if stx.world.smart_contract_state.get(&key).is_some() {
        return Err(fail("immutable reward beneficiary identity already exists"));
    }
    write(stx, key, value)
}
pub(super) fn ensure(
    stx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    account: &AccountId,
) -> Result<AccountId, Error> {
    ensure_reward_identity(account)?;
    let original = root(stx, binding, account)?;
    ensure_reward_identity(&original)?;
    if owner(stx, binding, &original)?.is_none() {
        if original != *account {
            return Err(fail("reward alias has no authorized owner"));
        }
        let alias = Alias {
            account_id: account.clone(),
            beneficiary_id: original.clone(),
        };
        immutable(stx, alias_key(binding, account).map_err(fail)?, &alias)?;
        let initial = Revision {
            beneficiary_id: original.clone(),
            revision: 0,
            account_id: original.clone(),
            previous_account_id: None,
            authorized_at_height: stx.block_height(),
        };
        immutable(
            stx,
            revision_key(binding, &original, 0).map_err(fail)?,
            &initial,
        )?;
        write(stx, current_key(binding, &original)?, &0u64)?;
    }
    Ok(original)
}
/// Called only by authorized native account-controller replacement before its atomic mutation.
/// Historical aliases cannot redirect an already recovered beneficiary or capture another identity.
pub(crate) fn rekey_beneficiary(
    stx: &mut StateTransaction<'_, '_>,
    old: &AccountId,
    new: &AccountId,
) -> Result<(), Error> {
    if old == new {
        return Ok(());
    }
    // Custody and beneficiary lineage outlive conversion activation. Recovery
    // must also cover delayed exposure when a retained lifecycle is not active.
    if let Some(binding) = crate::validation_fee::retained_payout_custody_binding(&stx.world)
        .map_err(|error| string_attempt_instruction_error(stx, error))?
    {
        ensure_reward_identity(new)?;
        if read::<Alias>(stx, &alias_key(&binding, new).map_err(fail)?)?.is_some() {
            return Err(fail(
                "new account is already a retained reward beneficiary identity",
            ));
        }
        let original = ensure(stx, &binding, old)?;
        let previous =
            owner(stx, &binding, &original)?.ok_or_else(|| fail("missing beneficiary owner"))?;
        if previous.account_id != *old {
            return Err(fail(
                "only the current reward beneficiary owner may recover its claims",
            ));
        }
        let revision = previous
            .revision
            .checked_add(1)
            .ok_or_else(|| fail("beneficiary revision exhausted"))?;
        immutable(
            stx,
            alias_key(&binding, new).map_err(fail)?,
            &Alias {
                account_id: new.clone(),
                beneficiary_id: original.clone(),
            },
        )?;
        let next = Revision {
            beneficiary_id: original.clone(),
            revision,
            account_id: new.clone(),
            previous_account_id: Some(old.clone()),
            authorized_at_height: stx.block_height(),
        };
        immutable(
            stx,
            revision_key(&binding, &original, revision).map_err(fail)?,
            &next,
        )?;
        write(stx, current_key(&binding, &original)?, &revision)?;
    }
    validate_pending_fee_evidence_budget(stx)
        .map_err(|error| string_attempt_instruction_error(stx, error))
}
/// Retain only the immutable alias/revision rows used in this block. No history scan.
pub(super) fn append_evidence_sources(
    stx: &StateTransaction<'_, '_>,
    records: &mut Vec<iroha_data_model::fee_evidence::FeeEvidenceRecordV1>,
) -> Result<(), ExecutionAttemptError<String>> {
    use iroha_data_model::fee_evidence::{FeeEvidencePayloadV1 as P, FeeEvidenceRecordV1};
    let mut aliases = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    for record in records.iter() {
        match &record.payload {
            P::RewardEntitlement(a) => aliases.extend(a.beneficiaries.keys().cloned()),
            P::RewardClaim(c) => {
                aliases.insert(c.account_id.clone());
                revisions.insert((c.beneficiary_id.clone(), c.beneficiary_revision));
            }
            P::RewardBeneficiaryRevision(r) => {
                aliases.insert(r.account_id.clone());
                if r.revision > 0 {
                    revisions.insert((r.beneficiary_id.clone(), r.revision - 1));
                }
            }
            _ => (),
        }
    }
    let mut keys = records
        .iter()
        .map(|r| r.key.clone())
        .collect::<BTreeSet<_>>();
    if let Some(binding) = crate::validation_fee::retained_payout_custody_binding(&stx.world)? {
        for account in &aliases {
            let key = alias_key(&binding, account)?;
            if keys.insert(key.clone()) {
                let alias = read_attempt::<Alias>(stx, &key)
                    .map_err(|error| error.map_rejection(|error| error.to_string()))?
                    .ok_or_else(|| "required immutable beneficiary alias is absent".to_owned())?;
                records.push(FeeEvidenceRecordV1 {
                    key,
                    recorded_at_height: stx.block_height(),
                    payload: P::RewardBeneficiaryAlias(alias),
                });
            }
        }
        for (original, revision) in &revisions {
            let key = revision_key(&binding, original, *revision)?;
            if keys.insert(key.clone()) {
                let value = read_attempt::<Revision>(stx, &key)
                    .map_err(|error| error.map_rejection(|error| error.to_string()))?
                    .ok_or_else(|| {
                        "required immutable beneficiary owner revision is absent".to_owned()
                    })?;
                records.push(FeeEvidenceRecordV1 {
                    key,
                    recorded_at_height: stx.block_height(),
                    payload: P::RewardBeneficiaryRevision(value),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
