//! Explicit classification and reconciliation for mandatory asset UID enrollment.

use super::*;
use iroha_data_model::{
    asset::{
        AssetBalanceScope,
        uid_enrollment::{AssetUidEnrollmentV1, AssetUidSystemAccountV1},
    },
    isi::error::InstructionExecutionError,
};

pub(crate) const ENROLLMENT_ROOT: &str = "asset_uid_enrollment_v1/";
pub(crate) const SYSTEM_ROOT: &str = "asset_uid_system_v1/";
type Error = InstructionExecutionError;

fn reject(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}

fn digest(value: impl std::fmt::Display) -> String {
    hex::encode(Hash::new(value.to_string().as_bytes()).as_ref())
}

pub(crate) fn enrollment_key(definition: &AssetDefinitionId) -> StatePath {
    format!("{ENROLLMENT_ROOT}{}", digest(definition))
        .parse()
        .expect("fixed native asset enrollment path")
}

pub(crate) fn system_key(definition: &AssetDefinitionId, account: &AccountId) -> StatePath {
    format!("{SYSTEM_ROOT}{}/{}", digest(definition), digest(account))
        .parse()
        .expect("fixed native system enrollment path")
}

fn read<T>(world: &impl WorldReadOnly, key: &StatePath) -> Result<Option<T>, Error>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    world
        .smart_contract_state()
        .get(key)
        .map(|bytes| {
            norito::decode_canonical(bytes)
                .map_err(|error| reject(format!("invalid native enrollment state: {error}")))
        })
        .transpose()
}

pub(crate) fn enrollment(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<Option<AssetUidEnrollmentV1>, Error> {
    let value: Option<AssetUidEnrollmentV1> = read(world, &enrollment_key(definition))?;
    if value
        .as_ref()
        .is_some_and(|v| v.asset_definition_id != *definition || v.activated_at_height == 0)
    {
        return Err(reject(
            "native asset enrollment differs from its canonical key",
        ));
    }
    Ok(value)
}

pub(crate) fn system(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<AssetUidSystemAccountV1>, Error> {
    let value: Option<AssetUidSystemAccountV1> = read(world, &system_key(definition, account))?;
    if value.as_ref().is_some_and(|v| {
        v.asset_definition_id != *definition || v.account_id != *account || v.revision == 0
    }) {
        return Err(reject(
            "native system enrollment differs from its canonical key",
        ));
    }
    Ok(value)
}

/// Beneficial categories never overlap, including revoked institutional records.
pub(crate) enum BeneficialEnrollment {
    Retail,
    Fi { enabled: bool },
    System { enabled: bool },
}

pub(crate) fn beneficial(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<BeneficialEnrollment>, Error> {
    let retail = super::asset_uid::member_policy(world, definition, account)?.is_some();
    let fi = super::asset_fi::fi(world, definition, account)?;
    let system = system(world, definition, account)?;
    if usize::from(retail) + usize::from(fi.is_some()) + usize::from(system.is_some()) > 1 {
        return Err(reject("asset enrollment categories overlap"));
    }
    Ok(if retail {
        Some(BeneficialEnrollment::Retail)
    } else if let Some(fi) = fi {
        Some(BeneficialEnrollment::Fi {
            enabled: fi.enabled,
        })
    } else {
        system.map(|v| BeneficialEnrollment::System { enabled: v.enabled })
    })
}

/// New ordinary monetary use requires current eligibility at both boundaries.
/// Native retained-payer returns use their separate sealed custody path.
pub(crate) fn require_active_beneficial(
    world: &impl WorldReadOnly,
    id: &AssetId,
) -> Result<(), Error> {
    if enrollment(world, id.definition())?.is_none() {
        return Ok(());
    }
    if id.scope() != &AssetBalanceScope::Global {
        return Err(reject("enrolled asset requires exact Global balances"));
    }
    match beneficial(world, id.definition(), id.account())? {
        Some(
            BeneficialEnrollment::Retail
            | BeneficialEnrollment::Fi { enabled: true }
            | BeneficialEnrollment::System { enabled: true },
        ) => Ok(()),
        Some(_) => Err(reject("institutional asset enrollment is disabled")),
        None => Err(reject(
            "asset account requires explicit UID or institutional enrollment",
        )),
    }
}

/// Activation examines every existing positive balance, never only the UID roster.
/// Native custody is recognized from its retained record and exact original payer.
///
/// This is also the snapshot invariant: revocation does not make existing funds
/// disappear or reclassify them as retail. A stale institutional approval stops
/// new movements while preserving the retained institutional ownership category.
pub(crate) fn validate_reconciliation(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<(), Error> {
    // Build one borrowed index for the exact asset. Each retained row is visited
    // once; activation must not rescan all escrows for every positive holder.
    let mut custody = BTreeMap::new();
    for (_, record) in world.asset_escrows().iter() {
        if record.asset_definition != *definition {
            continue;
        }
        if custody.insert(&record.custody, record).is_some()
            || beneficial(world, definition, &record.custody)?.is_some()
        {
            return Err(reject("asset custody classification is ambiguous"));
        }
        if !record.remaining_amount.is_zero() {
            let id = AssetId::new(definition.clone(), record.custody.clone());
            if world
                .assets()
                .get(&id)
                .is_none_or(|value| value.as_ref() != &record.remaining_amount)
                || beneficial(world, definition, &record.seller)?.is_none()
            {
                return Err(reject("unresolved native custody is not fully reconciled"));
            }
        }
    }
    for asset in world.asset_entries_by_definition_iter(definition) {
        let id = asset.id();
        if asset.value().as_ref().is_zero() {
            continue;
        }
        if id.scope() != &AssetBalanceScope::Global {
            return Err(reject(
                "positive non-Global balance blocks UID enrollment activation",
            ));
        }
        if beneficial(world, definition, id.account())?.is_some() {
            continue;
        }
        let record = custody.get(id.account()).ok_or_else(|| {
            reject("unclassified positive balance blocks UID enrollment activation")
        })?;
        if record.remaining_amount.is_zero()
            || asset.value().as_ref() != &record.remaining_amount
            || beneficial(world, definition, &record.seller)?.is_none()
        {
            return Err(reject(
                "unreconciled native custody blocks UID enrollment activation",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_persistence(world: &impl WorldReadOnly) -> Result<(), Error> {
    for (key, _) in world.smart_contract_state().iter() {
        if key.as_ref().starts_with(ENROLLMENT_ROOT) {
            let value: AssetUidEnrollmentV1 =
                read(world, key)?.ok_or_else(|| reject("missing enrollment state"))?;
            if *key != enrollment_key(&value.asset_definition_id)
                || enrollment(world, &value.asset_definition_id)?.as_ref() != Some(&value)
            {
                return Err(reject("invalid retained asset enrollment"));
            }
            world.asset_definition(&value.asset_definition_id)?;
            validate_reconciliation(world, &value.asset_definition_id)?;
        } else if key.as_ref().starts_with(SYSTEM_ROOT) {
            let value: AssetUidSystemAccountV1 =
                read(world, key)?.ok_or_else(|| reject("missing system enrollment"))?;
            if *key != system_key(&value.asset_definition_id, &value.account_id)
                || system(world, &value.asset_definition_id, &value.account_id)?.as_ref()
                    != Some(&value)
            {
                return Err(reject("invalid retained system enrollment"));
            }
            world.asset_definition(&value.asset_definition_id)?;
            world.account(&value.account_id)?;
            beneficial(world, &value.asset_definition_id, &value.account_id)?;
            if world
                .asset_escrows()
                .iter()
                .any(|(_, record)| record.custody == value.account_id)
            {
                return Err(reject(
                    "native custody cannot be an institutional system account",
                ));
            }
        }
    }
    Ok(())
}


/// Retained enrollment cannot be discarded by deleting its definition or account.
pub(crate) fn retained(
    world: &impl WorldReadOnly,
    definition: Option<&AssetDefinitionId>,
    account: Option<&AccountId>,
) -> Result<bool, Error> {
    for (key, _) in world.smart_contract_state().iter() {
        if key.as_ref() == ENROLLMENT_ROOT.trim_end_matches('/')
            || key.as_ref().starts_with(ENROLLMENT_ROOT)
        {
            let value: AssetUidEnrollmentV1 = read(world, key)?
                .ok_or_else(|| reject("missing retained asset enrollment"))?;
            if definition == Some(&value.asset_definition_id) {
                return Ok(true);
            }
        } else if key.as_ref() == SYSTEM_ROOT.trim_end_matches('/')
            || key.as_ref().starts_with(SYSTEM_ROOT)
        {
            let value: AssetUidSystemAccountV1 = read(world, key)?
                .ok_or_else(|| reject("missing retained system enrollment"))?;
            if definition == Some(&value.asset_definition_id)
                || account == Some(&value.account_id)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
