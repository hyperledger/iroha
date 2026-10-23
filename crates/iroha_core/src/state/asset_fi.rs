//! Native FI relationships retained separately from participant-held bank details.

use super::*;
#[path = "asset_fi/reader.rs"]
mod reader;
#[path = "asset_fi/receipt.rs"]
pub(crate) mod receipt;
use iroha_data_model::{
    asset::fi_link::{AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiV1},
    isi::error::InstructionExecutionError,
};
#[cfg(test)]
pub(crate) use reader::tests::Fixture as FiLinkReaderFixture;
pub(crate) use reader::{AssetFiLinkRevisionError, link_revision_for_contract};

pub(crate) const FI_ROOT: &str = "asset_fi_v1/";
pub(crate) const ATTESTATION_ROOT: &str = "asset_fi_link_attestation_v1/";
pub(crate) const LINK_ROOT: &str = "asset_fi_link_v1/";
// Native physical storage under the already-reserved sc/ root. A contract digest
// is 64 hexadecimal characters, so no contract owns sc/native/.
pub(crate) const RECEIPT_ROOT: &str = "sc/native/asset_fi_transfer_receipt_v1/";
type Error = InstructionExecutionError;

/// Existing transaction-frozen ceiling for assertion byte/codec graph bounds.
/// This is accounting only, not an independent physical allocation reservation.
pub(crate) fn assertion_encoding_ceiling(tx: &StateTransaction<'_, '_>) -> Result<usize, Error> {
    usize::try_from(tx.fastpq_source_policy.1.max_output_bytes)
        .map_err(|_| reject("FI assertion frozen byte ceiling exceeds host width"))
}

pub(crate) fn reject(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}

fn path(value: String) -> StatePath {
    value.parse().expect("fixed native FI relationship path")
}

pub(crate) fn fi_key(definition: &AssetDefinitionId, fi: &AccountId) -> StatePath {
    super::asset_context_keys::fi_native(definition, &fi.to_string())
}
pub(crate) fn attestation_key(definition: &AssetDefinitionId, account: &AccountId, fi: &AccountId, reference: &[u8; 32]) -> StatePath {
    super::asset_context_keys::attestation_native(definition, &account.to_string(), &fi.to_string(), reference)
}
pub(crate) fn link_key(definition: &AssetDefinitionId, account: &AccountId) -> StatePath {
    super::asset_context_keys::link_native(definition, &account.to_string())
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
                .map_err(|error| reject(format!("invalid native FI state: {error}")))
        })
        .transpose()
}

pub(crate) fn fi(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<AssetFiV1>, Error> {
    let value: Option<AssetFiV1> = read(world, &fi_key(definition, account))?;
    if value.as_ref().is_some_and(|v| {
        v.asset_definition_id != *definition || v.fi_account_id != *account || v.revision == 0
    }) {
        return Err(reject("native FI record differs from its canonical key"));
    }
    Ok(value)
}

pub(crate) fn attestation(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
    fi: &AccountId,
    reference: &[u8; 32],
) -> Result<Option<AssetFiLinkAttestationV1>, Error> {
    let value: Option<AssetFiLinkAttestationV1> =
        read(world, &attestation_key(definition, account, fi, reference))?;
    if value.as_ref().is_some_and(|v| {
        v.asset_definition_id != *definition
            || v.account_id != *account
            || v.fi_account_id != *fi
            || v.reference_digest != *reference
            || v.reference_digest == [0; 32]
            || v.revision == 0
            || v.account_id == v.fi_account_id
    }) {
        return Err(reject(
            "native FI attestation differs from its canonical key",
        ));
    }
    Ok(value)
}

pub(crate) fn validate_link_shape(value: &AssetFiLinkV1) -> Result<(), Error> {
    if value.revision == 0
        || value.fi_revision == 0
        || value.attestation_revision == 0
        || value.reference_digest == [0; 32]
        || value.account_id == value.fi_account_id
        || ((value.waterfall || value.reverse_waterfall)
            && (!value.enabled || value.controller.is_none()))
    {
        return Err(reject("invalid native owner-approved FI link shape"));
    }
    Ok(())
}

pub(crate) fn link(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<AssetFiLinkV1>, Error> {
    let value: Option<AssetFiLinkV1> = read(world, &link_key(definition, account))?;
    if let Some(value) = &value {
        validate_link_shape(value)?;
        if value.asset_definition_id != *definition || value.account_id != *account {
            return Err(reject("native FI link differs from its canonical key"));
        }
    }
    Ok(value)
}

/// Resolve only the exact currently eligible, FI-attested, owner-approved link.
pub(crate) fn active_link(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
    expected_revision: u64,
) -> Result<AssetFiLinkV1, Error> {
    let value = link(world, definition, account)?
        .ok_or_else(|| reject("wallet has no owner-approved FI link"))?;
    if !value.enabled || value.revision != expected_revision {
        return Err(reject(
            "owner-approved FI link is disabled or its revision changed",
        ));
    }
    let fi = fi(world, definition, &value.fi_account_id)?
        .ok_or_else(|| reject("linked FI is not registered"))?;
    let attestation = attestation(
        world,
        definition,
        account,
        &value.fi_account_id,
        &value.reference_digest,
    )?
    .ok_or_else(|| reject("FI reference is not authenticated"))?;
    if !fi.enabled
        || fi.revision != value.fi_revision
        || !attestation.enabled
        || attestation.revision != value.attestation_revision
    {
        return Err(reject(
            "linked FI or reference approval was revoked or revised",
        ));
    }
    Ok(value)
}

/// Materialize an exact private relationship at one captured ledger watermark.
pub(crate) fn view(
    world: &impl WorldReadOnly,
    query: &iroha_data_model::query::asset_fi::FindAssetFiLinkV1,
    ledger_time_ms: u64,
    as_of_height: u64,
) -> Result<iroha_data_model::asset::fi_link::AssetFiRelationshipViewV1, Error> {
    world.asset_definition(&query.asset_definition_id)?;
    world.account(&query.account_id)?;
    Ok(
        iroha_data_model::asset::fi_link::AssetFiRelationshipViewV1 {
            fi: fi(world, &query.asset_definition_id, &query.fi_account_id)?,
            attestation: attestation(
                world,
                &query.asset_definition_id,
                &query.account_id,
                &query.fi_account_id,
                &query.reference_digest,
            )?,
            link: link(world, &query.asset_definition_id, &query.account_id)?,
            ledger_time_ms,
            as_of_height,
        },
    )
}

fn in_root(key: &StatePath, root: &str) -> bool {
    key.as_ref() == root.trim_end_matches('/') || key.as_ref().starts_with(root)
}

/// Keep all referenced accounts and definitions alive across revocation.
pub(crate) fn retained(
    world: &impl WorldReadOnly,
    definition: Option<&AssetDefinitionId>,
    account: Option<&AccountId>,
) -> Result<bool, Error> {
    for (key, _) in world.smart_contract_state().iter() {
        let references = if in_root(key, FI_ROOT) {
            let value: AssetFiV1 = read(world, key)?.ok_or_else(|| reject("missing FI state"))?;
            Some((value.asset_definition_id, vec![value.fi_account_id]))
        } else if in_root(key, ATTESTATION_ROOT) {
            let value: AssetFiLinkAttestationV1 =
                read(world, key)?.ok_or_else(|| reject("missing FI attestation"))?;
            Some((
                value.asset_definition_id,
                vec![value.fi_account_id, value.account_id],
            ))
        } else if in_root(key, LINK_ROOT) {
            let value: AssetFiLinkV1 =
                read(world, key)?.ok_or_else(|| reject("missing FI link"))?;
            let mut accounts = vec![value.fi_account_id, value.account_id];
            if let Some(controller) = value.controller {
                accounts.push(controller.subject_id());
            }
            Some((value.asset_definition_id, accounts))
        } else if in_root(key, RECEIPT_ROOT) {
            let value = receipt::read_record(world, key)?;
            Some((
                value.instruction.asset_definition_id.clone(),
                receipt::referenced_accounts(&value),
            ))
        } else {
            None
        };
        if let Some((asset, accounts)) = references {
            if definition == Some(&asset) || account.is_some_and(|id| accounts.contains(id)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Validate canonical references on restore, while retaining legitimately stale approvals.
pub(crate) fn validate_persistence(world: &impl WorldReadOnly) -> Result<(), Error> {
    for (key, _) in world.smart_contract_state().iter() {
        if in_root(key, RECEIPT_ROOT) {
            let value = receipt::read_record(world, key)?;
            if world
                .asset_definition(&value.instruction.asset_definition_id)?
                .balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
            {
                return Err(reject("retained FI receipts require a Global definition"));
            }
            for account in receipt::referenced_accounts(&value) {
                world.account(&account)?;
            }
        } else if in_root(key, FI_ROOT) {
            let value: AssetFiV1 = read(world, key)?.ok_or_else(|| reject("missing FI state"))?;
            if key != &fi_key(&value.asset_definition_id, &value.fi_account_id)
                || fi(world, &value.asset_definition_id, &value.fi_account_id)?.is_none()
            {
                return Err(reject("noncanonical FI state path"));
            }
            if world
                .asset_definition(&value.asset_definition_id)?
                .balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
            {
                return Err(reject("FI relationships require a Global definition"));
            }
            world.account(&value.fi_account_id)?;
            if super::asset_uid::binding(world, &value.asset_definition_id, &value.fi_account_id)?
                .is_some()
                || super::asset_uid_enrollment::system(
                    world,
                    &value.asset_definition_id,
                    &value.fi_account_id,
                )?
                .is_some()
                || world
                    .asset_escrows()
                    .iter()
                    .any(|(_, record)| record.custody == value.fi_account_id)
            {
                return Err(reject(
                    "retained FI classification overlaps another category",
                ));
            }
        } else if in_root(key, ATTESTATION_ROOT) {
            let value: AssetFiLinkAttestationV1 =
                read(world, key)?.ok_or_else(|| reject("missing FI attestation"))?;
            if key
                != &attestation_key(
                    &value.asset_definition_id,
                    &value.account_id,
                    &value.fi_account_id,
                    &value.reference_digest,
                )
                || attestation(
                    world,
                    &value.asset_definition_id,
                    &value.account_id,
                    &value.fi_account_id,
                    &value.reference_digest,
                )?
                .is_none()
                || fi(world, &value.asset_definition_id, &value.fi_account_id)?.is_none()
            {
                return Err(reject("orphan or noncanonical FI attestation"));
            }
            world.account(&value.account_id)?;
        } else if in_root(key, LINK_ROOT) {
            let value: AssetFiLinkV1 =
                read(world, key)?.ok_or_else(|| reject("missing FI link"))?;
            if key != &link_key(&value.asset_definition_id, &value.account_id)
                || link(world, &value.asset_definition_id, &value.account_id)?.is_none()
                || attestation(
                    world,
                    &value.asset_definition_id,
                    &value.account_id,
                    &value.fi_account_id,
                    &value.reference_digest,
                )?
                .is_none()
            {
                return Err(reject("orphan or noncanonical FI link"));
            }
            world.account(&value.account_id)?;
            if super::asset_uid::member_policy(
                world,
                &value.asset_definition_id,
                &value.account_id,
            )?
            .is_none()
            {
                return Err(reject("owner-approved FI link has no retained UID policy"));
            }
            if let Some(controller) = value.controller {
                world.account(&controller.subject_id())?;
            }
        }
    }
    Ok(())
}
