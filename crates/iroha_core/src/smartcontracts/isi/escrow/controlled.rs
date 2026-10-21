//! Contract-authenticated native locks. Funds always belong to the original payer.
use super::*;
use crate::executor::ContractRuntimeExecutionContext;
use iroha_data_model::{
    escrow::control::{
        AssetLockControlV1, MAX_CONTROLLED_ASSET_LOCK_KEY_BYTES_V1, controlled_asset_lock_id,
        is_reserved_controlled_asset_lock_id_v1,
    },
    isi::{
        InstructionBox,
        escrow_control::{
            CancelControlledAssetLockV1, DrawdownControlledAssetLockV1,
            ExpireControlledAssetLockV1, OpenControlledAssetLockV1,
        },
    },
};

/// Reserved, native-written control terms; generic contract state cannot alter them.
pub(crate) const STATE_ROOT: &str = "asset_lock_control_v1/";

fn key(id: &EscrowId) -> StatePath {
    format!("{STATE_ROOT}{}", hex::encode(id.as_hash().as_ref()))
        .parse()
        .expect("native escrow control state path")
}

fn control(world: &impl WorldReadOnly, id: &EscrowId) -> Result<Option<AssetLockControlV1>, Error> {
    world
        .smart_contract_state()
        .get(&key(id))
        .map(|bytes| {
            norito::decode_canonical(bytes)
                .map_err(|_| validation_err("invalid native asset lock control state"))
        })
        .transpose()
}

/// Generic instructions never inherit a contract's authority over a controlled lock.
pub(super) fn reject_generic_mutation(
    world: &impl WorldReadOnly,
    id: &EscrowId,
) -> Result<(), Error> {
    if control(world, id)?.is_some() {
        return Err(validation_err(
            "controlled asset lock requires its authenticated controller instruction",
        ));
    }
    Ok(())
}

pub(super) fn authenticate<'a>(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    context: Option<&'a ContractRuntimeExecutionContext>,
    terms: &AssetLockControlV1,
) -> Result<&'a ContractRuntimeExecutionContext, Error> {
    let context = context.ok_or_else(|| {
        validation_err("controlled asset lock requires authenticated contract runtime")
    })?;
    if context.contract_address != terms.controller
        || !crate::executor::valid_contract_runtime_subject(world, authority, Some(context))
    {
        return Err(validation_err(
            "controlled asset lock requires the exact active controller instance",
        ));
    }
    Ok(context)
}

pub(super) fn existing_control(
    world: &impl WorldReadOnly,
    id: &EscrowId,
) -> Result<AssetLockControlV1, Error> {
    let terms =
        control(world, id)?.ok_or_else(|| validation_err("asset lock has no native controller"))?;
    let record = world
        .asset_escrows()
        .get(id)
        .ok_or_else(|| validation_err("controlled asset lock is missing"))?;
    ensure_asset_lock(record)?;
    if record.release_authority.as_ref() != Some(&terms.controller.subject_id()) {
        return Err(validation_err(
            "asset lock controller differs from retained record",
        ));
    }
    Ok(terms)
}

fn execute_open(
    instruction: OpenControlledAssetLockV1,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
    context: Option<&ContractRuntimeExecutionContext>,
) -> Result<(), Error> {
    authenticate(tx.world(), authority, context, &instruction.control)?;
    if instruction.key.is_empty() || instruction.key.len() > MAX_CONTROLLED_ASSET_LOCK_KEY_BYTES_V1
    {
        return Err(validation_err(
            "controlled asset lock key must contain 1..=4096 bytes",
        ));
    }
    if instruction.lock.escrow_id
        != controlled_asset_lock_id(&instruction.control.controller, &instruction.key)
    {
        return Err(validation_err(
            "controlled asset lock id differs from its exact controller and key",
        ));
    }
    if instruction.lock.release_authority.as_ref()
        != Some(&instruction.control.controller.subject_id())
    {
        return Err(validation_err(
            "controlled asset lock release authority must equal controller subject",
        ));
    }
    if control(tx.world(), &instruction.lock.escrow_id)?.is_some() {
        return Err(validation_err("asset lock control already exists"));
    }
    // Validate the contract's exact source-asset or asset-definition debit grant
    // before using native custody. No prefunding through the controller occurs.
    super::super::asset::isi::ensure_user_numeric_asset_source_authority(
        tx,
        authority,
        &AssetId::new(
            instruction.lock.asset_definition.clone(),
            instruction.source.clone(),
        ),
    )?;
    let bytes = norito::encode_canonical(&instruction.control)
        .map_err(|_| validation_err("cannot encode native asset lock control"))?;
    let state_key = key(&instruction.lock.escrow_id);
    execute_open_asset_lock(
        instruction.lock,
        &instruction.source,
        tx,
        AssetLockNamespace::Controlled,
    )?;
    tx.world.smart_contract_state.insert(state_key, bytes);
    Ok(())
}

/// Handle only the four controlled instructions after executor runtime guards.
/// JSON payloads, ordinary native instructions and a signed controller account
/// cannot construct the authenticated runtime frame passed through this corridor.
pub(crate) fn execute_instruction(
    instruction: &InstructionBox,
    authority: &AccountId,
    tx: &mut StateTransaction<'_, '_>,
    context: Option<&ContractRuntimeExecutionContext>,
) -> Option<Result<(), Error>> {
    if let Some(open) = instruction
        .as_any()
        .downcast_ref::<OpenControlledAssetLockV1>()
    {
        return Some(execute_open(open.clone(), authority, tx, context));
    }
    if let Some(draw) = instruction
        .as_any()
        .downcast_ref::<DrawdownControlledAssetLockV1>()
    {
        return Some((|| {
            let terms = existing_control(tx.world(), &draw.drawdown.escrow_id)?;
            authenticate(tx.world(), authority, context, &terms)?;
            if !terms.permits_claim_at(tx.block_unix_timestamp_ms()) {
                return Err(validation_err(
                    "controlled asset lock claim window has ended",
                ));
            }
            let frame = authenticate(tx.world(), authority, context, &terms)?;
            execute_drawdown_asset_lock(draw.drawdown.clone(), authority, tx, true, draw.waterfall.as_ref().map(|pins| (pins, frame)))
        })());
    }
    if let Some(cancel) = instruction
        .as_any()
        .downcast_ref::<CancelControlledAssetLockV1>()
    {
        return Some((|| {
            let terms = existing_control(tx.world(), &cancel.cancel.escrow_id)?;
            authenticate(tx.world(), authority, context, &terms)?;
            if !terms.permits_cancel_at(tx.block_unix_timestamp_ms()) {
                return Err(validation_err(
                    "controlled asset lock cancellation window has not begun",
                ));
            }
            let frame = authenticate(tx.world(), authority, context, &terms)?;
            execute_cancel_asset_lock(cancel.cancel.clone(), authority, tx, true, cancel.waterfall.as_ref().map(|pins| (pins, frame)))
        })());
    }
    if let Some(expiry) = instruction
        .as_any()
        .downcast_ref::<ExpireControlledAssetLockV1>()
    {
        return Some((|| {
            let terms = existing_control(tx.world(), &expiry.expiry.escrow_id)?;
            authenticate(tx.world(), authority, context, &terms)?;
            if !terms.permits_cancel_at(tx.block_unix_timestamp_ms()) {
                return Err(validation_err(
                    "controlled asset lock refund window has not begun",
                ));
            }
            let frame = authenticate(tx.world(), authority, context, &terms)?;
            execute_expire_asset_lock(expiry.expiry.clone(), authority, tx, true, expiry.waterfall.as_ref().map(|pins| (pins, frame)))
        })());
    }
    None
}

macro_rules! reject_unframed {
    ($($instruction:ty),+ $(,)?) => {$(
        impl Execute for $instruction {
            fn execute(self, _authority: &AccountId, _tx: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
                Err(validation_err("controlled asset lock requires authenticated executor runtime"))
            }
        }
    )+};
}
reject_unframed!(
    OpenControlledAssetLockV1,
    DrawdownControlledAssetLockV1,
    CancelControlledAssetLockV1,
    ExpireControlledAssetLockV1,
);

/// Fail closed on corrupted or orphaned retained control terms.
pub(crate) fn validate_persistence(world: &impl WorldReadOnly) -> Result<(), Error> {
    for (path, bytes) in world.smart_contract_state().iter() {
        let text = path.to_string();
        let Some(id) = text.strip_prefix(STATE_ROOT) else {
            continue;
        };
        let id = EscrowId::new(
            id.parse::<iroha_crypto::Hash>()
                .map_err(|_| validation_err("invalid native asset lock control key"))?,
        );
        if key(&id) != *path || !is_reserved_controlled_asset_lock_id_v1(&id) {
            return Err(validation_err("noncanonical native asset lock control key"));
        }
        let terms: AssetLockControlV1 = norito::decode_canonical(bytes)
            .map_err(|_| validation_err("invalid native asset lock control encoding"))?;
        if existing_control(world, &id)? != terms {
            return Err(validation_err("inconsistent native asset lock control"));
        }
    }
    Ok(())
}
