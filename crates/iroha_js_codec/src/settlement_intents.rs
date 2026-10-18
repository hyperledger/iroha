//! Atomic-settlement canonical ordering and consent intent hashes for JavaScript adapters.
//!
//! The executor admits an atomic settlement only when its movements are strictly
//! increasing by the native `(AssetId, AccountId)` ordering and its escrow legs by
//! `EscrowId` bytes, and every foreign source owner consents to the domain-separated
//! hash of the complete canonical instruction. Both properties depend on native `Ord`
//! and Norito encodings, so JavaScript delegates them here. The hashes are computed by
//! the same model methods Core checks: `SettleAtomic::intent_hash` and
//! `RepoIsi::{initiation,maturity}_intent_hash`.

use iroha_crypto::Hash;
use iroha_data_model::isi::{
    AtomicSettlementEscrow, AtomicSettlementMovement, InstructionBox, SettlementInstructionBox,
    repo::RepoInstructionBox,
};
use norito::json::{self, Value};

use crate::{CodecError, CodecErrorKind, CodecResult};

fn invalid(message: impl Into<String>) -> CodecError {
    CodecError::new(CodecErrorKind::InvalidArgument, message)
}

/// Borrow the `Settlement.Atomic` payload of an exact instruction envelope.
fn atomic_payload_mut(value: &mut Value) -> CodecResult<&mut json::Map> {
    let Value::Object(envelope) = value else {
        return Err(invalid("atomic settlement instruction must be an object"));
    };
    crate::require_exact_json_fields(envelope, &["Settlement"], "atomic settlement envelope")?;
    let Some(Value::Object(variants)) = envelope.get_mut("Settlement") else {
        return Err(invalid(
            "Settlement must be an object containing exactly Atomic",
        ));
    };
    crate::require_exact_json_fields(variants, &["Atomic"], "Settlement")?;
    let Some(Value::Object(payload)) = variants.get_mut("Atomic") else {
        return Err(invalid("Settlement.Atomic payload must be an object"));
    };
    Ok(payload)
}

/// Decode, sort and re-render one array field of `Settlement.Atomic`.
fn sort_field<T, K>(payload: &mut json::Map, field: &str, key: impl Fn(&T) -> K) -> CodecResult<()>
where
    T: json::JsonDeserialize + json::JsonSerialize,
    K: Ord,
{
    let Some(Value::Array(items)) = payload.get(field) else {
        return Err(invalid(format!(
            "Settlement.Atomic.{field} must be an array"
        )));
    };
    let mut parsed = items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            json::from_value::<T>(item.clone())
                .map_err(|error| invalid(format!("Settlement.Atomic.{field}[{index}]: {error}")))
        })
        .collect::<CodecResult<Vec<_>>>()?;
    parsed.sort_by_key(|item| key(item));
    let sorted = parsed
        .iter()
        .map(|item| json::to_value(item).map_err(crate::codec_error))
        .collect::<CodecResult<Vec<_>>>()?;
    payload.insert(field.to_owned(), Value::Array(sorted));
    Ok(())
}

/// Sort a `Settlement.Atomic` instruction into native canonical order.
///
/// Movements are ordered by `(source, recipient)` with the native `AssetId` and
/// `AccountId` orderings and escrow legs by `EscrowId` bytes. The complete instruction
/// is then admitted and rendered through its strict contract, so duplicate keys, leg
/// counts, scopes and every other model invariant remain rejected; quantities are never
/// coalesced.
///
/// # Errors
/// Returns an error when the envelope, a leg or the sorted instruction is invalid.
pub fn canonical_atomic_settlement_json(mut value: Value) -> CodecResult<Value> {
    let payload = atomic_payload_mut(&mut value)?;
    sort_field::<AtomicSettlementMovement, _>(payload, "movements", |movement| {
        (movement.source.clone(), movement.recipient.clone())
    })?;
    sort_field::<AtomicSettlementEscrow, _>(payload, "escrows", |escrow| escrow.escrow_id)?;
    let instruction = crate::value_to_instruction(value)?;
    crate::instruction_to_json_value(&instruction)
}

fn atomic_from_instruction(
    instruction: &InstructionBox,
) -> CodecResult<&iroha_data_model::isi::SettleAtomic> {
    match instruction
        .as_any()
        .downcast_ref::<SettlementInstructionBox>()
    {
        Some(SettlementInstructionBox::Atomic(atomic)) => Ok(atomic),
        _ => Err(invalid(
            "atomic intent hash requires a Settlement.Atomic instruction",
        )),
    }
}

/// Compute the `CanExecuteSettlement.intent_hash` for an exact `Settlement.Atomic` value.
///
/// The value is admitted through the strict instruction contract first, so a
/// noncanonical leg order or spelling is rejected rather than hashed.
///
/// # Errors
/// Returns an error when the value is not an admitted atomic settlement.
pub fn atomic_settlement_intent_hash(value: Value) -> CodecResult<Hash> {
    let instruction = crate::value_to_instruction(value)?;
    atomic_from_instruction(&instruction)?
        .intent_hash()
        .map_err(crate::codec_error)
}

/// Domain-separated initiation and maturity consent hashes of one repo initiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoIntentHashes {
    /// Hash consented by the counterparty for its cash debit.
    pub initiation: Hash,
    /// Hash consented by the collateral holder for the maturity collateral release.
    pub maturity: Hash,
}

/// Compute the exact `CanExecuteSettlement` intent hashes for a `Repo.Initiate` JSON value.
///
/// # Errors
/// Returns an error when the value is not an admitted `Repo.Initiate` instruction.
pub fn repo_intent_hashes(value: Value) -> CodecResult<RepoIntentHashes> {
    let instruction = crate::value_to_instruction(value)?;
    let Some(RepoInstructionBox::Initiate(repo)) =
        instruction.as_any().downcast_ref::<RepoInstructionBox>()
    else {
        return Err(invalid(
            "repo intent hashes require a Repo.Initiate instruction",
        ));
    };
    Ok(RepoIntentHashes {
        initiation: repo.initiation_intent_hash(),
        maturity: repo.maturity_intent_hash(),
    })
}

#[cfg(test)]
#[path = "settlement_intent_tests.rs"]
mod tests;
