//! Exact private FI occurrence candidates through the ordinary query owner.
//!
//! A returned original is not a certified membership or execution proof.
use super::*;
use crate::state::asset_fi::receipt;
use iroha_crypto::{Algorithm, Hash};
use iroha_data_model::{
    asset::{AssetBalancePolicy, fi_link::AssetFiTransferReceiptV1},
    isi::asset_fi::TransferToLinkedFiV1,
    query::asset_fi::FindAssetFiTransferReceiptV1,
};

fn decode_error(error: norito::core::DecodeAttemptError) -> QueryAttemptError {
    match error.into_local_refusal() {
        Ok(original) => crate::execution_attempt::ExecutionAttemptError::Deferred(original.into()),
        Err(error) if error.error().is_decode_resource_limit() => Error::CapacityLimit.into(),
        Err(_) => Error::Conversion("invalid canonical FI receipt candidate".into()).into(),
    }
}

/// Own temporary instruction material only after charging its exact layouts.
fn instruction_hash(
    value: &TransferToLinkedFiV1,
    graph: &mut RetainedDecodeBudget,
    maximum: usize,
) -> Result<Hash, QueryAttemptError> {
    let quantity_bytes = value.amount.admission_clone_layout()
        .map_err(|_| Error::CapacityLimit)?.size();
    let box_bytes = core::mem::size_of::<TransferToLinkedFiV1>();
    graph.record_decoded(quantity_bytes.checked_add(box_bytes).ok_or(Error::CapacityLimit)?)?;
    let scope = norito::DecodeLimits::new(0, 0, 0, graph.next_limit()?, 0);
    let (account, usage) = norito::core::with_decode_limits_measured(scope, || {
        norito::core::classify_decode_attempt(|| value.account_id.try_clone_for_admission())
    });
    let account_id = account.map_err(decode_error)?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    let amount = value.amount.try_clone_for_admission().map_err(|error| -> QueryAttemptError {
        match error {
            iroha_primitives::bigint::BigIntAdmissionCloneError::Allocator { .. } =>
                crate::execution_attempt::ExecutionAttemptError::Deferred(
                    ivm::error::ExecutionDeferral::AllocationUnavailable.into()),
            _ => Error::CapacityLimit.into(),
        }
    })?;
    // The existing exact allocation helper is used for the prepaid one-element box.
    // No infallible Box::new or unmetered clone is introduced into this corridor.
    let (mut allocation, _) = try_exact_uninit_box::<TransferToLinkedFiV1>(1)?;
    allocation[0].write(TransferToLinkedFiV1 {
        asset_definition_id: value.asset_definition_id.clone(),
        account_id,
        amount,
        expected_link_revision: value.expected_link_revision,
        expected_policy_revision: value.expected_policy_revision,
    });
    let pointer = Box::into_raw(allocation).cast::<TransferToLinkedFiV1>();
    // SAFETY: the exact allocation contains one initialized value; its alignment,
    // size and allocator are identical to Box<TransferToLinkedFiV1>.
    let instruction = unsafe { Box::from_raw(pointer) };
    let boxed = iroha_data_model::isi::Instruction::into_instruction_box(instruction);
    let available = maximum.min(graph.next_limit()?);
    let bytes = encode_bounded_frame(&boxed, available)?;
    graph.record_decoded(bytes.len())?;
    Ok(Hash::new(bytes))
}

pub(super) fn collect(
    query: &FindAssetFiTransferReceiptV1,
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<AssetFiTransferReceiptV1>, QueryExecutionStats), QueryAttemptError> {
    if mode != OrdinaryCursorMode::Ephemeral || params.pagination.offset_value() != 0
        || params.sorting.sort_by_metadata_key.is_some()
    {
        return Err(Error::Conversion("FI receipt requires one unsorted ephemeral exact lookup".into()).into());
    }
    let (_, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let mut stats = QueryExecutionStats::default();
    // Charge key rendering, canonical decoding and instruction/body validation
    // before any World lookup; even a missing receipt consumes this work.
    stats.record_preflighted_item(work.checked_mul(4).ok_or(Error::CapacityLimit)?, Some(limits.execution_budget()))?;
    query.expected_incarnation.validate().map_err(|error| Error::Conversion(error.to_string()))?;
    let world = state.world();
    let definition = world.asset_definition(&query.asset_definition_id)
        .map_err(|error| Error::Conversion(error.to_string()))?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err(Error::Conversion("FI receipt lookup requires a Global asset definition".into()).into());
    }
    world.account(&query.account_id).map_err(|error| Error::Conversion(error.to_string()))?;
    let (mut graph, slots) = RetainedDecodeBudget::new::<AssetFiTransferReceiptV1>(1, limits.max_source_item_bytes())?;
    let key_scope = norito::DecodeLimits::new(0, 0, 0, graph.next_limit()?, 64);
    let (account_json, key_usage) = norito::core::with_decode_limits_measured(key_scope, || {
        norito::core::classify_decode_attempt(|| {
            norito::json::to_json_bounded(&query.account_id, maximum)
                .map_err(norito::json::BoundedJsonError::into_core_error)
        })
    });
    let account_json = account_json.map_err(decode_error)?;
    graph.record_decoded(key_usage.total_allocated_bytes())?;
    // AccountId's checked JSON writer emits the canonical I105 literal directly,
    // enclosed in quotes. It contains no JSON escape sequences.
    let account_text = account_json.strip_prefix('"').and_then(|text| text.strip_suffix('"'))
        .filter(|text| !text.contains(['"', '\\']))
        .ok_or_else(|| Error::Conversion("invalid canonical account key text".into()))?;
    let key_scope = norito::DecodeLimits::new(0, 0, 0, graph.next_limit()?, 64);
    let (key, key_usage) = norito::core::with_decode_limits_measured(key_scope, || {
        norito::core::classify_decode_attempt(|| receipt::key_for_admission(
            &query.asset_definition_id, account_text, &query.execution_call_hash, query.transcript_index)
            .map_err(norito::json::Error::into_core_error))
    });
    let key = key.map_err(decode_error)?;
    graph.record_decoded(key_usage.total_allocated_bytes())?;
    drop(account_json);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok((ExactOwnedRows::new(0, 0)?.finish()?, stats));
    };
    if bytes.len() > maximum { return Err(Error::CapacityLimit.into()); }
    let elements = bytes.len().checked_mul(8).ok_or(Error::CapacityLimit)?;
    let scope = norito::DecodeLimits::new(elements, bytes.len(), elements, graph.next_limit()?, 64);
    let (value, usage) = norito::core::with_decode_limits_measured(scope, || {
        norito::decode_canonical_for_admission::<AssetFiTransferReceiptV1>(bytes, scope)
    });
    let value = value.map_err(decode_error)?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    if value.instruction.asset_definition_id != query.asset_definition_id
        || value.instruction.account_id != query.account_id
        || value.asset_incarnation != query.expected_incarnation
        || value.execution_call_hash != query.execution_call_hash
        || value.transcript_index != query.transcript_index
        || &value.network != state.network_id()
    {
        return Err(Error::Conversion("FI receipt differs from its exact native occurrence key".into()).into());
    }
    receipt::validate_fields(&value).map_err(|error| Error::Conversion(error.to_string()))?;
    if let Some(frame) = &value.controller {
        let expected = frame.address.try_subject_key_bytes(|bytes| {
            // Each deterministic hash-to-point attempt is charged before execution.
            stats.record_preflighted_item(u64::try_from(bytes).map_err(|_| Error::CapacityLimit)?, Some(limits.execution_budget()))
        })?;
        let matches = frame.subject.try_signatory().and_then(|key| key.try_to_bytes().ok())
            .is_some_and(|(algorithm, bytes)| algorithm == Algorithm::Ed25519 && bytes == expected);
        if !matches { return Err(Error::Conversion("FI receipt controller subject is inconsistent".into()).into()); }
    }
    if instruction_hash(&value.instruction, &mut graph, maximum)? != value.instruction_hash {
        return Err(Error::Conversion("FI receipt instruction hash is inconsistent".into()).into());
    }
    let mut rows = ExactOwnedRows::new(1, slots)?;
    rows.push(value)?;
    Ok((rows.finish()?, stats))
}
