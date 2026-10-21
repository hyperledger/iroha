//! Bounded exact native FI/enrollment observations, without a history or roster scan.
use super::*;
use crate::state::{asset_fi, asset_uid_enrollment};
use iroha_data_model::{
    asset::{fi_link::{AssetFiV1, AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiRelationshipViewV1}, uid_enrollment::{AssetUidEnrollmentV1, AssetUidEnrollmentViewV1}},
    query::{asset_fi::FindAssetFiLinkV1, asset_uid_enrollment::FindAssetUidEnrollmentV1},
};
use iroha_model_base::state_path::StatePath;

/// Admit every exact lookup before reading or decoding its borrowed value.
fn point<T>(
    state: &impl StateReadOnly,
    key: &StatePath,
    maximum: usize,
    graph: &mut RetainedDecodeBudget,
    stats: &mut QueryExecutionStats,
    limits: OrdinaryQueryExecutionLimits,
) -> Result<Option<T>, QueryAttemptError>
where T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de> {
    stats.record_preflighted_item(limits.max_source_item_bytes(), Some(limits.execution_budget()))?;
    let Some(bytes) = state.world().smart_contract_state().get(key) else { return Ok(None); };
    if bytes.len() > maximum { return Err(Error::CapacityLimit.into()); }
    let elements = maximum.checked_mul(8).ok_or(Error::CapacityLimit)?;
    let decode = norito::DecodeLimits::new(elements, maximum, elements, graph.next_limit()?, 64);
    let (result, usage) = norito::core::with_decode_limits_measured(decode, || norito::decode_canonical_for_admission(bytes, decode));
    let value = result.map_err(|error| -> QueryAttemptError { match error.into_local_refusal() {
        Ok(original) => crate::execution_attempt::ExecutionAttemptError::Deferred(original.into()),
        Err(error) if error.error().is_decode_resource_limit() => Error::CapacityLimit.into(),
        Err(_) => Error::Conversion("invalid canonical native relationship row".into()).into(),
    }})?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    Ok(Some(value))
}

fn watermark(state: &impl StateReadOnly) -> Result<(u64,u64), Error> {
    let time = state.authenticated_query_ledger_time_ms().ok_or_else(|| Error::Conversion("relationship query requires authenticated ledger time".into()))?;
    let height = u64::try_from(state.height()).map_err(|_| Error::CapacityLimit)?;
    Ok((time,height))
}

pub(super) fn collect_asset_fi(
    query: &FindAssetFiLinkV1, params: &QueryParams, mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits, state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<AssetFiRelationshipViewV1>, QueryExecutionStats), QueryAttemptError> {
    let (_,maximum,_) = trigger_source_limits(params, mode, limits)?;
    let (ledger_time_ms,as_of_height) = watermark(state)?;
    state.world().asset_definition(&query.asset_definition_id).map_err(|error| Error::Conversion(error.to_string()))?;
    state.world().account(&query.account_id).map_err(|error| Error::Conversion(error.to_string()))?;
    let (mut graph,slot_bytes) = RetainedDecodeBudget::new::<AssetFiRelationshipViewV1>(1,limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(1,slot_bytes)?;
    let mut stats = QueryExecutionStats::default();
    let fi: Option<AssetFiV1> = point(state,&asset_fi::fi_key(&query.asset_definition_id,&query.fi_account_id),maximum,&mut graph,&mut stats,limits)?;
    if fi.as_ref().is_some_and(|v| v.asset_definition_id!=query.asset_definition_id || v.fi_account_id!=query.fi_account_id || v.revision==0) {
        return Err(Error::Conversion("FI relationship differs from exact lookup".into()).into());
    }
    let attestation: Option<AssetFiLinkAttestationV1> = point(state,&asset_fi::attestation_key(&query.asset_definition_id,&query.account_id,&query.fi_account_id,&query.reference_digest),maximum,&mut graph,&mut stats,limits)?;
    if attestation.as_ref().is_some_and(|v| v.asset_definition_id!=query.asset_definition_id || v.account_id!=query.account_id || v.fi_account_id!=query.fi_account_id || v.reference_digest!=query.reference_digest || v.reference_digest==[0;32] || v.revision==0 || v.account_id==v.fi_account_id) {
        return Err(Error::Conversion("FI attestation differs from exact lookup".into()).into());
    }
    let link: Option<AssetFiLinkV1> = point(state,&asset_fi::link_key(&query.asset_definition_id,&query.account_id),maximum,&mut graph,&mut stats,limits)?;
    if let Some(value)=&link {
        asset_fi::validate_link_shape(value).map_err(|error| Error::Conversion(error.to_string()))?;
        if value.asset_definition_id!=query.asset_definition_id || value.account_id!=query.account_id {
            return Err(Error::Conversion("wallet FI link differs from exact lookup".into()).into());
        }
    }
    let row = AssetFiRelationshipViewV1{fi,attestation,link,ledger_time_ms,as_of_height};
    drop(encode_bounded_frame(&row,maximum)?);
    rows.push(row)?;
    Ok((rows.finish()?,stats))
}

pub(super) fn collect_asset_uid_enrollment(
    query: &FindAssetUidEnrollmentV1, params: &QueryParams, mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits, state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<AssetUidEnrollmentViewV1>, QueryExecutionStats), QueryAttemptError> {
    let (_,maximum,_) = trigger_source_limits(params,mode,limits)?;
    let (ledger_time_ms,as_of_height)=watermark(state)?;
    state.world().asset_definition(&query.asset_definition_id).map_err(|error| Error::Conversion(error.to_string()))?;
    let (mut graph,slot_bytes)=RetainedDecodeBudget::new::<AssetUidEnrollmentViewV1>(1,limits.max_source_item_bytes())?;
    let mut rows=ExactOwnedRows::new(1,slot_bytes)?;
    let mut stats=QueryExecutionStats::default();
    let enrollment: Option<AssetUidEnrollmentV1> = point(state,&asset_uid_enrollment::enrollment_key(&query.asset_definition_id),maximum,&mut graph,&mut stats,limits)?;
    if enrollment.as_ref().is_some_and(|v| v.asset_definition_id!=query.asset_definition_id || v.activated_at_height==0) {
        return Err(Error::Conversion("asset enrollment differs from exact lookup".into()).into());
    }
    let row=AssetUidEnrollmentViewV1{asset_definition_id:query.asset_definition_id.clone(),enrollment,ledger_time_ms,as_of_height};
    drop(encode_bounded_frame(&row,maximum)?);
    rows.push(row)?;
    Ok((rows.finish()?,stats))
}
