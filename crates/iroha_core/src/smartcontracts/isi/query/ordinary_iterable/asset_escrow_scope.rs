//! One complete asset original through the native ordinary-query allocation corridor.
use super::*;
use iroha_data_model::{
    escrow::{AssetEscrowRecord, scoped::{AssetEscrowScopeOriginalV1, AssetEscrowScopeV1, scope_key}},
    query::asset_escrow_scope::FindAssetEscrowsByAssetDefinitionV1,
};

fn decode<T>(bytes: &[u8], graph: &mut RetainedDecodeBudget) -> Result<T, QueryAttemptError>
where T: NoritoSerialize + for<'de> norito::core::NoritoDeserialize<'de> {
    let elements = bytes.len().checked_mul(8).ok_or(Error::CapacityLimit)?;
    let limits = norito::DecodeLimits::new(elements, bytes.len(), elements, graph.next_limit()?, 64);
    let (result, usage) = norito::core::with_decode_limits_measured(limits,
        || norito::decode_canonical_for_admission(bytes, limits));
    let owned = result.map_err(|error| -> QueryAttemptError { match error.into_local_refusal() {
        Ok(original) => crate::execution_attempt::ExecutionAttemptError::Deferred(original.into()),
        Err(error) if error.error().is_decode_resource_limit() => Error::CapacityLimit.into(),
        Err(_) => Error::Conversion("invalid canonical escrow scope source".into()).into(),
    }})?;
    graph.record_decoded(usage.total_allocated_bytes())?;
    Ok(owned)
}

pub(super) fn collect(
    query: &FindAssetEscrowsByAssetDefinitionV1, params: &QueryParams,
    mode: OrdinaryCursorMode, limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<(ExactOwnedRows<AssetEscrowScopeOriginalV1>, QueryExecutionStats), QueryAttemptError> {
    // One complete original cannot be split into a resumable prefix. Requiring
    // ephemeral mode also prevents a cursor from mixing scopes or World cuts.
    if mode != OrdinaryCursorMode::Ephemeral || params.pagination.offset_value() != 0
        || params.sorting.sort_by_metadata_key.is_some() {
        return Err(Error::Conversion("escrow scope admits only an unsorted ephemeral complete result".into()).into());
    }
    let (_, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let world = state.world();
    if world.axt_asset_incarnations().get(&query.asset_definition_id) != Some(&query.expected_incarnation) {
        return Err(Error::Conversion("escrow scope live incarnation differs from the selected original".into()).into());
    }
    let key = scope_key(&query.asset_definition_id, &query.expected_incarnation)
        .map_err(|message| Error::Conversion(message.into()))?;
    let mut stats = QueryExecutionStats::default();
    stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
    let bytes = world.smart_contract_state().get(&key)
        .ok_or_else(|| Error::Conversion("asset escrow scope is uninitialized".into()))?;
    if bytes.len() > maximum { return Err(Error::CapacityLimit.into()); }
    let (mut graph, output_slots) = RetainedDecodeBudget::new::<AssetEscrowScopeOriginalV1>(1, limits.max_source_item_bytes())?;
    let scope: AssetEscrowScopeV1 = decode(bytes, &mut graph)?;
    if scope.asset_definition_id != query.asset_definition_id
        || scope.asset_incarnation != query.expected_incarnation || scope.revision == 0 {
        return Err(Error::Conversion("escrow scope differs from its exact native key".into()).into());
    }
    let count = usize::try_from(scope.record_count).map_err(|_| Error::CapacityLimit)?;
    let record_slots = exact_slot_bytes::<AssetEscrowRecord>(count)?;
    graph.record_decoded(usize::try_from(record_slots).map_err(|_| Error::CapacityLimit)?)?;
    graph.record_decoded(bytes.len())?;
    let mut records = ExactOwnedRows::new(count, record_slots)?;
    let mut scope_bytes = ExactOwnedRows::new(bytes.len(), u64::try_from(bytes.len()).map_err(|_| Error::CapacityLimit)?)?;
    for byte in bytes { scope_bytes.push(*byte)?; }
    // Charge every visited canonical row before inspection, including other assets.
    // No finite prefix or scan failure can be returned as complete.
    for (id, record) in world.asset_escrows().iter() {
        stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
        if &record.id != id { return Err(Error::Conversion("escrow source key differs from record".into()).into()); }
        if record.asset_definition != query.asset_definition_id { continue; }
        let frame = encode_bounded_frame(record, maximum)?;
        let owned: AssetEscrowRecord = decode(&frame, &mut graph)?;
        records.push(owned)?;
    }
    let original = AssetEscrowScopeOriginalV1 {
        scope_original: scope_bytes.finish()?.into_vec()?, records: records.finish()?.into_vec()?,
    };
    scope.validate_records(&query.asset_definition_id, &query.expected_incarnation, &original.records)
        .map_err(|message| Error::Conversion(message.into()))?;
    drop(encode_bounded_frame(&original, maximum)?);
    let mut output = ExactOwnedRows::new(1, output_slots)?;
    output.push(original)?;
    Ok((output.finish()?, stats))
}
