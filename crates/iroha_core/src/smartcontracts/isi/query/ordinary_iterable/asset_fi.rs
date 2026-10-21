//! Bounded exact-wallet FI relationship projection for private native queries.

use super::*;
use crate::state::asset_fi;
use iroha_data_model::{
    asset::fi_link::{
        AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiRelationshipViewV1, AssetFiV1,
    },
    query::asset_fi::FindAssetFiLinkV1,
};
use iroha_model_base::state_path::StatePath;

/// The source has exactly one row; missing and revoked subrecords remain explicit.
pub(super) fn collect_asset_fi_link(
    query: &FindAssetFiLinkV1,
    params: &QueryParams,
    mode: OrdinaryCursorMode,
    limits: OrdinaryQueryExecutionLimits,
    state: &impl StateReadOnly,
) -> Result<
    (
        ExactOwnedRows<AssetFiRelationshipViewV1>,
        QueryExecutionStats,
    ),
    Error,
> {
    let (_, maximum, work) = trigger_source_limits(params, mode, limits)?;
    let now = state.authenticated_query_ledger_time_ms().ok_or_else(|| {
        Error::Conversion("FI link query requires authenticated ledger time".into())
    })?;
    let height = u64::try_from(state.height()).map_err(|_| Error::CapacityLimit)?;
    let world = state.world();
    world.asset_definition(&query.asset_definition_id)?;
    world.account(&query.account_id)?;
    let mut stats = QueryExecutionStats::default();
    let (mut graph, slot_bytes) =
        RetainedDecodeBudget::new::<AssetFiRelationshipViewV1>(1, limits.max_source_item_bytes())?;
    let mut rows = ExactOwnedRows::new(1, slot_bytes)?;
    let elements = maximum.checked_mul(8).ok_or(Error::CapacityLimit)?;
    let decode_limits =
        norito::DecodeLimits::new(elements, maximum, elements, graph.next_limit()?, 64);
    let (row, usage) = norito::core::with_decode_limits_measured(decode_limits, || {
        let mut read = |key: StatePath| -> Result<Option<&[u8]>, Error> {
            stats.record_preflighted_item(work, Some(limits.execution_budget()))?;
            let bytes = world.smart_contract_state().get(&key);
            if bytes.is_some_and(|bytes| bytes.len() > maximum) {
                return Err(Error::CapacityLimit);
            }
            Ok(bytes.map(Vec::as_slice))
        };
        let fi = read(asset_fi::fi_key(
            &query.asset_definition_id,
            &query.fi_account_id,
        ))?
        .map(|bytes| {
            norito::decode_canonical_with_limits::<AssetFiV1>(bytes, decode_limits)
                .map_err(|_| Error::CapacityLimit)
        })
        .transpose()?;
        let attestation = read(asset_fi::attestation_key(
            &query.asset_definition_id,
            &query.account_id,
            &query.fi_account_id,
            &query.reference_digest,
        ))?
        .map(|bytes| {
            norito::decode_canonical_with_limits::<AssetFiLinkAttestationV1>(bytes, decode_limits)
                .map_err(|_| Error::CapacityLimit)
        })
        .transpose()?;
        let link = read(asset_fi::link_key(
            &query.asset_definition_id,
            &query.account_id,
        ))?
        .map(|bytes| {
            norito::decode_canonical_with_limits::<AssetFiLinkV1>(bytes, decode_limits)
                .map_err(|_| Error::CapacityLimit)
        })
        .transpose()?;
        if fi.as_ref().is_some_and(|value| {
            value.asset_definition_id != query.asset_definition_id
                || value.fi_account_id != query.fi_account_id
                || value.revision == 0
        }) || attestation.as_ref().is_some_and(|value| {
            value.asset_definition_id != query.asset_definition_id
                || value.account_id != query.account_id
                || value.fi_account_id != query.fi_account_id
                || value.reference_digest != query.reference_digest
                || value.revision == 0
        }) || link.as_ref().is_some_and(|value| {
            value.asset_definition_id != query.asset_definition_id
                || value.account_id != query.account_id
                || asset_fi::validate_link_shape(value).is_err()
        }) {
            return Err(Error::Conversion(
                "FI relationship differs from exact native source key".into(),
            ));
        }
        Ok(AssetFiRelationshipViewV1 {
            fi,
            attestation,
            link,
            ledger_time_ms: now,
            as_of_height: height,
        })
    });
    let row = row?;
    drop(encode_bounded_frame(&row, maximum)?);
    graph.record_decoded(usage.total_allocated_bytes())?;
    rows.push(row)?;
    Ok((rows.finish()?, stats))
}
