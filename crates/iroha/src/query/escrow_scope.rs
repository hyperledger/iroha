//! Bounded owner-signed escrow scope transport. Results still require native World verification.
use super::*;
use iroha_data_model::{
    escrow::scoped::{AssetEscrowScopeOriginalV1, AssetEscrowScopeV1},
    query::{
        QueryOutputBatchBox, asset_escrow_scope::FindAssetEscrowsByAssetDefinitionV1,
        parameters::FetchSize,
    },
};

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

impl Client {
    /// Read one complete escrow scope as this client's signing authority.
    ///
    /// The native node admits only the exact current owner of the selected asset.
    /// This request always uses ephemeral, bounded-count execution with one result;
    /// it never inherits a stored-cursor default or follows a continuation. The
    /// response byte limit applies before decoding. No request is retransmitted.
    ///
    /// Returned data is an observation, not finality evidence. Authenticate it with
    /// `escrow::scoped::verify_at_world` against an independently selected certified
    /// World before using its completeness or records for monetary accounting.
    ///
    /// # Errors
    /// Refuses invalid response limits, unavailable transport or owner admission,
    /// noncanonical media/encoding, partial or repeated scopes, and selector changes.
    pub fn get_asset_escrow_scope_original(
        &self,
        query: FindAssetEscrowsByAssetDefinitionV1,
        maximum_bytes: usize,
    ) -> Result<AssetEscrowScopeOriginalV1, QueryError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_RESPONSE_BYTES {
            return Err(eyre!("escrow scope response limit must be in 1..=64 MiB").into());
        }
        query
            .expected_incarnation
            .validate()
            .map_err(|error| QueryError::Other(eyre!(error)))?;
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let (_, request) = self
            .query(query.clone())
            .with_fetch_size(FetchSize {
                fetch_size: NonZeroU64::new(1),
            })
            .into_request();
        let head = self.get_query_request_head();
        let body = head.sign_and_encode(QueryRequest::Start(request))?;
        let route = format!(
            "{}?cursor_mode=ephemeral&count_mode=bounded",
            torii_routes::pipeline::QUERY.path()
        );
        let response = send_once(|| {
            Ok(head
                .assemble_canonical_norito_body_at(body.clone(), &route)
                .max_response_bytes(maximum_bytes))
        })?;
        decode_scope_response(&response, &query, maximum_bytes)
    }
}

fn decode_scope_response(
    response: &http::Response<Vec<u8>>,
    query: &FindAssetEscrowsByAssetDefinitionV1,
    maximum_bytes: usize,
) -> Result<AssetEscrowScopeOriginalV1, QueryError> {
    if response.body().len() > maximum_bytes {
        return Err(eyre!("escrow scope response exceeds its byte limit").into());
    }
    if response.status() != StatusCode::OK {
        return Err(decode_query_failure(response));
    }
    let decoded: QueryResponse = Client::decode_canonical_norito_response(
        response,
        maximum_bytes,
        "query.asset_escrow_scope",
    )
    .map_err(QueryError::from)?;
    let QueryResponse::Iterable(output) = decoded else {
        return Err(eyre!("escrow scope response must be iterable").into());
    };
    let (batch, remaining, has_more, cursor) = output.into_parts_with_count_mode();
    if has_more
        || cursor.is_some()
        || remaining.is_some_and(|count| count != 0)
        || batch.column_count() != 1
        || batch.len() != 1
    {
        return Err(
            eyre!("escrow scope response must contain exactly one complete original").into(),
        );
    }
    let mut columns = batch.into_columns();
    let QueryOutputBatchBox::AssetEscrowScopeOriginalV1(mut originals) = columns.remove(0) else {
        return Err(eyre!("escrow scope response has a different item type").into());
    };
    let original = originals.remove(0);
    let scope: AssetEscrowScopeV1 = norito::decode_canonical_with_limits(
        &original.scope_original,
        norito::canonical_decode_limits(maximum_bytes),
    )
    .map_err(|error| QueryError::Other(eyre!("invalid escrow scope original: {error}")))?;
    scope
        .validate_records(
            &query.asset_definition_id,
            &query.expected_incarnation,
            &original.records,
        )
        .map_err(|error| QueryError::Other(eyre!(error)))?;
    Ok(original)
}

#[cfg(test)]
mod tests;
