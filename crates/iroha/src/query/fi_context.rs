//! Bounded owner-signed FI context observation; no execution or finality authority.
use super::*;
use iroha_data_model::{
    asset::fi_context::{AssetFiContextSnapshotV1, AssetFiContextTargetV1},
    query::{QueryOutputBatchBox, asset_fi_context::FindAssetFiContextV1, parameters::FetchSize},
};

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

impl Client {
    /// Read exactly one selected current FI context as this client's signing authority.
    ///
    /// Always requests ephemeral, bounded-count execution with one result. This
    /// call never inherits stored-cursor configuration, follows a continuation or
    /// retransmits its query. The response limit is enforced before decoding.
    /// Explicit absent rows remain observations; they are never filled from cache.
    ///
    /// The returned snapshot is not authenticated execution or finality evidence.
    /// Retain its exact native encoding and bind it to an independently verified
    /// successful native context assertion before using it for owner approval.
    ///
    /// # Errors
    /// Refuses invalid bounds or incarnation, transport/admission failures,
    /// noncanonical media/encoding, partial results and changed target selectors.
    pub fn get_asset_fi_context_snapshot(
        &self,
        query: FindAssetFiContextV1,
        maximum_bytes: usize,
    ) -> Result<AssetFiContextSnapshotV1, QueryError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_RESPONSE_BYTES {
            return Err(eyre!("FI context response limit must be in 1..=64 MiB").into());
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
        decode_context_response(&response, &query, maximum_bytes)
    }
}

fn decode_context_response(
    response: &http::Response<Vec<u8>>,
    query: &FindAssetFiContextV1,
    maximum_bytes: usize,
) -> Result<AssetFiContextSnapshotV1, QueryError> {
    if response.body().len() > maximum_bytes {
        return Err(eyre!("FI context response exceeds its byte limit").into());
    }
    if response.status() != StatusCode::OK {
        return Err(decode_query_failure(response));
    }
    let decoded: QueryResponse =
        Client::decode_canonical_norito_response(response, maximum_bytes, "query.asset_fi_context")
            .map_err(QueryError::from)?;
    let QueryResponse::Iterable(output) = decoded else {
        return Err(eyre!("FI context response must be iterable").into());
    };
    let (batch, remaining, has_more, cursor) = output.into_parts_with_count_mode();
    if has_more
        || cursor.is_some()
        || remaining.is_some_and(|count| count != 0)
        || batch.column_count() != 1
        || batch.len() != 1
    {
        return Err(eyre!("FI context response must contain one complete snapshot").into());
    }
    let mut columns = batch.into_columns();
    let QueryOutputBatchBox::AssetFiContextSnapshotV1(mut snapshots) = columns.remove(0) else {
        return Err(eyre!("FI context response has a different item type").into());
    };
    let snapshot = snapshots.remove(0);
    let (definition, wallet, fi, reference) = match &query.target {
        AssetFiContextTargetV1::LinkApproval(value) => (
            &value.link.asset_definition_id,
            &value.link.account_id,
            &value.link.fi_account_id,
            &value.link.reference_digest,
        ),
        AssetFiContextTargetV1::Transfer {
            instruction,
            fi_account_id,
            reference_digest,
            ..
        } => (
            &instruction.asset_definition_id,
            &instruction.account_id,
            fi_account_id,
            reference_digest,
        ),
    };
    if &snapshot.asset_definition_id != definition
        || &snapshot.account_id != wallet
        || &snapshot.fi_account_id != fi
        || &snapshot.reference_digest != reference
        || snapshot.asset_incarnation != query.expected_incarnation
        || snapshot.uid != query.expected_uid
    {
        return Err(eyre!("FI context response selectors differ from the exact request").into());
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests;
