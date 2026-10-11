//! Functions and types to make queries to the Iroha peer.
#![allow(clippy::result_large_err)]
mod asynchronous;
use crate::{
    client::{APPLICATION_NORITO, Client, QueryResult, ResponseReport, join_torii_url},
    crypto::{HashOf, KeyPair},
    data_model::{
        NetworkId, ValidationFail,
        account::AccountId,
        query::{
            CommittedTransaction, CommittedTxFilters, Query, QueryOutput, QueryRequest,
            QueryResponse, QueryWithParams, SingularQuery, SingularQueryBox,
            SingularQueryOutputBox,
            builder::{QueryBuilder, QueryExecutor},
            dsl::{CompoundPredicate, SelectorTuple},
            error::QueryExecutionFail,
            parameters::{DEFAULT_FETCH_SIZE, ForwardCursor, MAX_FETCH_SIZE, QueryParams},
            transaction::prelude::FindTransactions,
        },
        transaction::TransactionEntrypoint,
    },
    http::{Method as HttpMethod, RequestBuilder},
    http_default::{DefaultHttpTransport, DefaultRequestBuilder},
};
pub use asynchronous::{AsyncQueryBuilderExt, QueryStream};
use eyre::{Report, Result, eyre};
use http::{StatusCode, header::CONTENT_TYPE};
use iroha_data_model::query::QueryOutputBatchBoxTuple;
use iroha_torii_shared::{
    ErrorEnvelope, PipelineTransactionDetailsResponse, route_catalog as torii_routes,
};
use iroha_version::codec::EncodeVersioned;
use norito::{codec::Encode as _, json};
use std::{
    collections::HashMap,
    fmt::Debug,
    num::NonZeroU64,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

const TRANSACTION_DETAILS_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Check only the response's local source/output bindings, not inclusion or finality.
/// The full executed carrier and independently authenticated commitment remain required.
pub(crate) fn validate_transaction_details_bindings(
    details: &PipelineTransactionDetailsResponse,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> Result<()> {
    use iroha_data_model::block::execution_output::ExecutionOutputV1;
    let transaction = &details.transaction;
    let ExecutionOutputV1::Network(output) = transaction.output() else {
        return Err(eyre!(
            "transaction-details response carries an internal execution output"
        ));
    };
    if details.hash != entrypoint_hash.to_string()
        || transaction.entrypoint_hash() != &entrypoint_hash
        || transaction.entrypoint().hash() != entrypoint_hash
        || transaction.output_hash() != &HashOf::new(transaction.output())
        || output.input_index != transaction.entrypoint_proof().leaf_index()
        || output.input_index != transaction.output_proof().leaf_index()
        || (output.result.is_err()
            && (!output.result.batch_transfer_outcomes().is_empty()
                || !output.completions.is_empty()))
        || output
            .completions
            .windows(2)
            .any(|pair| pair[0].callback_index >= pair[1].callback_index)
    {
        return Err(eyre!(
            "transaction-details response does not match the requested entrypoint/output binding"
        ));
    }
    Ok(())
}

/// The exact details route must never manufacture proof absence from an HTTP status.
fn decode_transaction_details_failure(response: &http::Response<Vec<u8>>) -> QueryError {
    let protocol_error = |reason: &str| {
        QueryError::Other(eyre!(
            "transaction-details HTTP {} failure {reason}",
            response.status()
        ))
    };
    let content_type_values = response.headers().get_all(CONTENT_TYPE);
    let mut content_types = content_type_values.iter();
    if content_types.next().map(http::HeaderValue::as_bytes) != Some(APPLICATION_NORITO.as_bytes())
        || content_types.next().is_some()
    {
        return protocol_error("requires one Content-Type: application/x-norito header");
    }
    let body = response.body();
    if body.is_empty() || body.len() > TRANSACTION_DETAILS_RESPONSE_MAX_BYTES {
        return protocol_error("must contain a nonempty bounded canonical Norito payload");
    }
    match norito::decode_canonical_with_limits::<ErrorEnvelope>(
        body,
        norito::canonical_decode_limits(body.len()),
    ) {
        Ok(failure) if failure.code() == "transaction_details_not_found" => {
            if response.status() == StatusCode::NOT_FOUND {
                QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
            } else {
                protocol_error("claims query absence without HTTP 404")
            }
        }
        Ok(failure) => {
            let code = match failure.code() {
                "query_validation_failed" => "query_validation_failed",
                "internal_server_error" => "internal_server_error",
                _ => "unrecognized_error_code",
            };
            protocol_error(&format!("has code {code}"))
        }
        // A codec EOF is a protocol failure, not a dropped network response. Do not
        // expose a nested decoder I/O error to transport-only reconciliation.
        Err(_) => protocol_error("is not one canonical Norito ErrorEnvelope payload"),
    }
}

struct ClientQueryRequestHead {
    torii_url: Url,
    headers: HashMap<String, String>,
    network_id: NetworkId,
    account_id: AccountId,
    key_pair: KeyPair,
    request_timeout: Duration,
    accept_header: &'static str,
    transport: DefaultHttpTransport,
}
impl Debug for ClientQueryRequestHead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values carry listener credentials such as Basic auth and API tokens.
        let mut header_names: Vec<_> = self.headers.keys().map(String::as_str).collect();
        header_names.sort_unstable();
        formatter
            .debug_struct("ClientQueryRequestHead")
            .field(
                "torii_origin",
                &self.torii_url.origin().ascii_serialization(),
            )
            .field("network_id", &self.network_id)
            .field("account_id", &self.account_id)
            .field("public_key", self.key_pair.public_key())
            .field("header_names", &header_names)
            .field("request_timeout", &self.request_timeout)
            .field("accept_header", &self.accept_header)
            .finish_non_exhaustive()
    }
}
impl ClientQueryRequestHead {
    #[cfg(test)]
    fn assemble(&self, query: QueryRequest) -> Result<DefaultRequestBuilder, QueryError> {
        let body = self.sign_and_encode(query)?;
        Ok(self.assemble_body(body))
    }
    fn assemble_body(&self, body: Vec<u8>) -> DefaultRequestBuilder {
        DefaultRequestBuilder::new(
            HttpMethod::POST,
            join_torii_url(&self.torii_url, torii_routes::pipeline::QUERY.path()),
        )
        .with_transport(self.transport.clone())
        .headers(self.headers.clone())
        .header("Content-Type", APPLICATION_NORITO)
        // Prefer canonical Norito responses to avoid JSON decoding drift between
        // client/server versions.
        .header("Accept", self.accept_header)
        .timeout(self.request_timeout)
        .body(body)
    }
    fn assemble_body_with_accept(
        &self,
        body: Vec<u8>,
        accept: &'static str,
    ) -> DefaultRequestBuilder {
        DefaultRequestBuilder::new(
            HttpMethod::POST,
            join_torii_url(&self.torii_url, torii_routes::pipeline::QUERY.path()),
        )
        .with_transport(self.transport.clone())
        .headers(self.headers.clone())
        .header("Content-Type", APPLICATION_NORITO)
        .header("Accept", accept)
        .timeout(self.request_timeout)
        .body(body)
    }
    fn assemble_canonical_norito_body_at(
        &self,
        body: Vec<u8>,
        path: &'static str,
    ) -> DefaultRequestBuilder {
        let mut headers = self.headers.clone();
        headers.retain(|name, _| {
            !name.eq_ignore_ascii_case("accept") && !name.eq_ignore_ascii_case("content-type")
        });
        DefaultRequestBuilder::new(HttpMethod::POST, join_torii_url(&self.torii_url, path))
            .with_transport(self.transport.clone())
            .headers(headers)
            .header("Content-Type", APPLICATION_NORITO)
            .header("Accept", APPLICATION_NORITO)
            .timeout(self.request_timeout)
            .body(body)
    }
    fn sign_and_encode(&self, query: QueryRequest) -> Result<Vec<u8>, QueryError> {
        let creation_time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| QueryError::Other(eyre!("system clock precedes Unix epoch: {error}")))?
            .as_millis()
            .try_into()
            .map_err(|_| QueryError::Other(eyre!("query creation time exceeds u64")))?;
        let time_to_live_ms = NonZeroU64::new(
            crate::config::DEFAULT_QUERY_TIME_TO_LIVE
                .as_millis()
                .try_into()
                .map_err(|_| QueryError::Other(eyre!("query TTL exceeds u64")))?,
        )
        .ok_or_else(|| QueryError::Other(eyre!("query TTL must be nonzero")))?;
        let mut nonce = [0_u8; 32];
        for _ in 0..16 {
            rand::rand_core::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
                .map_err(|error| QueryError::Other(eyre!("query nonce OS RNG failed: {error}")))?;
            if nonce != [0_u8; 32] {
                break;
            }
        }
        if nonce == [0_u8; 32] {
            return Err(QueryError::Other(eyre!(
                "query nonce OS RNG repeatedly returned the forbidden all-zero value"
            )));
        }
        let with_auth = query.with_authority(
            self.network_id,
            self.account_id.clone(),
            creation_time_ms,
            time_to_live_ms,
            nonce,
        );
        let query = with_auth
            .try_sign(&self.key_pair)
            .map_err(|err| QueryError::Other(eyre!("failed to sign query request: {err}")))?;
        Ok(query.encode_versioned())
    }
}
/// Decode a raw response from the node's query endpoint
fn decode_query_response(resp: &http::Response<Vec<u8>>) -> QueryResult<QueryResponse> {
    match resp.status() {
        StatusCode::OK => {
            let body = resp.body();
            let is_json = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|ct| {
                    let media_type = ct.split(';').next().map(str::trim).unwrap_or_default();
                    let media_type_lower = media_type.to_ascii_lowercase();
                    media_type.eq_ignore_ascii_case("application/json")
                        || (media_type_lower.starts_with("application/")
                            && media_type_lower.ends_with("+json"))
                });
            if is_json {
                return json::from_slice::<QueryResponse>(body).map_err(|error| {
                    eyre!("Failed to decode JSON query response: {error}").into()
                });
            }
            decode_query_response_body(body)
        }
        _ => Err(decode_query_failure(resp)),
    }
}
/// Decode the public Torii failure contract without inventing query-store state.
/// Only an explicit asset-absence code with its typed identity proves a missing
/// asset. Typed asset-absence details require that code and HTTP 404. Generic
/// status codes and diagnostics never establish query-store state.
fn decode_query_failure(response: &http::Response<Vec<u8>>) -> QueryError {
    const MAX_ERROR_BYTES: usize = 64 * 1024;
    let protocol_error = |reason: &str| {
        QueryError::Other(eyre!("query HTTP {} failure {reason}", response.status()))
    };
    let content_type_values = response.headers().get_all(CONTENT_TYPE);
    let mut content_types = content_type_values.iter();
    let content_type = content_types.next().map(http::HeaderValue::as_bytes);
    if content_types.next().is_some() {
        return protocol_error("requires exactly one Content-Type header");
    }
    let body = response.body();
    if body.is_empty() || body.len() > MAX_ERROR_BYTES {
        return protocol_error("requires a nonempty error envelope of at most 65536 bytes");
    }
    let envelope = match content_type {
        Some(b"application/x-norito") => {
            match norito::decode_canonical_with_limits::<ErrorEnvelope>(
                body,
                norito::canonical_decode_limits(body.len()),
            ) {
                Ok(envelope) => envelope,
                Err(_) => return protocol_error("is not one canonical Norito ErrorEnvelope"),
            }
        }
        Some(b"application/json") => match json::from_slice::<ErrorEnvelope>(body) {
            Ok(envelope) => envelope,
            Err(_) => return protocol_error("is not one JSON ErrorEnvelope"),
        },
        _ => return protocol_error("requires application/x-norito or application/json"),
    };
    let missing_asset = envelope
        .details
        .as_ref()
        .and_then(|details| details.query_asset_not_found.as_ref());
    if envelope.code() == "query_asset_not_found" {
        if response.status() != StatusCode::NOT_FOUND {
            return protocol_error("claims asset absence without HTTP 404");
        }
        let Some(asset_id) = missing_asset else {
            return protocol_error("claims asset absence without its typed asset identity");
        };
        return QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
            crate::data_model::query::error::FindError::Asset(Box::new(asset_id.clone())),
        )));
    }
    if missing_asset.is_some() {
        return protocol_error("carries asset absence details without query_asset_not_found code");
    }
    // ErrorEnvelope is the node's public, redacted diagnostic. Never display
    // unparsed upstream bytes or infer ValidationFail variants from status alone.
    QueryError::Http {
        status: response.status(),
        code: envelope.code().to_owned(),
        message: envelope.message().to_owned(),
    }
}
/// Decode `QueryResponse` from a canonical Norito byte body.
fn decode_query_response_body(body: &[u8]) -> QueryResult<QueryResponse> {
    norito::decode_from_bytes::<QueryResponse>(body).map_err(|error| {
        Report::new(error)
            .wrap_err(
                "Failed to decode response from Iroha. You are likely using a version of the client library that is incompatible with the version of the peer software",
            )
            .into()
    })
}
fn send_once<F>(mut make_request: F) -> Result<http::Response<Vec<u8>>, QueryError>
where
    F: FnMut() -> Result<DefaultRequestBuilder, QueryError>,
{
    make_request().and_then(|builder| {
        builder
            .build()
            .map_err(QueryError::from)
            .and_then(|request| request.send_blocking().map_err(QueryError::from))
    })
}
/// Send a signed query exactly once and decode its response.
///
/// A transport or response-decode failure is deliberately ambiguous: the node may already have
/// consumed and executed the signed nonce. Retrying the same bytes would violate one-shot request
/// semantics, so callers receive the error and may issue a newly signed query if appropriate.
fn send_once_and_decode<F, D, T>(make_request: F, decode: D) -> Result<T, QueryError>
where
    F: FnMut() -> Result<DefaultRequestBuilder, QueryError>,
    D: Fn(&http::Response<Vec<u8>>) -> QueryResult<T>,
{
    let response = send_once(make_request)?;
    decode(&response)
}
fn decode_singular_query_response(
    resp: &http::Response<Vec<u8>>,
) -> QueryResult<SingularQueryOutputBox> {
    let QueryResponse::Singular(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected singular)"
        )
        .into());
    };
    Ok(resp)
}
fn decode_iterable_query_response(resp: &http::Response<Vec<u8>>) -> QueryResult<QueryOutput> {
    let QueryResponse::Iterable(resp) = decode_query_response(resp)? else {
        return Err(eyre!(
            "Got unexpected type of query response from the node (expected iterable)"
        )
        .into());
    };
    Ok(resp)
}
/// Ensure the requested fetch size respects client-side limits.
fn validate_fetch_size(fetch_size: NonZeroU64) -> QueryResult<()> {
    if fetch_size > MAX_FETCH_SIZE {
        return Err(ValidationFail::QueryFailed(QueryExecutionFail::FetchSizeTooBig).into());
    }
    Ok(())
}

fn exact_transaction_details_query(
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> QueryWithParams {
    let query = FindTransactions::new();
    let predicate = CompoundPredicate::from_filters(CommittedTxFilters {
        entry_eq: Some(entrypoint_hash),
        ..CommittedTxFilters::default()
    });
    QueryWithParams {
        query: (),
        query_payload: query.dyn_encode(),
        item: query.query_item_kind(),
        predicate_bytes: predicate.encode(),
        selector_bytes: SelectorTuple::<CommittedTransaction>::default().encode(),
        params: QueryParams::default(),
    }
}
/// Continuation of an iterable query after its delivered batch.
///
/// It owns the request head needed to sign the next continuation, so iteration
/// does not borrow the client. When the node reports more rows but returns no
/// server cursor (Torii's ephemeral cursor mode), the continuation is
/// truncated and continuing it fails with [`QueryError::Truncated`].
#[derive(Debug)]
pub struct QueryCursor {
    request_head: ClientQueryRequestHead,
    state: CursorState,
    remaining_items: Option<u64>,
}
#[derive(Debug)]
enum CursorState {
    /// The node stored the result; continue from this cursor.
    Continue(ForwardCursor),
    /// The node reported more rows without a way to fetch them.
    Truncated,
}
impl QueryCursor {
    /// Build the continuation of one response: a server cursor, an explicit
    /// truncation when more rows exist without one, or `None` after the last batch.
    fn after(
        request_head: ClientQueryRequestHead,
        remaining_items: Option<u64>,
        has_more: bool,
        cursor: Option<ForwardCursor>,
    ) -> Option<Self> {
        let state = match cursor {
            Some(cursor) => CursorState::Continue(cursor),
            None if has_more => CursorState::Truncated,
            None => return None,
        };
        Some(Self {
            request_head,
            state,
            remaining_items,
        })
    }

    /// Return the server cursor, or `None` when the node truncated the result.
    pub fn forward_cursor(&self) -> Option<&ForwardCursor> {
        match &self.state {
            CursorState::Continue(cursor) => Some(cursor),
            CursorState::Truncated => None,
        }
    }

    /// Whether the node reported more rows without returning a server cursor.
    pub const fn is_truncated(&self) -> bool {
        matches!(self.state, CursorState::Truncated)
    }

    /// Exact number of rows after the delivered batch, when the node reported it.
    pub const fn remaining_items(&self) -> Option<u64> {
        self.remaining_items
    }

    /// Split into the request head and the server cursor to continue from.
    fn into_continuation(self) -> Result<(ClientQueryRequestHead, ForwardCursor), QueryError> {
        match self.state {
            CursorState::Continue(cursor) => Ok((self.request_head, cursor)),
            CursorState::Truncated => Err(QueryError::Truncated {
                remaining_items: self.remaining_items,
            }),
        }
    }
}
/// Different errors as a result of query response handling
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// A server rejection decoded from one canonical public error envelope.
    #[error("query failed; HTTP {status}; {code}: {message}")]
    Http {
        /// HTTP status returned by the server.
        status: StatusCode,
        /// Machine-readable error code from the validated envelope.
        code: String,
        /// Public diagnostic from the validated envelope.
        message: String,
    },
    /// Query validation error
    #[error("query validation error: {0}")]
    Validation(#[from] ValidationFail),
    /// Iterable query response has an invalid batch shape: {0}
    #[error("iterable query response has an invalid batch shape: {0}")]
    ResponseShape(#[from] iroha_data_model::query::builder::TypedBatchDowncastError),
    /// A structured SDK operation failure, including original canonical decoder custody.
    #[error("{0}")]
    Sdk(#[from] crate::Error),
    /// A singular query response carried an output of a different type.
    #[error("singular query response has an unexpected output type: {0}")]
    UnexpectedOutput(String),
    /// The node reported more rows than it returned and offered no continuation cursor.
    ///
    /// Torii returns only the first batch of an iterable query in its ephemeral
    /// cursor mode. Every delivered row was yielded before this error; narrow
    /// the query, or read the collection through [`crate::collections`].
    #[error(
        "the node returned only part of the iterable query result and no continuation cursor{}",
        remaining_items.map_or_else(String::new, |remaining| format!(" ({remaining} more rows)"))
    )]
    Truncated {
        /// Exact number of undelivered rows, when the node reported it.
        remaining_items: Option<u64>,
    },
    /// Lower-level transport or decoding error, preserving its original diagnostic.
    ///
    /// This is an explicit source because transparent forwarding would skip an
    /// [`eyre::Report`]'s root error when exposing the source chain.
    #[error("{0}")]
    Other(#[from] eyre::Error),
}
impl From<ResponseReport> for QueryError {
    #[inline]
    fn from(ResponseReport(err): ResponseReport) -> Self {
        Self::Other(err)
    }
}
impl QueryExecutor for Client {
    type Cursor = QueryCursor;
    type Error = QueryError;
    fn execute_singular_query(
        &self,
        query: SingularQueryBox,
    ) -> Result<SingularQueryOutputBox, Self::Error> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let is_parameters_query = matches!(query, SingularQueryBox::FindParameters(_));
        let request_head = self.get_query_request_head();
        let request = QueryRequest::Singular(query);
        let body = request_head.sign_and_encode(request)?;
        let make_request = || {
            if is_parameters_query {
                Ok(request_head.assemble_body_with_accept(body.clone(), "application/json"))
            } else {
                Ok(request_head.assemble_body(body.clone()))
            }
        };
        send_once_and_decode(make_request, decode_singular_query_response)
    }
    fn start_query(
        &self,
        query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let requested_fetch_size = query
            .params
            .fetch_size
            .fetch_size
            .unwrap_or(DEFAULT_FETCH_SIZE);
        validate_fetch_size(requested_fetch_size)?;
        let request_head = self.get_query_request_head();
        let request = QueryRequest::Start(query);
        let body = request_head.sign_and_encode(request)?;
        let make_request = || Ok(request_head.assemble_body(body.clone()));
        let response = send_once_and_decode(make_request, decode_iterable_query_response)?;
        let (batch, remaining_items, has_more, cursor) = response.into_parts_with_count_mode();
        let cursor = QueryCursor::after(request_head, remaining_items, has_more, cursor);
        Ok((batch, remaining_items, cursor))
    }
    fn continue_query(
        cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        let (request_head, cursor) = cursor.into_continuation()?;
        let request = QueryRequest::Continue(cursor);
        let body = request_head.sign_and_encode(request)?;
        let make_request = || Ok(request_head.assemble_body(body.clone()));
        let response = send_once_and_decode(make_request, decode_iterable_query_response)?;
        let (batch, remaining_items, has_more, cursor) = response.into_parts_with_count_mode();
        let cursor = QueryCursor::after(request_head, remaining_items, has_more, cursor);
        Ok((batch, remaining_items, cursor))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::query::{SignedQuery, executor::prelude::FindExecutorDataModel};
    use iroha_version::codec::DecodeVersioned as _;
    use std::sync::Arc;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked query fixture keypair")
    }
    #[test]
    fn assemble_binds_network_freshness_and_one_shot_nonce() {
        let network_id =
            NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([1; iroha_crypto::Hash::LENGTH]),
            ));
        let transport = DefaultHttpTransport::mock(Arc::new(move |snapshot| {
            let accept = snapshot
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("accept"))
                .map(|(_, value)| value.as_str())
                .expect("accept header");
            assert_eq!(accept, APPLICATION_NORITO);
            let signed = SignedQuery::decode_all_versioned(&snapshot.body)
                .expect("decode signed query request");
            assert_eq!(signed.payload.network_id, network_id);
            assert!(signed.payload.creation_time_ms > 0);
            assert_eq!(
                signed.payload.time_to_live_ms,
                NonZeroU64::new(
                    crate::config::DEFAULT_QUERY_TIME_TO_LIVE
                        .as_millis()
                        .try_into()
                        .expect("default query TTL fits u64"),
                )
                .expect("default query TTL is nonzero")
            );
            assert_ne!(signed.payload.nonce, [0_u8; 32]);
            Ok(http::Response::new(Vec::new()))
        }));
        let head = ClientQueryRequestHead {
            torii_url: Url::parse("http://127.0.0.1:8080").expect("url"),
            headers: HashMap::new(),
            network_id,
            account_id: iroha_test_samples::ALICE_ID.clone(),
            key_pair: checked_random_keypair(),
            request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            accept_header: APPLICATION_NORITO,
            transport,
        };
        let req = head
            .assemble(QueryRequest::Singular(
                SingularQueryBox::FindExecutorDataModel(FindExecutorDataModel),
            ))
            .expect("sign query request")
            .build()
            .expect("request build");
        let _ = req.send_blocking();
    }
    #[test]
    fn validate_fetch_size_rejects_over_max() {
        let over = MAX_FETCH_SIZE.checked_add(1).expect("nonzero add");
        let err = super::validate_fetch_size(over).expect_err("should reject oversized fetch size");
        assert!(matches!(
            err,
            QueryError::Validation(ValidationFail::QueryFailed(
                QueryExecutionFail::FetchSizeTooBig
            ))
        ));
    }
    #[test]
    fn validate_fetch_size_accepts_limits() {
        assert!(super::validate_fetch_size(MAX_FETCH_SIZE).is_ok());
        assert!(super::validate_fetch_size(DEFAULT_FETCH_SIZE).is_ok());
    }
    #[test]
    fn garbled_not_found_remains_a_protocol_error() {
        let resp = http::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, APPLICATION_NORITO)
            .body(vec![0xff, 0x00, 0x01])
            .expect("response");
        let err = super::decode_query_response(&resp).expect_err("expected validation error");
        assert!(matches!(err, QueryError::Other(_)));
    }
    #[test]
    fn garbled_gone_remains_a_protocol_error() {
        let resp = http::Response::builder()
            .status(StatusCode::GONE)
            .header(CONTENT_TYPE, APPLICATION_NORITO)
            .body(b"query_validation_failed: The stored cursor has expired".to_vec())
            .expect("response");
        let err = super::decode_query_response(&resp).expect_err("expected validation error");
        assert!(matches!(err, QueryError::Other(_)));
    }
}
impl Client {
    /// Fetch the exact committed transaction selected by its entrypoint hash.
    ///
    /// This uses the dedicated authenticated transaction-details route with the one canonical
    /// `FindTransactions` equality predicate accepted by Torii. The response must be canonical
    /// bounded Norito and must repeat the requested entrypoint hash, a self-consistent entrypoint
    /// and full typed Network output hash, with its exact input-index join. Both successful and
    /// rejected results are returned unchanged. This local check does not authenticate finality.
    ///
    /// # Errors
    ///
    /// Returns an error if request binding or signing fails, Torii rejects the query, the response
    /// violates the strict transport/codec contract, or any requested source/output binding differs.
    pub fn get_transaction_details(
        &self,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Result<PipelineTransactionDetailsResponse, QueryError> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let request_head = self.get_query_request_head();
        let request = QueryRequest::Start(exact_transaction_details_query(entrypoint_hash));
        let body = request_head.sign_and_encode(request)?;
        let make_request = || {
            Ok(request_head
                .assemble_canonical_norito_body_at(
                    body.clone(),
                    torii_routes::pipeline::TRANSACTION_DETAILS.path(),
                )
                .max_response_bytes(TRANSACTION_DETAILS_RESPONSE_MAX_BYTES))
        };
        let response = send_once(make_request)?;
        if response.body().len() > TRANSACTION_DETAILS_RESPONSE_MAX_BYTES {
            return Err(QueryError::Other(eyre!(
                "transaction-details response exceeds {} bytes",
                TRANSACTION_DETAILS_RESPONSE_MAX_BYTES
            )));
        }
        if response.status() != StatusCode::OK {
            return Err(decode_transaction_details_failure(&response));
        }
        let details: PipelineTransactionDetailsResponse = Client::decode_canonical_norito_response(
            &response,
            TRANSACTION_DETAILS_RESPONSE_MAX_BYTES,
            "query.transaction_details",
        )
        .map_err(QueryError::from)?;
        validate_transaction_details_bindings(&details, entrypoint_hash)
            .map_err(QueryError::from)?;
        Ok(details)
    }

    /// Fetch the exact successful committed transaction selected by its entrypoint hash.
    ///
    /// This preserves the success-only contract used by readers which must not accept a committed
    /// rejection. Call [`Self::get_transaction_details`] when the authenticated rejection result is
    /// itself required.
    ///
    /// # Errors
    ///
    /// Returns any authenticated transaction-details lookup error, or an error when the exact
    /// committed result is a rejection.
    pub fn get_successful_transaction_details(
        &self,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Result<PipelineTransactionDetailsResponse, QueryError> {
        let details = self.get_transaction_details(entrypoint_hash)?;
        if details.transaction.result().is_err() {
            return Err(QueryError::Other(eyre!(
                "transaction-details response contains a rejected transaction result"
            )));
        }
        Ok(details)
    }

    /// Bind, sign, encode, and execute an arbitrary raw query request.
    ///
    /// The client supplies the configured network identity and authority plus a fresh creation
    /// time, nonzero lifetime, and operating-system nonce. This is the canonical boundary for
    /// callers that construct a dynamic [`QueryRequest`] rather than using a typed query builder.
    ///
    /// # Errors
    /// Returns an error if request binding or signing fails, the HTTP request
    /// fails, or the server rejects the query.
    pub fn execute_query_request(
        &self,
        request: QueryRequest,
    ) -> Result<iroha_data_model::query::QueryResponse, QueryError> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let request_head = self.get_query_request_head();
        let body = request_head.sign_and_encode(request)?;
        let make_request = || Ok(request_head.assemble_body(body.clone()));
        send_once_and_decode(make_request, decode_query_response)
    }
    /// Execute an arbitrary `SignedQuery` (already signed and Norito-encoded) against the `/query` endpoint.
    /// Returns a typed `QueryResponse` which may be singular or iterable.
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns a non-OK response.
    pub fn execute_signed_query_raw(
        &self,
        body: &[u8],
    ) -> Result<iroha_data_model::query::QueryResponse, QueryError> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let make_request = || {
            Ok(DefaultRequestBuilder::new(
                HttpMethod::POST,
                join_torii_url(&self.torii_url, torii_routes::pipeline::QUERY.path()),
            )
            .with_transport(self.http_transport.clone())
            .headers(self.headers.clone())
            .header("Content-Type", APPLICATION_NORITO)
            .header("Accept", self.wire_format_preference.accept_header())
            .timeout(self.torii_request_timeout)
            .body(body.to_owned()))
        };
        send_once_and_decode(make_request, decode_query_response)
    }
}
impl Client {
    /// Get a [`ClientQueryRequestHead`] - an object that can be used to make queries independently of the client.
    ///
    /// You probably do not want to use it directly, but rather use [`Client::query_single`] or [`Client::query`].
    fn get_query_request_head(&self) -> ClientQueryRequestHead {
        ClientQueryRequestHead {
            torii_url: self.torii_url.clone(),
            headers: self.headers.clone(),
            network_id: self.network_id,
            account_id: self.account.clone(),
            key_pair: self.key_pair.clone(),
            request_timeout: self.torii_request_timeout,
            accept_header: self.wire_format_preference.accept_header(),
            transport: self.http_transport.clone(),
        }
    }
    /// Execute a singular query and return the result
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn query_single<Q>(&self, query: Q) -> Result<Q::Output, QueryError>
    where
        Q: SingularQuery,
        SingularQueryBox: From<Q>,
        Q::Output: TryFrom<SingularQueryOutputBox>,
        <Q::Output as TryFrom<SingularQueryOutputBox>>::Error: Debug,
    {
        let query = SingularQueryBox::from(query);
        self.execute_singular_query(query)?
            .try_into()
            .map_err(|error| QueryError::UnexpectedOutput(format!("{error:?}")))
    }
    /// Build an iterable query and return a builder object
    pub fn query<Q>(&self, query: Q) -> QueryBuilder<'_, Self, Q, Q::Item>
    where
        Q: Query,
    {
        QueryBuilder::new(self, query)
    }
    /// Make a request to continue an iterable query with the provided raw [`ForwardCursor`]
    ///
    /// You probably do not want to use this function, but rather use the [`Self::query`] method to make a query and iterate over its results.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub fn raw_continue_iterable_query(
        &self,
        cursor: ForwardCursor,
    ) -> Result<QueryResponse, QueryError> {
        self.ensure_data_model_compatibility()
            .map_err(QueryError::from)?;
        let request_head = self.get_query_request_head();
        let request = QueryRequest::Continue(cursor);
        let body = request_head.sign_and_encode(request)?;
        let make_request = || Ok(request_head.assemble_body(body.clone()));
        let response = send_once_and_decode(make_request, decode_query_response)?;
        Ok(response)
    }
}
#[cfg(test)]
mod query_errors_handling {
    use super::*;
    use crate::{
        client::{
            APPLICATION_NORITO, CompatibilityProbeCoordinator, DataModelCompatibility,
            DataModelCompatibilityError,
        },
        data_model::ValidationFail,
        http::StatusCode as HttpStatusCode,
        http_default::{DefaultHttpTransport, RequestSnapshot},
    };
    use http::Response;
    use iroha_data_model::query::{
        QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryResponse, SignedQuery,
    };
    use iroha_model_base::chain::ChainId;
    use iroha_service_model::soranet::AnonymityPolicy;
    use iroha_service_model::soranet::RolloutPhase;
    use iroha_test_samples::gen_account_in;
    use iroha_version::codec::DecodeVersioned as _;
    use norito::codec::Decode;
    use sorafs_manifest::alias_cache::AliasCachePolicy;
    use std::{
        collections::HashMap,
        num::NonZeroU64,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use url::Url;
    #[test]
    fn query_error_envelope_preserves_missing_asset_diagnostic() -> Result<()> {
        use iroha_data_model::{
            asset::{AssetDefinitionId, AssetId},
            query::error::FindError,
        };
        use iroha_model_base::domain::DomainId;
        let asset = AssetId::new(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal")?,
                "xor".parse()?,
            ),
            iroha_test_samples::ALICE_ID.clone(),
        );
        let fail = QueryExecutionFail::Find(FindError::Asset(Box::new(asset)));
        let envelope = ErrorEnvelope::new("query_validation_failed", fail.to_string());
        for (media_type, body) in [
            (APPLICATION_NORITO, norito::to_bytes(&envelope)?),
            ("application/json", json::to_vec(&envelope)?),
        ] {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, media_type)
                .body(body)?;
            let error = decode_singular_query_response(&response).expect_err("asset is missing");
            assert!(matches!(&error, QueryError::Http { status, code, message }
                if *status == StatusCode::NOT_FOUND && code == envelope.code()
                    && message == envelope.message()));
            let message = error.to_string();
            assert!(message.contains("404") && message.contains(envelope.code()));
            assert!(message.contains(envelope.message()));
            assert!(!message.contains("live query store"));
        }
        Ok(())
    }
    #[test]
    fn query_error_envelope_decodes_exact_asset_absence() -> Result<()> {
        use iroha_data_model::{asset::AssetId, query::error::FindError};
        use iroha_torii_shared::ErrorDetails;

        let id = AssetId::new(
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse()?,
            iroha_test_samples::ALICE_ID.clone(),
        );
        let envelope = ErrorEnvelope::new("query_asset_not_found", "asset is missing")
            .with_details(ErrorDetails {
                query_asset_not_found: Some(id.clone()),
                ..ErrorDetails::default()
            });
        for (media_type, body) in [
            (APPLICATION_NORITO, norito::to_bytes(&envelope)?),
            ("application/json", json::to_vec(&envelope)?),
        ] {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, media_type)
                .body(body)?;
            let error = decode_query_response(&response).expect_err("exact asset is absent");
            assert!(matches!(
                error,
                QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::Find(
                    FindError::Asset(missing),
                ))) if missing.as_ref() == &id
            ));
        }
        Ok(())
    }
    #[test]
    fn query_error_envelope_rejects_unbound_asset_absence() -> Result<()> {
        use iroha_data_model::asset::AssetId;
        use iroha_torii_shared::ErrorDetails;

        let id = AssetId::new(
            "6TEAJqbb8oEPmLncoNiMRbLEK6tw".parse()?,
            iroha_test_samples::ALICE_ID.clone(),
        );
        let details = ErrorDetails {
            query_asset_not_found: Some(id),
            ..ErrorDetails::default()
        };
        for (status, envelope) in [
            (
                StatusCode::NOT_FOUND,
                ErrorEnvelope::new("query_asset_not_found", "missing typed details"),
            ),
            (
                StatusCode::NOT_FOUND,
                ErrorEnvelope::new("query_asset_not_found", "missing typed identity")
                    .with_details(ErrorDetails::default()),
            ),
            (
                StatusCode::NOT_FOUND,
                ErrorEnvelope::new("query_validation_failed", "asset is missing")
                    .with_details(details.clone()),
            ),
            (
                StatusCode::FORBIDDEN,
                ErrorEnvelope::new("query_validation_failed", "permission denied")
                    .with_details(details.clone()),
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorEnvelope::new("internal_server_error", "query failed")
                    .with_details(details.clone()),
            ),
            (
                StatusCode::GONE,
                ErrorEnvelope::new("query_asset_not_found", "asset is missing")
                    .with_details(details.clone()),
            ),
            (
                StatusCode::FORBIDDEN,
                ErrorEnvelope::new("query_asset_not_found", "asset is missing")
                    .with_details(details.clone()),
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorEnvelope::new("query_asset_not_found", "asset is missing")
                    .with_details(details),
            ),
        ] {
            for (media_type, body) in [
                (APPLICATION_NORITO, norito::to_bytes(&envelope)?),
                ("application/json", json::to_vec(&envelope)?),
            ] {
                let response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, media_type)
                    .body(body)?;
                let error = decode_query_response(&response).expect_err("invalid asset absence");
                assert!(
                    matches!(error, QueryError::Other(_)),
                    "{status} {} ({media_type}) returned {error:?}",
                    envelope.code()
                );
            }
        }
        for value in [
            json::Value::Null,
            norito::json!(42),
            norito::json!("invalid-asset-id"),
        ] {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, "application/json")
                .body(json::to_vec(&norito::json!({
                    "code": "query_asset_not_found",
                    "message": "asset is missing",
                    "details": { "query_asset_not_found": value },
                }))?)?;
            assert!(matches!(
                decode_query_response(&response),
                Err(QueryError::Other(_))
            ));
        }
        Ok(())
    }
    #[test]
    fn indeterminate() -> Result<()> {
        let response = Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Vec::<u8>::new())?;
        match decode_query_response(&response) {
            Err(QueryError::Other(_)) => Ok(()),
            x => Err(eyre!("Expected indeterminate, found: {:?}", x)),
        }
    }
    #[test]
    fn malformed_iterable_response_error_remains_typed() {
        let error = QueryError::from(
            iroha_data_model::query::builder::TypedBatchDowncastError::WrongType { column: 2 },
        );
        assert!(matches!(
            error,
            QueryError::ResponseShape(
                iroha_data_model::query::builder::TypedBatchDowncastError::WrongType { column: 2 }
            )
        ));
    }
    #[test]
    fn other_query_error_preserves_the_underlying_diagnostic() {
        let error = QueryError::from(eyre!(
            "transaction-details response is not one canonical Norito payload"
        ));
        assert_eq!(
            error.to_string(),
            "transaction-details response is not one canonical Norito payload"
        );
    }
    #[test]
    fn other_query_error_preserves_the_report_root_in_its_source_chain() {
        let error = QueryError::from(eyre::Report::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "torii down",
        )));
        let report = eyre::Report::new(error);

        assert!(report.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
        }));
    }
    #[test]
    fn signed_query_transport_never_retries_ambiguous_decode_failure() {
        let sends = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&sends);
        with_mock_http(
            move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(vec![0xFF])
                    .expect("malformed response"))
            },
            |mock_transport| {
                let make_request = || {
                    Ok(DefaultRequestBuilder::new(
                        HttpMethod::POST,
                        Url::parse("http://localhost:8080/query").expect("query URL"),
                    )
                    .with_transport(mock_transport.clone())
                    .body(vec![0xA5]))
                };
                send_once_and_decode(make_request, decode_query_response)
                    .expect_err("malformed response must be reported without retry");
            },
        );
        assert_eq!(sends.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn norito_body_with_json_content_type_errors_cleanly() -> Result<()> {
        let expected = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(Vec::new())),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        });
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .header("content-type", "application/json")
            .body(norito::to_bytes(&expected)?)?;
        match decode_query_response(&response) {
            Err(QueryError::Other(_)) => Ok(()),
            other => Err(eyre!("expected strict JSON decode failure, got {other:?}")),
        }
    }
    #[test]
    fn json_body_decodes_iterable_response() -> Result<()> {
        let expected = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(Vec::new())),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        });
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .header("content-type", "application/json")
            .body(norito::json::to_vec(&expected)?)?;
        let decoded = decode_query_response(&response)?;
        assert_eq!(decoded, expected);
        Ok(())
    }
    #[test]
    fn text_json_is_not_a_supported_response_media_type() -> Result<()> {
        let payload = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(Vec::new())),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        });
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .header("content-type", "text/json")
            .body(norito::json::to_vec(&payload)?)?;
        assert!(
            matches!(decode_query_response(&response), Err(QueryError::Other(_))),
            "the retired text/json alias must not select JSON decoding"
        );
        Ok(())
    }
    #[test]
    fn json_body_reports_decode_errors_with_json_context() -> Result<()> {
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .header("content-type", "application/json")
            .body(vec![0_u8, 1, 2, 3])?;
        match decode_query_response(&response) {
            Err(QueryError::Other(inner)) => {
                let messages: Vec<String> = inner.chain().map(ToString::to_string).collect();
                assert!(
                    messages
                        .iter()
                        .any(|message| message.contains("Failed to decode JSON query response")),
                    "error message should mention JSON decode failure: {messages:?}"
                );
            }
            other => panic!("decode must fail with QueryError::Other, got {other:?}"),
        }
        Ok(())
    }
    #[test]
    fn missing_content_type_defaults_to_norito_decode() -> Result<()> {
        let expected = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(Vec::new())),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        });
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .body(norito::to_bytes(&expected)?)?;
        let decoded = decode_query_response(&response)?;
        assert_eq!(decoded, expected);
        Ok(())
    }
    #[test]
    fn empty_ok_body_errors_cleanly() -> Result<()> {
        let response = Response::builder()
            .status(HttpStatusCode::OK)
            .body(Vec::<u8>::new())?;
        match decode_query_response(&response) {
            Err(QueryError::Other(_)) => Ok(()),
            other => Err(eyre!("expected Other error for empty body, got {other:?}")),
        }
    }
    #[test]
    fn non_ok_garbage_body_errors_cleanly() -> Result<()> {
        let response = Response::builder()
            .status(HttpStatusCode::INTERNAL_SERVER_ERROR)
            .body(vec![1_u8, 2, 3, 4])?;
        match decode_query_response(&response) {
            Err(QueryError::Other(_)) => Ok(()),
            other => Err(eyre!(
                "expected Other error for garbage body, got {other:?}"
            )),
        }
    }
    #[test]
    fn query_error_envelope_rejects_wrong_media_and_noncanonical_bytes() -> Result<()> {
        let envelope = ErrorEnvelope::new("query_validation_failed", "missing fixture entity");
        let canonical = norito::to_bytes(&envelope)?;
        let mut trailing = canonical.clone();
        trailing.push(0);
        for (media_type, body) in [
            ("application/json", canonical.clone()),
            (APPLICATION_NORITO, json::to_vec(&envelope)?),
            (
                APPLICATION_NORITO,
                norito::to_bytes(&ValidationFail::TooComplex)?,
            ),
            (APPLICATION_NORITO, trailing),
            ("text/plain", b"upstream-private-body-marker".to_vec()),
            (
                "application/json",
                br#"{"code":"query_validation_failed","message":"fixture","unknown":true}"#
                    .to_vec(),
            ),
            (
                "application/json",
                br#"{"code":"query_validation_failed","code":"replacement","message":"fixture"}"#
                    .to_vec(),
            ),
            (
                "application/json",
                br#"{"code":"query_validation_failed","message":"fixture","message":"replacement"}"#
                    .to_vec(),
            ),
            (APPLICATION_NORITO, Vec::new()),
            (APPLICATION_NORITO, vec![0; 65_537]),
        ] {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, media_type)
                .body(body)?;
            let error = decode_query_response(&response).expect_err("invalid envelope");
            assert!(matches!(error, QueryError::Other(_)));
            let message = error.to_string();
            assert!(message.starts_with("query HTTP 404 Not Found failure "));
            assert!(!message.contains("query failed;"));
            assert!(!message.contains("live query store"));
            assert!(!message.contains("upstream-private-body-marker"));
        }
        for duplicate in [false, true] {
            let mut response = Response::builder().status(StatusCode::GONE);
            if duplicate {
                response = response
                    .header(CONTENT_TYPE, APPLICATION_NORITO)
                    .header(CONTENT_TYPE, APPLICATION_NORITO);
            }
            let error = decode_query_response(&response.body(canonical.clone())?)
                .expect_err("missing or duplicate media type");
            assert!(matches!(error, QueryError::Other(_)));
            assert!(
                error
                    .to_string()
                    .starts_with("query HTTP 410 Gone failure ")
            );
            assert!(!error.to_string().contains("expired"));
        }
        Ok(())
    }
    #[test]
    fn query_error_envelope_preserves_service_failure_without_cursor_inference() -> Result<()> {
        for (status, code, message) in [
            (
                StatusCode::NOT_FOUND,
                "query_validation_failed",
                "missing fixture entity",
            ),
            (
                StatusCode::NOT_FOUND,
                "route_not_found",
                "route unavailable",
            ),
            (
                StatusCode::GONE,
                "query_validation_failed",
                "cursor lease expired",
            ),
            (
                StatusCode::FORBIDDEN,
                "query_validation_failed",
                "permission denied",
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "query_validation_failed",
                "query capacity reached",
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                "Torii could not complete the request.",
            ),
        ] {
            let envelope = ErrorEnvelope::new(code, message);
            for (media, body) in [
                (APPLICATION_NORITO, norito::to_bytes(&envelope)?),
                ("application/json", json::to_vec(&envelope)?),
            ] {
                let response = Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, media)
                    .body(body)?;
                let error = decode_query_response(&response).expect_err("server failure");
                assert!(matches!(error, QueryError::Http {
                status: actual_status,
                code: ref actual_code,
                message: ref actual_message,
            } if actual_status == status && actual_code == code && actual_message == message));
                let rendered = error.to_string();
                assert!(rendered.contains(status.as_str()));
                assert!(rendered.contains(code) && rendered.contains(message));
            }
        }
        Ok(())
    }
    #[test]
    fn query_request_head_sets_accept_header() {
        let (account_id, key_pair) = gen_account_in("wonderland");
        let mut head = ClientQueryRequestHead {
            torii_url: Url::parse("http://localhost:8080").expect("torii url"),
            headers: HashMap::new(),
            network_id: NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([2; iroha_crypto::Hash::LENGTH]),
            )),
            account_id,
            key_pair,
            request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            accept_header: APPLICATION_NORITO,
            transport: DefaultHttpTransport::new(),
        };
        let cursor = ForwardCursor {
            query: "cursor".into(),
            cursor: NonZeroU64::new(1).expect("cursor"),
            gas_budget: None,
        };
        let query_request = QueryRequest::Continue(cursor);
        let observed = Arc::new(AtomicBool::new(false));
        let observed_clone = Arc::clone(&observed);
        with_mock_http(
            move |snapshot| {
                observed_clone.store(true, Ordering::Relaxed);
                assert_accept_header(&snapshot, APPLICATION_NORITO);
                Ok(ok_empty_response())
            },
            move |mock_transport| {
                head.transport = mock_transport;
                head.assemble(query_request)
                    .expect("sign query request")
                    .build()
                    .expect("request")
                    .send_blocking()
                    .expect("send");
            },
        );
        assert!(
            observed.load(Ordering::Relaxed),
            "injected transport was not invoked"
        );
    }
    #[test]
    fn execute_signed_query_raw_sets_accept_header() {
        let (account_id, key_pair) = gen_account_in("wonderland");
        let client = Client {
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id: crate::client::test_network_id(),
            torii_url: Url::parse("http://localhost:8081").expect("torii url"),
            key_pair: key_pair.clone(),
            transaction_ttl: Some(Duration::from_secs(5)),
            transaction_status_timeout: Duration::from_secs(5),
            torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            account: account_id,
            headers: HashMap::new(),
            operator_key_pair: None,
            add_transaction_nonce: false,
            alias_cache_policy: sample_alias_policy(),
            default_anonymity_policy: AnonymityPolicy::GuardPq,
            rollout_phase: RolloutPhase::Default,
            data_model_compatibility: Arc::new(Mutex::new(
                DataModelCompatibility::SubmitCompatible,
            )),
            compatibility_probe: Arc::new(CompatibilityProbeCoordinator::new()),
            http_transport: DefaultHttpTransport::new(),
            stream_transport: std::sync::Arc::new(crate::stream::DefaultStreamTransport),
            wire_format_preference: crate::client::WireFormatPreference::default(),
        };
        let encoded_response = norito::to_bytes(&QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(Vec::new())),
            remaining_items: Some(0),
            has_more: false,
            continue_cursor: None,
        }))
        .expect("encode query response");
        let observed = Arc::new(AtomicBool::new(false));
        let observed_clone = Arc::clone(&observed);
        with_mock_http(
            move |snapshot| {
                observed_clone.store(true, Ordering::Relaxed);
                assert_accept_header(
                    &snapshot,
                    crate::client::WireFormatPreference::default().accept_header(),
                );
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(encoded_response.clone())
                    .expect("response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;

                let response = client.execute_signed_query_raw(&[]).expect("execute query");
                assert!(matches!(response, QueryResponse::Iterable(_)));
            },
        );
        assert!(
            observed.load(Ordering::Relaxed),
            "send hook was not triggered"
        );
    }
    #[test]
    fn execute_signed_query_raw_rejects_incompatible_data_model_version_before_query_request() {
        let (account_id, key_pair) = gen_account_in("wonderland");
        let client = Client {
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id: crate::client::test_network_id(),
            torii_url: Url::parse("http://localhost:8081").expect("torii url"),
            key_pair,
            transaction_ttl: Some(Duration::from_secs(5)),
            transaction_status_timeout: Duration::from_secs(5),
            torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            account: account_id,
            headers: HashMap::new(),
            operator_key_pair: None,
            add_transaction_nonce: false,
            alias_cache_policy: sample_alias_policy(),
            default_anonymity_policy: AnonymityPolicy::GuardPq,
            rollout_phase: RolloutPhase::Default,
            data_model_compatibility: Arc::new(Mutex::new(DataModelCompatibility::Unchecked)),
            compatibility_probe: Arc::new(CompatibilityProbeCoordinator::new()),
            http_transport: DefaultHttpTransport::new(),
            stream_transport: std::sync::Arc::new(crate::stream::DefaultStreamTransport),
            wire_format_preference: crate::client::WireFormatPreference::default(),
        };
        let query_seen = Arc::new(AtomicBool::new(false));
        let query_seen_clone = Arc::clone(&query_seen);
        let mismatched_version = crate::data_model::DATA_MODEL_VERSION + 1;
        let capabilities_body =
            format!(r#"{{"data_model_version":{mismatched_version}}}"#).into_bytes();
        with_mock_http(
            move |snapshot| match snapshot.url.path() {
                "/v1/node/capabilities" => Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", "application/json")
                    .body(capabilities_body.clone())
                    .expect("capabilities response")),
                p if p == torii_routes::pipeline::QUERY.path() => {
                    query_seen_clone.store(true, Ordering::Relaxed);
                    Ok(ok_empty_response())
                }
                path => Err(eyre!("unexpected request path: {path}")),
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());

                let err = client
                    .execute_signed_query_raw(&[])
                    .expect_err("compatibility mismatch must fail");
                let QueryError::Other(report) = err else {
                    panic!("expected QueryError::Other");
                };
                let incompat = report
                    .downcast_ref::<DataModelCompatibilityError>()
                    .expect("compatibility error");
                assert!(matches!(
                    incompat,
                    DataModelCompatibilityError::Mismatch {
                        expected,
                        actual,
                    } if *expected == crate::data_model::DATA_MODEL_VERSION && *actual == mismatched_version
                ));
            },
        );
        assert!(
            !query_seen.load(Ordering::Relaxed),
            "query request must not be sent after compatibility mismatch"
        );
    }
    #[test]
    fn execute_signed_query_raw_rejects_unavailable_capabilities_before_query_request() {
        for status in [
            HttpStatusCode::NOT_FOUND,
            HttpStatusCode::TOO_MANY_REQUESTS,
            HttpStatusCode::SERVICE_UNAVAILABLE,
        ] {
            let (account_id, key_pair) = gen_account_in("wonderland");
            let client = Client {
                account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
                chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
                network_id: crate::client::test_network_id(),
                torii_url: Url::parse("http://localhost:8081").expect("torii url"),
                key_pair,
                transaction_ttl: Some(Duration::from_secs(5)),
                transaction_status_timeout: Duration::from_secs(5),
                torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
                account: account_id,
                headers: HashMap::new(),
                operator_key_pair: None,
                add_transaction_nonce: false,
                alias_cache_policy: sample_alias_policy(),
                default_anonymity_policy: AnonymityPolicy::GuardPq,
                rollout_phase: RolloutPhase::Default,
                data_model_compatibility: Arc::new(Mutex::new(DataModelCompatibility::Unchecked)),
                compatibility_probe: Arc::new(CompatibilityProbeCoordinator::new()),
                http_transport: DefaultHttpTransport::new(),
                stream_transport: std::sync::Arc::new(crate::stream::DefaultStreamTransport),
                wire_format_preference: crate::client::WireFormatPreference::default(),
            };
            let request_paths = Arc::new(Mutex::new(Vec::new()));
            let observed_paths = Arc::clone(&request_paths);
            with_mock_http(
                move |snapshot| {
                    let path = snapshot.url.path().to_owned();
                    observed_paths
                        .lock()
                        .expect("request paths lock")
                        .push(path);
                    Ok(Response::builder()
                        .status(status)
                        .header("content-type", "text/plain")
                        .body(b"capabilities unavailable".to_vec())
                        .expect("capabilities response"))
                },
                |mock_transport| {
                    let client = client
                        .clone()
                        .with_test_http_transport(mock_transport.clone());

                    let error = client
                        .execute_signed_query_raw(&[])
                        .expect_err("unavailable capabilities must reject query");
                    let QueryError::Other(report) = error else {
                        panic!("expected QueryError::Other");
                    };
                    let rendered = format!("{report:#}");
                    assert!(rendered.contains(&status.to_string()), "{rendered}");
                    assert!(rendered.contains("capabilities unavailable"), "{rendered}");
                },
            );
            assert_eq!(
                request_paths.lock().expect("request paths lock").clone(),
                vec!["/v1/node/capabilities".to_owned()],
                "failed capability probe must not send a query request"
            );
            assert!(matches!(
                &*client
                    .data_model_compatibility
                    .lock()
                    .expect("data model compatibility lock"),
                DataModelCompatibility::Unchecked
            ));
        }
    }
    fn compatible_client_with_conflicting_wire_headers() -> Client {
        let (account_id, key_pair) = gen_account_in("wonderland");
        Client {
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id: crate::client::test_network_id(),
            torii_url: Url::parse("http://localhost:8081").expect("torii url"),
            key_pair,
            transaction_ttl: Some(Duration::from_secs(5)),
            transaction_status_timeout: Duration::from_secs(5),
            torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            account: account_id,
            headers: HashMap::from([
                ("Accept".to_owned(), "application/json".to_owned()),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ]),
            operator_key_pair: None,
            add_transaction_nonce: false,
            alias_cache_policy: sample_alias_policy(),
            default_anonymity_policy: AnonymityPolicy::GuardPq,
            rollout_phase: RolloutPhase::Default,
            data_model_compatibility: Arc::new(Mutex::new(
                DataModelCompatibility::SubmitCompatible,
            )),
            compatibility_probe: Arc::new(CompatibilityProbeCoordinator::new()),
            http_transport: DefaultHttpTransport::new(),
            stream_transport: std::sync::Arc::new(crate::stream::DefaultStreamTransport),
            wire_format_preference: crate::client::WireFormatPreference::default(),
        }
    }
    fn transaction_details_fixture(
        result: iroha_data_model::transaction::TransactionResult,
    ) -> (
        HashOf<TransactionEntrypoint>,
        PipelineTransactionDetailsResponse,
    ) {
        use crate::crypto::MerkleProof;
        use iroha_data_model::transaction::TransactionBuilder;
        let (authority, key_pair) = gen_account_in("wonderland");
        let signed = TransactionBuilder::new(
            crate::client::test_network_id(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .try_sign(key_pair.private_key())
        .expect("sign transaction-details fixture");
        let entrypoint = TransactionEntrypoint::External(signed);
        let entrypoint_hash = entrypoint.hash();
        let output = iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
            iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                input_index: 0,
                result,
                completions: Vec::new(),
            },
        );
        let transaction = CommittedTransaction {
            block_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
                [0x77; iroha_crypto::Hash::LENGTH],
            )),
            entrypoint_hash,
            entrypoint_proof: MerkleProof::from_audit_path(0, Vec::new()),
            entrypoint,
            output_hash: HashOf::new(&output),
            output_proof: MerkleProof::from_audit_path(0, Vec::new()),
            output,
        };
        (
            entrypoint_hash,
            PipelineTransactionDetailsResponse {
                hash: entrypoint_hash.to_string(),
                transaction,
            },
        )
    }
    fn successful_transaction_details_fixture() -> (
        HashOf<TransactionEntrypoint>,
        PipelineTransactionDetailsResponse,
    ) {
        use iroha_data_model::transaction::{DataTriggerSequence, TransactionResult};
        transaction_details_fixture(TransactionResult::new(Ok(DataTriggerSequence::default())))
    }
    fn rejected_transaction_details_fixture() -> (
        HashOf<TransactionEntrypoint>,
        PipelineTransactionDetailsResponse,
        iroha_data_model::transaction::error::TransactionRejectionReason,
    ) {
        use iroha_data_model::{
            isi::error::{InstructionExecutionError, InvalidParameterError},
            transaction::{TransactionResult, error::TransactionRejectionReason},
        };
        let reason = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
            InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
                "privacy activation at 306 is too early after height 7; earliest is 307".to_owned(),
            )),
        ));
        let (entrypoint_hash, details) =
            transaction_details_fixture(TransactionResult::new(Err(reason.clone())));
        (entrypoint_hash, details, reason)
    }
    fn assert_exact_transaction_details_query(
        query: &QueryWithParams,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) {
        let find = FindTransactions::new();
        assert_eq!(query.query_payload, find.dyn_encode());
        assert_eq!(query.item, find.query_item_kind());
        assert_eq!(query.params, QueryParams::default());
        let mut predicate_cursor = std::io::Cursor::new(query.predicate_bytes.as_slice());
        let predicate = CompoundPredicate::<CommittedTransaction>::decode(&mut predicate_cursor)
            .expect("decode transaction-details predicate");
        assert_eq!(
            usize::try_from(predicate_cursor.position()).expect("predicate cursor position"),
            query.predicate_bytes.len(),
            "predicate must not contain trailing bytes"
        );
        assert_eq!(
            predicate.committed_tx_filters(),
            Some(CommittedTxFilters {
                entry_eq: Some(entrypoint_hash),
                ..CommittedTxFilters::default()
            })
        );
        let mut selector_cursor = std::io::Cursor::new(query.selector_bytes.as_slice());
        let selector = SelectorTuple::<CommittedTransaction>::decode(&mut selector_cursor)
            .expect("decode transaction-details selector");
        assert_eq!(
            usize::try_from(selector_cursor.position()).expect("selector cursor position"),
            query.selector_bytes.len(),
            "selector must not contain trailing bytes"
        );
        assert_eq!(selector, SelectorTuple::<CommittedTransaction>::default());
    }
    #[test]
    fn transaction_details_reader_uses_exact_signed_query_and_transport_contract() {
        let client = compatible_client_with_conflicting_wire_headers();
        let (entrypoint_hash, details) = successful_transaction_details_fixture();
        let encoded = norito::to_bytes(&details).expect("encode transaction-details response");
        let expected_hash = entrypoint_hash;
        let actual = with_mock_http(
            move |snapshot| {
                assert_eq!(snapshot.method, HttpMethod::POST);
                assert_eq!(
                    snapshot.url.path(),
                    torii_routes::pipeline::TRANSACTION_DETAILS.path()
                );
                assert!(snapshot.url.query().is_none());
                assert_eq!(
                    snapshot.max_response_bytes,
                    TRANSACTION_DETAILS_RESPONSE_MAX_BYTES
                );
                for (name, value) in [
                    ("accept", APPLICATION_NORITO),
                    ("content-type", APPLICATION_NORITO),
                ] {
                    let matching = snapshot
                        .headers
                        .iter()
                        .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                        .collect::<Vec<_>>();
                    assert_eq!(matching.len(), 1, "expected one {name} header");
                    assert_eq!(matching[0].1, value);
                }
                let signed = SignedQuery::decode_all_versioned(&snapshot.body)
                    .expect("decode signed transaction-details query");
                let QueryRequest::Start(query) = signed.request() else {
                    panic!("transaction-details request must be a query start");
                };
                assert_exact_transaction_details_query(query, expected_hash);
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(encoded.clone())
                    .expect("transaction-details response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_successful_transaction_details(entrypoint_hash)
            },
        )
        .expect("exact transaction-details lookup");
        assert_eq!(actual, details);
    }
    #[test]
    fn transaction_details_reader_returns_exact_rejected_result() {
        let client = compatible_client_with_conflicting_wire_headers();
        let (entrypoint_hash, details, reason) = rejected_transaction_details_fixture();
        let encoded = norito::to_bytes(&details).expect("encode rejected transaction details");
        let actual = with_mock_http(
            move |_| {
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(encoded.clone())
                    .expect("rejected transaction-details response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_transaction_details(entrypoint_hash)
            },
        )
        .expect("authenticated rejected transaction-details lookup");
        assert_eq!(actual, details);
        assert_eq!(
            actual
                .transaction
                .result()
                .0
                .as_ref()
                .expect_err("fixture result must be rejected"),
            &reason
        );
    }
    fn transaction_details_http_failure(
        status: StatusCode,
        content_types: Vec<&'static str>,
        body: Vec<u8>,
    ) -> QueryError {
        let client = compatible_client_with_conflicting_wire_headers();
        let (entrypoint_hash, _) = successful_transaction_details_fixture();
        let sends = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&sends);
        let error = with_mock_http(
            move |snapshot| {
                observed.fetch_add(1, Ordering::Relaxed);
                assert_eq!(snapshot.method, HttpMethod::POST);
                assert_eq!(
                    snapshot.url.path(),
                    torii_routes::pipeline::TRANSACTION_DETAILS.path()
                );
                assert_eq!(
                    snapshot.max_response_bytes,
                    TRANSACTION_DETAILS_RESPONSE_MAX_BYTES
                );
                let mut response = Response::builder().status(status);
                for content_type in &content_types {
                    response = response.header(CONTENT_TYPE, *content_type);
                }
                Ok(response
                    .body(body.clone())
                    .expect("exact details HTTP fixture"))
            },
            |mock_transport| {
                let client = client.with_test_http_transport(mock_transport);
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility") = DataModelCompatibility::SubmitCompatible;
                client.get_transaction_details(entrypoint_hash)
            },
        )
        .expect_err("fixture must reject the exact details lookup");
        assert_eq!(
            sends.load(Ordering::Relaxed),
            1,
            "failure must never retry the query"
        );
        error
    }
    #[test]
    fn transaction_details_failure_only_maps_the_exact_missing_envelope_to_absence() {
        let error = transaction_details_http_failure(
            StatusCode::NOT_FOUND,
            vec![APPLICATION_NORITO],
            norito::to_bytes(&ErrorEnvelope::new(
                "transaction_details_not_found",
                "missing",
            ))
            .expect("canonical missing envelope"),
        );
        assert!(matches!(
            error,
            QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
        ));
        for (status, code) in [
            (StatusCode::FORBIDDEN, "query_validation_failed"),
            (StatusCode::NOT_FOUND, "query_validation_failed"),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_server_error"),
            (StatusCode::NOT_FOUND, "substituted_untrusted_code"),
        ] {
            let error = transaction_details_http_failure(
                status,
                vec![APPLICATION_NORITO],
                norito::to_bytes(&ErrorEnvelope::new(code, "secret-runtime-message-sentinel"))
                    .expect("canonical failure envelope"),
            );
            assert!(matches!(error, QueryError::Other(_)));
            let diagnostic = error.to_string();
            assert!(diagnostic.contains(status.as_str()));
            assert!(!diagnostic.contains("secret-runtime-message-sentinel"));
            assert!(!diagnostic.contains("substituted_untrusted_code"));
        }
    }
    #[test]
    fn transaction_details_failure_rejects_absence_with_a_non_404_status() {
        for status in [StatusCode::BAD_REQUEST, StatusCode::SERVICE_UNAVAILABLE] {
            let error = transaction_details_http_failure(
                status,
                vec![APPLICATION_NORITO],
                norito::to_bytes(&ErrorEnvelope::new(
                    "transaction_details_not_found",
                    "missing",
                ))
                .expect("canonical missing envelope"),
            );
            assert!(matches!(error, QueryError::Other(_)));
            assert!(error.to_string().contains("without HTTP 404"));
        }
    }
    #[test]
    fn transaction_details_failure_rejects_plain_404_and_malformed_norito_without_codec_io() {
        let missing = norito::to_bytes(&ErrorEnvelope::new(
            "transaction_details_not_found",
            "missing",
        ))
        .expect("canonical missing envelope");
        let mut trailing = missing.clone();
        trailing.push(0);
        for (status, content_type, body) in [
            (StatusCode::NOT_FOUND, "text/plain", b"not found".to_vec()),
            (
                StatusCode::NOT_FOUND,
                "text/html",
                b"<html>missing endpoint</html>".to_vec(),
            ),
            (StatusCode::NOT_FOUND, APPLICATION_NORITO, b"NRT0".to_vec()),
            (
                StatusCode::NOT_FOUND,
                APPLICATION_NORITO,
                missing[..missing.len() - 1].to_vec(),
            ),
            (StatusCode::NOT_FOUND, APPLICATION_NORITO, trailing),
            (StatusCode::NOT_FOUND, APPLICATION_NORITO, Vec::new()),
            (
                StatusCode::NOT_FOUND,
                APPLICATION_NORITO,
                norito::to_bytes(&ValidationFail::QueryFailed(QueryExecutionFail::NotFound))
                    .expect("unsupported alternate error format"),
            ),
            (StatusCode::OK, APPLICATION_NORITO, b"NRT0".to_vec()),
        ] {
            let error = transaction_details_http_failure(status, vec![content_type], body);
            if status == StatusCode::OK {
                assert!(
                    matches!(&error, QueryError::Sdk(crate::Error::CanonicalDecode { source, .. })
                    if source.kind() == norito::core::DecodeAttemptErrorKind::Invalid)
                );
            } else {
                assert!(matches!(error, QueryError::Other(_)));
            }
            let report = eyre::Report::new(error);
            assert!(
                !report
                    .chain()
                    .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()),
                "a received malformed proof is a protocol failure, not transport EOF"
            );
        }
    }
    #[test]
    fn transaction_details_failure_requires_one_exact_norito_media_type() {
        for content_types in [
            Vec::new(),
            vec!["application/json"],
            vec![APPLICATION_NORITO, APPLICATION_NORITO],
            vec![APPLICATION_NORITO, "text/plain"],
        ] {
            let error = transaction_details_http_failure(
                StatusCode::NOT_FOUND,
                content_types,
                norito::to_bytes(&ErrorEnvelope::new(
                    "transaction_details_not_found",
                    "missing",
                ))
                .expect("canonical missing envelope"),
            );
            assert!(matches!(error, QueryError::Other(_)));
            assert!(error.to_string().contains("Content-Type"));
        }
    }
    #[test]
    fn transaction_details_failure_rejects_response_over_the_wire_bound() {
        let error = transaction_details_http_failure(
            StatusCode::NOT_FOUND,
            vec![APPLICATION_NORITO],
            vec![0; TRANSACTION_DETAILS_RESPONSE_MAX_BYTES + 1],
        );
        assert!(matches!(error, QueryError::Other(_)));
    }
    #[test]
    fn successful_transaction_details_reader_still_rejects_rejected_result() {
        let client = compatible_client_with_conflicting_wire_headers();
        let (entrypoint_hash, details, _) = rejected_transaction_details_fixture();
        let encoded = norito::to_bytes(&details).expect("encode rejected transaction details");
        let error = with_mock_http(
            move |_| {
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(encoded.clone())
                    .expect("rejected transaction-details response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_successful_transaction_details(entrypoint_hash)
            },
        )
        .expect_err("success-only transaction reader must reject a committed failure");
        assert!(
            error
                .to_string()
                .contains("contains a rejected transaction result"),
            "unexpected success-only reader error: {error}"
        );
    }
    #[test]
    fn transaction_details_reader_rejects_noncanonical_or_non_norito_success() {
        let client = compatible_client_with_conflicting_wire_headers();
        let (entrypoint_hash, details) = successful_transaction_details_fixture();
        let mut trailing = norito::to_bytes(&details).expect("encode transaction-details response");
        trailing.push(0);
        let error = with_mock_http(
            move |_| {
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(trailing.clone())
                    .expect("trailing response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_successful_transaction_details(entrypoint_hash)
            },
        )
        .expect_err("trailing bytes must be rejected");
        assert!(matches!(
            &error,
            QueryError::Sdk(crate::Error::CanonicalDecode { operation: "query.transaction_details", source })
                if source.kind() == norito::core::DecodeAttemptErrorKind::Invalid
        ));

        let client = compatible_client_with_conflicting_wire_headers();
        let encoded = norito::to_bytes(&details).expect("encode transaction-details response");
        let error = with_mock_http(
            move |_| {
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", "application/json")
                    .body(encoded.clone())
                    .expect("wrong-media response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_successful_transaction_details(entrypoint_hash)
            },
        )
        .expect_err("non-Norito success must be rejected");
        assert!(error.to_string().contains("invalid content-type"));

        let client = compatible_client_with_conflicting_wire_headers();
        let mut mismatched = details;
        mismatched.transaction.output_hash = HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x93; iroha_crypto::Hash::LENGTH]),
        );
        let encoded = norito::to_bytes(&mismatched).expect("encode mismatched output hash");
        let error = with_mock_http(
            move |_| {
                Ok(Response::builder()
                    .status(HttpStatusCode::OK)
                    .header("content-type", APPLICATION_NORITO)
                    .body(encoded.clone())
                    .expect("mismatched output response"))
            },
            |mock_transport| {
                let client = client
                    .clone()
                    .with_test_http_transport(mock_transport.clone());
                *client
                    .data_model_compatibility
                    .lock()
                    .expect("fixture compatibility cache") =
                    DataModelCompatibility::SubmitCompatible;
                client.get_successful_transaction_details(entrypoint_hash)
            },
        )
        .expect_err("output hash mismatch must be rejected");
        assert!(error.to_string().contains("entrypoint/output binding"));
    }
    #[test]
    fn transaction_details_reader_rejects_internal_and_wrong_source_outputs() {
        use iroha_data_model::block::execution_output::{
            ExecutionOutputV1, InvocationCompletionV1, TimeInvocationV1, TriggerUseV1,
        };
        use iroha_data_model::events::{
            time::{TimeEvent, TimeInterval},
            trigger_completed::TriggerCompletedOutcome,
        };
        for mutation in 0..8 {
            let client = compatible_client_with_conflicting_wire_headers();
            let (hash, mut details) = successful_transaction_details_fixture();
            match mutation {
                0 => {
                    let ExecutionOutputV1::Network(row) = &mut details.transaction.output else {
                        unreachable!()
                    };
                    row.input_index = 1;
                }
                1 => {
                    details.transaction.entrypoint_proof =
                        crate::crypto::MerkleProof::from_audit_path(1, Vec::new())
                }
                2 => {
                    details.transaction.output =
                        ExecutionOutputV1::time_output_limit_rejection(TimeInvocationV1 {
                            schedule_index: 0,
                            event: TimeEvent {
                                interval: TimeInterval {
                                    since_ms: 0,
                                    length_ms: 1,
                                },
                            },
                            trigger: TriggerUseV1 {
                                trigger_id: "query-internal-output".parse().unwrap(),
                                registered_at_height: 0,
                                action_hash: iroha_crypto::Hash::new(
                                    b"query internal output fixture",
                                ),
                            },
                        });
                }
                3 => {
                    let ExecutionOutputV1::Network(row) = &mut details.transaction.output else {
                        unreachable!()
                    };
                    let completion = InvocationCompletionV1 {
                        callback_index: 1,
                        trigger_id: "duplicate-callback".parse().unwrap(),
                        outcome: TriggerCompletedOutcome::Success,
                    };
                    row.completions = vec![completion.clone(), completion];
                }
                4 => {
                    details.transaction.entrypoint = successful_transaction_details_fixture()
                        .1
                        .transaction
                        .entrypoint
                }
                5 => {
                    details.transaction.output_proof =
                        crate::crypto::MerkleProof::from_audit_path(1, Vec::new())
                }
                6 | 7 => {
                    let ExecutionOutputV1::Network(row) = &mut details.transaction.output else {
                        unreachable!()
                    };
                    row.result = iroha_data_model::transaction::TransactionResult::new(Err(
                        iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                            iroha_data_model::ValidationFail::NotPermitted("rolled back".into()),
                        ),
                    ));
                    row.completions = vec![InvocationCompletionV1 {
                        callback_index: 0,
                        trigger_id: "rolled-back-callback".parse().unwrap(),
                        outcome: if mutation == 6 {
                            TriggerCompletedOutcome::Success
                        } else {
                            TriggerCompletedOutcome::Failure("rolled back".into())
                        },
                    }];
                }
                _ => unreachable!(),
            }
            // Rehash the altered output: neither self-consistency nor an internal row's
            // complete result can establish the requested Network source binding.
            details.transaction.output_hash = HashOf::new(&details.transaction.output);
            let body = norito::to_bytes(&details).unwrap();
            let error = with_mock_http(
                move |_| {
                    Ok(Response::builder()
                        .status(HttpStatusCode::OK)
                        .header("content-type", APPLICATION_NORITO)
                        .body(body.clone())
                        .unwrap())
                },
                |transport| {
                    let client = client.with_test_http_transport(transport);
                    *client.data_model_compatibility.lock().unwrap() =
                        DataModelCompatibility::SubmitCompatible;
                    client.get_transaction_details(hash)
                },
            )
            .expect_err("foreign/internal output must fail exact-details binding");
            assert!(
                error.to_string().contains("transaction-details response"),
                "mutation {mutation}: {error}"
            );
        }
    }
    fn with_mock_http<R>(
        responder: impl Fn(RequestSnapshot) -> Result<Response<Vec<u8>>> + Send + Sync + 'static,
        f: impl FnOnce(DefaultHttpTransport) -> R,
    ) -> R {
        f(DefaultHttpTransport::mock(Arc::new(responder)))
    }
    fn ok_empty_response() -> Response<Vec<u8>> {
        Response::builder()
            .status(HttpStatusCode::OK)
            .body(Vec::new())
            .expect("response")
    }
    fn assert_accept_header(snapshot: &RequestSnapshot, expected: &str) {
        let header = snapshot
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept"))
            .map(|(_, value)| value.as_str());
        assert_eq!(
            header,
            Some(expected),
            "request must declare expected Accept header; got {:?}",
            snapshot.headers
        );
    }
    fn norito_query_response(response: &QueryResponse) -> Response<Vec<u8>> {
        Response::builder()
            .status(HttpStatusCode::OK)
            .header("content-type", APPLICATION_NORITO)
            .body(norito::to_bytes(response).expect("query response"))
            .expect("response")
    }
    fn mocked_compatible_client(mock_transport: DefaultHttpTransport) -> Client {
        let client = compatible_client_with_conflicting_wire_headers()
            .with_test_http_transport(mock_transport);
        *client
            .data_model_compatibility
            .lock()
            .expect("fixture compatibility cache") = DataModelCompatibility::SubmitCompatible;
        client
    }
    #[test]
    fn sync_iteration_yields_delivered_rows_then_reports_truncation() {
        use iroha_data_model::{
            Registrable as _, domain::Domain, query::builder::QueryBuilderExt as _,
            query::domain::FindDomains,
        };
        let domains: Vec<Domain> = ["alpha", "beta"]
            .into_iter()
            .map(|name| {
                Domain::new(
                    iroha_model_base::domain::DomainId::try_new(name, "universal")
                        .expect("domain id"),
                )
                .build(&iroha_test_samples::ALICE_ID)
            })
            .collect();
        // Ephemeral cursor mode: more rows exist, but no continuation is offered.
        let truncated = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Domain(
                domains.clone(),
            )),
            remaining_items: Some(4),
            has_more: true,
            continue_cursor: None,
        });
        let sends = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&sends);
        let (rows, all) = with_mock_http(
            move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
                Ok(norito_query_response(&truncated))
            },
            |mock_transport| {
                let client = mocked_compatible_client(mock_transport);
                let mut iter = client.query(FindDomains).execute().expect("first batch");
                let cursor = iter.continue_cursor().expect("truncated continuation");
                assert!(cursor.is_truncated());
                assert!(cursor.forward_cursor().is_none());
                assert_eq!(cursor.remaining_items(), Some(4));
                let rows: Vec<_> = iter.by_ref().collect();
                assert!(iter.next().is_none(), "truncation ends the iteration");
                (rows, client.query(FindDomains).execute_all())
            },
        );
        assert_eq!(
            rows.len(),
            3,
            "both delivered rows, then the truncation error"
        );
        assert_eq!(rows[0].as_ref().expect("first row"), &domains[0]);
        assert_eq!(rows[1].as_ref().expect("second row"), &domains[1]);
        assert!(matches!(
            rows[2],
            Err(QueryError::Truncated {
                remaining_items: Some(4)
            })
        ));
        assert!(matches!(
            all,
            Err(QueryError::Truncated {
                remaining_items: Some(4)
            })
        ));
        assert_eq!(
            QueryError::Truncated {
                remaining_items: Some(4)
            }
            .to_string(),
            "the node returned only part of the iterable query result and no continuation cursor (4 more rows)"
        );
        assert_eq!(
            sends.load(Ordering::Relaxed),
            2,
            "truncation never sends a continuation"
        );
    }
    #[test]
    fn sync_query_single_reports_unexpected_output_instead_of_panicking() {
        use iroha_data_model::query::{SingularQueryOutputBox, account::prelude::FindAccountById};
        let mismatched = QueryResponse::Singular(SingularQueryOutputBox::DomainIds(Vec::new()));
        let result = with_mock_http(
            move |_| Ok(norito_query_response(&mismatched)),
            |mock_transport| {
                let client = mocked_compatible_client(mock_transport);
                let id = client.account.clone();
                client.query_single(FindAccountById { id })
            },
        );
        assert!(
            matches!(&result, Err(QueryError::UnexpectedOutput(details)) if details.contains("Account")),
            "{result:?}"
        );
    }
    #[test]
    fn query_cursor_debug_redacts_header_values() {
        let mut client = compatible_client_with_conflicting_wire_headers();
        client.headers.insert(
            "Authorization".to_owned(),
            "Basic bWFkX2hhdHRlcjppbG92ZXRlYQ==".to_owned(),
        );
        client
            .headers
            .insert("X-API-Token".to_owned(), "owner-only-token".to_owned());
        let cursor = QueryCursor::after(
            client.get_query_request_head(),
            None,
            true,
            Some(ForwardCursor {
                query: "ab".repeat(32),
                cursor: NonZeroU64::new(1).expect("cursor"),
                gas_budget: None,
            }),
        )
        .expect("continuation");
        let debug = format!("{cursor:?}");
        for secret in ["bWFkX2hhdHRlcjppbG92ZXRlYQ==", "owner-only-token"] {
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
        assert!(debug.contains("Authorization") && debug.contains("X-API-Token"));
        assert!(!cursor.is_truncated());
        assert!(cursor.forward_cursor().is_some());
    }
    fn sample_alias_policy() -> AliasCachePolicy {
        AliasCachePolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }
}
