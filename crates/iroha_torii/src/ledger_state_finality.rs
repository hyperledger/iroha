//! Witnessed state roots with native finality from one immutable committed view.

use super::*;

/// Closed response shared by both authenticated ledger-state endpoints.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii::ledger_state_finality::StateFinalityResponse")]
#[derive(
    Debug,
    Clone,
    crate::json_macros::JsonSerialize,
    crate::json_macros::JsonDeserialize,
    norito::derive::NoritoSerialize,
    norito::derive::NoritoDeserialize,
)]
#[norito(deny_unknown_fields)]

pub(super) struct StateFinalityResponse {
    /// Requested certified non-genesis committed block height (at least two).
    pub(super) height: u64,
    /// Canonical header hash authenticated by State and native finality.
    pub(super) block_hash: HashOf<BlockHeader>,
    /// Post-state root of the witnessed write set; not a complete World-state hash.
    pub(super) witnessed_post_state_root: iroha_crypto::Hash,
    /// Canonical header matched to both committed State and durable Kura evidence.
    pub(super) block_header: BlockHeader,
    /// Exact canonical frame and authenticated committee from the native chain.
    pub(super) finality_proof: iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
}

fn not_found() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::NotFound,
    ))
}

fn internal_error(message: impl Into<String>) -> Error {
    Error::Query(iroha_data_model::ValidationFail::InternalError(
        message.into(),
    ))
}

fn load(app: &AppState, height: u64) -> Result<StateFinalityResponse, Error> {
    let height_nz = NonZeroU64::new(height)
        .ok_or_else(|| conversion_error("height must be at least 1".to_owned()))?;
    // A signed genesis body does not authenticate its execution R. This closed
    // single-proof response cannot supply the required successor capability.
    if height_nz.get() < 2 {
        return Err(conversion_error(
            "height must name a certified non-genesis execution".to_owned(),
        ));
    }
    let height_usize = NonZeroUsize::new(
        height_nz
            .get()
            .try_into()
            .map_err(|_| conversion_error("height exceeds host pointer width".to_owned()))?,
    )
    .ok_or_else(|| conversion_error("height must be at least 1".to_owned()))?;
    // A single immutable State generation selects the committed hash journal.
    // The native builder verifies durable frames, the complete authenticated
    // prefix and application attestations before returning this exact proof.
    let view = app.state.view();
    let block_hash = view
        .block_hashes()
        .get(height_usize.get() - 1)
        .copied()
        .ok_or_else(not_found)?;
    let finality_proof =
        iroha_core::sumeragi::finality::build_proof(&view, height).map_err(|error| {
            internal_error(format!(
                "invalid durable native finality for committed block {height}: {error}"
            ))
        })?;
    let block_header = finality_proof.block_header;
    if block_header.height() != height_nz || block_header.hash() != block_hash {
        return Err(internal_error(format!(
            "durable native finality does not match committed State block {height}"
        )));
    }
    // This decode extracts the root from the already authenticated exact proof;
    // candidate-committee decoding alone would not grant finality authority.
    let witnessed_post_state_root = finality_proof
        .decode_checked(
            view.native_execution_tip()
                .ok_or_else(|| internal_error("native execution scope unavailable"))?
                .root_scope()
                .into(),
        )
        .map_err(|error| internal_error(format!("invalid native proof framing: {error}")))?
        .execution()
        .post_state_root;
    Ok(StateFinalityResponse {
        height,
        block_hash,
        witnessed_post_state_root,
        block_header,
        finality_proof,
    })
}

fn response(
    app: &AppState,
    height: u64,
    headers: &axum::http::HeaderMap,
) -> Result<Response, Error> {
    let accept = headers.get(axum::http::header::ACCEPT);
    let format = match crate::utils::negotiate_response_format(accept) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let payload = load(app, height)?;
    match format {
        ResponseFormat::Norito => Ok(NoritoBody(payload).into_response()),
        ResponseFormat::Json => {
            let body = norito::json::to_json_pretty(&payload).map_err(|error| {
                Error::Query(iroha_data_model::ValidationFail::InternalError(
                    error.to_string(),
                ))
            })?;
            let mut response = Response::new(Body::from(body));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }
    }
}

/// Serve the authenticated ledger state-root route.
pub(super) async fn handler_ledger_state_root(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<u64>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Error> {
    response(app.as_ref(), height, &headers)
}

/// Serve the authenticated ledger state-proof route.
pub(super) async fn handler_ledger_state_proof(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<u64>,
    headers: axum::http::HeaderMap,
) -> Result<Response, Error> {
    response(app.as_ref(), height, &headers)
}
