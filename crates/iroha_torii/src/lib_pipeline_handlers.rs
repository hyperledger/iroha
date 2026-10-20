// Transaction batch and pipeline status/recovery handlers.
fn accept_transaction_metadata(
    err: &iroha_core::tx::AcceptTransactionFail,
) -> (&'static str, String) {
    match err {
        iroha_core::tx::AcceptTransactionFail::SignatureVerification(fail) => {
            let detail = if fail.detail.is_empty() {
                fail.code().summary().to_owned()
            } else {
                fail.detail.clone()
            };
            (
                fail.code().as_str(),
                format!("failed to accept transaction: {detail}"),
            )
        }
        iroha_core::tx::AcceptTransactionFail::NetworkTimeUnhealthy { .. } => (
            "PRTRY:NTS_UNHEALTHY",
            format!("failed to accept transaction: {err}"),
        ),
        iroha_core::tx::AcceptTransactionFail::TransactionLimit(limit) => (
            "transaction_rejected",
            format!("failed to accept transaction: {}", limit.reason),
        ),
        _ => (
            "transaction_rejected",
            format!("failed to accept transaction: {err}"),
        ),
    }
}
fn transaction_batch_submission_response(accepted_count: usize) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::ACCEPTED;
    response.headers_mut().insert(
        HeaderName::from_static("preference-applied"),
        HeaderValue::from_static(PREFER_RETURN_MINIMAL),
    );
    if let Ok(header) = HeaderValue::from_str(&accepted_count.to_string()) {
        response.headers_mut().insert(
            HeaderName::from_static("x-iroha-transactions-accepted"),
            header,
        );
    }
    response
}
/// Batch preflight is side-effect free. After dispatch starts, every input has
/// an explicit result; no aggregate rejection may conceal queue acceptance.
async fn handler_post_transactions_batch(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    crate::utils::extractors::NoritoBytes(body): crate::utils::extractors::NoritoBytes,
) -> Result<Response, Error> {
    use iroha_data_model::transaction::receipt::TransactionBatchEntryOutcome;
    // This deadline stops new dispatch and bounds cancellable transport waits.
    // Physical queue admission already in progress cannot be preempted: retain
    // its completed result, then decline to dispatch further fresh entries.
    #[cfg(feature = "connect")]
    let deadline = tokio::time::Instant::now() + TORII_PROXY_EXECUTION_BUDGET;
    let token = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    validate_transaction_batch_body_size(&body, app.transaction_batch_max_bytes)?;
    let permit =
        try_acquire_transaction_ingress_compute(&app.transaction_ingress_compute_inflight)?;
    let max_transactions = app.transaction_batch_max_transactions;
    let (transactions, permit) = run_transaction_ingress_compute_job(
        permit,
        "transaction_batch_decode_worker_failed",
        move || decode_transaction_batch_request(body, max_transactions),
    )
    .await?;
    admit_transaction_api_token_preauth(&app.tx_preauth_rate_limiter, token, transactions.len())
        .await?;
    let worker_app = app.clone();
    let (prepared, permit) = run_transaction_ingress_compute_job(
        permit,
        "transaction_batch_admission_worker_failed",
        move || {
            let prechecks = precheck_transaction_batch_ed25519(
                &transactions,
                worker_app
                    .state
                    .installed_pipeline()
                    .signature_batch_max_ed25519,
            );
            let mut prepared = Vec::with_capacity(transactions.len());
            // Authenticate the entire batch before any route selection or mutation.
            // Every input retains its signature-bound original expiry and limits.
            for (transaction, precheck) in transactions.into_iter().zip(prechecks) {
                let hash = transaction.hash();
                let accepted =
                    routing::accept_decoded_signed_transaction_for_ingress_with_precheck(
                        worker_app.state.clone(),
                        transaction,
                        &worker_app.telemetry,
                        precheck.single_ed25519_prechecked,
                        precheck.precheck_rejection,
                    )?;
                prepared.push((hash, PreparedTransactionIngress::Fresh(accepted)));
            }
            // Keep route/policy preflight before the first queue mutation. Ordinary
            // inputs must be single-route; lifecycle controls need their own QC.
            prepared
                .into_iter()
                .map(|(hash, prepared)| {
                    let prepared = match prepared {
                        PreparedTransactionIngress::Fresh(transaction) => {
                            let prepared =
                                prepare_fresh_transaction_ingress(&worker_app, transaction)?;
                            ordinary_transaction_ingress::authenticate(
                                &worker_app,
                                prepared.transaction.entrypoint(),
                                &prepared.routing_plan,
                            )
                            .map_err(|message| {
                                Error::Query(iroha_data_model::ValidationFail::NotPermitted(
                                    message,
                                ))
                            })?;
                            PreparedBatchEntry::Fresh(prepared)
                        }
                    };
                    Ok((hash, prepared))
                })
                .collect::<Result<Vec<_>, Error>>()
        },
    )
    .await?;
    drop(permit);
    let mut outcomes = Vec::with_capacity(prepared.len());
    for (hash, entry) in prepared {
        let response = match entry {
            PreparedBatchEntry::Fresh(prepared) => {
                #[cfg(feature = "connect")]
                {
                    if tokio::time::Instant::now() >= deadline {
                        torii_proxy_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "transaction_batch_not_dispatched",
                            "batch deadline elapsed before this entry was dispatched",
                        )
                    } else {
                        let entrypoint_hash = prepared.transaction.entrypoint().hash();
                        tokio::time::timeout_at(
                            deadline,
                            submit_prepared_transaction_ingress(
                                &app,
                                prepared,
                                true,
                                ResponseFormat::Json,
                            ),
                        )
                        .await
                        .map_or_else(
                            |_| {
                                transaction_dispatch_outcome_unknown_response(
                                    entrypoint_hash,
                                    Some(hash),
                                    "batch deadline elapsed after this entry was dispatched",
                                )
                            },
                            |result| result.unwrap_or_else(IntoResponse::into_response),
                        )
                    }
                }
                #[cfg(not(feature = "connect"))]
                submit_prepared_transaction_ingress(&app, prepared, true, ResponseFormat::Json)
                    .await
                    .unwrap_or_else(IntoResponse::into_response)
            }
        };
        outcomes.push(TransactionBatchEntryOutcome {
            signed_transaction_hash: hash,
            status: response.status().as_u16(),
            reject_code: response
                .headers()
                .get("x-iroha-reject-code")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
    }
    let accepted = outcomes.iter().filter(|entry| entry.status == 202).count();
    if accepted == outcomes.len() {
        return Ok(transaction_batch_submission_response(accepted));
    }
    let mut response = crate::utils::JsonBody(outcomes).into_response();
    *response.status_mut() = StatusCode::MULTI_STATUS;
    response.headers_mut().insert(
        HeaderName::from_static("x-iroha-transactions-accepted"),
        HeaderValue::from_str(&accepted.to_string()).expect("decimal count is a header"),
    );
    Ok(response)
}

enum PreparedBatchEntry {
    Fresh(PreparedFreshTransactionIngress),
}

#[cfg(feature = "app_api")]
async fn handler_proof_record_get(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    AxPath(id): AxPath<String>,
) -> Result<impl IntoResponse, Error> {
    let remote_ip = remote.ip();
    let enforce =
        !limits::is_allowed_by_cidr(&headers, Some(remote_ip), &app.api_rate_limit_bypass_nets);
    let start = std::time::Instant::now();
    check_proof_access(
        &app,
        &headers,
        Some(remote_ip),
        "/v1/proofs/{id}",
        1,
        enforce,
    )
    .await?;
    // Proof records are immutable protocol-verification artifacts, not
    // dataspace-owned ledger rows. They are intentionally public across the
    // configured route set; entity and transaction reads use caller visibility.
    let routes = torii_all_dataspace_routes(app.as_ref());
    let (rec, diagnostics, routed_by, fanout_reservation) =
        match resolve_torii_proof_record_for_routes(&app, routes, id).await {
            Ok(result) => result,
            Err(response) => return Ok(response),
        };
    let etag_value = format!("\"{}:{}\"", rec.id.backend, hex::encode(rec.id.proof_hash));
    let cache_control_value = format!(
        "public, max-age={}",
        app.proof_limits.cache_max_age.as_secs().max(1)
    );
    if crate::utils::if_none_match_matches(&headers, &etag_value) {
        app.telemetry.with_metrics(|tel| {
            tel.inc_torii_proof_cache_hit("/v1/proofs/{id}");
            tel.observe_torii_proof_request("/v1/proofs/{id}", "not_modified", 0, start.elapsed())
        });
        let mut resp = axum::response::Response::builder()
            .status(axum::http::StatusCode::NOT_MODIFIED)
            .body(axum::body::Body::empty())
            .map_err(|err| {
                Error::Query(iroha_data_model::ValidationFail::InternalError(
                    err.to_string(),
                ))
            })?;
        if let Ok(cache_header) = axum::http::HeaderValue::from_str(&cache_control_value) {
            resp.headers_mut()
                .insert(axum::http::header::CACHE_CONTROL, cache_header);
        }
        if let Ok(etag) = axum::http::HeaderValue::from_str(&etag_value) {
            resp.headers_mut().insert(axum::http::header::ETAG, etag);
        }
        insert_routed_by_header(&mut resp, routed_by);
        return Ok(hold_query_fanout_memory_in_response_body(
            with_torii_fanout_headers(resp, diagnostics),
            fanout_reservation,
        ));
    }
    let response_budget = ToriiRoutedReadMemoryBudget::new(
        app.query_fanout_working_set_bytes,
        app.torii_proxy_max_response_bytes,
    )
    .map_err(|_| {
        Error::Query(iroha_data_model::ValidationFail::InternalError(
            "failed to derive the admitted proof response envelope".to_owned(),
        ))
    })?;
    let bytes = norito::core::to_bytes_bounded(&rec, response_budget.final_body_limit()).map_err(
        |err| {
            Error::Query(iroha_data_model::ValidationFail::InternalError(
                err.to_string(),
            ))
        },
    )?;
    let body_len = bytes.len() as u64;
    enforce_proof_egress(
        &app,
        &headers,
        Some(remote_ip),
        "/v1/proofs/{id}",
        body_len,
        enforce,
    )
    .await?;
    let mut resp = axum::response::Response::new(axum::body::Body::from(bytes));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(utils::NORITO_MIME_TYPE),
    );
    if let Ok(cache_header) = axum::http::HeaderValue::from_str(&cache_control_value) {
        resp.headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, cache_header);
    }
    if let Ok(etag) = axum::http::HeaderValue::from_str(&etag_value) {
        resp.headers_mut().insert(axum::http::header::ETAG, etag);
    }
    insert_routed_by_header(&mut resp, routed_by);
    app.telemetry.with_metrics(|tel| {
        tel.observe_torii_proof_request("/v1/proofs/{id}", "ok", body_len, start.elapsed())
    });
    Ok(hold_query_fanout_memory_in_response_body(
        with_torii_fanout_headers(resp, diagnostics),
        fanout_reservation,
    ))
}
async fn handler_proof_retention_status(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    accept: Option<crate::utils::extractors::ExtractAccept>,
) -> Result<Response, Error> {
    let remote_ip = remote.ip();
    let format = match crate::utils::negotiate_response_format(accept.as_ref().map(|v| &v.0)) {
        Ok(fmt) => fmt,
        Err(resp) => return Ok(resp),
    };
    let enforce =
        !limits::is_allowed_by_cidr(&headers, Some(remote_ip), &app.api_rate_limit_bypass_nets);
    check_operator_proof_access(
        &app,
        &headers,
        Some(remote_ip),
        iroha_torii_shared::route_catalog::pipeline::PROOF_RETENTION.path(),
        1,
        enforce,
    )
    .await?;
    let status = routing::handle_proof_retention_status(app.state.clone())?;
    Ok(crate::utils::respond_with_format(status, format))
}
/// Debug endpoint exposing the current AXT proof cache state per dataspace.
#[cfg(test)]
#[cfg(feature = "telemetry")]
async fn handler_axt_proof_cache_status(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<impl IntoResponse, Error> {
    let remote_ip = remote.ip();
    check_access(&app, &headers, Some(remote_ip), "debug/axt/cache").await?;
    let snapshot = app.state.metrics().axt_debug_status();
    Ok(crate::utils::JsonBody(snapshot))
}
/// Fallback when telemetry is disabled.
#[cfg(not(feature = "telemetry"))]
async fn handler_axt_proof_cache_status(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<impl IntoResponse, Error> {
    let _ = (headers, remote);
    Ok(telemetry_unavailable_response(
        iroha_torii_shared::route_catalog::telemetry::DEBUG_AXT_CACHE.path(),
        &app.telemetry,
    ))
}
async fn handler_pipeline_recovery(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    AxPath(height): AxPath<u64>,
) -> Result<Response, Error> {
    check_operator_rate_limit(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/pipeline/recovery",
        true,
    )
    .await?;
    let admission = acquire_query_admission(&app, true).await?;
    let kura = Arc::clone(&app.kura);
    let (result, _admission) = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            // Keep both general-query and heavy-work permits in the physical worker.
            // Cancelling the HTTP future cannot release capacity while Kura reads,
            // JSON projection, or encoding still consume memory.
            let result = build_pipeline_recovery_response(&kura, height);
            (result, admission)
        }),
    )
    .await
    .map_err(|error| Error::AppServiceUnavailable {
        code: "pipeline_recovery_worker_failed",
        message: error.to_string(),
    })?;
    let serialized = result?;
    Ok(axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(serialized))
        .expect("static pipeline recovery response is valid"))
}
/// Maximum canonical source size for one persisted recovery sidecar.
const PIPELINE_RECOVERY_SOURCE_MAX_BYTES: usize =
    iroha_core::kura::MAX_PIPELINE_RECOVERY_SIDECAR_BYTES;
/// Hard transport ceiling for the compact JSON rendering of a recovery sidecar.
///
/// The canonical source is independently limited to one MiB before persistence.
/// Eight times that source ceiling leaves conservative room for JSON escaping
/// and structure while keeping the response allocation finite.
const PIPELINE_RECOVERY_MAX_RESPONSE_BYTES: usize = PIPELINE_RECOVERY_SOURCE_MAX_BYTES * 8;
fn build_pipeline_recovery_response(kura: &Kura, height: u64) -> Result<String, Error> {
    let sidecar = kura.read_pipeline_metadata(height).ok_or_else(|| {
        Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound,
        ))
    })?;
    let serialized = norito::json::to_json(&sidecar.to_json_value()).map_err(|source| {
        Error::SerializationFailure {
            context: "pipeline_recovery_sidecar",
            source: Box::new(source),
        }
    })?;
    bounded_pipeline_recovery_json(serialized)
}
fn bounded_pipeline_recovery_json(serialized: String) -> Result<String, Error> {
    if serialized.len() > PIPELINE_RECOVERY_MAX_RESPONSE_BYTES {
        return Err(Error::AppServiceUnavailable {
            code: "pipeline_recovery_response_too_large",
            message: format!(
                "encoded pipeline recovery sidecar exceeds the {PIPELINE_RECOVERY_MAX_RESPONSE_BYTES}-byte response budget"
            ),
        });
    }
    Ok(serialized)
}
#[cfg(test)]
mod pipeline_recovery_response_bounds_tests {
    use super::*;
    #[test]
    fn pipeline_recovery_handler_retains_bounded_physical_work_admission() {
        let source = include_str!("lib_pipeline_handlers.rs");
        let handler = source
            .split_once("async fn handler_pipeline_recovery(")
            .and_then(|(_, tail)| tail.split_once("async fn handler_pipeline_preflight("))
            .map(|(handler, _)| handler)
            .expect("locate pipeline recovery handler source");
        assert!(handler.contains("check_operator_rate_limit("));
        assert!(!handler.contains("validate_api_token("));
        assert!(handler.contains("acquire_query_admission(&app, true)"));
        assert!(handler.contains("spawn_blocking_recoverable"));
        assert!(handler.contains("join_recoverable"));
        assert!(handler.contains("(result, admission)"));
    }
    #[test]
    fn pipeline_recovery_json_rejects_response_larger_than_protocol_budget() {
        let oversized = "x".repeat(PIPELINE_RECOVERY_MAX_RESPONSE_BYTES + 1);
        let error = bounded_pipeline_recovery_json(oversized)
            .expect_err("response over the recovery transport budget must be rejected");
        match error {
            Error::AppServiceUnavailable { code, .. } => {
                assert_eq!(code, "pipeline_recovery_response_too_large");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn pipeline_recovery_json_accepts_response_at_protocol_budget() {
        let exact = "x".repeat(PIPELINE_RECOVERY_MAX_RESPONSE_BYTES);
        assert_eq!(
            bounded_pipeline_recovery_json(exact)
                .expect("response at the recovery transport budget must be accepted")
                .len(),
            PIPELINE_RECOVERY_MAX_RESPONSE_BYTES
        );
    }
}
async fn handler_pipeline_preflight(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    accept: Option<crate::utils::extractors::ExtractAccept>,
) -> Result<Response, Error> {
    let format = match crate::utils::negotiate_response_format(accept.as_ref().map(|v| &v.0)) {
        Ok(format) => format,
        Err(resp) => return Ok(resp),
    };
    check_operator_rate_limit(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/pipeline/preflight",
        true,
    )
    .await?;
    Ok(crate::utils::respond_with_format(
        routing::build_pipeline_preflight_response(app.state.as_ref(), app.queue.as_ref()),
        format,
    ))
}
async fn handler_pipeline_recovery_fastpq_proofs(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    AxPath(height): AxPath<u64>,
    crate::NoritoStringQuery(query): crate::NoritoStringQuery<PipelineFastpqRecoveryQuery>,
) -> Result<Response, Error> {
    // The route's sealed middleware has already verified its canonical,
    // replay-resistant operator signature before extractors or this handler can
    // run. Charge the authenticated request before touching Kura or acquiring
    // compute capacity.
    check_access_with_rate_limiter(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/pipeline/recovery/fastpq-proofs",
        &app.rate_limiter,
    )
    .await?;
    let page = PipelineFastpqRecoveryPage::parse(&query)?;
    let admission = acquire_query_admission(&app, true).await?;
    let kura = Arc::clone(&app.kura);
    let (result, _admission) = crate::panic_recovery::join_recoverable(
        crate::panic_recovery::spawn_blocking_recoverable(move || {
            // Keep both general-query and heavy-work permits in the physical worker.
            // Cancelling the HTTP future therefore cannot release capacity while
            // Kura reads, transcript reconstruction, or encoding still run.
            let result = build_pipeline_recovery_fastpq_response(&kura, height, page);
            (result, admission)
        }),
    )
    .await
    .map_err(|error| Error::AppServiceUnavailable {
        code: "pipeline_recovery_fastpq_worker_failed",
        message: error.to_string(),
    })?;
    let serialized = result?;
    Ok(axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(serialized))
        .expect("static FASTPQ recovery response is valid"))
}
const PIPELINE_FASTPQ_RECOVERY_DEFAULT_LIMIT: usize = 16;
const PIPELINE_FASTPQ_RECOVERY_MAX_LIMIT: usize = 64;
#[cfg(test)]
const PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const PIPELINE_FASTPQ_RECOVERY_MAX_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
#[derive(JsonDeserialize, crate::json_macros::JsonSerialize, Clone, Debug, Default)]
struct PipelineFastpqRecoveryQuery {
    #[norito(default)]
    offset: Option<u64>,
    #[norito(default)]
    limit: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PipelineFastpqRecoveryPage {
    offset: usize,
    limit: usize,
}
impl PipelineFastpqRecoveryPage {
    fn parse(query: &PipelineFastpqRecoveryQuery) -> Result<Self, Error> {
        let offset = usize::try_from(query.offset.unwrap_or_default())
            .map_err(|_| conversion_error("FASTPQ recovery offset exceeds this host".to_owned()))?;
        let raw_limit = query
            .limit
            .unwrap_or(PIPELINE_FASTPQ_RECOVERY_DEFAULT_LIMIT as u64);
        if raw_limit == 0 || raw_limit > PIPELINE_FASTPQ_RECOVERY_MAX_LIMIT as u64 {
            return Err(conversion_error(format!(
                "FASTPQ recovery limit must be between 1 and {PIPELINE_FASTPQ_RECOVERY_MAX_LIMIT}"
            )));
        }
        let limit = usize::try_from(raw_limit)
            .map_err(|_| conversion_error("FASTPQ recovery limit exceeds this host".to_owned()))?;
        Ok(Self { offset, limit })
    }
}
fn fastpq_recovery_capacity_error(message: impl Into<String>) -> Error {
    Error::AppServiceUnavailable {
        code: "pipeline_recovery_fastpq_artifact_too_large",
        message: message.into(),
    }
}
fn charge_fastpq_recovery_artifact_bytes(used: &mut usize, amount: usize) -> Result<(), Error> {
    let next = used.checked_add(amount).ok_or_else(|| {
        fastpq_recovery_capacity_error("FASTPQ recovery artifact size overflowed")
    })?;
    if next > PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES {
        return Err(fastpq_recovery_capacity_error(format!(
            "selected FASTPQ recovery artifacts exceed the {} byte response-source budget",
            PIPELINE_FASTPQ_RECOVERY_MAX_ARTIFACT_BYTES
        )));
    }
    *used = next;
    Ok(())
}
fn build_pipeline_recovery_fastpq_response(
    kura: &Kura,
    height: u64,
    page: PipelineFastpqRecoveryPage,
) -> Result<String, Error> {
    let Some(sidecar) = kura.read_pipeline_metadata(height) else {
        return Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::NotFound,
        )));
    };
    let total = sidecar.fastpq_proofs.len();
    let start = page.offset.min(total);
    let end = start.saturating_add(page.limit).min(total);
    let mut artifact_bytes = 0;
    let proofs = sidecar.fastpq_proofs[start..end]
        .iter()
        .map(|snapshot| {
            fastpq_proof_snapshot_recovery_json(kura, height, snapshot, &mut artifact_bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut root = norito::json::Map::new();
    root.insert(
        "height".to_owned(),
        norito::json::to_value(&sidecar.height).expect("serialize pipeline height"),
    );
    root.insert(
        "block_hash".to_owned(),
        norito::json::to_value(&sidecar.block_hash.to_string())
            .expect("serialize pipeline block hash"),
    );
    root.insert(
        "total_proofs".to_owned(),
        norito::json::to_value(&u64::try_from(total).unwrap_or(u64::MAX))
            .expect("serialize FASTPQ proof total"),
    );
    root.insert(
        "offset".to_owned(),
        norito::json::to_value(&u64::try_from(page.offset).unwrap_or(u64::MAX))
            .expect("serialize FASTPQ proof offset"),
    );
    root.insert(
        "limit".to_owned(),
        norito::json::to_value(&u64::try_from(page.limit).unwrap_or(u64::MAX))
            .expect("serialize FASTPQ proof limit"),
    );
    root.insert(
        "next_offset".to_owned(),
        norito::json::to_value(&(end < total).then(|| u64::try_from(end).unwrap_or(u64::MAX)))
            .expect("serialize FASTPQ proof continuation"),
    );
    root.insert("proofs".to_owned(), norito::json::Value::Array(proofs));
    let serialized =
        norito::json::to_json_pretty(&norito::json::Value::Object(root)).map_err(|source| {
            Error::SerializationFailure {
                context: "pipeline_recovery_fastpq_proofs",
                source: Box::new(source),
            }
        })?;
    if serialized.len() > PIPELINE_FASTPQ_RECOVERY_MAX_RESPONSE_BYTES {
        return Err(fastpq_recovery_capacity_error(format!(
            "encoded FASTPQ recovery page exceeds the {} byte response budget",
            PIPELINE_FASTPQ_RECOVERY_MAX_RESPONSE_BYTES
        )));
    }
    Ok(serialized)
}
fn fastpq_proof_snapshot_recovery_json(
    _kura: &Kura,
    _height: u64,
    snapshot: &iroha_core::kura::FastpqProofSnapshot,
    artifact_bytes: &mut usize,
) -> Result<norito::json::Value, Error> {
    // Recovery sidecars retain only public metadata and the canonical artifact
    // identity; proof frames and private witnesses are never served here.
    let value = snapshot.to_json_value();
    let encoded_len = norito::json::to_json(&value)
        .map_err(|source| Error::SerializationFailure {
            context: "pipeline_recovery_fastpq_proofs",
            source: Box::new(source),
        })?
        .len();
    charge_fastpq_recovery_artifact_bytes(artifact_bytes, encoded_len)?;
    Ok(value)
}
#[cfg(test)]
fn encode_fastpq_recovery_batch(
    batch: &fastpq_prover::TransitionBatch,
    reconstructed: bool,
    artifact_bytes: &mut usize,
) -> Result<(String, bool), Error> {
    // Pin both bounded passes to the same canonical V1 layout, independent of
    // any request-local Norito decode flags on this thread.
    let _canonical_flags =
        norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    // Count the borrowed source before the public-model conversion clones its row buffers.
    // The final model frame is counted again by the bounded encoder before output allocation.
    let source_bytes =
        norito::core::encoded_frame_len(batch).map_err(|source| Error::SerializationFailure {
            context: "pipeline_recovery_fastpq_batch",
            source: Box::new(source),
        })?;
    if source_bytes > PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES {
        return Err(fastpq_recovery_capacity_error(format!(
            "FASTPQ batch exceeds the {} byte per-batch budget",
            PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES
        )));
    }
    let model = fastpq_prover::transition_batch_to_model(batch);
    let bytes =
        match norito::core::to_bytes_bounded(&model, PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES) {
            Ok(bytes) => bytes,
            Err(norito::core::BoundedEncodeError::FrameTooLarge { .. }) => {
                return Err(fastpq_recovery_capacity_error(format!(
                    "FASTPQ batch exceeds the {} byte per-batch budget",
                    PIPELINE_FASTPQ_RECOVERY_MAX_BATCH_BYTES
                )));
            }
            Err(source) => {
                return Err(Error::SerializationFailure {
                    context: "pipeline_recovery_fastpq_batch",
                    source: Box::new(source),
                });
            }
        };
    charge_fastpq_recovery_artifact_bytes(artifact_bytes, bytes.len())?;
    Ok((
        base64::engine::general_purpose::STANDARD.encode(bytes),
        reconstructed,
    ))
}
#[derive(JsonDeserialize, crate::json_macros::JsonSerialize, Clone, Debug)]
#[norito(deny_unknown_fields)]
struct PipelineStatusQuery {
    #[norito(default)]
    hash: Option<String>,
    #[norito(default)]
    scope: Option<String>,
}
#[derive(JsonDeserialize, crate::json_macros::JsonSerialize, Clone, Debug)]
#[norito(deny_unknown_fields)]
struct TriggerCompletionQuery {
    #[norito(default)]
    id: Option<String>,
    #[norito(default)]
    entrypoint_hash: Option<String>,
    #[norito(default)]
    outcome: Option<String>,
    #[norito(default)]
    from_height: Option<u64>,
    #[norito(default)]
    to_height: Option<u64>,
    #[norito(default)]
    limit: Option<u64>,
    #[norito(default)]
    scan_limit_blocks: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TriggerCompletionOutcomeFilter {
    All,
    Success,
    Failure,
}
impl TriggerCompletionOutcomeFilter {
    fn parse(raw: Option<&str>) -> Result<Self, Error> {
        let normalized = raw
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("all")
            .to_ascii_lowercase();
        match normalized.as_str() {
            "all" | "*" => Ok(Self::All),
            "success" | "ok" => Ok(Self::Success),
            "failure" | "failed" | "error" => Ok(Self::Failure),
            _ => Err(conversion_error(format!(
                "invalid outcome query parameter \"{normalized}\" (expected all|success|failure)"
            ))),
        }
    }
    fn matches(self, outcome: &str) -> bool {
        match self {
            Self::All => true,
            Self::Success => matches!(outcome, "Success"),
            Self::Failure => matches!(outcome, "Failure"),
        }
    }
}
const TRIGGER_COMPLETION_DEFAULT_LIMIT: u64 = 100;
const TRIGGER_COMPLETION_MAX_LIMIT: u64 = 1_000;
const TRIGGER_COMPLETION_DEFAULT_SCAN_BLOCKS: u64 = 1_000;
const TRIGGER_COMPLETION_MAX_SCAN_BLOCKS: u64 = 10_000;
fn trigger_completion_outcome(outcome: &TriggerCompletedOutcome) -> (&'static str, Option<String>) {
    match outcome {
        TriggerCompletedOutcome::Success => ("Success", None),
        TriggerCompletedOutcome::Failure(message) => ("Failure", Some(message.clone())),
    }
}
fn trigger_completion_record_matches(
    record: &TriggerCompletionRecord,
    trigger_id: Option<&str>,
    entrypoint_hash: Option<&str>,
    outcome: TriggerCompletionOutcomeFilter,
) -> bool {
    if let Some(trigger_id) = trigger_id
        && record.completion.trigger_id != trigger_id
    {
        return false;
    }
    if let Some(entrypoint_hash) = entrypoint_hash
        && record.completion.trigger_execution_hash != entrypoint_hash
    {
        return false;
    }
    outcome.matches(&record.completion.outcome)
}
fn visit_trigger_completion_records_for_block<F>(
    block: &iroha_data_model::block::SignedBlock,
    block_height: u64,
    mut visit: F,
) -> Result<bool, Error>
where
    F: FnMut(TriggerCompletionRecord) -> bool,
{
    block
        .validate_output_merkle_cache()
        .map_err(pipeline_status_projection_error)?;
    for output in block.execution_outputs() {
        let call_hash = output
            .execution_call_hash(block.hash(), block)
            .map_err(pipeline_status_projection_error)?;
        let entrypoint_index = match output {
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(row) => {
                Some(u64::from(row.input_index))
            }
            _ => None,
        };
        for completion in output.completions() {
            let (outcome, message) = trigger_completion_outcome(&completion.outcome);
            if !visit(TriggerCompletionRecord {
                block_height,
                entrypoint_index,
                completion: TriggerCompletionSummary {
                    trigger_id: completion.trigger_id.to_string(),
                    trigger_execution_hash: call_hash.to_string(),
                    step_index: completion.callback_index,
                    outcome: outcome.to_owned(),
                    message,
                },
                source: "execution_output".to_owned(),
            }) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}
fn trigger_completion_from_height(query: &TriggerCompletionQuery, requested_to: u64) -> u64 {
    let scan_limit = query
        .scan_limit_blocks
        .unwrap_or(TRIGGER_COMPLETION_DEFAULT_SCAN_BLOCKS)
        .clamp(1, TRIGGER_COMPLETION_MAX_SCAN_BLOCKS);
    let bounded_from = requested_to
        .saturating_sub(scan_limit.saturating_sub(1))
        .max(1);
    query.from_height.unwrap_or(1).max(1).max(bounded_from)
}
fn trigger_completion_query_response(
    app: &SharedAppState,
    query: &TriggerCompletionQuery,
) -> Result<TriggerCompletionListResponse, Error> {
    let latest_height = u64::try_from(app.state.committed_height()).unwrap_or(u64::MAX);
    let limit = query
        .limit
        .unwrap_or(TRIGGER_COMPLETION_DEFAULT_LIMIT)
        .clamp(1, TRIGGER_COMPLETION_MAX_LIMIT);
    let outcome = TriggerCompletionOutcomeFilter::parse(query.outcome.as_deref())?;
    let requested_to = query.to_height.unwrap_or(latest_height).min(latest_height);
    if latest_height == 0 || requested_to == 0 {
        return Ok(TriggerCompletionListResponse {
            latest_height,
            from_height: 0,
            to_height: requested_to,
            scanned_blocks: 0,
            limit,
            completions: Vec::new(),
        });
    }
    let from_height = trigger_completion_from_height(query, requested_to);
    if from_height > requested_to {
        return Ok(TriggerCompletionListResponse {
            latest_height,
            from_height,
            to_height: requested_to,
            scanned_blocks: 0,
            limit,
            completions: Vec::new(),
        });
    }
    let anchor_index = usize::try_from(requested_to - 1)
        .map_err(|_| pipeline_status_projection_error("completion anchor exceeds host index"))?;
    let anchor = app
        .state
        .view()
        .block_hashes()
        .get(anchor_index)
        .copied()
        .ok_or_else(|| {
            pipeline_status_projection_error("completion history anchor is unavailable")
        })?;
    let mut completions = Vec::new();
    let mut scanned_blocks = 0_u64;
    let mut remaining_work = routing::app_query_limits().max_fetch_size;
    let mut remaining_bytes =
        iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(remaining_work);
    for height in (from_height..=requested_to).rev() {
        scanned_blocks = scanned_blocks.saturating_add(1);
        let height_usize = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| {
                pipeline_status_projection_error("completion height exceeds host index")
            })?;
        let carrier = app
            .state
            .read_finalized_execution_carrier(height_usize, remaining_work, remaining_bytes)
            .map_err(crate::canonical_history::query_attempt_error)?;
        remaining_work -= carrier.work_items();
        remaining_bytes -= carrier.wire_bytes();
        let mut reached_limit = false;
        visit_trigger_completion_records_for_block(carrier.block(), height, |record| {
            if !trigger_completion_record_matches(
                &record,
                query.id.as_deref(),
                query.entrypoint_hash.as_deref(),
                outcome,
            ) {
                return true;
            }
            completions.push(record);
            reached_limit = u64::try_from(completions.len()).unwrap_or(u64::MAX) >= limit;
            !reached_limit
        })?;
        if reached_limit {
            break;
        }
    }
    if app.state.view().block_hashes().get(anchor_index).copied() != Some(anchor) {
        return Err(pipeline_status_projection_error(
            "completion history changed during authentication",
        ));
    }
    Ok(TriggerCompletionListResponse {
        latest_height,
        from_height,
        to_height: requested_to,
        scanned_blocks,
        limit,
        completions,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipelineStatusReadScope {
    Local,
    Global,
}
impl PipelineStatusReadScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Global => "global",
        }
    }
}
fn parse_pipeline_status_scope(raw: Option<&str>) -> Result<PipelineStatusReadScope, Error> {
    let scope = raw.unwrap_or("global");
    match scope {
        "local" => Ok(PipelineStatusReadScope::Local),
        "global" => Ok(PipelineStatusReadScope::Global),
        _ => Err(conversion_error(format!(
            "invalid scope query parameter \"{scope}\" (expected local|global)"
        ))),
    }
}
fn parse_signed_transaction_hash(raw: &str) -> Result<HashOf<SignedTransaction>, Error> {
    if raw.is_empty() || raw.trim() != raw {
        return Err(conversion_error(
            "signed transaction hash must use exact canonical lowercase text".to_owned(),
        ));
    }
    let hash = raw
        .parse::<HashOf<SignedTransaction>>()
        .map_err(|_| conversion_error("invalid signed transaction hash".to_owned()))?;
    if hash.to_string() != raw {
        return Err(conversion_error(
            "signed transaction hash must use exact canonical lowercase text".to_owned(),
        ));
    }
    Ok(hash)
}
fn pipeline_status_response(
    hash: &HashOf<SignedTransaction>,
    entry: &PipelineStatusEntry,
    scope: PipelineStatusReadScope,
    resolved_from: &'static str,
) -> PipelineTransactionStatusResponse {
    PipelineTransactionStatusResponse::new(
        hash.to_string(),
        PipelineTransactionStatus {
            kind: entry.kind.as_str().to_owned(),
            block_height: entry.block_height.map(NonZeroU64::get),
        },
        scope.as_str().to_owned(),
        resolved_from.to_owned(),
    )
}
fn pipeline_status_projection_error(message: impl std::fmt::Display) -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::Conversion(format!(
            "committed transaction status projection is inconsistent: {message}"
        )),
    ))
}
#[derive(Clone, Debug)]
enum CanonicalTransactionOutcome {
    Applied {
        height: NonZeroU64,
        settled_at: SystemTime,
    },
    Rejected {
        height: NonZeroU64,
        reason: TransactionRejectionReason,
    },
}
impl CanonicalTransactionOutcome {
    fn into_pipeline_status_entry(self) -> PipelineStatusEntry {
        match self {
            Self::Applied { height, .. } => {
                PipelineStatusEntry::fresh(PipelineStatusKind::Applied, Some(height), None)
            }
            Self::Rejected { height, reason } => PipelineStatusEntry::fresh(
                PipelineStatusKind::Rejected,
                Some(height),
                Some(pipeline_rejection_summary(&reason)),
            ),
        }
    }
}
// The State authority needed to authenticate a transaction outcome is owned:
// no world snapshot or epoch read guard crosses the Kura/crypto handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CanonicalTransactionAnchor {
    entrypoint_hash: HashOf<TransactionEntrypoint>,
    height: NonZeroUsize,
    block_hash: HashOf<BlockHeader>,
}
fn canonical_transaction_anchor(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<CanonicalTransactionAnchor>, Error> {
    let entrypoint_hash = iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone());
    let state_view = state.view();
    let Some(height) = state_view.transactions.get(&entrypoint_hash) else {
        return Ok(None);
    };
    let block_hash = state_view
        .block_hashes()
        .get(height.get().saturating_sub(1))
        .copied()
        .ok_or_else(|| {
            pipeline_status_projection_error(format!(
                "transaction {hash} is indexed beyond the committed block-hash journal at height {}",
                height.get()
            ))
        })?;
    Ok(Some(CanonicalTransactionAnchor {
        entrypoint_hash,
        height,
        block_hash,
    }))
}
fn canonical_transaction_outcome(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<CanonicalTransactionOutcome>, Error> {
    canonical_transaction_outcome_with_authenticator(state, hash, |anchor| {
        authenticate_canonical_transaction_outcome(state, hash, anchor)
    })
}
fn canonical_transaction_outcome_with_authenticator(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
    authenticate: impl FnOnce(CanonicalTransactionAnchor) -> Result<CanonicalTransactionOutcome, Error>,
) -> Result<Option<CanonicalTransactionOutcome>, Error> {
    canonical_transaction_read_with_authenticator(state, hash, authenticate)
}
// Keep the exact canonical bracket around the owned result as well as its scalar projection.
// This retains the original carrier/query lease until the membership recheck has succeeded.
fn canonical_transaction_read_with_authenticator<T>(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
    authenticate: impl FnOnce(CanonicalTransactionAnchor) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    let Some(anchor) = canonical_transaction_anchor(state, hash)? else {
        return Ok(None);
    };
    let outcome = authenticate(anchor)?;
    // A later append does not invalidate this exact committed carrier. A rewind,
    // removed/rebound membership, or replaced journal hash does. Return an error
    // on a changed binding so neither the pipeline cache nor ISO reconciliation
    // can convert an unauthoritative outcome into a terminal success.
    if canonical_transaction_anchor(state, hash)? != Some(anchor) {
        return Err(pipeline_status_projection_error(format!(
            "transaction {hash} canonical binding changed during outcome authentication"
        )));
    }
    Ok(Some(outcome))
}
// State captures and rechecks membership; Kura authenticates the exact finalized
// execution wire without retaining a world-state read guard across storage I/O.
fn authenticate_canonical_transaction_outcome(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
) -> Result<CanonicalTransactionOutcome, Error> {
    let work = routing::app_query_limits().max_fetch_size;
    canonical_transaction_outcome_from_reader(hash, anchor, |visitor| {
        iroha_core::smartcontracts::isi::tx::visit_finalized_network_transactions(
            state,
            anchor.height,
            anchor.block_hash,
            work,
            iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work),
            visitor,
        )
        .map_err(crate::canonical_history::query_attempt_error)
    })
}
// HTTP status is an off-chain observation. Retain its exact query-owned carrier until
// the canonical membership bracket and matching pending projection have both completed.
// Field order retires the funded carrier before the last original query lease/control.
struct AuthenticatedPipelineCarrier {
    carrier: iroha_core::smartcontracts::isi::tx::FinalizedExecutionCarrier,
    owner: crate::history_producer::HistoryProducerOwner,
}
fn read_pipeline_transaction_carrier(
    app: &SharedAppState,
    anchor: CanonicalTransactionAnchor,
) -> Result<AuthenticatedPipelineCarrier, Error> {
    read_pipeline_execution_carrier(app, anchor.height)
}
fn read_pipeline_execution_carrier(
    app: &SharedAppState,
    height: NonZeroUsize,
) -> Result<AuthenticatedPipelineCarrier, Error> {
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
    let work = routing::app_query_limits().max_fetch_size;
    let carrier = owner.scope(|| {
        let budget = owner.canonical_history_budget();
        let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
        // G1 still requires its actual certified H2. Only successors use the original
        // State/checkpoint ancestry. Refusal never selects another reader or pool.
        if height == NonZeroUsize::MIN {
            app.state
                .read_finalized_execution_carrier_with_read_budget(height, work, bytes, &budget)
        } else {
            app.state
                .read_executed_carrier_from_checkpoints(height, work, bytes, &budget)
        }
        .map_err(crate::canonical_history::query_attempt_error)
    })?;
    Ok(AuthenticatedPipelineCarrier { carrier, owner })
}
// Existing private outcome controls use the same production acquisition/projection.
#[cfg(test)]
fn authenticate_pipeline_transaction_outcome(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
) -> Result<CanonicalTransactionOutcome, Error> {
    let original = read_pipeline_transaction_carrier(app, anchor)?;
    original.owner.scope(|| {
        canonical_transaction_outcome_from_reader(hash, anchor, |visitor| {
            original
                .carrier
                .visit_network_transactions(anchor.block_hash, visitor)
                .map_err(|error| crate::canonical_history::query_attempt_error(error.into()))
        })
    })
}
// A single outcome kernel retains the existing exact inclusion, duplicate, rejection and
// timestamp checks irrespective of which authenticated, bounded carrier reader supplied it.
fn canonical_transaction_outcome_from_reader(
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
    read: impl FnOnce(
        &mut dyn FnMut(&TransactionEntrypoint, &iroha_data_model::transaction::TransactionResult),
    ) -> Result<BlockHeader, Error>,
) -> Result<CanonicalTransactionOutcome, Error> {
    let mut result = None;
    let mut duplicate = false;
    let header = read(&mut |entrypoint, output| {
        if transaction_entrypoint_matches_indexed_identity(entrypoint, &anchor.entrypoint_hash) {
            let outcome = output.as_ref().map(|_| ()).map_err(Clone::clone);
            duplicate |= result.replace(outcome).is_some();
        }
    })?;
    canonical_transaction_outcome_from_matches(hash, &header, result, duplicate)
}
// The exact transaction's committed outcome from bounded windows of its carrier. Core matches
// the same indexed identity (entrypoint hash or sealed-reveal signed alias) as the carrier
// kernel above; this keeps its exact binding, duplicate, absence and timestamp checks.
fn canonical_transaction_outcome_from_committed(
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
    committed: &iroha_core::smartcontracts::isi::tx::CommittedNetworkOutcome,
) -> Result<CanonicalTransactionOutcome, Error> {
    if committed.header().hash() != anchor.block_hash {
        return Err(pipeline_status_projection_error(format!(
            "transaction {hash} outcome carrier differs from its exact committed binding"
        )));
    }
    let (result, duplicate) = match committed.matched_results() {
        [] => (None, false),
        [result] => (Some(result.clone()), false),
        [result, ..] => (Some(result.clone()), true),
    };
    canonical_transaction_outcome_from_matches(hash, committed.header(), result, duplicate)
}
fn canonical_transaction_outcome_from_matches(
    hash: &HashOf<SignedTransaction>,
    header: &BlockHeader,
    result: Option<Result<(), TransactionRejectionReason>>,
    duplicate: bool,
) -> Result<CanonicalTransactionOutcome, Error> {
    if duplicate {
        return Err(pipeline_status_projection_error(format!(
            "transaction {hash} occurs more than once in its finalized carrier"
        )));
    }
    let result = result.ok_or_else(|| {
        pipeline_status_projection_error(format!(
            "transaction {hash} is absent from its finalized carrier"
        ))
    })?;
    let settled_at = UNIX_EPOCH
        .checked_add(header.creation_time())
        .ok_or_else(|| pipeline_status_projection_error("carrier time exceeds SystemTime"))?;
    Ok(match result {
        Ok(()) => CanonicalTransactionOutcome::Applied {
            height: header.height(),
            settled_at,
        },
        Err(reason) => CanonicalTransactionOutcome::Rejected {
            height: header.height(),
            reason,
        },
    })
}

fn pipeline_status_from_state(
    state: &CoreState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<PipelineStatusEntry>, Error> {
    canonical_transaction_outcome(state, hash)
        .map(|outcome| outcome.map(CanonicalTransactionOutcome::into_pipeline_status_entry))
}
fn pipeline_status_terminal_or_state_entry(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<(PipelineStatusEntry, &'static str)>, Error> {
    let outcome = reconcile_pending_pipeline_transaction(app, hash)?;
    pipeline_status_terminal_or_state_entry_from_outcome(app, hash, outcome)
}
// The complete-carrier status kernel with a caller-supplied carrier reader, for its controls.
#[cfg(test)]
fn pipeline_status_terminal_or_state_entry_with_carrier_reader(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
    read: impl FnOnce(CanonicalTransactionAnchor) -> Result<AuthenticatedPipelineCarrier, Error>,
) -> Result<Option<(PipelineStatusEntry, &'static str)>, Error> {
    let outcome = reconcile_pending_pipeline_transaction_with_carrier_reader(app, hash, read)?;
    pipeline_status_terminal_or_state_entry_from_outcome(app, hash, outcome)
}
fn pipeline_status_terminal_or_state_entry_from_outcome(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
    outcome: Option<CanonicalTransactionOutcome>,
) -> Result<Option<(PipelineStatusEntry, &'static str)>, Error> {
    if let Some(entry) = outcome.map(CanonicalTransactionOutcome::into_pipeline_status_entry) {
        app.pipeline_status_cache.record_entry(*hash, entry.clone());
        return Ok(Some((entry, "state")));
    }
    if let Some(entry) = pipeline_status_cached_entry_without_canonical(app, hash)?
        && entry.kind.is_terminal()
    {
        return Ok(Some((entry, "cache")));
    }
    Ok(None)
}
// HTTP consumers authenticate the exact transaction with request-owned capacity and use the
// canonical outcome kernel. A cached status or membership alone cannot authorize settlement.
// Successors read only bounded windows of their carrier, so a committed outcome is readable
// whatever the size of its block or of the transaction itself; G1 still requires its actual
// certified H2 and keeps the complete-carrier reader.
fn reconcile_pending_pipeline_transaction(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<CanonicalTransactionOutcome>, Error> {
    // This deliberate mutant restores only the old pre-admission side effect. The ordinary
    // path neither reads unrelated pending carriers nor borrows State execution capacity.
    #[cfg(all(test, sumeragi_torii_mutation = "TOR2"))]
    app.pipeline_status_cache.refresh_pending_blocks(&app.state);
    let authenticated =
        canonical_transaction_read_with_authenticator(&app.state, hash, |anchor| {
            if anchor.height == NonZeroUsize::MIN {
                let original = read_pipeline_transaction_carrier(app, anchor)?;
                let outcome = pipeline_carrier_outcome(hash, anchor, &original)?;
                return Ok((outcome, anchor, PipelineOutcomeEvidence::Carrier(original)));
            }
            let (outcome, owner) = read_pipeline_transaction_outcome(app, hash, anchor)?;
            Ok((outcome, anchor, PipelineOutcomeEvidence::Exact(owner)))
        })?;
    let Some((outcome, anchor, evidence)) = authenticated else {
        return Ok(None);
    };
    match evidence {
        // Only this exact pending block can complete, using the already authenticated
        // immutable join. No second I/O/decode, State budget, or bulk pending drain occurs.
        PipelineOutcomeEvidence::Carrier(original) => original.owner.scope(|| {
            app.pipeline_status_cache
                .complete_pending_from_carrier(&original.carrier, anchor.block_hash)
        })?,
        // Only this exact pending block completes, after the canonical recheck, for its exact
        // authenticated transaction, without another read or a bulk pending drain; each of its
        // other transactions is authenticated by its own exact read when it is asked for.
        PipelineOutcomeEvidence::Exact(owner) => {
            if let Some(height) = u64::try_from(anchor.height.get())
                .ok()
                .and_then(NonZeroU64::new)
            {
                owner.scope(|| {
                    app.pipeline_status_cache
                        .complete_pending_from_exact_outcome(
                            height,
                            anchor.block_hash,
                            hash,
                            &outcome,
                        );
                });
            }
        }
    }
    Ok(Some(outcome))
}
// What authenticated one exact outcome; each form retains its original query owner.
enum PipelineOutcomeEvidence {
    // G1 requires its actual certified H2, so it keeps the complete H1/H2 carrier.
    Carrier(AuthenticatedPipelineCarrier),
    // Every successor: the exact transaction, read from bounded windows of its carrier.
    Exact(crate::history_producer::HistoryProducerOwner),
}
// The complete-carrier outcome kernel, projected under the carrier's original query owner.
fn pipeline_carrier_outcome(
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
    original: &AuthenticatedPipelineCarrier,
) -> Result<CanonicalTransactionOutcome, Error> {
    original.owner.scope(|| {
        canonical_transaction_outcome_from_reader(hash, anchor, |visitor| {
            original
                .carrier
                .visit_network_transactions(anchor.block_hash, visitor)
                .map_err(|error| crate::canonical_history::query_attempt_error(error.into()))
        })
    })
}
// HTTP status authenticates only the exact transaction: bounded windows of its carrier under the
// request's admitted query owner, never the State execution pool or a whole decoded block.
fn read_pipeline_transaction_outcome(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
    anchor: CanonicalTransactionAnchor,
) -> Result<
    (
        CanonicalTransactionOutcome,
        crate::history_producer::HistoryProducerOwner,
    ),
    Error,
> {
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
    let work = routing::app_query_limits().max_fetch_size;
    let outcome = owner.scope(|| {
        let budget = owner.canonical_history_budget();
        let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
        let committed = app
            .state
            .read_committed_network_outcome(
                anchor.height,
                &anchor.entrypoint_hash,
                work,
                bytes,
                &budget,
            )
            .map_err(crate::canonical_history::query_attempt_error)?;
        canonical_transaction_outcome_from_committed(hash, anchor, &committed)
    })?;
    Ok((outcome, owner))
}
impl PipelineStatusCache {
    // An exact authenticated transaction completes only its own matching pending block: it
    // records that transaction's result as the event projection would (the pending kind for an
    // applied result, a rejection summary otherwise) and retires the block. Keep the occupied
    // entry locked: a replacement at the same height is never completed by this outcome.
    fn complete_pending_from_exact_outcome(
        &self,
        height: NonZeroU64,
        expected_hash: HashOf<BlockHeader>,
        transaction: &HashOf<SignedTransaction>,
        outcome: &CanonicalTransactionOutcome,
    ) {
        if !self.event_hints_trustworthy.load(AtomicOrdering::Acquire) {
            return;
        }
        let DashEntry::Occupied(pending) = self.pending_blocks.entry(height) else {
            return;
        };
        if pending.get().block_hash != expected_hash {
            return;
        }
        if let Some(reason) = &pending.get().deferred {
            iroha_logger::trace!(height = height.get(), %reason, "completing original deferred pipeline history observation");
        }
        let (kind, rejection) = match outcome {
            CanonicalTransactionOutcome::Applied { .. } => (pending.get().kind, None),
            CanonicalTransactionOutcome::Rejected { reason, .. } => (
                PipelineStatusKind::Rejected,
                Some(pipeline_rejection_summary(reason)),
            ),
        };
        let observed_at = pending.get().observed_at;
        self.record_entry_inner(
            *transaction,
            PipelineStatusEntry::at_time(kind, Some(height), rejection, observed_at),
        );
        pending.remove();
        Self::decrement_live_count(&self.pending_count);
        // Do not prune while holding the pending-map entry: pruning acquires that same map.
    }
}
// The complete-carrier reconciliation with a caller-supplied carrier reader, for the
// existing carrier, pending-completion and binding controls.
#[cfg(test)]
fn reconcile_pending_pipeline_transaction_with_carrier_reader(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
    read: impl FnOnce(CanonicalTransactionAnchor) -> Result<AuthenticatedPipelineCarrier, Error>,
) -> Result<Option<CanonicalTransactionOutcome>, Error> {
    // This deliberate mutant restores only the old pre-admission side effect. The ordinary
    // path neither reads unrelated pending carriers nor borrows State execution capacity.
    #[cfg(all(test, sumeragi_torii_mutation = "TOR2"))]
    app.pipeline_status_cache.refresh_pending_blocks(&app.state);
    let authenticated =
        canonical_transaction_read_with_authenticator(&app.state, hash, |anchor| {
            let original = read(anchor)?;
            let outcome = pipeline_carrier_outcome(hash, anchor, &original)?;
            Ok((outcome, anchor, original))
        })?;
    if let Some((outcome, anchor, original)) = authenticated {
        // Only this exact pending block can complete, using the already authenticated
        // immutable join. No second I/O/decode, State budget, or bulk pending drain occurs.
        original.owner.scope(|| {
            app.pipeline_status_cache
                .complete_pending_from_carrier(&original.carrier, anchor.block_hash)
        })?;
        return Ok(Some(outcome));
    }
    Ok(None)
}
// A cached block outcome is only a hint once the exact State binding is absent. Keep
// ordinary local expiry/admission rejection distinct, and retain the original cache on
// refusal so neither retry nor prepared submission can manufacture canonical authority.
fn pipeline_status_cached_entry_without_canonical(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<PipelineStatusEntry>, Error> {
    let cached = app.pipeline_status_cache.lookup(hash);
    if let Some(entry) = &cached {
        let needs_canonical = matches!(
            entry.kind,
            PipelineStatusKind::Committed | PipelineStatusKind::Applied
        ) || (entry.block_height.is_some()
            && matches!(
                entry.kind,
                PipelineStatusKind::Rejected | PipelineStatusKind::Expired
            ));
        if needs_canonical && !cfg!(all(test, sumeragi_torii_mutation = "TOR1")) {
            return Err(pipeline_status_projection_error(format!(
                "transaction {hash} has cached {} without its exact canonical binding",
                entry.kind.as_str()
            )));
        }
    }
    Ok(cached)
}
pub(crate) fn pipeline_status_local_entry_checked(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<(PipelineStatusEntry, &'static str)>, Error> {
    if let Some(entry) = pipeline_status_terminal_or_state_entry(app, hash)? {
        return Ok(Some(entry));
    }
    if let Some(entry) = pipeline_status_cached_entry_without_canonical(app, hash)? {
        if entry.kind == PipelineStatusKind::Queued
            && !app.queue.contains_pending_hash(
                iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
                &app.state,
            )
        {
            app.pipeline_status_cache.remove_entry_by_hash(hash);
            return Ok(None);
        }
        return Ok(Some((entry, "cache")));
    }
    if app.queue.contains_pending_hash(
        iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone()),
        &app.state,
    ) {
        let entry = PipelineStatusEntry::fresh(PipelineStatusKind::Queued, None, None);
        app.pipeline_status_cache
            .record_entry(hash.clone(), entry.clone());
        return Ok(Some((entry, "queue")));
    }
    Ok(None)
}
fn pipeline_status_local_entry(
    app: &SharedAppState,
    hash: &HashOf<SignedTransaction>,
) -> Option<(PipelineStatusEntry, &'static str)> {
    match pipeline_status_local_entry_checked(app, hash) {
        Ok(entry) => entry,
        Err(error) => {
            iroha_logger::error!(
                ?error,
                %hash,
                "internal pipeline-status consumer rejected canonical transaction evidence"
            );
            None
        }
    }
}
fn pipeline_status_response_with_route(
    hash: &HashOf<SignedTransaction>,
    entry: &PipelineStatusEntry,
    scope: PipelineStatusReadScope,
    resolved_from: &'static str,
    format: ResponseFormat,
    route: Option<(RoutingDecision, &'static str)>,
) -> Response {
    let mut response = crate::utils::respond_with_format(
        pipeline_status_response(hash, entry, scope, resolved_from),
        format,
    );
    if let Some((routing_decision, routed_by)) = route {
        insert_routing_headers(&mut response, routing_decision, routed_by);
    }
    response
}
fn pipeline_status_not_found_response(
    hash: &HashOf<SignedTransaction>,
    scope: PipelineStatusReadScope,
    format: ResponseFormat,
) -> Response {
    crate::utils::respond_with_status_and_format(
        StatusCode::NOT_FOUND,
        ErrorEnvelope::new(
            iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
            "No transaction status is available for the exact requested hash and scope.",
        )
        .with_details(ErrorDetails {
            pipeline_transaction_status_not_found: Some(
                iroha_torii_shared::PipelineTransactionStatusNotFoundV1::new(hash, scope.as_str()),
            ),
            ..ErrorDetails::default()
        }),
        format,
    )
}
#[cfg(feature = "app_api")]
async fn validate_pipeline_status_absence_response(
    response: Response,
    hash: &HashOf<SignedTransaction>,
    scope: PipelineStatusReadScope,
    maximum: usize,
) -> Result<(), Response> {
    let envelope = decode_torii_scoped_absence_response(response, maximum).await?;
    if envelope.code() != iroha_torii_shared::PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE
        || !envelope
            .details
            .as_ref()
            .and_then(|details| details.pipeline_transaction_status_not_found.as_ref())
            .is_some_and(|absence| absence.matches(hash, scope.as_str()))
    {
        return Err(torii_proxy_error_response(
            StatusCode::BAD_GATEWAY,
            "invalid_proxy_response",
            "pipeline status absence differs from the exact requested hash and scope",
        ));
    }
    Ok(())
}
fn exact_transaction_details_query_hash(
    request: &iroha_data_model::query::QueryRequestWithAuthority,
) -> Result<HashOf<TransactionEntrypoint>, Error> {
    use iroha_data_model::query::{
        CommittedTxFilters, QueryItemKind, QueryRequest, transaction::prelude::FindTransactions,
    };
    fn exact_hash_from_predicate(
        predicate: &iroha_data_model::query::dsl::CompoundPredicate<CommittedTransaction>,
    ) -> Option<HashOf<TransactionEntrypoint>> {
        let filters = predicate.committed_tx_filters()?;
        let entry_eq = filters.entry_eq.clone()?;
        (filters
            == CommittedTxFilters {
                entry_eq: Some(entry_eq.clone()),
                ..CommittedTxFilters::default()
            })
        .then_some(entry_eq)
    }
    let QueryRequest::Start(query) = request.request() else {
        return Err(conversion_error(
            "transaction details requires a signed FindTransactions start query".to_owned(),
        ));
    };
    if query.params() != &iroha_data_model::query::parameters::QueryParams::default() {
        return Err(conversion_error(
            "transaction details query parameters must use their canonical defaults".to_owned(),
        ));
    }
    let (item_kind, predicate_bytes, selector_bytes, payload) = query.parts();
    if item_kind != QueryItemKind::CommittedTransaction
        || !payload_matches_query::<FindTransactions>(payload)
    {
        return Err(conversion_error(
            "transaction details requires canonical FindTransactions".to_owned(),
        ));
    }
    let predicate = decode_query_payload::<
        iroha_data_model::query::dsl::CompoundPredicate<CommittedTransaction>,
    >(predicate_bytes)
    .ok_or_else(|| conversion_error("transaction details predicate is not canonical".to_owned()))?;
    let selector = decode_query_payload::<
        iroha_data_model::query::dsl::SelectorTuple<CommittedTransaction>,
    >(selector_bytes)
    .ok_or_else(|| conversion_error("transaction details selector is not canonical".to_owned()))?;
    if selector != iroha_data_model::query::dsl::SelectorTuple::<CommittedTransaction>::default() {
        return Err(conversion_error(
            "transaction details query does not accept a projection".to_owned(),
        ));
    }
    let hash = exact_hash_from_predicate(&predicate);
    hash.ok_or_else(|| {
        conversion_error(
            "transaction details requires exactly one entrypoint_hash equality predicate"
                .to_owned(),
        )
    })
}
fn transaction_details_operator_authority(
    world: &impl WorldReadOnly,
    authority: &AccountId,
) -> bool {
    let permission: Permission = CanReadAllLedgerData.into();
    torii_account_has_permission(world, authority, &permission)
}
fn transaction_details_authority_is_involved(
    authority: &AccountId,
    transaction: &CommittedTransaction,
) -> bool {
    let already_involved = transaction.entrypoint().authority() == authority
        || transaction
            .result()
            .batch_transfer_outcomes()
            .iter()
            .any(|outcome| {
                outcome.asset.account() == authority || &outcome.destination == authority
            });
    if already_involved {
        return true;
    }
    // Only successful committed native execution establishes these beneficiaries.
    // A rejected instruction merely naming an account must not disclose its payload.
    if transaction.result().is_err() {
        return false;
    }
    let TransactionEntrypoint::External(entrypoint) = transaction.entrypoint() else {
        return false;
    };
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        entrypoint.instructions()
    else {
        return false;
    };
    instructions.iter().any(|instruction| {
        use iroha_data_model::{
            alias_setup::AliasIntentV1,
            isi::{RegisterBox, TransferBox, alias_setup::EnsureAlias},
        };
        let instruction = instruction.as_any();
        if let Some(RegisterBox::Account(register)) = instruction.downcast_ref::<RegisterBox>() {
            return &register.object.id == authority;
        }
        if let Some(ensure) = instruction.downcast_ref::<EnsureAlias>() {
            return matches!(
                &ensure.intent,
                AliasIntentV1::AccountAlias(intent) if &intent.target_account == authority
            );
        }
        matches!(
            instruction.downcast_ref::<TransferBox>(),
            Some(TransferBox::Asset(transfer)) if transfer.destination() == authority
        )
    })
}
fn canonical_transaction_details_for_indexed_identity(
    app: &AppState,
    block_height: NonZeroUsize,
    indexed_identity: &HashOf<TransactionEntrypoint>,
) -> Result<CommittedTransaction, Error> {
    let expected_hash = app
        .state
        .view()
        .block_hashes()
        .get(block_height.get() - 1)
        .copied()
        .ok_or_else(|| {
            pipeline_status_projection_error("indexed carrier is outside canonical history")
        })?;
    let work = routing::app_query_limits().max_fetch_size;
    let bytes = iroha_core::smartcontracts::isi::tx::transaction_history_byte_limit(work);
    let carrier = app
        .state
        .read_finalized_execution_carrier(block_height, work, bytes)
        .map_err(crate::canonical_history::query_attempt_error)?;
    if carrier.block().hash() != expected_hash {
        return Err(pipeline_status_projection_error(
            "native carrier differs from its exact committed binding",
        ));
    }
    let mut matched = None;
    let mut duplicate = false;
    for (input_index, entrypoint) in carrier.block().network_entrypoints().enumerate() {
        if transaction_entrypoint_matches_indexed_identity(entrypoint, indexed_identity) {
            let input_index =
                u32::try_from(input_index).map_err(pipeline_status_projection_error)?;
            duplicate |= matched.replace(input_index).is_some();
        }
    }
    if duplicate {
        return Err(pipeline_status_projection_error(
            "indexed identity selects multiple Network inputs",
        ));
    }
    let input_index = matched.ok_or_else(|| {
        pipeline_status_projection_error("indexed identity is absent from its finalized carrier")
    })?;
    let transaction = carrier
        .transaction_at(input_index, bytes)
        .map_err(pipeline_status_projection_error)?;
    if app.state.view().block_hashes().get(block_height.get() - 1) != Some(&expected_hash) {
        return Err(pipeline_status_projection_error(
            "canonical carrier changed during identity lookup",
        ));
    }
    Ok(transaction)
}
/// This code is reserved for absence of the one authenticated committed proof.
/// Generic route/account failures must never masquerade as delayed proof visibility.
fn transaction_details_not_found_error() -> Error {
    Error::AppNotFound {
        code: "transaction_details_not_found",
        message: "The exact committed transaction proof is not available.".to_owned(),
    }
}
fn pipeline_transaction_details_response(
    app: &SharedAppState,
    authority: &AccountId,
    entrypoint_hash: HashOf<TransactionEntrypoint>,
) -> Result<PipelineTransactionDetailsResponse, Error> {
    let state_view = app.state.view();
    let world = state_view.world();
    world.account(authority).map_err(|_| {
        Error::Query(iroha_data_model::ValidationFail::NotPermitted(format!(
            "transaction-details authority `{authority}` is not a registered account"
        )))
    })?;
    let is_operator = transaction_details_operator_authority(world, authority);
    drop(state_view);
    let block_height = app
        .state
        .committed_entrypoint_height(&entrypoint_hash)
        .ok_or_else(transaction_details_not_found_error)?;
    // State already binds this exact carrier. Its authenticated Network projection must not
    // depend on a complete auxiliary index of every unrelated historical transaction.
    let transaction = canonical_transaction_details_for_indexed_identity(
        app.as_ref(),
        block_height,
        &entrypoint_hash,
    )?;
    if !is_operator && !transaction_details_authority_is_involved(authority, &transaction) {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "transaction details are restricted to an involved account or operator".to_owned(),
            ),
        ));
    }
    let hash = entrypoint_hash.to_string();
    Ok(PipelineTransactionDetailsResponse { hash, transaction })
}
fn pipeline_status_proxy_query(
    hash: &HashOf<SignedTransaction>,
    scope: PipelineStatusReadScope,
) -> Result<Option<String>, Error> {
    encode_torii_proxy_query(&PipelineStatusQuery {
        hash: Some(hash.to_string()),
        scope: Some(scope.as_str().to_owned()),
    })
}
fn execute_pipeline_status_local_read(
    app: &SharedAppState,
    query: &PipelineStatusQuery,
    format: ResponseFormat,
    route: Option<(RoutingDecision, &'static str)>,
) -> Result<Response, Error> {
    let hash_raw = query
        .hash
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| conversion_error("missing hash query parameter".to_owned()))?;
    let read_scope = parse_pipeline_status_scope(query.scope.as_deref())?;
    let hash = parse_signed_transaction_hash(hash_raw)?;
    // A pending input is an existence hint for both scopes. Global fanout
    // must not report exact absence while one routed coordinator still owns
    // the accepted input or its block-pipeline cache entry. The checked
    // lookup keeps canonical committed outcomes ahead of all such hints.
    let local_entry = pipeline_status_local_entry_checked(app, &hash)?;
    if let Some((entry, resolved_from)) = local_entry {
        return Ok(pipeline_status_response_with_route(
            &hash,
            &entry,
            read_scope,
            resolved_from,
            format,
            route,
        ));
    }
    Ok(pipeline_status_not_found_response(
        &hash, read_scope, format,
    ))
}
#[cfg(feature = "app_api")]
fn pipeline_status_payload_is_authoritative_hint(
    payload: &PipelineTransactionStatusResponse,
) -> bool {
    match payload.status.kind.as_str() {
        "Applied" | "Rejected" | "Expired" => payload.resolved_from == "state",
        _ => false,
    }
}
#[cfg(feature = "app_api")]
async fn pipeline_status_hinted_global_response(
    response: Response,
    max_response_bytes: usize,
    hash: &HashOf<SignedTransaction>,
) -> Result<Option<Response>, Response> {
    if response.status() == StatusCode::NOT_FOUND {
        validate_pipeline_status_absence_response(
            response,
            hash,
            PipelineStatusReadScope::Global,
            max_response_bytes,
        )
        .await?;
        return Ok(None);
    }
    if torii_response_has_reject_code(&response, "route_unavailable") {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Ok(Some(response));
    }
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, max_response_bytes.max(1))
        .await
        .map_err(|error| {
            torii_proxy_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_proxy_response",
                format!("failed to read hinted pipeline status response: {error}"),
            )
        })?;
    let is_terminal = match norito::json::from_slice::<PipelineTransactionStatusResponse>(&bytes) {
        Ok(payload) => {
            if payload.hash != hash.to_string() || payload.scope != "global" {
                return Err(torii_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "invalid_proxy_response",
                    "hinted pipeline status differs from the exact requested hash and global scope",
                ));
            }
            pipeline_status_payload_is_authoritative_hint(&payload)
        }
        Err(_) => false,
    };
    let response = Response::from_parts(parts, Body::from(bytes));
    Ok(is_terminal.then_some(response))
}
#[cfg(feature = "app_api")]
async fn pipeline_status_global_response_with_local_hint(
    response: Response,
    local_hint: Option<(PipelineStatusEntry, &'static str)>,
    hash: &HashOf<SignedTransaction>,
    format: ResponseFormat,
    max_response_bytes: usize,
) -> Response {
    // Routed committed outcomes take precedence over a lagging ingress
    // queue. Keep a local existence hint only after complete exact absence
    // across the routed coordinators; failed fanout cannot establish absence.
    if response.status() != StatusCode::NOT_FOUND || local_hint.is_none() {
        return response;
    }
    if let Err(response) = validate_pipeline_status_absence_response(
        response,
        hash,
        PipelineStatusReadScope::Global,
        max_response_bytes,
    )
    .await
    {
        return response;
    }
    let (entry, source) = local_hint.expect("local hint presence checked");
    pipeline_status_response_with_route(
        hash,
        &entry,
        PipelineStatusReadScope::Global,
        source,
        format,
        None,
    )
}
async fn handler_pipeline_transaction_status(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    accept: Option<crate::utils::extractors::ExtractAccept>,
    crate::NoritoStringQuery(query): crate::NoritoStringQuery<PipelineStatusQuery>,
) -> Result<Response, Error> {
    let remote_ip = remote.ip();
    let format = match crate::utils::negotiate_response_format(accept.as_ref().map(|v| &v.0)) {
        Ok(format) => format,
        Err(resp) => return Ok(resp),
    };
    check_access_with_rate_limiter(
        &app,
        &headers,
        Some(remote_ip),
        "v1/pipeline/transactions/status",
        &app.pipeline_status_rate_limiter,
    )
    .await?;
    let read_scope = parse_pipeline_status_scope(query.scope.as_deref())?;
    let hash_raw = query
        .hash
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| conversion_error("missing hash query parameter".to_owned()))?;
    let hash = parse_signed_transaction_hash(hash_raw)?;
    let local_hint = pipeline_status_local_entry_checked(&app, &hash)?;
    if let Some((entry, source)) = local_hint.as_ref() {
        if matches!(read_scope, PipelineStatusReadScope::Local) || *source == "state" {
            return Ok(pipeline_status_response_with_route(
                &hash, entry, read_scope, source, format, None,
            ));
        }
    } else if matches!(read_scope, PipelineStatusReadScope::Local) {
        return Ok(pipeline_status_not_found_response(
            &hash, read_scope, format,
        ));
    }
    #[cfg(feature = "app_api")]
    {
        let query_string = pipeline_status_proxy_query(&hash, read_scope)?;
        let entrypoint_hash =
            iroha_core::tx::external_entrypoint_hash_from_signed_hash(hash.clone());
        if let Some(route) = app
            .queue
            .routing_plan_hint(&entrypoint_hash)
            .map(|plan| plan.coordinator_route())
        {
            let hinted = execute_torii_single_route_read(
                &app,
                route,
                ToriiReadEndpointV1::PipelineTransactionStatusGet,
                Vec::new(),
                query_string.clone(),
                Vec::new(),
            )
            .await;
            match pipeline_status_hinted_global_response(
                hinted,
                app.torii_proxy_max_response_bytes,
                &hash,
            )
            .await
            {
                Ok(Some(hinted)) => return Ok(hinted),
                Ok(None) => {}
                Err(response) => return Ok(response),
            }
        }
        let routed = execute_torii_public_pipeline_status_fanout(&app, query_string).await;
        Ok(pipeline_status_global_response_with_local_hint(
            routed,
            local_hint,
            &hash,
            format,
            app.torii_proxy_max_response_bytes,
        )
        .await)
    }
    #[cfg(not(feature = "app_api"))]
    {
        let _ = headers;
        let _ = remote_ip;
        let _ = hash;
        Ok(crate::utils::respond_with_status_and_format(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorEnvelope::new(
                "route_unavailable",
                "global pipeline status fanout is unavailable on this node",
            ),
            format,
        ))
    }
}
async fn handler_pipeline_transaction_details(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    accept: Option<crate::utils::extractors::ExtractAccept>,
    crate::utils::extractors::JsonOrNoritoVersioned(query): crate::utils::extractors::JsonOrNoritoVersioned<
        SignedQuery,
    >,
) -> Result<Response, Error> {
    let format =
        match crate::utils::negotiate_response_format(accept.as_ref().map(|value| &value.0)) {
            Ok(format) => format,
            Err(response) => return Ok(response),
        };
    if !limits::is_allowed_by_cidr(&headers, Some(remote.ip()), &app.api_rate_limit_bypass_nets) {
        admit_signed_query_preauth(app.as_ref(), &headers, Some(remote.ip())).await?;
    }
    // Exact network, freshness, signature, and one-shot nonce checks complete before the first
    // state or Kura access. The signed request itself binds the sole permitted entrypoint hash.
    let verified =
        routing::verify_signed_query_request(query, app.signed_query_admission.as_ref())?;
    let authority = verified.authority().clone();
    let entrypoint_hash = exact_transaction_details_query_hash(&verified)?;
    admit_signed_query_authority(app.as_ref(), &authority).await?;
    let _admission = acquire_signed_query_physical_admission(app.as_ref(), &verified).await?;
    let response = pipeline_transaction_details_response(&app, &authority, entrypoint_hash)?;
    Ok(crate::utils::respond_with_format(response, format))
}
async fn handler_trigger_completions(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    accept: Option<crate::utils::extractors::ExtractAccept>,
    AxQuery(query): AxQuery<TriggerCompletionQuery>,
) -> Result<Response, Error> {
    let format = match crate::utils::negotiate_response_format(accept.as_ref().map(|v| &v.0)) {
        Ok(format) => format,
        Err(resp) => return Ok(resp),
    };
    check_operator_rate_limit(
        &app,
        &headers,
        Some(remote.ip()),
        "v1/triggers/completed",
        true,
    )
    .await?;
    let admission = acquire_query_admission(&app, true).await?;
    let worker = crate::panic_recovery::spawn_blocking_recoverable(move || {
        // Keep the admission permits inside the physical task. Dropping the
        // HTTP future must not free capacity while Kura reconstruction still
        // consumes CPU and memory.
        let result = trigger_completion_query_response(&app, &query);
        (result, admission)
    });
    let (result, _admission) = crate::panic_recovery::join_recoverable(worker)
        .await
        .map_err(|error| Error::AppServiceUnavailable {
            code: "trigger_completion_worker_failed",
            message: error.to_string(),
        })?;
    Ok(crate::utils::respond_with_format(result?, format))
}
async fn handler_policy(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<impl IntoResponse, Error> {
    #[allow(clippy::too_many_arguments, clippy::ref_option)]
    fn build_policy_body(
        require_token: bool,
        fee_policy: &FeePolicy,
        queue_len: u64,
        normal_th: usize,
        stream_th: usize,
        sub_th: usize,
        token_required: bool,
    ) -> axum::response::Response {
        let mut obj = norito::json::Map::new();
        obj.insert(
            "require_api_token".into(),
            norito::json::Value::from(require_token),
        );
        obj.insert(
            "token_required".into(),
            norito::json::Value::from(token_required),
        );
        match fee_policy.asset_id() {
            Some(asset) => obj.insert(
                "fee_asset_id".into(),
                norito::json::Value::from(asset.to_owned()),
            ),
            None => obj.insert("fee_asset_id".into(), norito::json::Value::Null),
        };
        match fee_policy.receiver() {
            Some(r) => obj.insert(
                "fee_receiver".into(),
                norito::json::Value::from(r.to_owned()),
            ),
            None => obj.insert("fee_receiver".into(), norito::json::Value::Null),
        };
        match fee_policy.amount() {
            Some(amount) => obj.insert(
                "fee_amount".into(),
                norito::json::Value::from(amount.to_string()),
            ),
            None => obj.insert("fee_amount".into(), norito::json::Value::Null),
        };
        obj.insert("queue_len".into(), norito::json::Value::from(queue_len));
        obj.insert(
            "rate_limit_threshold".into(),
            norito::json::Value::from(normal_th as u64),
        );
        obj.insert(
            "stream_rate_limit_threshold".into(),
            norito::json::Value::from(stream_th as u64),
        );
        obj.insert(
            "subscription_rate_limit_threshold".into(),
            norito::json::Value::from(sub_th as u64),
        );
        let fees_enabled = fee_policy.is_enabled();
        let enforced = true;
        let stream_shed = (queue_len as usize) >= stream_th;
        let sub_shed = (queue_len as usize) >= sub_th;
        obj.insert(
            "rate_limit_enforced".into(),
            norito::json::Value::from(enforced),
        );
        obj.insert(
            "stream_rate_limit_enforced".into(),
            norito::json::Value::from(true),
        );
        obj.insert(
            "subscription_rate_limit_enforced".into(),
            norito::json::Value::from(true),
        );
        obj.insert(
            "stream_admission_shed".into(),
            norito::json::Value::from(stream_shed),
        );
        obj.insert(
            "subscription_admission_shed".into(),
            norito::json::Value::from(sub_shed),
        );
        let explain = format!(
            "rate_limits_always_on=true, fees_enabled={}, queue_len={}, high_load_admission_shed_thresholds(normal={}, stream={}, subscription={})",
            fees_enabled, queue_len, normal_th, stream_th, sub_th
        );
        obj.insert("explain".into(), norito::json::Value::from(explain));
        let body = norito::json::to_json_pretty(&norito::json::Value::Object(obj))
            .unwrap_or_else(|_| "{}".into());
        let mut resp = axum::response::Response::new(axum::body::Body::from(body));
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        resp
    }
    let queue_len = app.queue.active_len() as u64;
    let token_required = app.require_api_token;
    let enforce_rate =
        !limits::is_allowed_by_cidr(&headers, Some(remote.ip()), &app.api_rate_limit_bypass_nets);
    check_operator_rate_limit(&app, &headers, Some(remote.ip()), "v1/policy", enforce_rate).await?;
    Ok(build_policy_body(
        app.require_api_token,
        &app.fee_policy,
        queue_len,
        app.high_load_tx_threshold,
        app.high_load_stream_tx_threshold,
        app.high_load_subscription_tx_threshold,
        token_required,
    ))
}
