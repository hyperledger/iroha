//! Production stream-token admission for SoraFS serving routes.
use super::*;
use crate::sorafs::stream_token_cleanup::ExternalStreamTokenLeaseV1;
#[cfg(test)]
use crate::sorafs::{StreamTokenConcurrencyPermit, StreamTokenQuotaError};
use iroha_data_model::sorafs::stream_token_gateway::{
    StreamTokenGatewayAdmissionErrorV1, StreamTokenGatewayAdmissionRecordV1,
    StreamTokenGatewayAdmissionRequestV1, StreamTokenGatewayQuotaRequestV1,
};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    reputation::{
        StreamTokenExcludedKindV1, StreamTokenRequestContextErrorV1, StreamTokenRequestRouteV1,
        StreamTokenValidationRequestContextV1, StreamTokenValidationStatusV1,
        StreamTokenViolationKindV1,
    },
};
use rand::{rand_core::TryCryptoRng, rngs::OsRng};
use sorafs_manifest::{StreamTokenBodyV1, token::STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1};
/// An immutable lifetime bound derived from the authenticated accepted record.
#[derive(Clone, Copy, Debug)]
pub(super) struct RangeFetchLeaseWindow {
    /// The exact time bound into the returned external admission record.
    pub(super) validated_at_unix_ms: u64,
    /// The exclusive authenticated token/lease expiry.
    pub(super) expires_at_unix_ms: u64,
    /// A conservative bound retained from before the admission worker's wall-clock sample.
    pub(super) monotonic_deadline: std::time::Instant,
}
impl RangeFetchLeaseWindow {
    fn from_record(
        record: &StreamTokenGatewayAdmissionRecordV1,
        monotonic_anchor: std::time::Instant,
    ) -> Result<Self, Response> {
        let validated_at_unix_ms = record.outcome.validated_at_unix_ms;
        let expires_at_unix_ms = record.lease_expires_at_unix_ms.ok_or_else(|| {
            external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
        })?;
        let duration = expires_at_unix_ms
            .checked_sub(validated_at_unix_ms)
            .filter(|duration| *duration != 0)
            .ok_or_else(|| {
                external_admission_unavailable(
                    StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome,
                )
            })?;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_millis()).ok())
            .filter(|now| *now >= validated_at_unix_ms && *now < expires_at_unix_ms)
            .ok_or_else(|| {
                external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable)
            })?;
        let monotonic_deadline = monotonic_anchor
            .checked_add(std::time::Duration::from_millis(duration))
            .filter(|deadline| *deadline > std::time::Instant::now())
            .ok_or_else(|| {
                external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable)
            })?;
        Ok(Self {
            validated_at_unix_ms,
            expires_at_unix_ms,
            monotonic_deadline,
        })
    }
}
#[derive(Debug)]
pub(super) struct RangeFetchConcurrencyGuard {
    telemetry: MaybeTelemetry,
    external_lease: Option<ExternalStreamTokenLeaseV1>,
    lease_window: Option<RangeFetchLeaseWindow>,
    #[cfg(test)]
    local_permit: Option<StreamTokenConcurrencyPermit>,
}
impl RangeFetchConcurrencyGuard {
    fn external(
        telemetry: MaybeTelemetry,
        lease: ExternalStreamTokenLeaseV1,
        window: RangeFetchLeaseWindow,
    ) -> Self {
        let guard = Self {
            telemetry,
            external_lease: Some(lease),
            lease_window: Some(window),
            #[cfg(test)]
            local_permit: None,
        };
        guard.telemetry.with_metrics(|metrics| {
            metrics.inc_sorafs_range_fetch_concurrency();
        });
        guard
    }
    #[cfg(test)]
    fn local(telemetry: MaybeTelemetry, permit: Option<StreamTokenConcurrencyPermit>) -> Self {
        if permit.is_some() {
            telemetry.with_metrics(|metrics| {
                metrics.inc_sorafs_range_fetch_concurrency();
            });
        }
        Self {
            telemetry,
            external_lease: None,
            lease_window: None,
            local_permit: permit,
        }
    }
    /// Return the fixed authenticated lease window; only the test-local path has no window.
    pub(super) fn lease_window(&self) -> Option<RangeFetchLeaseWindow> {
        self.lease_window
    }
    #[cfg(test)]
    pub(super) fn has_permit(&self) -> bool {
        self.external_lease.is_some() || self.local_permit.is_some()
    }
}
impl Drop for RangeFetchConcurrencyGuard {
    fn drop(&mut self) {
        if self.external_lease.is_some() || {
            #[cfg(test)]
            {
                self.local_permit.is_some()
            }
            #[cfg(not(test))]
            {
                false
            }
        } {
            self.telemetry.with_metrics(|metrics| {
                metrics.dec_sorafs_range_fetch_concurrency();
            });
        }
    }
}
#[derive(Clone, Copy)]
struct DecodedAdmissionMaterial<'a> {
    body: &'a StreamTokenBodyV1,
    body_digest: [u8; 32],
}
fn external_admission_unavailable(error: StreamTokenGatewayAdmissionErrorV1) -> Response {
    error!(?error, "stream-token external admission failed closed");
    let mut response = json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "stream token admission is temporarily unavailable",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}
fn requested_bytes(route: StreamTokenRequestRouteV1) -> u64 {
    match route {
        StreamTokenRequestRouteV1::CarRange(range) => range
            .byte_length()
            .expect("a canonical CAR route has a representable byte length"),
        StreamTokenRequestRouteV1::Chunk(chunk) => chunk.stored_length,
    }
}
fn new_serving_attempt_id() -> Result<[u8; 32], StreamTokenGatewayAdmissionErrorV1> {
    serving_attempt_id_with_rng(&mut OsRng)
}
fn serving_attempt_id_with_rng<R: TryCryptoRng>(
    rng: &mut R,
) -> Result<[u8; 32], StreamTokenGatewayAdmissionErrorV1> {
    let mut id = [0; 32];
    rng.try_fill_bytes(&mut id)
        .map_err(|_| StreamTokenGatewayAdmissionErrorV1::Unavailable)?;
    if id == [0; 32] {
        return Err(StreamTokenGatewayAdmissionErrorV1::Unavailable);
    }
    Ok(id)
}
fn capture_terminal(
    state: &SharedAppState,
    deadline: Option<std::time::Instant>,
    serving_attempt_id: [u8; 32],
    context: &StreamTokenValidationRequestContextV1,
    validated_at_unix_ms: u64,
    status: StreamTokenValidationStatusV1,
    material: Option<DecodedAdmissionMaterial<'_>>,
) -> Result<
    Option<(
        StreamTokenGatewayAdmissionRecordV1,
        Option<ExternalStreamTokenLeaseV1>,
    )>,
    Response,
> {
    let Some(capture) = state.stream_token_admission_capture() else {
        #[cfg(test)]
        return Ok(None);
        #[cfg(not(test))]
        return Err(external_admission_unavailable(
            StreamTokenGatewayAdmissionErrorV1::Unavailable,
        ));
    };
    let quota = material.map(|material| StreamTokenGatewayQuotaRequestV1 {
        token_id: material.body.token_id.clone(),
        max_streams: material.body.max_streams,
        requests_per_minute: material.body.requests_per_minute,
        rate_limit_bytes: material.body.rate_limit_bytes,
        requested_bytes: requested_bytes(context.route()),
        expires_at_epoch: material.body.ttl_epoch,
        observed_at_epoch: validated_at_unix_ms / 1_000,
    });
    let request = StreamTokenGatewayAdmissionRequestV1 {
        serving_attempt_id,
        context: context.clone(),
        token_body_digest: material.map(|material| material.body_digest),
        token_key_version: material.map(|material| material.body.token_pk_version),
        validated_at_unix_ms,
        status,
        quota,
    };
    let ticket = if status == StreamTokenValidationStatusV1::Accepted {
        let cleanup = state.stream_token_cleanup.as_ref().ok_or_else(|| {
            external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable)
        })?;
        Some(cleanup.try_reserve().map_err(|_| {
            external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable)
        })?)
    } else {
        None
    };
    let deadline = deadline.ok_or_else(|| {
        external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable)
    })?;
    let record = capture
        .admit(&request, deadline)
        .map_err(external_admission_unavailable)?;
    // Capture can commit then fail callback/acknowledgement without returning a record. That
    // path retains its durable reconciliation/expiry semantics; no release is fabricated here.
    let lease = if record.outcome.status == StreamTokenValidationStatusV1::Accepted {
        ticket.map(|ticket| ticket.arm(capture, record))
    } else {
        None // The unused ticket is released for every external quota terminal.
    };
    Ok(Some((record, lease)))
}
fn capture_then_reject(
    state: &SharedAppState,
    deadline: Option<std::time::Instant>,
    serving_attempt_id: [u8; 32],
    context: &StreamTokenValidationRequestContextV1,
    validated_at_unix_ms: u64,
    (status, response): (StreamTokenValidationStatusV1, Response),
    material: Option<DecodedAdmissionMaterial<'_>>,
) -> Result<(RangeFetchConcurrencyGuard, StreamTokenBodyV1), Response> {
    let _ = capture_terminal(
        state,
        deadline,
        serving_attempt_id,
        context,
        validated_at_unix_ms,
        status,
        material,
    )?;
    Err(response)
}
fn retry_response(
    status: StreamTokenValidationStatusV1,
    retry_after_secs: Option<u32>,
) -> Response {
    let message = match status {
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::RequestQuotaExceeded,
        ) => "stream token request quota exceeded",
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::ByteRateLimitExceeded,
        ) => "stream token rate limit exceeded",
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::ConcurrencyLimitExceeded,
        ) => "stream token max_streams exceeded",
        _ => unreachable!("retry response is only built for quota terminals"),
    };
    let mut response = json_error(StatusCode::TOO_MANY_REQUESTS, message);
    if let Some(retry_after_secs) = retry_after_secs
        && let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}
fn response_for_external_terminal(
    telemetry: &MaybeTelemetry,
    record: &StreamTokenGatewayAdmissionRecordV1,
) -> Option<Response> {
    let status = record.outcome.status;
    let response = match status {
        StreamTokenValidationStatusV1::Accepted => return None,
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::ConcurrencyLimitExceeded
            | StreamTokenViolationKindV1::RequestQuotaExceeded
            | StreamTokenViolationKindV1::ByteRateLimitExceeded,
        ) => {
            let reason = match status {
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ConcurrencyLimitExceeded,
                ) => RANGE_THROTTLE_REASON_CONCURRENCY,
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::RequestQuotaExceeded,
                ) => RANGE_THROTTLE_REASON_QUOTA,
                _ => RANGE_THROTTLE_REASON_BYTE_RATE,
            };
            telemetry.with_metrics(|metrics| metrics.inc_sorafs_range_fetch_throttle(reason));
            retry_response(status, record.retry_after_secs)
        }
        StreamTokenValidationStatusV1::ProviderViolation(StreamTokenViolationKindV1::Expired) => {
            json_error(StatusCode::UNAUTHORIZED, "stream token has expired")
        }
        StreamTokenValidationStatusV1::ProviderViolation(
            StreamTokenViolationKindV1::IdentifierPolicyConflict,
        ) => json_error(
            StatusCode::UNAUTHORIZED,
            "stream token identifier conflicts with existing signed state",
        ),
        _ => external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome),
    };
    Some(response)
}
fn context_error_response(error: StreamTokenRequestContextErrorV1) -> Response {
    if matches!(error, StreamTokenRequestContextErrorV1::InvalidRequestNonce) {
        json_error(
            StatusCode::BAD_REQUEST,
            "X-SoraFS-Nonce header must contain canonical visible ASCII",
        )
    } else {
        error!(
            ?error,
            "failed to construct canonical stream-token request context"
        );
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to validate stream token",
        )
    }
}
pub(super) async fn enforce_stream_token_for_request(
    state: &SharedAppState,
    headers: &HeaderMap,
    manifest: &StoredManifest,
    request_nonce: &str,
    route: StreamTokenRequestRouteV1,
) -> Result<(RangeFetchConcurrencyGuard, StreamTokenBodyV1), Response> {
    // Queue latency belongs to the same admission attempt as verification and callback work.
    let deadline = state
        .stream_token_admission_capture()
        .map(|capture| capture.begin_operation())
        .transpose()
        .map_err(external_admission_unavailable)?;
    let worker_state = Arc::clone(state);
    let headers = headers.clone();
    let manifest = manifest.clone();
    let request_nonce = request_nonce.to_owned();
    sorafs_heavy_blocking_task(state, "SoraFS stream-token admission", move || {
        enforce_stream_token_in_worker(
            &worker_state,
            &headers,
            &manifest,
            &request_nonce,
            route,
            deadline,
        )
    })
    .await
}
// Queue time and local validation consume the same admission budget. Check before invoking
// the signer observer as well as at worker entry; only explicit test-local enforcement has no
// native gateway deadline.
#[allow(clippy::result_large_err)]
fn ensure_admission_operation_live(deadline: Option<std::time::Instant>) -> Result<(), Response> {
    match deadline {
        Some(deadline) if std::time::Instant::now() < deadline => Ok(()),
        #[cfg(test)]
        None => Ok(()),
        _ => Err(external_admission_unavailable(
            StreamTokenGatewayAdmissionErrorV1::Unavailable,
        )),
    }
}
#[allow(clippy::result_large_err)]
fn enforce_stream_token_in_worker(
    state: &SharedAppState,
    headers: &HeaderMap,
    manifest: &StoredManifest,
    request_nonce: &str,
    route: StreamTokenRequestRouteV1,
    deadline: Option<std::time::Instant>,
) -> Result<(RangeFetchConcurrencyGuard, StreamTokenBodyV1), Response> {
    ensure_admission_operation_live(deadline)?;
    let Some(issuer) = state.stream_token_issuer() else {
        return Err(feature_disabled(
            "stream token enforcement is not enabled on this node",
        ));
    };
    let telemetry = state.telemetry.clone();
    let mut token_headers = headers.get_all(HEADER_SORA_STREAM_TOKEN).iter();
    let token_header = token_headers.next();
    if token_headers.next().is_some() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "X-SoraFS-Stream-Token header must occur exactly once",
        ));
    }
    let authoritative_provider =
        state
            .sorafs_node
            .capacity_usage()
            .provider_id
            .ok_or_else(|| {
                json_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "stream token provider identity is not configured",
                )
            })?;
    // One physical HTTP worker owns this identity; provider retries retain its complete request.
    let serving_attempt_id = new_serving_attempt_id().map_err(external_admission_unavailable)?;
    let monotonic_anchor = std::time::Instant::now();
    let validated_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                error!(
                    ?error,
                    "system clock before UNIX epoch while validating token"
                );
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to validate stream token",
                )
            })?
            .as_millis(),
    )
    .map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to validate stream token",
        )
    })?;
    let context = StreamTokenValidationRequestContextV1::try_new(
        ProviderId::new(authoritative_provider),
        *manifest.manifest_digest(),
        manifest.manifest_cid().to_vec(),
        manifest.chunk_profile_handle().to_owned(),
        request_nonce,
        token_header.map(HeaderValue::as_bytes),
        route,
    )
    .map_err(context_error_response)?;
    let Some(token_header) = token_header else {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::Excluded(StreamTokenExcludedKindV1::MissingToken),
                json_error(
                    StatusCode::UNAUTHORIZED,
                    "missing X-SoraFS-Stream-Token header",
                ),
            ),
            None,
        );
    };
    let token_str = match token_header.to_str() {
        Ok(token) => token,
        Err(_) => {
            return capture_then_reject(
                state,
                deadline,
                serving_attempt_id,
                &context,
                validated_at_unix_ms,
                (
                    StreamTokenValidationStatusV1::Excluded(
                        StreamTokenExcludedKindV1::MalformedEncoding,
                    ),
                    json_error(
                        StatusCode::BAD_REQUEST,
                        "X-SoraFS-Stream-Token header must contain valid ASCII",
                    ),
                ),
                None,
            );
        }
    };
    if token_str.is_empty() {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::Excluded(
                    StreamTokenExcludedKindV1::MalformedEncoding,
                ),
                json_error(
                    StatusCode::BAD_REQUEST,
                    "X-SoraFS-Stream-Token header must not be empty",
                ),
            ),
            None,
        );
    }
    if token_str.len() > MAX_STREAM_TOKEN_BASE64_BYTES {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::Excluded(
                    StreamTokenExcludedKindV1::MalformedEncoding,
                ),
                json_error(
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "X-SoraFS-Stream-Token header exceeds the protocol limit",
                ),
            ),
            None,
        );
    }
    let token = match decode_token_base64(token_str) {
        Ok(token) => token,
        Err(error) => {
            let response = match error {
                StreamTokenHeaderError::InvalidEncoding => json_error(
                    StatusCode::BAD_REQUEST,
                    "stream token must be base64 encoded",
                ),
                StreamTokenHeaderError::HeaderTooLong { .. } => json_error(
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "stream token header exceeds the protocol limit",
                ),
                StreamTokenHeaderError::NonCanonicalEncoding => json_error(
                    StatusCode::BAD_REQUEST,
                    "stream token must use canonical padded base64",
                ),
                StreamTokenHeaderError::PayloadTooLong { .. } => json_error(
                    StatusCode::BAD_REQUEST,
                    "decoded stream token exceeds the protocol limit",
                ),
                StreamTokenHeaderError::InvalidPayload(_) => {
                    json_error(StatusCode::BAD_REQUEST, "invalid stream token payload")
                }
                StreamTokenHeaderError::InvalidBody(_)
                | StreamTokenHeaderError::InvalidSignatureLength => {
                    json_error(StatusCode::BAD_REQUEST, "invalid stream token policy")
                }
            };
            return capture_then_reject(
                state,
                deadline,
                serving_attempt_id,
                &context,
                validated_at_unix_ms,
                (
                    StreamTokenValidationStatusV1::Excluded(
                        StreamTokenExcludedKindV1::MalformedEncoding,
                    ),
                    response,
                ),
                None,
            );
        }
    };
    let body_digest = *token
        .body_hash()
        .map_err(|error| {
            error!(?error, "failed to hash validated stream token body");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate stream token",
            )
        })?
        .as_bytes();
    let material = Some(DecodedAdmissionMaterial {
        body: &token.body,
        body_digest,
    });
    if let Err(error) = token.verify(issuer.verifying_key()) {
        error!(?error, "stream token signature verification failed");
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::Excluded(
                    StreamTokenExcludedKindV1::InvalidSignature,
                ),
                json_error(StatusCode::UNAUTHORIZED, "stream token signature invalid"),
            ),
            material,
        );
    }
    if token.body.token_pk_version != issuer.key_version() {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::Excluded(
                    StreamTokenExcludedKindV1::UnsupportedKeyVersion,
                ),
                json_error(
                    StatusCode::UNAUTHORIZED,
                    "stream token signed with unexpected key version",
                ),
            ),
            material,
        );
    }
    let now = validated_at_unix_ms / 1_000;
    if token.body.issued_at > now.saturating_add(STREAM_TOKEN_MAX_FUTURE_SKEW_SECS_V1) {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::FutureIssuedAt,
                ),
                json_error(
                    StatusCode::UNAUTHORIZED,
                    "stream token was issued too far in the future",
                ),
            ),
            material,
        );
    }
    if token.body.manifest_cid.as_slice() != manifest.manifest_cid() {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ManifestMismatch,
                ),
                json_error(
                    StatusCode::FORBIDDEN,
                    "stream token does not authorise this manifest",
                ),
            ),
            material,
        );
    }
    if token.body.profile_handle != manifest.chunk_profile_handle() {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ProfileMismatch,
                ),
                json_error(StatusCode::CONFLICT, "stream token chunker handle mismatch"),
            ),
            material,
        );
    }
    if token.body.provider_id != authoritative_provider {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ProviderMismatch,
                ),
                json_error(StatusCode::FORBIDDEN, "stream token provider mismatch"),
            ),
            material,
        );
    }
    if now >= token.body.ttl_epoch {
        return capture_then_reject(
            state,
            deadline,
            serving_attempt_id,
            &context,
            validated_at_unix_ms,
            (
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::Expired,
                ),
                json_error(StatusCode::UNAUTHORIZED, "stream token has expired"),
            ),
            material,
        );
    }
    // Each new admission has its own challenged current-custody observation. The driver resamples
    // trusted time after observer I/O and local finality, including token issue/expiry checks.
    ensure_admission_operation_live(deadline)?;
    let validated_at_unix_ms = match issuer.before_admission(&token.body) {
        Ok(validated_at) => validated_at,
        Err(error) => {
            error!(
                ?error,
                "stream token signer authority failed closed before admission"
            );
            return capture_then_reject(
                state,
                deadline,
                serving_attempt_id,
                &context,
                validated_at_unix_ms,
                (
                    StreamTokenValidationStatusV1::Excluded(
                        StreamTokenExcludedKindV1::SignerAuthorityUnavailable,
                    ),
                    external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::Unavailable),
                ),
                material,
            );
        }
    };
    if let Some((record, lease)) = capture_terminal(
        state,
        deadline,
        serving_attempt_id,
        &context,
        validated_at_unix_ms,
        StreamTokenValidationStatusV1::Accepted,
        material,
    )? {
        if let Some(response) = response_for_external_terminal(&telemetry, &record) {
            return Err(response);
        }
        let lease = lease.ok_or_else(|| {
            external_admission_unavailable(StreamTokenGatewayAdmissionErrorV1::SubstitutedOutcome)
        })?;
        // Lease ownership is already armed: every checked-window failure queues release.
        let window = RangeFetchLeaseWindow::from_record(&record, monotonic_anchor)?;
        return Ok((
            RangeFetchConcurrencyGuard::external(telemetry, lease, window),
            token.body,
        ));
    }
    #[cfg(test)]
    return enforce_test_local_admission(
        state,
        telemetry,
        token,
        route,
        validated_at_unix_ms / 1_000,
    );
    #[cfg(not(test))]
    Err(external_admission_unavailable(
        StreamTokenGatewayAdmissionErrorV1::Unavailable,
    ))
}
#[cfg(test)]
fn enforce_test_local_admission(
    state: &SharedAppState,
    telemetry: MaybeTelemetry,
    token: StreamTokenV1,
    route: StreamTokenRequestRouteV1,
    now: u64,
) -> Result<(RangeFetchConcurrencyGuard, StreamTokenBodyV1), Response> {
    let permit = state
        .stream_token_concurrency()
        .try_acquire(&token.body.token_id, token.body.max_streams)
        .map_err(|_| {
            telemetry.with_metrics(|metrics| {
                metrics.inc_sorafs_range_fetch_throttle(RANGE_THROTTLE_REASON_CONCURRENCY)
            });
            json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "stream token max_streams exceeded",
            )
        })?;
    let guard = RangeFetchConcurrencyGuard::local(telemetry.clone(), permit);
    let token_fingerprint = *token
        .body_hash()
        .map_err(|error| {
            error!(?error, "failed to hash validated stream token body");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate stream token",
            )
        })?
        .as_bytes();
    match state.stream_token_quota().try_acquire(
        &token.body.token_id,
        token_fingerprint,
        token.body.requests_per_minute,
        token.body.rate_limit_bytes,
        requested_bytes(route),
        token.body.ttl_epoch,
        now,
    ) {
        Ok(()) => Ok((guard, token.body)),
        Err(StreamTokenQuotaError::Exceeded { retry_after_secs }) => {
            telemetry.with_metrics(|metrics| {
                metrics.inc_sorafs_range_fetch_throttle(RANGE_THROTTLE_REASON_QUOTA)
            });
            Err(retry_response(
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::RequestQuotaExceeded,
                ),
                Some(retry_after_secs),
            ))
        }
        Err(StreamTokenQuotaError::ByteRateExceeded { retry_after_secs }) => {
            telemetry.with_metrics(|metrics| {
                metrics.inc_sorafs_range_fetch_throttle(RANGE_THROTTLE_REASON_BYTE_RATE)
            });
            Err(retry_response(
                StreamTokenValidationStatusV1::ProviderViolation(
                    StreamTokenViolationKindV1::ByteRateLimitExceeded,
                ),
                Some(retry_after_secs),
            ))
        }
        Err(
            error @ (StreamTokenQuotaError::CapacityExceeded { .. }
            | StreamTokenQuotaError::StateUnavailable
            | StreamTokenQuotaError::ClockRollback { .. }),
        ) => {
            error!(?error, "stream token quota state unavailable");
            Err(external_admission_unavailable(
                StreamTokenGatewayAdmissionErrorV1::Unavailable,
            ))
        }
        Err(StreamTokenQuotaError::PolicyConflict) => Err(json_error(
            StatusCode::UNAUTHORIZED,
            "stream token identifier conflicts with existing signed state",
        )),
        Err(StreamTokenQuotaError::Expired) => Err(json_error(
            StatusCode::UNAUTHORIZED,
            "stream token has expired",
        )),
        Err(StreamTokenQuotaError::InvalidTokenId | StreamTokenQuotaError::InvalidPolicy(_)) => {
            Err(json_error(
                StatusCode::BAD_REQUEST,
                "invalid stream token quota policy",
            ))
        }
    }
}

#[cfg(test)]
#[path = "stream_token_lease_window_tests.rs"]
mod lease_window_tests;

#[cfg(test)]
#[path = "stream_token_attempt_tests.rs"]
mod attempt_tests;
