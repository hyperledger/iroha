//! Signed-body, scoped original publication for an existing native full-ledger reader.
//!
//! This route publishes data under current permission, never a permission grant or
//! finality/ownership fact. Every private original is borrowed from one qualified
//! native pre-tail cut and output keeps the aggregate finite pool through egress.

use super::*;
use crate::native_projection_response::{capacity, encode, native_committee_original_bytes};
use iroha_core::{
    state::AllocationBudget,
    sumeragi::certified_chain::{CertifiedChain, QcVerification},
};
use iroha_torii_shared::authority_originals::{
    NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1, NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1,
    NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1, NativeAccountAliasOriginalRefV1,
    NativeAccountAliasStateRefV1, NativeAuthorityOriginalsFamilyRefV1,
    NativeAuthorityOriginalsRefV1, NativeAuthorityOriginalsRequestV1,
    NativeAuthorityOriginalsSelectorV1, NativeGlobalFeeProgramStateRefV1,
    NativeIdentifierPolicyStateRefV1, decode_native_authority_originals_request_v1,
    native_authority_originals_request_digests_v1,
};

// Payload fields physically drop before their prepaid intake reservation. The
// decoded request remains owned by this object while a worker borrows its selector.
struct RequestOriginalOwner {
    request: NativeAuthorityOriginalsRequestV1,
    _body: Bytes,
    _charge: iroha_allocation::AllocationReservation,
}

/// Canonical POST authentication covers the actual body; API-token alone is insufficient.
pub(super) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    request: axum::http::Request<Body>,
) -> Result<AxResponse, Error> {
    Ok(finalize(handle(app, remote, request).await))
}

fn finalize(result: Result<AxResponse, Error>) -> AxResponse {
    let mut response = finalize_bridge_finality_attestation_response(result);
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "native_authority_originals_unavailable",
        message: "Current certified native authority originals are unavailable.".into(),
    }
}

fn target(method: &Method, uri: &Uri, headers: &HeaderMap) -> Result<(), Error> {
    if method != &Method::POST
        || uri.path() != NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1
        || uri.query().is_some()
    {
        return Err(conversion_error(
            "authority originals require the exact signed canonical POST target".into(),
        ));
    }
    let mut content_types = headers.get_all(axum::http::header::CONTENT_TYPE).iter();
    if content_types
        .next()
        .is_none_or(|value| value != utils::NORITO_MIME_TYPE)
        || content_types.next().is_some()
    {
        return Err(conversion_error(
            "authority originals require one canonical Norito Content-Type".into(),
        ));
    }
    validate_bounded_content_length(headers, NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1)
        .map_err(|_| {
            conversion_error(
                "authority originals request body length is invalid or exceeds its bound".into(),
            )
        })?;
    Ok(())
}

fn authenticate_body(
    app: &SharedAppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<AccountId, Error> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(&app) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error);
            }
        };

    let verified = crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        method,
        uri,
        body,
        None,
        authentication_owner.allocation_context(),
    )?
    .ok_or_else(|| Error::AppUnauthorized {
        code: "canonical_authentication_required",
        message: "canonical signed-body account authentication is required for authority originals"
            .into(),
    })?;
    require_full_ledger_carrier_permission(app, &verified.account)?;
    Ok(verified.account)
}

fn request_original(
    body: &[u8],
    network: &iroha_data_model::NetworkId,
    headers: &HeaderMap,
) -> Result<(NativeAuthorityOriginalsRequestV1, [u8; 32], [u8; 32]), Error> {
    let request = decode_native_authority_originals_request_v1(body).map_err(|_| {
        conversion_error("authority originals request is not bounded canonical native wire".into())
    })?;
    if &request.network_id != network {
        return Err(conversion_error(
            "authority originals request belongs to another network".into(),
        ));
    }
    let (digest, challenge) = native_authority_originals_request_digests_v1(body)
        .map_err(|_| conversion_error("authority originals request preimage is invalid".into()))?;
    if headers.contains_key(BRIDGE_FINALITY_CHALLENGE_HEADER)
        && bridge_finality_challenge(headers)? != challenge
    {
        return Err(conversion_error(
            "authority originals header challenge differs from the exact signed body".into(),
        ));
    }
    Ok((request, digest, challenge))
}

async fn handle(
    app: SharedAppState,
    remote: std::net::SocketAddr,
    request: axum::http::Request<Body>,
) -> Result<AxResponse, Error> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    target(&parts.method, &parts.uri, &headers)?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(
        &headers,
        Some(remote.ip()),
        NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1,
        principal,
    );
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    // Acquire original aggregate capacity before receiving/decoding the private
    // request. The pre-admitted bound covers bounded body collection, canonical
    // decode backing and validation's transient native re-encoding; none escapes.
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([u64::try_from(bytes).map_err(|_| capacity())?])
        .ok_or_else(capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let intake_bytes = NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1
        .checked_mul(8)
        .ok_or_else(capacity)?;
    let intake_charge = budget
        .try_reserve_bytes(intake_bytes)
        .map_err(|_| capacity())?;
    // The native authenticated account and its capture copy survive the worker
    // intake owner. Retain their finite original backing through both egress fences.
    let _principal_charge = budget
        .try_reserve_bytes(
            crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1
                .checked_mul(8)
                .ok_or_else(capacity)?,
        )
        .map_err(|_| capacity())?;
    let body = axum::body::to_bytes(body, NATIVE_AUTHORITY_ORIGINALS_REQUEST_MAX_BYTES_V1)
        .await
        .map_err(|_| {
            conversion_error("authority originals request body exceeds its finite bound".into())
        })?;
    let account = authenticate_body(&app, &headers, &parts.method, &parts.uri, body.as_ref())?;
    let (request, digest, challenge) =
        request_original(body.as_ref(), app.state.network_id_ref(), &headers)?;
    let intake = RequestOriginalOwner {
        request,
        _body: body,
        _charge: intake_charge,
    };
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    // Admission awaited: recheck a live grant before queuing any private cut work.
    require_full_ledger_carrier_permission(&app, &account)?;
    let driver = app.sumeragi.as_ref().ok_or_else(unavailable)?;
    if driver.restart_required() {
        return Err(unavailable());
    }
    let status = driver.status_dto().ok_or_else(unavailable)?;
    if status.unanchored || status.abstaining || status.halted.is_some() {
        return Err(unavailable());
    }
    let identity = driver.identity().clone();
    if status.signer.as_ref() != Some(identity.node_id.public_key()) {
        return Err(unavailable());
    }
    let fingerprint = iroha_crypto::Hash::new_from_chunks(&[
        app.build_status.version.as_bytes(),
        app.build_status.git_commit_sha.as_bytes(),
    ]);
    let state = app.state.clone();
    let signer = app.torii_proxy_bridge_signer.clone();
    let capture_authority = account.clone();
    let max_response = app
        .torii_proxy_max_response_bytes
        .min(NATIVE_AUTHORITY_ORIGINALS_MAX_BYTES_V1);
    let response = routing::run_admitted_blocking(
        admission,
        "native authority originals worker failed",
        move || {
            let _memory = memory;
            let intake = intake;
            let view = state.view();
            let height = u64::try_from(view.height()).map_err(|_| unavailable())?;
            if height < 2 {
                return Err(unavailable());
            }
            let chain = CertifiedChain::new(&view).map_err(|_| unavailable())?;
            let certified = chain.certified(height).map_err(|_| unavailable())?;
            if certified.verification() != QcVerification::Verified {
                return Err(unavailable());
            }
            let tip = certified.into_committed();
            let genesis = chain.committed(1).map_err(|_| unavailable())?;
            let genesis_bytes =
                norito::canonical_frame_len(genesis.block().as_ref()).map_err(|_| unavailable())?;
            let tip_bytes =
                norito::canonical_frame_len(tip.block().as_ref()).map_err(|_| unavailable())?;
            let genesis_committee = &genesis.commitment().schedule.current.committee;
            let tip_committee = &tip.commitment().schedule.current.committee;
            let genesis_storage = native_committee_original_bytes(
                genesis_committee.len(),
                genesis_committee.iter().map(|member| {
                    (
                        member.validator.public_key(),
                        member.proof_of_possession.as_slice(),
                    )
                }),
            )?;
            let tip_storage = native_committee_original_bytes(
                tip_committee.len(),
                tip_committee.iter().map(|member| {
                    (
                        member.validator.public_key(),
                        member.proof_of_possession.as_slice(),
                    )
                }),
            )?;
            let proof_bytes = genesis_bytes
                .checked_add(tip_bytes)
                .and_then(|value| value.checked_add(genesis_storage))
                .and_then(|value| value.checked_add(tip_storage))
                .and_then(|value| value.checked_add(16 * 1024))
                .ok_or_else(capacity)?;
            let _proof_charge = budget
                .try_reserve_bytes(proof_bytes)
                .map_err(|_| capacity())?;
            let attestation = iroha_core::sumeragi::finality::build_attestation(
                &view,
                status,
                &identity,
                fingerprint,
                height,
                challenge,
                &signer,
            )
            .map_err(|_| unavailable())?;
            drop(chain);
            drop(view);
            let mut encoded = match &intake.request.selector {
                NativeAuthorityOriginalsSelectorV1::AccountAlias(name) => state
                    .with_native_account_alias_originals_v1(
                        &tip,
                        &capture_authority,
                        name,
                        &budget,
                        |snapshot, alias, keys, selected| {
                            let selected = selected.map(|(bound, rekey, account, lease)| {
                                NativeAccountAliasOriginalRefV1::new(bound, rekey, account, lease)
                            });
                            let family = NativeAuthorityOriginalsFamilyRefV1::AccountAlias(
                                NativeAccountAliasStateRefV1::new(alias, keys, selected),
                            );
                            let payload = NativeAuthorityOriginalsRefV1::new(
                                &digest,
                                &intake.request.selector,
                                &attestation,
                                snapshot,
                                family,
                            );
                            encode(&payload, format, max_response, &budget, unavailable).map_err(
                                |_| "native authority account serialization refused".to_owned(),
                            )
                        },
                    )
                    .map_err(|_| unavailable())?,
                NativeAuthorityOriginalsSelectorV1::GlobalFeeProgram {
                    program_id,
                    fee_asset,
                } => state
                    .with_native_global_fee_originals_v1(
                        &tip,
                        &capture_authority,
                        program_id,
                        fee_asset,
                        &budget,
                        |snapshot,
                         assets,
                         programs,
                         revisions,
                         enrollments,
                         vaults,
                         counters,
                         account,
                         definition,
                         source,
                         program,
                         revision_values,
                         enrollment_values,
                         vault_values| {
                            let family = NativeAuthorityOriginalsFamilyRefV1::GlobalFeeProgram(
                                NativeGlobalFeeProgramStateRefV1::new(
                                    program_id,
                                    fee_asset,
                                    assets,
                                    programs,
                                    revisions,
                                    enrollments,
                                    vaults,
                                    counters,
                                    account,
                                    definition,
                                    source,
                                    program,
                                    revision_values,
                                    enrollment_values,
                                    vault_values,
                                ),
                            );
                            let payload = NativeAuthorityOriginalsRefV1::new(
                                &digest,
                                &intake.request.selector,
                                &attestation,
                                snapshot,
                                family,
                            );
                            encode(&payload, format, max_response, &budget, unavailable).map_err(
                                |_| "native authority fee serialization refused".to_owned(),
                            )
                        },
                    )
                    .map_err(|_| unavailable())?,
                NativeAuthorityOriginalsSelectorV1::IdentifierPolicy(policy_id) => state
                    .with_native_identifier_policy_originals_v1(
                        &tip,
                        &capture_authority,
                        policy_id,
                        &budget,
                        |snapshot, policy, program| {
                            let family = NativeAuthorityOriginalsFamilyRefV1::IdentifierPolicy(
                                NativeIdentifierPolicyStateRefV1::new(policy, program),
                            );
                            let payload = NativeAuthorityOriginalsRefV1::new(
                                &digest,
                                &intake.request.selector,
                                &attestation,
                                snapshot,
                                family,
                            );
                            encode(&payload, format, max_response, &budget, unavailable).map_err(
                                |_| "native authority identifier serialization refused".to_owned(),
                            )
                        },
                    )
                    .map_err(|_| unavailable())?,
            };
            encoded.memory = Some(_memory);
            let mut response = AxResponse::new(Body::from(Bytes::from_owner(encoded)));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(match format {
                    ResponseFormat::Norito => utils::NORITO_MIME_TYPE,
                    ResponseFormat::Json => "application/json",
                }),
            );
            Ok(response)
        },
    )
    .await?;
    require_full_ledger_carrier_permission(&app, &account)?;
    let response = proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        NATIVE_AUTHORITY_ORIGINALS_ROUTE_V1,
        response,
        true,
    )
    .await?;
    require_full_ledger_carrier_permission(&app, &account)?;
    Ok(response)
}

#[cfg(test)]
#[path = "authority_originals/tests.rs"]
mod tests;
