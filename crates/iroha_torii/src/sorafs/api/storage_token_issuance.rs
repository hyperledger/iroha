// Token issuance request validation, bounded worker dispatch and response rendering.

#[cfg(feature = "app_api")]
fn required_canonical_stream_header(
    headers: &HeaderMap,
    name: &'static str,
    display_name: &'static str,
    maximum_bytes: usize,
) -> Result<String, Response> {
    let value = match single_header_value(headers, name) {
        Ok(Some(value)) => value,
        Ok(None) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                format!("missing {display_name} header"),
            ));
        }
        Err(()) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                format!("{display_name} header must occur exactly once"),
            ));
        }
    }
    .to_str()
    .map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("{display_name} header must contain valid ASCII"),
        )
    })?;
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("{display_name} header must contain 1-{maximum_bytes} visible ASCII bytes"),
        ));
    }
    Ok(value.to_owned())
}
#[cfg(feature = "app_api")]
fn is_canonical_lower_hex(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
#[cfg(feature = "app_api")]
fn authenticated_stream_token_quota_subject(
    authenticated_operator: Option<
        Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
    >,
) -> Result<StreamTokenQuotaSubject, Response> {
    let Some(Extension(authenticated_operator)) = authenticated_operator else {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "stream token issuance requires an exact-network operator signature",
        ));
    };
    Ok(StreamTokenQuotaSubject::from_authenticated_operator(
        &authenticated_operator.0,
    ))
}
#[cfg(feature = "app_api")]
pub(crate) async fn handle_post_sorafs_storage_token_authenticated(
    authenticated_operator: Option<
        Extension<crate::operator_signatures::AuthenticatedOperatorPublicKey>,
    >,
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    JsonOnly(req): JsonOnly<StreamTokenRequestDto>,
) -> Response {
    let quota_subject = match authenticated_stream_token_quota_subject(authenticated_operator) {
        Ok(subject) => subject,
        Err(response) => return response,
    };
    issue_storage_token(state, headers, req, quota_subject, None).await
}

/// Canonical account route; middleware verifies the exact network/body and consumes its nonce once.
#[cfg(feature = "app_api")]
pub(crate) async fn handle_post_sorafs_storage_account_token(
    authenticated_account: Option<Extension<crate::app_auth::VerifiedCanonicalRequest>>,
    State(state): State<SharedAppState>,
    headers: HeaderMap,
    JsonOnly(req): JsonOnly<StreamTokenRequestDto>,
) -> Response {
    let Some(Extension(authenticated)) = authenticated_account else {
        return json_error(
            StatusCode::FORBIDDEN,
            "account stream token issuance requires a canonical network signature",
        );
    };
    let subject = StreamTokenQuotaSubject::from_authenticated_account(
        state.signed_query_admission.network_id(),
        &authenticated.account,
    );
    issue_storage_token(state, headers, req, subject, Some(authenticated.account)).await
}

#[cfg(feature = "app_api")]
fn current_account_read_policy(
    state: &iroha_core::state::State,
    account: &AccountId,
    provider: ProviderId,
) -> Result<sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1, Response> {
    use sorafs_manifest::provider_advert::account_read::RegisteredAccountReadV1;
    let denied = || {
        json_error(
            StatusCode::FORBIDDEN,
            "this provider has no active admitted account-read policy for this account",
        )
    };
    let view = state.view();
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(view.world())
        != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
        || view.world().accounts().get(account).is_none()
    {
        return Err(denied());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| denied())?
        .as_secs();
    let admitted = iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
        &view, provider, now,
    )
    .map_err(|_| denied())?
    .ok_or_else(denied)?;
    RegisteredAccountReadV1::from_capabilities(&admitted.envelope().proposal.capabilities)
        .map_err(|_| denied())?
        .ok_or_else(denied)
}

#[cfg(feature = "app_api")]
async fn issue_storage_token(
    state: SharedAppState,
    headers: HeaderMap,
    req: StreamTokenRequestDto,
    quota_subject: StreamTokenQuotaSubject,
    account: Option<AccountId>,
) -> Response {
    if !state.sorafs_node.is_enabled() {
        return storage_disabled_response();
    }
    let Some(issuer) = state.stream_token_issuer() else {
        return feature_disabled("stream token issuance is not enabled on this node");
    };
    let client_id = match required_canonical_stream_header(
        &headers,
        HEADER_SORA_CLIENT,
        "X-SoraFS-Client",
        MAX_CLIENT_ID_BYTES,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let nonce = match required_canonical_stream_header(
        &headers,
        HEADER_SORA_NONCE,
        "X-SoraFS-Nonce",
        MAX_NONCE_BYTES,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !is_canonical_lower_hex(&req.manifest_id_hex, 256) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "manifest_id_hex must be canonical lowercase hexadecimal and no more than 256 bytes",
        );
    }
    if !is_canonical_lower_hex(&req.provider_id_hex, 64) || req.provider_id_hex.len() != 64 {
        return json_error(
            StatusCode::BAD_REQUEST,
            "provider_id_hex must be exactly 64 lowercase hexadecimal characters",
        );
    }
    let storage_manifest_id = match resolve_manifest_storage_id(&state, &req.manifest_id_hex) {
        Ok(manifest_id) => manifest_id,
        Err(response) => return response,
    };
    let manifest = match state.sorafs_node.manifest_metadata(&storage_manifest_id) {
        Ok(manifest) => manifest,
        Err(err) => return node_storage_error_response(err),
    };
    let provider_id = match decode_hex_32(&req.provider_id_hex) {
        Ok(bytes) => bytes,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, message),
    };
    if provider_id.iter().all(|byte| *byte == 0) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "provider_id_hex must not be all zero",
        );
    }
    match state.sorafs_node.capacity_usage().provider_id {
        Some(local_provider_id) if local_provider_id == provider_id => {}
        Some(_) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "stream token provider does not match this gateway",
            );
        }
        None => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "stream token provider identity is not configured",
            );
        }
    }
    let overrides = TokenOverrides {
        ttl_secs: req.ttl_secs,
        max_streams: req.max_streams,
        rate_limit_bytes: req.rate_limit_bytes,
        requests_per_minute: req.requests_per_minute,
    };
    let manifest_cid = manifest.manifest_cid().to_vec();
    let profile_handle = manifest.chunk_profile_handle().to_string();
    let worker_issuer = Arc::clone(&issuer);
    let worker_state = state.state.clone();
    // The physical worker owns query and heavy-query admission until issuance finishes, even
    // if the HTTP request is cancelled. Custody checks and broker I/O must not run on an executor.
    let issuance_result =
        match sorafs_heavy_blocking_task(&state, "SoraFS token issuance", move || {
            let policy = account
                .as_ref()
                .map(|account| {
                    current_account_read_policy(
                        &worker_state,
                        account,
                        ProviderId::new(provider_id),
                    )
                })
                .transpose()?;
            let issuance_result = worker_issuer.issue_token(
                quota_subject,
                manifest_cid,
                provider_id,
                profile_handle,
                overrides,
                policy.as_ref(),
            );
            // Issuance can await external custody. Do not release a token after an intervening
            // finalized policy withdrawal, account deletion, expiry, or replacement.
            if let Some(account) = &account {
                if Some(current_account_read_policy(
                    &worker_state,
                    account,
                    ProviderId::new(provider_id),
                )?) != policy
                {
                    return Err(json_error(
                        StatusCode::FORBIDDEN,
                        "account-read policy changed during token issuance",
                    ));
                }
            }
            Ok(issuance_result)
        })
        .await
        {
            Ok(issuance_result) => issuance_result,
            Err(response) => return response,
        };
    let token_issue = match issuance_result {
        Ok(token) => token,
        Err(err) => {
            return match &err {
                StreamTokenIssuerError::IssuanceQuotaExceeded {
                    limit,
                    retry_after_secs,
                    ..
                } => {
                    let mut response = json_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        format!(
                            "stream token issuance quota exceeded (limit {limit} requests per minute)"
                        ),
                    );
                    let headers = response.headers_mut();
                    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                        headers.insert(header::RETRY_AFTER, value);
                    }
                    headers.insert(
                        header::HeaderName::from_static(HEADER_SORA_CLIENT),
                        header_value(&client_id, "X-SoraFS-Client"),
                    );
                    headers.insert(
                        header::HeaderName::from_static(HEADER_SORA_NONCE),
                        header_value(&nonce, "X-SoraFS-Nonce"),
                    );
                    headers.insert(
                        header::HeaderName::from_static(HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
                        header_value("0", "X-SoraFS-Issuance-Quota-Remaining"),
                    );
                    response
                }
                StreamTokenIssuerError::InvalidPolicy { .. }
                | StreamTokenIssuerError::InvalidBody(_) => {
                    json_error(StatusCode::BAD_REQUEST, err.to_string())
                }
                StreamTokenIssuerError::IssuanceQuotaCapacityExceeded { .. }
                | StreamTokenIssuerError::IssuanceQuotaStateUnavailable
                | StreamTokenIssuerError::ClockRollback { .. } => {
                    error!(?err, "stream token issuance quota state unavailable");
                    let mut response = json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "stream token issuance is temporarily unavailable",
                    );
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                    response
                }
                StreamTokenIssuerError::RuntimeSignerUnavailable
                | StreamTokenIssuerError::SignerEvidenceInvalid
                | StreamTokenIssuerError::SignerStateChanged
                | StreamTokenIssuerError::SignerFinalityUnavailable
                | StreamTokenIssuerError::SignerClockRollback => {
                    error!("stream token runtime signer unavailable");
                    let mut response = json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "stream token issuance is temporarily unavailable",
                    );
                    response
                        .headers_mut()
                        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                    response
                }
                StreamTokenIssuerError::RuntimeSignerRefused
                | StreamTokenIssuerError::RuntimeSignerOutputInvalid => {
                    error!("stream token runtime signer rejected issuance");
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to issue stream token",
                    )
                }
                _ => {
                    error!(?err, "failed to issue stream token");
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to issue stream token",
                    )
                }
            };
        }
    };
    let body_value = stream_token_body_json(&token_issue.token.body);
    let token_base64 = match encode_token_base64(&token_issue.token) {
        Ok(encoded) => encoded,
        Err(err) => {
            error!(?err, "failed to encode stream token payload");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to encode stream token",
            );
        }
    };
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::HeaderName::from_static(HEADER_SORA_NONCE),
        header_value(&nonce, "X-SoraFS-Nonce"),
    );
    response_headers.insert(
        header::HeaderName::from_static(HEADER_SORA_CLIENT),
        header_value(&client_id, "X-SoraFS-Client"),
    );
    response_headers.insert(
        header::HeaderName::from_static(HEADER_SORA_TOKEN_ID),
        header_value(&token_issue.token.body.token_id, "X-SoraFS-Token-Id"),
    );
    response_headers.insert(
        header::HeaderName::from_static(HEADER_SORA_VERIFYING_KEY),
        header_value(
            &hex::encode(issuer.verifying_key_bytes()),
            "X-SoraFS-Verifying-Key",
        ),
    );
    let quota_header = token_issue.remaining_quota.to_string();
    response_headers.insert(
        header::HeaderName::from_static(HEADER_SORA_ISSUANCE_QUOTA_REMAINING),
        header_value(&quota_header, "X-SoraFS-Issuance-Quota-Remaining"),
    );
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let token_value = json_object(vec![
        json_entry("body", body_value),
        json_entry(
            "signature_hex",
            Value::String(hex::encode(&token_issue.token.signature)),
        ),
        json_entry("encoded", Value::String(token_base64.clone())),
    ]);
    let response = json_object(vec![
        json_entry("token", token_value),
        json_entry("token_base64", Value::String(token_base64)),
    ]);
    (StatusCode::OK, response_headers, JsonBody(response)).into_response()
}
#[cfg(feature = "app_api")]
fn stream_token_body_json(body: &StreamTokenBodyV1) -> Value {
    let mut obj = Map::new();
    obj.insert("token_id".into(), Value::from(body.token_id.clone()));
    obj.insert(
        "manifest_cid_hex".into(),
        Value::from(body.manifest_cid.encode_hex::<String>()),
    );
    obj.insert(
        "provider_id_hex".into(),
        Value::from(body.provider_id.encode_hex::<String>()),
    );
    obj.insert(
        "profile_handle".into(),
        Value::from(body.profile_handle.clone()),
    );
    obj.insert("max_streams".into(), Value::from(body.max_streams));
    obj.insert("ttl_epoch".into(), Value::from(body.ttl_epoch));
    obj.insert(
        "rate_limit_bytes".into(),
        Value::from(body.rate_limit_bytes),
    );
    obj.insert("issued_at".into(), Value::from(body.issued_at));
    obj.insert(
        "requests_per_minute".into(),
        Value::from(body.requests_per_minute),
    );
    obj.insert(
        "token_pk_version".into(),
        Value::from(body.token_pk_version),
    );
    Value::Object(obj)
}
