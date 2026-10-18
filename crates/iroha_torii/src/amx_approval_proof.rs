//! Exact direct AMX debit approval at one explicitly full-ledger-authorized World cut.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    account::AccountId,
    sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityLimits,
    },
    sumeragi_amx::{
        AmxDebitApprovalProofRefV1, AmxDebitApprovalV1,
        approval_proof::{
            MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1, MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
        },
    },
};

const ROUTE: &str = "/v1/amx/debit-approval/{height}";

fn height_selector(value: &str) -> Result<u64, Error> {
    value
        .parse::<u64>()
        .ok()
        .filter(|height| *height >= 2 && height.to_string() == value)
        .ok_or_else(|| {
            conversion_error("height must be a canonical non-genesis decimal u64".into())
        })
}

fn invalid_source() -> Error {
    conversion_error("AMX approval source or proof failed its original binding".into())
}

fn projection_error(
    error: crate::native_projection_response::NativeProjectionError,
) -> iroha_core::state::WorldStateSnapshotError {
    use crate::native_projection_response::NativeProjectionError;
    use iroha_core::state::WorldStateSnapshotError;
    match error {
        NativeProjectionError::Buffer(error) => WorldStateSnapshotError::Buffer(error),
        NativeProjectionError::Encoding(error) => WorldStateSnapshotError::Encoding(error),
        error => WorldStateSnapshotError::Invalid(error.to_string()),
    }
}

fn snapshot_error(error: iroha_core::state::WorldStateSnapshotError) -> Error {
    use iroha_core::state::{StateViewError, WorldStateSnapshotError};
    match error {
        WorldStateSnapshotError::Encoding(ref cause)
            if cause.kind() != norito::core::DecodeAttemptErrorKind::Invalid =>
        {
            crate::native_projection_response::capacity()
        }
        WorldStateSnapshotError::RootScopeRead(_) => crate::native_projection_response::capacity(),
        WorldStateSnapshotError::View(StateViewError::Busy(_)) => {
            crate::native_projection_response::capacity()
        }
        WorldStateSnapshotError::Acquisition(ref cause)
            if cause.release_wait().is_some()
                || matches!(cause, mv::storage::AdmittedStorageError::Allocator { .. }) =>
        {
            crate::native_projection_response::capacity()
        }
        WorldStateSnapshotError::Allocation(iroha_allocation::AllocationRefusal::Capacity {
            ..
        })
        | WorldStateSnapshotError::Buffer(iroha_allocation::ChargedBufferError::Admission(
            iroha_allocation::AllocationRefusal::Capacity { .. },
        ))
        | WorldStateSnapshotError::Buffer(iroha_allocation::ChargedBufferError::Allocator {
            ..
        })
        | WorldStateSnapshotError::Allocator(_) => crate::native_projection_response::capacity(),
        WorldStateSnapshotError::DecodeControl(
            iroha_allocation::PrepaidSharedError::Allocator { .. },
        ) => crate::native_projection_response::capacity(),
        WorldStateSnapshotError::Amx(iroha_data_model::sumeragi_amx::AmxError::Resource(
            ref cause,
        )) if cause.local_refusal().is_some() => crate::native_projection_response::capacity(),
        error => conversion_error(error.to_string()),
    }
}

fn read_failure_response(
    approval: &AmxDebitApprovalV1,
    relay: &AccountId,
    height: u64,
    reason: iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1,
    observed_height: Option<u64>,
    format: ResponseFormat,
) -> Result<AxResponse, Error> {
    use iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1;
    let failure = AmxApprovalReadFailureV1::new(approval, relay, height, reason, observed_height)
        .map_err(conversion_error)?;
    let mut response = match format {
        ResponseFormat::Norito => NoritoBody(failure.into_error_envelope()).into_response(),
        ResponseFormat::Json => JsonBody(failure.into_error_envelope()).into_response(),
    };
    *response.status_mut() =
        if reason == iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::Capacity {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::CONFLICT
        };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

fn cut_height_observation(
    actual_scope: Option<iroha_data_model::block::consensus::SumeragiRootScope>,
    actual_network: iroha_data_model::NetworkId,
    actual_height: u64,
    approval: &AmxDebitApprovalV1,
    requested_height: u64,
) -> Result<Option<u64>, Error> {
    let scope = iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
        parent_network_id: approval.global_network,
        dataspace_id: approval.dataspace,
    };
    if actual_scope != Some(scope) || actual_network != approval.participant_network {
        return Err(conversion_error(
            "AMX approval request names a different signed root".into(),
        ));
    }
    // The independently verified bank block may be ahead of this peer's applied
    // State, or another authorized carrier may have advanced it. Neither condition
    // is a failed cryptographic proof or authenticated monetary absence.
    Ok((actual_height != requested_height).then_some(actual_height))
}

fn authentication_error(error: Error) -> Error {
    use iroha_data_model::ValidationFail;
    match error {
        Error::Query(ValidationFail::NotPermitted(_)) => Error::AppUnauthorized {
            code: "amx_debit_approval_authentication_required",
            message: "AMX debit approval proof requires canonical account authentication".into(),
        },
        error => error,
    }
}

// Keep one route-local boundary for original early request-pool refusal.
fn request_allocation_error(error: iroha_allocation::AllocationRefusal) -> Error {
    snapshot_error(error.into())
}

fn approval_decode_context(
    budget: &AllocationBudget,
    limits: norito::DecodeLimits,
) -> Result<norito::core::DecodeBudgetContext, Error> {
    let mut counters = budget
        .try_reserve(norito::core::DecodeBudgetContext::allocation_layout())
        .map_err(request_allocation_error)?;
    norito::core::DecodeBudgetContext::from_reservation(limits, &mut counters)
        .map_err(|error| snapshot_error(error.into()))
}

fn approval_source_admission(
    bytes: usize,
    budget: &AllocationBudget,
) -> Result<
    (
        NativeFinalityLimits,
        norito::DecodeLimits,
        iroha_allocation::AllocationReservation,
    ),
    Error,
> {
    let unit = bytes / 8;
    let limits = NativeFinalityLimits {
        block_bytes: unit.min(NATIVE_FINALITY_MAX_BLOCK_BYTES),
        journal_bytes: (unit * 2).min(NATIVE_FINALITY_MAX_JOURNAL_BYTES),
        block_count: 8,
        allocated_bytes: unit * 4,
    };
    let decode_limits = limits.decode_limits().map_err(conversion_error)?;
    let source_bytes = limits
        .journal_bytes
        .checked_add(limits.allocated_bytes)
        .ok_or_else(|| {
            request_allocation_error(iroha_allocation::AllocationRefusal::DemandOverflow)
        })?;
    let charge = budget
        .try_reserve_bytes(source_bytes)
        .map_err(request_allocation_error)?;
    Ok((limits, decode_limits, charge))
}

// The wire body, cumulative decoder scratch and its counter control all belong to the
// original admitted response pool. The decoded request cannot escape this scope.
fn with_approval<R>(
    body: &[u8],
    budget: &AllocationBudget,
    decode_bytes: usize,
    consume: impl FnOnce(&AmxDebitApprovalV1) -> Result<R, Error>,
) -> Result<R, Error> {
    let capacity = crate::native_projection_response::capacity;
    if body.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 {
        return Err(conversion_error(
            "AMX approval body exceeds its fixed canonical bound".into(),
        ));
    }
    let _body_charge = budget
        .try_reserve_bytes(body.len())
        .map_err(request_allocation_error)?;
    let _decode_charge = budget
        .try_reserve_bytes(decode_bytes)
        .map_err(request_allocation_error)?;
    let context = approval_decode_context(
        budget,
        norito::DecodeLimits::new(body.len(), body.len(), decode_bytes, decode_bytes, 64),
    )?;
    let approval: AmxDebitApprovalV1 = context
        .with(|| norito::core::classify_decode_attempt(|| norito::decode_canonical(body)))
        .map_err(|error| {
            if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid {
                conversion_error("AMX debit approval requires its canonical Norito frame".into())
            } else {
                capacity()
            }
        })?;
    approval
        .validate()
        .map_err(|error| conversion_error(error.to_string()))?;
    consume(&approval)
}

fn relay(
    app: &SharedAppState,
    headers: &HeaderMap,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
) -> Result<(AccountId, crate::history_producer::HistoryProducerOwner), Error> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(&app) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error);
            }
        };

    let deny = || Error::AppUnauthorized {
        code: "amx_debit_approval_authentication_required",
        message: "AMX debit approval proof requires canonical account authentication".into(),
    };
    match crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => {
            // An exact debit grant authorizes the monetary operation, not unrelated
            // account, asset or permission hashes in this complete World snapshot.
            require_approval_reader(
                app,
                &verified.account,
                authentication_owner.allocation_context(),
            )?;
            Ok((verified.account, authentication_owner))
        }
        Ok(None) => Err(deny()),
        Err(error) => Err(authentication_error(error)),
    }
}

fn require_approval_reader(
    app: &SharedAppState,
    reader: &AccountId,
    context: &norito::core::DecodeBudgetContext,
) -> Result<(), Error> {
    let permission: Permission = CanReadAllLedgerData.into();
    let allowed = app
        .state
        .try_with_authorization_view(context, |view| {
            torii_account_has_permission(view.world(), reader, &permission)
        })
        .map_err(crate::app_auth::authorization_view_error)?;
    if !allowed {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "AMX approval complete World carrier requires current CanReadAllLedgerData".into(),
            ),
        ));
    }
    Ok(())
}

// Hash only bounded exact request bytes. This is an unsigned read identity, not
// account authentication. It permits pre-authentication capacity scheduling without
// allocating/decoding an account or executing the protected World projection.
fn capacity_request_binding(
    headers: &HeaderMap,
    body: &[u8],
    height: u64,
) -> Option<iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1> {
    use iroha_torii_shared::amx_approval_read::{
        AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
    };
    if body.is_empty() || body.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 {
        return None;
    }
    let mut values = headers.get_all(crate::app_auth::HEADER_ACCOUNT).iter();
    let account = values.next()?;
    if account.as_bytes().is_empty()
        || account.as_bytes().len()
            > crate::app_auth::CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1
    {
        return None;
    }
    if values.next().is_some() {
        return None;
    }
    Some(AmxApprovalReadFailureV1 {
        approval_hash: Hash::new(body),
        relay_header_hash: Hash::new(account.as_bytes()),
        requested_height: height,
        reason: AmxApprovalReadReasonV1::Capacity,
        observed_height: None,
        retry_after_ms: None,
    })
}

fn capacity_observation(
    binding: Option<iroha_torii_shared::amx_approval_read::AmxApprovalReadFailureV1>,
    result: Result<AxResponse, Error>,
    format: ResponseFormat,
) -> Result<AxResponse, Error> {
    let retry_after_ms = match &result {
        Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))) => None,
        Err(Error::ProofRateLimited {
            retry_after_secs, ..
        }) => Some(retry_after_secs.saturating_mul(1_000)),
        _ => return result,
    };
    let Some(mut failure) = binding else {
        return result;
    };
    failure.retry_after_ms = retry_after_ms;
    let mut response = match format {
        ResponseFormat::Norito => NoritoBody(failure.into_error_envelope()).into_response(),
        ResponseFormat::Json => JsonBody(failure.into_error_envelope()).into_response(),
    };
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

// Recheck after both projection and egress awaits. A retained authorized
// request or historical grant cannot preserve disclosure after revocation.
fn finish_disclosure(
    app: &SharedAppState,
    reader: &AccountId,
    context: &norito::core::DecodeBudgetContext,
    response: Result<AxResponse, Error>,
) -> Result<AxResponse, Error> {
    let mut response = response?;
    require_approval_reader(app, reader, context)?;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

pub(crate) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<String>,
    headers: HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Result<AxResponse, Error> {
    let height = height_selector(&height)?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let binding = capacity_request_binding(&headers, &body, height);
    let result = read_approval(app, height, headers, method, uri, remote, body, format).await;
    capacity_observation(binding, result, format)
}

async fn read_approval(
    app: SharedAppState,
    height: u64,
    headers: HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    remote: std::net::SocketAddr,
    body: Bytes,
    format: ResponseFormat,
) -> Result<AxResponse, Error> {
    let (relay, authentication_owner) = relay(&app, &headers, &method, &uri, &body)?;
    if body.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 {
        return Err(conversion_error(
            "AMX approval body exceeds its fixed canonical bound".into(),
        ));
    }
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([u64::try_from(bytes).map_err(|_| {
            conversion_error("AMX approval working-set bound cannot be represented".into())
        })?])
        .ok_or_else(crate::native_projection_response::capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1);
    let state = app.state.clone();
    let (response, relay, authentication_owner) = routing::run_admitted_blocking(
        admission,
        "AMX debit approval proof worker failed",
        move || {
            let response = with_approval(
                &body,
                &budget,
                MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1,
                |approval| {
                    let result = (|| {
                    let scope = iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                        parent_network_id: approval.global_network,
                        dataspace_id: approval.dataspace,
                    };
                    let (limits, decode_limits, _source_charge) = approval_source_admission(bytes, &budget)?;
                    let view = state.try_view_once().map_err(|error| snapshot_error(error.into()))?;
                    let actual_height = view.native_world_snapshot_height_v1().map_err(snapshot_error)?;
                    if let Some(observed) = cut_height_observation(
                        iroha_core::sumeragi::lanes::routing::read_routing_root_scope(view.world())
                            .map_err(|cause| snapshot_error(iroha_core::state::WorldStateSnapshotError::RootScopeRead(cause)))?,
                        *state.network_id_ref(), actual_height, approval, height,
                    )? {
                        return read_failure_response(approval, &relay, height,
                            iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::CutChanged,
                            Some(observed), format);
                    }
                    let tip = norito::core::with_decode_limits_scope(decode_limits, || {
                        crate::native_projection_response::current_root_tip(
                            &view,
                            height,
                            scope,
                            limits,
                            invalid_source,
                        )
                    })?;
                    drop(view);
                    let produced = state
                        .with_native_amx_debit_approval_snapshot_v1(
                            &tip,
                            approval,
                            &relay,
                            &budget,
                            |world, permissions| {
                                let payload = AmxDebitApprovalProofRefV1::new(world, permissions);
                                crate::native_projection_response::encode(
                                    &payload,
                                    format,
                                    maximum,
                                    &budget,
                                )
                                .map_err(projection_error)
                            },
                        );
                    let mut body = match produced {
                        Ok(body) => body,
                        Err(iroha_core::state::WorldStateSnapshotError::CutChanged { requested_height, observed_height }) => {
                            if requested_height != height { return Err(invalid_source()); }
                            return read_failure_response(approval, &relay, height,
                                iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::CutChanged,
                                Some(observed_height), format);
                        }
                        Err(error) => return Err(snapshot_error(error)),
                    };
                    body.memory = Some(memory);
                    let mut response = AxResponse::new(Body::from(Bytes::from_owner(body)));
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static(match format {
                            ResponseFormat::Norito => "application/x-norito",
                            ResponseFormat::Json => "application/json",
                        }),
                    );
                    Ok(response)
                    })();
                    match result {
                        Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
                        ))) => read_failure_response(approval, &relay, height,
                            iroha_torii_shared::amx_approval_read::AmxApprovalReadReasonV1::Capacity,
                            None, format),
                        result => result,
                    }
                },
            )?;
            // Retain the actual authenticated account and its original allocation
            // owner through the final current-permission check after all awaits.
            Ok((response, relay, authentication_owner))
        },
    )
    .await?;
    // A revoked reader must be rejected before response collection or byte charging.
    require_approval_reader(&app, &relay, authentication_owner.allocation_context())?;
    let response = proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await;
    finish_disclosure(
        &app,
        &relay,
        authentication_owner.allocation_context(),
        response,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        NetworkId,
        asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    pub(super) fn approval() -> AmxDebitApprovalV1 {
        let dataspace = DataSpaceId::new(7);
        AmxDebitApprovalV1 {
            global_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"parent"),
            )),
            participant_network: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"bank"),
            )),
            participant_instance: [7; 32],
            dataspace,
            transaction_id: [9; 32],
            debited_asset: AssetId::with_scope(
                AssetDefinitionId::derive_from_components(
                    DomainId::try_new("bank", "universal").unwrap(),
                    "cash".parse().unwrap(),
                ),
                iroha_test_samples::ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(dataspace),
            ),
        }
    }

    #[tokio::test]
    async fn typed_capacity_observation_retains_exact_request_and_original_egress_delay() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let approval = approval();
        let relay = iroha_test_samples::ALICE_ID.clone();
        let body = norito::encode_canonical(&approval).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::app_auth::HEADER_ACCOUNT,
            relay.to_canonical_hex().unwrap().parse().unwrap(),
        );
        for (error, delay) in [
            (crate::native_projection_response::capacity(), None),
            (
                Error::ProofRateLimited {
                    endpoint: ROUTE,
                    retry_after_secs: 7,
                },
                Some(7_000),
            ),
        ] {
            let response = capacity_observation(
                capacity_request_binding(&headers, &body, 2),
                Err(error),
                ResponseFormat::Norito,
            )
            .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let failure = AmxApprovalReadFailureV1::decode_response(
                429,
                "application/x-norito",
                &bytes,
                &approval,
                &relay,
                2,
            )
            .unwrap();
            assert_eq!(failure.reason, AmxApprovalReadReasonV1::Capacity);
            assert_eq!(failure.retry_after_ms, delay);
        }
        for error in [
            conversion_error("invalid certified source".into()),
            Error::AppUnauthorized {
                code: "test",
                message: "wrong signature".into(),
            },
            Error::Query(iroha_data_model::ValidationFail::NotPermitted(
                "revoked read".into(),
            )),
            Error::AppServiceUnavailable {
                code: "generic",
                message: "unclassified".into(),
            },
        ] {
            assert!(
                capacity_observation(
                    capacity_request_binding(&headers, &body, 2),
                    Err(error),
                    ResponseFormat::Norito
                )
                .is_err()
            );
        }
        headers.append(
            crate::app_auth::HEADER_ACCOUNT,
            relay.to_canonical_hex().unwrap().parse().unwrap(),
        );
        assert!(capacity_request_binding(&headers, &body, 2).is_none());
        assert!(
            capacity_observation(
                None,
                Err(crate::native_projection_response::capacity()),
                ResponseFormat::Norito
            )
            .is_err()
        );
    }

    #[test]
    fn original_snapshot_request_capacity_is_retryable_but_invalid_lookalikes_are_terminal() {
        use iroha_allocation::{AllocationRefusal, ChargedBufferError};
        use iroha_core::state::WorldStateSnapshotError;
        let request = AllocationBudget::new(1024);
        let occupied = request.try_reserve_bytes(1024).unwrap();
        for wrapped in [false, true] {
            let refusal = request.try_reserve_bytes(1).unwrap_err();
            let error = if wrapped {
                WorldStateSnapshotError::Buffer(ChargedBufferError::Admission(refusal))
            } else {
                WorldStateSnapshotError::Allocation(refusal)
            };
            assert_eq!(
                snapshot_error(error).into_response().status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        for message in [
            "capacity unavailable",
            "World snapshot request allocation: occupied",
            "World cut tail differs from the complete applied preimage",
        ] {
            assert_eq!(
                snapshot_error(WorldStateSnapshotError::Invalid(message.into()))
                    .into_response()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        for refusal in [
            AllocationRefusal::DemandOverflow,
            AllocationRefusal::ExceedsLimit {
                requested_bytes: 2,
                limit_bytes: 1,
            },
        ] {
            assert_eq!(
                snapshot_error(WorldStateSnapshotError::Allocation(refusal.clone()))
                    .into_response()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                snapshot_error(WorldStateSnapshotError::Buffer(
                    ChargedBufferError::Admission(refusal)
                ))
                .into_response()
                .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::Buffer(
                ChargedBufferError::Allocator { requested_bytes: 1 }
            ))
            .into_response()
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(occupied);
        assert_eq!(request.reserved_bytes(), 0);
    }

    #[test]
    fn original_root_metadata_decode_refusal_has_capacity_response() {
        use iroha_core::{state::WorldStateSnapshotError, sumeragi::lanes::routing};
        let (chain, _approval, _signer) =
            iroha_core::sumeragi::test_chain::native_amx_approval_route_fixture();
        let view = chain.state().view();
        let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        let refusal = outer
            .with(|| routing::read_routing_root_scope(view.world()))
            .unwrap_err();
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::RootScopeRead(refusal))
                .into_response()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let empty = iroha_core::state::World::new();
        assert_eq!(
            routing::read_routing_root_scope(&empty.view()).unwrap(),
            None
        );
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::Invalid(
                "root scope decoding capacity".into()
            ))
            .into_response()
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn amx_response_producer_preserves_only_original_typed_capacity() {
        use crate::native_projection_response::{NativeProjectionError, encode_canonical};
        use iroha_allocation::{AllocationRefusal, ChargedBufferError};
        use iroha_core::state::WorldStateSnapshotError;
        let payload = 42_u64;
        let length = norito::canonical_frame_len(&payload).unwrap();
        let budget = AllocationBudget::new(length);
        let occupied = budget.try_reserve_bytes(1).unwrap();
        let original = encode_canonical(&payload, length, &budget).err().unwrap();
        let NativeProjectionError::Buffer(ChargedBufferError::Admission(cause)) = &original else {
            panic!("actual encoder did not retain its original occupied-pool refusal");
        };
        assert!(matches!(cause, AllocationRefusal::Capacity { .. }));
        let expected = cause.clone();
        let retained = projection_error(original);
        assert!(matches!(&retained,
            WorldStateSnapshotError::Buffer(ChargedBufferError::Admission(actual)) if *actual == expected));
        assert_eq!(
            snapshot_error(retained).into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), 0);
        for original in [
            NativeProjectionError::Invalid("forged capacity text".into()),
            NativeProjectionError::Unavailable(invalid_source()),
            encode_canonical(&payload, length - 1, &budget)
                .err()
                .unwrap(),
        ] {
            assert_eq!(
                snapshot_error(projection_error(original))
                    .into_response()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let original =
            crate::native_projection_response::encode(&payload, ResponseFormat::Json, 1, &budget)
                .err()
                .unwrap();
        let retained = projection_error(original);
        assert!(matches!(&retained, WorldStateSnapshotError::Encoding(cause)
            if cause.kind() == norito::core::DecodeAttemptErrorKind::Invalid));
        assert_eq!(
            snapshot_error(retained).into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn amx_decoder_control_and_checked_comparator_keep_exact_classification() {
        use iroha_allocation::PrepaidSharedError;
        use iroha_core::state::WorldStateSnapshotError;
        use iroha_data_model::sumeragi_amx::AmxError;
        let allocator = WorldStateSnapshotError::DecodeControl(PrepaidSharedError::Allocator {
            requested_bytes: 64,
        });
        assert_eq!(
            snapshot_error(allocator).into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let mut short = AllocationBudget::new(1024).try_reserve_bytes(0).unwrap();
        let refusal = norito::core::DecodeBudgetContext::from_reservation(
            norito::DecodeLimits::new(1, 1, 1, 1, 1),
            &mut short,
        )
        .err()
        .unwrap();
        assert!(matches!(refusal, PrepaidSharedError::Reservation(_)));
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::DecodeControl(refusal))
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let (chain, approval, _) =
            iroha_core::sumeragi::test_chain::native_amx_approval_route_fixture();
        let _chain = chain;
        let permission = approval.permission().unwrap();
        let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            0,
            64,
        ));
        let cause = outer
            .with(|| approval.matches_permission(&permission))
            .unwrap_err();
        assert!(
            matches!(&cause, AmxError::Resource(original) if original.local_refusal().is_some())
        );
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::Amx(cause))
                .into_response()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let forged = norito::core::classify_decode_attempt(|| {
            Err::<(), _>(norito::Error::TotalAllocationExceeded {
                attempted: 2,
                limit: 1,
            })
        })
        .unwrap_err();
        assert!(forged.local_refusal().is_none());
        assert_eq!(
            snapshot_error(WorldStateSnapshotError::Amx(AmxError::Resource(forged)))
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
        for invalid in [
            AmxError::Encoding("capacity unavailable".into()),
            AmxError::Proof("forged certified row".into()),
            AmxError::Transaction("malformed terms"),
        ] {
            assert_eq!(
                snapshot_error(WorldStateSnapshotError::Amx(invalid))
                    .into_response()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn invalid_amx_snapshot_is_terminal_at_the_error_boundary() {
        let error = snapshot_error(iroha_core::state::WorldStateSnapshotError::Invalid(
            "original certified permission proof differs".into(),
        ));
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn poisoned_amx_snapshot_reader_is_terminal_at_the_error_boundary() {
        let error = snapshot_error(iroha_core::state::WorldStateSnapshotError::View(
            iroha_core::state::StateViewError::Poisoned,
        ));
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn approval_cut_height_requires_exact_non_genesis_decimal() {
        assert_eq!(height_selector("2").unwrap(), 2);
        for value in ["0", "1", "02", "+2", "2 ", "-2", "18446744073709551616"] {
            assert!(height_selector(value).is_err(), "{value}");
        }
    }

    #[test]
    fn approval_authentication_capacity_preserves_original_cause_as_retryable() {
        use iroha_data_model::{ValidationFail, query::error::QueryExecutionFail};
        let cause = QueryExecutionFail::CapacityLimit;
        let error = authentication_error(Error::Query(ValidationFail::QueryFailed(cause)));
        assert!(matches!(
            &error,
            Error::Query(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            ))
        ));
        assert_eq!(
            error.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let denied = authentication_error(Error::Query(ValidationFail::NotPermitted(
            "incorrect request signature".into(),
        )));
        assert_eq!(denied.into_response().status(), StatusCode::UNAUTHORIZED);
        let invalid = authentication_error(invalid_source());
        assert_eq!(invalid.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn approval_request_decode_is_funded_and_capacity_remains_retryable() {
        let expected = approval();
        let body = norito::encode_canonical(&expected).unwrap();
        let decode_bytes = MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1;
        let budget = AllocationBudget::new(body.len() + decode_bytes + 1024);
        with_approval(&body, &budget, decode_bytes, |value| {
            assert_eq!(value, &expected);
            assert!(budget.reserved_bytes() >= body.len() + decode_bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(budget.reserved_bytes(), 0);
        let error = with_approval(&body, &budget, 0, |_| Ok(())).unwrap_err();
        assert!(
            matches!(
                error,
                Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                    iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
                ))
            ),
            "local decode refusal must remain capacity, not malformed authorization"
        );
        assert_eq!(budget.reserved_bytes(), 0);
        let short = AllocationBudget::new(body.len() - 1);
        assert!(with_approval(&body, &short, decode_bytes, |_| Ok(())).is_err());
        assert_eq!(short.reserved_bytes(), 0);
    }

    #[test]
    fn early_approval_pool_policy_and_geometry_refusals_are_terminal() {
        let body = norito::encode_canonical(&approval()).unwrap();
        let decode_bytes = MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1;
        for limit in [body.len() - 1, body.len()] {
            let budget = AllocationBudget::new(limit);
            let called = std::cell::Cell::new(false);
            let error = with_approval(&body, &budget, decode_bytes, |_| {
                called.set(true);
                Ok(())
            })
            .unwrap_err();
            assert_eq!(
                error.into_response().status(),
                StatusCode::BAD_REQUEST,
                "the original body/decode demand exceeds this finite pool policy"
            );
            assert!(!called.get());
            assert_eq!(budget.reserved_bytes(), 0);
        }
        let budget = AllocationBudget::new(1024);
        let layout = std::alloc::Layout::from_size_align(isize::MAX as usize, 1).unwrap();
        let overflow = budget.try_reserve_layouts([layout; 3]).unwrap_err();
        assert!(matches!(
            overflow,
            iroha_allocation::AllocationRefusal::DemandOverflow
        ));
        assert_eq!(
            request_allocation_error(overflow).into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(budget.reserved_bytes(), 0);
        let oversized = vec![0_u8; MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 + 1];
        let error = with_approval(&oversized, &budget, decode_bytes, |_| Ok(())).unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn early_decoder_control_preserves_original_pool_refusal_and_refund() {
        let bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
        assert!(bytes > 0);
        let limits = || norito::DecodeLimits::new(1024, 1024, 1024, 1024, 64);
        let short = AllocationBudget::new(bytes - 1);
        let error = approval_decode_context(&short, limits()).err().unwrap();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(short.reserved_bytes(), 0);
        let budget = AllocationBudget::new(bytes);
        let occupied = budget.try_reserve_bytes(bytes).unwrap();
        let error = approval_decode_context(&budget, limits()).err().unwrap();
        assert_eq!(
            error.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(occupied);
        let context = approval_decode_context(&budget, limits()).unwrap();
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(context);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn early_native_source_preserves_geometry_policy_capacity_and_original_charge() {
        let budget = AllocationBudget::new(4096);
        for bytes in [0, 7] {
            let error = approval_source_admission(bytes, &budget).err().unwrap();
            assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
            assert_eq!(budget.reserved_bytes(), 0);
        }
        let short = AllocationBudget::new(0);
        let error = approval_source_admission(4096, &short).err().unwrap();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(short.reserved_bytes(), 0);
        let occupied = budget.try_reserve_bytes(4096).unwrap();
        let error = approval_source_admission(4096, &budget).err().unwrap();
        assert_eq!(
            error.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(budget.reserved_bytes(), 4096);
        drop(occupied);
        let (limits, _, charge) = approval_source_admission(4096, &budget).unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            limits.journal_bytes + limits.allocated_bytes
        );
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn early_approval_capacity_echo_is_exact_and_permanent_bound_has_no_echo() {
        use iroha_torii_shared::amx_approval_read::{
            AmxApprovalReadFailureV1, AmxApprovalReadReasonV1,
        };
        let approval = approval();
        let relay = iroha_test_samples::ALICE_ID.clone();
        let body = norito::encode_canonical(&approval).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::app_auth::HEADER_ACCOUNT,
            relay.to_canonical_hex().unwrap().parse().unwrap(),
        );
        let decode_bytes = MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1;
        let budget = AllocationBudget::new(body.len() + decode_bytes + 1024);
        let occupied = budget.try_reserve_bytes(budget.limit_bytes()).unwrap();
        let error = with_approval(&body, &budget, decode_bytes, |_| Ok(())).unwrap_err();
        let response = capacity_observation(
            capacity_request_binding(&headers, &body, 2),
            Err(error),
            ResponseFormat::Norito,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let refusal = AmxApprovalReadFailureV1::decode_response(
            429,
            "application/x-norito",
            &bytes,
            &approval,
            &relay,
            2,
        )
        .unwrap();
        assert_eq!(refusal.reason, AmxApprovalReadReasonV1::Capacity);
        assert!(
            AmxApprovalReadFailureV1::decode_response(
                429,
                "application/x-norito",
                &bytes,
                &approval,
                &relay,
                3
            )
            .is_err()
        );
        drop(occupied);
        with_approval(&body, &budget, decode_bytes, |value| {
            assert_eq!(value, &approval);
            Ok(())
        })
        .unwrap();
        assert_eq!(budget.reserved_bytes(), 0);
        let short = AllocationBudget::new(body.len() - 1);
        let error = with_approval(&body, &short, decode_bytes, |_| Ok(())).unwrap_err();
        let error = capacity_observation(
            capacity_request_binding(&headers, &body, 2),
            Err(error),
            ResponseFormat::Norito,
        )
        .unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(short.reserved_bytes(), 0);
    }

    fn disclosure_fixture() -> (
        SharedAppState,
        AccountId,
        iroha_crypto::KeyPair,
        Vec<u8>,
        axum::http::Uri,
        Permission,
    ) {
        let key =
            iroha_crypto::KeyPair::from_seed(vec![0xc9; 32], iroha_crypto::Algorithm::Ed25519);
        let account = AccountId::new(key.public_key().clone());
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&account),
        );
        let mut expected = approval();
        expected.participant_network = *app.state.network_id_ref();
        let permission = expected.permission().unwrap();
        let body = norito::encode_canonical(&expected).unwrap();
        (
            app,
            account,
            key,
            body,
            "/v1/amx/debit-approval/2".parse().unwrap(),
            permission,
        )
    }

    fn change_disclosure_permission(
        app: &SharedAppState,
        account: &AccountId,
        permission: &Permission,
        grant: bool,
    ) {
        let header =
            iroha_data_model::block::BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 0, 0);
        let mut block = app.state.block(header);
        let mut transaction = block.transaction();
        if grant {
            transaction
                .world_mut_for_testing()
                .add_account_permission(account, permission.clone());
        } else {
            assert!(
                transaction
                    .world_mut_for_testing()
                    .remove_account_permission(account, permission)
            );
        }
        transaction.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }

    fn signed_disclosure_headers(
        app: &SharedAppState,
        account: &AccountId,
        key: &iroha_crypto::KeyPair,
        body: &[u8],
        uri: &axum::http::Uri,
    ) -> HeaderMap {
        crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(),
            account,
            key,
            &axum::http::Method::POST,
            uri,
            body,
        )
    }

    #[test]
    fn actual_signed_debit_permission_never_authorizes_complete_world_disclosure() {
        use iroha_executor_data_model::permission::query::{
            CanReadAccountData, CanReadRestrictedDataspace,
        };
        let (app, account, key, body, uri, debit) = disclosure_fixture();
        change_disclosure_permission(&app, &account, &debit, true);
        for permission in [
            CanReadAccountData {
                account: account.clone(),
            }
            .into(),
            CanReadRestrictedDataspace {
                dataspace: DataSpaceId::new(7),
            }
            .into(),
        ] {
            change_disclosure_permission(&app, &account, &permission, true);
        }
        let headers = signed_disclosure_headers(&app, &account, &key, &body, &uri);
        let response = match relay(&app, &headers, &axum::http::Method::POST, &uri, &body) {
            Ok(_) => panic!(
                "exact debit/account/dataspace grants must not disclose the complete World hash inventory"
            ),
            Err(error) => error.into_response(),
        };
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            torii_account_has_permission(app.state.view().world(), &account, &debit),
            "refusing disclosure must not revoke the separate exact debit grant"
        );
        let broad: Permission = CanReadAllLedgerData.into();
        change_disclosure_permission(&app, &account, &broad, true);
        let headers = signed_disclosure_headers(&app, &account, &key, &body, &uri);
        let (reader, original_authentication) =
            relay(&app, &headers, &axum::http::Method::POST, &uri, &body).unwrap_or_else(
                |response| {
                    panic!(
                        "explicit full-ledger reader was refused: {}",
                        response.into_response().status()
                    )
                },
            );
        assert_eq!(reader, account);
        drop(original_authentication);
        change_disclosure_permission(&app, &account, &broad, false);
        let headers = signed_disclosure_headers(&app, &account, &key, &body, &uri);
        assert!(
            relay(&app, &headers, &axum::http::Method::POST, &uri, &body)
                .err()
                .unwrap()
                .into_response()
                .status()
                == StatusCode::FORBIDDEN,
            "committed full-read revocation must refuse the next exact signed request"
        );
        assert!(torii_account_has_permission(
            app.state.view().world(),
            &account,
            &debit
        ));
    }

    #[test]
    fn complete_approval_response_is_withheld_after_full_read_revocation() {
        let (app, account, key, body, uri, debit) = disclosure_fixture();
        change_disclosure_permission(&app, &account, &debit, true);
        let broad: Permission = CanReadAllLedgerData.into();
        change_disclosure_permission(&app, &account, &broad, true);
        let headers = signed_disclosure_headers(&app, &account, &key, &body, &uri);
        let (reader, original_authentication) =
            relay(&app, &headers, &axum::http::Method::POST, &uri, &body).unwrap_or_else(
                |response| {
                    panic!(
                        "explicit reader auth failed: {}",
                        response.into_response().status()
                    )
                },
            );
        let allowed = finish_disclosure(
            &app,
            &reader,
            original_authentication.allocation_context(),
            Ok(AxResponse::new(Body::from("complete World inventory"))),
        )
        .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers()[axum::http::header::CACHE_CONTROL],
            "private, no-store"
        );
        drop(allowed);
        // This is the exact permission boundary after the production worker and
        // egress awaits. Keeping its original authentication owner cannot bypass it.
        change_disclosure_permission(&app, &account, &broad, false);
        let refused = finish_disclosure(
            &app,
            &reader,
            original_authentication.allocation_context(),
            Ok(AxResponse::new(Body::from("must remain private"))),
        );
        let response = refused
            .expect_err("revoked reader must never receive the buffered complete snapshot")
            .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(torii_account_has_permission(
            app.state.view().world(),
            &account,
            &debit
        ));
        drop(original_authentication);
    }

    #[test]
    fn disclosure_gate_preserves_capacity_and_terminal_source_rejection() {
        use iroha_data_model::{ValidationFail, query::error::QueryExecutionFail};
        let (app, account, _, _, _, _) = disclosure_fixture();
        let owner =
            crate::history_producer::HistoryProducerOwner::authentication_read(&app).unwrap();
        let capacity = Error::Query(ValidationFail::QueryFailed(
            QueryExecutionFail::CapacityLimit,
        ));
        assert!(matches!(
            finish_disclosure(&app, &account, owner.allocation_context(), Err(capacity)),
            Err(Error::Query(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            )))
        ));
        let refusal = finish_disclosure(
            &app,
            &account,
            owner.allocation_context(),
            Err(authentication_error(Error::Query(
                ValidationFail::QueryFailed(QueryExecutionFail::CapacityLimit),
            ))),
        )
        .unwrap_err();
        assert!(matches!(
            &refusal,
            Error::Query(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            ))
        ));
        assert_eq!(
            refusal.into_response().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let missing_source = finish_disclosure(
            &app,
            &account,
            owner.allocation_context(),
            Err(invalid_source()),
        )
        .unwrap_err();
        assert_eq!(
            missing_source.into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[cfg(test)]
#[path = "amx_approval_proof_worker_tests.rs"]
mod worker_tests;

#[cfg(test)]
#[path = "amx_approval_proof_boundary_tests.rs"]
mod boundary_tests;
