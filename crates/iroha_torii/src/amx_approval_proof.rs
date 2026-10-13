//! Exact direct AMX debit approval at one account-authenticated private World cut.

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

fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "amx_debit_approval_proof_unavailable",
        message: "Current certified AMX debit approval proof is unavailable.".into(),
    }
}

fn authentication_error(error: Error) -> Error {
    use iroha_data_model::{ValidationFail, query::error::QueryExecutionFail};
    match error {
        Error::Query(ValidationFail::QueryFailed(cause @ QueryExecutionFail::CapacityLimit)) => {
            Error::AppServiceUnavailable {
                code: "amx_debit_approval_authentication_capacity",
                message: cause.to_string(),
            }
        }
        Error::Query(ValidationFail::NotPermitted(_)) => Error::AppUnauthorized {
            code: "amx_debit_approval_authentication_required",
            message: "AMX debit approval proof requires canonical account authentication".into(),
        },
        error => error,
    }
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
        return Err(capacity());
    }
    let _body_charge = budget
        .try_reserve_bytes(body.len())
        .map_err(|_| capacity())?;
    let _decode_charge = budget
        .try_reserve_bytes(decode_bytes)
        .map_err(|_| capacity())?;
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(body.len(), body.len(), decode_bytes, decode_bytes, 64),
        budget,
    )
    .map_err(|_| capacity())?;
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
) -> Result<(AccountId, crate::history_producer::HistoryProducerOwner), AxResponse> {
    let authentication_owner =
        match crate::history_producer::HistoryProducerOwner::authentication_read(&app) {
            Ok(owner) => owner,
            Err(error) => {
                return Err(error.into_response());
            }
        };

    let deny = || {
        (
            StatusCode::UNAUTHORIZED,
            "AMX debit approval proof requires canonical account authentication",
        )
            .into_response()
    };
    match crate::app_auth::verify_canonical_network_request(
        &app.state,
        app.state.network_id_ref(),
        headers,
        crate::app_auth::CanonicalRequestParts { method, uri, body },
        None,
        authentication_owner.allocation_context(),
    ) {
        Ok(Some(verified)) => Ok((verified.account, authentication_owner)),
        Ok(None) => Err(deny()),
        Err(error) => Err(authentication_error(error).into_response()),
    }
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
    let (relay, authentication_owner) = match relay(&app, &headers, &method, &uri, &body) {
        Ok(relay) => relay,
        Err(response) => return Ok(response),
    };
    if body.len() > MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1 {
        return Err(crate::native_projection_response::capacity());
    }
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([
            u64::try_from(bytes).map_err(|_| crate::native_projection_response::capacity())?
        ])
        .ok_or_else(crate::native_projection_response::capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1);
    let state = app.state.clone();
    let response = routing::run_admitted_blocking(
        admission,
        "AMX debit approval proof worker failed",
        move || {
            let _authentication_owner = authentication_owner;
            with_approval(
                &body,
                &budget,
                MAX_AMX_DEBIT_APPROVAL_PERMISSION_BYTES_V1,
                |approval| {
                    let capacity = crate::native_projection_response::capacity;
                    let scope = iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
                        parent_network_id: approval.global_network,
                        dataspace_id: approval.dataspace,
                    };
                    let unit = bytes / 8;
                    let limits = NativeFinalityLimits {
                        block_bytes: unit.min(NATIVE_FINALITY_MAX_BLOCK_BYTES),
                        journal_bytes: (unit * 2).min(NATIVE_FINALITY_MAX_JOURNAL_BYTES),
                        block_count: 8,
                        allocated_bytes: unit * 4,
                    };
                    let decode_limits = limits.decode_limits().map_err(|_| capacity())?;
                    let _source_charge = budget
                        .try_reserve_bytes(limits.journal_bytes + limits.allocated_bytes)
                        .map_err(|_| capacity())?;
                    let view = state.view();
                    let tip = norito::core::with_decode_limits_scope(decode_limits, || {
                        crate::native_projection_response::current_root_tip(
                            &view,
                            height,
                            scope,
                            limits,
                            unavailable,
                        )
                    })?;
                    drop(view);
                    let mut body = state
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
                                    unavailable,
                                )
                                .map_err(|_| "AMX debit approval proof encoding refused".to_owned())
                            },
                        )
                        .map_err(|_| unavailable())?;
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
                },
            )
        },
    )
    .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        NetworkId,
        asset::{AssetBalanceScope, AssetDefinitionId, AssetId},
    };
    use iroha_model_base::{domain::DomainId, topology::DataSpaceId};

    fn approval() -> AmxDebitApprovalV1 {
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
        let original = cause.to_string();
        let error = authentication_error(Error::Query(ValidationFail::QueryFailed(cause)));
        assert!(matches!(
            &error,
            Error::AppServiceUnavailable { code, message }
                if *code == "amx_debit_approval_authentication_capacity" && message == &original
        ));
        assert_eq!(
            error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let denied = authentication_error(Error::Query(ValidationFail::NotPermitted(
            "incorrect request signature".into(),
        )));
        assert_eq!(denied.into_response().status(), StatusCode::UNAUTHORIZED);
        let unavailable = authentication_error(unavailable());
        assert_eq!(
            unavailable.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
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
}
