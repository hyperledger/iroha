// Exact DPN alias errors cross the production outer error contract.
async fn alias_error_through_contract(response: AxResponse, accept: &str) -> ErrorEnvelope {
    use axum::{Router, body::Body, http::Request, routing::post};
    use tower::ServiceExt as _;
    let status = response.status();
    let response = std::sync::Arc::new(std::sync::Mutex::new(Some(response)));
    let router = Router::new()
        .route(
            "/v1/aliases/setup/plan",
            post(move || {
                let response = response.lock().unwrap().take().expect("one request");
                async move { response }
            }),
        )
        .layer(axum::middleware::from_fn(
            crate::enforce_typed_error_contract,
        ))
        .layer(axum::middleware::from_fn(crate::enforce_json_utf8_charset));
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/aliases/setup/plan")
                .header("Accept", accept)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers()["content-type"],
        if accept == crate::utils::NORITO_MIME_TYPE {
            crate::utils::NORITO_MIME_TYPE
        } else {
            "application/json; charset=utf-8"
        }
    );
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    if accept == crate::utils::NORITO_MIME_TYPE {
        norito::decode_from_bytes(&bytes).unwrap()
    } else {
        norito::json::from_slice(&bytes).unwrap()
    }
}

#[tokio::test]
async fn alias_error_envelopes_preserve_reports_and_exact_absence_through_middleware() {
    use iroha_data_model::alias_setup::*;
    use iroha_torii_shared::aliases::*;
    let account = checked_torii_test_account_id(0xa3, "alias absence contract fixture");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: account.to_string(),
        dataspace: Some("dpn".into()),
        domain: None,
    };
    for accept in ["application/json", crate::utils::NORITO_MIME_TYPE] {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let pending = status == StatusCode::SERVICE_UNAVAILABLE;
            let report = AliasSetupReportV1::new(
                if pending {
                    AliasSetupStatusV1::Pending
                } else {
                    AliasSetupStatusV1::Blocked
                },
                ["alias.plan.first", "alias.plan.second"]
                    .into_iter()
                    .map(|code| AliasSetupDiagnosticV1 {
                        phase: AliasSetupValidationPhaseV1::Planning,
                        code: code.into(),
                        severity: if pending {
                            AliasSetupSeverityV1::Warning
                        } else {
                            AliasSetupSeverityV1::Error
                        },
                        resource: Some("admin@dpn".into()),
                        config_path: None,
                        expected: Some("exact owner".into()),
                        actual: Some("different owner".into()),
                        remediation: "use the resource owner and request a new plan".into(),
                    })
                    .collect(),
            );
            let envelope = alias_error_through_contract(
                alias_setup_report_error_response(status, report.clone()),
                accept,
            )
            .await;
            assert_eq!(
                envelope.code(),
                if pending {
                    ALIAS_SETUP_PENDING_CODE
                } else {
                    ALIAS_SETUP_REJECTED_CODE
                }
            );
            assert_eq!(
                envelope.details.unwrap().alias_setup_report,
                Some(report.clone())
            );
            // This is the old root cause: a standalone native report is not an ErrorEnvelope.
            let old =
                alias_error_through_contract((status, JsonBody(report)).into_response(), accept)
                    .await;
            assert!(
                old.details
                    .is_none_or(|details| details.alias_setup_report.is_none())
            );
        }
        // Exercise the actual one-diagnostic planning producer too.
        let envelope = alias_error_through_contract(
            alias_setup_plan_report_response(
                StatusCode::CONFLICT,
                AliasSetupStatusV1::Blocked,
                "alias.plan.changed",
                Some("admin@dpn".into()),
                None,
                None,
                "refresh the plan",
            ),
            accept,
        )
        .await;
        assert_eq!(
            envelope
                .details
                .unwrap()
                .alias_setup_report
                .unwrap()
                .diagnostics[0]
                .code,
            "alias.plan.changed"
        );
        let envelope =
            alias_error_through_contract(account_alias_not_found_response("admin@dpn"), accept)
                .await;
        assert_eq!(envelope.code(), ACCOUNT_ALIAS_NOT_FOUND_CODE);
        assert_eq!(
            envelope
                .details
                .unwrap()
                .account_alias_not_found
                .unwrap()
                .alias,
            "admin@dpn"
        );
        let envelope = alias_error_through_contract(
            account_aliases_by_account_not_found_response(&request),
            accept,
        )
        .await;
        assert_eq!(envelope.code(), ACCOUNT_ALIASES_BY_ACCOUNT_NOT_FOUND_CODE);
        assert!(
            envelope
                .details
                .unwrap()
                .account_aliases_by_account_not_found
                .unwrap()
                .matches_selector(&account.to_string(), Some("dpn"), None)
        );
        let generic =
            alias_error_through_contract(StatusCode::NOT_FOUND.into_response(), accept).await;
        assert!(generic.details.is_none());
        for (status, code, alias) in [
            (
                StatusCode::FORBIDDEN,
                ACCOUNT_ALIAS_NOT_FOUND_CODE,
                "admin@dpn",
            ),
            (StatusCode::NOT_FOUND, "not_found", "admin@dpn"),
            (
                StatusCode::NOT_FOUND,
                ACCOUNT_ALIAS_NOT_FOUND_CODE,
                " Admin@dpn ",
            ),
        ] {
            let envelope =
                ErrorEnvelope::new(code, "invalid scoped detail").with_details(ErrorDetails {
                    account_alias_not_found: Some(AccountAliasNotFoundV1 {
                        alias: alias.into(),
                    }),
                    ..Default::default()
                });
            let result =
                alias_error_through_contract((status, JsonBody(envelope)).into_response(), accept)
                    .await;
            assert!(
                result
                    .details
                    .is_none_or(|details| details.account_alias_not_found.is_none())
            );
        }
    }
}

#[tokio::test]
async fn alias_account_absence_requires_complete_scoped_fanout() {
    let app = mk_app_state_for_tests();
    let account = checked_torii_test_account_id(0xa4, "alias fanout absence fixture");
    let request = routing::AliasLookupByAccountRequestDto {
        account_id: account.to_string(),
        dataspace: None,
        domain: None,
    };
    let routes = [1, 2].map(|id| ToriiAliasLookupRouteAccess {
        route: RoutingDecision::new(LaneId::new(id), DataSpaceId::new(u64::from(id))),
        filter_by_permission: false,
    });
    let body_bytes = 1024 * 1024;
    let working_set = routed_read_working_set_for_phase(body_bytes);
    // Each route is a completed exact absence, so the aggregate retains the selector.
    let result = collect_torii_alias_lookup_json_payloads(
&app,
&routes,
(0, "denied alias lookup"),
None,
&request,
(working_set, body_bytes),
|_| {
            let response = account_aliases_by_account_not_found_response(&request);
            async move { response }
        },
)
    .await
    .expect_err("all routes absent");
    assert_eq!(result.status(), StatusCode::NOT_FOUND);
    let envelope = alias_error_through_contract(result, "application/json").await;
    assert!(
        envelope
            .details
            .unwrap()
            .account_aliases_by_account_not_found
            .unwrap()
            .matches_selector(&account.to_string(), None, None)
    );
    for mode in 0..4 {
        let result = collect_torii_alias_lookup_json_payloads(
&app,
&routes,
(0, "denied alias lookup"),
None,
&request,
(working_set, body_bytes),
|route| {
                let response = if route == routes[0].route {
                    account_aliases_by_account_not_found_response(&request)
                } else {
                    match mode {
                        0 => torii_proxy_error_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "route_unavailable",
                            "route is unavailable",
                        ),
                        1 => StatusCode::NOT_FOUND.into_response(),
                        2 => {
                            let wrong = routing::AliasLookupByAccountRequestDto {
                                account_id: request.account_id.clone(),
                                dataspace: Some("other".into()),
                                domain: request.domain.clone(),
                            };
                            account_aliases_by_account_not_found_response(&wrong)
                        }
                        _ => torii_alias_permission_denied_response("scope denied"),
                    }
                };
                async move { response }
            },
)
        .await
        .expect_err("incomplete or invalid absence must fail");
        assert_eq!(
            result.status(),
            match mode {
                0 => StatusCode::SERVICE_UNAVAILABLE,
                3 => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_GATEWAY,
            }
        );
    }
    let result = collect_torii_alias_lookup_json_payloads(
&app,
&[],
(0, "denied alias lookup"),
None,
&request,
(working_set, body_bytes),
|_| async { unreachable!("no routes") },
)
    .await
    .expect_err("no route cannot establish absence");
    assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
    // A known positive keeps the existing merge policy even if another route is unavailable.
    let result = collect_torii_alias_lookup_json_payloads(
&app,
&routes,
(0, "denied alias lookup"),
None,
&request,
(working_set, body_bytes),
|route| {
            let response = if route == routes[0].route {
                alias_lookup_by_account_ok(&account.to_string(), vec![], "on_chain").unwrap()
            } else {
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "route is unavailable",
                )
            };
            async move { response }
        },
)
    .await
    .expect("known positive survives");
    assert_eq!(result.payloads.len(), 1);
}
