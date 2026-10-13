//! Owner-token protected, body-free exports of a node's own private root custody.

use super::*;

fn anchor_height(height: &str) -> Result<u64, Error> {
    let value = height.parse::<u64>().map_err(|_| {
        routing::conversion_error(
            "anchor height must be a canonical non-genesis decimal u64".into(),
        )
    })?;
    if value < 2 || value.to_string() != height {
        return Err(routing::conversion_error(
            "anchor height must be a canonical non-genesis decimal u64".into(),
        ));
    }
    Ok(value)
}

fn require_private_root(world: &impl iroha_core::state::WorldReadOnly) -> Result<(), Error> {
    if !matches!(
        iroha_core::sumeragi::lanes::routing::committed_root_scope(world),
        Some(iroha_data_model::block::consensus::SumeragiRootScope::Dataspace { .. })
    ) {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "private root exports require an authenticated private root".into(),
            ),
        ));
    }
    Ok(())
}

fn owner_principal(
    app: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<limits::ApiTokenPrincipal, Error> {
    validate_api_token(app, headers)?
        .authenticated_principal()
        .ok_or_else(|| {
            Error::Query(iroha_data_model::ValidationFail::NotPermitted(
                "private root exports require an authenticated owner token".into(),
            ))
        })
}

pub async fn registration(
    State(app): State<SharedAppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    export(app, headers, remote, None).await
}

pub async fn anchor(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    export(app, headers, remote, Some(anchor_height(&height)?)).await
}

/// Project an unfinished local export attempt into the API's retry response.
fn export_error(error: iroha_core::sumeragi::private_dataspace_export::ExportError) -> Error {
    match error {
        iroha_core::sumeragi::private_dataspace_export::ExportError::Deferred(reason) => {
            Error::AppServiceUnavailable {
                code: "private_root_export_pending",
                message: format!("private root export read must retry: {reason}"),
            }
        }
        error => Error::Query(iroha_data_model::ValidationFail::InternalError(format!(
            "private root original certified custody is unavailable: {error}"
        ))),
    }
}

async fn export(
    app: SharedAppState,
    headers: axum::http::HeaderMap,
    remote: std::net::SocketAddr,
    height: Option<u64>,
) -> Result<AxResponse, Error> {
    let route = if height.is_some() {
        "/v1/private-root/anchors/{height}"
    } else {
        "/v1/private-root/registration"
    };
    let principal = owner_principal(app.as_ref(), &headers)?;
    require_private_root(app.state.view().world())?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(&headers, Some(remote.ip()), route, Some(principal));
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let state = app.state.clone();
    let response =
        routing::run_admitted_blocking(admission, "private root export worker failed", move || {
            let view = state.view();
            require_private_root(view.world())?;
            if let Some(height) = height {
                let proof = iroha_core::sumeragi::private_dataspace_export::anchor(&view, height)
                    .map_err(export_error)?;
                if matches!(format, crate::utils::ResponseFormat::Norito) {
                    Ok(crate::NoritoBody(proof).into_response())
                } else {
                    crate::routing::pretty_json_response(&proof)
                }
            } else {
                let proof = iroha_core::sumeragi::private_dataspace_export::registration(&view)
                    .map_err(export_error)?;
                if matches!(format, crate::utils::ResponseFormat::Norito) {
                    Ok(crate::NoritoBody(proof).into_response())
                } else {
                    crate::routing::pretty_json_response(&proof)
                }
            }
        })
        .await?;
    proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        route,
        response,
        true,
    )
    .await
}

#[cfg(all(test, feature = "app_api"))]
mod tests {
    use super::*;

    #[test]
    fn original_local_export_pool_refusal_is_a_retryable_http_response() {
        use iroha_allocation::release::ReleaseRegistration;
        use std::{future::Future, pin::Pin, task::Context};
        let registration_bytes = ReleaseRegistration::allocation_layout().size();
        let budget = iroha_allocation::AllocationBudget::new(8 + registration_bytes);
        let mut prepaid = budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
        drop(prepaid);
        let original_owner = budget.try_reserve_bytes(8).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let iroha_allocation::AllocationRefusal::Capacity { release, .. } = &refusal else {
            panic!("the original occupied pool refuses this actual attempt");
        };
        let mut release = release.clone().wait_for_release(&mut registration);
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(Pin::new(&mut release).poll(&mut context).is_pending());
        let error = export_error(
            iroha_core::sumeragi::private_dataspace_export::ExportError::Deferred(
                refusal.clone().into(),
            ),
        );
        assert!(
            matches!(&error, Error::AppServiceUnavailable { code, message }
            if *code == "private_root_export_pending" && message.contains(&refusal.to_string()))
        );
        assert_eq!(
            error.into_response().status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(budget.reserved_bytes(), 8 + registration_bytes);
        assert!(Pin::new(&mut release).poll(&mut context).is_pending());
        drop(original_owner);
        assert!(Pin::new(&mut release).poll(&mut context).is_ready());
        drop(release);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn export_height_rejects_aliases_and_genesis_without_narrowing_u64() {
        assert_eq!(anchor_height(&u64::MAX.to_string()).unwrap(), u64::MAX);
        for height in ["0", "1", "02", "+2", " 2", "2/3", "18446744073709551616"] {
            assert!(anchor_height(height).is_err());
        }
    }

    #[test]
    fn export_requires_private_scope_and_an_actual_owner_token() {
        let global = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            false,
        );
        assert!(require_private_root(global.state.view().world()).is_err());
        assert!(owner_principal(&global, &axum::http::HeaderMap::new()).is_err());
        assert!(require_private_root(&iroha_core::state::World::new().view()).is_err());
        let mut private = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            true,
        );
        require_private_root(private.state.view().world()).unwrap();
        let app = Arc::get_mut(&mut private).unwrap();
        app.require_api_token = false;
        app.api_token_digests = Arc::new(limits::ApiTokenDigestSet::from_tokens([
            "export-owner-token",
        ]));
        let mut headers = axum::http::HeaderMap::new();
        assert!(owner_principal(&private, &headers).is_err());
        headers.insert(
            HEADER_API_TOKEN,
            axum::http::HeaderValue::from_static("wrong"),
        );
        assert!(owner_principal(&private, &headers).is_err());
        headers.insert(
            HEADER_API_TOKEN,
            axum::http::HeaderValue::from_static("export-owner-token"),
        );
        owner_principal(&private, &headers).unwrap();
        headers.append(
            HEADER_API_TOKEN,
            axum::http::HeaderValue::from_static("export-owner-token"),
        );
        assert!(owner_principal(&private, &headers).is_err());
    }
}
