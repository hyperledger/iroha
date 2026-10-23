//! Finite global SNS lease publication at a caller-selected native certified cut.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_core::sumeragi::certified_chain::{CertifiedChain, QcVerification};
use iroha_data_model::sns::{
    DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1,
    lease::{MAX_SNS_LEASE_PROOF_BYTES_V1, SnsLeaseProofRefV1},
};

const ROUTE: &str = "/v1/sns/dataspaces/{alias}/lease/{height}";

fn selectors(alias: &str, height: &str) -> Result<(NameSelectorV1, u64), Error> {
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
        .map_err(|_| conversion_error("alias must be a canonical dataspace name".into()))?;
    if selector.label != alias || alias == "universal" || alias.contains('.') || alias.contains('/')
    {
        return Err(conversion_error(
            "alias must be a canonical private dataspace name".into(),
        ));
    }
    let number = height
        .parse::<u64>()
        .ok()
        .filter(|n| *n >= 2 && n.to_string() == height)
        .ok_or_else(|| {
            conversion_error("height must be a canonical non-genesis decimal u64".into())
        })?;
    Ok((selector, number))
}
fn global(world: &impl iroha_core::state::WorldReadOnly) -> Result<(), Error> {
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(world)
        != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "SNS lease projection requires an authenticated global root".into(),
            ),
        ));
    }
    Ok(())
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "sns_lease_unavailable",
        message: "Current certified SNS lease is unavailable.".into(),
    }
}
fn capacity() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
    ))
}

pub async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((alias, height)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    let (selector, height) = selectors(&alias, &height)?;
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    global(app.state.view().world())?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(format) => format,
        Err(response) => return Ok(response),
    };
    let key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let memory = crate::acquire_query_pool_credit(&app, bytes)
        .await
        .ok_or_else(capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_SNS_LEASE_PROOF_BYTES_V1);
    let state = app.state.clone();
    let response =
        routing::run_admitted_blocking(admission, "SNS lease worker failed", move || {
            let view = state.view();
            global(view.world())?;
            if u64::try_from(view.height()).ok() != Some(height) {
                return Err(unavailable());
            }
            let chain = CertifiedChain::new(&view).map_err(|_| unavailable())?;
            let certified = chain.certified(height).map_err(|_| unavailable())?;
            if certified.verification() != QcVerification::Verified {
                return Err(unavailable());
            }
            let tip = certified.into_committed();
            drop(chain);
            drop(view);
            let mut body = state
                .with_native_sns_lease_snapshot_v1(&tip, &selector, &budget, |world, record| {
                    crate::native_projection_response::encode(
                        &SnsLeaseProofRefV1::new(world, record),
                        format,
                        maximum,
                        &budget,
                    )
                    .map_err(|_| "SNS lease projection encoding refused".to_owned())
                })
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
        })
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
    #[test]
    fn lease_selectors_are_canonical_and_preserve_full_width_height() {
        assert_eq!(
            selectors("acme", &u64::MAX.to_string()).unwrap().1,
            u64::MAX
        );
        for alias in ["Acme", " acme", "acme ", "a/b", "a.b", "universal", ""] {
            assert!(selectors(alias, "2").is_err());
        }
        for height in ["0", "1", "02", "+2", " 2", "18446744073709551616"] {
            assert!(selectors("acme", height).is_err());
        }
    }
    #[test]
    fn lease_publication_refuses_private_or_unbound_roots() {
        let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            false,
        );
        global(app.state.view().world()).unwrap();
        let app = crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(
            iroha_core::state::World::new(),
            true,
        );
        assert!(global(app.state.view().world()).is_err());
        assert!(global(&iroha_core::state::World::new().view()).is_err());
    }
}
