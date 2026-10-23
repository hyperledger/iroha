//! Current finalized provider authority and advert publication for native clients.
//!
//! Recipients independently authenticate the selected height and native schema.
//! This data response neither supplies a trust root nor authorizes stream tokens.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_core::sumeragi::certified_chain::{CertifiedChain, QcVerification};
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    provider_admission::discovery::{
        MAX_PROVIDER_DISCOVERY_ADVERT_BYTES_V1, MAX_PROVIDER_DISCOVERY_BYTES_V1,
        ProviderDiscoveryProofRefV1,
    },
};

const ROUTE: &str = "/v1/sorafs/providers/{provider_id}/discovery/{height}";

fn selectors(provider: &str, height: &str) -> Result<(ProviderId, u64), Error> {
    let mut bytes = [0_u8; 32];
    if provider.len() != 64
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || hex::decode_to_slice(provider, &mut bytes).is_err()
        || bytes == [0; 32]
    {
        return Err(conversion_error(
            "provider_id must be canonical nonzero lowercase 32-byte hex".into(),
        ));
    }
    let number = height
        .parse::<u64>()
        .ok()
        .filter(|n| *n >= 2 && n.to_string() == height)
        .ok_or_else(|| {
            conversion_error("height must be a canonical non-genesis decimal u64".into())
        })?;
    Ok((ProviderId::new(bytes), number))
}
fn global(world: &impl iroha_core::state::WorldReadOnly) -> Result<(), Error> {
    if iroha_core::sumeragi::lanes::routing::committed_root_scope(world)
        != Some(iroha_data_model::block::consensus::SumeragiRootScope::Global)
    {
        return Err(Error::Query(
            iroha_data_model::ValidationFail::NotPermitted(
                "provider discovery requires an authenticated global root".into(),
            ),
        ));
    }
    Ok(())
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "provider_discovery_unavailable",
        message: "Current certified provider discovery is unavailable.".into(),
    }
}
fn capacity() -> Error {
    Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
    ))
}

pub async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path((provider, height)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Result<AxResponse, Error> {
    let (provider, height) = selectors(&provider, &height)?;
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    global(app.state.view().world())?;
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(f) => f,
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
        .min(MAX_PROVIDER_DISCOVERY_BYTES_V1);
    let cache = app.sorafs_cache.clone().ok_or_else(unavailable)?;
    let state = app.state.clone();
    let response =
        routing::run_admitted_blocking(admission, "provider discovery worker failed", move || {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| unavailable())?
                .as_secs();
            let view = state.view();
            global(view.world())?;
            if u64::try_from(view.height()).ok() != Some(height) {
                return Err(unavailable());
            }
            let admitted =
                iroha_core::query::provider_admission::read_finalized_provider_admission_v1(
                    &view, provider, now,
                )
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            let chain = CertifiedChain::new(&view).map_err(|_| unavailable())?;
            let certified = chain.certified(height).map_err(|_| unavailable())?;
            if certified.verification() != QcVerification::Verified {
                return Err(unavailable());
            }
            let tip = certified.into_committed();
            drop(chain);
            drop(view);
            let guard = cache.blocking_read();
            let advert = guard
                .admitted_record_by_provider(provider.as_bytes(), now)
                .ok_or_else(unavailable)?
                .advert();
            sorafs_manifest::provider_admission::verify_advert_against_record(advert, &admitted)
                .map_err(|_| unavailable())?;
            let length = norito::canonical_frame_len(advert).map_err(|_| unavailable())?;
            if length > MAX_PROVIDER_DISCOVERY_ADVERT_BYTES_V1 {
                return Err(capacity());
            }
            let _advert_charge = budget.try_reserve_bytes(length).map_err(|_| capacity())?;
            let advert = norito::encode_canonical(advert).map_err(|_| unavailable())?;
            drop(guard);
            let mut body = state
                .with_native_provider_admission_snapshot_v1(&tip, provider, &budget, |originals| {
                    let payload = ProviderDiscoveryProofRefV1::new(
                        originals.world,
                        (originals.council_head, originals.council_predecessor),
                        (originals.provider_head, originals.provider_predecessor),
                        originals.owner,
                        &advert,
                        originals.stream_token,
                    );
                    crate::native_projection_response::encode(&payload, format, maximum, &budget)
                        .map_err(|_| "provider discovery encoding refused".to_owned())
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
    fn provider_and_height_selectors_are_exact_and_full_width() {
        let value = hex::encode([0xab; 32]);
        assert_eq!(
            selectors(&value, &u64::MAX.to_string()).unwrap(),
            (ProviderId::new([0xab; 32]), u64::MAX)
        );
        for provider in [
            value.to_uppercase(),
            format!(" {value}"),
            "00".repeat(32),
            "ab".repeat(31),
            format!("{value}/suffix"),
        ] {
            assert!(selectors(&provider, "2").is_err());
        }
        for height in ["0", "1", "02", "+2", " 2", "18446744073709551616"] {
            assert!(selectors(&value, height).is_err());
        }
    }
    #[test]
    fn discovery_refuses_private_and_unbound_roots() {
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
