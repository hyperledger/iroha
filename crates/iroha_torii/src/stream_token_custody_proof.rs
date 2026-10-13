//! Native custody presence and absence before provider admission or advertisements.
//!
//! Recipients independently authenticate the selected height and native schema.
//! This data response grants no enrollment, current-use or token authority.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::sorafs::{
    capacity::ProviderId,
    stream_token_custody::proof::{
        MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1, StreamTokenCustodyProofRefV1,
    },
};
use iroha_data_model::sumeragi::finality::{
    NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityLimits,
};

const ROUTE: &str = "/v1/sorafs/providers/{provider_id}/custody/{height}";

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
                "custody proof requires an authenticated global root".into(),
            ),
        ));
    }
    Ok(())
}
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "stream_token_custody_unavailable",
        message: "Current certified custody proof is unavailable.".into(),
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
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([u64::try_from(bytes).map_err(|_| capacity())?])
        .ok_or_else(capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_STREAM_TOKEN_CUSTODY_PROOF_BYTES_V1);
    let state = app.state.clone();
    let response =
        routing::run_admitted_blocking(admission, "custody proof worker failed", move || {
            // Reserve canonical source and decoded graph overlap before any history I/O.
            // These charges outlive the retained tip and the complete World publication.
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
                crate::native_projection_response::current_global_tip(
                    &view,
                    height,
                    limits,
                    unavailable,
                )
            })?;
            drop(view);
            let mut body = state
                .with_native_stream_token_custody_snapshot_v1(
                    &tip,
                    provider,
                    &budget,
                    |world, owner, current| {
                        let payload = StreamTokenCustodyProofRefV1::new(world, owner, current);
                        crate::native_projection_response::encode(
                            &payload,
                            format,
                            maximum,
                            &budget,
                            unavailable,
                        )
                        .map_err(|_| "custody proof encoding refused".to_owned())
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
    fn custody_proof_refuses_private_and_unbound_roots() {
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
    #[test]
    fn current_tip_uses_one_bounded_native_source_and_refuses_stale_or_unfunded_reads() {
        use iroha_core::{
            state::World,
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1))
            .map_err(|error| error.error)
            .unwrap();
        chain.commit_at(1_000, Vec::new());
        let view = chain.state().view();
        let limits = NativeFinalityLimits {
            block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
            journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
            block_count: 8,
            allocated_bytes: 128 * 1024 * 1024,
        };
        let tip = norito::core::with_decode_limits_scope(limits.decode_limits().unwrap(), || {
            crate::native_projection_response::current_global_tip(&view, 2, limits, unavailable)
        })
        .unwrap();
        assert_eq!(tip.block_hash(), chain.committed(2).block_hash());
        assert!(
            crate::native_projection_response::current_global_tip(&view, 1, limits, unavailable)
                .is_err()
        );
        assert!(
            crate::native_projection_response::current_global_tip(&view, 3, limits, unavailable)
                .is_err()
        );
        let insufficient = NativeFinalityLimits {
            block_count: 1,
            ..limits
        };
        assert!(
            norito::core::with_decode_limits_scope(insufficient.decode_limits().unwrap(), || {
                crate::native_projection_response::current_global_tip(
                    &view,
                    2,
                    insufficient,
                    unavailable,
                )
            })
            .is_err()
        );
        let insufficient = NativeFinalityLimits {
            allocated_bytes: 1,
            ..limits
        };
        assert!(
            norito::core::with_decode_limits_scope(insufficient.decode_limits().unwrap(), || {
                crate::native_projection_response::current_global_tip(
                    &view,
                    2,
                    insufficient,
                    unavailable,
                )
            })
            .is_err()
        );
    }
}
