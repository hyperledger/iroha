//! Current-cut private-settlement originals under full-ledger read authority.
//! Complete World hashes authenticate absence but expose unrelated row identities and permit
//! low-entropy value dictionaries. Selected-dataspace grants cannot authorize this response.
//! TODO: replace this full snapshot with genuinely scoped keyed-State inclusion/absence proofs
//! before offering restricted bank one-call context reads.
use crate::*;
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    nexus::{
        PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1, PrivateSettlementContextRequestV1,
        PrivateSettlementPoolKeyV1,
    },
    sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES, NativeFinalityLimits,
    },
    sumeragi_finality::MAX_WORLD_STATE_SNAPSHOT_BYTES_V1,
};
type SelectedPools = iroha_allocation::shared::Shared<
    PrivateSettlementContextRequestV1,
    iroha_allocation::AllocationReservation,
>;
const ROUTE: &str = "/v1/nexus/private-settlements/context/{height}";
fn unavailable() -> Error {
    Error::AppServiceUnavailable {
        code: "private_settlement_context_unavailable",
        message: "The exact current certified private-settlement context is unavailable.".into(),
    }
}
fn height_selector(value: &str) -> Result<u64, Error> {
    value
        .parse::<u64>()
        .ok()
        .filter(|h| *h >= 2 && h.to_string() == value)
        .ok_or_else(|| {
            conversion_error("private context requires canonical non-genesis height".into())
        })
}
fn selector(body: &[u8], budget: &AllocationBudget) -> Result<SelectedPools, Error> {
    let capacity = crate::native_projection_response::capacity;
    if body.is_empty() || body.len() > PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1 {
        return Err(capacity());
    }
    let _decode = budget
        .try_reserve_bytes(256 * 1024)
        .map_err(|_| capacity())?;
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            255,
            PRIVATE_SETTLEMENT_CONTEXT_REQUEST_MAX_BYTES_V1,
            255,
            256 * 1024,
            16,
        ),
        budget,
    )
    .map_err(|_| capacity())?;
    let selector: PrivateSettlementContextRequestV1 = context
        .with(|| norito::core::classify_decode_attempt(|| norito::decode_canonical(body)))
        .map_err(|error| {
            if error.kind() == norito::core::DecodeAttemptErrorKind::Invalid {
                conversion_error("private context requires exact canonical pool selector".into())
            } else {
                capacity()
            }
        })?;
    selector.validate().map_err(|_| {
        conversion_error("private context requires exact unique native pools".into())
    })?;
    let retained = selector
        .pools
        .capacity()
        .checked_mul(std::mem::size_of::<PrivateSettlementPoolKeyV1>())
        .and_then(|bytes| bytes.checked_add(SelectedPools::layout().size()))
        .ok_or_else(capacity)?;
    let charge = budget.try_reserve_bytes(retained).map_err(|_| capacity())?;
    // Hand off while the decoder's original allocation scope still covers the Vec.
    // The concrete shared owner frees its nested selectors and control before refund.
    SelectedPools::try_new(selector, charge).map_err(|_| capacity())
}

fn require_permission(
    app: &SharedAppState,
    account: &AccountId,
    _selectors: &PrivateSettlementContextRequestV1,
) -> Result<(), Error> {
    // The selected typed values do not reduce the full hash-list disclosure. Reuse the
    // canonical all-ledger permission matcher at every current authorization check.
    let owner = crate::history_producer::HistoryProducerOwner::authentication_read(app)?;
    owner.scope(|| {
        app.state
            .try_with_authorization_view(owner.allocation_context(), |view| {
                use iroha_core::state::{StorageReadOnly as _, WorldReadOnly as _};
                let world = view.world();
                let allowed = world.accounts().get(account).is_some()
                    && crate::stream_control::can_read_all(world, account)?;
                if !allowed {
                    return Err(Error::Query(
                        iroha_data_model::ValidationFail::NotPermitted(
                            "private context full World snapshot requires all-ledger read permission".into(),
                        ),
                    ));
                }
                Ok(())
            })
            .map_err(crate::app_auth::authorization_view_error)?
    })
}
pub(crate) async fn handler(
    State(app): State<SharedAppState>,
    axum::extract::Path(height): axum::extract::Path<String>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Result<AxResponse, Error> {
    let height = height_selector(&height)?;
    if method != Method::POST
        || uri.query().is_some()
        || uri.path() != ROUTE.replace("{height}", &height.to_string())
    {
        return Err(conversion_error(
            "private context requires exact signed request target".into(),
        ));
    }
    let auth = crate::history_producer::HistoryProducerOwner::authentication_read(&app)?;
    let verified = auth
        .scope(|| {
            crate::app_auth::verify_canonical_network_request(
                &app.state,
                app.state.network_id_ref(),
                &headers,
                crate::app_auth::CanonicalRequestParts {
                    method: &method,
                    uri: &uri,
                    body: &body,
                },
                None,
                auth.allocation_context(),
            )
        })
        .map_err(crate::app_auth::canonical_authentication_error)?
        .ok_or_else(|| Error::AppUnauthorized {
            code: "private_settlement_context_authentication_required",
            message: "canonical signed account authentication is required".into(),
        })?;
    let principal = validate_api_token(app.as_ref(), &headers)?.authenticated_principal();
    let format = match negotiate_heavy_query_response_format(&headers) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let rate_key = rate_limit_key(&headers, Some(remote.ip()), ROUTE, principal);
    rate_limit_requests_with_cost(&app, &rate_key, FINALITY_HEAVY_QUERY_RATE_COST).await?;
    let admission = acquire_query_admission(app.as_ref(), true).await?;
    let bytes = app.query_fanout_working_set_bytes;
    let capacity = crate::native_projection_response::capacity;
    let memory = app
        .query_fanout_inflight
        .try_acquire_parts([u64::try_from(bytes).map_err(|_| capacity())?])
        .ok_or_else(capacity)?;
    let memory = QueryFanoutMemoryReservation::new(memory);
    let budget = AllocationBudget::new(bytes);
    let body_charge = budget
        .try_reserve_bytes(body.len())
        .map_err(|_| capacity())?;
    let selectors = selector(&body, &budget)?;
    require_permission(&app, &verified.account, &selectors)?;
    let state = app.state.clone();
    let maximum = app
        .torii_proxy_max_response_bytes
        .min(MAX_WORLD_STATE_SNAPSHOT_BYTES_V1);
    let original_selectors = selectors.clone();
    let response =
        routing::run_admitted_blocking(admission, "private context worker failed", move || {
            let _body = (body, body_charge);
            let unit = bytes / 8;
            let limits = NativeFinalityLimits {
                block_bytes: unit.min(NATIVE_FINALITY_MAX_BLOCK_BYTES),
                journal_bytes: (unit * 2).min(NATIVE_FINALITY_MAX_JOURNAL_BYTES),
                block_count: 8,
                allocated_bytes: unit * 4,
            };
            let decode_limits = limits.decode_limits().map_err(|_| capacity())?;
            let _source = budget
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
                .with_native_private_settlement_context_v1(
                    &tip,
                    &original_selectors,
                    &budget,
                    |proof| {
                        crate::native_projection_response::encode(&proof, format, maximum, &budget)
                            .map_err(|_| "private context output unavailable".to_owned())
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
    require_permission(&app, &verified.account, &selectors)?;
    let mut response = proof_response_with_exact_egress(
        app.as_ref(),
        &headers,
        Some(remote.ip()),
        ROUTE,
        response,
        true,
    )
    .await?;
    require_permission(&app, &verified.account, &selectors)?;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_context_exact_height_and_route_are_canonical() {
        assert_eq!(height_selector("2").unwrap(), 2);
        for bad in ["0", "1", "02", "+2", "2 ", "18446744073709551616"] {
            assert!(height_selector(bad).is_err());
        }
        assert_eq!(
            ROUTE,
            iroha_torii_shared::route_catalog::private_settlement::CONTEXT.path()
        );
    }
    #[test]
    fn private_context_selector_refuses_malformed_and_unfunded_input() {
        let key = PrivateSettlementPoolKeyV1 {
            route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
                lane_id: iroha_model_base::topology::LaneId::new(3),
                lane_incarnation: Hash::new(b"scope"),
            },
            pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new([9; 32]),
        };
        let selectors = PrivateSettlementContextRequestV1 { pools: vec![key] };
        let body = norito::encode_canonical(&selectors).unwrap();
        let budget = AllocationBudget::new(512 * 1024);
        let retained = selector(&body, &budget).unwrap();
        assert_eq!(*retained, selectors);
        let bytes = retained.pools.capacity() * std::mem::size_of::<PrivateSettlementPoolKeyV1>()
            + SelectedPools::layout().size();
        assert_eq!(budget.reserved_bytes(), bytes);
        let same = retained.clone();
        assert!(SelectedPools::ptr_eq(&retained, &same));
        drop(retained);
        assert_eq!(budget.reserved_bytes(), bytes);
        drop(same);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(selector(&body, &AllocationBudget::new(0)).is_err());
        let mut trailing = body;
        trailing.push(0);
        assert!(selector(&trailing, &budget).is_err());
    }
    #[test]
    fn private_context_full_world_permission_is_exact_and_revocation_applies_before_egress() {
        use iroha_core::state::World;
        use iroha_data_model::{Account, Registrable};
        let owner = iroha_test_samples::ALICE_ID.clone();
        let world = World::with([], [Account::new(owner.clone()).build(&owner)], []);
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(world);
        let ds = iroha_model_base::topology::DataSpaceId::new(7);
        let key = PrivateSettlementPoolKeyV1 {
            route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
                dataspace_id: ds,
                lane_id: iroha_model_base::topology::LaneId::new(3),
                lane_incarnation: Hash::new(b"scope"),
            },
            pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new([9; 32]),
        };
        let change = |permission: iroha_data_model::permission::Permission, grant| {
            let mut block = app.state.block(iroha_data_model::block::BlockHeader::new(
                std::num::NonZeroU64::new(1).unwrap(),
                None,
                None,
                0,
                0,
            ));
            let mut tx = block.transaction();
            if grant {
                tx.world_mut_for_testing()
                    .add_account_permission(&owner, permission);
            } else {
                assert!(
                    tx.world_mut_for_testing()
                        .remove_account_permission(&owner, &permission)
                );
            }
            tx.apply();
            block.commit_world_overlay_for_testing().unwrap();
        };
        assert!(
            require_permission(
                &app,
                &owner,
                &PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .is_err()
        );
        change(
            CanReadRestrictedDataspace {
                dataspace: iroha_model_base::topology::DataSpaceId::new(8),
            }
            .into(),
            true,
        );
        assert!(
            require_permission(
                &app,
                &owner,
                &PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .is_err(),
            "foreign dataspace grant grants no selected-context read"
        );
        change(CanReadRestrictedDataspace { dataspace: ds }.into(), true);
        assert!(
            require_permission(
                &app,
                &owner,
                &PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .is_err(),
            "even all selected dataspace grants cannot disclose unrelated complete World hashes"
        );
        change(CanReadAllLedgerData.into(), true);
        require_permission(
            &app,
            &owner,
            &PrivateSettlementContextRequestV1 { pools: vec![key] },
        )
        .unwrap();
        change(CanReadAllLedgerData.into(), false);
        assert!(
            require_permission(
                &app,
                &owner,
                &PrivateSettlementContextRequestV1 { pools: vec![key] }
            )
            .is_err(),
            "a retained request cannot hide current revocation"
        );
    }
    #[tokio::test]
    async fn private_context_authentication_refuses_invalid_and_replay_but_preserves_capacity() {
        use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
        use std::sync::mpsc;
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(
            crate::tests_runtime_handlers::world_with_account(&ALICE_ID),
        );
        let uri: Uri = "/v1/nexus/private-settlements/context/2".parse().unwrap();
        let key = PrivateSettlementPoolKeyV1 {
            route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
                dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
                lane_id: iroha_model_base::topology::LaneId::new(3),
                lane_incarnation: Hash::new(b"auth scope"),
            },
            pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new([9; 32]),
        };
        let body = Bytes::from(
            norito::encode_canonical(&PrivateSettlementContextRequestV1 { pools: vec![key] })
                .unwrap(),
        );
        let headers = crate::tests_runtime_handlers::signed_network_app_headers(
            app.state.network_id_ref(),
            &ALICE_ID,
            &ALICE_KEYPAIR,
            &Method::POST,
            &uri,
            &body,
        );
        let call = |headers, body| {
            handler(
                State(app.clone()),
                axum::extract::Path("2".to_owned()),
                headers,
                Method::POST,
                uri.clone(),
                axum::extract::ConnectInfo("127.0.0.1:19080".parse().unwrap()),
                body,
            )
        };
        assert_eq!(
            call(HeaderMap::new(), body.clone())
                .await
                .unwrap_err()
                .status_code(),
            StatusCode::UNAUTHORIZED
        );
        let invalid = call(headers.clone(), Bytes::from_static(b"changed signed body"))
            .await
            .unwrap_err();
        assert!(
            matches!(&invalid, Error::AppUnauthorized { code, .. } if *code == "canonical_authentication_invalid")
        );
        assert_eq!(invalid.status_code(), StatusCode::UNAUTHORIZED);
        let (held_tx, held_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
        let state = app.state.clone();
        let holder = std::thread::spawn(move || {
            state.with_held_header_for_reader_test(|_| {
                held_tx.send(()).unwrap();
                let _ = release_rx.recv();
            })
        });
        held_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let busy = call(headers.clone(), body.clone()).await.unwrap_err();
        drop(release_tx);
        holder.join().unwrap();
        assert!(matches!(
            &busy,
            Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
            ))
        ));
        assert_eq!(
            busy.status_code(),
            StatusCode::TOO_MANY_REQUESTS,
            "actual source contention must retain its capacity classification"
        );
        let forbidden = call(headers.clone(), body.clone()).await.unwrap_err();
        assert!(
            matches!(&forbidden, Error::Query(iroha_data_model::ValidationFail::NotPermitted(message))
            if message == "private context full World snapshot requires all-ledger read permission"),
            "the exact nonce must authenticate after invalid-body and source-capacity refusals: {forbidden:?}"
        );
        assert_eq!(forbidden.status_code(), StatusCode::FORBIDDEN);
        let replay = call(headers, body).await.unwrap_err();
        assert!(matches!(&replay, Error::AppUnauthorized { code, message }
            if *code == "canonical_authentication_invalid" && message == "request nonce already used"));
        assert_eq!(replay.status_code(), StatusCode::UNAUTHORIZED);
    }
    #[test]
    fn private_context_restricted_grant_cannot_disclose_foreign_balance_dictionary() {
        use iroha_core::state::{StorageReadOnly as _, World, WorldReadOnly as _};
        use iroha_data_model::{
            Registrable,
            account::Account,
            asset::{
                Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
                AssetId, AssetValue,
            },
            domain::Domain,
            sumeragi_finality::{
                WorldStateElementKindV1, WorldStateSnapshotEntryV1, world_state_value_hash_v1,
            },
        };
        use iroha_model_base::{domain::DomainId, topology::DataSpaceId};
        use iroha_primitives::numeric::Quantity;
        let owner = iroha_test_samples::ALICE_ID.clone();
        let bank_a = DataSpaceId::new(7);
        let bank_b = DataSpaceId::new(8);
        let domain = DomainId::parse_fully_qualified("balances.private-context").unwrap();
        let asset =
            AssetDefinitionId::derive_from_components(domain.clone(), "cash".parse().unwrap());
        let mut definition = AssetDefinition::numeric(
            asset.clone(),
            "Restricted test cash",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain.clone()),
        )
        .build(&owner);
        definition.total_quantity = 114_u32.into();
        let a = AssetId::with_scope(
            asset.clone(),
            owner.clone(),
            AssetBalanceScope::Dataspace(bank_a),
        );
        let b = AssetId::with_scope(asset, owner.clone(), AssetBalanceScope::Dataspace(bank_b));
        let world = World::with_assets(
            [Domain::new(domain).build(&owner)],
            [Account::new(owner.clone()).build(&owner)],
            [definition],
            [Asset::new(a, 41_u32), Asset::new(b.clone(), 73_u32)],
            [],
        );
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests_with_world(world);
        let mut block = app.state.block(iroha_data_model::block::BlockHeader::new(
            std::num::NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        tx.world_mut_for_testing().add_account_permission(
            &owner,
            CanReadRestrictedDataspace { dataspace: bank_a }.into(),
        );
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
        let view = app.state.view();
        assert!(crate::stream_control::can_read_dataspace(view.world(), &owner, bank_a).unwrap());
        assert!(!crate::stream_control::can_read_dataspace(view.world(), &owner, bank_b).unwrap());
        assert!(!crate::stream_control::can_read_all(view.world(), &owner).unwrap());
        // These are the exact registry key/value encodings disclosed by the full-World
        // publisher, not an encrypted value or a membership proof invented by this test.
        let leaked = WorldStateSnapshotEntryV1 {
            field_id: "world.assets".into(),
            kind: WorldStateElementKindV1::Table,
            key_hash: Some(world_state_value_hash_v1(&b).unwrap()),
            value_hash: world_state_value_hash_v1(view.world().assets().get(&b).unwrap()).unwrap(),
        };
        drop(view);
        let recovered = (0_u32..=100)
            .filter(|candidate| {
                world_state_value_hash_v1(&AssetValue::new(Quantity::from(*candidate))).unwrap()
                    == leaked.value_hash
            })
            .collect::<Vec<_>>();
        assert_eq!(
            recovered,
            vec![73],
            "unsalted complete-World value hashes reveal the exact foreign low-entropy quantity"
        );
        let selectors = PrivateSettlementContextRequestV1 {
            pools: vec![PrivateSettlementPoolKeyV1 {
                route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
                    dataspace_id: bank_a,
                    lane_id: iroha_model_base::topology::LaneId::new(3),
                    lane_incarnation: Hash::new(b"authorized bank A"),
                },
                pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new([9; 32]),
            }],
        };
        assert!(
            require_permission(&app, &owner, &selectors).is_err(),
            "Bank A read permission must not authorize a full World hash list that reveals Bank B balances"
        );
    }
}

#[cfg(test)]
#[path = "private_settlement_context_worker_tests.rs"]
mod worker_tests;
