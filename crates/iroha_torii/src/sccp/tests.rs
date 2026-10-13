//! Seeded-state tests of the SCCP v1 read routes (`specs/sccp.md` §6).

use super::*;
use axum::http::header;
use iroha_core::smartcontracts::isi::sccp::read::api::{
    SccpCapabilitiesV1, SccpControlPageV1, SccpHistoryPathViewV1, SccpLcCheckpointCoverV1,
    SccpLightClientDetailV1, SccpMessageStatusV1, SccpOutboundPageV1, SccpOutboundStateV1,
    SccpReadLimitsV1, SccpRecentMessagesV1,
};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::isi::sccp::{commitment, light_clients},
    state::{State, StateTransaction, World},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::BlockHeader,
    sccp::{
        control::{SccpControlRecordV1, SccpLeafRefV1, SccpTransferLeafRefV1},
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        escrow::sccp_xor_route_escrow_account_id_v1,
        inbound::{
            SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1, SccpSourceLocatorV1,
        },
        light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1, SccpStatusHeightV1},
        registry::{SccpRouteRevisionV1, SccpRouteV1},
    },
};
use std::num::NonZeroU64;

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;

fn norito_accept() -> ExtractAccept {
    ExtractAccept(HeaderValue::from_static(crate::utils::NORITO_MIME_TYPE))
}

fn json_accept() -> ExtractAccept {
    ExtractAccept(HeaderValue::from_static("application/json"))
}

fn blank_state() -> State {
    State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

/// Commit `write` into the world of `state` as one overlay.
fn seed(state: &State, write: impl FnOnce(&mut StateTransaction<'_, '_>)) {
    let header = BlockHeader::new(NonZeroU64::new(1).expect("nonzero"), None, None, 0, 0);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    write(&mut transaction);
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit the SCCP fixture");
}

async fn body(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
}

async fn decode<T>(response: Response) -> T
where
    T: norito::NoritoSerialize + for<'a> norito::NoritoDeserialize<'a>,
{
    assert_eq!(response.status(), StatusCode::OK);
    norito::decode_from_bytes(&body(response).await).expect("Norito body")
}

async fn error_code(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let value: Value = norito::json::from_slice(&body(response).await).expect("JSON error");
    (
        status,
        value
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

fn account(seed: u8) -> AccountId {
    let key_pair =
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic seed");
    AccountId::new(key_pair.public_key().clone())
}

fn route(state: &State, next_outbound_nonce: u64) -> SccpRouteV1 {
    let escrow = sccp_xor_route_escrow_account_id_v1(state.network_id_ref(), ETH).expect("escrow");
    let mut route = SccpRouteV1::empty(ETH, escrow).expect("route");
    let mut revision = SccpRouteRevisionV1::staged(
        1,
        SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [0x33; 20],
            runtime_code_hash: [0x34; 32],
        }),
        iroha_data_model::sccp::deployment::SccpCommitteePinV1 {
            generation: 1,
            committee_root: [0x44; 32],
            start_height: 1,
            until_ms: 1_801_209_600_000,
        },
        1_000_000,
        1,
    );
    revision.next_outbound_nonce = next_outbound_nonce;
    revision.next_control_nonce = 2;
    route.revisions.insert(1, revision);
    route
}

fn outbound_record(
    nonce: u64,
    height: u64,
    status: SccpOutboundStatusV1,
) -> SccpOutboundMessageRecordV1 {
    SccpOutboundMessageRecordV1 {
        network: ETH,
        revision: 1,
        nonce,
        height,
        commitment_index: 0,
        deadline_ms: 9_000 + nonce,
        sender: account(1),
        amount: 7,
        payload: vec![1, 2, 3],
        leaf: [u8::try_from(height).expect("small"); 32],
        status,
    }
}

/// Record outbound `nonce` alone in SCCP block `height` and commit the block.
fn record_outbound(
    transaction: &mut StateTransaction<'_, '_>,
    nonce: u64,
    height: u64,
    status: SccpOutboundStatusV1,
) -> [u8; 32] {
    let message_id = [u8::try_from(nonce + 1).expect("small"); 32];
    store::block_leaves::insert(
        transaction,
        (height, 0),
        SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
    )
    .expect("leaf");
    store::outbound_messages::insert(
        transaction,
        message_id,
        outbound_record(nonce, height, status),
    )
    .expect("record");
    store::outbound_by_nonce::insert(transaction, (ETH, 1, nonce), message_id).expect("nonce");
    commitment::commit_block(transaction, height)
        .expect("commit")
        .expect("commitment");
    message_id
}

fn inbound_record(height: u64) -> SccpInboundRecordV1 {
    SccpInboundRecordV1 {
        network: ETH,
        revision: 1,
        payload: vec![4, 5],
        source_locator: SccpSourceLocatorV1 {
            source_height: 77,
            block_hash: [6; 32],
            index_in_block: 0,
        },
        proven_at_height: height,
        fee_due: 0,
        status: SccpInboundStatusV1::pending(SccpPendingReasonV1::RevisionNotSettleable),
    }
}

/// A state with route revision 1 of Ethereum, three outbound records (nonce 0 recorded,
/// nonce 1 recorded, nonce 2 refunded), one inbound record, two controls and an
/// Ethereum light client with three checkpoints.
fn seeded() -> (State, [u8; 32], [u8; 32], u64) {
    let state = blank_state();
    let stride = SccpLightClientParamsV1::defaults_for(ETH)
        .expect("external")
        .checkpoint_stride;
    let route = route(&state, 3);
    seed(&state, |transaction| {
        store::routes::insert(transaction, ETH, route).expect("route");
        record_outbound(transaction, 0, 10, SccpOutboundStatusV1::Recorded);
        record_outbound(transaction, 1, 11, SccpOutboundStatusV1::Recorded);
        record_outbound(
            transaction,
            2,
            12,
            SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height: 20 }),
        );
        store::inbound_messages::insert(transaction, [0x44; 32], inbound_record(15))
            .expect("inbound");
        for (nonce, height) in [(1_u64, 10_u64), (2, 11)] {
            store::control_messages::insert(
                transaction,
                (ETH, 1, nonce),
                SccpControlRecordV1 {
                    track: 1,
                    parliament_paused: nonce == 1,
                    fast_pause_until_ms: 0,
                    height,
                    commitment_index: 1,
                    leaf: [9; 32],
                    certificate_id: [8; 32],
                    effect_hash: [5; 32],
                },
            )
            .expect("control");
        }
        store::light_clients::insert(
            transaction,
            ETH,
            SccpLightClientV1 {
                params: SccpLightClientParamsV1::defaults_for(ETH).expect("external"),
                head: SccpLcHeadV1 {
                    latest_set_id: 1,
                    latest_finalized: SccpLcPointV1 {
                        source_height: 3 * stride,
                        block_hash: [7; 32],
                        source_time_ms: 1,
                    },
                    last_progress_taira_ms: 1,
                },
                frozen: None,
                state_hash: [8; 32],
            },
        )
        .expect("light client");
        for (height, origin) in [
            (stride + 10, SccpLcCheckpointOriginV1::Advance),
            (stride + 20, SccpLcCheckpointOriginV1::Proof),
            (2 * stride + 5, SccpLcCheckpointOriginV1::Advance),
        ] {
            light_clients::record_checkpoint(
                transaction,
                ETH,
                SccpLcCheckpointV1 {
                    data: SccpLcCheckpointDataV1 {
                        source_height: height,
                        block_hash: [1; 32],
                        state_root: Some([2; 32]),
                        receipts_or_tx_root: [3; 32],
                        source_time_ms: height,
                    },
                    recorded_at_taira_ms: 0,
                    origin,
                },
            )
            .expect("checkpoint");
        }
    });
    (state, [1; 32], [3; 32], stride)
}

#[test]
fn identifiers_and_networks_parse_strictly() {
    assert_eq!(parse_word(&"ab".repeat(32)).ok(), Some([0xab; 32]));
    assert_eq!(
        parse_word(&format!("0x{}", "01".repeat(32))).ok(),
        Some([1; 32])
    );
    assert!(parse_word("abcd").is_err());
    assert_eq!(
        parse_network("ethereum-mainnet").ok(),
        Some(SccpNetworkV1::EthereumMainnet)
    );
    assert!(parse_network("sora-taira").is_err());
    assert!(parse_network("eth").is_err());
}

#[test]
fn numbers_and_directions_parse_with_defaults() {
    assert_eq!(parse_number(None, 1_u64).ok(), Some(1));
    assert_eq!(parse_number(Some("7"), 1_u64).ok(), Some(7));
    assert!(parse_number(Some("seven"), 1_u64).is_err());
    assert_eq!(parse_direction(None).ok(), Some(SccpDirectionV1::Outbound));
    assert_eq!(
        parse_direction(Some("inbound")).ok(),
        Some(SccpDirectionV1::Inbound)
    );
    assert!(parse_direction(Some("sideways")).is_err());
}

#[test]
fn read_errors_map_to_http_statuses() {
    for (failure, status) in [
        (SccpReadError::NotFound("x".into()), StatusCode::NOT_FOUND),
        (SccpReadError::Pruned("x".into()), StatusCode::GONE),
        (SccpReadError::Invalid("x".into()), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(read_error(&failure).status(), status);
    }
}

#[tokio::test]
async fn immutable_responses_carry_validators_per_representation() {
    let headers = HeaderMap::new();
    let json = respond_immutable(Some(&json_accept()), &headers, SccpReadLimitsV1::v1());
    let norito = respond_immutable(Some(&norito_accept()), &headers, SccpReadLimitsV1::v1());
    let json_tag = json.headers()[header::ETAG].clone();
    let norito_tag = norito.headers()[header::ETAG].clone();
    assert_ne!(json_tag, norito_tag, "ETags bind the representation");
    assert_eq!(json.headers()[header::VARY], "Accept");
    assert_eq!(json.headers()[header::CACHE_CONTROL], "public, no-cache");
    let bytes = body(json).await;
    assert_eq!(
        json_tag.to_str().expect("ascii"),
        format!("\"{}\"", blake3::hash(&bytes).to_hex())
    );
    let mut conditional = HeaderMap::new();
    conditional.insert(header::IF_NONE_MATCH, json_tag.clone());
    let not_modified =
        respond_immutable(Some(&json_accept()), &conditional, SccpReadLimitsV1::v1());
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.headers()[header::ETAG], json_tag);
    assert!(body(not_modified).await.is_empty());
}

#[tokio::test]
async fn immutable_response_validator_refuses_changed_representation_or_body() {
    let original = respond_immutable(
        Some(&json_accept()),
        &HeaderMap::new(),
        SccpReadLimitsV1::v1(),
    );
    assert_eq!(original.status(), StatusCode::OK);
    let original_tag = original.headers()[header::ETAG].clone();
    let mut conditional = HeaderMap::new();
    conditional.insert(header::IF_NONE_MATCH, original_tag.clone());

    let norito = respond_immutable(Some(&norito_accept()), &conditional, SccpReadLimitsV1::v1());
    assert_eq!(norito.status(), StatusCode::OK);
    assert_ne!(norito.headers()[header::ETAG], original_tag);
    assert_eq!(norito.headers()[header::VARY], "Accept");
    assert!(!body(norito).await.is_empty());

    let mut changed = SccpReadLimitsV1::v1();
    changed.recent_messages += 1;
    let expected = norito::json::to_vec(&changed).expect("changed representation");
    let json = respond_immutable(Some(&json_accept()), &conditional, changed);
    assert_eq!(json.status(), StatusCode::OK);
    assert_ne!(json.headers()[header::ETAG], original_tag);
    assert_eq!(json.headers()[header::VARY], "Accept");
    assert_eq!(body(json).await, expected);
}

#[tokio::test]
async fn message_route_serves_the_status_union() {
    let (state, first_recorded, refunded, _) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let headers = HeaderMap::new();
    let unknown: SccpMessageStatusV1 = decode(message_response(
        &view,
        &"99".repeat(32),
        Some(&accept),
        &headers,
    ))
    .await;
    assert_eq!(unknown, SccpMessageStatusV1::Unknown);
    let first = message_response(&view, &hex::encode(first_recorded), Some(&accept), &headers);
    assert!(
        first.headers().get(header::ETAG).is_none(),
        "a recorded state can still change"
    );
    let first: SccpMessageStatusV1 = decode(first).await;
    assert!(matches!(
        first.outbound().map(|view| view.state),
        Some(SccpOutboundStateV1::Recorded(recorded))
            if recorded.deadline_ms == 9_000
    ));
    let recorded: SccpMessageStatusV1 = decode(message_response(
        &view,
        &hex::encode([2_u8; 32]),
        Some(&accept),
        &headers,
    ))
    .await;
    assert!(matches!(
        recorded.outbound().map(|view| view.state),
        Some(SccpOutboundStateV1::Recorded(state)) if state.deadline_ms == 9_001
    ));
    // A refunded record is final: it carries an ETag and revalidates to 304.
    let final_state = message_response(&view, &hex::encode(refunded), Some(&accept), &headers);
    let etag = final_state.headers()[header::ETAG].clone();
    let refunded_status: SccpMessageStatusV1 = decode(final_state).await;
    assert!(refunded_status.is_final());
    let mut conditional = HeaderMap::new();
    conditional.insert(header::IF_NONE_MATCH, etag);
    assert_eq!(
        message_response(&view, &hex::encode(refunded), Some(&accept), &conditional).status(),
        StatusCode::NOT_MODIFIED
    );
    // Inbound ids are served instead of 404.
    let inbound: SccpMessageStatusV1 = decode(message_response(
        &view,
        &hex::encode([0x44_u8; 32]),
        Some(&accept),
        &headers,
    ))
    .await;
    assert_eq!(
        inbound.inbound().map(|view| view.record.status),
        Some(SccpInboundStatusV1::pending(
            SccpPendingReasonV1::RevisionNotSettleable
        ))
    );
    assert_eq!(
        error_code(message_response(&view, "abcd", Some(&accept), &headers)).await,
        (StatusCode::BAD_REQUEST, "sccp_invalid_query".to_owned())
    );
}

#[tokio::test]
async fn outbound_route_pages_by_nonce() {
    let (state, ..) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let page: SccpOutboundPageV1 = decode(outbound_response(
        &view,
        "ethereum-mainnet",
        1,
        &OutboundQuery {
            from_nonce: Some("1".into()),
            limit: Some("1".into()),
        },
        Some(&accept),
    ))
    .await;
    assert_eq!(page.next_outbound_nonce, 3);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].record.nonce, 1);
    assert_eq!(page.next_from_nonce, Some(2));
    assert_eq!(
        error_code(outbound_response(
            &view,
            "ethereum-mainnet",
            9,
            &OutboundQuery::default(),
            Some(&accept),
        ))
        .await,
        (StatusCode::NOT_FOUND, "sccp_not_found".to_owned())
    );
    assert_eq!(
        error_code(outbound_response(
            &view,
            "sora-taira",
            1,
            &OutboundQuery::default(),
            Some(&accept),
        ))
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn recent_route_pages_both_directions() {
    let (state, ..) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let first: SccpRecentMessagesV1 = decode(recent_response(
        &view,
        &RecentQuery {
            limit: Some("2".into()),
            ..RecentQuery::default()
        },
        Some(&accept),
    ))
    .await;
    let nonces = |page: &SccpRecentMessagesV1| {
        page.messages
            .iter()
            .map(|status| status.outbound().expect("outbound").record.nonce)
            .collect::<Vec<_>>()
    };
    assert_eq!(nonces(&first), vec![2, 1]);
    let second: SccpRecentMessagesV1 = decode(recent_response(
        &view,
        &RecentQuery {
            before: first.next_before.clone(),
            limit: Some("2".into()),
            ..RecentQuery::default()
        },
        Some(&accept),
    ))
    .await;
    assert_eq!(nonces(&second), vec![0]);
    let inbound: SccpRecentMessagesV1 = decode(recent_response(
        &view,
        &RecentQuery {
            direction: Some("inbound".into()),
            network: Some("ethereum-mainnet".into()),
            ..RecentQuery::default()
        },
        Some(&accept),
    ))
    .await;
    assert_eq!(inbound.messages.len(), 1);
    assert!(inbound.messages[0].inbound().is_some());
    for query in [
        RecentQuery {
            direction: Some("both".into()),
            ..RecentQuery::default()
        },
        RecentQuery {
            before: Some("not-a-cursor".into()),
            ..RecentQuery::default()
        },
    ] {
        assert_eq!(
            error_code(recent_response(&view, &query, Some(&accept))).await,
            (StatusCode::BAD_REQUEST, "sccp_invalid_query".to_owned())
        );
    }
}

#[tokio::test]
async fn controls_route_reports_native_control_records() {
    let (state, ..) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let page: SccpControlPageV1 = decode(controls_response(
        &view,
        "ethereum-mainnet",
        1,
        &ControlsQuery::default(),
        Some(&accept),
    ))
    .await;
    assert_eq!(page.next_control_nonce, 2);
    assert_eq!(page.controls.len(), 2);
    assert_eq!(page.controls[0].control_nonce, 1);
    assert_eq!(page.controls[1].control_nonce, 2);
    assert_eq!(page.controls[0].record.height, 10);
    assert_eq!(page.controls[1].record.height, 11);
    assert!(page.controls[0].record.parliament_paused);
    let after: SccpControlPageV1 = decode(controls_response(
        &view,
        "ethereum-mainnet",
        1,
        &ControlsQuery {
            after_nonce: Some("1".into()),
            limit: None,
        },
        Some(&accept),
    ))
    .await;
    assert_eq!(after.controls.len(), 1);
    assert_eq!(after.controls[0].control_nonce, 2);
}

#[tokio::test]
async fn light_client_routes_cover_checkpoint_edges() {
    let (state, _, _, stride) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let detail: SccpLightClientDetailV1 = decode(light_client_response(
        &view,
        "ethereum-mainnet",
        Some(&accept),
    ))
    .await;
    assert_eq!(detail.checkpoints.count, 3);
    assert_eq!(detail.checkpoints.permanent_buckets, 2);
    assert_eq!(
        error_code(light_client_response(&view, "bsc-mainnet", Some(&accept))).await,
        (StatusCode::NOT_FOUND, "sccp_not_found".to_owned())
    );
    let cover = |covering: Option<u64>| {
        checkpoints_response(
            &view,
            "ethereum-mainnet",
            &CoveringQuery {
                covering: covering.map(|height| height.to_string()),
            },
            Some(&accept),
        )
    };
    let exact: SccpLcCheckpointCoverV1 = decode(cover(Some(stride + 10))).await;
    assert_eq!(exact.nearest.checkpoint.data.source_height, stride + 10);
    assert!(exact.nearest.permanent);
    let between: SccpLcCheckpointCoverV1 = decode(cover(Some(stride + 11))).await;
    assert_eq!(between.nearest.checkpoint.data.source_height, stride + 20);
    assert!(!between.nearest.permanent);
    assert_eq!(
        between
            .nearest_permanent
            .map(|entry| entry.checkpoint.data.source_height),
        Some(2 * stride + 5)
    );
    let below_all: SccpLcCheckpointCoverV1 = decode(cover(Some(0))).await;
    assert_eq!(below_all.nearest.checkpoint.data.source_height, stride + 10);
    assert_eq!(
        error_code(cover(Some(2 * stride + 6))).await,
        (StatusCode::GONE, "sccp_pruned".to_owned()),
        "the head covers it but no checkpoint at or above it is retained"
    );
    assert_eq!(
        error_code(cover(Some(3 * stride + 1))).await,
        (StatusCode::NOT_FOUND, "sccp_not_found".to_owned()),
        "not finalized on Taira yet"
    );
    assert_eq!(
        error_code(cover(None)).await,
        (StatusCode::BAD_REQUEST, "sccp_invalid_query".to_owned())
    );
}

#[tokio::test]
async fn history_route_serves_logarithmic_paths_with_validators() {
    let (state, ..) = seeded();
    let view = state.view();
    let accept = norito_accept();
    let headers = HeaderMap::new();
    let cache_budget = iroha_allocation::AllocationBudget::new(1 << 20);
    let mut cache = read::SccpHistoryNodeCache::new();
    let (_, owner) = history_owner();
    let current: SccpHistoryPathViewV1 = decode(history_response(
        &view,
        10,
        &HistoryQuery::default(),
        Some(&accept),
        &headers,
        &mut cache,
        &cache_budget,
        &owner,
    ))
    .await;
    assert_eq!(current.history_size, 3);
    assert_eq!(
        (current.history_root, current.history_size),
        commitment::history_root_and_size(view.world()),
        "the served root is the stored accumulator root"
    );
    assert_eq!(current.proof.history_index, 0);
    assert_eq!(
        current.proof.history_path.len(),
        2,
        "promote-odd path of leaf 0 of 3"
    );
    let sized = history_response(
        &view,
        10,
        &HistoryQuery {
            size: Some("2".into()),
        },
        Some(&accept),
        &headers,
        &mut cache,
        &cache_budget,
        &owner,
    );
    let etag = sized.headers()[header::ETAG].clone();
    let older: SccpHistoryPathViewV1 = decode(sized).await;
    assert_eq!(older.history_size, 2);
    let mut conditional = HeaderMap::new();
    conditional.insert(header::IF_NONE_MATCH, etag);
    assert_eq!(
        history_response(
            &view,
            10,
            &HistoryQuery {
                size: Some("2".into()),
            },
            Some(&accept),
            &conditional,
            &mut cache,
            &cache_budget,
            &owner,
        )
        .status(),
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        error_code(history_response(
            &view,
            12,
            &HistoryQuery {
                size: Some("2".into()),
            },
            Some(&accept),
            &headers,
            &mut cache,
            &cache_budget,
            &owner,
        ))
        .await,
        (StatusCode::BAD_REQUEST, "sccp_invalid_query".to_owned())
    );
    assert_eq!(
        error_code(history_response(
            &view,
            99,
            &HistoryQuery::default(),
            Some(&accept),
            &headers,
            &mut cache,
            &cache_budget,
            &owner,
        ))
        .await,
        (StatusCode::NOT_FOUND, "sccp_not_found".to_owned())
    );
}

#[tokio::test]
async fn governance_route_reports_missing_records() {
    let state = blank_state();
    let view = state.view();
    let missing = hex::encode([0x99; 32]);
    let response = governance_proposal_response(&view, &missing, None);
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn capabilities_list_paths_profiles_and_limits() {
    let state = blank_state();
    let capabilities: SccpCapabilitiesV1 =
        decode(capabilities_response(&state.view(), Some(&norito_accept()))).await;
    assert_eq!(capabilities.limits, SccpReadLimitsV1::v1());
    assert_eq!(capabilities.profiles.len(), 3);
    for route in iroha_torii_shared::route_catalog::sccp::ROUTES {
        assert!(
            capabilities
                .path_templates
                .iter()
                .any(|path| path == route.path()),
            "{} is advertised",
            route.path()
        );
    }
    assert!(
        capabilities
            .path_templates
            .iter()
            .any(|path| path == "/v1/sccp/light-clients/{network}/checkpoints")
    );
}

/// Extract `T` from `uri`'s query the way the SCCP handlers do.
async fn extract_query<T>(uri: &str) -> Result<T, StatusCode>
where
    T: norito::json::JsonDeserializeOwned + Send,
{
    use axum::extract::FromRequestParts as _;
    let request = axum::http::Request::builder()
        .uri(uri)
        .body(())
        .expect("request");
    let (mut parts, _) = request.into_parts();
    crate::NoritoStringQuery::<T>::from_request_parts(&mut parts, &())
        .await
        .map(|crate::NoritoStringQuery(query)| query)
        .map_err(|response| response.status())
}

#[tokio::test]
async fn numeric_query_values_reach_the_handlers_as_text() {
    let outbound: OutboundQuery =
        extract_query("/v1/sccp/outbound/ethereum-mainnet/1?from_nonce=1&limit=2")
            .await
            .expect("outbound query");
    assert_eq!(outbound.from_nonce.as_deref(), Some("1"));
    assert_eq!(outbound.limit.as_deref(), Some("2"));
    let controls: ControlsQuery =
        extract_query("/v1/sccp/controls/ethereum-mainnet/1?after_nonce=7&limit=3")
            .await
            .expect("controls query");
    assert_eq!(controls.after_nonce.as_deref(), Some("7"));
    let recent: RecentQuery = extract_query(
        "/v1/sccp/messages/recent?direction=inbound&network=ton-mainnet&before=12:3&limit=5",
    )
    .await
    .expect("recent query");
    assert_eq!(recent.before.as_deref(), Some("12:3"));
    assert_eq!(recent.limit.as_deref(), Some("5"));
    let covering: CoveringQuery =
        extract_query("/v1/sccp/light-clients/bsc-mainnet/checkpoints?covering=255")
            .await
            .expect("covering query");
    assert_eq!(covering.covering.as_deref(), Some("255"));
    let history: HistoryQuery = extract_query("/v1/sccp/history/9?size=16")
        .await
        .expect("history query");
    assert_eq!(history.size.as_deref(), Some("16"));
    let proof: native::ProofQuery = extract_query("/v1/sccp/messages/00/proof?at=42")
        .await
        .expect("proof query");
    assert_eq!(proof.at.as_deref(), Some("42"));
    assert_eq!(
        extract_query::<OutboundQuery>(
            "/v1/sccp/outbound/ethereum-mainnet/1?from_nonce=1&from_nonce=2"
        )
        .await
        .err(),
        Some(StatusCode::BAD_REQUEST),
        "duplicate keys are still refused"
    );
}

#[tokio::test]
async fn committee_routes_report_current_records_and_reject_zero_or_absent_generation() {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::{
        isi::sccp::InitializeSccpV1,
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        },
        sccp::params::SccpParametersV1,
    };
    use iroha_sccp::api::SccpGenerationV1;
    let state = blank_state();
    assert_eq!(
        committee_response(&state.view(), None, None).status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        committee_response(&state.view(), Some(0), None).status(),
        StatusCode::BAD_REQUEST
    );
    // Core owns generation admission: obtain the retained record by executing the
    // public initializer against its original signed NPoS genesis context.
    let parameters = SccpParametersV1::taira_default();
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.genesis_block_cadence_ms = NonZeroU64::new(1_000).unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.unbonding_delay = std::time::Duration::from_millis(
        parameters.committee_validity_ms + parameters.forgery_evidence_grace_ms,
    );
    nexus.staking.max_slash_bps = 10_000;
    config.nexus = Some(nexus);
    config.genesis_instructions.push(
        InitializeSccpV1 {
            parameters,
            reset_nonce: [0x5a; 32],
        }
        .into(),
    );
    let chain = CertifiedTestChain::start(config).expect("initialize genuine SCCP genesis");
    let state = chain.state();
    let mut keys = chain
        .validators()
        .iter()
        .map(|(peer, _)| {
            peer.public_key()
                .try_to_bytes()
                .unwrap()
                .1
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[u8; 48]>>();
    keys.sort();
    let view = state.view();
    let record = store::committee_generations::get(view.world(), &1).unwrap();
    let liability_clock = record.liable_until_lc + 1;
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(30).unwrap(),
        None,
        None,
        30_000,
        0,
    ));
    let mut stx = block.transaction();
    store::liability_clock::set(&mut stx, liability_clock);
    let current: SccpGenerationV1 =
        decode(committee_response(&stx, None, Some(&norito_accept()))).await;
    let explicit: SccpGenerationV1 = norito::json::from_slice(
        &body(committee_response(&stx, Some(1), Some(&json_accept()))).await,
    )
    .unwrap();
    assert_eq!(current, explicit);
    assert_eq!(current.keys, keys);
    assert_eq!(
        current.committee_root,
        iroha_sccp::v1::committee::committee_root(&keys).unwrap()
    );
    assert!(current.liable, "the current generation remains liable");
    assert_eq!(
        committee_response(&stx, Some(2), None).status(),
        StatusCode::NOT_FOUND
    );
    let capabilities = read::capabilities(&stx);
    assert_eq!(
        capabilities.current_generation.unwrap().deadline_ms,
        chain.genesis().header().creation_time_ms + parameters.committee_validity_ms
    );
    assert_eq!(capabilities.liability_clock, liability_clock);
}

fn history_owner() -> (
    std::sync::Arc<tokio::sync::Semaphore>,
    crate::history_producer::HistoryProducerOwner,
) {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let reservation = crate::QueryFanoutMemoryReservation::from_admitted_fanout(
        semaphore.clone().try_acquire_owned().unwrap(),
        crate::QueryFanoutMemoryEnvelope::for_body_admission(48_000_000).unwrap(),
        1,
    )
    .unwrap();
    let owner =
        crate::history_producer::HistoryProducerOwner::from_reservation(&reservation).unwrap();
    (semaphore, owner)
}

#[tokio::test]
async fn history_response_bytes_keep_query_custody_after_body_and_path_retire() {
    use http_body_util::BodyExt as _;
    let (state, ..) = seeded();
    let cache_budget = iroha_allocation::AllocationBudget::new(1 << 20);
    let mut cache = read::SccpHistoryNodeCache::new();
    for accept in [norito_accept(), json_accept()] {
        let (semaphore, owner) = history_owner();
        let response = history_response(
            &state.view(),
            10,
            &HistoryQuery {
                size: Some("3".into()),
            },
            Some(&accept),
            &HeaderMap::new(),
            &mut cache,
            &cache_budget,
            &owner,
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::ETAG));
        assert_eq!(
            owner.cold_frames().reserved_bytes(),
            0,
            "the projected path has retired after encoding"
        );
        let mut body = response.into_body();
        drop(owner);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let final_slice = bytes.slice(..);
        drop(body);
        drop(bytes);
        assert_eq!(
            semaphore.available_permits(),
            0,
            "extracted last reader still owns the admission"
        );
        assert!(!final_slice.is_empty());
        drop(final_slice);
        assert_eq!(semaphore.available_permits(), 1);
    }
}

#[test]
fn history_query_refuses_retired_or_unknown_fields() {
    assert!(norito::json::from_str::<HistoryQuery>(r#"{"size":"3","attestation":"own"}"#).is_err());
    let valid = norito::json::from_str::<HistoryQuery>(r#"{"size":"3"}"#).unwrap();
    assert_eq!(valid.size.as_deref(), Some("3"));
}

#[tokio::test]
async fn app_history_cache_is_local_reused_and_survives_query_refusal() {
    use std::sync::Arc;
    let mut app = crate::mk_app_state_for_tests();
    let second_app = crate::mk_app_state_for_tests();
    Arc::get_mut(&mut app).unwrap().sccp_history_budget =
        iroha_allocation::AllocationBudget::new(128);
    let cloned = Arc::clone(&app);
    assert!(
        app.sccp_history_budget
            .same_pool(&cloned.sccp_history_budget)
    );
    assert!(
        !app.sccp_history_budget
            .same_pool(&second_app.sccp_history_budget)
    );
    seed(&app.state, |transaction| {
        for height in 1..=64 {
            record_outbound(
                transaction,
                height - 1,
                height,
                SccpOutboundStatusV1::Recorded,
            );
        }
    });
    let original_view = app.state.view();
    let (first_query, owner) = history_owner();
    let original = {
        let mut cache = app.sccp_history.lock().unwrap();
        history_response(
            &original_view,
            1,
            &HistoryQuery::default(),
            Some(&norito_accept()),
            &HeaderMap::new(),
            &mut cache,
            &app.sccp_history_budget,
            &owner,
        )
    };
    assert_eq!(original.status(), StatusCode::OK);
    drop(owner);
    let first: SccpHistoryPathViewV1 = decode(original).await;
    assert_eq!(first_query.available_permits(), 1);
    assert_eq!(app.sccp_history_budget.reserved_bytes(), 128);
    // A new actual query owner reuses the application backing, never the old query pool.
    let (warm_query, warm_owner) = history_owner();
    let warm = {
        let mut cache = cloned.sccp_history.lock().unwrap();
        history_response(
            &original_view,
            1,
            &HistoryQuery::default(),
            Some(&norito_accept()),
            &HeaderMap::new(),
            &mut cache,
            &cloned.sccp_history_budget,
            &warm_owner,
        )
    };
    drop(warm_owner);
    let warm: SccpHistoryPathViewV1 = decode(warm).await;
    assert_eq!(warm, first);
    assert_eq!(warm_query.available_permits(), 1);
    assert_eq!(app.sccp_history_budget.reserved_bytes(), 128);
    assert_eq!(second_app.sccp_history_budget.reserved_bytes(), 0);
    seed(&app.state, |transaction| {
        for height in 65..=128 {
            record_outbound(
                transaction,
                height - 1,
                height,
                SccpOutboundStatusV1::Recorded,
            );
        }
    });
    let (refused_query, refused_owner) = history_owner();
    let refused = {
        let mut cache = app.sccp_history.lock().unwrap();
        history_response(
            &app.state.view(),
            1,
            &HistoryQuery::default(),
            Some(&norito_accept()),
            &HeaderMap::new(),
            &mut cache,
            &app.sccp_history_budget,
            &refused_owner,
        )
    };
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(refused_owner);
    drop(refused);
    assert_eq!(refused_query.available_permits(), 1);
    assert_eq!(app.sccp_history_budget.reserved_bytes(), 128);
    let (_, retry_owner) = history_owner();
    let old = {
        let mut cache = app.sccp_history.lock().unwrap();
        history_response(
            &original_view,
            1,
            &HistoryQuery::default(),
            Some(&norito_accept()),
            &HeaderMap::new(),
            &mut cache,
            &app.sccp_history_budget,
            &retry_owner,
        )
    };
    let old: SccpHistoryPathViewV1 = decode(old).await;
    assert_eq!(
        old, first,
        "refusal preserves the original view and published path"
    );
}

#[tokio::test]
async fn proof_routes_refuse_known_uncertified_records_without_cache_authority() {
    use super::native::{ProofQuery, handler_control_proof, handler_message_proof};
    use crate::finality_interval::RouteExecutionDeadline;
    use axum::{
        Extension,
        extract::{ConnectInfo, Path, State as AppState},
    };
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    let app =
        crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(World::new(), false);
    let current_route = route(&app.state, 3);
    seed(&app.state, |transaction| {
        store::routes::insert(transaction, ETH, current_route).unwrap();
        record_outbound(transaction, 0, 10, SccpOutboundStatusV1::Recorded);
        store::control_messages::insert(
            transaction,
            (ETH, 1, 1),
            SccpControlRecordV1 {
                track: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0,
                height: 10,
                commitment_index: 1,
                leaf: [9; 32],
                certificate_id: [8; 32],
                effect_hash: [5; 32],
            },
        )
        .unwrap();
    });
    let remote = "127.0.0.1:1234".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    for accept in ["application/json", crate::utils::NORITO_MIME_TYPE] {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
        for at in [None, Some("record"), Some("latest"), Some("10")] {
            let query = ProofQuery {
                at: at.map(str::to_owned),
            };
            let message = handler_message_proof(
                AppState(app.clone()),
                Path("01".repeat(32)),
                crate::NoritoStringQuery(query.clone()),
                Extension(RouteExecutionDeadline(deadline)),
                headers.clone(),
                ConnectInfo(remote),
            )
            .await
            .unwrap();
            let control = handler_control_proof(
                AppState(app.clone()),
                Path(("ethereum-mainnet".into(), "1".into(), "1".into())),
                crate::NoritoStringQuery(query),
                Extension(RouteExecutionDeadline(deadline)),
                headers.clone(),
                ConnectInfo(remote),
            )
            .await
            .unwrap();
            for response in [message, control] {
                assert!(!response.headers().contains_key(header::ETAG));
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "private, no-store"
                );
                assert_eq!(
                    error_code(response).await,
                    (StatusCode::SERVICE_UNAVAILABLE, "sccp_unavailable".into())
                );
            }
        }
    }

    // Absence is asserted only against a genuine committed source. An unavailable
    // native tip cannot certify that a record is absent, even when its local map is empty.
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let mut committed = crate::tests_runtime_handlers::mk_app_state_for_tests();
    let fixture = Arc::get_mut(&mut committed).unwrap();
    fixture.state = Arc::clone(chain.state());
    fixture.kura = Arc::clone(chain.kura());
    let deadline = Instant::now() + Duration::from_secs(30);
    for accept in ["application/json", crate::utils::NORITO_MIME_TYPE] {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
        let message = handler_message_proof(
            AppState(committed.clone()),
            Path("99".repeat(32)),
            crate::NoritoStringQuery(ProofQuery::default()),
            Extension(RouteExecutionDeadline(deadline)),
            headers.clone(),
            ConnectInfo(remote),
        )
        .await
        .unwrap();
        let control = handler_control_proof(
            AppState(committed.clone()),
            Path(("ethereum-mainnet".into(), "1".into(), "99".into())),
            crate::NoritoStringQuery(ProofQuery::default()),
            Extension(RouteExecutionDeadline(deadline)),
            headers,
            ConnectInfo(remote),
        )
        .await
        .unwrap();
        for response in [message, control] {
            assert!(!response.headers().contains_key(header::ETAG));
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            assert_eq!(
                error_code(response).await,
                (StatusCode::NOT_FOUND, "sccp_not_found".into())
            );
        }
    }
}

#[tokio::test]
async fn proof_handlers_reject_short_id_and_unknown_network_before_source() {
    use super::native::{ProofQuery, handler_control_proof, handler_message_proof};
    use crate::finality_interval::RouteExecutionDeadline;
    use axum::{
        Extension,
        extract::{ConnectInfo, Path, State as AppState},
    };
    use std::time::{Duration, Instant};
    let app =
        crate::tests_runtime_handlers::app_with_root_scope_for_handler_test(World::new(), false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let remote = "127.0.0.1:1234".parse().unwrap();
    let short_id = handler_message_proof(
        AppState(app.clone()),
        Path("01".into()),
        crate::NoritoStringQuery(ProofQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    let unknown_network = handler_control_proof(
        AppState(app),
        Path(("unknown-network".into(), "1".into(), "1".into())),
        crate::NoritoStringQuery(ProofQuery::default()),
        Extension(RouteExecutionDeadline(deadline)),
        HeaderMap::new(),
        ConnectInfo(remote),
    )
    .await
    .unwrap();
    for response in [short_id, unknown_network] {
        assert!(!response.headers().contains_key(header::ETAG));
        assert_eq!(
            error_code(response).await,
            (StatusCode::BAD_REQUEST, "sccp_invalid_query".into())
        );
    }
}
