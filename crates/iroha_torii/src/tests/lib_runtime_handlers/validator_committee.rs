// Actual native finality committee status transport and closed public codecs.

fn native_committee_status_app(
    height: u64,
) -> (
    SharedAppState,
    iroha_data_model::sumeragi::finality::NativeFinalityArtifact,
) {
    use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::sumeragi::finality::{NativeFinalityArtifact, NativeFinalityLimits};
    let mut chain =
        CertifiedTestChain::start(TestChainConfig::new(iroha_core::state::World::default(), 1))
            .expect("actual genesis");
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    let block = chain.committed(height);
    let artifact = NativeFinalityArtifact::from_block(
        block.block(),
        NativeFinalityLimits {
            block_bytes: 32 * 1024 * 1024,
            journal_bytes: 64 * 1024 * 1024,
            block_count: 256,
            allocated_bytes: 128 * 1024 * 1024,
        },
    )
    .expect("bounded native source");
    let mut app = mk_app_state_for_tests();
    let app_mut = Arc::get_mut(&mut app).expect("unique test app");
    app_mut.state = chain.state().clone();
    app_mut.kura = chain.kura().clone();
    (app, artifact)
}

#[tokio::test]
async fn validator_committee_status_serves_exact_finality_and_closed_queries() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    use iroha_data_model::nexus::ValidatorCommitteeStatusV1;
    let (app, artifact) = native_committee_status_app(2);
    assert!(
        artifact.block_wire.len() > 1_024,
        "fixture must exceed the ordinary ID source cap"
    );
    let network_id = *app.state.network_id_ref();
    let peer = "127.0.0.1:12345".parse().unwrap();
    for accept in ["application/x-norito", "application/json"] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::ACCEPT, accept.parse().unwrap());
        let available = app.query_fanout_inflight.available_permits();
        let response = handler_validator_committee_status(
            State(app.clone()),
            crate::NoritoQuery(CommitteeStatusQuery { target_epoch: None }),
            headers,
            axum::extract::ConnectInfo(peer),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(
            app.query_fanout_inflight.available_permits() < available,
            "the response retains its admitted memory through body delivery"
        );
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert!(
            app.query_fanout_inflight.available_permits() < available,
            "collected bytes still retain the original response memory"
        );
        let status: ValidatorCommitteeStatusV1 = if accept == "application/x-norito" {
            norito::decode_from_bytes(&body).unwrap()
        } else {
            norito::json::from_slice(&body).unwrap()
        };
        assert_eq!(status.target_epoch, 1);
        assert_eq!(status.latest_finality, artifact);
        assert_eq!(status.network_id, network_id);
        assert_eq!(status.selected, None);
        assert_eq!(status.pending_beacon_session, None);
        let retained = body.clone();
        drop(body);
        assert!(
            app.query_fanout_inflight.available_permits() < available,
            "the last byte clone owns the original reservation"
        );
        drop(retained);
        assert_eq!(app.query_fanout_inflight.available_permits(), available);
    }
    for query in [
        "unknown=2",
        "target_epoch=-1",
        "target_epoch=2&target_epoch=3",
    ] {
        use axum::extract::FromRequestParts as _;
        let (mut parts, _) = axum::http::Request::builder()
            .uri(format!("/v1/nexus/validator-committee?{query}"))
            .body(())
            .unwrap()
            .into_parts();
        assert!(
            crate::NoritoQuery::<CommitteeStatusQuery>::from_request_parts(&mut parts, &())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn validator_committee_status_refuses_exhausted_memory_before_reading_state() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    // This State has no certified history: a read before capacity admission
    // would return an unavailable/error response instead of the capacity refusal.
    let app = mk_app_state_for_tests();
    let available = app.query_fanout_inflight.available_permits();
    let held = app
        .query_fanout_inflight
        .semaphore
        .clone()
        .try_acquire_many_owned(u32::try_from(available).unwrap())
        .unwrap();
    let response = handler_validator_committee_status(
        State(app.clone()),
        crate::NoritoQuery(CommitteeStatusQuery {
            target_epoch: Some(2),
        }),
        axum::http::HeaderMap::from_iter([(
            axum::http::header::ACCEPT,
            "application/x-norito".parse().unwrap(),
        )]),
        axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    drop(response);
    drop(held);
    assert_eq!(app.query_fanout_inflight.available_permits(), available);
}

#[tokio::test]
async fn validator_committee_status_reads_recent_finality_without_genesis_length_growth() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    use iroha_data_model::nexus::ValidatorCommitteeStatusV1;
    let (app, artifact) = native_committee_status_app(32);
    let response = handler_validator_committee_status(
        State(app),
        crate::NoritoQuery(CommitteeStatusQuery { target_epoch: None }),
        axum::http::HeaderMap::from_iter([(
            axum::http::header::ACCEPT,
            "application/x-norito".parse().unwrap(),
        )]),
        axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
    )
    .await
    .expect("recent original execution must fit the unchanged default query reservation");
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let status: ValidatorCommitteeStatusV1 = norito::decode_from_bytes(&body).unwrap();
    assert_eq!(status.latest_finality, artifact);
}

#[tokio::test]
async fn validator_committee_status_verifies_boundary_with_original_state_authority() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    use iroha_core::sumeragi::test_chain::CertifiedTestChain;
    use iroha_data_model::{
        nexus::ValidatorCommitteeStatusV1, sumeragi::finality::NativeFinalityLimits,
    };
    let mut chain = CertifiedTestChain::npos_boundary_fixture();
    chain.commit(Vec::new());
    let mut app = mk_app_state_for_tests();
    let app_mut = Arc::get_mut(&mut app).unwrap();
    app_mut.state = chain.state().clone();
    app_mut.kura = chain.kura().clone();
    let response = handler_validator_committee_status(
        State(app),
        crate::NoritoQuery(CommitteeStatusQuery {
            target_epoch: Some(2),
        }),
        axum::http::HeaderMap::from_iter([(
            axum::http::header::ACCEPT,
            "application/x-norito".parse().unwrap(),
        )]),
        axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let status: ValidatorCommitteeStatusV1 = norito::decode_from_bytes(&body).unwrap();
    let block = status
        .latest_finality
        .decode_block(NativeFinalityLimits {
            block_bytes: 32 * 1024 * 1024,
            journal_bytes: 64 * 1024 * 1024,
            block_count: 256,
            allocated_bytes: 128 * 1024 * 1024,
        })
        .unwrap();
    assert_eq!(
        block.encode_wire().unwrap(),
        chain.committed(10).block().encode_wire().unwrap()
    );
    assert_eq!(status.target_epoch, 2);
}

#[tokio::test]
async fn validator_committee_status_rejects_missing_committed_finality() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    let app = mk_app_state_for_tests();
    let block = make_empty_signed_block(1, None, 1);
    let header = block.header();
    let hash = store_block(&app, block);
    record_committed_block_hash_for_test(&app, header, hash);
    let result = handler_validator_committee_status(
        State(app),
        crate::NoritoQuery(CommitteeStatusQuery {
            target_epoch: Some(1),
        }),
        axum::http::HeaderMap::from_iter([(
            axum::http::header::ACCEPT,
            "application/x-norito".parse().unwrap(),
        )]),
        axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
    )
    .await;
    assert!(
        result.is_err(),
        "raw committed State without exact durable finality is not status proof"
    );
}

#[tokio::test]
async fn signed_genesis_body_alone_does_not_authorize_committee_status_result() {
    use crate::validator_committee::{CommitteeStatusQuery, handler_validator_committee_status};
    let (app, _) = native_committee_status_app(1);
    assert!(
        handler_validator_committee_status(
            State(app),
            crate::NoritoQuery(CommitteeStatusQuery { target_epoch: None }),
            axum::http::HeaderMap::new(),
            axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        )
        .await
        .is_err()
    );
}

#[test]
fn validator_committee_status_native_source_roundtrips_with_required_fields() {
    use iroha_data_model::nexus::ValidatorCommitteeStatusV1;
    let (app, artifact) = native_committee_status_app(2);
    let status = ValidatorCommitteeStatusV1 {
        network_id: *app.state.network_id_ref(),
        target_epoch: 1,
        latest_finality: artifact,
        selected: None,
        pending_beacon_session: None,
    };
    let binary = norito::to_bytes(&status).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<ValidatorCommitteeStatusV1>(&binary).unwrap(),
        status
    );
    let json = norito::json::to_vec(&status).unwrap();
    assert_eq!(
        norito::json::from_slice::<ValidatorCommitteeStatusV1>(&json).unwrap(),
        status
    );
    let mut missing = norito::json::to_value(&status).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("pending_beacon_session");
    assert!(norito::json::from_value::<ValidatorCommitteeStatusV1>(missing).is_err());
    // The exact selecting-boundary mutation suite now exercises the shared production
    // validator in Core against a genuine signed 14-block native/beacon prefix.
    // TODO: qualify a positive NPoS selected-state response on the real 4→7→4 network.
}
