#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration test for /v1/proofs/query (signed core query wrapper).
#![cfg(feature = "app_api")]
use axum::{Router, routing::post};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    NetworkId, Registrable,
    block::BlockHeader,
    proof::{ProofId, ProofRecord, ProofStatus, VerifyingKeyId},
    query::{QueryRequest, prelude::SingularQueryBox, proof::prelude::FindProofRecordById},
};
use iroha_torii::QueryOptions;
use iroha_version::codec::EncodeVersioned as _;
use mv::storage::StorageReadOnly;
use norito::json;
use std::{
    collections::BTreeSet,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt as _;
fn checked_proof_query_authority_fixture() -> iroha_crypto::KeyPair {
    iroha_crypto::KeyPair::try_random()
        .expect("generate checked ZK proof query authority fixture keypair")
}
#[test]
fn proof_query_authority_fixture_uses_checked_ed25519_key_generation() {
    let key_pair = checked_proof_query_authority_fixture();
    let algorithm = key_pair
        .public_key()
        .try_algorithm()
        .expect("fixture proof query public key has a valid algorithm");
    assert_eq!(algorithm, iroha_crypto::Algorithm::Ed25519);
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn proofs_query_find_by_id_returns_norito() {
    let backend = "pipa-r/pasta";
    let proof_hash = [0xAA; 32];
    // The signed proof query requires a registered authority with ledger-read permission.
    let key_pair = checked_proof_query_authority_fixture();
    let domain_name = "wonderland";
    let domain_id = iroha_model_base::domain::DomainId::try_new(domain_name, "universal").unwrap();
    let authority = iroha_data_model::account::AccountId::new(key_pair.public_key().clone());
    let domain = iroha_data_model::domain::Domain::new(domain_id.clone()).build(&authority);
    let account = iroha_data_model::account::Account::new(authority.clone()).build(&authority);
    let mut world = World::with(
        [domain],
        [account],
        std::iter::empty::<iroha_data_model::asset::definition::AssetDefinition>(),
    );
    world.account_permissions_mut_for_testing().insert(
        authority.clone(),
        BTreeSet::from([iroha_executor_data_model::permission::query::CanReadAllLedgerData.into()]),
    );
    // Minimal state and live query store
    let kura = Kura::blank_kura_for_testing();
    let live = LiveQueryStore::start_test();
    let live_for_route = live.clone();
    let state = State::new_for_testing(world, kura, live);
    let mut state = state;
    // Seed one proof record
    let id = ProofId {
        backend: backend.into(),
        proof_hash,
    };
    let proof_id = id.clone();
    let rec = ProofRecord {
        id: id.clone(),
        vk_ref: Some(VerifyingKeyId::new("pipa-r/pasta", "vk_test")),
        vk_commitment: None,
        status: ProofStatus::Verified,
        verified_at_height: Some(1),
        bridge: None,
    };
    iroha_core::query::insert_proof_record_for_test(&mut state, id, rec);
    {
        let view = state.view();
        assert!(
            view.world().proofs().get(&proof_id).is_some(),
            "proof record not inserted"
        );
    }
    let state = Arc::new(state);
    let network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA5; iroha_crypto::Hash::LENGTH]),
        ));
    let signed_query_admission = Arc::new(
        iroha_torii::SignedQueryAdmission::new(
            network_id,
            Duration::from_secs(1),
            Duration::from_secs(120),
            NonZeroUsize::new(16).expect("nonzero replay capacity"),
        )
        .expect("valid signed-query admission"),
    );
    #[cfg(feature = "telemetry")]
    let tel = iroha_torii::MaybeTelemetry::for_tests();
    #[cfg(not(feature = "telemetry"))]
    let tel = iroha_torii::MaybeTelemetry::for_tests();
    let app = Router::new().route(
        "/v1/proofs/query",
        post({
            let state = state.clone();
            let signed_query_admission = Arc::clone(&signed_query_admission);
            move |iroha_torii::NoritoJson(dto): iroha_torii::NoritoJson<
                iroha_torii::ProofFindByIdQueryDto,
            >| async move {
                let signed = iroha_torii::signed_find_proof_by_id(&dto)?;
                iroha_torii::handle_queries_with_opts(
                    live_for_route.clone(),
                    state,
                    signed_query_admission,
                    signed,
                    tel,
                    iroha_torii::NoritoQuery(QueryOptions::default()),
                    iroha_torii::ResponseFormat::Norito,
                )
                .await
            }
        }),
    );
    let signed_query =
        QueryRequest::Singular(SingularQueryBox::FindProofRecordById(FindProofRecordById {
            id: proof_id.clone(),
        }))
        .with_authority(
            network_id,
            authority,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock follows Unix epoch")
                .as_millis()
                .try_into()
                .expect("query creation time fits u64"),
            NonZeroU64::new(100_000).expect("nonzero query TTL"),
            [0x51; 32],
        )
        .try_sign(&key_pair)
        .expect("sign proof query locally");
    let dto = iroha_torii::json_object(vec![iroha_torii::json_entry(
        "signed_query_b64",
        base64::engine::general_purpose::STANDARD.encode(signed_query.encode_versioned()),
    )]);
    let body = json::to_vec(&dto).unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/proofs/query")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        http::StatusCode::OK,
        "unexpected status {status} body={}",
        String::from_utf8_lossy(&bytes)
    );
    assert!(ct.contains("application/x-norito"), "content-type: {ct}");
    // Body should be non-empty Norito payload
    assert!(!bytes.is_empty());
}
