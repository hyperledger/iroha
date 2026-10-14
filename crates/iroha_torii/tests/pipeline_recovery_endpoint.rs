//! Tests for the pipeline recovery endpoints.
use axum::{Router, routing::get};
use http_body_util::{BodyExt as _, Full};
use iroha_config::parameters::actual::LaneConfig;
use iroha_core::kura::{FastpqProofSnapshot, Kura, PipelineDagSnapshot, PipelineRecoverySidecar};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::block::BlockHeader;
use tower::ServiceExt as _; // for Router::oneshot
#[tokio::test]
async fn recovery_endpoint_serves_sidecar_and_404_on_missing() {
    // Initialize a persistent Kura in a temp dir so sidecars can be written/read
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let (kura, _count) = Kura::new_fresh_single_lane(
        &iroha_config::parameters::actual::Kura {
            init_mode: iroha_config::kura::InitMode::Strict,
            store_dir: iroha_config::base::WithOrigin::inline(
                temp_dir.path().to_str().unwrap().into(),
            ),
            max_disk_usage_bytes: iroha_config::parameters::defaults::kura::MAX_DISK_USAGE_BYTES,
            blocks_in_memory: iroha_config::parameters::defaults::kura::BLOCKS_IN_MEMORY,
            debug_output_new_blocks: false,
            fsync_mode: iroha_config::kura::FsyncMode::Batched,
            fsync_interval: iroha_config::parameters::defaults::kura::FSYNC_INTERVAL,

            native_context_archive_max_bytes:
                iroha_config::parameters::defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
            history_checkpoint_cache_capacity:
                iroha_config::parameters::defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
            block_hash_history_bytes:
                iroha_config::parameters::defaults::kura::BLOCK_HASH_HISTORY_BYTES,
            transaction_history_bytes:
                iroha_config::parameters::defaults::kura::TRANSACTION_HISTORY_BYTES,
            membership_storage: iroha_config::parameters::defaults::kura::MEMBERSHIP_STORAGE_POLICY,
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        },
        &LaneConfig::default(),
    )
    .expect("kura init");
    // Wire only the tested route, mimicking the closure in lib.rs
    let app = Router::new()
        .route(
            "/v1/pipeline/recovery/{height}",
            get({
                let kura = kura.clone();
                move |axum::extract::Path(height): axum::extract::Path<u64>| async move {
                    kura.read_pipeline_metadata(height).map_or_else(
                        || {
                            Err(iroha_torii::Error::Query(
                                iroha_data_model::ValidationFail::QueryFailed(
                                    iroha_data_model::query::error::QueryExecutionFail::NotFound,
                                ),
                            ))
                        },
                        |sidecar| {
                            let json = sidecar.to_json_value();
                            let serialized = norito::json::to_json_pretty(&json)
                                .expect("serialize pipeline metadata");
                            let body = Full::from(serialized.into_bytes());
                            Ok::<_, iroha_torii::Error>(
                                axum::http::Response::builder()
                                    .status(axum::http::StatusCode::OK)
                                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                                    .body(body)
                                    .unwrap(),
                            )
                        },
                    )
                }
            }),
        )
        .route(
            "/v1/pipeline/recovery/{height}/fastpq-proofs",
            get({
                let kura = kura.clone();
                move |axum::extract::Path(height): axum::extract::Path<u64>| async move {
                    let Some(sidecar) = kura.read_pipeline_metadata(height) else {
                        return Err(iroha_torii::Error::Query(
                            iroha_data_model::ValidationFail::QueryFailed(
                                iroha_data_model::query::error::QueryExecutionFail::NotFound,
                            ),
                        ));
                    };
                    let mut root = norito::json::Map::new();
                    root.insert(
                        "height".to_string(),
                        norito::json::to_value(&sidecar.height).expect("serialize height"),
                    );
                    root.insert(
                        "block_hash".to_string(),
                        norito::json::to_value(&sidecar.block_hash.to_string())
                            .expect("serialize block hash"),
                    );
                    root.insert(
                        "proofs".to_string(),
                        norito::json::Value::Array(
                            sidecar
                                .fastpq_proofs
                                .iter()
                                .map(FastpqProofSnapshot::to_json_value)
                                .collect(),
                        ),
                    );
                    let serialized =
                        norito::json::to_json_pretty(&norito::json::Value::Object(root))
                            .expect("serialize FASTPQ proofs");
                    let body = Full::from(serialized.into_bytes());
                    Ok::<_, iroha_torii::Error>(
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header(axum::http::header::CONTENT_TYPE, "application/json")
                            .body(body)
                            .unwrap(),
                    )
                }
            }),
        );
    // Prepare a sidecar for height=1
    let mut fingerprint = [0u8; 32];
    fingerprint[..3].copy_from_slice(&[0xAB, 0xCD, 0xEF]);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xAA; 32]));
    let block_hash_str = block_hash.to_string();
    let sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint,
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    // Query existing height
    let req_ok = http::Request::builder()
        .method("GET")
        .uri("/v1/pipeline/recovery/1")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_ok = app.clone().oneshot(req_ok).await.unwrap();
    assert_eq!(resp_ok.status(), http::StatusCode::OK);
    let resp_body = resp_ok.into_body().collect().await.unwrap().to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&resp_body).unwrap();
    assert_eq!(
        v.get("format").and_then(|x| x.as_str()),
        Some("pipeline.recovery")
    );
    assert_eq!(
        v.get("block_hash").and_then(|x| x.as_str()),
        Some(block_hash_str.as_str())
    );
    let req_fastpq_empty = http::Request::builder()
        .method("GET")
        .uri("/v1/pipeline/recovery/1/fastpq-proofs")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_fastpq_empty = app.clone().oneshot(req_fastpq_empty).await.unwrap();
    assert_eq!(resp_fastpq_empty.status(), http::StatusCode::OK);
    let resp_body = resp_fastpq_empty
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&resp_body).unwrap();
    assert_eq!(v.get("proofs").and_then(|x| x.as_array()).unwrap().len(), 0);
    let proof = b"fastpq-proof".to_vec();
    let mut sidecar_with_proof = sidecar;
    sidecar_with_proof.fastpq_proofs.push(FastpqProofSnapshot {
        height: 1,
        block_hash,
        entry_hash: Hash::prehashed([0x11; 32]),
        batch_index: 0,
        transition_count: 0,
        public_inputs: iroha_data_model::fastpq::FastpqPublicInputs {
            dsid: [0; 16],
            slot: 0,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
            tx_set_hash: [0; 32],
        },
        ordering_hash: [0; 32],
        artifact_identity: iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1 {
            proof_kind: iroha_data_model::fastpq::FastpqProofKindV1::OrdinaryCompact,
            profile_id: fastpq_prover::offline_compact::quantity_profile_id(),
            public_statement_digest: Hash::new(b"recovery statement").into(),
            artifact_digest: Hash::new(&proof).into(),
            inner_bundle_digest: Hash::new(b"recovery inner bundle").into(),
            artifact_bytes: proof.len() as u64,
            commitments: iroha_data_model::fastpq::FastpqCommitmentDescriptionV1::OrderedCompactAir(
                iroha_data_model::fastpq::FastpqOrderedCompactAirCommitmentsV1 {
                    segment_count: 1,
                    segment_air_row_roots: vec![
                        iroha_data_model::fastpq::FastpqCommitmentV1::from_bytes([0x41; 32]),
                    ],
                },
            ),
        },
    });
    kura.write_pipeline_metadata(&sidecar_with_proof);
    let req_fastpq_populated = http::Request::builder()
        .method("GET")
        .uri("/v1/pipeline/recovery/1/fastpq-proofs")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_fastpq_populated = app.clone().oneshot(req_fastpq_populated).await.unwrap();
    assert_eq!(resp_fastpq_populated.status(), http::StatusCode::OK);
    let resp_body = resp_fastpq_populated
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let v: norito::json::Value = norito::json::from_slice(&resp_body).unwrap();
    let proofs = v.get("proofs").and_then(|x| x.as_array()).unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(
        proofs[0].get("profile_id").and_then(|x| x.as_str()),
        Some(hex::encode(fastpq_prover::offline_compact::quantity_profile_id().0).as_str())
    );
    // Query missing height
    let req_missing = http::Request::builder()
        .method("GET")
        .uri("/v1/pipeline/recovery/2")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_missing = app.clone().oneshot(req_missing).await.unwrap();
    assert_eq!(resp_missing.status(), http::StatusCode::NOT_FOUND);
    let req_fastpq_missing = http::Request::builder()
        .method("GET")
        .uri("/v1/pipeline/recovery/2/fastpq-proofs")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_fastpq_missing = app.clone().oneshot(req_fastpq_missing).await.unwrap();
    assert_eq!(resp_fastpq_missing.status(), http::StatusCode::NOT_FOUND);
}
