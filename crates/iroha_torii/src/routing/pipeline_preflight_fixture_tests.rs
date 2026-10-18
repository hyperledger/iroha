//! Golden JSON body of `GET /v1/pipeline/preflight`, shared by the SDK preflight parsers.
//!
//! `fixtures/torii/pipeline_preflight.json` is the body Torii serves for the
//! [`PipelinePreflightResponse`] built here, encoded through the handler's own JSON response
//! path. The JavaScript, Python and Swift SDK tests parse that file, so a change to the served
//! field set fails here before an SDK silently drifts from the node. After an intentional DTO
//! change, regenerate the file with
//! `UPDATE_FIXTURES=1 cargo test -p iroha_torii --lib pipeline_preflight_fixture`
//! and update every SDK preflight parser to the new contract.
use std::path::PathBuf;

use axum::http::{StatusCode, header};
use iroha_crypto::Algorithm;
use iroha_data_model::account::AccountId;
use norito::json::Value;

use super::{
    PipelinePreflightAdmission, PipelinePreflightBlock, PipelinePreflightFees,
    PipelinePreflightPipeline, PipelinePreflightQueue, PipelinePreflightResponse,
    PipelinePreflightSumeragi, checked_routing_fixture_keypair,
};

/// Repository-relative path of the shared SDK fixture.
const FIXTURE_PATH: &str = "fixtures/torii/pipeline_preflight.json";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FIXTURE_PATH)
}

fn fixture_account(seed: u8) -> String {
    let key_pair = checked_routing_fixture_keypair(
        seed,
        Algorithm::Ed25519,
        "pipeline preflight fixture account key",
    );
    AccountId::new(key_pair.public_key().clone())
        .canonical_i105()
        .expect("fixture account must encode as canonical I105")
}

fn quantity(literal: &str) -> iroha_primitives::numeric::Quantity {
    literal.parse().expect("canonical fixture fee quantity")
}

/// Every numeric field carries a distinct value so SDK tests detect swapped field mappings.
fn sample_response() -> PipelinePreflightResponse {
    PipelinePreflightResponse {
        schema_version: 1,
        chain_height: 42,
        sumeragi: PipelinePreflightSumeragi {
            block_cadence_ms: 1_000,
        },
        admission: PipelinePreflightAdmission {
            max_signatures: 16,
            max_instructions: 4_096,
            max_tx_bytes: 1_048_576,
            max_decompressed_bytes: 4_194_304,
            max_metadata_depth: 8,
        },
        block: PipelinePreflightBlock {
            max_transactions: 512,
        },
        pipeline: PipelinePreflightPipeline {
            signature_batch_max_ed25519: 64,
            signature_batch_max_secp256k1: 32,
            signature_batch_max_pqc: 12,
            signature_batch_max_bls: 24,
            overlay_max_instructions: 2_048,
            ivm_max_cycles_upper_bound: 2_000_000,
            ivm_admission_cycle_limit: 1_000_000,
            ivm_max_decoded_instructions: 131_072,
        },
        queue: PipelinePreflightQueue {
            size: 3,
            queued: 2,
            inflight: 1,
        },
        fees: PipelinePreflightFees {
            fee_asset_id: iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
            fee_sink_account_id: fixture_account(0x51),
            base_fee: quantity("0.1"),
            per_byte_fee: quantity("0.0002"),
            per_instruction_fee: quantity("0.001"),
            per_gas_unit_fee: quantity("0.00005"),
            sponsor_vault_custody_account_id: fixture_account(0x52),
            successful_claim_fee_exempt_authorities: vec![fixture_account(0x53)],
        },
    }
}

/// Encode the sample exactly as `handler_pipeline_preflight` answers a JSON request.
async fn served_json_body() -> Vec<u8> {
    let response =
        crate::utils::respond_with_format(sample_response(), crate::utils::ResponseFormat::Json);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read served preflight body")
        .to_vec()
}

fn parse_value(bytes: &[u8], context: &str) -> Value {
    let text = std::str::from_utf8(bytes).expect("preflight JSON is UTF-8");
    norito::json::from_json(text).unwrap_or_else(|error| panic!("{context}: {error}"))
}

#[tokio::test]
async fn pipeline_preflight_fixture_matches_the_served_json_body() {
    let served = served_json_body().await;
    let mut expected_text =
        norito::json::to_json_pretty(&sample_response()).expect("pretty preflight JSON");
    expected_text.push('\n');
    let path = fixture_path();
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &expected_text).expect("write pipeline preflight fixture");
        panic!(
            "fixture updated: {}. Re-run tests without UPDATE_FIXTURES to verify.",
            path.display()
        );
    }
    let fixture = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; generate it with UPDATE_FIXTURES=1",
            path.display()
        )
    });
    assert_eq!(
        parse_value(fixture.as_bytes(), "fixture JSON"),
        parse_value(&served, "served JSON"),
        "{FIXTURE_PATH} no longer matches the served preflight body; regenerate it with \
         UPDATE_FIXTURES=1 and update the SDK preflight parsers"
    );
    assert_eq!(
        fixture, expected_text,
        "{FIXTURE_PATH} must keep the canonical pretty encoding"
    );
}

#[tokio::test]
async fn pipeline_preflight_fixture_decodes_into_the_served_dto() {
    let fixture = std::fs::read_to_string(fixture_path()).expect("read preflight fixture");
    let decoded: PipelinePreflightResponse =
        norito::json::from_json(&fixture).expect("fixture decodes into the preflight DTO");
    assert_eq!(decoded.sumeragi.block_cadence_ms, 1_000);
    let reencoded = norito::json::to_json(&decoded).expect("re-encode preflight DTO");
    assert_eq!(
        parse_value(reencoded.as_bytes(), "re-encoded JSON"),
        parse_value(&served_json_body().await, "served JSON"),
        "the fixture must round-trip through the DTO to the served body"
    );
}
