#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Telemetry-enabled tests for the sumeragi evidence list endpoint.
#![cfg(feature = "telemetry")]
use super::sumeragi_evidence::{make_phase_vote_attribution, make_phase_vote_evidence};
use axum::{extract::State, http::header};
use http_body_util::BodyExt as _;
use iroha_core::{
    kura::Kura,
    query::{insert_evidence_record_for_test, store::LiveQueryStore},
    state::{State as CoreState, World},
    telemetry::StateTelemetry,
};
use iroha_data_model::block::consensus::{
    EvidencePenaltyStatus, EvidenceRecord, RecordedEvidenceV1,
};
use iroha_torii::{Error, EvidenceListQuery, NoritoQuery, handle_v1_sumeragi_evidence_list};
use std::sync::Arc;
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn evidence_list_endpoint_supports_filters_and_pagination() {
    let kura = Arc::new(Kura::blank_kura_for_testing());
    let query = LiveQueryStore::start_test();
    let state = CoreState::with_telemetry(
        World::default(),
        Arc::clone(&kura),
        query,
        StateTelemetry::default(),
    );
    let mut state = state;
    let records = [
        EvidenceRecord {
            evidence: RecordedEvidenceV1::Native(make_phase_vote_evidence(10, 0xA1)),
            attribution: make_phase_vote_attribution(10, 0xA1),
            recorded_at_height: 1,
            recorded_at_view: 0,
            recorded_at_ms: 10,
            penalty_status: EvidencePenaltyStatus::Pending,
        },
        EvidenceRecord {
            evidence: RecordedEvidenceV1::Native(make_phase_vote_evidence(20, 0xB2)),
            attribution: make_phase_vote_attribution(20, 0xB2),
            recorded_at_height: 2,
            recorded_at_view: 0,
            recorded_at_ms: 20,
            penalty_status: EvidencePenaltyStatus::Applied { height: 4 },
        },
        EvidenceRecord {
            evidence: RecordedEvidenceV1::Native(make_phase_vote_evidence(30, 0xC3)),
            attribution: make_phase_vote_attribution(30, 0xC3),
            recorded_at_height: 3,
            recorded_at_view: 0,
            recorded_at_ms: 30,
            penalty_status: EvidencePenaltyStatus::Applied { height: 5 },
        },
    ];
    for record in records {
        insert_evidence_record_for_test(&mut state, record);
    }
    let state = Arc::new(state);
    let query_all = EvidenceListQuery {
        limit: Some(3),
        offset: Some(0),
        kind: None,
    };
    let response = handle_v1_sumeragi_evidence_list(
        State(state.clone()),
        NoritoQuery(query_all),
        Some(axum::http::HeaderValue::from_static("application/json")),
    )
    .await
    .expect("handler returns OK");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let json: norito::json::Value = norito::json::from_slice(&body).expect("parse json");
    let response_object = json.as_object().expect("evidence list response object");
    assert_eq!(response_object.len(), 2);
    for key in ["total", "items"] {
        assert!(
            response_object.contains_key(key),
            "evidence list response must contain `{key}`"
        );
    }
    assert_eq!(
        json.get("total").and_then(norito::json::Value::as_u64),
        Some(3)
    );
    let items = json
        .get("items")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .expect("array of items");
    assert_eq!(items.len(), 3);
    let expected_statuses = [
        norito::json!({
            "status": "applied",
            "details": { "height": 5 }
        }),
        norito::json!({
            "status": "applied",
            "details": { "height": 4 }
        }),
        norito::json!({
            "status": "pending",
            "details": null
        }),
    ];
    for ((item, expected_status), expected_admission_height) in items
        .iter()
        .zip(expected_statuses.iter())
        .zip([3_u64, 2, 1])
    {
        assert_eq!(
            item.get("kind").and_then(norito::json::Value::as_str),
            Some("NativeSumeragiEvidence")
        );
        assert_eq!(
            item.as_object().unwrap().len(),
            2,
            "closed kind/value envelope"
        );
        let item = item.get("value").expect("native audit payload");
        assert_eq!(item["scope"]["kind"].as_str(), Some("root"));
        assert_eq!(item.get("penalty_status"), Some(expected_status));
        assert_eq!(
            item.get("consensus_admitted_height")
                .and_then(norito::json::Value::as_u64),
            Some(expected_admission_height)
        );
        let item = item.as_object().expect("evidence audit object");
        let expected_keys = [
            "scope",
            "class",
            "instance",
            "height",
            "epoch",
            "context_id",
            "authority_generation",
            "offenders",
            "safety_violation",
            "native_frame_hash",
            "recorded_height",
            "recorded_view",
            "recorded_ms",
            "consensus_admitted_height",
            "penalty_status",
        ];
        assert_eq!(item.len(), expected_keys.len());
        for key in expected_keys {
            assert!(item.contains_key(key), "evidence item must contain `{key}`");
        }
        for retired in [
            "view",
            "signer",
            "artifact_hash_1",
            "artifact_hash_2",
            "penalty_applied",
            "penalty_cancelled",
            "penalty_cancelled_at_height",
            "penalty_applied_at_height",
            "consensus_admitted_at_height",
        ] {
            assert!(
                !item.contains_key(retired),
                "retired evidence field `{retired}` must remain absent"
            );
        }
    }
    let query_filtered = EvidenceListQuery {
        limit: Some(1),
        offset: Some(1),
        kind: Some("NativeSumeragiEvidence".to_string()),
    };
    let response_filtered = handle_v1_sumeragi_evidence_list(
        State(state.clone()),
        NoritoQuery(query_filtered),
        Some(axum::http::HeaderValue::from_static("application/json")),
    )
    .await
    .expect("handler returns OK");
    assert_eq!(
        response_filtered
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_filtered = response_filtered
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let json_filtered: norito::json::Value =
        norito::json::from_slice(&body_filtered).expect("parse json");
    assert_eq!(
        json_filtered
            .get("total")
            .and_then(norito::json::Value::as_u64),
        Some(3)
    );
    let filtered_items = json_filtered
        .get("items")
        .and_then(norito::json::Value::as_array)
        .cloned()
        .expect("items array");
    assert_eq!(filtered_items.len(), 1);
    assert_eq!(
        filtered_items[0]["value"]
            .get("class")
            .and_then(norito::json::Value::as_str),
        Some("phase_vote"),
    );
    for kind in ["NativeSumeragiEvidence", "SccpForgeryEvidence"] {
        let query = EvidenceListQuery {
            limit: None,
            offset: None,
            kind: Some(kind.to_owned()),
        };
        assert!(
            handle_v1_sumeragi_evidence_list(State(state.clone()), NoritoQuery(query), None)
                .await
                .is_ok(),
            "canonical evidence kind `{kind}` must be accepted"
        );
    }
    // Unsupported SCCP retention never makes an explicit SCCP filter return Native DATA.
    for accept in ["application/json", "application/x-norito"] {
        let response = handle_v1_sumeragi_evidence_list(
            State(state.clone()),
            NoritoQuery(EvidenceListQuery {
                limit: Some(3),
                offset: Some(0),
                kind: Some("SccpForgeryEvidence".into()),
            }),
            Some(axum::http::HeaderValue::from_static(accept)),
        )
        .await
        .expect("explicit empty SCCP selection");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if accept == "application/json" {
            let value: norito::json::Value = norito::json::from_slice(&bytes).unwrap();
            assert_eq!(value["total"].as_u64(), Some(0));
            assert!(value["items"].as_array().unwrap().is_empty());
        } else {
            let value: iroha_torii_shared::sumeragi_evidence_api::SumeragiEvidenceListWireResponse =
                norito::decode_from_bytes(&bytes).unwrap();
            assert_eq!(value.total, 0);
            assert!(value.items.is_empty());
        }
    }
    for kind in [
        "DoublePrevote",
        "DoublePrecommit",
        "DoublePrepare",
        "DoubleCommit",
        "InvalidQc",
        "InvalidProposal",
        "Censorship",
        "InvalidQC",
        "doubleprepare",
        " InvalidQc",
        "InvalidQc ",
        "null",
        "NULL",
        "",
        "Unknown",
    ] {
        let query = EvidenceListQuery {
            limit: None,
            offset: None,
            kind: Some(kind.to_owned()),
        };
        let result =
            handle_v1_sumeragi_evidence_list(State(state.clone()), NoritoQuery(query), None).await;
        let Err(Error::AppQueryValidation { code, message }) = result else {
            panic!("noncanonical evidence kind `{kind}` must fail closed");
        };
        assert_eq!(code, "sumeragi_evidence_kind_invalid");
        assert!(message.contains(kind));
    }
}
