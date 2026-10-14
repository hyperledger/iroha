//! Integration coverage for Torii `SoraNet` privacy ingestion endpoints.
#![cfg(feature = "telemetry")]
use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use iroha_config::parameters::actual::TelemetryProfile;
use iroha_data_model::soranet::privacy_metrics::{
    SoranetPrivacyEventHandshakeSuccessV1, SoranetPrivacyEventKindV1, SoranetPrivacyEventV1,
    SoranetPrivacyModeV1, SoranetPrivacyPrioShareV1,
};
use iroha_torii::{
    MaybeTelemetry, NoritoJson, RecordSoranetPrivacyEventDto, RecordSoranetPrivacyShareDto,
    handle_post_soranet_privacy_event, handle_post_soranet_privacy_share,
};
use norito::json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
async fn norito_json_response_value(response: axum::response::Response) -> Value {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body_bytes = BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    norito::json::from_slice(&body_bytes).unwrap()
}
#[test]
fn privacy_ingress_dtos_reject_unknown_fields() {
    let event = SoranetPrivacyEventV1 {
        timestamp_unix: 1,
        mode: SoranetPrivacyModeV1::Entry,
        kind: SoranetPrivacyEventKindV1::HandshakeSuccess(SoranetPrivacyEventHandshakeSuccessV1 {
            rtt_ms: None,
            active_circuits_after: None,
        }),
    };
    let event_json =
        norito::json::to_string(&norito::json::to_value(&event).expect("serialize privacy event"))
            .expect("render privacy event");
    let event_dto = format!(r#"{{"event":{event_json},"unexpected":true}}"#);
    assert!(
        norito::json::from_str::<RecordSoranetPrivacyEventDto>(&event_dto).is_err(),
        "event DTO must reject unknown fields"
    );

    let share = SoranetPrivacyPrioShareV1::new([1; 32], 0, 60);
    let share_json =
        norito::json::to_string(&norito::json::to_value(&share).expect("serialize privacy share"))
            .expect("render privacy share");
    let share_dto = format!(r#"{{"share":{share_json},"unexpected":true}}"#);
    assert!(
        norito::json::from_str::<RecordSoranetPrivacyShareDto>(&share_dto).is_err(),
        "share DTO must reject unknown fields"
    );
}

#[test]
fn privacy_ingress_dtos_roundtrip_canonical_norito() {
    let event = RecordSoranetPrivacyEventDto {
        event: SoranetPrivacyEventV1 {
            timestamp_unix: 1_720_000_060,
            mode: SoranetPrivacyModeV1::Middle,
            kind: SoranetPrivacyEventKindV1::HandshakeSuccess(
                SoranetPrivacyEventHandshakeSuccessV1 {
                    rtt_ms: Some(120),
                    active_circuits_after: Some(42),
                },
            ),
        },
        source: Some("norito-roundtrip".to_owned()),
    };
    let event_bytes = norito::to_bytes(&event).expect("encode privacy event DTO");
    let decoded_event: RecordSoranetPrivacyEventDto =
        norito::decode_from_bytes(&event_bytes).expect("decode privacy event DTO");
    assert_eq!(decoded_event.event, event.event);
    assert_eq!(decoded_event.source, event.source);

    let share = RecordSoranetPrivacyShareDto {
        share: SoranetPrivacyPrioShareV1::new([0x5a; 32], 1_720_000_020, 60),
        forwarded_by: Some("norito-roundtrip".to_owned()),
    };
    let share_bytes = norito::to_bytes(&share).expect("encode privacy share DTO");
    let decoded_share: RecordSoranetPrivacyShareDto =
        norito::decode_from_bytes(&share_bytes).expect("decode privacy share DTO");
    assert_eq!(decoded_share.share, share.share);
    assert_eq!(decoded_share.forwarded_by, share.forwarded_by);
}
#[tokio::test]
async fn privacy_event_endpoint_rejects_when_disabled() {
    let telemetry = MaybeTelemetry::disabled();
    let event = SoranetPrivacyEventV1 {
        timestamp_unix: 1_720_000_060,
        mode: SoranetPrivacyModeV1::Middle,
        kind: SoranetPrivacyEventKindV1::HandshakeSuccess(SoranetPrivacyEventHandshakeSuccessV1 {
            rtt_ms: Some(120),
            active_circuits_after: Some(42),
        }),
    };
    let dto = RecordSoranetPrivacyEventDto {
        event,
        source: Some("disabled-test".into()),
    };
    let result = handle_post_soranet_privacy_event(telemetry, NoritoJson(dto)).await;
    let err = match result {
        Ok(_) => panic!("disabled telemetry must reject privacy events"),
        Err(err) => err,
    };
    assert_eq!(
        err.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn privacy_event_endpoint_accepts_payload() {
    let telemetry = MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    let event = SoranetPrivacyEventV1 {
        timestamp_unix: timestamp,
        mode: SoranetPrivacyModeV1::Entry,
        kind: SoranetPrivacyEventKindV1::HandshakeSuccess(SoranetPrivacyEventHandshakeSuccessV1 {
            rtt_ms: Some(88),
            active_circuits_after: Some(7),
        }),
    };
    let dto = RecordSoranetPrivacyEventDto {
        event,
        source: None,
    };
    let response = handle_post_soranet_privacy_event(telemetry.clone(), NoritoJson(dto))
        .await
        .unwrap()
        .into_response();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = norito_json_response_value(response).await;
    assert_eq!(body.get("status").and_then(Value::as_str), Some("accepted"));
    let bucket_secs = telemetry
        .telemetry()
        .unwrap()
        .soranet_privacy()
        .config()
        .bucket_secs;
    let bucket_start = (timestamp / bucket_secs) * bucket_secs;
    assert_eq!(
        body.get("bucket_start_unix").and_then(Value::as_u64),
        Some(bucket_start)
    );
}
#[tokio::test]
async fn privacy_event_endpoint_rejects_out_of_window_timestamp() {
    let telemetry = MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let config = telemetry
        .telemetry()
        .expect("test telemetry")
        .soranet_privacy()
        .config();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    let future_timestamp = now_unix.saturating_add(config.bucket_secs.saturating_mul(2));
    let dto = RecordSoranetPrivacyEventDto {
        event: SoranetPrivacyEventV1 {
            timestamp_unix: future_timestamp,
            mode: SoranetPrivacyModeV1::Entry,
            kind: SoranetPrivacyEventKindV1::HandshakeSuccess(
                SoranetPrivacyEventHandshakeSuccessV1 {
                    rtt_ms: None,
                    active_circuits_after: None,
                },
            ),
        },
        source: None,
    };
    let error = match handle_post_soranet_privacy_event(telemetry, NoritoJson(dto)).await {
        Ok(_) => panic!("future privacy event must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn privacy_event_endpoint_rejects_unsafe_source_label() {
    let telemetry = MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    let dto = RecordSoranetPrivacyEventDto {
        event: SoranetPrivacyEventV1 {
            timestamp_unix: timestamp,
            mode: SoranetPrivacyModeV1::Entry,
            kind: SoranetPrivacyEventKindV1::HandshakeSuccess(
                SoranetPrivacyEventHandshakeSuccessV1 {
                    rtt_ms: None,
                    active_circuits_after: None,
                },
            ),
        },
        source: Some("collector\nforged-log-line".to_owned()),
    };
    let error = match handle_post_soranet_privacy_event(telemetry, NoritoJson(dto)).await {
        Ok(_) => panic!("control-bearing source label must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
}
fn make_share(
    collector_id: [u8; 32],
    bucket_start: u64,
    bucket_duration_secs: u32,
    mode: SoranetPrivacyModeV1,
    handshake_share: i64,
) -> SoranetPrivacyPrioShareV1 {
    let mut share =
        SoranetPrivacyPrioShareV1::new(collector_id, bucket_start, bucket_duration_secs);
    share.mode = mode;
    share.handshake_accept_share = handshake_share;
    share.active_circuits_sum_share = 6 * handshake_share;
    share.active_circuits_sample_share = handshake_share;
    share.active_circuits_max_observed = Some(9);
    share.verified_bytes_share = 512;
    share
}
#[tokio::test]
async fn privacy_share_endpoint_combines_shares() {
    let telemetry = MaybeTelemetry::for_tests().with_profile(TelemetryProfile::Full);
    let privacy_config = telemetry.telemetry().unwrap().soranet_privacy().config();
    let bucket_secs =
        u32::try_from(privacy_config.bucket_secs).expect("bucket duration fits within u32");
    let bucket_secs_u64 = u64::from(bucket_secs);
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs();
    let bucket_start = (now_unix / bucket_secs_u64) * bucket_secs_u64;
    let handshake_share = i64::try_from((privacy_config.min_contributors / 2).saturating_add(1))
        .expect("minimum contributor threshold fits within i64");
    let expected_accepted_total =
        u64::try_from(handshake_share).expect("handshake share is non-negative") * 2;
    let mode = SoranetPrivacyModeV1::Middle;
    let share_a = make_share([1; 32], bucket_start, bucket_secs, mode, handshake_share);
    let share_b = make_share([2; 32], bucket_start, bucket_secs, mode, handshake_share);
    let replay = share_a.clone();
    for (share, fwd) in [
        (share_a, Some("collector-a".to_string())),
        (share_b, Some("collector-b".to_string())),
    ] {
        let dto = RecordSoranetPrivacyShareDto {
            share,
            forwarded_by: fwd,
        };
        let response = handle_post_soranet_privacy_share(telemetry.clone(), NoritoJson(dto))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    let replay_error = match handle_post_soranet_privacy_share(
        telemetry.clone(),
        NoritoJson(RecordSoranetPrivacyShareDto {
            share: replay,
            forwarded_by: None,
        }),
    )
    .await
    {
        Ok(_) => panic!("finalized collector bucket replay must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        replay_error.into_response().status(),
        StatusCode::BAD_REQUEST
    );
    let metrics = telemetry.metrics();
    let suppressed = metrics
        .soranet_privacy_bucket_suppressed
        .get_metric_with_label_values(&["middle"])
        .unwrap()
        .get();
    assert!(
        (suppressed - 0.0).abs() < f64::EPSILON,
        "bucket should not be suppressed (value {suppressed})"
    );
    let accepted_total = metrics
        .soranet_privacy_circuit_events_total
        .get_metric_with_label_values(&["middle", "accepted"])
        .unwrap()
        .get();
    assert_eq!(accepted_total, expected_accepted_total);
    let verified_bytes = metrics
        .soranet_privacy_verified_bytes_total
        .get_metric_with_label_values(&["middle"])
        .unwrap()
        .get();
    assert_eq!(verified_bytes, 1024);
    let avg_circuits = metrics
        .soranet_privacy_active_circuits_avg
        .get_metric_with_label_values(&["middle"])
        .unwrap()
        .get();
    assert!(avg_circuits > 0.0);
}
