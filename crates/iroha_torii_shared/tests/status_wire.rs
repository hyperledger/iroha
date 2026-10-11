//! Named status wire identities and complete payloads captured before DTO extraction.
use iroha_torii_shared::status::*;
use norito::{
    core::{NoritoDeserialize, NoritoSerialize},
    json::{self, JsonDeserialize, JsonSerialize, Value},
};

fn check<T>(name: &str, fixtures: &Value)
where
    T: NoritoSerialize + for<'de> NoritoDeserialize<'de> + JsonSerialize + JsonDeserialize,
{
    let record = fixtures.get(name).expect("named golden record");
    let expected_json = record.get("json").expect("golden JSON");
    let value: T = json::from_value(expected_json.clone()).expect("decode fixture JSON");
    let bytes = hex::decode(
        record
            .get("wire_hex")
            .and_then(Value::as_str)
            .expect("golden frame"),
    )
    .expect("hex frame");
    assert_eq!(
        norito::to_bytes(&value).expect("encode frame"),
        bytes,
        "{name} frame changed"
    );
    assert_eq!(
        hex::encode(norito::schema::identity::frame_hash::<T>()),
        record
            .get("serialize_schema_hash")
            .and_then(Value::as_str)
            .unwrap(),
        "{name} encode schema identity changed"
    );
    assert_eq!(
        hex::encode(norito::schema::identity::frame_hash::<T>()),
        record
            .get("deserialize_schema_hash")
            .and_then(Value::as_str)
            .unwrap(),
        "{name} decode schema identity changed"
    );
    assert_eq!(
        norito::schema::identity::frame_hash::<T>(),
        norito::core::schema_hash_for_name(
            record.get("schema_name").and_then(Value::as_str).unwrap()
        )
    );
    let decoded = norito::from_bytes::<T>(&bytes).expect("decode golden frame");
    let decoded = T::deserialize(decoded);
    assert_eq!(
        json::to_value(&decoded).expect("roundtrip JSON"),
        *expected_json,
        "{name} roundtrip changed"
    );
    assert!(
        norito::from_bytes::<T>(&bytes[..bytes.len() - 1]).is_err(),
        "{name} truncated frame accepted"
    );
}

#[test]
fn named_status_frames_preserve_complete_wire_contract() {
    let fixtures: Value = json::from_json(include_str!(
        "../../../fixtures/torii/status_wire_golden.v1.json"
    ))
    .expect("golden JSON");
    check::<BuildStatus>("BuildStatus", &fixtures);
    check::<CryptoStatus>("CryptoStatus", &fixtures);
    check::<DaReceiptCursorStatus>("DaReceiptCursorStatus", &fixtures);
    check::<GovernanceManifestActivation>("GovernanceManifestActivation", &fixtures);
    check::<GovernanceManifestAdmissionCounters>("GovernanceManifestAdmissionCounters", &fixtures);
    check::<GovernanceManifestQuorumCounters>("GovernanceManifestQuorumCounters", &fixtures);
    check::<GovernanceProposalCounters>("GovernanceProposalCounters", &fixtures);
    check::<GovernanceProtectedNamespaceCounters>(
        "GovernanceProtectedNamespaceCounters",
        &fixtures,
    );
    check::<GovernanceStatus>("GovernanceStatus", &fixtures);
    check::<DiagnosticTraceStatus>("DiagnosticTraceStatus", &fixtures);
    check::<NexusDataspaceCatalogStatus>("NexusDataspaceCatalogStatus", &fixtures);
    check::<NexusDataspaceTeuStatus>("NexusDataspaceTeuStatus", &fixtures);
    check::<NexusLaneManifestValidatorBindingStatus>(
        "NexusLaneManifestValidatorBindingStatus",
        &fixtures,
    );
    check::<NexusLaneRuntimeUpgradeHookStatus>("NexusLaneRuntimeUpgradeHookStatus", &fixtures);
    check::<NexusLaneTeuBuckets>("NexusLaneTeuBuckets", &fixtures);
    check::<NexusLaneTeuDeferrals>("NexusLaneTeuDeferrals", &fixtures);
    check::<NexusLaneTeuStatus>("NexusLaneTeuStatus", &fixtures);
    check::<NexusRoutingMatcherStatus>("NexusRoutingMatcherStatus", &fixtures);
    check::<NexusRoutingPolicyStatus>("NexusRoutingPolicyStatus", &fixtures);
    check::<NexusRoutingRuleStatus>("NexusRoutingRuleStatus", &fixtures);
    check::<NexusStatus>("NexusStatus", &fixtures);
    check::<SchedulerLayerWidthBuckets>("SchedulerLayerWidthBuckets", &fixtures);
    check::<StackStatus>("StackStatus", &fixtures);
    check::<Status>("Status", &fixtures);
    check::<SumeragiConsensusStatus>("SumeragiConsensusStatus", &fixtures);
    check::<TaikaiAliasRotationStatus>("TaikaiAliasRotationStatus", &fixtures);
    check::<TaikaiIngestErrorCounter>("TaikaiIngestErrorCounter", &fixtures);
    check::<TaikaiIngestStatus>("TaikaiIngestStatus", &fixtures);
    check::<TxGossipCaps>("TxGossipCaps", &fixtures);
    check::<TxGossipSnapshot>("TxGossipSnapshot", &fixtures);
    check::<TxGossipStatus>("TxGossipStatus", &fixtures);
    check::<Uptime>("Uptime", &fixtures);
}
