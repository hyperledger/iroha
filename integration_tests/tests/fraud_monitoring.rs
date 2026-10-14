//! Integration coverage for fraud monitoring admission policy using mocked assessments.
use eyre::{Report, Result};
use integration_tests::sandbox;
use iroha::data_model::{
    Level,
    fraud::{FraudAdmissionPolicyV1, FraudRiskBandV1},
    prelude::*,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_network::NetworkBuilder;
use std::str::FromStr;
use toml::Value as TomlValue;
fn error_chain(err: &Report) -> Vec<String> {
    err.chain().map(ToString::to_string).collect()
}
#[test]
fn fraud_monitoring_requires_assessment_bands() -> Result<()> {
    let context = stringify!(fraud_monitoring_requires_assessment_bands);
    let policy = FraudAdmissionPolicyV1 {
        enabled: true,
        required_minimum_band: Some(FraudRiskBandV1::High),
        missing_assessment_permitted: false,
        ..FraudAdmissionPolicyV1::protocol_default()
    };
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            policy.into_custom_parameter(),
        )))
        .with_config_layer(|layer| {
            layer.write(
                ["fraud_monitoring", "service_endpoints"],
                TomlValue::Array(vec![TomlValue::String(
                    "https://mocked.assessor.test/api".to_string(),
                )]),
            );
        });
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(builder, context)? else {
        return Ok(());
    };
    let client = network.client();
    let indicator = Name::from_str("fraud_assessment_band").expect("static metadata key");
    let score_key = Name::from_str("fraud_assessment_score_bps").expect("static score key");
    let tenant_key = Name::from_str("fraud_assessment_tenant").expect("static tenant key");
    let latency_key = Name::from_str("fraud_assessment_latency_ms").expect("static latency key");
    let message = "fraud-monitor integration".to_string();
    let missing_err = client
        .submit_with_metadata(
            Log::new(Level::INFO, message.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        )
        .expect_err("transaction without assessment must be rejected");
    if let Some(reason) = sandbox::sandbox_reason(&missing_err) {
        return Err(Report::msg(format!(
            "sandboxed network restriction detected while running {context}: {reason}"
        )));
    }
    let missing_chain = error_chain(&missing_err);
    assert!(
        missing_chain
            .iter()
            .any(|msg| msg.contains("fraud monitoring requires an attached assessment")),
        "unexpected rejection chain: {missing_chain:?}"
    );
    let mut low_metadata = Metadata::default();
    low_metadata.insert(indicator.clone(), Json::new("medium"));
    low_metadata.insert(score_key.clone(), Json::new(450_u64));
    low_metadata.insert(tenant_key.clone(), Json::new("tenant-eu"));
    low_metadata.insert(latency_key.clone(), Json::new(85_u64));
    let low_err = client
        .submit_with_metadata(
            Log::new(Level::INFO, message.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            low_metadata,
        )
        .expect_err("transaction with insufficient band must be rejected");
    if let Some(reason) = sandbox::sandbox_reason(&low_err) {
        return Err(Report::msg(format!(
            "sandboxed network restriction detected while running {context}: {reason}"
        )));
    }
    let low_chain = error_chain(&low_err);
    assert!(
        low_chain
            .iter()
            .any(|msg| msg.contains("fraud assessment band medium below required minimum high")),
        "unexpected rejection chain: {low_chain:?}"
    );
    let mut ok_metadata = Metadata::default();
    ok_metadata.insert(indicator, Json::new("critical"));
    ok_metadata.insert(score_key, Json::new(8_500_u64));
    ok_metadata.insert(tenant_key, Json::new("tenant-eu"));
    ok_metadata.insert(latency_key, Json::new(92_u64));
    if let Err(err) = client.submit_with_metadata(
        Log::new(Level::INFO, message),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        ok_metadata,
    ) {
        if let Some(reason) = sandbox::sandbox_reason(&err) {
            return Err(err.wrap_err(format!(
                "sandboxed network restriction detected while running {context}: {reason}"
            )));
        }
        return Err(err);
    }
    Ok(())
}
