//! Fraud monitoring admission tests consume the committed parameter projection.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_config::parameters::actual::FraudMonitoring;
use iroha_core::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, KeyPair, PrivateKey, Signature, SignatureOf};
use iroha_data_model::fraud::{FraudAdmissionAttesterV1, FraudRiskBandV1};
use iroha_data_model::{
    ValidationFail,
    asset::AssetDefinition,
    fraud::types::{AssessmentDecision, FraudAssessment, FraudAssessmentParts},
    prelude::*,
    transaction::error::TransactionRejectionReason,
};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use norito::codec::Encode;
use std::{str::FromStr, time::Duration};
fn checked_random_fraud_monitoring_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked fraud monitoring keypair")
}
#[test]
fn fraud_monitoring_fixture_uses_checked_randomness() {
    let key_pair = checked_random_fraud_monitoring_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
fn build_state(settings: FraudMonitoring) -> (CertifiedTestChain, NetworkId, AccountId, KeyPair) {
    let key_pair = checked_random_fraud_monitoring_keypair();
    let account_id = AccountId::new(key_pair.public_key().clone());
    let domain_id = DomainId::try_new("wonderland", "universal").expect("static domain id");
    let domain = Domain::new(domain_id).build(&account_id);
    let account = Account::new(account_id.clone()).build(&account_id);
    let world = World::with([domain], [account], std::iter::empty::<AssetDefinition>());
    let mut config = TestChainConfig::new(world, 1_000);
    config.chain_id = ChainId::from("fraud-monitor-chain");
    config.genesis_parameters.push(Parameter::Custom(
        iroha_core::fraud_admission_policy::policy_of(&settings).into_custom_parameter(),
    ));
    config.fraud_monitoring = settings;
    let chain = CertifiedTestChain::start(config).expect("authenticated fraud-policy genesis");
    let network_id = chain.network_id();
    (chain, network_id, account_id, key_pair)
}
fn make_transaction(
    network_id: &NetworkId,
    authority: &AccountId,
    key_pair: &KeyPair,
    metadata: Metadata,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        *network_id,
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(1_001));
    builder
        .with_instructions([Log::new(Level::INFO, "noop".to_string())])
        .with_metadata(metadata)
        .sign(key_pair.private_key())
}
fn execute(
    chain: &mut CertifiedTestChain,
    transaction: SignedTransaction,
) -> Result<(), TransactionRejectionReason> {
    let exact_hash = transaction.hash_as_entrypoint();
    let accepted = chain.commit(vec![transaction]);
    let committed = chain.committed(chain.height());
    assert_eq!(committed.block().network_input_hashes().count(), 1);
    assert_eq!(
        committed.block().network_input_hashes().next(),
        Some(exact_hash)
    );
    let (input, output) = committed
        .block()
        .network_output_at(0)
        .expect("original carrier output");
    assert_eq!(input, 0);
    let result = output.result.as_ref().map(|_| ()).map_err(Clone::clone);
    assert_eq!(accepted, vec![result.is_ok()]);
    result
}
fn metadata_key(key: &str) -> Name {
    Name::from_str(key).expect("static metadata key")
}
fn checked_signature_of<T: Encode>(private_key: &PrivateKey, payload: &T) -> SignatureOf<T> {
    SignatureOf::try_new(private_key, payload).expect("test fixture signing should succeed")
}
fn insert_base_metadata(
    metadata: &mut Metadata,
    band: &str,
    score_bps: u64,
    tenant: &str,
    latency_ms: u64,
) {
    metadata.insert(metadata_key("fraud_assessment_band"), Json::new(band));
    metadata.insert(
        metadata_key("fraud_assessment_score_bps"),
        Json::new(score_bps),
    );
    metadata.insert(metadata_key("fraud_assessment_tenant"), Json::new(tenant));
    metadata.insert(
        metadata_key("fraud_assessment_latency_ms"),
        Json::new(latency_ms),
    );
}
fn build_attested_metadata(
    band: &str,
    score_bps: u16,
    tenant: &str,
    latency_ms: u64,
    engine_id: &str,
    attester: &KeyPair,
) -> Metadata {
    let mut metadata = Metadata::default();
    insert_base_metadata(
        &mut metadata,
        band,
        u64::from(score_bps),
        tenant,
        latency_ms,
    );
    let parts = FraudAssessmentParts {
        query_id: [0xAB; 32],
        engine_id: engine_id.to_string(),
        risk_score_bps: score_bps,
        confidence_bps: 9_000,
        decision: AssessmentDecision::Review,
        generated_at_ms: 1_700_000_000_000,
        signature: None,
    };
    let unsigned = FraudAssessment::new(Vec::new(), parts);
    let signature = checked_signature_of(attester.private_key(), &unsigned);
    let raw_signature: Signature = signature.clone().into();
    let signature_bytes = raw_signature.payload().to_vec();
    let mut signed_assessment = unsigned.clone();
    signed_assessment.signature = Some(signature_bytes);
    let envelope_bytes = signed_assessment.encode();
    let envelope_b64 = BASE64_STANDARD.encode(envelope_bytes);
    metadata.insert(
        metadata_key("fraud_assessment_envelope"),
        Json::new(envelope_b64),
    );
    let unsigned_bytes = unsigned.encode();
    let digest_bytes: [u8; 32] = Hash::new(&unsigned_bytes).into();
    let digest_hex = hex::encode_upper(digest_bytes);
    metadata.insert(
        metadata_key("fraud_assessment_digest"),
        Json::new(digest_hex),
    );
    metadata
}
#[test]
fn admission_allows_when_fraud_disabled() {
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: false,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let tx = make_transaction(&chain_id, &authority, &key_pair, Metadata::default());
    let result = execute(&mut state, tx);
    assert!(
        result.is_ok(),
        "disabled fraud monitoring should permit tx: {result:?}"
    );
}
#[test]
fn admission_rejects_missing_assessment_when_required() {
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::High),
            missing_assessment_permitted: false,
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let tx = make_transaction(&chain_id, &authority, &key_pair, Metadata::default());
    let result = execute(&mut state, tx);
    let err = result.expect_err("missing assessment must reject");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
            assert!(
                msg.contains("fraud monitoring requires an attached assessment"),
                "unexpected rejection message: {msg}"
            );
        }
        other => panic!("unexpected rejection reason: {other:?}"),
    }
}
#[test]
fn block_pipeline_rejects_missing_assessment() {
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::High),
            missing_assessment_permitted: false,
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let tx = make_transaction(&chain_id, &authority, &key_pair, Metadata::default());
    let err = execute(&mut state, tx)
        .expect_err("certified native fraud admission should reject missing assessment");
    assert_eq!(state.height(), 2, "the original carrier is the final tip");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
            assert!(
                msg.contains("fraud monitoring requires an attached assessment"),
                "unexpected rejection: {msg}"
            );
        }
        other => panic!("unexpected rejection reason: {other:?}"),
    }
}
#[test]
fn admission_rejects_when_band_insufficient() {
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::High),
            missing_assessment_permitted: false,
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let mut metadata = Metadata::default();
    insert_base_metadata(&mut metadata, "medium", 450, "tenant-eu", 85);
    let tx = make_transaction(&chain_id, &authority, &key_pair, metadata);
    let result = execute(&mut state, tx);
    let err = result.expect_err("insufficient band must reject");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
            assert!(
                msg.contains("below required minimum"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("unexpected rejection reason: {other:?}"),
    }
}
#[test]
fn admission_allows_when_band_sufficient() {
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            missing_assessment_permitted: false,
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let mut metadata = Metadata::default();
    insert_base_metadata(&mut metadata, "high", 6_800, "tenant-eu", 92);
    let tx = make_transaction(&chain_id, &authority, &key_pair, metadata);
    let result = execute(&mut state, tx);
    assert!(
        result.is_ok(),
        "sufficient band should permit tx: {result:?}"
    );
}
#[test]
fn admission_rejects_missing_attestation_when_required() {
    let attester = checked_random_fraud_monitoring_keypair();
    let (public_key, _) = attester.clone().into_parts();
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            missing_assessment_permitted: false,
            attesters: vec![FraudAdmissionAttesterV1 {
                engine_id: "risk-engine-eu1".to_string(),
                public_key,
            }],
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let mut metadata = Metadata::default();
    insert_base_metadata(&mut metadata, "high", 6_800, "tenant-eu", 64);
    let tx = make_transaction(&chain_id, &authority, &key_pair, metadata);
    let result = execute(&mut state, tx);
    let err = result.expect_err("attestation metadata must be required");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
            assert!(
                msg.contains("fraud_assessment_envelope"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("unexpected rejection reason: {other:?}"),
    }
}
#[test]
fn admission_rejects_attestation_signature_mismatch() {
    let attester = checked_random_fraud_monitoring_keypair();
    let (public_key, _) = attester.clone().into_parts();
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            missing_assessment_permitted: false,
            attesters: vec![FraudAdmissionAttesterV1 {
                engine_id: "risk-engine-eu1".to_string(),
                public_key,
            }],
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let mut metadata = build_attested_metadata(
        "high",
        6_600,
        "tenant-eu",
        120,
        "risk-engine-eu1",
        &attester,
    );
    let envelope_key = metadata_key("fraud_assessment_envelope");
    let envelope_b64 = metadata
        .get(envelope_key.as_ref())
        .and_then(|value| value.try_into_any_norito::<String>().ok())
        .expect("envelope present");
    let envelope_bytes = BASE64_STANDARD
        .decode(envelope_b64.as_bytes())
        .expect("valid base64");
    let mut cursor = envelope_bytes.as_slice();
    let mut decoded: FraudAssessment =
        norito::codec::Decode::decode(&mut cursor).expect("decode envelope");
    decoded.signature = None;
    let wrong_attester = checked_random_fraud_monitoring_keypair();
    let wrong_signature = checked_signature_of(wrong_attester.private_key(), &decoded);
    let raw_wrong_signature: Signature = wrong_signature.into();
    decoded.signature = Some(raw_wrong_signature.payload().to_vec());
    let tampered_bytes = decoded.encode();
    let tampered_b64 = BASE64_STANDARD.encode(tampered_bytes);
    metadata.insert(envelope_key, Json::new(tampered_b64));
    let tx = make_transaction(&chain_id, &authority, &key_pair, metadata);
    let result = execute(&mut state, tx);
    let err = result.expect_err("tampered signature must reject");
    match err {
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(msg)) => {
            assert_eq!(msg, "fraud assessment signature failed verification");
        }
        other => panic!("unexpected rejection reason: {other:?}"),
    }
}
#[test]
fn admission_allows_with_valid_attestation() {
    let attester = checked_random_fraud_monitoring_keypair();
    let (public_key, _) = attester.clone().into_parts();
    let cfg = FraudMonitoring {
        policy: iroha_data_model::fraud::FraudAdmissionPolicyV1 {
            enabled: true,
            required_minimum_band: Some(FraudRiskBandV1::Medium),
            missing_assessment_permitted: false,
            attesters: vec![FraudAdmissionAttesterV1 {
                engine_id: "risk-engine-eu1".to_string(),
                public_key,
            }],
            ..iroha_data_model::fraud::FraudAdmissionPolicyV1::protocol_default()
        },
        ..Default::default()
    };
    let (mut state, chain_id, authority, key_pair) = build_state(cfg);
    let metadata = build_attested_metadata(
        "critical",
        9_100,
        "tenant-eu",
        75,
        "risk-engine-eu1",
        &attester,
    );
    let tx = make_transaction(&chain_id, &authority, &key_pair, metadata);
    let result = execute(&mut state, tx);
    assert!(
        result.is_ok(),
        "valid attestation must be accepted: {result:?}"
    );
}
