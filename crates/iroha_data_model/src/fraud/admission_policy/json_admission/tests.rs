//! Fraud destination field parity, original allocation and refusal controls.

use std::alloc::Layout;

use crate::amx_prepare_streaming_allocations::{PhysicalObservation, with_exact_allocation_denial};
use iroha_crypto::{Algorithm, KeyPair};
use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits};

use super::*;

#[derive(norito::derive::JsonDeserialize)]
#[norito(tag = "band", content = "value", rename_all = "snake_case")]
enum CapturedBand {
    Low,
    Medium,
    High,
    Critical,
}
impl CapturedBand {
    fn into_value(self) -> FraudRiskBandV1 {
        match self {
            Self::Low => FraudRiskBandV1::Low,
            Self::Medium => FraudRiskBandV1::Medium,
            Self::High => FraudRiskBandV1::High,
            Self::Critical => FraudRiskBandV1::Critical,
        }
    }
}
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CapturedAttester {
    engine_id: String,
    public_key: PublicKey,
}
#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct CapturedPolicy {
    version: u8,
    enabled: bool,
    required_minimum_band: Option<CapturedBand>,
    missing_assessment_permitted: bool,
    attesters: Vec<CapturedAttester>,
}
impl CapturedPolicy {
    fn into_value(self) -> FraudAdmissionPolicyV1 {
        FraudAdmissionPolicyV1 {
            version: self.version,
            enabled: self.enabled,
            required_minimum_band: self.required_minimum_band.map(CapturedBand::into_value),
            missing_assessment_permitted: self.missing_assessment_permitted,
            attesters: self
                .attesters
                .into_iter()
                .map(|value| FraudAdmissionAttesterV1 {
                    engine_id: value.engine_id,
                    public_key: value.public_key,
                })
                .collect(),
        }
    }
}
fn policy() -> FraudAdmissionPolicyV1 {
    FraudAdmissionPolicyV1 {
        version: 1,
        enabled: true,
        required_minimum_band: Some(FraudRiskBandV1::High),
        missing_assessment_permitted: false,
        attesters: ["risk-a", "risk-b"]
            .into_iter()
            .map(|id| FraudAdmissionAttesterV1 {
                engine_id: id.into(),
                public_key: KeyPair::from_seed(id.as_bytes().to_vec(), Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            })
            .collect(),
    }
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<AdmittedFraudAdmissionPolicy, FraudPolicyJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let owner = AdmittedFraudAdmissionPolicy::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(owner)
}

#[test]
fn populated_graph_keeps_canonical_wire_and_exact_original_leaf_custody() {
    let expected = policy();
    let source = json::to_json(&expected).unwrap();
    let ordinary_context = DecodeBudgetContext::new(limits(usize::MAX));
    let captured = ordinary_context
        .with(|| json::from_str::<CapturedPolicy>(&source))
        .unwrap()
        .into_value();
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let pool = AllocationBudget::new(8192);
    let observation = PhysicalObservation::start();
    let owner = context.with(|| decode(&source, &pool)).unwrap();
    let pointer = owner.get().attesters.as_ptr() as usize;
    assert_eq!(owner.get(), &captured);
    assert_eq!(owner.get(), &expected);
    owner.get().validate().unwrap();
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&AllocationBudget::new(8192)));
    assert_eq!(owner.allocation_count(), 5);
    assert_eq!(
        context.consumed_allocated_bytes(),
        ordinary_context.consumed_allocated_bytes()
    );
    assert_eq!(
        observation
            .snapshot()
            .single_live_pointer(Layout::array::<FraudAdmissionAttesterV1>(2).unwrap()),
        Some(pointer)
    );
    let expected_bytes = Layout::array::<FraudAdmissionAttesterV1>(2).unwrap().size()
        + Layout::array::<AllocationCharge>(5).unwrap().size()
        + expected
            .attesters
            .iter()
            .map(|value| {
                value.engine_id.len() + value.public_key.retained_allocation_layout().size()
            })
            .sum::<usize>();
    assert_eq!(pool.reserved_bytes(), expected_bytes);
    // End the bounded allocator observation before allocating wire oracle bytes.
    drop(observation);
    assert_eq!(
        norito::encode_canonical(owner.get()).unwrap(),
        norito::encode_canonical(&expected).unwrap()
    );
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn captured_field_errors_option_absence_and_unit_band_envelope_are_preserved() {
    let source = json::to_json(&policy()).unwrap();
    let cases = [
        "{}".to_owned(),
        "{\"version\":1}".to_owned(),
        source.replacen("\"version\":1", "\"version\":1,\"version\":false", 1),
        source.replacen("\"version\":1", "\"unexpected\":false,\"version\":1", 1),
        source.replacen("\"public_key\":", "\"engine_id\":false,\"public_key\":", 1),
        source.replacen("\"engine_id\":", "\"unknown\":false,\"engine_id\":", 1),
        source.replacen("\"band\":\"high\"", "\"band\":\"unknown\"", 1),
        source.replacen("\"value\":null", "\"value\":false", 1),
        source.replacen("\"value\":null", "\"value\":null,\"value\":false", 1),
        source.replacen("\"band\":\"high\"", "\"band\":\"high\",\"band\":false", 1),
    ];
    for input in cases {
        let original = json::from_str::<CapturedPolicy>(&input)
            .err()
            .expect("captured malformed record");
        let ordinary = json::from_str::<FraudAdmissionPolicyV1>(&input).unwrap_err();
        let pool = AllocationBudget::new(8192);
        let admitted = decode(&input, &pool).unwrap_err();
        let FraudPolicyJsonAdmissionError::Json(admitted) = admitted else {
            panic!("record failure, not key or pool: {admitted:?}");
        };
        assert_eq!(
            format!("{ordinary:?}"),
            format!("{original:?}"),
            "ordinary {input}"
        );
        assert_eq!(
            format!("{admitted:?}"),
            format!("{original:?}"),
            "admitted {input}"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
    for source in [
        r#"{"version":1,"enabled":false,"missing_assessment_permitted":false,"attesters":[]}"#,
        r#"{"version":1,"enabled":false,"required_minimum_band":{"value":null,"ignored":{"x":1},"band":"low"},"missing_assessment_permitted":false,"attesters":[]}"#,
    ] {
        let expected = json::from_str::<CapturedPolicy>(source)
            .unwrap()
            .into_value();
        let pool = AllocationBudget::new(8192);
        let owner = decode(source, &pool).unwrap();
        assert_eq!(owner.get(), &expected);
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn all_bands_and_escaped_names_decode_without_normalizing_policy_validity() {
    for band in [
        FraudRiskBandV1::Low,
        FraudRiskBandV1::Medium,
        FraudRiskBandV1::High,
        FraudRiskBandV1::Critical,
    ] {
        let mut expected = policy();
        expected.required_minimum_band = Some(band);
        let source = json::to_json(&expected)
            .unwrap()
            .replace("\"engine_id\"", "\"engine_\\u0069d\"")
            .replace("risk-a", "risk-\\u0061");
        let pool = AllocationBudget::new(8192);
        let owner = decode(&source, &pool).unwrap();
        assert_eq!(owner.get(), &expected);
        owner.get().validate().unwrap();
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let mut invalid = policy();
    invalid.version = 2;
    let source = json::to_json(&invalid).unwrap();
    let pool = AllocationBudget::new(8192);
    let owner = decode(&source, &pool).unwrap();
    assert_eq!(
        owner.get(),
        &json::from_str::<FraudAdmissionPolicyV1>(&source).unwrap()
    );
    assert_eq!(
        owner.get().validate(),
        invalid.validate(),
        "typed decode grants no policy authority"
    );
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn every_finite_pool_prefix_refunds_and_a_funded_retry_succeeds() {
    let source = json::to_json(&policy()).unwrap();
    for capacity in [0, 1, 32, 64, 128, 256] {
        let pool = AllocationBudget::new(capacity);
        let result = decode(&source, &pool);
        match result {
            Ok(value) => drop(value),
            Err(FraudPolicyJsonAdmissionError::Allocation(ChargedBufferError::Admission(_))) => {}
            Err(error) => {
                panic!("only original pool capacity may refuse this valid source: {error:?}")
            }
        }
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let pool = AllocationBudget::new(8192);
    let owner = decode(&source, &pool).unwrap();
    owner.get().validate().unwrap();
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_ledger_array_engine_text_key_text_and_compact_allocator_refusals_are_typed() {
    let expected = policy();
    let source = json::to_json(&expected).unwrap();
    let escaped = source.replace(
        "\"missing_assessment_permitted\"",
        "\"missing_assessment_\\u0070ermitted\"",
    );
    for (input, layout) in [
        (
            source.as_str(),
            Layout::array::<AllocationCharge>(5).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<FraudAdmissionAttesterV1>(2).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<u8>("risk-a".len()).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<u8>(expected.attesters[0].public_key.to_string().len()).unwrap(),
        ),
        (
            source.as_str(),
            expected.attesters[0]
                .public_key
                .retained_allocation_layout(),
        ),
        (
            escaped.as_str(),
            Layout::array::<u8>("missing_assessment_permitted".len()).unwrap(),
        ),
    ] {
        let pool = AllocationBudget::new(8192);
        let (result, occurred) = with_exact_allocation_denial(layout, || decode(input, &pool));
        assert!(
            occurred,
            "selected exact allocator request must actually occur"
        );
        assert!(
            matches!(result, Err(FraudPolicyJsonAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == layout.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        let retry = decode(input, &pool).unwrap();
        assert_eq!(retry.get(), &expected);
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn original_key_codec_scope_survives_partial_graph_and_saved_replay_is_invalid() {
    let source = json::to_json(&policy()).unwrap();
    let oracle = DecodeBudgetContext::new(limits(usize::MAX));
    oracle
        .with(|| json::from_str::<CapturedPolicy>(&source))
        .unwrap();
    let limit = usize::try_from(oracle.consumed_allocated_bytes()).unwrap() - 1;
    let context = DecodeBudgetContext::new(limits(limit));
    let pool = AllocationBudget::new(8192);
    let mut original = None;
    let attempt = context
        .with(|| {
            norito::core::classify_decode_attempt(|| {
                decode(&source, &pool).map_err(|error| {
                    let error = match error {
                        FraudPolicyJsonAdmissionError::Json(error) => error.into_core_error(),
                        FraudPolicyJsonAdmissionError::Codec(error) => error,
                        error => panic!("ample pool, original codec refusal: {error:?}"),
                    };
                    let norito::Error::ScopedDecodeResource(scope) = &error else {
                        panic!("actual key/string scope: {error:?}");
                    };
                    original = Some(scope.clone());
                    error
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    assert_eq!(pool.reserved_bytes(), 0);
    let saved = attempt.into_local_refusal().unwrap().into_error();
    let norito::Error::ScopedDecodeResource(scope) = &saved else {
        panic!("original retained identity");
    };
    assert_eq!(scope, &original.unwrap());
    let replay = norito::core::classify_decode_attempt::<()>(|| Err(saved)).unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(replay.local_refusal().is_none());
    let retry = decode(&source, &pool).unwrap();
    drop(retry);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
#[allow(unsafe_code)]
fn move_parts_keep_every_original_leaf_and_ledger_until_real_destruction() {
    let source = json::to_json(&policy()).unwrap();
    let pool = AllocationBudget::new(8192);
    let owner = decode(&source, &pool).unwrap();
    let pointer = owner.get().attesters.as_ptr();
    let used = pool.reserved_bytes();
    // SAFETY: this test preserves the exact immutable value and original ledger,
    // destroying the full value before any ledger charge or backing is released.
    let (value, ledger) = unsafe { owner.into_allocation_parts() };
    assert_eq!(pointer, value.attesters.as_ptr());
    assert_eq!(pool.reserved_bytes(), used);
    assert!(ledger.belongs_to(&pool));
    assert!(
        ledger
            .as_slice()
            .iter()
            .all(|charge| charge.belongs_to(&pool))
    );
    drop(value);
    assert_eq!(pool.reserved_bytes(), used);
    drop(ledger);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn protocol_default_uses_no_native_allocation_or_decoder_quota() {
    use crate::amx_prepare_streaming_allocations::PhysicalObservation;
    let pool = AllocationBudget::new(0);
    let expected = FraudAdmissionPolicyV1::protocol_default();
    let zero =
        norito::core::DecodeBudgetContext::new(norito::core::DecodeLimits::new(0, 0, 0, 0, 0));
    let observation = PhysicalObservation::start();
    let owner = zero
        .with(|| AdmittedFraudAdmissionPolicy::try_protocol_default(&pool))
        .unwrap();
    let requests = observation.snapshot().requests();
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(owner.get(), &expected);
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&AllocationBudget::new(0)));
    assert_eq!(owner.allocation_count(), 0);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}
