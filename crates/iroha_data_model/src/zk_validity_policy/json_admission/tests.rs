//! ZK declaration parity and complete original string-custody controls.
use super::super::ZkVerifyingKeyRefV1;
use super::*;
use crate::amx_prepare_streaming_allocations::with_exact_allocation_denial;
use norito::codec::{Decode, Encode};
use norito::core::{DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits};
use std::alloc::Layout;

mod captured {
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkPipaRValidityV1 {
        pub enabled: bool,
        pub max_envelope_bytes: u64,
        pub max_proof_bytes: u64,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkStarkValidityV1 {
        pub enabled: bool,
        pub max_envelope_bytes: u64,
        pub max_proof_bytes: u64,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkSccpValidityV1 {
        pub max_proofs_per_transaction: u32,
        pub max_proofs_per_block: u32,
        pub max_proof_bytes_per_proof: u64,
        pub max_proof_bytes_per_transaction: u64,
        pub max_proof_bytes_per_block: u64,
        pub max_native_headers_per_transaction: u32,
        pub max_native_headers_per_block: u32,
        pub max_ethereum_light_client_updates_per_transaction: u32,
        pub max_ethereum_light_client_updates_per_block: u32,
        pub max_native_header_bytes_per_transaction: u64,
        pub max_native_header_bytes_per_block: u64,
        pub max_ed25519_signature_checks_per_transaction: u32,
        pub max_ed25519_signature_checks_per_block: u32,
        pub max_bls_vote_attestations_per_transaction: u32,
        pub max_bls_vote_attestations_per_block: u32,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkProofValidityV1 {
        pub max_verify_batch: u32,
        pub ballot_history_cap: u64,
        pub preverify_max_bytes: u64,
        pub preverify_budget_bytes: u64,
        pub proof_history_cap: u64,
        pub proof_retention_grace_blocks: u64,
        pub proof_prune_batch: u64,
        pub bridge_proof_max_range_len: u64,
        pub bridge_proof_max_past_age_blocks: u64,
        pub bridge_proof_max_future_drift_blocks: u64,
        #[norito(required)]
        pub poseidon_params_id: Option<u32>,
        #[norito(required)]
        pub pedersen_params_id: Option<u32>,
        #[norito(required)]
        pub kaigi_authorization_vk: Option<ZkVerifyingKeyRefV1>,
        #[norito(required)]
        pub kaigi_usage_vk: Option<ZkVerifyingKeyRefV1>,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkConfidentialValidityV1 {
        pub max_proof_size_bytes: u32,
        pub max_nullifiers_per_tx: u32,
        pub max_commitments_per_tx: u32,
        pub max_confidential_ops_per_block: u32,
        pub max_anchor_age_blocks: u64,
        pub max_proof_bytes_block: u64,
        pub max_verify_calls_per_tx: u32,
        pub max_verify_calls_per_block: u32,
        pub max_public_inputs: u32,
        pub reorg_depth_bound: u64,
        pub policy_transition_delay_blocks: u64,
        pub policy_transition_window_blocks: u64,
        pub policy_transition_max_per_height: u32,
        pub tree_roots_history_len: u64,
        pub tree_frontier_checkpoint_interval: u64,
        pub registry_max_vk_entries: u32,
        pub registry_max_params_entries: u32,
        pub registry_max_delta_per_block: u32,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkVerificationGasV1 {
        pub proof_base: u64,
        pub per_public_input: u64,
        pub per_proof_byte: u64,
        pub per_nullifier: u64,
        pub per_commitment: u64,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkVerifyingKeyRefV1 {
        pub backend: String,
        pub name: String,
    }
    #[derive(norito::derive::JsonDeserialize, norito::derive::JsonSerialize)]
    #[norito(deny_unknown_fields)]
    pub struct ZkValidityPolicyV1 {
        pub pipa_r: ZkPipaRValidityV1,
        pub stark: ZkStarkValidityV1,
        pub sccp: ZkSccpValidityV1,
        pub proofs: ZkProofValidityV1,
        pub confidential: ZkConfidentialValidityV1,
        pub gas: ZkVerificationGasV1,
    }
}

fn policy() -> ZkValidityPolicyV1 {
    let mut value = ZkValidityPolicyV1::protocol_default();
    value.proofs.kaigi_authorization_vk = Some(ZkVerifyingKeyRefV1 {
        backend: "backend-one".into(),
        name: "authorization-key".into(),
    });
    value.proofs.kaigi_usage_vk = Some(ZkVerifyingKeyRefV1 {
        backend: "backend-two".into(),
        name: "usage-proof-key".into(),
    });
    value
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<AdmittedZkValidityPolicy, ZkPolicyJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let owner = AdmittedZkValidityPolicy::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(owner)
}
#[test]
fn both_reference_cuts_keep_canonical_wire_and_original_cumulative_demand() {
    for expected in [ZkValidityPolicyV1::protocol_default(), policy()] {
        let source = json::to_json(&expected).unwrap();
        let original = DecodeBudgetContext::new(limits(usize::MAX));
        let captured = original
            .with(|| json::from_str::<captured::ZkValidityPolicyV1>(&source))
            .unwrap();
        let context = DecodeBudgetContext::new(limits(usize::MAX));
        let pool = AllocationBudget::new(8192);
        let owner = context.with(|| decode(&source, &pool)).unwrap();
        assert_eq!(owner.get(), &expected);
        owner.get().validate().unwrap();
        assert_eq!(json::to_json(&captured).unwrap(), source);
        // This policy declares the fixed-v1 payload codec, not a framed schema.
        let bytes = owner.get().encode();
        assert_eq!(bytes, expected.encode());
        assert_eq!(
            ZkValidityPolicyV1::decode(&mut bytes.as_slice()).unwrap(),
            expected
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            original.consumed_allocated_bytes()
        );
        assert!(owner.belongs_to(&pool));
        assert!(!owner.belongs_to(&AllocationBudget::new(8192)));
        let fields: Vec<_> = [
            expected.proofs.kaigi_authorization_vk.as_ref(),
            expected.proofs.kaigi_usage_vk.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flat_map(|key| [key.backend.as_str(), key.name.as_str()])
        .collect();
        assert_eq!(owner.allocation_count(), fields.len());
        assert_eq!(
            pool.reserved_bytes(),
            Layout::array::<AllocationCharge>(4).unwrap().size()
                + fields.iter().map(|s| s.len()).sum::<usize>()
        );
        drop(owner);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn captured_sections_required_options_and_nested_key_error_order_are_preserved() {
    let source = json::to_json(&policy()).unwrap();
    let cases = [
        "{}".to_owned(),
        source.replacen("\"pipa_r\":", "\"unexpected\":false,\"pipa_r\":", 1),
        source.replacen("\"enabled\":true", "\"enabled\":true,\"enabled\":false", 1),
        source.replacen("\"poseidon_params_id\":null,", "", 1),
        source.replacen(
            "\"pedersen_params_id\":null",
            "\"pedersen_params_id\":false",
            1,
        ),
        source.replacen("\"backend\":", "\"unknown\":false,\"backend\":", 1),
        source.replacen(
            "\"name\":\"authorization-key\"",
            "\"name\":\"authorization-key\",\"name\":false",
            1,
        ),
        source.replacen("\"name\":\"authorization-key\"", "\"name\":false", 1),
        source.replacen("\"backend\":\"backend-one\",", "", 1),
        source.replacen(
            "\"max_envelope_bytes\":1048576",
            "\"max_envelope_bytes\":-1",
            1,
        ),
    ];
    for input in cases {
        let captured = json::from_str::<captured::ZkValidityPolicyV1>(&input)
            .err()
            .expect("changed malformed fixture");
        let ordinary = json::from_str::<ZkValidityPolicyV1>(&input).unwrap_err();
        let pool = AllocationBudget::new(8192);
        let admitted = decode(&input, &pool).unwrap_err();
        let ZkPolicyJsonAdmissionError::Json(admitted) = admitted else {
            panic!("ample original pool: {admitted:?}");
        };
        assert_eq!(
            format!("{ordinary:?}"),
            format!("{captured:?}"),
            "ordinary {input}"
        );
        assert_eq!(
            format!("{admitted:?}"),
            format!("{captured:?}"),
            "admitted {input}"
        );
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn escaped_keys_and_strings_keep_values_and_semantic_validation_separate() {
    let mut expected = policy();
    // Zero batch size is allowed by the current policy. Use an actual committed
    // nonzero rule to distinguish successful decoding from semantic validation.
    expected.sccp.max_proofs_per_transaction = 0;
    let source = json::to_json(&expected)
        .unwrap()
        .replace("\"backend\"", "\"back\\u0065nd\"")
        .replace("backend-one", "back\\u0065nd-one");
    let pool = AllocationBudget::new(8192);
    let owner = decode(&source, &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(owner.get().validate(), expected.validate());
    assert_eq!(
        owner.get().validate(),
        Err(super::super::ZkValidityPolicyError::Zero(
            "sccp.max_proofs_per_transaction",
        ))
    );
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn finite_pool_and_actual_ledger_string_key_allocator_refusals_are_distinct() {
    let expected = policy();
    let source = json::to_json(&expected).unwrap();
    for limit in [0, 1, 32, 64, 128] {
        let pool = AllocationBudget::new(limit);
        match decode(&source, &pool) {
            Ok(owner) => drop(owner),
            Err(ZkPolicyJsonAdmissionError::Allocation(ChargedBufferError::Admission(_))) => {}
            Err(error) => panic!("valid source only refused for finite pool: {error:?}"),
        }
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let escaped = source.replacen(
        "\"kaigi_authorization_vk\"",
        "\"kaigi_authorization_\\u0076k\"",
        1,
    );
    for (input, layout) in [
        (
            source.as_str(),
            Layout::array::<AllocationCharge>(4).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<u8>("backend-one".len()).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<u8>("authorization-key".len()).unwrap(),
        ),
        (
            source.as_str(),
            Layout::array::<u8>("usage-proof-key".len()).unwrap(),
        ),
        (
            escaped.as_str(),
            Layout::array::<u8>("kaigi_authorization_vk".len()).unwrap(),
        ),
    ] {
        let pool = AllocationBudget::new(8192);
        let (result, actual_request) =
            with_exact_allocation_denial(layout, || decode(input, &pool));
        assert!(actual_request);
        assert!(
            matches!(result, Err(ZkPolicyJsonAdmissionError::Allocation(ChargedBufferError::Allocator { requested_bytes })) if requested_bytes == layout.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        let retry = decode(input, &pool).unwrap();
        assert_eq!(retry.get(), &expected);
        drop(retry);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn actual_final_string_scope_retains_original_identity_and_refunds_partial_fields() {
    let source = json::to_json(&policy()).unwrap();
    let oracle = DecodeBudgetContext::new(limits(usize::MAX));
    oracle
        .with(|| json::from_str::<captured::ZkValidityPolicyV1>(&source))
        .unwrap();
    let limit = usize::try_from(oracle.consumed_allocated_bytes()).unwrap() - 1;
    let context = DecodeBudgetContext::new(limits(limit));
    let pool = AllocationBudget::new(8192);
    let mut original = None;
    let attempt = context
        .with(|| {
            norito::core::classify_decode_attempt(|| {
                decode(&source, &pool).map_err(|error| {
                    let ZkPolicyJsonAdmissionError::Json(error) = error else {
                        panic!("ample original pool");
                    };
                    let error = error.into_core_error();
                    let norito::Error::ScopedDecodeResource(scope) = &error else {
                        panic!("real string scope");
                    };
                    original = Some(scope.clone());
                    error
                })
            })
        })
        .unwrap_err();
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let retained = attempt.into_local_refusal().unwrap().into_error();
    let norito::Error::ScopedDecodeResource(scope) = &retained else {
        panic!("retained original");
    };
    assert_eq!(scope, &original.unwrap());
    let replay = norito::core::classify_decode_attempt::<()>(|| Err(retained)).unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
}
#[test]
#[allow(unsafe_code)]
fn exact_original_reference_allocations_move_without_clone_or_refund() {
    let source = json::to_json(&policy()).unwrap();
    let pool = AllocationBudget::new(8192);
    let owner = decode(&source, &pool).unwrap();
    let pointer = owner
        .get()
        .proofs
        .kaigi_usage_vk
        .as_ref()
        .unwrap()
        .name
        .as_ptr();
    let used = pool.reserved_bytes();
    // SAFETY: the complete immutable value is destroyed before its original ledger.
    let (value, ledger) = unsafe { owner.into_allocation_parts() };
    assert_eq!(
        pointer,
        value.proofs.kaigi_usage_vk.as_ref().unwrap().name.as_ptr()
    );
    assert_eq!(pool.reserved_bytes(), used);
    drop(value);
    assert_eq!(pool.reserved_bytes(), used);
    drop(ledger);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn protocol_default_uses_no_native_allocation_or_decoder_quota() {
    use crate::amx_prepare_streaming_allocations::PhysicalObservation;
    let pool = AllocationBudget::new(0);
    let expected = ZkValidityPolicyV1::protocol_default();
    let zero =
        norito::core::DecodeBudgetContext::new(norito::core::DecodeLimits::new(0, 0, 0, 0, 0));
    let observation = PhysicalObservation::start();
    let owner = zero
        .with(|| AdmittedZkValidityPolicy::try_protocol_default(&pool))
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
