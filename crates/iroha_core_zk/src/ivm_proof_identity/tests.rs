//! Reserved identities fail at admission, independently of proof validity.

use super::{RESERVED_RELATIONS, circuit_id_uses_reserved_ivm_namespace};
use crate::{
    ZK_BACKEND_STARK_FRI_V1, canonical_stark_fri_circuit_id_for_backend,
    stark_open_verify_circuit_id_matches_backend, stark_registry_circuit_id_matches_backend,
    validate_and_prepare_verifying_key_record_v1,
};
use iroha_data_model::{
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::{BackendTag, open_verify_circuit_id_is_portable},
};

#[test]
fn reserved_ivm_identity_checks_every_component_without_normalizing() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    for relation in RESERVED_RELATIONS {
        let circuit = format!("{backend}:{relation}");
        assert!(open_verify_circuit_id_is_portable(&circuit), "{circuit}");
        assert!(canonical_stark_fri_circuit_id_for_backend(backend, &circuit).is_some());
        assert!(
            circuit_id_uses_reserved_ivm_namespace(&circuit),
            "{circuit}"
        );
        assert!(!stark_open_verify_circuit_id_matches_backend(
            backend, &circuit
        ));
        assert!(!stark_registry_circuit_id_matches_backend(
            backend, &circuit
        ));
    }
    for relation in [
        "ivmish-v1",
        "tenant:my-ivm-execution-v1/binding",
        "tenant/my_ivm_execution_v1",
        "tenant:public.binding_v1",
    ] {
        let circuit = format!("{backend}:{relation}");
        assert!(
            !circuit_id_uses_reserved_ivm_namespace(&circuit),
            "{circuit}"
        );
        assert!(stark_open_verify_circuit_id_matches_backend(
            backend, &circuit
        ));
        assert!(stark_registry_circuit_id_matches_backend(backend, &circuit));
    }
    // Case folding, whitespace stripping and URL decoding never turn an invalid
    // portable identifier into an admitted spelling.
    for relation in [
        "IVM-execution-v1",
        "tenant:IvM_execution_v1",
        "tenant:ivm-execution-v1 ",
        "tenant:%69vm-execution-v1",
        "tenant:ivm-execution-v1\u{200b}",
        "tenant//ivm-execution-v1",
        "tenant/:ivm-execution-v1",
    ] {
        let circuit = format!("{backend}:{relation}");
        assert!(!open_verify_circuit_id_is_portable(&circuit), "{circuit}");
        assert!(!stark_open_verify_circuit_id_matches_backend(
            backend, &circuit
        ));
        assert!(!stark_registry_circuit_id_matches_backend(
            backend, &circuit
        ));
    }
}

fn record(circuit: &str) -> VerifyingKeyRecord {
    let mut record = VerifyingKeyRecord::new(
        1,
        circuit,
        BackendTag::Stark,
        "goldilocks",
        [0x22; 32],
        [0x42; 32],
    );
    record.gas_schedule_id = Some("stark_default".to_owned());
    record
}

#[test]
fn reserved_ivm_registry_records_reject_before_inline_material() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let id = VerifyingKeyId::new(backend, "reserved-identity-test");
    let control = record(&format!("{backend}:tenant:my-ivm-execution-v1/binding"));
    assert!(
        validate_and_prepare_verifying_key_record_v1(&id, &control)
            .expect("valid off-ledger generic record")
            .is_none()
    );
    for relation in RESERVED_RELATIONS {
        let circuit = format!("{backend}:{relation}");
        let error = validate_and_prepare_verifying_key_record_v1(&id, &record(&circuit))
            .expect_err("an off-ledger commitment cannot reserve an IVM binding identity");
        assert!(error.contains("not admitted"), "{circuit}: {error}");
    }
}

#[cfg(feature = "zk-stark")]
fn key_payload(circuit: &str) -> crate::stark::StarkFriVerifyingKeyV1 {
    use crate::stark::*;
    StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit.to_owned(),
        n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    }
}

#[cfg(feature = "zk-stark")]
fn key(circuit: &str) -> iroha_data_model::proof::VerifyingKeyBox {
    iroha_data_model::proof::VerifyingKeyBox::new(
        ZK_BACKEND_STARK_FRI_V1.to_owned(),
        norito::encode_canonical(&key_payload(circuit)).expect("canonical STARK key"),
    )
}

#[cfg(feature = "zk-stark")]
#[test]
fn reserved_ivm_native_material_rejects_interior_and_snake_case_components() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let control = format!("{backend}:tenant:my-ivm-execution-v1/binding");
    crate::validate_stark_fri_verifying_key_v1(backend, &control, &key(&control).bytes)
        .expect("real canonical generic material control");
    for relation in RESERVED_RELATIONS {
        let circuit = format!("{backend}:{relation}");
        let payload = key_payload(&circuit);
        let vk = key(&circuit);
        assert!(
            crate::validate_stark_fri_verifying_key_v1(backend, &circuit, &vk.bytes).is_err(),
            "registry material admitted {circuit}"
        );
        let error = crate::stark::validate_stark_fri_canonical_verifying_key_payload(
            &payload, &circuit, "test",
        )
        .expect_err("direct native material cannot bypass registry identity rejection");
        assert!(error.contains("IVM execution"), "{circuit}: {error}");
        assert!(
            crate::prove_stark_fri_open_verify_envelope(
                backend,
                &circuit,
                &vk,
                b"reserved-identity-test:v1",
                vec![vec![[1; 32]]],
            )
            .is_err(),
            "generic OpenVerify prover admitted {circuit}"
        );
        let params = crate::stark::StarkFriParamsV1 {
            version: 1,
            n_log2: payload.n_log2,
            blowup_log2: payload.blowup_log2,
            fold_arity: payload.fold_arity,
            queries: payload.queries,
            merkle_arity: payload.merkle_arity,
            domain_tag: "reserved-identity-test:v1".to_owned(),
        };
        let error = crate::stark::prove_stark_fri_air_envelope_bytes(
            params,
            crate::STARK_OPEN_VERIFY_AIR_TRANSCRIPT_LABEL_V1.to_owned(),
            circuit.clone(),
            Default::default(),
        )
        .expect_err("direct native AIR prover cannot bypass the common identity guard");
        assert!(error.contains("IVM execution"), "{circuit}: {error}");
    }
}

#[cfg(feature = "zk-stark")]
#[test]
fn reserved_ivm_valid_public_binding_control_verifies() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let circuit = format!("{backend}:tenant:my-ivm-execution-v1/binding");
    let vk = key(&circuit);
    let schema = b"generic-binding-control:v1";
    let mut record = record(&circuit);
    record.vk_len = u32::try_from(vk.bytes.len()).expect("bounded key");
    record.commitment = crate::hash_vk(&vk);
    record.public_inputs_schema_hash = iroha_crypto::Hash::new(schema).into();
    record.key = Some(vk.clone());
    let id = VerifyingKeyId::new(backend, "generic-binding-control");
    assert!(
        validate_and_prepare_verifying_key_record_v1(&id, &record)
            .expect("real inline generic record")
            .is_some()
    );
    let proof = crate::prove_stark_fri_open_verify_envelope(
        backend,
        &circuit,
        &vk,
        schema,
        vec![vec![[1; 32]]],
    )
    .expect("real native public-input binding proof");
    let verified = crate::verify_for_relation(
        crate::ProofRelation::PublicInputBinding,
        &proof,
        &vk,
        crate::ZkVerifyGuardrails {
            pipa_r_enabled: true,
            pipa_r_max_envelope_bytes: 8 * 1024 * 1024,
            pipa_r_max_proof_bytes: 8 * 1024 * 1024,
            stark_enabled: true,
            stark_max_envelope_bytes: 1024 * 1024,
            stark_max_proof_bytes: 1024 * 1024,
        },
    )
    .expect("generic near-miss proves and verifies its actual public binding relation");
    assert_eq!(
        verified.relation(),
        crate::ProofRelation::PublicInputBinding
    );
}
