//! Relation-confusion and fail-closed coverage for the public verifier API.

use super::*;
use crate::{ZK_BACKEND_NATIVE_PIPA_R, ZK_BACKEND_STARK_FRI_V1};

fn policy() -> ZkVerifyGuardrails {
    ZkVerifyGuardrails {
        pipa_r_enabled: true,
        pipa_r_max_envelope_bytes: 8 * 1024 * 1024,
        pipa_r_max_proof_bytes: 8 * 1024 * 1024,
        stark_enabled: true,
        stark_max_envelope_bytes: 1024 * 1024,
        stark_max_proof_bytes: 1024 * 1024,
    }
}

fn envelope(backend: BackendTag, circuit: &str) -> Vec<u8> {
    norito::encode_canonical(&OpenVerifyEnvelope {
        backend,
        circuit_id: circuit.to_owned(),
        vk_hash: [1; 32],
        public_inputs: vec![1],
        proof_bytes: vec![1],
        aux: Vec::new(),
    })
    .expect("canonical test envelope")
}

#[test]
fn admission_rejects_policy_and_size_before_decoding() {
    let key = VerifyingKeyBox::new(ZK_BACKEND_NATIVE_PIPA_R.to_owned(), Vec::new());
    let proof = ProofBox::new(ZK_BACKEND_NATIVE_PIPA_R.to_owned(), vec![0; 2]);
    let mut limits = policy();
    limits.pipa_r_enabled = false;
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &proof, &key, limits),
        Err(ProofVerificationError::BackendDisabled)
    );
    limits.pipa_r_enabled = true;
    limits.pipa_r_max_envelope_bytes = 1;
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &proof, &key, limits),
        Err(ProofVerificationError::EnvelopeTooLarge {
            actual: 2,
            maximum: 1
        })
    );
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &proof, &key, policy()),
        Err(ProofVerificationError::MalformedEnvelope)
    );
    let unsupported = ProofBox::new("not-a-proof-backend".to_owned(), proof.bytes);
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &unsupported, &key, policy()),
        Err(ProofVerificationError::UnsupportedBackend)
    );
}

#[test]
fn every_admitted_native_circuit_has_one_explicit_relation() {
    use ProofRelation::*;
    for (circuit, expected) in [
        (
            crate::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            ConfidentialTransfer,
        ),
        (
            crate::confidential_v2::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
            ConfidentialFullUnshield,
        ),
        (
            crate::confidential_v2::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
            ConfidentialChangeUnshield,
        ),
    ] {
        for backend in [crate::ZK_BACKEND_NATIVE_PIPA_R, circuit] {
            assert_eq!(compiled_relation(backend, circuit), Some(expected));
        }
        assert_eq!(compiled_relation("halo2/ipa", circuit), None);
        assert_eq!(compiled_relation(ZK_BACKEND_STARK_FRI_V1, circuit), None);
    }
    assert_eq!(
        compiled_relation("halo2/ipa", "halo2/pasta/ipa/unreviewed"),
        None
    );
    for (kind, expected) in [
        (
            kaigi_zk::native::NativeRelationV1::Authorization,
            KaigiAuthorization,
        ),
        (kaigi_zk::native::NativeRelationV1::Usage, KaigiUsage),
    ] {
        for backend in [crate::ZK_BACKEND_NATIVE_PIPA_R, kind.circuit_id()] {
            assert_eq!(
                compiled_relation(backend, kind.circuit_id()),
                Some(expected)
            );
        }
        assert_eq!(compiled_relation("halo2/ipa", kind.circuit_id()), None);
        assert_eq!(
            compiled_relation(ZK_BACKEND_STARK_FRI_V1, kind.circuit_id()),
            None
        );
    }
}

#[test]
fn public_binding_cannot_satisfy_a_confidential_requirement() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let circuit = format!("{backend}:public-binding-demo");
    let proof = ProofBox::new(backend.to_owned(), envelope(BackendTag::Stark, &circuit));
    let key = VerifyingKeyBox::new(backend.to_owned(), Vec::new());
    assert_eq!(
        verify_for_relation(ProofRelation::ConfidentialTransfer, &proof, &key, policy()),
        Err(ProofVerificationError::RelationMismatch {
            expected: ProofRelation::ConfidentialTransfer,
            actual: ProofRelation::PublicInputBinding,
        })
    );
    assert_eq!(
        verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, policy()),
        Err(ProofVerificationError::VerifyingKeyMismatch)
    );
    let mut decoded: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
    decoded.vk_hash = crate::hash_vk(&key);
    let proof = ProofBox::new(
        backend.to_owned(),
        norito::encode_canonical(&decoded).unwrap(),
    );
    // Matching a label and key digest is insufficient: native verification must succeed.
    assert_eq!(
        verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, policy()),
        Err(ProofVerificationError::InvalidProof)
    );
    for reserved in [
        iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID,
        "zk-ace-other",
        crate::GOVERNANCE_BALLOT_CIRCUIT_ID_V1,
        crate::GOVERNANCE_TALLY_CIRCUIT_ID_V1,
        iroha_data_model::soracloud::SORACLOUD_FHE_INPUT_ADMISSION_CIRCUIT_ID_V1,
        iroha_crypto::BFV_FULL_BOOTSTRAP_CIRCUIT_ID_V1,
    ] {
        let circuit = format!("{backend}:{reserved}");
        // Dedicated protocols must not fall through to the public binding AIR.
        assert_eq!(compiled_relation(backend, &circuit), None, "{circuit}");
    }
}

#[test]
fn backend_confusion_and_unknown_circuits_reject_before_crypto() {
    let key = VerifyingKeyBox::new(
        super::super::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
        Vec::new(),
    );
    let wrong_backend = ProofBox::new(
        super::super::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
        envelope(BackendTag::Stark, "pipa-r/pasta/kaigi-usage-v1"),
    );
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &wrong_backend, &key, policy()),
        Err(ProofVerificationError::MalformedEnvelope)
    );
    let unknown = ProofBox::new(
        super::super::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
        envelope(BackendTag::NativePipaRPasta, "pipa-r/pasta/unreviewed"),
    );
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &unknown, &key, policy()),
        Err(ProofVerificationError::UnsupportedRelation)
    );
    let oversized = ProofBox::new(
        super::super::ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
        envelope(BackendTag::NativePipaRPasta, "pipa-r/pasta/kaigi-usage-v1"),
    );
    let mut limits = policy();
    limits.pipa_r_max_proof_bytes = 0;
    assert_eq!(
        verify_for_relation(ProofRelation::KaigiUsage, &oversized, &key, limits),
        Err(ProofVerificationError::ProofTooLarge {
            actual: 1,
            maximum: 0
        })
    );
}

#[test]
fn retired_ivm_binding_names_cannot_select_any_generic_relation() {
    for name in [
        "ivm-execution-v1",
        "ivm-replay-binding-v1",
        "ivm-overlay-bind",
    ] {
        for (backend, tag, circuit, expected) in [
            (
                "halo2/ipa",
                BackendTag::Stark,
                format!("halo2/pasta/ipa/{name}"),
                ProofVerificationError::UnsupportedBackend,
            ),
            (
                ZK_BACKEND_NATIVE_PIPA_R,
                BackendTag::NativePipaRPasta,
                format!("pipa-r/pasta/{name}"),
                ProofVerificationError::UnsupportedRelation,
            ),
            (
                ZK_BACKEND_STARK_FRI_V1,
                BackendTag::Stark,
                format!("{ZK_BACKEND_STARK_FRI_V1}:{name}"),
                ProofVerificationError::UnsupportedRelation,
            ),
        ] {
            let proof = ProofBox::new(backend.to_owned(), envelope(tag, &circuit));
            let key = VerifyingKeyBox::new(backend.to_owned(), Vec::new());
            assert_eq!(compiled_relation(backend, &circuit), None);
            assert_eq!(
                verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, policy()),
                Err(expected),
                "retired IVM binding was admitted: {circuit}",
            );
        }
    }
}

#[test]
fn reserved_ivm_components_cannot_select_a_generic_relation() {
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let control = format!("{backend}:tenant:my-ivm-execution-v1/binding");
    assert_eq!(
        compiled_relation(backend, &control),
        Some(ProofRelation::PublicInputBinding)
    );
    for relation in crate::ivm_proof_identity::RESERVED_RELATIONS {
        let circuit = format!("{backend}:{relation}");
        assert_eq!(compiled_relation(backend, &circuit), None, "{circuit}");
        let proof = ProofBox::new(backend.to_owned(), envelope(BackendTag::Stark, &circuit));
        let key = VerifyingKeyBox::new(backend.to_owned(), Vec::new());
        assert_eq!(
            verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, policy()),
            Err(ProofVerificationError::UnsupportedRelation),
            "identity rejection must precede key/proof validity: {circuit}"
        );
    }
}

#[cfg(feature = "zk-stark")]
#[test]
fn native_public_binding_verifies_only_its_relation_and_rejects_tampering() {
    use crate::stark::{
        STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2, STARK_FRI_CONSENSUS_MIN_N_LOG2,
        STARK_FRI_CONSENSUS_MIN_QUERIES, StarkFriVerifyingKeyV1,
    };
    let backend = ZK_BACKEND_STARK_FRI_V1;
    let circuit = format!("{backend}:purpose-bound-public-inputs-v1");
    let key = VerifyingKeyBox::new(
        backend.to_owned(),
        norito::encode_canonical(&StarkFriVerifyingKeyV1 {
            version: 1,
            circuit_id: circuit.clone(),
            n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
            blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
            fold_arity: 2,
            queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
            merkle_arity: 2,
        })
        .expect("canonical native verifier key"),
    );
    let proof = crate::prove_stark_fri_open_verify_envelope(
        backend,
        &circuit,
        &key,
        b"purpose-bound-public-inputs:v1",
        vec![vec![[0x11; 32]]],
    )
    .expect("native public-input proof");
    let verified = verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, policy())
        .expect("native public-input proof verifies");
    assert_eq!(verified.relation(), ProofRelation::PublicInputBinding);
    let _ = verified.elapsed();
    let wrong_key = VerifyingKeyBox::new(backend.to_owned(), vec![1, 2, 3]);
    assert_eq!(
        verify_for_relation(
            ProofRelation::PublicInputBinding,
            &proof,
            &wrong_key,
            policy()
        ),
        Err(ProofVerificationError::VerifyingKeyMismatch),
    );
    assert_eq!(
        verify_for_relation(ProofRelation::ConfidentialTransfer, &proof, &key, policy()),
        Err(ProofVerificationError::RelationMismatch {
            expected: ProofRelation::ConfidentialTransfer,
            actual: ProofRelation::PublicInputBinding,
        }),
    );
    // These supported-relation controls replace the retired RAM-LFE generic
    // verifier's metadata and resource assertions. Start with an actual valid
    // proof so a malformed native fixture cannot make every negative pass.
    let original: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).expect("envelope");
    let metadata_cases: [(&str, fn(&mut OpenVerifyEnvelope), ProofVerificationError); 5] = [
        (
            "backend tag",
            |e| e.backend = BackendTag::NativePipaRPasta,
            ProofVerificationError::MalformedEnvelope,
        ),
        (
            "auxiliary bytes",
            |e| e.aux = b"unbound-metadata".to_vec(),
            ProofVerificationError::InvalidProof,
        ),
        (
            "zero key hash",
            |e| e.vk_hash = [0; 32],
            ProofVerificationError::VerifyingKeyMismatch,
        ),
        (
            "wrong key hash",
            |e| e.vk_hash = [0xa5; 32],
            ProofVerificationError::VerifyingKeyMismatch,
        ),
        (
            "schema drift",
            |e| e.public_inputs.extend_from_slice(b":drift"),
            ProofVerificationError::InvalidProof,
        ),
    ];
    for (label, mutate, expected) in metadata_cases {
        let mut changed = original.clone();
        mutate(&mut changed);
        let changed = ProofBox::new(
            proof.backend.clone(),
            norito::encode_canonical(&changed).expect("mutated envelope"),
        );
        assert_eq!(
            verify_for_relation(ProofRelation::PublicInputBinding, &changed, &key, policy()),
            Err(expected),
            "{label}"
        );
    }
    for backend in [
        "halo2/ipa:debug",
        "halo2/ipa:trusted-setup",
        "halo2/ipa:production-ready",
    ] {
        let changed = ProofBox::new(backend.to_owned(), proof.bytes.clone());
        assert_eq!(
            verify_for_relation(ProofRelation::PublicInputBinding, &changed, &key, policy()),
            Err(ProofVerificationError::UnsupportedBackend),
            "{backend}"
        );
    }
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate = {
        let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&original).expect("alternate layout")
    };
    assert_ne!(alternate, proof.bytes);
    assert_eq!(
        verify_for_relation(
            ProofRelation::PublicInputBinding,
            &ProofBox::new(proof.backend.clone(), alternate),
            &key,
            policy(),
        ),
        Err(ProofVerificationError::MalformedEnvelope)
    );
    let mut disabled = policy();
    disabled.stark_enabled = false;
    assert_eq!(
        verify_for_relation(ProofRelation::PublicInputBinding, &proof, &key, disabled),
        Err(ProofVerificationError::BackendDisabled)
    );
    let mut envelope_limited = policy();
    envelope_limited.stark_max_envelope_bytes = proof.bytes.len() - 1;
    assert_eq!(
        verify_for_relation(
            ProofRelation::PublicInputBinding,
            &proof,
            &key,
            envelope_limited
        ),
        Err(ProofVerificationError::EnvelopeTooLarge {
            actual: proof.bytes.len(),
            maximum: proof.bytes.len() - 1,
        })
    );
    let mut proof_limited = policy();
    proof_limited.stark_max_proof_bytes = original.proof_bytes.len() - 1;
    assert_eq!(
        verify_for_relation(
            ProofRelation::PublicInputBinding,
            &proof,
            &key,
            proof_limited
        ),
        Err(ProofVerificationError::ProofTooLarge {
            actual: original.proof_bytes.len(),
            maximum: original.proof_bytes.len() - 1,
        })
    );
    let mut decoded: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).expect("envelope");
    *decoded.proof_bytes.last_mut().expect("native proof bytes") ^= 1;
    let tampered = ProofBox::new(
        backend.to_owned(),
        norito::encode_canonical(&decoded).expect("tampered envelope"),
    );
    assert_eq!(
        verify_for_relation(ProofRelation::PublicInputBinding, &tampered, &key, policy()),
        Err(ProofVerificationError::InvalidProof),
    );
}
