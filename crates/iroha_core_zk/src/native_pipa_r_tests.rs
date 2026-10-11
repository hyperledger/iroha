//! Native dispatch, governed key identity and policy regressions using real proofs.
use super::*;
use crate::{
    PreparedVerifyingKeyMaterialV1, ProofRelation, ProofVerificationError, ZkVerifyGuardrails,
};
use iroha_data_model::proof::{VerifyingKeyId, VerifyingKeyRecord};

fn policy() -> ZkVerifyGuardrails {
    ZkVerifyGuardrails {
        pipa_r_enabled: true,
        pipa_r_max_envelope_bytes: 128 * 1024,
        pipa_r_max_proof_bytes: 128 * 1024,
        stark_enabled: false,
        stark_max_envelope_bytes: 0,
        stark_max_proof_bytes: 0,
    }
}
#[test]
fn native_confidential_fixture_is_genuine_cached_and_relation_scoped() {
    let first = crate::test_utils::native_confidential_fixture_envelope();
    let repeated = crate::test_utils::native_confidential_fixture_envelope();
    assert_eq!(first.proof_bytes, repeated.proof_bytes);
    assert_eq!(first.vk_bytes, repeated.vk_bytes);
    let proof = first.proof_box(BACKEND);
    let key = first.vk_box(BACKEND).unwrap();
    assert!(
        crate::verify_for_relation(ProofRelation::ConfidentialTransfer, &proof, &key, policy(),)
            .is_ok()
    );
    for relation in [
        ProofRelation::KaigiAuthorization,
        ProofRelation::ConfidentialFullUnshield,
    ] {
        assert!(matches!(
            crate::verify_for_relation(relation, &proof, &key, policy()),
            Err(ProofVerificationError::RelationMismatch { .. }),
        ));
    }
    assert_eq!(
        first.schema_hash,
        <[u8; 32]>::from(iroha_crypto::Hash::new(&first.public_inputs))
    );
}
#[test]
fn native_key_records_bind_curve_schema_relation_length_and_compiled_key() {
    for kind in [KaigiRelation::Authorization, KaigiRelation::Usage] {
        let key = kaigi_verifying_key(kind).unwrap();
        assert!(key.bytes.len() <= MAX_KEY_BYTES);
        eprintln!("{kind:?} compiled key carrier: {} bytes", key.bytes.len());
        let decoded: CompiledVerifyingKeyV1 = norito::decode_canonical(&key.bytes).unwrap();
        assert_eq!(
            decoded.descriptor,
            kind.verifier().unwrap().descriptor_bytes()
        );
        assert_eq!(decoded.key, kind.verifier().unwrap().key_bytes());
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), key.bytes);
        let mut trailing = key.bytes.clone();
        trailing.push(0);
        for bytes in [
            decoded.key.clone(),
            trailing,
            norito::encode_canonical(&CompiledVerifyingKeyV1 {
                descriptor: Vec::new(),
                key: decoded.key,
            })
            .unwrap(),
        ] {
            assert!(
                validate_key(
                    BACKEND,
                    kind.circuit_id(),
                    &VerifyingKeyBox::new(BACKEND.into(), bytes),
                )
                .is_err()
            );
        }
        let id = VerifyingKeyId::new(BACKEND, "kaigi-current");
        let mut record = VerifyingKeyRecord::new(
            1,
            kind.circuit_id(),
            BackendTag::NativePipaRPasta,
            "vesta",
            iroha_crypto::Hash::new(public_schema(kind.into())).into(),
            crate::hash_vk(&key),
        );
        record.vk_len = key.bytes.len().try_into().unwrap();
        record.max_proof_bytes = 128 * 1024;
        record.gas_schedule_id = Some("native-kaigi".into());
        record.key = Some(key);
        assert_eq!(
            crate::validate_and_prepare_verifying_key_record_v1(&id, &record).unwrap(),
            Some(PreparedVerifyingKeyMaterialV1::NativePipaRPasta { ipa_k: kind.k() })
        );
        let mut changed = record.clone();
        changed.curve = "pallas".into();
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
        let mut changed = record.clone();
        changed.public_inputs_schema_hash[0] ^= 1;
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
        let mut changed = record.clone();
        changed.vk_len += 1;
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
        let mut changed = record.clone();
        changed.key.as_mut().unwrap().bytes[0] ^= 1;
        changed.commitment = crate::hash_vk(changed.key.as_ref().unwrap());
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
        let mut changed = record.clone();
        changed.circuit_id = "pipa-r/pasta/unreviewed".into();
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
        let mut changed = record.clone();
        changed.key = None;
        assert_eq!(
            crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).unwrap(),
            None
        );
        changed.vk_len = MAX_KEY_BYTES as u32 + 1;
        assert!(crate::validate_and_prepare_verifying_key_record_v1(&id, &changed).is_err());
    }
}
#[test]
fn native_real_proofs_obey_relation_policy_caps_and_preverify() {
    for (proof, key, relation) in [
        {
            let (p, k) = crate::kaigi_authorization_v1_tests::valid_envelope(BACKEND);
            (p, k, ProofRelation::KaigiAuthorization)
        },
        {
            let (p, k) = crate::kaigi_usage_v1_tests::valid_envelope(BACKEND);
            (p, k, ProofRelation::KaigiUsage)
        },
    ] {
        assert_eq!(
            crate::verify_for_relation(relation, &proof, &key, policy())
                .unwrap()
                .relation(),
            relation
        );
        let wrong = if relation == ProofRelation::KaigiUsage {
            ProofRelation::KaigiAuthorization
        } else {
            ProofRelation::KaigiUsage
        };
        assert!(matches!(
            crate::verify_for_relation(wrong, &proof, &key, policy()),
            Err(ProofVerificationError::RelationMismatch { .. })
        ));
        let envelope: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
        let kind = validate_metadata(BACKEND, &envelope).unwrap();
        assert_eq!(
            public_instances(BACKEND, &envelope).unwrap()[0].len(),
            kind.instance_rows()
        );
        let mut limits = policy();
        limits.pipa_r_enabled = false;
        assert_eq!(
            crate::verify_for_relation(relation, &proof, &key, limits),
            Err(ProofVerificationError::BackendDisabled)
        );
        limits = policy();
        limits.pipa_r_max_envelope_bytes = proof.bytes.len() - 1;
        assert!(matches!(
            crate::verify_for_relation(relation, &proof, &key, limits),
            Err(ProofVerificationError::EnvelopeTooLarge { .. })
        ));
        limits = policy();
        limits.pipa_r_max_proof_bytes = envelope.proof_bytes.len() - 1;
        assert!(matches!(
            crate::verify_for_relation(relation, &proof, &key, limits),
            Err(ProofVerificationError::ProofTooLarge { .. })
        ));
        limits.pipa_r_max_proof_bytes += 1;
        limits.pipa_r_max_envelope_bytes = proof.bytes.len();
        assert!(crate::verify_for_relation(relation, &proof, &key, limits).is_ok());
        let mut dedup = crate::DedupCache::new();
        assert_eq!(
            crate::preverify_with_budget(
                &proof,
                Some(&key),
                &mut dedup,
                0,
                Some(crate::hash_vk(&key)),
                Some(crate::hash_vk(&key)),
                true
            ),
            crate::PreverifyResult::Accepted
        );
        assert!(!verify(BACKEND, &proof, None));
        let mut bad = envelope.clone();
        bad.aux.push(1);
        assert!(public_instances(BACKEND, &bad).is_err());
        bad = envelope.clone();
        bad.proof_bytes.resize(128 * 1024 + 1, 0);
        assert!(public_instances(BACKEND, &bad).is_err());
        bad = envelope.clone();
        let mut inner: NativePipaRProofV1 = norito::decode_canonical(&bad.proof_bytes).unwrap();
        inner.public_inputs[0] = [255; 32];
        bad.proof_bytes = norito::encode_canonical(&inner).unwrap();
        assert!(public_instances(BACKEND, &bad).is_err());
        assert!(!verify(
            BACKEND,
            &ProofBox::new(BACKEND.into(), norito::encode_canonical(&bad).unwrap()),
            Some(&key)
        ));
    }
}

#[test]
fn native_framing_fixture_has_exact_schema_but_cannot_verify() {
    use crate::confidential_v2 as confidential;
    for (circuit, key) in [
        (
            confidential::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            confidential::confidential_transfer_v2_vk_box().unwrap(),
        ),
        (
            confidential::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID,
            confidential::confidential_unshield_v2_vk_box().unwrap(),
        ),
        (
            confidential::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID,
            confidential::confidential_unshield_v3_vk_box().unwrap(),
        ),
    ] {
        let fixture =
            crate::test_utils::native_framing_fixture_envelope(circuit, crate::hash_vk(&key));
        assert!(fixture.vk_bytes.is_none());
        let envelope: OpenVerifyEnvelope = norito::decode_canonical(&fixture.proof_bytes).unwrap();
        assert_eq!(
            norito::encode_canonical(&envelope).unwrap(),
            fixture.proof_bytes
        );
        let kind = validate_metadata(BACKEND, &envelope).unwrap();
        assert_eq!(
            public_instances(BACKEND, &envelope).unwrap()[0].len(),
            kind.instance_rows()
        );
        assert_eq!(
            fixture.schema_hash,
            <[u8; 32]>::from(iroha_crypto::Hash::new(&fixture.public_inputs))
        );
        assert!(!verify(
            BACKEND,
            &ProofBox::new(BACKEND.into(), fixture.proof_bytes),
            Some(&key)
        ));
    }
}

#[test]
fn native_compiled_key_cache_shares_exact_material_across_threads() {
    use std::sync::{Arc, Barrier};
    const WORKERS: usize = 8;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let results = std::thread::scope(|scope| {
        (0..WORKERS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    NativeRelationV1::ALL.map(|kind| compiled_key(kind).unwrap())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().expect("compiled key worker"))
            .collect::<Vec<_>>()
    });
    for keys in &results {
        for (index, kind) in NativeRelationV1::ALL.into_iter().enumerate() {
            assert!(std::ptr::eq(keys[index], results[0][index]));
            assert!(std::ptr::eq(keys[index], compiled_key(kind).unwrap()));
            assert!(!keys[index].is_empty());
            assert!(keys[index].len() <= MAX_KEY_BYTES);
        }
    }
}

#[test]
fn native_compiled_descriptors_bind_pinned_parameters_and_exact_domains() {
    use iroha_plonk::cs::{CircuitDescriptorV2, CurveV1, descriptor::pinned_params_digest};
    let mut identities = std::collections::BTreeSet::new();
    for kind in NativeRelationV1::ALL {
        assert!(identities.insert(kind.circuit_id()));
        let bytes = compiled_key(kind).unwrap();
        let carrier: CompiledVerifyingKeyV1 = norito::decode_canonical(bytes).unwrap();
        let descriptor = CircuitDescriptorV2::decode(&carrier.descriptor).unwrap();
        assert_eq!(descriptor.curve, CurveV1::Vesta);
        assert_eq!(u32::from(descriptor.k), kind.k());
        assert!(matches!(kind.k(), 12 | 13));
        assert_eq!(
            Some(descriptor.params_digest),
            pinned_params_digest(descriptor.curve, kind.k())
        );
        assert_eq!(
            descriptor.instance_lengths,
            [u32::try_from(kind.instance_rows()).unwrap()]
        );
        assert_eq!(descriptor.encode().unwrap(), carrier.descriptor);
        assert_eq!(norito::encode_canonical(&carrier).unwrap(), bytes);
        for changed in [
            CircuitDescriptorV2 {
                k: 31,
                ..descriptor.clone()
            },
            CircuitDescriptorV2 {
                params_digest: [0; 32],
                ..descriptor
            },
        ] {
            let foreign = CompiledVerifyingKeyV1 {
                descriptor: changed.encode().unwrap(),
                key: carrier.key.clone(),
            };
            let key =
                VerifyingKeyBox::new(BACKEND.into(), norito::encode_canonical(&foreign).unwrap());
            assert_eq!(
                validate_key(BACKEND, kind.circuit_id(), &key).unwrap_err(),
                "native PIPA-R key differs from the compiled relation"
            );
        }
    }
}

#[test]
fn native_parameter_admission_rejects_unadmitted_and_oversized_sources() {
    let key = VerifyingKeyBox::new(BACKEND.into(), Vec::new());
    for circuit in [
        "",
        "pipa-r/pasta/unreviewed",
        "halo2/pasta/ipa/kaigi-roster-v1",
    ] {
        assert_eq!(relation(BACKEND, circuit), None);
        assert_eq!(
            validate_key(BACKEND, circuit, &key).unwrap_err(),
            "unadmitted native PIPA-R key relation"
        );
    }
    for kind in NativeRelationV1::ALL {
        for backend in ["PIPA-R/PASTA", "pipa-r/pasta ", "halo2/ipa", "stark/fri"] {
            assert_eq!(relation(backend, kind.circuit_id()), None);
            let foreign = VerifyingKeyBox::new(backend.into(), Vec::new());
            assert_eq!(
                validate_key(backend, kind.circuit_id(), &foreign).unwrap_err(),
                "unadmitted native PIPA-R key relation"
            );
        }
        let oversized = VerifyingKeyBox::new(BACKEND.into(), vec![0; MAX_KEY_BYTES + 1]);
        assert_eq!(
            validate_key(BACKEND, kind.circuit_id(), &oversized).unwrap_err(),
            "invalid native PIPA-R key container"
        );
    }
}
