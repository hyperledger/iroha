//! Real final V1 Kaigi proofs through the canonical Core verifier boundary.

use super::*;
use ff::{Field, PrimeField};
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use kaigi_zk::authorization_v1::{
    KaigiAuthorizationActionV1, KaigiAuthorizationContextV1, KaigiAuthorizationPublicInputsV1,
    KaigiAuthorizationWitnessV1, compute_authorization_v1,
};
use kaigi_zk::native::NativeRelationV1;
use std::sync::OnceLock;

struct Fixture {
    vk_bytes: Vec<u8>,
    proof: Vec<u8>,
    instance: [kaigi_zk::Scalar; KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1],
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let context = KaigiAuthorizationContextV1 {
            network_id: [0x21; 32],
            call_id: [1, 2, 3, 4, 5, 6],
            host_id: [11, 12, 13, 14, 15, 16],
            subject_id: [21, 22, 23, 24, 25, 26],
            participation_sequence: 1,
            action: KaigiAuthorizationActionV1::Join,
            pre_roster_root: [0x43; 32],
        };
        let mut secret =
            (kaigi_zk::Scalar::from(2).pow_vartime([190]) + kaigi_zk::Scalar::from(31)).to_repr();
        let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut secret).unwrap();
        assert_eq!(secret, [0; 32]);
        let outputs = compute_authorization_v1(&context, &witness).unwrap();
        let instance = KaigiAuthorizationPublicInputsV1 { context, outputs }.instance();
        let kind = NativeRelationV1::Authorization;
        let (_, proof) = kind
            .prover()
            .unwrap()
            .prove_authorization(context, witness)
            .unwrap()
            .into_parts();
        let vk_bytes = native_pipa_r::kaigi_verifying_key(kind).unwrap().bytes;
        Fixture {
            vk_bytes,
            proof,
            instance,
        }
    })
}

fn envelope(
    backend: &str,
    vk_bytes: Vec<u8>,
    columns: &[&[kaigi_zk::Scalar]],
) -> (ProofBox, VerifyingKeyBox) {
    let vk = VerifyingKeyBox::new(backend.to_owned(), vk_bytes);
    let inner = if let [column] = columns {
        norito::encode_canonical(&iroha_data_model::zk::NativePipaRProofV1 {
            public_inputs: column.iter().map(PrimeField::to_repr).collect(),
            proof: fixture().proof.clone(),
        })
        .unwrap()
    } else {
        // The canonical native format has exactly one column. Multi-column
        // and transposed carriers are deliberately foreign Norito payloads.
        let nested: Vec<Vec<[u8; 32]>> = columns
            .iter()
            .map(|column| column.iter().map(PrimeField::to_repr).collect())
            .collect();
        norito::encode_canonical(&(nested, fixture().proof.clone())).unwrap()
    };
    let outer = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: KAIGI_AUTHORIZATION_CIRCUIT_ID_V1.to_owned(),
        vk_hash: hash_vk(&vk),
        public_inputs: KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1.to_vec(),
        proof_bytes: inner,
        aux: Vec::new(),
    };
    (
        ProofBox::new(
            backend.to_owned(),
            norito::encode_canonical(&outer).unwrap(),
        ),
        vk,
    )
}

fn mutate_outer(proof: &ProofBox, mutate: impl FnOnce(&mut OpenVerifyEnvelope)) -> ProofBox {
    let mut outer: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
    mutate(&mut outer);
    ProofBox::new(
        proof.backend.clone(),
        norito::encode_canonical(&outer).unwrap(),
    )
}

/// Canonical real proof shared by the exact-registry positive regression.
pub(super) fn valid_envelope(backend: &str) -> (ProofBox, VerifyingKeyBox) {
    let fixture = fixture();
    envelope(backend, fixture.vk_bytes.clone(), &[&fixture.instance])
}

#[test]
fn final_kaigi_real_proof_verifies_and_binds_all_31_rows() {
    let fixture = fixture();
    for backend in [ZK_BACKEND_NATIVE_PIPA_R, KAIGI_AUTHORIZATION_BACKEND_V1] {
        let (proof, vk) = valid_envelope(backend);
        assert!(
            native_pipa_r::validate_key(backend, KAIGI_AUTHORIZATION_CIRCUIT_ID_V1, &vk).is_ok()
        );
        assert!(verify_backend(backend, &proof, Some(&vk)), "{backend}");
        for row in 0..KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1 {
            let mut instance = fixture.instance;
            instance[row] += kaigi_zk::Scalar::ONE;
            let (changed, _) = envelope(backend, fixture.vk_bytes.clone(), &[&instance]);
            assert!(
                !verify_backend(backend, &changed, Some(&vk)),
                "{backend} row {row}"
            );
        }
    }
}

#[test]
fn final_kaigi_rejects_nonexact_instance_dimensions() {
    let fixture = fixture();
    let mut extra_zero = fixture.instance.to_vec();
    extra_zero.push(kaigi_zk::Scalar::ZERO);
    // A trailing zero may be algebraically invisible to an IPA instance
    // commitment. The final wire schema still permits exactly 31 rows.
    let transposed: Vec<&[kaigi_zk::Scalar]> = fixture.instance.chunks_exact(1).collect();
    let shapes = [
        vec![],
        vec![&fixture.instance[..30]],
        vec![extra_zero.as_slice()],
        vec![&fixture.instance[..], &fixture.instance[..]],
        transposed,
    ];
    for backend in [ZK_BACKEND_NATIVE_PIPA_R, KAIGI_AUTHORIZATION_BACKEND_V1] {
        for columns in &shapes {
            let (proof, vk) = envelope(backend, fixture.vk_bytes.clone(), columns);
            assert!(
                !verify_backend(backend, &proof, Some(&vk)),
                "{backend} shape {:?}",
                columns.iter().map(|c| c.len()).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn final_kaigi_rejects_retired_labels_schema_metadata_and_relabelled_keys() {
    let fixture = fixture();
    let (proof, vk) = envelope(
        ZK_BACKEND_NATIVE_PIPA_R,
        fixture.vk_bytes.clone(),
        &[&fixture.instance],
    );
    for retired in [
        "kaigi-roster-v1",
        "halo2/pasta/kaigi-roster-v1",
        "halo2/pasta/ipa/kaigi-roster-v1",
    ] {
        assert!(native_pipa_r::relation(ZK_BACKEND_NATIVE_PIPA_R, retired).is_none());
        assert!(!verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &mutate_outer(&proof, |outer| outer.circuit_id = retired.to_owned()),
            Some(&vk)
        ));
        let (retired_proof, retired_vk) =
            envelope(retired, fixture.vk_bytes.clone(), &[&fixture.instance]);
        assert!(!verify_backend(retired, &retired_proof, Some(&retired_vk)));
    }
    for schema in [
        b"kaigi-roster-v1".as_slice(),
        b"kaigi-usage-v1",
        b"kaigi-authorization-v1\0",
    ] {
        assert!(!verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &mutate_outer(&proof, |outer| outer.public_inputs = schema.to_vec()),
            Some(&vk)
        ));
    }
    for alias in [
        "kaigi-authorization-v1",
        "halo2/pasta/kaigi-authorization-v1",
        "halo2/ipa:kaigi-authorization-v1",
        "halo2/pasta/ipa/kaigi-authorization-v1",
    ] {
        assert!(!verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &mutate_outer(&proof, |outer| outer.circuit_id = alias.to_owned()),
            Some(&vk)
        ));
        assert!(native_pipa_r::validate_key(ZK_BACKEND_NATIVE_PIPA_R, alias, &vk).is_err());
    }
    let mut wrong_k: native_pipa_r::CompiledVerifyingKeyV1 =
        norito::decode_canonical(&fixture.vk_bytes).unwrap();
    // The native processed-key header stores k immediately after its version.
    wrong_k.key[1..5].copy_from_slice(&8_u32.to_le_bytes());
    let wrong_k = norito::encode_canonical(&wrong_k).unwrap();
    let mut duplicate_k = fixture.vk_bytes.clone();
    duplicate_k.extend_from_slice(&KAIGI_AUTHORIZATION_CIRCUIT_K_V1.to_le_bytes());
    for material in [wrong_k, duplicate_k] {
        let (changed, changed_vk) =
            envelope(ZK_BACKEND_NATIVE_PIPA_R, material, &[&fixture.instance]);
        assert!(
            native_pipa_r::validate_key(
                ZK_BACKEND_NATIVE_PIPA_R,
                KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
                &changed_vk
            )
            .is_err()
        );
        assert!(!verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &changed,
            Some(&changed_vk)
        ));
    }
    // Keep CID, k, outer public schema and VK hash mutually consistent;
    // exact compiled key equality must still reject a foreign descriptor.
    // Same k and curve with a foreign typed-instance descriptor: accepting
    // a parseable key or merely its domain size would miss this substitution.
    let params = iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Eq>::derive(
        NativeRelationV1::Authorization.k(),
    )
    .unwrap();
    let (other_binding, other) = iroha_plonk::keys::keygen_vk_with_binding_v2(
        &params,
        &kaigi_zk::authorization_v1::KaigiAuthorizationCircuitV1::default(),
        &iroha_plonk::keys::KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]),
    )
    .unwrap();
    assert_eq!(
        other.to_bytes(),
        NativeRelationV1::Authorization
            .verifier()
            .unwrap()
            .key_bytes()
    );
    let material = norito::encode_canonical(&native_pipa_r::CompiledVerifyingKeyV1 {
        descriptor: other_binding.encoded().to_vec(),
        key: other.to_bytes().to_vec(),
    })
    .unwrap();
    let (changed, changed_vk) = envelope(ZK_BACKEND_NATIVE_PIPA_R, material, &[&fixture.instance]);
    assert!(
        native_pipa_r::validate_key(
            ZK_BACKEND_NATIVE_PIPA_R,
            KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
            &changed_vk
        )
        .is_err()
    );
    assert!(!verify_backend(
        ZK_BACKEND_NATIVE_PIPA_R,
        &changed,
        Some(&changed_vk)
    ));
}
