//! Final usage proofs through Core's canonical-key and exact-instance boundary.
use super::*;
use ff::{Field, PrimeField};
use iroha_data_model::zk::{BackendTag, OpenVerifyEnvelope};
use kaigi_zk::native::NativeRelationV1;
use kaigi_zk::{
    authorization_v1::KaigiAuthorizationWitnessV1,
    usage_v1::{KaigiUsageContextV1, KaigiUsagePublicInputsV1, compute_usage_v1},
};
use std::sync::OnceLock;

struct Fixture {
    vk_bytes: Vec<u8>,
    proof: Vec<u8>,
    instance: [kaigi_zk::Scalar; 25],
}
fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let context = KaigiUsageContextV1 {
            network_id: [0x21; 32],
            call_id: [1, 2, 3, 4, 5, 6],
            host_id: [11, 12, 13, 14, 15, 16],
            pre_roster_root: [0x43; 32],
            segment_index: 3,
            duration_ms: 1200,
            billed_gas: 345,
        };
        let mut secret =
            (kaigi_zk::Scalar::from(2).pow_vartime([190]) + kaigi_zk::Scalar::from(31)).to_repr();
        let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut secret).unwrap();
        assert_eq!(secret, [0; 32]);
        let outputs = compute_usage_v1(&context, &witness).unwrap();
        let instance = KaigiUsagePublicInputsV1 { context, outputs }.instance();
        let kind = NativeRelationV1::Usage;
        let (_, proof) = kind
            .prover()
            .unwrap()
            .prove_usage(context, witness)
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
    material: Vec<u8>,
    columns: &[&[kaigi_zk::Scalar]],
) -> (ProofBox, VerifyingKeyBox) {
    let vk = VerifyingKeyBox::new(backend.to_owned(), material);
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
        circuit_id: KAIGI_USAGE_CIRCUIT_ID_V1.to_owned(),
        vk_hash: hash_vk(&vk),
        public_inputs: KAIGI_USAGE_PUBLIC_INPUTS_SCHEMA_V1.to_vec(),
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

/// Canonical real proof shared by the exact-registry positive regression.
pub(super) fn valid_envelope(backend: &str) -> (ProofBox, VerifyingKeyBox) {
    let fixture = fixture();
    envelope(backend, fixture.vk_bytes.clone(), &[&fixture.instance])
}

#[test]
fn final_usage_real_proof_binds_all_25_rows_and_both_admission_routes() {
    let fixture = fixture();
    for backend in [ZK_BACKEND_NATIVE_PIPA_R, KAIGI_USAGE_BACKEND_V1] {
        let (proof, vk) = valid_envelope(backend);
        assert!(native_pipa_r::validate_key(backend, KAIGI_USAGE_CIRCUIT_ID_V1, &vk).is_ok());
        assert!(verify_backend(backend, &proof, Some(&vk)), "{backend}");
    }
    // Both entry points delegate to the same exact relation. Mutate every
    // network/call/host/root/metric limb and C/U through its generic entry point.
    for row in 0..25 {
        let mut instance = fixture.instance;
        instance[row] += kaigi_zk::Scalar::ONE;
        let (proof, vk) = envelope(
            ZK_BACKEND_NATIVE_PIPA_R,
            fixture.vk_bytes.clone(),
            &[&instance],
        );
        assert!(
            !verify_backend(ZK_BACKEND_NATIVE_PIPA_R, &proof, Some(&vk)),
            "usage row {row}"
        );
    }
}

#[test]
fn final_usage_rejects_old_single_output_and_all_nonexact_shapes() {
    let fixture = fixture();
    let mut trailing_zero = fixture.instance.to_vec();
    trailing_zero.push(kaigi_zk::Scalar::ZERO);
    let shapes = [
        vec![],
        vec![&fixture.instance[24..]],
        vec![&fixture.instance[..24]],
        vec![trailing_zero.as_slice()],
        vec![&fixture.instance[..], &fixture.instance[..]],
        fixture.instance.chunks_exact(1).collect(),
    ];
    for columns in shapes {
        let (proof, vk) = envelope(ZK_BACKEND_NATIVE_PIPA_R, fixture.vk_bytes.clone(), &columns);
        assert!(
            !verify_backend(ZK_BACKEND_NATIVE_PIPA_R, &proof, Some(&vk)),
            "shape {:?}",
            columns.iter().map(|c| c.len()).collect::<Vec<_>>()
        );
    }
}

#[test]
fn final_usage_rejects_k8_aliases_and_wrong_canonical_key() {
    let fixture = fixture();
    let (proof, vk) = envelope(
        ZK_BACKEND_NATIVE_PIPA_R,
        fixture.vk_bytes.clone(),
        &[&fixture.instance],
    );
    for alias in [
        "kaigi-usage-v1",
        "halo2/pasta/kaigi-usage-v1",
        "halo2/ipa:kaigi-usage-v1",
        "halo2/pasta/ipa/kaigi-usage-v1",
    ] {
        let mut outer: OpenVerifyEnvelope = norito::decode_canonical(&proof.bytes).unwrap();
        outer.circuit_id = alias.to_owned();
        let changed = ProofBox::new(
            ZK_BACKEND_NATIVE_PIPA_R.to_owned(),
            norito::encode_canonical(&outer).unwrap(),
        );
        assert!(!verify_backend(
            ZK_BACKEND_NATIVE_PIPA_R,
            &changed,
            Some(&vk)
        ));
        assert!(native_pipa_r::validate_key(ZK_BACKEND_NATIVE_PIPA_R, alias, &vk).is_err());
    }
    let mut old_k: native_pipa_r::CompiledVerifyingKeyV1 =
        norito::decode_canonical(&fixture.vk_bytes).unwrap();
    old_k.key[1..5].copy_from_slice(&8_u32.to_le_bytes());
    let old_k = norito::encode_canonical(&old_k).unwrap();
    let (changed, changed_vk) = envelope(ZK_BACKEND_NATIVE_PIPA_R, old_k, &[&fixture.instance]);
    assert!(
        native_pipa_r::validate_key(
            ZK_BACKEND_NATIVE_PIPA_R,
            KAIGI_USAGE_CIRCUIT_ID_V1,
            &changed_vk
        )
        .is_err()
    );
    assert!(!verify_backend(
        ZK_BACKEND_NATIVE_PIPA_R,
        &changed,
        Some(&changed_vk)
    ));
    // Same k and curve with a foreign typed-instance descriptor: accepting
    // a parseable key or merely its domain size would miss this substitution.
    let params =
        iroha_plonk::pcs::ipa::PinnedParams::<iroha_pasta::Eq>::derive(NativeRelationV1::Usage.k())
            .unwrap();
    let (other_binding, other) = iroha_plonk::keys::keygen_vk_with_binding_v2(
        &params,
        &kaigi_zk::usage_v1::KaigiUsageCircuitV1::default(),
        &iroha_plonk::keys::KeygenConfigV2::pipa_r(vec![iroha_plonk::cs::InstanceType::Bounded]),
    )
    .unwrap();
    assert_eq!(
        other.to_bytes(),
        NativeRelationV1::Usage.verifier().unwrap().key_bytes()
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
            KAIGI_USAGE_CIRCUIT_ID_V1,
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
