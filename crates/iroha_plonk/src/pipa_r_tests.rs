//! Native PIPA-R schema, transcript, typed-instance and proof parity coverage.

use crate::{
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, DescriptorRule, InstanceModeV1, InstanceType,
        ProofSuffixV1, TranscriptV2,
    },
    frontend::Circuit,
    keys::{DescriptorBinding, KeygenConfigV2, keygen_pk_v2, keygen_vk_v2},
    pcs::ipa::{GeneratorClaim, IpaError, PinnedParams},
    protocol::Protocol,
    prover::{
        ProverConfig, ProverError, ProverRandomness, Witness, create_proof,
        create_proof_owned_with_claim,
    },
    test_circuits::{Arithmetic, BUDGET, K, Lookups, Permutations},
    transcript::{
        BasePoseidonHash, DescriptorHash, Transcript, TranscriptError, TranscriptHash,
        TranscriptRepr, TranscriptWriter, absorb_prelude_v2,
        pipa_r::{challenge_from_base, scalar_elements},
        recording::record,
    },
    verifier::{VerifyError, accumulate_generator, verify_full, verify_full_from_bytes_v2},
};
use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, PastaCurve, PastaField, poseidon::PoseidonField};

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            write!(text, "{byte:02x}").expect("string write");
            text
        })
}

fn kat<C: PastaCurve>(expected: [&str; 3])
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::new());
    absorb_prelude_v2(
        &mut transcript,
        &TranscriptRepr::Base(C::Base::from(5)),
        &[2],
        &[InstanceType::Bounded],
    )
    .expect("frame");
    transcript.common_scalar(&C::ScalarExt::from(3));
    transcript.common_scalar(&-C::ScalarExt::ONE);
    let point =
        Option::<C::AffineExt>::from(C::AffineExt::from_xy(-C::Base::ONE, C::Base::from(2)))
            .expect("(-1,2)");
    transcript.common_point(&point).expect("finite");
    let first = transcript.squeeze_challenge();
    let second = transcript.squeeze_challenge();
    transcript.common_scalar(&first);
    transcript.common_scalar(&C::ScalarExt::ZERO);
    let third = transcript.squeeze_challenge();
    assert_eq!([first, second, third].map(|v| hex(v.to_repr())), expected);
    assert_eq!(
        BasePoseidonHash::<C>::new().absorb_point(&C::AffineExt::identity()),
        Err(TranscriptError::IdentityPoint)
    );
    assert_ne!(
        BasePoseidonHash::<C>::new().squeeze(),
        BasePoseidonHash::<C>::with_domain(*b"pipa-as1").squeeze()
    );
    let mut base = TranscriptWriter::<C, _>::new(BasePoseidonHash::default());
    assert_eq!(
        base.common_binding(&TranscriptRepr::Scalar(C::ScalarExt::ONE)),
        Err(TranscriptError::ProfileMismatch)
    );
    let mut scalar = TranscriptWriter::<C, _>::new(DescriptorHash::production(
        TranscriptV2::KagemushaPoseidonRp57,
    ));
    assert_eq!(
        scalar.common_binding(&TranscriptRepr::Base(C::Base::ONE)),
        Err(TranscriptError::ProfileMismatch)
    );
}

/// DEV-12: independent base-field transcript vectors on Pallas.
#[test]
fn pipa_r_transcript_kats_pallas() {
    kat::<Ep>([
        "0cee0482c6b8ef2335190c0721dc8e8dfce22f738948b8b47d582ad2c0b04d3b",
        "f3b4af0bb61e1e6723f5fae1c55a0b88104580854f30c6e78acf1f76053f9b2e",
        "c9d932bf515003049d7d7e773f96a7c4f7fae137e6dd68b4fd402bd45806e30c",
    ]);
}
/// DEV-12: independent base-field transcript vectors on Vesta.
#[test]
fn pipa_r_transcript_kats_vesta() {
    kat::<Eq>([
        "a5b84f592814b0888cd3a0cf5c3ca36c06d53af9652da528d4682b7543250010",
        "1b26d3379eb77a737dd332a6584ff733c5f38c9c105a19ac7a046b61525fcd34",
        "9b78382d8e49d4785a78b3f05960f02cc603e4f8228803aaadb0e31d7012190a",
    ]);
}
#[test]
fn fq_to_fp_challenge_map_kat() {
    let p = Fq::from_raw_reduced((-Fp::ONE).to_canonical_limbs()) + Fq::ONE;
    for (input, output) in [
        (Fq::ZERO, Fp::ZERO),
        (p - Fq::ONE, -Fp::ONE),
        (p, Fp::ZERO),
        (p + Fq::ONE, Fp::ONE),
    ] {
        assert_eq!(challenge_from_base::<Eq>(&input), output);
    }
    let q_minus_p_minus_one = -Fq::ONE - p;
    assert_eq!(
        challenge_from_base::<Eq>(&-Fq::ONE).to_repr(),
        q_minus_p_minus_one.to_repr()
    );
    for input in [Fp::ZERO, Fp::ONE, -Fp::ONE] {
        assert_eq!(challenge_from_base::<Ep>(&input).to_repr(), input.to_repr());
    }
    assert_eq!(
        scalar_elements::<Eq>(&-Fp::ONE)[0].to_repr(),
        (-Fp::ONE).to_repr()
    );
    let value = -Fq::ONE;
    let limbs = scalar_elements::<Ep>(&value);
    assert_eq!(limbs.len(), 2);
    let raw = value.to_canonical_limbs();
    assert_eq!(limbs[0].to_canonical_limbs(), [raw[0], raw[1], 0, 0]);
    assert_eq!(limbs[1].to_canonical_limbs(), [raw[2], raw[3], 0, 0]);
}

const ARITHMETIC: Arithmetic = Arithmetic {
    start: 3,
    rows: 6,
    tamper: None,
};

#[test]
fn descriptor_v2_requires_direct_and_suffix() {
    let params = PinnedParams::<Ep>::derive(K).expect("params");
    let config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    let pk = keygen_pk_v2(&params, &ARITHMETIC, &config).expect("key");
    let encoded = pk.binding().encoded();
    let descriptor = CircuitDescriptorV2::decode(encoded).expect("v2");
    assert!(CircuitDescriptorV1::decode(encoded).is_err());
    assert!(DescriptorBinding::decode(encoded).is_err());
    assert_eq!(
        DescriptorBinding::decode_v2(encoded).expect("explicit v2"),
        *pk.binding()
    );
    assert_eq!(descriptor.digest().expect("digest"), *pk.binding().digest());
    let mut changed = descriptor.clone();
    changed.instance_mode = InstanceModeV1::Committed;
    assert_eq!(
        changed.validate(),
        Err(DescriptorRule::TranscriptProfile.into())
    );
    changed = descriptor.clone();
    changed.proof_suffix = ProofSuffixV1::None;
    assert_eq!(
        changed.validate(),
        Err(DescriptorRule::TranscriptProfile.into())
    );
    changed = descriptor.clone();
    changed.instance_types.clear();
    assert_eq!(changed.validate(), Err(DescriptorRule::InstanceType.into()));
    changed = descriptor.clone();
    changed.instance_types[0] = InstanceType::Bits(254);
    assert_eq!(changed.validate(), Err(DescriptorRule::InstanceType.into()));
    changed = descriptor.clone();
    changed.instance_types[0] = InstanceType::Bits(253);
    assert_ne!(
        changed.digest().expect("digest"),
        descriptor.digest().expect("digest")
    );
    let mut tail = encoded.to_vec();
    tail.push(0);
    assert!(CircuitDescriptorV2::decode(&tail).is_err());
    assert!(CircuitDescriptorV2::decode(&encoded[..encoded.len() - 1]).is_err());
    assert_eq!(
        keygen_vk_v2(&params, &ARITHMETIC, &config)
            .expect("vk")
            .to_bytes(),
        pk.vk().to_bytes()
    );
    assert!(matches!(pk.vk().transcript_repr(), TranscriptRepr::Base(_)));
}

fn proof_case<C, Ci>(circuit: &Ci, instances: &[Vec<C::ScalarExt>])
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
    Ci: Circuit<C::ScalarExt> + Sync,
{
    let params = PinnedParams::<C>::derive(K).expect("params");
    let config = KeygenConfigV2::pipa_r(vec![InstanceType::Field; instances.len()]);
    let pk = keygen_pk_v2(&params, circuit, &config).expect("key");
    let protocol = Protocol::new(pk.binding().descriptor()).expect("protocol");
    let expected: Vec<_> = protocol
        .transcript_schedule()
        .iter()
        .filter_map(crate::protocol::TranscriptStep::hash_operation)
        .collect();
    let mut first = None;
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .expect("pool");
        pool.install(|| {
            let witness = Witness::from_circuit(&pk, circuit, instances).expect("witness");
            let borrowed = create_proof(
                &params,
                &pk,
                &witness,
                ProverRandomness::fixed_seed_for_tests([5; 32]),
                ProverConfig::default(),
            )
            .expect("borrowed");
            let (output, trace) = record(|| {
                create_proof_owned_with_claim(
                    &params,
                    &pk,
                    witness,
                    ProverRandomness::fixed_seed_for_tests([5; 32]),
                    ProverConfig::default(),
                )
            });
            let output = output.expect("owned");
            assert_eq!(output.proof, borrowed);
            assert_eq!(trace, expected);
            assert_eq!(output.proof.len(), protocol.proof_length());
            assert_eq!(output.opening.decide(&params, BUDGET), Ok(()));
            let (result, trace) = record(|| {
                verify_full(
                    &params,
                    pk.binding(),
                    pk.vk(),
                    instances,
                    &output.proof,
                    BUDGET,
                )
            });
            assert_eq!(result, Ok(()));
            assert_eq!(trace, expected);
            assert_eq!(
                verify_full_from_bytes_v2(
                    &params,
                    pk.binding().encoded(),
                    pk.vk().to_bytes(),
                    instances,
                    &output.proof,
                    BUDGET
                ),
                Ok(())
            );
            let claim = accumulate_generator(
                &params,
                pk.binding(),
                pk.vk(),
                instances,
                &output.proof,
                BUDGET,
            )
            .expect("succinct");
            assert_eq!(claim, output.opening);
            assert_eq!(claim.decide(&params, BUDGET), Ok(()));
            let wrong = GeneratorClaim::new(claim.k(), -*claim.g(), claim.challenges().to_vec())
                .expect("well formed");
            assert_eq!(wrong.decide(&params, BUDGET), Err(IpaError::OpeningFailed));
            if let Some(bytes) = &first {
                assert_eq!(bytes, &output.proof);
            } else {
                first = Some(output.proof.clone());
            }
            for offset in (0..output.proof.len()).step_by(32) {
                let mut tampered = output.proof.clone();
                tampered[offset..offset + 32].fill(255);
                assert!(
                    verify_full(&params, pk.binding(), pk.vk(), instances, &tampered, BUDGET)
                        .is_err()
                );
            }
        });
    }
}
#[test]
fn pipa_r_native_owned_proof_and_schedule_parity_both_curves() {
    proof_case::<Ep, _>(&ARITHMETIC, &ARITHMETIC.instances());
    proof_case::<Eq, _>(&ARITHMETIC, &ARITHMETIC.instances());
    let lookups = Lookups {
        rows: 9,
        tamper: None,
        out_of_range: false,
        offset: 0,
    };
    proof_case::<Ep, _>(&lookups, &[]);
    proof_case::<Eq, _>(&lookups, &[]);
    let permutation = Permutations {
        rows: 10,
        tamper: None,
    };
    proof_case::<Ep, _>(&permutation, &permutation.instances());
    proof_case::<Eq, _>(&permutation, &permutation.instances());
}

/// DEV-13: typed-instance integer bounds are checked before proving.
#[test]
fn pipa_r_instance_type_out_of_range_rejected() {
    let p = Fq::from_raw_reduced((-Fp::ONE).to_canonical_limbs()) + Fq::ONE;
    assert!(InstanceType::Bounded.contains(&(p - Fq::ONE)));
    assert!(!InstanceType::Bounded.contains(&p));
    assert!(InstanceType::Field.contains(&-Fq::ONE));
    for bits in [0, 1, 64, 128, 253] {
        let bound = Fq::from(2).pow_vartime([u64::from(bits)]);
        assert!(InstanceType::Bits(bits).contains(&(bound - Fq::ONE)));
        assert!(!InstanceType::Bits(bits).contains(&bound));
    }
    let params = PinnedParams::<Ep>::derive(K).expect("params");
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bits(1)]);
    let pk = keygen_pk_v2(&params, &ARITHMETIC, &config).expect("key");
    let instances = ARITHMETIC.instances::<Fq>();
    assert!(matches!(
        Witness::from_circuit(&pk, &ARITHMETIC, &instances),
        Err(ProverError::InstanceType { column: 0, row: 0 })
    ));
    assert!(matches!(
        verify_full(&params, pk.binding(), pk.vk(), &instances, &[], BUDGET),
        Err(VerifyError::InstanceType { column: 0, row: 0 })
    ));
    config.instance_types[0] = InstanceType::Bounded;
    let pk = keygen_pk_v2(&params, &ARITHMETIC, &config).expect("key");
    let bad = vec![vec![p, p]];
    assert!(matches!(
        Witness::from_circuit(&pk, &ARITHMETIC, &bad),
        Err(ProverError::InstanceType { column: 0, row: 0 })
    ));
}

#[test]
fn explicit_v2_retained_profiles_use_v2_binding_and_typed_frame() {
    let params = PinnedParams::<Eq>::derive(K).expect("params");
    let instances = ARITHMETIC.instances();
    for transcript in [
        TranscriptV2::Blake2bChallenge255,
        TranscriptV2::KagemushaPoseidonRp57,
    ] {
        let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Field]);
        config.transcript = transcript;
        let pk = keygen_pk_v2(&params, &ARITHMETIC, &config).expect("key");
        assert!(matches!(
            pk.vk().transcript_repr(),
            TranscriptRepr::Scalar(_)
        ));
        let witness = Witness::from_circuit(&pk, &ARITHMETIC, &instances).expect("witness");
        let (output, trace) = record(|| {
            create_proof_owned_with_claim(
                &params,
                &pk,
                witness,
                ProverRandomness::fixed_seed_for_tests([8; 32]),
                ProverConfig::default(),
            )
        });
        let output = output.expect("proof");
        let protocol = Protocol::new(pk.binding().descriptor()).expect("protocol");
        assert_eq!(
            trace,
            protocol
                .transcript_schedule()
                .iter()
                .filter_map(crate::protocol::TranscriptStep::hash_operation)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            verify_full_from_bytes_v2(
                &params,
                pk.binding().encoded(),
                pk.vk().to_bytes(),
                &instances,
                &output.proof,
                BUDGET
            ),
            Ok(())
        );
    }
}

#[test]
fn generator_claim_rejects_malformed_or_undecided_values() {
    use group::{Curve, Group};
    let g = Ep::generator().to_affine();
    assert!(matches!(
        GeneratorClaim::<Ep>::new(2, g, vec![Fq::ONE]),
        Err(IpaError::OpeningFailed)
    ));
    assert!(matches!(
        GeneratorClaim::<Ep>::new(1, g, vec![Fq::ZERO]),
        Err(IpaError::ZeroChallenge { round: 0 })
    ));
    assert!(matches!(
        GeneratorClaim::<Ep>::new(1, <Ep as PastaCurve>::AffineExt::identity(), vec![Fq::ONE]),
        Err(IpaError::OpeningFailed)
    ));
    let claim = GeneratorClaim::<Ep>::new(6, g, vec![Fq::ONE; 6]).expect("syntactic claim");
    let small = PinnedParams::<Ep>::derive(5).expect("small params");
    assert!(claim.decide(&small, BUDGET).is_err());
}
