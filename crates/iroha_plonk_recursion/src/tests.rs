//! Native accumulator, transcript, complete-arithmetic and fold regressions.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use iroha_pasta::{
    Ep, Eq, PastaAffine, PastaCurve, PastaField,
    msm::{MemoryBudget, SharedMemoryBudget},
    poseidon::{PoseidonField, Sponge},
};
use iroha_plonk::{
    pcs::ipa::{PinnedParams, commit::msm_complete, fold_evaluation, fold_scalars},
    transcript::{BasePoseidonHash, Transcript, TranscriptWrite, TranscriptWriter, encode_point},
};
use sha2::{Digest, Sha256};

use super::*;
use crate::accumulation::{combined_commitment, prelude};

fn syntactic_body<C: PastaCurve>() -> [u8; FOLD_BODY_BYTES] {
    let mut body = [0; FOLD_BODY_BYTES];
    for chunk in body.chunks_exact_mut(32) {
        chunk.copy_from_slice(&encode_point::<C>(&C::generator().to_affine()));
    }
    body[64 * K..64 * K + 32].copy_from_slice(&C::ScalarExt::ONE.to_repr());
    body
}

fn encoding_case<C: PastaCurve>() {
    let generator = C::generator().to_affine();
    let challenges = [C::ScalarExt::ONE; K];
    let claim = AccumulatorT::<C>::new(generator, challenges).expect("canonical");
    let bytes = claim.to_bytes();
    assert_eq!(bytes.len(), 544);
    assert_eq!(AccumulatorT::from_bytes(&bytes), Ok(claim.clone()));
    assert_eq!(claim.g(), &generator);
    assert_eq!(claim.challenges(), &challenges);
    for length in [0, 31, ACCUMULATOR_BYTES - 1, ACCUMULATOR_BYTES + 1] {
        assert!(matches!(
            AccumulatorT::<C>::from_bytes(&vec![0; length]),
            Err(Error::Length { .. })
        ));
    }
    let mut bad = bytes;
    bad[..32].fill(0);
    assert!(matches!(
        AccumulatorT::<C>::from_bytes(&bad),
        Err(Error::Encoding(_))
    ));
    bad = bytes;
    bad[32..64].fill(0);
    assert_eq!(
        AccumulatorT::<C>::from_bytes(&bad),
        Err(Error::ZeroChallenge { round: 0 })
    );
    bad[32..64].fill(255);
    assert!(matches!(
        AccumulatorT::<C>::from_bytes(&bad),
        Err(Error::Encoding(_))
    ));
    let short = FoldInput::<C>::from_opening(generator, &[C::ScalarExt::ONE; 3]).expect("short");
    assert_eq!(short.source_k(), 3);
    assert_eq!(&short.challenges()[..13], &[C::ScalarExt::ZERO; 13]);
    for k in [0, 17, u32::MAX] {
        assert_eq!(
            FoldInput::<C>::from_normalized(generator, k, challenges),
            Err(Error::SourceK)
        );
    }
    assert_eq!(
        FoldInput::<C>::from_normalized(generator, 3, challenges),
        Err(Error::Padding)
    );
    let mut interior_zero = *short.challenges();
    interior_zero[14] = C::ScalarExt::ZERO;
    assert_eq!(
        FoldInput::<C>::from_normalized(generator, 3, interior_zero),
        Err(Error::ZeroChallenge { round: 14 })
    );
    assert!(FoldInput::<C>::from_opening(generator, &[]).is_err());
    assert!(FoldInput::<C>::from_opening(generator, &[C::ScalarExt::ONE; 17]).is_err());

    let body = syntactic_body::<C>();
    let salt = C::Base::from(7_u64).to_repr();
    let witness = FoldWitness::<C>::new(salt, &body).expect("canonical messages");
    assert_eq!(witness.salt_bytes(), salt);
    assert_eq!(witness.body(), &body);
    assert_eq!(witness.to_bytes().len(), 1120);
    assert_eq!(
        FoldWitness::<C>::from_bytes(&witness.to_bytes()),
        Ok(witness)
    );
    assert!(FoldWitness::<C>::new([255; 32], &body).is_err());
    assert!(FoldWitness::<C>::new(salt, &body[..1087]).is_err());
    assert!(FoldWitness::<C>::from_bytes(&[0; 1119]).is_err());
    for index in 0..2 * K + 2 {
        let mut malformed = body;
        malformed[32 * index..32 * (index + 1)].fill(255);
        assert!(
            FoldWitness::<C>::new(salt, &malformed).is_err(),
            "message {index}"
        );
        if index != 2 * K {
            malformed[32 * index..32 * (index + 1)].fill(0);
            assert!(
                FoldWitness::<C>::new(salt, &malformed).is_err(),
                "identity message {index}"
            );
        }
    }
}

#[test]
fn canonical_encodings_and_padding_both_curves() {
    encoding_case::<Ep>();
    encoding_case::<Eq>();
}

fn cancellation_case<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let params = PinnedParams::<C>::derive(4).expect("small pinned parameters");
    let token = iroha_pasta::CancellationToken::default();
    token.cancel();
    let shared = SharedMemoryBudget::new(1 << 20);
    let config = FoldConfig {
        kernel_budget: MemoryBudget::DEFAULT,
        shared_budget: shared.clone(),
        cancellation: Some(token.clone()),
    };
    let salt = C::Base::from(7).to_repr();
    let witness = FoldWitness::<C>::new(salt, &syntactic_body::<C>()).unwrap();
    assert_eq!(
        create_fold(&params, &[], salt, &config),
        Err(Error::Cancelled)
    );
    assert_eq!(
        verify_fold(&params, &[], &witness, &config),
        Err(Error::Cancelled)
    );
    assert_eq!(
        AccumulatorT::trivial_cancellable(&params, MemoryBudget::DEFAULT, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(shared.in_use_bytes(), 0);
    let challenges = [C::ScalarExt::from(3), C::ScalarExt::from(5)];
    let coefficients = fold_scalars(&challenges, C::ScalarExt::ONE);
    let generator = msm_complete::<C>(
        &coefficients,
        &params.params().g()[..4],
        MemoryBudget::DEFAULT,
    )
    .to_affine();
    let claim = FoldInput::<C>::from_opening(generator, &challenges).unwrap();
    assert_eq!(
        claim.decide_cancellable(&params, MemoryBudget::DEFAULT, Some(&token)),
        Err(Error::Cancelled)
    );
    assert_eq!(
        claim.corrected_cancellable(&params, MemoryBudget::DEFAULT, Some(&token)),
        Err(Error::Cancelled)
    );
    let fresh = iroha_pasta::CancellationToken::default();
    assert_eq!(
        claim.decide_cancellable(&params, MemoryBudget::DEFAULT, Some(&fresh)),
        Ok(())
    );
    assert_eq!(
        claim.corrected_cancellable(&params, MemoryBudget::DEFAULT, Some(&fresh)),
        Err(Error::NotCorrected)
    );
    assert!(Error::from(iroha_pasta::msm::MsmError::Cancelled).is_cancelled());
    assert!(!Error::FoldEquation.is_cancelled());
    assert!(!Error::Undecidable.is_cancelled());
}

#[test]
fn cancellation_returns_no_fold_or_correction_and_fresh_retry_decides_both_curves() {
    cancellation_case::<Ep>();
    cancellation_case::<Eq>();
}

fn exceptional_identity_case<C: PastaCurve>() {
    // A test-only known-relation basis demonstrates the algebraic exception;
    // no production pinned parameters or challenge generation are replaced.
    let basis = [C::generator().to_affine(), (-C::generator()).to_affine()];
    let coefficients = fold_scalars(&[C::ScalarExt::ONE], C::ScalarExt::ONE);
    let corrected = msm_complete::<C>(&coefficients, &basis, MemoryBudget::DEFAULT).to_affine();
    assert!(bool::from(corrected.is_identity()));
    let mut normalized = [C::ScalarExt::ZERO; K];
    normalized[K - 1] = C::ScalarExt::ONE;
    assert_eq!(
        FoldInput::<C>::from_normalized(corrected, 1, normalized),
        Err(Error::Encoding(
            iroha_plonk::transcript::TranscriptError::IdentityPoint
        )),
        "an algebraically deciding identity cannot become a transportable correction"
    );
    assert_eq!(
        AccumulatorT::<C>::new(corrected, [C::ScalarExt::ONE; K]),
        Err(Error::Encoding(
            iroha_plonk::transcript::TranscriptError::IdentityPoint
        )),
        "construction failure is distinct from an undecidable finite claim"
    );
}

#[test]
fn exceptional_identity_correction_is_an_encoding_error_not_acceptance() {
    exceptional_identity_case::<Ep>();
    exceptional_identity_case::<Eq>();
}

fn prefix_case<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(4).expect("small pinned params");
    let challenges = [
        C::ScalarExt::from(3_u64),
        C::ScalarExt::from(5_u64),
        C::ScalarExt::from(7_u64),
    ];
    let coefficients = fold_scalars(&challenges, C::ScalarExt::ONE);
    let g = msm_complete::<C>(
        &coefficients,
        &params.params().g()[..8],
        MemoryBudget::new(0),
    )
    .to_affine();
    let source = FoldInput::<C>::from_opening(g, &challenges).expect("source");
    assert_eq!(source.decide(&params, MemoryBudget::new(0)), Ok(()));
    let padded = fold_scalars(source.challenges(), C::ScalarExt::ONE);
    assert_eq!(&padded[..8], &coefficients);
    assert!(padded[8..].iter().all(|value| bool::from(value.is_zero())));
    assert_eq!(
        source.corrected(&params, MemoryBudget::DEFAULT),
        Err(Error::NotCorrected)
    );
    let false_g = (g.to_curve() + C::generator()).to_affine();
    let false_claim = FoldInput::<C>::from_opening(false_g, &challenges).expect("false claim");
    assert_eq!(
        false_claim.decide(&params, MemoryBudget::DEFAULT),
        Err(Error::Undecidable)
    );
    let correction = false_claim
        .corrected(&params, MemoryBudget::DEFAULT)
        .expect("correction");
    assert_eq!(correction.original(), &false_claim);
    assert_eq!(correction.replacement(), &source);
    assert_eq!(
        correction
            .replacement()
            .decide(&params, MemoryBudget::DEFAULT),
        Ok(())
    );
    assert!(matches!(
        source.decide(
            &PinnedParams::<C>::derive(2).expect("params"),
            MemoryBudget::DEFAULT
        ),
        Err(Error::Parameters(_))
    ));
    assert!(matches!(
        AccumulatorT::<C>::trivial(&params, MemoryBudget::DEFAULT),
        Err(Error::Parameters(_))
    ));
}

#[test]
fn checked_prefix_and_correction_use_independent_complete_decide() {
    prefix_case::<Ep>();
    prefix_case::<Eq>();
}

fn generator_chunk_case<C: PastaCurve>() {
    let point = C::generator().to_affine();
    let original = vec![
        point,
        -point,
        C::identity().to_affine(),
        point,
        point,
        point,
        point,
        -point,
    ];
    for challenge in [C::ScalarExt::ONE, C::ScalarExt::from(13_u64)] {
        let expected: Vec<_> = original[..4]
            .iter()
            .zip(&original[4..])
            .map(|(low, high)| (low.to_curve() + high.to_curve() * challenge).to_affine())
            .collect();
        let held = SharedMemoryBudget::new(1);
        let guard = held.try_reserve(1).expect("saturate caller budget");
        for config in [
            FoldConfig::default(),
            FoldConfig {
                kernel_budget: MemoryBudget::new(0),
                shared_budget: SharedMemoryBudget::new(0),
                cancellation: None,
            },
            FoldConfig {
                kernel_budget: MemoryBudget::DEFAULT,
                shared_budget: held.clone(),
                cancellation: None,
            },
        ] {
            let mut actual = original.clone();
            crate::accumulation::fold_generators::<C>(&mut actual, challenge, &config).unwrap();
            assert_eq!(&actual[..4], expected);
        }
        drop(guard);
        assert_eq!(held.in_use_bytes(), 0);
    }
}

#[test]
fn generator_chunks_are_complete_and_budget_independent() {
    generator_chunk_case::<Ep>();
    generator_chunk_case::<Eq>();
}

/// Independent, direct base-field sponge framing, without Transcript/Writer.
fn reference_prelude<C: PastaCurve>(inputs: &[FoldInput<C>], salt: C::Base) -> [C::ScalarExt; 3]
where
    C::Base: PoseidonField,
{
    let mut sponge = Sponge::<C::Base>::new();
    sponge.update(&[
        C::Base::from(u64::from_le_bytes(*b"pipa-as1")),
        salt,
        C::Base::from(inputs.len() as u64),
    ]);
    for input in inputs {
        sponge.update(&[
            input.g().x(),
            input.g().y(),
            C::Base::from(u64::from(input.source_k())),
        ]);
        for scalar in input.challenges() {
            let words = scalar.to_canonical_limbs();
            if C::CURVE_ID == "pallas" {
                sponge.update(&[
                    C::Base::from_u128(u128::from(words[0]) | (u128::from(words[1]) << 64)),
                    C::Base::from_u128(u128::from(words[2]) | (u128::from(words[3]) << 64)),
                ]);
            } else {
                sponge.update(&[C::Base::from_canonical_limbs(words).expect("Fp fits Fq")]);
            }
        }
    }
    core::array::from_fn(|_| C::ScalarExt::from_raw_reduced(sponge.squeeze().to_canonical_limbs()))
}

fn transcript_case<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let generator = C::generator().to_affine();
    let full = AccumulatorT::<C>::new(
        generator,
        core::array::from_fn(|i| C::ScalarExt::from(i as u64 + 2)),
    )
    .expect("claim")
    .as_input();
    let short = FoldInput::<C>::from_opening(
        (-C::generator()).to_affine(),
        &[C::ScalarExt::from(9_u64); 3],
    )
    .expect("short");
    let inputs = [short, full];
    let salt = C::Base::from(42_u64);
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    let actual = prelude(&mut transcript, &inputs, &salt).expect("prelude");
    assert_eq!(actual, reference_prelude::<C>(&inputs, salt));
    let digest: [u8; 32] = Sha256::digest(
        actual
            .iter()
            .flat_map(PrimeField::to_repr)
            .collect::<Vec<_>>(),
    )
    .into();
    let expected = match C::CURVE_ID {
        "pallas" => "e55b8d7af07c5f4460cdf4aaadbe7e20da293398ec29d0f509f86131ccf398d6",
        "vesta" => "4a2cf8c915586737505a1d97b8dee219b640077411d287c52b0f16bd09c44a3b",
        _ => unreachable!("sealed Pasta curve"),
    };
    assert_eq!(hex(&digest), expected, "PIPA-AS prelude KAT");
    assert_ne!(actual, reference_prelude::<C>(&[inputs[1].clone()], salt));
    assert_ne!(
        actual,
        reference_prelude::<C>(&[inputs[1].clone(), inputs[0].clone()], salt)
    );
    assert_ne!(actual, reference_prelude::<C>(&inputs, salt + C::Base::ONE));
    assert_eq!(
        prelude(&mut transcript, &[], &salt),
        Err(Error::EmptyInputs)
    );
    assert_eq!(
        prelude(&mut transcript, &inputs[..1], &salt),
        Err(Error::MissingFullLengthInput)
    );
    // Complete Horner must support cancellation, repeated bases and alpha=0.
    let minus =
        FoldInput::<C>::from_opening(-generator, &[C::ScalarExt::ONE; K]).expect("opposite");
    let plus = FoldInput::<C>::from_opening(generator, &[C::ScalarExt::ONE; K]).expect("positive");
    assert_eq!(
        combined_commitment(&[plus.clone(), minus, plus.clone()], C::ScalarExt::ONE).to_affine(),
        generator
    );
    assert_eq!(
        combined_commitment(&[plus.clone(), plus], C::ScalarExt::ZERO),
        C::generator()
    );
}

#[test]
fn exact_transcript_order_and_complete_horner_both_curves() {
    transcript_case::<Ep>();
    transcript_case::<Eq>();
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(&mut out, "{byte:02x}").expect("write String");
        out
    })
}

fn full_fold_case<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let params = PinnedParams::<C>::derive(K_U32).expect("pinned params");
    let config = FoldConfig::default();
    let trivial = AccumulatorT::<C>::trivial(&params, config.kernel_budget).expect("trivial");
    let sum = params.params().g()[..GENERATORS]
        .iter()
        .fold(C::identity(), |sum, point| sum + point.to_curve());
    assert_eq!(*trivial.g(), sum.to_affine());
    trivial
        .decide(&params, config.kernel_budget)
        .expect("trivial decides");
    let source_challenges = [
        C::ScalarExt::from(3_u64),
        C::ScalarExt::from(5_u64),
        C::ScalarExt::from(7_u64),
    ];
    let coefficients = fold_scalars(&source_challenges, C::ScalarExt::ONE);
    let source_g = msm_complete::<C>(
        &coefficients,
        &params.params().g()[..8],
        config.kernel_budget,
    )
    .to_affine();
    let short = FoldInput::<C>::from_opening(source_g, &source_challenges).expect("short input");
    let salt = C::Base::from(123_u64).to_repr();
    assert_eq!(
        create_fold(&params, std::slice::from_ref(&short), salt, &config),
        Err(Error::MissingFullLengthInput)
    );
    let inputs = [short, trivial.as_input()];
    let (proof, output) = create_fold(&params, &inputs, salt, &config)
        .expect("explicit trivial fixes short-only liveness");
    let one_worker = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("pool");
    let serial = one_worker
        .install(|| create_fold(&params, &inputs, salt, &config))
        .expect("serial fold");
    assert_eq!(
        serial,
        (proof.clone(), output.clone()),
        "pool-independent proof bytes"
    );
    output
        .decide(&params, config.kernel_budget)
        .expect("honest fold decides");
    assert_eq!(
        verify_fold(&params, &inputs, &proof, &config),
        Ok(output.clone())
    );
    let no_scratch = FoldConfig {
        kernel_budget: MemoryBudget::new(0),
        shared_budget: SharedMemoryBudget::new(0),
        cancellation: None,
    };
    assert_eq!(
        verify_fold(&params, &inputs, &proof, &no_scratch),
        Ok(output.clone())
    );
    let (trivial_bytes, proof_digest, output_digest) = match C::CURVE_ID {
        "pallas" => (
            PALLAS_TRIVIAL_GENERATOR,
            "dab4df41fa90c325fbd9fd37737e3e344c8bb27f2c4434dd0c2e52870e5f3502",
            "38e31a279acd53a4734c854135a85ea2eebe439225b927bd9e9d9d2ee6ecde32",
        ),
        "vesta" => (
            VESTA_TRIVIAL_GENERATOR,
            "d16fc416b1564876768e2967737e0e205a047494331a4115fa941079a506dde2",
            "0c82ba5f627e8f75a3e284caf36464b5c92919fa10a5fa351ef7c540f9b33927",
        ),
        _ => unreachable!("sealed Pasta curve"),
    };
    assert_eq!(encode_point::<C>(trivial.g()), trivial_bytes);
    assert_eq!(hex(&Sha256::digest(proof.to_bytes())), proof_digest);
    assert_eq!(hex(&Sha256::digest(output.to_bytes())), output_digest);
    assert_eq!(
        verify_fold(&params, &inputs[..1], &proof, &config),
        Err(Error::MissingFullLengthInput)
    );
    assert_eq!(
        verify_fold(&params, &inputs[1..], &proof, &config),
        Err(Error::FoldEquation)
    );
    assert_eq!(
        verify_fold(
            &params,
            &[inputs[1].clone(), inputs[0].clone()],
            &proof,
            &config
        ),
        Err(Error::FoldEquation)
    );
    let changed_salt = FoldWitness::<C>::new(C::Base::from(124_u64).to_repr(), proof.body())
        .expect("changed salt");
    assert_eq!(
        verify_fold(&params, &inputs, &changed_salt, &config),
        Err(Error::FoldEquation)
    );
    for index in [0, 1, 15, 31, 33] {
        let mut body = *proof.body();
        let point = iroha_plonk::transcript::decode_point::<C>(
            &body[index * 32..(index + 1) * 32]
                .try_into()
                .expect("point"),
        )
        .expect("point");
        body[index * 32..(index + 1) * 32].copy_from_slice(&encode_point::<C>(&(-point)));
        let tampered = FoldWitness::<C>::new(salt, &body).expect("canonical tamper");
        assert_eq!(
            verify_fold(&params, &inputs, &tampered, &config),
            Err(Error::FoldEquation),
            "point {index}"
        );
    }
    let mut body = *proof.body();
    let value = iroha_plonk::transcript::decode_scalar::<C::ScalarExt>(
        &body[1024..1056].try_into().expect("scalar"),
    )
    .expect("scalar");
    body[1024..1056].copy_from_slice(&(value + C::ScalarExt::ONE).to_repr());
    assert_eq!(
        verify_fold(
            &params,
            &inputs,
            &FoldWitness::new(salt, &body).expect("scalar mutation"),
            &config
        ),
        Err(Error::FoldEquation)
    );
    let forged = forged_suffix(&params, &inputs, salt);
    let pending =
        verify_fold(&params, &inputs, &forged, &config).expect("solved succinct equation");
    assert_eq!(
        pending.decide(&params, config.kernel_budget),
        Err(Error::Undecidable)
    );
    // A false claim cannot be laundered by the honest fold prover.
    let mut false_inputs = inputs.clone();
    false_inputs[0] = FoldInput::from_opening(
        (source_g.to_curve() + C::generator()).to_affine(),
        &source_challenges,
    )
    .expect("false claim");
    assert_eq!(
        verify_fold(&params, &false_inputs, &proof, &config),
        Err(Error::FoldEquation)
    );
    assert_eq!(
        create_fold(&params, &false_inputs, salt, &config),
        Err(Error::FoldEquation)
    );
    let corrected = false_inputs[0]
        .corrected(&params, config.kernel_budget)
        .expect("corrected slot");
    assert_eq!(corrected.replacement(), &inputs[0]);
}

/// Forge a satisfiable succinct equation by choosing its unabsorbed suffix;
/// the independent decide must still reject the result.
fn forged_suffix<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    salt: [u8; 32],
) -> FoldWitness<C>
where
    C::Base: PoseidonField,
{
    let salt_value = C::Base::from_repr(salt).unwrap();
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    let [alpha, z, zeta] = prelude(&mut transcript, inputs, &salt_value).expect("prelude");
    let value = inputs.iter().rev().fold(C::ScalarExt::ZERO, |v, input| {
        v * alpha + fold_evaluation(z, input.challenges())
    });
    let mut equation =
        combined_commitment(inputs, alpha) - params.params().g()[0].to_curve() * value;
    let mut challenges = [C::ScalarExt::ZERO; K];
    for challenge in &mut challenges {
        let left = C::generator().to_affine();
        let right = (C::generator() * C::ScalarExt::from(2_u64)).to_affine();
        transcript.write_point(&left).expect("left");
        transcript.write_point(&right).expect("right");
        *challenge = transcript.squeeze_challenge();
        equation = equation
            + left.to_curve() * challenge.invert().unwrap()
            + right.to_curve() * *challenge;
    }
    transcript.write_scalar(&C::ScalarExt::ONE);
    equation -= params.params().u().to_curve() * (fold_evaluation(z, &challenges) * zeta);
    transcript
        .append_unabsorbed_point(&equation.to_affine())
        .expect("solved suffix");
    FoldWitness::new(salt, &transcript.finish()).expect("canonical forgery")
}

#[test]
#[ignore = "k16 native fold and independent decide; run with --release --ignored"]
fn pipa_as_full_pallas_fold_and_adversaries() {
    full_fold_case::<Ep>();
}

#[test]
#[ignore = "k16 native fold and independent decide; run with --release --ignored"]
fn pipa_as_full_vesta_fold_and_adversaries() {
    full_fold_case::<Eq>();
}
