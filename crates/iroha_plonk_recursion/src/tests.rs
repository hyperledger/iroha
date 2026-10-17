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
use crate::accumulation::{combined_commitment, digest_limbs, input_digest, prelude};
use core::ops::Deref;
use zeroize::Zeroizing;

/// Public deterministic DATA for algebraic regressions, never producer entropy.
fn fixture_tape<C: PastaCurve>(start: u64) -> FoldTape<C> {
    let mut value = start;
    FoldTape::try_fill::<()>(|coin| {
        *coin = C::ScalarExt::from(value);
        value += 1;
        Ok(())
    })
    .expect("public fixture tape")
}
fn fixture_purpose<C: PastaCurve>() -> FoldPurpose {
    if C::CURVE_ID == "pallas" {
        FoldPurpose::AInitial
    } else {
        FoldPurpose::SigmaBatch
    }
}
fn syntactic_bytes<C: PastaCurve>() -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES]);
    for chunk in bytes[..FOLD_BODY_BYTES].chunks_exact_mut(32) {
        chunk.copy_from_slice(&encode_point::<C>(&C::generator().to_affine()));
    }
    bytes[32 * (2 * K + 1)..32 * (2 * K + 2)].copy_from_slice(&C::ScalarExt::ONE.to_repr());
    bytes[FOLD_BODY_BYTES..].copy_from_slice(&fixture_tape::<C>(7).to_private_bytes());
    bytes
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
    let identity_claim = AccumulatorT::<C>::from_bytes(&bad).expect("canonical full-group G");
    assert!(bool::from(identity_claim.g().is_identity()));
    assert_eq!(identity_claim.to_bytes(), bad);
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

    let bytes = syntactic_bytes::<C>();
    let witness = FoldWitness::<C>::from_private_bytes(&bytes).expect("canonical messages");
    let retained = witness.to_private_bytes();
    assert_eq!(retained.deref(), bytes.as_slice());
    assert_eq!(retained.len(), 2176);
    let restored = FoldWitness::<C>::from_private_bytes(retained.deref()).expect("restored");
    assert_eq!(restored.to_private_bytes().deref(), retained.deref());
    for length in [0, 1087, 1119, 2175, 2177] {
        assert!(FoldWitness::<C>::from_private_bytes(&vec![0; length]).is_err());
    }
    for index in 0..2 * K + 3 {
        let mut malformed = syntactic_bytes::<C>();
        malformed[32 * index..32 * (index + 1)].fill(255);
        assert!(
            FoldWitness::<C>::from_private_bytes(&malformed).is_err(),
            "message {index}"
        );
        if index <= 2 * K {
            malformed[32 * index..32 * (index + 1)].fill(0);
            assert!(
                FoldWitness::<C>::from_private_bytes(&malformed).is_err(),
                "identity finite message {index}"
            );
        } else if index == 2 * K + 2 {
            malformed[32 * index..32 * (index + 1)].fill(0);
            assert!(
                FoldWitness::<C>::from_private_bytes(&malformed).is_ok(),
                "canonical identity generator suffix"
            );
        }
    }
    for index in 0..33 {
        let mut malformed = syntactic_bytes::<C>();
        malformed[FOLD_BODY_BYTES + 32 * index..FOLD_BODY_BYTES + 32 * (index + 1)].fill(255);
        assert!(
            FoldWitness::<C>::from_private_bytes(&malformed).is_err(),
            "coin {index}"
        );
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
    let witness = FoldWitness::<C>::from_private_bytes(&syntactic_bytes::<C>()).unwrap();
    let inputs =
        [FoldInput::from_opening(C::generator().to_affine(), &[C::ScalarExt::ONE; K]).unwrap()];
    let purpose = fixture_purpose::<C>();
    assert!(matches!(
        create_fold(&params, &inputs, fixture_tape(7), purpose, &config),
        Err(Error::Cancelled)
    ));
    assert_eq!(
        verify_fold(&params, &inputs, &witness, purpose, &config),
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
    let input = FoldInput::<C>::from_normalized(corrected, 1, normalized)
        .expect("full-group correction syntax");
    let full = AccumulatorT::<C>::new(corrected, [C::ScalarExt::ONE; K])
        .expect("full-group accumulator syntax");
    assert_eq!(AccumulatorT::from_bytes(&full.to_bytes()), Ok(full));
    // Syntax is not a decision. The same identity is false for the installed
    // independently derived two-generator prefix and must still be rejected.
    let params = PinnedParams::<C>::derive(1).unwrap();
    assert_eq!(
        input.decide(&params, MemoryBudget::DEFAULT),
        Err(Error::Undecidable)
    );
    let replacement = input
        .corrected(&params, MemoryBudget::DEFAULT)
        .expect("distinct actual generator");
    replacement
        .replacement()
        .decide(&params, MemoryBudget::DEFAULT)
        .unwrap();
    assert_eq!(
        replacement.original().challenges(),
        replacement.replacement().challenges()
    );
}

#[test]
fn full_group_identity_correction_still_requires_independent_decision() {
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

/// Independent base-field framing; no input_digest or Transcript calls.
fn reference_digest<C: PastaCurve>(
    params: &PinnedParams<C>,
    inputs: &[FoldInput<C>],
    tape: &FoldTape<C>,
    purpose: FoldPurpose,
) -> C::Base
where
    C::Base: PoseidonField,
{
    let parameter_digest = params.digest();
    let mut words = vec![
        C::Base::from_u128(u128::from_le_bytes(
            parameter_digest[..16].try_into().unwrap(),
        )),
        C::Base::from_u128(u128::from_le_bytes(
            parameter_digest[16..].try_into().unwrap(),
        )),
        C::Base::from(purpose.word()),
        C::Base::from(inputs.len() as u64),
    ];
    fn scalar<C: PastaCurve>(words: &mut Vec<C::Base>, value: &C::ScalarExt) {
        let limbs = value.to_canonical_limbs();
        if C::CURVE_ID == "pallas" {
            words.push(C::Base::from_u128(
                u128::from(limbs[0]) | (u128::from(limbs[1]) << 64),
            ));
            words.push(C::Base::from_u128(
                u128::from(limbs[2]) | (u128::from(limbs[3]) << 64),
            ));
        } else {
            words.push(C::Base::from_canonical_limbs(limbs).expect("Fp fits Fq"));
        }
    }
    for input in inputs {
        words.extend([
            input.g().x(),
            input.g().y(),
            C::Base::from(u64::from(input.source_k())),
        ]);
        for value in input.challenges() {
            scalar::<C>(&mut words, value);
        }
    }
    for value in tape.masks() {
        scalar::<C>(&mut words, value);
    }
    let mut sponge = Sponge::<C::Base>::new();
    sponge.update(&[
        C::Base::from(u64::from_le_bytes(*b"pipa-in1")),
        C::Base::from(words.len() as u64),
    ]);
    sponge.update(&words);
    sponge.squeeze()
}
/// Independent challenge context followed by the first committed point.
fn reference_prelude<C: PastaCurve>(
    params: &PinnedParams<C>,
    count: usize,
    purpose: FoldPurpose,
    d: C::AffineExt,
) -> [C::ScalarExt; 3]
where
    C::Base: PoseidonField,
{
    let parameter_digest = params.digest();
    let mut sponge = Sponge::<C::Base>::new();
    sponge.update(&[
        C::Base::from(u64::from_le_bytes(*b"pipa-as1")),
        C::Base::from_u128(u128::from_le_bytes(
            parameter_digest[..16].try_into().unwrap(),
        )),
        C::Base::from_u128(u128::from_le_bytes(
            parameter_digest[16..].try_into().unwrap(),
        )),
        C::Base::from(purpose.word()),
        C::Base::from(count as u64),
        d.x(),
        d.y(),
    ]);
    core::array::from_fn(|_| C::ScalarExt::from_raw_reduced(sponge.squeeze().to_canonical_limbs()))
}
fn fixture_opening<C: PastaCurve>(
    params: &PinnedParams<C>,
    digest: C::Base,
    tape: &FoldTape<C>,
) -> C::AffineExt {
    let [low, high] = digest_limbs::<C>(digest);
    (params.params().g()[0].to_curve() * low
        + params.params().g()[1].to_curve() * high
        + params.params().w().to_curve() * *tape.rho())
    .to_affine()
}

fn transcript_case<C: PastaCurve>()
where
    C::Base: PoseidonField,
{
    let params = PinnedParams::<C>::derive(4).expect("small pinned params");
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
    let purpose = fixture_purpose::<C>();
    let tape = fixture_tape::<C>(42);
    let h = input_digest(&params, &inputs, &tape, purpose);
    let identity_input = AccumulatorT::<C>::new(C::identity().to_affine(), [C::ScalarExt::ONE; K])
        .unwrap()
        .as_input();
    let identity_hash = input_digest(&params, &[identity_input], &tape, purpose);
    assert_ne!(
        identity_hash, h,
        "identity G has a defined canonical hash frame"
    );
    assert_eq!(h, reference_digest(&params, &inputs, &tape, purpose));
    let d = fixture_opening(&params, h, &tape);
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    prelude(&mut transcript, &params, &inputs, purpose).expect("prelude");
    transcript.write_point(&d).unwrap();
    let actual: [C::ScalarExt; 3] = core::array::from_fn(|_| transcript.squeeze_challenge());
    assert_eq!(
        actual,
        reference_prelude::<C>(&params, inputs.len(), purpose, d)
    );
    assert_eq!(
        transcript.finish(),
        encode_point::<C>(&d),
        "D is first and only proof message before alpha/z/zeta"
    );
    let digest: [u8; 32] = Sha256::digest(
        actual
            .iter()
            .flat_map(PrimeField::to_repr)
            .collect::<Vec<_>>(),
    )
    .into();
    let expected = match C::CURVE_ID {
        "pallas" => "50b9499cbbbbde6c024e4a0ccfe4411c9e6481d1b1e35c126c3636996af9601a",
        "vesta" => "2d3a0dfc3a3f7b376931fae7c76def42a3f5543375b2470c3359a99fe418f44f",
        _ => unreachable!("sealed Pasta curve"),
    };
    assert_eq!(hex(&digest), expected, "PIPA-AS committed prelude KAT");
    assert_ne!(
        h,
        reference_digest(&params, &[inputs[1].clone()], &tape, purpose)
    );
    assert_ne!(
        h,
        reference_digest(
            &params,
            &[inputs[1].clone(), inputs[0].clone()],
            &tape,
            purpose
        )
    );
    assert_ne!(
        h,
        reference_digest(&params, &inputs, &fixture_tape(43), purpose)
    );
    assert_ne!(actual, reference_prelude::<C>(&params, 1, purpose, d));
    assert_ne!(
        actual,
        reference_prelude::<C>(&params, inputs.len(), purpose, -d)
    );
    let alternate = if C::CURVE_ID == "pallas" {
        FoldPurpose::AContinuation
    } else {
        FoldPurpose::WrapperVesta
    };
    assert_ne!(h, reference_digest(&params, &inputs, &tape, alternate));
    assert_ne!(
        actual,
        reference_prelude::<C>(&params, inputs.len(), alternate, d)
    );
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    assert_eq!(
        prelude(&mut transcript, &params, &[], purpose),
        Err(Error::EmptyInputs)
    );
    assert_eq!(
        prelude(&mut transcript, &params, &inputs[..1], purpose),
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
    let purpose = fixture_purpose::<C>();
    assert!(matches!(
        create_fold(
            &params,
            std::slice::from_ref(&short),
            fixture_tape(123),
            purpose,
            &config
        ),
        Err(Error::MissingFullLengthInput)
    ));
    let inputs = [short, trivial.as_input()];
    let (proof, output) = create_fold(&params, &inputs, fixture_tape(123), purpose, &config)
        .expect("explicit trivial fixes short-only liveness");
    let one_worker = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("pool");
    let serial = one_worker
        .install(|| create_fold(&params, &inputs, fixture_tape(123), purpose, &config))
        .expect("serial fold");
    let original = proof.to_private_bytes();
    assert_eq!(
        serial.0.to_private_bytes().deref(),
        original.deref(),
        "pool-independent proof bytes"
    );
    assert_eq!(serial.1, output, "pool-independent accumulator");
    output
        .decide(&params, config.kernel_budget)
        .expect("honest fold decides");
    assert_eq!(
        verify_fold(&params, &inputs, &proof, purpose, &config),
        Ok(output.clone())
    );
    let no_scratch = FoldConfig {
        kernel_budget: MemoryBudget::new(0),
        shared_budget: SharedMemoryBudget::new(0),
        cancellation: None,
    };
    assert_eq!(
        verify_fold(&params, &inputs, &proof, purpose, &no_scratch),
        Ok(output.clone())
    );
    let (trivial_bytes, proof_digest, output_digest) = match C::CURVE_ID {
        "pallas" => (
            PALLAS_TRIVIAL_GENERATOR,
            "d9dd041e643773b95eacfd656aaff0b1038867a2d7957871d039417393c050e8",
            "8163b08a40c93450b8b52095aaccafc5614a0fddb9e904c676b422bcd4fe70b6",
        ),
        "vesta" => (
            VESTA_TRIVIAL_GENERATOR,
            "b504228ccc2f630eb4863b01888f1e399808715b21740d9226fb33d9f4c684ce",
            "3e0e2ac6de70b2c5cde576fee8d242ff2f52cfee81b36dc0dcc0eecc3a7781e0",
        ),
        _ => unreachable!("sealed Pasta curve"),
    };
    assert_eq!(encode_point::<C>(trivial.g()), trivial_bytes);
    assert_eq!(hex(&Sha256::digest(original.deref())), proof_digest);
    assert_eq!(hex(&Sha256::digest(output.to_bytes())), output_digest);
    assert_eq!(
        verify_fold(&params, &inputs[..1], &proof, purpose, &config),
        Err(Error::MissingFullLengthInput)
    );
    assert_eq!(
        verify_fold(&params, &inputs[1..], &proof, purpose, &config),
        Err(Error::FoldEquation)
    );
    assert_eq!(
        verify_fold(
            &params,
            &[inputs[1].clone(), inputs[0].clone()],
            &proof,
            purpose,
            &config
        ),
        Err(Error::FoldEquation)
    );
    for coin in 0..33 {
        let changed = proof.to_private_bytes();
        // This explicit writer keeps mutation output under its clearing owner.
        let offset = FOLD_BODY_BYTES + coin * 32;
        let value = iroha_plonk::transcript::decode_scalar::<C::ScalarExt>(
            &changed[offset..offset + 32].try_into().unwrap(),
        )
        .unwrap();
        let mutation = (value + C::ScalarExt::ONE).to_repr();
        let owned =
            crate::PrivateWitnessBytes::try_write::<std::io::Error>(FOLD_WITNESS_BYTES, |writer| {
                writer.write_all(&changed[..offset])?;
                writer.write_all(&mutation)?;
                writer.write_all(&changed[offset + 32..])
            })
            .unwrap();
        let tampered = FoldWitness::<C>::from_private_bytes(owned.deref()).unwrap();
        assert_eq!(
            verify_fold(&params, &inputs, &tampered, purpose, &config),
            Err(Error::FoldEquation),
            "coin {coin}"
        );
        // Preserve the retained source, even after a failed replay.
        assert_eq!(changed.deref(), original.deref());
    }
    for index in [0, 1, 2, 16, 32, 34] {
        let mut bytes = Zeroizing::new(original.to_vec());
        let point = iroha_plonk::transcript::decode_point::<C>(
            &bytes[index * 32..(index + 1) * 32].try_into().unwrap(),
        )
        .unwrap();
        bytes[index * 32..(index + 1) * 32].copy_from_slice(&encode_point::<C>(&(-point)));
        let tampered = FoldWitness::<C>::from_private_bytes(&bytes).expect("canonical tamper");
        assert_eq!(
            verify_fold(&params, &inputs, &tampered, purpose, &config),
            Err(Error::FoldEquation),
            "point {index}"
        );
    }
    let mut bytes = Zeroizing::new(original.to_vec());
    let offset = 32 * (2 * K + 1);
    let value = iroha_plonk::transcript::decode_scalar::<C::ScalarExt>(
        &bytes[offset..offset + 32].try_into().unwrap(),
    )
    .unwrap();
    bytes[offset..offset + 32].copy_from_slice(&(value + C::ScalarExt::ONE).to_repr());
    assert_eq!(
        verify_fold(
            &params,
            &inputs,
            &FoldWitness::from_private_bytes(&bytes).unwrap(),
            purpose,
            &config
        ),
        Err(Error::FoldEquation)
    );
    let forged = forged_suffix(&params, &inputs, purpose);
    let pending =
        verify_fold(&params, &inputs, &forged, purpose, &config).expect("solved succinct equation");
    assert_eq!(
        pending.decide(&params, config.kernel_budget),
        Err(Error::Undecidable)
    );
    let correction = pending
        .as_input()
        .corrected(&params, config.kernel_budget)
        .expect("distinct correction");
    assert_ne!(correction.original().g(), correction.replacement().g());
    assert_eq!(
        correction.original().challenges(),
        correction.replacement().challenges()
    );
    correction
        .replacement()
        .decide(&params, config.kernel_budget)
        .expect("corrected claim decides");
    // A false claim cannot be laundered by the honest fold prover.
    let mut false_inputs = inputs.clone();
    false_inputs[0] = FoldInput::from_opening(
        (source_g.to_curve() + C::generator()).to_affine(),
        &source_challenges,
    )
    .expect("false claim");
    assert_eq!(
        verify_fold(&params, &false_inputs, &proof, purpose, &config),
        Err(Error::FoldEquation)
    );
    assert!(matches!(
        create_fold(&params, &false_inputs, fixture_tape(123), purpose, &config),
        Err(Error::FoldEquation)
    ));
    assert_eq!(proof.to_private_bytes().deref(), original.deref());
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
    purpose: FoldPurpose,
) -> FoldWitness<C>
where
    C::Base: PoseidonField,
{
    let tape = fixture_tape::<C>(181);
    let digest = input_digest(params, inputs, &tape, purpose);
    let d = fixture_opening(params, digest, &tape);
    let mut transcript = TranscriptWriter::<C, _>::new(BasePoseidonHash::with_domain(*b"pipa-as1"));
    prelude(&mut transcript, params, inputs, purpose).expect("prelude");
    transcript.write_point(&d).unwrap();
    let [alpha, z, zeta] = core::array::from_fn(|_| transcript.squeeze_challenge());
    let value = inputs.iter().rev().fold(C::ScalarExt::ZERO, |v, input| {
        v * alpha + fold_evaluation(z, input.challenges())
    });
    let mut equation =
        combined_commitment(inputs, alpha) - params.params().g()[0].to_curve() * value;
    let mut challenges = [C::ScalarExt::ZERO; K];
    let mut gamma = C::ScalarExt::ZERO;
    for (round, challenge) in challenges.iter_mut().enumerate() {
        let left =
            (C::generator() + params.params().w().to_curve() * tape.masks()[2 * round]).to_affine();
        let right = (C::generator() * C::ScalarExt::from(2_u64)
            + params.params().w().to_curve() * tape.masks()[2 * round + 1])
            .to_affine();
        transcript.write_point(&left).expect("left");
        transcript.write_point(&right).expect("right");
        *challenge =
            iroha_plonk::transcript::pipa_r::nonzero_challenge(transcript.squeeze_challenge());
        gamma += tape.masks()[2 * round] * challenge.invert().unwrap()
            + tape.masks()[2 * round + 1] * *challenge;
        equation = equation
            + left.to_curve() * challenge.invert().unwrap()
            + right.to_curve() * *challenge;
    }
    transcript.write_scalar(&C::ScalarExt::ONE);
    equation -= params.params().w().to_curve() * gamma;
    equation -= params.params().u().to_curve() * (fold_evaluation(z, &challenges) * zeta);
    transcript
        .append_unabsorbed_generator(&equation.to_affine())
        .expect("solved suffix");
    let body = Zeroizing::new(transcript.finish());
    let coins = tape.to_private_bytes();
    let mut bytes = Zeroizing::new(vec![0; FOLD_WITNESS_BYTES]);
    bytes[..FOLD_BODY_BYTES].copy_from_slice(&body);
    bytes[FOLD_BODY_BYTES..].copy_from_slice(&coins);
    FoldWitness::from_private_bytes(&bytes).expect("canonical forgery")
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
