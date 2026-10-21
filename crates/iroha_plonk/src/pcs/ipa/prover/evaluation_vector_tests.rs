//! The original explicit public vector is the independent round oracle.

use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaField};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::*;
use crate::transcript::{Blake2bHash, Transcript, TranscriptError, TranscriptWriter};

fn check_rounds<F: PastaField>(domains: &[u32]) {
    let mut rng = ChaCha20Rng::seed_from_u64(821);
    for &k in domains {
        let n = 1usize << k;
        for x in [F::ZERO, F::ONE, -F::ONE, F::random(&mut rng)] {
            let mut p: Vec<F> = (0..n).map(|_| F::random(&mut rng)).collect();
            let mut b = Vec::with_capacity(n);
            let mut power = F::ONE;
            for _ in 0..n {
                b.push(power);
                power *= x;
            }
            let mut evaluation = FoldedEvaluation::new(x, k);
            assert_eq!(evaluation.powers.len(), k as usize);
            for round in 0..k {
                let half = n >> (round + 1);
                let expected_l = super::super::inner_product(&p[half..2 * half], &b[..half]);
                let expected_r = super::super::inner_product(&p[..half], &b[half..2 * half]);
                assert_eq!(
                    evaluation.cross_terms(&p[..half], &p[half..2 * half], None),
                    Ok((expected_l, expected_r))
                );
                // For x = +/-1 this forces a zero factor. The formulas must
                // continue to work without dividing by that factor.
                let challenge = if round == 0 {
                    -F::ONE
                } else {
                    crate::transcript::pipa_r::nonzero_challenge(F::random(&mut rng))
                };
                let inverse = Option::<F>::from(challenge.invert()).unwrap();
                let (p_lo, p_hi) = p.split_at_mut(half);
                for (lo, hi) in p_lo.iter_mut().zip(p_hi.iter()) {
                    *lo += *hi * inverse;
                }
                let (b_lo, b_hi) = b.split_at_mut(half);
                for (lo, hi) in b_lo.iter_mut().zip(b_hi.iter()) {
                    *lo += *hi * challenge;
                }
                p.truncate(half);
                b.truncate(half);
                evaluation.fold(challenge);
                assert_eq!(evaluation.powers.len(), (k - round - 1) as usize);
                let mut power = F::ONE;
                for value in &b {
                    assert_eq!(*value, evaluation.factor * power);
                    power *= x;
                }
            }
            assert!(evaluation.powers.is_empty());
            assert_eq!(b, vec![evaluation.factor]);
        }
    }
}

#[test]
fn implicit_vector_matches_explicit_rounds_on_both_fields() {
    for workers in [1, 4] {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check_rounds::<Fp>(&[0, 1, 4, 8, 12]);
                check_rounds::<Fq>(&[0, 1, 4, 8, 12]);
            });
    }
}

#[test]
#[ignore = "explicit k16 arithmetic parity check; not a timing or phone measurement"]
fn implicit_vector_matches_explicit_k16_rounds() {
    for workers in [1, 4] {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                check_rounds::<Fp>(&[16]);
                check_rounds::<Fq>(&[16]);
            });
    }
}

#[test]
fn implicit_cross_terms_preserve_cancellation() {
    let evaluation = FoldedEvaluation::new(Fp::from(7), 1);
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        evaluation.cross_terms(&[Fp::ONE], &[Fp::ONE], Some(&token)),
        Err(iroha_pasta::Cancelled)
    );
}

struct CancelAfterRound<'a, C: PastaCurve> {
    inner: TranscriptWriter<C, Blake2bHash<C>>,
    token: &'a CancellationToken,
    writes: usize,
}

impl<C: PastaCurve> Transcript<C> for CancelAfterRound<'_, C> {
    fn squeeze_challenge(&mut self) -> C::ScalarExt {
        self.inner.squeeze_challenge()
    }
    fn common_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.inner.common_point(point)
    }
    fn common_scalar(&mut self, scalar: &C::ScalarExt) {
        self.inner.common_scalar(scalar);
    }
}

impl<C: PastaCurve> TranscriptWrite<C> for CancelAfterRound<'_, C> {
    fn write_point(&mut self, point: &C::AffineExt) -> Result<(), TranscriptError> {
        self.inner.write_point(point)?;
        self.writes += 1;
        // S, L0 and R0 have all been computed; cancellation must not return
        // a completed claim and a fresh seeded retry must keep exact bytes.
        if self.writes == 3 {
            self.token.cancel();
        }
        Ok(())
    }
    fn write_scalar(&mut self, scalar: &C::ScalarExt) {
        self.inner.write_scalar(scalar);
    }
}

fn cancel_and_retry<C: PastaCurve>() {
    let params = ParamsIpa::<C>::new(3).unwrap();
    let mut setup_rng = ChaCha20Rng::seed_from_u64(822);
    let poly: Vec<_> = (0..params.n())
        .map(|_| C::ScalarExt::random(&mut setup_rng))
        .collect();
    let prove = |token: Option<&CancellationToken>| {
        let mut transcript = TranscriptWriter::<C, _>::new(Blake2bHash::<C>::new());
        let claim = create_proof_with_claim_cancellable(
            &params,
            &mut ChaCha20Rng::seed_from_u64(823),
            &mut transcript,
            &poly,
            &C::ScalarExt::ONE,
            &C::ScalarExt::from(7),
            MemoryBudget::DEFAULT,
            token,
        )
        .unwrap();
        (transcript.finish(), claim)
    };
    let expected = prove(None);
    let token = CancellationToken::new();
    let mut transcript = CancelAfterRound {
        inner: TranscriptWriter::<C, _>::new(Blake2bHash::<C>::new()),
        token: &token,
        writes: 0,
    };
    let cancelled = create_proof_with_claim_cancellable(
        &params,
        &mut ChaCha20Rng::seed_from_u64(823),
        &mut transcript,
        &poly,
        &C::ScalarExt::ONE,
        &C::ScalarExt::from(7),
        MemoryBudget::DEFAULT,
        Some(&token),
    );
    assert!(matches!(cancelled, Err(IpaError::Cancelled)));
    assert_eq!(transcript.writes, 3);
    let fresh = CancellationToken::new();
    let resumed = prove(Some(&fresh));
    assert_eq!(resumed.0, expected.0);
    assert_eq!(resumed.1, expected.1);
}

#[test]
fn implicit_vector_opening_cancellation_retains_exact_seeded_retry() {
    for workers in [1, 4] {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
            .install(|| {
                cancel_and_retry::<Ep>();
                cancel_and_retry::<Eq>();
            });
    }
}

/// Synthetic public inputs shared by both arithmetic arms. Prepare the common
/// p' folds outside timing; these are neither secret witnesses nor proof RNG.
fn diagnostic_rounds<F: PastaField>(k: u32, x: F, challenges: &[F], seed: u64) -> Vec<Vec<F>> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut p: Vec<F> = (0..1usize << k).map(|_| F::random(&mut rng)).collect();
    let at_x = evaluate_polynomial(&p, x);
    p[0] -= at_x;
    let mut rounds = Vec::with_capacity(k as usize);
    for &challenge in challenges {
        rounds.push(p.clone());
        let half = p.len() / 2;
        let inverse = Option::<F>::from(challenge.invert()).unwrap();
        let (low, high) = p.split_at_mut(half);
        for (low, high) in low.iter_mut().zip(high.iter()) {
            *low += *high * inverse;
        }
        p.truncate(half);
    }
    rounds
}

/// Includes construction, every cross term/fold, and public-state deallocation.
/// The supplied output has capacity for every round before this function runs.
fn diagnostic_explicit<F: PastaField>(
    rounds: &[Vec<F>],
    x: F,
    challenges: &[F],
    output: &mut Vec<(F, F)>,
) -> (F, usize, usize) {
    let mut b = Vec::with_capacity(rounds[0].len());
    let mut power = F::ONE;
    for _ in 0..rounds[0].len() {
        b.push(power);
        power *= x;
    }
    let payload = b.capacity() * size_of::<F>();
    for (p, &challenge) in rounds.iter().zip(challenges) {
        let half = p.len() / 2;
        output.push((
            super::super::inner_product(&p[half..], &b[..half]),
            super::super::inner_product(&p[..half], &b[half..]),
        ));
        let (low, high) = b.split_at_mut(half);
        for (low, high) in low.iter_mut().zip(high.iter()) {
            *low += *high * challenge;
        }
        b.truncate(half);
    }
    let final_value = b[0];
    std::hint::black_box(&b);
    drop(b);
    (final_value, payload, size_of::<Vec<F>>())
}

fn diagnostic_implicit<F: PastaField>(
    rounds: &[Vec<F>],
    x: F,
    challenges: &[F],
    output: &mut Vec<(F, F)>,
) -> (F, usize, usize) {
    let mut evaluation = FoldedEvaluation::new(x, challenges.len() as u32);
    let payload = evaluation.powers.capacity() * size_of::<F>();
    for (p, &challenge) in rounds.iter().zip(challenges) {
        let half = p.len() / 2;
        output.push(
            evaluation
                .cross_terms(&p[..half], &p[half..], None)
                .unwrap(),
        );
        evaluation.fold(challenge);
    }
    let final_value = evaluation.factor;
    std::hint::black_box(&evaluation);
    drop(evaluation);
    (final_value, payload, size_of::<FoldedEvaluation<F>>())
}

fn measure_evaluation_vector<C: PastaCurve>(curve: &str, workers: usize) {
    use std::{hint::black_box, time::Instant};
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    pool.install(|| {
        for k in [12_u32, 16] {
            // Two bounded blocks use different public seeds. ABBA followed by
            // BAAB balances positions; each arm runs four measured samples.
            for block in 0_u64..2 {
                let seed = 0x4950_4100 + u64::from(k) * 16 + block;
                let mut rng = ChaCha20Rng::seed_from_u64(seed);
                let x = crate::transcript::pipa_r::nonzero_challenge(C::ScalarExt::random(&mut rng));
                let challenges: Vec<_> = (0..k).map(|_| {
                    crate::transcript::pipa_r::nonzero_challenge(C::ScalarExt::random(&mut rng))
                }).collect();
                let rounds = diagnostic_rounds(k, x, &challenges, seed + 1024);
                let mut expected = Vec::with_capacity(k as usize);
                let expected_final = diagnostic_explicit(&rounds, x, &challenges, &mut expected).0;
                let mut output = Vec::with_capacity(k as usize);
                let warm = diagnostic_implicit(&rounds, x, &challenges, &mut output).0;
                assert_eq!(output, expected);
                assert_eq!(warm, expected_final);
                let order = if block == 0 { [false, true, true, false] } else { [true, false, false, true] };
                for (position, implicit) in order.into_iter().enumerate() {
                    output.clear();
                    let start = Instant::now();
                    let (final_value, payload_bytes, state_bytes) = if implicit {
                        diagnostic_implicit(black_box(&rounds), black_box(x), black_box(&challenges), &mut output)
                    } else {
                        diagnostic_explicit(black_box(&rounds), black_box(x), black_box(&challenges), &mut output)
                    };
                    black_box((&output, final_value));
                    let elapsed_ns = start.elapsed().as_nanos();
                    // Complete cross-term and final-vector equality is outside
                    // timing; neither comparison nor output drop is counted.
                    assert_eq!(output, expected);
                    assert_eq!(final_value, expected_final);
                    assert_eq!(output.len(), k as usize);
                    let arm = if implicit { "implicit" } else { "explicit" };
                    println!(
                        "IPA_VECTOR_ARITHMETIC curve={curve} k={k} workers={workers} block={block} position={position} seed={seed} arm={arm} elapsed_ns={elapsed_ns} public_payload_capacity_bytes={payload_bytes} state_size_bytes={state_bytes} rounds={k} equal=true scope=arithmetic_component_only"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "release-only balanced scalar-component diagnostic; not proof or phone latency"]
fn measure_explicit_implicit_evaluation_vectors() {
    assert!(
        !cfg!(debug_assertions),
        "run this diagnostic with --release"
    );
    for workers in [1, 4] {
        measure_evaluation_vector::<Ep>("Pallas", workers);
        measure_evaluation_vector::<Eq>("Vesta", workers);
    }
}
