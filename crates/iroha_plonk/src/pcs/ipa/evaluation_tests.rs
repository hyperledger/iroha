//! Differential and diagnostic coverage of the polynomial evaluation leaves.

use std::{hint::black_box, time::Instant};

use ff::Field;
use iroha_pasta::{Fp, Fq};
use rand_chacha::ChaCha20Rng;
use rand_core_06::SeedableRng;

use super::{evaluate_horner_interleaved, evaluate_polynomial};

fn reference<F: Field>(coeffs: &[F], x: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

fn differential<F: Field>() {
    let mut rng = ChaCha20Rng::seed_from_u64(79);
    for len in (0..80).chain([511, 512, 513, 4095, 4096, 4097, 8191, 8192, 8193]) {
        let coeffs: Vec<F> = (0..len).map(|_| F::random(&mut rng)).collect();
        for x in [F::ZERO, F::ONE, -F::ONE, F::random(&mut rng)] {
            let expected = reference(&coeffs, x);
            assert_eq!(
                evaluate_horner_interleaved(&coeffs, x),
                expected,
                "len={len}"
            );
            assert_eq!(evaluate_polynomial(&coeffs, x), expected, "len={len}");
        }
    }
}

#[test]
fn interleaved_horner_matches_random_full_width_coefficients_and_tails() {
    differential::<Fp>();
    differential::<Fq>();
}

fn measure<F: Field>(field: &str) {
    let mut rng = ChaCha20Rng::seed_from_u64(179);
    for k in [12, 16, 18] {
        let coeffs: Vec<F> = (0..1 << k).map(|_| F::random(&mut rng)).collect();
        let x = F::random(&mut rng);
        assert_eq!(
            evaluate_horner_interleaved(&coeffs, x),
            reference(&coeffs, x)
        );
        let runs = 1 << (21 - k);
        let mut baseline = Vec::new();
        let mut interleaved = Vec::new();
        for sample in 0..9 {
            for optimized in if sample % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = Instant::now();
                for _ in 0..runs {
                    let coeffs = black_box(&coeffs);
                    let x = black_box(x);
                    black_box(if optimized {
                        evaluate_horner_interleaved(coeffs, x)
                    } else {
                        reference(coeffs, x)
                    });
                }
                let elapsed = start.elapsed().as_secs_f64() * 1000.0 / f64::from(runs);
                if optimized {
                    interleaved.push(elapsed);
                } else {
                    baseline.push(elapsed);
                }
            }
        }
        baseline.sort_by(f64::total_cmp);
        interleaved.sort_by(f64::total_cmp);
        println!(
            "HORNER field={field} k={k} samples=9 repeats={runs} baseline_median_ms={:.6} interleaved_median_ms={:.6} ratio={:.4}",
            baseline[4],
            interleaved[4],
            interleaved[4] / baseline[4]
        );
    }
}

#[test]
#[ignore = "release-only paired arithmetic diagnostic; not a phone latency measurement"]
fn measure_interleaved_horner_leaves() {
    assert!(
        !cfg!(debug_assertions),
        "run this diagnostic with --release"
    );
    measure::<Fp>("Fp");
    measure::<Fq>("Fq");
}
