//! Differential checks and a paired diagnostic for exact row-mask interpolation.

use super::*;
use iroha_pasta::{CancellationToken, Fp, Fq};

fn values<F: PastaField>(n: usize, last: usize) -> Masks<F> {
    let mut l0 = vec![F::ZERO; n];
    l0[0] = F::ONE;
    let mut l_last = vec![F::ZERO; n];
    l_last[last] = F::ONE;
    let l_active = (0..n)
        .map(|row| if row < last { F::ONE } else { F::ZERO })
        .collect();
    Masks {
        l0,
        l_last,
        l_active,
    }
}

/// The former three-transform implementation, retained only as a test oracle.
fn reference<F: PastaField>(domain: &FftDomain<F>, values: &Masks<F>) -> Masks<F> {
    let polynomials = interpolate_all(
        domain,
        &[
            values.l0.clone(),
            values.l_last.clone(),
            values.l_active.clone(),
        ],
        None,
    )
    .expect("reference transforms");
    let [l0, l_last, l_active] = polynomials.try_into().unwrap();
    Masks {
        l0,
        l_last,
        l_active,
    }
}

fn compare<F: PastaField>() {
    for k in [0, 1, 3, 6, 10] {
        let domain = FftDomain::<F>::new(k).unwrap();
        let n = domain.n();
        // All small-domain rows, plus both endpoints and ordinary blind-row
        // boundaries at larger sizes, exercise the inverse-root sign and phase.
        let rows: Vec<_> = if n <= 8 {
            (0..n).collect()
        } else {
            vec![0, 1, n / 2, n - 6, n - 1]
        };
        for last in rows {
            let values = values(n, last);
            let actual = interpolate_masks(&domain, &values, last, None).unwrap();
            assert_eq!(actual, reference(&domain, &values));
            for (coefficients, expected) in [
                (&actual.l0, &values.l0),
                (&actual.l_last, &values.l_last),
                (&actual.l_active, &values.l_active),
            ] {
                let mut evaluations = coefficients.clone();
                domain.fft(&mut evaluations).unwrap();
                assert_eq!(&evaluations, expected);
            }
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert_eq!(
                interpolate_masks(&domain, &values, last, Some(&cancelled)),
                Err(KeyError::Cancelled)
            );
            let active = CancellationToken::new();
            assert_eq!(
                interpolate_masks(&domain, &values, last, Some(&active)).unwrap(),
                actual
            );
        }
    }
}

#[test]
fn closed_form_masks_match_three_iffts_on_both_fields() {
    compare::<Fp>();
    compare::<Fq>();
}

/// Host-only paired timing; never a wallet, proof or physical-device result.
#[test]
#[ignore = "release-mode diagnostic; run alone to avoid benchmark contention"]
fn mask_interpolation_paired_timing() {
    use std::{hint::black_box, time::Instant};

    fn bench<F: PastaField>(field: &str) {
        for k in [11, 14, 17] {
            let domain = FftDomain::<F>::new(k).unwrap();
            let last = domain.n() - 6;
            let values = values(domain.n(), last);
            assert_eq!(
                interpolate_masks(&domain, &values, last, None).unwrap(),
                reference(&domain, &values)
            );
            let mut before = Vec::new();
            let mut after = Vec::new();
            for sample in 0..9 {
                let mut old = || {
                    let start = Instant::now();
                    black_box(reference(&domain, black_box(&values)));
                    before.push(start.elapsed().as_micros());
                };
                let mut new = || {
                    let start = Instant::now();
                    black_box(interpolate_masks(&domain, black_box(&values), last, None).unwrap());
                    after.push(start.elapsed().as_micros());
                };
                if sample % 2 == 0 {
                    old();
                    new();
                } else {
                    new();
                    old();
                }
            }
            before.sort_unstable();
            after.sort_unstable();
            eprintln!(
                "mask_interpolation field={field} k={k} samples=9 before_median_us={} after_median_us={} before_us={before:?} after_us={after:?}",
                before[4], after[4]
            );
        }
    }
    bench::<Fp>("Fp");
    bench::<Fq>("Fq");
}
