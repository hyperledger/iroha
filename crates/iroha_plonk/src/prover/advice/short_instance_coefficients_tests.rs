//! Exact public-prefix interpolation against the unchanged dense IFFT.
use super::*;
use ff::Field;
use iroha_pasta::{
    Ep, Eq, Fp, Fq, PastaCurve, PastaField,
    fft::{FftDomain, FftError},
};

fn dense<F: PastaField>(domain: &FftDomain<F>, values: &[F]) -> Vec<F> {
    let mut output = values.to_vec();
    domain.ifft(&mut output).unwrap();
    output
}

#[test]
fn short_instance_coefficients_match_dense_ifft_both_fields_all_sizes() {
    fn check<F: PastaField>() {
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                for k in 0..=16 {
                    let domain = FftDomain::<F>::new(k).unwrap();
                    for len in 0..=4_usize {
                        if len > domain.n() {
                            continue;
                        }
                        for variant in 0..2 {
                            let prefix: Vec<F> = (0..len)
                                .map(|j| {
                                    if variant == 1 && j == 0 {
                                        F::ZERO
                                    } else {
                                        F::from((j * 19 + 7) as u64)
                                    }
                                })
                                .collect();
                            let mut padded = prefix.clone();
                            padded.resize(domain.n(), F::ZERO);
                            let expected = dense(&domain, &padded);
                            let mut actual = padded.clone();
                            let pointer = actual.as_ptr();
                            let capacity = actual.capacity();
                            let used =
                                interpolate_short_instance(&domain, &prefix, &mut actual, None)
                                    .unwrap();
                            assert_eq!(used, len <= 2);
                            if !used {
                                assert_eq!(
                                    actual, padded,
                                    "long prefixes retain the old IFFT input"
                                );
                                domain.ifft(&mut actual).unwrap();
                            }
                            assert_eq!(actual, expected, "k={k}, length={len}, workers={workers}");
                            assert_eq!(actual.as_ptr(), pointer);
                            assert_eq!(actual.capacity(), capacity);
                            assert_eq!(&padded[..len], &prefix);
                        }
                    }
                }
            });
        }
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn short_instance_coefficients_preflight_chunk_cancellation_and_retry() {
    fn check<F: PastaField>() {
        let domain = FftDomain::<F>::new(12).unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        for prefix in [vec![], vec![F::from(3)], vec![F::from(3), F::from(7)]] {
            let sentinel = vec![F::from(101); domain.n()];
            let mut output = sentinel.clone();
            assert_eq!(
                interpolate_short_instance(&domain, &prefix, &mut output, Some(&cancelled)),
                Err(FftError::Cancelled)
            );
            assert_eq!(output, sentinel);
            let mut short_output = vec![F::ONE; domain.n() - 1];
            assert_eq!(
                interpolate_short_instance(&domain, &prefix, &mut short_output, None),
                Err(FftError::WrongLength {
                    expected: domain.n(),
                    actual: domain.n() - 1
                })
            );
            assert!(short_output.iter().all(|v| *v == F::ONE));

            let constant = prefix.first().copied().unwrap_or(F::ZERO) * domain.n_inv();
            let linear = prefix
                .get(1)
                .map(|value| (*value * domain.n_inv(), domain.omega_inv()));
            let token = CancellationToken::new();
            // Exercise the exact production chunk function, then retire its token
            // before the next chunk. No timing-dependent cancellation race.
            interpolate_short_instance_chunk(
                &mut output[..1024],
                0,
                constant,
                linear,
                Some(&token),
            )
            .unwrap();
            let first = output[..1024].to_vec();
            token.cancel();
            assert_eq!(
                interpolate_short_instance_chunk(
                    &mut output[1024..2048],
                    1024,
                    constant,
                    linear,
                    Some(&token)
                ),
                Err(FftError::Cancelled)
            );
            assert_eq!(&output[..1024], &first);
            assert_eq!(&output[1024..], &sentinel[1024..]);
            let fresh = CancellationToken::new();
            assert!(
                interpolate_short_instance(&domain, &prefix, &mut output, Some(&fresh)).unwrap()
            );
            let mut padded = prefix;
            padded.resize(domain.n(), F::ZERO);
            assert_eq!(output, dense(&domain, &padded));
        }
        let one = FftDomain::<F>::new(0).unwrap();
        let mut output = vec![F::from(23)];
        assert!(!interpolate_short_instance(&one, &[F::ONE, F::ONE], &mut output, None).unwrap());
        assert_eq!(
            output,
            vec![F::from(23)],
            "oversized prefix cannot select the shortcut"
        );
    }
    check::<Fp>();
    check::<Fq>();
}

#[test]
fn short_instance_coefficient_owner_and_oversized_instance_rejection() {
    use crate::{
        pcs::ipa::PinnedParams,
        prover::{ProverError, Witness},
        test_circuits::{Arithmetic, CHOICES, keygen_config},
    };
    fn check<C: PastaCurve>() {
        let circuit = Arithmetic {
            start: 3,
            rows: 12,
            tamper: None,
        };
        let params = PinnedParams::<C>::derive(8).unwrap();
        let pk = crate::keys::keygen_pk(&params, &circuit, &keygen_config(CHOICES[0])).unwrap();
        let inputs: Vec<Vec<C::ScalarExt>> = (0..=4_usize)
            .map(|len| {
                (0..len)
                    .map(|j| C::ScalarExt::from((j + 3) as u64))
                    .collect()
            })
            .collect();
        let before = inputs.clone();
        let owner = InstanceColumns::new(&pk, &inputs, None).unwrap();
        assert_eq!(inputs, before);
        assert_eq!(owner.lengths, vec![0, 1, 2, 3, 4]);
        for (i, prefix) in inputs.iter().enumerate() {
            let mut padded = prefix.clone();
            padded.resize(pk.domain().n(), C::ScalarExt::ZERO);
            assert_eq!(owner.values[i], padded);
            assert_eq!(owner.polys()[i], dense(pk.domain(), &padded));
            assert_eq!(owner.short_prefix(i), Some(prefix.as_slice()));
        }
        let expected = pk.binding().descriptor().instance_lengths[0] as usize;
        let oversized = vec![vec![C::ScalarExt::ONE; pk.domain().n() + 1]];
        assert_eq!(
            Witness::from_circuit(&pk, &circuit, &oversized).err(),
            Some(ProverError::InstanceLength {
                column: 0,
                expected,
                found: pk.domain().n() + 1
            })
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            InstanceColumns::new(&pk, &inputs, Some(&cancelled))
                .unwrap_err()
                .is_cancelled()
        );
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
#[ignore = "public-instance coefficient component diagnostic; no proof or phone timing claim"]
fn short_instance_coefficient_shape_timing_diagnostic() {
    use std::{hint::black_box, time::Instant};
    assert!(!cfg!(debug_assertions), "run in release");
    fn check<F: PastaField>() {
        for (label, k, lengths) in [
            ("sigma_shape", 12, &[1_usize][..]),
            ("w_omega_shape", 16, &[1_usize, 2, 16][..]),
            ("two_sigma_q_shape", 16, &[241_usize, 2, 2, 5, 1][..]),
        ] {
            let domain = FftDomain::<F>::new(k).unwrap();
            let prefixes: Vec<Vec<F>> = lengths
                .iter()
                .enumerate()
                .map(|(column, &len)| {
                    (0..len)
                        .map(|row| F::from((column * 31 + row + 3) as u64))
                        .collect()
                })
                .collect();
            let padded: Vec<Vec<F>> = prefixes
                .iter()
                .map(|prefix| {
                    let mut v = prefix.clone();
                    v.resize(domain.n(), F::ZERO);
                    v
                })
                .collect();
            let oracle: Vec<Vec<F>> = padded.iter().map(|column| dense(&domain, column)).collect();
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                pool.install(|| {
                    let interpolate = |shortcut:bool| -> Vec<Vec<F>> {
                        padded.iter().zip(&prefixes).map(|(column,prefix)| {
                            let mut coefficients=column.clone();
                            if !shortcut || !interpolate_short_instance(&domain,prefix,&mut coefficients,None).unwrap() {domain.ifft(&mut coefficients).unwrap();}
                            coefficients
                        }).collect()
                    };
                    for shortcut in [false,true] {assert_eq!(interpolate(shortcut),oracle);}
                    for (block,order) in [[false,true,true,false],[true,false,false,true]].into_iter().enumerate() {
                        for (position,shortcut) in order.into_iter().enumerate() {
                            let started=Instant::now();
                            let output=interpolate(shortcut);
                            black_box(&output);
                            let allocation_compute_ns=started.elapsed().as_nanos();
                            assert_eq!(output,oracle,"all coefficients before timed cleanup");
                            let cleanup=Instant::now();drop(output);let cleanup_ns=cleanup.elapsed().as_nanos();
                            let elapsed_ns=allocation_compute_ns+cleanup_ns;
                            println!("SHORT_INSTANCE_COEFFICIENTS label={label} field={} k={k} workers={workers} block={block} position={position} variant={} allocation_compute_ns={allocation_compute_ns} cleanup_ns={cleanup_ns} elapsed_ns={elapsed_ns} output_columns={} output_elements={} output_requested_bytes={} exact_coefficients_equal=true clone_fill_recurrence_fft_allocation_included=true returned_output_drop_included=true equality_check_outside_timed_intervals=true padded_input_domain_creation_included=false production_proof=false phone=false",std::any::type_name::<F>(),if shortcut {"short_prefix"} else {"dense_ifft"},lengths.len(),domain.n()*lengths.len(),domain.n()*lengths.len()*size_of::<F>());
                        }
                    }
                });
            }
        }
    }
    check::<Fp>();
    check::<Fq>();
}
