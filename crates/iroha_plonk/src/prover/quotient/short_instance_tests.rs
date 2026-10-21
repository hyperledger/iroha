//! Short-prefix cosets against the unchanged coefficient FFT, across both fields.
use super::*;
use crate::{
    pcs::ipa::PinnedParams,
    prover::advice::InstanceColumns,
    test_circuits::{Arithmetic, CHOICES, keygen_config},
};
use ff::Field;
use iroha_pasta::{Ep, Eq};

fn key<C: PastaCurve>() -> ProvingKey<C> {
    let circuit = Arithmetic {
        start: 3,
        rows: 12,
        tamper: None,
    };
    let params = PinnedParams::<C>::derive(8).unwrap();
    crate::keys::keygen_pk(&params, &circuit, &keygen_config(CHOICES[0])).unwrap()
}

#[test]
fn short_instance_cosets_match_dense_coefficients_and_keep_storage() {
    fn check<C: PastaCurve>() {
        let pk = key::<C>();
        let n = pk.domain().n();
        let prefixes: Vec<Vec<C::ScalarExt>> = [0, 1, 2, 3, 4, 5, 16]
            .into_iter()
            .map(|len| {
                (0..len)
                    .map(|j| {
                        if j == 1 {
                            C::ScalarExt::ZERO
                        } else {
                            C::ScalarExt::from(j as u64 + 3)
                        }
                    })
                    .collect()
            })
            .collect();
        let mut owner = InstanceColumns::new(&pk, &prefixes, None).unwrap();
        for (index, prefix) in prefixes.iter().enumerate() {
            assert_eq!(
                owner.short_prefix(index),
                (prefix.len() <= 4).then_some(prefix.as_slice())
            );
        }
        // Production releases padded values before quotient evaluation.
        owner.values.clear();
        let before = owner.polys().to_vec();
        for workers in [1, 4] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                let mut output = vec![vec![C::ScalarExt::ONE; n]; prefixes.len()];
                let pointers: Vec<_> = output.iter().map(|v| v.as_ptr()).collect();
                let mut powers = vec![C::ScalarExt::ZERO; n];
                for coset in 0..pk.quotient_domain().pieces() {
                    let masks = pk.coset_masks(coset).unwrap();
                    let plan = pk
                        .domain()
                        .coset_plan(&mut powers, pk.quotient_domain().shift(coset).unwrap())
                        .unwrap();
                    let mut expected = vec![vec![C::ScalarExt::ZERO; n]; prefixes.len()];
                    evaluate_many(
                        Some(&plan),
                        owner.polys(),
                        &mut expected
                            .iter_mut()
                            .map(Vec::as_mut_slice)
                            .collect::<Vec<_>>(),
                        None,
                    )
                    .unwrap();
                    evaluate_instance_many(
                        Some(&plan),
                        owner.polys(),
                        Some(&owner),
                        &masks.l0,
                        &mut output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                        None,
                    )
                    .unwrap();
                    assert_eq!(output, expected);
                    assert_eq!(
                        output.iter().map(|v| v.as_ptr()).collect::<Vec<_>>(),
                        pointers
                    );
                }
            });
        }
        assert_eq!(owner.polys(), before);
    }
    check::<Ep>();
    check::<Eq>();
}

#[test]
fn short_instance_cosets_reject_foreign_coefficients_and_cancel_before_writes() {
    fn check<C: PastaCurve>() {
        let pk = key::<C>();
        let n = pk.domain().n();
        let prefixes = vec![vec![C::ScalarExt::ONE; 2], vec![C::ScalarExt::from(3); 5]];
        let owner = InstanceColumns::new(&pk, &prefixes, None).unwrap();
        let masks = pk.coset_masks(0).unwrap();
        let mut powers = vec![C::ScalarExt::ZERO; n];
        let plan = pk
            .domain()
            .coset_plan(&mut powers, pk.quotient_domain().shift(0).unwrap())
            .unwrap();
        let mut output = vec![vec![C::ScalarExt::from(7); n]; prefixes.len()];
        let before = output.clone();
        let foreign = owner.polys().to_vec();
        assert_eq!(
            evaluate_instance_many(
                Some(&plan),
                &foreign,
                Some(&owner),
                &masks.l0,
                &mut output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                None
            ),
            Err(KeyError::CosetIndex)
        );
        assert_eq!(output, before);
        assert!(matches!(
            evaluate_instance_many(
                Some(&plan),
                owner.polys(),
                Some(&owner),
                &masks.l0[..n - 1],
                &mut output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                None
            ),
            Err(KeyError::Shape {
                what: "instance coset mask",
                ..
            })
        ));
        assert_eq!(output, before);
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            evaluate_instance_many(
                Some(&plan),
                owner.polys(),
                Some(&owner),
                &masks.l0,
                &mut output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                Some(&token)
            ),
            Err(KeyError::Cancelled)
        );
        assert_eq!(output, before);
        evaluate_instance_many(
            Some(&plan),
            owner.polys(),
            Some(&owner),
            &masks.l0,
            &mut output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        let mut expected = before;
        evaluate_many(
            Some(&plan),
            owner.polys(),
            &mut expected
                .iter_mut()
                .map(Vec::as_mut_slice)
                .collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        assert_eq!(output, expected);
    }
    check::<Ep>();
    check::<Eq>();
}

struct OmitFirstGate(bool);
impl ConstraintFilter for OmitFirstGate {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        !self.0 || !matches!(term, ConstraintTerm::Gate { polynomial: 0 })
    }
}
struct CancelGate<'a>(&'a CancellationToken);
impl ConstraintFilter for CancelGate<'_> {
    fn keeps(&self, term: ConstraintTerm) -> bool {
        if matches!(term, ConstraintTerm::Gate { .. }) {
            self.0.cancel();
        }
        true
    }
}

#[test]
fn bound_instance_quotient_matches_dense_and_cancellation_wipes_workspace() {
    fn check<C: PastaCurve>() {
        let circuit = Arithmetic {
            start: 3,
            rows: 12,
            tamper: None,
        };
        let params = PinnedParams::<C>::derive(8).unwrap();
        for policy in [
            crate::keys::CosetCachePolicy::Eager,
            crate::keys::CosetCachePolicy::OnDemand,
        ] {
            let mut config = keygen_config(CHOICES[0]);
            config.coset_cache = policy;
            let pk = crate::keys::keygen_pk(&params, &circuit, &config).unwrap();
            let protocol = Protocol::new(pk.binding().descriptor()).unwrap();
            let shape = protocol.shape();
            assert_eq!(shape.lookups, 0);
            let compiled = CompiledExpressions::compile(pk.binding().descriptor(), true).unwrap();
            let mut owner = InstanceColumns::new(&pk, &circuit.instances(), None).unwrap();
            assert_eq!(owner.short_prefix(0).unwrap().len(), 2);
            owner.values.clear();
            let advice: Vec<Vec<C::ScalarExt>> = (0..shape.num_advice)
                .map(|column| {
                    (0..shape.n)
                        .map(|row| C::ScalarExt::from((column + row + 1) as u64))
                        .collect()
                })
                .collect();
            let products = vec![vec![C::ScalarExt::ONE; shape.n]; shape.permutation_sets];
            let inputs = QuotientInputs {
                advice: &advice,
                instance: owner.polys(),
                permutation_products: products.iter().map(Vec::as_slice).collect(),
                lookups: Vec::new(),
            };
            let challenges = Challenges {
                theta: C::ScalarExt::from(3),
                beta: C::ScalarExt::from(5),
                gamma: C::ScalarExt::from(7),
                y: C::ScalarExt::from(11),
            };
            let bytes = workspace_elements(&pk, &protocol).unwrap() * size_of::<C::ScalarExt>();
            let mut workspace = QuotientWorkspace::new(bytes);
            for omit in [false, true] {
                let filter = OmitFirstGate(omit);
                let expected = evaluate_with_workspace_cancellable(
                    &pk,
                    &protocol,
                    &compiled,
                    &inputs,
                    challenges,
                    &filter,
                    &mut workspace,
                    None,
                )
                .unwrap();
                assert!(workspace.is_zeroized());
                let actual = evaluate_with_bound_instances_cancellable(
                    &pk,
                    &protocol,
                    &compiled,
                    &inputs,
                    &owner,
                    challenges,
                    &filter,
                    Some(&mut workspace),
                    None,
                )
                .unwrap();
                assert_eq!(actual, expected);
                assert!(workspace.is_zeroized());
                assert_eq!(workspace.allocated_bytes(), bytes);
                let token = CancellationToken::new();
                let cancelled = evaluate_with_bound_instances_cancellable(
                    &pk,
                    &protocol,
                    &compiled,
                    &inputs,
                    &owner,
                    challenges,
                    &CancelGate(&token),
                    Some(&mut workspace),
                    Some(&token),
                );
                assert!(token.is_cancelled());
                assert!(matches!(cancelled, Err(ProverError::Cancelled)));
                assert!(workspace.is_zeroized());
                let retried = evaluate_with_bound_instances_cancellable(
                    &pk,
                    &protocol,
                    &compiled,
                    &inputs,
                    &owner,
                    challenges,
                    &filter,
                    Some(&mut workspace),
                    None,
                )
                .unwrap();
                assert_eq!(retried, expected);
                assert!(workspace.is_zeroized());
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}

/// Public-prefix component timing with production-style reused output storage.
/// Fixture/key/IFFT/plan/mask setup and output verification are outside the cut.
#[test]
#[ignore = "bounded short-instance coset component diagnostic; no proof or phone timing claim"]
fn short_instance_coset_shape_timing_diagnostic() {
    use std::{hint::black_box, time::Instant};

    assert!(
        !cfg!(debug_assertions),
        "run component diagnostic with --release"
    );
    fn check<C: PastaCurve>() {
        let circuit = Arithmetic {
            start: 3,
            rows: 12,
            tamper: None,
        };
        for (label, k, lengths) in [
            ("sigma_shape", 12, &[1_usize][..]),
            ("w_omega_shape", 16, &[1_usize, 2, 16][..]),
        ] {
            let params = PinnedParams::<C>::derive(k).unwrap();
            let mut config = keygen_config(CHOICES[0]);
            config.coset_cache = crate::keys::CosetCachePolicy::OnDemand;
            let pk = crate::keys::keygen_pk(&params, &circuit, &config).unwrap();
            let prefixes: Vec<Vec<C::ScalarExt>> = lengths
                .iter()
                .enumerate()
                .map(|(column, &len)| {
                    (0..len)
                        .map(|row| C::ScalarExt::from((column * 31 + row + 3) as u64))
                        .collect()
                })
                .collect();
            let mut owner = InstanceColumns::new(&pk, &prefixes, None).unwrap();
            owner.values.clear();
            let n = pk.domain().n();
            assert_eq!(n, 1 << k);
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                pool.install(|| {
                    // Existing all-coset correctness tests cover rotation. This
                    // bounded component cut measures the first valid coset only.
                    let coset = 0;
                    let masks = pk.coset_masks(coset).unwrap();
                    let mut powers = vec![C::ScalarExt::ZERO; n];
                    let plan = pk.domain().coset_plan(&mut powers, pk.quotient_domain().shift(coset).unwrap()).unwrap();
                    let mut oracle = vec![vec![C::ScalarExt::ZERO; n]; lengths.len()];
                    evaluate_many(Some(&plan), owner.polys(), &mut oracle.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(), None).unwrap();
                    let mut output = vec![vec![C::ScalarExt::ZERO; n]; lengths.len()];
                    let pointers: Vec<_> = output.iter().map(|column| column.as_ptr()).collect();
                    let evaluate = |bound: bool, output: &mut Vec<Vec<C::ScalarExt>>| {
                        // Caller view creation/drop and helper partition metadata
                        // allocation/drop are inside the timing cut for both arms.
                        let mut views = output.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>();
                        if bound {
                            evaluate_instance_many(Some(&plan), owner.polys(), Some(&owner), &masks.l0, &mut views, None).unwrap();
                        } else {
                            evaluate_many(Some(&plan), owner.polys(), &mut views, None).unwrap();
                        }
                    };
                    // One checked warmup per arm, never reported as a sample.
                    for bound in [false, true] {
                        evaluate(bound, &mut output);
                        assert_eq!(output, oracle);
                    }
                    // Two balanced blocks, each containing two calls per arm.
                    // This does not remove host-load, cache or thermal variation.
                    for (block, order) in [[false, true, true, false], [true, false, false, true]].into_iter().enumerate() {
                        for (position, bound) in order.into_iter().enumerate() {
                            let started = Instant::now();
                            evaluate(bound, &mut output);
                            black_box(&output);
                            let elapsed_ns = started.elapsed().as_nanos();
                            assert_eq!(output, oracle, "every output element, every arm");
                            assert_eq!(output.iter().map(|column| column.as_ptr()).collect::<Vec<_>>(), pointers);
                            println!(
                                "SHORT_INSTANCE_COSET label={label} field={} k={k} workers={workers} coset={coset} block={block} position={position} variant={} elapsed_ns={elapsed_ns} output_columns={} output_elements={} output_requested_bytes={} exact_output_equal=true output_storage_reused=true helper_metadata_allocation_drop_included=true output_allocation_drop_included=false key_ifft_plan_masks_included=false production_proof=false phone=false",
                                std::any::type_name::<C::ScalarExt>(),
                                if bound { "bound_prefix" } else { "dense_fft" },
                                lengths.len(), n * lengths.len(), n * lengths.len() * size_of::<C::ScalarExt>()
                            );
                        }
                    }
                });
            }
        }
    }
    check::<Ep>();
    check::<Eq>();
}
