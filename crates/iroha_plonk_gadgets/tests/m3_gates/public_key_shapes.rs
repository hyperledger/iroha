//! Unmeasured public-key DATA to decide whether redundant coset FFTs exist.
//! This scans public coefficient columns only and creates no proof or witness.

use super::*;

fn column_shape<F: PastaField>(values: &[F]) -> (usize, Option<usize>, &'static str) {
    let mut nonzero = 0;
    let mut first = None;
    for (index, value) in values.iter().enumerate() {
        if *value != F::ZERO {
            nonzero += 1;
            first.get_or_insert(index);
        }
    }
    let kind = match (nonzero, first) {
        (0, _) => "zero",
        (1, Some(0)) => "constant",
        (1, _) => "monomial",
        _ => "general",
    };
    (nonzero, first, kind)
}

fn describe<C, Ci>(gate: &str, circuit: &Ci)
where
    C: PastaCurve,
    C::ScalarExt: PoseidonField,
    Ci: Circuit<C::ScalarExt>,
{
    let (params, _) = pinned_params::<C>(K);
    let pk = keygen_pk_v2(
        &params,
        &circuit.without_witnesses(),
        &measurement_key_config(),
    )
    .expect("actual public key");
    let mut prior: Vec<(&str, usize, &[C::ScalarExt])> = Vec::new();
    let mut columns = Vec::new();
    for (family, values) in [
        ("fixed", pk.fixed_polys()),
        ("sigma", pk.permutation_polys()),
    ] {
        for (index, coefficients) in values.iter().enumerate() {
            assert_eq!(coefficients.len(), 1_usize << K);
            let (nonzero, first, kind) = column_shape(coefficients);
            let duplicate = prior
                .iter()
                .position(|(_, _, previous)| *previous == coefficients.as_slice());
            let mut hash = Sha256::new();
            for coefficient in coefficients {
                hash.update(coefficient.to_repr().as_ref());
            }
            columns.push(norito::json!({
                "family": family, "index": index, "coefficients": (coefficients.len()),
                "nonzero": nonzero, "first_nonzero": first, "kind": kind,
                "duplicate_of_flat_index": duplicate,
                "canonical_coefficients_sha256": (hex(&hash.finalize())),
            }));
            prior.push((family, index, coefficients));
        }
    }
    let report = norito::json!({
        "scope": "Actual current public-key coefficient DATA; no proof/timing/privacy or optimization claim",
        "gate": gate, "curve": (C::CURVE_ID), "k": K,
        "descriptor_digest": (hex(pk.vk().descriptor_digest())),
        "quotient_pieces": (pk.quotient_domain().pieces()),
        "fixed_count": (pk.fixed_polys().len()),
        "sigma_count": (pk.permutation_polys().len()), "columns": columns,
    });
    println!(
        "M3_PUBLIC_KEY_SHAPES_JSON {}",
        norito::json::to_json(&report).unwrap()
    );
}

#[test]
#[ignore = "explicit public keygen/column inspection; not a proof or timing run"]
fn actual_m3_public_key_column_shapes() {
    describe::<Pallas, _>("G3.6/q_leaf_chips", &q_leaf(Q_VARIABLE, Q_FIXED, 60));
    describe::<Pallas, _>(
        "G3.6/q_exact_shape",
        &ExactCircuit::<Fq>::new(Q_SHAPE, ExactCircuit::<Fq>::usable_rows(Q_SHAPE, K), 66),
    );
    describe::<Vesta, _>("G3.7/a_imt_load", &a_load(70));
    describe::<Vesta, _>(
        "G3.7/a_exact_shape",
        &ExactCircuit::<Fp>::new(A_SHAPE, ExactCircuit::<Fp>::usable_rows(A_SHAPE, K), 77),
    );
}

#[test]
fn public_column_shape_distinguishes_zero_constant_monomial_and_general() {
    fn check<F: PastaField>() {
        assert_eq!(column_shape(&[F::ZERO; 4]), (0, None, "zero"));
        assert_eq!(column_shape(&[F::ONE, F::ZERO]), (1, Some(0), "constant"));
        assert_eq!(column_shape(&[F::ZERO, F::ONE]), (1, Some(1), "monomial"));
        assert_eq!(column_shape(&[F::ONE, F::ONE]), (2, Some(0), "general"));
        let columns = [
            vec![F::ONE, F::ZERO],
            vec![F::ZERO, F::ONE],
            vec![F::ONE, F::ZERO],
        ];
        assert_eq!(columns[..2].iter().position(|v| v == &columns[2]), Some(0));
        assert_ne!(columns[0], columns[1]);
    }
    check::<Fp>();
    check::<Fq>();
}
