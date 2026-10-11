//! The glue chip: every operation against its native reference on both
//! fields, the per-cell tamper suite, rejections of false booleans, zero
//! inverses and wrong constants, and the one-row-per-operation inventory.

mod common;

use common::{
    Chips, GLUE_COLUMNS, GadgetCircuit, Inputs, Shape, accepts, assigned, extent, report,
};
use ff::Field as _;
use iroha_pasta::{Fp, Fq, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region};
use iroha_plonk_gadgets::{
    GlueChip, Word,
    arith::{is_zero_native, select_native},
    tamper::undetected_tampers,
};

const K: u32 = 7;

/// Every glue operation; inputs `x, y, z, b, 0` with `b` boolean.
fn all_operations<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let glue = &mut chips.glue;
    let w = glue.witnesses(region, &inputs.all())?;
    let (x, y, z, zero) = (&w[0], &w[1], &w[2], &w[4]);
    let seven = glue.constant(region, F::from(7u64))?;
    let sum = glue.add(region, x, y)?;
    let difference = glue.sub(region, x, y)?;
    let product = glue.mul(region, x, y)?;
    let fused = glue.mul_add(region, x, y, z)?;
    let shifted = glue.add_constant(region, x, F::from(11u64))?;
    let linear = glue.linear(
        region,
        &[(F::from(3u64), x), (-F::from(2u64), y), (F::from(5u64), z)],
        F::ONE,
    )?;
    let bit = glue.boolean(region, inputs.get(3).map(|b| b == F::ONE))?;
    let checked = glue.assert_bool(region, &w[3])?;
    GlueChip::assert_equal(region, bit.word(), checked.word())?;
    let selected = glue.select(region, &bit, x, y)?;
    let selected_constant = glue.select_constant(region, &bit, z, F::from(13u64))?;
    let zero_is_zero = glue.is_zero(region, zero)?;
    let x_is_zero = glue.is_zero(region, x)?;
    let x_equals_y = glue.is_equal(region, x, y)?;
    let seven_equals_seven = glue.is_equal(region, &seven, &seven)?;
    let negated = glue.not(region, &bit)?;
    let both = glue.and(region, &bit, &checked)?;
    glue.assert_nonzero(region, x)?;
    GlueChip::assert_constant(region, &seven, F::from(7u64))?;
    Ok(vec![
        seven,
        sum,
        difference,
        product,
        fused,
        shifted,
        linear,
        selected,
        selected_constant,
        zero_is_zero.word().clone(),
        x_is_zero.word().clone(),
        x_equals_y.word().clone(),
        seven_equals_seven.word().clone(),
        negated.word().clone(),
        both.word().clone(),
    ])
}

/// The native outputs of [`all_operations`].
fn expected<F: PoseidonField>(x: F, y: F, z: F, b: bool) -> Vec<F> {
    let bit = |value: bool| if value { F::ONE } else { F::ZERO };
    vec![
        F::from(7u64),
        x + y,
        x - y,
        x * y,
        x * y + z,
        x + F::from(11u64),
        F::from(3u64) * x - F::from(2u64) * y + F::from(5u64) * z + F::ONE,
        select_native(b, x, y),
        select_native(b, z, F::from(13u64)),
        bit(is_zero_native(&F::ZERO)),
        bit(is_zero_native(&x)),
        bit(is_zero_native(&(x - y))),
        F::ONE,
        bit(!b),
        bit(b),
    ]
}

fn glue_circuit<F: PoseidonField>(x: F, y: F, z: F, b: bool) -> (GadgetCircuit<F>, Vec<F>) {
    let bit = if b { F::ONE } else { F::ZERO };
    let circuit = GadgetCircuit::new(
        Shape::new(0, 4, 15),
        all_operations::<F>,
        vec![x, y, z, bit, F::ZERO],
    );
    (circuit, expected(x, y, z, b))
}

fn operations_match_native<F: PoseidonField>() {
    for (x, y, z, b) in [
        (F::from(9u64), F::from(4u64), F::from(2u64), true),
        (-F::ONE, F::from(3u64), F::ZERO, false),
        (F::from(5u64), F::from(5u64), -F::from(7u64), true),
    ] {
        let (circuit, public) = glue_circuit(x, y, z, b);
        assert!(
            accepts(&circuit, K, &public),
            "{}",
            report(&circuit, K, &public)
        );
        for index in 0..public.len() {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(
                !accepts(&circuit, K, &wrong),
                "output {index} is unconstrained"
            );
        }
    }
}

#[test]
fn operations_match_the_native_references() {
    operations_match_native::<Fp>();
    operations_match_native::<Fq>();
}

#[test]
fn every_glue_cell_is_pinned() {
    let (circuit, public) = glue_circuit(Fp::from(9u64), Fp::from(4u64), Fp::from(2u64), true);
    assert_eq!(undetected_tampers(&circuit, K, &[public]), Ok(Vec::new()));
    let (circuit, public) = glue_circuit(-Fq::ONE, Fq::from(3u64), Fq::ZERO, false);
    assert_eq!(undetected_tampers(&circuit, K, &[public]), Ok(Vec::new()));
}

#[test]
fn false_premises_have_no_witness() {
    // A boolean witness of 2: the boolean gate rejects it, whatever the
    // public outputs claim.
    let (circuit, _) = glue_circuit(Fp::from(9u64), Fp::from(4u64), Fp::from(2u64), true);
    let mut two = circuit.clone();
    two.inputs[3] = Fp::from(2u64);
    let public = expected(Fp::from(9u64), Fp::from(4u64), Fp::from(2u64), true);
    assert!(!accepts(&two, K, &public));
    // `assert_nonzero(0)` has no inverse.
    let (zero, public) = glue_circuit(Fp::ZERO, Fp::from(4u64), Fp::from(2u64), false);
    let report = report(&zero, K, &public);
    assert!(report.contains("q_m a b"), "{report}");
}

/// Each operation's row cost, checked against the cursor.
fn row_costs<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let glue = &mut chips.glue;
    let mut rows = glue.next_row();
    let mut expect = |glue: &GlueChip<F>, cost: usize| {
        let next = glue.next_row();
        let ok = next == rows + cost;
        rows = next;
        if ok { Ok(()) } else { Err(Error::Synthesis) }
    };
    let w = glue.witnesses(region, &inputs.all())?;
    expect(glue, 2)?; // five witnesses, four per row
    let bit = glue.boolean(region, inputs.get(3).map(|b| b == F::ONE))?;
    expect(glue, 1)?;
    let out = glue.add(region, &w[0], &w[1])?;
    expect(glue, 1)?;
    let _ = glue.select(region, &bit, &w[0], &out)?;
    expect(glue, 1)?;
    let _ = glue.select_constant(region, &bit, &w[0], F::ONE)?;
    expect(glue, 1)?;
    let _ = glue.is_zero(region, &w[4])?;
    expect(glue, 1)?;
    let _ = glue.is_equal(region, &w[0], &w[1])?;
    expect(glue, 2)?;
    GlueChip::assert_equal(region, &w[4], &w[4])?;
    GlueChip::assert_constant(region, &w[4], F::ZERO)?;
    expect(glue, 0)?;
    Ok(vec![out])
}

#[test]
fn inventory_one_row_per_operation() {
    let inputs = vec![Fp::from(9u64), Fp::from(4u64), Fp::ZERO, Fp::ONE, Fp::ZERO];
    let circuit = GadgetCircuit::new(Shape::new(0, 4, 1), row_costs::<Fp>, inputs);
    let public = vec![Fp::from(13u64)];
    assert!(
        accepts(&circuit, K, &public),
        "{}",
        report(&circuit, K, &public)
    );
    let flags = assigned(&circuit, K, &public);
    assert_eq!(extent(&flags[GLUE_COLUMNS[0]]), 9);
    // The full operation set: 15 outputs in 22 rows of four cells.
    let (all, public) = circuit_rows();
    let flags = assigned(&all, K, &public);
    assert_eq!(extent(&flags[GLUE_COLUMNS[0]]), 22);
}

fn circuit_rows() -> (GadgetCircuit<Fp>, Vec<Fp>) {
    glue_circuit(Fp::from(9u64), Fp::from(4u64), Fp::from(2u64), true)
}
