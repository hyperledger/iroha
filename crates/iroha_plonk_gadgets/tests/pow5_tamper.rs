//! The Pow5 permutation chip: native parity with
//! `iroha_pasta::poseidon::permute` on both fields, the per-cell tamper suite
//! (including every `m8_custom_gate_checks` Poseidon case), the inventory
//! (37 rows and 148 cells per permutation, arithmetic degree 6), lane sharing and
//! misuse rejections.

mod common;

use common::{
    Chips, GadgetCircuit, Inputs, Shape, accepts, assigned, count, extent, lane_columns, report,
};
use ff::Field as _;
use iroha_pasta::{Fp, Fq, poseidon::PoseidonField};
use iroha_plonk::frontend::{Error, Region, Value, configure, synthesize};
use iroha_plonk_gadgets::{
    Word,
    cells::known,
    poseidon::{
        Absorb, AbsorbInput, CELLS_PER_PERMUTATION, ROWS_PER_PERMUTATION, permute_native,
        raw_initial_state,
    },
    tamper::{Tamper, check_tampered, undetected_tampers},
};

const K: u32 = 7;

/// Fails synthesis when a known state differs from its native reference.
fn expect_state<F: PoseidonField>(
    value: Value<[F; 3]>,
    native: Option<[F; 3]>,
) -> Result<(), Error> {
    match (known(&value), native) {
        (Some(value), Some(native)) if value != native => Err(Error::Synthesis),
        _ => Ok(()),
    }
}

/// The native states of [`permutations`]: after block 0 (absorbing inputs 0
/// and 1), after block 1 (plain) and the squeezed output of block 2
/// (absorbing the constant 5 and input 2).
fn native_chain<F: PoseidonField>(inputs: &[F]) -> ([F; 3], [F; 3], F) {
    let first = permute_native(raw_initial_state(), [inputs[0], inputs[1]]);
    let second = permute_native(first, [F::ZERO; 2]);
    let third = permute_native(second, [F::from(5u64), inputs[2]]);
    (first, second, third[1])
}

/// Three blocks on lane 0: absorb two witnesses, a plain permutation, then
/// a squeeze absorbing a constant and a witness. Every intermediate state is
/// compared with the native permutation.
fn permutations<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let words = chips
        .glue
        .witnesses(region, &[inputs.get(0), inputs.get(1), inputs.get(2)])?;
    let native = (0..3)
        .map(|index| inputs.native(index))
        .collect::<Option<Vec<_>>>()
        .map(|values| native_chain(&values));
    let lane = chips.sponges[0].lane_mut();
    let start = lane.start(region, raw_initial_state())?;
    let first = lane.permute(
        region,
        start,
        Absorb::Block([AbsorbInput::Word(&words[0]), AbsorbInput::Word(&words[1])]),
    )?;
    expect_state(first.value(), native.map(|n| n.0))?;
    let second = lane.permute(region, first, Absorb::Nothing)?;
    expect_state(second.value(), native.map(|n| n.1))?;
    let output = lane.squeeze(
        region,
        second,
        Absorb::Block([
            AbsorbInput::Constant(F::from(5u64)),
            AbsorbInput::Word(&words[2]),
        ]),
    )?;
    if let (Some(value), Some(native)) = (known(&output.value()), native)
        && value != native.2
    {
        return Err(Error::Synthesis);
    }
    Ok(vec![output])
}

fn chain_circuit<F: PoseidonField>(inputs: Vec<F>) -> (GadgetCircuit<F>, Vec<F>) {
    let public = vec![native_chain(&inputs).2];
    (
        GadgetCircuit::new(Shape::new(1, 4, 1), permutations::<F>, inputs),
        public,
    )
}

fn inputs<F: PoseidonField>() -> Vec<F> {
    vec![F::from(0x1234_5678u64), -F::ONE, F::from_u128(u128::MAX)]
}

fn parity_and_acceptance<F: PoseidonField>() {
    let (circuit, public) = chain_circuit(inputs::<F>());
    assert!(
        accepts(&circuit, K, &public),
        "{}",
        report(&circuit, K, &public)
    );
    // A wrong public digest is rejected (M8 "wrong public digest").
    let mut wrong = public.clone();
    wrong[0] += F::ONE;
    assert!(!accepts(&circuit, K, &wrong));
    // Zero inputs too.
    let (zeros, public) = chain_circuit(vec![F::ZERO; 3]);
    assert!(accepts(&zeros, K, &public));
}

#[test]
fn permutation_matches_the_native_reference_on_both_fields() {
    parity_and_acceptance::<Fp>();
    parity_and_acceptance::<Fq>();
}

fn every_cell_is_pinned<F: PoseidonField>() {
    let (circuit, public) = chain_circuit(inputs::<F>());
    let undetected = undetected_tampers(&circuit, K, &[public]).expect("tamper run");
    assert_eq!(undetected, Vec::<(usize, usize)>::new());
}

#[test]
fn every_assigned_cell_is_pinned_fp() {
    every_cell_is_pinned::<Fp>();
}

#[test]
fn every_assigned_cell_is_pinned_fq() {
    every_cell_is_pinned::<Fq>();
}

#[test]
fn m8_poseidon_tamper_cases_are_rejected() {
    let (circuit, public) = chain_circuit(inputs::<Fp>());
    let [s0, s1, s2, aux] = lane_columns(0);
    let block = ROWS_PER_PERMUTATION;
    let cases = [
        ("initial state", s0, 0),
        ("full round", s1, 2),
        ("pair round", s2, 10),
        ("pair S-box", aux, 12),
        ("single partial round", s0, 33),
        ("absorbed constant", aux, 2 * block),
        ("absorbed input", aux, 2 * block + 1),
        ("state entering a plain permutation", s2, block),
        ("state leaving a plain permutation", s2, 2 * block),
        ("squeezed output", aux, 3 * block - 1),
    ];
    for (label, column, row) in cases {
        let tamper = Tamper {
            column,
            row,
            delta: Fp::from(1u64),
        };
        let report = check_tampered(&circuit, K, std::slice::from_ref(&public), Some(tamper))
            .expect("check");
        assert!(!report.is_satisfied(), "{label} tamper accepted");
    }
}

#[test]
fn inventory_37_rows_and_148_cells_per_permutation() {
    assert_eq!(ROWS_PER_PERMUTATION, 37);
    assert_eq!(CELLS_PER_PERMUTATION, 148);
    let (circuit, public) = chain_circuit(inputs::<Fp>());
    let flags = assigned(&circuit, K, &public);
    let [s0, s1, s2, aux] = lane_columns(0);
    // Three blocks: rows 0..111 of the lane.
    for column in [s0, s1, s2, aux] {
        assert_eq!(extent(&flags[column]), 3 * ROWS_PER_PERMUTATION);
    }
    for column in [s0, s1, s2] {
        assert_eq!(count(&flags[column]), 3 * ROWS_PER_PERMUTATION);
    }
    // Aux: 28 pair S-boxes per block, 2 absorbed words in blocks 0 and 2,
    // and the squeezed output.
    assert_eq!(count(&flags[aux]), 3 * 28 + 2 * 2 + 1);
    // The shared fixture also configures an ordinary running-sum lookup:
    // input degree two and table degree one require norm degree eight, even
    // when this program assigns only Pow5 rows. The Pow5 gates stay degree six.
    let (cs, _) = configure(&circuit).expect("configure");
    assert_eq!(cs.lookups().len(), 1);
    let lookup = &cs.lookups()[0];
    assert_eq!(lookup.name(), "running-sum limb");
    assert_eq!(lookup.width(), 1);
    assert_eq!(lookup.input_expressions()[0].degree(), 2);
    assert_eq!(lookup.table_expressions()[0].degree(), 1);
    assert_eq!(lookup.required_degree(), 8);
    assert_eq!(cs.degree(), 8);
    assert_eq!(cs.blinding_factors(), 5);
    let lane_gates = cs
        .gates()
        .iter()
        .filter(|gate| gate.name().starts_with("pow5"))
        .map(|gate| {
            gate.polynomials()
                .iter()
                .map(iroha_plonk::Expression::degree)
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    // absorb, full, pair, partial, squeeze, start (raw state).
    assert_eq!(lane_gates, vec![6, 6, 6, 6, 6, 2]);
}

/// Starts a hash from a state that has no start gate.
fn unconfigured_start<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    _inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let lane = chips.sponges[0].lane_mut();
    let state = lane.start(region, [F::ONE, F::ONE, F::ONE])?;
    Ok(vec![lane.squeeze(region, state, Absorb::Nothing)?])
}

/// Permutes a state after a newer one was started.
fn stale_state<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    _inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let lane = chips.sponges[0].lane_mut();
    let first = lane.start(region, raw_initial_state())?;
    let pending = lane.permute(region, first, Absorb::Nothing)?;
    let newer = lane.start(region, raw_initial_state())?;
    let _ = lane.squeeze(region, newer, Absorb::Nothing)?;
    Ok(vec![lane.squeeze(region, pending, Absorb::Nothing)?])
}

#[test]
fn lane_misuse_is_a_typed_error() {
    for program in [unconfigured_start::<Fp>, stale_state::<Fp>] {
        let circuit = GadgetCircuit::new(Shape::new(1, 4, 1), program, Vec::new());
        assert_eq!(
            synthesize(&circuit, K, Some(&[vec![Fp::ZERO]][..])).map(|_| ()),
            Err(Error::Synthesis)
        );
    }
}

/// A plain permutation, a dangling state and a new hash on the same lane:
/// the new hash skips the block that holds the dangling state.
fn dangling_then_hash<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let words = chips.glue.witnesses(region, &[inputs.get(0)])?;
    let lane = chips.sponges[0].lane_mut();
    let start = lane.start(region, raw_initial_state())?;
    let dangling = lane.permute(region, start, Absorb::Nothing)?;
    if dangling.block() != 1 || lane.next_block() != 2 {
        return Err(Error::Synthesis);
    }
    let digest = chips.sponges[0].hash_raw(region, &[AbsorbInput::Word(&words[0])])?;
    if chips.sponges[0].lane().next_block() != 3 {
        return Err(Error::Synthesis);
    }
    Ok(vec![digest])
}

#[test]
fn a_dangling_state_keeps_its_block() {
    let x = Fq::from(9u64);
    let circuit = GadgetCircuit::new(Shape::new(1, 4, 1), dangling_then_hash::<Fq>, vec![x]);
    let public = vec![iroha_pasta::poseidon::hash(&[x])];
    assert!(
        accepts(&circuit, K, &public),
        "{}",
        report(&circuit, K, &public)
    );
    let undetected = undetected_tampers(&circuit, K, &[public]).expect("tamper run");
    assert_eq!(undetected, Vec::<(usize, usize)>::new());
}

/// One hash per lane, of different lengths, on two lanes.
fn two_lanes<F: PoseidonField>(
    chips: &mut Chips<F>,
    region: &mut Region<'_, F>,
    inputs: &Inputs<F>,
) -> Result<Vec<Word<F>>, Error> {
    let values = (0..inputs.len())
        .map(|index| inputs.get(index))
        .collect::<Vec<_>>();
    let words = chips.glue.witnesses(region, &values)?;
    let first = chips.sponges[0].hash_words(region, 7, &words[..1])?;
    let second = chips.sponges[1].hash_words(region, 8, &words[1..])?;
    Ok(vec![first, second])
}

fn lanes_share_or_own_round_constants<F: PoseidonField>(shape: Shape) {
    let inputs = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let public = vec![
        iroha_pasta::poseidon::hash_with_domain(7, &inputs[..1]),
        iroha_pasta::poseidon::hash_with_domain(8, &inputs[1..]),
    ];
    let circuit = GadgetCircuit::new(shape, two_lanes::<F>, inputs);
    assert!(
        accepts(&circuit, K, &public),
        "{}",
        report(&circuit, K, &public)
    );
    let mut wrong = public;
    wrong[1] += F::ONE;
    assert!(!accepts(&circuit, K, &wrong));
}

#[test]
fn lanes_may_share_round_constant_columns() {
    lanes_share_or_own_round_constants::<Fp>(Shape::new(2, 4, 2));
    lanes_share_or_own_round_constants::<Fq>(Shape::new(2, 4, 2).unshared());
    let shared = configure(&GadgetCircuit::new(
        Shape::new(2, 4, 2),
        two_lanes::<Fp>,
        Vec::new(),
    ))
    .expect("configure")
    .0;
    let unshared = configure(&GadgetCircuit::new(
        Shape::new(2, 4, 2).unshared(),
        two_lanes::<Fp>,
        Vec::new(),
    ))
    .expect("configure")
    .0;
    assert_eq!(unshared.num_fixed_columns(), shared.num_fixed_columns() + 6);
}
