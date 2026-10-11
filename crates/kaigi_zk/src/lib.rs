//! Final V1 native prover relations for Kaigi authorization and host-bound usage.
//!
//! [`authorization_v1`] binds complete network, call, host, subject, sequence,
//! action and pre-state inputs. [`usage_v1`] opens the stored host commitment
//! and binds the authenticated usage context. Both use one fixed framed
//! Poseidon construction and canonical raw Pasta scalars. Ledger state and
//! authority validation remain the responsibility of the Core adapter.
#![deny(missing_docs)]

pub mod authorization_v1;
pub mod native;
mod relation_v1;
pub mod usage_v1;

use core::array;
use ff::Field;
use iroha_pasta::Fp;
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
    frontend::Value,
};
use std::sync::OnceLock;

/// Scalar field used by the Kaigi native prover circuits (Pasta Fp).
pub type Scalar = Fp;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 56;
const POSEIDON_ROUNDS: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;
struct PoseidonConstants {
    round_constants: Vec<[Scalar; POSEIDON_WIDTH]>,
    mds: [[Scalar; POSEIDON_WIDTH]; POSEIDON_WIDTH],
}
fn poseidon_constants() -> &'static PoseidonConstants {
    static CONSTANTS: OnceLock<PoseidonConstants> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        let (round_constants, mds) = iroha_pasta::poseidon::grain::generate_constants::<
            Scalar,
            POSEIDON_WIDTH,
        >(POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, 0);
        assert_eq!(round_constants.len(), POSEIDON_ROUNDS);
        PoseidonConstants {
            round_constants,
            mds,
        }
    })
}
/// Shared configuration for the fixed Poseidon permutation.
#[derive(Clone, Debug)]
struct KaigiPoseidonConfig {
    state: [Column<Advice>; POSEIDON_WIDTH],
    round_constants: [Column<Fixed>; POSEIDON_WIDTH],
    q_full_round: Selector,
    q_partial_round: Selector,
}
fn configure_poseidon(meta: &mut ConstraintSystem<Scalar>) -> KaigiPoseidonConfig {
    let state = array::from_fn(|_| {
        let column = meta.advice_column();
        meta.enable_equality(column);
        column
    });
    let round_constants = array::from_fn(|_| meta.fixed_column());
    let q_full_round = meta.selector();
    let q_partial_round = meta.selector();
    let constants = poseidon_constants();
    meta.create_gate("kaigi Poseidon full round", |meta| {
        let enabled = meta.query_selector(q_full_round);
        (0..POSEIDON_WIDTH)
            .map(|row| {
                let expected = (0..POSEIDON_WIDTH).fold(
                    iroha_plonk::cs::Expression::Constant(Scalar::ZERO),
                    |accumulator, column| {
                        let current = meta.query_advice(state[column], Rotation::cur());
                        let round_constant =
                            meta.query_fixed(round_constants[column], Rotation::cur());
                        let shifted = current + round_constant;
                        let square = shifted.clone() * shifted.clone();
                        let fifth = square.clone() * square * shifted;
                        accumulator + fifth * constants.mds[row][column]
                    },
                );
                let next = meta.query_advice(state[row], Rotation::next());
                enabled.clone() * (expected - next)
            })
            .collect::<Vec<_>>()
    });
    meta.create_gate("kaigi Poseidon partial round", |meta| {
        let enabled = meta.query_selector(q_partial_round);
        let shifted = array::from_fn::<_, POSEIDON_WIDTH, _>(|column| {
            meta.query_advice(state[column], Rotation::cur())
                + meta.query_fixed(round_constants[column], Rotation::cur())
        });
        let square = shifted[0].clone() * shifted[0].clone();
        let first_fifth = square.clone() * square * shifted[0].clone();
        (0..POSEIDON_WIDTH)
            .map(|row| {
                let expected = first_fifth.clone() * constants.mds[row][0]
                    + shifted[1].clone() * constants.mds[row][1]
                    + shifted[2].clone() * constants.mds[row][2];
                let next = meta.query_advice(state[row], Rotation::next());
                enabled.clone() * (expected - next)
            })
            .collect::<Vec<_>>()
    });
    KaigiPoseidonConfig {
        state,
        round_constants,
        q_full_round,
        q_partial_round,
    }
}
fn value_pow5(value: Value<Scalar>) -> Value<Scalar> {
    let square = value * value;
    square * square * value
}
fn poseidon_round(mut state: [Scalar; POSEIDON_WIDTH], round: usize) -> [Scalar; POSEIDON_WIDTH] {
    let constants = poseidon_constants();
    for (word, round_constant) in state
        .iter_mut()
        .zip(constants.round_constants[round].iter())
    {
        *word += round_constant;
    }
    let half_full_rounds = POSEIDON_FULL_ROUNDS / 2;
    if round < half_full_rounds || round >= half_full_rounds + POSEIDON_PARTIAL_ROUNDS {
        for word in &mut state {
            *word = word.pow_vartime([5]);
        }
    } else {
        state[0] = state[0].pow_vartime([5]);
    }
    array::from_fn(|row| {
        (0..POSEIDON_WIDTH).fold(Scalar::ZERO, |accumulator, column| {
            accumulator + constants.mds[row][column] * state[column]
        })
    })
}
fn poseidon_round_value(
    mut state: [Value<Scalar>; POSEIDON_WIDTH],
    round: usize,
) -> [Value<Scalar>; POSEIDON_WIDTH] {
    let constants = poseidon_constants();
    for (word, round_constant) in state
        .iter_mut()
        .zip(constants.round_constants[round].iter())
    {
        *word = *word + Value::known(*round_constant);
    }
    let half_full_rounds = POSEIDON_FULL_ROUNDS / 2;
    if round < half_full_rounds || round >= half_full_rounds + POSEIDON_PARTIAL_ROUNDS {
        for word in &mut state {
            *word = value_pow5(*word);
        }
    } else {
        state[0] = value_pow5(state[0]);
    }
    array::from_fn(|row| {
        (0..POSEIDON_WIDTH).fold(Value::known(Scalar::ZERO), |accumulator, column| {
            accumulator + state[column] * Value::known(constants.mds[row][column])
        })
    })
}

#[cfg(test)]
mod tests;
