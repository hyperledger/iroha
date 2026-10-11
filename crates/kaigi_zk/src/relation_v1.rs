//! Shared fixed-frame Poseidon and bounded-limb gadgets for Kaigi V1 relations.
//! Named CPU scratch slots are erased; native prover-owned assignment/prover copies are not.
use super::{
    KaigiPoseidonConfig, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_ROUNDS, Scalar,
    configure_poseidon, poseidon_constants, poseidon_round, poseidon_round_value,
};
use core::array;
use ff::{Field, PrimeField};
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Instance, Rotation, Selector},
    frontend::{Cell, Error, Layouter, Value},
};
use zeroize::{DefaultIsZeroes, Zeroizing};
pub(super) const GOLDILOCKS_MODULUS_V1: u64 = 0xffff_ffff_0000_0001;
pub(super) type AssignedValue = (Cell, Value<Scalar>);
#[derive(Clone, Copy)]
pub(super) struct ScalarSlots<const N: usize>(pub(super) [Scalar; N]);
impl<const N: usize> Default for ScalarSlots<N> {
    fn default() -> Self {
        Self([Scalar::ZERO; N])
    }
}
// Every byte of these concrete Pasta field slots is replaced by field ZERO.
impl<const N: usize> DefaultIsZeroes for ScalarSlots<N> {}

pub(super) fn sponge(domain: u64, payload: &[Scalar]) -> Scalar {
    // Fixed role, exact payload length, terminator one, then at most one rate pad.
    let mut state = Zeroizing::new(ScalarSlots([
        Scalar::ZERO,
        Scalar::ZERO,
        Scalar::from(domain),
    ]));
    let mut input = payload.iter().copied().chain(core::iter::once(Scalar::ONE));
    let mut first = Some(Scalar::from(payload.len() as u64));
    loop {
        let Some(left) = first.take().or_else(|| input.next()) else {
            break;
        };
        let right = input.next().unwrap_or(Scalar::ZERO);
        state.0[0] += left;
        state.0[1] += right;
        for round in 0..POSEIDON_ROUNDS {
            state.0 = poseidon_round(state.0, round);
        }
    }
    state.0[0]
}

#[derive(Clone, Debug)]
pub(super) struct KaigiRelationConfigV1 {
    pub(super) poseidon: KaigiPoseidonConfig,
    pub(super) instance: Column<Instance>,
    pub(super) value: Column<Advice>,
    pub(super) previous: [Column<Advice>; 3],
    pub(super) input: [Column<Advice>; 2],
    pub(super) range_accumulator: Column<Advice>,
    pub(super) range_bit: Column<Advice>,
    pub(super) q_absorb: Selector,
    pub(super) q_range: Selector,
    pub(super) q_goldilocks: Selector,
}
impl KaigiRelationConfigV1 {
    pub(super) fn configure(meta: &mut ConstraintSystem<Scalar>, instance_rows: usize) -> Self {
        let poseidon = configure_poseidon(meta);
        let instance = meta.instance_column(instance_rows);
        meta.enable_equality(instance);
        let value = meta.advice_column();
        let previous = array::from_fn(|_| meta.advice_column());
        let input = array::from_fn(|_| meta.advice_column());
        let range_accumulator = meta.advice_column();
        let range_bit = meta.advice_column();
        for column in [value, range_accumulator]
            .into_iter()
            .chain(previous)
            .chain(input)
        {
            meta.enable_equality(column);
        }
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let q_absorb = meta.selector();
        let q_range = meta.selector();
        let q_goldilocks = meta.selector();
        meta.create_gate("Kaigi framed sponge absorption", |meta| {
            let q = meta.query_selector(q_absorb);
            (0..3)
                .map(|index| {
                    let absorbed = if index < 2 {
                        meta.query_advice(input[index], Rotation::cur())
                    } else {
                        Expression::Constant(Scalar::ZERO)
                    };
                    q.clone()
                        * (meta.query_advice(poseidon.state[index], Rotation::cur())
                            - meta.query_advice(previous[index], Rotation::cur())
                            - absorbed)
                })
                .collect::<Vec<_>>()
        });
        meta.create_gate("Kaigi exact u64 limb", |meta| {
            let q = meta.query_selector(q_range);
            let bit = meta.query_advice(range_bit, Rotation::cur());
            let acc = meta.query_advice(range_accumulator, Rotation::cur());
            let next = meta.query_advice(range_accumulator, Rotation::next());
            vec![
                q.clone() * bit.clone() * (bit.clone() - Expression::Constant(Scalar::ONE)),
                q * (acc - bit - next * Scalar::from(2)),
            ]
        });
        meta.create_gate("Kaigi canonical Goldilocks limb", |meta| {
            vec![
                meta.query_selector(q_goldilocks)
                    * (meta.query_advice(previous[0], Rotation::cur())
                        + meta.query_advice(previous[1], Rotation::cur())
                        - Expression::Constant(Scalar::from(GOLDILOCKS_MODULUS_V1 - 1))),
            ]
        });
        Self {
            poseidon,
            instance,
            value,
            previous,
            input,
            range_accumulator,
            range_bit,
            q_absorb,
            q_range,
            q_goldilocks,
        }
    }
}
pub(super) fn assign_range<const BITS: usize>(
    layouter: &mut impl Layouter<Scalar>,
    config: &KaigiRelationConfigV1,
    offset: usize,
    source: AssignedValue,
) -> Result<(), Error> {
    assert!(matches!(BITS, 32 | 64), "fixed supported limb widths");
    layouter.assign_region(
        || "Kaigi u64 range",
        |mut region| {
            let mut accumulator = source.1;
            let initial = region
                .assign_advice(config.range_accumulator, offset, accumulator)?
                .cell();
            region.constrain_equal(initial, source.0)?;
            for bit_index in 0..BITS {
                config.q_range.enable(&mut region, offset + bit_index)?;
                let bit = source.1.map(|value| {
                    let repr = value.to_repr();
                    Scalar::from(u64::from((repr[bit_index / 8] >> (bit_index % 8)) & 1))
                });
                region.assign_advice(config.range_bit, offset + bit_index, bit)?;
                accumulator = (accumulator - bit) * Value::known(Scalar::from(2).invert().unwrap());
                let cell = region
                    .assign_advice(
                        config.range_accumulator,
                        offset + bit_index + 1,
                        accumulator,
                    )?
                    .cell();
                if bit_index + 1 == BITS {
                    region.constrain_constant(cell, Scalar::ZERO)?;
                }
            }
            Ok(())
        },
    )
}

pub(super) fn assign_sponge(
    layouter: &mut impl Layouter<Scalar>,
    config: &KaigiRelationConfigV1,
    offset: usize,
    domain: u64,
    payload: &[AssignedValue],
) -> Result<AssignedValue, Error> {
    layouter.assign_region(
        || "Kaigi framed Poseidon sponge",
        |mut region| {
            let mut framed = Vec::with_capacity(payload.len() + 3);
            framed.push((None, Value::known(Scalar::from(payload.len() as u64))));
            framed.extend(payload.iter().map(|(cell, value)| (Some(*cell), *value)));
            framed.push((None, Value::known(Scalar::ONE)));
            if framed.len() % 2 != 0 {
                framed.push((None, Value::known(Scalar::ZERO)));
            }
            let mut state = [
                Value::known(Scalar::ZERO),
                Value::known(Scalar::ZERO),
                Value::known(Scalar::from(domain)),
            ];
            let mut state_cells: Option<[Cell; 3]> = None;
            for (block, pair) in framed.chunks_exact(2).enumerate() {
                let start = offset + block * (POSEIDON_ROUNDS + 1);
                config.q_absorb.enable(&mut region, start)?;
                for index in 0..3 {
                    let cell = region
                        .assign_advice(config.previous[index], start, state[index])?
                        .cell();
                    if let Some(previous) = state_cells {
                        region.constrain_equal(cell, previous[index])?;
                    } else {
                        region.constrain_constant(
                            cell,
                            if index == 2 {
                                Scalar::from(domain)
                            } else {
                                Scalar::ZERO
                            },
                        )?;
                    }
                }
                for index in 0..2 {
                    let cell = region
                        .assign_advice(config.input[index], start, pair[index].1)?
                        .cell();
                    if let Some(source) = pair[index].0 {
                        region.constrain_equal(cell, source)?;
                    } else {
                        let constant = if block == 0 && index == 0 {
                            Scalar::from(payload.len() as u64)
                        } else if block * 2 + index == payload.len() + 1 {
                            Scalar::ONE
                        } else {
                            Scalar::ZERO
                        };
                        region.constrain_constant(cell, constant)?;
                    }
                    state[index] = state[index] + pair[index].1;
                }
                for (column, value) in config.poseidon.state.iter().zip(state) {
                    region.assign_advice(*column, start, value)?;
                }
                for round in 0..POSEIDON_ROUNDS {
                    for index in 0..3 {
                        region.assign_fixed(
                            config.poseidon.round_constants[index],
                            start + round,
                            poseidon_constants().round_constants[round][index],
                        )?;
                    }
                    let half = POSEIDON_FULL_ROUNDS / 2;
                    if round < half || round >= half + POSEIDON_PARTIAL_ROUNDS {
                        config
                            .poseidon
                            .q_full_round
                            .enable(&mut region, start + round)?;
                    } else {
                        config
                            .poseidon
                            .q_partial_round
                            .enable(&mut region, start + round)?;
                    }
                    state = poseidon_round_value(state, round);
                    state_cells = Some(
                        (0..3)
                            .map(|index| {
                                Ok(region
                                    .assign_advice(
                                        config.poseidon.state[index],
                                        start + round + 1,
                                        state[index],
                                    )?
                                    .cell())
                            })
                            .collect::<Result<Vec<_>, Error>>()?
                            .try_into()
                            .map_err(|_| Error::Synthesis)?,
                    );
                }
            }
            Ok((state_cells.expect("fixed nonempty frame")[0], state[0]))
        },
    )
}
