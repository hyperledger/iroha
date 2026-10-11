//! Independent integer-oracle, boundary, forged-relation and per-cell tests.

use core::marker::PhantomData;

use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use num_bigint::{BigInt, BigUint};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};

use super::*;
use crate::{
    arith::GlueConfig,
    range::{LimbBits, RunningSumConfig},
    tamper::undetected_tampers,
};

const K: u32 = 11;

fn big(a: &Fp) -> BigUint {
    BigUint::from_bytes_le(&a.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>())
}

fn words(a: &BigUint) -> Fp {
    let digits = a.to_u64_digits();
    assert!(digits.len() <= 6);
    core::array::from_fn(|i| digits.get(i).copied().unwrap_or(0))
}

fn boundaries() -> Vec<Fp> {
    let p = big(&native::MODULUS);
    let mut out = vec![
        native::ZERO,
        native::ONE,
        words(&(&p - 1_u8)),
        words(&(&p - 2_u8)),
    ];
    for bit in [63, 64, 65, 127, 128, 191, 192, 255, 256, 319, 320, 380] {
        let value = BigUint::from(1_u8) << bit;
        out.push(words(&(&value - 1_u8)));
        out.push(words(&value));
        out.push(words(&(value + 1_u8)));
    }
    out
}

#[test]
fn fixed_width_native_arithmetic_matches_independent_bigints() {
    assert_eq!(
        native::MODULUS,
        <ark_bls12_381::Fq as ark_ff::PrimeField>::MODULUS.0
    );
    let p = big(&native::MODULUS);
    assert_eq!(p.bits(), 381);
    let mut values = boundaries();
    let mut rng = ChaCha20Rng::from_seed([0x38; 32]);
    for _ in 0..48 {
        let raw = core::array::from_fn(|_| rng.next_u64());
        values.push(words(&(big(&raw) % &p)));
    }
    for (index, a) in values.iter().enumerate() {
        assert!(native::is_canonical(a));
        assert_eq!(big(&native::neg(a)), (&p - big(a)) % &p);
        for b in [
            &values[(index * 7 + 3) % values.len()],
            &values[2],
            &native::ZERO,
        ] {
            let ab = big(a) * big(b);
            let (r, q) = native::mul_with_quotient(a, b);
            assert_eq!(big(&r), &ab % &p);
            assert_eq!(big(&q), &ab / &p);
            assert_eq!(big(&native::add(a, b)), (big(a) + big(b)) % &p);
            assert_eq!(big(&native::sub(a, b)), (big(a) + &p - big(b)) % &p);
            let carries = native::multiplication_carries(a, b, &r, &q);
            assert_eq!(carries[0], 0);
            assert_eq!(carries[12], 0);
            for column in 0..12 {
                assert!(carries[column].unsigned_abs() < 7 * RADIX);
                let mut integer = BigInt::from(carries[column]);
                for i in 0..6 {
                    if column >= i && column - i < 6 {
                        let j = column - i;
                        integer += BigInt::from(a[i]) * BigInt::from(b[j]);
                        integer -= BigInt::from(q[i]) * BigInt::from(native::MODULUS[j]);
                    }
                }
                if column < 6 {
                    integer -= BigInt::from(r[column]);
                }
                assert_eq!(
                    integer,
                    BigInt::from(RADIX) * BigInt::from(carries[column + 1])
                );
            }
        }
    }
    for a in [native::ZERO, native::ONE, values[2], values[16]] {
        assert_eq!(big(&native::invert(&a)), big(&a).modpow(&(&p - 2_u8), &p));
    }
    assert!(!native::is_canonical(&native::MODULUS));
    assert!(!native::is_canonical(&[u64::MAX; 6]));
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Assign,
    Reduce,
    Add,
    Sub,
    Mul,
    Square,
    Neg,
    Invert,
    Select(bool),
    Zero,
    Equal,
    ForgedProduct,
    Carry,
}

#[derive(Clone)]
struct TestCircuit<F: PastaField> {
    op: Op,
    a: Fp,
    b: Fp,
    r: Fp,
    q: Fp,
    carry: i128,
    wide: [u64; 8],
    wide_overflow: bool,
    known: bool,
    marker: PhantomData<F>,
}

impl<F: PastaField> TestCircuit<F> {
    fn new(op: Op, a: Fp, b: Fp) -> Self {
        Self {
            op,
            a,
            b,
            r: native::ZERO,
            q: native::ZERO,
            carry: 0,
            wide: [u64::MAX; 8],
            wide_overflow: false,
            known: true,
            marker: PhantomData,
        }
    }

    fn public(&self) -> Vec<F> {
        let value = match self.op {
            Op::Assign | Op::Select(true) => self.a,
            Op::Reduce => words(
                &(BigUint::from_bytes_le(
                    &self
                        .wide
                        .iter()
                        .flat_map(|x| x.to_le_bytes())
                        .collect::<Vec<_>>(),
                ) % big(&native::MODULUS)),
            ),
            Op::Add => native::add(&self.a, &self.b),
            Op::Sub => native::sub(&self.a, &self.b),
            Op::Mul => native::mul(&self.a, &self.b),
            Op::Square => native::square(&self.a),
            Op::Neg => native::neg(&self.a),
            Op::Invert => native::invert(&self.a),
            Op::Select(false) => self.b,
            Op::Zero => return vec![F::from(u64::from(self.a == native::ZERO))],
            Op::Equal => return vec![F::from(u64::from(self.a == self.b))],
            Op::ForgedProduct => self.r,
            Op::Carry => {
                return vec![
                    F::from_u128(self.carry.unsigned_abs())
                        * if self.carry < 0 { -F::ONE } else { F::ONE },
                ];
            }
        };
        value.into_iter().map(F::from).collect()
    }

    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}

#[derive(Clone)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    instance: Column<Instance>,
}

impl<F: PastaField> Circuit<F> for TestCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn params(&self) -> usize {
        self.public().len()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        Self::configure_with_params(meta, 6)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, public: usize) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(8).expect("8 bits"));
        let instance = meta.instance_column(public);
        meta.enable_equality(instance);
        Config {
            glue,
            range,
            instance,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let mut chip = Bls381Chip::new(&mut glue, &mut range);
        let outputs = layouter.assign_region(
            || "BLS base field",
            |mut region| {
                if matches!(self.op, Op::Reduce) {
                    let mut limbs = Vec::new();
                    for i in 0..8 {
                        let value = F::from(self.wide[i])
                            + if self.wide_overflow && i == 0 {
                                F::from_u128(RADIX)
                            } else {
                                F::ZERO
                            };
                        limbs.push(chip.glue().witness(&mut region, self.witness(value))?);
                    }
                    let limbs: [Word<F>; 8] = limbs.try_into().map_err(|_| Error::Synthesis)?;
                    return Ok(chip.reduce_words(&mut region, &limbs)?.limbs.to_vec());
                }
                if matches!(self.op, Op::Carry) {
                    return Ok(vec![chip.signed_carry(
                        &mut region,
                        self.witness(self.carry),
                        CARRY_OFFSET,
                        69,
                        false,
                    )?]);
                }
                let a = chip.assign(&mut region, self.witness(self.a))?;
                let result = match self.op {
                    Op::Assign => a,
                    Op::Square => chip.square(&mut region, &a)?,
                    Op::Neg => chip.neg(&mut region, &a)?,
                    Op::Invert => chip.invert(&mut region, &a)?,
                    Op::Zero => return Ok(vec![chip.is_zero(&mut region, &a)?.word().clone()]),
                    _ => {
                        let b = chip.assign(&mut region, self.witness(self.b))?;
                        match self.op {
                            Op::Add => chip.add(&mut region, &a, &b)?,
                            Op::Sub => chip.sub(&mut region, &a, &b)?,
                            Op::Mul => chip.mul(&mut region, &a, &b)?,
                            Op::Select(bit) => {
                                let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                                chip.select(&mut region, &bit, &a, &b)?
                            }
                            Op::Equal => {
                                return Ok(vec![
                                    chip.is_equal(&mut region, &a, &b)?.word().clone(),
                                ]);
                            }
                            Op::ForgedProduct => {
                                let r = chip.assign(&mut region, self.witness(self.r))?;
                                let q = chip.assign(&mut region, self.witness(self.q))?;
                                chip.constrain_product(&mut region, &a, &b, &r, &q)?;
                                r
                            }
                            _ => return Err(Error::Synthesis),
                        }
                    }
                };
                Ok(result.limbs.to_vec())
            },
        )?;
        for (i, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}

fn accepts<F: PastaField>(circuit: &TestCircuit<F>) -> bool {
    check_circuit(circuit, K, &[circuit.public()], CheckMode::Strict)
        .expect("synthesis/check")
        .is_satisfied()
}

fn constrained_boundaries<F: PastaField>() {
    let values = boundaries();
    for (index, a) in values.iter().enumerate() {
        let b = values[(index * 3 + 5) % values.len()];
        for op in [
            Op::Assign,
            Op::Add,
            Op::Sub,
            Op::Mul,
            Op::Square,
            Op::Neg,
            Op::Select(true),
            Op::Select(false),
            Op::Zero,
            Op::Equal,
        ] {
            assert!(
                accepts(&TestCircuit::<F>::new(op, *a, b)),
                "{op:?} case {index}"
            );
        }
    }
    for a in [native::ONE, values[2], values[17]] {
        assert!(accepts(&TestCircuit::<F>::new(Op::Invert, a, native::ZERO)));
    }
    assert!(!accepts(&TestCircuit::<F>::new(
        Op::Invert,
        native::ZERO,
        native::ZERO
    )));
    assert!(accepts(&TestCircuit::<F>::new(
        Op::Equal,
        values[2],
        values[2]
    )));
    for bad in [
        native::MODULUS,
        words(&(big(&native::MODULUS) + 1_u8)),
        [u64::MAX; 6],
    ] {
        assert!(!accepts(&TestCircuit::<F>::new(
            Op::Assign,
            bad,
            native::ZERO
        )));
    }
    for wide in [
        [0; 8],
        [u64::MAX; 8],
        [0, 0, 0, 0, 0, 0, 0, 1_u64 << 63],
        core::array::from_fn(|i| native::MODULUS.get(i).copied().unwrap_or(0)),
    ] {
        let mut circuit = TestCircuit::<F>::new(Op::Reduce, native::ZERO, native::ZERO);
        circuit.wide = wide;
        assert!(accepts(&circuit));
        circuit.wide_overflow = true;
        assert!(
            !accepts(&circuit),
            "512-bit reduction must range-check source words"
        );
    }
}

#[test]
fn constrained_boundary_vectors_over_both_pasta_fields() {
    constrained_boundaries::<PastaFp>();
    constrained_boundaries::<PastaFq>();
}

fn forged_relations<F: PastaField>() {
    let p = big(&native::MODULUS);
    let mut circuit =
        TestCircuit::<F>::new(Op::ForgedProduct, words(&(&p - 1_u8)), words(&(&p - 1_u8)));
    (circuit.r, circuit.q) = native::mul_with_quotient(&circuit.a, &circuit.b);
    assert!(accepts(&circuit));
    let correct = circuit.clone();
    circuit.r = native::add(&circuit.r, &native::ONE);
    assert!(!accepts(&circuit), "canonical but wrong residue");
    circuit = correct.clone();
    circuit.q = native::sub(&circuit.q, &native::ONE);
    assert!(!accepts(&circuit), "canonical but wrong quotient");
    circuit = correct;
    circuit.r = words(&(big(&circuit.r) + &p));
    circuit.q = native::sub(&circuit.q, &native::ONE);
    assert!(
        !accepts(&circuit),
        "same integer product with noncanonical residue"
    );
    for (carry, ok) in [
        (-CARRY_OFFSET, true),
        (CARRY_OFFSET - 1, true),
        (-CARRY_OFFSET - 1, false),
        (CARRY_OFFSET, false),
    ] {
        let mut c = TestCircuit::<F>::new(Op::Carry, native::ZERO, native::ZERO);
        c.carry = carry;
        assert_eq!(accepts(&c), ok, "carry {carry}");
    }
    // Public outputs are independently binding, not recomputed authority.
    let c = TestCircuit::<F>::new(Op::Mul, [17, 0, 0, 0, 0, 0], [23, 0, 0, 0, 0, 0]);
    let mut wrong = c.public();
    wrong[0] += F::ONE;
    assert!(
        !check_circuit(&c, K, &[wrong], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    assert!(synthesize(&c.without_witnesses(), K, None).is_ok());
}

#[test]
fn consistent_forged_arithmetic_and_out_of_range_carries_fail_both_fields() {
    forged_relations::<PastaFp>();
    forged_relations::<PastaFq>();
}

fn every_cell<F: PastaField>() {
    let a = words(&(big(&native::MODULUS) - 2_u8));
    let b = words(&(big(&native::MODULUS) - 3_u8));
    // Includes every distinct layout path. Invert/square share multiplication
    // constraints, but are swept independently to cover their assignments too.
    for op in [
        Op::Assign,
        Op::Reduce,
        Op::Add,
        Op::Sub,
        Op::Mul,
        Op::Square,
        Op::Neg,
        Op::Invert,
        Op::Select(true),
        Op::Select(false),
        Op::Zero,
        Op::Equal,
    ] {
        let circuit = TestCircuit::<F>::new(op, a, b);
        let undetected =
            undetected_tampers(&circuit, K, &[circuit.public()]).expect("honest circuit");
        assert!(undetected.is_empty(), "{op:?}: {undetected:?}");
    }
    for op in [Op::Zero, Op::Equal] {
        let circuit = TestCircuit::<F>::new(op, native::ZERO, native::ZERO);
        assert!(
            undetected_tampers(&circuit, K, &[circuit.public()])
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn every_assigned_advice_cell_is_pinned_over_fp() {
    every_cell::<PastaFp>();
}

#[test]
fn every_assigned_advice_cell_is_pinned_over_fq() {
    every_cell::<PastaFq>();
}
