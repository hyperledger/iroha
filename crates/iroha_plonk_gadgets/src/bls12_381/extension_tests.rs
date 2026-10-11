//! Extension arithmetic checked against the independent arkworks tower.

use core::marker::PhantomData;

use ark_bls12_381::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{BigInt, Field, PrimeField};
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};

use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    cells::Word,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};

#[derive(Clone, Copy, Debug)]
enum Op {
    Assign,
    Add,
    Sub,
    Neg,
    Mul,
    Square,
    Invert,
    Nonresidue,
    Conjugate,
    Scale,
    Select(bool),
    Zero,
    Equal,
    Frobenius(u8),
}

fn fq(a: native::Fp) -> Fq {
    Fq::from_bigint(BigInt(a)).expect("canonical test input")
}
fn fq2(a: Fp2) -> Fq2 {
    Fq2::new(fq(a[0]), fq(a[1]))
}
fn fq6(a: &Fp6) -> Fq6 {
    Fq6::new(fq2(a[0]), fq2(a[1]), fq2(a[2]))
}
fn fq12(a: &Fp12) -> Fq12 {
    Fq12::new(fq6(&a[0]), fq6(&a[1]))
}
fn out2(a: Fq2) -> Fp2 {
    [a.c0.into_bigint().0, a.c1.into_bigint().0]
}
fn out6(a: &Fq6) -> Fp6 {
    [out2(a.c0), out2(a.c1), out2(a.c2)]
}
fn out12(a: &Fq12) -> Fp12 {
    [out6(&a.c0), out6(&a.c1)]
}
fn flatten2(a: Fp2) -> Vec<native::Fp> {
    a.into_iter().collect()
}
fn flatten6(a: &Fp6) -> Vec<native::Fp> {
    a.iter().flatten().copied().collect()
}
fn flatten12(a: &Fp12) -> Vec<native::Fp> {
    a.iter().flatten().flatten().copied().collect()
}

fn sample(seed: u64) -> Fp12 {
    // Large, distinct canonical coefficients exercise carries and tower order.
    core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            core::array::from_fn(|k| {
                let n = seed + 1 + (i * 6 + j * 2 + k) as u64;
                (-Fq::from(n * n + 17)).into_bigint().0
            })
        })
    })
}

#[derive(Clone)]
struct TestCircuit<F: PastaField> {
    degree: usize,
    op: Op,
    a: Fp12,
    b: Fp12,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> TestCircuit<F> {
    fn new(degree: usize, op: Op) -> Self {
        Self {
            degree,
            op,
            a: sample(3),
            b: sample(29),
            known: true,
            marker: PhantomData,
        }
    }
    fn witness<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn k(&self) -> u32 {
        match self.degree {
            2 => 13,
            6 => 15,
            12 => 17,
            _ => unreachable!(),
        }
    }
    fn public(&self) -> Vec<F> {
        let a2 = fq2(self.a[0][0]);
        let b2 = fq2(self.b[0][0]);
        let a6 = fq6(&self.a[0]);
        let b6 = fq6(&self.b[0]);
        let a12 = fq12(&self.a);
        let b12 = fq12(&self.b);
        if matches!(self.op, Op::Zero | Op::Equal) {
            let bit = match self.op {
                Op::Zero => a2 == Fq2::ZERO,
                Op::Equal => a2 == b2,
                _ => unreachable!(),
            };
            return vec![F::from(u64::from(bit))];
        }
        let result = match self.degree {
            2 => flatten2(out2(match self.op {
                Op::Assign | Op::Select(true) => a2,
                Op::Frobenius(power) => a2.frobenius_map(usize::from(power)),
                Op::Add => a2 + b2,
                Op::Sub => a2 - b2,
                Op::Neg => -a2,
                Op::Mul => a2 * b2,
                Op::Square => a2.square(),
                Op::Invert => a2.inverse().unwrap_or(Fq2::ZERO),
                Op::Nonresidue => a2 * Fq2::new(Fq::ONE, Fq::ONE),
                Op::Conjugate => Fq2::new(a2.c0, -a2.c1),
                Op::Scale => a2 * Fq2::new(b2.c0, Fq::ZERO),
                Op::Select(false) => b2,
                _ => unreachable!(),
            })),
            6 => flatten6(&out6(&match self.op {
                Op::Assign => a6,
                Op::Frobenius(power) => a6.frobenius_map(usize::from(power)),
                Op::Add => a6 + b6,
                Op::Sub => a6 - b6,
                Op::Neg => -a6,
                Op::Mul => a6 * b6,
                Op::Square => a6.square(),
                Op::Invert => a6.inverse().unwrap_or(Fq6::ZERO),
                Op::Nonresidue => a6 * Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO),
                _ => unreachable!(),
            })),
            12 => flatten12(&out12(&match self.op {
                Op::Assign => a12,
                Op::Frobenius(power) => a12.frobenius_map(usize::from(power)),
                Op::Mul => a12 * b12,
                Op::Square => a12.square(),
                Op::Invert => a12.inverse().unwrap_or(Fq12::ZERO),
                Op::Conjugate => Fq12::new(a12.c0, -a12.c1),
                _ => unreachable!(),
            })),
            _ => unreachable!(),
        };
        result.into_iter().flatten().map(F::from).collect()
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
        Self::configure_with_params(meta, 72)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, public: usize) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(8).unwrap());
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
        let output = layouter.assign_region(
            || "BLS extension tower",
            |mut region| {
                Ok(match self.degree {
                    2 => {
                        let a = chip.assign_fp2(&mut region, self.witness(self.a[0][0]))?;
                        let b = chip.assign_fp2(&mut region, self.witness(self.b[0][0]))?;
                        let result = match self.op {
                            Op::Assign => a,
                            Op::Frobenius(power) => {
                                chip.frobenius_fp2(&mut region, &a, usize::from(power))?
                            }
                            Op::Add => chip.add_fp2(&mut region, &a, &b)?,
                            Op::Sub => chip.sub_fp2(&mut region, &a, &b)?,
                            Op::Neg => chip.neg_fp2(&mut region, &a)?,
                            Op::Mul => chip.mul_fp2(&mut region, &a, &b)?,
                            Op::Square => chip.square_fp2(&mut region, &a)?,
                            Op::Invert => chip.invert_fp2(&mut region, &a)?,
                            Op::Nonresidue => chip.mul_fp2_nonresidue(&mut region, &a)?,
                            Op::Conjugate => chip.conjugate_fp2(&mut region, &a)?,
                            Op::Scale => {
                                chip.mul_fp2_by_fp(&mut region, &a, &b.coefficients()[0])?
                            }
                            Op::Select(bit) => {
                                let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                                chip.select_fp2(&mut region, &bit, &a, &b)?
                            }
                            Op::Zero => {
                                return Ok(vec![chip.is_zero_fp2(&mut region, &a)?.word().clone()]);
                            }
                            Op::Equal => {
                                return Ok(vec![
                                    chip.is_equal_fp2(&mut region, &a, &b)?.word().clone(),
                                ]);
                            }
                        };
                        let constant = chip.constant_fp2(&mut region, self.a[0][0])?;
                        let assigned = chip.assign_fp2(&mut region, self.witness(self.a[0][0]))?;
                        Bls381Chip::assert_equal_fp2(&mut region, &assigned, &constant)?;
                        result
                            .coefficients()
                            .iter()
                            .flat_map(|x| x.limbs().iter().cloned())
                            .collect()
                    }
                    6 => {
                        let a = chip.assign_fp6(&mut region, &self.witness(self.a[0]))?;
                        let b = chip.assign_fp6(&mut region, &self.witness(self.b[0]))?;
                        let result = match self.op {
                            Op::Assign => a,
                            Op::Frobenius(power) => {
                                chip.frobenius_fp6(&mut region, &a, usize::from(power))?
                            }
                            Op::Add => chip.add_fp6(&mut region, &a, &b)?,
                            Op::Sub => chip.sub_fp6(&mut region, &a, &b)?,
                            Op::Neg => chip.neg_fp6(&mut region, &a)?,
                            Op::Mul => chip.mul_fp6(&mut region, &a, &b)?,
                            Op::Square => chip.square_fp6(&mut region, &a)?,
                            Op::Invert => chip.invert_fp6(&mut region, &a)?,
                            Op::Nonresidue => chip.mul_fp6_nonresidue(&mut region, &a)?,
                            _ => return Err(Error::Synthesis),
                        };
                        let constant = chip.constant_fp6(&mut region, &self.a[0])?;
                        let assigned = chip.assign_fp6(&mut region, &self.witness(self.a[0]))?;
                        Bls381Chip::assert_equal_fp6(&mut region, &assigned, &constant)?;
                        result
                            .coefficients()
                            .iter()
                            .flat_map(Fp2Value::coefficients)
                            .flat_map(|x| x.limbs().iter().cloned())
                            .collect()
                    }
                    12 => {
                        let a = chip.assign_fp12(&mut region, &self.witness(self.a))?;
                        let b = chip.assign_fp12(&mut region, &self.witness(self.b))?;
                        let result = match self.op {
                            Op::Assign => a,
                            Op::Frobenius(power) => {
                                chip.frobenius_fp12(&mut region, &a, usize::from(power))?
                            }
                            Op::Mul => chip.mul_fp12(&mut region, &a, &b)?,
                            Op::Square => chip.square_fp12(&mut region, &a)?,
                            Op::Invert => chip.invert_fp12(&mut region, &a)?,
                            Op::Conjugate => chip.conjugate_fp12(&mut region, &a)?,
                            _ => return Err(Error::Synthesis),
                        };
                        let constant = chip.constant_fp12(&mut region, &self.a)?;
                        let assigned = chip.assign_fp12(&mut region, &self.witness(self.a))?;
                        Bls381Chip::assert_equal_fp12(&mut region, &assigned, &constant)?;
                        result
                            .coefficients()
                            .iter()
                            .flat_map(Fp6Value::coefficients)
                            .flat_map(Fp2Value::coefficients)
                            .flat_map(|x| x.limbs().iter().cloned())
                            .collect()
                    }
                    _ => return Err(Error::Synthesis),
                })
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            let word: &Word<F> = word;
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn run<F: PastaField>() {
    let operations: &[(usize, &[Op])] = &[
        (
            2,
            &[
                Op::Assign,
                Op::Add,
                Op::Sub,
                Op::Neg,
                Op::Mul,
                Op::Square,
                Op::Invert,
                Op::Nonresidue,
                Op::Conjugate,
                Op::Scale,
                Op::Select(false),
                Op::Select(true),
                Op::Zero,
                Op::Equal,
            ],
        ),
        (
            6,
            &[
                Op::Assign,
                Op::Add,
                Op::Sub,
                Op::Neg,
                Op::Mul,
                Op::Square,
                Op::Invert,
                Op::Nonresidue,
            ],
        ),
        (
            12,
            &[Op::Assign, Op::Mul, Op::Square, Op::Invert, Op::Conjugate],
        ),
    ];
    for &(degree, ops) in operations {
        for &op in ops {
            let c = TestCircuit::<F>::new(degree, op);
            let public = c.public();
            assert!(
                check_circuit(&c, c.k(), std::slice::from_ref(&public), CheckMode::Strict)
                    .expect("extension layout")
                    .is_satisfied(),
                "degree {degree} {op:?}"
            );
            let mut wrong = public;
            wrong[0] += F::ONE;
            assert!(
                !check_circuit(&c, c.k(), &[wrong], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "forged degree {degree} {op:?}"
            );
        }
        let mut zero = TestCircuit::<F>::new(degree, Op::Invert);
        zero.a = [[[native::ZERO; 2]; 3]; 2];
        assert!(
            !check_circuit(&zero, zero.k(), &[zero.public()], CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "zero inverse degree {degree}"
        );
    }
    for op in [Op::Zero, Op::Equal] {
        let mut c = TestCircuit::<F>::new(2, op);
        c.a = [[[native::ZERO; 2]; 3]; 2];
        c.b = c.a;
        assert!(
            check_circuit(&c, c.k(), &[c.public()], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    let c = TestCircuit::<F>::new(12, Op::Mul);
    assert!(synthesize(&c.without_witnesses(), c.k(), None).is_ok());
}
#[test]
fn tower_oracle_and_consistent_forgery_over_fp() {
    run::<PastaFp>();
}
#[test]
fn tower_oracle_and_consistent_forgery_over_fq() {
    run::<PastaFq>();
}

fn sampled_tamper<F: PastaField>() {
    // Base arithmetic sweeps every assigned cell. Here sample all extension
    // composition paths, including the first and last coefficient regions.
    for (degree, op) in [
        (2, Op::Mul),
        (2, Op::Invert),
        (6, Op::Mul),
        (6, Op::Invert),
        (12, Op::Mul),
        (12, Op::Invert),
    ] {
        let c = TestCircuit::<F>::new(degree, op);
        let public = [c.public()];
        let cells = assigned_advice_cells(&c, c.k(), &public).unwrap();
        let indices = [
            0,
            cells.len() / 4,
            cells.len() / 2,
            cells.len() * 3 / 4,
            cells.len() - 1,
        ];
        for i in indices {
            let (column, row) = cells[i];
            assert!(
                !check_tampered(
                    &c,
                    c.k(),
                    &public,
                    Some(Tamper {
                        column,
                        row,
                        delta: F::ONE
                    })
                )
                .unwrap()
                .is_satisfied(),
                "degree {degree} {op:?} cell {column}:{row}"
            );
        }
    }
}
#[test]
fn extension_composition_tampers_over_fp() {
    sampled_tamper::<PastaFp>();
}
#[test]
fn extension_composition_tampers_over_fq() {
    sampled_tamper::<PastaFq>();
}

fn frobenius<F: PastaField>() {
    for degree in [2, 6, 12] {
        for power in 0..12 {
            let c = TestCircuit::<F>::new(degree, Op::Frobenius(power));
            let public = c.public();
            assert!(
                check_circuit(&c, c.k(), std::slice::from_ref(&public), CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "degree {degree} power {power}"
            );
            let mut bad = public;
            bad[0] += F::ONE;
            assert!(
                !check_circuit(&c, c.k(), &[bad], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
}
#[test]
fn all_frobenius_powers_over_both_fields() {
    frobenius::<PastaFp>();
    frobenius::<PastaFq>();
}
