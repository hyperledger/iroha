//! Curve cases and malformed representations checked against arkworks.

use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    cells::Word,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};
use ark_bls12_381::{Fq, Fq2, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInt, Field, PrimeField, Zero};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
fn fq(a: native::Fp) -> Fq {
    Fq::from_bigint(BigInt(a)).expect("canonical")
}
fn fp2(a: Fq2) -> Fp2 {
    [a.c0.into_bigint().0, a.c1.into_bigint().0]
}
fn fq2(a: Fp2) -> Fq2 {
    Fq2::new(fq(a[0]), fq(a[1]))
}
fn native1(a: G1Affine) -> G1AffineWitness {
    if a.is_zero() {
        G1AffineWitness {
            x: native::ZERO,
            y: native::ZERO,
            infinity: true,
        }
    } else {
        G1AffineWitness {
            x: a.x.into_bigint().0,
            y: a.y.into_bigint().0,
            infinity: false,
        }
    }
}
fn native2(a: G2Affine) -> G2AffineWitness {
    if a.is_zero() {
        G2AffineWitness {
            x: [native::ZERO; 2],
            y: [native::ZERO; 2],
            infinity: true,
        }
    } else {
        G2AffineWitness {
            x: fp2(a.x),
            y: fp2(a.y),
            infinity: false,
        }
    }
}
fn ark1(a: G1AffineWitness) -> G1Affine {
    if a.infinity {
        G1Affine::identity()
    } else {
        G1Affine::new_unchecked(fq(a.x), fq(a.y))
    }
}
fn ark2(a: G2AffineWitness) -> G2Affine {
    if a.infinity {
        G2Affine::identity()
    } else {
        G2Affine::new_unchecked(fq2(a.x), fq2(a.y))
    }
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Assign,
    Identity,
    Add,
    Neg,
    Select(bool),
    Step(bool),
    Equal,
    Nonidentity,
    Psi,
    Psi2,
}
#[derive(Clone)]
struct TestCircuit<F: PastaField> {
    g2: bool,
    op: Op,
    a1: G1AffineWitness,
    b1: G1AffineWitness,
    a2: G2AffineWitness,
    b2: G2AffineWitness,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> TestCircuit<F> {
    fn new(g2: bool, op: Op) -> Self {
        let one = G1Projective::generator();
        let two = G2Projective::generator();
        Self {
            g2,
            op,
            a1: native1((one.double() + one).into_affine()),
            b1: native1(one.into_affine()),
            a2: native2((two.double() + two).into_affine()),
            b2: native2(two.into_affine()),
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
        if self.g2 { 16 } else { 14 }
    }
    fn public(&self) -> Vec<F> {
        if self.g2 {
            let a = ark2(self.a2);
            let b = ark2(self.b2);
            let expected = match self.op {
                Op::Assign | Op::Equal | Op::Nonidentity | Op::Select(true) => self.a2,
                Op::Psi => native2(-a.mul_bigint([0xd201_0000_0001_0000]).into_affine()),
                Op::Psi2 => native2(
                    a.mul_bigint([0xd201_0000_0001_0000])
                        .mul_bigint([0xd201_0000_0001_0000])
                        .into_affine(),
                ),
                Op::Identity => native2(G2Affine::identity()),
                Op::Add => native2((a + b).into_affine()),
                Op::Neg => native2(-a),
                Op::Select(false) => self.b2,
                Op::Step(bit) => native2(
                    (a.into_group().double()
                        + if bit {
                            b.into_group()
                        } else {
                            G2Projective::zero()
                        })
                    .into_affine(),
                ),
            };
            expected
                .x
                .into_iter()
                .chain(expected.y)
                .flatten()
                .map(F::from)
                .chain([F::from(u64::from(expected.infinity))])
                .collect()
        } else {
            let a = ark1(self.a1);
            let b = ark1(self.b1);
            let expected = match self.op {
                Op::Assign
                | Op::Equal
                | Op::Nonidentity
                | Op::Psi
                | Op::Psi2
                | Op::Select(true) => self.a1,
                Op::Identity => native1(G1Affine::identity()),
                Op::Add => native1((a + b).into_affine()),
                Op::Neg => native1(-a),
                Op::Select(false) => self.b1,
                Op::Step(bit) => native1(
                    (a.into_group().double()
                        + if bit {
                            b.into_group()
                        } else {
                            G1Projective::zero()
                        })
                    .into_affine(),
                ),
            };
            expected
                .x
                .into_iter()
                .chain(expected.y)
                .map(F::from)
                .chain([F::from(u64::from(expected.infinity))])
                .collect()
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
        if self.g2 { 25 } else { 13 }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        Self::configure_with_params(meta, 25)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, count: usize) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(8).unwrap());
        let instance = meta.instance_column(count);
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
        let output: Vec<Word<F>> = layouter.assign_region(
            || "BLS curve",
            |mut region| {
                if self.g2 {
                    let a = chip.assign_g2(&mut region, self.witness(self.a2))?;
                    let b = chip.assign_g2(&mut region, self.witness(self.b2))?;
                    let result = match self.op {
                        Op::Assign => a,
                        Op::Psi => chip.psi_g2(&mut region, &a)?,
                        Op::Psi2 => chip.psi2_g2(&mut region, &a)?,
                        Op::Identity => chip.identity_g2(&mut region)?,
                        Op::Add => chip.add_g2(&mut region, &a, &b)?,
                        Op::Neg => chip.neg_g2(&mut region, &a)?,
                        Op::Select(bit) => {
                            let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                            chip.select_g2(&mut region, &bit, &a, &b)?
                        }
                        Op::Step(bit) => {
                            let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                            chip.scalar_step_g2(&mut region, &a, &b, &bit)?
                        }
                        Op::Equal => {
                            Bls381Chip::assert_equal_g2(&mut region, &a, &b)?;
                            a
                        }
                        Op::Nonidentity => {
                            chip.assert_nonidentity_g2(&mut region, &a)?;
                            a
                        }
                    };
                    Ok(result
                        .x()
                        .coefficients()
                        .iter()
                        .chain(result.y().coefficients())
                        .flat_map(|x| x.limbs().iter().cloned())
                        .chain([result.infinity().word().clone()])
                        .collect())
                } else {
                    let a = chip.assign_g1(&mut region, self.witness(self.a1))?;
                    let b = chip.assign_g1(&mut region, self.witness(self.b1))?;
                    let result = match self.op {
                        Op::Assign => a,
                        Op::Psi | Op::Psi2 => return Err(Error::Synthesis),
                        Op::Identity => chip.identity_g1(&mut region)?,
                        Op::Add => chip.add_g1(&mut region, &a, &b)?,
                        Op::Neg => chip.neg_g1(&mut region, &a)?,
                        Op::Select(bit) => {
                            let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                            chip.select_g1(&mut region, &bit, &a, &b)?
                        }
                        Op::Step(bit) => {
                            let bit = chip.glue().boolean(&mut region, self.witness(bit))?;
                            chip.scalar_step_g1(&mut region, &a, &b, &bit)?
                        }
                        Op::Equal => {
                            Bls381Chip::assert_equal_g1(&mut region, &a, &b)?;
                            a
                        }
                        Op::Nonidentity => {
                            chip.assert_nonidentity_g1(&mut region, &a)?;
                            a
                        }
                    };
                    Ok(result
                        .x()
                        .limbs()
                        .iter()
                        .chain(result.y().limbs())
                        .cloned()
                        .chain([result.infinity().word().clone()])
                        .collect())
                }
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn accepts<F: PastaField>(c: &TestCircuit<F>) -> bool {
    check_circuit(c, c.k(), &[c.public()], CheckMode::Strict)
        .expect("curve layout")
        .is_satisfied()
}
fn run<F: PastaField>() {
    for g2 in [false, true] {
        for op in [
            Op::Assign,
            Op::Identity,
            Op::Add,
            Op::Neg,
            Op::Select(false),
            Op::Select(true),
            Op::Step(false),
            Op::Step(true),
            Op::Nonidentity,
        ] {
            let c = TestCircuit::<F>::new(g2, op);
            assert!(accepts(&c), "g2={g2} {op:?}");
            let mut wrong = c.public();
            wrong[0] += F::ONE;
            assert!(
                !check_circuit(&c, c.k(), &[wrong], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        for case in 0..5 {
            let mut c = TestCircuit::<F>::new(g2, Op::Add);
            match case {
                0 => {
                    c.b1 = c.a1;
                    c.b2 = c.a2;
                }
                1 => {
                    c.b1 = native1(-ark1(c.a1));
                    c.b2 = native2(-ark2(c.a2));
                }
                2 => {
                    c.a1 = native1(G1Affine::identity());
                    c.a2 = native2(G2Affine::identity());
                }
                3 => {
                    c.b1 = native1(G1Affine::identity());
                    c.b2 = native2(G2Affine::identity());
                }
                _ => {
                    c.a1 = native1(G1Affine::identity());
                    c.a2 = native2(G2Affine::identity());
                    c.b1 = c.a1;
                    c.b2 = c.a2;
                }
            }
            assert!(accepts(&c), "g2={g2} complete case {case}");
        }
        let mut c = TestCircuit::<F>::new(g2, Op::Equal);
        assert!(!accepts(&c));
        c.b1 = c.a1;
        c.b2 = c.a2;
        assert!(accepts(&c));
        let mut c = TestCircuit::<F>::new(g2, Op::Assign);
        c.a1.y = native::add(&c.a1.y, &native::ONE);
        c.a2.y[0] = native::add(&c.a2.y[0], &native::ONE);
        assert!(!accepts(&c), "off curve");
        c = TestCircuit::new(g2, Op::Assign);
        c.a1.infinity = true;
        c.a2.infinity = true;
        assert!(!accepts(&c), "noncanonical identity");
        c = TestCircuit::new(g2, Op::Nonidentity);
        c.a1 = native1(G1Affine::identity());
        c.a2 = native2(G2Affine::identity());
        assert!(!accepts(&c), "identity admission");
        let c = TestCircuit::<F>::new(g2, Op::Step(true));
        assert!(synthesize(&c.without_witnesses(), c.k(), None).is_ok());
    }
    // (0,2) is on G1 but has order 3: this demonstrates why these types cannot
    // be treated as subgroup credentials. Complete arithmetic still applies.
    let torsion = G1Affine::new_unchecked(Fq::ZERO, Fq::from(2_u64));
    assert!(torsion.is_on_curve());
    assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
    let mut c = TestCircuit::<F>::new(false, Op::Add);
    c.a1 = native1(torsion);
    c.b1 = c.a1;
    assert!(accepts(&c));
}
#[test]
fn complete_curve_laws_and_forgery_over_fp() {
    run::<PastaFp>();
}
#[test]
fn complete_curve_laws_and_forgery_over_fq() {
    run::<PastaFq>();
}
fn tamper<F: PastaField>() {
    for g2 in [false, true] {
        let c = TestCircuit::<F>::new(g2, Op::Add);
        let public = [c.public()];
        let cells = assigned_advice_cells(&c, c.k(), &public).unwrap();
        for i in [0, cells.len() / 3, cells.len() * 2 / 3, cells.len() - 1] {
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
                .is_satisfied()
            );
        }
    }
}
#[test]
fn curve_composition_tampers_over_both_fields() {
    tamper::<PastaFp>();
    tamper::<PastaFq>();
}

fn psi<F: PastaField>() {
    for op in [Op::Psi, Op::Psi2] {
        for identity in [false, true] {
            let mut c = TestCircuit::<F>::new(true, op);
            if identity {
                c.a2 = native2(G2Affine::identity());
            }
            assert!(accepts(&c));
            let mut bad = c.public();
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
fn psi_endomorphisms_over_both_fields() {
    psi::<PastaFp>();
    psi::<PastaFq>();
}
