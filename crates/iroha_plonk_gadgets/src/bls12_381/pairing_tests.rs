//! Exact M-twist line coefficients compared to arkworks' native preparation.
use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    bls12_381::{
        curve::{G1AffineWitness, G2AffineWitness},
        extension::{Fp2Value, Fp6Value, Fp12},
    },
    cells::Word,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
};
use ark_bls12_381::{Config as BlsConfig, Fq, Fq2, Fq6, Fq12, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, bls12::G2Prepared};
use ark_ff::{Field, PrimeField};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
fn native2(a: Fq2) -> Fp2 {
    [a.c0.into_bigint().0, a.c1.into_bigint().0]
}
fn native6(a: &Fq6) -> [Fp2; 3] {
    [native2(a.c0), native2(a.c1), native2(a.c2)]
}
fn native12(a: &Fq12) -> Fp12 {
    [native6(&a.c0), native6(&a.c1)]
}
fn q() -> G2Affine {
    G2Affine::generator()
}
fn line(index: usize) -> [Fp2; 3] {
    let c = G2Prepared::<BlsConfig>::from(q()).ell_coeffs[index];
    [native2(c.0), native2(c.1), native2(c.2)]
}
fn accumulator() -> Fq12 {
    Fq12::new(
        Fq6::new(
            Fq2::new(Fq::from(5_u64), Fq::from(7_u64)),
            Fq2::ONE,
            Fq2::ZERO,
        ),
        Fq6::ONE,
    )
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Assign,
    Double,
    Add,
    Evaluate,
    Final(usize),
}
#[derive(Clone)]
struct TestCircuit<F: PastaField> {
    op: Op,
    initial: MillerG2Witness,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> TestCircuit<F> {
    fn new(op: Op) -> Self {
        Self {
            op,
            initial: MillerG2Witness {
                x: native2(q().x),
                y: native2(q().y),
                z: [native::ONE, native::ZERO],
            },
            known: true,
            marker: PhantomData,
        }
    }
    fn witness<T: Copy>(&self, x: T) -> Value<T> {
        if self.known {
            Value::known(x)
        } else {
            Value::unknown()
        }
    }
    fn k(&self) -> u32 {
        if matches!(self.op, Op::Evaluate | Op::Final(_)) {
            17
        } else {
            16
        }
    }
    fn public(&self) -> Vec<F> {
        if let Op::Final(index) = self.op {
            let mut registers = initial_registers();
            native_final_step(final_exponent::FINAL_EXPONENT_STEPS[index], &mut registers);
            return registers
                .iter()
                .flat_map(native12)
                .flatten()
                .flatten()
                .flatten()
                .map(F::from)
                .collect();
        }
        if matches!(self.op, Op::Evaluate) {
            let mut out = accumulator();
            let c = G2Prepared::<BlsConfig>::from(q()).ell_coeffs[0];
            let p = G1Affine::generator();
            out.mul_by_014(
                &c.0,
                &(c.1 * Fq2::new(p.x, Fq::ZERO)),
                &(c.2 * Fq2::new(p.y, Fq::ZERO)),
            );
            return native12(&out)
                .into_iter()
                .flatten()
                .flatten()
                .flatten()
                .map(F::from)
                .collect();
        }
        let multiplier = match self.op {
            Op::Assign => 1_u64,
            Op::Double => 2,
            Op::Add => 3,
            _ => unreachable!(),
        };
        let point = q().mul_bigint([multiplier]).into_affine();
        let mut words: Vec<native::Fp> = native2(point.x)
            .into_iter()
            .chain(native2(point.y))
            .collect();
        if !matches!(self.op, Op::Assign) {
            words.extend(
                line(usize::from(!matches!(self.op, Op::Double)))
                    .into_iter()
                    .flatten(),
            );
        }
        words.into_iter().flatten().map(F::from).collect()
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
        Self::configure_with_params(meta, 60)
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
            || "Miller arithmetic step",
            |mut region| {
                if let Op::Final(index) = self.op {
                    let values = initial_registers();
                    let mut assigned = Vec::with_capacity(5);
                    for value in values {
                        assigned
                            .push(chip.assign_fp12(&mut region, &self.witness(native12(&value)))?);
                    }
                    let assigned: [Fp12Value<F>; 5] =
                        assigned.try_into().map_err(|_| Error::Synthesis)?;
                    let out = chip.final_exponent_step(&mut region, &assigned, index)?;
                    return Ok(out
                        .iter()
                        .flat_map(Fp12Value::coefficients)
                        .flat_map(Fp6Value::coefficients)
                        .flat_map(Fp2Value::coefficients)
                        .flat_map(|x| x.limbs().iter().cloned())
                        .collect());
                }
                if matches!(self.op, Op::Evaluate) {
                    let line = chip.assign_miller_line(&mut region, &self.witness(line(0)))?;
                    let p = G1Affine::generator();
                    let p = chip.assign_g1(
                        &mut region,
                        self.witness(G1AffineWitness {
                            x: p.x.into_bigint().0,
                            y: p.y.into_bigint().0,
                            infinity: false,
                        }),
                    )?;
                    let acc =
                        chip.assign_fp12(&mut region, &self.witness(native12(&accumulator())))?;
                    let out = chip.miller_evaluate(&mut region, &acc, &line, &p)?;
                    return Ok(out
                        .coefficients()
                        .iter()
                        .flat_map(Fp6Value::coefficients)
                        .flat_map(Fp2Value::coefficients)
                        .flat_map(|x| x.limbs().iter().cloned())
                        .collect());
                }
                let (point, line) = if matches!(self.op, Op::Assign) {
                    (
                        chip.assign_miller_g2(&mut region, &self.witness(self.initial))?,
                        None,
                    )
                } else {
                    let base = chip.assign_g2(
                        &mut region,
                        self.witness(G2AffineWitness {
                            x: native2(q().x),
                            y: native2(q().y),
                            infinity: false,
                        }),
                    )?;
                    let start = chip.start_miller_g2(&mut region, &base)?;
                    let (double, line) = chip.miller_double(&mut region, &start)?;
                    if matches!(self.op, Op::Double) {
                        (double, Some(line))
                    } else {
                        let (added, line) = chip.miller_add(&mut region, &double, &base)?;
                        (added, Some(line))
                    }
                };
                let zi = chip.invert_fp2(&mut region, point.z())?;
                let x = chip.mul_fp2(&mut region, point.x(), &zi)?;
                let y = chip.mul_fp2(&mut region, point.y(), &zi)?;
                let mut out: Vec<Word<F>> = x
                    .coefficients()
                    .iter()
                    .chain(y.coefficients())
                    .flat_map(|x| x.limbs().iter().cloned())
                    .collect();
                if let Some(line) = line {
                    out.extend(
                        line.coefficients()
                            .iter()
                            .flat_map(Fp2Value::coefficients)
                            .flat_map(|x| x.limbs().iter().cloned()),
                    );
                }
                Ok(out)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn run<F: PastaField>() {
    for op in [
        Op::Assign,
        Op::Double,
        Op::Add,
        Op::Evaluate,
        Op::Final(0),
        Op::Final(1),
        Op::Final(2),
        Op::Final(4),
        Op::Final(6),
        Op::Final(7),
    ] {
        let c = TestCircuit::<F>::new(op);
        let public = c.public();
        assert!(
            check_circuit(&c, c.k(), std::slice::from_ref(&public), CheckMode::Strict)
                .expect("Miller layout")
                .is_satisfied(),
            "{op:?}"
        );
        let mut forged = public;
        let last = forged.len() - 1;
        forged[last] += F::ONE;
        assert!(
            !check_circuit(&c, c.k(), &[forged], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    let mut c = TestCircuit::<F>::new(Op::Assign);
    c.initial.z = [native::ZERO; 2];
    assert!(
        !check_circuit(&c, c.k(), &[c.public()], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let mut c = TestCircuit::<F>::new(Op::Assign);
    c.initial.y[0] = native::add(&c.initial.y[0], &native::ONE);
    assert!(
        !check_circuit(&c, c.k(), &[c.public()], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let c = TestCircuit::<F>::new(Op::Double);
    assert!(synthesize(&c.without_witnesses(), c.k(), None).is_ok());
}
#[test]
fn exact_miller_lines_and_forgery_over_fp() {
    run::<PastaFp>();
}
#[test]
fn exact_miller_lines_and_forgery_over_fq() {
    run::<PastaFq>();
}

fn initial_registers() -> [Fq12; 5] {
    core::array::from_fn(|i| {
        accumulator()
            + Fq12::new(
                Fq6::new(Fq2::new(Fq::from(i as u64), Fq::ZERO), Fq2::ZERO, Fq2::ZERO),
                Fq6::ZERO,
            )
    })
}
fn native_final_step(step: final_exponent::FinalExponentStep, r: &mut [Fq12; 5]) {
    use final_exponent::FinalExponentStep as S;
    match step {
        S::Copy {
            destination,
            source,
        } => r[destination] = r[source],
        S::Multiply {
            destination,
            left,
            right,
        } => r[destination] = r[left] * r[right],
        S::Square {
            destination,
            source,
        } => r[destination] = r[source].square(),
        S::Inverse {
            destination,
            source,
        } => r[destination] = r[source].inverse().unwrap(),
        S::Conjugate {
            destination,
            source,
        } => r[destination] = Fq12::new(r[source].c0, -r[source].c1),
        S::Frobenius {
            destination,
            source,
            power,
        } => r[destination] = r[source].frobenius_map(power),
    }
}
