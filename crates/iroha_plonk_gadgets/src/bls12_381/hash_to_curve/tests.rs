//! Native SWU/isogeny differential tests and constrained output mutations.
use super::*;
use crate::{
    arith::GlueConfig,
    cells::Word,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
};
use ark_bls12_381::{Fq, Fq2, g2};
use ark_ec::hashing::{
    curve_maps::{
        swu::SWUMap,
        wb::{WBConfig, WBMap},
    },
    map_to_curve_hasher::MapToCurve,
};
use ark_ff::{BigInt, Field, PrimeField};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
type Iso = <g2::Config as WBConfig>::IsogenousCurve;
fn fq(a: base::Fp) -> Fq {
    Fq::from_bigint(BigInt(a)).expect("canonical")
}
fn fq2(a: Fp2) -> Fq2 {
    Fq2::new(fq(a[0]), fq(a[1]))
}
fn fp2(a: Fq2) -> Fp2 {
    [a.c0.into_bigint().0, a.c1.into_bigint().0]
}
fn input(n: u64) -> Fp2 {
    fp2(Fq2::new(-Fq::from(n), Fq::from(n + 1)))
}
fn swu(a: Fp2) -> [Fp2; 2] {
    let p = SWUMap::<Iso>::new().unwrap().map_to_curve(fq2(a)).unwrap();
    [fp2(p.x), fp2(p.y)]
}
fn mapped(a: Fp2) -> [Fp2; 2] {
    let p = WBMap::<g2::Config>::new()
        .unwrap()
        .map_to_curve(fq2(a))
        .unwrap();
    [fp2(p.x), fp2(p.y)]
}
#[test]
fn native_root_witness_matches_ark_and_has_no_authority() {
    for a in [
        [base::ZERO; 2],
        [base::ONE, base::ZERO],
        ZETA,
        input(7),
        input(99),
        [[2, 0, 0, 0, 0, 0], base::ZERO],
    ] {
        let expected = fq2(a).sqrt();
        let actual = native::sqrt(&a);
        assert_eq!(actual.is_some(), expected.is_some());
        if let Some(root) = actual {
            assert_eq!(fq2(root).square(), fq2(a));
        }
    }
    assert!(!fq2(ZETA).legendre().is_qr());
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Parity,
    Swu,
    Assign,
    Isogeny,
}
#[derive(Clone)]
struct TestCircuit<F: PastaField> {
    op: Op,
    u: Fp2,
    point: [Fp2; 2],
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> TestCircuit<F> {
    fn new(op: Op, u: Fp2) -> Self {
        Self {
            op,
            u,
            point: swu(u),
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
        match self.op {
            Op::Parity => 11,
            Op::Assign => 14,
            _ => 17,
        }
    }
    fn public(&self) -> Vec<F> {
        if matches!(self.op, Op::Parity) {
            let a = fq2(self.u);
            let b = ark_ec::hashing::curve_maps::swu::parity(&a);
            return vec![F::from(u64::from(b))];
        }
        let p = if matches!(self.op, Op::Isogeny) {
            mapped(self.u)
        } else {
            swu(self.u)
        };
        p.into_iter().flatten().flatten().map(F::from).collect()
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
        Self::configure_with_params(meta, 24)
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
            || "W3f G2 map stage",
            |mut region| {
                if matches!(self.op, Op::Parity) {
                    let u = chip.assign_fp2(&mut region, self.witness(self.u))?;
                    return Ok(vec![chip.parity_bls_fp2(&mut region, &u)?.word().clone()]);
                }
                let point = if matches!(self.op, Op::Swu) {
                    let u = chip.assign_fp2(&mut region, self.witness(self.u))?;
                    chip.map_to_swu_g2(&mut region, &u)?
                } else {
                    chip.assign_swu_g2(&mut region, self.witness(self.point))?
                };
                if matches!(self.op, Op::Isogeny) {
                    let mapped = chip.isogeny_to_g2(&mut region, &point)?;
                    return Ok(mapped
                        .x()
                        .coefficients()
                        .iter()
                        .chain(mapped.y().coefficients())
                        .flat_map(|x| x.limbs().iter().cloned())
                        .collect());
                }
                Ok(point
                    .x()
                    .coefficients()
                    .iter()
                    .chain(point.y().coefficients())
                    .flat_map(|x| x.limbs().iter().cloned())
                    .collect())
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn run<F: PastaField>() {
    for u in [
        [base::ZERO; 2],
        [base::ONE, base::ZERO],
        [base::ZERO, base::ONE],
        input(17),
        input(28),
    ] {
        for op in [Op::Parity, Op::Swu, Op::Assign, Op::Isogeny] {
            let c = TestCircuit::<F>::new(op, u);
            let public = c.public();
            assert!(
                check_circuit(&c, c.k(), core::slice::from_ref(&public), CheckMode::Strict)
                    .expect("SWU layout")
                    .is_satisfied(),
                "{op:?} {u:?}"
            );
            let mut wrong = public;
            wrong[0] += F::ONE;
            assert!(
                !check_circuit(&c, c.k(), &[wrong], CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
    }
    let mut c = TestCircuit::<F>::new(Op::Assign, input(9));
    c.point[1][0] = base::add(&c.point[1][0], &base::ONE);
    assert!(
        !check_circuit(&c, c.k(), &[c.public()], CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    let c = TestCircuit::<F>::new(Op::Swu, input(3));
    assert!(synthesize(&c.without_witnesses(), c.k(), None).is_ok());
}
#[test]
fn exact_swu_isogeny_and_mutations_over_fp() {
    run::<PastaFp>();
}
#[test]
fn exact_swu_isogeny_and_mutations_over_fq() {
    run::<PastaFq>();
}
