//! Native G1 subgroup schedule and terminal/fixed-point constraint checks.
use super::super::super::native;
use super::super::G1AffineWitness;
use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    range::{LimbBits, RunningSumChip, RunningSumConfig},
};
use ark_bls12_381::{Fq, G1Affine, g1};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};
fn witness(p: G1Affine) -> G1AffineWitness {
    if p.infinity {
        G1AffineWitness {
            x: native::ZERO,
            y: native::ZERO,
            infinity: true,
        }
    } else {
        G1AffineWitness {
            x: p.x.into_bigint().0,
            y: p.y.into_bigint().0,
            infinity: false,
        }
    }
}
fn execute(step: G1Step, r: &mut [G1Affine; 3]) -> bool {
    match step {
        G1Step::Copy {
            destination,
            source,
        } => r[destination] = r[source],
        G1Step::Double {
            destination,
            source,
        } => r[destination] = (r[source] + r[source]).into_affine(),
        G1Step::Add {
            destination,
            left,
            right,
        } => r[destination] = (r[left] + r[right]).into_affine(),
        G1Step::Negate {
            destination,
            source,
        } => r[destination] = -r[source],
        G1Step::Phi {
            destination,
            source,
        } => r[destination] = g1::endomorphism(&r[source]),
        G1Step::RejectNonidentityFixedPoint => return r[0] != r[1] || r[0].infinity,
    }
    true
}
fn torsion() -> G1Affine {
    G1Affine::new_unchecked(Fq::ZERO, Fq::from(2_u64))
}
#[test]
fn whole_native_g1_subgroup_schedule_matches_native_validation() {
    let mut points = vec![G1Affine::generator(), G1Affine::identity(), torsion()];
    for i in 1_u64..8 {
        if let Some(p) = G1Affine::get_point_from_x_unchecked(Fq::from(i), false) {
            points.push(p);
        }
    }
    for point in points {
        let mut r = [G1Affine::identity(); 3];
        r[0] = point;
        let mut valid = true;
        for step in G1_SUBGROUP_STEPS {
            valid &= execute(step, &mut r);
        }
        valid &= r[1] == r[2];
        assert_eq!(valid, point.is_in_correct_subgroup_assuming_on_curve());
    }
}
#[derive(Clone)]
struct StepCircuit<F: PastaField> {
    before: [G1AffineWitness; 3],
    after: [G1AffineWitness; 3],
    index: usize,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> StepCircuit<F> {
    fn new(index: usize, point: G1Affine) -> Self {
        let mut r = [G1Affine::identity(); 3];
        r[0] = point;
        for step in &G1_SUBGROUP_STEPS[..index] {
            execute(*step, &mut r);
        }
        let before = r.map(witness);
        execute(G1_SUBGROUP_STEPS[index], &mut r);
        Self {
            before,
            after: r.map(witness),
            index,
            known: true,
            marker: PhantomData,
        }
    }
    fn value<T: Copy>(&self, x: T) -> Value<T> {
        if self.known {
            Value::known(x)
        } else {
            Value::unknown()
        }
    }
    fn public(&self) -> Vec<F> {
        self.after
            .iter()
            .flat_map(|p| {
                p.x.into_iter()
                    .chain(p.y)
                    .map(F::from)
                    .chain([F::from(u64::from(p.infinity))])
            })
            .collect()
    }
}
#[derive(Clone)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    instance: Column<Instance>,
}
impl<F: PastaField> Circuit<F> for StepCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(8).unwrap());
        let instance = meta.instance_column(39);
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
        let out = layouter.assign_region(
            || "G1 fixed continuation",
            |mut region| {
                let mut r = Vec::with_capacity(3);
                for value in self.before {
                    r.push(chip.assign_g1(&mut region, self.value(value))?);
                }
                let r: [G1Value<F>; 3] = r.try_into().map_err(|_| Error::Synthesis)?;
                let after = chip.g1_subgroup_step(&mut region, &r, self.index)?;
                Ok(after
                    .iter()
                    .flat_map(|p| {
                        p.x()
                            .limbs()
                            .iter()
                            .chain(p.y().limbs())
                            .cloned()
                            .chain([p.infinity().word().clone()])
                    })
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn run<F: PastaField>() {
    for index in [0, 1, 2, 69, 70, 139, 140] {
        let c = StepCircuit::<F>::new(index, G1Affine::generator());
        let public = c.public();
        assert!(
            check_circuit(&c, 15, core::slice::from_ref(&public), CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "step {index}"
        );
        let mut forged = public;
        forged[13] += F::ONE;
        assert!(
            !check_circuit(&c, 15, &[forged], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    for (point, accepted) in [(G1Affine::identity(), true), (torsion(), false)] {
        let c = StepCircuit::<F>::new(140, point);
        assert_eq!(
            check_circuit(&c, 15, &[c.public()], CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            accepted
        );
    }
    let mut c = StepCircuit::<F>::new(69, G1Affine::generator());
    c.before[1] = c.before[0];
    c.after = c.before;
    assert!(
        !check_circuit(&c, 15, &[c.public()], CheckMode::Strict)
            .unwrap()
            .is_satisfied(),
        "native nonidentity fixed-point guard"
    );
}
#[test]
fn g1_continuations_subgroup_and_fixed_point_guard_over_fp() {
    run::<PastaFp>();
}
#[test]
fn g1_continuations_subgroup_and_fixed_point_guard_over_fq() {
    run::<PastaFq>();
}
