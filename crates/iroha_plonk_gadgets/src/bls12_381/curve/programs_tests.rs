//! Fixed G2 program oracle and continuation/terminal constraint tests.
use super::super::super::{extension::Fp2, native};
use super::super::G2AffineWitness;
use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    range::{LimbBits, RunningSumChip, RunningSumConfig},
};
use ark_bls12_381::{Fq, Fq2, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};
fn fp2(a: Fq2) -> Fp2 {
    [a.c0.into_bigint().0, a.c1.into_bigint().0]
}
fn witness(p: G2Affine) -> G2AffineWitness {
    if p.infinity {
        G2AffineWitness {
            x: [native::ZERO; 2],
            y: [native::ZERO; 2],
            infinity: true,
        }
    } else {
        G2AffineWitness {
            x: fp2(p.x),
            y: fp2(p.y),
            infinity: false,
        }
    }
}
fn psi(p: G2Affine) -> G2Affine {
    if p.infinity {
        return p;
    }
    let mut e = Fq::MODULUS;
    e.sub_with_borrow(&1_u64.into());
    let mut third = [0_u64; 6];
    let mut carry = 0_u128;
    for i in (0..6).rev() {
        let n = (carry << 64) + u128::from(e.0[i]);
        third[i] = u64::try_from(n / 3).expect("quotient fits one limb");
        carry = n % 3;
    }
    let mut half = e;
    half.div2();
    let xi = Fq2::new(Fq::ONE, Fq::ONE);
    G2Affine::new_unchecked(
        p.x.frobenius_map(1) * xi.pow(third).inverse().unwrap(),
        p.y.frobenius_map(1) * xi.pow(half).inverse().unwrap(),
    )
}
fn execute(step: G2Step, r: &mut [G2Affine; 6]) {
    match step {
        G2Step::Copy {
            destination,
            source,
        } => r[destination] = r[source],
        G2Step::Double {
            destination,
            source,
        } => r[destination] = (r[source] + r[source]).into_affine(),
        G2Step::Add {
            destination,
            left,
            right,
        } => r[destination] = (r[left] + r[right]).into_affine(),
        G2Step::Negate {
            destination,
            source,
        } => r[destination] = -r[source],
        G2Step::Psi {
            destination,
            source,
        } => r[destination] = psi(r[source]),
        G2Step::Psi2 {
            destination,
            source,
        } => r[destination] = psi(psi(r[source])),
    }
}
fn nonmember() -> G2Affine {
    for i in 0..100 {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::ONE), false)
            && !p.is_in_correct_subgroup_assuming_on_curve()
        {
            return p;
        }
    }
    panic!("fixed nonmember fixture");
}
#[test]
fn full_native_cofactor_and_subgroup_schedules_match_ark() {
    for point in [G2Affine::generator(), G2Affine::identity(), nonmember()] {
        let mut r = [G2Affine::identity(); 6];
        r[0] = point;
        for step in G2_COFACTOR_STEPS {
            execute(step, &mut r);
        }
        assert_eq!(r[4], point.clear_cofactor());
        assert!(r[4].is_in_correct_subgroup_assuming_on_curve());
        let mut r = [G2Affine::identity(); 6];
        r[0] = point;
        for step in G2_SUBGROUP_STEPS {
            execute(step, &mut r);
        }
        assert_eq!(
            r[1] == r[2],
            point.is_in_correct_subgroup_assuming_on_curve()
        );
    }
}
#[derive(Clone)]
struct StepCircuit<F: PastaField> {
    before: [G2AffineWitness; 6],
    after: [G2AffineWitness; 6],
    index: usize,
    subgroup: bool,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> StepCircuit<F> {
    fn new(index: usize, subgroup: bool, point: G2Affine) -> Self {
        let mut r = [G2Affine::identity(); 6];
        r[0] = point;
        let program = if subgroup {
            G2_SUBGROUP_STEPS.as_slice()
        } else {
            G2_COFACTOR_STEPS.as_slice()
        };
        for step in &program[..index] {
            execute(*step, &mut r);
        }
        let before = r.map(witness);
        execute(program[index], &mut r);
        Self {
            before,
            after: r.map(witness),
            index,
            subgroup,
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
                    .flatten()
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
        let instance = meta.instance_column(150);
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
            || "G2 fixed continuation",
            |mut region| {
                let mut r = Vec::with_capacity(6);
                for value in self.before {
                    r.push(chip.assign_g2(&mut region, self.value(value))?);
                }
                let r: [G2Value<F>; 6] = r.try_into().map_err(|_| Error::Synthesis)?;
                let after = if self.subgroup {
                    chip.g2_subgroup_step(&mut region, &r, self.index)?
                } else {
                    chip.g2_cofactor_step(&mut region, &r, self.index)?
                };
                Ok(after
                    .iter()
                    .flat_map(|p| {
                        p.x()
                            .coefficients()
                            .iter()
                            .chain(p.y().coefficients())
                            .flat_map(|x| x.limbs().iter().cloned())
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
    for index in [0, 1, 2, 69, 70, 71, 72, 73, 150] {
        let c = StepCircuit::<F>::new(index, false, G2Affine::generator());
        let public = c.public();
        assert!(
            check_circuit(&c, 17, core::slice::from_ref(&public), CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "cofactor step {index}"
        );
        let mut forged = public;
        forged[100] += F::ONE;
        assert!(
            !check_circuit(&c, 17, &[forged], CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
    for (point, accepted) in [
        (G2Affine::generator(), true),
        (G2Affine::identity(), true),
        (nonmember(), false),
    ] {
        let c = StepCircuit::<F>::new(70, true, point);
        assert_eq!(
            check_circuit(&c, 17, &[c.public()], CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            accepted
        );
    }
}
#[test]
fn fixed_group_continuations_and_terminal_subgroup_over_fp() {
    run::<PastaFp>();
}
#[test]
fn fixed_group_continuations_and_terminal_subgroup_over_fq() {
    run::<PastaFq>();
}
