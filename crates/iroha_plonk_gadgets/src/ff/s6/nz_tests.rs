//! Retained-certificate nonzero map: both moduli, exact boundaries and mutations.
use super::*;
use crate::{
    GlueConfig,
    range::{LimbBits, RunningSumChip, RunningSumConfig},
    tamper::undetected_tampers,
};
use iroha_pasta::{Fp, Fq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
#[derive(Clone)]
struct Nz<F: PastaField> {
    modulus: ForeignModulus,
    value: Nat,
    known: bool,
    marker: core::marker::PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Nz<F> {
    type Config = (GlueConfig, RunningSumConfig);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, fixed);
        let range = meta.advice_column();
        (
            glue,
            RunningSumConfig::configure_compact(meta, range, LimbBits::new(7).unwrap()),
        )
    }
    fn synthesize(
        &self,
        (glue, range): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(glue);
        let mut range = RunningSumChip::new(range);
        range.load_table(&mut layouter)?;
        layouter.assign_region(
            || "nz",
            |mut reg| {
                let value = if self.known {
                    Value::known(self.value)
                } else {
                    Value::unknown()
                };
                let mut uint = UintChip::new(&mut glue, &mut range);
                let lo = uint.assign::<128>(&mut reg, value.map(|n| n.low_u128()))?;
                let hi = uint.assign::<127>(&mut reg, value.map(|n| n.shr(128).low_u128()))?;
                let canonical =
                    CanonicalS6::from_limbs(&mut uint, &mut reg, self.modulus, &lo, &hi)?;
                let mapped = canonical.nonzero_or_one(&mut uint, &mut reg)?;
                let expected = if self.value == Nat::ZERO {
                    Nat::ONE
                } else {
                    self.value
                };
                uint.glue().enforce_constant(
                    &mut reg,
                    mapped.lo().word(),
                    F::from_u128(expected.low_u128()),
                )?;
                uint.glue().enforce_constant(
                    &mut reg,
                    mapped.hi().word(),
                    F::from_u128(expected.shr(128).low_u128()),
                )?;
                // Fix the source too: returning a valid constant must not hide an omitted source tie.
                uint.glue().enforce_constant(
                    &mut reg,
                    lo.word(),
                    F::from_u128(self.value.low_u128()),
                )?;
                uint.glue().enforce_constant(
                    &mut reg,
                    hi.word(),
                    F::from_u128(self.value.shr(128).low_u128()),
                )?;
                Ok(())
            },
        )
    }
}
#[test]
fn retained_nz_boundaries_and_every_cell_both_fields() {
    fn run<F: PastaField>() {
        for modulus in [ForeignModulus::PASTA_FP, ForeignModulus::PASTA_FQ] {
            for value in [
                Nat::ZERO,
                Nat::ONE,
                Nat::pow2(128).wrapping_sub(&Nat::ONE),
                Nat::pow2(128),
                modulus.nat().wrapping_sub(&Nat::ONE),
            ] {
                let c = Nz::<F> {
                    modulus,
                    value,
                    known: true,
                    marker: core::marker::PhantomData,
                };
                assert!(
                    check_circuit(&c, 10, &[], CheckMode::Strict)
                        .unwrap()
                        .is_satisfied()
                );
                let k = synthesize(&c, 10, Some(&[])).unwrap();
                let u = synthesize(&c.without_witnesses(), 10, None).unwrap();
                assert_eq!(k.tables.fixed(), u.tables.fixed());
                assert_eq!(k.tables.permutation(), u.tables.permutation());
                assert_eq!(k.tables.advice_assigned(), u.tables.advice_assigned());
                assert!(undetected_tampers(&c, 10, &[]).unwrap().is_empty());
            }
        }
    }
    run::<Fp>();
    run::<Fq>();
}
