//! Disjoint Glue/Poseidon coefficient sharing and every-cell binding.

use iroha_pasta::{Fp, Fq, poseidon::PoseidonField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, RowCursor,
    poseidon::{Pow5Columns, RoundConstantColumns, SpongeChip, SpongeConfig},
    tamper::undetected_tampers,
};

#[derive(Clone)]
struct Shared<F: PoseidonField>(Value<F>);
impl<F: PoseidonField> Circuit<F> for Shared<F> {
    type Config = (GlueConfig, SpongeConfig<F>, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self(Value::unknown())
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let shared = core::array::from_fn(|_| meta.fixed_column());
        let glue = GlueConfig::configure_with_shared_coefficients(meta, advice, constants, shared);
        let sponge = SpongeConfig::configure(
            meta,
            Pow5Columns {
                state: [advice[0], advice[1], advice[2]],
                aux: advice[3],
            },
            RoundConstantColumns::from_columns(shared),
            &[],
        );
        let public = meta.instance_column(4);
        meta.enable_equality(public);
        (glue, sponge, public)
    }
    fn synthesize(
        &self,
        (glue, sponge, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let words = layouter.assign_region(
            || "shared coefficient phases",
            |mut region| {
                let mut glue = GlueChip::with_cursor(glue, RowCursor::bounded(148, 256));
                let x = glue.witness(&mut region, self.0)?;
                let one = glue.constant(&mut region, F::ONE)?;
                let sum = glue.add(&mut region, &x, &one)?;
                let product = glue.mul(&mut region, &sum, &x)?;
                let is_zero = glue.is_zero(&mut region, &x)?;
                let chosen = glue.select(&mut region, &is_zero, &one, &product)?;
                let mut sponge = SpongeChip::new(sponge);
                let digest = sponge.hash_words(&mut region, 42, std::slice::from_ref(&chosen))?;
                assert!(sponge.lane().rows_used() < 148);
                Ok(vec![x, sum, chosen, digest])
            },
        )?;
        for (i, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, i)?;
        }
        Ok(())
    }
}
fn run<F: PoseidonField>() {
    for x in [F::ZERO, F::from(7)] {
        let chosen = if bool::from(x.is_zero()) {
            F::ONE
        } else {
            (x + F::ONE) * x
        };
        let public = [vec![
            x,
            x + F::ONE,
            chosen,
            iroha_pasta::poseidon::hash_with_domain(42, &[chosen]),
        ]];
        let circuit = Shared(Value::known(x));
        assert!(
            check_circuit(&circuit, 9, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let known = synthesize(&circuit, 9, Some(&public)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 9, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert!(undetected_tampers(&circuit, 9, &public).unwrap().is_empty());
    }
}
#[test]
fn shared_fixed_coefficients_preserve_native_values_and_every_cell() {
    run::<Fp>();
    run::<Fq>();
}
