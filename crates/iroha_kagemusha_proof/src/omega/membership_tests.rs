//! Exact hard key membership, metadata bounds and every-cell regressions.

use super::*;
use iroha_plonk::{
    check::{CheckMode, check},
    frontend::synthesize,
};
use iroha_plonk_gadgets::{GlueConfig, tamper::undetected_tampers};

#[derive(Clone)]
struct Membership {
    digests: Vec<Fq>,
    actual: Value<Fq>,
}

impl Circuit<Fq> for Membership {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            actual: Value::unknown(),
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (glue, public)
    }

    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::new(config);
        let actual = layouter.assign_region(
            || "computed key digest membership",
            |mut region| {
                let actual = glue.witness(&mut region, self.actual)?;
                constrain_allowed_key(&mut glue, &mut region, &actual, &self.digests)?;
                Ok(actual)
            },
        )?;
        layouter.constrain_instance(actual.cell(), public, 0)
    }
}

#[test]
fn every_allowed_index_and_foreign_digest_match_exact_membership() {
    let digests: Vec<_> = (0..32).map(Fq::from).collect();
    for actual in digests.iter().copied().chain([Fq::from(32), -Fq::ONE]) {
        let circuit = Membership {
            digests: digests.clone(),
            actual: Value::known(actual),
        };
        let public = [vec![actual]];
        let assigned = synthesize(&circuit, 9, Some(&public)).unwrap();
        let report = check(&assigned.cs, &assigned.tables, CheckMode::Strict).unwrap();
        assert_eq!(report.is_satisfied(), digests.contains(&actual));
    }
}

#[test]
fn metadata_rejects_empty_duplicate_and_oversized_catalogs() {
    for digests in [
        vec![],
        vec![Fq::ONE, Fq::ONE],
        (0..33).map(Fq::from).collect(),
    ] {
        assert!(!valid_allowlist(&digests));
        let circuit = Membership {
            digests,
            actual: Value::known(Fq::ONE),
        };
        assert!(synthesize(&circuit, 9, Some(&[vec![Fq::ONE]])).is_err());
    }
    assert!(valid_allowlist(&[Fq::ZERO]));
    assert!(valid_allowlist(&(0..32).map(Fq::from).collect::<Vec<_>>()));
}

#[test]
fn product_cells_and_computed_digest_are_bound_with_fixed_unknown_shape() {
    for (digests, actual) in [
        (vec![Fq::ZERO], Fq::ZERO),
        ((0..32).map(Fq::from).collect(), Fq::ZERO),
        ((0..32).map(Fq::from).collect(), Fq::from(31)),
    ] {
        let circuit = Membership {
            digests,
            actual: Value::known(actual),
        };
        let public = [vec![actual]];
        let assigned = synthesize(&circuit, 9, Some(&public)).unwrap();
        let unknown = synthesize(&circuit.without_witnesses(), 9, None).unwrap();
        assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
        assert_eq!(assigned.tables.selectors(), unknown.tables.selectors());
        assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            assigned.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        assert!(undetected_tampers(&circuit, 9, &public).unwrap().is_empty());
        let wrong_public = [vec![actual + Fq::ONE]];
        let wrong = synthesize(&circuit, 9, Some(&wrong_public)).unwrap();
        assert!(
            !check(&wrong.cs, &wrong.tables, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
    }
}
