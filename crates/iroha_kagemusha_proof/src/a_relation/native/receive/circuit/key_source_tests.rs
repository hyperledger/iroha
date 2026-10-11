//! Incoming merge coverage of witnessed Omega keys under the current Receive owner.

use super::*;
use ff::Field;
use iroha_plonk::pcs::ipa::PinnedParams;

// Tiny genuine VKs test only the installation witness view. They are never
// passed to Receive::Plan (which requires the actual installed k16 profile),
// admitted as wallet keys, or used to assert monetary proof readiness.
#[derive(Clone)]
struct KeySourceFixture(Fq);
impl Circuit<Fq> for KeySourceFixture {
    type Config = Column<iroha_plonk::cs::Fixed>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        meta.advice_column();
        meta.instance_column(1);
        meta.fixed_column()
    }
    fn synthesize(
        &self,
        fixed: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "source-only fixed original",
            |mut region| {
                region.assign_fixed(fixed, 0, self.0)?;
                Ok(())
            },
        )
    }
}

#[test]
fn omega_vk_values_are_unknown_in_key_source_and_descriptor_substitution_fails() {
    let params = PinnedParams::<Ep>::derive(6).unwrap();
    let config = iroha_plonk::keys::KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    let (binding, first) =
        iroha_plonk::keys::keygen_vk_with_binding_v2(&params, &KeySourceFixture(Fq::ONE), &config)
            .unwrap();
    let (second_binding, second) = iroha_plonk::keys::keygen_vk_with_binding_v2(
        &params,
        &KeySourceFixture(Fq::from(2)),
        &config,
    )
    .unwrap();
    assert_eq!(binding, second_binding);
    assert_ne!(first.to_bytes(), second.to_bytes());
    assert_ne!(
        first.kagemusha_digest(&binding).unwrap(),
        second.kagemusha_digest(&binding).unwrap()
    );
    let plan = VerifierPlan::new(binding, params).unwrap();
    let a = omega_key_source(&plan, &first, false).unwrap();
    let b = omega_key_source(&plan, &second, false).unwrap();
    assert!(!a.representation.is_known());
    assert!(!b.representation.is_known());
    assert_eq!(a.fixed, b.fixed);
    assert_eq!(a.permutation, b.permutation);
    assert!(a.fixed.iter().chain(&a.permutation).all(|v| !v.is_known()));
    let actual = omega_key_source(&plan, &first, true).unwrap();
    assert!(actual.representation.is_known());
    assert!(
        actual
            .fixed
            .iter()
            .chain(&actual.permutation)
            .all(Value::is_known)
    );
    assert_eq!(actual.fixed.len(), first.fixed_commitments().len());
    assert_eq!(
        actual.permutation.len(),
        first.permutation_commitments().len()
    );
    let other_params = PinnedParams::<Ep>::derive(7).unwrap();
    let (_, foreign) = iroha_plonk::keys::keygen_vk_with_binding_v2(
        &other_params,
        &KeySourceFixture(Fq::ONE),
        &config,
    )
    .unwrap();
    assert!(matches!(
        omega_key_source(&plan, &foreign, false),
        Err(Error::Synthesis)
    ));
    assert!(matches!(
        omega_key_source(&plan, &foreign, true),
        Err(Error::Synthesis)
    ));
}
