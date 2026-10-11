//! Exact stage-key identity checks retain only verifier metadata after PK release.

use super::*;
use crate::a_relation::native::artifact::ArtifactError;
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error as CircuitError, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_pk_v2},
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig};

#[derive(Clone)]
struct KeyShape(Fp);
impl Circuit<Fp> for KeyShape {
    type Config = (GlueConfig, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, fixed);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (glue, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), CircuitError> {
        let word = layouter.assign_region(
            || "distinct fixed stage identity",
            |mut region| GlueChip::new(config).constant(&mut region, self.0),
        )?;
        layouter.constrain_instance(word.cell(), public, 0)
    }
}

#[test]
fn metadata_rejects_same_descriptor_foreign_key_and_outlives_proving_buffers() {
    let params = PinnedParams::<Eq>::derive(8).unwrap();
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let original = keygen_pk_v2(&params, &KeyShape(Fp::ONE), &config).unwrap();
    let foreign = keygen_pk_v2(&params, &KeyShape(Fp::from(2)), &config).unwrap();
    assert_eq!(original.binding(), foreign.binding());
    assert_ne!(original.vk().to_bytes(), foreign.vk().to_bytes());
    let artifact = KeyArtifact::new(original.binding().clone(), original.vk().clone()).unwrap();
    assert!(artifact.require_prover(&original).is_ok());
    assert_eq!(
        artifact.require_prover(&foreign),
        Err(ArtifactError::Identity)
    );
    let digest = artifact.key().kagemusha_digest(artifact.binding()).unwrap();
    drop(original);
    assert_eq!(
        artifact.key().kagemusha_digest(artifact.binding()).unwrap(),
        digest
    );
    let larger = keygen_pk_v2(
        &PinnedParams::<Eq>::derive(9).unwrap(),
        &KeyShape(Fp::ONE),
        &config,
    )
    .unwrap();
    assert_eq!(
        artifact.require_prover(&larger),
        Err(ArtifactError::Identity)
    );
    assert!(matches!(
        KeyArtifact::new(larger.binding().clone(), foreign.vk().clone()),
        Err(ArtifactError::Identity),
    ));
}
