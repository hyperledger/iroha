//! Tiny real engine originals check the private installed-member and seal boundary.
//! These are not accepted wallet/Omega fixtures and generate no proofs.

use super::*;
use ff::Field;
use iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact;
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error as LayoutError, Layouter, SimpleFloorPlanner},
    keys::{
        CosetCachePolicy, KeygenConfigV2, SourceAdmissionSealV2, keygen_pk_v2,
        pk::artifact::ReadConfig,
    },
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig};

#[derive(Clone)]
struct Shape<F: iroha_pasta::PastaField>(F);
impl<F: iroha_pasta::PastaField> Circuit<F> for Shape<F> {
    type Config = (GlueConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
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
        mut layouter: impl Layouter<F>,
    ) -> Result<(), LayoutError> {
        let value = layouter.assign_region(
            || "fixed member",
            |mut region| GlueChip::new(config).constant(&mut region, self.0),
        )?;
        layouter.constrain_instance(value.cell(), public, 0)
    }
}
fn check<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    config.coset_cache = CosetCachePolicy::OnDemand;
    let source = Shape(C::ScalarExt::ONE);
    let producer = keygen_pk_v2(&params, &source, &config).unwrap();
    let original = producer.artifact_bytes_v2().unwrap();
    let read = ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 64,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
    };
    let imported = iroha_plonk::ProvingKey::from_artifact_v2(
        &original,
        producer.binding(),
        &params,
        &source,
        read,
    )
    .unwrap();
    let seal = SourceAdmissionSealV2::from_proving_key(&imported, None).unwrap();
    let key = KeyArtifact::new(imported.binding().clone(), imported.vk().clone()).unwrap();
    drop(imported);
    let installed = InstalledSourceSealV1::new(7, seal);
    assert!(matches!(installed.seal(8), Err(Error::Inventory)));
    assert!(matches!(
        installed.bind(8, &key, None),
        Err(Error::Inventory)
    ));
    let view = installed.bind(7, &key, None).unwrap();
    assert!(core::ptr::eq(view.binding(), key.binding()));
    assert!(core::ptr::eq(view.verifying_key(), key.key()));
    let foreign = keygen_pk_v2(&params, &Shape(C::ScalarExt::from(2)), &config).unwrap();
    assert_eq!(foreign.binding(), key.binding());
    let foreign_key = KeyArtifact::new(foreign.binding().clone(), foreign.vk().clone()).unwrap();
    assert!(matches!(
        installed.bind(7, &foreign_key, None),
        Err(Error::Inventory)
    ));
    let changed = InstalledSourceSealV1::new(
        7,
        SourceAdmissionSealV2::from_proving_key(&foreign, None).unwrap(),
    );
    assert!(matches!(changed.bind(7, &key, None), Err(Error::Inventory)));
    let token = iroha_pasta::CancellationToken::new();
    token.cancel();
    assert!(matches!(
        installed.bind(7, &key, Some(&token)),
        Err(Error::Cancelled)
    ));
    assert!(installed.bind(7, &key, None).is_ok());
}
#[test]
fn installed_member_seal_rejects_wrong_member_or_source_before_any_io() {
    check::<Ep>();
    check::<Eq>();
}
