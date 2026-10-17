//! Both-curve verifier metadata rejects foreign stages and outlives proving buffers.

use super::*;
use ff::Field;
use iroha_pasta::{Ep, Eq, PastaField};
use iroha_plonk::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned_with_claim,
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, SourceBoundVerifyingKeyV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
    verifier::verify_full,
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig};

#[derive(Clone)]
struct KeyShape<F: PastaField>(F);
impl<F: PastaField> Circuit<F> for KeyShape<F> {
    type Config = (GlueConfig, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
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
    ) -> Result<(), Error> {
        let word = layouter.assign_region(
            || "distinct fixed source identity",
            |mut region| GlueChip::new(config).constant(&mut region, self.0),
        )?;
        layouter.constrain_instance(word.cell(), public, 0)
    }
}
fn identity<C: PastaCurve>() {
    use super::super::proving;

    let params = PinnedParams::<C>::derive(8).unwrap();
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    config.compress_selectors = false;
    let original = keygen_pk_v2(&params, &KeyShape(C::ScalarExt::ONE), &config).unwrap();
    let foreign = keygen_pk_v2(&params, &KeyShape(C::ScalarExt::from(2)), &config).unwrap();
    assert_eq!(original.binding(), foreign.binding());
    assert_ne!(original.vk().to_bytes(), foreign.vk().to_bytes());
    let artifact = KeyArtifact::new(original.binding().clone(), original.vk().clone()).unwrap();
    assert_eq!(artifact.require_prover(&original), Ok(()));
    assert_eq!(
        artifact.require_prover(&foreign),
        Err(ArtifactError::Identity)
    );
    let metadata = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let foreign_metadata = SourceBoundVerifyingKeyV2::from_proving_key(&foreign, None).unwrap();
    assert_eq!(artifact.require_source_bound(&metadata.view()), Ok(()));
    assert_eq!(
        artifact.require_source_bound(&foreign_metadata.view()),
        Err(ArtifactError::Identity)
    );
    let seal = iroha_plonk::keys::SourceAdmissionSealV2::from_proving_key(&original, None).unwrap();
    let borrowed = seal.bind(artifact.binding(), artifact.key(), None).unwrap();
    assert!(std::ptr::eq(borrowed.binding(), artifact.binding()));
    assert!(std::ptr::eq(borrowed.verifying_key(), artifact.key()));
    assert_eq!(artifact.require_source_bound(&borrowed), Ok(()));
    assert!(seal.bind(foreign.binding(), foreign.vk(), None).is_err());
    let interrupted = iroha_pasta::CancellationToken::new();
    interrupted.cancel();
    assert!(
        seal.bind(artifact.binding(), artifact.key(), Some(&interrupted))
            .unwrap_err()
            .is_cancelled()
    );
    let descriptor = artifact.binding().encoded().to_vec();
    let verifier = artifact.key().to_bytes().to_vec();
    let public = [vec![C::ScalarExt::ONE]];
    let source = KeyShape(C::ScalarExt::ONE);
    let baseline = create_proof_owned_with_claim(
        &params,
        &original,
        Witness::from_circuit(&original, &source, &public).unwrap(),
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .unwrap();
    drop(original);
    let cancelled = iroha_pasta::CancellationToken::new();
    cancelled.cancel();
    let early = crate::proof_entry_probe::Guard::new(None);
    let no_entropy = ProverRandomness::hedged;
    assert!(matches!(
        proving::prove(
            &params,
            &metadata.view(),
            &source,
            &public,
            no_entropy(),
            ProverConfig {
                cancellation: Some(&cancelled),
                ..ProverConfig::default()
            },
        ),
        Err(proving::Error::Cancelled)
    ));
    // Same D but changed fixed source cannot acquire authority from the live witness.
    assert!(matches!(
        proving::prove(
            &params,
            &metadata.view(),
            &KeyShape(C::ScalarExt::from(2)),
            &public,
            no_entropy(),
            ProverConfig::default(),
        ),
        Err(proving::Error::Artifact)
    ));
    assert_eq!(early.entries(), 0);
    drop(early);
    let late_cancel = iroha_pasta::CancellationToken::new();
    let late_entry = crate::proof_entry_probe::Guard::new(Some(late_cancel.clone()));
    let late = ProverRandomness::hedged();
    assert!(matches!(
        proving::prove(
            &params,
            &metadata.view(),
            &source,
            &public,
            late,
            ProverConfig {
                cancellation: Some(&late_cancel),
                ..ProverConfig::default()
            },
        ),
        Err(proving::Error::Cancelled)
    ));
    assert_eq!(late_entry.entries(), 1);
    drop(late_entry);
    let rebuilt = proving::prove(
        &params,
        &metadata.view(),
        &source,
        &public,
        ProverRandomness::hedged(),
        ProverConfig::default(),
    )
    .unwrap();
    assert_ne!(rebuilt.proof, baseline.proof, "fresh proof entropy");
    let retained = baseline.proof.clone();
    let restored = iroha_plonk::verifier::accumulate_generator(
        &params,
        metadata.binding(),
        metadata.verifying_key(),
        &public,
        &retained,
        iroha_pasta::msm::MemoryBudget::DEFAULT,
    )
    .unwrap();
    assert_eq!(restored.g(), baseline.opening.g());
    assert_eq!(restored.challenges(), baseline.opening.challenges());
    assert_eq!(retained, baseline.proof, "original bytes are immutable");
    for output in [&baseline, &rebuilt] {
        verify_full(
            &params,
            metadata.binding(),
            metadata.verifying_key(),
            &public,
            &output.proof,
            iroha_pasta::msm::MemoryBudget::DEFAULT,
        )
        .unwrap();
        output
            .opening
            .decide(&params, iroha_pasta::msm::MemoryBudget::DEFAULT)
            .unwrap();
    }
    assert_eq!(artifact.binding().encoded(), descriptor);
    assert_eq!(artifact.key().to_bytes(), verifier);
    let larger = keygen_pk_v2(
        &PinnedParams::<C>::derive(9).unwrap(),
        &KeyShape(C::ScalarExt::ONE),
        &config,
    )
    .unwrap();
    assert_eq!(
        artifact.require_prover(&larger),
        Err(ArtifactError::Identity)
    );
    let larger_metadata = SourceBoundVerifyingKeyV2::from_proving_key(&larger, None).unwrap();
    assert_eq!(
        artifact.require_source_bound(&larger_metadata.view()),
        Err(ArtifactError::Identity)
    );
    assert!(matches!(
        KeyArtifact::new(larger.binding().clone(), foreign.vk().clone()),
        Err(ArtifactError::Identity)
    ));
}
#[test]
fn pallas_metadata_rejects_foreign_stage_and_releases_proving_buffers() {
    identity::<Ep>();
}
#[test]
fn vesta_metadata_rejects_foreign_stage_and_releases_proving_buffers() {
    identity::<Eq>();
}
