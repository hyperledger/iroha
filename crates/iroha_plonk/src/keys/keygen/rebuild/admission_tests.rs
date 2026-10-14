//! Compact metadata admission must preserve strict source and commitment authority.

use super::*;
use crate::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
    frontend::{Error as LayoutError, Layouter, SimpleFloorPlanner, Value},
    keys::pk::artifact::{Error as ArtifactError, ReadConfig},
    pcs::ipa::commit::test_observation::CommitmentProbe,
};
use ff::Field;

#[derive(Clone)]
struct FixedSource<F: PastaField> {
    fixed: F,
    copy: bool,
    enabled: bool,
}
impl<F: PastaField> Circuit<F> for FixedSource<F> {
    type Config = (Column<Advice>, Column<Advice>, Column<Fixed>, Selector);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        let copied = meta.advice_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();
        meta.enable_equality(advice);
        meta.enable_equality(copied);
        meta.create_gate("fixed source", |cells| {
            vec![
                cells.query_selector(selector)
                    * (cells.query_advice(advice, Rotation::cur())
                        - cells.query_fixed(fixed, Rotation::cur())),
            ]
        });
        (advice, copied, fixed, selector)
    }

    fn synthesize(
        &self,
        (advice, copied, fixed, selector): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), LayoutError> {
        layouter.assign_region(
            || "source-bound fixed original",
            |mut region| {
                let a = region
                    .assign_advice(advice, 0, Value::<F>::unknown())?
                    .cell();
                let b = region
                    .assign_advice(copied, 0, Value::<F>::unknown())?
                    .cell();
                region.assign_fixed(fixed, 0, self.fixed)?;
                if self.enabled {
                    selector.enable(&mut region, 0)?;
                }
                if self.copy {
                    region.constrain_equal(a, b)?;
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone)]
struct NeverSynthesize;
impl<F: PastaField> Circuit<F> for NeverSynthesize {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        panic!("invalid original reached source construction")
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        panic!("invalid original reached configuration")
    }

    fn synthesize(&self, (): Self::Config, _: impl Layouter<F>) -> Result<(), LayoutError> {
        panic!("invalid original reached synthesis")
    }
}

fn check<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = FixedSource {
        fixed: C::ScalarExt::ONE,
        copy: true,
        enabled: true,
    };
    let mut profile = KeygenConfigV2::pipa_r(Vec::new());
    profile.compress_selectors = false;
    profile.coset_cache = CosetCachePolicy::OnDemand;
    let generated = keygen_pk_v2(&params, &source, &profile).unwrap();
    let original = generated.artifact_bytes_v2().unwrap();
    let config = ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 64,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let admit = |bytes: &[u8], source: &FixedSource<C::ScalarExt>| {
        let metadata = SourceBoundVerifyingKeyV2::<C>::from_artifact_v2_cancellable(
            bytes,
            generated.binding(),
            &params,
            source,
            config,
            None,
        );
        let full = ProvingKey::<C>::from_artifact_v2_cancellable(
            bytes,
            generated.binding(),
            &params,
            source,
            config,
            None,
        );
        assert_eq!(metadata.as_ref().err(), full.as_ref().err());
        metadata
    };
    let admitted = admit(&original, &source).unwrap();
    let noncancellable = SourceBoundVerifyingKeyV2::<C>::from_artifact_v2(
        &original,
        generated.binding(),
        &params,
        &source,
        config,
    )
    .unwrap();
    assert_eq!(noncancellable.binding(), admitted.binding());
    assert_eq!(
        noncancellable.verifying_key().to_bytes(),
        admitted.verifying_key().to_bytes()
    );
    assert_eq!(admitted.binding(), generated.binding());
    assert_eq!(
        admitted.verifying_key().to_bytes(),
        generated.vk().to_bytes()
    );
    let full =
        ProvingKey::from_artifact_v2(&original, generated.binding(), &params, &source, config)
            .unwrap();
    let reconstructed = keygen_pk_from_vk_v2(
        &params,
        &source,
        &admitted.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    assert_eq!(reconstructed.artifact_bytes_v2().unwrap(), original);
    assert_eq!(reconstructed.fixed_values(), full.fixed_values());
    assert_eq!(
        reconstructed.permutation_values(),
        full.permutation_values()
    );
    assert_eq!(reconstructed.fixed_polys(), full.fixed_polys());
    assert_eq!(reconstructed.permutation_polys(), full.permutation_polys());
    assert_eq!(reconstructed.mask_polys(), full.mask_polys());
    assert_eq!(reconstructed.mask_values(), full.mask_values());

    let foreign_source = FixedSource {
        fixed: C::ScalarExt::from(2),
        ..source.clone()
    };
    let foreign = keygen_pk_v2(&params, &foreign_source, &profile).unwrap();
    assert_eq!(foreign.binding(), generated.binding());
    assert_eq!(
        admit(&original, &foreign_source).err(),
        Some(ArtifactError::Source)
    );
    for changed_source in [
        FixedSource {
            copy: false,
            ..source.clone()
        },
        FixedSource {
            enabled: false,
            ..source.clone()
        },
    ] {
        assert_eq!(
            admit(&original, &changed_source).err(),
            Some(ArtifactError::Source)
        );
    }
    let vk_end = 44 + generated.vk().to_bytes().len();
    let mut changed = original.clone();
    changed[vk_end] ^= 1;
    assert_eq!(admit(&changed, &source).err(), Some(ArtifactError::Source));
    changed = original.clone();
    changed[vk_end + 32] ^= 1;
    assert_eq!(admit(&changed, &source).err(), Some(ArtifactError::Source));
    // A canonical, descriptor-compatible foreign VK is still not the committed key.
    changed = original.clone();
    changed[44..vk_end].copy_from_slice(foreign.vk().to_bytes());
    let probe = CommitmentProbe::start();
    assert_eq!(
        admit(&changed, &source).err(),
        Some(ArtifactError::Commitment)
    );
    // Warm cached actual points are still compared to every untrusted VK point.
    assert_eq!(probe.calls(), 0);
    drop(probe);
    // A bad source claim must win over a canonical wrong VK, even after all
    // actual columns are warm. Fusion cannot move commitment checks earlier.
    changed[vk_end + 32] ^= 1;
    let probe = CommitmentProbe::start();
    assert_eq!(admit(&changed, &source).err(), Some(ArtifactError::Source));
    assert_eq!(probe.calls(), 0);
    drop(probe);
    // Rebinding both source claims cannot grant the original VK to a different source.
    changed = original.clone();
    changed[vk_end..].copy_from_slice(&foreign.artifact_bytes_v2().unwrap()[vk_end..]);
    assert_eq!(
        admit(&changed, &foreign_source).err(),
        Some(ArtifactError::Commitment)
    );

    let preflight = |bytes: &[u8], selected: ReadConfig, cancellation| {
        let metadata = SourceBoundVerifyingKeyV2::<C>::from_artifact_v2_cancellable(
            bytes,
            generated.binding(),
            &params,
            &NeverSynthesize,
            selected,
            cancellation,
        )
        .err();
        let full = ProvingKey::<C>::from_artifact_v2_cancellable(
            bytes,
            generated.binding(),
            &params,
            &NeverSynthesize,
            selected,
            cancellation,
        )
        .err();
        assert_eq!(metadata, full);
        metadata
    };
    assert_eq!(
        preflight(&original[..original.len() - 1], config, None),
        Some(ArtifactError::Length)
    );
    let mut capped = config;
    capped.maximum_bytes -= 1;
    assert_eq!(
        preflight(&original, capped, None),
        Some(ArtifactError::Length)
    );
    capped = config;
    capped.maximum_rows -= 1;
    assert_eq!(
        preflight(&original, capped, None),
        Some(ArtifactError::Length)
    );
    changed = original.clone();
    changed[0] ^= 1;
    assert_eq!(
        preflight(&changed, config, None),
        Some(ArtifactError::Encoding)
    );
    changed = original.clone();
    changed[40] ^= 1;
    assert_eq!(
        preflight(&changed, config, None),
        Some(ArtifactError::Length)
    );
    let wrong_params = PinnedParams::<C>::derive(5).unwrap();
    let wrong_metadata = SourceBoundVerifyingKeyV2::<C>::from_artifact_v2_cancellable(
        &original,
        generated.binding(),
        &wrong_params,
        &NeverSynthesize,
        config,
        None,
    )
    .err();
    assert_eq!(
        ProvingKey::<C>::from_artifact_v2_cancellable(
            &original,
            generated.binding(),
            &wrong_params,
            &NeverSynthesize,
            config,
            None,
        )
        .err(),
        wrong_metadata
    );
    assert_eq!(wrong_metadata, Some(ArtifactError::Profile));
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        preflight(&original, config, Some(&cancelled)),
        Some(ArtifactError::Cancelled)
    );
}

#[test]
fn compact_metadata_admission_preserves_source_and_commitment_checks_on_both_curves() {
    check::<iroha_pasta::Ep>();
    check::<iroha_pasta::Eq>();
}
