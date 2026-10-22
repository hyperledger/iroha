//! Exact-source parity, one-synthesis accounting and failure-path ownership.

use std::{cell::Cell, rc::Rc};

use super::*;
use crate::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Instance, InstanceType, Rotation, Selector},
    frontend::{Error, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfigV2, SourceBoundVerifyingKeyV2, keygen_pk_from_vk_v2, keygen_pk_v2},
    pcs::ipa::commit::test_observation::CommitmentProbe,
    prover::{ProverConfig, ProverRandomness, create_proof_owned},
    verify_full,
};
use iroha_pasta::{Ep, Eq, PastaField, msm::MemoryBudget};

#[derive(Clone)]
struct Source<F: PastaField> {
    value: Value<F>,
    actual: bool,
    mutation: u8,
    syntheses: Rc<Cell<usize>>,
    witnessless: Rc<Cell<usize>>,
    cancel: Option<CancellationToken>,
}
impl<F: PastaField> Source<F> {
    fn new() -> Self {
        Self {
            value: Value::known(F::from(7)),
            actual: true,
            mutation: 0,
            syntheses: Rc::new(Cell::new(0)),
            witnessless: Rc::new(Cell::new(0)),
            cancel: None,
        }
    }
    fn reset_counts(&self) {
        self.syntheses.set(0);
        self.witnessless.set(0);
    }
}
impl<F: PastaField> Circuit<F> for Source<F> {
    type Config = (
        Column<Advice>,
        Column<Advice>,
        Column<Fixed>,
        Column<Instance>,
        Selector,
    );
    type FloorPlanner = SimpleFloorPlanner;
    type Params = bool;

    fn without_witnesses(&self) -> Self {
        self.witnessless.set(self.witnessless.get() + 1);
        Self {
            value: Value::unknown(),
            actual: false,
            ..self.clone()
        }
    }
    fn params(&self) -> bool {
        self.actual && self.mutation == 4
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, false)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, changed: bool) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        if changed {
            let _extra = meta.advice_column();
        }
        let fixed = meta.fixed_column();
        let instance = meta.instance_column(1);
        let selector = meta.selector();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(instance);
        meta.create_gate("sealed actual source", |cells| {
            vec![
                cells.query_selector(selector)
                    * (cells.query_advice(a, Rotation::cur())
                        * cells.query_fixed(fixed, Rotation::cur())
                        - cells.query_advice(b, Rotation::cur())),
            ]
        });
        (a, b, fixed, instance, selector)
    }
    fn synthesize(
        &self,
        (a, b, fixed, instance, selector): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.syntheses.set(self.syntheses.get() + 1);
        let mutation = if self.actual { self.mutation } else { 0 };
        let a = layouter.assign_region(
            || "actual source",
            |mut region| {
                let a = region.assign_advice(a, 0, self.value)?.cell();
                let b = region.assign_advice(b, 0, self.value)?.cell();
                region.assign_fixed(fixed, 0, F::from(if mutation == 1 { 2 } else { 1 }))?;
                if mutation != 2 {
                    region.constrain_equal(a, b)?;
                }
                if mutation != 3 {
                    selector.enable(&mut region, 0)?;
                }
                Ok(a)
            },
        )?;
        layouter.constrain_instance(a, instance, 0)?;
        if let Some(token) = &self.cancel {
            token.cancel();
        }
        Ok(())
    }
}
fn config(compress: bool) -> KeygenConfigV2 {
    let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Bits(8)]);
    config.compress_selectors = compress;
    config.coset_cache = CosetCachePolicy::OnDemand;
    config
}

fn parity<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::<C::ScalarExt>::new();
    let instances = vec![vec![C::ScalarExt::from(7)]];
    for compress in [false, true] {
        let original = keygen_pk_v2(&params, &source, &config(compress)).unwrap();
        let owner = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
        for policy in [CosetCachePolicy::OnDemand, CosetCachePolicy::Eager] {
            let expected_key =
                keygen_pk_from_vk_v2(&params, &source, &owner.view(), policy).unwrap();
            let expected_witness =
                Witness::from_circuit(&expected_key, &source, &instances).unwrap();
            source.reset_counts();
            let probe = CommitmentProbe::start();
            let (actual_key, actual_witness) = rebuild_key_and_witness_v2_cancellable(
                &params,
                &source,
                &owner.view(),
                &instances,
                policy,
                None,
            )
            .unwrap();
            assert_eq!(source.syntheses.get(), 1);
            assert_eq!(source.witnessless.get(), 0);
            assert_eq!(probe.calls(), 0, "preparation does no commitment MSM");
            drop(probe);
            assert_eq!(
                actual_key.artifact_bytes_v2().unwrap(),
                expected_key.artifact_bytes_v2().unwrap()
            );
            assert_eq!(actual_key.copy_digest(), expected_key.copy_digest());
            assert_eq!(actual_key.fixed_polys(), expected_key.fixed_polys());
            assert_eq!(
                actual_key.permutation_polys(),
                expected_key.permutation_polys()
            );
            assert_eq!(actual_key.mask_polys(), expected_key.mask_polys());
            assert_eq!(
                actual_key.has_coset_cache(),
                policy == CosetCachePolicy::Eager
            );
            assert_eq!(actual_key.commitment_tables().present(), (false, false));
            assert_eq!(actual_witness.advice, expected_witness.advice);
            assert_eq!(actual_witness.instances, expected_witness.instances);
            for workers in [1, 4] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .unwrap();
                let prove = |key: &ProvingKey<C>, witness: &Witness<C::ScalarExt>| {
                    let owned = Witness {
                        advice: witness.advice.clone(),
                        instances: witness.instances.clone(),
                    };
                    pool.install(|| {
                        create_proof_owned(
                            &params,
                            key,
                            owned,
                            ProverRandomness::fixed_seed_for_tests([83; 32]),
                            ProverConfig::default(),
                        )
                    })
                    .unwrap()
                };
                let expected = prove(&expected_key, &expected_witness);
                let actual = prove(&actual_key, &actual_witness);
                assert_eq!(actual, expected);
                verify_full(
                    &params,
                    original.binding(),
                    original.vk(),
                    &instances,
                    &actual,
                    MemoryBudget::DEFAULT,
                )
                .unwrap();
            }
        }
    }
}
#[test]
fn one_synthesis_preserves_exact_keys_witnesses_and_verified_bytes_on_both_curves() {
    parity::<Ep>();
    parity::<Eq>();
}

struct WipeProbe;
impl WipeProbe {
    fn new() -> Self {
        WIPED_WITNESS.with(|state| {
            assert!(state.get().is_none());
            state.set(Some((0, true)));
        });
        Self
    }
    fn assert_wiped(&self, expected: usize) {
        assert_eq!(WIPED_WITNESS.with(Cell::get), Some((expected, true)));
    }
}
impl Drop for WipeProbe {
    fn drop(&mut self) {
        WIPED_WITNESS.with(|state| state.set(None));
    }
}

fn actual_source_mutations<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::<C::ScalarExt>::new();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let owner = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let instances = vec![vec![C::ScalarExt::from(7)]];
    for mutation in 1..=4 {
        let changed = Source {
            mutation,
            ..source.clone()
        };
        // The original witnessless source still qualifies. Only the actual
        // witness-bearing fixed/copy/selector/config source has changed.
        assert!(
            keygen_pk_from_vk_v2(&params, &changed, &owner.view(), CosetCachePolicy::OnDemand)
                .is_ok()
        );
        assert!(matches!(
            Witness::from_circuit(&original, &changed, &instances),
            Err(ProverError::CircuitMismatch)
        ));
        let wipe = WipeProbe::new();
        let error = rebuild_key_and_witness_v2_cancellable(
            &params,
            &changed,
            &owner.view(),
            &instances,
            CosetCachePolicy::OnDemand,
            None,
        )
        .unwrap_err();
        assert_eq!(
            error,
            RebuildWitnessError::Rebuild(if mutation == 4 {
                RebuildError::Profile
            } else {
                RebuildError::Source
            })
        );
        wipe.assert_wiped((if mutation == 4 { 3 } else { 2 }) * (1 << 6));
    }
}
#[test]
fn actual_witness_dependent_fixed_copy_selectors_and_configuration_reject_and_wipe() {
    actual_source_mutations::<Ep>();
    actual_source_mutations::<Eq>();
}

fn instance_rejections<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::<C::ScalarExt>::new();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let owner = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let malformed = [
        vec![],
        vec![vec![]],
        vec![vec![C::ScalarExt::from(7); 2]],
        vec![vec![C::ScalarExt::from(256)]],
    ];
    for instances in malformed {
        source.reset_counts();
        let expected = Witness::from_circuit(&original, &source, &instances).unwrap_err();
        let actual = rebuild_key_and_witness_v2_cancellable(
            &params,
            &source,
            &owner.view(),
            &instances,
            CosetCachePolicy::OnDemand,
            None,
        )
        .unwrap_err();
        assert_eq!(actual, RebuildWitnessError::Witness(expected));
        assert_eq!(
            source.syntheses.get(),
            0,
            "typed instances fail before synthesis"
        );
    }
    source.reset_counts();
    let wrong_params = PinnedParams::<C>::derive(7).unwrap();
    assert_eq!(
        rebuild_key_and_witness_v2_cancellable(
            &wrong_params,
            &source,
            &owner.view(),
            &[vec![C::ScalarExt::from(7)]],
            CosetCachePolicy::OnDemand,
            None
        )
        .unwrap_err(),
        RebuildWitnessError::Rebuild(RebuildError::Profile)
    );
    assert_eq!(
        source.syntheses.get(),
        0,
        "parameter preflight precedes synthesis"
    );
}
#[test]
fn exact_instance_shapes_types_and_parameter_preflight_reject_before_synthesis() {
    instance_rejections::<Ep>();
    instance_rejections::<Eq>();
}

fn cancellation<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::<C::ScalarExt>::new();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let owner = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let instances = vec![vec![C::ScalarExt::from(7)]];
    let before = CancellationToken::new();
    before.cancel();
    source.reset_counts();
    let error = rebuild_key_and_witness_v2_cancellable(
        &params,
        &source,
        &owner.view(),
        &instances,
        CosetCachePolicy::OnDemand,
        Some(&before),
    )
    .unwrap_err();
    assert!(error.is_cancelled());
    assert_eq!(source.syntheses.get(), 0);
    let during = CancellationToken::new();
    let interrupted = Source {
        cancel: Some(during.clone()),
        ..source.clone()
    };
    assert!(
        rebuild_key_and_witness_v2_cancellable(
            &params,
            &interrupted,
            &owner.view(),
            &instances,
            CosetCachePolicy::OnDemand,
            Some(&during)
        )
        .unwrap_err()
        .is_cancelled()
    );

    // Cancel at the reconstruction boundary, after advice has left the synthesis
    // owner. No key is returned and the complete moved witness is wiped.
    let mut synthesized = frontend::synthesize(&source, 6, Some(&instances)).unwrap();
    let advice = SecretColumns::new(synthesized.tables.take_advice().unwrap());
    let public = instances.clone();
    let witness = Witness {
        advice: advice.into_vec(),
        instances: public,
    };
    let at_rebuild = CancellationToken::new();
    at_rebuild.cancel();
    let wipe = WipeProbe::new();
    assert!(
        finish_rebuild(
            &params,
            synthesized,
            witness,
            &owner.view(),
            CosetCachePolicy::OnDemand,
            Some(&at_rebuild)
        )
        .unwrap_err()
        .is_cancelled()
    );
    wipe.assert_wiped(2 * (1 << 6));
    drop(wipe);
    let (key, witness) = rebuild_key_and_witness_v2_cancellable(
        &params,
        &source,
        &owner.view(),
        &instances,
        CosetCachePolicy::OnDemand,
        None,
    )
    .unwrap();
    assert_eq!(
        key.artifact_bytes_v2().unwrap(),
        original.artifact_bytes_v2().unwrap()
    );
    assert_eq!(witness.instances, instances);
    assert!(!RebuildWitnessError::Rebuild(RebuildError::Source).is_cancelled());
}
#[test]
fn cancellation_before_during_and_after_synthesis_is_typed_and_wipes_moved_witness() {
    cancellation::<Ep>();
    cancellation::<Eq>();
}
