//! Exact-source reconstruction, strict-admission preservation and deterministic parity.

use super::*;
use crate::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned,
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
    frontend::{Error as FrontendError, Layouter, SimpleFloorPlanner, Value},
    keys::pk::artifact::{self, ReadConfig},
    pcs::ipa::commit::test_observation::CommitmentProbe,
    verify_full,
};
use ff::Field;
use iroha_pasta::{Ep, Eq};

#[derive(Clone)]
struct Source<F: PastaField> {
    value: Value<F>,
    fixed: F,
    copy: bool,
    enabled: bool,
    cancel_after_assignment: Option<CancellationToken>,
}
impl<F: PastaField> Default for Source<F> {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            fixed: F::from(7),
            copy: true,
            enabled: true,
            cancel_after_assignment: None,
        }
    }
}
impl<F: PastaField> Circuit<F> for Source<F> {
    type Config = (Column<Advice>, Column<Advice>, Column<Fixed>, Selector);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.create_gate("source-bound rebuild", |cells| {
            vec![
                cells.query_selector(selector)
                    * (cells.query_advice(a, Rotation::cur())
                        * cells.query_fixed(fixed, Rotation::cur())
                        - cells.query_advice(b, Rotation::cur())),
            ]
        });
        (a, b, fixed, selector)
    }
    fn synthesize(
        &self,
        (a, b, fixed, selector): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), FrontendError> {
        layouter.assign_region(
            || "exact source",
            |mut region| {
                let a = region.assign_advice(a, 0, self.value)?.cell();
                let b = region.assign_advice(b, 0, self.value)?.cell();
                region.assign_fixed(fixed, 0, self.fixed)?;
                if self.enabled {
                    selector.enable(&mut region, 0)?;
                }
                if self.copy {
                    region.constrain_equal(a, b)?;
                }
                if let Some(token) = &self.cancel_after_assignment {
                    token.cancel();
                }
                Ok(())
            },
        )
    }
}

fn config(compress: bool) -> KeygenConfigV2 {
    let mut config = KeygenConfigV2::pipa_r(vec![]);
    config.compress_selectors = compress;
    config.coset_cache = CosetCachePolicy::OnDemand;
    config
}
fn read_config(original: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: original.len(),
        maximum_rows: 1 << 6,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
fn assert_same_key<C: PastaCurve>(expected: &ProvingKey<C>, actual: &ProvingKey<C>) {
    assert_eq!(actual.binding(), expected.binding());
    assert_eq!(actual.vk(), expected.vk());
    assert_eq!(
        actual.artifact_bytes_v2().unwrap(),
        expected.artifact_bytes_v2().unwrap()
    );
    assert_eq!(actual.copy_digest(), expected.copy_digest());
    assert_eq!(actual.constraint_system(), expected.constraint_system());
    assert_eq!(actual.selector_values(), expected.selector_values());
    assert_eq!(actual.quotient_domain(), expected.quotient_domain());
    assert_eq!(actual.fixed_values(), expected.fixed_values());
    assert_eq!(actual.permutation_values(), expected.permutation_values());
    assert_eq!(actual.fixed_polys(), expected.fixed_polys());
    assert_eq!(actual.permutation_polys(), expected.permutation_polys());
    assert_eq!(actual.mask_polys(), expected.mask_polys());
    assert_eq!(actual.mask_values(), expected.mask_values());
}

fn parity<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::default();
    for compress in [false, true] {
        let probe = CommitmentProbe::start();
        let original = keygen_pk_v2(&params, &source, &config(compress)).unwrap();
        let expected_commits = original.fixed_values().len() + original.permutation_values().len();
        assert_eq!(probe.calls(), expected_commits);
        let verifier = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
        assert_eq!(probe.calls(), expected_commits);
        assert_eq!(verifier.binding(), original.binding());
        assert_eq!(verifier.verifying_key(), original.vk());
        for policy in [CosetCachePolicy::OnDemand, CosetCachePolicy::Eager] {
            let rebuilt = keygen_pk_from_vk_v2(&params, &source, &verifier.view(), policy).unwrap();
            assert_eq!(
                probe.calls(),
                expected_commits,
                "rebuild must perform no commitments"
            );
            assert_same_key(&original, &rebuilt);
            assert_eq!(rebuilt.has_coset_cache(), policy == CosetCachePolicy::Eager);
            assert_eq!(rebuilt.commitment_tables().present(), (false, false));
        }
    }
}

#[test]
fn keygen_pk_from_vk_matches_keygen_pk() {
    parity::<Ep>();
    parity::<Eq>();
}

fn proof_parity<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source {
        value: Value::known(C::ScalarExt::ZERO),
        ..Source::default()
    };
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let verifier = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let rebuilt = keygen_pk_from_vk_v2(
        &params,
        &source,
        &verifier.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    let prove = |key: &ProvingKey<C>| {
        let witness = Witness::from_circuit(key, &source, &[]).unwrap();
        let bytes = create_proof_owned(
            &params,
            key,
            witness,
            ProverRandomness::fixed_seed_for_tests([29; 32]),
            ProverConfig::default(),
        )
        .unwrap();
        verify_full(
            &params,
            original.binding(),
            original.vk(),
            &[],
            &bytes,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        bytes
    };
    assert_eq!(prove(&original), prove(&rebuilt));
}

#[test]
fn rebuilt_keys_produce_identical_fully_verified_proof_bytes_on_both_curves() {
    proof_parity::<Ep>();
    proof_parity::<Eq>();
}

fn imported<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::default();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let bytes = original.artifact_bytes_v2().unwrap();
    let probe = CommitmentProbe::start();
    let imported = ProvingKey::from_artifact_v2(
        &bytes,
        original.binding(),
        &params,
        &source,
        read_config(&bytes),
    )
    .unwrap();
    assert_eq!(
        probe.calls(),
        original.fixed_values().len() + original.permutation_values().len()
    );
    let before = probe.calls();
    let verifier = SourceBoundVerifyingKeyV2::from_proving_key(&imported, None).unwrap();
    drop(imported);
    let rebuilt = keygen_pk_from_vk_v2(
        &params,
        &source,
        &verifier.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    assert_eq!(probe.calls(), before);
    assert_same_key(&original, &rebuilt);
    drop(probe);

    // A canonical foreign commitment retains source lookup identity but cannot mint
    // a capability: strict original import must still reject it first.
    let mut false_key = bytes.clone();
    let replacement = original.vk().to_bytes()[42..74].to_vec();
    assert_ne!(&false_key[54..86], replacement.as_slice());
    false_key[54..86].copy_from_slice(&replacement);
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(
            &false_key,
            original.binding(),
            read_config(&bytes),
            None
        )
        .unwrap(),
        artifact::source_fingerprint_v2::<C>(&bytes, original.binding(), read_config(&bytes), None)
            .unwrap(),
    );
    assert_eq!(
        ProvingKey::from_artifact_v2(
            &false_key,
            original.binding(),
            &params,
            &source,
            read_config(&bytes),
        )
        .err(),
        Some(artifact::Error::Commitment)
    );
}

#[test]
fn strict_import_remains_mandatory_before_imported_capability_minting() {
    imported::<Ep>();
    imported::<Eq>();
}

#[test]
fn non_v2_key_cannot_mint_rebuild_authority() {
    let params = PinnedParams::<Ep>::derive(6).unwrap();
    let source = Source::default();
    let original = keygen_pk(
        &params,
        &source,
        &KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
    )
    .unwrap();
    assert!(!original.binding().is_v2());
    let probe = CommitmentProbe::start();
    assert!(matches!(
        SourceBoundVerifyingKeyV2::from_proving_key(&original, None),
        Err(RebuildError::Profile)
    ));
    assert_eq!(probe.calls(), 0);
}

fn mutations<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::default();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let verifier = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let changed = [
        Source {
            fixed: C::ScalarExt::from(8),
            ..source.clone()
        },
        Source {
            copy: false,
            ..source.clone()
        },
        Source {
            enabled: false,
            ..source.clone()
        },
    ];
    for source in changed {
        let fingerprint = source_fingerprint_v2(&params, &source, &config(false), None).unwrap();
        assert_eq!(
            fingerprint.binding(),
            original.binding(),
            "isolate same-descriptor source mutation"
        );
        let probe = CommitmentProbe::start();
        assert_eq!(
            keygen_pk_from_vk_v2(
                &params,
                &source,
                &verifier.view(),
                CosetCachePolicy::OnDemand
            )
            .err(),
            Some(RebuildError::Source)
        );
        assert_eq!(probe.calls(), 0);
        // Per-witness exact fixed/copy/selector checks remain independently present.
        let known = Source {
            value: Value::known(C::ScalarExt::ZERO),
            ..source
        };
        assert!(matches!(
            Witness::from_circuit(&original, &known, &[]),
            Err(crate::ProverError::CircuitMismatch)
        ));
    }
    let larger = PinnedParams::<C>::derive(7).unwrap();
    assert_eq!(
        keygen_pk_from_vk_v2(
            &larger,
            &source,
            &verifier.view(),
            CosetCachePolicy::OnDemand
        )
        .err(),
        Some(RebuildError::Profile)
    );

    // Test-only private-field mutation checks the explicit exact-VK guard. Such a
    // capability cannot be constructed through the shipping public API.
    let foreign = keygen_pk_v2(
        &params,
        &Source {
            fixed: C::ScalarExt::from(8),
            ..source.clone()
        },
        &config(false),
    )
    .unwrap();
    assert_eq!(foreign.binding(), original.binding());
    let mut corrupt = verifier.clone();
    corrupt.key = foreign.vk().clone();
    assert_eq!(
        keygen_pk_from_vk_v2(
            &params,
            &source,
            &corrupt.view(),
            CosetCachePolicy::OnDemand
        )
        .err(),
        Some(RebuildError::Profile)
    );
}

#[test]
fn same_descriptor_fixed_copy_selector_and_parameter_changes_refuse() {
    mutations::<Ep>();
    mutations::<Eq>();
}

#[test]
fn cancellation_never_returns_partial_capability_or_key_and_retry_matches() {
    let params = PinnedParams::<Ep>::derive(6).unwrap();
    let source = Source::default();
    let original = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let verifier = SourceBoundVerifyingKeyV2::from_proving_key(&original, None).unwrap();
    let token = CancellationToken::new();
    token.cancel();
    assert!(
        SourceBoundVerifyingKeyV2::from_proving_key(&original, Some(&token))
            .unwrap_err()
            .is_cancelled()
    );
    assert!(
        keygen_pk_from_vk_v2_cancellable(
            &params,
            &source,
            &verifier.view(),
            CosetCachePolicy::OnDemand,
            Some(&token)
        )
        .unwrap_err()
        .is_cancelled()
    );
    let during = CancellationToken::new();
    let interrupted = Source {
        cancel_after_assignment: Some(during.clone()),
        ..source.clone()
    };
    let probe = CommitmentProbe::start();
    assert!(
        keygen_pk_from_vk_v2_cancellable(
            &params,
            &interrupted,
            &verifier.view(),
            CosetCachePolicy::OnDemand,
            Some(&during)
        )
        .unwrap_err()
        .is_cancelled()
    );
    assert_eq!(probe.calls(), 0);
    let fresh = CancellationToken::new();
    let rebuilt = keygen_pk_from_vk_v2_cancellable(
        &params,
        &source,
        &verifier.view(),
        CosetCachePolicy::OnDemand,
        Some(&fresh),
    )
    .unwrap();
    assert_eq!(probe.calls(), 0);
    assert_same_key(&original, &rebuilt);
}

#[test]
fn commitment_probe_rejects_nesting_and_releases_on_unwind() {
    let unwind = std::panic::catch_unwind(|| {
        let _probe = CommitmentProbe::start();
        let _nested = CommitmentProbe::start();
    });
    assert!(unwind.is_err());
    let next = CommitmentProbe::start();
    assert_eq!(next.calls(), 0);
}

fn seal_borrow<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::default();
    let key = keygen_pk_v2(&params, &source, &config(false)).unwrap();
    let metadata = SourceBoundVerifyingKeyV2::from_proving_key(&key, None).unwrap();
    let (binding, verifier, seal) = metadata.into_parts();
    drop(key);
    assert_eq!(core::mem::size_of::<SourceAdmissionSealV2<C>>(), 96);
    let probe = CommitmentProbe::start();
    let view = seal.bind(&binding, &verifier, None).unwrap();
    assert!(core::ptr::eq(view.binding(), &raw const binding));
    assert!(core::ptr::eq(view.verifying_key(), &raw const verifier));
    let copied = view;
    let rebuilt =
        keygen_pk_from_vk_v2(&params, &source, &copied, CosetCachePolicy::OnDemand).unwrap();
    assert_eq!(rebuilt.binding(), &binding);
    assert_eq!(rebuilt.vk(), &verifier);
    assert_eq!(probe.calls(), 0);
    assert_eq!(rebuilt.commitment_tables().present(), (false, false));
    drop(probe);
    let foreign = keygen_pk_v2(
        &params,
        &Source {
            fixed: C::ScalarExt::from(8),
            ..source.clone()
        },
        &config(false),
    )
    .unwrap();
    assert_eq!(foreign.binding(), &binding);
    assert!(matches!(
        seal.bind(&binding, foreign.vk(), None),
        Err(RebuildError::Profile)
    ));
    let v1 = keygen_pk(
        &params,
        &source,
        &KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
    )
    .unwrap();
    assert!(matches!(
        seal.bind(v1.binding(), v1.vk(), None),
        Err(RebuildError::Profile)
    ));
    assert!(matches!(
        SourceAdmissionSealV2::from_proving_key(&v1, None),
        Err(RebuildError::Profile)
    ));
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(
        seal.bind(&binding, &verifier, Some(&cancelled))
            .unwrap_err()
            .is_cancelled()
    );
    assert!(
        SourceAdmissionSealV2::from_proving_key(&foreign, Some(&cancelled))
            .unwrap_err()
            .is_cancelled()
    );
    assert!(seal.bind(&binding, &verifier, None).is_ok());
}

#[test]
fn compact_seal_borrows_exact_metadata_and_rejects_foreign_or_v1_on_both_curves() {
    seal_borrow::<Ep>();
    seal_borrow::<Eq>();
}
