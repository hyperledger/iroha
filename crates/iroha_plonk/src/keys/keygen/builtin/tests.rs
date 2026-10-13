//! Closed registry authority, canonical original rejection and exact proof parity.

use super::*;
use crate::{
    ProverConfig, ProverRandomness, Witness, create_proof_owned,
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
    frontend::{Circuit, Error as LayoutError, Layouter, SimpleFloorPlanner, Value},
    keys::pk::CosetCachePolicy,
    keys::{KeygenConfigV2, ProvingKey, RebuildError, keygen_pk_from_vk_v2, keygen_pk_v2},
    pcs::ipa::commit::test_observation::CommitmentProbe,
    verify_full,
};
use iroha_pasta::{Ep, Eq, PastaField, msm::MemoryBudget};

#[derive(Clone)]
struct Source<F: PastaField> {
    fixed: F,
    value: Value<F>,
}
impl<F: PastaField> Circuit<F> for Source<F> {
    type Config = (Column<Advice>, Column<Fixed>, Selector);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            fixed: self.fixed,
            value: Value::unknown(),
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = meta.advice_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();
        meta.enable_equality(advice);
        meta.create_gate("closed source", |cells| {
            vec![
                cells.query_selector(selector)
                    * (cells.query_advice(advice, Rotation::cur())
                        - cells.query_fixed(fixed, Rotation::cur())),
            ]
        });
        (advice, fixed, selector)
    }
    fn synthesize(
        &self,
        (advice, fixed, selector): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), LayoutError> {
        layouter.assign_region(
            || "closed native source",
            |mut region| {
                region.assign_advice(advice, 0, self.value)?;
                region.assign_fixed(fixed, 0, self.fixed)?;
                selector.enable(&mut region, 0)?;
                Ok(())
            },
        )
    }
}

const PROFILE: &[u8] = b"complete synthetic strict native graph";
const SOURCE_ID: [u8; 32] = [11; 32];
const ROLE: &[u32] = &[3, 4, 2];

fn blob(bytes: &[u8]) -> BuiltinBlob {
    BuiltinBlob {
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

struct Fixture<C: PastaCurve> {
    params: PinnedParams<C>,
    source: Source<C::ScalarExt>,
    generated: ProvingKey<C>,
    original: Vec<u8>,
    config: artifact::ReadConfig,
}
impl<C: PastaCurve> Fixture<C> {
    fn new() -> Self {
        Self::with_compression(false)
    }
    fn with_compression(compress_selectors: bool) -> Self {
        let params = PinnedParams::<C>::derive(6).unwrap();
        let source = Source {
            fixed: C::ScalarExt::from(7),
            value: Value::known(C::ScalarExt::from(7)),
        };
        let mut profile = KeygenConfigV2::pipa_r(vec![]);
        profile.compress_selectors = compress_selectors;
        profile.coset_cache = CosetCachePolicy::OnDemand;
        let generated = keygen_pk_v2(&params, &source, &profile).unwrap();
        let original = generated.artifact_bytes_v2().unwrap();
        let config = artifact::ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 64,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        // The generated test entry is derived only after the actual strict importer
        // verifies source and every commitment; lookup fields alone are not authority.
        let probe = CommitmentProbe::start();
        SourceBoundVerifyingKeyV2::from_artifact_v2(
            &original,
            generated.binding(),
            &params,
            &source,
            config,
        )
        .unwrap();
        assert_eq!(
            probe.calls(),
            generated.fixed_values().len() + generated.permutation_values().len()
        );
        Self {
            params,
            source,
            generated,
            original,
            config,
        }
    }
    fn entry(&self) -> BuiltinMemberEntry {
        let parts = artifact::read_bounded_original_v2::<C>(
            &self.original,
            self.generated.binding(),
            self.config,
            None,
        )
        .unwrap();
        let d = self.generated.binding().descriptor();
        BuiltinMemberEntry {
            role_path: ROLE,
            curve: d.curve,
            k: d.k,
            params_digest: d.params_digest,
            descriptor: blob(self.generated.binding().encoded()),
            verifying_key: blob(self.generated.vk().to_bytes()),
            compact_pk: blob(&self.original),
            descriptor_digest: *self.generated.binding().digest(),
            copy_digest: parts.copy_digest,
            source_digest: parts.source_digest,
        }
    }
    fn admit(
        &self,
        member: &BuiltinSourceMemberV1,
    ) -> Result<SourceBoundVerifyingKeyV2<C>, BuiltinSourceErrorV1> {
        member.admit_originals_cancellable(
            self.generated.binding().encoded(),
            self.generated.vk().to_bytes(),
            &self.original,
            &self.params,
            self.config,
            None,
        )
    }
}

fn entries(members: Vec<BuiltinMemberEntry>) -> &'static [BuiltinProfileEntry] {
    Box::leak(
        vec![BuiltinProfileEntry {
            profile: blob(PROFILE),
            source_identity: SOURCE_ID,
            members: Box::leak(members.into_boxed_slice()),
        }]
        .into_boxed_slice(),
    )
}
fn profile(entries: &'static [BuiltinProfileEntry]) -> BuiltinSourceProfileV1 {
    select_profile(entries, PROFILE, &SOURCE_ID, true, true, None).unwrap()
}

fn parity<C: PastaCurve>() {
    let f = Fixture::<C>::new();
    let member = profile(entries(vec![f.entry()])).member(ROLE).unwrap();
    let probe = CommitmentProbe::start();
    let admitted = f.admit(&member).unwrap();
    assert_eq!(
        probe.calls(),
        0,
        "compiled admission must not perform commitment work"
    );
    assert_eq!(admitted.binding(), f.generated.binding());
    assert_eq!(admitted.verifying_key(), f.generated.vk());
    let rebuilt = keygen_pk_from_vk_v2(
        &f.params,
        &f.source,
        &admitted.view(),
        CosetCachePolicy::OnDemand,
    )
    .unwrap();
    assert_eq!(rebuilt.artifact_bytes_v2().unwrap(), f.original);
    assert_eq!(rebuilt.fixed_values(), f.generated.fixed_values());
    assert_eq!(
        rebuilt.permutation_values(),
        f.generated.permutation_values()
    );
    assert_eq!(probe.calls(), 0);
    drop(probe);
    let prove = |key: &ProvingKey<C>| {
        let witness = Witness::from_circuit(key, &f.source, &[]).unwrap();
        let proof = create_proof_owned(
            &f.params,
            key,
            witness,
            ProverRandomness::fixed_seed_for_tests([67; 32]),
            ProverConfig::default(),
        )
        .unwrap();
        verify_full(
            &f.params,
            f.generated.binding(),
            f.generated.vk(),
            &[],
            &proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        proof
    };
    assert_eq!(prove(&f.generated), prove(&rebuilt));
    let changed = Source {
        fixed: C::ScalarExt::from(8),
        value: Value::unknown(),
    };
    assert_eq!(
        keygen_pk_from_vk_v2(
            &f.params,
            &changed,
            &admitted.view(),
            CosetCachePolicy::OnDemand
        )
        .err(),
        Some(RebuildError::Source)
    );
}

#[test]
fn compiled_member_preserves_original_and_verified_proof_bytes_on_both_curves() {
    parity::<Ep>();
    parity::<Eq>();
}

#[test]
fn profile_and_role_selection_are_closed_fresh_and_unambiguous() {
    let f = Fixture::<Ep>::new();
    let registry = entries(vec![f.entry()]);
    for (actual, identity, complete, supported, expected) in [
        (
            b"foreign graph".as_slice(),
            SOURCE_ID,
            true,
            true,
            BuiltinSourceErrorV1::UnsupportedProfile,
        ),
        (
            PROFILE,
            [12; 32],
            true,
            true,
            BuiltinSourceErrorV1::StaleSource,
        ),
        (
            PROFILE,
            SOURCE_ID,
            false,
            true,
            BuiltinSourceErrorV1::IncompleteSourceClosure,
        ),
        (
            PROFILE,
            SOURCE_ID,
            true,
            false,
            BuiltinSourceErrorV1::UnsupportedTarget,
        ),
    ] {
        assert_eq!(
            select_profile(registry, actual, &identity, complete, supported, None).err(),
            Some(expected)
        );
    }
    assert_eq!(
        select_profile(&[], PROFILE, &SOURCE_ID, true, true, None).err(),
        Some(BuiltinSourceErrorV1::UnsupportedProfile)
    );
    let selected = profile(registry);
    for path in [
        vec![],
        vec![3, 4, 3],
        vec![4, 4, 2],
        vec![3, 4, 2, 0],
        vec![1; 9],
    ] {
        assert_eq!(
            selected.member(&path).err(),
            Some(BuiltinSourceErrorV1::Member)
        );
    }
    assert_eq!(
        profile(entries(vec![f.entry(), f.entry()]))
            .member(ROLE)
            .err(),
        Some(BuiltinSourceErrorV1::Member)
    );
    let duplicate_profiles = Box::leak(
        vec![
            BuiltinProfileEntry {
                profile: blob(PROFILE),
                source_identity: SOURCE_ID,
                members: registry[0].members,
            },
            BuiltinProfileEntry {
                profile: blob(PROFILE),
                source_identity: SOURCE_ID,
                members: registry[0].members,
            },
        ]
        .into_boxed_slice(),
    );
    assert_eq!(
        select_profile(duplicate_profiles, PROFILE, &SOURCE_ID, true, true, None).err(),
        Some(BuiltinSourceErrorV1::UnsupportedProfile)
    );
}

fn mutations<C: PastaCurve>() {
    let f = Fixture::<C>::new();
    let member = profile(entries(vec![f.entry()])).member(ROLE).unwrap();
    let descriptor = f.generated.binding().encoded();
    let vk = f.generated.vk().to_bytes();
    for role in 0..3 {
        let mut originals = [descriptor.to_vec(), vk.to_vec(), f.original.clone()];
        let last = originals[role].len() - 1;
        originals[role][last] ^= 1;
        assert_eq!(
            member
                .admit_originals_cancellable::<C>(
                    &originals[0],
                    &originals[1],
                    &originals[2],
                    &f.params,
                    f.config,
                    None
                )
                .err(),
            Some(BuiltinSourceErrorV1::Original)
        );
        originals[role].pop();
        assert_eq!(
            member
                .admit_originals_cancellable::<C>(
                    &originals[0],
                    &originals[1],
                    &originals[2],
                    &f.params,
                    f.config,
                    None
                )
                .err(),
            Some(BuiltinSourceErrorV1::Original)
        );
    }
    for config in [
        artifact::ReadConfig {
            maximum_bytes: f.original.len() - 1,
            ..f.config
        },
        artifact::ReadConfig {
            maximum_rows: 63,
            ..f.config
        },
    ] {
        assert_eq!(
            member
                .admit_originals_cancellable::<C>(
                    descriptor,
                    vk,
                    &f.original,
                    &f.params,
                    config,
                    None
                )
                .err(),
            Some(BuiltinSourceErrorV1::Artifact(artifact::Error::Length))
        );
    }
    let wrong_params = PinnedParams::<C>::derive(5).unwrap();
    assert_eq!(
        member
            .admit_originals_cancellable::<C>(
                descriptor,
                vk,
                &f.original,
                &wrong_params,
                f.config,
                None
            )
            .err(),
        Some(BuiltinSourceErrorV1::Artifact(artifact::Error::Profile))
    );
    let mut overflow = f.entry();
    overflow.k = u8::MAX;
    assert_eq!(
        f.admit(&profile(entries(vec![overflow])).member(ROLE).unwrap())
            .err(),
        Some(BuiltinSourceErrorV1::Artifact(artifact::Error::Length))
    );
    let mut oversized = f.entry();
    oversized.descriptor.bytes = u64::MAX;
    assert_eq!(
        f.admit(&profile(entries(vec![oversized])).member(ROLE).unwrap())
            .err(),
        Some(BuiltinSourceErrorV1::Original)
    );
    for which in 0..4 {
        let mut entry = f.entry();
        match which {
            0 => entry.copy_digest[0] ^= 1,
            1 => entry.source_digest[0] ^= 1,
            2 => entry.descriptor_digest[0] ^= 1,
            _ => entry.params_digest[0] ^= 1,
        }
        assert!(
            f.admit(&profile(entries(vec![entry])).member(ROLE).unwrap())
                .is_err()
        );
    }
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        member
            .admit_originals_cancellable::<C>(
                descriptor,
                vk,
                &f.original,
                &f.params,
                f.config,
                Some(&cancelled)
            )
            .err(),
        Some(BuiltinSourceErrorV1::Cancelled)
    );
    assert_eq!(
        select_profile(
            entries(vec![f.entry()]),
            PROFILE,
            &SOURCE_ID,
            true,
            true,
            Some(&cancelled)
        )
        .err(),
        Some(BuiltinSourceErrorV1::Cancelled)
    );
}

#[test]
fn exact_original_parameter_limits_and_cancellation_reject_on_both_curves() {
    mutations::<Ep>();
    mutations::<Eq>();
}

#[test]
fn declared_registry_hashes_do_not_bypass_canonical_original_parsing() {
    let f = Fixture::<Ep>::new();
    for mutation in 0..3 {
        let mut bytes = f.original.clone();
        match mutation {
            0 => bytes[0] ^= 1,
            1 => bytes[40] ^= 1,
            _ => bytes[54..86].fill(255), // Noncanonical first compressed commitment.
        }
        let mut entry = f.entry();
        entry.compact_pk = blob(&bytes);
        let member = profile(entries(vec![entry])).member(ROLE).unwrap();
        assert!(matches!(
            member.admit_originals_cancellable::<Ep>(
                f.generated.binding().encoded(),
                f.generated.vk().to_bytes(),
                &bytes,
                &f.params,
                f.config,
                None
            ),
            Err(BuiltinSourceErrorV1::Artifact(_))
        ));
    }
    let foreign = Fixture::<Eq>::new();
    let member = profile(entries(vec![f.entry()])).member(ROLE).unwrap();
    assert_eq!(
        member
            .admit_originals_cancellable::<Eq>(
                f.generated.binding().encoded(),
                f.generated.vk().to_bytes(),
                &f.original,
                &foreign.params,
                f.config,
                None
            )
            .err(),
        Some(BuiltinSourceErrorV1::Artifact(artifact::Error::Profile))
    );
}

#[path = "tests/metadata.rs"]
mod metadata;
