//! Reused typed metadata never replaces exact originals or closed-member checks.

use super::*;

fn typed<C: PastaCurve>(
    f: &Fixture<C>,
    member: BuiltinSourceMemberV1,
    binding: &DescriptorBinding,
    key: &VerifyingKey<C>,
) -> Result<SourceBoundVerifyingKeyV2<C>, BuiltinSourceErrorV1> {
    member.admit_originals_with_metadata_cancellable(
        f.generated.binding().encoded(),
        f.generated.vk().to_bytes(),
        &f.original,
        binding,
        key,
        &f.params,
        f.config,
        None,
    )
}

fn same_metadata<C: PastaCurve>(
    actual: &SourceBoundVerifyingKeyV2<C>,
    expected: &SourceBoundVerifyingKeyV2<C>,
) {
    assert_eq!(actual.binding(), expected.binding());
    assert_eq!(actual.verifying_key(), expected.verifying_key());
    assert!(
        actual
            .clone()
            .into_parts()
            .2
            .same_source(&expected.clone().into_parts().2)
    );
}

fn parity<C: PastaCurve>(compress: bool) {
    let f = Fixture::<C>::with_compression(compress);
    let member = profile(entries(vec![f.entry()])).member(ROLE).unwrap();
    let original = f.admit(member).unwrap();
    let probe = CommitmentProbe::start();
    let admitted = typed(&f, member, f.generated.binding(), f.generated.vk()).unwrap();
    same_metadata(&admitted, &original);
    assert_eq!(probe.calls(), 0);
    // Independently decoded and cloned values are equivalent; object identity
    // cannot itself be the authority or a requirement for reuse.
    let binding = DescriptorBinding::decode_v2(f.generated.binding().encoded()).unwrap();
    let key = VerifyingKey::<C>::read(f.generated.vk().to_bytes(), &binding).unwrap();
    same_metadata(&typed(&f, member, &binding, &key).unwrap(), &original);
    same_metadata(
        &typed(&f, member, &binding.clone(), &key.clone()).unwrap(),
        &original,
    );
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
    let create_verified_proof = |key: &ProvingKey<C>| {
        let witness = Witness::from_circuit(key, &f.source, &[]).unwrap();
        let bytes = create_proof_owned(
            &f.params,
            key,
            witness,
            ProverRandomness::fixed_seed_for_tests([71; 32]),
            ProverConfig::default(),
        )
        .unwrap();
        verify_full(
            &f.params,
            f.generated.binding(),
            f.generated.vk(),
            &[],
            &bytes,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        bytes
    };
    assert_eq!(
        create_verified_proof(&rebuilt),
        create_verified_proof(&f.generated)
    );
    let changed = Source {
        fixed: C::ScalarExt::from(8),
        value: Value::unknown(),
    };
    assert_eq!(
        keygen_pk_from_vk_v2(
            &f.params,
            &changed,
            &admitted.view(),
            CosetCachePolicy::OnDemand,
        )
        .err(),
        Some(RebuildError::Source)
    );
}

#[test]
fn reused_metadata_preserves_seals_and_verified_proofs_for_both_selector_modes_and_curves() {
    for compress in [false, true] {
        parity::<Ep>(compress);
        parity::<Eq>(compress);
    }
}

fn mutations<C: PastaCurve>(compress: bool) {
    let f = Fixture::<C>::with_compression(compress);
    let member = profile(entries(vec![f.entry()])).member(ROLE).unwrap();
    let originals = [
        f.generated.binding().encoded().to_vec(),
        f.generated.vk().to_bytes().to_vec(),
        f.original.clone(),
    ];
    let compare = |raw: &[Vec<u8>; 3], params: &PinnedParams<C>, config, cancellation| {
        let old = member.admit_originals_cancellable::<C>(
            &raw[0],
            &raw[1],
            &raw[2],
            params,
            config,
            cancellation,
        );
        let new = member.admit_originals_with_metadata_cancellable::<C>(
            &raw[0],
            &raw[1],
            &raw[2],
            f.generated.binding(),
            f.generated.vk(),
            params,
            config,
            cancellation,
        );
        assert!(old.is_err());
        assert_eq!(old.err(), new.err());
    };
    for role in 0..3 {
        for mutation in 0..4 {
            let mut changed = originals.clone();
            match mutation {
                0 => {
                    let last = changed[role].len() - 1;
                    changed[role][last] ^= 1;
                }
                1 => {
                    changed[role].pop();
                }
                2 => changed[role].push(0),
                _ => changed[role].clear(),
            }
            compare(&changed, &f.params, f.config, None);
        }
    }
    for config in [
        artifact::ReadConfig {
            maximum_bytes: 0,
            ..f.config
        },
        artifact::ReadConfig {
            maximum_bytes: f.original.len() - 1,
            ..f.config
        },
        artifact::ReadConfig {
            maximum_rows: 0,
            ..f.config
        },
        artifact::ReadConfig {
            maximum_rows: 63,
            ..f.config
        },
    ] {
        compare(&originals, &f.params, config, None);
    }
    compare(
        &originals,
        &PinnedParams::<C>::derive(5).unwrap(),
        f.config,
        None,
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    compare(&originals, &f.params, f.config, Some(&cancelled));

    let foreign = Fixture::<C>::with_compression(!compress);
    assert!(typed(&f, member, foreign.generated.binding(), f.generated.vk()).is_err());
    assert!(typed(&f, member, f.generated.binding(), foreign.generated.vk()).is_err());
    let changed = Source {
        fixed: C::ScalarExt::from(8),
        value: Value::unknown(),
    };
    let mut config = KeygenConfigV2::pipa_r(vec![]);
    config.compress_selectors = compress;
    config.coset_cache = CosetCachePolicy::OnDemand;
    let foreign_key = keygen_pk_v2(&f.params, &changed, &config).unwrap();
    assert_eq!(foreign_key.binding(), f.generated.binding());
    assert_ne!(foreign_key.vk(), f.generated.vk());
    assert!(typed(&f, member, f.generated.binding(), foreign_key.vk()).is_err());
    let wrong_member = profile(entries(vec![foreign.entry()]))
        .member(ROLE)
        .unwrap();
    assert!(typed(&f, wrong_member, f.generated.binding(), f.generated.vk()).is_err());
}

#[test]
fn reused_metadata_refuses_changed_originals_foreign_typed_values_limits_and_cancellation() {
    for compress in [false, true] {
        mutations::<Ep>(compress);
        mutations::<Eq>(compress);
    }
}

fn malformed<C: PastaCurve>() {
    let f = Fixture::<C>::with_compression(true);
    // Rebind only the private test entry's CPK blob pin. This forces parsing and
    // demonstrates that a declared identity cannot replace canonical framing or
    // equality with a validated key. No runtime registry extension exists.
    for index in [
        0,
        8,
        40,
        44,
        49,
        54,
        f.original.len() - 64,
        f.original.len() - 1,
    ] {
        let mut raw = f.original.clone();
        raw[index] ^= 255;
        let mut entry = f.entry();
        entry.compact_pk = blob(&raw);
        let member = profile(entries(vec![entry])).member(ROLE).unwrap();
        let old = member.admit_originals_cancellable::<C>(
            f.generated.binding().encoded(),
            f.generated.vk().to_bytes(),
            &raw,
            &f.params,
            f.config,
            None,
        );
        let new = member.admit_originals_with_metadata_cancellable::<C>(
            f.generated.binding().encoded(),
            f.generated.vk().to_bytes(),
            &raw,
            f.generated.binding(),
            f.generated.vk(),
            &f.params,
            f.config,
            None,
        );
        assert!(old.is_err(), "raw path accepted mutation {index}");
        assert!(new.is_err(), "typed path accepted mutation {index}");
    }
    // Even when the private test DATA pins both changed encodings, supplied
    // typed values cannot be relabelled as a malformed VK.
    let mut vk = f.generated.vk().to_bytes().to_vec();
    vk[10..42].fill(255);
    let mut raw = f.original.clone();
    raw[44..44 + vk.len()].copy_from_slice(&vk);
    let mut entry = f.entry();
    entry.verifying_key = blob(&vk);
    entry.compact_pk = blob(&raw);
    let member = profile(entries(vec![entry])).member(ROLE).unwrap();
    assert!(
        member
            .admit_originals_cancellable::<C>(
                f.generated.binding().encoded(),
                &vk,
                &raw,
                &f.params,
                f.config,
                None,
            )
            .is_err()
    );
    assert!(
        member
            .admit_originals_with_metadata_cancellable::<C>(
                f.generated.binding().encoded(),
                &vk,
                &raw,
                f.generated.binding(),
                f.generated.vk(),
                &f.params,
                f.config,
                None,
            )
            .is_err()
    );
}

#[test]
fn pinned_test_metadata_does_not_bypass_shared_cpk_framing_or_canonical_vk() {
    malformed::<Ep>();
    malformed::<Eq>();
}

#[test]
fn bounded_byte_equality_covers_chunks_lengths_and_cancellation() {
    let first = vec![7; 8193];
    assert!(equal_bytes(&first, &first, None).unwrap());
    assert!(equal_bytes(&[], &[], None).unwrap());
    assert!(!equal_bytes(&first, &first[..8192], None).unwrap());
    let mut second = first.clone();
    second[4096] ^= 1;
    assert!(!equal_bytes(&first, &second, None).unwrap());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        equal_bytes(&first, &first, Some(&cancelled)).err(),
        Some(BuiltinSourceErrorV1::Cancelled)
    );
    assert_eq!(
        equal_bytes(&[], &[1], Some(&cancelled)).err(),
        Some(BuiltinSourceErrorV1::Cancelled)
    );
}
