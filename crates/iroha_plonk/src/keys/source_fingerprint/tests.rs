//! Lookup equality, exact public source changes and mandatory strict admission.

use iroha_pasta::{CancellationToken, Ep, Eq, PastaCurve, PastaField, msm::MemoryBudget};

use crate::{
    cs::{Advice, Column, ConstraintSystem, Fixed, Rotation, Selector},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{
        CosetCachePolicy, KeyError, KeygenConfigV2, ProvingKey, keygen_pk_v2,
        pk::artifact::{self, ReadConfig},
        source_fingerprint_v2,
    },
    pcs::ipa::PinnedParams,
};

#[derive(Clone)]
struct Source<F: PastaField> {
    value: Value<F>,
    fixed: F,
    copy: bool,
    enabled: bool,
}

impl<F: PastaField> Default for Source<F> {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            fixed: F::from(7),
            copy: true,
            enabled: true,
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
        meta.create_gate("public source", |cells| {
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
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "source",
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
                Ok(())
            },
        )
    }
}

fn read_config(bytes: &[u8], k: u32) -> ReadConfig {
    ReadConfig {
        maximum_bytes: bytes.len(),
        maximum_rows: 1 << k,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}

fn equality<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let source = Source::default();
    for compress in [false, true] {
        let mut config = KeygenConfigV2::pipa_r(vec![]);
        config.compress_selectors = compress;
        let key = keygen_pk_v2(&params, &source, &config).unwrap();
        let original = key.artifact_bytes_v2().unwrap();
        let expected = source_fingerprint_v2(&params, &source, &config, None).unwrap();
        assert_eq!(expected.binding(), key.binding());
        assert_ne!(expected.digest(), &[0; 32]);
        let read = read_config(&original, 6);
        let actual =
            artifact::source_fingerprint_v2::<C>(&original, key.binding(), read, None).unwrap();
        assert_eq!(actual, expected);
        let imported =
            ProvingKey::<C>::from_artifact_v2(&original, key.binding(), &params, &source, read)
                .unwrap();
        assert_eq!(imported.artifact_bytes_v2().unwrap(), original);
        let mut known = source.clone();
        known.value = Value::known(C::ScalarExt::from(99));
        assert_eq!(
            source_fingerprint_v2(&params, &known, &config, None).unwrap(),
            expected
        );
        config.coset_cache = CosetCachePolicy::OnDemand;
        config.table_budget = Some(MemoryBudget::new(0));
        config.msm_budget = MemoryBudget::new(0);
        assert_eq!(
            source_fingerprint_v2(&params, &source, &config, None).unwrap(),
            expected
        );
    }
}

#[test]
fn source_and_original_fingerprints_match_both_curves_and_selector_modes() {
    equality::<Ep>();
    equality::<Eq>();
}

fn changes<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let config = KeygenConfigV2::pipa_r(vec![]);
    let source = Source::default();
    let expected = source_fingerprint_v2(&params, &source, &config, None).unwrap();
    for changed in [
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
    ] {
        assert_ne!(
            source_fingerprint_v2(&params, &changed, &config, None).unwrap(),
            expected
        );
    }
    let larger = PinnedParams::<C>::derive(7).unwrap();
    assert_ne!(
        source_fingerprint_v2(&larger, &source, &config, None).unwrap(),
        expected
    );
    let mut changed = config;
    changed.transcript = crate::cs::TranscriptV2::Blake2bChallenge255;
    assert_ne!(
        source_fingerprint_v2(&params, &source, &changed, None).unwrap(),
        expected
    );
}

#[test]
fn exact_public_tables_copy_selector_profile_and_domain_change_identity() {
    changes::<Ep>();
    changes::<Eq>();
    let ep = source_fingerprint_v2(
        &PinnedParams::<Ep>::derive(6).unwrap(),
        &Source::default(),
        &KeygenConfigV2::pipa_r(vec![]),
        None,
    )
    .unwrap();
    let eq = source_fingerprint_v2(
        &PinnedParams::<Eq>::derive(6).unwrap(),
        &Source::default(),
        &KeygenConfigV2::pipa_r(vec![]),
        None,
    )
    .unwrap();
    assert_ne!(ep.digest(), eq.digest());
}

fn untrusted<C: PastaCurve>() {
    let params = PinnedParams::<C>::derive(6).unwrap();
    let config = KeygenConfigV2::pipa_r(vec![]);
    let source = Source::default();
    let key = keygen_pk_v2(&params, &source, &config).unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let read = read_config(&original, 6);
    let expected =
        artifact::source_fingerprint_v2::<C>(&original, key.binding(), read, None).unwrap();
    // Replace one commitment by a different canonical nonidentity point, retaining every
    // source table. Lookup equality must never authenticate this well-formed false key.
    let mut false_key = original.clone();
    let vk_point = 44 + 10;
    let replacement = key.vk().to_bytes()[42..74].to_vec();
    assert_ne!(&false_key[vk_point..vk_point + 32], replacement.as_slice());
    false_key[vk_point..vk_point + 32].copy_from_slice(&replacement);
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(&false_key, key.binding(), read, None).unwrap(),
        expected
    );
    assert_eq!(
        ProvingKey::<C>::from_artifact_v2(&false_key, key.binding(), &params, &source, read).err(),
        Some(artifact::Error::Commitment)
    );
    let other_source = Source {
        copy: false,
        ..source.clone()
    };
    assert!(
        ProvingKey::<C>::from_artifact_v2(&original, key.binding(), &params, &other_source, read)
            .is_err()
    );
    let tables = 44 + key.vk().to_bytes().len() + 32;
    for index in [
        tables - 32,
        tables,
        tables + 64 * 32 * key.fixed_values().len(),
    ] {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert_ne!(
            artifact::source_fingerprint_v2::<C>(&changed, key.binding(), read, None).unwrap(),
            expected
        );
    }
    let mut malformed = original.clone();
    malformed[tables..tables + 32].fill(0xff);
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(&malformed, key.binding(), read, None).err(),
        Some(artifact::Error::Encoding)
    );
    let mut changed = original.clone();
    changed[vk_point..vk_point + 32].fill(0);
    assert!(artifact::source_fingerprint_v2::<C>(&changed, key.binding(), read, None).is_err());
    for index in [0, 8, 40] {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert!(artifact::source_fingerprint_v2::<C>(&changed, key.binding(), read, None).is_err());
    }
    for bytes in [
        &original[..0],
        &original[..43],
        &original[..original.len() - 1],
    ] {
        assert_eq!(
            artifact::source_fingerprint_v2::<C>(bytes, key.binding(), read, None).err(),
            Some(artifact::Error::Length)
        );
    }
    let mut capped = read;
    capped.maximum_rows -= 1;
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(&original, key.binding(), capped, None).err(),
        Some(artifact::Error::Length)
    );
    capped = read;
    capped.maximum_bytes -= 1;
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(&original, key.binding(), capped, None).err(),
        Some(artifact::Error::Length)
    );
    let token = CancellationToken::new();
    token.cancel();
    assert_eq!(
        artifact::source_fingerprint_v2::<C>(&original, key.binding(), read, Some(&token)).err(),
        Some(artifact::Error::Cancelled)
    );
    assert_eq!(
        source_fingerprint_v2(&params, &source, &config, Some(&token)).err(),
        Some(KeyError::Cancelled)
    );
    assert_eq!(
        source_fingerprint_v2(&params, &source, &config, None).unwrap(),
        expected
    );
}

#[test]
fn lookup_data_never_bypasses_strict_import_or_admits_malformed_originals() {
    untrusted::<Ep>();
    untrusted::<Eq>();
}

#[test]
fn original_lookup_rejects_foreign_curve_and_retired_descriptor_shape() {
    let params = PinnedParams::<Ep>::derive(6).unwrap();
    let source = Source::default();
    let key = keygen_pk_v2(&params, &source, &KeygenConfigV2::pipa_r(vec![])).unwrap();
    let original = key.artifact_bytes_v2().unwrap();
    let config = read_config(&original, 6);
    assert!(artifact::source_fingerprint_v2::<Eq>(&original, key.binding(), config, None).is_err());
    let v1 = crate::keys::keygen_pk(
        &params,
        &source,
        &crate::keys::KeygenConfig::new(crate::cs::TranscriptV1::Blake2bChallenge255),
    )
    .unwrap();
    assert_eq!(
        artifact::source_fingerprint_v2::<Ep>(&original, v1.binding(), config, None).err(),
        Some(artifact::Error::Profile)
    );
    let mut extended = original;
    extended.push(0);
    assert_eq!(
        artifact::source_fingerprint_v2::<Ep>(&extended, key.binding(), config, None).err(),
        Some(artifact::Error::Length)
    );
}
