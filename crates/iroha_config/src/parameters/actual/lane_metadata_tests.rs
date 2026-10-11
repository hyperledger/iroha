//! Borrowed catalog validation checks every derived lane field without rebuilding it.

use super::*;
use iroha_data_model::{
    da::confidential_compute::{ConfidentialComputeMechanism, ConfidentialComputePolicy},
    nexus::{LaneSettlementBufferPolicy, LaneVisibility},
};
use std::{
    collections::BTreeSet,
    fmt::Write as _,
    num::{NonZeroU32, NonZeroU64},
};

#[test]
fn streaming_slug_preserves_canonical_names_and_rejects_extra_bytes() {
    for (alias, expected) in [
        ("Primary", "primary"),
        (" __A.B - C__ ", "a_b_c"),
        ("A東京B💡C", "a_b_c"),
        ("__東京💡__", "lane7"),
        ("", "lane7"),
    ] {
        let lane = LaneId::new(7);
        assert_eq!(LaneConfigEntry::slugify(alias, lane), expected);
        assert!(lane_rendering_matches(expected, |out| {
            LaneConfigEntry::write_slug(alias, lane, out)
        }));
        assert!(!lane_rendering_matches(&format!("{expected}x"), |out| {
            LaneConfigEntry::write_slug(alias, lane, out)
        }));
        assert!(!lane_rendering_matches("", |out| {
            LaneConfigEntry::write_slug(alias, lane, out)
        }));
    }
    assert!(lane_rendering_matches("abcdef", |out| {
        out.write_str("abc")?;
        out.write_str("def")
    }));
    assert!(!lane_rendering_matches("abcdef", |out| {
        out.write_str("abc")?;
        out.write_str("deg")
    }));
    assert!(!lane_rendering_matches("abc", |out| out.write_str("abcdef")));
}

#[test]
fn borrowed_metadata_check_rejects_every_representable_field_drift() {
    let key = iroha_crypto::KeyPair::from_seed(vec![74; 32], iroha_crypto::Algorithm::Ed25519);
    let metadata = LaneConfigMetadata {
        id: LaneId::new(7),
        alias: " _Exact Policy_ ".into(),
        storage: LaneStorageProfile::SplitReplica,
        confidential_compute: Some(ConfidentialComputePolicy::new(
            ConfidentialComputeMechanism::Encryption,
            NonZeroU32::MIN,
            BTreeSet::from(["original audience".into()]),
        )),
        scheduler: Some(LaneSchedulerPolicy::new(Some(NonZeroU64::MIN), None)),
        settlement_buffer: Some(LaneSettlementBufferPolicy::new(
            iroha_data_model::account::AccountId::new(key.public_key().clone()),
            iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
                "6TEAJqbb8oEPmLncoNiMRbLEK6tw",
            )
            .expect("canonical fixture asset identity"),
            "1".parse().unwrap(),
        )),
        ..LaneConfigMetadata::default()
    };
    let entry = LaneConfigEntry::from_metadata(&metadata);
    assert!(entry.matches_metadata(&metadata));
    // The proof-scheme enum currently has exactly one variant; the equality
    // remains explicit in production even though no distinct value can be built.
    let mutations: [fn(&mut LaneConfigEntry); 18] = [
        |e| e.lane_id = LaneId::new(8),
        |e| e.shard_id += 1,
        |e| e.dataspace_id = DataSpaceId::new(99),
        |e| e.visibility = LaneVisibility::Restricted,
        |e| e.storage_profile = LaneStorageProfile::FullReplica,
        |e| e.alias.push('x'),
        |e| e.slug.push('x'),
        |e| e.kura_segment.push('x'),
        |e| e.merge_segment.push('x'),
        |e| e.key_prefix[0] ^= 1,
        |e| e.manifest_policy = DaManifestPolicy::Audit,
        |e| e.confidential_compute = None,
        |e| e.confidential_compute.as_mut().unwrap().key_version = NonZeroU32::new(2).unwrap(),
        |e| {
            e.confidential_compute
                .as_mut()
                .unwrap()
                .allowed_audiences
                .insert("extra audience".into());
        },
        |e| e.scheduler = None,
        |e| e.scheduler.as_mut().unwrap().teu_capacity = NonZeroU64::new(2),
        |e| e.settlement_buffer = None,
        |e| e.settlement_buffer.as_mut().unwrap().capacity = "2".parse().unwrap(),
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut drifted = entry.clone();
        mutate(&mut drifted);
        assert!(
            !drifted.matches_metadata(&metadata),
            "derived field mutation {index}"
        );
    }
}

#[test]
fn borrowed_catalog_check_preserves_exact_derived_entries_and_lookup_index() {
    let catalog = LaneCatalog::new(
        NonZeroU32::new(2).unwrap(),
        vec![
            LaneConfigMetadata::default(),
            LaneConfigMetadata {
                id: LaneId::new(1),
                alias: " _Second 東京 Lane_ ".into(),
                ..LaneConfigMetadata::default()
            },
        ],
    )
    .unwrap();
    let original = LaneConfig::from_catalog(&catalog);
    assert!(original.matches_catalog(&catalog));
    let mutations: [fn(&mut LaneConfig); 9] = [
        |config| {
            config.entries.pop();
        },
        |config| config.entries.push(config.entries[0].clone()),
        |config| config.entries.swap(0, 1),
        |config| {
            config.by_id.remove(&LaneId::new(1));
        },
        |config| {
            config.by_id.insert(LaneId::new(99), 1);
        },
        |config| {
            config.by_id.insert(LaneId::new(1), 0);
        },
        |config| {
            config.by_id.insert(LaneId::new(1), usize::MAX);
        },
        |config| config.entries[1].merge_segment.push('x'),
        |config| config.entries[1].manifest_policy = DaManifestPolicy::Audit,
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(
            changed, original,
            "fixture mutation {index} must change the derived graph"
        );
        assert_eq!(
            changed.matches_catalog(&catalog),
            changed == LaneConfig::from_catalog(&catalog),
            "borrowed equality for mutation {index}"
        );
        assert!(
            !changed.matches_catalog(&catalog),
            "derived graph mutation {index}"
        );
    }
    let one = LaneCatalog::default();
    assert!(!original.matches_catalog(&one));
    assert!(!LaneConfig::from_catalog(&one).matches_catalog(&catalog));
}
