//! Tests for compiled profiles, `derive(n)` and the profile digests.

use super::*;
use crate::parameters::defaults;
use crate::parameters::user;
use iroha_data_model::{account::AccountId, asset::AssetDefinitionId};
use iroha_model_base::{domain::DomainId, name::Name};

fn sora() -> Profile {
    Profile::compiled(ProfileId::SoraNexusV1).expect("sora-nexus-v1 loads")
}

fn value_at<'a>(table: &'a toml::Table, key: &str) -> &'a toml::Value {
    let mut segments = key.split('.');
    let first = segments.next().expect("non-empty key");
    let mut value = table
        .get(first)
        .unwrap_or_else(|| panic!("missing `{key}`"));
    for segment in segments {
        value = value
            .get(segment)
            .unwrap_or_else(|| panic!("missing `{key}`"));
    }
    value
}

fn integer_at(table: &toml::Table, key: &str) -> i64 {
    value_at(table, key)
        .as_integer()
        .unwrap_or_else(|| panic!("`{key}` is not an integer"))
}

fn string_at<'a>(table: &'a toml::Table, key: &str) -> &'a str {
    value_at(table, key)
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` is not a string"))
}

fn set(table: &mut toml::Table, key: &str, value: toml::Value) {
    let path: Vec<&str> = key.split('.').collect();
    let (leaf, parent) = path.split_last().unwrap();
    let mut cursor = table;
    for segment in parent {
        cursor = cursor
            .entry((*segment).to_owned())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .unwrap();
    }
    cursor.insert((*leaf).to_owned(), value);
}

#[test]
fn every_compiled_profile_loads_with_its_identity() {
    for (id, discriminant) in [
        (ProfileId::SoraNexusV1, 369),
        (ProfileId::SoraNexusV1Qual, 369),
        (ProfileId::IrohaDevV1, 753),
    ] {
        let profile = Profile::compiled(id).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(profile.id(), id);
        assert_eq!(profile.version(), 1);
        assert_eq!(profile.chain_discriminant(), discriminant);
        assert_eq!(profile.node_tunable(), ["logger.level", "logger.filter"]);
        for role in ProfileRole::ALL {
            assert!(profile.role(role).contains_key("sumeragi"), "{id} {role}");
        }
        assert_eq!(
            profile.genesis_recipe().consensus_mode(),
            if id == ProfileId::IrohaDevV1 {
                ConsensusMode::Permissioned
            } else {
                ConsensusMode::Npos
            }
        );
    }
}

#[test]
fn profile_and_role_names_roundtrip() {
    for id in ProfileId::ALL {
        assert_eq!(id.as_str().parse::<ProfileId>(), Ok(id));
        assert_eq!(id.to_string(), id.as_str());
    }
    assert_eq!(
        "sora-nexus-v2".parse::<ProfileId>(),
        Err(ProfileError::UnknownProfile("sora-nexus-v2".to_owned()))
    );
    for role in ProfileRole::ALL {
        assert_eq!(role.as_str().parse::<ProfileRole>(), Ok(role));
        assert_eq!(role.to_string(), role.as_str());
    }
    assert!(matches!(
        "voter".parse::<ProfileRole>(),
        Err(ProfileError::UnknownRole(_))
    ));
}

#[test]
fn sora_nexus_v1_carries_the_deployed_taira_shape() {
    let profile = sora();
    let recipe = profile.genesis_recipe();
    assert_eq!(recipe.block_cadence_ms, 5_000);
    assert_eq!(recipe.epoch_length_blocks, 3_600);
    let derive = profile.derive_inputs();
    assert_eq!(derive.authenticated_non_validator_sources, 4);
    assert_eq!(derive.max_external_committee_peers, 12);
    // Baseline catalog: core system lanes plus the public `nexus` lane, no customer dataspace.
    let lanes = value_at(profile.static_config(), "nexus.lane_catalog")
        .as_array()
        .unwrap();
    let aliases: Vec<&str> = lanes
        .iter()
        .map(|lane| lane.get("alias").and_then(toml::Value::as_str).unwrap())
        .collect();
    assert_eq!(aliases, ["core", "governance", "zk", "nexus"]);
    assert_eq!(integer_at(profile.static_config(), "nexus.lane_count"), 4);
    let dataspaces: Vec<&str> = derive
        .dataspace_catalog
        .iter()
        .map(|entry| entry.get("alias").and_then(toml::Value::as_str).unwrap())
        .collect();
    assert_eq!(dataspaces, ["universal", "nexus"]);
    assert!(
        !profile.static_config()["nexus"]
            .as_table()
            .unwrap()
            .contains_key("registry")
    );
    assert_eq!(
        value_at(profile.static_config(), "sumeragi")
            .as_table()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["keys"],
        "the profile binds only the consensus key policy; block limits are chain parameters"
    );
    assert_eq!(
        value_at(profile.static_config(), "sumeragi.keys.allowed_algorithms")
            .as_array()
            .unwrap(),
        &[toml::Value::String("bls_normal".to_owned())]
    );
    assert!(
        profile
            .derived_config(&profile.derive(4).unwrap())
            .get("sumeragi")
            .is_none(),
        "validator counts derive network capacity, not consensus node settings"
    );
    assert_eq!(profile.host().systemd_memory_max, "4G");
    assert_eq!(profile.host().systemd_cpu_quota, "200%");
    assert_eq!(
        integer_at(profile.policy(), "snapshot.create_every_ms"),
        600_000
    );
    assert_eq!(
        value_at(
            profile.role(ProfileRole::Validator),
            "soracloud_runtime.production_mode"
        )
        .as_bool(),
        Some(true)
    );
    for role in [ProfileRole::LaneValidator, ProfileRole::Observer] {
        assert_eq!(
            value_at(profile.role(role), "soracloud_runtime.production_mode").as_bool(),
            Some(false)
        );
    }
}

/// Every governance role and the VPN operator is its own keyless role account, never the published
/// sample key of the code defaults (which Kagami's Taira output still uses). Every protocol
/// custody role is the profile's keyless custody account, which has no signing key (Kagami derived
/// its equivalent from each genesis key). Staking and fees both use the canonical XOR, as the code
/// defaults and Kagami's Taira output do.
#[test]
fn sora_nexus_v1_literals_are_the_defaults_for_discriminant_369() {
    let profile = sora();
    let published_sample = defaults::governance::bond_escrow_account_id()
        .to_i105_for_discriminant(369)
        .unwrap();
    let static_config = profile.static_config();
    for role in KeylessRole::ALL {
        let section = if role.is_static() {
            static_config
        } else {
            profile.policy()
        };
        let expected = keyless_role_account(ProfileId::SoraNexusV1, role)
            .to_i105_for_discriminant(369)
            .unwrap();
        let literal = string_at(section, role.config_key());
        assert_eq!(literal, expected, "{}", role.config_key());
        assert_ne!(literal, published_sample, "{}", role.config_key());
    }
    let custody = protocol_custody_account(ProfileId::SoraNexusV1)
        .to_i105_for_discriminant(369)
        .unwrap();
    for key in [
        "pipeline.gas.tech_account_id",
        "nexus.staking.stake_escrow_account_id",
        "nexus.staking.slash_sink_account_id",
        "nexus.fees.fee_sink_account_id",
        "nexus.fees.sponsor_vault_custody_account_id",
    ] {
        assert_eq!(string_at(static_config, key), custody, "{key}");
    }
    let asset = |domain: &str| {
        AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified(domain).unwrap(),
            "xor".parse::<Name>().unwrap(),
        )
        .to_string()
    };
    assert_eq!(
        string_at(static_config, "nexus.fees.fee_asset_id"),
        defaults::nexus::fees::fee_asset_id()
    );
    assert_eq!(
        string_at(static_config, "nexus.fees.fee_asset_id"),
        asset("universal.universal")
    );
    assert_eq!(
        string_at(profile.policy(), "torii.faucet.asset_definition_id"),
        asset("universal.universal")
    );
    assert_eq!(
        string_at(static_config, "nexus.staking.stake_asset_id"),
        defaults::nexus::staking::stake_asset_id()
    );
    assert_eq!(
        string_at(static_config, "nexus.staking.stake_asset_id"),
        asset("universal.universal")
    );
}

/// The custody account is a keyless derivation scoped to the base profile. The code-default
/// custody and governance literals belong to the published sample key and must not be reused.
#[test]
fn protocol_custody_account_is_keyless_and_profile_scoped() {
    let sora = protocol_custody_account(ProfileId::SoraNexusV1);
    assert_eq!(sora, protocol_custody_account(ProfileId::SoraNexusV1));
    assert_ne!(sora, protocol_custody_account(ProfileId::IrohaDevV1));
    assert_eq!(
        sora,
        AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            PROTOCOL_CUSTODY_ACCOUNT_DOMAIN,
            &[b"sora-nexus-v1"],
        ))
    );
    assert_ne!(sora, defaults::governance::bond_escrow_account_id());
    let _default = iroha_data_model::account::address::ChainDiscriminantGuard::enter(
        defaults::common::chain_discriminant(),
    );
    assert_ne!(
        sora,
        AccountId::parse_encoded(defaults::pipeline::GAS_TECH_ACCOUNT_ID).unwrap()
    );
}

/// Each keyless role has its own account, scoped to the base profile, distinct from the custody
/// account and from the published sample key.
#[test]
fn keyless_role_accounts_are_distinct_and_profile_scoped() {
    let accounts: std::collections::BTreeSet<_> = KeylessRole::ALL
        .into_iter()
        .map(|role| keyless_role_account(ProfileId::SoraNexusV1, role))
        .collect();
    assert_eq!(accounts.len(), KeylessRole::ALL.len());
    assert!(!accounts.contains(&protocol_custody_account(ProfileId::SoraNexusV1)));
    assert!(!accounts.contains(&defaults::governance::bond_escrow_account_id()));
    assert_ne!(
        keyless_role_account(ProfileId::SoraNexusV1, KeylessRole::BondEscrow),
        keyless_role_account(ProfileId::IrohaDevV1, KeylessRole::BondEscrow)
    );
    assert_eq!(
        keyless_role_account(ProfileId::SoraNexusV1, KeylessRole::BondEscrow),
        AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            KEYLESS_ROLE_ACCOUNT_DOMAIN,
            &[b"sora-nexus-v1", b"gov.bond_escrow_account"],
        ))
    );
    assert!(
        KeylessRole::ALL
            .iter()
            .all(|role| { role.is_static() == role.config_key().starts_with("gov.") })
    );
}

/// `crypto.curves.allowed_curve_ids` must follow each profile's `allowed_signing`; omitting the
/// curves section would keep the code default, which drops `bls_normal`. The `bls_normal` curve id
/// exists only in builds with the data model's `bls` feature, so the profile must request the
/// derivation explicitly (an empty list) rather than rely on what this build derives.
#[test]
fn every_profile_derives_curve_ids_from_its_signing_algorithms() {
    use iroha_config_base::util::Emitter;
    for id in ProfileId::ALL {
        let profile = Profile::compiled(id).unwrap();
        assert_eq!(
            value_at(profile.static_config(), "crypto.curves.allowed_curve_ids").as_array(),
            Some(&Vec::new()),
            "{id} must derive crypto.curves.allowed_curve_ids from crypto.allowed_signing"
        );
        let crypto = profile
            .static_config()
            .get("crypto")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_else(|| panic!("{id} sets [static.crypto]"));
        let user = ConfigReader::new()
            .without_env()
            .with_toml_source(TomlSource::inline(crypto))
            .read_and_complete::<user::Crypto>()
            .unwrap_or_else(|report| panic!("{id}: {report:?}"));
        let mut emitter = Emitter::new();
        let crypto = user.parse(&mut emitter);
        emitter
            .into_result()
            .unwrap_or_else(|report| panic!("{id}: {report:?}"));
        assert_eq!(
            crypto.allowed_curve_ids,
            defaults::crypto::derive_curve_ids_from_algorithms(&crypto.allowed_signing),
            "{id}"
        );
    }
}

/// TODO: delete together with `defaults::taira` at the P8 cutover.
#[test]
fn sora_nexus_v1_policy_matches_defaults_taira() {
    use defaults::taira;
    let profile = sora();
    let policy = profile.policy();
    let expect = |key: &str, value: u64| {
        assert_eq!(
            u64::try_from(integer_at(policy, key)).unwrap(),
            value,
            "{key} drifted from defaults::taira"
        );
    };
    expect(
        "soracloud_runtime.hydration_concurrency",
        taira::HYDRATION_CONCURRENCY as u64,
    );
    expect(
        "soracloud_runtime.prepared_runtime_cache_capacity",
        taira::PREPARED_RUNTIME_CACHE_CAPACITY as u64,
    );
    expect(
        "soracloud_runtime.inrou.guest_image_max_bytes",
        taira::INROU_GUEST_IMAGE_MAX_BYTES,
    );
    expect(
        "soracloud_runtime.inrou.max_cpu_millis",
        u64::from(taira::INROU_MAX_CPU_MILLIS),
    );
    expect(
        "soracloud_runtime.inrou.max_memory_bytes",
        taira::INROU_MAX_MEMORY_BYTES,
    );
    expect(
        "soracloud_runtime.inrou.max_storage_bytes",
        taira::INROU_MAX_STORAGE_BYTES,
    );
    // `iroha3d_taira` guards `TAIRA_INROU_{START,STOP}_GRACE_MS_V1`.
    expect("soracloud_runtime.inrou.start_grace_ms", 30_000);
    expect("soracloud_runtime.inrou.stop_grace_ms", 10_000);
    expect(
        "soracloud_runtime.egress.rate_per_minute",
        u64::from(taira::INROU_EGRESS_RATE_PER_MINUTE),
    );
    expect(
        "soracloud_runtime.egress.max_bytes_per_minute",
        taira::INROU_EGRESS_MAX_BYTES_PER_MINUTE,
    );
    assert_eq!(
        value_at(policy, "soracloud_runtime.egress.default_allow").as_bool(),
        Some(false)
    );
    assert_eq!(
        value_at(policy, "soracloud_runtime.egress.allowed_hosts").as_array(),
        Some(&Vec::new())
    );
    expect(
        "nexus.storage.local_budget_bytes",
        taira::NEXUS_STORAGE_BUDGET_BYTES,
    );
    expect(
        "nexus.storage.max_wsv_memory_bytes",
        taira::NEXUS_MAX_WSV_MEMORY_BYTES,
    );
    expect(
        "nexus.storage.disk_budget_weights.kura_blocks_bps",
        u64::from(taira::NEXUS_KURA_BLOCKS_BPS),
    );
    expect(
        "nexus.storage.disk_budget_weights.wsv_snapshots_bps",
        u64::from(taira::NEXUS_WSV_SNAPSHOTS_BPS),
    );
    expect(
        "nexus.storage.disk_budget_weights.sorafs_bps",
        u64::from(taira::NEXUS_SORAFS_BPS),
    );
    expect(
        "sorafs.storage.max_capacity_bytes",
        taira::SORAFS_STORAGE_CAP_BYTES,
    );
    assert_eq!(
        value_at(policy, "sorafs.storage.enabled").as_bool(),
        Some(false)
    );
}

#[test]
fn qual_overrides_only_cadence_epoch_snapshot_and_storage_budget() {
    let base = sora();
    let qual = Profile::compiled(ProfileId::SoraNexusV1Qual).unwrap();
    assert_eq!(qual.static_config(), base.static_config());
    assert_eq!(qual.derive_inputs(), base.derive_inputs());
    assert_eq!(qual.host(), base.host());
    for role in ProfileRole::ALL {
        assert_eq!(qual.role(role), base.role(role));
    }
    assert_eq!(qual.chain_discriminant(), base.chain_discriminant());
    assert_eq!(
        qual.genesis_recipe(),
        &GenesisRecipeV1 {
            block_cadence_ms: 1_000,
            epoch_length_blocks: 64,
            ..base.genesis_recipe().clone()
        }
    );
    let mut expected_policy = base.policy().clone();
    set(
        &mut expected_policy,
        "snapshot.create_every_ms",
        toml::Value::Integer(30_000),
    );
    set(
        &mut expected_policy,
        "nexus.storage.local_budget_bytes",
        toml::Value::Integer(512 * 1024 * 1024),
    );
    assert_eq!(qual.policy(), &expected_policy);
}

#[test]
fn derive_admits_three_f_plus_one_rosters() {
    let profile = sora();
    for (validators, faults) in [(4_u32, 1_u32), (7, 2), (10, 3)] {
        let geometry = profile.derive(validators as usize).unwrap();
        let committee = validators + 12;
        assert_eq!(geometry.validators, validators);
        assert_eq!(geometry.npos_max_validators, validators);
        assert_eq!(geometry.fault_tolerance, faults);
        assert_eq!(geometry.commit_quorum, 2 * faults + 1);
        assert_eq!(geometry.committee_sources, committee);
        assert_eq!(geometry.authenticated_non_validator_sources, 4);
        assert_eq!(
            geometry.max_total_connections,
            u64::from(validators - 1 + 12 + 4)
        );
        let fragment = profile.derived_config(&geometry);
        assert_eq!(
            integer_at(&fragment, "network.max_total_connections"),
            i64::try_from(geometry.max_total_connections).unwrap()
        );
        assert!(
            fragment.get("sumeragi").is_none(),
            "the roster derives no Sumeragi node configuration"
        );
        for entry in value_at(&fragment, "nexus.dataspace_catalog")
            .as_array()
            .unwrap()
        {
            assert_eq!(
                entry
                    .get("fault_tolerance")
                    .and_then(toml::Value::as_integer),
                Some(i64::from(faults))
            );
        }
    }
    for id in [ProfileId::SoraNexusV1Qual, ProfileId::IrohaDevV1] {
        let profile = Profile::compiled(id).unwrap();
        for validators in [4, 7, 10] {
            profile
                .derive(validators)
                .unwrap_or_else(|error| panic!("{id} derive({validators}): {error}"));
        }
    }
}

#[test]
fn derive_rejects_rosters_that_are_not_three_f_plus_one() {
    let profile = sora();
    for validators in [0, 1, 2, 3, 5, 6, 8, 9, 11] {
        assert!(
            matches!(
                profile.derive(validators),
                Err(ProfileError::Geometry { .. })
            ),
            "{validators}"
        );
    }
    assert!(matches!(
        profile.derive(34),
        Err(ProfileError::Geometry { .. })
    ));
}

#[test]
fn digests_are_stable_across_loads_and_formatting() {
    let first = sora();
    let second = sora();
    assert_eq!(
        first.consensus_digest(4).unwrap(),
        second.consensus_digest(4).unwrap()
    );
    assert_eq!(
        first.policy_digest().unwrap(),
        second.policy_digest().unwrap()
    );
    // Re-serializing the fragments changes the TOML text, never the digest.
    let mut reformatted = sora();
    reformatted.static_config =
        toml::from_str(&toml::to_string_pretty(&first.static_config).unwrap()).unwrap();
    reformatted.policy = toml::from_str(&toml::to_string(&first.policy).unwrap()).unwrap();
    assert_eq!(
        reformatted.consensus_digest(4).unwrap(),
        first.consensus_digest(4).unwrap()
    );
    assert_eq!(
        reformatted.policy_digest().unwrap(),
        first.policy_digest().unwrap()
    );
    assert_eq!(
        first
            .consensus_digest_for(&first.derive(4).unwrap())
            .unwrap(),
        first.consensus_digest(4).unwrap()
    );
}

/// Golden digests of `sora-nexus-v1` for four validators. Any change to the profile file, the
/// derivation or the canonical encoding moves them; update them deliberately, because a new
/// consensus digest means a network reset.
#[test]
fn digests_are_pinned() {
    let profile = sora();
    // The native Sumeragi hard cut removed block/queue geometry from both the
    // static profile and DerivedGeometryV1 (8a99f3f5ba). Pin the resulting first-
    // release shape; retaining the removed queue fields would change semantics.
    // ZK delivery plan task F.4 removed `[static.zk.halo2] enabled = true`: ZK
    // validity values are the committed `zk_validity_policy_v1` parameter, not
    // node configuration, and the key no longer exists in the node schema.
    assert_eq!(
        profile.consensus_digest(4).unwrap().to_string(),
        "6dcc49948b24ea6675e4cfbfd3dfd963b5d91daa011f3d8b6eb4f00296c073fb"
    );
    assert_eq!(
        profile.policy_digest().unwrap().to_string(),
        "8c4ccda4944019c394c4439feb06516aaf16f3dfb1cffdb07c0dd2b850f9d023"
    );
}

#[test]
fn consensus_digest_is_sensitive_to_every_consensus_input() {
    let base = sora();
    let consensus = base.consensus_digest(4).unwrap();
    let policy = base.policy_digest().unwrap();
    assert_ne!(base.consensus_digest(7).unwrap(), consensus, "roster size");

    for (key, value) in [
        ("sumeragi.keys.overlap_grace_blocks", 9),
        ("nexus.lane_count", 5),
    ] {
        let mut changed = sora();
        set(&mut changed.static_config, key, toml::Value::Integer(value));
        assert_ne!(changed.consensus_digest(4).unwrap(), consensus, "{key}");
        assert_eq!(
            changed.policy_digest().unwrap(),
            policy,
            "static is not policy: {key}"
        );
    }

    let mut changed = sora();
    changed.derive.authenticated_non_validator_sources = 8;
    assert_ne!(
        changed.consensus_digest(4).unwrap(),
        consensus,
        "derive input"
    );

    let mut changed = sora();
    changed.derive.dataspace_catalog[1].insert(
        "description".into(),
        toml::Value::String("renamed".to_owned()),
    );
    assert_ne!(
        changed.consensus_digest(4).unwrap(),
        consensus,
        "catalog template"
    );

    let mut changed = sora();
    changed.genesis_recipe.epoch_length_blocks = 64;
    assert_ne!(
        changed.consensus_digest(4).unwrap(),
        consensus,
        "genesis recipe"
    );
    assert_eq!(changed.policy_digest().unwrap(), policy);

    let mut changed = sora();
    changed.chain_discriminant = 753;
    assert_ne!(
        changed.consensus_digest(4).unwrap(),
        consensus,
        "discriminant"
    );

    let qual = Profile::compiled(ProfileId::SoraNexusV1Qual).unwrap();
    assert_ne!(qual.consensus_digest(4).unwrap(), consensus, "profile id");
}

#[test]
fn policy_digest_is_sensitive_to_every_policy_input() {
    let base = sora();
    let consensus = base.consensus_digest(4).unwrap();
    let policy = base.policy_digest().unwrap();

    let mut changed = sora();
    set(
        &mut changed.policy,
        "snapshot.create_every_ms",
        toml::Value::Integer(60_000),
    );
    assert_ne!(changed.policy_digest().unwrap(), policy, "policy");
    assert_eq!(
        changed.consensus_digest(4).unwrap(),
        consensus,
        "policy is not consensus"
    );

    let mut changed = sora();
    set(
        changed.roles.get_mut(&ProfileRole::Observer).unwrap(),
        "logger.level",
        toml::Value::String("debug".to_owned()),
    );
    assert_ne!(changed.policy_digest().unwrap(), policy, "role overlay");
    assert_eq!(changed.consensus_digest(4).unwrap(), consensus);

    let mut changed = sora();
    changed.host.systemd_memory_max = "8G".to_owned();
    assert_ne!(changed.policy_digest().unwrap(), policy, "host");

    let mut changed = sora();
    changed.node_tunable.pop();
    assert_ne!(changed.policy_digest().unwrap(), policy, "node tunable");
}

#[test]
fn digest_inputs_roundtrip_through_norito() {
    let profile = sora();
    let geometry = profile.derive(4).unwrap();
    let decoded: DerivedGeometryV1 =
        norito::decode_canonical(&norito::encode_canonical(&geometry).unwrap()).unwrap();
    assert_eq!(decoded, geometry);
    let recipe = profile.genesis_recipe().clone();
    let decoded: GenesisRecipeV1 =
        norito::decode_canonical(&norito::encode_canonical(&recipe).unwrap()).unwrap();
    assert_eq!(decoded, recipe);
    let host = profile.host().clone();
    let decoded: HostPolicyV1 =
        norito::decode_canonical(&norito::encode_canonical(&host).unwrap()).unwrap();
    assert_eq!(decoded, host);
    let consensus = ConsensusDigestInputV1 {
        profile: profile.id().as_str().to_owned(),
        version: profile.version(),
        chain_discriminant: profile.chain_discriminant(),
        static_config: CanonicalTableV1::from_table(profile.static_config()).unwrap(),
        derived_config: CanonicalTableV1::from_table(&profile.derived_config(&geometry)).unwrap(),
        geometry,
        genesis_recipe: recipe,
    };
    let decoded: ConsensusDigestInputV1 =
        norito::decode_canonical(&norito::encode_canonical(&consensus).unwrap()).unwrap();
    assert_eq!(decoded, consensus);
    let policy = PolicyDigestInputV1 {
        profile: profile.id().as_str().to_owned(),
        version: profile.version(),
        node_tunable: profile.node_tunable().to_vec(),
        policy: CanonicalTableV1::from_table(profile.policy()).unwrap(),
        host,
        roles: ProfileRole::ALL
            .into_iter()
            .map(|role| {
                (
                    role.as_str().to_owned(),
                    CanonicalTableV1::from_table(profile.role(role)).unwrap(),
                )
            })
            .collect(),
    };
    let decoded: PolicyDigestInputV1 =
        norito::decode_canonical(&norito::encode_canonical(&policy).unwrap()).unwrap();
    assert_eq!(decoded, policy);
    let digest = profile.consensus_digest(4).unwrap();
    let decoded: ProfileDigest =
        norito::decode_canonical(&norito::encode_canonical(&digest).unwrap()).unwrap();
    assert_eq!(decoded, digest);
    assert_eq!(digest.to_string().len(), 64);
}

fn sora_table() -> toml::Table {
    parse_profile_text(ProfileId::SoraNexusV1).unwrap()
}

#[test]
fn genesis_recipe_rejects_retired_seat_band() {
    Profile::from_table(ProfileId::SoraNexusV1, sora_table()).expect("canonical profile");
    for value in [0, 5, 100] {
        let mut table = sora_table();
        set(
            &mut table,
            "genesis_recipe.npos_seat_band_pct",
            toml::Value::Integer(value),
        );
        assert!(matches!(
            Profile::from_table(ProfileId::SoraNexusV1, table),
            Err(ProfileError::Malformed { .. })
        ));
    }
}

#[test]
fn chain_discriminant_cannot_be_overridden_by_policy_or_roles() {
    for layer in [
        "policy",
        "role.validator",
        "role.lane_validator",
        "role.observer",
    ] {
        let mut table = sora_table();
        set(
            &mut table,
            &format!("{layer}.chain_discriminant"),
            toml::Value::Integer(753),
        );
        assert!(
            matches!(
                Profile::from_table(ProfileId::SoraNexusV1, table),
                Err(ProfileError::StaticOverride { key, layer: found, .. })
                    if key == "chain_discriminant" && found == layer
            ),
            "{layer} must not replace the profile's network identity"
        );
    }
}

#[test]
fn consensus_keys_cannot_be_reached_by_later_layers() {
    let cases: [(&str, &str); 6] = [
        ("policy.sumeragi.keys.allowed_algorithms", "policy"),
        ("policy.nexus.lane_count", "policy"),
        ("role.observer.nexus.lane_count", "role.observer"),
        ("policy.network.max_total_connections", "policy"),
        ("static.network.max_total_connections", "derive(n)"),
        ("static.genesis.public_key", "node file"),
    ];
    for (key, layer) in cases {
        let mut table = sora_table();
        set(&mut table, key, toml::Value::Integer(1));
        match Profile::from_table(ProfileId::SoraNexusV1, table) {
            Err(ProfileError::StaticOverride { layer: found, .. }) => {
                assert_eq!(found, layer, "{key}");
            }
            other => panic!("{key}: expected a static override, got {other:?}"),
        }
    }
    // A profile-tunable key in `[static]` would be node-overridable too.
    let mut table = sora_table();
    set(
        &mut table,
        "static.logger.level",
        toml::Value::String("info".to_owned()),
    );
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::StaticOverride { .. })
    ));
}

#[test]
fn malformed_profiles_are_rejected() {
    let mut table = sora_table();
    set(
        &mut table,
        "profile.id",
        toml::Value::String("iroha-dev-v1".to_owned()),
    );
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::Malformed { .. })
    ));
    let mut table = sora_table();
    set(&mut table, "profile.unknown_key", toml::Value::Integer(1));
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::Malformed { .. })
    ));
    let mut table = sora_table();
    table
        .get_mut("role")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .remove("observer");
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::Malformed { .. })
    ));
    let mut table = sora_table();
    set(
        &mut table,
        "genesis_recipe.consensus_mode",
        toml::Value::String("pow".to_owned()),
    );
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::Malformed { .. })
    ));
    let mut table = sora_table();
    table.remove("static");
    assert!(matches!(
        Profile::from_table(ProfileId::SoraNexusV1, table),
        Err(ProfileError::Malformed { .. })
    ));
}

#[test]
fn node_key_admission_follows_the_allowlist_and_tunables() {
    let profile = sora();
    for admitted in [
        "chain",
        "genesis.expected_hash",
        "genesis.file",
        "torii.account_onboarding.credentials",
        "soracloud_runtime.submission.signer.handle",
        "soracloud_runtime.inrou.portable_vm_uid",
        "lifecycle.exit_on_stdin_close",
        "logger.level",
        "logger.filter",
    ] {
        assert!(profile.admits_node_key(admitted), "{admitted}");
    }
    for rejected in [
        "chainx",
        "chain_discriminant",
        "sumeragi.role",
        "genesisx",
        "logger.format",
        "torii.faucet.amount",
        "torii.kagemusha_v1_commands.redemption_authority",
        "soracloud_runtime.inrou.max_cpu_millis",
        "sumeragi.keys.allowed_algorithms",
        "kura.store_dir",
        "private_key_file",
    ] {
        assert!(!profile.admits_node_key(rejected), "{rejected}");
    }
}

#[test]
fn layers_are_ordered_static_derive_policy_role() {
    let profile = sora();
    let geometry = profile.derive(4).unwrap();
    let layers = profile.layers(&geometry, ProfileRole::Observer);
    let names: Vec<String> = layers
        .iter()
        .map(|layer| layer.path().display().to_string())
        .collect();
    assert_eq!(
        names,
        [
            "<profile sora-nexus-v1>/static",
            "<profile sora-nexus-v1>/derive(4)",
            "<profile sora-nexus-v1>/policy",
            "<profile sora-nexus-v1>/role.observer",
        ]
    );
    let mut static_config = profile.static_config().clone();
    static_config.insert(
        "chain_discriminant".to_owned(),
        toml::Value::Integer(i64::from(profile.chain_discriminant())),
    );
    assert_eq!(layers[0].table(), &static_config);
    assert_eq!(layers[1].table(), &profile.derived_config(&geometry));
    assert_eq!(layers[2].table(), profile.policy());
    assert_eq!(layers[3].table(), profile.role(ProfileRole::Observer));
}

#[test]
fn table_helpers_merge_and_enumerate() {
    let mut base: toml::Table = toml::from_str("a = 1\n[t]\nx = 1\ny = [1]\n").unwrap();
    let overlay: toml::Table = toml::from_str("b = 2\n[t]\ny = [2]\nz = 3\n").unwrap();
    deep_merge(&mut base, overlay);
    let expected: toml::Table =
        toml::from_str("a = 1\nb = 2\n[t]\nx = 1\ny = [2]\nz = 3\n").unwrap();
    assert_eq!(base, expected);
    let mut keys = leaf_keys(&base);
    keys.sort();
    assert_eq!(keys, ["a", "b", "t.x", "t.y", "t.z"]);
    assert!(is_below("t.x", "t"));
    assert!(!is_below("tx", "t"));
    assert!(!is_below("t", "t"));
    assert!(keys_overlap("a.b", "a"));
    assert!(keys_overlap("a", "a.b"));
    assert!(keys_overlap("a", "a"));
    assert!(!keys_overlap("a", "ab"));
    assert_eq!(to_usize(7), 7);
    assert_eq!(parse_consensus_mode("npos"), Some(ConsensusMode::Npos));
    assert_eq!(parse_consensus_mode("other"), None);
}
