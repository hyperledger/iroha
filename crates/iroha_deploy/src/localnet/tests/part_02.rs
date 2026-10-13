include!("../profile_policy_tests.rs");
#[test]
#[allow(clippy::too_many_lines)]
fn nexus_localnet_alias_lanes_bind_dataspaces_and_seed_validators() {
    use std::collections::{BTreeMap, BTreeSet};
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let peer_count = NonZeroU16::new(4).expect("non-zero");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: peer_count,
        seed: Some("localnet-nexus-alias-lanes".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 32080,
        base_p2p_port: 32337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let nexus = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .expect("nexus table");
    assert_eq!(
        nexus
            .get("storage")
            .and_then(toml::Value::as_table)
            .and_then(|storage| storage.get("local_budget_bytes"))
            .and_then(toml::Value::as_integer),
        Some(
            i64::try_from(LOCALNET_NEXUS_STORAGE_BUDGET_BYTES)
                .expect("localnet Nexus storage budget fits i64")
        ),
        "nexus localnet should use an explicit disposable storage budget"
    );
    assert_eq!(
        nexus.get("lane_count").and_then(toml::Value::as_integer),
        Some(LOCALNET_NEXUS_ALIAS_LANE_COUNT),
        "nexus profile should declare explicit alias-aware lane count"
    );
    let lane_catalog = nexus
        .get("lane_catalog")
        .and_then(toml::Value::as_array)
        .expect("nexus lane catalog");
    let lanes_by_alias: BTreeMap<_, _> = lane_catalog
        .iter()
        .map(|entry| {
            let entry = entry.as_table().expect("lane entry");
            let alias = entry
                .get("alias")
                .and_then(toml::Value::as_str)
                .expect("lane alias")
                .to_owned();
            let dataspace = entry
                .get("dataspace")
                .and_then(toml::Value::as_str)
                .expect("lane dataspace")
                .to_owned();
            let visibility = entry
                .get("visibility")
                .and_then(toml::Value::as_str)
                .expect("lane visibility")
                .to_owned();
            (alias, (dataspace, visibility))
        })
        .collect();
    assert_eq!(
        lanes_by_alias.get("paynet"),
        Some(&("paynet".to_owned(), "public".to_owned()))
    );
    assert_eq!(
        lanes_by_alias.get("nexus"),
        Some(&("nexus".to_owned(), "public".to_owned()))
    );
    assert_eq!(
        lanes_by_alias.get("governance"),
        Some(&("universal".to_owned(), "public".to_owned()))
    );
    assert_eq!(
        lanes_by_alias.get("zk"),
        Some(&("universal".to_owned(), "public".to_owned()))
    );
    let dataspace_catalog = nexus
        .get("dataspace_catalog")
        .and_then(toml::Value::as_array)
        .expect("nexus dataspace catalog");
    let dataspaces_by_alias: BTreeMap<_, _> = dataspace_catalog
        .iter()
        .map(|entry| {
            let entry = entry.as_table().expect("dataspace entry");
            let alias = entry
                .get("alias")
                .and_then(toml::Value::as_str)
                .expect("dataspace alias")
                .to_owned();
            let id = entry
                .get("id")
                .and_then(toml::Value::as_integer)
                .expect("dataspace id");
            (alias, id)
        })
        .collect();
    assert_eq!(
        dataspaces_by_alias
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["nexus", "paynet", "universal"]),
        "logical governance and zk lanes must not create localnet dataspaces"
    );
    assert_eq!(
        dataspaces_by_alias.get("paynet"),
        Some(
            &i64::try_from(LOCALNET_PAYNET_ALIAS_DATASPACE_ID)
                .expect("PAYNET dataspace id fits i64")
        )
    );
    assert_eq!(
        dataspaces_by_alias.get("nexus"),
        Some(
            &i64::try_from(LOCALNET_CBUAE_ALIAS_DATASPACE_ID).expect("CBUAE dataspace id fits i64")
        )
    );
    let manifest = localnet_genesis_for_opts(&opts);
    let peers = build_peers(
        opts.peers.get(),
        opts.seed.as_ref().map(String::as_bytes),
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("rebuild deterministic Nexus peers");
    let committee_keys = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<RegisterConsensusKey>())
        .collect::<Vec<_>>();
    assert_eq!(committee_keys.len(), peers.len());
    for peer in &peers {
        let expected_id = derive_committee_key_id(&peer.public_key);
        assert!(committee_keys.iter().any(|registration| {
            registration.id == expected_id
                && registration.record.id == expected_id
                && registration.record.public_key == peer.public_key
                && registration.record.pop.as_deref() == Some(peer.bls_pop.as_slice())
                && registration.record.activation_height == 1
                && registration.record.expiry_height.is_none()
                && registration.record.status == ConsensusKeyStatus::Active
        }));
    }
    let key_permission = Permission::from(CanManageConsensusKeys);
    let key_grants = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant) if grant.object() == &key_permission => {
                Some(grant.destination())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let key_revokes = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<RevokeBox>())
        .filter_map(|revoke| match revoke {
            RevokeBox::Permission(revoke) if revoke.object() == &key_permission => {
                Some(revoke.destination())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(key_grants.len(), 1);
    assert_eq!(key_revokes, key_grants);
    let mut registrations_by_lane = BTreeMap::<u32, usize>::new();
    let mut activations_by_lane = BTreeMap::<u32, usize>::new();
    for instruction in manifest.instructions() {
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
        {
            *registrations_by_lane
                .entry(register.lane_id.as_u32())
                .or_default() += 1;
        }
        if let Some(activate) = instruction
            .as_any()
            .downcast_ref::<ActivatePublicLaneValidator>()
        {
            *activations_by_lane
                .entry(activate.lane_id.as_u32())
                .or_default() += 1;
        }
    }
    let expected_lanes = BTreeSet::from([
        LaneId::SINGLE.as_u32(),
        LOCALNET_PAYNET_ALIAS_LANE_INDEX,
        LOCALNET_CBUAE_ALIAS_LANE_INDEX,
    ]);
    assert_eq!(
        registrations_by_lane
            .keys()
            .copied()
            .collect::<BTreeSet<_>>(),
        expected_lanes,
        "nexus localnet should seed validators for each public alias lane"
    );
    assert_eq!(
        activations_by_lane.keys().copied().collect::<BTreeSet<_>>(),
        expected_lanes,
        "nexus localnet should activate validators for each public alias lane"
    );
    for lane in expected_lanes {
        assert_eq!(
            registrations_by_lane.get(&lane),
            Some(&usize::from(peer_count.get())),
            "expected one validator registration per peer on lane {lane}"
        );
        assert_eq!(
            activations_by_lane.get(&lane),
            Some(&usize::from(peer_count.get())),
            "expected one validator activation per peer on lane {lane}"
        );
    }
}

#[test]
fn invalid_chain_requests_do_not_create_partial_output_directories() {
    fn options(out_dir: PathBuf) -> LocalnetOptions {
        LocalnetOptions {
            service_profile: crate::localnet::LocalnetServiceProfile::Standard,
            sora_profile: None,
            perf_profile: None,
            peers: NonZeroU16::new(4).expect("non-zero"),
            seed: Some("pre-write-chain-validation".to_owned()),
            bind_host: DEFAULT_BIND_HOST.to_owned(),
            public_host: DEFAULT_PUBLIC_HOST.to_owned(),
            base_api_port: 28_080,
            base_p2p_port: 28_337,
            out_dir,
            extra_accounts: 0,
            assets: Vec::new(),
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Permissioned,
        }
    }

    let parent = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("create localnet validation parent");
    let malformed_out = parent.path().join("malformed-chain");
    let malformed = options(malformed_out.clone());
    let _error = generate_localnet_with_chain(
        &malformed,
        &mut BufWriter::new(Vec::new()),
        Some(" padded"),
        None,
    )
    .expect_err("malformed chain must fail");
    assert!(
        !malformed_out.exists(),
        "malformed chain must fail before creating its output directory"
    );

    let taira_out = parent.path().join("invalid-taira-profile");
    let invalid_taira = options(taira_out.clone());
    let _error = generate_localnet_with_chain(
        &invalid_taira,
        &mut BufWriter::new(Vec::new()),
        Some(PUBLIC_TAIRA_CHAIN_ID),
        None,
    )
    .expect_err("Taira profile mismatch must fail");
    assert!(
        !taira_out.exists(),
        "Taira profile mismatch must fail before creating its output directory"
    );
}
#[test]
fn invalid_asset_requests_do_not_create_partial_output_directories() {
    fn options(out_dir: PathBuf, assets: Vec<AssetSpec>) -> LocalnetOptions {
        LocalnetOptions {
            service_profile: crate::localnet::LocalnetServiceProfile::Standard,
            sora_profile: None,
            perf_profile: None,
            peers: NonZeroU16::new(4).expect("non-zero"),
            seed: Some("pre-write-asset-validation".to_owned()),
            bind_host: DEFAULT_BIND_HOST.to_owned(),
            public_host: DEFAULT_PUBLIC_HOST.to_owned(),
            base_api_port: 28_080,
            base_p2p_port: 28_337,
            out_dir,
            extra_accounts: 0,
            assets,
            block_cadence_ms: None,
            consensus_mode: SumeragiConsensusMode::Permissioned,
        }
    }
    fn asset(id: String, alias: Option<&str>) -> AssetSpec {
        AssetSpec {
            id,
            name: "Preflight asset".to_owned(),
            alias: alias.map(str::to_owned),
            owned_by: ALICE_ID.clone(),
            mint_to: ALICE_ID.clone(),
            quantity: 1,
        }
    }

    let parent = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("create asset-validation parent");
    let valid_id = localnet_sample_asset_literal();
    let cases = [
        ("invalid-id", vec![asset("not-an-id".to_owned(), None)]),
        (
            "invalid-alias",
            vec![asset(valid_id.clone(), Some("not an alias"))],
        ),
        (
            "duplicate-id",
            vec![asset(valid_id.clone(), None), asset(valid_id, None)],
        ),
        (
            "duplicate-alias",
            vec![
                asset(localnet_sample_asset_literal(), Some("sample#localnet")),
                asset(localnet_xor_asset_literal(), Some("sample#localnet")),
            ],
        ),
    ];
    for (name, assets) in cases {
        let out_dir = parent.path().join(name);
        let _error = generate_localnet(
            &options(out_dir.clone(), assets),
            &mut BufWriter::new(Vec::new()),
        )
        .expect_err("invalid asset request must fail");
        assert!(
            !out_dir.exists(),
            "invalid asset request `{name}` must fail before creating output"
        );
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn private_dataspace_profiles_match_their_exact_routing_contract() {
    fn expected_dataspace(
        alias: &str,
        id: i64,
        description: &str,
        fault_tolerance: i64,
    ) -> toml::Value {
        let mut entry = toml::Table::new();
        entry.insert("alias".into(), toml::Value::String(alias.to_owned()));
        entry.insert("id".into(), toml::Value::Integer(id));
        if id != 0 {
            entry.insert(
                "manifest_hash".into(),
                toml::Value::String(localnet_dataspace_manifest_hash(id)),
            );
        }
        entry.insert(
            "description".into(),
            toml::Value::String(description.to_owned()),
        );
        entry.insert(
            "fault_tolerance".into(),
            toml::Value::Integer(fault_tolerance),
        );
        toml::Value::Table(entry)
    }
    fn expected_lane(
        index: i64,
        alias: &str,
        description: &str,
        dataspace: &str,
        visibility: &str,
        governance: Option<&str>,
    ) -> toml::Value {
        let mut entry = toml::Table::new();
        entry.insert("index".into(), toml::Value::Integer(index));
        entry.insert("alias".into(), toml::Value::String(alias.to_owned()));
        entry.insert(
            "description".into(),
            toml::Value::String(description.to_owned()),
        );
        entry.insert(
            "dataspace".into(),
            toml::Value::String(dataspace.to_owned()),
        );
        entry.insert(
            "visibility".into(),
            toml::Value::String(visibility.to_owned()),
        );
        if let Some(governance) = governance {
            entry.insert(
                "governance".into(),
                toml::Value::String(governance.to_owned()),
            );
        }
        entry.insert("metadata".into(), toml::Value::Table(toml::Table::new()));
        toml::Value::Table(entry)
    }
    struct Case {
        profile: SoraProfile,
        alias: &'static str,
        id: i64,
        lane: i64,
        lane_count: i64,
        dataspace_description: &'static str,
        lane_description: &'static str,
        routes: &'static [(&'static str, &'static str, i64, &'static str)],
    }
    const SBP_ROUTES: &[(&str, &str, i64, &str)] = &[
        ("account", "*@sbp", 3, "sbp"),
        ("account", "*@hbl.sbp", 3, "sbp"),
        ("account", "*@ubl.sbp", 3, "sbp"),
        ("instruction", "governance", 1, "universal"),
        ("instruction", "smartcontract::deploy", 2, "universal"),
        ("instruction", "transfer::asset@sbp", 3, "sbp"),
        ("instruction", "transfer::asset@hbl.sbp", 3, "sbp"),
        ("instruction", "transfer::asset@ubl.sbp", 3, "sbp"),
    ];
    const CBUAE_ROUTES: &[(&str, &str, i64, &str)] = &[
        ("account", "*@cbuae", 4, "cbuae"),
        ("instruction", "governance", 1, "universal"),
        ("instruction", "smartcontract::deploy", 2, "universal"),
        ("instruction", "transfer::asset@cbuae", 4, "cbuae"),
    ];
    const BPNG_ROUTES: &[(&str, &str, i64, &str)] = &[
        ("account", "*@bpng", 5, "bpng"),
        ("account", "*@mibank.bpng", 5, "bpng"),
        ("instruction", "governance", 1, "universal"),
        ("instruction", "smartcontract::deploy", 2, "universal"),
        ("instruction", "transfer::asset@bpng", 5, "bpng"),
        ("instruction", "transfer::asset@mibank.bpng", 5, "bpng"),
    ];
    let cases = [
        Case {
            profile: SoraProfile::PrivateSbp,
            alias: "sbp",
            id: 10,
            lane: 3,
            lane_count: 4,
            dataspace_description: "State Bank of Pakistan dataspace",
            lane_description: "State Bank of Pakistan private lane",
            routes: SBP_ROUTES,
        },
        Case {
            profile: SoraProfile::PrivateCbuae,
            alias: "cbuae",
            id: 12,
            lane: 4,
            lane_count: 5,
            dataspace_description: "CBUAE dataspace",
            lane_description: "CBUAE private lane",
            routes: CBUAE_ROUTES,
        },
        Case {
            profile: SoraProfile::PrivateBpng,
            alias: "bpng",
            id: 8_648_377_547_929_788_715,
            lane: 5,
            lane_count: 6,
            dataspace_description: "Bank of Papua New Guinea dataspace",
            lane_description: "Bank of Papua New Guinea private lane",
            routes: BPNG_ROUTES,
        },
    ];
    for case in cases {
        let profile = Some(case.profile);
        let dataspace_catalog = localnet_dataspace_catalog(profile, 1, false);
        assert_eq!(
            dataspace_catalog,
            vec![
                expected_dataspace(
                    "universal",
                    0,
                    "Shared public data space for core, governance, and zero-knowledge lanes",
                    1,
                ),
                expected_dataspace(case.alias, case.id, case.dataspace_description, 1,),
            ],
            "private dataspace catalog must exactly match the selected physical identity"
        );
        let (lane_count, lane_catalog) =
            localnet_lane_catalog(profile, false).expect("private lane catalog");
        assert_eq!(lane_count, case.lane_count);
        assert_eq!(
            lane_catalog,
            vec![
                expected_lane(
                    0,
                    "core",
                    "Primary public lane",
                    "universal",
                    "public",
                    None,
                ),
                expected_lane(
                    1,
                    "governance",
                    "Governance lane",
                    "universal",
                    "public",
                    None,
                ),
                expected_lane(2, "zk", "Zero-knowledge lane", "universal", "public", None,),
                expected_lane(
                    case.lane,
                    case.alias,
                    case.lane_description,
                    case.alias,
                    "restricted",
                    Some("parliament"),
                ),
            ],
            "private lane catalog must preserve the selected identity and leave unrelated lanes absent"
        );
        let routing = localnet_routing_policy(profile, false).expect("private routing policy");
        let observed = routing
            .get("rules")
            .and_then(toml::Value::as_array)
            .expect("private routing rules")
            .iter()
            .map(|rule| {
                let rule = rule.as_table().expect("routing rule table");
                let matcher = rule
                    .get("matcher")
                    .and_then(toml::Value::as_table)
                    .expect("routing matcher");
                let (matcher_kind, matcher_value) = ["account", "instruction"]
                    .into_iter()
                    .find_map(|kind| {
                        matcher
                            .get(kind)
                            .and_then(toml::Value::as_str)
                            .map(|value| (kind.to_owned(), value.to_owned()))
                    })
                    .expect("account or instruction routing matcher");
                (
                    matcher_kind,
                    matcher_value,
                    rule.get("lane")
                        .and_then(toml::Value::as_integer)
                        .expect("routing lane"),
                    rule.get("dataspace")
                        .and_then(toml::Value::as_str)
                        .expect("routing dataspace")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let expected = case
            .routes
            .iter()
            .map(|(kind, matcher, lane, dataspace)| {
                (
                    (*kind).to_owned(),
                    (*matcher).to_owned(),
                    *lane,
                    (*dataspace).to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed, expected,
            "routing identity and order must be exact"
        );
        assert_eq!(
            localnet_public_validator_lanes(profile, false),
            vec![LaneId::SINGLE],
            "only the canonical owner of the shared universal physical dataspace may receive mutable NPoS staking state"
        );
    }
}
#[test]
fn private_dataspace_manifests_use_the_selected_lane_alias() {
    use std::collections::BTreeSet;
    let peers = build_peers(4, Some(b"private-dataspace-manifest"), 34_080, 34_337)
        .expect("build deterministic manifest validators");
    let expected_peer_ids = peers
        .iter()
        .map(|peer| PeerId::from(peer.public_key.clone()).to_string())
        .collect::<BTreeSet<_>>();
    for (profile, alias) in [
        (SoraProfile::PrivateSbp, "sbp"),
        (SoraProfile::PrivateCbuae, "cbuae"),
        (SoraProfile::PrivateBpng, "bpng"),
    ] {
        let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
        let manifest_directory =
            write_localnet_lane_manifests(temp.path(), Some(profile), &peers, None, false)
                .expect("write private lane manifest")
                .expect("private lane manifest directory");
        assert_eq!(manifest_directory, temp.path().join("lane-manifests"));
        let manifest_files = fs::read_dir(&manifest_directory)
            .expect("read private lane manifest directory")
            .map(|entry| {
                entry
                    .expect("private lane manifest directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(manifest_files, vec![format!("{alias}.manifest.json")]);
        let manifest: json::Value = json::from_str(
            &fs::read_to_string(manifest_directory.join(format!("{alias}.manifest.json")))
                .expect("read private lane manifest"),
        )
        .expect("parse private lane manifest");
        let manifest_fields = manifest
            .as_object()
            .expect("private lane manifest object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            manifest_fields,
            BTreeSet::from(["governance", "lane", "quorum", "validators", "version"])
        );
        assert_eq!(
            manifest.get("lane").and_then(json::Value::as_str),
            Some(alias)
        );
        assert_eq!(
            manifest.get("governance").and_then(json::Value::as_str),
            Some("parliament")
        );
        assert_eq!(
            manifest.get("quorum").and_then(json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            manifest.get("version").and_then(json::Value::as_u64),
            Some(1)
        );
        let manifest_peer_ids = manifest
            .get("validators")
            .and_then(json::Value::as_array)
            .expect("private lane manifest validators")
            .iter()
            .map(|validator| {
                validator
                    .get("peer_id")
                    .and_then(json::Value::as_str)
                    .expect("private lane manifest peer id")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(manifest_peer_ids, expected_peer_ids);
    }
}
#[test]
#[allow(clippy::too_many_lines)]
fn dataspace_localnet_binds_paynet_restricted_lane_before_genesis_signing() {
    use std::collections::{BTreeMap, BTreeSet};
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let peer_count = NonZeroU16::new(4).expect("non-zero");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Dataspace),
        perf_profile: None,
        peers: peer_count,
        seed: Some("localnet-paynet-dataspace-lane".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 34080,
        base_p2p_port: 34337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let nexus = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .expect("nexus table");
    assert_eq!(
        nexus.get("lane_count").and_then(toml::Value::as_integer),
        Some(LOCALNET_PAYNET_ALIAS_LANE_COUNT),
        "dataspace profile should declare the PAYNET lane before genesis signing"
    );
    let lane_catalog = nexus
        .get("lane_catalog")
        .and_then(toml::Value::as_array)
        .expect("nexus lane catalog");
    let lanes_by_alias: BTreeMap<_, _> = lane_catalog
        .iter()
        .map(|entry| {
            let entry = entry.as_table().expect("lane entry");
            let alias = entry
                .get("alias")
                .and_then(toml::Value::as_str)
                .expect("lane alias")
                .to_owned();
            let dataspace = entry
                .get("dataspace")
                .and_then(toml::Value::as_str)
                .expect("lane dataspace")
                .to_owned();
            let visibility = entry
                .get("visibility")
                .and_then(toml::Value::as_str)
                .expect("lane visibility")
                .to_owned();
            let governance = entry
                .get("governance")
                .and_then(toml::Value::as_str)
                .map(str::to_owned);
            (alias, (dataspace, visibility, governance))
        })
        .collect();
    assert_eq!(
        lanes_by_alias.get("paynet"),
        Some(&(
            "paynet".to_owned(),
            "restricted".to_owned(),
            Some("parliament".to_owned()),
        ))
    );
    let registry = nexus
        .get("registry")
        .and_then(toml::Value::as_table)
        .expect("dataspace lane manifest registry");
    let manifest_directory = registry
        .get("manifest_directory")
        .and_then(toml::Value::as_str)
        .expect("dataspace lane manifest directory");
    assert_eq!(
        fs::canonicalize(manifest_directory).expect("canonical manifest directory"),
        fs::canonicalize(temp.path().join("lane-manifests"))
            .expect("canonical expected manifest directory")
    );
    let governance = nexus
        .get("governance")
        .and_then(toml::Value::as_table)
        .expect("dataspace governance catalog");
    assert_eq!(
        governance
            .get("default_module")
            .and_then(toml::Value::as_str),
        Some("parliament")
    );
    assert_eq!(
        governance
            .get("modules")
            .and_then(toml::Value::as_table)
            .and_then(|modules| modules.get("parliament"))
            .and_then(toml::Value::as_table)
            .and_then(|module| module.get("module_type"))
            .and_then(toml::Value::as_str),
        Some("parliament_sortition_jit")
    );
    let parliament_params = governance
        .get("modules")
        .and_then(toml::Value::as_table)
        .and_then(|modules| modules.get("parliament"))
        .and_then(toml::Value::as_table)
        .and_then(|module| module.get("params"))
        .and_then(toml::Value::as_table)
        .expect("parliament governance params");
    assert_eq!(
        parliament_params
            .get("selection")
            .and_then(toml::Value::as_str),
        Some("multibody_sortition")
    );
    assert_eq!(
        parliament_params
            .get("approval_flow")
            .and_then(toml::Value::as_str),
        Some("jit")
    );
    let paynet_manifest: json::Value = json::from_str(
        &fs::read_to_string(temp.path().join("lane-manifests/paynet.manifest.json"))
            .expect("read PAYNET lane manifest"),
    )
    .expect("parse PAYNET lane manifest");
    assert_eq!(
        paynet_manifest.get("lane").and_then(json::Value::as_str),
        Some("paynet")
    );
    assert_eq!(
        paynet_manifest
            .get("governance")
            .and_then(json::Value::as_str),
        Some("parliament")
    );
    assert_eq!(
        paynet_manifest
            .get("validators")
            .and_then(json::Value::as_array)
            .map(Vec::len),
        Some(usize::from(peer_count.get()))
    );
    assert_eq!(
        paynet_manifest.get("quorum").and_then(json::Value::as_u64),
        Some(3)
    );
    let dataspace_catalog = nexus
        .get("dataspace_catalog")
        .and_then(toml::Value::as_array)
        .expect("nexus dataspace catalog");
    let dataspaces_by_alias: BTreeMap<_, _> = dataspace_catalog
        .iter()
        .map(|entry| {
            let entry = entry.as_table().expect("dataspace entry");
            let alias = entry
                .get("alias")
                .and_then(toml::Value::as_str)
                .expect("dataspace alias")
                .to_owned();
            let id = entry
                .get("id")
                .and_then(toml::Value::as_integer)
                .expect("dataspace id");
            (alias, id)
        })
        .collect();
    assert_eq!(
        dataspaces_by_alias.get("paynet"),
        Some(
            &i64::try_from(LOCALNET_PAYNET_ALIAS_DATASPACE_ID)
                .expect("PAYNET dataspace id fits i64")
        )
    );
    let routing_policy = nexus
        .get("routing_policy")
        .and_then(toml::Value::as_table)
        .expect("routing policy");
    let account_rules: BTreeSet<_> = routing_policy
        .get("rules")
        .and_then(toml::Value::as_array)
        .expect("routing rules")
        .iter()
        .filter_map(|rule| {
            rule.as_table()
                .and_then(|rule| rule.get("matcher"))
                .and_then(toml::Value::as_table)
                .and_then(|matcher| matcher.get("account"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        account_rules,
        BTreeSet::from(["*@paynet".to_owned(), "*@mibank.paynet".to_owned()])
    );
    let manifest = localnet_genesis_for_opts(&opts);
    let validator_lanes = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
                .map(|register| register.lane_id.as_u32())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        validator_lanes,
        BTreeSet::from([LaneId::SINGLE.as_u32()]),
        "restricted PAYNET dataspace lane must not be bootstrapped as a public stake-elected lane"
    );
    let source = TomlSource::from_file(temp.path().join("peer0.toml")).expect("read config");
    let parsed = actual::Root::from_toml_source(source).expect("config should parse");
    let expected_hash = iroha_core::da::proof_policy_bundle_hash(&parsed.nexus.lane_config);
    let bytes = fs::read(temp.path().join("genesis.signed.nrt")).expect("read signed genesis");
    let block =
        decode_framed_signed_block(&bytes).expect("decode signed genesis from framed payload");
    assert_eq!(
        block.header().da_proof_policies_hash(),
        Some(expected_hash),
        "signed genesis should embed the PAYNET dataspace proof policy bundle from peer config"
    );
}
#[test]
fn nexus_localnet_signed_genesis_uses_peer_config_da_proof_policies() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-nexus-da-proof-policy".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 33080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let source = TomlSource::from_file(temp.path().join("peer0.toml")).expect("read config");
    let parsed = actual::Root::from_toml_source(source).expect("config should parse");
    let expected_hash = iroha_core::da::proof_policy_bundle_hash(&parsed.nexus.lane_config);
    let expected_confidential_policy_hash =
        iroha_core::state::default_genesis_confidential_policy_hash();
    let bytes = fs::read(temp.path().join("genesis.signed.nrt")).expect("read signed genesis");
    let block =
        decode_framed_signed_block(&bytes).expect("decode signed genesis from framed payload");
    assert_eq!(
        block.header().da_proof_policies_hash(),
        Some(expected_hash),
        "signed genesis should embed the same DA proof policy bundle as peer configs",
    );
    assert_eq!(
        block
            .header()
            .confidential_features()
            .expect("signed genesis should carry confidential feature digest")
            .zk_policy_hash,
        Some(expected_confidential_policy_hash),
        "signed genesis should embed the same genesis confidential policy as peer configs",
    );
}
#[test]
fn permissioned_localnet_pins_gas_limit_without_enabling_gas_fees() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("permissioned-gas-metering-only".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(1_000),
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let manifest = genesis_json_from_path(&temp.path().join("genesis.json"));
    let params = genesis_parameters(&manifest);
    let gas_limit: u64 = params
        .custom()
        .get(&localnet_custom_parameter_id("ivm_gas_limit_per_block"))
        .expect("permissioned localnet should pin the IVM gas limit")
        .payload()
        .try_into_any_norito()
        .expect("gas limit payload should decode");
    assert_eq!(gas_limit, LOCALNET_IVM_GAS_LIMIT_PER_BLOCK);
    assert!(
        !params
            .custom()
            .contains_key(&localnet_custom_parameter_id("ivm_gas_accepted_assets")),
        "permissioned localnet must not enable gas fee assets without bootstrapping XOR"
    );
    assert!(
        !params
            .custom()
            .contains_key(&localnet_custom_parameter_id("ivm_gas_units_per_gas")),
        "permissioned localnet must not override peer gas rates to a charging value"
    );
}
#[test]
fn block_cadence_override_is_signed_into_genesis() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("block-time-commit-default".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(1_000),
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let genesis_path = temp.path().join("genesis.json");
    let manifest = genesis_json_from_path(&genesis_path);
    let params = genesis_parameters(&manifest);
    assert_eq!(params.sumeragi().block_cadence_ms().get(), 1_000);
    let gas_param_id = localnet_custom_parameter_id("ivm_gas_limit_per_block");
    let gas_limit: u64 = params
        .custom()
        .get(&gas_param_id)
        .expect("localnet should pin the IVM gas limit")
        .payload()
        .try_into_any_norito()
        .expect("gas limit payload should decode");
    assert_eq!(gas_limit, LOCALNET_IVM_GAS_LIMIT_PER_BLOCK);
    let expected_fee_asset = localnet_xor_asset_literal();
    let accepted_assets: Vec<String> = params
        .custom()
        .get(&localnet_custom_parameter_id("ivm_gas_accepted_assets"))
        .expect("localnet should pin accepted IVM gas assets")
        .payload()
        .try_into_any_norito()
        .expect("accepted assets payload should decode");
    assert_eq!(accepted_assets, vec![expected_fee_asset.clone()]);
    let units_per_gas = params
        .custom()
        .get(&localnet_custom_parameter_id("ivm_gas_units_per_gas"))
        .expect("localnet should pin IVM gas rates")
        .payload();
    assert_eq!(
        units_per_gas,
        &localnet_ivm_gas_units_per_gas_payload(&expected_fee_asset)
    );
}
#[test]
fn npos_localnet_keeps_payload_for_fast_block_cadence() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("npos-fast-timeouts".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 38180,
        base_p2p_port: 38437,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(333),
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let genesis_path = temp.path().join("genesis.json");
    let manifest = genesis_json_from_path(&genesis_path);
    let params = genesis_parameters(&manifest);
    assert_eq!(params.sumeragi().block_cadence_ms().get(), 333);
    let npos = params
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .expect("valid fixture NPoS parameters")
        .flatten()
        .expect("npos parameters must be present");
    assert_eq!(npos.min_self_bond(), &Quantity::from(1_u64));
}
#[test]
fn npos_localnet_keeps_genesis_under_transaction_cap() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("npos-genesis-cap".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 38280,
        base_p2p_port: 38537,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(333),
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let genesis_path = temp.path().join("genesis.json");
    let transactions = RawGenesisTransaction::from_path(&genesis_path)
        .expect("parse generated genesis")
        .normalize()
        .expect("normalize generated genesis")
        .transactions;
    assert!(
        transactions.len() <= 16,
        "localnet genesis must stay within the block validation transaction cap"
    );
}
#[test]
fn client_config_selects_the_generated_identity_file_only() {
    let tmp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let root = crate::localnet::custody::prepare_empty_private_directory(tmp.path())
        .expect("prepare private client config directory");
    let host =
        CanonicalHost::parse(DEFAULT_PUBLIC_HOST, "--public-host").expect("canonicalize host");
    write_client_config(
        &root,
        8080,
        &host,
        DEFAULT_CHAIN_ID,
        None,
        &localnet_client_identity(None, false).expect("default client"),
        None,
    )
    .expect("write client config");
    let contents = fs::read_to_string(root.join("client.toml")).expect("read client config");
    assert!(contents.contains("private_key = \"802620"));
    let value: toml::Value = toml::from_str(&contents).expect("parse client config");
    assert_eq!(
        value.get("network_id_file").and_then(toml::Value::as_str),
        Some(GENESIS_EXPECTED_HASH_FILE)
    );
    assert!(
        value.get("network_id").is_none(),
        "generated client config must not duplicate the checked identity inline"
    );
    assert_eq!(
        value
            .get("torii_url")
            .and_then(toml::Value::as_str)
            .unwrap_or_default(),
        "http://127.0.0.1:8080/"
    );
    let account = value
        .get("account")
        .and_then(toml::Value::as_table)
        .expect("account table");
    assert!(
        !account.contains_key("domain"),
        "client configurations carry no account domain"
    );
    assert_eq!(
        account
            .get("chain_discriminant")
            .and_then(toml::Value::as_integer),
        Some(i64::from(
            iroha_config::parameters::defaults::common::chain_discriminant()
        )),
        "peers without an explicit prefix run with the node default, which the client states"
    );
    assert!(
        !account.contains_key("profile"),
        "a local network must not claim a public network profile"
    );
}
#[test]
fn client_config_records_chain_discriminant_when_known() {
    let tmp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let root = crate::localnet::custody::prepare_empty_private_directory(tmp.path())
        .expect("prepare private client config directory");
    let host =
        CanonicalHost::parse(DEFAULT_PUBLIC_HOST, "--public-host").expect("canonicalize host");
    write_client_config(
        &root,
        8080,
        &host,
        DEFAULT_CHAIN_ID,
        Some(369),
        &localnet_client_identity(None, false).expect("default client"),
        None,
    )
    .expect("write client config");
    let contents = fs::read_to_string(root.join("client.toml")).expect("read client config");
    let value: toml::Value = toml::from_str(&contents).expect("parse client config");
    let account = value
        .get("account")
        .and_then(toml::Value::as_table)
        .expect("account table");
    assert_eq!(
        account
            .get("chain_discriminant")
            .and_then(toml::Value::as_integer),
        Some(369)
    );
}
#[test]
fn client_config_preserves_publication_with_explicit_network_context() {
    let host =
        CanonicalHost::parse(DEFAULT_PUBLIC_HOST, "--public-host").expect("canonicalize host");
    let client = localnet_client_identity(None, false).expect("default client");
    let publication =
        toml::Table::from_iter([("request_timeout_ms".into(), toml::Value::Integer(30_000))]);
    for configured in [None, Some(369)] {
        let rendered = render_client_config(
            8080,
            &host,
            DEFAULT_CHAIN_ID,
            configured,
            &client,
            Some(&publication),
        )
        .expect("render client config");
        let value: toml::Value = toml::from_str(&rendered).expect("parse client config");
        let expected = configured
            .unwrap_or_else(iroha_config::parameters::defaults::common::chain_discriminant);
        assert_eq!(
            value["account"]["chain_discriminant"].as_integer(),
            Some(i64::from(expected))
        );
        assert_eq!(
            value["musubi"]["publication"].as_table(),
            Some(&publication)
        );
    }
}
#[test]
fn generated_taira_genesis_grants_deployment_only_to_generated_client() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(369);
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("temporary Taira directory");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
        seed: Some("taira-generated-deployer-permission".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29_080,
        base_p2p_port: 33_337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(5_000),
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet_with_chain(
        &opts,
        &mut BufWriter::new(Vec::new()),
        Some(PUBLIC_TAIRA_CHAIN_ID),
        None,
    )
    .expect("generate Taira with its runtime operator");
    let client_config: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("client.toml")).expect("read generated client"),
    )
    .expect("parse generated client");
    let client_public_key = client_config
        .get("account")
        .and_then(|account| account.get("public_key"))
        .and_then(toml::Value::as_str)
        .expect("generated client public key")
        .parse::<iroha_crypto::PublicKey>()
        .expect("canonical client public key");
    let client_account_id = AccountId::new(client_public_key);
    let operator =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("derive expected generated operator");
    assert_eq!(client_account_id, operator.account_id);
    assert_ne!(client_account_id, localnet_client_account_id());
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated Taira genesis");
    let code_management_grantees = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant)
                if CanManageSmartContractCode::try_from(grant.object()).is_ok() =>
            {
                Some(grant.destination().clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        code_management_grantees,
        vec![client_account_id.clone()],
        "only the generated client receives contract-code management authority, exactly once"
    );
    let managers = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant)
                if CanGrantSmartContractCodeManagement::try_from(grant.object()).is_ok() =>
            {
                Some(grant.destination().clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(managers, vec![client_account_id.clone()]);
    assert!(manifest.instructions().any(|instruction| {
        matches!(
            instruction.as_any().downcast_ref::<RegisterBox>(),
            Some(RegisterBox::Account(register)) if register.object().id() == &client_account_id
        )
    }));
    let client_fee_asset = AssetId::new(localnet_xor_asset_definition_id(), client_account_id);
    assert!(manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<MintBox>()
            .is_some_and(|mint| match mint {
                MintBox::Asset(mint) => {
                    mint.destination() == &client_fee_asset && !mint.object().is_zero()
                }
                _ => false,
            })
    }));
}
#[test]
fn generated_permissioned_localnet_cannot_mint_additional_xor() {
    use iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition;
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("permissioned-faucet-mint-permission".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let operator =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("derive generated operator");
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated genesis");
    let mut operator_mint_permissions = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant) if grant.destination() == &operator.account_id => {
                CanMintAssetWithDefinition::try_from(grant.object()).ok()
            }
            _ => None,
        });
    assert!(operator_mint_permissions.next().is_none());
    let signed = read_signed_genesis(&temp.path().join("genesis.signed.nrt"))
        .expect("read executed permissioned genesis");
    assert!(signed.network_entrypoint_count() > 0);
    signed
        .validate_output_merkle_cache()
        .expect("generated genesis retains its complete execution outputs");
    assert!(
        signed
            .output_results()
            .all(|result| result.as_ref().is_ok()),
        "faucet funding must execute successfully in the real generated genesis"
    );
    for peer_index in 0..opts.peers.get() {
        let source = TomlSource::from_file(temp.path().join(format!("peer{peer_index}.toml")))
            .expect("read generated permissioned peer config");
        let parsed = actual::Root::from_toml_source(source)
            .expect("parse generated permissioned peer config");
        assert!(parsed.torii.operator_signatures.enabled);
        assert!(parsed.torii.operator_signatures.allow_node_key);
        assert_eq!(
            parsed.torii.operator_signatures.allowed_public_keys,
            vec![
                localnet_test_sidecar_key(
                    &temp
                        .path()
                        .join(LOCALNET_RUNTIME_DIRECTORY)
                        .join(LOCALNET_OPERATOR_SIGNER_KEY_FILE)
                )
                .public_key()
                .clone()
            ],
            "generic localnet must authorize exactly its dedicated HTTP operator"
        );
        assert!(
            !parsed
                .torii
                .operator_signatures
                .allowed_public_keys
                .contains(&operator.public_key)
        );
        let faucet = parsed
            .torii
            .faucet
            .as_ref()
            .expect("native faucet admission");
        assert_eq!(faucet.authority, operator.account_id);
        assert_eq!(faucet.signer.public_key(), &operator.public_key);
        let fee_definition = faucet
            .asset_definition_id
            .parse::<AssetDefinitionId>()
            .expect("configured canonical faucet asset definition");
        assert_eq!(fee_definition, localnet_xor_asset_definition_id());
        let faucet_asset = AssetId::new(fee_definition, faucet.authority.clone());
        let minted = manifest
            .instructions()
            .filter_map(
                |instruction| match instruction.as_any().downcast_ref::<MintBox>() {
                    Some(MintBox::Asset(mint)) if mint.destination() == &faucet_asset => {
                        Some(mint.object().clone())
                    }
                    _ => None,
                },
            )
            .collect::<Vec<_>>();
        assert_eq!(
            minted,
            vec![
                Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
                Quantity::from(LOCALNET_FAUCET_AUTHORITY_BALANCE),
            ],
            "Permissioned faucet must receive its explicit Global allocation once"
        );
        assert!(Quantity::from(LOCALNET_FAUCET_AUTHORITY_BALANCE) > faucet.amount);
    }
}
#[test]
fn generated_nexus_localnet_mints_fee_asset_to_client_signer() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("Iroha".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let client_config: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("client.toml")).expect("read generated client"),
    )
    .expect("parse generated client");
    let client_public_key = client_config["account"]["public_key"]
        .as_str()
        .expect("generated client public key")
        .parse::<iroha_crypto::PublicKey>()
        .expect("canonical client public key");
    let operator =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("derive generated operator");
    assert_eq!(client_public_key, operator.public_key);
    let client_fee_asset = AssetId::new(
        localnet_xor_asset_definition_id(),
        AccountId::new(client_public_key),
    );
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated genesis");
    let minted = manifest
        .instructions()
        .filter_map(
            |instruction| match instruction.as_any().downcast_ref::<MintBox>() {
                Some(MintBox::Asset(mint)) if mint.destination() == &client_fee_asset => {
                    Some(mint.object().clone())
                }
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    assert!(
        !minted.is_empty(),
        "generated genesis should fund the client signer fee asset"
    );
    assert_eq!(
        minted,
        vec![
            Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
            Quantity::from(LOCALNET_FAUCET_AUTHORITY_BALANCE),
        ],
        "generated genesis should fund alias setup and the reused faucet signer exactly once each"
    );
}
#[test]
fn npos_localnet_seeds_exact_onboarding_fee_sponsor_program() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("typed-fee-sponsor".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29_080,
        base_p2p_port: 33_337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let (genesis_public_key, _) =
        generate_genesis_key_pair(opts.seed.as_deref().map(str::as_bytes), GENESIS_SEED)
            .expect("derive expected genesis sponsor");
    let expected_program = localnet_fee_sponsor_program_id(&AccountId::new(genesis_public_key));
    let expected_client = localnet_client_account_id();
    let manifest = localnet_genesis_for_opts(&opts);
    let created = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<CreateFeeSponsorProgram>()
        })
        .collect::<Vec<_>>();
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].program().id, expected_program);
    let staged = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<StageFeeSponsorProgramRevision>()
        })
        .collect::<Vec<_>>();
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].revision().program_id, expected_program);
    assert_eq!(staged[0].revision().revision, 1);
    staged[0]
        .revision()
        .validate()
        .expect("localnet sponsor revision must validate");
    let publish_manifest_wire_id = iroha_data_model::isi::registry::default()
        .wire_id(std::any::type_name::<PublishSpaceDirectoryManifest>())
        .expect("space-directory publication must be registered");
    assert!(staged[0].revision().rules.iter().any(|rule| {
        rule.selectors.iter().any(|selector| {
            matches!(
                selector,
                FeeSponsorRuleSelector::NativeInstruction(selector)
                    if selector.wire_id == publish_manifest_wire_id
            )
        })
    }));
    let enrollment = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<EnrollFeeSponsorBeneficiary>()
        })
        .find(|enrollment| enrollment.program_id() == &expected_program)
        .expect("client enrollment for exact localnet program");
    assert_eq!(enrollment.beneficiary(), &expected_client);
    let has_exact_permission = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant) if grant.destination() == &expected_client => {
                CanEnrollFeeSponsorProgram::try_from(grant.object()).ok()
            }
            _ => None,
        })
        .any(|permission| permission.program_id == expected_program);
    assert!(has_exact_permission);
}
#[test]
fn generated_nexus_localnet_serves_xor_faucet_from_client_signer() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-faucet-config".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read peer config"),
    )
    .expect("parse peer config");
    let faucet = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("faucet"))
        .and_then(toml::Value::as_table)
        .expect("torii faucet table");
    assert_eq!(
        faucet.get("enabled").and_then(toml::Value::as_bool),
        Some(true)
    );
    let operator =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("derive generated operator");
    let client_config: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("client.toml")).expect("read generated client"),
    )
    .expect("parse generated client");
    let client_public_key = client_config["account"]["public_key"]
        .as_str()
        .expect("generated client public key")
        .parse::<iroha_crypto::PublicKey>()
        .expect("canonical client public key");
    assert_eq!(client_public_key, operator.public_key);
    let expected_authority = operator.account_literal(None);
    let http_key = localnet_test_sidecar_key(
        &temp
            .path()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
    );
    let ledger_key = localnet_test_sidecar_key(
        &temp
            .path()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(LOCALNET_LEDGER_SIGNER_KEY_FILE),
    );
    assert_eq!(ledger_key.public_key(), &operator.public_key);
    assert_ne!(ledger_key.public_key(), http_key.public_key());
    let expected_fee_asset = localnet_xor_asset_literal();
    assert_eq!(
        faucet.get("authority").and_then(toml::Value::as_str),
        Some(expected_authority.as_str())
    );
    assert!(faucet.get("private_key").is_none());
    assert_eq!(
        faucet
            .get("private_key_file")
            .and_then(toml::Value::as_str)
            .map(PathBuf::from),
        Some(
            temp.path()
                .canonicalize()
                .expect("canonical localnet root")
                .join(LOCALNET_RUNTIME_DIRECTORY)
                .join(LOCALNET_LEDGER_SIGNER_KEY_FILE)
        )
    );
    assert_eq!(
        faucet
            .get("asset_definition_id")
            .and_then(toml::Value::as_str),
        Some(expected_fee_asset.as_str())
    );
    assert_eq!(
        faucet.get("amount").and_then(toml::Value::as_str),
        Some(LOCALNET_FAUCET_AMOUNT)
    );
    assert_eq!(
        faucet
            .get("pow_beacon_seed_enabled")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn generated_nexus_localnet_keeps_fee_asset_convertible_for_taira_wallets() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-fee-asset-convertible".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read peer config"),
    )
    .expect("parse peer config");
    // Native PIPA-R verification is chain policy (`zk_validity_policy_v1`, on by
    // protocol default); a generated node configuration carries no ZK
    // validity value.
    assert!(
        peer_cfg.get("zk").is_none(),
        "generated TAIRA configs must not carry chain-policy ZK values"
    );
    let manifest = genesis_json_from_path(&temp.path().join("genesis.json"));
    let raw_genesis =
        RawGenesisTransaction::from_path(temp.path().join("genesis.json")).expect("parse genesis");
    let fee_asset_id = localnet_xor_asset_literal();
    let fee_asset = manifest
        .get("transactions")
        .and_then(json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tx| tx.get("instructions").and_then(json::Value::as_array))
        .flatten()
        .find_map(|instruction| {
            let asset = instruction
                .get("Register")
                .and_then(|register| register.get("AssetDefinition"))?;
            (asset.get("id").and_then(json::Value::as_str) == Some(fee_asset_id.as_str()))
                .then_some(asset)
        })
        .expect("fee asset definition registration");
    assert_eq!(
        fee_asset.get("name").and_then(json::Value::as_str),
        Some("XOR"),
        "generated fee asset should surface as XOR in TAIRA UIs"
    );
    assert_eq!(
        fee_asset
            .get("spec")
            .and_then(|spec| spec.get("scale"))
            .and_then(json::Value::as_u64),
        Some(u64::from(LOCALNET_FEE_ASSET_SCALE)),
        "generated fee asset must use nano-XOR scale for fees and SNS charges"
    );
    assert!(
        fee_asset.get("confidential_policy").is_none(),
        "asset registration must not bypass canonical confidential verifier activation"
    );
    let unshield_vk_id = localnet_fee_vk_unshield_id();
    let zk_registration = raw_genesis
        .instructions()
        .find_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<iroha_data_model::isi::zk::RegisterZkAsset>()
        })
        .expect("generated fee asset must emit a RegisterZkAsset instruction");
    assert!(
        zk_registration.asset() == &localnet_xor_asset_definition_id(),
        "generated fee asset must emit a RegisterZkAsset instruction for shield flows"
    );
    assert_eq!(
        zk_registration.vk_unshield(),
        &Some(unshield_vk_id.clone()),
        "generated fee asset must advertise an unshield verifier for withdrawals"
    );
    let vk_registrations = raw_genesis
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<verifying_keys::RegisterVerifyingKey>()
        })
        .collect::<Vec<_>>();
    assert!(
        vk_registrations.iter().any(|register| {
            register.id == unshield_vk_id
                && register.record.is_active()
                && register.record.key.is_some()
                && register.record.max_proof_bytes > 0
                && register.record.circuit_id
                    == confidential_v2::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID
        }),
        "generated fee asset must register an active confidential unshield verifier"
    );
}
#[test]
fn generated_fee_unshield_verifier_uses_canonical_native_registry_material() {
    use iroha_core_zk::{
        PreparedVerifyingKeyMaterialV1, native_pipa_r, validate_and_prepare_verifying_key_record_v1,
    };
    use iroha_data_model::zk::BackendTag;

    let [(id, record)] = localnet_confidential_fee_vk_registrations().unwrap();
    assert_eq!(id.backend, native_pipa_r::BACKEND);
    assert_eq!(record.backend, BackendTag::NativePipaRPasta);
    assert_eq!(record.curve, "vesta");
    assert_eq!(
        record.circuit_id,
        confidential_v2::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID
    );
    let key = record.key.as_ref().expect("the generated key is inline");
    assert_eq!(key.backend, id.backend);
    let original_key_ptr = key.bytes.as_ptr();
    let original_key_len = key.bytes.len();
    let original_commitment = record.commitment;
    let expected = Some(PreparedVerifyingKeyMaterialV1::NativePipaRPasta {
        ipa_k: native_pipa_r::NativeRelationV1::ConfidentialFullUnshield.k(),
    });
    assert_eq!(
        validate_and_prepare_verifying_key_record_v1(&id, &record).unwrap(),
        expected
    );

    let retired_id = VerifyingKeyId::new("halo2/ipa", id.name.clone());
    assert!(retired_id.is_portable_registry_id());
    assert_eq!(
        iroha_data_model::zk::verifier_backend_registry_tag_v1(&retired_id.backend),
        None
    );
    assert_eq!(
        validate_and_prepare_verifying_key_record_v1(&retired_id, &record).unwrap_err(),
        "verifying-key record backend does not match the production registry backend"
    );
    assert_eq!(
        validate_and_prepare_verifying_key_record_v1(&id, &record).unwrap(),
        expected,
        "retired-ID refusal must leave the same original key admissible"
    );
    let retry_key = record.key.as_ref().unwrap();
    assert_eq!(retry_key.bytes.as_ptr(), original_key_ptr);
    assert_eq!(retry_key.bytes.len(), original_key_len);
    assert_eq!(iroha_core_zk::hash_vk(retry_key), original_commitment);
}
#[test]
fn canonical_host_formats_ipv6_literals_and_urls() {
    let host = CanonicalHost::parse("::1", "--public-host").expect("ipv6 host");
    let literal = host.addr_literal(8080);
    let body = literal::parse("addr", &literal).expect("parse addr literal");
    assert_eq!(body, "[::1]:8080");
    assert_eq!(host.url_host(), "[::1]");
}
#[test]
fn canonical_host_lowercases_names() {
    let host = CanonicalHost::parse("LOCALHOST", "--public-host").expect("host");
    let literal = host.addr_literal(1337);
    let body = literal::parse("addr", &literal).expect("parse addr literal");
    assert_eq!(body, "localhost:1337");
    assert_eq!(host.url_host(), "localhost");
}
#[test]
fn canonical_host_rejects_host_with_port() {
    let err = CanonicalHost::parse("127.0.0.1:8080", "--public-host")
        .expect_err("host with port should fail");
    assert!(err.to_string().contains("without a port"));
}
#[test]
fn canonical_host_rejects_unbalanced_brackets() {
    let err = CanonicalHost::parse("[::1", "--public-host")
        .expect_err("missing closing bracket should fail");
    assert!(err.to_string().contains("unmatched"));
    let err = CanonicalHost::parse("::1]", "--public-host")
        .expect_err("missing opening bracket should fail");
    assert!(err.to_string().contains("unmatched"));
}
#[test]
fn canonical_host_rejects_non_dns_names_and_injection_characters() {
    for raw in [
        " example.test",
        "example.test ",
        "example.test/path",
        "example.test\nnext",
        "example\".test",
        "$(command)",
        "-leading.example",
        "trailing-.example",
        "two..labels",
        "[localhost]",
    ] {
        let _error = CanonicalHost::parse(raw, "--public-host")
            .expect_err("noncanonical or injectable host must fail");
    }
    let host =
        CanonicalHost::parse("Node-1.Example.Test", "--public-host").expect("canonical DNS host");
    assert_eq!(host.url_host(), "node-1.example.test");
}
#[test]
fn client_config_renders_ipv6_torii_url() {
    let tmp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let root = crate::localnet::custody::prepare_empty_private_directory(tmp.path())
        .expect("prepare private client config directory");
    let host = CanonicalHost::parse("::1", "--public-host").expect("ipv6 host");
    write_client_config(
        &root,
        8080,
        &host,
        DEFAULT_CHAIN_ID,
        None,
        &localnet_client_identity(None, false).expect("default client"),
        None,
    )
    .expect("write client config");
    let contents = fs::read_to_string(root.join("client.toml")).expect("read client config");
    assert!(contents.contains("torii_url = \"http://[::1]:8080/\""));
}
#[test]
fn localnet_readme_records_only_base_seed_fingerprint_when_present() {
    let tmp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let shell_out_dir = crate::shell::quote_path(tmp.path()).expect("quote temp path");
    let runtime_bundle = LocalnetRuntimeBundle {
        ledger_signer_key: tmp.path().join(LOCALNET_LEDGER_SIGNER_KEY_FILE),
        operator_signer_key: tmp.path().join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
        onboarding_signer_key: tmp.path().join(LOCALNET_ONBOARDING_SIGNER_KEY_FILE),
        onboarding_token_file: tmp.path().join(LOCALNET_ONBOARDING_TOKEN_FILE),
        onboarding_token_hash: [0; 32],
    };
    write_localnet_readme(
        tmp.path(),
        DEFAULT_CHAIN_ID,
        Some("Iroha"),
        SumeragiConsensusMode::Npos,
        4,
        "http://127.0.0.1:29080/",
        &tmp.path().join("genesis.json"),
        &tmp.path().join("genesis.signed.nrt"),
        &tmp.path().join(GENESIS_EXPECTED_HASH_FILE),
        &tmp.path().join(GENESIS_PUBLIC_KEY_FILE),
        &tmp.path().join(GENESIS_PRIVATE_KEY_FILE),
        &tmp.path().join("client.toml"),
        &tmp.path().join("start.sh"),
        &tmp.path().join("stop.sh"),
        &localnet_client_account_literal(None),
        &localnet_client_account_literal(None),
        &runtime_bundle,
        &tmp.path().join(LOCALNET_ALIAS_SETUP_INTENT_FILE),
        &shell_out_dir,
    )
    .expect("write readme");
    let contents = fs::read_to_string(tmp.path().join("README.md")).expect("read readme");
    let fingerprint = blake3::hash(b"Iroha").to_hex();
    assert!(contents.contains(&format!("- Base seed BLAKE3 fingerprint: `{fingerprint}`")));
    assert!(!contents.contains("- Base seed: `Iroha`"));
    assert!(!contents.contains("`Iroha`"));
    assert!(contents.contains("genesis.expected_hash"));
    assert!(contents.contains("`kagami docker` without `--seed`"));
    assert!(!contents.contains("IROHA_GENESIS_SIGNED_FILE"));
    assert!(!contents.contains("IROHA_GENESIS_EXPECTED_HASH_FILE"));
    assert!(!contents.contains("IROHA_GENESIS_PRIVATE_KEY_FILE"));
    assert!(contents.contains("- Ephemeral ledger administrator: `"));
    assert!(contents.contains("- Ledger/faucet signer sidecar: `"));
    assert!(contents.contains("- Dedicated HTTP operator signer sidecar: `"));
    assert!(contents.contains("- Ephemeral onboarding authority: `"));
    assert!(!contents.contains("Localnet app authority / escrow account"));
}
#[test]
fn private_custody_readme_invokes_lifecycle_scripts_through_bash() {
    let tmp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let shell_out_dir = crate::shell::quote_path(tmp.path()).expect("quote temp path");
    let runtime_bundle = LocalnetRuntimeBundle {
        ledger_signer_key: tmp.path().join(LOCALNET_LEDGER_SIGNER_KEY_FILE),
        operator_signer_key: tmp.path().join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
        onboarding_signer_key: tmp.path().join(LOCALNET_ONBOARDING_SIGNER_KEY_FILE),
        onboarding_token_file: tmp.path().join(LOCALNET_ONBOARDING_TOKEN_FILE),
        onboarding_token_hash: [0; 32],
    };
    write_localnet_readme(
        tmp.path(),
        DEFAULT_CHAIN_ID,
        None,
        SumeragiConsensusMode::Npos,
        4,
        "http://127.0.0.1:29080/",
        &tmp.path().join("genesis.json"),
        &tmp.path().join("genesis.signed.nrt"),
        &tmp.path().join(GENESIS_EXPECTED_HASH_FILE),
        &tmp.path().join(GENESIS_PUBLIC_KEY_FILE),
        &tmp.path().join(GENESIS_PRIVATE_KEY_FILE),
        &tmp.path().join("client.toml"),
        &tmp.path().join("start.sh"),
        &tmp.path().join("stop.sh"),
        &localnet_client_account_literal(None),
        &localnet_client_account_literal(None),
        &runtime_bundle,
        &tmp.path().join(LOCALNET_ALIAS_SETUP_INTENT_FILE),
        &shell_out_dir,
    )
    .expect("write private-custody readme");
    let contents = fs::read_to_string(tmp.path().join("README.md")).expect("read readme");
    assert!(contents.lines().any(|line| line == "bash ./start.sh"));
    assert!(contents.lines().any(|line| line == "bash ./stop.sh"));
    assert!(!contents.lines().any(|line| line == "sh ./start.sh"));
    assert!(!contents.lines().any(|line| line == "sh ./stop.sh"));
    assert!(!contents.lines().any(|line| line == "./start.sh"));
    assert!(!contents.lines().any(|line| line == "./stop.sh"));
}
#[test]
fn omitted_seed_uses_independent_os_random_keys() {
    let peer_index = 0_u16.to_be_bytes();
    let (first_public, first_private) = generate_streaming_identity_key_pair(None, &peer_index)
        .expect("generate first streaming identity");
    let (second_public, second_private) = generate_streaming_identity_key_pair(None, &peer_index)
        .expect("generate second streaming identity");
    assert_ne!(first_public, second_public);
    assert_ne!(first_private.to_string(), second_private.to_string());
}
#[cfg(all(
    unix,
    not(any(target_os = "espidf", target_os = "horizon", target_os = "redox"))
))]
#[test]
fn localnet_refuses_to_mix_with_existing_output() {
    let output =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("localnet output");
    fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700))
        .expect("harden localnet output directory");
    let sentinel = output.path().join("keep.txt");
    fs::write(&sentinel, b"do not overwrite").expect("write sentinel");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("nonzero peers"),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29_080,
        base_p2p_port: 33_337,
        out_dir: output.path().to_owned(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    let error = generate_localnet(&opts, &mut BufWriter::new(Vec::new()))
        .expect_err("non-empty output must be rejected");
    assert!(format!("{error:#}").contains("must be empty"));
    assert_eq!(
        fs::read(sentinel).expect("read sentinel"),
        b"do not overwrite"
    );
}
fn localnet_test_sidecar_key(path: &Path) -> KeyPair {
    let record = Zeroizing::new(fs::read_to_string(path).expect("read fixture signer sidecar"));
    let private = record
        .trim()
        .parse::<ExposedPrivateKey>()
        .expect("decode fixture signer");
    KeyPair::from_private_key(private.0).expect("derive fixture signer public key")
}

#[test]
fn localnet_runtime_bundle_separates_ledger_and_http_operator_custody() {
    let seed = Some(b"localnet-separated-custody".as_slice());
    let ledger = localnet_ephemeral_identity(seed, b"operator-root").expect("ledger identity");
    let http = localnet_ephemeral_identity(seed, b"http-operator-root").expect("HTTP identity");
    let onboarding =
        localnet_ephemeral_identity(seed, b"onboarding-root").expect("onboarding identity");
    assert_eq!(
        http.public_key,
        localnet_ephemeral_identity(seed, b"http-operator-root")
            .unwrap()
            .public_key
    );
    assert_ne!(ledger.public_key, http.public_key);
    let root =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("runtime bundle parent");
    let bundle = write_localnet_runtime_bundle(root.path(), &ledger, &http, &onboarding)
        .expect("write separated runtime bundle");
    assert_eq!(
        localnet_test_sidecar_key(&bundle.ledger_signer_key).public_key(),
        &ledger.public_key
    );
    assert_eq!(
        localnet_test_sidecar_key(&bundle.operator_signer_key).public_key(),
        &http.public_key
    );
    assert_eq!(
        localnet_test_sidecar_key(&bundle.onboarding_signer_key).public_key(),
        &onboarding.public_key
    );
    for path in [
        &bundle.ledger_signer_key,
        &bundle.operator_signer_key,
        &bundle.onboarding_signer_key,
    ] {
        assert!(path.is_file());
        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(path).expect("signer custody metadata");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
    }
    for (ledger, http, onboarding) in [
        (&ledger, &ledger, &onboarding),
        (&ledger, &http, &ledger),
        (&ledger, &http, &http),
    ] {
        let rejected = crate::localnet::localnet_test_helpers::private_tempdir()
            .expect("rejected bundle parent");
        assert!(write_localnet_runtime_bundle(rejected.path(), ledger, http, onboarding).is_err());
        assert!(!rejected.path().join(LOCALNET_RUNTIME_DIRECTORY).exists());
    }
}

#[test]
fn onboarding_tokens_remain_random_with_reproducible_identity_keys() {
    let operator = localnet_ephemeral_identity(Some(b"fixed-localnet-seed"), b"operator-root")
        .expect("derive operator identity");
    let onboarding = localnet_ephemeral_identity(Some(b"fixed-localnet-seed"), b"onboarding-root")
        .expect("derive onboarding identity");
    let first =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("first runtime parent");
    let second =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("second runtime parent");
    let http_operator =
        localnet_ephemeral_identity(Some(b"fixed-localnet-seed"), b"http-operator-root")
            .expect("derive HTTP operator identity");
    let first_bundle =
        write_localnet_runtime_bundle(first.path(), &operator, &http_operator, &onboarding)
            .expect("write first runtime bundle");
    let second_bundle =
        write_localnet_runtime_bundle(second.path(), &operator, &http_operator, &onboarding)
            .expect("write second runtime bundle");
    assert_ne!(
        first_bundle.onboarding_token_hash, second_bundle.onboarding_token_hash,
        "a reproducible key seed must never make API tokens reproducible"
    );
    let first_token = fs::read_to_string(first_bundle.onboarding_token_file)
        .expect("read first onboarding token");
    let second_token = fs::read_to_string(second_bundle.onboarding_token_file)
        .expect("read second onboarding token");
    assert_ne!(first_token, second_token);
}
fn mandatory_da_localnet_options(out_dir: PathBuf) -> LocalnetOptions {
    LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("mandatory-da".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 19090,
        base_p2p_port: 23347,
        out_dir,
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    }
}
fn assert_da_is_protocol_invariant_not_configuration() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = mandatory_da_localnet_options(temp.path().to_path_buf());
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let sumeragi = peer_cfg
        .get("sumeragi")
        .and_then(toml::Value::as_table)
        .expect("sumeragi table");
    for retired in ["da", "collectors", "rbc"] {
        assert!(
            !sumeragi.contains_key(retired),
            "node-local config must not contain sumeragi.{retired}"
        );
    }
    let manifest_json = fs::read_to_string(temp.path().join("genesis.json"))
        .expect("read generated genesis manifest");
    assert!(!manifest_json.contains("da_enabled"));
    assert!(!manifest_json.contains("collectors_k"));
}
#[test]
fn localnet_omits_retired_da_configuration() {
    assert_da_is_protocol_invariant_not_configuration();
}
#[test]
fn rejects_overflowing_port_ranges() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: u16::MAX,
        base_p2p_port: 10,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let mut sink = BufWriter::new(Vec::<u8>::new());
    let err = generate_localnet(&opts, &mut sink).expect_err("port overflow should fail");
    assert!(
        err.to_string().contains("base_api_port"),
        "unexpected error: {err}"
    );
}
#[test]
fn rejects_overlapping_port_ranges() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 1337,
        base_p2p_port: 1337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let mut sink = BufWriter::new(Vec::<u8>::new());
    let err = generate_localnet(&opts, &mut sink).expect_err("overlapping ports should fail");
    assert!(
        err.to_string().contains("overlap"),
        "unexpected error: {err}"
    );
}
#[test]
fn rejects_zero_ports() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 0,
        base_p2p_port: 1000,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let mut sink = BufWriter::new(Vec::<u8>::new());
    let err = generate_localnet(&opts, &mut sink).expect_err("zero port should fail");
    assert!(
        err.to_string().contains("must be > 0"),
        "unexpected error: {err}"
    );
}
#[test]
fn validate_localnet_options_rejects_zero_block_cadence() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(0),
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let err = validate_localnet_options(&opts).expect_err("zero block cadence should fail");
    assert!(
        err.to_string().contains("--block-cadence-ms"),
        "unexpected error: {err}"
    );
}
#[test]
fn validate_localnet_options_rejects_roster_above_protocol_maximum() {
    let oversized =
        u16::try_from(MAX_VALIDATORS_PER_HEIGHT + 1).expect("protocol test boundary fits u16");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(oversized).expect("non-zero"),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28_080,
        base_p2p_port: 28_337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let error = validate_localnet_options(&opts)
        .expect_err("the CLI must reject a roster above the wire-protocol limit");
    let expected = format!(
        "`--peers` ({oversized}) exceeds the Sumeragi protocol maximum validator roster of {MAX_VALIDATORS_PER_HEIGHT}"
    );
    assert!(
        error.to_string().contains(&expected),
        "unexpected error: {error}"
    );
}
#[test]
fn validate_localnet_options_rejects_non_three_f_plus_one_roster() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(5).expect("non-zero"),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28_080,
        base_p2p_port: 28_337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let error = validate_localnet_options(&opts)
        .expect_err("the CLI must reject a non-3f+1 validator roster");
    assert!(
        error.to_string().contains("exact Sumeragi 3f+1"),
        "unexpected error: {error}"
    );
}
#[test]
fn validate_localnet_options_rejects_every_profile_with_too_few_peers() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(3).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let err = validate_localnet_options(&opts)
        .expect_err("every generated localnet should enforce the minimum peer count");
    assert!(
        err.to_string().contains("`--peers` must be at least 4"),
        "unexpected error: {err}"
    );
}
#[test]
fn validate_localnet_options_rejects_permissioned_on_sora_nexus() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    let err = validate_localnet_options(&opts).expect_err("sora nexus should require NPoS");
    assert!(
        err.to_string().contains("sora-profile"),
        "unexpected error: {err}"
    );
}
#[test]
fn validate_localnet_options_rejects_permissioned_on_sora_dataspace() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Dataspace),
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    let err = validate_localnet_options(&opts).expect_err("sora profile should require NPoS");
    assert!(
        err.to_string().contains("sora-profile"),
        "unexpected error: {err}"
    );
}
#[test]
fn validate_localnet_options_allows_permissioned_localnet() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    validate_localnet_options(&opts).expect("permissioned localnet should be allowed");
}
#[test]
fn permissioned_localnet_uses_mandatory_nexus_default() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: Some("permissioned-localnet".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new()))
        .expect("generate permissioned localnet");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let nexus = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .expect("nexus table");
    assert!(
        !nexus.contains_key("enabled"),
        "generated configs must not expose the retired Nexus availability switch"
    );
    assert_eq!(
        nexus["storage"]["local_budget_bytes"].as_integer(),
        Some(i64::try_from(LOCALNET_NEXUS_STORAGE_BUDGET_BYTES).unwrap()),
        "mandatory Nexus storage must have a finite developer cap in permissioned mode"
    );
}
#[test]
#[allow(clippy::too_many_lines)] // End-to-end config assertions are kept together for this localnet scenario.
fn npos_without_sora_profile_uses_mandatory_nexus() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: Some("npos-localnet".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_string(),
        public_host: DEFAULT_PUBLIC_HOST.to_string(),
        base_api_port: 28080,
        base_p2p_port: 28337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate npos localnet");
    let seed_bytes = opts.seed.as_ref().map(String::as_bytes);
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let nexus = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .expect("nexus table");
    assert!(
        !nexus.contains_key("enabled"),
        "generated configs must rely on mandatory Nexus"
    );
    assert_eq!(
        nexus
            .get("storage")
            .and_then(toml::Value::as_table)
            .and_then(|storage| storage.get("local_budget_bytes"))
            .and_then(toml::Value::as_integer),
        Some(
            i64::try_from(LOCALNET_NEXUS_STORAGE_BUDGET_BYTES)
                .expect("localnet Nexus storage budget fits i64")
        ),
        "npos iroha3 localnet should use an explicit disposable storage budget"
    );
    let gas_account_id = account_id_runtime_literal(&gas_account_id, None);
    let staking = nexus
        .get("staking")
        .and_then(toml::Value::as_table)
        .expect("nexus staking table");
    let expected_stake_asset_id = localnet_xor_asset_literal();
    let expected_fee_asset_id = localnet_xor_asset_literal();
    assert_eq!(
        staking.get("stake_asset_id").and_then(toml::Value::as_str),
        Some(expected_stake_asset_id.as_str())
    );
    assert_eq!(
        staking
            .get("stake_escrow_account_id")
            .and_then(toml::Value::as_str),
        Some(gas_account_id.as_str())
    );
    assert_eq!(
        staking
            .get("slash_sink_account_id")
            .and_then(toml::Value::as_str),
        Some(gas_account_id.as_str())
    );
    let fees = nexus
        .get("fees")
        .and_then(toml::Value::as_table)
        .expect("nexus fees table");
    assert_eq!(
        fees.get("fee_asset_id").and_then(toml::Value::as_str),
        Some(expected_fee_asset_id.as_str())
    );
    assert_eq!(
        fees.get("base_fee").and_then(toml::Value::as_str),
        Some("0")
    );
    assert_eq!(
        fees.get("per_instruction_fee")
            .and_then(toml::Value::as_str),
        Some("0.001")
    );
    assert_eq!(
        fees.get("per_gas_unit_fee").and_then(toml::Value::as_str),
        Some("0.00005")
    );
    assert_eq!(
        fees.get("settlement_mode").and_then(toml::Value::as_str),
        Some("direct")
    );
    assert_eq!(
        fees.get("fee_sink_account_id")
            .and_then(toml::Value::as_str),
        Some(gas_account_id.as_str())
    );
    assert_eq!(
        fees.get("sponsor_vault_custody_account_id")
            .and_then(toml::Value::as_str),
        Some(gas_account_id.as_str())
    );
    let pipeline = peer_cfg
        .get("pipeline")
        .and_then(toml::Value::as_table)
        .expect("pipeline table");
    assert!(
        pipeline.get("gas").is_none(),
        "fee policy is committed chain state"
    );
    let manifest = genesis_json_from_path(&temp.path().join("genesis.json"));
    let parameters = genesis_parameters(&manifest);
    let projected = iroha_core::state::StateParameters::try_from(parameters).unwrap();
    assert_eq!(
        AccountId::parse_encoded(&projected.gas().tech_account_id).unwrap(),
        localnet_gas_account_id(&genesis_public_key),
        "the same deterministic custody account is pinned in signed parameters"
    );
}
include!("../private_fee_and_account_tests.rs");
#[test]
fn localnet_gas_custody_derivation_is_deterministic() {
    let genesis = KeyPair::try_from_seed(
        b"localnet-gas-custody-genesis-v1".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
    .expect("fixture genesis key");
    let custody = localnet_gas_account_id(genesis.public_key());
    assert_eq!(custody, localnet_gas_account_id(genesis.public_key()));
    assert_ne!(custody, AccountId::new(genesis.public_key().clone()));
}

#[test]
fn localnet_gas_custody_parameter_projects_the_original_account() {
    let custody = localnet_gas_account_id(KeyPair::random().public_key());
    let mut parameters = Parameters::default();
    parameters.set_parameter(localnet_gas_custody_parameter(&custody));
    let projected = iroha_core::state::StateParameters::try_from(parameters).unwrap();
    assert_eq!(
        AccountId::parse_encoded(&projected.gas().tech_account_id).unwrap(),
        custody
    );
    assert!(
        projected.gas().accepted_assets.is_empty(),
        "pinning a receiver alone enables no fee asset"
    );
}
#[test]
fn localnet_gas_custody_is_bound_to_genesis_identity() {
    let first = KeyPair::try_from_seed(
        b"localnet-gas-custody-first-genesis-v1".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
    .expect("first fixture genesis key");
    let second = KeyPair::try_from_seed(
        b"localnet-gas-custody-second-genesis-v1".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
    .expect("second fixture genesis key");
    assert_ne!(
        localnet_gas_account_id(first.public_key()),
        localnet_gas_account_id(second.public_key())
    );
}
#[test]
fn localnet_gas_custody_rejects_the_public_seed_signer() {
    let genesis = KeyPair::try_from_seed(
        b"localnet-gas-custody-public-seed-attack-v1".to_vec(),
        iroha_crypto::Algorithm::Ed25519,
    )
    .expect("fixture genesis key");
    // Reproduce the exposed signer using only public genesis material.
    let public_seed = genesis
        .public_key()
        .to_string()
        .bytes()
        .chain(b"localnet-gas-account".iter().copied())
        .collect();
    let exposed = KeyPair::try_from_seed(public_seed, iroha_crypto::Algorithm::Ed25519)
        .expect("public seed derives its exposed signer");
    let custody = localnet_gas_account_id(genesis.public_key());
    assert_ne!(custody, AccountId::new(exposed.public_key().clone()));
    let payload = b"ordinary transfer attempting to drain protocol custody";
    let signature = iroha_crypto::Signature::new(exposed.private_key(), payload);
    signature
        .verify(exposed.public_key(), payload)
        .expect("control signature must verify for the exposed account");
    assert!(
        signature
            .verify(custody.expect_single_signatory(), payload)
            .is_err(),
        "publicly derived signing material must not authorize custody debits"
    );
}
#[test]
fn account_id_runtime_literal_uses_encoded_literal() {
    let seed_bytes = Some(b"localnet-gas-runtime-literal".as_slice());
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let literal = account_id_runtime_literal(&gas_account_id, None);
    assert_eq!(literal, gas_account_id.to_string());
}
#[test]
fn account_id_runtime_literal_respects_requested_chain_discriminant() {
    let seed_bytes = Some(b"localnet-gas-runtime-taira".as_slice());
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let literal = account_id_runtime_literal(&gas_account_id, Some(369));
    assert!(
        literal.starts_with("test"),
        "expected testnet i105 literal, got {literal}"
    );
    assert!(
        !literal.starts_with("sora"),
        "localnet runtime literal must not use mainnet prefix under Taira"
    );
}
#[test]
fn default_sorafs_telemetry_submitters_match_self_service_policy() {
    let submitters = iroha_config::parameters::defaults::governance::sorafs_telemetry::submitters();
    assert!(
        submitters.is_empty(),
        "self-service telemetry should not pin default submitter accounts"
    );
}
#[test]
fn localnet_npos_bootstrap_does_not_re_register_genesis_account() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-genesis-account-dedupe".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 31080,
        base_p2p_port: 31337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let manifest = localnet_genesis_for_opts(&opts);
    let seed_bytes = opts.seed.as_ref().map(String::as_bytes);
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let genesis_account_id = AccountId::new(genesis_public_key.clone());
    let ivm_genesis_registrations = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<Register<Account>>())
        .filter(|register| register.object.id == genesis_account_id)
        .count();
    assert_eq!(
        ivm_genesis_registrations, 0,
        "expected NPoS bootstrap to avoid re-registering the genesis controller under ivm"
    );
}
include!("../path_and_script_tests.rs");
#[cfg(unix)]
#[test]
fn start_script_includes_sora_flag_when_enabled() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let client_account_literal = localnet_client_account_literal(None);
    let fee_asset_definition_id = localnet_xor_asset_literal();
    write_scripts(
        temp.path(),
        1,
        true,
        false,
        &client_account_literal,
        &fee_asset_definition_id,
    )
    .expect("write scripts");
    let start_contents =
        fs::read_to_string(temp.path().join("start.sh")).expect("read start script");
    assert!(
        start_contents.contains("if env.get(\"IROHA_SORA_MODE\") == \"1\":")
            && start_contents.contains("cmd.append(\"--sora\")")
            && start_contents.contains("cmd.extend([\"--config\", env[\"IROHA_PEER_CONFIG\"]])"),
        "validator launcher must include --sora when profile enabled"
    );
}
// Keep the generated rANS table contract tests in a focused child under `localnet::tests`.
include!("../rans_table_tests.rs");

#[test]
fn validator_bls_keys_use_private_entropy_unless_development_seed_is_explicit() {
    let first = build_peers(4, None, 8080, 1337).expect("OS entropy");
    let second = build_peers(4, None, 8080, 1337).expect("independent OS entropy");
    assert_ne!(first[0].public_key, second[0].public_key);
    let development = build_peers(4, Some(b"explicit-development-only"), 8080, 1337).unwrap();
    let repeat = build_peers(4, Some(b"explicit-development-only"), 8080, 1337).unwrap();
    for (peer, repeated) in development.iter().zip(&repeat) {
        assert_eq!(peer.public_key, repeated.public_key);
        assert_eq!(peer.private_key, repeated.private_key);
        assert_eq!(peer.bls_pop, repeated.bls_pop);
        iroha_crypto::bls_normal_pop_verify(&peer.public_key, &peer.bls_pop).unwrap();
    }
    assert_ne!(development[0].public_key, development[1].public_key);
    let another = build_peers(4, Some(b"another-development-seed"), 8080, 1337).unwrap();
    assert_ne!(development[0].public_key, another[0].public_key);
}

#[test]
fn localnet_genesis_signing_rejects_incomplete_duplicate_and_invalid_pop_rosters() {
    let seed = b"exact-genesis-validator-roster";
    let mut peers = build_peers(4, Some(seed), 8080, 1337).unwrap();
    let (public, private) = generate_genesis_key_pair(Some(seed), GENESIS_SEED).unwrap();
    let key_pair = KeyPair::from_private_key(private.0).unwrap();
    let raw = generate_raw_genesis(
        &public,
        SumeragiConsensusMode::Permissioned,
        "roster-refusal",
    )
    .unwrap();
    let incomplete = append_peer_pop(raw.clone(), &peers[..3]).unwrap();
    assert!(incomplete.build_and_sign(&key_pair).is_err());
    let mut duplicate = peers
        .iter()
        .map(|peer| {
            GenesisTopologyEntry::new(PeerId::new(peer.public_key.clone()), peer.bls_pop.clone())
        })
        .collect::<Vec<_>>();
    duplicate[1] = duplicate[0].clone();
    let duplicate = raw
        .clone()
        .into_builder()
        .next_transaction()
        .set_topology(duplicate)
        .build_raw()
        .unwrap();
    assert!(duplicate.build_and_sign(&key_pair).is_err());
    peers[0].bls_pop[0] ^= 1;
    let invalid_pop = append_peer_pop(raw, &peers).unwrap();
    assert!(invalid_pop.build_and_sign(&key_pair).is_err());
}

#[test]
fn taira_private_output_rejects_git_directory_and_worktree_pointer() {
    let root =
        crate::localnet::localnet_test_helpers::private_tempdir().expect("private output test");
    let output = root.path().join("future/runtime/output");
    require_taira_private_output_outside_git(&output).expect("outside checkout");
    fs::create_dir(root.path().join(".git")).expect("repository marker");
    assert!(require_taira_private_output_outside_git(&output).is_err());
    fs::remove_dir(root.path().join(".git")).expect("remove directory marker");
    fs::write(
        root.path().join(".git"),
        "gitdir: /unused/worktree/metadata",
    )
    .expect("worktree pointer marker");
    assert!(require_taira_private_output_outside_git(&output).is_err());
    assert!(
        !output.exists(),
        "rejected request must not create runtime output"
    );
}

#[test]
fn localnet_chain_discriminant_preserves_defaults_and_fixed_public_prefixes() {
    assert_eq!(
        resolve_localnet_chain_discriminant(DEFAULT_CHAIN_ID, None).unwrap(),
        None
    );
    assert_eq!(
        resolve_localnet_chain_discriminant(DEFAULT_CHAIN_ID, Some(369)).unwrap(),
        Some(369)
    );
    for chain in [PUBLIC_TAIRA_CHAIN_ID, PUBLIC_NEXUS_CHAIN_ID] {
        let fixed = known_chain_discriminant_for_chain_id(chain).expect("known public prefix");
        assert_eq!(
            resolve_localnet_chain_discriminant(chain, None).unwrap(),
            Some(fixed)
        );
        assert_eq!(
            resolve_localnet_chain_discriminant(chain, Some(fixed)).unwrap(),
            Some(fixed)
        );
        assert!(resolve_localnet_chain_discriminant(chain, Some(fixed.wrapping_add(1))).is_err());
    }
}
