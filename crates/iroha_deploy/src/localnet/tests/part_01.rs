#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::{
    env, fs,
    io::BufWriter,
    path::{Path, PathBuf},
};
include!("../runtime_artifact_tests.rs");

#[test]
fn parent_admission_is_explicit_and_exclusive_to_global_localnets() {
    let seed = b"localnet-private-root-admission";
    let (genesis_public_key, _) = generate_genesis_key_pair(Some(seed), GENESIS_SEED).unwrap();
    let chain_id = "disposable-parent-localnet";
    let original = generate_raw_genesis(
        &genesis_public_key,
        SumeragiConsensusMode::Permissioned,
        chain_id,
    )
    .unwrap();
    let policy_id = PrivateDataspaceAdmissionPolicy::parameter_id();
    assert!(
        !original
            .effective_parameters()
            .unwrap()
            .custom()
            .contains_key(&policy_id)
    );
    let enabled = append_localnet_private_root_admission_policy(original.clone(), chain_id)
        .unwrap()
        .effective_parameters()
        .unwrap();
    assert_eq!(
        PrivateDataspaceAdmissionPolicy::from_custom_parameter(
            enabled.custom().get(&policy_id).unwrap()
        )
        .unwrap(),
        PrivateDataspaceAdmissionPolicy {
            max_registered_roots: 64,
            max_roots_per_owner: 8,
        }
    );
    let public =
        append_localnet_private_root_admission_policy(original.clone(), PUBLIC_TAIRA_CHAIN_ID)
            .unwrap();
    assert!(
        !public
            .effective_parameters()
            .unwrap()
            .custom()
            .contains_key(&policy_id)
    );

    let mut context = original.sumeragi_context_parameters().clone();
    context.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"parent admission fixture")),
        ),
        dataspace_id: DataSpaceId::new(u64::MAX),
    };
    let private = original
        .into_builder()
        .with_sumeragi_context_parameters(context)
        .build_raw()
        .unwrap();
    let private = append_localnet_private_root_admission_policy(private, chain_id).unwrap();
    assert!(
        !private
            .effective_parameters()
            .unwrap()
            .custom()
            .contains_key(&policy_id)
    );
}

#[test]
fn asset_extension_preserves_global_prefix_and_scoped_home_owners() {
    let _chain_discriminant = ChainDiscriminantGuard::enter(
        known_chain_discriminant_for_chain_id(PUBLIC_TAIRA_CHAIN_ID).unwrap(),
    );
    let seed = b"explicit-localnet-asset-phases";
    let peers = build_peers(4, Some(seed), 8_080, 13_337).unwrap();
    let (genesis_public_key, _) = generate_genesis_key_pair(Some(seed), GENESIS_SEED).unwrap();
    let genesis_account_id = AccountId::new(genesis_public_key.clone());
    let original = generate_raw_genesis(
        &genesis_public_key,
        SumeragiConsensusMode::Npos,
        PUBLIC_TAIRA_CHAIN_ID,
    )
    .unwrap();
    let asset = AssetSpec {
        id: AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("phase.paynet").unwrap(),
            "asset".parse().unwrap(),
        )
        .to_string(),
        name: "Explicit phase asset".to_owned(),
        alias: Some("asset#phase.paynet".to_owned()),
        owned_by: localnet_client_account_id(),
        mint_to: localnet_client_account_id(),
        quantity: 5,
    };
    let extended = extend_genesis(
        original.clone(),
        &genesis_account_id,
        Some(seed),
        0,
        std::slice::from_ref(&asset),
    )
    .unwrap();
    assert_eq!(
        extended.transactions().len(),
        original.transactions().len() + 2
    );
    let original_prefix = original.instructions().collect::<Vec<_>>();
    assert_eq!(
        &extended.instructions().collect::<Vec<_>>()[..original_prefix.len()],
        original_prefix,
        "every original instruction and value precedes the exact appended asset sequence"
    );
    assert_eq!(
        json::to_json(&extended.transactions()[0]).unwrap(),
        json::to_json(&original.transactions()[0]).unwrap(),
        "structured parameters and domain registration retain their boundary"
    );
    let global = extended.transactions()[original.transactions().len() - 1].instructions();
    assert_eq!(
        global.len(),
        original.transactions().last().unwrap().instructions().len() + 2
    );
    assert!(matches!(
        global[global.len() - 2]
            .as_any()
            .downcast_ref::<RegisterBox>(),
        Some(RegisterBox::Account(_))
    ));
    assert!(matches!(
        global
            .last()
            .unwrap()
            .as_any()
            .downcast_ref::<RegisterBox>(),
        Some(RegisterBox::AssetDefinition(_))
    ));
    let home = extended.transactions()[original.transactions().len()].instructions();
    assert_eq!(home.len(), 1);
    assert!(matches!(
        home[0].as_any().downcast_ref::<RegisterBox>(),
        Some(RegisterBox::Domain(_))
    ));
    let asset_phase = extended.transactions().last().unwrap().instructions();
    assert_eq!(asset_phase.len(), 3);
    assert!(asset_phase[0].as_any().is::<SetAssetDefinitionAlias>());
    assert!(matches!(
        asset_phase[1].as_any().downcast_ref::<MintBox>(),
        Some(MintBox::Asset(_))
    ));
    assert!(matches!(
        asset_phase[2].as_any().downcast_ref::<TransferBox>(),
        Some(TransferBox::AssetDefinition(_))
    ));
    let mut before = json::value::to_value(&original).unwrap();
    let mut after = json::value::to_value(&extended).unwrap();
    before.as_object_mut().unwrap().remove("transactions");
    after.as_object_mut().unwrap().remove("transactions");
    assert_eq!(
        after, before,
        "all original genesis authorities and metadata stay exact"
    );

    let service_id = AccountId::new(generate_account_key_pair(Some(seed), b"service").unwrap().0);
    let with_service =
        append_localnet_service_accounts(extended.clone(), &[Account::new(service_id.clone())])
            .unwrap();
    assert_eq!(
        with_service.transactions().len(),
        extended.transactions().len(),
        "generated universal service custody continues the open global asset phase"
    );
    let before_service = extended.instructions().collect::<Vec<_>>();
    let after_service = with_service.instructions().collect::<Vec<_>>();
    assert_eq!(&after_service[..before_service.len()], before_service);
    assert_eq!(after_service.len(), before_service.len() + 1);
    let Some(RegisterBox::Account(register)) = after_service
        .last()
        .unwrap()
        .as_any()
        .downcast_ref::<RegisterBox>()
    else {
        panic!("service phase must append the requested universal account");
    };
    assert_eq!(register.object.id, service_id);
    assert_eq!(
        json::to_json(
            &append_localnet_service_accounts(
                with_service.clone(),
                &[Account::new(service_id.clone())]
            )
            .unwrap()
        )
        .unwrap(),
        json::to_json(&with_service).unwrap(),
        "already registered service custody is idempotent"
    );

    let unexpected = original
        .clone()
        .into_builder()
        .append_instruction(iroha_data_model::isi::Log::new(
            iroha_data_model::level::Level::INFO,
            "unexpected owner".to_owned(),
        ))
        .build_raw()
        .unwrap();
    assert!(
        extend_genesis(
            unexpected,
            &genesis_account_id,
            Some(seed),
            0,
            std::slice::from_ref(&asset)
        )
        .unwrap_err()
        .to_string()
        .contains("bootstrap permission phase")
    );
    let structured = original
        .into_builder()
        .set_topology(
            peers
                .iter()
                .map(|peer| {
                    GenesisTopologyEntry::new(
                        PeerId::new(peer.public_key.clone()),
                        peer.bls_pop.clone(),
                    )
                })
                .collect(),
        )
        .build_raw()
        .unwrap();
    assert!(
        extend_genesis(structured, &genesis_account_id, Some(seed), 0, &[asset])
            .unwrap_err()
            .to_string()
            .contains("not instruction-only")
    );
}

#[test]
fn localnet_signed_topology_establishes_exact_bls_generation_zero() {
    let seed = b"validator-generation-fixture";
    let peers =
        build_peers(4, Some(seed), 8_080, 13_337).expect("derive deterministic localnet peers");
    let (public, private) = generate_genesis_key_pair(Some(seed), GENESIS_SEED).unwrap();
    let key_pair = KeyPair::from_private_key(private.0).unwrap();
    let raw = generate_raw_genesis(
        &public,
        SumeragiConsensusMode::Permissioned,
        "generation-fixture",
    )
    .unwrap();
    let raw = append_peer_pop(raw, &peers).unwrap();
    raw.validate_genesis_topology().unwrap();
    let signed = raw.build_and_sign(&key_pair).unwrap();
    let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(&signed.0)
        .map(|genesis| genesis.into_parts().0)
        .expect("signed BLS registrations are the sole genesis validator authority");
    let mut expected = peers
        .iter()
        .map(|peer| (PeerId::new(peer.public_key.clone()), peer.bls_pop.clone()))
        .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(epoch.committee.len(), 4);
    assert_eq!(
        epoch
            .committee
            .iter()
            .map(|member| (member.validator.clone(), member.proof_of_possession.clone()))
            .collect::<Vec<_>>(),
        expected
    );
    let generation = epoch.generation();
    assert_eq!(generation.generation, 0);
    assert_eq!(
        generation.network_id,
        NetworkId::from_genesis_hash(signed.0.hash())
    );
    generation.validate().unwrap();
    epoch
        .authorization
        .validate_against_generation(&generation)
        .unwrap();
    let mut changed = generation.clone();
    changed.validators.swap(0, 1);
    assert!(changed.validate().is_err());
    changed = generation.clone();
    changed.validators[1] = changed.validators[0].clone();
    assert!(changed.validate().is_err());
    changed = generation;
    changed.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"foreign genesis",
    )));
    assert!(
        epoch
            .authorization
            .validate_against_generation(&changed)
            .is_err()
    );
}

/// Fresh SORA Taira participants: lane, alias (lane and dataspace), SNS-derived dataspace id and
/// whether the lane is restricted (Parliament manifest) rather than public (stake-elected).
const EXPECTED_TAIRA_PARTICIPANTS: [(u32, &str, u64, bool); 5] = [
    (3, "dpn", 9_884_542_487_407_331_249, true),
    (4, "is2", 9_700_280_040_122_529_948, true),
    (5, "bpng", 8_648_377_547_929_788_715, false),
    (6, "cbsi", 6_983_892_400_042_691_068, true),
    (7, "is", 6_647_857_470_246_403_404, true),
];
/// Instruction-only transactions `iroha taira seat-parliament` appends to the generated Taira
/// genesis: the citizen seating transaction and the SCCP initialization transaction
/// (`append_genesis_transaction` in `crates/iroha_cli/src/taira_parliament_seating.rs`).
const TAIRA_PARLIAMENT_SEATING_TRANSACTIONS: usize = 2;

fn canonical_taira_options(out_dir: &Path, seed: &str) -> LocalnetOptions {
    LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
        seed: Some(seed.to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29_080,
        base_p2p_port: 33_337,
        out_dir: out_dir.to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: Some(5_000),
        consensus_mode: SumeragiConsensusMode::Npos,
    }
}

/// Assert the exact rendered `[nexus]` catalog tables of the fresh SORA Taira layout.
#[test]
fn public_taira_template_matches_genesis_catalog_and_routes() {
    let template: toml::Value = toml::from_str(include_str!(
        "../../../../../configs/soranexus/taira/config.toml"
    ))
    .expect("public Taira template is valid TOML");
    assert_taira_nexus_catalog_tables(template["nexus"].as_table().unwrap());
}

#[allow(clippy::too_many_lines)]
fn assert_taira_nexus_catalog_tables(nexus: &toml::Table) {
    assert_eq!(nexus["lane_count"].as_integer(), Some(8));
    assert!(
        !nexus.contains_key("autoscale"),
        "the fixed Taira catalog has no lane autoscaling"
    );
    let lanes = nexus["lane_catalog"]
        .as_array()
        .expect("Taira lane catalog");
    let mut expected_lanes = vec![
        (0, "core", "universal", "public", None),
        (1, "governance", "universal", "public", None),
        (2, "zk", "universal", "public", None),
    ];
    expected_lanes.extend(EXPECTED_TAIRA_PARTICIPANTS.iter().map(
        |(index, alias, _, restricted)| {
            if *restricted {
                (*index, *alias, *alias, "restricted", Some("parliament"))
            } else {
                (*index, *alias, *alias, "public", None)
            }
        },
    ));
    assert_eq!(lanes.len(), expected_lanes.len());
    for (lane, (index, alias, dataspace, visibility, governance)) in
        lanes.iter().zip(expected_lanes)
    {
        let lane = lane.as_table().expect("Taira lane entry");
        assert_eq!(lane["index"].as_integer(), Some(i64::from(index)));
        assert_eq!(lane["alias"].as_str(), Some(alias));
        assert_eq!(lane["dataspace"].as_str(), Some(dataspace));
        assert_eq!(lane["visibility"].as_str(), Some(visibility));
        assert_eq!(lane["storage"].as_str(), Some("full_replica"));
        assert_eq!(
            lane.get("governance").and_then(toml::Value::as_str),
            governance
        );
        assert_eq!(lane["metadata"].as_table(), Some(&toml::Table::new()));
        assert!(lane["description"].as_str().is_some());
        for absent in ["proof_scheme", "manifest_policy", "scheduler"] {
            assert!(
                !lane.contains_key(absent),
                "lane {alias} keeps the default {absent}"
            );
        }
    }
    let dataspaces = nexus["dataspace_catalog"]
        .as_array()
        .expect("Taira dataspace catalog");
    assert_eq!(dataspaces.len(), 1 + EXPECTED_TAIRA_PARTICIPANTS.len());
    let universal = dataspaces[0].as_table().expect("universal dataspace");
    assert_eq!(universal["alias"].as_str(), Some("universal"));
    assert_eq!(universal["id"].as_integer(), Some(0));
    assert_eq!(universal["fault_tolerance"].as_integer(), Some(1));
    assert!(!universal.contains_key("manifest_hash"));
    assert!(!universal.contains_key("fee_sponsor_program_id"));
    for (entry, (_, alias, dataspace_id, _)) in
        dataspaces[1..].iter().zip(EXPECTED_TAIRA_PARTICIPANTS)
    {
        let entry = entry.as_table().expect("participant dataspace");
        let name_hash = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
            .expect("canonical SNS dataspace label")
            .name_hash();
        assert_eq!(DataSpaceId::from_hash(&name_hash).as_u64(), dataspace_id);
        assert_eq!(entry["alias"].as_str(), Some(alias));
        assert_eq!(
            entry["manifest_hash"].as_str(),
            Some(hex::encode(name_hash).as_str()),
            "{alias} carries its full SNS dataspace-alias name hash"
        );
        assert!(
            !entry.contains_key("id"),
            "{alias} derives its id from manifest_hash"
        );
        assert!(!entry.contains_key("fee_sponsor_program_id"));
        assert_eq!(entry["fault_tolerance"].as_integer(), Some(1));
        assert!(entry["description"].as_str().is_some());
    }
    let routing = nexus["routing_policy"]
        .as_table()
        .expect("Taira routing policy");
    assert_eq!(routing["default_lane"].as_integer(), Some(0));
    assert_eq!(routing["default_dataspace"].as_str(), Some("universal"));
    let rules = routing["rules"]
        .as_array()
        .expect("Taira route rules")
        .iter()
        .map(|rule| {
            let matcher = rule["matcher"].as_table().expect("route matcher");
            let (kind, value) = matcher
                .iter()
                .find(|(key, _)| key.as_str() != "description")
                .expect("route matcher selector");
            assert_eq!(matcher.len(), 2, "one selector plus its description");
            (
                rule["lane"].as_integer().expect("route lane"),
                rule["dataspace"]
                    .as_str()
                    .expect("route dataspace")
                    .to_owned(),
                kind.clone(),
                value.as_str().expect("route selector").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let route = |lane: i64, dataspace: &str, kind: &str, value: &str| {
        (
            lane,
            dataspace.to_owned(),
            kind.to_owned(),
            value.to_owned(),
        )
    };
    assert_eq!(
        rules,
        vec![
            route(1, "universal", "instruction", "governance"),
            route(2, "universal", "instruction", "smartcontract::deploy"),
            route(3, "dpn", "account", "*@dpn"),
            route(4, "is2", "account", "*@is2"),
            route(6, "cbsi", "account", "*@cbsi"),
            route(7, "is", "account", "*@is"),
        ],
        "BPNG routes by target dataspace and no nested-scope routes remain"
    );
}

#[test]
fn taira_catalog_binds_sns_dataspaces_lanes_routes_and_public_validator_lanes() {
    let (lane_count, lanes) =
        localnet_lane_catalog(Some(SoraProfile::Nexus), true).expect("Taira lane catalog");
    let routing =
        localnet_routing_policy(Some(SoraProfile::Nexus), true).expect("Taira routing policy");
    let nexus = toml::Table::from_iter([
        ("lane_count".to_owned(), toml::Value::Integer(lane_count)),
        ("lane_catalog".to_owned(), toml::Value::Array(lanes)),
        (
            "dataspace_catalog".to_owned(),
            toml::Value::Array(localnet_dataspace_catalog(
                Some(SoraProfile::Nexus),
                localnet_dataspace_fault_tolerance(
                    NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
                ),
                true,
            )),
        ),
        ("routing_policy".to_owned(), toml::Value::Table(routing)),
    ]);
    assert_taira_nexus_catalog_tables(&nexus);
    for participant in TAIRA_PARTICIPANT_LANES {
        let (index, alias, dataspace_id, restricted) = EXPECTED_TAIRA_PARTICIPANTS
            .into_iter()
            .find(|(_, alias, _, _)| *alias == participant.alias)
            .expect("expected Taira participant");
        assert_eq!(participant.lane_index, index);
        assert_eq!(participant.alias, alias);
        assert_eq!(participant.dataspace_id().as_u64(), dataspace_id);
        assert_eq!(participant.restricted(), restricted);
    }
    assert_eq!(
        localnet_public_validator_lanes(Some(SoraProfile::Nexus), true),
        vec![LaneId::SINGLE, LaneId::new(5)],
        "restricted Taira lanes are manifest-governed and receive no public staking pool"
    );
    assert_eq!(
        localnet_public_validator_lanes(Some(SoraProfile::Nexus), false),
        vec![
            LaneId::SINGLE,
            LaneId::new(LOCALNET_PAYNET_ALIAS_LANE_INDEX),
            LaneId::new(LOCALNET_CBUAE_ALIAS_LANE_INDEX)
        ],
        "the generic Nexus profile keeps its public alias lanes"
    );
}

#[test]
fn canonical_taira_seated_genesis_stays_within_bootstrap_network_inputs() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("temporary Taira directory");
    let opts = canonical_taira_options(temp.path(), "taira-genesis-input-budget");
    generate_localnet_with_chain(
        &opts,
        &mut BufWriter::new(Vec::new()),
        Some(PUBLIC_TAIRA_CHAIN_ID),
        None,
    )
    .expect("generate canonical Taira localnet");
    let _chain_discriminant = ChainDiscriminantGuard::enter(
        known_chain_discriminant_for_chain_id(PUBLIC_TAIRA_CHAIN_ID).expect("Taira discriminant"),
    );
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse bound Taira genesis");
    // Root domain and parameters; bootstrap authority, service and fee custody; topology; NPoS
    // bootstrap with universal validators; the public BPNG validator registrations; alias setup.
    assert_eq!(manifest.transactions().len(), 6);
    let generated_inputs = manifest
        .clone()
        .parse()
        .expect("generated Taira genesis inputs")
        .len();
    assert_eq!(
        generated_inputs,
        manifest.transactions().len() + 2,
        "parsing adds the consensus-metadata batch and one crypto/confidential batch"
    );
    let mut seated = manifest;
    for index in 0..TAIRA_PARLIAMENT_SEATING_TRANSACTIONS {
        seated = seated
            .append_instruction_transaction(iroha_data_model::isi::Log::new(
                iroha_data_model::Level::INFO,
                format!("seat-parliament transaction {index}"),
            ))
            .expect("append seat-parliament transaction");
    }
    let seated_inputs = seated
        .parse()
        .expect("seated Taira genesis must stay within the FASTPQ bootstrap input budget")
        .len();
    assert_eq!(
        seated_inputs,
        generated_inputs + TAIRA_PARLIAMENT_SEATING_TRANSACTIONS
    );
    assert!(
        seated_inputs
            <= usize::try_from(
                iroha_data_model::parameter::FastpqSourcePolicyV1::BOOTSTRAP_NETWORK_INPUTS
            )
            .expect("bootstrap input count fits usize"),
        "seated Taira genesis has {seated_inputs} network inputs"
    );
}

#[test]
fn canonical_taira_generation_binds_four_runtime_signers_to_validator_peers() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("temporary Taira directory");
    let opts = canonical_taira_options(temp.path(), "taira-runtime-signer-fixture");
    let mut output = BufWriter::new(Vec::new());
    generate_localnet_with_chain(&opts, &mut output, Some(PUBLIC_TAIRA_CHAIN_ID), None)
        .expect("generate canonical Taira localnet");
    for index in 0..4 {
        let path = temp.path().join(format!("peer{index}.toml"));
        let source = iroha_fs::read_private(&path, 1024 * 1024).unwrap();
        let parsed =
            parse_localnet_peer_config(std::str::from_utf8(&source).unwrap(), Some(&path)).unwrap();
        managed_puzzle::assert_public_profile(&parsed.network.soranet_handshake.pow);
    }
    let peers = build_peers(
        TAIRA_TESTNET_PEERS,
        opts.seed.as_deref().map(str::as_bytes),
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("rebuild deterministic peer identities");
    let operator_identity =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("rebuild deterministic operator identity");
    let http_operator_identity = localnet_ephemeral_identity(
        opts.seed.as_deref().map(str::as_bytes),
        b"http-operator-root",
    )
    .expect("rebuild deterministic HTTP operator identity");
    let client: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("client.toml")).expect("generated client"),
    )
    .expect("parse generated client");
    let client_key = client["account"]["private_key"]
        .as_str()
        .expect("client private key")
        .parse::<ExposedPrivateKey>()
        .expect("decode client key");
    let client_key = KeyPair::from_private_key(client_key.0).expect("derive client public key");
    let http_key = localnet_test_sidecar_key(
        &temp
            .path()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(LOCALNET_OPERATOR_SIGNER_KEY_FILE),
    );
    assert_eq!(client_key.public_key(), &operator_identity.public_key);
    assert_eq!(
        client["account"]["public_key"].as_str(),
        Some(client_key.public_key().to_string().as_str())
    );
    assert_eq!(http_key.public_key(), &http_operator_identity.public_key);
    assert_ne!(client_key.public_key(), http_key.public_key());
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated Taira genesis");
    // The fresh catalog carries no built-in application asset: XOR is the only definition, its
    // public alias is the only binding, and every genesis domain stays in `universal`.
    let definitions = manifest
        .instructions()
        .filter_map(
            |instruction| match instruction.as_any().downcast_ref::<RegisterBox>() {
                Some(RegisterBox::AssetDefinition(register)) => Some(register.object().id.clone()),
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(definitions, vec![localnet_xor_asset_definition_id()]);
    let alias_bindings = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<SetAssetDefinitionAlias>()
        })
        .map(|binding| binding.alias().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        alias_bindings,
        vec![Some(
            crate::genesis::PUBLIC_XOR_ALIAS
                .parse::<AssetDefinitionAlias>()
                .expect("canonical XOR alias")
        )]
    );
    for instruction in manifest.instructions() {
        if let Some(RegisterBox::Domain(register)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        {
            assert_eq!(
                register.object().id().dataspace().to_string(),
                "universal",
                "fresh Taira genesis materializes no participant namespace"
            );
        }
    }
    let readme = fs::read_to_string(temp.path().join("README.md")).expect("generated public guide");
    assert!(!readme.contains("Digital Shekel"));
    assert!(!readme.contains("ds#boi.is"));
    assert!(readme.contains("Registered lanes: `0,1,2,3,4,5,6,7`"));
    assert!(readme.contains("Public validator lanes: `0,5`"));
    assert!(readme.contains("Genesis registers no application assets"));
    for (lane, alias, dataspace_id, restricted) in EXPECTED_TAIRA_PARTICIPANTS {
        assert!(readme.contains(&format!(
            "Lane `{lane}` `{alias}`: {}",
            if restricted {
                "restricted Parliament lane"
            } else {
                "public lane"
            }
        )));
        assert!(readme.contains(&format!("dataspace `{alias}` id `{dataspace_id}`")));
        assert_eq!(
            readme.contains(&format!("lane-manifests/{alias}.manifest.json")),
            restricted
        );
    }
    let peer_config_text = fs::read_to_string(temp.path().join("peer0.toml"))
        .expect("read generated Taira peer config");
    let peer_config: toml::Value =
        toml::from_str(&peer_config_text).expect("parse generated Taira peer config");
    let nexus_config = peer_config["nexus"].as_table().expect("Taira Nexus config");
    assert_taira_nexus_catalog_tables(nexus_config);
    for (_, alias, _, restricted) in EXPECTED_TAIRA_PARTICIPANTS {
        let path = temp
            .path()
            .join("lane-manifests")
            .join(format!("{alias}.manifest.json"));
        if !restricted {
            assert!(!path.exists(), "public {alias} lane has no lane manifest");
            continue;
        }
        let lane_manifest: json::Value = json::from_str(
            &fs::read_to_string(&path).expect("read generated restricted lane manifest"),
        )
        .expect("parse generated restricted lane manifest");
        assert_eq!(lane_manifest["lane"].as_str(), Some(alias));
        assert_eq!(lane_manifest["governance"].as_str(), Some("parliament"));
        assert_eq!(lane_manifest["version"].as_u64(), Some(1));
        assert_eq!(lane_manifest["quorum"].as_u64(), Some(3));
        let validators = lane_manifest["validators"]
            .as_array()
            .expect("lane manifest validators");
        assert_eq!(validators.len(), usize::from(TAIRA_TESTNET_PEERS));
        for (validator, peer) in validators.iter().zip(&peers) {
            assert_eq!(
                validator["peer_id"].as_str(),
                Some(PeerId::from(peer.public_key.clone()).to_string().as_str())
            );
            assert!(validator["validator"].as_str().is_some());
        }
    }
    assert_eq!(
        fs::read_dir(temp.path().join("lane-manifests"))
            .expect("read generated lane manifest directory")
            .count(),
        4,
        "exactly the four restricted lanes carry a manifest"
    );
    let soracloud_runtime = peer_config
        .get("soracloud_runtime")
        .and_then(toml::Value::as_table)
        .expect("canonical Taira Soracloud runtime profile");
    assert_eq!(
        soracloud_runtime
            .get("hydration_concurrency")
            .and_then(toml::Value::as_integer),
        Some(TAIRA_SORACLOUD_HYDRATION_CONCURRENCY),
        "canonical Taira configs must explicitly pin the first-release hydration worker count"
    );
    assert_eq!(
        soracloud_runtime
            .get("prepared_runtime_cache_capacity")
            .and_then(toml::Value::as_integer),
        Some(TAIRA_SORACLOUD_PREPARED_RUNTIME_CACHE_CAPACITY),
        "canonical Taira configs must explicitly pin the independent first-release prepared-runtime cache capacity"
    );
    let credential_scope = peer_config
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("account_onboarding"))
        .and_then(toml::Value::as_table)
        .and_then(|onboarding| onboarding.get("credentials"))
        .and_then(toml::Value::as_array)
        .and_then(|credentials| credentials.as_slice().first())
        .and_then(toml::Value::as_table)
        .and_then(|credential| credential.get("scope"))
        .and_then(toml::Value::as_table)
        .expect("canonical Taira onboarding credential scope");
    assert_eq!(
        credential_scope
            .get("dataspace")
            .and_then(toml::Value::as_str),
        Some(TAIRA_CANARY_DATASPACE_ALIAS)
    );
    assert!(!credential_scope.contains_key("domain"));
    let alias_setup = manifest
        .transactions()
        .last()
        .expect("canonical Taira alias setup transaction")
        .instructions();
    let domain_intent = alias_setup[1]
        .as_any()
        .downcast_ref::<EnsureAlias>()
        .expect("canonical Taira domain setup");
    let AliasIntentV1::Domain(domain_intent) = &domain_intent.intent else {
        panic!("canonical Taira setup must create its canary domain");
    };
    assert_eq!(domain_intent.domain.canonical_text(), TAIRA_CANARY_DOMAIN);
    let account_intent = alias_setup[2]
        .as_any()
        .downcast_ref::<EnsureAlias>()
        .expect("canonical Taira operator alias setup");
    let AliasIntentV1::AccountAlias(account_intent) = &account_intent.intent else {
        panic!("canonical Taira setup must bind its operator alias");
    };
    assert_eq!(
        account_intent.alias.canonical_text(),
        TAIRA_LOCALNET_OPERATOR_ALIAS
    );
    let fixture_accounts = [
        ALICE_ID.clone(),
        iroha_test_samples::CARPENTER_ID.clone(),
        localnet_client_account_id(),
    ];
    let mut registered_domains = BTreeSet::new();
    for instruction in manifest.instructions() {
        if let Some(RegisterBox::Account(register)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        {
            assert!(
                !fixture_accounts.contains(register.object().id()),
                "public fixture account entered Taira genesis"
            );
        }
        if let Some(GrantBox::Permission(grant)) = instruction.as_any().downcast_ref::<GrantBox>() {
            assert!(
                !fixture_accounts.contains(grant.destination()),
                "public fixture received a Taira permission"
            );
            assert_ne!(
                grant.destination(),
                &http_operator_identity.account_id,
                "HTTP authentication must not acquire ledger administration grants"
            );
        }
        if let Some(RegisterBox::Domain(register)) =
            instruction.as_any().downcast_ref::<RegisterBox>()
        {
            assert!(
                registered_domains.insert(register.object().id().clone()),
                "duplicate genesis domain"
            );
        }
        if let Some(binding) = instruction
            .as_any()
            .downcast_ref::<SetAssetDefinitionAlias>()
        {
            if let Some(alias) = binding.alias.as_ref() {
                if let Some(domain_name) = alias.domain_segment() {
                    let domain = DomainId::try_new(domain_name, alias.dataspace_segment())
                        .expect("alias domain");
                    assert!(
                        registered_domains.contains(&domain),
                        "alias namespace must precede its binding"
                    );
                }
            }
        }
    }
    for permission in [
        Permission::from(CanSetParameters),
        Permission::from(CanSetHijiriParameters),
        Permission::from(CanReadAllLedgerData),
        Permission::from(CanEnactGovernance),
    ] {
        assert_eq!(manifest.instructions().filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>()).filter(|grant| matches!(grant, GrantBox::Permission(grant) if grant.destination() == &operator_identity.account_id && grant.object() == &permission)).count(), 1, "actual runtime operator must receive each required permission once");
    }
    let validator_records = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .filter(|registration| registration.lane_id == LaneId::SINGLE)
        .collect::<Vec<_>>();
    assert_eq!(validator_records.len(), usize::from(TAIRA_TESTNET_PEERS));
    let public_registrations = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .collect::<Vec<_>>();
    assert_eq!(public_registrations.len(), 8);
    assert_eq!(
        public_registrations
            .iter()
            .map(|registration| registration.lane_id.as_u32())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 5]),
        "only universal and public BPNG lanes gain public staking pools; restricted lanes are manifest-governed"
    );
    let bpng_registration_transactions = manifest
        .transactions()
        .iter()
        .filter(|transaction| {
            transaction.instructions().iter().any(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_some_and(|registration| registration.lane_id == LaneId::new(5))
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(bpng_registration_transactions.len(), 1);
    assert!(
        bpng_registration_transactions[0]
            .instructions()
            .iter()
            .all(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<RegisterPublicLaneValidator>()
                    .is_some_and(|registration| registration.lane_id == LaneId::new(5))
                    || instruction
                        .as_any()
                        .downcast_ref::<ActivatePublicLaneValidator>()
                        .is_some_and(|activation| activation.lane_id == LaneId::new(5))
            }),
        "the public BPNG lane registrations form their own genesis transaction"
    );

    // Generation already executes this exact body through native State/Kura and
    // ValidBlock validation; require the persisted result to retain that success.
    let signed = read_signed_genesis(&temp.path().join("genesis.signed.nrt"))
        .expect("read native executed Taira genesis");
    signed
        .validate_output_merkle_cache()
        .expect("generated genesis has complete typed execution outputs");
    for index in 0..signed.network_entrypoint_count() {
        let (_, output) = signed
            .network_output_at(u32::try_from(index).expect("genesis input fits u32"))
            .expect("genesis input must have its exact Network output");
        assert!(
            output.result.as_ref().is_ok(),
            "genesis transaction {index} failed"
        );
    }
    assert!(
        signed
            .output_results()
            .all(|result| result.as_ref().is_ok()),
        "all generated genesis invocation outputs must be successful"
    );

    let start_script = fs::read_to_string(temp.path().join("start.sh"))
        .expect("read generated Taira start script");
    assert!(start_script.contains("peer{}.fd198"));
    assert!(!start_script.contains("peer{}.fd199"));
    assert!(start_script.contains("os.dup2(launch_fd, descriptor, inheritable=True)"));
    assert!(start_script.contains("pass_fds = (198,)"));
    assert!(start_script.contains("_reserve_taira_fds(reserved)"));
    assert!(start_script.contains("_erase_owned_taira_launch(record)"));
    assert!(!start_script.contains("os.dup2(source_fd, 198, inheritable=True)"));
    assert!(start_script.contains("Taira runtime signer source changed while staging"));
    assert!(start_script.contains("iroha3d_taira"));
    let mut authorities = BTreeSet::new();
    for (peer_index, peer) in peers.iter().enumerate() {
        let source = TomlSource::from_file(temp.path().join(format!("peer{peer_index}.toml")))
            .expect("read Taira peer config");
        let parsed = actual::Root::from_toml_source(source).expect("parse Taira peer config");

        assert!(parsed.torii.operator_signatures.enabled);
        assert!(parsed.torii.operator_signatures.allow_node_key);
        assert_eq!(
            parsed.torii.operator_signatures.allowed_public_keys,
            vec![http_operator_identity.public_key.clone()],
            "each validator must authorize exactly the dedicated HTTP operator"
        );
        assert!(
            !parsed
                .torii
                .operator_signatures
                .allowed_public_keys
                .contains(client_key.public_key())
        );
        let faucet = parsed
            .torii
            .faucet
            .as_ref()
            .expect("native faucet admission");
        assert_eq!(faucet.authority, operator_identity.account_id);
        assert_eq!(faucet.signer.public_key(), client_key.public_key());
        assert_ne!(faucet.signer.public_key(), http_key.public_key());
        assert_eq!(
            faucet
                .private_key_file
                .file_name()
                .and_then(|name| name.to_str()),
            Some(LOCALNET_LEDGER_SIGNER_KEY_FILE)
        );
        assert!(parsed.nexus.governance.default_module.is_none());
        assert_eq!(parsed.nexus.lane_catalog.lane_count().get(), 8);
        let lanes = parsed.nexus.lane_catalog.lanes();
        assert_eq!(
            lanes
                .iter()
                .map(|lane| lane.id.as_u32())
                .collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>(),
            "every Taira lane index is registered"
        );
        for (lane, alias) in lanes.iter().zip(["core", "governance", "zk"]) {
            assert_eq!(lane.alias, alias);
            assert_eq!(lane.dataspace_id, DataSpaceId::UNIVERSAL);
            assert_eq!(
                lane.visibility,
                iroha_data_model::nexus::LaneVisibility::Public
            );
            assert!(lane.governance.is_none());
            assert_eq!(
                lane.storage,
                iroha_data_model::nexus::LaneStorageProfile::FullReplica
            );
        }
        for (index, alias, dataspace_id, restricted) in EXPECTED_TAIRA_PARTICIPANTS {
            let lane = lanes
                .iter()
                .find(|lane| lane.id.as_u32() == index)
                .expect("native parsed participant lane");
            assert_eq!(lane.alias, alias);
            assert_eq!(lane.dataspace_id, DataSpaceId::new(dataspace_id));
            assert_eq!(
                lane.visibility,
                if restricted {
                    iroha_data_model::nexus::LaneVisibility::Restricted
                } else {
                    iroha_data_model::nexus::LaneVisibility::Public
                }
            );
            assert_eq!(
                lane.governance.as_deref(),
                restricted.then_some("parliament")
            );
            assert_eq!(
                lane.storage,
                iroha_data_model::nexus::LaneStorageProfile::FullReplica
            );
        }
        let mut expected_dataspaces = EXPECTED_TAIRA_PARTICIPANTS
            .iter()
            .map(|(_, alias, id, _)| (*id, *alias, 1))
            .collect::<Vec<_>>();
        expected_dataspaces.push((0, "universal", 1));
        expected_dataspaces.sort_unstable();
        assert_eq!(
            parsed
                .nexus
                .dataspace_catalog
                .entries()
                .iter()
                .map(|dataspace| (
                    dataspace.id.as_u64(),
                    dataspace.alias.as_str(),
                    dataspace.fault_tolerance
                ))
                .collect::<Vec<_>>(),
            expected_dataspaces,
            "paynet and nexus are absent; participant ids derive from SNS name hashes"
        );
        assert!(parsed.nexus.dataspace_fee_sponsor_program_ids.is_empty());
        let _manifest_scope = ChainDiscriminantGuard::enter(manifest.chain_discriminant());
        let registry = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
            &parsed.nexus.lane_catalog,
            &parsed.nexus.governance,
            &parsed.nexus.registry,
        );
        registry
            .validate_active_coverage_for_catalog(&parsed.nexus.lane_catalog)
            .expect("native authenticated manifest coverage");
        let expected_bindings = peers
            .iter()
            .map(|peer| {
                (
                    peer.validator_account_id(true),
                    PeerId::from(peer.public_key.clone()),
                )
            })
            .collect::<BTreeSet<_>>();
        for (index, alias, _, restricted) in EXPECTED_TAIRA_PARTICIPANTS {
            let lane_id = LaneId::new(index);
            if !restricted {
                assert_eq!(
                    registry.lane_quorum(lane_id),
                    None,
                    "{alias} has no manifest"
                );
                continue;
            }
            assert_eq!(registry.lane_quorum(lane_id), Some(3), "{alias} quorum");
            assert_eq!(
                registry
                    .lane_validator_bindings(lane_id)
                    .expect("restricted lane manifest validator bindings")
                    .into_iter()
                    .map(|binding| {
                        assert!(binding.torii_url.is_none());
                        (binding.validator, binding.peer_id)
                    })
                    .collect::<BTreeSet<_>>(),
                expected_bindings,
                "{alias} manifest binds every runtime validator to its peer"
            );
        }
        assert_eq!(
            parsed.network.soranet_vpn.operator_account_id,
            operator_identity.account_id
        );
        assert_eq!(
            parsed.gov.sorafs_pin_fee_treasury_account,
            iroha_config::parameters::defaults::governance::sorafs_pin_fee::treasury_account_id()
        );
        let binding = parsed
            .soracloud_runtime
            .submission
            .signer
            .expect("exact Taira runtime signer binding");
        let expected_authority = AccountId::new(peer.runtime_signer_public_key.clone());
        assert_eq!(binding.authority, expected_authority);
        assert_eq!(binding.public_key, peer.runtime_signer_public_key);
        assert_eq!(binding.revision, TAIRA_RUNTIME_SIGNER_REVISION);
        assert_eq!(
            hex::encode(binding.policy_digest),
            hex::encode(taira_runtime_signer_policy_digest())
        );
        assert!(authorities.insert(binding.authority.clone()));
        assert_eq!(validator_records[peer_index].validator, binding.authority);
        assert_eq!(
            validator_records[peer_index].peer_id,
            PeerId::from(peer.public_key.clone())
        );
        assert_eq!(
            parsed.soracloud_runtime.hydration_concurrency.get(),
            usize::try_from(TAIRA_SORACLOUD_HYDRATION_CONCURRENCY)
                .expect("Taira hydration worker count fits usize")
        );
        assert_eq!(
            parsed
                .soracloud_runtime
                .prepared_runtime_cache_capacity
                .get(),
            usize::try_from(TAIRA_SORACLOUD_PREPARED_RUNTIME_CACHE_CAPACITY)
                .expect("Taira prepared-runtime cache capacity fits usize")
        );
        let inrou = &parsed.soracloud_runtime.inrou;
        assert!(!inrou.enabled);
        assert!(inrou.portable_vm_uid.is_none());
        assert!(inrou.portable_vm_gid.is_none());

        let key_path = taira_runtime_signer_key_path(
            &temp
                .path()
                .join("runtime")
                .join(TAIRA_RUNTIME_SIGNER_DIRECTORY),
            peer_index,
        );
        let key_record = fs::read_to_string(&key_path).expect("read Taira runtime signer key");
        assert_eq!(key_record.len(), 71);
        assert_eq!(key_record.lines().count(), 1);
        assert_eq!(
            key_record.trim_end(),
            peer.runtime_signer_private_key
                .try_to_multihash_string()
                .expect("canonical runtime signer key")
        );
        let metadata = fs::metadata(&key_path).expect("inspect runtime signer key");
        #[cfg(unix)]
        {
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert!(!temp.path().join("runtime/mint-finality-signers").exists());
        let config = fs::read_to_string(temp.path().join(format!("peer{peer_index}.toml")))
            .expect("read rendered Taira config");
        assert!(!config.contains(key_record.trim_end()));
        assert!(!start_script.contains(key_record.trim_end()));
        let config: toml::Value = toml::from_str(&config).expect("parse rendered Taira config");
        let storage = config
            .get("nexus")
            .and_then(toml::Value::as_table)
            .and_then(|nexus| nexus.get("storage"))
            .and_then(toml::Value::as_table)
            .expect("canonical Taira Nexus storage profile");
        assert_eq!(
            storage
                .get("local_budget_bytes")
                .and_then(toml::Value::as_integer),
            Some(
                i64::try_from(taira_defaults::NEXUS_STORAGE_BUDGET_BYTES)
                    .expect("Taira Nexus storage budget fits i64")
            )
        );
        let weights = storage
            .get("disk_budget_weights")
            .and_then(toml::Value::as_table)
            .expect("canonical Taira Nexus storage weights");
        for (name, expected) in TAIRA_NEXUS_STORAGE_WEIGHTS {
            assert_eq!(
                weights.get(name).and_then(toml::Value::as_integer),
                Some(i64::from(expected))
            );
        }
        let sorafs_storage = config
            .get("sorafs")
            .and_then(toml::Value::as_table)
            .and_then(|sorafs| sorafs.get("storage"))
            .and_then(toml::Value::as_table)
            .expect("canonical Taira SoraFS storage profile");
        assert_eq!(
            sorafs_storage
                .get("max_capacity_bytes")
                .and_then(toml::Value::as_integer),
            Some(
                i64::try_from(taira_defaults::SORAFS_STORAGE_CAP_BYTES)
                    .expect("Taira SoraFS storage cap fits i64")
            )
        );
        assert_eq!(
            parsed
                .nexus
                .storage
                .local_budget_bytes
                .map(|bytes| bytes.get()),
            Some(taira_defaults::NEXUS_STORAGE_BUDGET_BYTES)
        );
        assert_eq!(
            parsed
                .nexus
                .storage
                .effective_local_budget_bytes
                .map(|bytes| bytes.get()),
            Some(taira_defaults::NEXUS_STORAGE_BUDGET_BYTES)
        );
        assert_eq!(
            parsed
                .nexus
                .storage
                .configured_sorafs_max_capacity_bytes()
                .map(|bytes| bytes.get()),
            Some(taira_defaults::SORAFS_STORAGE_CAP_BYTES)
        );
        assert_eq!(
            parsed.torii.sorafs_storage.max_capacity_bytes.get(),
            taira_defaults::SORAFS_STORAGE_CAP_BYTES,
            "Nexus parsing must preserve the capacity needed by the complete preseed"
        );
        let egress = config
            .get("soracloud_runtime")
            .and_then(toml::Value::as_table)
            .and_then(|runtime| runtime.get("egress"))
            .and_then(toml::Value::as_table)
            .expect("canonical Taira runtime egress profile");
        assert_eq!(
            egress
                .get("rate_per_minute")
                .and_then(toml::Value::as_integer),
            Some(i64::from(taira_defaults::INROU_EGRESS_RATE_PER_MINUTE))
        );
        assert_eq!(
            egress
                .get("max_bytes_per_minute")
                .and_then(toml::Value::as_integer),
            Some(
                i64::try_from(taira_defaults::INROU_EGRESS_MAX_BYTES_PER_MINUTE)
                    .expect("Taira Inrou egress byte budget fits i64")
            )
        );
        assert!(
            config
                .get("soracloud_runtime")
                .and_then(toml::Value::as_table)
                .is_none_or(|runtime| !runtime.contains_key("inrou")),
            "Kagami must leave Inrou disabled until the trusted guest identity is staged"
        );
    }
    assert_eq!(authorities.len(), usize::from(TAIRA_TESTNET_PEERS));
}

fn localnet_genesis_for_opts(opts: &LocalnetOptions) -> RawGenesisTransaction {
    localnet_genesis_for_opts_and_client(opts, &localnet_client_account_id())
}
#[allow(clippy::too_many_lines)]
fn localnet_genesis_for_opts_and_client(
    opts: &LocalnetOptions,
    client_account_id: &AccountId,
) -> RawGenesisTransaction {
    let default_client_account_id = localnet_client_account_id();
    let uses_default_client = client_account_id == &default_client_account_id;
    let seed_bytes = opts.seed.as_ref().map(String::as_bytes);
    let peers = build_peers(
        opts.peers.get(),
        seed_bytes,
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("test localnet peer key generation should succeed");
    let npos_bootstrap = localnet_uses_npos(opts.consensus_mode);
    let perf_spec = opts.perf_profile.map(LocalnetPerfProfile::spec);
    let block_cadence_override = opts
        .block_cadence_ms
        .or_else(|| perf_spec.map(|spec| spec.block_cadence_ms));
    let block_cadence_ms = Some(block_cadence_override.unwrap_or(LOCALNET_PIPELINE_TIME_MS));
    let block_max_transactions = perf_spec.map_or(LOCALNET_BLOCK_MAX_TRANSACTIONS, |spec| {
        spec.block_max_transactions
    });
    let requested_stake_amount = perf_spec.map(|spec| spec.stake_amount);
    let (genesis_public_key, _) = generate_genesis_key_pair(seed_bytes, GENESIS_SEED)
        .expect("test localnet genesis key generation should succeed");
    let genesis_account_id = AccountId::new(genesis_public_key.clone());
    let assets = if uses_default_client {
        effective_localnet_assets(&opts.assets)
    } else {
        effective_localnet_assets_for_client(&opts.assets, client_account_id)
    };
    let mut genesis =
        generate_raw_genesis(&genesis_public_key, opts.consensus_mode, DEFAULT_CHAIN_ID)
            .expect("generate raw genesis");
    if opts.extra_accounts > 0 || !assets.is_empty() {
        genesis = extend_genesis(
            genesis,
            &genesis_account_id,
            seed_bytes,
            opts.extra_accounts,
            &assets,
        )
        .expect("extend genesis");
    }
    genesis = append_localnet_service_accounts(genesis, &[Account::new(client_account_id.clone())])
        .expect("register generated localnet fixture service account");
    genesis = append_localnet_service_fee_bootstrap(
        genesis,
        &genesis_account_id,
        client_account_id,
        client_account_id,
    )
    .expect("fund generated localnet fixture services");
    genesis = apply_parameter_overrides(
        genesis,
        opts.peers,
        block_cadence_ms,
        block_max_transactions,
        opts.consensus_mode,
    )
    .expect("apply generated localnet fixture parameter overrides");
    genesis = if uses_default_client {
        append_localnet_contract_permissions(genesis, &genesis_account_id)
    } else {
        append_localnet_contract_permissions_for_client(
            genesis,
            &genesis_account_id,
            client_account_id,
        )
        .expect("append generated localnet fixture contract permissions")
    };
    genesis = append_peer_pop(genesis, &peers)
        .expect("append generated localnet fixture topology and proofs of possession");
    let gas_account_id = localnet_gas_account_id(&genesis_public_key);
    let stake_amount = localnet_npos_stake_amount(
        &genesis
            .effective_parameters()
            .expect("generated localnet genesis has one structured parameter block"),
        requested_stake_amount,
    )
    .unwrap();
    if npos_bootstrap {
        genesis = append_localnet_npos_bootstrap(
            genesis,
            &LocalnetNposBootstrapContext {
                peers: &peers,
                gas_account_id: &gas_account_id,
                stake_amount: &stake_amount,
                sora_profile: opts.sora_profile,
                genesis_account_id: &genesis_account_id,
                client_account_id,
                onboarding_account_id: client_account_id,
                taira: false,
            },
        )
        .expect("append localnet NPoS bootstrap");
        genesis = append_private_dataspace_genesis_bootstrap_for_client(
            genesis,
            opts.sora_profile,
            &genesis_account_id,
            client_account_id,
        )
        .expect("append private-dataspace genesis bootstrap");
    } else {
        genesis =
            append_localnet_permissioned_support_accounts(genesis, &peers, &gas_account_id, false)
                .expect("append localnet permissioned support accounts");
    }
    apply_localnet_crypto_overrides(genesis)
        .expect("apply generated localnet fixture cryptography overrides")
}
include!("../private_profile_bootstrap_tests.rs");
fn genesis_json_from_path(path: &Path) -> json::Value {
    let contents = fs::read_to_string(path).expect("read genesis");
    json::from_str(&contents).expect("parse genesis json")
}
fn genesis_parameters(manifest: &json::Value) -> Parameters {
    let transactions = manifest
        .get("transactions")
        .and_then(json::Value::as_array)
        .expect("genesis transactions");
    let params_value = transactions
        .iter()
        .rev()
        .find_map(|tx| tx.get("parameters"))
        .expect("parameters entry");
    json::from_value(params_value.clone()).expect("parse genesis parameters")
}
#[test]
fn generated_configs_parse_with_current_schema() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-config-compat".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 19080,
        base_p2p_port: 23337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let start_script =
        fs::read_to_string(temp.path().join("start.sh")).expect("read generated start script");
    assert!(
        start_script.contains("IROHA_SORA_MODE=\"0\""),
        "plain NPoS must not request the post-parse Sora profile"
    );
    assert!(
        !start_script.contains(" --sora --config "),
        "plain NPoS fallback startup must not add --sora"
    );
    let expected_hash_record = fs::read_to_string(temp.path().join(GENESIS_EXPECTED_HASH_FILE))
        .expect("read generated exact genesis hash");
    assert!(expected_hash_record.ends_with('\n'));
    assert_eq!(expected_hash_record.matches('\n').count(), 1);
    let expected_hash = expected_hash_record
        .strip_suffix('\n')
        .expect("hash record has final newline")
        .parse::<NetworkId>()
        .expect("checked genesis network identity parses");
    assert_eq!(expected_hash_record, format!("{expected_hash}\n"));
    let signed =
        fs::read(temp.path().join("genesis.signed.nrt")).expect("read generated signed genesis");
    let decoded = decode_framed_signed_block(&signed).expect("decode generated signed genesis");
    assert_eq!(decoded.hash(), expected_hash.into_genesis_hash());
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("read generated manifest");
    let parameters = manifest
        .effective_parameters()
        .expect("one genesis parameter block");
    let npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()
        .expect("valid fixture NPoS parameters")
        .flatten()
        .expect("generated NPoS parameters");
    assert_eq!(npos.max_validators(), u32::from(opts.peers.get()));
    for index in 0..opts.peers.get() {
        let path = temp.path().join(format!("peer{index}.toml"));
        let rendered = fs::read_to_string(&path).expect("read rendered validator config");
        let table = rendered
            .parse::<toml::Table>()
            .expect("rendered validator config is TOML");
        let genesis = table
            .get("genesis")
            .and_then(toml::Value::as_table)
            .expect("rendered validator genesis table");
        assert_eq!(
            genesis
                .get("expected_hash_file")
                .and_then(toml::Value::as_str),
            Some(GENESIS_EXPECTED_HASH_FILE)
        );
        assert!(!genesis.contains_key("expected_hash"));
        let source = TomlSource::from_file(&path).expect("read generated config");
        let config = actual::Root::from_toml_source(source).expect("generated config must parse");
        assert_eq!(config.genesis.expected_hash, decoded.hash());
        assert!(config.sumeragi.local.is_empty());
        assert!(matches!(config.sumeragi.role, actual::NodeRole::Validator));
        assert!(table["sumeragi"].get("mint_finality_seed_fd").is_none());
    }
    let client = fs::read_to_string(temp.path().join("client.toml"))
        .expect("read generated client config")
        .parse::<toml::Table>()
        .expect("generated client config is TOML");
    assert_eq!(
        client.get("network_id_file").and_then(toml::Value::as_str),
        Some(GENESIS_EXPECTED_HASH_FILE)
    );
    assert!(!client.contains_key("network_id"));
}
#[test]
fn generated_configs_for_user_localnet_parse() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("Iroha".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: vec![AssetSpec {
            id: localnet_sample_asset_literal(),
            name: LOCALNET_SAMPLE_ASSET_NAME.to_owned(),
            alias: None,
            owned_by: ALICE_ID.clone(),
            mint_to: ALICE_ID.clone(),
            quantity: 100,
        }],
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let source =
        TomlSource::from_file(temp.path().join("peer0.toml")).expect("read generated config");
    actual::Root::from_toml_source(source).expect("generated config must parse");
}
#[test]
fn localnet_assets_contain_only_explicit_requests() {
    let client = localnet_client_account_id();
    assert!(
        effective_localnet_assets_for_client(&[], &client).is_empty(),
        "no localnet, including Taira, bootstraps a built-in application asset"
    );
    let requested = requested_localnet_asset_spec(&localnet_sample_asset_literal())
        .expect("requested sample asset");
    assert_eq!(
        effective_localnet_assets_for_client(std::slice::from_ref(&requested), &client).len(),
        1
    );
}

#[test]
fn localnet_asset_validation_rejects_duplicate_identity_or_alias() {
    let mut first = requested_localnet_asset_spec(&localnet_sample_asset_literal())
        .expect("requested sample asset");
    first.alias = Some("sample#wonderland.universal".to_owned());
    validate_localnet_asset_specs(std::slice::from_ref(&first))
        .expect("one explicit asset is admitted");
    assert!(validate_localnet_asset_specs(&[first.clone(), first.clone()]).is_err());
    let mut second = requested_localnet_asset_spec(&canonical_asset_definition_literal(
        LOCALNET_SAMPLE_ASSET_DOMAIN,
        "other",
    ))
    .expect("distinct requested identity");
    second.alias = first.alias.clone();
    assert!(validate_localnet_asset_specs(&[first, second.clone()]).is_err());
    second.alias = None;
    let first = requested_localnet_asset_spec(&localnet_sample_asset_literal())
        .expect("requested sample asset");
    validate_localnet_asset_specs(&[first, second]).expect("distinct explicit assets");
}

#[test]
fn requested_localnet_asset_spec_trims_and_uses_client_owner_with_initial_reserve() {
    let asset_id = localnet_sample_asset_literal();
    let spec = requested_localnet_asset_spec(&format!("  {asset_id}  ")).expect("asset spec");
    let client_account_id = localnet_client_account_id();
    assert_eq!(spec.id, asset_id);
    assert_eq!(spec.alias, None);
    assert_eq!(spec.owned_by, client_account_id);
    assert_eq!(spec.mint_to, spec.owned_by);
    assert_eq!(spec.quantity, LOCALNET_REQUESTED_ASSET_INITIAL_QUANTITY);
}
#[test]
fn requested_localnet_asset_spec_rejects_blank_or_invalid_asset_definition_id() {
    assert!(requested_localnet_asset_spec("   ").is_err());
    assert!(requested_localnet_asset_spec("not-valid").is_err());
}
#[test]
fn generated_localnet_registers_requested_asset_definition_for_client_owner() {
    let requested_asset_literal = localnet_sample_asset_literal();
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("requested-asset-bootstrap".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: vec![requested_localnet_asset_spec(&requested_asset_literal).expect("asset spec")],
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let manifest = localnet_genesis_for_opts(&opts);
    let requested_asset_id = AssetDefinitionId::parse_address_literal(&requested_asset_literal)
        .expect("requested asset id");
    let client_account_id = localnet_client_account_id();
    let requested_asset = AssetId::new(requested_asset_id.clone(), client_account_id.clone());
    let has_definition = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .is_some_and(|register| {
                matches!(
                    register,
                    RegisterBox::AssetDefinition(register)
                        if register.object().id == requested_asset_id
                )
            })
    });
    assert!(
        has_definition,
        "localnet must register requested asset definitions"
    );
    let has_owner_transfer = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<TransferBox>()
            .is_some_and(|transfer| match transfer {
                TransferBox::AssetDefinition(transfer_asset) => {
                    transfer_asset.object() == &requested_asset_id
                        && transfer_asset.destination() == &client_account_id
                }
                _ => false,
            })
    });
    assert!(
        has_owner_transfer,
        "requested asset definition ownership must transfer to the generated client signer"
    );
    let has_initial_mint = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<MintBox>()
            .is_some_and(|mint| match mint {
                MintBox::Asset(mint_asset) => mint_asset.destination() == &requested_asset,
                _ => false,
            })
    });
    assert!(
        has_initial_mint,
        "requested asset definitions must mint an initial reserve to the generated client signer"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn generated_localnet_bootstraps_explicitly_requested_asset() {
    let mut requested = requested_localnet_asset_spec(&localnet_sample_asset_literal()).unwrap();
    requested.alias = Some("sample#wonderland.universal".to_owned());
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("requested-asset-bootstrap".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: vec![requested.clone()],
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let manifest = localnet_genesis_for_opts(&opts);
    let requested_asset_id =
        AssetDefinitionId::parse_address_literal(&requested.id).expect("requested asset id");
    let requested_alias = requested
        .alias
        .as_deref()
        .unwrap()
        .parse::<AssetDefinitionAlias>()
        .expect("requested asset alias");
    let client_account_id = localnet_client_account_id();
    let (genesis_public_key, _) =
        generate_genesis_key_pair(opts.seed.as_ref().map(String::as_bytes), GENESIS_SEED)
            .expect("test localnet genesis key generation should succeed");
    let genesis_account_id = AccountId::new(genesis_public_key);
    let expected_mint_destination =
        AssetId::new(requested_asset_id.clone(), client_account_id.clone());
    let has_definition = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .is_some_and(|register| {
                matches!(
                    register,
                    RegisterBox::AssetDefinition(register)
                        if register.object().id == requested_asset_id
                )
            })
    });
    assert!(has_definition, "localnet must register the requested asset");
    let has_alias_binding = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<SetAssetDefinitionAlias>()
            .is_some_and(|set_alias| {
                set_alias.asset_definition_id() == &requested_asset_id
                    && set_alias.alias().as_ref() == Some(&requested_alias)
            })
    });
    assert!(
        has_alias_binding,
        "localnet must bind the requested asset alias"
    );
    let has_initial_mint = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<MintBox>()
            .is_some_and(|mint| match mint {
                MintBox::Asset(mint_asset) => {
                    mint_asset.destination() == &expected_mint_destination
                }
                _ => false,
            })
    });
    assert!(
        has_initial_mint,
        "localnet must mint the requested asset to the client signer"
    );
    let has_owner_transfer = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<TransferBox>()
            .is_some_and(|transfer| match transfer {
                TransferBox::AssetDefinition(transfer_asset) => {
                    transfer_asset.object() == &requested_asset_id
                        && transfer_asset.destination() == &client_account_id
                }
                _ => false,
            })
    });
    assert!(
        has_owner_transfer,
        "localnet must transfer requested asset ownership to the client signer"
    );
    let mut has_alias_manage = false;
    let mut has_manifest_publish = false;
    let mut genesis_manage_verifying_keys_grants = 0usize;
    let mut client_manage_verifying_keys_grants = 0usize;
    let mut total_manage_verifying_keys_grants = 0usize;
    for instruction in manifest.instructions() {
        let Some(grant) = instruction.as_any().downcast_ref::<GrantBox>() else {
            continue;
        };
        let GrantBox::Permission(grant_permission) = grant else {
            continue;
        };
        let permission_name: &str = grant_permission.object().name();
        if permission_name == "CanManageVerifyingKeys" {
            total_manage_verifying_keys_grants =
                total_manage_verifying_keys_grants.saturating_add(1);
        }
        if permission_name == "CanManageVerifyingKeys"
            && grant_permission.destination() == &genesis_account_id
        {
            genesis_manage_verifying_keys_grants =
                genesis_manage_verifying_keys_grants.saturating_add(1);
        }
        if grant_permission.destination() != &client_account_id {
            continue;
        }
        match permission_name {
            "CanManageAccountAlias" => has_alias_manage = true,
            "CanManageVerifyingKeys" => {
                client_manage_verifying_keys_grants =
                    client_manage_verifying_keys_grants.saturating_add(1);
            }
            "CanPublishSpaceDirectoryManifest" => has_manifest_publish = true,
            _ => {}
        }
    }
    assert!(
        has_alias_manage,
        "localnet client signer must be able to manage account aliases for onboarding"
    );
    assert!(
        has_manifest_publish,
        "localnet client signer must be able to publish onboarding manifests"
    );
    assert_eq!(
        genesis_manage_verifying_keys_grants, 1,
        "localnet genesis must grant CanManageVerifyingKeys to the genesis signer exactly once"
    );
    assert_eq!(
        client_manage_verifying_keys_grants, 1,
        "localnet genesis must grant CanManageVerifyingKeys to the maintenance client signer exactly once"
    );
    let expected_total_manage_verifying_keys_grants = if client_account_id == genesis_account_id {
        1
    } else {
        2
    };
    assert_eq!(
        total_manage_verifying_keys_grants, expected_total_manage_verifying_keys_grants,
        "localnet genesis must not emit duplicate CanManageVerifyingKeys grants"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn generated_localnet_onboarding_keeps_credentials_in_owner_only_sidecars() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("make localnet output directory owner-held");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("onboarding-config".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().canonicalize().expect("canonical temp dir"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let mut command_output = BufWriter::new(Vec::new());
    generate_localnet_with_chain(&opts, &mut command_output, None, None)
        .expect("generate fresh-custody localnet files");
    let command_output = String::from_utf8(
        command_output
            .into_inner()
            .expect("flush localnet command output"),
    )
    .expect("localnet command output is UTF-8");
    let peer_config_text =
        fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config");
    let peer_cfg: toml::Value = toml::from_str(&peer_config_text).expect("parse peer config");
    let operator =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"operator-root")
            .expect("derive generated operator");
    let onboarding_identity =
        localnet_ephemeral_identity(opts.seed.as_deref().map(str::as_bytes), b"onboarding-root")
            .expect("derive generated onboarding signer");
    let onboarding_account_id = onboarding_identity.account_literal(None);
    let onboarding = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("account_onboarding"))
        .and_then(toml::Value::as_table)
        .expect("torii.account_onboarding table");
    assert_eq!(
        onboarding.get("authority").and_then(toml::Value::as_str),
        Some(onboarding_account_id.as_str())
    );
    assert_ne!(onboarding_identity.account_id, operator.account_id);
    assert!(onboarding.get("enabled").is_none());
    assert!(onboarding.get("private_key").is_none());
    let signer_path = onboarding
        .get("private_key_file")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from)
        .expect("runtime-only signer key path");
    assert_eq!(
        signer_path,
        temp.path()
            .canonicalize()
            .expect("canonical temp dir")
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(LOCALNET_ONBOARDING_SIGNER_KEY_FILE)
    );
    let credentials = onboarding
        .get("credentials")
        .and_then(toml::Value::as_array)
        .expect("onboarding credentials");
    assert_eq!(credentials.len(), 1);
    let credential = credentials[0].as_table().expect("credential table");
    assert_eq!(
        credential.get("id").and_then(toml::Value::as_str),
        Some(LOCALNET_ONBOARDING_CREDENTIAL_ID)
    );
    let scope = credential
        .get("scope")
        .and_then(toml::Value::as_table)
        .expect("credential scope");
    assert_eq!(
        scope.get("domain").and_then(toml::Value::as_str),
        Some(CLIENT_ACCOUNT_DOMAIN)
    );
    let raw_token = fs::read_to_string(
        temp.path()
            .join(LOCALNET_RUNTIME_DIRECTORY)
            .join(LOCALNET_ONBOARDING_TOKEN_FILE),
    )
    .expect("read runtime-only onboarding token");
    assert_eq!(
        raw_token,
        raw_token.trim_end(),
        "the runtime token file must contain only the exact header credential"
    );
    assert!(!peer_config_text.contains(&raw_token));
    assert!(!peer_config_text.contains(operator.private_key.as_str()));
    assert!(!peer_config_text.contains(onboarding_identity.private_key.as_str()));
    assert!(!command_output.contains(&raw_token));
    assert!(!command_output.contains(operator.private_key.as_str()));
    assert!(!command_output.contains(onboarding_identity.private_key.as_str()));
    for peer_index in 0..opts.peers.get() {
        let config = fs::read_to_string(temp.path().join(format!("peer{peer_index}.toml")))
            .expect("read validator config for output redaction check");
        let config: toml::Value = toml::from_str(&config).expect("parse validator config");
        let private_key = config
            .get("private_key")
            .and_then(toml::Value::as_str)
            .expect("validator private key");
        assert!(!command_output.contains(private_key));
    }
    assert!(command_output.contains("onboarding_signer_key:"));
    assert!(command_output.contains("onboarding_token_file:"));
    assert!(command_output.contains("alias_setup_intent:"));
    let expected_digest = format!("blake3:{}", blake3::hash(raw_token.as_bytes()).to_hex());
    assert_eq!(
        credential.get("token_hash").and_then(toml::Value::as_str),
        Some(expected_digest.as_str())
    );
    let configured_program = onboarding
        .get("fee_sponsor_program_id")
        .and_then(toml::Value::as_str)
        .expect("exact onboarding fee sponsor program");
    let configured_program = configured_program
        .parse::<FeeSponsorProgramId>()
        .expect("canonical onboarding fee sponsor program id");
    let (genesis_public_key, _) =
        generate_genesis_key_pair(opts.seed.as_deref().map(str::as_bytes), GENESIS_SEED)
            .expect("derive expected genesis sponsor");
    assert_eq!(
        configured_program,
        localnet_fee_sponsor_program_id(&AccountId::new(genesis_public_key))
    );
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated genesis");
    let setup_transactions = manifest
        .transactions()
        .iter()
        .filter(|transaction| {
            transaction
                .instructions()
                .iter()
                .any(|instruction| instruction.as_any().downcast_ref::<EnsureAlias>().is_some())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        setup_transactions.len(),
        1,
        "one original alias setup owner"
    );
    let setup_transaction = setup_transactions[0];
    let setup_instructions = setup_transaction
        .instructions()
        .iter()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<EnsureAlias>().cloned())
        .collect::<Vec<_>>();
    assert_eq!(setup_instructions.len(), 3);
    assert!(matches!(
        &setup_instructions[0].intent,
        AliasIntentV1::Dataspace(_)
    ));
    assert!(matches!(
        &setup_instructions[1].intent,
        AliasIntentV1::Domain(_)
    ));
    assert!(matches!(
        &setup_instructions[2].intent,
        AliasIntentV1::AccountAlias(_)
    ));
    let final_instructions = setup_transaction.instructions();
    let last_alias_setup_index = final_instructions
        .iter()
        .rposition(|instruction| instruction.as_any().is::<EnsureAlias>())
        .expect("final transaction contains alias setup");
    assert!(
        final_instructions[last_alias_setup_index + 1..]
            .iter()
            .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
            .filter_map(|grant| match grant {
                GrantBox::Permission(grant)
                    if grant.destination() == &onboarding_identity.account_id =>
                {
                    Some(grant)
                }
                _ => None,
            })
            .count()
            >= 3
    );
    let setup_intent_json = fs::read_to_string(temp.path().join(LOCALNET_ALIAS_SETUP_INTENT_FILE))
        .expect("read secret-free setup intent");
    assert!(!setup_intent_json.contains(raw_token.trim_end()));
    assert!(!setup_intent_json.contains(onboarding_identity.private_key.as_str()));
    let setup_request: AliasSetupPlanRequestV1 =
        norito::json::from_str(&setup_intent_json).expect("parse generated setup intent");
    assert_eq!(setup_request.intents, setup_instructions);
    let registrations = BootstrapRegistrations::from_manifest(&manifest);
    assert!(
        registrations
            .accounts
            .contains(&onboarding_identity.account_id),
        "onboarding signer must exist before Torii starts"
    );
    let domain =
        DomainId::parse_fully_qualified(CLIENT_ACCOUNT_DOMAIN).expect("local onboarding domain");
    let expected_onboarding_permissions = BTreeSet::from([
        Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain.clone()),
        }),
        Permission::from(CanRegisterAccount {
            domain: domain.clone(),
        }),
        Permission::from(CanPublishSpaceDirectoryManifestForAccountDomain {
            dataspace: DataSpaceId::UNIVERSAL,
            domain,
        }),
        Permission::from(CanEnrollFeeSponsorProgram {
            program_id: configured_program.clone(),
        }),
    ]);
    let actual_onboarding_permissions = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant) => Some(grant),
            _ => None,
        })
        .filter(|grant| grant.destination() == &onboarding_identity.account_id)
        .map(|grant| grant.object().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_onboarding_permissions, expected_onboarding_permissions,
        "generated onboarding must use only exact execution capabilities"
    );
    let onboarding_fee_asset = AssetId::new(
        localnet_xor_asset_definition_id(),
        onboarding_identity.account_id.clone(),
    );
    assert!(manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<MintBox>()
            .is_some_and(|mint| match mint {
                MintBox::Asset(mint) => mint.destination() == &onboarding_fee_asset,
                _ => false,
            })
    }));
    assert!(onboarding.get("fee_sponsor_account").is_none());
    assert!(onboarding.get("fee_sponsor_policy").is_none());
    assert_eq!(
        fs::read_to_string(temp.path().join(".gitignore")).expect("protective ignore file"),
        concat!(
            "# Kagami localnets contain private signing material and runtime tokens.\n",
            "*\n",
            "!.gitignore\n",
        )
    );
    #[cfg(unix)]
    {
        fn assert_private_tree_modes(root: &Path, path: &Path) {
            let metadata = fs::symlink_metadata(path).expect("private tree entry metadata");
            let relative = path.strip_prefix(root).expect("entry below localnet root");
            if metadata.is_dir() {
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o700,
                    "private directory must be owner-only: {}",
                    relative.display()
                );
                for entry in fs::read_dir(path).expect("read private localnet directory") {
                    let entry = entry.expect("read private localnet entry");
                    assert_private_tree_modes(root, &entry.path());
                }
                return;
            }
            assert!(
                metadata.is_file(),
                "fresh localnet must not contain special entries: {}",
                relative.display()
            );
            assert_eq!(
                metadata.nlink(),
                1,
                "fresh localnet files must be single-link: {}",
                relative.display()
            );
            let expected_mode = if matches!(relative.to_str(), Some("start.sh" | "stop.sh")) {
                0o700
            } else {
                0o600
            };
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                expected_mode,
                "fresh localnet entry has the wrong custody mode: {}",
                relative.display()
            );
        }
        assert_private_tree_modes(temp.path(), temp.path());
    }
    assert_eq!(
        peer_cfg
            .get("settlement")
            .and_then(toml::Value::as_table)
            .and_then(|settlement| settlement.get("offline")),
        None,
        "offline protocol support is universal and must not be represented as a localnet opt-in"
    );
}
#[test]
fn generated_peer_config_includes_required_addr_literals() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-addr-literals".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 21080,
        base_p2p_port: 24337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    assert!(
        peer_cfg.get("public_key").is_some(),
        "public_key is required"
    );
    assert!(
        peer_cfg.get("private_key").is_some(),
        "private_key is required"
    );
    assert!(
        peer_cfg.get("soranet_transport_public_key").is_some(),
        "soranet_transport_public_key is required"
    );
    assert!(
        peer_cfg.get("soranet_transport_private_key").is_some(),
        "soranet_transport_private_key is required"
    );
    assert!(peer_cfg.get("genesis").is_some(), "genesis is required");
    let network = peer_cfg
        .get("network")
        .and_then(toml::Value::as_table)
        .expect("network table");
    let torii = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .expect("torii table");
    let addr_fields = [
        ("network.address", network.get("address")),
        ("network.public_address", network.get("public_address")),
        ("torii.address", torii.get("address")),
    ];
    for (label, value) in addr_fields {
        let literal = value
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{label} is required"));
        let body = literal::parse("addr", literal).unwrap_or_else(|err| panic!("{label}: {err}"));
        assert!(
            body.contains(':'),
            "expected host:port in {label}, got {body}"
        );
    }
}
#[test]
fn generated_peers_use_dedicated_deterministic_transport_and_streaming_identities() {
    let seed = b"kagami-transport-identity-test";
    let peers = build_peers(4, Some(seed), 21_080, 24_337).expect("build peers");
    let replay = build_peers(4, Some(seed), 21_080, 24_337).expect("rebuild peers");
    let mut transport_public_keys = std::collections::BTreeSet::new();
    let mut streaming_public_keys = std::collections::BTreeSet::new();
    for (peer, replay_peer) in peers.iter().zip(&replay) {
        KeyPair::new(
            peer.soranet_transport_public_key.clone(),
            peer.soranet_transport_private_key.0.clone(),
        )
        .expect("generated SoraNet transport key pair must match");
        assert_eq!(
            peer.soranet_transport_public_key
                .try_algorithm()
                .expect("transport public-key algorithm"),
            iroha_crypto::Algorithm::Ed25519
        );
        assert_ne!(peer.soranet_transport_public_key, peer.public_key);
        assert_eq!(
            peer.soranet_transport_public_key,
            replay_peer.soranet_transport_public_key
        );
        assert_eq!(
            peer.soranet_transport_private_key.to_string(),
            replay_peer.soranet_transport_private_key.to_string()
        );
        assert!(
            transport_public_keys.insert(peer.soranet_transport_public_key.clone()),
            "each localnet peer must receive a unique SoraNet transport identity"
        );
        KeyPair::new(
            peer.streaming_public_key.clone(),
            peer.streaming_private_key.0.clone(),
        )
        .expect("generated streaming identity key pair must match");
        assert_eq!(
            peer.streaming_public_key
                .try_algorithm()
                .expect("streaming public-key algorithm"),
            iroha_crypto::Algorithm::Ed25519
        );
        assert_ne!(peer.streaming_public_key, peer.public_key);
        assert_ne!(
            peer.streaming_public_key, peer.soranet_transport_public_key,
            "streaming control-plane and SoraNet transport identities must be domain-separated"
        );
        assert_eq!(
            peer.streaming_public_key, replay_peer.streaming_public_key,
            "seeded streaming identities must be reproducible"
        );
        assert_eq!(
            peer.streaming_private_key.to_string(),
            replay_peer.streaming_private_key.to_string(),
            "seeded streaming private keys must be reproducible"
        );
        assert!(
            streaming_public_keys.insert(peer.streaming_public_key.clone()),
            "each localnet peer must receive a unique streaming identity"
        );
    }
}
#[test]
fn generated_peer_config_allows_bls_signing_for_npos() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-crypto-allow".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 31080,
        base_p2p_port: 35337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let allowed = peer_cfg
        .get("crypto")
        .and_then(|crypto| crypto.get("allowed_signing"))
        .and_then(|value| value.as_array())
        .expect("crypto.allowed_signing should be set for NPoS localnet");
    assert!(
        allowed
            .iter()
            .filter_map(|value| value.as_str())
            .any(|value| value.eq_ignore_ascii_case("bls_normal")),
        "allowed_signing must include bls_normal for NPoS localnet"
    );
    assert!(peer_cfg["sumeragi"].get("mint_finality_seed_fd").is_none());
    assert!(!temp.path().join("runtime/mint-finality-signers").exists());
    let start = fs::read_to_string(temp.path().join("start.sh"))
        .expect("read ordinary localnet start script");
    assert!(start.contains("subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env, close_fds=True, start_new_session=True)"));
    assert!(!start.contains("pass_fds="));
    assert!(!start.contains("nohup env SNAPSHOT_STORE_DIR="));
}
#[test]
fn generated_genesis_allows_bls_signing_for_npos() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-genesis-crypto".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 32080,
        base_p2p_port: 36337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let manifest = localnet_genesis_for_opts(&opts);
    let crypto = manifest.crypto();
    assert!(
        crypto
            .allowed_signing
            .iter()
            .any(|algo| matches!(algo, iroha_crypto::Algorithm::BlsNormal)),
        "genesis allowed_signing must include bls_normal for NPoS localnet"
    );
    let bls_curve = iroha_data_model::account::curve::CurveId::try_from_algorithm(
        iroha_crypto::Algorithm::BlsNormal,
    )
    .expect("bls curve id");
    assert!(
        crypto.allowed_curve_ids.contains(&bls_curve.as_u8()),
        "genesis allowed_curve_ids must include bls_normal for NPoS localnet"
    );
}
#[test]
fn generated_peer_configs_include_peer_telemetry_urls() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-peer-telemetry".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 19080,
        base_p2p_port: 23337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let urls = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("peer_telemetry_urls"))
        .and_then(toml::Value::as_array)
        .expect("peer_telemetry_urls array");
    let urls = urls
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        urls,
        vec![
            "http://127.0.0.1:19080/",
            "http://127.0.0.1:19081/",
            "http://127.0.0.1:19082/",
            "http://127.0.0.1:19083/",
        ],
    );
    let allowlist = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("preauth_allow_cidrs"))
        .and_then(toml::Value::as_array)
        .expect("preauth_allow_cidrs array");
    let allowlist = allowlist
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(allowlist, LOCALNET_PREAUTH_ALLOW_CIDRS);
    let allowlist = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("api_rate_limit_bypass_cidrs"))
        .and_then(toml::Value::as_array)
        .expect("api_rate_limit_bypass_cidrs array");
    let allowlist = allowlist
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(allowlist, LOCALNET_PREAUTH_ALLOW_CIDRS);
    let internal_trust = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("internal_api_trusted_cidrs"))
        .and_then(toml::Value::as_array)
        .expect("internal_api_trusted_cidrs array");
    let internal_trust = internal_trust
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(internal_trust, LOCALNET_INTERNAL_API_TRUSTED_CIDRS);
    assert_eq!(
        peer_cfg
            .get("torii")
            .and_then(toml::Value::as_table)
            .and_then(|torii| torii.get("max_content_len"))
            .and_then(toml::Value::as_integer),
        Some(
            i64::try_from(LOCALNET_TORII_MAX_CONTENT_LEN)
                .expect("LOCALNET_TORII_MAX_CONTENT_LEN fits i64")
        ),
        "localnet configs should pin the resolved Torii body-cap default explicitly"
    );
    let telemetry_profile = peer_cfg
        .get("telemetry_profile")
        .and_then(toml::Value::as_str)
        .expect("telemetry_profile string");
    assert_eq!(telemetry_profile, LOCALNET_TELEMETRY_PROFILE);
}
#[test]
fn generated_sora_profile_peer_config_includes_mcp_writer_profile() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-taira-mcp".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let mcp = peer_cfg
        .get("torii")
        .and_then(toml::Value::as_table)
        .and_then(|torii| torii.get("mcp"))
        .and_then(toml::Value::as_table)
        .expect("torii.mcp table");
    assert_eq!(
        peer_cfg
            .get("torii")
            .and_then(toml::Value::as_table)
            .and_then(|torii| torii.get("max_content_len"))
            .and_then(toml::Value::as_integer),
        Some(
            i64::try_from(LOCALNET_TORII_MAX_CONTENT_LEN)
                .expect("LOCALNET_TORII_MAX_CONTENT_LEN fits i64")
        ),
        "Sora-profile localnet should pin the resolved Torii body-cap default explicitly"
    );
    assert_eq!(
        mcp.get("enabled").and_then(toml::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        mcp.get("profile").and_then(toml::Value::as_str),
        Some("writer")
    );
    let network = peer_cfg
        .get("network")
        .and_then(toml::Value::as_table)
        .expect("network table");
    assert_eq!(
        network
            .get("max_frame_bytes_tx_gossip")
            .and_then(toml::Value::as_integer),
        Some(
            i64::try_from(LOCALNET_MAX_FRAME_BYTES_TX_GOSSIP_NEXUS)
                .expect("LOCALNET_MAX_FRAME_BYTES_TX_GOSSIP_NEXUS fits i64")
        ),
        "sora-profile localnet should raise tx gossip frame cap for large public writes"
    );
    assert_eq!(
        mcp.get("expose_operator_routes")
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    let allow_prefixes = mcp
        .get("allow_tool_prefixes")
        .and_then(toml::Value::as_array)
        .expect("allow_tool_prefixes array")
        .iter()
        .filter_map(toml::Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(allow_prefixes, vec!["iroha."]);
}
#[test]
fn generated_configs_use_strict_sumeragi_schema() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagami-channel-caps".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 20080,
        base_p2p_port: 24337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated config"),
    )
    .expect("parse generated config");
    let network = peer_cfg
        .get("network")
        .and_then(toml::Value::as_table)
        .expect("network table");
    let max_total_connections = network
        .get("max_total_connections")
        .and_then(toml::Value::as_integer)
        .and_then(|value| usize::try_from(value).ok())
        .expect("positive network connection bound");
    assert_eq!(
        max_total_connections, LOCALNET_MAX_TOTAL_CONNECTIONS,
        "the localnet connection envelope must be explicit"
    );
    assert_eq!(
        network
            .get("max_frame_bytes")
            .and_then(toml::Value::as_integer),
        Some(i64::try_from(LOCALNET_MAX_FRAME_BYTES).expect("production frame cap fits i64")),
        "the global encrypted frame cap must carry maximal topic plaintext plus P2P framing"
    );
    for (key, expected) in [
        (
            "max_frame_bytes_consensus",
            LOCALNET_MAX_FRAME_BYTES_CONSENSUS,
        ),
        (
            "max_frame_bytes_block_sync",
            LOCALNET_MAX_FRAME_BYTES_BLOCK_SYNC,
        ),
    ] {
        assert_eq!(
            network.get(key).and_then(toml::Value::as_integer),
            Some(i64::try_from(expected).expect("topic plaintext frame cap fits i64")),
            "{key} must remain within the global encrypted frame ceiling"
        );
    }
    assert_eq!(
        network
            .get("max_frame_bytes_control")
            .and_then(toml::Value::as_integer),
        Some(i64::try_from(LOCALNET_MAX_FRAME_BYTES_CONTROL).expect("control frame cap fits i64")),
        "the control topic must carry worst-case proposals and timeout certificates"
    );
    let sumeragi = peer_cfg
        .get("sumeragi")
        .and_then(toml::Value::as_table)
        .expect("sumeragi table");
    assert!(
        !sumeragi.contains_key("round_timeout_ms"),
        "round timing is derived from signed genesis cadence"
    );
    assert_eq!(
        sumeragi.get("role").and_then(toml::Value::as_str),
        Some("validator")
    );
    for retired in ["queues", "block", "limits", "storage"] {
        assert!(
            !sumeragi.contains_key(retired),
            "retired local consensus knob {retired}"
        );
    }
    let keys = sumeragi
        .get("keys")
        .and_then(toml::Value::as_table)
        .expect("sumeragi keys");
    assert_eq!(
        keys.get("allowed_algorithms")
            .and_then(toml::Value::as_array)
            .and_then(|algorithms| algorithms.first())
            .and_then(toml::Value::as_str),
        Some("bls_normal")
    );
    for retired in [
        "consensus_mode",
        "protocol_version",
        "da",
        "advanced",
        "recovery",
        "collectors",
        "rbc",
        "pacing_governor",
        "persistence",
    ] {
        assert!(
            !sumeragi.contains_key(retired),
            "generated config must not contain retired sumeragi.{retired}"
        );
    }
}
#[test]
fn localnet_tx_gossip_overrides_follow_fast_pipeline() {
    let overrides = localnet_tx_gossip_overrides(LOCALNET_PIPELINE_TIME_MS).expect("fast pipeline");
    assert_eq!(overrides.period_ms, LOCALNET_TX_GOSSIP_PERIOD_FAST_MS);
    assert_eq!(overrides.resend_ticks, LOCALNET_TX_GOSSIP_RESEND_TICKS_FAST);
    assert!(
        localnet_tx_gossip_overrides(LOCALNET_PIPELINE_TIME_MS + 1).is_none(),
        "slow pipelines should keep default tx gossip cadence"
    );
}
#[test]
fn perf_profile_permissioned_applies_bounded_runtime_limits() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: Some(LocalnetPerfProfile::Throughput10kPermissioned),
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("perf-profile-permissioned".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 48080,
        base_p2p_port: 48337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let source = TomlSource::from_file(temp.path().join("peer0.toml")).expect("read config");
    let parsed = actual::Root::from_toml_source(source).expect("config should parse");
    let rendered: toml::Table = fs::read_to_string(temp.path().join("peer0.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(rendered["sumeragi"].get("mint_finality_seed_fd").is_none());
    assert_eq!(
        parsed.queue.capacity.get(),
        LOCALNET_PERF_QUEUE_CAPACITY,
        "perf localnet should keep the fixed queue allocation bounded"
    );
    assert_eq!(
        parsed.queue.capacity_per_user.get(),
        LOCALNET_PERF_QUEUE_CAPACITY,
        "perf localnet per-user capacity should match the bounded queue capacity"
    );
    assert_eq!(
        parsed.torii.api_high_load_tx_threshold,
        Some(LOCALNET_PERF_QUEUE_CAPACITY),
        "perf localnet should expose backpressure at the bounded queue capacity"
    );
    assert!(parsed.sumeragi.local.is_empty());
    let expected_filter: Directives = LOCALNET_PERF_LOGGER_FILTER
        .parse()
        .expect("perf logger filter should parse");
    assert_eq!(parsed.logger.filter, Some(expected_filter));
    assert_eq!(
        parsed.pipeline.signature_batch_max_ed25519,
        LOCALNET_SIGNATURE_BATCH_MAX_ED25519
    );
    let genesis_path = temp.path().join("genesis.json");
    let manifest = genesis_json_from_path(&genesis_path);
    let params = genesis_parameters(&manifest);
    assert_eq!(params.sumeragi().block_cadence_ms().get(), 1_000);
    assert_eq!(
        params.block.max_transactions.get(),
        LOCALNET_BLOCK_MAX_TRANSACTIONS
    );
}
#[test]
fn perf_profile_npos_applies_election_and_runtime_limits() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: Some(LocalnetPerfProfile::Throughput10kNpos),
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("perf-profile-npos".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 58080,
        base_p2p_port: 58337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let source = TomlSource::from_file(temp.path().join("peer0.toml")).expect("read config");
    let parsed = actual::Root::from_toml_source(source).expect("config should parse");
    let expected_filter: Directives = LOCALNET_PERF_LOGGER_FILTER
        .parse()
        .expect("perf logger filter should parse");
    assert_eq!(parsed.logger.filter, Some(expected_filter));
    assert_eq!(
        parsed.pipeline.signature_batch_max_ed25519,
        LOCALNET_SIGNATURE_BATCH_MAX_ED25519
    );
    assert!(parsed.sumeragi.local.is_empty());
    let genesis_path = temp.path().join("genesis.json");
    let manifest = genesis_json_from_path(&genesis_path);
    let params = genesis_parameters(&manifest);
    assert_eq!(params.sumeragi().block_cadence_ms().get(), 1_000);
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
fn validate_localnet_options_rejects_perf_profile_mismatch() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: Some(LocalnetPerfProfile::Throughput10kNpos),
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: None,
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 58080,
        base_p2p_port: 58337,
        out_dir: PathBuf::from("localnet"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    let err = validate_localnet_options(&opts).expect_err("mismatch should fail");
    assert!(
        err.to_string().contains("perf-profile"),
        "unexpected error: {err}"
    );
}
#[test]
fn test_build_uses_explicit_fixture_for_unseeded_genesis_helpers() {
    let (public_key, _) = generate_genesis_key_pair(None, GENESIS_SEED)
        .expect("unseeded genesis key fixture should succeed");
    assert_eq!(
        public_key,
        REAL_GENESIS_ACCOUNT_KEYPAIR.public_key().clone()
    );
}
#[test]
fn extra_account_keys_are_unique_when_unseeded() {
    let (first, _) = generate_account_key_pair(None, b"acct0").expect("first random account key");
    let (second, _) = generate_account_key_pair(None, b"acct1").expect("second random account key");
    assert_ne!(first, second);
}
type ConsensusHandshakeMetaTest = iroha_data_model::parameter::system::ConsensusHandshakeMetadata;
#[test]
fn generated_genesis_handshake_meta_decodes() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("Iroha".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: vec![AssetSpec {
            id: localnet_sample_asset_literal(),
            name: LOCALNET_SAMPLE_ASSET_NAME.to_owned(),
            alias: None,
            owned_by: ALICE_ID.clone(),
            mint_to: ALICE_ID.clone(),
            quantity: 100,
        }],
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let genesis_path = temp.path().join("genesis.signed.nrt");
    let bytes = fs::read(&genesis_path).expect("read signed genesis");
    let block =
        decode_framed_signed_block(&bytes).expect("decode signed genesis from framed payload");
    let mut found = None;
    for tx in block.external_transactions() {
        if let Executable::Instructions(batch) = tx.instructions() {
            for instr in batch {
                if let Some(set_param) = instr.as_any().downcast_ref::<SetParameter>()
                    && let Parameter::Custom(custom) = set_param.inner()
                    && custom.id() == &consensus_metadata::handshake_meta_id()
                {
                    let meta: ConsensusHandshakeMetaTest = custom
                        .payload()
                        .try_into_any()
                        .expect("decode consensus_handshake_meta payload");
                    found = Some(meta);
                }
            }
        }
    }
    let meta = found.expect("handshake metadata must be present");
    assert_eq!(
        meta.wire_protocol_version,
        u32::from(PROTOCOL_VERSION),
        "unexpected wire proto version"
    );
    assert!(
        meta.consensus_fingerprint.to_string().starts_with("0x"),
        "fingerprint must be hex-prefixed"
    );
}
#[test]
fn localnet_signed_genesis_uses_first_release_npos_context() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-da-enabled".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 28180,
        base_p2p_port: 28437,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet");
    let manifest = localnet_genesis_for_opts(&opts);
    assert_eq!(manifest.consensus_mode(), SumeragiConsensusMode::Npos);
    assert!(manifest.consensus_fingerprint().is_some());
}
#[test]
fn default_block_cadence_is_injected_when_unset() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("default-pipeline-time".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 28090,
        base_p2p_port: 28357,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let genesis_path = temp.path().join("genesis.json");
    let manifest = genesis_json_from_path(&genesis_path);
    let params = genesis_parameters(&manifest);
    assert_eq!(
        params.sumeragi().block_cadence_ms().get(),
        LOCALNET_PIPELINE_TIME_MS
    );
}
#[test]
fn localnet_sets_block_max_transactions() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-block-max".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 30080,
        base_p2p_port: 30337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let manifest = localnet_genesis_for_opts(&opts);
    let params = manifest
        .effective_parameters()
        .expect("generated localnet genesis has one structured parameter block");
    assert_eq!(
        params.block().max_transactions().get(),
        LOCALNET_BLOCK_MAX_TRANSACTIONS,
        "localnet should raise max transactions per block"
    );
}
#[test]
fn localnet_npos_bootstraps_public_lane_stake() {
    use std::collections::BTreeSet;
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-npos-stake".to_owned()),
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
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let manifest = localnet_genesis_for_opts(&opts);
    let mut validators = Vec::new();
    let mut activations = Vec::new();
    for instruction in manifest.instructions() {
        if let Some(register) = instruction
            .as_any()
            .downcast_ref::<RegisterPublicLaneValidator>()
        {
            validators.push(register);
        }
        if let Some(activate) = instruction
            .as_any()
            .downcast_ref::<ActivatePublicLaneValidator>()
        {
            activations.push(activate);
        }
    }
    assert_eq!(
        validators.len(),
        usize::from(opts.peers.get()),
        "expected one public-lane validator per peer"
    );
    assert_eq!(
        activations.len(),
        validators.len(),
        "expected one activation per public-lane validator"
    );
    let params = manifest
        .effective_parameters()
        .expect("generated localnet genesis has one structured parameter block");
    let expected_stake_amount = localnet_npos_stake_amount(
        &params,
        opts.perf_profile
            .map(LocalnetPerfProfile::spec)
            .map(|spec| spec.stake_amount),
    )
    .unwrap();
    for register in &validators {
        assert_eq!(register.lane_id, LaneId::SINGLE);
        assert_eq!(register.validator, register.stake_account);
        assert_eq!(register.initial_stake, expected_stake_amount);
    }
    for activate in &activations {
        assert_eq!(activate.lane_id, LaneId::SINGLE);
    }
    let peers = build_peers(
        opts.peers.get(),
        opts.seed.as_ref().map(String::as_bytes),
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("test localnet peer key generation should succeed");
    let expected: BTreeSet<_> = peers
        .iter()
        .map(|peer| AccountId::new(peer.public_key.clone()))
        .collect();
    let actual: BTreeSet<_> = validators
        .iter()
        .map(|register| register.validator.clone())
        .collect();
    assert_eq!(actual, expected, "validator roster should match peers");
    let actual_activations: BTreeSet<_> = activations
        .iter()
        .map(|activate| activate.validator.clone())
        .collect();
    assert_eq!(
        actual_activations, expected,
        "activation roster should match peers"
    );
}
/// Staking is NPoS-only, so a permissioned localnet stakes nothing: it registers the Nexus
/// support accounts and every validator account, and its committee is the genesis roster.
#[test]
fn permissioned_localnet_registers_support_accounts_without_staking() {
    use std::collections::BTreeSet;
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("localnet-permissioned-support-accounts".to_owned()),
        bind_host: DEFAULT_BIND_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 34080,
        base_p2p_port: 34337,
        out_dir: temp.path().to_path_buf(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let manifest = RawGenesisTransaction::from_path(temp.path().join("genesis.json"))
        .expect("parse generated genesis");
    let parameters = manifest
        .effective_parameters()
        .expect("read generated genesis parameters");
    assert!(
        parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .is_none(),
        "permissioned genesis must not commit NPoS epoch parameters"
    );
    assert!(
        !manifest.instructions().any(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
                .is_some()
                || instruction
                    .as_any()
                    .downcast_ref::<ActivatePublicLaneValidator>()
                    .is_some()
        }),
        "permissioned localnets must not stake public-lane validators"
    );
    let registered_accounts: BTreeSet<_> = manifest
        .instructions()
        .filter_map(
            |instruction| match instruction.as_any().downcast_ref::<RegisterBox>() {
                Some(RegisterBox::Account(register)) => {
                    Some(account_id_runtime_literal(register.object().id(), None))
                }
                _ => None,
            },
        )
        .collect();
    let peers = build_peers(
        opts.peers.get(),
        opts.seed.as_ref().map(String::as_bytes),
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("test localnet peer key generation should succeed");
    for peer in &peers {
        assert!(
            registered_accounts.contains(&account_id_runtime_literal(
                &peer.validator_account_id(false),
                None
            )),
            "every validator account is registered in genesis"
        );
    }
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let nexus = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .expect("nexus table");
    let staking = nexus
        .get("staking")
        .and_then(toml::Value::as_table)
        .expect("nexus staking table");
    for key in ["stake_escrow_account_id", "slash_sink_account_id"] {
        let literal = staking
            .get(key)
            .and_then(toml::Value::as_str)
            .expect("staking account literal");
        assert!(
            registered_accounts.contains(literal),
            "{key} must name an account registered in genesis"
        );
    }
    assert!(!nexus.contains_key("fees"));
    assert_eq!(
        nexus["storage"]["local_budget_bytes"].as_integer(),
        Some(LOCALNET_NEXUS_STORAGE_BUDGET_BYTES as i64),
        "permissioned localnet storage must have the same finite developer cap"
    );
    assert!(
        manifest
            .crypto()
            .allowed_signing
            .contains(&iroha_crypto::Algorithm::BlsNormal)
    );
}
#[test]
fn localnet_npos_stake_amount_respects_min_self_bond() {
    let mut params = Parameters::default();
    let npos = SumeragiNposParameters {
        min_self_bond: (LOCALNET_STAKE_AMOUNT + 1).into(),
        ..Default::default()
    };
    let expected = npos.min_self_bond.clone();
    params.set_parameter(Parameter::Custom(npos.into_custom_parameter()));
    let stake_amount = localnet_npos_stake_amount(&params, Some(LOCALNET_STAKE_AMOUNT)).unwrap();
    assert_eq!(stake_amount, expected);
}
fn assert_localnet_dataspace_catalog_quorum(out_dir: &Path, peer_count: NonZeroU16) {
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(out_dir.join("peer0.toml")).expect("read generated peer config"),
    )
    .expect("parse peer config");
    let catalog = peer_cfg
        .get("nexus")
        .and_then(toml::Value::as_table)
        .and_then(|nexus| nexus.get("dataspace_catalog"))
        .and_then(toml::Value::as_array)
        .expect("nexus dataspace catalog");
    let fault_tolerance = localnet_dataspace_fault_tolerance(peer_count);
    let committee_size = fault_tolerance
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .expect("committee size");
    assert_eq!(
        committee_size,
        u32::from(peer_count.get()),
        "committee size should match peer count"
    );
    for entry in catalog {
        let entry = entry.as_table().expect("dataspace entry");
        let alias = entry
            .get("alias")
            .and_then(toml::Value::as_str)
            .expect("dataspace alias");
        let id = entry
            .get("id")
            .and_then(toml::Value::as_integer)
            .expect("dataspace id");
        assert_eq!(
            entry
                .get("fault_tolerance")
                .and_then(toml::Value::as_integer),
            Some(i64::from(fault_tolerance)),
            "fault tolerance should scale with peers"
        );
        if alias == "universal" {
            assert!(
                entry.get("manifest_hash").is_none(),
                "universal dataspace keeps the reserved id without a manifest hash"
            );
        } else {
            let expected_manifest = localnet_dataspace_manifest_hash(id);
            assert_eq!(
                entry.get("manifest_hash").and_then(toml::Value::as_str),
                Some(expected_manifest.as_str()),
                "non-universal dataspaces must carry an id-derived manifest hash"
            );
        }
    }
}
#[test]
fn localnet_npos_validator_roster_and_quorum_match_peer_count() {
    use std::collections::BTreeSet;
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("tmp dir");
    let peer_count = NonZeroU16::new(7).expect("non-zero");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: peer_count,
        seed: Some("localnet-npos-quorum".to_owned()),
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
    generate_localnet(&opts, &mut BufWriter::new(Vec::new())).expect("generate localnet files");
    let peer_cfg: toml::Value = toml::from_str(
        &fs::read_to_string(temp.path().join("peer0.toml"))
            .expect("read seven-validator peer config"),
    )
    .expect("parse seven-validator peer config");
    assert!(peer_cfg["sumeragi"].get("queues").is_none());
    let manifest = localnet_genesis_for_opts(&opts);
    let validators: Vec<_> = manifest
        .instructions()
        .filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterPublicLaneValidator>()
        })
        .collect();
    assert_eq!(
        validators.len(),
        usize::from(peer_count.get()),
        "expected one public-lane validator per peer"
    );
    let peers = build_peers(
        peer_count.get(),
        opts.seed.as_ref().map(String::as_bytes),
        opts.base_api_port,
        opts.base_p2p_port,
    )
    .expect("test localnet peer key generation should succeed");
    let expected: BTreeSet<_> = peers
        .iter()
        .map(|peer| AccountId::new(peer.public_key.clone()))
        .collect();
    let actual: BTreeSet<_> = validators
        .iter()
        .map(|register| register.validator.clone())
        .collect();
    assert_eq!(actual, expected, "validator roster should match peers");
    let staking = &peer_cfg["nexus"]["staking"];
    let stake_asset_id = AssetDefinitionId::parse_address_literal(
        staking["stake_asset_id"]
            .as_str()
            .expect("configured stake asset"),
    )
    .expect("canonical stake asset");
    let escrow_account_id = AccountId::parse_encoded(
        staking["stake_escrow_account_id"]
            .as_str()
            .expect("configured stake escrow"),
    )
    .expect("canonical stake escrow");
    for register in &validators {
        assert_eq!(
            register.monetary_plan,
            iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                AssetId::new(stake_asset_id.clone(), register.stake_account.clone()),
                AssetId::new(stake_asset_id.clone(), escrow_account_id.clone()),
                register.initial_stake.clone(),
            ),
        );
    }
    assert_localnet_dataspace_catalog_quorum(temp.path(), peer_count);
}
#[test]
fn localnet_npos_election_ceiling_matches_generated_committee() {
    let chain_id = ChainId::from(DEFAULT_CHAIN_ID);
    for count in [4, 7, 31] {
        let peers = NonZeroU16::new(count).expect("nonzero committee");
        let mut parameters = Parameters::default();
        apply_localnet_npos_overrides(&mut parameters, &chain_id, peers).unwrap();
        let npos = parameters
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .map(SumeragiNposParameters::from_custom_parameter)
            .transpose()
            .expect("valid fixture NPoS parameters")
            .flatten()
            .expect("generated NPoS parameters");
        assert_eq!(npos.max_validators(), u32::from(count));
        assert_eq!(
            npos.epoch_length_blocks(),
            parameters.sumeragi().epoch_length_blocks
        );
        assert!(iroha_data_model::block::consensus::is_valid_committee_size(
            usize::try_from(npos.max_validators()).expect("bounded committee")
        ));
    }
}
