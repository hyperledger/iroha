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
    let peers = build_peers(4, Some(seed), 8_080, 13_337).unwrap();
    let (genesis_public_key, _) = generate_genesis_key_pair(Some(seed), GENESIS_SEED).unwrap();
    let chain_id = "disposable-parent-localnet";
    let original = generate_raw_genesis(
        &genesis_public_key,
        SumeragiConsensusMode::Permissioned,
        chain_id,
        &peers,
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
        &peers,
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
fn localnet_kagemusha_authority_matches_canonical_four_validator_topology() {
    let peers = build_peers(4, Some(b"kagemusha-authority-fixture"), 8_080, 13_337)
        .expect("derive deterministic localnet peers");
    let mut expected_topology = peers
        .iter()
        .map(|peer| PeerId::new(peer.public_key.clone()))
        .collect::<Vec<_>>();
    expected_topology.sort();
    let parameters = localnet_kagemusha_mint_finality_genesis_parameters(&peers)
        .expect("derive validated localnet KAGEMUSHA authority");
    let actual_topology = parameters
        .authority_generation
        .validators
        .iter()
        .map(|keys| keys.validator.clone())
        .collect::<Vec<_>>();
    assert_eq!(actual_topology, expected_topology);
    assert_eq!(actual_topology.len(), 4);
    assert_eq!(parameters.authority_generation.generation, 0);
    let encoded = norito::json::to_value(&parameters).expect("encode current genesis authority");
    assert!(encoded.get("next_epoch_roster").is_none());
    assert_eq!(
        parameters,
        localnet_kagemusha_mint_finality_genesis_parameters(&peers)
            .expect("repeat deterministic localnet KAGEMUSHA authority derivation")
    );
}

#[test]
fn canonical_taira_generation_binds_four_runtime_signers_to_validator_peers() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir()
        .expect("temporary Taira directory");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: Some(SoraProfile::Nexus),
        perf_profile: None,
        peers: NonZeroU16::new(TAIRA_TESTNET_PEERS).expect("four peers"),
        seed: Some("taira-runtime-signer-fixture".to_owned()),
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
    let mut output = BufWriter::new(Vec::new());
    generate_localnet_with_chain(&opts, &mut output, Some(PUBLIC_TAIRA_CHAIN_ID), None)
        .expect("generate canonical Taira localnet");
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
    let definitions = manifest
        .instructions()
        .filter_map(
            |instruction| match instruction.as_any().downcast_ref::<RegisterBox>() {
                Some(RegisterBox::AssetDefinition(register)) => Some(register.object()),
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    let digital_shekel_id = AssetDefinitionId::parse_address_literal(TAIRA_DIGITAL_SHEKEL_ASSET_ID)
        .expect("Digital Shekel identity");
    let digital_shekels = definitions
        .iter()
        .filter(|definition| definition.id == digital_shekel_id)
        .collect::<Vec<_>>();
    assert_eq!(
        digital_shekels.len(),
        1,
        "one canonical Digital Shekel definition"
    );
    let template: json::Value = json::from_str(include_str!(
        "../../../../../configs/soranexus/taira/genesis.template.json"
    ))
    .expect("canonical public Taira template");
    let expected = template["transactions"]
        .as_array()
        .expect("template transactions")
        .iter()
        .flat_map(|transaction| transaction["instructions"].as_array().into_iter().flatten())
        .filter_map(|instruction| instruction.pointer("/Register/AssetDefinition"))
        .find(|definition| definition["id"].as_str() == Some(TAIRA_DIGITAL_SHEKEL_ASSET_ID))
        .expect("template Digital Shekel definition");
    assert_eq!(
        json::to_value(*digital_shekels[0]).expect("native definition JSON"),
        *expected
    );
    assert!(
        definitions
            .iter()
            .all(|definition| definition.id.to_string() != LOCALNET_KAGEMUSHA_ASSET_ID)
    );
    let digital_shekel_alias = TAIRA_DIGITAL_SHEKEL_ASSET_ALIAS
        .parse::<AssetDefinitionAlias>()
        .expect("Digital Shekel alias");
    assert_eq!(
        manifest
            .instructions()
            .filter(|instruction| {
                instruction
                    .as_any()
                    .downcast_ref::<SetAssetDefinitionAlias>()
                    .is_some_and(|binding| {
                        binding.asset_definition_id() == &digital_shekel_id
                            && binding.alias().as_ref() == Some(&digital_shekel_alias)
                    })
            })
            .count(),
        1,
    );
    let operator_asset = AssetId::new(
        digital_shekel_id.clone(),
        operator_identity.account_id.clone(),
    );
    let minted = manifest
        .instructions()
        .filter_map(
            |instruction| match instruction.as_any().downcast_ref::<MintBox>() {
                Some(MintBox::Asset(mint)) if mint.destination() == &operator_asset => {
                    Some(mint.object().clone())
                }
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(
        minted,
        vec![Quantity::from(TAIRA_DIGITAL_SHEKEL_INITIAL_QUANTITY)]
    );
    assert!(manifest.instructions().any(|instruction| {
        matches!(instruction.as_any().downcast_ref::<TransferBox>(),
            Some(TransferBox::AssetDefinition(transfer))
                if transfer.object() == &digital_shekel_id
                    && transfer.destination() == &operator_identity.account_id)
    }));
    let readme = fs::read_to_string(temp.path().join("README.md")).expect("generated public guide");
    assert!(readme.contains(TAIRA_DIGITAL_SHEKEL_ASSET_ID));
    assert!(readme.contains(TAIRA_DIGITAL_SHEKEL_ASSET_ALIAS));
    assert!(!readme.contains(LOCALNET_KAGEMUSHA_ASSET_ID));
    assert!(!readme.contains(LOCALNET_KAGEMUSHA_ASSET_ALIAS));
    assert!(readme.contains("Registered lanes: `0,1,2,3,4,7`"));
    assert!(readme.contains("lane-manifests/is.manifest.json"));
    let peer_config_text = fs::read_to_string(temp.path().join("peer0.toml"))
        .expect("read generated Taira peer config");
    let peer_config: toml::Value =
        toml::from_str(&peer_config_text).expect("parse generated Taira peer config");
    let nexus_config = peer_config["nexus"].as_table().expect("Taira Nexus config");
    assert_eq!(nexus_config["lane_count"].as_integer(), Some(8));
    let dataspace_config = nexus_config["dataspace_catalog"]
        .as_array()
        .expect("Taira physical dataspace catalog");
    let is_config = dataspace_config
        .iter()
        .find(|entry| entry["alias"].as_str() == Some("is"))
        .expect("Digital Shekel physical dataspace");
    assert_eq!(
        is_config["id"].as_integer(),
        Some(6_647_857_470_246_403_404)
    );
    assert_eq!(
        is_config["manifest_hash"].as_str(),
        Some("4cbd76b725ef415c000000000000000000000000000000000000000000000000")
    );
    let routing = nexus_config["routing_policy"]
        .as_table()
        .expect("Taira routes");
    let rules = routing["rules"].as_array().expect("Taira route rules");
    assert_eq!(
        rules.len(),
        6,
        "four baseline routes plus two is authority routes"
    );
    for (rule, pattern) in rules[4..].iter().zip(["*@is", "*@*.is"]) {
        assert_eq!(rule["lane"].as_integer(), Some(7));
        assert_eq!(rule["dataspace"].as_str(), Some("is"));
        assert_eq!(rule["matcher"]["account"].as_str(), Some(pattern));
    }
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
    assert_eq!(public_registrations.len(), 12);
    assert_eq!(
        public_registrations
            .iter()
            .map(|registration| registration.lane_id.as_u32())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 3, 4]),
        "the admin-managed is lane must not gain a public staking pool"
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
    assert!(start_script.contains("peer{}.fd199"));
    assert!(start_script.contains("os.dup2(launch_fd, descriptor, inheritable=True)"));
    assert!(start_script.contains("pass_fds = (198, 199)"));
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
        assert_eq!(
            parsed.sumeragi.mint_finality_seed_fd, None,
            "Taira launcher owns FD 199 and must reject a second configured source"
        );
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
        assert!(
            parsed
                .nexus
                .lane_catalog
                .lanes()
                .iter()
                .filter(|lane| lane.id.as_u32() < 5)
                .all(|lane| lane.governance.is_none()),
            "IS governance must not change the baseline lanes"
        );
        assert_eq!(parsed.nexus.lane_catalog.lane_count().get(), 8);
        assert_eq!(
            parsed
                .nexus
                .lane_catalog
                .lanes()
                .iter()
                .map(|lane| lane.id.as_u32())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 7],
            "BPNG5 and DPN6 remain absent in the fresh baseline"
        );
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
            vec![
                (0, "universal", 1),
                (10, "paynet", 1),
                (12, "nexus", 1),
                (6_647_857_470_246_403_404, "is", 1)
            ]
        );
        let is_lane = parsed
            .nexus
            .lane_catalog
            .lanes()
            .iter()
            .find(|lane| lane.id.as_u32() == 7)
            .expect("native parsed IS lane");
        assert_eq!(
            is_lane.dataspace_id,
            DataSpaceId::new(TAIRA_IS_DATASPACE_ID)
        );
        assert_eq!(
            is_lane.visibility,
            iroha_data_model::nexus::LaneVisibility::Restricted
        );
        assert_eq!(
            is_lane.storage,
            iroha_data_model::nexus::LaneStorageProfile::FullReplica
        );
        assert_eq!(is_lane.governance.as_deref(), Some("parliament"));
        let _manifest_scope = ChainDiscriminantGuard::enter(manifest.chain_discriminant());
        let registry = iroha_core::governance::manifest::LaneManifestRegistry::from_config(
            &parsed.nexus.lane_catalog,
            &parsed.nexus.governance,
            &parsed.nexus.registry,
        );
        registry
            .validate_active_coverage_for_catalog(&parsed.nexus.lane_catalog)
            .expect("native authenticated manifest coverage");
        let is_lane_id = LaneId::new(TAIRA_IS_LANE_INDEX);
        assert_eq!(registry.lane_quorum(is_lane_id), Some(3));
        assert_eq!(
            registry
                .lane_validator_bindings(is_lane_id)
                .expect("IS manifest validator bindings")
                .into_iter()
                .map(|binding| {
                    assert!(binding.torii_url.is_none());
                    (binding.validator, binding.peer_id)
                })
                .collect::<BTreeSet<_>>(),
            peers
                .iter()
                .map(|peer| (
                    peer.validator_account_id(true),
                    PeerId::from(peer.public_key.clone())
                ))
                .collect::<BTreeSet<_>>()
        );
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
        let seed_path = temp
            .path()
            .join("runtime")
            .join(MINT_FINALITY_SEED_DIRECTORY)
            .join(format!("peer{peer_index}.seed"));
        let seed = fs::read(&seed_path).expect("read private mint-finality seed");
        assert_eq!(seed.as_slice(), peer.mint_finality_seed.as_ref());
        assert_eq!(seed.len(), 32);
        let seed_metadata = fs::metadata(&seed_path).expect("inspect mint-finality seed");
        #[cfg(unix)]
        {
            assert_eq!(seed_metadata.permissions().mode() & 0o7777, 0o600);
            assert_eq!(seed_metadata.nlink(), 1);
        }
        assert!(!start_script.contains(&hex::encode(&seed)));
        assert!(
            !fs::read_to_string(temp.path().join("genesis.json"))
                .expect("public genesis manifest")
                .contains(&hex::encode(&seed))
        );
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
        effective_localnet_assets_for_client(&opts.assets, client_account_id, false)
    };
    let mut genesis = generate_raw_genesis(
        &genesis_public_key,
        opts.consensus_mode,
        DEFAULT_CHAIN_ID,
        &peers,
    )
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
        assert_eq!(config.sumeragi.mint_finality_seed_fd, Some(199));
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
fn localnet_asset_defaults_are_selected_by_exact_taira_chain_context() {
    let client = localnet_client_account_id();
    let taira = effective_localnet_assets_for_client(&[], &client, true);
    assert_eq!(taira.len(), 1);
    assert_eq!(taira[0].id, TAIRA_DIGITAL_SHEKEL_ASSET_ID);
    assert_eq!(
        taira[0].alias.as_deref(),
        Some(TAIRA_DIGITAL_SHEKEL_ASSET_ALIAS)
    );
    assert_eq!(taira[0].name, "ds");
    assert_eq!(taira[0].quantity, 1_000_000_000);
    assert_eq!(taira[0].owned_by, client);
    assert_eq!(taira[0].mint_to, client);
    let generic = effective_localnet_assets_for_client(&[], &client, false);
    assert_eq!(generic.len(), 1);
    assert_eq!(generic[0].id, LOCALNET_KAGEMUSHA_ASSET_ID);
    assert_eq!(
        generic[0].alias.as_deref(),
        Some(LOCALNET_KAGEMUSHA_ASSET_ALIAS)
    );
    assert_eq!(generic[0].name, LOCALNET_KAGEMUSHA_ASSET_NAME);
    assert_eq!(generic[0].quantity, 100);
    assert_eq!(generic[0].owned_by, client);
    assert_eq!(generic[0].mint_to, client);
}

#[test]
fn localnet_asset_validation_rejects_selected_builtin_identity_or_alias_collision() {
    let client = localnet_client_account_id();
    for taira in [false, true] {
        let builtin = localnet_kagemusha_asset_spec_for_client(&client, taira);
        let by_id = requested_localnet_asset_spec(&builtin.id).expect("requested builtin identity");
        assert!(validate_localnet_asset_specs(&[by_id], taira).is_err());
        let mut by_alias = requested_localnet_asset_spec(&localnet_sample_asset_literal())
            .expect("distinct requested identity");
        by_alias.alias = builtin.alias;
        assert!(validate_localnet_asset_specs(&[by_alias], taira).is_err());
        let other_profile = localnet_kagemusha_asset_spec_for_client(&client, !taira);
        validate_localnet_asset_specs(&[other_profile], taira)
            .expect("the other workflow's independent asset can be explicitly requested");
    }
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
fn generated_localnet_bootstraps_universal_kagemusha_asset() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagemusha-bootstrap".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Npos,
    };
    let manifest = localnet_genesis_for_opts(&opts);
    let kagemusha_asset_id = AssetDefinitionId::parse_address_literal(LOCALNET_KAGEMUSHA_ASSET_ID)
        .expect("KAGEMUSHA V1 asset id");
    let kagemusha_alias = LOCALNET_KAGEMUSHA_ASSET_ALIAS
        .parse::<AssetDefinitionAlias>()
        .expect("KAGEMUSHA V1 asset alias");
    let client_account_id = localnet_client_account_id();
    let (genesis_public_key, _) =
        generate_genesis_key_pair(opts.seed.as_ref().map(String::as_bytes), GENESIS_SEED)
            .expect("test localnet genesis key generation should succeed");
    let genesis_account_id = AccountId::new(genesis_public_key);
    let expected_mint_destination =
        AssetId::new(kagemusha_asset_id.clone(), client_account_id.clone());
    let has_definition = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .is_some_and(|register| {
                matches!(
                    register,
                    RegisterBox::AssetDefinition(register)
                        if register.object().id == kagemusha_asset_id
                )
            })
    });
    assert!(
        has_definition,
        "localnet must register the built-in KAGEMUSHA V1 asset"
    );
    let has_alias_binding = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<SetAssetDefinitionAlias>()
            .is_some_and(|set_alias| {
                set_alias.asset_definition_id() == &kagemusha_asset_id
                    && set_alias.alias().as_ref() == Some(&kagemusha_alias)
            })
    });
    assert!(
        has_alias_binding,
        "localnet must bind the built-in KAGEMUSHA V1 asset alias"
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
        "localnet must mint the built-in KAGEMUSHA V1 asset to the client signer"
    );
    let has_owner_transfer = manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<TransferBox>()
            .is_some_and(|transfer| match transfer {
                TransferBox::AssetDefinition(transfer_asset) => {
                    transfer_asset.object() == &kagemusha_asset_id
                        && transfer_asset.destination() == &client_account_id
                }
                _ => false,
            })
    });
    assert!(
        has_owner_transfer,
        "localnet must transfer KAGEMUSHA V1 asset ownership to the client signer"
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
        assert_ne!(
            permission_name, "CanManageKagemushaReserve",
            "localnet genesis must not grant the retired KAGEMUSHA reserve permission"
        );
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
fn permissioned_localnet_genesis_grants_no_kagemusha_reserve_permission() {
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("permissioned-kagemusha-reserve-dedup".to_owned()),
        bind_host: DEFAULT_PUBLIC_HOST.to_owned(),
        public_host: DEFAULT_PUBLIC_HOST.to_owned(),
        base_api_port: 29080,
        base_p2p_port: 33337,
        out_dir: PathBuf::from("unused"),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    let manifest = localnet_genesis_for_opts(&opts);
    let kagemusha_reserve_grants = manifest
        .instructions()
        .filter_map(|instruction| instruction.as_any().downcast_ref::<GrantBox>())
        .filter_map(|grant| match grant {
            GrantBox::Permission(grant_permission) => Some(grant_permission),
            _ => None,
        })
        .filter(|grant_permission| grant_permission.object().name() == "CanManageKagemushaReserve")
        .count();
    assert_eq!(
        kagemusha_reserve_grants, 0,
        "permissioned localnet genesis must not grant the retired KAGEMUSHA reserve permission"
    );
}
#[test]
#[allow(clippy::too_many_lines)]
fn generated_localnet_needs_no_kagemusha_feature_switch() {
    let temp = crate::localnet::localnet_test_helpers::private_tempdir().expect("make temp dir");
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("make localnet output directory owner-held");
    let opts = LocalnetOptions {
        service_profile: crate::localnet::LocalnetServiceProfile::Standard,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).expect("non-zero"),
        seed: Some("kagemusha-config".to_owned()),
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
    assert_eq!(
        peer_cfg["sumeragi"]["mint_finality_seed_fd"].as_integer(),
        Some(199)
    );
    let retained = fs::metadata(temp.path().join("runtime/mint-finality-signers/peer0.seed"))
        .expect("ordinary localnet retains the exact private Pasta seed");
    assert_eq!(retained.len(), 32);
    #[cfg(unix)]
    assert_eq!(retained.permissions().mode() & 0o7777, 0o600);
    let start = fs::read_to_string(temp.path().join("start.sh"))
        .expect("read ordinary localnet start script");
    assert!(start.contains("launch_ordinary_validator_with_mint_seed(cmd, env)"));
    assert!(start.contains("pass_fds=(_MINT_SEED_FD,)"));
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
    assert_eq!(
        parsed.sumeragi.mint_finality_seed_fd,
        Some(199),
        "permissioned voters are seated in the signed Pasta authority too"
    );
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
    let err = validate_localnet_options(&opts, false).expect_err("mismatch should fail");
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
