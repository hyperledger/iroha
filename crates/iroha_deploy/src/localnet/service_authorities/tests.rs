//! Genuine generated genesis, retained identity and private service-credential regressions.
use super::*;
use iroha_fs::{PrivateDirectory, PublishMode};

fn prepared(root: &Path) -> PreparedLocalnet {
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    prepare_localnet_at(
        "authorities",
        root,
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .expect("prepare and execute genuine signed authority genesis")
}

#[test]
fn reserve_accounts_are_distinct_non_signing_public_points_bound_to_network_operations() {
    let seed = [0x73; 32];
    let pair = KeyPair::try_from_seed(seed.to_vec(), iroha_crypto::Algorithm::Ed25519).unwrap();
    let operations = AccountId::new(pair.public_key().clone());
    let other = KeyPair::try_from_seed(vec![0x74; 32], iroha_crypto::Algorithm::Ed25519).unwrap();
    let accounts = reserve_accounts(&operations).unwrap();
    assert_eq!(accounts, reserve_accounts(&operations).unwrap());
    assert_ne!(accounts.custody, accounts.treasury);
    assert_ne!(
        accounts,
        reserve_accounts(&AccountId::new(other.public_key().clone())).unwrap()
    );
    for account in [&accounts.custody, &accounts.treasury] {
        assert_eq!(
            account.try_signatory().unwrap().algorithm(),
            iroha_crypto::Algorithm::Ed25519
        );
        assert_ne!(account, &operations);
    }
    assert_ne!(
        Json::new(ReserveAccountRole::ReserveCustody),
        Json::new(ReserveAccountRole::ReserveTreasury)
    );
}

#[test]
fn owner_seed_is_initial_only_and_uses_the_explicit_address_profile() {
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let seed = Some(b"owner-seed-test".as_slice());
    let manager = localnet_ephemeral_identity(seed, b"manager").unwrap();
    let http = localnet_ephemeral_identity(seed, b"http").unwrap();
    let onboarding = localnet_ephemeral_identity(seed, b"onboarding").unwrap();
    let generated = generate(
        LocalnetServiceProfile::StreamTokenAuthorities,
        temporary.path(),
        seed,
        &manager,
        &http,
        &onboarding,
    )
    .unwrap()
    .unwrap();
    let _ambient = ChainDiscriminantGuard::enter(369);
    let rendered = generated
        .configure_peer(
            "[gov]\nconviction_step_blocks = 10\n",
            Some(42),
            temporary.path(),
            0,
        )
        .unwrap();
    let table = crate::secret_toml::Table::new(
        crate::secret_toml::parse_table(&rendered, "seed fixture").unwrap(),
    );
    let gov = table.get("gov").unwrap().as_table().unwrap();
    assert_eq!(gov["conviction_step_blocks"].as_integer(), Some(10));
    let owners = gov["sorafs_provider_owners"].as_table().unwrap();
    assert_eq!(owners.len(), PROVIDER_COUNT);
    for provider in &generated.providers {
        assert_eq!(
            owners[hex::encode(provider.provider_id.as_bytes()).as_str()].as_str(),
            Some(
                account_id_runtime_literal(&provider.authorities[0].1.account_id, Some(42))
                    .as_str()
            )
        );
    }
    assert!(
        generated
            .configure_peer(&rendered, Some(42), temporary.path(), 0)
            .is_err()
    );
    assert!(
        generated
            .configure_peer("gov = 1", Some(42), temporary.path(), 0)
            .is_err()
    );
    assert_eq!(
        iroha_data_model::account::address::chain_discriminant(),
        369
    );
}

#[test]
fn managed_authority_genesis_registers_grants_funds_and_keeps_services_disabled() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    {
        let _parent_profile = ChainDiscriminantGuard::enter(369);
        assert_eq!(
            prepared.stream_token_authorities().unwrap(),
            Some(manifest.clone())
        );
        assert_eq!(
            iroha_data_model::account::address::chain_discriminant(),
            369
        );
    }
    assert_eq!(manifest.providers.len(), 3);
    assert_eq!(manifest.network.authorities.len(), 3);
    assert_eq!(manifest.providers[0].authorities.len(), 10);
    for provider in &manifest.providers {
        assert_eq!(
            provider
                .authorities
                .iter()
                .map(|entry| entry.role)
                .collect::<Vec<_>>(),
            ROLES
        );
    }
    assert_eq!(
        manifest.network.reserve_accounts,
        reserve_accounts(
            &manifest
                .network
                .authority(NetworkServiceAuthorityRole::ReserveOperations)
                .unwrap()
                .account
        )
        .unwrap()
    );
    let reserve_ids = [
        &manifest.network.reserve_accounts.custody,
        &manifest.network.reserve_accounts.treasury,
    ];
    assert_ne!(reserve_ids[0], reserve_ids[1]);
    for account in reserve_ids {
        assert_ne!(account, &manifest.manager);
        assert!(
            manifest
                .providers
                .iter()
                .flat_map(|provider| &provider.authorities)
                .all(|entry| &entry.account != account)
        );
    }
    let reserve_permissions = [
        Permission::from(CanSetSorafsReservePolicy),
        Permission::from(CanUpsertSorafsProviderCredit),
    ];
    let mut reserve_grants = BTreeSet::new();
    let root = prepared.context.client_config.parent().unwrap();
    let block = read_signed_genesis(&root.join("genesis.signed.nrt")).unwrap();
    block.validate_output_merkle_cache().unwrap();
    assert!(block.output_results().all(|result| result.as_ref().is_ok()));
    assert_eq!(
        NetworkId::from_genesis_hash(block.hash()),
        manifest.network_id
    );
    let mut expected = grants(&manifest.manager, &manifest.network, &manifest.providers).unwrap();
    let mut registered = BTreeSet::new();
    let mut provider_initializers = 0;
    let mut pricing_initializers = 0;
    for transaction in block.external_transactions() {
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(RegisterBox::Account(register)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
            {
                registered.insert(register.object.id.clone());
            }
            if let Some(GrantBox::Permission(grant)) =
                instruction.as_any().downcast_ref::<GrantBox>()
            {
                expected.retain(|(account, permission)| {
                    grant.destination() != account || grant.object() != permission
                });
                assert!(
                    !reserve_ids.contains(&grant.destination()),
                    "non-signing reserve accounts receive no permissions"
                );
                if reserve_permissions.contains(grant.object()) {
                    assert_eq!(grant.destination(), &manifest.manager);
                    assert_eq!(grant.object().payload(), &Json::new(()));
                    assert!(
                        reserve_grants.insert(grant.object().clone()),
                        "reserve capabilities are seeded exactly once"
                    );
                }
                assert!(!matches!(
                    grant.object().name(),
                    "CanOperateSorafsStreamTokenGateway" | "CanCheckSorafsStreamTokenGateway"
                ));
            }
            provider_initializers += usize::from(
                instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1>(),
            );
            pricing_initializers += usize::from(
                instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::SetPricingSchedule>(),
            );
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenGateway>()
            );
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::MutateSorafsStreamTokenCustody>()
            );
            assert!(!instruction.as_any().is::<iroha_data_model::isi::sorafs::SetSorafsReputationJournalAuthorityPolicy>());
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::SetSorafsReservePolicy>()
            );
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::RegisterSorafsReserveAccount>()
            );
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::UpsertProviderCredit>()
            );
            assert!(
                !instruction
                    .as_any()
                    .is::<iroha_data_model::isi::sorafs::RegisterCapacityDeclaration>()
            );
            if let Some(MintBox::Asset(mint)) = instruction.as_any().downcast_ref::<MintBox>() {
                assert!(!reserve_ids.contains(&mint.destination().account()));
            }
        }
    }
    assert_eq!((provider_initializers, pricing_initializers), (1, 1));
    assert!(
        expected.is_empty(),
        "every required capability was actually granted in signed genesis"
    );
    assert!(
        manifest
            .providers
            .iter()
            .flat_map(|provider| &provider.authorities)
            .all(|entry| registered.contains(&entry.account))
    );
    assert_eq!(reserve_grants, BTreeSet::from(reserve_permissions));
    for account in reserve_ids {
        assert!(registered.contains(account));
    }
    let inventory =
        PrivateDirectory::open_exact(root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY))
            .unwrap();
    let expected_files = BTreeSet::from(
        [MANIFEST, NETWORK_DIRECTORY, PROVIDERS_DIRECTORY].map(std::ffi::OsString::from),
    );
    assert_eq!(
        inventory
            .entries(expected_files.len())
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        expected_files
    );
    let public_bytes = inventory.read(MANIFEST, MAX_MANIFEST).unwrap();
    let public_text = std::str::from_utf8(&public_bytes).unwrap();
    let network_directory = inventory.open_child(NETWORK_DIRECTORY).unwrap();
    let network_files = NETWORK_ROLES
        .into_iter()
        .map(super::NetworkServiceAuthorityRole::credential_filename)
        .chain(network_material::COUNCIL_KEYS)
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        network_directory
            .entries(network_files.len())
            .unwrap()
            .into_iter()
            .collect::<BTreeSet<_>>(),
        network_files
    );
    for authority in &manifest.network.authorities {
        let bytes = network_directory
            .read(authority.role.credential_filename(), 256)
            .unwrap();
        assert!(
            !public_text.contains(std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap()).unwrap())
        );
    }
    let expected_files = ROLES
        .into_iter()
        .map(super::StreamTokenAuthorityRole::credential_filename)
        .chain(provider_material::filenames())
        .chain(compliance_material::filenames())
        .map(std::ffi::OsString::from)
        .collect::<BTreeSet<_>>();
    for provider in &manifest.providers {
        let directory = open_provider_directory(&inventory, provider.slot).unwrap();
        assert_eq!(
            directory
                .entries(expected_files.len())
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected_files
        );
        for authority in &provider.authorities {
            let bytes = directory
                .read(authority.role.credential_filename(), 256)
                .unwrap();
            let private = std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap()).unwrap();
            assert!(!public_text.contains(private));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    fs::metadata(directory.path().join(authority.role.credential_filename()))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o600
                );
            }
        }
    }
    let metadata = iroha_genesis::signed_genesis_consensus_metadata(&block).unwrap();
    for peer in &prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
        let config = parse_localnet_peer_config(
            std::str::from_utf8(&bytes).unwrap(),
            Some(&peer.config_path),
        )
        .unwrap();
        assert_eq!(
            config.gov.sorafs_provider_owners,
            manifest
                .providers
                .iter()
                .map(|provider| (
                    provider.provider_id,
                    provider.authorities[0].account.clone()
                ))
                .collect::<std::collections::BTreeMap<_, _>>()
        );
        assert_eq!(
            configured_execution_policy(
                &config,
                &iroha_genesis::signed_genesis_root_fee_policy(&block).unwrap()
            )
            .unwrap(),
            Hash::prehashed(metadata.sumeragi_context.execution_policy_hash)
        );
        assert!(!config.torii.sorafs_storage.stream_tokens.enabled);
        assert!(config.torii.sorafs_storage.stream_tokens.signer.is_none());
        assert!(
            config
                .torii
                .sorafs_storage
                .stream_tokens
                .admission_native
                .is_none()
        );
    }
    // Prove the cheap retained projection against actual signed native genesis execution and
    // query the provider owner from that same staged World, without a fixture-injected row.
    let bytes = iroha_fs::read_private(&prepared.peers[0].config_path, 1024 * 1024).unwrap();
    let config = parse_localnet_peer_config(
        std::str::from_utf8(&bytes).unwrap(),
        Some(&prepared.peers[0].config_path),
    )
    .unwrap();
    let genesis = RawGenesisTransaction::from_path(root.join("genesis.json")).unwrap();
    let signed =
        iroha_fs::read_private(root.join("genesis.signed.nrt"), SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap();
    let (receipt, (owner, policy)) =
        crate::genesis::staging::staged_signed_native_genesis_with_projection(
            &genesis,
            &signed,
            &config,
            |_, staged| {
                use iroha_core::{
                    smartcontracts::ValidSingularQuery as _, state::WorldReadOnly as _,
                };
                let compliance_role: RoleId = "sorafs_gateway_compliance_operator".parse().unwrap();
                assert!(
                    staged
                        .world()
                        .account_roles_iter(&manifest.manager)
                        .any(|role| role == &compliance_role)
                );
                assert_eq!(
                    staged
                        .world()
                        .role(&compliance_role)
                        .unwrap()
                        .permissions()
                        .len(),
                    0
                );
                let manager = iroha_data_model::query::account::prelude::FindAccountById {
                    id: manifest.manager.clone(),
                }
                .execute(staged)
                .map_err(|_| eyre!("native genesis has no compliance manager"))?;
                assert_eq!(
                    manager.metadata().get(MATERIAL_METADATA),
                    Some(&Json::new(
                        profile_commitment(
                            &manifest.manager,
                            &manifest.network,
                            &manifest.providers
                        )
                        .unwrap()
                    ))
                );
                let owner = iroha_data_model::query::sorafs::prelude::FindSorafsProviderOwner {
                    provider_id: manifest.providers[0].provider_id,
                }
                .execute(staged)
                .map_err(|_| eyre!("native genesis has no provider owner"))?;
                for (id, role) in [
                    (
                        &manifest.network.reserve_accounts.custody,
                        ReserveAccountRole::ReserveCustody,
                    ),
                    (
                        &manifest.network.reserve_accounts.treasury,
                        ReserveAccountRole::ReserveTreasury,
                    ),
                ] {
                    let account = iroha_data_model::query::account::prelude::FindAccountById {
                        id: id.clone(),
                    }
                    .execute(staged)
                    .map_err(|_| eyre!("native genesis has no reserve account"))?;
                    assert_eq!(
                        account.metadata().get(ROLE_METADATA),
                        Some(&Json::new(role))
                    );
                    let asset_id = AssetId::new(localnet_xor_asset_definition_id(), id.clone());
                    let error = iroha_data_model::query::asset::prelude::FindAssetById {
                        id: asset_id.clone(),
                    }
                    .execute(staged)
                    .expect_err("native reserve accounts start without a funded asset");
                    assert!(
                        matches!(
                            error,
                            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
                                iroha_data_model::query::error::QueryExecutionFail::Find(
                                    iroha_data_model::query::error::FindError::Asset(found)
                                )
                            ) if *found == asset_id
                        ),
                        "the exact missing asset must be a completed rejection, not a local refusal",
                    );
                }
                let policy = iroha_core::sumeragi::staged_genesis_execution_policy_hash(staged)
                    .map_err(|_| eyre!("native genesis execution policy is invalid"))?;
                Ok((owner, policy))
            },
        )
        .unwrap();
    assert_eq!(receipt.genesis().hash(), block.hash());
    assert_eq!(owner, manifest.providers[0].authorities[0].account);
    assert_eq!(
        policy,
        configured_execution_policy(
            &config,
            &iroha_genesis::signed_genesis_root_fee_policy(&block).unwrap()
        )
        .unwrap()
    );
    let mut external_compliance = config;
    external_compliance.nexus.compliance.enabled = true;
    assert!(
        configured_execution_policy(
            &external_compliance,
            &iroha_genesis::signed_genesis_root_fee_policy(&block).unwrap()
        )
        .is_err()
    );
}

#[test]
fn retained_owner_seed_rejects_config_drift_and_reopens_exact_original() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let root = prepared.context.client_config.parent().unwrap();
    let directory = PrivateDirectory::open_exact(root).unwrap();
    let signed = directory
        .read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)
        .unwrap();
    for (index, peer) in prepared.peers.iter().enumerate() {
        let filename = format!("peer{index}.toml");
        let original = directory.read(&filename, 1024 * 1024).unwrap();
        for mutation in 0..4 {
            let mut table = crate::secret_toml::Table::new(
                crate::secret_toml::parse_table(
                    std::str::from_utf8(&original).unwrap(),
                    "retained owner fixture",
                )
                .unwrap(),
            );
            let gov = table.get_mut("gov").unwrap().as_table_mut().unwrap();
            match mutation {
                0 => crate::secret_toml::remove(gov, "sorafs_provider_owners"),
                1 => {
                    let owners = gov
                        .get_mut("sorafs_provider_owners")
                        .unwrap()
                        .as_table_mut()
                        .unwrap();
                    owners.insert(
                        hex::encode(manifest.providers[0].provider_id.as_bytes()),
                        toml::Value::String(account_id_runtime_literal(
                            &manifest.providers[0].authorities[1].account,
                            Some(
                                prepared
                                    .context
                                    .load_client_config()
                                    .unwrap()
                                    .account_chain_discriminant,
                            ),
                        )),
                    );
                }
                2 => {
                    let owners = gov
                        .get_mut("sorafs_provider_owners")
                        .unwrap()
                        .as_table_mut()
                        .unwrap();
                    owners.insert(
                        hex::encode([0xA5; 32]),
                        toml::Value::String(account_id_runtime_literal(
                            &manifest.providers[0].authorities[0].account,
                            Some(
                                prepared
                                    .context
                                    .load_client_config()
                                    .unwrap()
                                    .account_chain_discriminant,
                            ),
                        )),
                    );
                }
                3 => {
                    let config = parse_localnet_peer_config(
                        std::str::from_utf8(&original).unwrap(),
                        Some(&peer.config_path),
                    )
                    .unwrap();
                    gov.insert(
                        "conviction_step_blocks".into(),
                        toml::Value::Integer(
                            i64::try_from(config.gov.conviction_step_blocks + 1).unwrap(),
                        ),
                    );
                }
                _ => unreachable!(),
            }
            let changed = Zeroizing::new(toml::to_string(&*table).unwrap());
            directory
                .write_atomic(&filename, changed.as_bytes(), PublishMode::Replace)
                .unwrap();
            parse_localnet_peer_config(&changed, Some(&peer.config_path))
                .expect("tampered owner/policy config is syntactically and structurally valid");
            assert!(
                prepared.stream_token_authorities().is_err(),
                "peer {index}, mutation {mutation}"
            );
            directory
                .write_atomic(&filename, &original, PublishMode::Replace)
                .unwrap();
        }
    }
    let reopened: PreparedLocalnet =
        norito::json::from_slice(&norito::json::to_vec(&prepared).unwrap()).unwrap();
    assert_eq!(reopened.stream_token_authorities().unwrap(), Some(manifest));
    assert_eq!(
        directory
            .read("genesis.signed.nrt", SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap(),
        signed
    );
}

#[test]
fn retained_authority_inventory_and_credentials_reject_substitution() {
    let _resources = crate::managed::native_test_guard();
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let prepared = prepared(&temporary.path().join("generation"));
    let root = prepared.context.client_config.parent().unwrap();
    let inventory =
        PrivateDirectory::open_exact(root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY))
            .unwrap();
    let original = inventory.read(MANIFEST, MAX_MANIFEST).unwrap();
    let signed_genesis =
        iroha_fs::read_private(root.join("genesis.signed.nrt"), SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap();
    let initial: StreamTokenAuthorityManifest = norito::json::from_slice(&original).unwrap();
    for mutation in 0..3 {
        let mut changed = initial.clone();
        match mutation {
            0 => std::mem::swap(
                &mut changed.network.reserve_accounts.custody,
                &mut changed.network.reserve_accounts.treasury,
            ),
            1 => {
                changed.network.reserve_accounts.custody =
                    changed.providers[0].authorities[0].account.clone()
            }
            2 => {
                changed.network.reserve_accounts =
                    reserve_accounts(&changed.providers[1].authorities[0].account).unwrap()
            }
            _ => unreachable!(),
        }
        inventory
            .write_atomic(
                MANIFEST,
                &norito::json::to_vec(&changed).unwrap(),
                PublishMode::Replace,
            )
            .unwrap();
        assert!(
            prepared.stream_token_authorities().is_err(),
            "reserve role substitution {mutation}"
        );
    }
    inventory
        .write_atomic(MANIFEST, &original, PublishMode::Replace)
        .unwrap();
    let mut missing: norito::json::Value = norito::json::from_slice(&original).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .get_mut("network")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("reserve_accounts");
    assert!(
        norito::json::from_value::<StreamTokenAuthorityManifest>(missing).is_err(),
        "reserve identity is mandatory"
    );
    inventory
        .write_atomic(
            "reserve-custody.key",
            b"unexpected credential\n",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(
        prepared.stream_token_authorities().is_err(),
        "no reserve credential or unknown file is admitted"
    );
    fs::remove_file(inventory.path().join("reserve-custody.key")).unwrap();
    let mut manifest: StreamTokenAuthorityManifest = norito::json::from_slice(&original).unwrap();
    manifest.providers[0].authorities.swap(0, 1);
    inventory
        .write_atomic(
            MANIFEST,
            &norito::json::to_vec(&manifest).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(prepared.stream_token_authorities().is_err());
    inventory
        .write_atomic(MANIFEST, &original, PublishMode::Replace)
        .unwrap();
    let credentials = open_provider_directory(&inventory, 0).unwrap();
    let observer = credentials
        .read(
            StreamTokenAuthorityRole::IssuerObserver.credential_filename(),
            256,
        )
        .unwrap();
    let operator = credentials
        .read(
            StreamTokenAuthorityRole::IssuerOperator.credential_filename(),
            256,
        )
        .unwrap();
    credentials
        .write_atomic(
            StreamTokenAuthorityRole::IssuerOperator.credential_filename(),
            &observer,
            PublishMode::Replace,
        )
        .unwrap();
    assert!(prepared.stream_token_authorities().is_err());
    credentials
        .write_atomic(
            StreamTokenAuthorityRole::IssuerOperator.credential_filename(),
            &operator,
            PublishMode::Replace,
        )
        .unwrap();
    // Preserve the canonical role order and replace both matching credentials: account
    // registration/funding sets alone cannot detect this reinterpretation of signed genesis.
    for (left, right) in [(4, 5), (2, 3), (6, 7), (7, 8)] {
        let mut paired: StreamTokenAuthorityManifest = norito::json::from_slice(&original).unwrap();
        let left_name = paired.providers[0].authorities[left]
            .role
            .credential_filename();
        let right_name = paired.providers[0].authorities[right]
            .role
            .credential_filename();
        let left_key = credentials.read(left_name, 256).unwrap();
        let right_key = credentials.read(right_name, 256).unwrap();
        let left_account = paired.providers[0].authorities[left].account.clone();
        paired.providers[0].authorities[left].account =
            paired.providers[0].authorities[right].account.clone();
        paired.providers[0].authorities[right].account = left_account;
        inventory
            .write_atomic(
                MANIFEST,
                &norito::json::to_vec(&paired).unwrap(),
                PublishMode::Replace,
            )
            .unwrap();
        credentials
            .write_atomic(left_name, &right_key, PublishMode::Replace)
            .unwrap();
        credentials
            .write_atomic(right_name, &left_key, PublishMode::Replace)
            .unwrap();
        assert!(
            prepared.stream_token_authorities().is_err(),
            "signed genesis fixes each original role"
        );
        credentials
            .write_atomic(left_name, &left_key, PublishMode::Replace)
            .unwrap();
        credentials
            .write_atomic(right_name, &right_key, PublishMode::Replace)
            .unwrap();
        inventory
            .write_atomic(MANIFEST, &original, PublishMode::Replace)
            .unwrap();
    }
    let mut changed = prepared.clone();
    changed.service_profile = LocalnetServiceProfile::Standard;
    assert!(
        changed.stream_token_authorities().is_err(),
        "profile cannot hide retained service custody"
    );
    changed = prepared.clone();
    changed.peers.clear();
    assert!(changed.stream_token_authorities().is_err());
    changed = prepared.clone();
    changed.peers[1].config_path = changed.peers[0].config_path.clone();
    assert!(changed.stream_token_authorities().is_err());
    changed = prepared.clone();
    changed.context.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"different-network"),
    ))
    .to_string();
    assert!(changed.stream_token_authorities().is_err());
    let mut metadata: norito::json::Value =
        norito::json::from_slice(&norito::json::to_vec(&prepared).unwrap()).unwrap();
    metadata.as_object_mut().unwrap().remove("service_profile");
    assert!(
        norito::json::from_value::<PreparedLocalnet>(metadata).is_err(),
        "retained profile is mandatory; no fallback decoding"
    );
    let alias = inventory.path().join("linked-key");
    fs::hard_link(
        credentials
            .path()
            .join(StreamTokenAuthorityRole::IssuerOperator.credential_filename()),
        &alias,
    )
    .unwrap();
    assert!(
        prepared.stream_token_authorities().is_err(),
        "shared writable key identity violates private custody"
    );
    fs::remove_file(alias).unwrap();
    prepared.stream_token_authorities().unwrap().unwrap();
    // Parent publication requires releasing its original descendant directory custody.
    drop(credentials);
    let removed = inventory
        .rename_to_sibling("removed-native-authorities", PublishMode::CreateNew)
        .unwrap();
    changed = prepared.clone();
    changed.service_profile = LocalnetServiceProfile::Standard;
    assert!(
        changed.stream_token_authorities().is_err(),
        "removing custody cannot downgrade signed profile"
    );
    assert!(prepared.stream_token_authorities().is_err());
    removed
        .rename_to_sibling(DIRECTORY, PublishMode::CreateNew)
        .unwrap();
    prepared.stream_token_authorities().unwrap().unwrap();
    assert_eq!(
        iroha_fs::read_private(root.join("genesis.signed.nrt"), SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap(),
        signed_genesis
    );
}

#[test]
fn authority_profile_rejects_raw_private_and_public_selection_before_output() {
    let temporary = crate::localnet::localnet_test_helpers::private_tempdir().unwrap();
    let out = temporary.path().join("not-created");
    let mut options = LocalnetOptions {
        service_profile: LocalnetServiceProfile::StreamTokenAuthorities,
        sora_profile: None,
        perf_profile: None,
        peers: NonZeroU16::new(4).unwrap(),
        seed: None,
        bind_host: "127.0.0.1".into(),
        public_host: "127.0.0.1".into(),
        base_api_port: 8080,
        base_p2p_port: 1337,
        out_dir: out.clone(),
        extra_accounts: 0,
        assets: Vec::new(),
        block_cadence_ms: None,
        consensus_mode: SumeragiConsensusMode::Permissioned,
    };
    assert!(generate_localnet(&options, &mut BufWriter::new(Vec::new())).is_err());
    assert!(!out.exists());
    assert!(validate_selection(&options, true, true).is_err());
    options.sora_profile = Some(SoraProfile::PrivateSbp);
    assert!(generate_managed_localnet(&options).is_err());
    assert!(!out.exists());
    options.sora_profile = None;
    validate_selection(&options, true, false).unwrap();
    options.service_profile = LocalnetServiceProfile::Standard;
    validate_selection(&options, false, false).unwrap();
}
