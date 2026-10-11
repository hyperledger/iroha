//! Original generated signer roles, native genesis grants and closed runtime-selection controls.

use super::*;
use iroha_core::{
    smartcontracts::ValidSingularQuery as _,
    state::{StorageReadOnly as _, WorldReadOnly as _},
};
use iroha_fs::{PrivateDirectory, PublishMode};

fn fixture() -> (tempfile::TempDir, PreparedLocalnet) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = prepare_localnet_at(
        "native-signer-roles",
        &temporary.path().join("generation"),
        &ports,
        LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    (temporary, prepared)
}

#[test]
fn original_native_signer_roles_are_distinct_funded_and_exactly_scoped_in_executed_genesis() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let selected = manifest.providers[0]
        .native_transaction_signer_authorities(&manifest.network)
        .unwrap();
    assert_eq!(
        selected.proof_outcome.role,
        StreamTokenAuthorityRole::ProofOutcome
    );
    assert_eq!(selected.repair.role, StreamTokenAuthorityRole::Repair);
    assert_eq!(
        selected.reserve.role,
        NetworkServiceAuthorityRole::ReserveOperations
    );
    assert_eq!(
        selected.orderbook.role,
        StreamTokenAuthorityRole::OrderbookMatcher
    );
    let ingest = manifest.providers[0]
        .authorities
        .iter()
        .find(|entry| entry.role == StreamTokenAuthorityRole::ProviderIngest)
        .unwrap();
    let four = [
        &selected.proof_outcome.account,
        &selected.repair.account,
        &selected.reserve.account,
        &selected.orderbook.account,
    ];
    assert_eq!(four.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    assert!(four.iter().all(|account| *account != &manifest.manager));
    assert!(four.iter().all(|account| *account != &ingest.account));
    assert_ne!(ingest.account, manifest.manager);
    assert_eq!(ingest.role.credential_filename(), "provider-ingest.key");
    assert_eq!(
        [
            selected.proof_outcome.role.credential_filename(),
            selected.repair.role.credential_filename(),
            selected.reserve.role.credential_filename(),
            selected.orderbook.role.credential_filename()
        ],
        [
            "proof-outcome.key",
            "repair.key",
            "reserve-operations.key",
            "orderbook-matcher.key"
        ]
    );
    let root = prepared.context.client_config.parent().unwrap();
    let retained =
        PrivateDirectory::open_exact(root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY))
            .unwrap();
    assert!(
        !retained
            .entries(64)
            .unwrap()
            .iter()
            .any(|name| name == "reserve.key")
    );
    let provider_directory = open_provider_directory(&retained, 0).unwrap();
    for entry in [
        selected.proof_outcome,
        selected.repair,
        selected.orderbook,
        ingest,
    ] {
        let key = read_role_key(&provider_directory, entry).unwrap();
        assert_eq!(&entry.account, &AccountId::new(key.public_key().clone()));
    }
    let reserve_key = read_network_role_key(
        &retained.open_child(NETWORK_DIRECTORY).unwrap(),
        selected.reserve,
    )
    .unwrap();
    assert_eq!(
        selected.reserve.account,
        AccountId::new(reserve_key.public_key().clone())
    );
    let config_bytes = iroha_fs::read_private(&prepared.peers[0].config_path, 1024 * 1024).unwrap();
    let config = parse_localnet_peer_config(
        std::str::from_utf8(&config_bytes).unwrap(),
        Some(&prepared.peers[0].config_path),
    )
    .unwrap();
    let genesis = RawGenesisTransaction::from_path(&root.join("genesis.json")).unwrap();
    let signed =
        iroha_fs::read_private(root.join("genesis.signed.nrt"), SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap();
    let (receipt, ()) = crate::genesis::staging::staged_signed_native_genesis_with_projection(
        &genesis,
        &signed,
        &config,
        |_, staged| {
            let mut expected = Vec::new();
            for role in NETWORK_ROLES {
                let entry = manifest.network.authority(role).unwrap();
                let permissions = match role {
                    NetworkServiceAuthorityRole::ReserveOperations
                    | NetworkServiceAuthorityRole::MusubiPin => BTreeSet::new(),
                    NetworkServiceAuthorityRole::ReputationRecorder => {
                        BTreeSet::from([Permission::from(CanRecordSorafsReputationJournal)])
                    }
                };
                expected.push((
                    &entry.account,
                    Json::new(role),
                    permissions,
                    Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE),
                ));
            }
            for provider in &manifest.providers {
                for (role, permissions) in [
                    (
                        StreamTokenAuthorityRole::IssuerOperator,
                        BTreeSet::from([
                            Permission::from(CanOperateSorafsStreamToken {
                                provider_id: provider.provider_id,
                            }),
                            Permission::from(CanDeclareSorafsCapacity),
                            // Native provider establishment also grants repair authority to its owner.
                            Permission::from(CanOperateSorafsRepair {
                                provider_id: provider.provider_id,
                            }),
                        ]),
                    ),
                    (
                        StreamTokenAuthorityRole::ProofOutcome,
                        BTreeSet::from([Permission::from(CanRecordSorafsProofOutcome {
                            provider_id: provider.provider_id,
                        })]),
                    ),
                    (
                        StreamTokenAuthorityRole::Repair,
                        BTreeSet::from([Permission::from(CanOperateSorafsRepair {
                            provider_id: provider.provider_id,
                        })]),
                    ),
                    (StreamTokenAuthorityRole::OrderbookMatcher, BTreeSet::new()),
                    (
                        StreamTokenAuthorityRole::ProviderIngest,
                        BTreeSet::from([Permission::from(CanCompleteSorafsReplicationOrder {
                            provider_id: provider.provider_id,
                        })]),
                    ),
                ] {
                    expected.push((
                        &provider.authority(role).unwrap().account,
                        Json::new(role),
                        permissions,
                        if role == StreamTokenAuthorityRole::IssuerOperator {
                            Quantity::from(34_u64)
                        } else {
                            Quantity::from(LOCALNET_ALIAS_SETUP_PAYER_BALANCE)
                        },
                    ));
                }
                assert_eq!(
                    staged.world().provider_owners().get(&provider.provider_id),
                    Some(
                        &provider
                            .authority(StreamTokenAuthorityRole::IssuerOperator)
                            .unwrap()
                            .account
                    )
                );
            }
            for (id, role, permissions, endowment) in expected {
                let account =
                    iroha_data_model::query::account::prelude::FindAccountById { id: id.clone() }
                        .execute(staged)
                        .unwrap();
                assert_eq!(account.metadata().get(ROLE_METADATA), Some(&role));
                let balance = iroha_data_model::query::asset::prelude::FindAssetById {
                    id: AssetId::new(localnet_xor_asset_definition_id(), id.clone()),
                }
                .execute(staged)
                .unwrap();
                assert_eq!(balance.value(), &endowment);
                assert_eq!(
                    staged
                        .world()
                        .account_permissions()
                        .get(id)
                        .cloned()
                        .unwrap_or_default(),
                    permissions
                );
            }
            assert_eq!(
                staged
                    .world()
                    .provider_owners()
                    .get(&manifest.providers[0].provider_id),
                Some(&manifest.providers[0].authorities[0].account)
            );
            // Registration/funds do not select an orderbook policy or enable a native adapter.
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        NetworkId::from_genesis_hash(receipt.genesis().hash()),
        manifest.network_id
    );
    for peer in &prepared.peers {
        let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
        let config = parse_localnet_peer_config(
            std::str::from_utf8(&bytes).unwrap(),
            Some(&peer.config_path),
        )
        .unwrap();
        assert_eq!(
            config.torii.sorafs_storage.native_transaction_signers,
            actual::SorafsNativeTransactionSignerBindings::default()
        );
        assert!(!config.torii.sorafs_storage.enabled);
    }
}

#[test]
fn native_role_manifest_cannot_omit_reorder_duplicate_or_reinterpret_signed_accounts() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let root = prepared.context.client_config.parent().unwrap();
    let retained =
        PrivateDirectory::open_exact(root.join(LOCALNET_RUNTIME_DIRECTORY).join(DIRECTORY))
            .unwrap();
    let original = retained.read(MANIFEST, MAX_MANIFEST).unwrap();
    let credentials = open_provider_directory(&retained, 0).unwrap();
    for mutation in 0..4 {
        let mut changed = manifest.clone();
        match mutation {
            0 => {
                changed.providers[0].authorities.pop();
            }
            1 => changed.providers[0].authorities.swap(6, 7),
            2 => {
                changed.providers[0].authorities[6].account =
                    changed.providers[0].authorities[0].account.clone()
            }
            3 => {
                changed.providers[0].authorities[8].role = StreamTokenAuthorityRole::IssuerOperator
            }
            _ => unreachable!(),
        }
        assert!(
            changed.providers[0]
                .native_transaction_signer_authorities(&changed.network)
                .is_err()
        );
        retained
            .write_atomic(
                MANIFEST,
                &norito::json::to_vec(&changed).unwrap(),
                PublishMode::Replace,
            )
            .unwrap();
        assert!(prepared.stream_token_authorities().is_err());
    }
    retained
        .write_atomic(MANIFEST, &original, PublishMode::Replace)
        .unwrap();
    for (left, right) in [(6, 7), (7, 8)] {
        let mut changed = manifest.clone();
        let left_name = changed.providers[0].authorities[left]
            .role
            .credential_filename();
        let right_name = changed.providers[0].authorities[right]
            .role
            .credential_filename();
        let left_key = credentials
            .read(left_name, MAX_ROLE_CREDENTIAL_BYTES)
            .unwrap();
        let right_key = credentials
            .read(right_name, MAX_ROLE_CREDENTIAL_BYTES)
            .unwrap();
        let left_account = changed.providers[0].authorities[left].account.clone();
        changed.providers[0].authorities[left].account =
            changed.providers[0].authorities[right].account.clone();
        changed.providers[0].authorities[right].account = left_account;
        // A structurally complete borrowed selection is still only intent. Actual signed genesis
        // must reject swapping two accounts even when both corresponding key files are swapped.
        changed.providers[0]
            .native_transaction_signer_authorities(&changed.network)
            .unwrap();
        retained
            .write_atomic(
                MANIFEST,
                &norito::json::to_vec(&changed).unwrap(),
                PublishMode::Replace,
            )
            .unwrap();
        credentials
            .write_atomic(left_name, &right_key, PublishMode::Replace)
            .unwrap();
        credentials
            .write_atomic(right_name, &left_key, PublishMode::Replace)
            .unwrap();
        assert!(prepared.stream_token_authorities().is_err());
        credentials
            .write_atomic(left_name, &left_key, PublishMode::Replace)
            .unwrap();
        credentials
            .write_atomic(right_name, &right_key, PublishMode::Replace)
            .unwrap();
        retained
            .write_atomic(MANIFEST, &original, PublishMode::Replace)
            .unwrap();
    }
    assert_eq!(
        prepared.stream_token_authorities().unwrap().unwrap(),
        manifest
    );
}

#[test]
fn original_disabled_profile_refuses_valid_native_runtime_activation() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture();
    let manifest = prepared.stream_token_authorities().unwrap().unwrap();
    let selected = manifest.providers[0]
        .native_transaction_signer_authorities(&manifest.network)
        .unwrap();
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original = generation.read("peer0.toml", 1024 * 1024).unwrap();
    let discriminant = prepared
        .context
        .load_client_config()
        .unwrap()
        .account_chain_discriminant;
    let mut table = crate::secret_toml::Table::new(
        crate::secret_toml::parse_table(
            std::str::from_utf8(&original).unwrap(),
            "native role fixture",
        )
        .unwrap(),
    );
    let mut storage = &mut *table;
    for part in ["sorafs", "storage"] {
        storage = storage
            .entry(part)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .unwrap();
    }
    storage.insert("enabled".into(), toml::Value::Boolean(true));
    storage.insert(
        "provider_id_hex".into(),
        toml::Value::String(hex::encode(manifest.providers[0].provider_id.as_bytes())),
    );
    let mut bindings = toml::Table::new();
    for (role, entry) in [
        ("proof_outcome", &selected.proof_outcome.account),
        ("repair", &selected.repair.account),
        ("reserve", &selected.reserve.account),
        ("orderbook", &selected.orderbook.account),
    ] {
        let key = entry.try_signatory().unwrap();
        let mut binding = toml::Table::new();
        binding.insert(
            "handle".into(),
            toml::Value::String(format!("software://managed/native/{role}")),
        );
        binding.insert(
            "authority".into(),
            toml::Value::String(account_id_runtime_literal(entry, Some(discriminant))),
        );
        binding.insert("algorithm".into(), toml::Value::String("ed25519".into()));
        binding.insert(
            "public_key_hex".into(),
            toml::Value::String(hex::encode(key.try_to_bytes().unwrap().1)),
        );
        binding.insert("revision".into(), toml::Value::Integer(1));
        // Syntactically valid public qualification claims only; no adapter is constructed.
        binding.insert(
            "policy_digest_hex".into(),
            toml::Value::String(hex::encode([0x42; 32])),
        );
        bindings.insert(role.into(), toml::Value::Table(binding));
    }
    storage.insert(
        "native_transaction_signers".into(),
        toml::Value::Table(bindings),
    );
    let bytes = Zeroizing::new(toml::to_string(&*table).unwrap());
    let parsed = parse_localnet_peer_config(&bytes, Some(&prepared.peers[0].config_path)).unwrap();
    assert!(parsed.torii.sorafs_storage.enabled);
    let parsed_bindings = &parsed.torii.sorafs_storage.native_transaction_signers;
    assert_eq!(
        parsed_bindings.reserve.as_ref().unwrap().authority,
        selected.reserve.account
    );
    assert_eq!(
        parsed_bindings.proof_outcome.as_ref().unwrap().authority,
        selected.proof_outcome.account
    );
    assert_eq!(
        parsed_bindings.repair.as_ref().unwrap().authority,
        selected.repair.account
    );
    assert_eq!(
        parsed_bindings.orderbook.as_ref().unwrap().authority,
        selected.orderbook.account
    );
    generation
        .write_atomic("peer0.toml", bytes.as_bytes(), PublishMode::Replace)
        .unwrap();
    assert!(
        prepared.stream_token_authorities().is_err(),
        "a valid derived runtime selection must not masquerade as its original disabled profile"
    );
    generation
        .write_atomic("peer0.toml", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        prepared.stream_token_authorities().unwrap().unwrap(),
        manifest
    );
}
