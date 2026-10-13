fn asset_alias_test_world() -> (World, AssetDefinitionId) {
    let authority = AccountId::new(crate::state::checked_keypair().public_key().clone());
    let domain_id: DomainId = DomainId::try_new("issuer", "universal").expect("domain");
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id.clone(),
        "usd".parse().expect("asset name"),
    );
    let definition = AssetDefinition::numeric(
        definition_id.clone(),
        "usd".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    )
    .build(&authority);
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    (
        World::with([domain], [account], [definition]),
        definition_id,
    )
}
fn alias_in_domain(domain_id: &DomainId, label: Name) -> AccountAlias {
    AccountAlias::new(
        label,
        Some(AccountAliasDomain::new(domain_id.name().clone())),
        DataSpaceId::UNIVERSAL,
    )
}
fn seed_active_account_alias_binding(world: &mut World, owner: &AccountId, alias: &AccountAlias) {
    world.account_aliases.insert(alias.clone(), owner.clone());
    let mut aliases = world
        .account_aliases_by_account
        .view()
        .get(owner)
        .cloned()
        .unwrap_or_default();
    aliases.insert(alias.clone());
    world
        .account_aliases_by_account
        .insert(owner.clone(), aliases);
    world.replace_account_rekey_record_for_testing(AccountRekeyRecord::new(
        alias.clone(),
        owner.clone(),
    ));
    let selector = crate::sns::selector_for_account_alias(alias, &DataSpaceCatalog::default())
        .expect("account alias selector");
    let address =
        iroha_data_model::account::AccountAddress::from_account_id(owner).expect("account address");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    world.smart_contract_state.insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
    world
        .rebuild_account_scope_directory()
        .expect("active account alias must define a valid account scope");
}
/// Retain the canonical live domain lease needed by a component's domain-owned state.
fn seed_trigger_domain_name_lease(
    tx: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    domain_id: &DomainId,
) {
    let selector = crate::sns::selector_for_domain(domain_id).expect("domain selector");
    let storage_key = crate::sns::record_storage_key(&selector);
    if tx.world.smart_contract_state.get(&storage_key).is_none() {
        let domain_owner = tx
            .world
            .domains
            .get(domain_id)
            .map(|domain| domain.owned_by().clone())
            .unwrap_or_else(|| owner.clone());
        let address = iroha_data_model::account::AccountAddress::from_account_id(&domain_owner)
            .expect("domain owner address");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector,
            domain_owner,
            vec![iroha_data_model::sns::NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            iroha_model_base::metadata::Metadata::default(),
        );
        tx.world
            .smart_contract_state
            .insert(storage_key, norito::codec::Encode::encode(&record));
    }
}

fn seed_account_alias_lease(
    tx: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    alias: &AccountAlias,
) {
    if let Some(domain_id) = alias
        .domain_id(&tx.nexus.dataspace_catalog)
        .expect("fixture alias domain")
    {
        seed_trigger_domain_name_lease(tx, owner, &domain_id);
    }
    let selector = crate::sns::selector_for_account_alias(alias, &tx.nexus.dataspace_catalog)
        .expect("account alias selector");
    let address =
        iroha_data_model::account::AccountAddress::from_account_id(owner).expect("account address");
    let record = iroha_data_model::sns::NameRecordV1::new(
        selector.clone(),
        owner.clone(),
        vec![iroha_data_model::sns::NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        iroha_model_base::metadata::Metadata::default(),
    );
    tx.world.smart_contract_state.insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}
#[test]
fn new_for_testing_seeds_reserved_universal_dataspace_name_record() {
    let genesis_id = (*SAMPLE_GENESIS_ACCOUNT_ID).clone();
    let genesis_domain = Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&genesis_id);
    let genesis_account = Account::new(genesis_id.clone()).build(&genesis_id);
    let state = State::new_for_testing(
        World::with([genesis_domain], [genesis_account], []),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let view = state.view();
    assert_eq!(
        (crate::sns::active_dataspace_owner_by_alias(
            view.world(),
            crate::sns::RESERVED_UNIVERSAL_DATASPACE_ALIAS,
            0,
        ))
        .expect("completed successful fixture"),
        Some(genesis_id)
    );
}
#[test]
fn reserved_universal_dataspace_seed_classifies_noop_then_permission_repair() {
    let owner = (*SAMPLE_GENESIS_ACCOUNT_ID).clone();
    let domain = Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&owner);
    let account = Account::new(owner.clone()).build(&owner);
    let mut world = World::with([domain], [account], []);
    State::seed_reserved_universal_dataspace_name_record(&mut world);
    let intent = iroha_data_model::alias_setup::AliasIntentV1::Dataspace(
        iroha_data_model::alias_setup::AliasDataSpaceIntentV1 {
            dataspace: iroha_data_model::alias_setup::ResolvedDataSpaceV1::new(
                crate::sns::RESERVED_UNIVERSAL_DATASPACE_ALIAS
                    .parse()
                    .expect("reserved dataspace alias"),
                DataSpaceId::UNIVERSAL,
            ),
            owner: owner.clone(),
        },
    );
    assert_eq!(
        crate::alias_setup::classify_alias_intent(
            &world.view(),
            &iroha_data_model::nexus::DataSpaceCatalog::default(),
            &intent,
            0,
        )
        .expect("classify seeded universal dataspace"),
        iroha_data_model::alias_setup::AliasPlanDispositionV1::NoOp
    );
    let removed = crate::alias_setup::exact_alias_permission_bundle(&intent)
        .into_iter()
        .next()
        .expect("exact permission bundle");
    let mut permissions = world
        .account_permissions
        .view()
        .get(&owner)
        .cloned()
        .expect("seeded permissions");
    assert!(permissions.remove(&removed));
    world.account_permissions.insert(owner.clone(), permissions);
    assert_eq!(
        crate::alias_setup::classify_alias_intent(
            &world.view(),
            &iroha_data_model::nexus::DataSpaceCatalog::default(),
            &intent,
            0,
        )
        .expect("classify permission repair"),
        iroha_data_model::alias_setup::AliasPlanDispositionV1::Repair
    );
}
#[test]
fn asset_definition_alias_binding_status_classifies_lifecycle() {
    let leased_alias: AssetDefinitionAlias = "usd#lease".parse().expect("lease alias");
    let binding = AssetDefinitionAliasBindingRecord {
        alias: leased_alias,
        lease_expiry_ms: Some(200),
        grace_until_ms: Some(250),
        bound_at_ms: 100,
    };
    assert_eq!(
        binding.status_at(150),
        AssetDefinitionAliasLeaseStatus::LeasedActive
    );
    assert_eq!(
        binding.status_at(200),
        AssetDefinitionAliasLeaseStatus::LeasedGrace
    );
    assert_eq!(
        binding.status_at(250),
        AssetDefinitionAliasLeaseStatus::LeasedGrace
    );
    assert_eq!(
        binding.status_at(251),
        AssetDefinitionAliasLeaseStatus::ExpiredPendingCleanup
    );
    let permanent_binding = AssetDefinitionAliasBindingRecord {
        alias: "usd#permanent".parse().expect("permanent alias"),
        lease_expiry_ms: None,
        grace_until_ms: None,
        bound_at_ms: 100,
    };
    assert_eq!(
        permanent_binding.status_at(10_000),
        AssetDefinitionAliasLeaseStatus::Permanent
    );
    assert!(!permanent_binding.is_grace_expired_at(u64::MAX));
    let no_grace_binding = AssetDefinitionAliasBindingRecord {
        alias: "usd#no_grace".parse().expect("no-grace alias"),
        lease_expiry_ms: Some(200),
        grace_until_ms: None,
        bound_at_ms: 100,
    };
    assert!(!no_grace_binding.is_grace_expired_at(199));
    assert!(no_grace_binding.is_grace_expired_at(200));
    assert_eq!(
        no_grace_binding.status_at(200),
        AssetDefinitionAliasLeaseStatus::ExpiredPendingCleanup
    );
    let malformed_binding = AssetDefinitionAliasBindingRecord {
        alias: "usd#malformed".parse().expect("malformed alias"),
        lease_expiry_ms: None,
        grace_until_ms: Some(250),
        bound_at_ms: 100,
    };
    assert!(
        malformed_binding.is_grace_expired_at(0),
        "a grace-only record must never revive a permanent alias"
    );
}
#[test]
fn contract_alias_binding_without_grace_expires_at_lease_boundary() {
    let binding = ContractAliasBindingRecord {
        alias: "router::universal".parse().expect("contract alias"),
        lease_expiry_ms: Some(200),
        grace_until_ms: None,
        bound_at_ms: 100,
    };
    assert!(!binding.is_grace_expired_at(199));
    assert!(binding.is_grace_expired_at(200));
    assert_eq!(
        binding.status_at(200),
        ContractAliasLeaseStatus::ExpiredPendingCleanup
    );
}
#[test]
fn alias_binding_rejects_incoherent_lease_windows() {
    let error = validate_alias_lease_window(None, Some(300), 100)
        .expect_err("grace without a lease must fail");
    assert!(error.to_string().contains("requires lease_expiry_ms"));
    let mut world = World::new();
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        6,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let error = world
        .bind_contract_alias(
            &contract_address,
            "router_invalid::universal".parse().expect("contract alias"),
            Some(200),
            Some(199),
            100,
        )
        .expect_err("grace before expiry must fail");
    assert!(error.to_string().contains("must not precede"));
    let error = world
        .bind_contract_alias(
            &contract_address,
            "router_expired::universal".parse().expect("contract alias"),
            Some(100),
            None,
            100,
        )
        .expect_err("already-expired lease must fail");
    assert!(error.to_string().contains("greater than bound_at_ms"));
}
#[test]
fn alias_index_rebuild_rejects_incoherent_persisted_lease_windows() {
    let (mut world, definition_id) = asset_alias_test_world();
    world.asset_definition_alias_bindings = std::iter::once((
        definition_id,
        AssetDefinitionAliasBindingRecord {
            alias: "usd#invalid_persisted".parse().expect("asset alias"),
            lease_expiry_ms: None,
            grace_until_ms: Some(300),
            bound_at_ms: 100,
        },
    ))
    .collect();
    let error = world
        .rebuild_asset_definition_alias_indexes()
        .expect_err("asset alias rebuild must reject grace without a lease");
    assert!(error.contains("requires lease_expiry_ms"));
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        7,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    world.contract_alias_bindings = std::iter::once((
        contract_address,
        ContractAliasBindingRecord {
            alias: "router_invalid_persisted::universal"
                .parse()
                .expect("contract alias"),
            lease_expiry_ms: Some(100),
            grace_until_ms: None,
            bound_at_ms: 100,
        },
    ))
    .collect();
    let error = world
        .rebuild_contract_alias_indexes()
        .expect_err("contract alias rebuild must reject a non-forward lease");
    assert!(error.contains("greater than bound_at_ms"));
}
#[test]
fn world_bind_contract_alias_keeps_indexes_consistent() {
    let mut world = World::new();
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        1,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let other_contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        2,
        DataSpaceId::UNIVERSAL,
    )
    .expect("other contract address");
    let first_alias: ContractAlias = "router::universal".parse().expect("first alias");
    let second_alias: ContractAlias = "router_v2::universal".parse().expect("second alias");
    world
        .bind_contract_alias(
            &contract_address,
            first_alias.clone(),
            Some(200),
            Some(300),
            100,
        )
        .expect("bind first alias");
    assert_eq!(
        world.contract_aliases.view().get(&first_alias),
        Some(&contract_address)
    );
    assert_eq!(
        world
            .contract_alias_bindings
            .view()
            .get(&contract_address)
            .expect("first binding")
            .alias,
        first_alias
    );
    world
        .bind_contract_alias(&contract_address, second_alias.clone(), None, None, 400)
        .expect("rebind alias");
    assert!(world.contract_aliases.view().get(&first_alias).is_none());
    assert_eq!(
        world.contract_aliases.view().get(&second_alias),
        Some(&contract_address)
    );
    assert_eq!(
        world
            .contract_alias_bindings
            .view()
            .get(&contract_address)
            .expect("second binding")
            .bound_at_ms,
        400
    );
    let err = world
        .bind_contract_alias(&other_contract_address, second_alias, None, None, 500)
        .expect_err("alias reuse across contracts must fail");
    assert!(
        err.to_string().contains("already bound"),
        "unexpected error: {err}"
    );
}
#[test]
fn contract_alias_time_lookup_rejects_index_without_binding_record() {
    let mut world = World::new();
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        7,
        DataSpaceId::UNIVERSAL,
    )
    .expect("contract address");
    let alias: ContractAlias = "index_only::universal".parse().expect("contract alias");
    world
        .contract_aliases
        .insert(alias.clone(), contract_address.clone());
    let view = world.view();
    assert_eq!(
        view.contract_address_by_alias(&alias),
        Some(contract_address),
        "the raw index remains inspectable for state repair"
    );
    assert_eq!(
        view.contract_address_by_alias_at(&alias, 0),
        None,
        "an index-only entry must never become an effective first-release binding"
    );
}
#[test]
fn asset_alias_time_lookup_rejects_index_without_binding_record() {
    let (mut world, definition_id) = asset_alias_test_world();
    let alias: AssetDefinitionAlias = "usd#index_only".parse().expect("asset alias");
    world
        .asset_definition_aliases
        .insert(alias.clone(), definition_id.clone());
    let view = world.view();
    assert_eq!(
        view.asset_definition_id_by_alias(&alias),
        Some(definition_id),
        "the raw index remains inspectable for state repair"
    );
    assert_eq!(
        view.asset_definition_id_by_alias_at(&alias, 0),
        None,
        "an index-only entry must never become an effective first-release binding"
    );
}
#[test]
fn rebuild_asset_definition_alias_indexes_prefers_persisted_bindings() {
    let (mut world, definition_id) = asset_alias_test_world();
    let persisted_alias: AssetDefinitionAlias = "usd#canonical".parse().expect("alias");
    let binding = AssetDefinitionAliasBindingRecord {
        alias: persisted_alias.clone(),
        lease_expiry_ms: Some(200),
        grace_until_ms: Some(300),
        bound_at_ms: 100,
    };
    world.asset_definition_aliases = Storage::default();
    world.asset_definition_alias_bindings =
        std::iter::once((definition_id.clone(), binding.clone())).collect();
    world
        .rebuild_asset_definition_alias_indexes()
        .expect("rebuild should succeed");
    let view = world.view();
    assert_eq!(
        view.asset_definition_aliases().get(&persisted_alias),
        Some(&definition_id)
    );
    assert_eq!(
        view.asset_definition_alias_bindings()
            .get(&definition_id)
            .expect("binding"),
        &binding
    );
    assert_eq!(
        view.asset_definition(&definition_id)
            .expect("definition")
            .alias()
            .as_ref(),
        Some(&persisted_alias)
    );
    assert!(
        world
            .asset_definitions
            .view()
            .get(&definition_id)
            .expect("stored definition")
            .alias()
            .is_none(),
        "stored asset definition alias must stay empty; bindings drive alias reads"
    );
}
#[test]
fn rebuild_asset_definition_alias_indexes_preserves_mv_revert_maps() {
    let (mut world, existing_definition_id) = asset_alias_test_world();
    let existing_definition = world
        .asset_definitions
        .view()
        .get(&existing_definition_id)
        .expect("fixture definition")
        .clone();
    let added_definition_id = AssetDefinitionId::derive_from_components(
        existing_definition
            .owning_domain()
            .as_ref()
            .expect("fixture definition is explicitly domain-owned")
            .clone(),
        "rollback".parse().expect("asset name"),
    );
    let added_definition = AssetDefinition::numeric(
        added_definition_id.clone(),
        "rollback".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        existing_definition.owning_domain().clone(),
    )
    .build(existing_definition.owned_by());
    let alias: AssetDefinitionAlias = "rollback#universal".parse().expect("asset alias");
    let binding = AssetDefinitionAliasBindingRecord {
        alias,
        lease_expiry_ms: None,
        grace_until_ms: None,
        bound_at_ms: 100,
    };
    {
        let mut definitions = world.asset_definitions.block();
        assert!(
            definitions
                .insert(added_definition_id.clone(), added_definition)
                .is_none()
        );
        definitions.commit();
    }
    {
        let mut bindings = world.asset_definition_alias_bindings.block();
        assert!(
            bindings
                .insert(added_definition_id.clone(), binding)
                .is_none()
        );
        bindings.commit();
    }
    let definitions_before =
        norito::json::to_json(&world.asset_definitions).expect("serialize definitions");
    let bindings_before = norito::json::to_json(&world.asset_definition_alias_bindings)
        .expect("serialize alias bindings");
    world
        .rebuild_asset_definition_alias_indexes()
        .expect("rebuild should succeed");
    assert_eq!(
        norito::json::to_json(&world.asset_definitions).expect("serialize definitions"),
        definitions_before,
        "rebuilding a derived index must preserve the authoritative definition MV history"
    );
    assert_eq!(
        norito::json::to_json(&world.asset_definition_alias_bindings)
            .expect("serialize alias bindings"),
        bindings_before,
        "rebuilding a derived index must preserve the authoritative binding MV history"
    );
    let definitions = world.asset_definitions.block_and_revert();
    assert!(
        definitions.get(&added_definition_id).is_none(),
        "the latest definition insertion must remain rollback-capable"
    );
    definitions.commit();
    let bindings = world.asset_definition_alias_bindings.block_and_revert();
    assert!(
        bindings.get(&added_definition_id).is_none(),
        "the latest alias binding insertion must remain rollback-capable"
    );
    bindings.commit();
}
#[test]
fn rebuild_asset_definition_alias_indexes_rejects_inline_alias_without_binding() {
    let (mut world, definition_id) = asset_alias_test_world();
    let legacy_alias: AssetDefinitionAlias = "usd#legacy".parse().expect("legacy alias");
    world.asset_definition_aliases = Storage::default();
    world.asset_definition_alias_bindings = Storage::default();
    let mut stored_definition = world
        .asset_definitions
        .view()
        .get(&definition_id)
        .expect("stored definition")
        .clone();
    stored_definition.alias = Some(legacy_alias.clone());
    world
        .asset_definitions
        .insert(definition_id.clone(), stored_definition);
    let err = world
        .rebuild_asset_definition_alias_indexes()
        .expect_err("rebuild must reject inline asset-definition aliases");
    assert_eq!(
        err,
        format!(
            "Asset definition {definition_id} stores inline alias `{legacy_alias}`; persist aliases only in asset_definition_alias_bindings"
        )
    );
}
#[test]
fn rebuild_asset_definition_alias_indexes_rejects_inline_alias_even_with_binding() {
    let (mut world, definition_id) = asset_alias_test_world();
    let inline_alias: AssetDefinitionAlias = "usd#legacy".parse().expect("inline alias");
    world.asset_definition_aliases = Storage::default();
    world.asset_definition_alias_bindings = std::iter::once((
        definition_id.clone(),
        AssetDefinitionAliasBindingRecord {
            alias: "usd#canonical".parse().expect("persisted alias"),
            lease_expiry_ms: None,
            grace_until_ms: None,
            bound_at_ms: 100,
        },
    ))
    .collect();
    let mut stored_definition = world
        .asset_definitions
        .view()
        .get(&definition_id)
        .expect("stored definition")
        .clone();
    stored_definition.alias = Some(inline_alias.clone());
    world
        .asset_definitions
        .insert(definition_id.clone(), stored_definition);
    let err = world
        .rebuild_asset_definition_alias_indexes()
        .expect_err("rebuild must reject inline asset-definition aliases");
    assert_eq!(
        err,
        format!(
            "Asset definition {definition_id} stores inline alias `{inline_alias}`; persist aliases only in asset_definition_alias_bindings"
        )
    );
}
#[test]
fn asset_definition_alias_lookup_stops_after_grace_even_before_sweep() {
    let (mut world, definition_id) = asset_alias_test_world();
    let alias: AssetDefinitionAlias = "usd#lease".parse().expect("alias");
    world.asset_definition_aliases = Storage::default();
    world.asset_definition_alias_bindings = std::iter::once((
        definition_id.clone(),
        AssetDefinitionAliasBindingRecord {
            alias: alias.clone(),
            lease_expiry_ms: Some(200),
            grace_until_ms: Some(250),
            bound_at_ms: 100,
        },
    ))
    .collect();
    world
        .rebuild_asset_definition_alias_indexes()
        .expect("rebuild should succeed");
    let view = world.view();
    assert_eq!(
        view.asset_definition_id_by_alias_at(&alias, 249),
        Some(definition_id.clone())
    );
    assert_eq!(view.asset_definition_id_by_alias_at(&alias, 251), None);
    assert_eq!(
        view.asset_definition_aliases().get(&alias),
        Some(&definition_id),
        "stale binding remains indexed until sweep"
    );
    assert_eq!(
        view.asset_definition(&definition_id)
            .expect("definition")
            .alias()
            .as_ref(),
        Some(&alias),
        "effective definition still exposes the persisted binding for inspection"
    );
}
