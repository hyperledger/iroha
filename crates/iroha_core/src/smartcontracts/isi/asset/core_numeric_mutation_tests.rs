// Same-scope regression coverage extracted to keep the parent source budget bounded.
#[test]
fn raw_numeric_balance_mutation_is_reachable_only_inside_asset_module() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let asset_source_path = source_root.join("smartcontracts/isi/asset.rs");
    let private_delta_test_path =
        source_root.join("smartcontracts/isi/asset/prepared_source_additional_owner_tests.rs");
    let state_source_path = source_root.join("state.rs");
    let asset_source =
        std::fs::read_to_string(&asset_source_path).expect("read asset implementation");
    let exposed_signatures = [
        ["pub(crate) fn withdraw", "_numeric_asset("].concat(),
        ["pub(crate) fn deposit", "_numeric_asset("].concat(),
        ["pub(crate) fn deposit", "_numeric_asset_exact("].concat(),
        [
            "pub(crate) fn apply_prechecked_numeric_asset_transfer_",
            "delta_exact(",
        ]
        .concat(),
    ];
    for exposed_signature in exposed_signatures {
        assert!(
            !asset_source.contains(&exposed_signature),
            "raw balance primitive became crate-reachable: {exposed_signature}"
        );
    }
    let mut sources = Vec::new();
    collect_rust_sources(&source_root, &mut sources);
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("read Rust source");
        if path != asset_source_path {
            for raw_call in [
                [".withdraw_numeric_asset", "("].concat(),
                [".deposit_numeric_asset", "("].concat(),
                [".deposit_numeric_asset_exact", "("].concat(),
                [".apply_prechecked_numeric_asset_transfer_delta_exact", "("].concat(),
            ] {
                // This exact file is included by asset.rs's private #[cfg(test)]
                // prepared_source_additional_owner_tests module. Its low-level
                // delta checks must remain able to exercise the private primitive.
                let private_delta_test = path == private_delta_test_path
                    && raw_call
                        == [".apply_prechecked_numeric_asset_transfer_delta_exact", "("].concat();
                assert!(
                    private_delta_test || !source.contains(&raw_call),
                    "{} reaches raw balance mutation through {raw_call}",
                    path.display()
                );
            }
        }
        if path != asset_source_path && path != state_source_path {
            assert!(
                !source.contains(&["record_transfer_transcripts_with_", "batch_hash("].concat()),
                "{} bypasses the typed movement transcript boundary",
                path.display()
            );
        }
        let broad_source_policy =
            ["NumericAssetTransferSourcePolicy::Protocol", "Retained"].concat();
        let broad_control_policy =
            ["NumericAssetTransferControlPolicy::Mandatory", "Retained"].concat();
        assert!(
            !source.contains(&broad_source_policy) && !source.contains(&broad_control_policy),
            "{} reintroduced a generic retained movement bypass",
            path.display()
        );
    }
}
fn seed_test_account_alias_lease(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    alias: &AccountAlias,
) {
    let selector = crate::sns::active_account_alias_selector(
        state_transaction.world(),
        &state_transaction.nexus.dataspace_catalog,
        alias,
        state_transaction.block_unix_timestamp_ms(),
    )
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
    state_transaction.world.smart_contract_state.insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}
fn seed_test_account_alias_binding(
    state_transaction: &mut StateTransaction<'_, '_>,
    owner: &AccountId,
    alias: &AccountAlias,
) {
    state_transaction
        .world
        .account_mut(owner)
        .expect("canonical account exists")
        .set_label(Some(alias.clone()));
    state_transaction
        .world
        .insert_account_alias_binding(alias.clone(), owner.clone());
    state_transaction
        .world
        .replace_account_rekey_record(AccountRekeyRecord::new(alias.clone(), owner.clone()));
}
fn fee_sponsor_custody_state() -> (State, AccountId, AssetDefinitionId, AssetId) {
    let custody_key =
        KeyPair::try_from_seed(vec![0xC5; 32], Algorithm::Ed25519).expect("custody fixture key");
    let custody = AccountId::new(custody_key.public_key().clone());
    drop(custody_key);
    let domain_id = DomainId::try_new("fees", "universal").expect("fee domain");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "xor".parse().expect("asset name"));
    let definition = build_numeric_asset_definition(&definition_id, "xor", &ALICE_ID);
    let source_id = AssetId::new(definition_id.clone(), custody.clone());
    let world = World::with_assets(
        [domain],
        [
            Account::new(ALICE_ID.clone()).build(&ALICE_ID),
            Account::new(BOB_ID.clone()).build(&ALICE_ID),
            Account::new(custody.clone()).build(&ALICE_ID),
        ],
        [definition],
        [Asset::new(source_id.clone(), Quantity::from(10_u32))],
        [],
    );
    let mut state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state.nexus.get_mut().fees.sponsor_vault_custody_account_id = custody.clone();
    (state, custody, definition_id, source_id)
}
#[test]
fn fee_sponsor_custody_transfer_needs_no_custody_signature_and_conserves_balance() {
    let (state, custody, definition_id, source_id) = fee_sponsor_custody_state();
    assert_ne!(custody, *ALICE_ID, "submitting authority is not custody");
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC5; Hash::LENGTH]));
    let program_id = iroha_data_model::nexus::FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "custody-transfer-test"
            .parse()
            .expect("fee sponsor program name"),
    );
    let authorization = crate::executor::VerifiedFeeSponsorCharge::transfer_for_test(
        ALICE_ID.clone(),
        program_id,
        source_id.clone(),
        BOB_ID.clone(),
        Quantity::from(4_u32),
    );
    super::isi::execute_verified_fee_sponsor_charge(&mut stx, authorization)
        .expect("protocol custody transfer does not require custody authorization");
    let destination_id = AssetId::new(definition_id, BOB_ID.clone());
    assert_eq!(
        stx.world.assets.get(&source_id).map(|value| value.as_ref()),
        Some(&Quantity::from(6_u32))
    );
    assert_eq!(
        stx.world
            .assets
            .get(&destination_id)
            .map(|value| value.as_ref()),
        Some(&Quantity::from(4_u32))
    );
    assert!(stx.world.internal_event_buf.iter().any(|event| matches!(
        event.as_ref(),
        DataEvent::Asset(AssetEvent::Transferred(transfer)) if transfer.source() == &source_id
            && transfer.destination() == &destination_id
            && transfer.amount() == &Quantity::from(4_u32)
    )));
}
#[test]
fn fee_sponsor_custody_burn_reduces_balance_and_total_supply_together() {
    let (state, _custody, definition_id, source_id) = fee_sponsor_custody_state();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    assert_eq!(
        stx.world
            .asset_definition(&definition_id)
            .expect("seeded asset definition")
            .total_quantity(),
        &Quantity::from(10_u32),
        "the constructor already accounts for the exact initial custody balance"
    );
    stx.world.internal_event_buf.clear();
    let program_id = iroha_data_model::nexus::FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "custody-burn-test"
            .parse()
            .expect("fee sponsor program name"),
    );
    let authorization = crate::executor::VerifiedFeeSponsorCharge::burn_for_test(
        ALICE_ID.clone(),
        program_id,
        source_id.clone(),
        Quantity::from(2_u32),
    );
    super::isi::execute_verified_fee_sponsor_charge(&mut stx, authorization)
        .expect("protocol custody burn does not require custody authorization");
    assert_eq!(
        stx.world.assets.get(&source_id).map(|value| value.as_ref()),
        Some(&Quantity::from(8_u32))
    );
    assert_eq!(
        stx.world
            .asset_definition(&definition_id)
            .expect("asset definition")
            .total_quantity(),
        &Quantity::from(8_u32)
    );
    assert!(
        stx.world.internal_event_buf.iter().all(|event| !matches!(
            event.as_ref(),
            DataEvent::Asset(AssetEvent::Transferred(_))
                | DataEvent::Domain(DomainEvent::Asset(ScopedAsset {
                    event: AssetEvent::Transferred(_),
                    ..
                }))
        )),
        "burn must never be represented as an account-to-account transfer"
    );
}
fn build_asset_transfer_control_test_state(
    source_balance: u32,
) -> (State, AssetDefinitionId, AssetId) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
    let asset_definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_definition = build_numeric_asset_definition(&asset_definition_id, "rose", &ALICE_ID);
    let source_asset_id = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(source_balance));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_definition],
        [source_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    (state, asset_definition_id, source_asset_id)
}
#[test]
fn user_transfer_rejects_third_party_source_before_mutation() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA1; Hash::LENGTH]));
    let event_count = stx.world.internal_event_buf.len();
    let error = execute_user_numeric_asset_transfer(
        &mut stx,
        &BOB_ID,
        source_asset_id.clone(),
        BOB_ID.clone(),
        Quantity::one(),
    )
    .expect_err("an authority without an exact grant must not debit another account");
    assert!(
        error
            .to_string()
            .contains("lacks authority to transfer source asset"),
        "unexpected authorization error: {error}"
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::zero()
    );
    assert_eq!(
        stx.world.internal_event_buf.len(),
        event_count,
        "authorization denial must precede event staging"
    );
}
#[test]
fn user_transfer_accepts_exact_direct_asset_permission() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA2; Hash::LENGTH]));
    stx.world.add_account_permission(
        &BOB_ID,
        Permission::from(
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: source_asset_id.clone(),
            },
        ),
    );
    execute_user_numeric_asset_transfer(
        &mut stx,
        &BOB_ID,
        source_asset_id.clone(),
        BOB_ID.clone(),
        Quantity::from(3_u32),
    )
    .expect("the exact direct asset permission must authorize the debit");
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(7_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(3_u32)
    );
}
#[test]
fn user_transfer_accepts_exact_definition_permission_from_assigned_role() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA3; Hash::LENGTH]));
    let role_id: RoleId = "asset_transfer_delegate".parse().expect("valid role id");
    let role = Role::new(role_id.clone(), BOB_ID.clone())
        .add_permission(Permission::from(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition {
                asset_definition: asset_definition_id,
            },
        ))
        .build(&BOB_ID);
    stx.world.roles.insert(role_id.clone(), role);
    stx.world.account_roles.insert(
        crate::role::RoleIdWithOwner::new(BOB_ID.clone(), role_id),
        (),
    );
    execute_user_numeric_asset_transfer(
        &mut stx,
        &BOB_ID,
        source_asset_id.clone(),
        BOB_ID.clone(),
        Quantity::from(4_u32),
    )
    .expect("the exact definition permission inherited from a role must authorize");
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(6_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(4_u32)
    );
}
#[test]
fn user_transfer_rejects_same_name_permissions_with_wrong_payloads() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA4; Hash::LENGTH]));
    stx.world.add_account_permission(
        &BOB_ID,
        Permission::new("CanTransferAsset".into(), Json::new(())),
    );
    let role_id: RoleId = "malformed_asset_transfer_delegate"
        .parse()
        .expect("valid role id");
    let role = Role::new(role_id.clone(), BOB_ID.clone())
        .add_permission(Permission::new(
            "CanTransferAssetWithDefinition".into(),
            Json::new("all"),
        ))
        .build(&BOB_ID);
    stx.world.roles.insert(role_id.clone(), role);
    stx.world.account_roles.insert(
        crate::role::RoleIdWithOwner::new(BOB_ID.clone(), role_id),
        (),
    );
    execute_user_numeric_asset_transfer(
        &mut stx,
        &BOB_ID,
        source_asset_id.clone(),
        BOB_ID.clone(),
        Quantity::one(),
    )
    .expect_err("permission names without exact typed payloads must not authorize");
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::zero()
    );
}
#[test]
fn zero_mint_rejects_before_account_admission_and_preserves_once_budget() {
    let domain_id = DomainId::try_new("mint_budget", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id,
        "voucher".parse().expect("asset name"),
    );
    let definition = AssetDefinition::numeric(
        definition_id.clone(),
        "voucher".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .mintable_once()
    .build(&ALICE_ID);
    let world = World::with(
        [domain],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [definition],
    );
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let destination_id = AssetId::new(definition_id.clone(), BOB_ID.clone());
    let event_count = stx.world.internal_event_buf.len();
    let error = Mint::asset_quantity(Quantity::zero(), destination_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("a zero mint must be rejected before consuming issuance budget");
    assert!(
        error.to_string().contains("mint amount must be non-zero"),
        "unexpected zero-mint error: {error}"
    );
    assert!(
        stx.world.account(&BOB_ID).is_err(),
        "zero mint must not create the destination account"
    );
    assert!(stx.world.assets.get(&destination_id).is_none());
    let definition = stx
        .world
        .asset_definition(&definition_id)
        .expect("definition remains registered");
    assert_eq!(definition.mintable(), Mintable::Once);
    assert_eq!(definition.total_quantity(), &Quantity::zero());
    assert_eq!(
        stx.world.internal_event_buf.len(),
        event_count,
        "zero mint must not stage events"
    );
    let valid_destination = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    Mint::asset_quantity(Quantity::one(), valid_destination.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("the preserved once budget must permit one non-zero mint");
    let definition = stx
        .world
        .asset_definition(&definition_id)
        .expect("definition remains registered");
    assert_eq!(definition.mintable(), Mintable::Not);
    assert_eq!(definition.total_quantity(), &Quantity::one());
    assert_eq!(
        asset_balance_or_zero(&stx, &valid_destination),
        Quantity::one()
    );
}
#[test]
fn find_asset_definitions_filters_owner_with_owner_index() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
    let alice_definition_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "rose".parse().unwrap());
    let bob_definition_id =
        AssetDefinitionId::derive_from_components(domain_id.clone(), "tea".parse().unwrap());
    let alice_definition = build_numeric_asset_definition(&alice_definition_id, "rose", &ALICE_ID);
    let bob_definition = build_numeric_asset_definition(&bob_definition_id, "tea", &BOB_ID);
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [alice_definition, bob_definition],
        [],
        [],
    );
    assert!(
        world
            .view()
            .asset_definitions_by_owner
            .get(&ALICE_ID)
            .is_some_and(|ids| ids.contains(&alice_definition_id)),
        "world constructor should build the asset-definition owner index",
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let predicate =
        CompoundPredicate::<AssetDefinition>::build(|p| p.equals("owned_by", ALICE_ID.to_string()));
    let results: Vec<_> = FindAssetDefinitions
        .execute(predicate, &view)
        .unwrap()
        .map(|definition| definition.id().clone())
        .collect();
    assert_eq!(results, vec![alice_definition_id]);
}
fn asset_balance_or_zero(
    state_transaction: &crate::state::StateTransaction<'_, '_>,
    asset_id: &AssetId,
) -> Quantity {
    state_transaction
        .world
        .assets
        .get(asset_id)
        .map(|asset| asset.as_ref().clone())
        .unwrap_or_else(Quantity::zero)
}
fn load_asset_transfer_control_store(
    state_transaction: &crate::state::StateTransaction<'_, '_>,
    account_id: &AccountId,
) -> AssetTransferControlStoreV1 {
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    let account = state_transaction
        .world
        .account(account_id)
        .expect("controlled account exists");
    let raw = account
        .metadata()
        .get(&metadata_key)
        .cloned()
        .expect("asset transfer control metadata stored");
    raw.try_into_any_norito::<AssetTransferControlStoreV1>()
        .expect("stored control metadata decodes")
}
#[test]
fn find_assets_returns_registered_balances() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = build_account_in_domain(&ALICE_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&ALICE_ID);
    let asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let asset = Asset::new(asset_id.clone(), Quantity::from(13_u32));
    let world = World::with_assets([domain], [account], [asset_def], [asset], []);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let iter = ValidQuery::execute(FindAssets, CompoundPredicate::PASS, &view)
        .expect("query execution succeeds");
    let assets: Vec<_> = iter.collect();
    assert_eq!(assets.len(), 1, "expected the pre-registered asset");
    let fetched = &assets[0];
    assert_eq!(fetched.id(), &asset_id);
    assert_eq!(*fetched.value(), Quantity::from(13_u32));
}
#[test]
fn find_assets_by_account_id_limits_results_to_requested_owner() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let bob_account = build_account_in_domain(&bob_id, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&ALICE_ID);
    let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(asset_def_id.clone(), bob_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(13_u32));
    let bob_asset = Asset::new(bob_asset_id, Quantity::from(7_u32));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset, bob_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let assets: Vec<_> = FindAssetsByAccountId::new(ALICE_ID.clone())
        .execute(CompoundPredicate::PASS, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].id().account(), &*ALICE_ID);
    assert_eq!(assets[0].id(), &alice_asset_id);
}
#[test]
fn find_assets_filters_by_account_predicate() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let bob_account = build_account_in_domain(&bob_id, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&ALICE_ID);
    let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(asset_def_id.clone(), bob_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(13_u32));
    let bob_asset = Asset::new(bob_asset_id, Quantity::from(7_u32));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset, bob_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let mut predicate = PredicateJson::default();
    predicate.equals.push(EqualsCondition::new(
        "account",
        Value::String(ALICE_ID.to_string()),
    ));
    let filter = predicate
        .into_compound::<Asset>()
        .expect("predicate is valid JSON");
    let assets: Vec<_> = ValidQuery::execute(FindAssets, filter, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].id(), &alice_asset_id);
    assert_eq!(*assets[0].value(), Quantity::from(13_u32));
}
#[test]
fn asset_predicate_view_extracts_alias_fields_for_planner() {
    let account_filter =
        CompoundPredicate::<Asset>::build(|p| p.equals("id.account", ALICE_ID.to_string()));
    let account_view = AssetPredicateView::from_predicate(&account_filter);
    assert!(
        matches!(account_view.plan(), AssetQueryPlan::Subjects { .. }),
        "id.account should seed subject plan"
    );
    let definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let definition_filter =
        CompoundPredicate::<Asset>::build(|p| p.equals("id.definition", definition_id.clone()));
    let definition_view = AssetPredicateView::from_predicate(&definition_filter);
    assert!(
        matches!(definition_view.plan(), AssetQueryPlan::Definitions(_)),
        "id.definition should seed definition plan"
    );
    let domain_filter =
        CompoundPredicate::<Asset>::build(|p| p.equals("definition.domain", "wonderland"));
    let domain_view = AssetPredicateView::from_predicate(&domain_filter);
    assert!(
        matches!(domain_view.plan(), AssetQueryPlan::Domains { .. }),
        "definition.domain should seed domain plan"
    );
    let id_domain_filter =
        CompoundPredicate::<Asset>::build(|p| p.equals("id.definition.domain", "wonderland"));
    let id_domain_view = AssetPredicateView::from_predicate(&id_domain_filter);
    assert!(
        matches!(id_domain_view.plan(), AssetQueryPlan::Domains { .. }),
        "id.definition.domain should seed domain plan"
    );
    let asset_id = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let id_filter = CompoundPredicate::<Asset>::build(|p| {
        p.equals("id", asset_id.to_string())
            .equals("id.definition.domain", "wonderland")
    });
    let id_view = AssetPredicateView::from_predicate(&id_filter);
    let AssetQueryPlan::Ids(ids) = id_view.plan() else {
        panic!("exact asset id should seed direct id plan");
    };
    assert_eq!(ids, vec![asset_id]);
}
#[test]
fn find_assets_filters_by_id_account_alias_predicate() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let bob_account = build_account_in_domain(&bob_id, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&ALICE_ID);
    let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(asset_def_id.clone(), bob_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(13_u32));
    let bob_asset = Asset::new(bob_asset_id, Quantity::from(7_u32));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset, bob_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let predicate =
        CompoundPredicate::<Asset>::build(|p| p.equals("id.account", ALICE_ID.to_string()));
    let assets: Vec<_> = ValidQuery::execute(FindAssets, predicate, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].id(), &alice_asset_id);
    assert_eq!(*assets[0].value(), Quantity::from(13_u32));
}
#[test]
fn find_assets_filters_by_exact_id_with_extra_predicate() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let bob_account = build_account_in_domain(&bob_id, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        )
    }
    .build(&ALICE_ID);
    let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(asset_def_id, bob_id.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(13_u32));
    let bob_asset = Asset::new(bob_asset_id, Quantity::from(7_u32));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset, bob_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let predicate = CompoundPredicate::<Asset>::build(|p| {
        p.equals("id", alice_asset_id.to_string())
            .equals("id.definition.domain", domain_id.to_string())
    });
    let assets: Vec<_> = ValidQuery::execute(FindAssets, predicate, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].id(), &alice_asset_id);
    assert_eq!(*assets[0].value(), Quantity::from(13_u32));
}
#[test]
fn find_assets_filters_by_account_and_domain_predicate() {
    let primary_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    let secondary_domain_id: DomainId =
        DomainId::try_new("redland", "universal").expect("domain id");
    let primary_domain = Domain::new(primary_domain_id.clone()).build(&ALICE_ID);
    let secondary_domain = Domain::new(secondary_domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &primary_domain_id);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let bob_account = build_account_in_domain(&bob_id, &primary_domain_id);
    let primary_asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            primary_domain_id.clone(),
            "rose".parse().unwrap(),
        );
    let secondary_asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            secondary_domain_id.clone(),
            "lily".parse().unwrap(),
        );
    let primary_asset_def = {
        let __asset_definition_id = primary_asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(primary_domain_id.clone()),
        )
    }
    .build(&ALICE_ID);
    let secondary_asset_def = {
        let __asset_definition_id = secondary_asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "lily".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(secondary_domain_id.clone()),
        )
    }
    .build(&ALICE_ID);
    let alice_primary_asset_id = AssetId::new(primary_asset_def_id.clone(), ALICE_ID.clone());
    let alice_secondary_asset_id = AssetId::new(secondary_asset_def_id.clone(), ALICE_ID.clone());
    let bob_primary_asset_id = AssetId::new(primary_asset_def_id, bob_id.clone());
    let alice_primary_asset = Asset::new(alice_primary_asset_id.clone(), Quantity::from(13_u32));
    let alice_secondary_asset = Asset::new(alice_secondary_asset_id, Quantity::from(7_u32));
    let bob_primary_asset = Asset::new(bob_primary_asset_id, Quantity::from(5_u32));
    let world = World::with_assets(
        [primary_domain, secondary_domain],
        [alice_account, bob_account],
        [primary_asset_def, secondary_asset_def],
        [
            alice_primary_asset,
            alice_secondary_asset,
            bob_primary_asset,
        ],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let mut predicate = PredicateJson::default();
    predicate.equals.push(EqualsCondition::new(
        "account",
        Value::String(ALICE_ID.to_string()),
    ));
    predicate.equals.push(EqualsCondition::new(
        "domain",
        Value::String(primary_domain_id.to_string()),
    ));
    let filter = predicate
        .into_compound::<Asset>()
        .expect("predicate is valid JSON");
    let assets: Vec<_> = ValidQuery::execute(FindAssets, filter, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].id(), &alice_primary_asset_id);
    assert_eq!(*assets[0].value(), Quantity::from(13_u32));
}
#[test]
fn transfer_removes_metadata_when_balance_zero() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let bob_account = build_account_in_domain(&BOB_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = {
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "rose".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    }
    .build(&ALICE_ID);
    let alice_asset_id = AssetId::new(asset_def_id, ALICE_ID.clone());
    let alice_asset = Asset::new(alice_asset_id.clone(), Quantity::from(1_u32));
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB1; Hash::LENGTH]));
    let key: Name = "tag".parse().expect("metadata key");
    let value = Json::from(norito::json!("seed"));
    SetAssetKeyValue::new(alice_asset_id.clone(), key, value)
        .execute(&ALICE_ID, &mut stx)
        .expect("set metadata");
    Transfer::asset_quantity(alice_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("transfer succeeds");
    assert!(stx.world.assets.get(&alice_asset_id).is_none());
    assert!(stx.world.asset_metadata.get(&alice_asset_id).is_none());
}
#[test]
fn full_balance_self_transfer_preserves_asset_metadata_and_indexes() {
    let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id parses");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let definition_id = AssetDefinitionId::derive_from_components(
        domain_id,
        "rose".parse().expect("asset definition name parses"),
    );
    let definition = build_numeric_asset_definition(&definition_id, "rose", &ALICE_ID);
    let asset_id = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let asset = Asset::new(asset_id.clone(), Quantity::one());
    let world = World::with_assets([domain], [alice_account], [definition], [asset], []);
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB2; Hash::LENGTH]));
    let key: Name = "tag".parse().expect("metadata key parses");
    SetAssetKeyValue::new(
        asset_id.clone(),
        key,
        Json::from(norito::json!("preserve-me")),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("set asset metadata");
    let metadata_before = stx
        .world
        .asset_metadata
        .get(&asset_id)
        .cloned()
        .expect("metadata exists before self-transfer");
    stx.world.internal_event_buf.clear();
    Transfer::asset_quantity(asset_id.clone(), Quantity::one(), ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("a full-balance self-transfer is an identity movement");
    assert_eq!(asset_balance_or_zero(&stx, &asset_id), Quantity::one());
    assert_eq!(
        stx.world.asset_metadata.get(&asset_id),
        Some(&metadata_before),
        "the identity transfer must not remove and recreate the asset"
    );
    assert!(
        stx.world
            .asset_definition_assets
            .get(&definition_id)
            .is_some_and(|assets| assets.contains(&asset_id))
    );
    assert!(
        stx.world
            .asset_definition_holders
            .get(&definition_id)
            .is_some_and(|holders| holders.contains(&ALICE_ID))
    );
    assert!(
        stx.world
            .asset_definition_nonzero_holders
            .get(&definition_id)
            .is_some_and(|holders| holders.contains(&ALICE_ID))
    );
    assert_eq!(
        stx.world.internal_event_buf.len(),
        3,
        "identity movement emits the canonical deltas and one paired transfer event"
    );
    assert!(stx.world.internal_event_buf.iter().any(|event| matches!(
        event.as_ref(),
        DataEvent::Asset(AssetEvent::Transferred(transfer)) if transfer.source() == &asset_id
            && transfer.destination() == &asset_id
            && transfer.amount() == &Quantity::one()
    )));
}
#[test]
fn asset_transfer_controls_require_asset_owner_authority() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let alice_alias = AccountAlias::new(
        "alice".parse().expect("account alias label"),
        Some(AccountAliasDomain::new(
            "wonderland".parse().expect("account alias domain"),
        )),
        DataSpaceId::UNIVERSAL,
    );
    seed_test_account_alias_binding(&mut stx, &ALICE_ID, &alice_alias);
    seed_test_account_alias_lease(&mut stx, &ALICE_ID, &alice_alias);
    let err = SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some("operator hold".to_owned()),
    )
    .execute(&BOB_ID, &mut stx)
    .expect_err("non-owner must be rejected");
    assert!(
        err.to_string().contains("owner is"),
        "unexpected error: {err}"
    );
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    let account = stx
        .world
        .account(&ALICE_ID)
        .expect("controlled account exists");
    assert!(
        account.metadata().get(&metadata_key).is_none(),
        "rejected control instruction must not persist metadata"
    );
}
#[test]
fn generic_account_metadata_instructions_cannot_replace_or_remove_transfer_controls() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id,
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some("compliance hold".to_owned()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("native control instruction stores the reserved metadata");
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    let original = stx
        .world
        .account(&ALICE_ID)
        .expect("controlled account exists")
        .metadata()
        .get(&metadata_key)
        .cloned()
        .expect("native controls exist");
    let set_error = SetKeyValue::account(
        ALICE_ID.clone(),
        metadata_key.clone(),
        iroha_primitives::json::Json::new("attacker replacement"),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect_err("generic metadata set must reject the native control key");
    assert!(set_error.to_string().contains("reserved"));
    let remove_error = RemoveKeyValue::account(ALICE_ID.clone(), metadata_key.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("generic metadata removal must reject the native control key");
    assert!(remove_error.to_string().contains("reserved"));
    assert_eq!(
        stx.world
            .account(&ALICE_ID)
            .expect("controlled account exists")
            .metadata()
            .get(&metadata_key),
        Some(&original),
        "rejected generic mutations must leave controls intact"
    );
}
#[test]
fn genesis_has_inherent_transfer_control_authority() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some("genesis policy".to_owned()),
    )
    .execute(&BOB_ID, &mut stx)
    .expect("genesis may establish initial availability independent of ownership");
    SetAssetHoldingLimit::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        Some(Quantity::from(5_000_u32)),
    )
    .execute(&BOB_ID, &mut stx)
    .expect("genesis may establish an initial holding limit independent of ownership");
    let record = load_asset_transfer_control_store(&stx, &ALICE_ID)
        .find(&asset_definition_id)
        .cloned()
        .expect("genesis availability persisted");
    assert_eq!(record.availability_revision, 1);
    assert_eq!(
        record.outgoing_availability,
        AssetTransferAvailability::Disabled
    );
    assert_eq!(record.holding_limit, Some(Quantity::from(5_000_u32)));
}
#[test]
fn delegated_controls_use_exact_availability_scoped_daily_and_exact_holding() {
    let domain_id = DomainId::try_new("currency", "sbp").expect("asset definition domain");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let owner = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let delegate = Account::new(BOB_ID.clone()).build(&ALICE_ID);
    let hbl_sbp_id = iroha_test_samples::gen_account_in("hbl").0;
    let hbl_other_id = iroha_test_samples::gen_account_in("hbl_other").0;
    let ubl_sbp_id = iroha_test_samples::gen_account_in("ubl").0;
    let unlabeled_id = iroha_test_samples::gen_account_in("unlabeled").0;
    let hbl_sbp_alias = AccountAlias::new(
        "retail_hbl_sbp".parse().expect("alias label"),
        Some(AccountAliasDomain::new(
            "hbl".parse().expect("alias domain"),
        )),
        DataSpaceId::new(10),
    );
    let hbl_other_alias = AccountAlias::new(
        "retail_hbl_other".parse().expect("alias label"),
        Some(AccountAliasDomain::new(
            "hbl".parse().expect("alias domain"),
        )),
        DataSpaceId::new(11),
    );
    let ubl_sbp_alias = AccountAlias::new(
        "retail_ubl_sbp".parse().expect("alias label"),
        Some(AccountAliasDomain::new(
            "ubl".parse().expect("alias domain"),
        )),
        DataSpaceId::new(10),
    );
    let hbl_sbp = Account::new(hbl_sbp_id.clone()).build(&ALICE_ID);
    let hbl_other = Account::new(hbl_other_id.clone()).build(&ALICE_ID);
    let ubl_sbp = Account::new(ubl_sbp_id.clone()).build(&ALICE_ID);
    let unlabeled = Account::new(unlabeled_id.clone()).build(&ALICE_ID);
    let asset_definition_id = AssetDefinitionId::derive_from_components(
        domain_id,
        "pkr".parse().expect("asset definition name"),
    );
    let asset_definition = build_numeric_asset_definition(&asset_definition_id, "pkr", &ALICE_ID);
    let account_domain = AccountAliasDomain::new("hbl".parse().expect("HBL domain"));
    let account_dataspace = DataSpaceId::new(10);
    let mut world = World::with_assets(
        [domain],
        [owner, delegate, hbl_sbp, hbl_other, ubl_sbp, unlabeled],
        [asset_definition],
        [],
        [],
    );
    world.account_permissions.insert(
        BOB_ID.clone(),
        BTreeSet::from([
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferAvailability {
                    account: hbl_sbp_id.clone(),
                    asset_definition: asset_definition_id.clone(),
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetTransferDailyLimit {
                    asset_definition: asset_definition_id.clone(),
                    account_domain,
                    account_dataspace,
                },
            ),
            Permission::from(
                iroha_executor_data_model::permission::asset::CanSetAssetHoldingLimit {
                    account: hbl_sbp_id.clone(),
                    asset_definition: asset_definition_id.clone(),
                },
            ),
        ]),
    );
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let dataspace_catalog = DataSpaceCatalog::new(vec![
        iroha_data_model::nexus::DataSpaceMetadata::default(),
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(10),
            alias: "banking".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
        iroha_data_model::nexus::DataSpaceMetadata {
            id: DataSpaceId::new(11),
            alias: "alternate".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("transfer-control dataspace catalog");
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 86_400_000, 0);
    let mut block = state.block(header);
    block.nexus.dataspace_catalog = dataspace_catalog.clone();
    let mut stx = block.transaction();
    stx.nexus.dataspace_catalog = dataspace_catalog.clone();
    stx.world.dataspace_catalog = dataspace_catalog;
    seed_test_account_alias_binding(&mut stx, &hbl_sbp_id, &hbl_sbp_alias);
    seed_test_account_alias_binding(&mut stx, &hbl_other_id, &hbl_other_alias);
    seed_test_account_alias_binding(&mut stx, &ubl_sbp_id, &ubl_sbp_alias);
    seed_test_account_alias_lease(&mut stx, &hbl_sbp_id, &hbl_sbp_alias);
    seed_test_account_alias_lease(&mut stx, &hbl_other_id, &hbl_other_alias);
    seed_test_account_alias_lease(&mut stx, &ubl_sbp_id, &ubl_sbp_alias);
    SetAssetTransferAvailability::new(
        hbl_sbp_id.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Disabled,
        AssetTransferAvailability::Disabled,
        Some("exact FI scope".to_owned()),
    )
    .execute(&BOB_ID, &mut stx)
    .expect("exact HBL/SBP availability permission must execute");
    SetAssetTransferControl::new(
        hbl_sbp_id.clone(),
        asset_definition_id.clone(),
        vec![AssetTransferLimit {
            window: AssetTransferControlWindow::Day,
            cap_amount: Some(Quantity::from(100_u32)),
        }],
    )
    .execute(&BOB_ID, &mut stx)
    .expect("exact HBL/SBP daily-limit permission must execute");
    SetAssetHoldingLimit::new(
        hbl_sbp_id.clone(),
        asset_definition_id.clone(),
        Some(Quantity::from(1_000_u32)),
    )
    .execute(&BOB_ID, &mut stx)
    .expect("exact holding-limit permission must execute");
    let blacklist_error =
        SetAssetTransferBlacklist::new(hbl_sbp_id.clone(), asset_definition_id.clone(), true)
            .execute(&BOB_ID, &mut stx)
            .expect_err("holding-limit permission must not authorize blacklist changes");
    assert!(
        blacklist_error
            .to_string()
            .contains("required asset-owner transfer-control permission"),
        "unexpected blacklist authorization error: {blacklist_error}",
    );
    for (target, expected_error) in [
        (
            &hbl_other_id,
            "lacks the required account-domain-and-dataspace transfer-control permission",
        ),
        (
            &ubl_sbp_id,
            "lacks the required account-domain-and-dataspace transfer-control permission",
        ),
        (&unlabeled_id, "no canonical on-chain alias label"),
    ] {
        let availability_error = SetAssetTransferAvailability::new(
            target.clone(),
            asset_definition_id.clone(),
            0,
            AssetTransferAvailability::Disabled,
            AssetTransferAvailability::Disabled,
            Some("out of scope".to_owned()),
        )
        .execute(&BOB_ID, &mut stx)
        .expect_err("cross-scope availability update must be rejected");
        assert!(
            availability_error
                .to_string()
                .contains("lacks the required exact account-and-asset"),
            "unexpected availability error for {target}: {availability_error}",
        );
        let limit_error = SetAssetTransferControl::new(
            target.clone(),
            asset_definition_id.clone(),
            vec![AssetTransferLimit {
                window: AssetTransferControlWindow::Day,
                cap_amount: Some(Quantity::from(100_u32)),
            }],
        )
        .execute(&BOB_ID, &mut stx)
        .expect_err("cross-scope limit must be rejected");
        assert!(
            limit_error.to_string().contains(expected_error),
            "unexpected limit error for {target}: {limit_error}",
        );
        let holding_error = SetAssetHoldingLimit::new(
            target.clone(),
            asset_definition_id.clone(),
            Some(Quantity::from(1_000_u32)),
        )
        .execute(&BOB_ID, &mut stx)
        .expect_err("cross-account holding limit must be rejected");
        assert!(
            holding_error
                .to_string()
                .contains("lacks the required exact account-and-asset"),
            "unexpected holding-limit error for {target}: {holding_error}",
        );
    }
    let exact = load_asset_transfer_control_store(&stx, &hbl_sbp_id);
    let exact = exact
        .find(&asset_definition_id)
        .expect("exact-scope controls persisted");
    assert_eq!(
        exact.outgoing_availability,
        AssetTransferAvailability::Disabled
    );
    assert_eq!(exact.limits.len(), 1);
    assert_eq!(exact.holding_limit, Some(Quantity::from(1_000_u32)));
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    for target in [&hbl_other_id, &ubl_sbp_id, &unlabeled_id] {
        assert!(
            stx.world
                .account(target)
                .expect("target account")
                .metadata()
                .get(&metadata_key)
                .is_none(),
            "rejected cross-scope operation must not mutate {target}",
        );
    }
}
#[test]
fn availability_is_revisioned_and_only_blocks_account_transfers_until_reopened() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xCB; Hash::LENGTH]));
    SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Disabled,
        AssetTransferAvailability::Disabled,
        Some("compliance hold".to_owned()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("availability close succeeds");
    let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("disabled outgoing transfer must be rejected");
    assert!(matches!(
        err,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::OutgoingDisabled(_)
        )
    ));
    Mint::asset_quantity(2_u32, source_asset_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("mint is a supply operation, not an incoming transfer");
    Burn::asset_quantity(1_u32, source_asset_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("burn is a supply operation, not an outgoing transfer");
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(11_u32)
    );
    assert!(
        !stx.world.internal_event_buf.iter().any(|event| matches!(
            event.as_ref(),
            DataEvent::Asset(AssetEvent::Transferred(_))
                | DataEvent::Domain(DomainEvent::Asset(ScopedAsset {
                    event: AssetEvent::Transferred(_),
                    ..
                }))
        )),
        "mint and burn must not emit the transfer-specific event"
    );
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    Mint::asset_quantity(Quantity::one(), destination_asset_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("asset owner funds the incoming-transfer source");
    let incoming_err =
        Transfer::asset_quantity(destination_asset_id.clone(), 1_u32, ALICE_ID.clone())
            .execute(&BOB_ID, &mut stx)
            .expect_err("disabled incoming transfer must be rejected");
    assert!(matches!(
        incoming_err,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::IncomingDisabled(_)
        )
    ));
    let stale = SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Enabled,
        Some("stale reopen".to_owned()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect_err("stale revision must fail");
    assert!(matches!(
        stale,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::AvailabilityRevisionMismatch(_)
        )
    ));
    SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        1,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Enabled,
        Some("hold released".to_owned()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("matching revision reopens both directions");
    Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("outgoing transfer succeeds after reopen");
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(2_u32)
    );
    let store = load_asset_transfer_control_store(&stx, &ALICE_ID);
    let record = store
        .find(&asset_definition_id)
        .expect("reopened revisioned record remains stored");
    assert_eq!(record.availability_revision, 2);
    assert!(record.incoming_availability.is_enabled());
    assert!(record.outgoing_availability.is_enabled());
    assert!(!record.blacklisted);
    assert!(record.usages.is_empty());
}
#[test]
fn availability_reason_over_limit_is_rejected_without_persistence() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let reason =
        "x".repeat(iroha_data_model::asset::ASSET_TRANSFER_AVAILABILITY_MAX_REASON_BYTES_V1 + 1);
    let error = SetAssetTransferAvailability::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        0,
        AssetTransferAvailability::Enabled,
        AssetTransferAvailability::Disabled,
        Some(reason),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect_err("oversized persisted reason must be rejected");
    assert!(
        error.to_string().contains("maximum byte length"),
        "unexpected error: {error}"
    );
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    let account = stx
        .world
        .account(&ALICE_ID)
        .expect("controlled account exists");
    assert!(
        account.metadata().get(&metadata_key).is_none(),
        "invalid reason must not persist transfer-control metadata"
    );
}
#[test]
fn transfer_rejects_when_account_is_blacklisted_for_asset() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    SetAssetTransferBlacklist::new(ALICE_ID.clone(), asset_definition_id.clone(), true)
        .execute(&ALICE_ID, &mut stx)
        .expect("blacklist succeeds");
    let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("blacklisted outbound transfer must be rejected");
    assert!(
        matches!(
            err,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::Blacklisted(_)
            )
        ),
        "unexpected error: {err}"
    );
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::zero()
    );
    let store = load_asset_transfer_control_store(&stx, &ALICE_ID);
    let record = store
        .find(&asset_definition_id)
        .expect("blacklist record stored");
    assert!(record.blacklisted);
    assert!(record.outgoing_availability.is_enabled());
    assert!(record.usages.is_empty());
}
#[test]
fn holding_limit_applies_to_transfer_and_mint_credit_paths() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xCA; Hash::LENGTH]));
    SetAssetHoldingLimit::new(
        BOB_ID.clone(),
        asset_definition_id.clone(),
        Some(Quantity::from(5_u32)),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("asset owner sets destination holding limit");
    Transfer::asset_quantity(source_asset_id.clone(), 5_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("credit exactly at holding limit");
    let transfer_error = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("transfer above holding limit must fail");
    assert!(matches!(
        transfer_error,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    let mint_error = Mint::asset_quantity(1_u32, destination_asset_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("mint above holding limit must fail");
    assert!(matches!(
        mint_error,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(5_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32)
    );
    let store = load_asset_transfer_control_store(&stx, &BOB_ID);
    assert_eq!(
        store
            .find(&asset_definition_id)
            .and_then(|record| record.holding_limit.as_ref()),
        Some(&Quantity::from(5_u32))
    );
    SetAssetHoldingLimit::new(
        BOB_ID.clone(),
        asset_definition_id.clone(),
        Some(Quantity::zero()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("asset owner can close inbound credit while a balance remains");
    let closed_error = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("zero holding limit must reject further inbound credit");
    assert!(matches!(
        closed_error,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32)
    );
}
#[test]
fn exact_numeric_credit_precheck_enforces_holding_limit_without_mutation() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    SetAssetHoldingLimit::new(
        BOB_ID.clone(),
        asset_definition_id.clone(),
        Some(Quantity::from(5_u32)),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("asset owner sets destination holding limit");
    let (resolved_id, candidate) = stx
        .world
        .precheck_numeric_asset_credit(&destination_asset_id, &Quantity::from(5_u32))
        .expect("credit exactly at the holding limit must precheck");
    assert_eq!(resolved_id, destination_asset_id);
    assert_eq!(candidate, Quantity::from(5_u32));
    assert!(
        stx.world.assets.get(&destination_asset_id).is_none(),
        "read-only credit precheck must not create a balance"
    );
    super::super::isi::seed_numeric_asset_balance_exact_for_test(
        &mut stx.world,
        &resolved_id,
        &Quantity::from(5_u32),
    )
    .expect("checked exact credit at the holding limit must apply");
    let error = stx
        .world
        .precheck_numeric_asset_credit_exact(&resolved_id, &Quantity::one())
        .expect_err("exact credit above the holding limit must fail");
    assert!(matches!(
        error,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32),
        "rejected exact credit must leave the balance unchanged"
    );
    SetAssetHoldingLimit::new(
        BOB_ID.clone(),
        asset_definition_id,
        Some(Quantity::from(4_u32)),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("asset owner may lower the limit below the current balance");
    let error = super::super::isi::seed_numeric_asset_balance_for_test(
        &mut stx.world,
        &destination_asset_id,
        &Quantity::one(),
    )
    .expect_err("a balance already above its limit must reject further credit");
    assert!(matches!(
        error,
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_)
        )
    ));
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32)
    );
}
#[test]
fn duplicate_transfer_limit_windows_are_rejected() {
    let (state, asset_definition_id, _) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let error = SetAssetTransferControl::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        vec![
            AssetTransferLimit {
                window: AssetTransferControlWindow::Day,
                cap_amount: Some(Quantity::from(5_u32)),
            },
            AssetTransferLimit {
                window: AssetTransferControlWindow::Day,
                cap_amount: Some(Quantity::from(10_u32)),
            },
        ],
    )
    .execute(&ALICE_ID, &mut stx)
    .expect_err("duplicate windows must not be order-dependent");
    assert!(
        error
            .to_string()
            .contains("duplicate asset transfer limit window DAY"),
        "unexpected error: {error}"
    );
    let metadata_key: Name = ASSET_TRANSFER_CONTROL_METADATA_KEY
        .parse()
        .expect("metadata key");
    assert!(
        stx.world
            .account(&ALICE_ID)
            .expect("controlled account exists")
            .metadata()
            .get(&metadata_key)
            .is_none(),
        "rejected duplicate windows must not create control metadata",
    );
}
#[test]
fn prepared_numeric_transfer_rejects_stale_balance_without_applying() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_protocol_testing();
    let error = super::super::isi::apply_prepared_numeric_transfer_after_source_credit_for_test(
        &mut stx,
        &ALICE_ID,
        source_asset_id.clone(),
        destination_asset_id.clone(),
        Quantity::from(3_u32),
        Quantity::one(),
    )
    .expect_err("stale prepared movement must fail closed");
    assert!(error.to_string().contains("source balance changed"));
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(11_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::zero(),
        "stale movement must not credit its destination"
    );
}
#[test]
fn direct_typed_movement_identity_is_stable_and_purpose_bound() {
    let (state, asset_definition_id, source_id) = build_asset_transfer_control_test_state(10);
    let destination_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let stx = block.transaction();
    assert!(stx.tx_call_hash.is_none());
    let legs = vec![(source_id, destination_id, Quantity::from(3_u32))];
    let first = super::super::isi::resolve_social_send_movement_identity_for_test(
        &stx,
        &ALICE_ID,
        &legs,
        vec![0x11],
    )
    .expect("direct typed identity");
    let repeated = super::super::isi::resolve_social_send_movement_identity_for_test(
        &stx,
        &ALICE_ID,
        &legs,
        vec![0x11],
    )
    .expect("stable direct typed identity");
    assert_eq!(first, repeated);
    let distinct = super::super::isi::resolve_social_send_movement_identity_for_test(
        &stx,
        &ALICE_ID,
        &legs,
        vec![0x12],
    )
    .expect("purpose-bound direct identity");
    assert_ne!(first, distinct);
}
#[test]
fn typed_movement_rejects_empty_purpose_binding_even_with_call_hash() {
    let (state, asset_definition_id, source_id) = build_asset_transfer_control_test_state(10);
    let destination_id = AssetId::new(asset_definition_id, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xD5; Hash::LENGTH]));
    let error = super::super::isi::resolve_social_send_movement_identity_for_test(
        &stx,
        &ALICE_ID,
        &[(source_id, destination_id, Quantity::from(3_u32))],
        Vec::new(),
    )
    .expect_err("empty typed purpose must fail closed");
    assert!(error.to_string().contains("binding must not be empty"));
}
#[test]
fn atomic_batch_aggregates_repeated_source_before_enforcing_cap() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 86_400_000, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xD4; Hash::LENGTH]));
    SetAssetTransferControl::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        vec![AssetTransferLimit {
            window: AssetTransferControlWindow::Day,
            cap_amount: Some(Quantity::from(5_u32)),
        }],
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("configure source cap");
    let batch = TransferAssetBatch::new(vec![
        TransferAssetBatchEntry::with_leg_id(
            "first",
            ALICE_ID.clone(),
            BOB_ID.clone(),
            asset_definition_id.clone(),
            3_u32,
        ),
        TransferAssetBatchEntry::with_leg_id(
            "second",
            ALICE_ID.clone(),
            BOB_ID.clone(),
            asset_definition_id.clone(),
            3_u32,
        ),
    ]);
    let error = batch
        .execute(&ALICE_ID, &mut stx)
        .expect_err("aggregate six-unit debit must exceed five-unit cap");
    assert!(
        matches!(
            &error,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::PolicyRejected(message)
            ) if message.contains("outbound transfer cap exceeded")
        ),
        "unexpected admission error: {error:?}"
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(10_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::zero()
    );
    let store = load_asset_transfer_control_store(&stx, &ALICE_ID);
    let record = store
        .find(&asset_definition_id)
        .expect("configured source control remains present");
    assert!(
        record.usages.is_empty(),
        "rejected aggregate batch must not consume rolling-cap usage"
    );
    assert_eq!(stx.pending_transfer_transcript_count_for_testing(), 0);
}
#[test]
fn transfer_allows_exact_cap_and_preserves_usage_on_rejected_overage() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 86_400_000, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB2; Hash::LENGTH]));
    SetAssetTransferControl::new(
        ALICE_ID.clone(),
        asset_definition_id.clone(),
        vec![AssetTransferLimit {
            window: AssetTransferControlWindow::Day,
            cap_amount: Some(Quantity::from(5_u32)),
        }],
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("limit update succeeds");
    Transfer::asset_quantity(source_asset_id.clone(), 5_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("exact-cap transfer must succeed");
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(5_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32)
    );
    let store_after_success = load_asset_transfer_control_store(&stx, &ALICE_ID);
    let record_after_success = store_after_success
        .find(&asset_definition_id)
        .expect("limit record stored after successful transfer");
    assert_eq!(record_after_success.limits.len(), 1);
    assert_eq!(record_after_success.usages.len(), 1);
    let usage = &record_after_success.usages[0];
    assert_eq!(usage.window, AssetTransferControlWindow::Day);
    assert_eq!(usage.bucket_start_ms, 86_400_000);
    assert_eq!(usage.spent_amount, Quantity::from(5_u32));
    let err = Transfer::asset_quantity(source_asset_id.clone(), 1_u32, BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("over-cap transfer must be rejected");
    assert!(
        matches!(
            &err,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::PolicyRejected(message)
            ) if message.contains("outbound transfer cap exceeded")
        ),
        "unexpected admission error: {err:?}"
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &source_asset_id),
        Quantity::from(5_u32)
    );
    assert_eq!(
        asset_balance_or_zero(&stx, &destination_asset_id),
        Quantity::from(5_u32)
    );
    let store_after_rejection = load_asset_transfer_control_store(&stx, &ALICE_ID);
    let record_after_rejection = store_after_rejection
        .find(&asset_definition_id)
        .expect("limit record retained after rejected transfer");
    assert_eq!(record_after_rejection.usages.len(), 1);
    assert_eq!(
        record_after_rejection.usages[0].spent_amount,
        Quantity::from(5_u32)
    );
    assert_eq!(record_after_rejection.usages[0].bucket_start_ms, 86_400_000);
}
#[test]
fn find_assets_filters_by_definition_predicate() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let accounts = [
        build_account_in_domain(&ALICE_ID, &domain_id),
        build_account_in_domain(&bob_id, &domain_id),
    ];
    let rose_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let tulip_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "tulip".parse().unwrap(),
        );
    let definitions = [
        {
            let __asset_definition_id = rose_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID),
        {
            let __asset_definition_id = tulip_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "tulip".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID),
    ];
    let assets = [
        Asset::new(
            AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(13_u32),
        ),
        Asset::new(
            AssetId::new(rose_def_id.clone(), bob_id.clone()),
            Quantity::from(7_u32),
        ),
        Asset::new(
            AssetId::new(tulip_def_id, ALICE_ID.clone()),
            Quantity::from(3_u32),
        ),
    ];
    let world = World::with_assets([domain], accounts, definitions, assets, /*nfts*/ []);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let mut predicate = PredicateJson::default();
    predicate.equals.push(EqualsCondition::new(
        "definition",
        Value::String(rose_def_id.to_string()),
    ));
    let filter = predicate
        .into_compound::<Asset>()
        .expect("predicate is valid JSON");
    let assets: Vec<_> = ValidQuery::execute(FindAssets, filter, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 2);
    assert!(
        assets
            .iter()
            .all(|asset| asset.id().definition() == &rose_def_id)
    );
    let mut ids: Vec<_> = assets.into_iter().map(|asset| asset.id().clone()).collect();
    ids.sort();
    let mut expected = vec![
        AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
        AssetId::new(rose_def_id, bob_id),
    ];
    expected.sort();
    assert_eq!(ids, expected);
}
#[test]
fn find_assets_filters_by_id_definition_alias_predicate() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let accounts = [
        build_account_in_domain(&ALICE_ID, &domain_id),
        build_account_in_domain(&bob_id, &domain_id),
    ];
    let rose_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let tulip_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "tulip".parse().unwrap(),
        );
    let definitions = [
        {
            let __asset_definition_id = rose_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID),
        {
            let __asset_definition_id = tulip_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "tulip".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        }
        .build(&ALICE_ID),
    ];
    let assets = [
        Asset::new(
            AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(13_u32),
        ),
        Asset::new(
            AssetId::new(rose_def_id.clone(), bob_id.clone()),
            Quantity::from(7_u32),
        ),
        Asset::new(
            AssetId::new(tulip_def_id, ALICE_ID.clone()),
            Quantity::from(3_u32),
        ),
    ];
    let world = World::with_assets([domain], accounts, definitions, assets, /*nfts*/ []);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let predicate =
        CompoundPredicate::<Asset>::build(|p| p.equals("id.definition", rose_def_id.clone()));
    let assets: Vec<_> = ValidQuery::execute(FindAssets, predicate, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 2);
    assert!(
        assets
            .iter()
            .all(|asset| asset.id().definition() == &rose_def_id)
    );
}
#[test]
fn find_assets_filters_by_domain_predicate() {
    let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let oasis_id: DomainId = DomainId::try_new("oasis", "universal").expect("domain id");
    let domains = [
        Domain::new(wonderland_id.clone()).build(&ALICE_ID),
        Domain::new(oasis_id.clone()).build(&ALICE_ID),
    ];
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let (dune_id, _) = iroha_test_samples::gen_account_in("oasis");
    let accounts = [
        build_account_in_domain(&ALICE_ID, &wonderland_id),
        build_account_in_domain(&bob_id, &wonderland_id),
        build_account_in_domain(&dune_id, &oasis_id),
    ];
    let rose_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let spice_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("oasis", "universal").unwrap(),
            "spice".parse().unwrap(),
        );
    let definitions = [
        {
            let __asset_definition_id = rose_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(wonderland_id.clone()),
            )
        }
        .build(&ALICE_ID),
        {
            let __asset_definition_id = spice_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "spice".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(oasis_id.clone()),
            )
        }
        .build(&ALICE_ID),
    ];
    let assets = [
        Asset::new(
            AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(5_u32),
        ),
        Asset::new(
            AssetId::new(rose_def_id.clone(), bob_id.clone()),
            Quantity::from(11_u32),
        ),
        Asset::new(
            AssetId::new(spice_def_id, dune_id.clone()),
            Quantity::from(42_u32),
        ),
    ];
    let world = World::with_assets(domains, accounts, definitions, assets, /*nfts*/ []);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let mut predicate = PredicateJson::default();
    predicate.equals.push(EqualsCondition::new(
        "domain",
        Value::String(wonderland_id.to_string()),
    ));
    let filter = predicate
        .into_compound::<Asset>()
        .expect("predicate is valid JSON");
    let assets: Vec<_> = ValidQuery::execute(FindAssets, filter, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 2);
    for asset in &assets {
        assert_eq!(asset.id().definition(), &rose_def_id);
    }
    let mut ids: Vec<_> = assets.into_iter().map(|asset| asset.id().clone()).collect();
    ids.sort();
    let mut expected = vec![
        AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
        AssetId::new(rose_def_id, bob_id),
    ];
    expected.sort();
    assert_eq!(ids, expected);
}
#[test]
fn find_assets_filters_by_definition_domain_alias_predicate() {
    let wonderland_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let oasis_id: DomainId = DomainId::try_new("oasis", "universal").expect("domain id");
    let domains = [
        Domain::new(wonderland_id.clone()).build(&ALICE_ID),
        Domain::new(oasis_id.clone()).build(&ALICE_ID),
    ];
    let (bob_id, _) = iroha_test_samples::gen_account_in("wonderland");
    let (dune_id, _) = iroha_test_samples::gen_account_in("oasis");
    let accounts = [
        build_account_in_domain(&ALICE_ID, &wonderland_id),
        build_account_in_domain(&bob_id, &wonderland_id),
        build_account_in_domain(&dune_id, &oasis_id),
    ];
    let rose_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let spice_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("oasis", "universal").unwrap(),
            "spice".parse().unwrap(),
        );
    let definitions = [
        {
            let __asset_definition_id = rose_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(wonderland_id.clone()),
            )
        }
        .build(&ALICE_ID),
        {
            let __asset_definition_id = spice_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "spice".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                Some(oasis_id.clone()),
            )
        }
        .build(&ALICE_ID),
    ];
    let assets = [
        Asset::new(
            AssetId::new(rose_def_id.clone(), ALICE_ID.clone()),
            Quantity::from(5_u32),
        ),
        Asset::new(
            AssetId::new(rose_def_id.clone(), bob_id.clone()),
            Quantity::from(11_u32),
        ),
        Asset::new(
            AssetId::new(spice_def_id, dune_id.clone()),
            Quantity::from(42_u32),
        ),
    ];
    let world = World::with_assets(domains, accounts, definitions, assets, /*nfts*/ []);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let view = state.view();
    let predicate = CompoundPredicate::<Asset>::build(|p| {
        p.equals("definition.domain", wonderland_id.to_string())
    });
    let assets: Vec<_> = ValidQuery::execute(FindAssets, predicate, &view)
        .expect("query execution succeeds")
        .collect();
    assert_eq!(assets.len(), 2);
    assert!(
        assets
            .iter()
            .all(|asset| asset.id().definition() == &rose_def_id)
    );
}
#[test]
fn nominal_asset_mutation_boundaries_reject_negative_values_and_underflow() {
    let (state, asset_definition_id, source_asset_id) = build_asset_transfer_control_test_state(10);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_testing(Hash::prehashed([0x91; Hash::LENGTH]));
    let negative = Numeric::new(-1_i32, 0);
    let destination_asset_id = AssetId::new(asset_definition_id.clone(), BOB_ID.clone());
    assert!(
        Quantity::try_from_numeric(negative).is_err(),
        "negative signed values must not cross the nominal asset boundary"
    );
    assert!(stx.world.assets.get(&destination_asset_id).is_none());
    let err = stx
        .world
        .decrease_asset_total_amount(&asset_definition_id, &Quantity::from(11_u32))
        .expect_err("quantity subtraction must not create a negative total");
    assert!(matches!(
        err,
        InstructionExecutionError::Math(MathError::NotEnoughQuantity)
    ));
    assert_eq!(
        stx.world
            .assets
            .get(&source_asset_id)
            .map(|value| value.as_ref()),
        Some(&Quantity::from(10_u32))
    );
    assert!(stx.world.assets.get(&destination_asset_id).is_none());
    assert_eq!(
        stx.world
            .asset_definition(&asset_definition_id)
            .expect("asset definition")
            .total_quantity(),
        &Quantity::from(10_u32)
    );
}
#[test]
fn asset_insert_and_totals_reject_values_outside_numeric_spec() {
    let domain_id = DomainId::try_new("integer_assets", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let alice_account = build_account_in_domain(&ALICE_ID, &domain_id);
    let definition_id =
        AssetDefinitionId::derive_from_components(domain_id, "coin".parse().expect("asset name"));
    let definition = AssetDefinition::new(
        definition_id.clone(),
        "coin".to_owned(),
        iroha_primitives::numeric::NumericSpec::integer(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let world = World::with([domain], [alice_account], [definition]);
    let state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let asset_id = AssetId::new(definition_id.clone(), ALICE_ID.clone());
    let fractional_quantity: Quantity = "0.1".parse().expect("non-negative fractional quantity");
    let err = stx
        .world
        .asset_or_insert_exact(&asset_id, fractional_quantity.clone())
        .expect_err("fractional default must violate integer asset spec");
    assert!(matches!(
        err,
        InstructionExecutionError::Evaluate(InstructionEvaluationError::Type(
            TypeError::AssetNumericSpec(_)
        ))
    ));
    let err = stx
        .world
        .increase_asset_total_amount(&definition_id, &fractional_quantity)
        .expect_err("fractional total delta must violate integer asset spec");
    assert!(matches!(
        err,
        InstructionExecutionError::Evaluate(InstructionEvaluationError::Type(
            TypeError::AssetNumericSpec(_)
        ))
    ));
    assert!(stx.world.assets.get(&asset_id).is_none());
    assert_eq!(
        stx.world
            .asset_definition(&definition_id)
            .expect("asset definition must remain present")
            .total_quantity(),
        &Quantity::zero(),
        "rejected out-of-spec values must not mutate aggregate supply"
    );
}
#[test]
fn mint_restricted_asset_uses_current_dataspace_bucket() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = build_account_in_domain(&ALICE_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        Some(domain_id.clone()),
    )
    .build(&ALICE_ID);
    let world = World::with([domain], [account], [asset_def]);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let dsid = DataSpaceId::new(7);
    stx.current_dataspace_id = Some(dsid);
    stx.world.current_dataspace_id = Some(dsid);
    let mint_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    Mint::asset_quantity(5_u32, mint_id)
        .execute(&ALICE_ID, &mut stx)
        .expect("mint must succeed in dataspace context");
    let scoped_id = AssetId::with_scope(
        asset_def_id.clone(),
        ALICE_ID.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(dsid),
    );
    assert!(
        stx.world.assets.get(&scoped_id).is_some(),
        "restricted asset must be stored under dataspace scope"
    );
    assert!(
        stx.world
            .assets
            .get(&AssetId::new(asset_def_id, ALICE_ID.clone()))
            .is_none(),
        "global bucket must stay empty for restricted assets"
    );
}
#[test]
fn mint_restricted_asset_honors_explicit_dataspace_bucket_from_universal_route() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = build_account_in_domain(&ALICE_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        Some(domain_id.clone()),
    )
    .build(&ALICE_ID);
    let world = World::with([domain], [account], [asset_def]);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let dsid = DataSpaceId::new(7);
    let scoped_id = AssetId::with_scope(
        asset_def_id.clone(),
        ALICE_ID.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(dsid),
    );
    Mint::asset_quantity(5_u32, scoped_id.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("explicit dataspace scope must be honored from the universal route");
    assert!(
        stx.world.assets.get(&scoped_id).is_some(),
        "restricted asset must be stored under the requested dataspace scope"
    );
    assert!(
        stx.world
            .assets
            .get(&AssetId::with_scope(
                asset_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
            ))
            .is_none(),
        "universal dataspace bucket must not be used for explicit private scope"
    );
}
#[test]
fn mint_restricted_asset_rejects_explicit_dataspace_bucket_mismatch() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = build_account_in_domain(&ALICE_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        Some(domain_id.clone()),
    )
    .build(&ALICE_ID);
    let world = World::with([domain], [account], [asset_def]);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    stx.current_dataspace_id = Some(DataSpaceId::new(8));
    stx.world.current_dataspace_id = Some(DataSpaceId::new(8));
    let scoped_id = AssetId::with_scope(
        asset_def_id,
        ALICE_ID.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(DataSpaceId::new(7)),
    );
    let err = Mint::asset_quantity(5_u32, scoped_id)
        .execute(&ALICE_ID, &mut stx)
        .expect_err("private routes must reject explicit foreign dataspace scopes");
    match err {
        InstructionExecutionError::InvariantViolation(message) => {
            assert!(
                message.contains("cannot move across dataspaces"),
                "unexpected invariant message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn mint_global_asset_rejects_non_authoritative_dataspace_route() {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let account = build_account_in_domain(&ALICE_ID, &domain_id);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let world = World::with([domain], [account], [asset_def]);
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let private_dataspace = DataSpaceId::new(7);
    stx.current_dataspace_id = Some(private_dataspace);
    stx.world.current_dataspace_id = Some(private_dataspace);
    let mint_id = AssetId::new(asset_def_id, ALICE_ID.clone());
    let err = Mint::asset_quantity(5_u32, mint_id)
        .execute(&ALICE_ID, &mut stx)
        .expect_err("global asset writes must use the authoritative route");
    match err {
        InstructionExecutionError::InvariantViolation(message) => {
            assert!(
                message.contains("authoritative dataspace"),
                "unexpected invariant message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn prepared_movement_records_exact_delta_under_current_apply_context() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition.clone(), BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 7, 0);
    let mut block = state.block(header);
    let hash = iroha_crypto::Hash::new(b"identity at movement apply");
    block.admit_fastpq_source_for_testing(hash);
    {
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x70; Hash::LENGTH]));
        super::super::isi::apply_prepared_numeric_movement_for_test(
            &mut tx,
            &ALICE_ID,
            source.clone(),
            destination.clone(),
            Quantity::from(3_u32),
            |tx| {
                tx.tx_call_hash = Some(hash);
                tx.current_lane_id = Some(iroha_model_base::topology::LaneId::SINGLE);
                tx.current_dataspace_id = Some(iroha_model_base::topology::DataSpaceId::new(7));
            },
            true,
        )
        .unwrap();
        assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(7_u32));
        assert_eq!(
            asset_balance_or_zero(&tx, &destination),
            Quantity::from(3_u32)
        );
        tx.apply();
    }
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 1);
    let transcript = &transcripts[&hash][0];
    let expected = iroha_data_model::fastpq::TransferDeltaTranscript {
        from_account: ALICE_ID.clone(),
        to_account: BOB_ID.clone(),
        asset_definition: definition,
        amount: Quantity::from(3_u32),
        from_balance_before: Quantity::from(10_u32),
        from_balance_after: Quantity::from(7_u32),
        to_balance_before: Quantity::zero(),
        to_balance_after: Quantity::from(3_u32),
        from_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
        to_smt_witness: iroha_data_model::fastpq::TransferSmtWitness::default(),
    };
    assert_eq!(transcript.deltas, vec![expected.clone()]);
    assert_eq!(
        transcript.authority_digest,
        crate::fastpq::authority_digest(&ALICE_ID)
    );
    assert_eq!(
        transcript.poseidon_preimage_digest,
        Some(crate::fastpq::poseidon_preimage_digest(&expected, &hash))
    );
    let capture = block.captured_fastpq_transcript_sources().unwrap()[&hash];
    assert_eq!(
        capture.dataspace_id(),
        iroha_model_base::topology::DataSpaceId::new(7)
    );
    assert!(!capture.is_protocol_purpose());
}

#[test]
fn prepared_movement_preserves_direct_typed_purpose_identity() {
    let _suppression = crate::exec_witness::suppress_recording_for_current_thread();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 7, 0);
    let mut block = state.block(header);
    let hash;
    {
        let mut tx = block.transaction_for_fastpq_protocol_testing();
        assert!(tx.tx_call_hash.is_none());
        hash = super::super::isi::resolve_social_send_movement_identity_for_test(
            &tx,
            &ALICE_ID,
            &[(source.clone(), destination.clone(), Quantity::from(3_u32))],
            vec![0x71],
        )
        .unwrap();
        super::super::isi::apply_prepared_numeric_movement_for_test(
            &mut tx,
            &ALICE_ID,
            source,
            destination,
            Quantity::from(3_u32),
            |_| {},
            true,
        )
        .unwrap();
        tx.apply();
    }
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert_eq!(transcripts[&hash].len(), 1);
    assert_eq!(transcripts[&hash][0].batch_hash, hash);
    assert!(block.captured_fastpq_transcript_sources().unwrap()[&hash].is_protocol_purpose());
}

#[test]
fn stale_prepared_movement_discards_its_prepared_occurrence() {
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 7, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x72; Hash::LENGTH]));
    let error = super::super::isi::apply_prepared_numeric_movement_for_test(
        &mut tx,
        &ALICE_ID,
        source.clone(),
        destination.clone(),
        Quantity::from(3_u32),
        |tx| **tx.world.assets.get_mut(&source).unwrap() = Quantity::from(11_u32),
        true,
    )
    .unwrap_err();
    assert!(error.to_string().contains("source balance changed"));
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(11_u32));
    assert_eq!(asset_balance_or_zero(&tx, &destination), Quantity::zero());
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    tx.apply();
    assert!(block.drain_transfer_transcripts().is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::exec_witness::drain_exec_witness()
            .fastpq_transcripts
            .is_empty()
    );
}

#[test]
fn suppressed_prepared_movement_keeps_events_without_source_occurrence() {
    let _guard = crate::exec_witness::exec_witness_guard();
    crate::exec_witness::start_block();
    let (state, definition, source) = build_asset_transfer_control_test_state(10);
    let destination = AssetId::new(definition, BOB_ID.clone());
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 7, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    super::super::isi::apply_prepared_numeric_movement_for_test(
        &mut tx,
        &ALICE_ID,
        source.clone(),
        destination.clone(),
        Quantity::from(3_u32),
        |_| {},
        false,
    )
    .unwrap();
    assert_eq!(asset_balance_or_zero(&tx, &source), Quantity::from(7_u32));
    assert_eq!(
        asset_balance_or_zero(&tx, &destination),
        Quantity::from(3_u32)
    );
    assert!(
        tx.world
            .internal_event_buf
            .iter()
            .any(|event| matches!(event.as_ref(),
                DataEvent::Asset(AssetEvent::Transferred(transfer))
                    if transfer.source() == &source && transfer.destination() == &destination
                        && transfer.amount() == &Quantity::from(3_u32)
            ))
    );
    assert_eq!(tx.pending_transfer_transcript_count_for_testing(), 0);
    tx.apply();
    assert!(block.drain_transfer_transcripts().is_empty());
    assert!(
        block
            .captured_fastpq_transcript_sources()
            .unwrap()
            .is_empty()
    );
    assert!(
        crate::exec_witness::drain_exec_witness()
            .fastpq_transcripts
            .is_empty()
    );
}
