//! Validates that aggregate asset totals stay aligned with per-account balances.

use core::num::NonZeroU64;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::{Execute, ValidQuery},
    state::{State, World},
};
use iroha_data_model::{prelude::*, query::dsl::CompoundPredicate};
use iroha_model_base::domain::DomainId;
use iroha_primitives::numeric::Quantity;
use iroha_test_samples::{ALICE_ID, gen_account_in};
#[test]
#[allow(clippy::too_many_lines)]
fn asset_totals_track_multi_account_mint_and_burn() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut state_block = state.block(header);
    let mut stx = state_block.transaction();
    let wonderland: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    let looking_glass: DomainId = DomainId::try_new("looking_glass", "universal").expect("domain");
    Register::domain(Domain::new(wonderland.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register wonderland");
    Register::domain(Domain::new(looking_glass.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register looking_glass");
    let (holder_wonderland, _kp_a) = gen_account_in("wonderland");
    let (holder_looking_glass, _kp_b) = gen_account_in("looking_glass");
    let (burn_to_zero, _kp_c) = gen_account_in("looking_glass");
    for (account_id, _domain_id) in [
        (holder_wonderland.clone(), wonderland.clone()),
        (holder_looking_glass.clone(), looking_glass.clone()),
        (burn_to_zero.clone(), looking_glass.clone()),
    ] {
        Register::account(Account::new(account_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register account");
    }
    let definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "multi_total".parse().unwrap(),
        );
    Register::asset_definition(AssetDefinition::numeric(
        definition_id.clone(),
        "multi_total".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(wonderland.clone()),
    ))
    .execute(&ALICE_ID, &mut stx)
    .expect("register asset definition");
    Mint::asset_quantity(
        50_u32,
        AssetId::new(definition_id.clone(), holder_wonderland.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("mint wonderland holder");
    Mint::asset_quantity(
        40_u32,
        AssetId::new(definition_id.clone(), holder_looking_glass.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("mint looking glass holder");
    Mint::asset_quantity(
        10_u32,
        AssetId::new(definition_id.clone(), burn_to_zero.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("mint burn-to-zero holder");
    Burn::asset_quantity(
        15_u32,
        AssetId::new(definition_id.clone(), holder_wonderland.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("partial burn from wonderland holder");
    Burn::asset_quantity(
        5_u32,
        AssetId::new(definition_id.clone(), holder_looking_glass.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("partial burn from looking glass holder");
    Burn::asset_quantity(
        10_u32,
        AssetId::new(definition_id.clone(), burn_to_zero.clone()),
    )
    .execute(&ALICE_ID, &mut stx)
    .expect("burn to zero");
    stx.apply();
    state_block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let definition = FindAssetDefinitions::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query asset definitions")
        .find(|definition| definition.id() == &definition_id)
        .expect("definition present");
    let definition_total = definition.total_quantity();
    let mut manual_total = Quantity::zero();
    for asset in FindAssets::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query assets")
        .filter(|asset| asset.id().definition() == &definition_id)
    {
        manual_total = manual_total
            .checked_add(asset.value())
            .expect("manual total should not overflow");
    }
    assert_eq!(manual_total, definition_total.clone());
    assert_eq!(manual_total, Quantity::from(70_u32));
}
#[test]
fn asset_totals_drop_when_unregistering_account() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query_handle);
    let header_1 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_1 = state.block(header_1);
    let mut stx_1 = block_1.transaction();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain");
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register domain");
    let (holder, _holder_key) = gen_account_in("wonderland");
    Register::account(Account::new(holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register holder");
    let definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "account_drop".parse().unwrap(),
        );
    Register::asset_definition(AssetDefinition::numeric(
        definition_id.clone(),
        "account_drop".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(domain_id.clone()),
    ))
    .execute(&ALICE_ID, &mut stx_1)
    .expect("register definition");
    Mint::asset_quantity(25_u32, AssetId::new(definition_id.clone(), holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("mint holder balance");
    stx_1.apply();
    block_1
        .commit_world_overlay_for_testing()
        .expect("commit block 1");
    let header_2 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_2 = state.block(header_2);
    let mut stx_2 = block_2.transaction();
    Unregister::account(holder.clone())
        .execute(&ALICE_ID, &mut stx_2)
        .expect("unregister account");
    stx_2.apply();
    block_2
        .commit_world_overlay_for_testing()
        .expect("commit block 2");
    let view = state.view();
    let definition = FindAssetDefinitions::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query definitions")
        .find(|candidate| candidate.id() == &definition_id)
        .expect("definition remains after account removal");
    assert_eq!(definition.total_quantity(), &Quantity::zero());
    let manual_total = FindAssets::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query assets")
        .filter(|asset| asset.id().definition() == &definition_id)
        .fold(Quantity::zero(), |acc, asset| {
            acc.checked_add(asset.value())
                .expect("manual total should not overflow")
        });
    assert_eq!(manual_total, Quantity::zero());
}
#[test]
fn asset_totals_preserve_when_unregistering_domain_with_foreign_holders() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query_handle);
    let header_1 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_1 = state.block(header_1);
    let mut stx_1 = block_1.transaction();
    let source_domain: DomainId = DomainId::try_new("source", "universal").expect("domain");
    let foreign_domain: DomainId = DomainId::try_new("foreign", "universal").expect("domain");
    Register::domain(Domain::new(source_domain.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register source domain");
    Register::domain(Domain::new(foreign_domain.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register foreign domain");
    let (source_holder, _source_key) = gen_account_in("source");
    let (foreign_holder, _foreign_key) = gen_account_in("foreign");
    Register::account(Account::new(source_holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register source holder");
    Register::account(Account::new(foreign_holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register foreign holder");
    let definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("source", "universal").unwrap(),
            "domain_drop".parse().unwrap(),
        );
    Register::asset_definition(AssetDefinition::numeric(
        definition_id.clone(),
        "domain_drop".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(source_domain.clone()),
    ))
    .execute(&ALICE_ID, &mut stx_1)
    .expect("register source definition");
    Mint::asset_quantity(
        7_u32,
        AssetId::new(definition_id.clone(), source_holder.clone()),
    )
    .execute(&ALICE_ID, &mut stx_1)
    .expect("mint source holder");
    Mint::asset_quantity(
        33_u32,
        AssetId::new(definition_id.clone(), foreign_holder.clone()),
    )
    .execute(&ALICE_ID, &mut stx_1)
    .expect("mint foreign holder");
    stx_1.apply();
    block_1
        .commit_world_overlay_for_testing()
        .expect("commit block 1");
    let header_2 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_2 = state.block(header_2);
    let mut stx_2 = block_2.transaction();
    Unregister::domain(foreign_domain.clone())
        .execute(&ALICE_ID, &mut stx_2)
        .expect("unregister foreign domain");
    stx_2.apply();
    block_2
        .commit_world_overlay_for_testing()
        .expect("commit block 2");
    let view = state.view();
    let definition = FindAssetDefinitions::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query definitions")
        .find(|candidate| candidate.id() == &definition_id)
        .expect("source definition should remain");
    assert_eq!(definition.owning_domain(), &Some(source_domain));
    assert_eq!(definition.total_quantity(), &Quantity::from(40_u32));
    let manual_total = FindAssets::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query assets")
        .filter(|asset| asset.id().definition() == &definition_id)
        .fold(Quantity::zero(), |acc, asset| {
            acc.checked_add(asset.value())
                .expect("manual total should not overflow")
        });
    assert_eq!(manual_total, Quantity::from(40_u32));
    assert!(
        FindAccounts::new()
            .execute(CompoundPredicate::PASS, &view)
            .expect("query accounts")
            .any(|account| account.id() == &foreign_holder),
        "foreign subject should remain after domain removal"
    );
}
#[test]
fn unregistering_definition_domain_cleans_foreign_assets() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(World::default(), kura, query_handle);
    let header_1 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_1 = state.block(header_1);
    let mut stx_1 = block_1.transaction();
    let source_domain: DomainId = DomainId::try_new("source", "universal").expect("domain");
    let foreign_domain: DomainId = DomainId::try_new("foreign", "universal").expect("domain");
    Register::domain(Domain::new(source_domain.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register source domain");
    Register::domain(Domain::new(foreign_domain.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register foreign domain");
    let (source_holder, _source_key) = gen_account_in("source");
    let (foreign_holder, _foreign_key) = gen_account_in("foreign");
    Register::account(Account::new(source_holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register source holder");
    Register::account(Account::new(foreign_holder.clone()))
        .execute(&ALICE_ID, &mut stx_1)
        .expect("register foreign holder");
    let definition_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("source", "universal").unwrap(),
            "teardown".parse().unwrap(),
        );
    Register::asset_definition(AssetDefinition::numeric(
        definition_id.clone(),
        "teardown".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        Some(source_domain.clone()),
    ))
    .execute(&ALICE_ID, &mut stx_1)
    .expect("register source definition");
    Mint::asset_quantity(
        4_u32,
        AssetId::new(definition_id.clone(), source_holder.clone()),
    )
    .execute(&ALICE_ID, &mut stx_1)
    .expect("mint source holder");
    Mint::asset_quantity(
        11_u32,
        AssetId::new(definition_id.clone(), foreign_holder.clone()),
    )
    .execute(&ALICE_ID, &mut stx_1)
    .expect("mint foreign holder");
    stx_1.apply();
    block_1
        .commit_world_overlay_for_testing()
        .expect("commit block 1");
    let header_2 = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("non-zero"),
        None,
        None,
        0,
        0,
    );
    let mut block_2 = state.block(header_2);
    let mut stx_2 = block_2.transaction();
    Unregister::domain(source_domain.clone())
        .execute(&ALICE_ID, &mut stx_2)
        .expect("unregister source domain");
    stx_2.apply();
    block_2
        .commit_world_overlay_for_testing()
        .expect("commit block 2");
    let view = state.view();
    assert!(
        FindAssetDefinitions::new()
            .execute(CompoundPredicate::PASS, &view)
            .expect("query definitions")
            .all(|definition| definition.id() != &definition_id),
        "definition should be removed with its domain"
    );
    assert!(
        FindAssets::new()
            .execute(CompoundPredicate::PASS, &view)
            .expect("query assets")
            .all(|asset| asset.id().definition() != &definition_id),
        "all assets from removed definition should be cleaned across domains"
    );
    let surviving_accounts: Vec<_> = FindAccounts::new()
        .execute(CompoundPredicate::PASS, &view)
        .expect("query accounts")
        .map(|account| account.id().clone())
        .collect();
    for holder in [source_holder, foreign_holder] {
        assert!(
            surviving_accounts.contains(&holder),
            "universal accounts must survive removal of an asset's owning domain"
        );
    }
    assert!(
        FindDomains::new()
            .execute(CompoundPredicate::PASS, &view)
            .expect("query domains")
            .any(|domain| domain.id() == &foreign_domain),
        "the unrelated domain must remain after source domain removal"
    );
}
