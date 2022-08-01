#![allow(clippy::restriction, clippy::pedantic)]

use std::str::FromStr as _;

use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn correct_pagination_assets_after_creating_new_one() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();

    let sort_by_metadata_key = Name::from_str("sort").expect("Valid");

    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");

    let mut assets = vec![];
    let mut instructions: Vec<Instruction> = vec![];

    for i in 0..10 {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor{}#wonderland", i)).expect("Valid");
        let asset_definition = AssetDefinition::store(asset_definition_id.clone());
        let mut asset_metadata = Metadata::new();
        asset_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                Value::U128(i),
                MetadataLimits::new(10, 22),
            )
            .expect("Valid");
        let asset = Asset::new(
            AssetId::new(asset_definition_id, account_id.clone()),
            AssetValue::Store(asset_metadata),
        );

        assets.push(asset.clone());

        let create_asset_definition = RegisterBox::new(asset_definition);
        let create_asset = RegisterBox::new(asset);

        instructions.push(create_asset_definition.into());
        instructions.push(create_asset.into());
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let sorting = Sorting::by_metadata_key(sort_by_metadata_key.clone());

    let res = test_client
        .request_with_pagination_and_sorting(
            client::asset::by_account_id(account_id.clone()),
            Pagination::new(Some(1), Some(5)),
            sorting.clone(),
        )
        .expect("Valid");

    assert_eq!(
        res.output
            .iter()
            .map(|asset| asset.id().definition_id.name.clone())
            .collect::<Vec<_>>(),
        assets
            .iter()
            .take(5)
            .map(|asset| asset.id().definition_id.name.clone())
            .collect::<Vec<_>>()
    );

    let new_asset_definition_id = AssetDefinitionId::from_str("xor10#wonderland").expect("Valid");
    let new_asset_definition = AssetDefinition::store(new_asset_definition_id.clone());
    let mut new_asset_metadata = Metadata::new();
    new_asset_metadata
        .insert_with_limits(
            sort_by_metadata_key,
            Value::U128(10),
            MetadataLimits::new(10, 22),
        )
        .expect("Valid");
    let new_asset = Asset::new(
        AssetId::new(new_asset_definition_id, account_id.clone()),
        AssetValue::Store(new_asset_metadata),
    );

    let create_asset_definition = RegisterBox::new(new_asset_definition);
    let create_asset = RegisterBox::new(new_asset.clone());

    test_client
        .submit_all_blocking(vec![create_asset_definition.into(), create_asset.into()])
        .expect("Valid");

    let res = test_client
        .request_with_pagination_and_sorting(
            client::asset::by_account_id(account_id),
            Pagination::new(Some(6), None),
            sorting,
        )
        .expect("Valid");

    let mut right = assets.into_iter().skip(5).take(5).collect::<Vec<_>>();

    right.push(new_asset);

    assert_eq!(
        res.output
            .into_iter()
            .map(|asset| asset.id().definition_id.name.clone())
            .collect::<Vec<_>>(),
        right
            .into_iter()
            .map(|asset| asset.id().definition_id.name.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn correct_sorting_of_asset_definitions() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();

    let sort_by_metadata_key = Name::from_str("test_sort").expect("Valid");

    // Test sorting asset definitions

    let mut asset_definitions = vec![];
    let mut instructions: Vec<Instruction> = vec![];

    for i in 0..10 {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor{}#wonderland", i)).expect("Valid");
        let mut asset_metadata = Metadata::new();
        asset_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                Value::U128(i),
                MetadataLimits::new(10, 27),
            )
            .expect("Valid");
        let asset_definition =
            AssetDefinition::quantity(asset_definition_id.clone()).with_metadata(asset_metadata);

        asset_definitions.push(asset_definition.clone());

        let create_asset_definition = RegisterBox::new(asset_definition);
        instructions.push(create_asset_definition.into());
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    asset_definitions.sort_by_key(|definition| {
        definition
            .metadata()
            .get(&sort_by_metadata_key)
            .unwrap()
            .clone()
    });

    let res = test_client
        .request_with_sorting(
            client::asset::all_definitions(),
            Sorting::by_metadata_key(sort_by_metadata_key.clone()),
        )
        .expect("Valid");

    assert_eq!(
        // skip rose and tulip
        res.output.into_iter().skip(2).collect::<Vec<_>>(),
        asset_definitions
            .into_iter()
            .map(Registrable::build)
            .collect::<Vec<_>>()
    );

    // Test sorting accounts

    let mut accounts = vec![];
    let mut instructions = vec![];

    for i in 0..10 {
        let account_id = AccountId::from_str(&format!("bob{}@wonderland", i)).expect("Valid");
        let mut account_metadata = Metadata::new();
        account_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                Value::U128(i),
                MetadataLimits::new(10, 27),
            )
            .expect("Valid");
        let account = Account::new(account_id, []).with_metadata(account_metadata);

        accounts.push(account.clone().build());

        let create_account = RegisterBox::new(account);
        instructions.push(create_account.into());
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    accounts.sort_by_key(|account| {
        account
            .metadata()
            .get(&sort_by_metadata_key)
            .unwrap()
            .clone()
    });

    let res = test_client
        .request_with_sorting(
            client::account::all(),
            Sorting::by_metadata_key(sort_by_metadata_key.clone()),
        )
        .expect("Valid");

    let alice_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let genesis_id = AccountId::from_str("genesis@genesis").expect("Valid");

    assert_eq!(
        res.output
            .into_iter()
            .map(|acc| acc.id().clone())
            .filter(|id| id != &alice_id && id != &genesis_id)
            .collect::<Vec<_>>(),
        accounts
            .into_iter()
            .map(|acc| acc.id().clone())
            .collect::<Vec<_>>()
    );

    // Test sorting domains

    let mut domains = vec![];
    let mut instructions = vec![];

    for i in 0..10 {
        let domain_id = DomainId::from_str(&format!("neverland{}", i)).expect("Valid");
        let mut domain_metadata = Metadata::new();
        domain_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                Value::U128(i),
                MetadataLimits::new(10, 27),
            )
            .expect("Valid");
        let domain = Domain::new(domain_id).with_metadata(domain_metadata);

        domains.push(domain.clone().build());

        let create_account = RegisterBox::new(domain);
        instructions.push(create_account.into());
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    domains.sort_by_key(|account| {
        account
            .metadata()
            .get(&sort_by_metadata_key)
            .unwrap()
            .clone()
    });

    let res = test_client
        .request_with_sorting(
            client::domain::all(),
            Sorting::by_metadata_key(sort_by_metadata_key),
        )
        .expect("Valid");

    let genesis_id = DomainId::from_str("genesis").expect("Valid");
    let wonderland_id = DomainId::from_str("wonderland").expect("Valid");

    assert_eq!(
        res.output
            .into_iter()
            .filter(|domain| domain.id() != &wonderland_id && domain.id() != &genesis_id)
            .collect::<Vec<_>>(),
        domains
    );
}
