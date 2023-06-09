#![allow(clippy::restriction, clippy::pedantic)]

use std::{collections::HashSet, str::FromStr as _};

use eyre::{Result, WrapErr as _};
use iroha_client::client;
use iroha_data_model::{
    predicate::{string, value, PredicateBox},
    prelude::*,
};
use test_network::*;

#[test]
fn correct_pagination_assets_after_creating_new_one() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_635).start_with_runtime();

    let sort_by_metadata_key = Name::from_str("sort").expect("Valid");

    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");

    let mut assets = vec![];
    let mut instructions = vec![];

    for i in 0..10_u128 {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor{i}#wonderland")).expect("Valid");
        let asset_definition = AssetDefinition::store(asset_definition_id.clone());
        let mut asset_metadata = Metadata::new();
        asset_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                i.to_value(),
                MetadataLimits::new(10, 23),
            )
            .expect("Valid");
        let asset = Asset::new(
            AssetId::new(asset_definition_id, account_id.clone()),
            AssetValue::Store(asset_metadata),
        );

        assets.push(asset.clone());

        let create_asset_definition = RegisterBox::new(asset_definition);
        let create_asset = RegisterBox::new(asset);

        instructions.push(create_asset_definition);
        instructions.push(create_asset);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let sorting = Sorting::by_metadata_key(sort_by_metadata_key.clone());

    let res = test_client
        .request_with_pagination_and_sorting(
            client::asset::by_account_id(account_id.clone()),
            Pagination::new(None, Some(5)),
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
            10_u128.to_value(),
            MetadataLimits::new(10, 23),
        )
        .expect("Valid");
    let new_asset = Asset::new(
        AssetId::new(new_asset_definition_id, account_id.clone()),
        AssetValue::Store(new_asset_metadata),
    );

    let create_asset_definition = RegisterBox::new(new_asset_definition);
    let create_asset = RegisterBox::new(new_asset.clone());

    test_client
        .submit_all_blocking([create_asset_definition, create_asset])
        .expect("Valid");

    let res = test_client
        .request_with_pagination_and_sorting(
            client::asset::by_account_id(account_id),
            Pagination::new(Some(5), Some(6)),
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
fn correct_sorting_of_entities() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_640).start_with_runtime();

    let sort_by_metadata_key = Name::from_str("test_sort").expect("Valid");

    // Test sorting asset definitions

    let mut asset_definitions = vec![];
    let mut assets_metadata = vec![];
    let mut instructions = vec![];
    let n = 10u128;
    for i in 0..n {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor_{i}#wonderland")).expect("Valid");
        let mut asset_metadata = Metadata::new();
        asset_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                (n - i - 1).to_value(),
                MetadataLimits::new(10, 28),
            )
            .expect("Valid");
        let asset_definition = AssetDefinition::quantity(asset_definition_id.clone())
            .with_metadata(asset_metadata.clone());

        assets_metadata.push(asset_metadata);
        asset_definitions.push(asset_definition_id);

        let create_asset_definition = RegisterBox::new(asset_definition);
        instructions.push(create_asset_definition);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .request_with_sorting_and_filter(
            client::asset::all_definitions(),
            Sorting::by_metadata_key(sort_by_metadata_key.clone()),
            PredicateBox::new(value::ValuePredicate::Identifiable(
                string::StringPredicate::starts_with("xor_"),
            )),
        )
        .expect("Valid");

    assert!(res
        .output
        .iter()
        .map(Identifiable::id)
        .eq(asset_definitions.iter().rev()));
    assert!(res
        .output
        .iter()
        .map(|asset_definition| asset_definition.metadata())
        .eq(assets_metadata.iter().rev()));

    // Test sorting accounts

    let mut accounts = vec![];
    let mut accounts_metadata = vec![];
    let mut instructions = vec![];

    let n = 10u32;
    for i in 0..n {
        let account_id = AccountId::from_str(&format!("charlie{i}@wonderland")).expect("Valid");
        let mut account_metadata = Metadata::new();
        account_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                (n - i - 1).to_value(),
                MetadataLimits::new(10, 28),
            )
            .expect("Valid");
        let account = Account::new(account_id.clone(), []).with_metadata(account_metadata.clone());

        accounts.push(account_id);
        accounts_metadata.push(account_metadata);

        let create_account = RegisterBox::new(account);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .request_with_sorting_and_filter(
            client::account::all(),
            Sorting::by_metadata_key(sort_by_metadata_key.clone()),
            PredicateBox::new(value::ValuePredicate::Identifiable(
                string::StringPredicate::starts_with("charlie"),
            )),
        )
        .expect("Valid");

    assert!(res
        .output
        .iter()
        .map(Identifiable::id)
        .eq(accounts.iter().rev()));
    assert!(res
        .output
        .iter()
        .map(|account| account.metadata())
        .eq(accounts_metadata.iter().rev()));

    // Test sorting domains

    let mut domains = vec![];
    let mut domains_metadata = vec![];
    let mut instructions = vec![];
    let n = 10u32;
    for i in 0..n {
        let domain_id = DomainId::from_str(&format!("neverland{i}")).expect("Valid");
        let mut domain_metadata = Metadata::new();
        domain_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                (n - i - 1).to_value(),
                MetadataLimits::new(10, 28),
            )
            .expect("Valid");
        let domain = Domain::new(domain_id.clone()).with_metadata(domain_metadata.clone());

        domains.push(domain_id);
        domains_metadata.push(domain_metadata);

        let create_account = RegisterBox::new(domain);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .request_with_pagination_and_filter_and_sorting(
            client::domain::all(),
            Pagination::default(),
            Sorting::by_metadata_key(sort_by_metadata_key.clone()),
            PredicateBox::new(value::ValuePredicate::Identifiable(
                string::StringPredicate::starts_with("neverland"),
            )),
        )
        .expect("Valid");

    assert!(res
        .output
        .iter()
        .map(Identifiable::id)
        .eq(domains.iter().rev()));
    assert!(res
        .output
        .iter()
        .map(|domain| domain.metadata())
        .eq(domains_metadata.iter().rev()));

    // Naive test sorting of domains
    let input = [(0i32, 1u128), (2, 0), (1, 2)];
    let mut domains = vec![];
    let mut domains_metadata = vec![];
    let mut instructions = vec![];
    for (idx, val) in input {
        let domain_id = DomainId::from_str(&format!("neverland_{idx}")).expect("Valid");
        let mut domain_metadata = Metadata::new();
        domain_metadata
            .insert_with_limits(
                sort_by_metadata_key.clone(),
                val.to_value(),
                MetadataLimits::new(10, 28),
            )
            .expect("Valid");
        let domain = Domain::new(domain_id.clone()).with_metadata(domain_metadata.clone());

        domains.push(domain_id);
        domains_metadata.push(domain_metadata);

        let create_account = RegisterBox::new(domain);
        instructions.push(create_account);
    }
    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let filter = PredicateBox::new(value::ValuePredicate::Identifiable(
        string::StringPredicate::starts_with("neverland_"),
    ));
    let res = test_client
        .request_with_pagination_and_filter_and_sorting(
            client::domain::all(),
            Pagination::default(),
            Sorting::by_metadata_key(sort_by_metadata_key),
            filter,
        )
        .expect("Valid");

    assert_eq!(res.output[0].id(), &domains[1]);
    assert_eq!(res.output[1].id(), &domains[0]);
    assert_eq!(res.output[2].id(), &domains[2]);
    assert_eq!(res.output[0].metadata(), &domains_metadata[1]);
    assert_eq!(res.output[1].metadata(), &domains_metadata[0]);
    assert_eq!(res.output[2].metadata(), &domains_metadata[2]);
}

#[test]
fn sort_only_elements_which_have_sorting_key() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_680).start_with_runtime();

    let sort_by_metadata_key = Name::from_str("test_sort").expect("Valid");

    let mut accounts_a = vec![];
    let mut accounts_b = vec![];
    let mut instructions = vec![];

    let mut skip_set = HashSet::new();
    skip_set.insert(4);
    skip_set.insert(7);

    let n = 10u32;
    for i in 0..n {
        let account_id = AccountId::from_str(&format!("charlie{i}@wonderland")).expect("Valid");
        let account = if !skip_set.contains(&i) {
            let mut account_metadata = Metadata::new();
            account_metadata
                .insert_with_limits(
                    sort_by_metadata_key.clone(),
                    (n - i - 1).to_value(),
                    MetadataLimits::new(10, 28),
                )
                .expect("Valid");
            let account = Account::new(account_id.clone(), []).with_metadata(account_metadata);
            accounts_a.push(account_id);
            account
        } else {
            let account = Account::new(account_id.clone(), []);
            accounts_b.push(account_id);
            account
        };

        let create_account = RegisterBox::new(account);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .wrap_err("Failed to register accounts")?;

    let res = test_client
        .request_with_sorting_and_filter(
            client::account::all(),
            Sorting::by_metadata_key(sort_by_metadata_key),
            PredicateBox::new(value::ValuePredicate::Identifiable(
                string::StringPredicate::starts_with("charlie"),
            )),
        )
        .wrap_err("Failed to submit request")?;

    let accounts = accounts_a.into_iter().rev().chain(accounts_b.into_iter());
    assert!(res
        .output
        .iter()
        .map(Identifiable::id)
        .cloned()
        .eq(accounts));

    Ok(())
}
