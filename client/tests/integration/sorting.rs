use std::{collections::HashSet, str::FromStr as _};

use eyre::{Result, WrapErr as _};
use iroha::{
    client::{self, QueryResult},
    crypto::KeyPair,
    data_model::{account::Account, prelude::*},
};
use iroha_data_model::query::predicate::predicate_atoms::asset::AssetPredicateBox;
use nonzero_ext::nonzero;
use rand::{seq::SliceRandom, thread_rng};
use test_network::*;
use test_samples::ALICE_ID;

#[test]
#[ignore]
#[allow(clippy::cast_possible_truncation)]
fn correct_pagination_assets_after_creating_new_one() {
    // FIXME transaction is rejected for more than a certain number of instructions
    const N_ASSETS: usize = 12;
    // 0 < pagination.start < missing_idx < pagination.end < N_ASSETS
    let missing_indices = vec![N_ASSETS / 2];
    let pagination = Pagination {
        limit: Some(nonzero!(N_ASSETS as u64 / 3)),
        offset: N_ASSETS as u64 / 3,
    };
    let xor_filter =
        AssetPredicateBox::build(|asset| asset.id.definition_id.name.starts_with("xor"));

    let sort_by_metadata_key = Name::from_str("sort").expect("Valid");
    let sorting = Sorting::by_metadata_key(sort_by_metadata_key.clone());
    let account_id = ALICE_ID.clone();

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_635).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let mut tester_assets = vec![];
    let mut register_asset_definitions = vec![];
    let mut register_assets = vec![];

    let mut missing_tester_assets = vec![];
    let mut missing_register_asset_definitions = vec![];
    let mut missing_register_assets = vec![];

    for i in 0..N_ASSETS {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor{i}#wonderland")).expect("Valid");
        let asset_definition = AssetDefinition::store(asset_definition_id.clone());
        let mut asset_metadata = Metadata::default();
        asset_metadata.insert(sort_by_metadata_key.clone(), i as u32);
        let asset = Asset::new(
            AssetId::new(asset_definition_id, account_id.clone()),
            AssetValue::Store(asset_metadata),
        );

        if missing_indices.contains(&i) {
            missing_tester_assets.push(asset.clone());
            missing_register_asset_definitions.push(Register::asset_definition(asset_definition));
            missing_register_assets.push(Register::asset(asset));
        } else {
            tester_assets.push(asset.clone());
            register_asset_definitions.push(Register::asset_definition(asset_definition));
            register_assets.push(Register::asset(asset));
        }
    }
    register_asset_definitions.shuffle(&mut thread_rng());
    register_assets.shuffle(&mut thread_rng());

    test_client
        .submit_all_blocking(register_asset_definitions)
        .expect("Valid");
    test_client
        .submit_all_blocking(register_assets)
        .expect("Valid");

    let queried_assets = test_client
        .query(client::asset::all())
        .filter(xor_filter.clone())
        .with_pagination(pagination)
        .with_sorting(sorting.clone())
        .execute_all()
        .expect("Valid");

    tester_assets
        .iter()
        .skip(N_ASSETS / 3)
        .take(N_ASSETS / 3)
        .zip(queried_assets)
        .for_each(|(tester, queried)| assert_eq!(*tester, queried));

    for (i, missing_idx) in missing_indices.into_iter().enumerate() {
        tester_assets.insert(missing_idx, missing_tester_assets[i].clone());
    }
    test_client
        .submit_all_blocking(missing_register_asset_definitions)
        .expect("Valid");
    test_client
        .submit_all_blocking(missing_register_assets)
        .expect("Valid");

    let queried_assets = test_client
        .query(client::asset::all())
        .filter(xor_filter)
        .with_pagination(pagination)
        .with_sorting(sorting)
        .execute_all()
        .expect("Valid");

    tester_assets
        .iter()
        .skip(N_ASSETS / 3)
        .take(N_ASSETS / 3)
        .zip(queried_assets)
        .for_each(|(tester, queried)| assert_eq!(*tester, queried));
}

#[test]
#[allow(clippy::too_many_lines)]
fn correct_sorting_of_entities() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_640).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let sort_by_metadata_key = Name::from_str("test_sort").expect("Valid");

    // Test sorting asset definitions

    let mut asset_definitions = vec![];
    let mut metadata_of_assets = vec![];
    let mut instructions = vec![];
    let n = 10_u32;
    for i in 0..n {
        let asset_definition_id =
            AssetDefinitionId::from_str(&format!("xor_{i}#wonderland")).expect("Valid");
        let mut asset_metadata = Metadata::default();
        asset_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let asset_definition = AssetDefinition::numeric(asset_definition_id.clone())
            .with_metadata(asset_metadata.clone());

        metadata_of_assets.push(asset_metadata);
        asset_definitions.push(asset_definition_id);

        let create_asset_definition = Register::asset_definition(asset_definition);
        instructions.push(create_asset_definition);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .query(client::asset::all_definitions())
        .with_sorting(Sorting::by_metadata_key(sort_by_metadata_key.clone()))
        .filter_with(|asset_definition| asset_definition.id.name.starts_with("xor_"))
        .execute_all()
        .expect("Valid");

    assert!(res
        .iter()
        .map(Identifiable::id)
        .eq(asset_definitions.iter().rev()));
    assert!(res
        .iter()
        .map(AssetDefinition::metadata)
        .eq(metadata_of_assets.iter().rev()));

    // Test sorting accounts

    let domain_name = "_neverland";
    let domain_id: DomainId = domain_name.parse().unwrap();
    test_client
        .submit_blocking(Register::domain(Domain::new(domain_id.clone())))
        .expect("should be committed");

    let mut accounts = vec![];
    let mut metadata_of_accounts = vec![];
    let mut instructions = vec![];

    let n = 10u32;
    let mut public_keys = (0..n)
        .map(|_| KeyPair::random().into_parts().0)
        .collect::<Vec<_>>();
    public_keys.sort_unstable();
    for i in 0..n {
        let account_id = AccountId::new(domain_id.clone(), public_keys[i as usize].clone());
        let mut account_metadata = Metadata::default();
        account_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let account = Account::new(account_id.clone()).with_metadata(account_metadata.clone());

        accounts.push(account_id);
        metadata_of_accounts.push(account_metadata);

        let create_account = Register::account(account);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .query(client::account::all())
        .with_sorting(Sorting::by_metadata_key(sort_by_metadata_key.clone()))
        .filter_with(|account| account.id.domain_id.eq(domain_id))
        .execute_all()
        .expect("Valid");

    assert!(res.iter().map(Identifiable::id).eq(accounts.iter().rev()));
    assert!(res
        .iter()
        .map(Account::metadata)
        .eq(metadata_of_accounts.iter().rev()));

    // Test sorting domains

    let mut domains = vec![];
    let mut metadata_of_domains = vec![];
    let mut instructions = vec![];
    let n = 10u32;
    for i in 0..n {
        let domain_id = DomainId::from_str(&format!("neverland{i}")).expect("Valid");
        let mut domain_metadata = Metadata::default();
        domain_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
        let domain = Domain::new(domain_id.clone()).with_metadata(domain_metadata.clone());

        domains.push(domain_id);
        metadata_of_domains.push(domain_metadata);

        let create_account = Register::domain(domain);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .query(client::domain::all())
        .with_sorting(Sorting::by_metadata_key(sort_by_metadata_key.clone()))
        .filter_with(|domain| domain.id.name.starts_with("neverland"))
        .execute_all()
        .expect("Valid");

    assert!(res.iter().map(Identifiable::id).eq(domains.iter().rev()));
    assert!(res
        .iter()
        .map(Domain::metadata)
        .eq(metadata_of_domains.iter().rev()));

    // Naive test sorting of domains
    let input = [(0_i32, 1_u32), (2, 0), (1, 2)];
    let mut domains = vec![];
    let mut metadata_of_domains = vec![];
    let mut instructions = vec![];
    for (idx, val) in input {
        let domain_id = DomainId::from_str(&format!("neverland_{idx}")).expect("Valid");
        let mut domain_metadata = Metadata::default();
        domain_metadata.insert(sort_by_metadata_key.clone(), val);
        let domain = Domain::new(domain_id.clone()).with_metadata(domain_metadata.clone());

        domains.push(domain_id);
        metadata_of_domains.push(domain_metadata);

        let create_account = Register::domain(domain);
        instructions.push(create_account);
    }
    test_client
        .submit_all_blocking(instructions)
        .expect("Valid");

    let res = test_client
        .query(client::domain::all())
        .with_sorting(Sorting::by_metadata_key(sort_by_metadata_key))
        .filter_with(|domain| domain.id.name.starts_with("neverland_"))
        .execute()
        .expect("Valid")
        .collect::<QueryResult<Vec<_>>>()
        .expect("Valid");

    assert_eq!(res[0].id(), &domains[1]);
    assert_eq!(res[1].id(), &domains[0]);
    assert_eq!(res[2].id(), &domains[2]);
    assert_eq!(res[0].metadata(), &metadata_of_domains[1]);
    assert_eq!(res[1].metadata(), &metadata_of_domains[0]);
    assert_eq!(res[2].metadata(), &metadata_of_domains[2]);
}

#[test]
fn sort_only_elements_which_have_sorting_key() -> Result<()> {
    const TEST_DOMAIN: &str = "neverland";

    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_680).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let domain_id: DomainId = TEST_DOMAIN.parse().unwrap();
    test_client
        .submit_blocking(Register::domain(Domain::new(domain_id.clone())))
        .expect("should be committed");

    let sort_by_metadata_key = Name::from_str("test_sort").expect("Valid");

    let mut accounts_a = vec![];
    let mut accounts_b = vec![];
    let mut instructions = vec![];

    let mut skip_set = HashSet::new();
    skip_set.insert(4);
    skip_set.insert(7);

    let n = 10u32;
    let mut public_keys = (0..n)
        .map(|_| KeyPair::random().into_parts().0)
        .collect::<Vec<_>>();
    public_keys.sort_unstable();
    for i in 0..n {
        let account_id = AccountId::new(domain_id.clone(), public_keys[i as usize].clone());
        let account = if skip_set.contains(&i) {
            let account = Account::new(account_id.clone());
            accounts_b.push(account_id);
            account
        } else {
            let mut account_metadata = Metadata::default();
            account_metadata.insert(sort_by_metadata_key.clone(), n - i - 1);
            let account = Account::new(account_id.clone()).with_metadata(account_metadata);
            accounts_a.push(account_id);
            account
        };

        let create_account = Register::account(account);
        instructions.push(create_account);
    }

    test_client
        .submit_all_blocking(instructions)
        .wrap_err("Failed to register accounts")?;

    let res = test_client
        .query(client::account::all())
        .with_sorting(Sorting::by_metadata_key(sort_by_metadata_key))
        .filter_with(|account| account.id.domain_id.eq(domain_id))
        .execute_all()
        .wrap_err("Failed to submit request")?;

    let accounts = accounts_a.iter().rev().chain(accounts_b.iter());
    assert!(res.iter().map(Identifiable::id).eq(accounts));

    Ok(())
}
