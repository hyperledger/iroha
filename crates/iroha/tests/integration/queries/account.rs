use std::collections::HashSet;

use eyre::Result;
use iroha::{client, data_model::prelude::*};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID};

#[test]
fn find_accounts_with_asset() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    // Registering new asset definition
    let definition_id = "test_coin#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let asset_definition = AssetDefinition::numeric(definition_id.clone());
    test_client.submit_blocking(Register::asset_definition(asset_definition.clone()))?;

    // Checking results before all
    let received_asset_definition = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(definition_id.clone()))
        .execute_single()?;

    assert_eq!(received_asset_definition.id(), asset_definition.id());
    assert!(matches!(
        received_asset_definition.type_(),
        AssetType::Numeric(_)
    ));

    let accounts: [AccountId; 5] = [
        ALICE_ID.clone(),
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| Register::account(Account::new(account_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    let mint_asset = accounts
        .iter()
        .cloned()
        .map(|account_id| AssetId::new(definition_id.clone(), account_id))
        .map(|asset_id| Mint::asset_numeric(1u32, asset_id))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(mint_asset)?;

    let accounts = HashSet::from(accounts);

    // Checking results
    let received_asset_definition = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(definition_id.clone()))
        .execute_single()?;

    assert_eq!(received_asset_definition.id(), asset_definition.id());
    assert_eq!(
        received_asset_definition.type_(),
        AssetType::Numeric(NumericSpec::default()),
    );

    let found_accounts = test_client
        .query(client::account::all_with_asset(definition_id))
        .execute_all()?;
    let found_ids = found_accounts
        .into_iter()
        .map(|account| account.id().clone())
        .collect::<HashSet<_>>();

    assert_eq!(found_ids, accounts);

    Ok(())
}
