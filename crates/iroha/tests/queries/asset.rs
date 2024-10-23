use eyre::Result;
use iroha::{
    client::{Client, QueryError},
    data_model::{isi::Instruction, prelude::*, query::builder::SingleQueryError},
};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID};

#[test]
#[allow(clippy::too_many_lines)]
fn find_asset_total_quantity() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    // Register new domain
    let domain_id: DomainId = "looking_glass".parse()?;
    let domain = Domain::new(domain_id);
    test_client.submit_blocking(Register::domain(domain))?;

    let accounts: [AccountId; 5] = [
        ALICE_ID.clone(),
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("looking_glass").0,
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| Register::account(Account::new(account_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    // Test for numeric assets value types
    test_total_quantity(
        &test_client,
        &accounts,
        "quantity#wonderland",
        numeric!(10),
        numeric!(5),
        numeric!(25),
        Mint::asset_numeric,
        Burn::asset_numeric,
    )?;
    test_total_quantity(
        &test_client,
        &accounts,
        "fixed#wonderland",
        numeric!(10.0),
        numeric!(5.0),
        numeric!(25.0),
        Mint::asset_numeric,
        Burn::asset_numeric,
    )?;
    Ok(())
}

// TODO: re-add store asset test

#[allow(clippy::too_many_arguments)]
fn test_total_quantity(
    test_client: &Client,
    accounts: &[AccountId; 5],
    definition: &str,
    to_mint: Numeric,
    to_burn: Numeric,
    expected_total_asset_quantity: Numeric,
    mint_ctr: impl Fn(Numeric, AssetId) -> Mint<Numeric, Asset>,
    burn_ctr: impl Fn(Numeric, AssetId) -> Burn<Numeric, Asset>,
) -> Result<()>
where
    Mint<Numeric, Asset>: Instruction,
    Burn<Numeric, Asset>: Instruction,
{
    // Registering new asset definition
    let definition_id: AssetDefinitionId =
        definition.parse().expect("Failed to parse `definition_id`");
    let asset_definition = AssetDefinition::new(definition_id.clone());
    test_client.submit_blocking(Register::asset_definition(asset_definition))?;

    let asset_ids = accounts
        .iter()
        .cloned()
        .map(|account_id| AssetId::new(definition_id.clone(), account_id))
        .collect::<Vec<_>>();

    let get_quantity = || -> Result<Numeric, SingleQueryError<QueryError>> {
        Ok(test_client
            .query(FindAssetsDefinitions::new())
            .filter_with(|asset_definition| asset_definition.id.eq(definition_id.clone()))
            .execute_single()?
            .total_quantity)
    };

    // Assert that initial total quantity before any burns and mints is zero
    let initial_total_asset_quantity = get_quantity()?;
    assert!(initial_total_asset_quantity.is_zero());

    let mint_assets = asset_ids
        .iter()
        .cloned()
        .map(|asset_id| mint_ctr(to_mint, asset_id));
    test_client.submit_all_blocking(mint_assets)?;

    let burn_assets = asset_ids
        .iter()
        .cloned()
        .map(|asset_id| burn_ctr(to_burn, asset_id))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(burn_assets)?;

    // Assert that total asset quantity is equal to: `n_accounts * (to_mint - to_burn)`
    let total_asset_quantity = get_quantity()?;
    assert_eq!(expected_total_asset_quantity, total_asset_quantity);

    // Unregister asset definition
    test_client.submit_blocking(Unregister::asset_definition(definition_id.clone()))?;

    // Assert that total asset quantity cleared with unregistering of asset definition
    let result = get_quantity();
    assert!(matches!(result, Err(SingleQueryError::ExpectedOneGotNone)));

    Ok(())
}
