use eyre::Result;
use iroha::{
    client::{Client, QueryError},
    data_model::{
        asset::AssetValue,
        isi::Instruction,
        prelude::*,
        query::{asset::FindTotalAssetQuantityByAssetDefinitionId, error::QueryExecutionFail},
    },
};
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID};

#[test]
#[allow(clippy::too_many_lines)]
fn find_asset_total_quantity() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_765).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

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
        AssetType::Numeric(NumericSpec::default()),
        numeric!(1),
        numeric!(10),
        numeric!(5),
        numeric!(30),
        Mint::asset_numeric,
        Burn::asset_numeric,
    )?;
    test_total_quantity(
        &test_client,
        &accounts,
        "fixed#wonderland",
        AssetType::Numeric(NumericSpec::default()),
        numeric!(1.0),
        numeric!(10.0),
        numeric!(5.0),
        numeric!(30.0),
        Mint::asset_numeric,
        Burn::asset_numeric,
    )?;

    // Test for `Store` asset value type
    let definition_id: AssetDefinitionId = "store#wonderland".parse().expect("Valid");
    let asset_definition = AssetDefinition::store(definition_id.clone());
    test_client.submit_blocking(Register::asset_definition(asset_definition))?;

    let asset_ids = accounts
        .iter()
        .cloned()
        .map(|account_id| AssetId::new(definition_id.clone(), account_id))
        .collect::<Vec<_>>();

    // Assert that initial total quantity before any registrations and unregistrations is zero
    let initial_total_asset_quantity = test_client.query_single(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(initial_total_asset_quantity.is_zero());

    let register_assets = asset_ids
        .iter()
        .cloned()
        .map(|asset_id| Asset::new(asset_id, Metadata::default()))
        .map(Register::asset)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_assets)?;

    // Assert that total quantity is equal to number of registrations
    let result = test_client.query_single(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id.clone(),
    ))?;
    assert_eq!(numeric!(5), result);

    let unregister_assets = asset_ids
        .iter()
        .cloned()
        .map(Unregister::asset)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(unregister_assets)?;

    // Assert that total asset quantity is zero after unregistering asset from all accounts
    let total_asset_quantity = test_client.query_single(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(total_asset_quantity.is_zero());

    // Unregister asset definition
    test_client.submit_blocking(Unregister::asset_definition(definition_id.clone()))?;

    // Assert that total asset quantity cleared with unregistering of asset definition
    let result = test_client.query_single(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id,
    ));
    assert!(matches!(
        result,
        Err(QueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::Find(_)
        )))
    ));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn test_total_quantity<T>(
    test_client: &Client,
    accounts: &[AccountId; 5],
    definition: &str,
    asset_type: AssetType,
    initial_value: T,
    to_mint: T,
    to_burn: T,
    expected_total_asset_quantity: Numeric,
    mint_ctr: impl Fn(T, AssetId) -> Mint<T, Asset>,
    burn_ctr: impl Fn(T, AssetId) -> Burn<T, Asset>,
) -> Result<()>
where
    T: Copy + Into<AssetValue>,
    Mint<T, Asset>: Instruction,
    Burn<T, Asset>: Instruction,
{
    // Registering new asset definition
    let definition_id: AssetDefinitionId =
        definition.parse().expect("Failed to parse `definition_id`");
    let asset_definition = AssetDefinition::new(definition_id.clone(), asset_type);
    test_client.submit_blocking(Register::asset_definition(asset_definition))?;

    let asset_ids = accounts
        .iter()
        .cloned()
        .map(|account_id| AssetId::new(definition_id.clone(), account_id))
        .collect::<Vec<_>>();

    // Assert that initial total quantity before any burns and mints is zero
    let initial_total_asset_quantity = test_client.query_single(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(initial_total_asset_quantity.is_zero());

    let register_assets = asset_ids
        .iter()
        .cloned()
        .map(|asset_id| Asset::new(asset_id, initial_value))
        .map(Register::asset)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_assets)?;

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

    // Assert that total asset quantity is equal to: `n_accounts * (initial_value + to_mint - to_burn)`
    let total_asset_quantity = test_client.query_single(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert_eq!(expected_total_asset_quantity, total_asset_quantity);

    let unregister_assets = asset_ids
        .iter()
        .cloned()
        .map(Unregister::asset)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(unregister_assets)?;

    // Assert that total asset quantity is zero after unregistering asset from all accounts
    let total_asset_quantity = test_client.query_single(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(total_asset_quantity.is_zero());

    // Unregister asset definition
    test_client.submit_blocking(Unregister::asset_definition(definition_id.clone()))?;

    // Assert that total asset quantity cleared with unregistering of asset definition
    let result = test_client.query_single(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id,
    ));
    assert!(matches!(
        result,
        Err(QueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::Find(_)
        )))
    ));

    Ok(())
}
