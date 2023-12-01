use eyre::Result;
use iroha_client::{
    client::ClientQueryError,
    crypto::KeyPair,
    data_model::{
        prelude::*,
        query::{asset::FindTotalAssetQuantityByAssetDefinitionId, error::QueryExecutionFail},
    },
};
use iroha_primitives::fixed::Fixed;
use test_network::*;

#[test]
#[allow(clippy::too_many_lines)]
fn find_asset_total_quantity() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_765).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Register new domain
    let domain_id: DomainId = "looking_glass".parse()?;
    let domain = Domain::new(domain_id);
    test_client.submit_blocking(RegisterExpr::new(domain))?;

    let accounts: [AccountId; 5] = [
        "alice@wonderland".parse()?,
        "mad_hatter@wonderland".parse()?,
        "cheshire_cat@wonderland".parse()?,
        "caterpillar@wonderland".parse()?,
        "white_rabbit@looking_glass".parse()?,
    ];

    let keys =
        core::iter::repeat_with(|| KeyPair::generate().expect("Failed to generate `KeyPair`"))
            .take(accounts.len() - 1)
            .collect::<Vec<_>>();

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .zip(keys.iter().map(KeyPair::public_key).cloned())
        .map(|(account_id, public_key)| RegisterExpr::new(Account::new(account_id, [public_key])))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    // Test for numeric assets value types
    for (
        definition,
        asset_value_type,
        initial_value,
        to_mint,
        to_burn,
        expected_total_asset_quantity,
    ) in [
        (
            "quantity#wonderland",
            AssetValueType::Quantity,
            AssetValue::Quantity(1_u32),
            10_u32.to_value(),
            5_u32.to_value(),
            NumericValue::U32(30_u32),
        ),
        (
            "big-quantity#wonderland",
            AssetValueType::BigQuantity,
            AssetValue::BigQuantity(1_u128),
            10_u128.to_value(),
            5_u128.to_value(),
            NumericValue::U128(30_u128),
        ),
        (
            "fixed#wonderland",
            AssetValueType::Fixed,
            AssetValue::Fixed(Fixed::try_from(1.0)?),
            10.0_f64.try_to_value()?,
            5.0_f64.try_to_value()?,
            NumericValue::Fixed(Fixed::try_from(30.0)?),
        ),
    ] {
        // Registering new asset definition
        let definition_id: AssetDefinitionId =
            definition.parse().expect("Failed to parse `definition_id`");
        let asset_definition = AssetDefinition::new(definition_id.clone(), asset_value_type);
        test_client.submit_blocking(RegisterExpr::new(asset_definition.clone()))?;

        let asset_ids = accounts
            .iter()
            .cloned()
            .map(|account_id| AssetId::new(definition_id.clone(), account_id))
            .collect::<Vec<_>>();

        // Assert that initial total quantity before any burns and mints is zero
        let initial_total_asset_quantity = test_client.request(
            FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
        )?;
        assert!(initial_total_asset_quantity.is_zero_value());

        let register_asset = asset_ids
            .iter()
            .cloned()
            .map(|asset_id| Asset::new(asset_id, initial_value.clone()))
            .map(RegisterExpr::new)
            .collect::<Vec<_>>();
        test_client.submit_all_blocking(register_asset)?;

        let mint_asset = asset_ids
            .iter()
            .cloned()
            .map(|asset_id| MintExpr::new(to_mint.clone(), asset_id));
        test_client.submit_all_blocking(mint_asset)?;

        let burn_asset = asset_ids
            .iter()
            .cloned()
            .map(|asset_id| BurnExpr::new(to_burn.clone(), asset_id))
            .collect::<Vec<_>>();
        test_client.submit_all_blocking(burn_asset)?;

        // Assert that total asset quantity is equal to: `n_accounts * (initial_value + to_mint - to_burn)`
        let total_asset_quantity = test_client.request(
            FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
        )?;
        assert_eq!(expected_total_asset_quantity, total_asset_quantity);

        let unregister_asset = asset_ids
            .iter()
            .cloned()
            .map(UnregisterExpr::new)
            .collect::<Vec<_>>();
        test_client.submit_all_blocking(unregister_asset)?;

        // Assert that total asset quantity is zero after unregistering asset from all accounts
        let total_asset_quantity = test_client.request(
            FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
        )?;
        assert!(total_asset_quantity.is_zero_value());

        // Unregister asset definition
        test_client.submit_blocking(UnregisterExpr::new(definition_id.clone()))?;

        // Assert that total asset quantity cleared with unregistering of asset definition
        let result = test_client.request(FindTotalAssetQuantityByAssetDefinitionId::new(
            definition_id.clone(),
        ));
        assert!(matches!(
            result,
            Err(ClientQueryError::Validation(ValidationFail::QueryFailed(
                QueryExecutionFail::Find(_)
            )))
        ));
    }

    // Test for `Store` asset value type
    let definition_id: AssetDefinitionId = "store#wonderland".parse().expect("Valid");
    let asset_definition = AssetDefinition::store(definition_id.clone());
    test_client.submit_blocking(RegisterExpr::new(asset_definition))?;

    let asset_ids = accounts
        .iter()
        .cloned()
        .map(|account_id| AssetId::new(definition_id.clone(), account_id))
        .collect::<Vec<_>>();

    // Assert that initial total quantity before any registrations and unregistrations is zero
    let initial_total_asset_quantity = test_client.request(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(initial_total_asset_quantity.is_zero_value());

    let register_asset = asset_ids
        .iter()
        .cloned()
        .map(|asset_id| Asset::new(asset_id, Metadata::default()))
        .map(RegisterExpr::new)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_asset)?;

    // Assert that total quantity is equal to number of registrations
    let result = test_client.request(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id.clone(),
    ))?;
    assert_eq!(NumericValue::U32(5), result);

    let unregister_asset = asset_ids
        .iter()
        .cloned()
        .map(UnregisterExpr::new)
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(unregister_asset)?;

    // Assert that total asset quantity is zero after unregistering asset from all accounts
    let total_asset_quantity = test_client.request(
        FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
    )?;
    assert!(total_asset_quantity.is_zero_value());

    // Unregister asset definition
    test_client.submit_blocking(UnregisterExpr::new(definition_id.clone()))?;

    // Assert that total asset quantity cleared with unregistering of asset definition
    let result = test_client.request(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id,
    ));
    assert!(matches!(
        result,
        Err(ClientQueryError::Validation(ValidationFail::QueryFailed(
            QueryExecutionFail::Find(_)
        )))
    ));

    Ok(())
}
