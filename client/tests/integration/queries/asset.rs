#![allow(clippy::restriction)]
use eyre::Result;
use iroha_client::client::ClientQueryError;
use iroha_core::smartcontracts::isi::query::Error as QueryError;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    prelude::*, query::asset::FindTotalAssetQuantityByAssetDefinitionId, Registered,
};
use iroha_permissions_validators::public_blockchain::burn::CanBurnUserAssets;
use iroha_primitives::fixed::Fixed;
use test_network::*;

#[test]
#[allow(clippy::too_many_lines)]
fn find_asset_total_quantity() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Register new domain
    let domain_id: DomainId = "looking_glass".parse()?;
    let domain = Domain::new(domain_id);
    test_client.submit_blocking(RegisterBox::new(domain))?;

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
        .map(|(account_id, public_key)| RegisterBox::new(Account::new(account_id, [public_key])).into())
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    for (definition, asset_value_type, to_mint, to_burn, expected_total_asset_quantity) in [
        (
            "quantity#wonderland",
            AssetValueType::Quantity,
            Value::U32(10),
            Value::U32(5),
            AssetValue::Quantity(25),
        ),
        (
            "big-quantity#wonderland",
            AssetValueType::BigQuantity,
            Value::U128(10),
            Value::U128(5),
            AssetValue::BigQuantity(25),
        ),
        (
            "fixed#wonderland",
            AssetValueType::Fixed,
            Value::Fixed(Fixed::try_from(10.0)?),
            Value::Fixed(Fixed::try_from(5.0)?),
            AssetValue::Fixed(Fixed::try_from(25.0)?),
        ),
    ] {
        // Registering new asset definition
        let definition_id: <AssetDefinition as Identifiable>::Id =
            definition.parse().expect("Valid");
        let asset_definition =
            <AssetDefinition as Registered>::With::new(definition_id.clone(), asset_value_type);
        test_client.submit_blocking(RegisterBox::new(asset_definition.clone()))?;

        let assets = accounts
            .iter()
            .cloned()
            .map(|account_id| <Asset as Identifiable>::Id::new(definition_id.clone(), account_id))
            .collect::<Vec<_>>();

        // Assert that initial total quantity before any burns and mints is zero
        let initial_total_asset_quantity = test_client.request(
            FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
        )?;
        assert!(initial_total_asset_quantity.is_zero_value());

        // Give Alice ability to mint and burn other accounts assets
        assets
            .iter()
            .skip(1)
            .cloned()
            .map(|asset_id| CanBurnUserAssets::new(asset_id).into())
            .map(|permission_token: PermissionToken| {
                GrantBox::new(permission_token, accounts[0].clone())
            })
            .zip(accounts.iter().skip(1).cloned())
            .zip(keys.iter().cloned())
            .map(|((grant_box, account_id), key_pair)| {
                Transaction::new(
                    account_id,
                    Executable::Instructions(vec![grant_box.into()]),
                    100_000,
                )
                .sign(key_pair)
                .expect("Signing failed")
            })
            .for_each(|transaction| {
                test_client
                    .submit_transaction_blocking(transaction)
                    .expect("Unable to execute transaction");
            });

        let mint_asset = assets
            .iter()
            .cloned()
            .map(|asset_id| MintBox::new(to_mint.clone(), asset_id).into());
        test_client.submit_all_blocking(mint_asset)?;

        let burn_asset = accounts
            .iter()
            .cloned()
            .map(|account_id| <Asset as Identifiable>::Id::new(definition_id.clone(), account_id))
            .map(|asset_id| BurnBox::new(to_burn.clone(), asset_id).into())
            .collect::<Vec<_>>();
        test_client.submit_all_blocking(burn_asset)?;

        // Assert that total asset quantity is equal to: `sum(mints) - sum(burns)`
        let total_asset_quantity = test_client.request(
            FindTotalAssetQuantityByAssetDefinitionId::new(definition_id.clone()),
        )?;
        assert_eq!(expected_total_asset_quantity, total_asset_quantity);

        // Unregister asset definition
        test_client.submit_blocking(UnregisterBox::new(definition_id.clone()))?;

        // Assert that total asset quantity cleared with unregistering of asset definition
        let result = test_client.request(FindTotalAssetQuantityByAssetDefinitionId::new(
            definition_id.clone(),
        ));
        assert!(matches!(
            result,
            Err(ClientQueryError::QueryError(QueryError::Find(_)))
        ));
    }

    Ok(())
}

#[test]
fn find_asset_total_quantity_not_supported_for_store() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Registering new asset definition
    let definition_id: <AssetDefinition as Identifiable>::Id =
        "store#wonderland".parse().expect("Valid");
    let asset_definition = AssetDefinition::store(definition_id.clone());
    test_client.submit_blocking(RegisterBox::new(asset_definition))?;

    // Assert that querying total quantity for `Store` is error
    let result = test_client.request(FindTotalAssetQuantityByAssetDefinitionId::new(
        definition_id,
    ));
    assert!(
        matches!(result, Err(ClientQueryError::QueryError(QueryError::Conversion(message))) if message == "`AssetValueType::Store`")
    );

    Ok(())
}
