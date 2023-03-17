#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::client;
use iroha_data_model::prelude::*;
use iroha_primitives::fixed::Fixed;
use test_network::*;

use super::Configuration;

#[test]
fn client_register_asset_should_add_asset_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_620).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");

    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_asset = RegisterBox::new(Asset::new(
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
        AssetValue::Quantity(0),
    ));

    test_client.submit_all(vec![create_asset.into(), register_asset.clone().into()])?;

    // Registering an asset to an account which doesn't have one
    // should result in asset being created
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(0)
        })
    })?;

    // But registering an asset to account already having one should fail
    assert!(test_client.submit_blocking(register_asset).is_err());

    Ok(())
}

#[test]
fn unregister_asset_should_remove_asset_from_account() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_555).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");

    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").expect("Valid");
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_asset = RegisterBox::new(Asset::new(asset_id.clone(), AssetValue::Quantity(0)));
    let unregister_asset = UnregisterBox::new(asset_id);

    test_client.submit_all(vec![create_asset.into(), register_asset.into()])?;

    // Wait for asset to be registered
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        result
            .iter()
            .any(|asset| asset.id().definition_id == asset_definition_id)
    })?;

    test_client.submit(unregister_asset)?;

    // ... and check that it is removed after Unregister
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result
            .iter()
            .all(|asset| asset.id().definition_id != asset_definition_id)
    })?;

    Ok(())
}

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_000).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let metadata = iroha_data_model::metadata::UnlimitedMetadata::default();
    //When
    let quantity: u32 = 200;
    let mint = MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    let instructions: Vec<Instruction> = vec![create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata)?;
    test_client.submit_transaction(tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Quantity(quantity)
        })
    })?;
    Ok(())
}

#[test]
fn client_add_big_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_510).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::big_quantity(asset_definition_id.clone()));
    let metadata = iroha_data_model::metadata::UnlimitedMetadata::default();
    //When
    let quantity: u128 = 2_u128.pow(65);
    let mint = MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    let instructions: Vec<Instruction> = vec![create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata)?;
    test_client.submit_transaction(tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::BigQuantity(quantity)
        })
    })?;
    Ok(())
}

#[test]
fn client_add_asset_with_decimal_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_515).start_with_runtime();

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let identifiable_box = AssetDefinition::fixed(asset_definition_id.clone());
    let create_asset = RegisterBox::new(identifiable_box);
    let metadata = iroha_data_model::metadata::UnlimitedMetadata::default();

    //When
    let quantity: Fixed = Fixed::try_from(123.456_f64).unwrap();
    let mint = MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    let instructions: Vec<Instruction> = vec![create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata)?;
    test_client.submit_transaction(tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Fixed(quantity)
        })
    })?;

    // Add some fractional part
    let quantity2: Fixed = Fixed::try_from(0.55_f64).unwrap();
    let mint = MintBox::new(
        quantity2.to_value(),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );
    // and check that it is added without errors
    let sum = quantity
        .checked_add(quantity2)
        .map_err(|e| eyre::eyre!("{}", e))?;
    test_client.submit_till(mint, client::asset::by_account_id(account_id), |result| {
        result.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Fixed(sum)
        })
    })?;
    Ok(())
}

#[test]
fn client_add_asset_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_520).start_with_runtime();
    let pipeline_time = Configuration::pipeline_time();

    // Given
    let normal_asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(
        normal_asset_definition_id.clone(),
    ));
    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating asset");

    let too_long_asset_name = "0".repeat(2_usize.pow(14));
    let incorrect_asset_definition_id =
        AssetDefinitionId::from_str(&(too_long_asset_name + "#wonderland")).expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::quantity(
        incorrect_asset_definition_id.clone(),
    ));

    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating another asset");
    thread::sleep(pipeline_time * 4);

    let asset_definition_ids = test_client
        .request(client::asset::all_definitions())
        .expect("Failed to execute request.")
        .into_iter()
        .map(|asset| asset.id().clone())
        .collect::<Vec<_>>();
    iroha_logger::debug!(
        "Collected asset definitions ID's: {:?}",
        &asset_definition_ids
    );

    assert!(asset_definition_ids.contains(&normal_asset_definition_id));
    assert!(!asset_definition_ids.contains(&incorrect_asset_definition_id));

    Ok(())
}

#[allow(unused_must_use)]
#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_675).start_with_runtime();

    test_client
        .submit_all_blocking(vec![
            register::domain("exchange").into(),
            register::domain("company").into(),
            register::domain("crypto").into(),
            register::account("seller", "company").into(),
            register::account("buyer", "company").into(),
            register::account("dex", "exchange").into(),
            register::asset_definition("btc", "crypto").into(),
            register::asset_definition("eth", "crypto").into(),
            register::asset_definition("btc2eth_rate", "exchange").into(),
            MintBox::new(
                200_u32.to_value(),
                IdBox::AssetId(asset_id_new("eth", "crypto", "buyer", "company")),
            )
            .into(),
            MintBox::new(
                20_u32.to_value(),
                IdBox::AssetId(asset_id_new("btc", "crypto", "seller", "company")),
            )
            .into(),
            MintBox::new(
                20_u32.to_value(),
                IdBox::AssetId(asset_id_new("btc2eth_rate", "exchange", "dex", "exchange")),
            )
            .into(),
            Pair::new(
                TransferBox::new(
                    IdBox::AssetId(asset_id_new("btc", "crypto", "seller", "company")),
                    EvaluatesTo::new_evaluates_to_value(
                        Expression::Query(
                            FindAssetQuantityById::new(asset_id_new(
                                "btc2eth_rate",
                                "exchange",
                                "dex",
                                "exchange",
                            ))
                            .into(),
                        )
                        .into(),
                    ),
                    IdBox::AssetId(asset_id_new("btc", "crypto", "buyer", "company")),
                ),
                TransferBox::new(
                    IdBox::AssetId(asset_id_new("eth", "crypto", "buyer", "company")),
                    EvaluatesTo::new_evaluates_to_value(
                        Expression::Query(
                            FindAssetQuantityById::new(asset_id_new(
                                "btc2eth_rate",
                                "exchange",
                                "dex",
                                "exchange",
                            ))
                            .into(),
                        )
                        .into(),
                    ),
                    IdBox::AssetId(asset_id_new("eth", "crypto", "seller", "company")),
                ),
            )
            .into(),
        ])
        .expect("Failed to execute Iroha Special Instruction.");

    let expected_seller_eth = NumericValue::U32(20);
    let expected_buyer_eth = NumericValue::U32(180);
    let expected_buyer_btc = NumericValue::U32(20);

    let eth_quantity = test_client
        .request(FindAssetQuantityById::new(asset_id_new(
            "eth", "crypto", "seller", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_seller_eth, eth_quantity);

    // For the btc amount we expect an error, as zero assets are purged from accounts
    test_client
        .request(FindAssetQuantityById::new(asset_id_new(
            "btc", "crypto", "seller", "company",
        )))
        .expect_err("Query must fail");

    let buyer_eth_quantity = test_client
        .request(FindAssetQuantityById::new(asset_id_new(
            "eth", "crypto", "buyer", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_eth, buyer_eth_quantity);

    let buyer_btc_quantity = test_client
        .request(FindAssetQuantityById::new(asset_id_new(
            "btc", "crypto", "buyer", "company",
        )))
        .expect("Failed to execute Iroha Query");
    assert_eq!(expected_buyer_btc, buyer_btc_quantity);
}

fn asset_id_new(
    definition_name: &str,
    definition_domain: &str,
    account_name: &str,
    account_domain: &str,
) -> AssetId {
    AssetId::new(
        AssetDefinitionId::new(
            definition_name.parse().expect("Valid"),
            definition_domain.parse().expect("Valid"),
        ),
        AccountId::new(
            account_name.parse().expect("Valid"),
            account_domain.parse().expect("Valid"),
        ),
    )
}

mod register {
    use super::*;

    pub fn domain(name: &str) -> RegisterBox {
        RegisterBox::new(Domain::new(DomainId::from_str(name).expect("Valid")))
    }

    pub fn account(account_name: &str, domain_name: &str) -> RegisterBox {
        RegisterBox::new(Account::new(
            AccountId::new(
                account_name.parse().expect("Valid"),
                domain_name.parse().expect("Valid"),
            ),
            [],
        ))
    }

    pub fn asset_definition(asset_name: &str, domain_name: &str) -> RegisterBox {
        RegisterBox::new(AssetDefinition::quantity(AssetDefinitionId::new(
            asset_name.parse().expect("Valid"),
            domain_name.parse().expect("Valid"),
        )))
    }
}
