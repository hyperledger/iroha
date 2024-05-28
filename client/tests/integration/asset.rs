use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::{
    client::{self, QueryResult},
    crypto::KeyPair,
    data_model::prelude::*,
};
use iroha_config::parameters::actual::Root as Config;
use iroha_data_model::{
    asset::{AssetId, AssetValue, AssetValueType},
    isi::error::{InstructionEvaluationError, InstructionExecutionError, Mismatch, TypeError},
    transaction::error::TransactionRejectionReason,
};
use serde_json::json;
use test_network::*;
use test_samples::{gen_account_in, ALICE_ID, BOB_ID};

#[test]
// This test is also covered at the UI level in the iroha_client_cli tests
// in test_register_asset_definitions.py
fn client_register_asset_should_add_asset_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_620).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();

    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").expect("Valid");
    let create_asset: InstructionBox =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();
    let register_asset: InstructionBox = Register::asset(Asset::new(
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
        0_u32,
    ))
    .into();

    test_client.submit_all([create_asset, register_asset.clone()])?;

    // Registering an asset to an account which doesn't have one
    // should result in asset being created
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Numeric(Numeric::ZERO)
        })
    })?;

    // But registering an asset to account already having one should fail
    assert!(test_client.submit_blocking(register_asset).is_err());

    Ok(())
}

#[test]
fn unregister_asset_should_remove_asset_from_account() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_555).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();

    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").expect("Valid");
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let create_asset: InstructionBox =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();
    let register_asset = Register::asset(Asset::new(asset_id.clone(), 0_u32)).into();
    let unregister_asset = Unregister::asset(asset_id);

    test_client.submit_all([create_asset, register_asset])?;

    // Wait for asset to be registered
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets
            .iter()
            .any(|asset| asset.id().definition_id == asset_definition_id)
    })?;

    test_client.submit(unregister_asset)?;

    // ... and check that it is removed after Unregister
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets
            .iter()
            .all(|asset| asset.id().definition_id != asset_definition_id)
    })?;

    Ok(())
}

#[test]
// This test is also covered at the UI level in the iroha_client_cli tests
// in test_mint_assets.py
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_000).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let metadata = iroha_client::data_model::metadata::UnlimitedMetadata::default();
    //When
    let quantity = numeric!(200);
    let mint = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    let instructions: [InstructionBox; 2] = [create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata);
    test_client.submit_transaction(&tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Numeric(quantity)
        })
    })?;
    Ok(())
}

#[test]
fn client_add_big_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_510).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let metadata = iroha_client::data_model::metadata::UnlimitedMetadata::default();
    //When
    let quantity = Numeric::new(2_u128.pow(65), 0);
    let mint = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    let instructions: [InstructionBox; 2] = [create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata);
    test_client.submit_transaction(&tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Numeric(quantity)
        })
    })?;
    Ok(())
}

#[test]
fn client_add_asset_with_decimal_should_increase_asset_amount() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_515).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let asset_definition = AssetDefinition::numeric(asset_definition_id.clone());
    let create_asset = Register::asset_definition(asset_definition);
    let metadata = iroha_client::data_model::metadata::UnlimitedMetadata::default();

    //When
    let quantity = numeric!(123.456);
    let mint = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    let instructions: [InstructionBox; 2] = [create_asset.into(), mint.into()];
    let tx = test_client.build_transaction(instructions, metadata);
    test_client.submit_transaction(&tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Numeric(quantity)
        })
    })?;

    // Add some fractional part
    let quantity2 = numeric!(0.55);
    let mint = Mint::asset_numeric(
        quantity2,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    // and check that it is added without errors
    let sum = quantity
        .checked_add(quantity2)
        .ok_or_else(|| eyre::eyre!("overflow"))?;
    test_client.submit_till(mint, client::asset::by_account_id(account_id), |result| {
        let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

        assets.iter().any(|asset| {
            asset.id().definition_id == asset_definition_id
                && *asset.value() == AssetValue::Numeric(sum)
        })
    })?;
    Ok(())
}

#[test]
// This test is also covered at the UI level in the iroha_client_cli tests
// in test_register_asset_definitions.py
fn client_add_asset_with_name_length_more_than_limit_should_not_commit_transaction() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_520).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);
    let pipeline_time = Config::pipeline_time();

    // Given
    let normal_asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(normal_asset_definition_id.clone()));
    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating asset");

    let too_long_asset_name = "0".repeat(2_usize.pow(14));
    let incorrect_asset_definition_id =
        AssetDefinitionId::from_str(&(too_long_asset_name + "#wonderland")).expect("Valid");
    let create_asset = Register::asset_definition(AssetDefinition::numeric(
        incorrect_asset_definition_id.clone(),
    ));

    test_client.submit(create_asset)?;
    iroha_logger::info!("Creating another asset");
    thread::sleep(pipeline_time * 4);

    let mut asset_definition_ids = test_client
        .request(client::asset::all_definitions())
        .expect("Failed to execute request.")
        .collect::<QueryResult<Vec<_>>>()
        .expect("Failed to execute request.")
        .into_iter()
        .map(|asset| asset.id().clone());
    iroha_logger::debug!(
        "Collected asset definitions ID's: {:?}",
        &asset_definition_ids
    );

    assert!(asset_definition_ids
        .any(|asset_definition_id| asset_definition_id == normal_asset_definition_id));
    assert!(!asset_definition_ids
        .any(|asset_definition_id| asset_definition_id == incorrect_asset_definition_id));

    Ok(())
}

#[allow(unused_must_use)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::expect_fun_call)]
#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_675).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let (dex_id, _dex_keypair) = gen_account_in("exchange");
    let (seller_id, seller_keypair) = gen_account_in("company");
    let (buyer_id, buyer_keypair) = gen_account_in("company");
    let rate: AssetId = format!("btc/eth##{}", &dex_id)
        .parse()
        .expect("should be valid");
    let seller_btc: AssetId = format!("btc#crypto#{}", &seller_id)
        .parse()
        .expect("should be valid");
    let buyer_eth: AssetId = format!("eth#crypto#{}", &buyer_id)
        .parse()
        .expect("should be valid");
    let instructions: [InstructionBox; 12] = [
        register::domain("exchange").into(),
        register::domain("company").into(),
        register::domain("crypto").into(),
        register::account(dex_id.clone()).into(),
        register::account(seller_id.clone()).into(),
        register::account(buyer_id.clone()).into(),
        register::asset_definition_numeric("btc/eth#exchange").into(),
        register::asset_definition_numeric("btc#crypto").into(),
        register::asset_definition_numeric("eth#crypto").into(),
        Mint::asset_numeric(20_u32, rate.clone()).into(),
        Mint::asset_numeric(10_u32, seller_btc.clone()).into(),
        Mint::asset_numeric(200_u32, buyer_eth.clone()).into(),
    ];
    test_client
        .submit_all_blocking(instructions)
        .expect("transaction should be committed");

    let alice_id = ALICE_ID.clone();
    let alice_can_transfer_asset = |asset_id: AssetId, owner_key_pair: KeyPair| {
        let instruction = Grant::permission(
            Permission::new(
                "CanTransferUserAsset".parse().unwrap(),
                json!({ "asset_id": asset_id }).into(),
            ),
            alice_id.clone(),
        );
        let transaction =
            TransactionBuilder::new(ChainId::from("0"), asset_id.account_id().clone())
                .with_instructions([instruction])
                .sign(&owner_key_pair);

        test_client
            .submit_transaction_blocking(&transaction)
            .expect("transaction should be committed");
    };
    alice_can_transfer_asset(seller_btc.clone(), seller_keypair);
    alice_can_transfer_asset(buyer_eth.clone(), buyer_keypair);

    let assert_balance = |asset_id: AssetId, expected: Numeric| {
        let got = test_client
            .request(FindAssetQuantityById::new(asset_id))
            .expect("query should succeed");
        assert_eq!(got, expected);
    };
    // before: seller has $BTC10 and buyer has $ETH200
    assert_balance(seller_btc.clone(), numeric!(10));
    assert_balance(buyer_eth.clone(), numeric!(200));

    let rate: u32 = test_client
        .request(FindAssetQuantityById::new(rate))
        .expect("query should succeed")
        .try_into()
        .expect("numeric should be u32 originally");
    test_client
        .submit_all_blocking([
            Transfer::asset_numeric(seller_btc.clone(), 10_u32, buyer_id.clone()),
            Transfer::asset_numeric(buyer_eth.clone(), 10_u32 * rate, seller_id.clone()),
        ])
        .expect("transaction should be committed");

    let assert_purged = |asset_id: AssetId| {
        let _err = test_client
            .request(FindAssetQuantityById::new(asset_id))
            .expect_err("query should fail, as zero assets are purged from accounts");
    };
    let seller_eth: AssetId = format!("eth#crypto#{}", &seller_id)
        .parse()
        .expect("should be valid");
    let buyer_btc: AssetId = format!("btc#crypto#{}", &buyer_id)
        .parse()
        .expect("should be valid");
    // after: seller has $ETH200 and buyer has $BTC10
    assert_purged(seller_btc);
    assert_purged(buyer_eth);
    assert_balance(seller_eth, numeric!(200));
    assert_balance(buyer_btc, numeric!(10));
}

#[test]
fn transfer_asset_definition() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_060).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let asset_definition_id: AssetDefinitionId = "asset#wonderland".parse().expect("Valid");

    test_client
        .submit_blocking(Register::asset_definition(AssetDefinition::numeric(
            asset_definition_id.clone(),
        )))
        .expect("Failed to submit transaction");

    let asset_definition = test_client
        .request(FindAssetDefinitionById::new(asset_definition_id.clone()))
        .expect("Failed to execute Iroha Query");
    assert_eq!(asset_definition.owned_by(), &alice_id);

    test_client
        .submit_blocking(Transfer::asset_definition(
            alice_id,
            asset_definition_id.clone(),
            bob_id.clone(),
        ))
        .expect("Failed to submit transaction");

    let asset_definition = test_client
        .request(FindAssetDefinitionById::new(asset_definition_id))
        .expect("Failed to execute Iroha Query");
    assert_eq!(asset_definition.owned_by(), &bob_id);
}

#[test]
fn fail_if_dont_satisfy_spec() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_125).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let asset_definition_id: AssetDefinitionId = "asset#wonderland".parse().expect("Valid");
    let asset_id: AssetId = AssetId::new(asset_definition_id.clone(), alice_id.clone());
    // Create asset definition which accepts only integers
    let asset_definition = AssetDefinition::new(
        asset_definition_id.clone(),
        AssetValueType::Numeric(NumericSpec::integer()),
    );

    test_client
        .submit_blocking(Register::asset_definition(asset_definition))
        .expect("Failed to submit transaction");

    let isi = |value: Numeric| {
        [
            InstructionBox::from(Register::asset(Asset::new(asset_id.clone(), value))),
            Mint::asset_numeric(value, asset_id.clone()).into(),
            Burn::asset_numeric(value, asset_id.clone()).into(),
            Transfer::asset_numeric(asset_id.clone(), value, bob_id.clone()).into(),
        ]
    };

    // Fail if submitting fractional value
    let fractional_value = numeric!(0.01);

    for isi in isi(fractional_value) {
        let err = test_client
            .submit_blocking(isi)
            .expect_err("Should be rejected due to non integer value");

        let rejection_reason = err
            .downcast_ref::<TransactionRejectionReason>()
            .unwrap_or_else(|| panic!("Error {err} is not TransactionRejectionReason"));

        assert_eq!(
            rejection_reason,
            &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::Evaluate(InstructionEvaluationError::Type(
                    TypeError::from(Mismatch {
                        expected: AssetValueType::Numeric(NumericSpec::integer()),
                        actual: AssetValueType::Numeric(NumericSpec::fractional(2))
                    })
                ))
            ))
        );
    }

    // Everything works fine when submitting proper integer value
    let integer_value = numeric!(1);

    for isi in isi(integer_value) {
        test_client
            .submit_blocking(isi)
            .expect("Should be accepted since submitting integer value");
    }
}

mod register {
    use super::*;

    pub fn domain(id: &str) -> Register<Domain> {
        Register::domain(Domain::new(id.parse().expect("should parse to DomainId")))
    }

    pub fn account(id: AccountId) -> Register<Account> {
        Register::account(Account::new(id))
    }

    pub fn asset_definition_numeric(id: &str) -> Register<AssetDefinition> {
        Register::asset_definition(AssetDefinition::numeric(
            id.parse().expect("should parse to AssetDefinitionId"),
        ))
    }
}
