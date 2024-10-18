use eyre::Result;
use iroha::{
    client,
    crypto::KeyPair,
    data_model::{
        asset::AssetId,
        isi::error::{InstructionEvaluationError, InstructionExecutionError, Mismatch, TypeError},
        prelude::*,
        transaction::error::TransactionRejectionReason,
    },
};
use iroha_executor_data_model::permission::asset::CanTransferAsset;
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID, BOB_ID};

#[test]
// This test is also covered at the UI level in the iroha_cli tests
// in test_mint_assets.py
fn mint_asset_should_increase_asset_amount() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();
    // Given
    let account = ALICE_ID.clone();
    let asset_definition = "xor#wonderland".parse::<AssetDefinitionId>()?;
    let define_asset = Register::asset_definition(AssetDefinition::new(asset_definition.clone()));
    //When
    let asset_id = AssetId::new(asset_definition.clone(), account.clone());
    let quantity = numeric!(200);
    let mint = Mint::asset_numeric(quantity, asset_id.clone());
    test_client.submit_all_blocking::<InstructionBox>([define_asset.into(), mint.into()])?;
    assert_eq!(
        quantity,
        test_client.query_single(FindAssetQuantityById::new(asset_id))?
    );
    Ok(())
}

#[test]
fn client_add_big_asset_quantity_to_existing_asset_should_increase_asset_amount() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    // Given
    let account = ALICE_ID.clone();
    let asset_definition = "xor#wonderland".parse::<AssetDefinitionId>()?;
    let create_asset = Register::asset_definition(AssetDefinition::new(asset_definition.clone()));
    //When
    let quantity = Numeric::new(2_u128.pow(65), 0);
    let asset_id = AssetId::new(asset_definition, account);
    let mint = Mint::asset_numeric(quantity, asset_id.clone());
    test_client.submit_all_blocking::<InstructionBox>([create_asset.into(), mint.into()])?;
    assert_eq!(
        quantity,
        test_client.query_single(FindAssetQuantityById::new(asset_id))?
    );
    Ok(())
}

#[test]
fn client_add_asset_with_decimal_should_increase_asset_amount() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    // Given
    let account = ALICE_ID.clone();
    let asset_definition = "xor#wonderland".parse::<AssetDefinitionId>()?;
    let define_asset = Register::asset_definition(AssetDefinition::new(asset_definition.clone()));

    //When
    let quantity = numeric!(123.456);
    let asset_id = AssetId::new(asset_definition.clone(), account.clone());
    let mint = Mint::asset_numeric(quantity, asset_id.clone());
    test_client
        .submit_all_blocking::<InstructionBox>([define_asset.into(), mint.clone().into()])?;
    {
        let value = test_client.query_single(FindAssetQuantityById::new(asset_id.clone()))?;
        assert_eq!(value, quantity)
    }

    // Add some fractional part
    let incremint = numeric!(0.55);
    let mint = Mint::asset_numeric(incremint, asset_id.clone());
    test_client.submit_blocking(mint)?;
    // and check that it is added without errors
    let sum = quantity.checked_add(incremint).unwrap();
    {
        let value = test_client.query_single(FindAssetQuantityById::new(asset_id.clone()))?;
        assert_eq!(value, sum)
    }
    Ok(())
}

#[allow(unused_must_use)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::expect_fun_call)]
#[test]
fn find_rate_and_make_exchange_isi_should_succeed() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

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
    test_client
        .submit_all_blocking::<InstructionBox>([
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
        ])
        .expect("transaction should be committed");

    let alice_id = ALICE_ID.clone();
    let alice_can_transfer_asset = |asset_id: AssetId, owner_key_pair: KeyPair| {
        let permission = CanTransferAsset {
            asset: asset_id.clone(),
        };
        let instruction = Grant::account_permission(permission, alice_id.clone());
        let transaction = TransactionBuilder::new(
            ChainId::from("00000000-0000-0000-0000-000000000000"),
            asset_id.account().clone(),
        )
        .with_instructions([instruction])
        .sign(owner_key_pair.private_key());

        test_client
            .submit_transaction_blocking(&transaction)
            .expect("transaction should be committed");
    };
    alice_can_transfer_asset(seller_btc.clone(), seller_keypair);
    alice_can_transfer_asset(buyer_eth.clone(), buyer_keypair);

    let assert_balance = |asset_id: AssetId, expected: Numeric| {
        let got = test_client
            .query_single(FindAssetQuantityById::new(asset_id))
            .expect("query should succeed");
        assert_eq!(got, expected);
    };
    // before: seller has $BTC10 and buyer has $ETH200
    assert_balance(seller_btc.clone(), numeric!(10));
    assert_balance(buyer_eth.clone(), numeric!(200));

    let rate: u32 = test_client
        .query_single(FindAssetQuantityById::new(rate))
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
            .query_single(FindAssetQuantityById::new(asset_id))
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
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let asset_definition_id: AssetDefinitionId = "asset#wonderland".parse().expect("Valid");

    test_client
        .submit_blocking(Register::asset_definition(AssetDefinition::new(
            asset_definition_id.clone(),
        )))
        .expect("Failed to submit transaction");

    let asset_definition = test_client
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id.clone()))
        .execute_single()
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
        .query(client::asset::all_definitions())
        .filter_with(|asset_definition| asset_definition.id.eq(asset_definition_id))
        .execute_single()
        .expect("Failed to execute Iroha Query");
    assert_eq!(asset_definition.owned_by(), &bob_id);
}

#[test]
fn fail_if_dont_satisfy_spec() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let alice_id = ALICE_ID.clone();
    let bob_id = BOB_ID.clone();
    let asset_definition_id: AssetDefinitionId = "asset#wonderland".parse().expect("Valid");
    let asset_id: AssetId = AssetId::new(asset_definition_id.clone(), alice_id.clone());
    // Create asset definition which accepts only integers
    let asset_definition =
        AssetDefinition::new(asset_definition_id).with_numeric_spec(NumericSpec::integer());

    test_client
        .submit_blocking(Register::asset_definition(asset_definition))
        .expect("Failed to submit transaction");

    let isi = |value: Numeric| {
        [
            Mint::asset_numeric(value, asset_id.clone()).into(),
            Mint::asset_numeric(value, asset_id.clone()).into(),
            Burn::asset_numeric(value, asset_id.clone()).into(),
            Transfer::asset_numeric(asset_id.clone(), value, bob_id.clone()).into(),
        ]
    };

    // Fail if submitting fractional value
    let fractional_value = numeric!(0.01);

    for isi in isi(fractional_value) {
        let err = test_client
            .submit_blocking::<InstructionBox>(isi)
            .expect_err("Should be rejected due to non integer value");

        let rejection_reason = err
            .downcast_ref::<TransactionRejectionReason>()
            .unwrap_or_else(|| panic!("Error {err} is not TransactionRejectionReason"));

        assert_eq!(
            rejection_reason,
            &TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
                InstructionExecutionError::Evaluate(InstructionEvaluationError::Type(
                    TypeError::from(Mismatch {
                        expected: NumericSpec::integer(),
                        actual: NumericSpec::fractional(2)
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
        Register::asset_definition(AssetDefinition::new(
            id.parse().expect("should parse to AssetDefinitionId"),
        ))
    }
}
