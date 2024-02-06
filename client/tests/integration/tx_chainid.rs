use std::str::FromStr;

use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;
use test_network::*;

use crate::integration::asset::asset_id_new;

#[test]
fn send_tx_with_different_chain_id() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_240).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);
    // Given
    let sender_account_id = AccountId::from_str("sender@wonderland").expect("Valid");
    let sender_keypair = KeyPair::generate().expect("Failed to generate sender KeyPair.");
    let receiver_account_id = AccountId::from_str("receiver@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").expect("Valid");
    let to_transfer = 1;
    let create_sender_accout = Register::account(Account::new(
        sender_account_id.clone(),
        [sender_keypair.public_key().clone()],
    ));
    let create_receiver_account = Register::account(Account::new(receiver_account_id.clone(), []));
    let create_asset =
        Register::asset_definition(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_asset: InstructionBox = Register::asset(Asset::new(
        AssetId::new(asset_definition_id.clone(), sender_account_id.clone()),
        AssetValue::Quantity(10),
    ))
    .into();

    test_client
        .submit_blocking(create_sender_accout)
        .expect("Failed to create sender account.");
    test_client
        .submit_blocking(create_receiver_account)
        .expect("Failed to create receiver account.");
    test_client
        .submit_blocking(create_asset)
        .expect("Failed to create asset");
    test_client
        .submit_blocking(register_asset.clone())
        .expect("Failed to register asset");
    let chain_id_0 = ChainId::new("0");
    let chain_id_1 = ChainId::new("1");

    let transfer_instruction = Transfer::asset_quantity(
        asset_id_new("test_asset", "wonderland", sender_account_id.clone()),
        to_transfer,
        receiver_account_id.clone(),
    );
    let asset_transfer_tx_0 = TransactionBuilder::new(chain_id_0, sender_account_id.clone())
        .with_instructions([transfer_instruction.clone()])
        .sign(sender_keypair.clone())
        .expect("Failed to sign sender transaction, chainId = 0");
    let asset_transfer_tx_1 = TransactionBuilder::new(chain_id_1, sender_account_id.clone())
        .with_instructions([transfer_instruction])
        .sign(sender_keypair)
        .expect("Failed to sign sender transaction, chainId = 1");
    test_client
        .submit_transaction_blocking(&asset_transfer_tx_0)
        .unwrap();
    let _err = test_client
        .submit_transaction_blocking(&asset_transfer_tx_1)
        .unwrap_err();
}