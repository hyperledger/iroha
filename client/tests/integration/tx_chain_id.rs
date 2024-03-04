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
    let sender_account_id = AccountId::from_str("sender@wonderland").unwrap();
    let sender_keypair = KeyPair::generate().unwrap();
    let receiver_account_id = AccountId::from_str("receiver@wonderland").unwrap();
    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").unwrap();
    let to_transfer = 1;
    let create_sender_account = Register::account(Account::new(
        sender_account_id.clone(),
        [sender_keypair.public_key().clone()],
    ));
    let create_receiver_account = Register::account(Account::new(receiver_account_id.clone(), []));
    let register_asset_definition =
        Register::asset_definition(AssetDefinition::quantity(asset_definition_id.clone()));
    let register_asset: InstructionBox = Register::asset(Asset::new(
        AssetId::new(asset_definition_id.clone(), sender_account_id.clone()),
        AssetValue::Quantity(10),
    ))
    .into();
    test_client
        .submit_all_blocking([
            create_sender_account,
            create_receiver_account
        ])
        .expect("Failed to sumbit precondition instructions");

    test_client
        .submit_blocking(register_asset_definition)
        .expect("Failed to register asset definition");
    test_client
        .submit_blocking(register_asset.clone())
        .expect("Failed to register asset");

    let chain_id_0 = ChainId::new("0"); // Value configured by default
    let chain_id_1 = ChainId::new("1");

    let transfer_instruction = Transfer::asset_quantity(
        asset_id_new("test_asset", "wonderland", sender_account_id.clone()),
        to_transfer,
        receiver_account_id.clone(),
    );
    let asset_transfer_tx_0 = TransactionBuilder::new(chain_id_0, sender_account_id.clone())
        .with_instructions([transfer_instruction.clone()])
        .sign(&sender_keypair.clone());
    let asset_transfer_tx_1 = TransactionBuilder::new(chain_id_1, sender_account_id.clone())
        .with_instructions([transfer_instruction])
        .sign(&sender_keypair);
    test_client
        .submit_transaction_blocking(&asset_transfer_tx_0)
        .unwrap();
    let _err = test_client
        .submit_transaction_blocking(&asset_transfer_tx_1)
        .unwrap_err();
}
