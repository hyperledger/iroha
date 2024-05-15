use std::str::FromStr;

use iroha_data_model::prelude::*;
use iroha_primitives::numeric::numeric;
use test_network::*;
use test_samples::gen_account_in;

#[test]
fn send_tx_with_different_chain_id() {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(11_250).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);
    // Given
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _receiver_keypair) = gen_account_in("wonderland");
    let asset_definition_id = AssetDefinitionId::from_str("test_asset#wonderland").unwrap();
    let to_transfer = numeric!(1);

    let create_sender_account: InstructionBox =
        Register::account(Account::new(sender_id.clone())).into();
    let create_receiver_account: InstructionBox =
        Register::account(Account::new(receiver_id.clone())).into();
    let register_asset_definition: InstructionBox =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone())).into();
    let register_asset: InstructionBox = Register::asset(Asset::new(
        AssetId::new(asset_definition_id.clone(), sender_id.clone()),
        numeric!(10),
    ))
    .into();
    test_client
        .submit_all_blocking([
            create_sender_account,
            create_receiver_account,
            register_asset_definition,
            register_asset,
        ])
        .unwrap();
    let chain_id_0 = ChainId::from("0"); // Value configured by default
    let chain_id_1 = ChainId::from("1");

    let transfer_instruction = Transfer::asset_numeric(
        AssetId::new("test_asset#wonderland".parse().unwrap(), sender_id.clone()),
        to_transfer,
        receiver_id.clone(),
    );
    let asset_transfer_tx_0 = TransactionBuilder::new(chain_id_0, sender_id.clone())
        .with_instructions([transfer_instruction.clone()])
        .sign(&sender_keypair);
    let asset_transfer_tx_1 = TransactionBuilder::new(chain_id_1, sender_id.clone())
        .with_instructions([transfer_instruction])
        .sign(&sender_keypair);
    test_client
        .submit_transaction_blocking(&asset_transfer_tx_0)
        .unwrap();
    let _err = test_client
        .submit_transaction_blocking(&asset_transfer_tx_1)
        .unwrap_err();
}
