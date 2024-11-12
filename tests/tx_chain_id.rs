use iroha::data_model::prelude::*;
use iroha_primitives::numeric::numeric;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;

#[test]
fn send_tx_with_different_chain_id() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();
    // Given
    let (sender_id, sender_keypair) = gen_account_in("wonderland");
    let (receiver_id, _receiver_keypair) = gen_account_in("wonderland");
    let asset_definition_id = "test_asset#wonderland"
        .parse::<AssetDefinitionId>()
        .unwrap();
    let to_transfer = numeric!(1);

    let create_sender_account = Register::account(Account::new(sender_id.clone()));
    let create_receiver_account = Register::account(Account::new(receiver_id.clone()));
    let register_asset_definition =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let register_asset = Register::asset(Asset::new(
        AssetId::new(asset_definition_id.clone(), sender_id.clone()),
        numeric!(10),
    ));
    test_client
        .submit_all_blocking::<InstructionBox>([
            create_sender_account.into(),
            create_receiver_account.into(),
            register_asset_definition.into(),
            register_asset.into(),
        ])
        .unwrap();
    let chain_id_0 = network.chain_id();
    let chain_id_1 = ChainId::from("1");
    assert_ne!(chain_id_0, chain_id_1);

    let transfer_instruction = Transfer::asset_numeric(
        AssetId::new("test_asset#wonderland".parse().unwrap(), sender_id.clone()),
        to_transfer,
        receiver_id.clone(),
    );
    let asset_transfer_tx_0 = TransactionBuilder::new(chain_id_0, sender_id.clone())
        .with_instructions([transfer_instruction.clone()])
        .sign(sender_keypair.private_key());
    let asset_transfer_tx_1 = TransactionBuilder::new(chain_id_1, sender_id.clone())
        .with_instructions([transfer_instruction])
        .sign(sender_keypair.private_key());
    test_client
        .submit_transaction_blocking(&asset_transfer_tx_0)
        .unwrap();
    let _err = test_client
        // no need for "blocking" - it must be rejected synchronously
        .submit_transaction(&asset_transfer_tx_1)
        .unwrap_err();
}
