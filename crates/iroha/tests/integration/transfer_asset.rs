use iroha::{
    client,
    data_model::{
        account::{Account, AccountId},
        isi::InstructionBox,
        prelude::*,
    },
};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID};

#[test]
// This test suite is also covered at the UI level in the iroha_cli tests
// in test_tranfer_assets.py
fn simulate_transfer_numeric() {
    simulate_transfer(numeric!(200), numeric!(20))
}

fn simulate_transfer(starting_amount: Numeric, amount_to_transfer: Numeric) {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let (alice_id, mouse_id) = generate_two_ids();
    let create_mouse = create_mouse(mouse_id.clone());
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().unwrap();
    let create_asset =
        Register::asset_definition(AssetDefinition::new(asset_definition_id.clone()));
    let mint_asset = Mint::asset_numeric(
        starting_amount,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );

    iroha
        .submit_all_blocking::<InstructionBox>([
            // We don't need to register Alice, because she is created in genesis
            create_mouse.into(),
            create_asset.into(),
            mint_asset.into(),
        ])
        .expect("Failed to prepare state.");

    //When
    let transfer_asset = Transfer::asset_numeric(
        AssetId::new(asset_definition_id.clone(), alice_id),
        amount_to_transfer,
        mouse_id.clone(),
    );
    iroha
        .submit_blocking(transfer_asset)
        .expect("Failed to transfer asset.");
    assert!(iroha
        .query(client::asset::all())
        .filter_with(|asset| asset.id.account.eq(mouse_id.clone()))
        .execute_all()
        .unwrap()
        .into_iter()
        .any(|asset| {
            *asset.id().definition() == asset_definition_id
                && *asset.value() == amount_to_transfer
                && *asset.id().account() == mouse_id
        }));
}

fn generate_two_ids() -> (AccountId, AccountId) {
    let alice_id = ALICE_ID.clone();
    let (mouse_id, _mouse_keypair) = gen_account_in("wonderland");
    (alice_id, mouse_id)
}

fn create_mouse(mouse_id: AccountId) -> Register<Account> {
    Register::account(Account::new(mouse_id))
}
