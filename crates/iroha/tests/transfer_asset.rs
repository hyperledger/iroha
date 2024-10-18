use iroha::{
    client,
    data_model::{
        account::{Account, AccountId},
        asset::{Asset, AssetDefinition},
        isi::{Instruction, InstructionBox},
        prelude::*,
        Registered,
    },
};
use iroha_test_network::*;
use iroha_test_samples::{gen_account_in, ALICE_ID};

#[test]
// This test suite is also covered at the UI level in the iroha_cli tests
// in test_tranfer_assets.py
fn simulate_transfer_numeric() {
    simulate_transfer(
        numeric!(200),
        &numeric!(20),
        AssetDefinition::numeric,
        Mint::asset_numeric,
        Transfer::asset_numeric,
    )
}

#[test]
fn simulate_transfer_store_asset() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let (alice_id, mouse_id) = generate_two_ids();
    let create_mouse = create_mouse(mouse_id.clone());
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().unwrap();
    let create_asset =
        Register::asset_definition(AssetDefinition::store(asset_definition_id.clone()));
    let set_key_value = SetKeyValue::asset(
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        "alicek".parse().unwrap(),
        true,
    );

    iroha
        .submit_all_blocking::<InstructionBox>([
            // create_alice.into(), We don't need to register Alice, because she is created in genesis
            create_mouse.into(),
            create_asset.into(),
            set_key_value.into(),
        ])
        .expect("Failed to prepare state.");

    let transfer_asset = Transfer::asset_store(
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
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
            *asset.id().definition() == asset_definition_id && *asset.id().account() == mouse_id
        }));
}

fn simulate_transfer<T>(
    starting_amount: T,
    amount_to_transfer: &T,
    asset_definition_ctr: impl FnOnce(AssetDefinitionId) -> <AssetDefinition as Registered>::With,
    mint_ctr: impl FnOnce(T, AssetId) -> Mint<T, Asset>,
    transfer_ctr: impl FnOnce(AssetId, T, AccountId) -> Transfer<Asset, T, Account>,
) where
    T: std::fmt::Debug + Clone + Into<AssetValue>,
    Mint<T, Asset>: Instruction,
    Transfer<Asset, T, Account>: Instruction,
{
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let iroha = network.client();

    let (alice_id, mouse_id) = generate_two_ids();
    let create_mouse = create_mouse(mouse_id.clone());
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().unwrap();
    let create_asset =
        Register::asset_definition(asset_definition_ctr(asset_definition_id.clone()));
    let mint_asset = mint_ctr(
        starting_amount,
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
    );

    let instructions: [InstructionBox; 3] = [
        // create_alice.into(), We don't need to register Alice, because she is created in genesis
        create_mouse.into(),
        create_asset.into(),
        mint_asset.into(),
    ];
    iroha
        .submit_all_blocking(instructions)
        .expect("Failed to prepare state.");

    //When
    let transfer_asset = transfer_ctr(
        AssetId::new(asset_definition_id.clone(), alice_id),
        amount_to_transfer.clone(),
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
                && *asset.value() == amount_to_transfer.clone().into()
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
