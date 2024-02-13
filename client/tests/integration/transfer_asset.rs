use std::str::FromStr;

use iroha_client::{
    client::{self, QueryResult},
    crypto::KeyPair,
    data_model::{isi::Instruction, prelude::*, Registered},
};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{Asset, AssetDefinition},
    isi::InstructionBox,
    name::Name,
};
use iroha_primitives::fixed::Fixed;
use test_network::*;

#[test]
fn simulate_transfer_quantity() {
    simulate_transfer(
        200_u32,
        &20_u32,
        AssetDefinition::quantity,
        Mint::asset_quantity,
        Transfer::asset_quantity,
        10_710,
    )
}

#[test]
fn simulate_transfer_big_quantity() {
    simulate_transfer(
        200_u128,
        &20_u128,
        AssetDefinition::big_quantity,
        Mint::asset_big_quantity,
        Transfer::asset_big_quantity,
        10_785,
    )
}

#[test]
fn simulate_transfer_fixed() {
    simulate_transfer(
        Fixed::try_from(200_f64).unwrap(),
        &Fixed::try_from(20_f64).unwrap(),
        AssetDefinition::fixed,
        Mint::asset_fixed,
        Transfer::asset_fixed,
        10_790,
    )
}

#[test]
#[ignore = "long"]
#[should_panic(expected = "insufficient funds")]
fn simulate_insufficient_funds() {
    simulate_transfer(
        Fixed::try_from(20_f64).unwrap(),
        &Fixed::try_from(200_f64).unwrap(),
        AssetDefinition::fixed,
        Mint::asset_fixed,
        Transfer::asset_fixed,
        10_800,
    )
}

#[test]
fn simulate_transfer_store_asset() {
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new().with_port(10_805).start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);
    let (alice_id, mouse_id) = generate_two_ids();
    let create_mouse = create_mouse(mouse_id.clone());
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().unwrap();
    let create_asset =
        Register::asset_definition(AssetDefinition::store(asset_definition_id.clone()));
    let set_key_value = SetKeyValue::asset(
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        Name::from_str("alicek").unwrap(),
        true,
    );

    let instructions: [InstructionBox; 3] = [
        // create_alice.into(), We don't need to register Alice, because she is created in genesis
        create_mouse.into(),
        create_asset.into(),
        set_key_value.into(),
    ];

    iroha_client
        .submit_all_blocking(instructions)
        .expect("Failed to prepare state.");

    let transfer_asset = Transfer::asset_store(
        AssetId::new(asset_definition_id.clone(), alice_id.clone()),
        mouse_id.clone(),
    );
    let transfer_box: InstructionBox = transfer_asset.into();

    iroha_client
        .submit_till(
            transfer_box,
            client::asset::by_account_id(mouse_id.clone()),
            |result| {
                let assets = result.collect::<QueryResult<Vec<_>>>().unwrap();
                assets.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && asset.id().account_id == mouse_id
                })
            },
        )
        .expect("Test case failure.");
}

fn simulate_transfer<T>(
    starting_amount: T,
    amount_to_transfer: &T,
    asset_definition_ctr: impl FnOnce(AssetDefinitionId) -> <AssetDefinition as Registered>::With,
    mint_ctr: impl FnOnce(T, AssetId) -> Mint<T, Asset>,
    transfer_ctr: impl FnOnce(AssetId, T, AccountId) -> Transfer<Asset, T, Account>,
    port_number: u16,
) where
    T: std::fmt::Debug + Clone + Into<AssetValue>,
    Value: From<T>,
    Mint<T, Asset>: Instruction,
    Transfer<Asset, T, Account>: Instruction,
{
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new()
        .with_port(port_number)
        .start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

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
    iroha_client
        .submit_all_blocking(instructions)
        .expect("Failed to prepare state.");

    //When
    let transfer_asset = transfer_ctr(
        AssetId::new(asset_definition_id.clone(), alice_id),
        amount_to_transfer.clone(),
        mouse_id.clone(),
    );
    iroha_client
        .submit_till(
            transfer_asset,
            client::asset::by_account_id(mouse_id.clone()),
            |result| {
                let assets = result.collect::<QueryResult<Vec<_>>>().unwrap();

                assets.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && *asset.value() == amount_to_transfer.clone().into()
                        && asset.id().account_id == mouse_id
                })
            },
        )
        .expect("Test case failure.");
}

fn generate_two_ids() -> (AccountId, AccountId) {
    let alice_id: AccountId = "alice@wonderland".parse().unwrap();
    let mouse_id: AccountId = "mouse@wonderland".parse().unwrap();
    (alice_id, mouse_id)
}

fn create_mouse(mouse_id: AccountId) -> Register<Account> {
    let (mouse_public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    Register::account(Account::new(mouse_id, [mouse_public_key]))
}
