use iroha_client::{
    client::{self, QueryResult},
    crypto::KeyPair,
    data_model::{prelude::*, Registered},
};
use iroha_primitives::fixed::Fixed;
use test_network::*;

#[test]
fn simulate_transfer_quantity() {
    simulate_transfer(200_u32, &20_u32, AssetDefinition::quantity, 10_710)
}

#[test]
fn simulate_transfer_big_quantity() {
    simulate_transfer(200_u128, &20_u128, AssetDefinition::big_quantity, 10_785)
}

#[test]
fn simulate_transfer_fixed() {
    simulate_transfer(
        Fixed::try_from(200_f64).expect("Valid"),
        &Fixed::try_from(20_f64).expect("Valid"),
        AssetDefinition::fixed,
        10_790,
    )
}

#[should_panic]
#[test]
#[ignore = "long"]
fn simulate_insufficient_funds() {
    simulate_transfer(
        Fixed::try_from(20_f64).expect("Valid"),
        &Fixed::try_from(200_f64).expect("Valid"),
        AssetDefinition::fixed,
        10_800,
    )
}

// TODO add tests when the transfer uses the wrong AssetId.

fn simulate_transfer<
    T: Into<AssetValue> + Clone,
    D: FnOnce(AssetDefinitionId) -> <AssetDefinition as Registered>::With,
>(
    starting_amount: T,
    amount_to_transfer: &T,
    value_type: D,
    port_number: u16,
) where
    Value: From<T>,
{
    let (_rt, _peer, iroha_client) = <PeerBuilder>::new()
        .with_port(port_number)
        .start_with_runtime();
    wait_for_genesis_committed(&[iroha_client.clone()], 0);

    let alice_id: AccountId = "alice@wonderland".parse().expect("Valid");
    let mouse_id: AccountId = "mouse@wonderland".parse().expect("Valid");
    let (bob_public_key, _) = KeyPair::generate()
        .expect("Failed to generate KeyPair")
        .into();
    let create_mouse = RegisterExpr::new(Account::new(mouse_id.clone(), [bob_public_key]));
    let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().expect("Valid");
    let create_asset = RegisterExpr::new(value_type(asset_definition_id.clone()));
    let mint_asset = MintExpr::new(
        starting_amount.to_value(),
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id.clone())),
    );

    let instructions: [InstructionExpr; 3] = [
        // create_alice.into(), We don't need to register Alice, because she is created in genesis
        create_mouse.into(),
        create_asset.into(),
        mint_asset.into(),
    ];
    iroha_client
        .submit_all_blocking(instructions)
        .expect("Failed to prepare state.");

    //When
    let transfer_asset = TransferExpr::new(
        IdBox::AssetId(AssetId::new(asset_definition_id.clone(), alice_id)),
        amount_to_transfer.clone().to_value(),
        IdBox::AccountId(mouse_id.clone()),
    );
    iroha_client
        .submit_till(
            transfer_asset,
            client::asset::by_account_id(mouse_id.clone()),
            |result| {
                let assets = result.collect::<QueryResult<Vec<_>>>().expect("Valid");

                assets.iter().any(|asset| {
                    asset.id().definition_id == asset_definition_id
                        && *asset.value() == amount_to_transfer.clone().into()
                        && asset.id().account_id == mouse_id
                })
            },
        )
        .expect("Test case failure.");
}
