#![allow(clippy::restriction)]

use eyre::Result;
use iroha_client::client;
use iroha_data_model::{metadata::UnlimitedMetadata, prelude::*};
use test_network::{Peer as TestPeer, *};

#[test]
fn non_mintable_asset_can_be_minted_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, mut test_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    // Given
    let account_id = AccountId::new("alice", "wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::new("xor", "wonderland").expect("Valid");
    let create_asset = RegisterBox::new(IdentifiableBox::from(
        AssetDefinition::new_quantity_token(asset_definition_id.clone()),
    ));

    let metadata = UnlimitedMetadata::default();

    let mint = MintBox::new(
        Value::U32(200_u32),
        IdBox::AssetId(AssetId::new(
            asset_definition_id.clone(),
            account_id.clone(),
        )),
    );

    let instructions: Vec<Instruction> = vec![create_asset.into(), mint.clone().into()];
    let tx = test_client.build_transaction(instructions.into(), metadata)?;

    // We can register and mint the non-mintable token
    test_client.submit_transaction(tx)?;
    test_client.poll_request(client::asset::by_account_id(account_id.clone()), |result| {
        result.iter().any(|asset| {
            asset.id.definition_id == asset_definition_id
                && asset.value == AssetValue::Quantity(200_u32)
        })
    })?;

    // We can submit the request to mint again.
    test_client.submit_all(vec![mint.into()])?;

    // However, this will fail
    assert!(test_client
        .poll_request(client::asset::by_account_id(account_id), |result| {
            result.iter().any(|asset| {
                asset.id.definition_id == asset_definition_id
                    && asset.value == AssetValue::Quantity(400_u32)
            })
        })
        .is_err());
    Ok(())
}
