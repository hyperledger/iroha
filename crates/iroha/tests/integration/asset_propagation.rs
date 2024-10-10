// use std::thread;

use eyre::Result;
use iroha::{
    client,
    data_model::{parameter::BlockParameter, prelude::*},
};
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;

#[test]
// This test is also covered at the UI level in the iroha_cli tests
// in test_mint_asset.py
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount_on_another_peer(
) -> Result<()> {
    // Given
    let (network, rt) = NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )))
        .start_blocking()?;
    let mut peers = network.peers().iter();
    let peer_a = peers.next().unwrap();
    let peer_b = peers.next().unwrap();

    let create_domain = Register::domain(Domain::new("domain".parse()?));
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id = "xor#domain".parse::<AssetDefinitionId>()?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    peer_a.client().submit_all_blocking::<InstructionBox>([
        create_domain.into(),
        create_account.into(),
        create_asset.into(),
    ])?;

    // When
    let quantity = numeric!(200);
    peer_a.client().submit_blocking(Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    ))?;
    rt.block_on(async { network.ensure_blocks(3).await })?;

    // Then
    let asset = peer_b
        .client()
        .query(client::asset::all())
        .filter_with(|asset| asset.id.account.eq(account_id))
        .execute_all()?
        .into_iter()
        .find(|asset| *asset.id().definition() == asset_definition_id)
        .expect("should be");
    assert_eq!(*asset.value(), AssetValue::Numeric(quantity));

    Ok(())
}
