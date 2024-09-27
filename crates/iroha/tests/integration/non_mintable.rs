use eyre::Result;
use iroha::data_model::{isi::InstructionBox, prelude::*};
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;

#[test]
fn non_mintable_asset_can_be_minted_once_but_not_twice() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_625).start_with_runtime();
    wait_for_genesis_committed(&[test_client.clone()], 0);

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = "xor#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let create_asset = Register::asset_definition(
        AssetDefinition::new(asset_definition_id.clone()).mintable_once(),
    );

    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());
    let mint = Mint::asset_numeric(numeric!(200), asset_id.clone());

    // We can register and mint the non-mintable token
    test_client
        .submit_all_blocking::<InstructionBox>([create_asset.into(), mint.clone().into()])?;
    assert_eq!(
        numeric!(200),
        test_client.query_single(FindAssetQuantityById::new(asset_id.clone()))?
    );

    // We can submit the request to mint again.
    test_client.submit(mint)?;
    // However, this will fail:
    assert_ne!(
        numeric!(400),
        test_client.query_single(FindAssetQuantityById::new(asset_id))?
    );
    Ok(())
}
