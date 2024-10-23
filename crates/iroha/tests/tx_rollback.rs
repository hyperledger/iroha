use eyre::Result;
use iroha::{client, data_model::prelude::*};
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;

#[test]
fn client_sends_transaction_with_invalid_instruction_should_not_see_any_changes() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let client = network.client();

    //When
    let account_id = ALICE_ID.clone();
    let asset_definition_id = "xor#wonderland".parse()?;
    let wrong_asset_definition_id = "ksor#wonderland".parse::<AssetDefinitionId>()?;
    let create_asset = Register::asset_definition(AssetDefinition::new(asset_definition_id));
    let mint_asset = Mint::asset_numeric(
        200u32,
        AssetId::new(wrong_asset_definition_id.clone(), account_id.clone()),
    );
    let _ = client.submit_all_blocking::<InstructionBox>([create_asset.into(), mint_asset.into()]);

    //Then;
    let query_result = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.account.eq(account_id))
        .execute_all()?;

    assert!(query_result
        .iter()
        .all(|asset| *asset.id().definition() != wrong_asset_definition_id));
    let definition_query_result = client
        .query(client::asset::all_definitions())
        .execute_all()?;
    assert!(definition_query_result
        .iter()
        .all(|asset| *asset.id() != wrong_asset_definition_id));
    Ok(())
}
