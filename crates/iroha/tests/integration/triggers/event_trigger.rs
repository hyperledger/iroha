use eyre::Result;
use iroha::{client, client::Client, data_model::prelude::*};
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;

#[test]
fn test_mint_asset_when_new_asset_definition_created() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let prev_value = get_asset_value(&test_client, asset_id.clone());

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            account_id,
            AssetDefinitionEventFilter::new().for_events(AssetDefinitionEventSet::Created),
        ),
    ));
    test_client.submit(register_trigger)?;

    let tea_definition_id = "tea#wonderland".parse()?;
    let register_tea_definition =
        Register::asset_definition(AssetDefinition::new(tea_definition_id));
    test_client.submit_blocking(register_tea_definition)?;

    let new_value = get_asset_value(&test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

fn get_asset_value(client: &Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();
    *asset.value()
}
