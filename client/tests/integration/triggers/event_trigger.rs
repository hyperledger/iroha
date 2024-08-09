use eyre::Result;
use iroha::{
    client::{self, Client},
    data_model::prelude::*,
};
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn test_mint_asset_when_new_asset_definition_created() -> Result<()> {
    let (_rt, _peer, mut test_client) = <PeerBuilder>::new().with_port(10_770).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let asset_definition_id = "rose#wonderland".parse()?;
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let prev_value = get_asset_value(&mut test_client, asset_id.clone());

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
        Register::asset_definition(AssetDefinition::numeric(tea_definition_id));
    test_client.submit_blocking(register_tea_definition)?;

    let new_value = get_asset_value(&mut test_client, asset_id);
    assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());

    Ok(())
}

fn get_asset_value(client: &mut Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();

    let AssetValue::Numeric(val) = *asset.value() else {
        panic!("Unexpected asset value");
    };

    val
}
