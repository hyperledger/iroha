use std::str::FromStr as _;

use eyre::Result;
use iroha::{
    client,
    data_model::{prelude::*, trigger::TriggerId},
};
use test_network::*;
use test_samples::ALICE_ID;

#[test]
fn failed_trigger_revert() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_150).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    //When
    let trigger_id = TriggerId::from_str("trigger")?;
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland")?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    let fail_isi = Unregister::domain("dummy".parse().unwrap());
    let instructions: [InstructionBox; 2] = [create_asset.into(), fail_isi.into()];
    let register_trigger = Register::trigger(Trigger::new(
        trigger_id.clone(),
        Action::new(
            instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            ExecuteTriggerEventFilter::new()
                .for_trigger(trigger_id.clone())
                .under_authority(account_id),
        ),
    ));
    let _ = client.submit_blocking(register_trigger);

    let call_trigger = ExecuteTrigger::new(trigger_id);
    client.submit_blocking(call_trigger)?;

    //Then
    let query_result = client
        .query(client::asset::all_definitions())
        .execute_all()?;
    assert!(query_result
        .iter()
        .all(|asset_definition| asset_definition.id() != &asset_definition_id));
    Ok(())
}
