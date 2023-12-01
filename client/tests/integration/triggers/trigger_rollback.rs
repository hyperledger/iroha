use std::str::FromStr as _;

use eyre::Result;
use iroha_client::{
    client::QueryResult,
    data_model::{prelude::*, query::asset::FindAllAssetsDefinitions, trigger::TriggerId},
};
use test_network::*;

#[test]
fn failed_trigger_revert() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(11_110).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    //When
    let trigger_id = TriggerId::from_str("trigger")?;
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland")?;
    let create_asset = RegisterExpr::new(AssetDefinition::quantity(asset_definition_id.clone()));
    let instructions: [InstructionExpr; 2] = [create_asset.into(), Fail::new("Always fail").into()];
    let register_trigger = RegisterExpr::new(Trigger::new(
        trigger_id.clone(),
        Action::new(
            instructions,
            Repeats::Indefinitely,
            account_id.clone(),
            TriggeringFilterBox::ExecuteTrigger(ExecuteTriggerEventFilter::new(
                trigger_id.clone(),
                account_id,
            )),
        ),
    ));
    let _ = client.submit_blocking(register_trigger);

    let call_trigger = ExecuteTriggerExpr::new(trigger_id);
    client.submit_blocking(call_trigger)?;

    //Then
    let request = FindAllAssetsDefinitions;
    let query_result = client.request(request)?.collect::<QueryResult<Vec<_>>>()?;
    assert!(query_result
        .iter()
        .all(|asset_definition| asset_definition.id() != &asset_definition_id));
    Ok(())
}
