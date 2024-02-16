use std::str::FromStr as _;

use eyre::Result;
use iroha_client::data_model::prelude::*;
use iroha_telemetry::metrics::Status;
use parity_scale_codec::DecodeAll;
use test_network::*;

fn status_eq_excluding_uptime_and_queue(lhs: &Status, rhs: &Status) -> bool {
    lhs.peers == rhs.peers
        && lhs.blocks == rhs.blocks
        && lhs.txs_accepted == rhs.txs_accepted
        && lhs.txs_rejected == rhs.txs_rejected
        && lhs.view_changes == rhs.view_changes
}

#[test]
fn json_and_scale_statuses_equality() -> Result<()> {
    let (_rt, network, client) = Network::start_test_with_runtime(1, Some(10_935));
    wait_for_genesis_committed(&network.clients(), 0);

    let json_status_zero = client.get_status().unwrap();

    let scale_status_zero = client.get_status_scale_encoded().unwrap();
    let scale_status_zero_decoded: Status =
        DecodeAll::decode_all(&mut scale_status_zero.as_slice())?;

    assert!(
        status_eq_excluding_uptime_and_queue(&json_status_zero, &scale_status_zero_decoded),
        "get_status() result is not equal to decoded get_status_scale_encoded()"
    );

    let coins = ["xor", "btc", "eth", "doge"];

    for coin in coins {
        let asset_definition_id = AssetDefinitionId::from_str(&format!("{}#wonderland", coin))?;
        let create_asset =
            Register::asset_definition(AssetDefinition::quantity(asset_definition_id.clone()));
        client.submit_blocking(create_asset)?;
    }

    let json_status_coins = client.get_status().unwrap();

    let scale_status_coins = client.get_status_scale_encoded().unwrap();
    let scale_status_coins_decoded: Status =
        DecodeAll::decode_all(&mut scale_status_coins.as_slice())?;

    assert!(
        status_eq_excluding_uptime_and_queue(&json_status_coins, &scale_status_coins_decoded),
        "get_status() result is not equal to decoded get_status_scale_encoded()"
    );

    Ok(())
}
