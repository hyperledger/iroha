use eyre::Result;
use iroha::{data_model::prelude::*, samples::get_status_json};
use iroha_telemetry::metrics::Status;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;

fn status_eq_excluding_uptime_and_queue(lhs: &Status, rhs: &Status) -> bool {
    lhs.peers == rhs.peers
        && lhs.blocks == rhs.blocks
        && lhs.txs_accepted == rhs.txs_accepted
        && lhs.txs_rejected == rhs.txs_rejected
        && lhs.view_changes == rhs.view_changes
}

#[test]
fn json_and_scale_statuses_equality() -> Result<()> {
    let (_rt, network, client) = Network::start_test_with_runtime(2, Some(11_200));
    wait_for_genesis_committed(&network.clients(), 0);

    let json_status_zero = get_status_json(&client).unwrap();

    let scale_status_zero_decoded = client.get_status().unwrap();

    assert!(
        status_eq_excluding_uptime_and_queue(&json_status_zero, &scale_status_zero_decoded),
        "get_status() result is not equal to decoded get_status_scale_encoded()"
    );

    let coins = ["xor", "btc", "eth", "doge"];

    let (account_id, _account_keypair) = gen_account_in("domain");

    for coin in coins {
        let asset_definition_id = format!("{coin}#wonderland").parse::<AssetDefinitionId>()?;
        let create_asset =
            Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
        let mint_asset = Mint::asset_numeric(
            1234u32,
            AssetId::new(asset_definition_id, account_id.clone()),
        );
        client.submit_all::<InstructionBox>([create_asset.into(), mint_asset.into()])?;
    }

    let json_status_coins = get_status_json(&client).unwrap();

    let scale_status_coins_decoded = client.get_status().unwrap();

    assert!(
        status_eq_excluding_uptime_and_queue(&json_status_coins, &scale_status_coins_decoded),
        "get_status() result is not equal to decoded get_status_scale_encoded()"
    );

    Ok(())
}
