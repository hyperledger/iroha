#![allow(clippy::restriction)]

use std::str::FromStr;

use eyre::Result;
use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn can_change_parameter_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_800).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let parameter = Parameter::from_str("?BlockSyncGossipPeriod=20000")?;
    let parameter_id = ParameterId::from_str("BlockSyncGossipPeriod")?;
    let param_box = SetParameterBox::new(parameter);

    let old_params = test_client.request(client::parameter::all())?;
    let param_val_old = old_params
        .iter()
        .find(|param| param.id() == &parameter_id)
        .expect("Parameter should exist")
        .val();

    test_client.submit_blocking(param_box)?;

    let new_params = test_client.request(client::parameter::all())?;

    let param_val_new = new_params
        .iter()
        .find(|param| param.id() == &parameter_id)
        .expect("Parameter should exist")
        .val();

    assert_ne!(param_val_old, param_val_new);
    Ok(())
}
