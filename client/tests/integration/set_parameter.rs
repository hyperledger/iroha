#![allow(clippy::restriction)]

use std::str::FromStr;

use eyre::Result;
use iroha_client::client;
use iroha_data_model::prelude::*;
use test_network::*;

#[test]
fn can_change_parameter_value() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_810).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let parameter = Parameter::from_str("?BlockTime=4000")?;
    let parameter_id = ParameterId::from_str("BlockTime")?;
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

#[test]
fn parameter_propagated() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_985).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let too_long_domain_name: DomainId = "0".repeat(2_usize.pow(8)).parse()?;
    let create_domain = RegisterBox::new(Domain::new(too_long_domain_name));
    let _ = test_client
        .submit_blocking(create_domain.clone())
        .expect_err("Should fail before ident length limits update");

    let parameter = Parameter::from_str("?WSVIdentLengthLimits=1,256_LL")?;
    let param_box = SetParameterBox::new(parameter);
    test_client.submit_blocking(param_box)?;

    test_client
        .submit_blocking(create_domain)
        .expect("Should work after ident length limits update");
    Ok(())
}
