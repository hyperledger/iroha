use std::time::Duration;

use eyre::Result;
use iroha::{
    client,
    data_model::{
        parameter::{Parameter, Parameters, SumeragiParameter, SumeragiParameters},
        prelude::*,
    },
};
use iroha_test_network::*;

#[test]
fn can_change_parameter_value() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new()
        .with_default_pipeline_time()
        .start_blocking()?;
    let test_client = network.client();

    let old_params: Parameters = test_client.query_single(client::parameter::all())?;
    assert_eq!(
        old_params.sumeragi().block_time(),
        SumeragiParameters::default().block_time()
    );

    let block_time = 40_000;
    let parameter = Parameter::Sumeragi(SumeragiParameter::BlockTimeMs(block_time));
    let set_param_isi = SetParameter::new(parameter);
    test_client.submit_blocking(set_param_isi)?;

    let sumeragi_params = test_client.query_single(client::parameter::all())?.sumeragi;
    assert_eq!(
        sumeragi_params.block_time(),
        Duration::from_millis(block_time)
    );

    Ok(())
}
