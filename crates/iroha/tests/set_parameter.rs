use eyre::Result;
use iroha::data_model::{
    parameter::{BlockParameter, Parameter, Parameters},
    prelude::*,
};
use iroha_test_network::*;
use nonzero_ext::nonzero;

#[test]
fn can_change_parameter_value() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new()
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(16u64)),
        )))
        .start_blocking()?;
    let test_client = network.client();

    let old_params: Parameters = test_client.query_single(FindParameters::new())?;
    assert_eq!(old_params.block().max_transactions(), nonzero!(16u64));

    let new_value = nonzero!(32u64);
    test_client.submit_blocking(SetParameter::new(Parameter::Block(
        BlockParameter::MaxTransactions(new_value),
    )))?;

    let params = test_client.query_single(FindParameters::new())?;
    assert_eq!(params.block().max_transactions(), new_value);

    Ok(())
}
