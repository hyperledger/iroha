//! Integration coverage for installing and executing a real IVM executor.
use eyre::Result;
use integration_tests::sandbox;
use iroha::data_model::prelude::*;
use iroha_test_network::{IvmFuelConfig, NetworkBuilder};
const CANONICAL_EXECUTOR: &[u8] = include_bytes!("../../defaults/executor.to");
#[test]
fn canonical_guest_executor_upgrade_works() -> Result<()> {
    let builder = NetworkBuilder::new()
        .with_ivm_fuel(IvmFuelConfig::Auto)
        .with_min_peers(4);
    let Some((network, _runtime)) = sandbox::start_network_blocking_or_skip(
        builder,
        stringify!(canonical_guest_executor_upgrade_works),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    let initial_data_model = client.client().query_single(FindExecutorDataModel)?;
    let upgrade = Upgrade::new(Executor::new(IvmBytecode::from_compiled(
        CANONICAL_EXECUTOR.to_vec(),
    )));
    client.submit(upgrade, FeePaymentIntent::authority(Vec::new(), None))?;
    client.submit(
        Log::new(Level::INFO, "canonical executor is active".to_owned()),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    assert_eq!(
        client.client().query_single(FindExecutorDataModel)?,
        initial_data_model,
        "a unit migration result must retain the current executor data model"
    );
    Ok(())
}
