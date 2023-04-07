#![allow(clippy::restriction)]

use eyre::{Context as _, Result};
use iroha_data_model::{
    permission::{validator, Validator},
    prelude::*,
    transaction::WasmSmartContract,
};
use iroha_logger::info;
use test_network::*;

#[test]
fn deny_new_validators() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().with_port(10_755).start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    info!("Building Runtime Validator");

    let temp_out_dir =
        tempfile::tempdir().wrap_err("Failed to create temporary output directory")?;

    let wasm = iroha_wasm_builder::Builder::new(
        "tests/integration/smartcontracts/deny_new_validators_validator",
    )
    .out_dir(temp_out_dir.path())
    .build()?
    .optimize()?
    .into_bytes();

    temp_out_dir
        .close()
        .wrap_err("Failed to remove temporary output directory")?;

    info!("WASM size is {} bytes", wasm.len());

    let validator = Validator::new(
        "deny_new_validators%alice@wonderland".parse().unwrap(),
        validator::ValidatorType::Instruction,
        WasmSmartContract::new(wasm.clone()),
    );
    info!("Submitting registration of the validator (should pass)");
    test_client.submit_blocking(RegisterBox::new(validator))?;

    // Trying to register the validator again
    let validator_2 = Validator::new(
        "deny_new_validators_2%alice@wonderland".parse().unwrap(),
        validator::ValidatorType::Instruction,
        WasmSmartContract::new(wasm),
    );
    info!("Submitting registration of a new validator (should fail)");
    let error = test_client
        .submit_blocking(RegisterBox::new(validator_2))
        .expect_err("Registration of a new validator should be denied");
    info!(?error);
    assert!(error
        .chain()
        .any(|err| err.to_string().contains("New validators are not allowed")));
    Ok(())
}
