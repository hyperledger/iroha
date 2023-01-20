#![allow(clippy::restriction)]

use std::fs;

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
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let filename = concat!(
        env!("OUT_DIR"),
        "/wasm32-unknown-unknown/release/deny_new_validators_validator.wasm"
    );
    info!("Reading wasm from {filename}");

    let wasm = fs::read(filename).wrap_err("Can't read smartcontract")?;
    info!("wasm size is {} bytes", wasm.len());

    let validator = Validator::new(
        "deny_new_validators%alice@wonderland".parse().unwrap(),
        validator::Type::Instruction,
        WasmSmartContract {
            raw_data: wasm.clone(),
        },
    );
    info!("Submitting registration of the validator (should pass)");
    test_client.submit_blocking(RegisterBox::new(validator))?;

    // Trying to register the validator again
    let validator_2 = Validator::new(
        "deny_new_validators_2%alice@wonderland".parse().unwrap(),
        validator::Type::Instruction,
        WasmSmartContract { raw_data: wasm },
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
