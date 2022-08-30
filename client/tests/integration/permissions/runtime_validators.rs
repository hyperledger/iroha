#![allow(clippy::restriction)]

use std::fs;

use eyre::{Context as _, Result};
use iroha_data_model::{
    permission::{validator, Validator},
    prelude::*,
    transaction::WasmSmartContract,
};
use test_network::*;

#[test]
// TODO: Maybe activate with a feature,
// which will be enabled in the build-script when `nightly` is enabled?
// Same for `mint_nft_for_every_use_every_1_sec()` test.
#[ignore = "Only on nightly"]
fn deny_new_validators() -> Result<()> {
    let (_rt, _peer, test_client) = <PeerBuilder>::new().start_with_runtime();
    wait_for_genesis_committed(&vec![test_client.clone()], 0);

    let filename = concat!(
        env!("OUT_DIR"),
        "/wasm32-unknown-unknown/release/deny_new_validators_validator.wasm"
    );
    println!("Reading wasm from {filename}");

    let wasm = fs::read(filename).wrap_err("Can't read smartcontract")?;
    println!("wasm size is {} bytes", wasm.len());

    let validator = Validator::new(
        "deny_new_validators%alice@wonderland".parse().unwrap(),
        validator::Type::Instruction,
        WasmSmartContract {
            raw_data: wasm.clone(),
        },
    );
    test_client.submit_blocking(RegisterBox::new(validator))?;

    // Trying to register the validator again
    let validator_2 = Validator::new(
        "deny_new_validators_2%alice@wonderland".parse().unwrap(),
        validator::Type::Instruction,
        WasmSmartContract { raw_data: wasm },
    );
    let error_mes = test_client
        .submit_blocking(RegisterBox::new(validator_2))
        .expect_err("Registration of a new validator should be denied")
        .to_string();
    assert!(error_mes.contains("New validators are not allowed"));
    Ok(())
}
