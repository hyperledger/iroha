//! Compile binary containing common logic to each multisig account for handling multisig transactions

use std::{io::Write, path::Path};

const TRIGGER_DIR: &str = "../multisig_transactions";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        TRIGGER_DIR,
        "../../crates/iroha_data_model/src",
        "../../crates/iroha_core/src/smartcontracts",
        "../../crates/iroha_smart_contract/src",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let wasm = iroha_wasm_builder::Builder::new(TRIGGER_DIR)
        .show_output()
        .build()?
        .optimize()?
        .into_bytes()?;

    let mut file = std::fs::File::create(Path::new(&out_dir).join("multisig_transactions.wasm"))?;
    file.write_all(&wasm)?;
    Ok(())
}
