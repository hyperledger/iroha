use std::{
    io::Read,
    path::{Path, PathBuf},
};

use iroha_data_model::prelude::WasmSmartContract;

mod integration;

fn read_file(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut blob = vec![];
    std::fs::File::open(path.as_ref())?.read_to_end(&mut blob)?;
    Ok(blob)
}

const WASM_SAMPLES_PREBUILT_DIR: &str = "wasm_samples/target/prebuilt";

/// Load WASM smart contract from `wasm_samples` by the name of smart contract,
/// e.g. `default_executor`.
///
/// WASMs must be pre-built with the `build_wasm_samples.sh` script
fn load_sample_wasm(name: impl AsRef<str>) -> WasmSmartContract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(WASM_SAMPLES_PREBUILT_DIR)
        .join(name.as_ref())
        .with_extension("wasm");

    let blob = match read_file(&path) {
        Err(err) => {
            eprintln!(
                "ERROR: Could not load sample WASM `{}` from `{}`: {err}\n  \
                    There are two possible reasons why:\n    \
                    1. You haven't pre-built WASM samples before running tests. Make sure to run `build_wasm_samples.sh` first.\n    \
                    2. `{}` is not a valid name. Check the `wasm_samples` directory and make sure you haven't made a mistake.",
                name.as_ref(),
                path.display(),
                name.as_ref()
            );
            panic!("could not build WASM, see the message above");
        }
        Ok(blob) => blob,
    };

    WasmSmartContract::from_compiled(blob)
}
