//! Build script which builds smartcontracts for test
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)

use std::{env, fs, path::Path};

use eyre::{Result, WrapErr as _};

fn main() -> Result<()> {
    const TEST_SMARTCONTRACTS_DIR: &str = "tests/integration/smartcontracts";

    println!("cargo:rerun-if-changed={TEST_SMARTCONTRACTS_DIR}");

    check_all_smartcontracts(TEST_SMARTCONTRACTS_DIR)
}

fn check_all_smartcontracts(path: impl AsRef<Path>) -> Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .wrap_err("Expected `CARGO_MANIFEST_DIR` environment variable")?;

    let full_smartcontracts_path = Path::new(&manifest_dir).join(path.as_ref());

    for entry in fs::read_dir(full_smartcontracts_path)
        .wrap_err("Failed to read test smartcontracts directory: {full_smartcontracts_path}")?
    {
        let entry = entry.wrap_err("Failed to read test smartcontracts directory entry")?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();
        if !entry
            .file_type()
            .wrap_err_with(|| format!("Failed to get file type of entry: {}", file_name_str))?
            .is_dir()
        {
            continue;
        }

        iroha_wasm_builder::Builder::new(&path.as_ref().join(file_name.clone()))
            .format()
            .check()
            .wrap_err_with(|| {
                format!(
                    "Failed to format and check smartcontract at path: {}",
                    file_name_str
                )
            })?;
    }

    Ok(())
}
