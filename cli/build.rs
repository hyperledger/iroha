//! Build script to extract git hash of iroha build and to check runtime validator

use eyre::{eyre, Result, WrapErr};

const DEFAULT_VALIDATOR_PATH: &str = "../default_validator";

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={DEFAULT_VALIDATOR_PATH}");

    extract_git_hash()?;

    // HACK: used by Nix, since at the moment
    // the checks are a process that's hard to accomodate
    // in Nix environment
    if std::option_env!("IROHA_SKIP_WASM_CHECKS").is_none() {
        check_default_validator()?;
    }

    Ok(())
}

fn extract_git_hash() -> Result<()> {
    vergen::EmitBuilder::builder()
        .git_sha(true)
        .cargo_features()
        .emit()
        .map_err(|err| eyre!(Box::new(err)))
        .wrap_err("Failed to extract git hash")
}

/// Apply `cargo check` to the smartcontract.
fn check_default_validator() -> Result<()> {
    iroha_wasm_builder::Builder::new(DEFAULT_VALIDATOR_PATH)
        .format()
        .check()
}
