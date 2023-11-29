//! Build script to extract git hash of iroha build and to check runtime executor

use eyre::{eyre, Result, WrapErr};
use std::env;

const DEFAULT_EXECUTOR_PATH: &str = "../default_executor";

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={DEFAULT_EXECUTOR_PATH}");

    extract_git_hash()?;

    if env::var("PROFILE") == Ok("test".to_string()) {
        check_default_executor()?;
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
fn check_default_executor() -> Result<()> {
    iroha_wasm_builder::Builder::new(DEFAULT_EXECUTOR_PATH)
        .format()
        .check()
}
