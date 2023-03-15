//! Build script to extract git hash of iroha build and to check runtime permission validators

use eyre::{eyre, Result};
use vergen::{vergen, Config};

const DEFAULT_PERMISSION_VALIDATOR_PATH: &str = "../default_validator";

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        DEFAULT_PERMISSION_VALIDATOR_PATH
    );

    extract_git_hash()?;
    check_default_validator()
}

fn extract_git_hash() -> Result<()> {
    let mut config = Config::default();
    *config.git_mut().branch_mut() = false;
    *config.git_mut().commit_timestamp_mut() = false;
    *config.git_mut().semver_mut() = false;
    vergen(config).map_err(|err| eyre!(Box::new(err)))
}

fn check_default_validator() -> Result<()> {
    iroha_wasm_builder::Builder::new(DEFAULT_PERMISSION_VALIDATOR_PATH)
        .format()
        .check()?;
    Ok(())
}
