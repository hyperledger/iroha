//! Build script to extract git hash of iroha build and to build runtime permission validators
use eyre::{eyre, Result};
use vergen::{vergen, Config};

const PERMISSION_VALIDATORS_PATH: &str = "../permission_validators";

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", PERMISSION_VALIDATORS_PATH);

    extract_git_hash()?;
    check_permission_validators()
}

fn extract_git_hash() -> Result<()> {
    let mut config = Config::default();
    *config.git_mut().branch_mut() = false;
    *config.git_mut().commit_timestamp_mut() = false;
    *config.git_mut().semver_mut() = false;
    vergen(config).map_err(|err| eyre!(Box::new(err)))
}

fn check_permission_validators() -> Result<()> {
    iroha_wasm_builder::Builder::new(PERMISSION_VALIDATORS_PATH)
        .format()
        .check()?;
    Ok(())
}
