//! Build script which checks smartcontracts for tests
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)
//! and [#4789](https://github.com/rust-lang/cargo/issues/4789)

use eyre::Result;

const TEST_SMARTCONTRACTS_DIR: &str = "tests/integration/smartcontracts";

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed={TEST_SMARTCONTRACTS_DIR}");

    // HACK: used by Nix, since at the moment
    // the checks are a process that's hard to accomodate
    // in Nix environment
    if std::option_env!("IROHA_SKIP_WASM_CHECKS").is_some() {
        check_all_smartcontracts()?;
    }

    Ok(())
}

fn check_all_smartcontracts() -> Result<()> {
    iroha_wasm_builder::Builder::new(TEST_SMARTCONTRACTS_DIR)
        .check()
}
