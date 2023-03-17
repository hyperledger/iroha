//! Build script which checks smartcontracts for tests
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)

const TEST_SMARTCONTRACTS_DIR: &str = "tests/integration/smartcontracts";

fn main() -> eyre::Result<()> {
    println!("cargo:rerun-if-changed={TEST_SMARTCONTRACTS_DIR}");
    check_all_smartcontracts()
}

fn check_all_smartcontracts() -> eyre::Result<()> {
    iroha_wasm_builder::Builder::new(TEST_SMARTCONTRACTS_DIR)
        .format()
        .check()?;
    Ok(())
}
