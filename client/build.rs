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

    Ok(())
}
