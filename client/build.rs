//! Build script which builds smartcontract for test
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)

use std::{env, path::Path, process::Command};

#[allow(clippy::expect_used)]
fn main() {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("Expected `CARGO_MANIFEST_DIR` environment variable");
    let smartcontract_path =
        Path::new(&manifest_dir).join("tests/integration/create_nft_for_every_user_smartcontract");
    let out_dir = env::var_os("OUT_DIR").expect("Expected `OUT_DIR` environment variable");

    println!("cargo:rerun-if-changed=..");

    let fmt = Command::new("cargo")
        // Removing environment variable to avoid
        // `error: infinite recursion detected` when running `cargo lints`
        .env_remove("RUST_RECURSION_COUNT")
        .current_dir(smartcontract_path.clone())
        .args(&["+nightly-2022-04-20", "fmt", "--all"])
        .status()
        .expect("Failed to run `cargo fmt` on smartcontract");
    assert!(fmt.success(), "Can't format smartcontract");

    let build = Command::new("cargo")
        // Removing environment variable to avoid
        // `error: infinite recursion detected` when running `cargo lints`
        .env_remove("RUST_RECURSION_COUNT")
        .env("CARGO_TARGET_DIR", out_dir)
        .current_dir(smartcontract_path)
        .args(&[
            "+nightly-2022-04-20",
            "build",
            "--release",
            "-Z",
            "build-std",
            "-Z",
            "build-std-features=panic_immediate_abort",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .status()
        .expect("Failed to run `cargo build` on smartcontract");
    assert!(build.success(), "Can't build smartcontract")
}
