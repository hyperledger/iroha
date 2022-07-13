//! Build script which builds smartcontract for test
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)

use std::{env, path::Path, process::Command};

#[allow(clippy::expect_used)]
fn main() {
    // Build and format the smartcontract if and only if the tests are
    // invoked with the nightly toolchain. We should not force our
    // users to have the `nightly` if we don't use any `nightly`
    // features in the actual binary.
    let rustc_version_output = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("Failed to run `rustc --version`");

    if std::str::from_utf8(&rustc_version_output.stdout)
        .expect("Garbage in `rustc --version` output")
        .contains("nightly")
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("Expected `CARGO_MANIFEST_DIR` environment variable");
        let smartcontract_path = Path::new(&manifest_dir)
            .join("tests/integration/create_nft_for_every_user_smartcontract");
        let out_dir = env::var_os("OUT_DIR").expect("Expected `OUT_DIR` environment variable");

        // TODO: check if this was causing the recursive loop.
        // println!("cargo:rerun-if-changed=..");

        let fmt = Command::new("rustfmt")
            .current_dir(smartcontract_path.clone())
            .args(&[smartcontract_path
                .join("src/lib.rs")
                .to_str()
                .expect("Can't convert smartcontract path to str")])
            .status()
            .expect("Failed to run `rustfmt` on smartcontract");
        assert!(fmt.success(), "Can't format smartcontract");

        // TODO: Remove cargo invocation (#2152)
        let build = Command::new("cargo")
        // Removing environment variable to avoid
        // `error: infinite recursion detected` when running `cargo lints`
            .env_remove("RUST_RECURSION_COUNT")
        // Removing environment variable to avoid
        // `error: `profiler_builtins` crate (required by compiler options) is not compatible with crate attribute `#![no_core]``
        // when running with `-C instrument-coverage`
        // TODO: Check if there are no problems with that
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
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
}
