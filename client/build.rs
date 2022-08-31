//! Build script which builds smartcontract for test
//!
//! Technically this script is used only for testing purposes, but current cargo implementation
//! doesn't allow to run build script only for tests or get info about current profile from it.
//! See [cargo issue #4001](https://github.com/rust-lang/cargo/issues/4001)

use core::str::from_utf8;
use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{eyre, Context as _, Result};

#[allow(clippy::expect_used)]
fn main() {
    const TEST_SMARTCONTRACTS_DIR: &str = "tests/integration/smartcontracts";
    const TEST_SMARTCONTRACTS: [&str; 2] = [
        "create_nft_for_every_user_smartcontract",
        "deny_new_validators_validator",
    ];

    println!("cargo:rerun-if-changed={TEST_SMARTCONTRACTS_DIR}");
    // TODO: check if this was causing the recursive loop.
    // println!("cargo:rerun-if-changed=..");

    // Build and format the smartcontract if and only if the tests are
    // invoked with the nightly toolchain. We should not force our
    // users to have the `nightly` if we don't use any `nightly`
    // features in the actual binary.
    let rustc_version_output = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("Failed to run `rustc --version`");

    if from_utf8(&rustc_version_output.stdout)
        .expect("Garbage in `rustc --version` output")
        .contains("nightly")
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("Expected `CARGO_MANIFEST_DIR` environment variable");
        let out_dir = env::var_os("OUT_DIR").expect("Expected `OUT_DIR` environment variable");

        for local_path_str in &TEST_SMARTCONTRACTS {
            let smartcontract_path = Path::new(&manifest_dir)
                .join(TEST_SMARTCONTRACTS_DIR)
                .join(local_path_str);
            format_smartcontract(smartcontract_path.clone())
                .expect("Failed to format the smartcontract");
            build_smartcontract(&smartcontract_path, &out_dir)
                .expect("Failed to build the smartcontract");
        }
    }
}

fn format_smartcontract(smartcontract_path: PathBuf) -> Result<()> {
    let code_path = smartcontract_path.join("src/lib.rs");
    let fmt = Command::new("rustfmt")
        .current_dir(smartcontract_path)
        .args(&[code_path.to_str().ok_or_else(|| {
            eyre!(
                "Can't convert the smartcontract code path `{}` to str",
                code_path.display()
            )
        })?])
        .status()
        .wrap_err(eyre!(
            "Failed to run `rustfmt` on smartcontract code at path `{}`",
            code_path.display()
        ))?;
    if !fmt.success() {
        return Err(eyre!(
            "`rustfmt` returned non zero exit code ({}) then trying to format smartcontract code at path `{}`",
            fmt,
            code_path.display()
        ));
    }

    Ok(())
}

fn build_smartcontract(smartcontract_path: &Path, out_dir: &OsStr) -> Result<()> {
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
            "+nightly-2022-08-15",
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
        .wrap_err(eyre!(
            "Failed to run `cargo build` on smartcontract at path `{}`",
            smartcontract_path.display()
        ))?;

    if !build.success() {
        return Err(eyre!(
            "`cargo build` returned non zero exit code ({}) then trying to build smartcontract at path `{}`",
            build,
            smartcontract_path.display()
        ));
    }

    Ok(())
}
