//! Build script which builds smartcontract for test

use std::{env, process::Command};

#[allow(clippy::unwrap_used)]
fn main() {
    let smartcontract_path = "tests/integration/create_nft_for_every_user_smartcontract";
    let out_dir = env::var_os("OUT_DIR").unwrap();

    println!("cargo:rerun-if-changed={}", smartcontract_path);
    println!("cargo:rerun-if-changed=build.rs");

    Command::new("cargo")
        .env("CARGO_TARGET_DIR", out_dir)
        .current_dir(smartcontract_path)
        .args(&[
            "+nightly",
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
        .unwrap();
}
