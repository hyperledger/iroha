//! Build script which builds smartcontract for test

use std::{env, process::Command};

#[allow(clippy::unwrap_used)]
fn main() {
    let smartcontract_path = "tests/integration/create_nft_for_every_user_smartcontract";
    let out_dir = env::var_os("OUT_DIR").unwrap();

    // It's better to rerun this script anytime something in the main folder is changed so that
    // we don't have to manually monitor every iroha_wasm dependency
    println!("cargo:rerun-if-changed=..");

    let fmt = Command::new("cargo")
        .current_dir(smartcontract_path)
        .args(&["+nightly", "fmt", "--all"])
        .status()
        .unwrap();

    let build = Command::new("cargo")
        .env("CARGO_TARGET_DIR", out_dir)
        .current_dir(smartcontract_path)
        .args(&[
            "+nightly",
            "build",
            "-Z",
            "build-std",
            "-Z",
            "build-std-features=panic_immediate_abort",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .status()
        .unwrap();

    let success = fmt.success() && build.success();

    assert!(success, "Can't build smartcontract")
}
