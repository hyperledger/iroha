//! Nexus CBDC rollout bundle tooling smoke tests.
#![cfg(target_family = "unix")]
use eyre::{Result, WrapErr, ensure};
use integration_tests::process::{process_timeout, status_with_timeout};
use std::{path::PathBuf, process::Command};
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("integration_tests workspace root")
        .to_path_buf()
}
#[test]
fn cbdc_rollout_fixture_passes_validator() -> Result<()> {
    let root = repo_root();
    let bundle_root = root.join("fixtures/nexus/cbdc_rollouts");
    let script = root.join("ci/check_cbdc_rollout.sh");
    ensure!(
        script.is_file(),
        "ci/check_cbdc_rollout.sh not found at {}",
        script.display()
    );
    ensure!(
        bundle_root.is_dir(),
        "fixture bundle directory missing at {}",
        bundle_root.display()
    );
    let mut command = Command::new(&script);
    command
        .env("CBDC_ROLLOUT_BUNDLE", &bundle_root)
        .current_dir(&root);
    let status = status_with_timeout(&mut command, process_timeout())
        .wrap_err("failed to execute ci/check_cbdc_rollout.sh")?;
    ensure!(
        status.success(),
        "ci/check_cbdc_rollout.sh exited with status {status:?}"
    );
    Ok(())
}
