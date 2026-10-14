//! Kotodama + IVM example runner with optional external tool coverage.
//!
//! This integration test attempts to compile and run the example in `examples/hello/hello.ko`
//! if the external tools `koto` and `ivm_run` are available on PATH (or specified via
//! environment variables `KOTO_BIN` and `IVM_BIN`). The tests self-skip when those tools are not
//! present, so they do not fail CI on hosts without the local Kotodama toolchain.
//!
//! Run manually with:
//!   cargo test -p `integration_tests` --test `nexus_and_streaming` `kotodama_examples::` -- --nocapture
use integration_tests::process::{output_with_timeout, process_timeout, status_with_timeout};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
fn on_path(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for p in env::split_paths(&path) {
        let candidate = p.join(bin);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
        // Windows: add .exe fallback
        #[cfg(windows)]
        {
            let candidate_exe = p.join(format!("{}.exe", bin));
            if candidate_exe.is_file() && is_executable(&candidate_exe) {
                return Some(candidate_exe);
            }
        }
    }
    None
}
#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}
#[cfg(windows)]
fn is_executable(p: &Path) -> bool {
    p.extension().map(|e| e == "exe").unwrap_or(false)
}
#[test]
fn compile_and_run_hello() {
    let koto_bin = env::var("KOTO_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| on_path("koto"));
    if koto_bin.is_none() {
        eprintln!("Skipping: KOTO_BIN not set and koto not found on PATH");
        return;
    }
    let koto_bin = koto_bin.unwrap();
    let ivm_bin = env::var("IVM_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| on_path("ivm_run"));
    if ivm_bin.is_none() {
        eprintln!("Skipping: IVM_BIN not set and ivm_run not found on PATH");
        return;
    }
    let ivm_bin = ivm_bin.unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let src = root.join("examples/hello/hello.ko");
    let out = root.join("target/examples/hello.to");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    // Compile
    let mut command = Command::new(&koto_bin);
    command.arg("build").arg(&src).arg("--out").arg(&out);
    let status =
        status_with_timeout(&mut command, process_timeout()).expect("failed to spawn koto");
    assert!(status.success(), "koto build failed: {status:?}");
    // Run
    let mut command = Command::new(&ivm_bin);
    command.arg(&out).arg("--args").arg("{}");
    let output =
        output_with_timeout(&mut command, process_timeout()).expect("failed to spawn ivm_run");
    assert!(
        output.status.success(),
        "ivm_run failed: status={:?}\nstdout=\n{}\nstderr=\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Hello from Kotodama") || stdout.contains("write_detail"),
        "unexpected VM output: {stdout}"
    );
}
#[test]
fn inspect_hello() {
    let ivm_tool = env::var("IVM_TOOL_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| on_path("ivm_tool"));
    if ivm_tool.is_none() {
        eprintln!("Skipping: IVM_TOOL_BIN not set and ivm_tool not found on PATH");
        return;
    }
    let ivm_tool = ivm_tool.unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let out = root.join("target/examples/hello.to");
    assert!(
        out.exists(),
        "hello.to not found; run compile_and_run_hello first or compile manually"
    );
    let mut command = Command::new(&ivm_tool);
    command.arg("inspect").arg(&out);
    let output = output_with_timeout(&mut command, process_timeout())
        .expect("failed to spawn ivm_tool inspect");
    let out_stdout = String::from_utf8_lossy(&output.stdout);
    let out_stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ivm_tool inspect failed: status={:?}\nstdout=\n{out_stdout}\nstderr=\n{out_stderr}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("magic") && stdout.contains("abi_version"),
        "unexpected inspect output: {stdout}"
    );
}
#[test]
fn compile_and_run_nft() {
    let koto_bin = env::var("KOTO_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| on_path("koto"));
    if koto_bin.is_none() {
        eprintln!("Skipping: KOTO_BIN not set and koto not found on PATH");
        return;
    }
    let koto_bin = koto_bin.unwrap();
    let ivm_bin = env::var("IVM_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| on_path("ivm_run"));
    if ivm_bin.is_none() {
        eprintln!("Skipping: IVM_BIN not set and ivm_run not found on PATH");
        return;
    }
    let ivm_bin = ivm_bin.unwrap();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let src = root.join("examples/nft/nft.ko");
    let out = root.join("target/examples/nft.to");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    let mut command = Command::new(&koto_bin);
    command.arg("build").arg(&src).arg("--out").arg(&out);
    let status =
        status_with_timeout(&mut command, process_timeout()).expect("failed to spawn koto");
    assert!(status.success(), "koto build failed: {status:?}");
    let mut command = Command::new(&ivm_bin);
    command.arg(&out).arg("--args").arg("{}");
    let output =
        output_with_timeout(&mut command, process_timeout()).expect("failed to spawn ivm_run");
    assert!(
        output.status.success(),
        "ivm_run failed: status={:?}\nstdout=\n{}\nstderr=\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
