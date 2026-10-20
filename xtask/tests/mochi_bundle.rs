//! Acceptance checks for complete native Mochi developer runtime bundles.

use assert_cmd::cargo::cargo_bin_cmd;
use iroha_deploy::managed::NativeBundleLayout;
use norito::json::{self, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};
use tempfile::TempDir;
#[test]
fn mochi_bundle_command_generates_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let output_dir = temp.path().join("bundle-output");
    cargo_bin_cmd!("xtask")
        .args([
            "mochi-bundle",
            "--out",
            output_dir.to_str().expect("utf8 path"),
            "--profile",
            "debug",
            "--no-archive",
        ])
        .assert()
        .success();
    let bundle_name = format!("mochi-{}-{}-debug", env::consts::OS, env::consts::ARCH);
    let bundle_root = output_dir.join(&bundle_name);
    assert!(
        bundle_root.exists(),
        "expected bundle directory at {}",
        bundle_root.display()
    );
    let manifest_path = bundle_root.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|_| panic!("missing manifest {}", manifest_path.display()));
    let manifest_json: Value = json::from_str(&manifest).expect("parse manifest");
    assert_eq!(
        manifest_json["profile"],
        Value::String("debug".to_owned()),
        "manifest should record the build profile"
    );
    let files = manifest_json["files"]
        .as_array()
        .expect("files array in manifest");
    let executable_name = NativeBundleLayout::current()
        .executable(Path::new(""), "mochi")
        .to_string_lossy()
        .replace('\\', "/");
    assert!(
        files
            .iter()
            .any(|entry| entry["path"] == Value::String(executable_name.clone())),
        "manifest should list {executable_name}"
    );
    let kagami_name = NativeBundleLayout::current()
        .executable(Path::new(""), "kagami")
        .to_string_lossy()
        .replace('\\', "/");
    assert!(
        files
            .iter()
            .any(|entry| entry["path"] == Value::String(kagami_name.clone())),
        "manifest should list {kagami_name}"
    );
    let daemon_name = NativeBundleLayout::current()
        .executable(Path::new(""), "iroha3d")
        .to_string_lossy()
        .replace('\\', "/");
    assert!(
        files
            .iter()
            .any(|entry| entry["path"] == Value::String(daemon_name.clone())),
        "manifest should list {daemon_name}"
    );
    #[cfg(target_os = "macos")]
    {
        let plist = bundle_root.join("Mochi.app/Contents/Info.plist");
        let output = std::process::Command::new("/usr/bin/plutil")
            .args(["-extract", "CFBundleIconFile", "raw", "-o", "-"])
            .arg(&plist)
            .output()
            .expect("read the real application's icon metadata");
        assert!(
            output.status.success(),
            "packaged Info.plist should name its icon: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 icon filename"),
            "Mochi.icns\n"
        );
        let icon_relative = "Mochi.app/Contents/Resources/Mochi.icns";
        let packaged_icon = fs::read(bundle_root.join(icon_relative)).expect("packaged icon");
        let source_icon = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .join("mochi/assets/mochi-icon.icns"),
        )
        .expect("source icon");
        assert_eq!(
            packaged_icon, source_icon,
            "packaging must preserve the icon"
        );
        let icon_entry = files
            .iter()
            .find(|entry| entry["path"].as_str() == Some(icon_relative))
            .expect("manifest should list the packaged icon");
        assert_eq!(
            icon_entry["size"].as_u64(),
            Some(packaged_icon.len() as u64)
        );
        assert_eq!(
            icon_entry["sha256"].as_str(),
            Some(format!("{:x}", Sha256::digest(&packaged_icon)).as_str())
        );
    }
}
#[test]
fn mochi_bundle_matrix_and_smoke() {
    let temp = TempDir::new().expect("temp dir");
    let output_dir = temp.path().join("bundle-output");
    let matrix_path = temp.path().join("matrix.json");
    cargo_bin_cmd!("xtask")
        .args([
            "mochi-bundle",
            "--out",
            output_dir.to_str().expect("utf8 path"),
            "--profile",
            "debug",
            "--no-archive",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--smoke",
        ])
        .assert()
        .success();
    let matrix_contents = fs::read_to_string(&matrix_path)
        .unwrap_or_else(|_| panic!("missing matrix {}", matrix_path.display()));
    let matrix: Value = json::from_str(&matrix_contents).expect("parse matrix");
    let entries = matrix["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "expected single matrix entry");
    let entry = entries[0].as_object().expect("entry object");
    let bundle_name = format!("mochi-{}-{}-debug", env::consts::OS, env::consts::ARCH);
    assert_eq!(
        entry["target"].as_str().expect("target"),
        format!("{}-{}", env::consts::OS, env::consts::ARCH)
    );
    assert_eq!(entry["profile"], Value::String("debug".to_owned()));
    assert!(
        entry.contains_key("manifest"),
        "entry should record manifest path"
    );
    assert_eq!(
        entry["manifest"],
        Value::String(format!("{bundle_name}/manifest.json"))
    );
    assert_eq!(
        entry["bundle_dir"],
        Value::String(bundle_name.clone()),
        "bundle_dir should match relative directory"
    );
    assert_eq!(entry["smoke_passed"], Value::Bool(true));
    assert!(
        !entry.contains_key("archive"),
        "archive field must be absent when --no-archive is used"
    );
    let manifest_path = output_dir.join(&bundle_name).join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .unwrap_or_else(|_| panic!("missing manifest {}", manifest_path.display()));
    let mut hasher = Sha256::new();
    hasher.update(&manifest_bytes);
    let manifest_sha = format!("{:x}", hasher.finalize());
    assert_eq!(
        entry["manifest_sha256"],
        Value::String(manifest_sha),
        "matrix should include manifest digest"
    );
}
#[test]
fn mochi_bundle_stage_directory_copies_bundle() {
    let temp = TempDir::new().expect("temp dir");
    let output_dir = temp.path().join("bundle-output");
    let stage_dir = temp.path().join("stage-output");
    cargo_bin_cmd!("xtask")
        .args([
            "mochi-bundle",
            "--out",
            output_dir.to_str().expect("utf8 path"),
            "--profile",
            "debug",
            "--no-archive",
            "--stage",
            stage_dir.to_str().expect("utf8 stage path"),
        ])
        .assert()
        .success();
    let bundle_name = format!("mochi-{}-{}-debug", env::consts::OS, env::consts::ARCH);
    let original_bundle = output_dir.join(&bundle_name);
    let staged_bundle = stage_dir.join(&bundle_name);
    assert!(
        staged_bundle.exists(),
        "expected staged bundle directory at {}",
        staged_bundle.display()
    );
    let original_manifest = original_bundle.join("manifest.json");
    let staged_manifest = staged_bundle.join("manifest.json");
    let original_contents = fs::read_to_string(&original_manifest)
        .unwrap_or_else(|_| panic!("missing original manifest {}", original_manifest.display()));
    let staged_contents = fs::read_to_string(&staged_manifest)
        .unwrap_or_else(|_| panic!("missing staged manifest {}", staged_manifest.display()));
    assert_eq!(
        original_contents, staged_contents,
        "staged manifest should match original manifest"
    );
}
