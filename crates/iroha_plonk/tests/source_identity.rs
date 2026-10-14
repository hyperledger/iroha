//! Closed registry freshness: real file membership, assets, staging and fail-closed inputs.

#[path = "../build_support/source_identity.rs"]
mod source_identity;

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use source_identity::{GENERATED, snapshot, supported_target};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "iroha-source-identity-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let workspace = Self(directory.canonicalize().unwrap());
        workspace.git(&["init", "--quiet"]);
        workspace.write("Cargo.toml", b"[workspace]\nmembers = []\n");
        workspace.write("Cargo.lock", b"version = 4\n");
        workspace.write(
            ".gitignore",
            b"/target/\n/output/\n/dist/*\n!/dist/.gitkeep\n",
        );
        workspace.write(
            "crates/proof/src/circuit.rs",
            b"pub const ROWS: u32 = 65536;\n",
        );
        workspace.write("crates/pasta/src/poseidon/constants.bin", &[1, 2, 3, 4]);
        workspace.write(
            GENERATED,
            b"const PROFILES: &[BuiltinProfileEntry] = &[];\n",
        );
        workspace.git(&["add", "."]);
        workspace
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn git(&self, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.0)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Git command failed: {:?}",
            output.stderr
        );
    }
    fn digest(&self) -> [u8; 32] {
        snapshot(&self.0).unwrap().digest
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn source_assets_dependency_lock_and_membership_change_identity() {
    let workspace = Workspace::new();
    let mut previous = workspace.digest();
    for (name, value) in [
        (
            "crates/proof/src/circuit.rs",
            b"pub const ROWS: u32 = 32768;\n".as_slice(),
        ),
        ("crates/pasta/src/poseidon/constants.bin", &[1, 2, 3, 5]),
        ("Cargo.lock", b"version = 4\n# changed dependency\n"),
        (".cargo/config.toml", b"[build]\nincremental = false\n"),
        (
            "crates/proof/src/new_relation.rs",
            b"pub const RELATION: u32 = 1;\n",
        ),
    ] {
        workspace.write(name, value);
        let changed = workspace.digest();
        assert_ne!(
            previous, changed,
            "input {name} must invalidate compiled entries"
        );
        previous = changed;
    }
    fs::remove_file(workspace.0.join("crates/proof/src/new_relation.rs")).unwrap();
    assert_ne!(
        previous,
        workspace.digest(),
        "untracked source removal changes membership"
    );
}

#[test]
fn generated_data_and_ignored_build_outputs_do_not_create_self_hash_cycle() {
    let workspace = Workspace::new();
    let expected = workspace.digest();
    workspace.write(
        GENERATED,
        b"const PROFILES: &[BuiltinProfileEntry] = &[NEW_PROFILE];\n",
    );
    workspace.write("target/output/native.so", &[0; 128]);
    workspace.write("output/generator/run.log", b"generation complete\n");
    assert_eq!(workspace.digest(), expected);
    workspace.write("dist/.gitkeep", b"");
    workspace.git(&["add", "dist/.gitkeep"]);
    let expected = workspace.digest();
    workspace.write("dist/framework/library.so", b"new native output");
    assert_eq!(workspace.digest(), expected);
    let snapshot = snapshot(&workspace.0).unwrap();
    assert!(
        snapshot
            .watched_paths
            .contains(&workspace.0.join(GENERATED))
    );
    assert!(!snapshot.watched_paths.contains(&workspace.0));
    assert!(!snapshot.watched_paths.contains(&workspace.0.join("target")));
    assert!(!snapshot.watched_paths.contains(&workspace.0.join("dist")));
    assert!(
        snapshot
            .watched_paths
            .contains(&workspace.0.join("crates/proof/src/circuit.rs"))
    );
    workspace.write("crates/proof/src/registry.rs", b"pub fn select() {}\n");
    assert_ne!(
        workspace.digest(),
        expected,
        "registry admission logic is an input"
    );
}

#[test]
fn staging_without_byte_changes_does_not_change_mathematical_identity() {
    let workspace = Workspace::new();
    workspace.write("crates/proof/src/new.rs", b"pub const X: u64 = 1;\n");
    let before = workspace.digest();
    workspace.git(&["add", "crates/proof/src/new.rs"]);
    assert_eq!(workspace.digest(), before);
    workspace.write("crates/proof/src/circuit.rs", b"pub const ROWS: u32 = 2;\n");
    let dirty = workspace.digest();
    workspace.git(&["add", "crates/proof/src/circuit.rs"]);
    assert_eq!(workspace.digest(), dirty);
}

#[test]
fn fresh_invocation_detects_untracked_inputs_beside_ignored_outputs() {
    let workspace = Workspace::new();
    workspace.write(
        ".gitignore",
        b"/target/\n/output/\n/dist/*\n!/dist/.gitkeep\n**/build/\n",
    );
    workspace.write("crates/proof/build/old-output.bin", b"ignored build output");
    let before = workspace.digest();
    workspace.write("crates/proof/new_mathematical_asset.bin", &[9, 8, 7]);
    let after_asset = workspace.digest();
    assert_ne!(after_asset, before);
    workspace.write(".cargo/config.toml", b"[build]\nincremental = false\n");
    assert_ne!(workspace.digest(), after_asset);
}

#[test]
fn ignored_native_modules_assets_and_cargo_configuration_remain_inputs() {
    let workspace = Workspace::new();
    workspace.write(
        ".gitignore",
        b"/target/\n/output/\n**/ignored_*\n/.cargo/\n",
    );
    let before = workspace.digest();
    for (path, first, second) in [
        (
            "crates/proof/src/ignored_module.rs",
            b"const X: u8 = 1;".as_slice(),
            b"const X: u8 = 2;".as_slice(),
        ),
        (
            "crates/pasta/src/ignored_constants.bin",
            &[1, 2, 3],
            &[1, 2, 4],
        ),
        (
            "crates/proof/build_support/ignored_generator.rs",
            b"fn first() {}",
            b"fn second() {}",
        ),
        (".cargo/config.toml", b"# first", b"# second"),
    ] {
        let previous = workspace.digest();
        workspace.write(path, first);
        let added = workspace.digest();
        assert_ne!(added, previous, "ignored input {path} was omitted");
        workspace.write(path, second);
        assert_ne!(
            workspace.digest(),
            added,
            "ignored input {path} mutation was omitted"
        );
        fs::remove_file(workspace.0.join(path)).unwrap();
        assert_eq!(workspace.digest(), previous);
    }
    assert_eq!(workspace.digest(), before);
}

#[test]
fn deleted_tracked_or_missing_git_inputs_cannot_report_freshness() {
    let workspace = Workspace::new();
    fs::remove_file(workspace.0.join("Cargo.lock")).unwrap();
    assert!(
        snapshot(&workspace.0)
            .unwrap_err()
            .contains("missing source input")
    );
    workspace.write("Cargo.lock", b"version = 4\n");
    assert!(snapshot(&workspace.0).is_ok());
    fs::rename(
        workspace.0.join(".git"),
        workspace.0.join("unavailable-git"),
    )
    .unwrap();
    assert!(snapshot(&workspace.0).is_err());
}

#[cfg(unix)]
#[test]
fn source_links_are_bounded_and_generated_swift_output_is_only_link_metadata() {
    use std::os::unix::fs::symlink;
    let workspace = Workspace::new();
    let expected = workspace.digest();
    workspace.write(
        ".gitignore",
        b"/target/\n/output/\n/dist/*\n/crates/ignored/\n",
    );
    fs::create_dir_all(workspace.0.join("crates/ignored")).unwrap();
    symlink("missing", workspace.0.join("crates/ignored/src")).unwrap();
    assert!(
        snapshot(&workspace.0).is_err(),
        "ignored dangling source root"
    );
    fs::remove_file(workspace.0.join("crates/ignored/src")).unwrap();
    workspace.write(
        ".gitignore",
        b"/target/\n/output/\n/dist/*\n!/dist/.gitkeep\n",
    );
    assert_eq!(workspace.digest(), expected);
    symlink("circuit.rs", workspace.0.join("crates/proof/src/same.rs")).unwrap();
    let with_link = workspace.digest();
    assert_ne!(with_link, expected);
    fs::remove_file(workspace.0.join("crates/proof/src/same.rs")).unwrap();
    symlink(
        "/etc/hosts",
        workspace.0.join("crates/proof/src/outside.rs"),
    )
    .unwrap();
    assert!(snapshot(&workspace.0).is_err());
    fs::remove_file(workspace.0.join("crates/proof/src/outside.rs")).unwrap();
    fs::create_dir_all(workspace.0.join("IrohaSwift")).unwrap();
    symlink(
        "../dist/NoritoBridge.xcframework",
        workspace.0.join("IrohaSwift/NoritoBridge.xcframework"),
    )
    .unwrap();
    let swift = workspace.digest();
    workspace.write(
        "dist/NoritoBridge.xcframework/library.so",
        b"first native output",
    );
    assert_eq!(workspace.digest(), swift);
    workspace.write(
        "dist/NoritoBridge.xcframework/library.so",
        b"second native output",
    );
    assert_eq!(workspace.digest(), swift);
    fs::remove_file(workspace.0.join("IrohaSwift/NoritoBridge.xcframework")).unwrap();
    symlink(
        "../dist/other",
        workspace.0.join("IrohaSwift/NoritoBridge.xcframework"),
    )
    .unwrap();
    assert!(snapshot(&workspace.0).is_err());
}

#[test]
fn only_the_optional_docs_gitlink_is_opaque_membership() {
    let workspace = Workspace::new();
    let before = workspace.digest();
    workspace.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000,1111111111111111111111111111111111111111,iroha-docs",
    ]);
    let first = workspace.digest();
    assert_ne!(first, before);
    workspace.git(&[
        "update-index",
        "--cacheinfo",
        "160000,2222222222222222222222222222222222222222,iroha-docs",
    ]);
    assert_ne!(workspace.digest(), first);
    workspace.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "160000,1111111111111111111111111111111111111111,crates/unknown",
    ]);
    assert!(snapshot(&workspace.0).is_err());
}

#[test]
fn target_support_is_separate_and_unknown_or_inconsistent_backends_deny_builtin() {
    for (arch, os, width) in [
        ("aarch64", "macos", "64"),
        ("aarch64", "ios", "64"),
        ("aarch64", "android", "64"),
        ("arm", "android", "32"),
        ("x86_64", "android", "64"),
        ("x86_64", "linux", "64"),
    ] {
        assert!(supported_target(arch, os, width, "little"));
    }
    for (arch, os, width, endian) in [
        ("aarch64", "android", "32", "little"),
        ("arm", "android", "32", "big"),
        ("wasm32", "unknown", "32", "little"),
        ("riscv64", "linux", "64", "little"),
        ("arm", "unknown", "32", "little"),
    ] {
        assert!(!supported_target(arch, os, width, endian));
    }
}
