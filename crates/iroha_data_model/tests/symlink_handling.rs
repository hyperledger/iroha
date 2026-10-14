//! Tests that the model item collector ignores filesystem symlinks.
use crate::support;
use std::fs;
use tempfile::tempdir;
#[test]
fn collect_model_items_ignores_symlinks() {
    let dir = tempdir().expect("create temp dir");
    let real = dir.path().join("real.rs");
    fs::write(&real, "#[model]\npub mod model {\n    pub struct Foo;\n}\n").expect("write real.rs");
    let link = dir.path().join("link.rs");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).expect("create symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&real, &link).expect("create symlink");
    // Create a directory symlink that points back to the temp dir to simulate a
    // potential symlink loop. The collector should ignore it and avoid
    // recursing indefinitely.
    let loop_dir = dir.path().join("loop");
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.path(), &loop_dir).expect("create dir symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(dir.path(), &loop_dir).expect("create dir symlink");
    let map = support::collect_model_items(dir.path()).expect("collect items");
    assert!(map.contains_key("real"), "real module missing");
    assert!(
        !map.contains_key("link"),
        "symlink module should be ignored"
    );
    assert_eq!(map.len(), 1, "symlinked dirs should be ignored");
}
