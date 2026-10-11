//! Native four-stage Load fixture intake. Callers must supply the installed
//! originals and genuine finalized receipt evidence for the exact predecessor.
//! No synthetic funding source or alternate test-only Load circuit exists here.

#![allow(clippy::duplicate_mod)] // Reuses independently executable Bootstrap fixtures.

/// Genuine Bootstrap predecessor fixtures, independently tested in their own suite.
#[path = "common/proof_fixtures/bootstrap_omega.rs"]
pub mod bootstrap_outer;
mod common;

include!("common/proof_fixtures/a_load_recursive_body.rs");

#[test]
fn original_file_handle_keeps_only_metadata_and_rejects_changed_payloads() {
    let root = std::env::temp_dir().join(format!(
        "kg-load-original-{}-{}",
        std::process::id(),
        module_path!().replace(':', "_")
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("a0.pk");
    fs::write(path.with_extension("pending"), [0]).unwrap();
    // Storage-only bytes are never imported or represented as a valid key.
    let original = Original::persist(&path, vec![1], vec![2], vec![3, 4]);
    assert_eq!(original.read(2), [3, 4]);
    assert!(!path.with_extension("pending").try_exists().unwrap());
    assert!(std::panic::catch_unwind(|| original.read(1)).is_err());
    fs::write(&path, [3, 5]).unwrap();
    assert!(std::panic::catch_unwind(|| original.read(2)).is_err());
    fs::write(&path, [3]).unwrap();
    assert!(std::panic::catch_unwind(|| original.read(2)).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(std::panic::catch_unwind(|| original.read(2)).is_err());
    fs::remove_dir_all(root).unwrap();
}
