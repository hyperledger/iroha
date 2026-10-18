//! Shared test-only paths for a retained KAGEMUSHA fixture cohort.

use std::{ffi::OsString, path::PathBuf};

const ROOT_VARIABLE: &str = "IROHA_KAGEMUSHA_TEST_FIXTURE_ROOT";
const COHORT_PATHS: [&str; 6] = [
    "fixtures/kagemusha/wallet_v1_vectors.json",
    "fixtures/kagemusha/wallet_enrollment_policy_v1_vectors.json",
    "fixtures/kagemusha/ordinary_load_npos_schedule_v1.json",
    "fixtures/kagemusha/ordinary_load_receipt_v1.json",
    "fixtures/kagemusha/ordinary_first_load_receipt_v1.json",
    "specs/references/schema.json",
];

fn path_with_root(selected_root: Option<OsString>, relative: &str) -> PathBuf {
    assert!(
        COHORT_PATHS.contains(&relative),
        "unknown KAGEMUSHA test fixture: {relative}"
    );
    let Some(selected_root) = selected_root else {
        return PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
    };
    let root = PathBuf::from(selected_root);
    assert!(
        root.is_absolute(),
        "{ROOT_VARIABLE} must name an absolute fixture root"
    );
    assert!(
        root.is_dir(),
        "{ROOT_VARIABLE} fixture root is missing: {}",
        root.display()
    );
    for member in COHORT_PATHS {
        let file = root.join(member);
        let regular = std::fs::symlink_metadata(&file)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false);
        assert!(
            regular,
            "{ROOT_VARIABLE} fixture cohort is incomplete: {}",
            file.display()
        );
    }
    root.join(relative)
}

pub(crate) fn path(relative: &str) -> PathBuf {
    path_with_root(std::env::var_os(ROOT_VARIABLE), relative)
}
