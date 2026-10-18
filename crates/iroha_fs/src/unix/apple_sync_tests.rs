//! Apple ordered syncs and their durability fence on the host's APFS volume.

use super::*;
use std::{
    os::unix::fs::OpenOptionsExt as _,
    sync::{Mutex, PoisonError},
};

// The fence registry is process-wide; these tests are its only callers in this crate.
static SERIAL: Mutex<()> = Mutex::new(());

fn written(directory: &Path, name: &str) -> File {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .unwrap();
    file.write_all(b"kagemusha").unwrap();
    file
}

#[test]
fn ordered_syncs_need_one_fence_per_device_and_a_clean_device_none() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    durability_fence().unwrap();
    assert_eq!(
        durability_fence().unwrap(),
        0,
        "nothing ordered since the last fence"
    );
    let file = written(&root, "first");
    sync_file_ordered(&file).unwrap();
    assert_eq!(durability_fence().unwrap(), 1);
    assert_eq!(
        durability_fence().unwrap(),
        0,
        "a fenced device needs no second flush"
    );
    let second = written(&root, "second");
    sync_file_ordered(&second).unwrap();
    sync_file_ordered(&File::open(&root).unwrap()).unwrap();
    sync_file_ordered(&file).unwrap();
    assert_eq!(
        durability_fence().unwrap(),
        1,
        "one flush covers every ordered sync of a device"
    );
}

#[test]
fn private_directory_and_custody_file_ordered_syncs_reach_the_fence() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let temporary = tempfile::tempdir().unwrap();
    // Exact ancestry must not encounter the operating-system /var alias.
    let root = temporary.path().canonicalize().unwrap().join("store");
    let directory = crate::PrivateDirectory::open_or_create(&root).unwrap();
    durability_fence().unwrap();
    directory.sync_ordered().unwrap();
    assert_eq!(
        durability_fence().unwrap(),
        1,
        "a directory's ordered sync is fenced"
    );
    drop(written(&root, "journal"));
    directory.sync_custody_file_ordered("journal").unwrap();
    assert_eq!(
        durability_fence().unwrap(),
        1,
        "a custody file's ordered sync is fenced"
    );
    directory.sync().unwrap();
    assert_eq!(
        durability_fence().unwrap(),
        0,
        "a durable sync registers nothing for the fence"
    );
}
