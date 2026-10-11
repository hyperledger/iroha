//! Portable strict receipt custody and bounded inventory regressions.

use super::*;
use std::io::{SeekFrom, Write as _};

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().unwrap();
    let store = PrivateDirectory::open_or_create(temporary.path().join("receipts")).unwrap();
    (temporary, store)
}

#[test]
fn portable_name_checks_preserve_case_insensitive_device_and_unicode_boundaries() {
    for device in [
        "CON", "con", "CoN", "PrN", "aUX", "nuL", "conIn$", "CoNoUt$", "com1", "CoM9", "Lpt1",
        "lPT9", "com¹", "CoM²", "com³", "lpt¹", "LpT²", "lPT³",
    ] {
        for extension in ["", ".txt", ".archive.car"] {
            let name = format!("{device}{extension}");
            assert!(checked_name(OsStr::new(&name)).is_err(), "{name}");
        }
    }
    for name in [
        "conman",
        "prefix.con",
        "com0",
        "COM10",
        "com١",
        "lpt0",
        "LPT10",
        "COM¹x",
        "conout",
        "com4x",
        "éCOM1",
        "報告",
        "a報告",
        ".receipt",
    ] {
        assert_eq!(checked_name(OsStr::new(name)).unwrap(), OsStr::new(name));
    }
}

#[test]
fn exact_directory_open_rejects_alias_spelling_and_missing_custody() {
    let (_temporary, directory) = store();
    let exact = PrivateDirectory::open_exact(directory.path()).unwrap();
    assert_eq!(exact.identity().unwrap(), directory.identity().unwrap());
    assert!(PrivateDirectory::open_exact("relative").is_err());
    assert!(PrivateDirectory::open_exact(directory.path().join("missing")).is_err());
    assert!(PrivateDirectory::open_exact(directory.path().join(".")).is_err());
    assert!(PrivateDirectory::open_exact(directory.path().join("..")).is_err());
}

#[test]
fn relative_receipt_create_seal_and_read_preserve_identity_and_strict_access() {
    let (_temporary, directory) = store();
    let mut writer = directory.create_retained_private("receipt", 64).unwrap();
    writer.write_all(b"exact receipt").unwrap();
    assert!(directory.create_retained_private("receipt", 64).is_err());
    assert!(directory.open_retained_read_only("receipt", 64).is_err());
    let sealed = writer.seal_read_only().unwrap();
    let id = sealed.identity().unwrap();
    assert_eq!(sealed.len().unwrap(), 13);
    assert!(!sealed.is_empty().unwrap());
    assert_eq!(sealed.snapshot().unwrap(), sealed.snapshot().unwrap());
    assert!(directory.open_retained_read_only("receipt", 12).is_err());
    sealed.revalidate().unwrap();
    let mut reader = directory.open_retained_read_only("receipt", 64).unwrap();
    assert_eq!(reader.identity().unwrap(), id);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"exact receipt");
    reader.revalidate().unwrap();
    drop(reader);
    drop(sealed);
}

#[test]
fn optional_sealed_original_distinguishes_absence_from_admission_refusal() {
    let (_temporary, directory) = store();
    assert!(
        directory
            .open_retained_read_only_optional("absent", 64)
            .unwrap()
            .is_none()
    );
    let mut writer = directory
        .create_retained_private("optional-receipt", 64)
        .unwrap();
    writer.write_all(b"exact receipt").unwrap();
    assert!(
        directory
            .open_retained_read_only_optional("optional-receipt", 64)
            .is_err()
    );
    let sealed = writer.seal_read_only().unwrap();
    assert!(
        directory
            .open_retained_read_only_optional("optional-receipt", 12)
            .is_err()
    );
    let mut original = directory
        .open_retained_read_only_optional("optional-receipt", 64)
        .unwrap()
        .unwrap();
    assert_eq!(original.identity().unwrap(), sealed.identity().unwrap());
    let mut bytes = Vec::new();
    original.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"exact receipt");
    assert!(
        directory
            .open_retained_read_only_optional("../missing", 64)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn optional_sealed_original_late_disappearance_never_becomes_absence() {
    let (_temporary, directory) = store();
    let mut writer = directory
        .create_retained_private("optional-late", 64)
        .unwrap();
    writer.write_all(b"exact receipt").unwrap();
    let _sealed = writer.seal_read_only().unwrap();
    let path = directory.path().join("optional-late");
    let result = crate::platform::with_readonly_named_hook(
        "optional-late",
        move || std::fs::remove_file(path).unwrap(),
        || directory.open_retained_read_only_optional("optional-late", 64),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(
        directory
            .open_retained_read_only_optional("optional-late", 64)
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn optional_sealed_original_refuses_replaced_directory_even_for_missing_name() {
    let (temporary, directory) = store();
    std::fs::rename(directory.path(), temporary.path().join("old-receipts")).unwrap();
    std::fs::create_dir(directory.path()).unwrap();
    assert!(
        directory
            .open_retained_read_only_optional("absent", 64)
            .is_err()
    );
}

#[test]
fn optional_private_original_preserves_initial_absence_and_bounded_prefix_reads() {
    let (_temporary, directory) = store();
    assert!(
        directory
            .open_retained_private_optional("missing")
            .unwrap()
            .is_none()
    );
    directory
        .write_atomic(
            "optional-private",
            b"private original",
            PublishMode::CreateNew,
        )
        .unwrap();
    let original = directory
        .open_retained_private_optional("optional-private")
        .unwrap()
        .unwrap();
    let mut prefix = Vec::new();
    original.file().take(7).read_to_end(&mut prefix).unwrap();
    assert_eq!(prefix, b"private");
    original.revalidate().unwrap();
    assert!(
        directory
            .open_retained_private_optional("../missing")
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn optional_private_original_late_disappearance_never_becomes_absence() {
    let (_temporary, directory) = store();
    directory
        .write_atomic("private-late", b"private original", PublishMode::CreateNew)
        .unwrap();
    let path = directory.path().join("private-late");
    let result = crate::platform::with_readonly_named_hook(
        "private-late",
        move || std::fs::remove_file(path).unwrap(),
        || directory.open_retained_private_optional("private-late"),
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(
        directory
            .open_retained_private_optional("private-late")
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn optional_private_original_refuses_replaced_parent_for_initially_absent_file() {
    let (temporary, directory) = store();
    std::fs::rename(directory.path(), temporary.path().join("old-receipts")).unwrap();
    std::fs::create_dir(directory.path()).unwrap();
    assert!(directory.open_retained_private_optional("missing").is_err());
}

#[cfg(windows)]
#[test]
fn optional_private_original_keeps_native_directory_rename_refusal_and_original_retry() {
    let (temporary, directory) = store();
    assert!(
        directory
            .open_retained_private_optional("absent")
            .unwrap()
            .is_none()
    );
    directory
        .write_atomic(
            "optional-private",
            b"private original",
            PublishMode::CreateNew,
        )
        .unwrap();
    let original = directory
        .open_retained_private_optional("optional-private")
        .unwrap()
        .unwrap();
    let id = original.identity().unwrap();
    let moved = temporary.path().join("old-receipts");
    assert!(std::fs::rename(directory.path(), &moved).is_err());
    assert!(!moved.exists());
    assert!(
        directory
            .open_retained_private_optional("absent")
            .unwrap()
            .is_none()
    );
    let retry = directory
        .open_retained_private_optional("optional-private")
        .unwrap()
        .unwrap();
    assert_eq!(retry.identity().unwrap(), id);
    let mut bytes = Vec::new();
    retry.file().take(64).read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"private original");
    retry.revalidate().unwrap();
    assert_eq!(original.identity().unwrap(), id);
    original.revalidate().unwrap();
}

#[cfg(windows)]
#[test]
fn optional_sealed_original_keeps_native_directory_rename_refusal_and_original_retry() {
    let (temporary, directory) = store();
    let mut writer = directory
        .create_retained_private("optional-receipt", 64)
        .unwrap();
    writer.write_all(b"exact receipt").unwrap();
    let sealed = writer.seal_read_only().unwrap();
    assert!(
        directory
            .open_retained_read_only_optional("absent", 64)
            .unwrap()
            .is_none()
    );
    let moved = temporary.path().join("old-receipts");
    assert!(std::fs::rename(directory.path(), &moved).is_err());
    assert!(!moved.exists());
    assert!(
        directory
            .open_retained_read_only_optional("absent", 64)
            .unwrap()
            .is_none()
    );
    let mut original = directory
        .open_retained_read_only_optional("optional-receipt", 64)
        .unwrap()
        .unwrap();
    assert_eq!(original.identity().unwrap(), sealed.identity().unwrap());
    let mut bytes = Vec::new();
    original.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"exact receipt");
}

#[test]
fn bounded_inventory_distinguishes_empty_writable_and_sealed_files() {
    let (_temporary, directory) = store();
    directory
        .visit_private_files(0, |_, _| panic!("empty"))
        .unwrap();
    let empty = directory.create_retained_private("incomplete", 64).unwrap();
    let mut writer = directory.create_retained_private("receipt", 64).unwrap();
    writer.write_all(b"body").unwrap();
    let _sealed = writer.seal_read_only().unwrap();
    let mut seen = std::collections::BTreeMap::new();
    directory
        .visit_private_files(2, |name, metadata| {
            seen.insert(name.to_owned(), metadata);
            Ok(())
        })
        .unwrap();
    let incomplete = seen[OsStr::new("incomplete")];
    assert!(incomplete.is_empty());
    assert_eq!(incomplete.len(), 0);
    assert!(!incomplete.is_read_only());
    let receipt = seen[OsStr::new("receipt")];
    assert_eq!(receipt.len(), 4);
    assert!(receipt.is_read_only());
    let mut callbacks = 0;
    assert!(
        directory
            .visit_private_files(1, |_, _| {
                callbacks += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(callbacks, 1);
    assert!(
        directory
            .visit_private_files(0, |_, _| panic!("bound precedes callback"))
            .is_err()
    );
    assert!(
        directory
            .visit_private_files(2, |_, _| Err(io::Error::other("visitor refused")))
            .is_err()
    );
    drop(empty);
}

#[test]
fn inventory_rejects_nonfiles_and_directory_mutation_during_callback() {
    let (_temporary, directory) = store();
    let child = directory.create_child("nested").unwrap();
    assert!(directory.visit_private_files(1, |_, _| Ok(())).is_err());
    child.remove_empty().unwrap();
    let file = directory.create_retained_private("one", 64).unwrap();
    let mut mutated = false;
    assert!(
        directory
            .visit_private_files(2, |_, _| {
                if !mutated {
                    mutated = true;
                    let _new = directory.create_retained_private("two", 64)?;
                }
                Ok(())
            })
            .is_err()
    );
    drop(file);
}

#[test]
fn opaque_writer_and_reader_enforce_original_extent_through_sparse_seeks() {
    let (_temporary, directory) = store();
    let mut writer = directory.create_retained_private("bounded", 8).unwrap();
    assert!(writer.write_all(b"too many bytes").is_err());
    assert_eq!(writer.stream_position().unwrap(), 0);
    assert!(writer.seek(SeekFrom::Start(9)).is_err());
    assert!(writer.seek(SeekFrom::Current(-1)).is_err());
    assert_eq!(writer.seek(SeekFrom::End(7)).unwrap(), 7);
    writer.write_all(b"x").unwrap();
    writer.flush().unwrap();
    assert!(writer.write_all(b"y").is_err());
    assert_eq!(writer.stream_position().unwrap(), 8);
    let mut sealed = writer.seal_read_only().unwrap();
    assert_eq!(sealed.len().unwrap(), 8);
    assert_eq!(sealed.seek(SeekFrom::End(-1)).unwrap(), 7);
    let mut bytes = [0; 16];
    assert_eq!(sealed.read(&mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], b'x');
    assert_eq!(sealed.read(&mut bytes).unwrap(), 0);
    assert!(sealed.seek(SeekFrom::Start(9)).is_err());
    assert!(sealed.seek(SeekFrom::Current(i64::MAX)).is_err());
    sealed.revalidate().unwrap();
    let empty = directory.create_retained_private("zero", 0).unwrap();
    let mut empty = empty.seal_read_only().unwrap();
    assert!(empty.is_empty().unwrap());
    assert_eq!(empty.read(&mut bytes).unwrap(), 0);
}

#[test]
fn no_replace_publication_retains_exact_file_and_refuses_reopened_sources() {
    let (_temporary, directory) = store();
    let mut writer = directory.create_retained_private("inflight", 64).unwrap();
    writer.write_all(b"original").unwrap();
    let sealed = writer.seal_read_only().unwrap();
    let id = sealed.identity().unwrap();
    let published = sealed.publish_new_name("receipt").unwrap();
    assert_eq!(published.identity().unwrap(), id);
    published.revalidate().unwrap();
    assert!(directory.open_retained_read_only("inflight", 64).is_err());
    let reopened = directory.open_retained_read_only("receipt", 64).unwrap();
    assert!(reopened.publish_new_name("moved").is_err());
    let mut other = directory
        .create_retained_private("other-inflight", 64)
        .unwrap();
    other.write_all(b"substitute").unwrap();
    assert!(
        other
            .seal_read_only()
            .unwrap()
            .publish_new_name("receipt")
            .is_err()
    );
    assert_eq!(
        directory
            .open_retained_read_only("receipt", 64)
            .unwrap()
            .identity()
            .unwrap(),
        id
    );
    assert!(
        directory
            .open_retained_read_only("other-inflight", 64)
            .is_ok()
    );
    assert!(published.publish_new_name("second").is_err());
}

#[cfg(unix)]
#[test]
fn inventory_counts_mode_zero_tombstones_but_rejects_links_and_nonprivate_modes() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let (_temporary, directory) = store();
    let tombstone = directory.create_retained_private("incomplete", 64).unwrap();
    std::fs::set_permissions(
        directory.path().join("incomplete"),
        std::fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    drop(tombstone);
    let mut count = 0;
    directory
        .visit_private_files(1, |_, metadata| {
            count += 1;
            assert!(metadata.is_empty());
            assert!(!metadata.is_read_only());
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 1);
    assert!(directory.open_retained_read_only("incomplete", 64).is_err());
    std::fs::set_permissions(
        directory.path().join("incomplete"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink("incomplete", directory.path().join("alias")).unwrap();
    assert!(directory.visit_private_files(2, |_, _| Ok(())).is_err());
    std::fs::remove_file(directory.path().join("alias")).unwrap();
    std::fs::hard_link(
        directory.path().join("incomplete"),
        directory.path().join("hardlink"),
    )
    .unwrap();
    assert!(directory.visit_private_files(2, |_, _| Ok(())).is_err());
    std::fs::remove_file(directory.path().join("hardlink")).unwrap();
    std::fs::set_permissions(
        directory.path().join("incomplete"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(directory.visit_private_files(1, |_, _| Ok(())).is_err());
    let alias = directory.path().parent().unwrap().join("directory-alias");
    symlink(directory.path(), &alias).unwrap();
    assert!(PrivateDirectory::open_exact(alias).is_err());
}

#[cfg(windows)]
#[test]
fn windows_readonly_attribute_cannot_substitute_for_immutable_receipt_acl() {
    let (_temporary, directory) = store();
    let file = directory
        .create_retained_private("writable-acl", 64)
        .unwrap();
    let mut permissions = std::fs::metadata(directory.path().join("writable-acl"))
        .unwrap()
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(directory.path().join("writable-acl"), permissions).unwrap();
    drop(file);
    assert!(
        directory
            .open_retained_read_only("writable-acl", 64)
            .is_err()
    );
    directory
        .visit_private_files(1, |_, metadata| {
            assert!(!metadata.is_read_only());
            Ok(())
        })
        .unwrap();
}

#[cfg(unix)]
#[test]
fn publication_rejects_substituted_source_name_before_creating_destination() {
    let (_temporary, directory) = store();
    let mut original = directory.create_retained_private("inflight", 64).unwrap();
    original.write_all(b"original").unwrap();
    let original = original.seal_read_only().unwrap();
    let id = original.identity().unwrap();
    std::fs::rename(
        directory.path().join("inflight"),
        directory.path().join("retained-original"),
    )
    .unwrap();
    let mut replacement = directory.create_retained_private("inflight", 64).unwrap();
    replacement.write_all(b"substitute").unwrap();
    let _replacement = replacement.seal_read_only().unwrap();
    assert!(original.publish_new_name("receipt").is_err());
    assert!(!directory.path().join("receipt").exists());
    assert_eq!(
        directory
            .open_retained_read_only("retained-original", 64)
            .unwrap()
            .identity()
            .unwrap(),
        id
    );
}

#[cfg(unix)]
#[test]
fn opaque_sealed_reader_rejects_external_rewrite_and_oversized_creation() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, directory) = store();
    let mut writer = directory.create_retained_private("receipt", 8).unwrap();
    writer.write_all(b"original").unwrap();
    let sealed = writer.seal_read_only().unwrap();
    let path = directory.path().join("receipt");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, b"modified").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(sealed.revalidate().is_err());
    let writer = directory.create_retained_private("oversized", 8).unwrap();
    std::fs::write(
        directory.path().join("oversized"),
        b"external oversized extent",
    )
    .unwrap();
    assert!(writer.seal_read_only().is_err());
    assert!(directory.open_retained_read_only("oversized", 8).is_err());
}

#[cfg(target_vendor = "apple")]
#[test]
fn mode_zero_inventory_authenticates_extended_acl_without_reading_file_data() {
    use std::{
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        process::Command,
    };
    let (_temporary, directory) = store();
    let tombstone = directory.create_retained_private("incomplete", 64).unwrap();
    let path = directory.path().join("incomplete");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
    drop(tombstone);
    assert!(
        Command::new("chmod")
            .args(["+a", "everyone allow readsecurity"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        directory
            .visit_private_files(1, |_, _| panic!("granting ACL must fail before visitor"))
            .is_err()
    );
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0);
    assert!(
        Command::new("chmod")
            .args(["-N"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("chmod")
            .args(["+a", "everyone deny read"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut count = 0;
    directory
        .visit_private_files(1, |_, metadata| {
            count += 1;
            assert_eq!(metadata.len(), 0);
            assert!(!metadata.is_read_only());
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        std::fs::metadata(&path).unwrap().mode() & 0o7777,
        0,
        "inventory must never repair or harden the tombstone"
    );
}
