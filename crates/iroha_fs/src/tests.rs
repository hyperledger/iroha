//! Native custody, immutable reads, atomic publication and ownership regressions.

use super::*;
use std::{
    fs,
    io::{SeekFrom, Write as _},
};

fn store() -> (tempfile::TempDir, PrivateDirectory) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let store =
        PrivateDirectory::open_or_create(temporary.path().join("private")).expect("private store");
    (temporary, store)
}

#[test]
fn atomic_staging_names_accept_only_the_native_writer_grammar() {
    assert!(is_atomic_staging_name(OsStr::new(&temporary_name())));
    for name in [
        ".iroha-fs-1-0.tmp",
        ".iroha-fs-4294967295-18446744073709551615.tmp",
    ] {
        assert!(is_atomic_staging_name(OsStr::new(name)), "{name}");
    }
    for name in [
        ".iroha-fs-0-0.tmp",
        ".iroha-fs-01-0.tmp",
        ".iroha-fs-1-00.tmp",
        ".iroha-fs-+1-0.tmp",
        ".iroha-fs-1-+0.tmp",
        ".iroha-fs-1--1.tmp",
        ".iroha-fs-4294967296-0.tmp",
        ".iroha-fs-1-18446744073709551616.tmp",
        ".iroha-fs-1-0.tmp.extra",
        "clock-floor-v1.next",
        "record",
    ] {
        assert!(!is_atomic_staging_name(OsStr::new(name)), "{name}");
    }
}

#[test]
fn interrupted_atomic_staging_cleanup_preserves_original_state_and_lock() {
    let (_temporary, store) = store();
    let lock = store.create_lock("lock").unwrap();
    lock.try_lock().unwrap();
    store
        .write_atomic("state", b"committed", PublishMode::CreateNew)
        .unwrap();
    let state = FileSnapshot::private_journal(&store.open_read("state").unwrap()).unwrap();
    // Reproduce crashes before a body write and after a partial body write. Neither file has
    // reached its destination name; recovery never treats either as committed state.
    let zero = store.create_lock(".iroha-fs-1-0.tmp").unwrap();
    zero.sync_all().unwrap();
    drop(zero);
    let mut partial = store.create_lock(".iroha-fs-1-1.tmp").unwrap();
    partial.write_all(b"partial").unwrap();
    partial.sync_all().unwrap();
    drop(partial);
    assert_eq!(
        store
            .reconcile_atomic_staging(&["lock", "state"], 2, 7)
            .unwrap(),
        2
    );
    assert_eq!(store.read("state", 9).unwrap().as_slice(), b"committed");
    assert_eq!(
        FileSnapshot::private_journal(&store.open_read("state").unwrap()).unwrap(),
        state
    );
    assert!(
        store
            .open_existing_lock("lock")
            .unwrap()
            .try_lock()
            .is_err()
    );
    assert_eq!(
        store
            .reconcile_atomic_staging(&["lock", "state"], 0, 0)
            .unwrap(),
        0
    );
}

#[test]
fn atomic_staging_cleanup_never_recovers_a_missing_committed_file() {
    let (_temporary, store) = store();
    let lock = store.create_lock("lock").unwrap();
    lock.try_lock().unwrap();
    store
        .write_atomic(".iroha-fs-1-0.tmp", b"uncommitted", PublishMode::CreateNew)
        .unwrap();
    let before = store.entries(2).unwrap();
    assert_eq!(
        store
            .reconcile_atomic_staging(&["lock", "state"], 1, 32)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(store.entries(2).unwrap(), before);
    assert_eq!(
        store.read(".iroha-fs-1-0.tmp", 32).unwrap().as_slice(),
        b"uncommitted"
    );
}

#[test]
fn atomic_staging_cleanup_validates_every_name_and_extent_before_mutation() {
    let (_temporary, store) = store();
    let lock = store.create_lock("lock").unwrap();
    lock.try_lock().unwrap();
    store
        .write_atomic("state", b"original", PublishMode::CreateNew)
        .unwrap();
    store
        .write_atomic(".iroha-fs-1-0.tmp", b"small", PublishMode::CreateNew)
        .unwrap();
    store
        .write_atomic(".iroha-fs-1-1.tmp", b"larger", PublishMode::CreateNew)
        .unwrap();
    let before = store.entries(4).unwrap();
    for (count, bytes) in [(1, 6), (2, 5), (17, 6)] {
        assert!(
            store
                .reconcile_atomic_staging(&["lock", "state"], count, bytes)
                .is_err()
        );
        assert_eq!(store.entries(4).unwrap(), before);
    }
    for required in [
        vec![],
        vec!["state", "state"],
        vec!["../escape"],
        vec![".iroha-fs-1-0.tmp"],
    ] {
        assert!(store.reconcile_atomic_staging(&required, 2, 6).is_err());
        assert_eq!(store.entries(4).unwrap(), before);
    }
    store
        .write_atomic("z-unknown", b"unowned", PublishMode::CreateNew)
        .unwrap();
    let before = store.entries(5).unwrap();
    assert!(
        store
            .reconcile_atomic_staging(&["lock", "state"], 3, 6)
            .is_err()
    );
    assert_eq!(store.entries(5).unwrap(), before);
    assert_eq!(
        store.read(".iroha-fs-1-0.tmp", 6).unwrap().as_slice(),
        b"small"
    );
    assert_eq!(store.read("state", 8).unwrap().as_slice(), b"original");
}

#[test]
fn atomic_staging_cleanup_refuses_a_directory_before_removing_any_file() {
    let (_temporary, store) = store();
    let lock = store.create_lock("lock").unwrap();
    lock.try_lock().unwrap();
    store
        .write_atomic(".iroha-fs-1-0.tmp", b"retained", PublishMode::CreateNew)
        .unwrap();
    let child = store.create_child(".iroha-fs-1-1.tmp").unwrap();
    assert!(store.reconcile_atomic_staging(&["lock"], 2, 8).is_err());
    assert_eq!(store.entries(3).unwrap().len(), 3);
    assert_eq!(
        store.read(".iroha-fs-1-0.tmp", 8).unwrap().as_slice(),
        b"retained"
    );
    child.revalidate().unwrap();
}

#[cfg(unix)]
#[test]
fn atomic_staging_cleanup_refuses_links_modes_and_replaced_ancestors() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["symlink", "hardlink", "mode", "ancestor"] {
        let (temporary, store) = store();
        let lock = store.create_lock("lock").unwrap();
        lock.try_lock().unwrap();
        store
            .write_atomic("state", b"committed", PublishMode::CreateNew)
            .unwrap();
        store
            .write_atomic(".iroha-fs-1-0.tmp", b"retained", PublishMode::CreateNew)
            .unwrap();
        let unsafe_path = store.path().join(".iroha-fs-1-1.tmp");
        let mut actual = store.path().to_owned();
        match attack {
            "symlink" => symlink("state", &unsafe_path).unwrap(),
            "hardlink" => fs::hard_link(store.path().join("state"), &unsafe_path).unwrap(),
            "mode" => {
                store
                    .write_atomic(".iroha-fs-1-1.tmp", b"unsafe", PublishMode::CreateNew)
                    .unwrap();
                fs::set_permissions(unsafe_path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "ancestor" => {
                actual = temporary.path().join("displaced");
                fs::rename(store.path(), &actual).unwrap();
                fs::create_dir(store.path()).unwrap();
                fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            store
                .reconcile_atomic_staging(&["lock", "state"], 2, 16)
                .is_err(),
            "{attack}"
        );
        assert_eq!(fs::read(actual.join("state")).unwrap(), b"committed");
        assert_eq!(
            fs::read(actual.join(".iroha-fs-1-0.tmp")).unwrap(),
            b"retained"
        );
        if attack == "ancestor" {
            assert_eq!(fs::read_dir(store.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn complete_private_directory_publication_never_exposes_partial_destination() {
    let (temporary, _) = store();
    let parent = OwnerDirectory::open(temporary.path()).unwrap();
    let single = parent
        .publish_private_child("single", &[("record", b"complete")])
        .unwrap();
    let single_identity = single.identity().unwrap();
    assert_eq!(
        single.entries(1).unwrap(),
        vec![std::ffi::OsString::from("record")]
    );
    assert_eq!(single.read("record", 16).unwrap().as_slice(), b"complete");
    // The published owner supplies canonical spelling even when the OS temporary root
    // uses an alias such as macOS /var. Exact reopen must use that retained native path.
    let reopened = PrivateDirectory::open_exact(single.path()).unwrap();
    assert_eq!(reopened.identity().unwrap(), single_identity);
    assert_eq!(reopened.read("record", 16).unwrap().as_slice(), b"complete");
    assert!(
        parent
            .publish_private_child("single", &[("record", b"replacement")])
            .is_err()
    );
    assert_eq!(single.identity().unwrap(), single_identity);
    assert_eq!(single.read("record", 16).unwrap().as_slice(), b"complete");
    // A crash before rename leaves only an unpublished private sibling. A retry can still
    // publish the complete destination; no caller has to delete ambiguous operation evidence.
    let interrupted = parent.create_private_child("unpublished").unwrap();
    interrupted
        .write_atomic("lock", b"", PublishMode::CreateNew)
        .unwrap();
    let published = parent
        .publish_private_child("ready", &[("lock", b""), ("record", b"original")])
        .unwrap();
    assert_eq!(
        published.entries(2).unwrap(),
        vec![
            std::ffi::OsString::from("lock"),
            std::ffi::OsString::from("record")
        ]
    );
    assert!(published.read("lock", 1).unwrap().is_empty());
    assert_eq!(
        published.read("record", 16).unwrap().as_slice(),
        b"original"
    );
    let lock = published.open_existing_lock("lock").unwrap();
    lock.try_lock().unwrap();
    assert!(
        parent
            .publish_private_child("ready", &[("record", b"replacement")])
            .is_err()
    );
    assert_eq!(
        published.read("record", 16).unwrap().as_slice(),
        b"original"
    );
    let oversized_names: Vec<_> = (0..129).map(|index| format!("entry-{index}")).collect();
    let oversized_files: Vec<_> = oversized_names
        .iter()
        .map(|name| (name.as_str(), b"x".as_slice()))
        .collect();
    for files in [
        vec![],
        vec![("same", b"a".as_slice()), ("same", b"b".as_slice())],
        vec![("../escape", b"a".as_slice())],
        oversized_files,
    ] {
        assert!(parent.publish_private_child("absent", &files).is_err());
        assert!(!temporary.path().join("absent").exists());
    }
    assert!(interrupted.path().join("lock").is_file());
}

#[test]
fn exact_lock_creation_and_open_never_change_missing_or_existing_custody() {
    let (_temporary, store) = store();
    assert_eq!(
        store.open_existing_lock("journal.lock").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(store.entries(0).unwrap().is_empty());
    let mut first = store.create_lock("journal.lock").unwrap();
    first.write_all(b"retained").unwrap();
    first.sync_all().unwrap();
    assert!(store.create_lock("journal.lock").is_err());
    first.try_lock().unwrap();
    let second = store.open_existing_lock("journal.lock").unwrap();
    assert!(second.try_lock().is_err());
    assert_eq!(
        store.read("journal.lock", 8).unwrap().as_slice(),
        b"retained"
    );
}

#[test]
fn consuming_empty_directory_removal_preserves_parent_and_refuses_descendants() {
    let (_temporary, store) = store();
    let parent = OwnerDirectory::open(store.path()).unwrap();
    let pending = parent.create_private_child("pending").unwrap();
    assert!(parent.create_private_child("pending").is_err());
    let child = pending.create_child("nested").unwrap();
    assert!(pending.remove_empty().is_err());
    drop(child);
    assert!(store.open_child("pending").unwrap().remove_empty().is_err());
    let pending = store.open_child("pending").unwrap();
    pending.clear_contents_preserving(&[]).unwrap();
    pending.remove_empty().unwrap();
    assert!(store.open_child("pending").is_err());
    parent.revalidate().unwrap();
    assert!(store.entries(0).unwrap().is_empty());
}

#[test]
fn retained_directory_listing_is_bounded_and_does_not_follow_children() {
    let (_temporary, store) = store();
    assert!(store.entries(0).unwrap().is_empty());
    store
        .write_atomic("zeta", b"one", PublishMode::CreateNew)
        .unwrap();
    let child = store.create_child("alpha").unwrap();
    child
        .write_atomic("nested", b"two", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        store.entries(2).unwrap(),
        vec![
            std::ffi::OsString::from("alpha"),
            std::ffi::OsString::from("zeta")
        ]
    );
    assert!(store.entries(1).is_err());
    assert!(store.entries(0).is_err());
}

#[test]
fn project_directory_listing_preserves_reader_access_and_enforces_entry_bound() {
    let (_temporary, private) = store();
    let path = private.path().to_path_buf();
    drop(private);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let project = OwnerDirectory::open(&path).unwrap();
    assert!(project.entries(0).unwrap().is_empty());
    project
        .write_atomic("zeta.ko", b"source", PublishMode::CreateNew)
        .unwrap();
    let child = project.create_child("alpha").unwrap();
    child
        .write_atomic("nested.ko", b"nested", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        project.entries(2).unwrap(),
        vec![
            OsStr::new("alpha").to_owned(),
            OsStr::new("zeta.ko").to_owned()
        ]
    );
    assert!(project.entries(1).is_err());
    assert!(project.entries(0).is_err());
    project.revalidate().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[test]
fn project_authority_keeps_readers_and_publishes_private_files() {
    let (_temporary, private) = store();
    let path = private.path().to_path_buf();
    drop(private);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let project = OwnerDirectory::open(&path).unwrap();
    let identity = project.identity().unwrap();
    assert_eq!(
        OwnerDirectory::open_or_create(&path)
            .unwrap()
            .identity()
            .unwrap(),
        identity
    );
    fs::write(path.join("existing"), b"readable source").unwrap();
    assert_eq!(
        project.read_regular("existing", 15).unwrap().as_slice(),
        b"readable source"
    );
    project
        .write_atomic("existing", b"generated", PublishMode::Replace)
        .unwrap();
    assert_eq!(
        read_private(path.join("existing"), 9).unwrap().as_slice(),
        b"generated"
    );
    let child = project.create_child("target").unwrap();
    assert_eq!(
        project.open_child("target").unwrap().identity().unwrap(),
        child.identity().unwrap()
    );
    assert_eq!(
        project.ensure_child("target").unwrap().identity().unwrap(),
        child.identity().unwrap()
    );
    assert_eq!(
        project.create_child("target").unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(project.open_child("missing").is_err());
    assert!(!path.join("missing").exists());
    child.sync().unwrap();
    project.revalidate().unwrap();
    project.sync().unwrap();
    let lock = project.open_lock("target.lock").unwrap();
    lock.try_lock().unwrap();
    assert!(
        project
            .open_lock("target.lock")
            .unwrap()
            .try_lock()
            .is_err()
    );
    assert!(project.open_child("../escape").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[test]
fn retained_streaming_preserves_identity_bounds_and_exclusive_creation() {
    let (_temporary, directory) = store();
    let path = directory.path().join("payload");
    let mut writer = RetainedFile::create_new_private(&path).unwrap();
    let identity = writer.identity().unwrap();
    writer.file_mut().write_all(b"bounded payload").unwrap();
    writer.file().sync_all().unwrap();
    writer.revalidate().unwrap();
    assert_eq!(FileIdentity::of(writer.file()).unwrap(), identity);
    assert!(RetainedFile::create_new_private(&path).is_err());
    drop(writer);
    for mut reader in [
        RetainedFile::open_regular(&path).unwrap(),
        RetainedFile::open_private(&path).unwrap(),
    ] {
        let mut buffer = [0; 7];
        reader.file_mut().read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"bounded");
        reader.file_mut().seek(SeekFrom::Start(8)).unwrap();
        let mut remainder = String::new();
        reader.file_mut().read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, "payload");
        reader.revalidate().unwrap();
        assert_eq!(reader.identity().unwrap(), identity);
    }
    fs::hard_link(&path, directory.path().join("alias")).unwrap();
    assert!(RetainedFile::open_regular(&path).is_err());
    assert!(RetainedFile::open_private(&path).is_err());
}

#[test]
fn sealing_a_writer_keeps_its_identity_and_detects_later_writes() {
    let (_temporary, directory) = store();
    let mut file = RetainedFile::create_new_private(directory.path().join("payload")).unwrap();
    file.file_mut().write_all(b"complete").unwrap();
    let identity = file.identity().unwrap();
    let mut sealed = file.seal().unwrap();
    assert_eq!(sealed.identity().unwrap(), identity);
    sealed.revalidate().unwrap();
    sealed.file_mut().write_all(b"changed").unwrap();
    sealed.file().sync_all().unwrap();
    assert!(sealed.revalidate().is_err());
}

#[test]
fn snapshot_tokens_bind_separately_opened_object_and_content() {
    let (_temporary, directory) = store();
    let path = directory.path().join("source");
    directory
        .write_atomic("source", b"first", PublishMode::CreateNew)
        .unwrap();
    let first = RetainedFile::open_regular(&path)
        .unwrap()
        .snapshot()
        .unwrap();
    let same = RetainedFile::open_regular(&path)
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(first, same);
    directory
        .write_atomic("source", b"other", PublishMode::Replace)
        .unwrap();
    let different = RetainedFile::open_regular(&path)
        .unwrap()
        .snapshot()
        .unwrap();
    assert_ne!(first, different);
}

#[test]
fn read_only_log_open_never_creates_or_writes() {
    let (_temporary, directory) = store();
    assert!(directory.open_read("missing").is_err());
    assert!(!directory.path().join("missing").exists());
    directory
        .write_atomic("log", b"one\n", PublishMode::CreateNew)
        .unwrap();
    let mut reader = directory.open_read("log").unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"one\n");
    assert!(reader.write_all(b"replacement").is_err());
    assert_eq!(directory.read("log", 4).unwrap().as_slice(), b"one\n");
}

#[test]
fn directory_publication_preserves_exact_tree_and_never_replaces() {
    let (_temporary, directory) = store();
    let staged = directory.create_child("staged").unwrap();
    staged
        .write_atomic("complete", b"verified", PublishMode::CreateNew)
        .unwrap();
    staged.sync().unwrap();
    let identity = staged.identity().unwrap();
    let published = staged
        .rename_to_sibling("src", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(published.identity().unwrap(), identity);
    assert_eq!(published.path(), directory.path().join("src"));
    assert_eq!(
        published.read("complete", 8).unwrap().as_slice(),
        b"verified"
    );
    assert!(!directory.path().join("staged").exists());
    let conflicting = directory.create_child("other").unwrap();
    assert!(
        conflicting
            .rename_to_sibling("src", PublishMode::CreateNew)
            .is_err()
    );
    assert_eq!(published.identity().unwrap(), identity);
    assert!(
        directory
            .create_child("replace")
            .unwrap()
            .rename_to_sibling("src", PublishMode::Replace)
            .is_err()
    );
}

#[test]
fn published_directory_keeps_original_identity_and_allows_independent_readers() {
    let (_temporary, parent) = store();
    let staging = parent.create_child("staged-readers").unwrap();
    staging
        .write_atomic("original", b"complete", PublishMode::CreateNew)
        .unwrap();
    let identity = staging.identity().unwrap();
    let published = staging
        .rename_to_sibling("published-readers", PublishMode::CreateNew)
        .unwrap();
    // Keep the returned publication owner alive while unrelated reader owners traverse it.
    // A Windows DELETE publication handle must not escape into this ordinary read phase.
    let reopened = PrivateDirectory::open_exact(published.path()).unwrap();
    assert_eq!(reopened.identity().unwrap(), identity);
    // Publication returns a normal owner: metadata durability and later writes remain usable.
    // On Windows that requires WRITE_ATTRIBUTES without retaining DELETE authority.
    published.sync().unwrap();
    published
        .write_atomic("later", b"retained", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(reopened.read("later", 8).unwrap().as_slice(), b"retained");
    let namespace = ReaderDirectory::open(published.path()).unwrap();
    let before = namespace.snapshot().unwrap();
    let mut original = RetainedFile::open_private(published.path().join("original")).unwrap();
    let mut bytes = Vec::new();
    original.file_mut().read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"complete");
    original.revalidate().unwrap();
    assert_eq!(namespace.snapshot().unwrap(), before);
    assert_eq!(published.identity().unwrap(), identity);
    published.revalidate().unwrap();
}

#[test]
fn retained_descendants_block_directory_publication() {
    let (_temporary, directory) = store();
    let staged = directory.create_child("staged").unwrap();
    let child = staged.create_child("live").unwrap();
    assert!(
        staged
            .rename_to_sibling("src", PublishMode::CreateNew)
            .is_err()
    );
    child.revalidate().unwrap();
    assert!(!directory.path().join("src").exists());
}

#[test]
fn private_publication_and_bounded_read_round_trip() {
    let (_temporary, store) = store();
    store
        .write_atomic("key", b"sensitive-data", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(store.read("key", 14).unwrap().as_slice(), b"sensitive-data");
    assert!(store.read("key", 13).is_err());
    assert_eq!(
        read_private(store.path().join("key"), 14)
            .unwrap()
            .as_slice(),
        b"sensitive-data"
    );
    assert_eq!(
        read_regular(store.path().join("key"), 14)
            .unwrap()
            .as_slice(),
        b"sensitive-data"
    );
    store.sync().unwrap();
}

#[test]
fn create_new_never_clobbers_and_replace_changes_identity() {
    let (_temporary, store) = store();
    store
        .write_atomic("journal", b"prepared", PublishMode::CreateNew)
        .unwrap();
    let identity = FileIdentity::of(&File::open(store.path().join("journal")).unwrap()).unwrap();
    let error = store
        .write_atomic("journal", b"second", PublishMode::CreateNew)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(store.read("journal", 8).unwrap().as_slice(), b"prepared");
    store
        .write_atomic("journal", b"committed", PublishMode::Replace)
        .unwrap();
    assert_eq!(store.read("journal", 9).unwrap().as_slice(), b"committed");
    assert_ne!(
        identity,
        FileIdentity::of(&File::open(store.path().join("journal")).unwrap()).unwrap()
    );
    assert_eq!(fs::read_dir(store.path()).unwrap().count(), 1);
}

#[test]
fn child_creation_preserves_existing_custody_and_names() {
    let (_temporary, store) = store();
    let child = store.create_child("日本語").unwrap();
    let existing = store.ensure_child("日本語").unwrap();
    assert_eq!(child.path(), existing.path());
    assert_eq!(
        store.create_child("日本語").unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    child
        .write_atomic("bytes", b"", PublishMode::CreateNew)
        .unwrap();
    assert!(child.read("bytes", 0).unwrap().is_empty());
    let reopened = PrivateDirectory::open(child.path()).unwrap();
    reopened.revalidate().unwrap();
    assert!(PrivateDirectory::open(store.path().join("missing")).is_err());
    assert!(!store.path().join("missing").exists());
}

#[test]
fn traversal_stream_and_device_names_are_rejected_before_mutation() {
    let (_temporary, store) = store();
    for name in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "secret:stream",
        "NUL",
        "nul.txt",
        "COM1",
        "LPT9.txt",
        "trailing.",
        "trailing ",
        "nul\0byte",
    ] {
        assert!(
            store
                .write_atomic(name, b"secret", PublishMode::CreateNew)
                .is_err(),
            "{name:?}"
        );
        assert!(store.ensure_child(name).is_err(), "{name:?}");
        assert!(store.read(name, 10).is_err(), "{name:?}");
        assert!(store.open_lock(name).is_err(), "{name:?}");
    }
    assert_eq!(fs::read_dir(store.path()).unwrap().count(), 0);
    assert!(PrivateDirectory::open_or_create(store.path().join("../escaped")).is_err());
}

#[test]
fn persistent_lock_handles_exclude_another_open_and_do_not_truncate() {
    let (_temporary, store) = store();
    let mut first = store.open_lock("owner.lock").unwrap();
    first.try_lock().unwrap();
    first.write_all(b"owner").unwrap();
    first.sync_all().unwrap();
    let mut second = store.open_lock("owner.lock").unwrap();
    assert!(second.try_lock().is_err());
    let mut bytes = Vec::new();
    second.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"owner");
    drop(first);
    // Another parallel test may be between fork/posix_spawn and exec. CLOEXEC keeps this
    // descriptor out of the executed child, but the inherited open-file description can
    // briefly retain its lock until exec completes. Ownership must remain excluded then.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match second.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => panic!("released lock remained unavailable: {error}"),
        }
    }
}

#[test]
fn append_handle_can_read_tail_and_never_overwrites() {
    let (_temporary, store) = store();
    let mut log = store.open_append("serve.log").unwrap();
    log.write_all(b"one\n").unwrap();
    log.seek(SeekFrom::Start(0)).unwrap();
    log.write_all(b"two\n").unwrap();
    log.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    log.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"one\ntwo\n");
}

#[test]
fn hard_linked_files_are_never_read_or_replaced() {
    let (_temporary, store) = store();
    store
        .write_atomic("key", b"original", PublishMode::CreateNew)
        .unwrap();
    fs::hard_link(store.path().join("key"), store.path().join("alias")).unwrap();
    assert!(store.read("key", 1024).is_err());
    assert!(read_private(store.path().join("key"), 1024).is_err());
    assert!(read_regular(store.path().join("key"), 1024).is_err());
    assert!(store.open_lock("key").is_err());
    assert!(
        store
            .write_atomic("key", b"replaced", PublishMode::Replace)
            .is_err()
    );
    assert_eq!(fs::read(store.path().join("alias")).unwrap(), b"original");
}

#[test]
fn clear_preserves_locked_files_and_directory_identity() {
    let (_temporary, store) = store();
    let lock = store.open_lock("owner.lock").unwrap();
    lock.try_lock().unwrap();
    let identity = FileIdentity::of(&lock).unwrap();
    let child = store.create_child("generation").unwrap();
    child
        .write_atomic("secret", b"secret", PublishMode::CreateNew)
        .unwrap();
    drop(child);
    store
        .write_atomic("context", b"ready", PublishMode::CreateNew)
        .unwrap();
    store.clear_contents_preserving(&["owner.lock"]).unwrap();
    assert_eq!(fs::read_dir(store.path()).unwrap().count(), 1);
    assert_eq!(
        FileIdentity::of(&store.open_lock("owner.lock").unwrap()).unwrap(),
        identity
    );
    assert!(store.open_lock("owner.lock").unwrap().try_lock().is_err());
    store.revalidate().unwrap();
    assert!(store.clear_contents_preserving(&["../outside"]).is_err());
}

#[test]
fn clear_rejects_shared_entries_and_missing_preserved_files() {
    let (_temporary, store) = store();
    store
        .write_atomic("one", b"secret", PublishMode::CreateNew)
        .unwrap();
    fs::hard_link(store.path().join("one"), store.path().join("two")).unwrap();
    assert!(store.clear_contents_preserving(&["missing"]).is_err());
    assert!(store.clear_contents_preserving(&[]).is_err());
    assert_eq!(fs::read(store.path().join("one")).unwrap(), b"secret");
}

#[cfg(windows)]
mod windows {
    use super::*;

    #[test]
    fn process_owner_comes_from_kernel_token() {
        assert!(crate::windows::is_current_user_process(std::process::id()).unwrap());
        assert!(crate::windows::is_current_user_process(0).is_err());
    }

    #[test]
    fn retained_directories_cannot_be_renamed_or_replaced() {
        let (temporary, store) = store();
        assert!(fs::rename(store.path(), temporary.path().join("moved")).is_err());
        store
            .write_atomic("key", b"secret", PublishMode::CreateNew)
            .unwrap();
        assert_eq!(store.read("key", 6).unwrap().as_slice(), b"secret");
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    #[test]
    fn private_modes_are_present_from_creation_and_not_silently_hardened() {
        let (_temporary, store) = store();
        assert_eq!(fs::metadata(store.path()).unwrap().mode() & 0o7777, 0o700);
        store
            .write_atomic("key", b"secret", PublishMode::CreateNew)
            .unwrap();
        let path = store.path().join("key");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read("key", 100).is_err());
        assert!(
            store
                .write_atomic("key", b"replacement", PublishMode::Replace)
                .is_err()
        );
        assert_eq!(read_regular(&path, 100).unwrap().as_slice(), b"secret");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o644);
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(PrivateDirectory::open_or_create(store.path()).is_err());
        assert!(store.revalidate().is_err());
    }

    #[test]
    fn links_and_replaced_ancestors_do_not_redirect_operations() {
        let (temporary, store) = store();
        store
            .write_atomic("key", b"original", PublishMode::CreateNew)
            .unwrap();
        symlink(store.path().join("key"), store.path().join("linked")).unwrap();
        assert!(store.read("linked", 1024).is_err());
        assert!(store.open_append("linked").is_err());
        let moved = temporary.path().join("moved");
        fs::rename(store.path(), &moved).unwrap();
        fs::create_dir(store.path()).unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            store
                .write_atomic("new", b"do not write", PublishMode::CreateNew)
                .is_err()
        );
        assert!(!moved.join("new").exists());
        assert!(!store.path().join("new").exists());
    }

    #[test]
    fn unsafe_ancestors_are_rejected_before_private_creation() {
        let temporary = tempfile::tempdir().unwrap();
        let unsafe_parent = temporary.path().join("shared");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(PrivateDirectory::open_or_create(unsafe_parent.join("secret")).is_err());
        assert!(!unsafe_parent.join("secret").exists());
    }

    #[test]
    fn fifo_is_refused_without_waiting_for_a_writer() {
        let (_temporary, store) = store();
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(store.path().join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        assert!(store.read("fifo", 1024).is_err());
        assert!(store.open_lock("fifo").is_err());
    }

    #[test]
    fn public_input_rejects_an_untrusted_user_link() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("real");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("input"), b"code").unwrap();
        symlink(&directory, temporary.path().join("alias")).unwrap();
        assert!(read_regular(temporary.path().join("alias/input"), 1024).is_err());
    }
}

#[test]
fn retained_directory_custody_shares_original_ancestry_and_preserves_access() {
    let (_temporary, store) = store();
    let child = store.create_child("retained").unwrap();
    child
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let identity = child.identity().unwrap();
    let path = child.path().to_owned();
    let retained = (0..64).map(|_| child.retain().unwrap()).collect::<Vec<_>>();
    drop(child);
    drop(store);
    for directory in &retained {
        assert_eq!(directory.identity().unwrap(), identity);
        assert_eq!(directory.path(), path);
        assert_eq!(directory.read("record", 8).unwrap().as_slice(), b"original");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path.join("record"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(retained[0].retain().is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn retained_directory_custody_refuses_replaced_child_and_ancestor() {
    use std::os::unix::fs::PermissionsExt as _;
    for ancestor in [false, true] {
        let (temporary, store) = store();
        let child = store.create_child("retained").unwrap();
        child
            .write_atomic("record", b"original", PublishMode::CreateNew)
            .unwrap();
        let retained = child.retain().unwrap();
        let target = if ancestor { store.path() } else { child.path() };
        let displaced = temporary.path().join("displaced");
        fs::rename(target, &displaced).unwrap();
        fs::create_dir(target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(child.revalidate().is_err());
        assert!(retained.revalidate().is_err());
        assert!(child.retain().is_err());
        assert!(retained.retain().is_err());
        assert!(retained.read("record", 8).is_err());
        let original = if ancestor {
            displaced.join("retained/record")
        } else {
            displaced.join("record")
        };
        assert_eq!(fs::read(original).unwrap(), b"original");
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
    }
}

#[cfg(windows)]
#[test]
fn retained_directory_custody_keeps_native_child_and_ancestor_replacement_blocked() {
    let (temporary, store) = store();
    let child = store.create_child("retained").unwrap();
    let retained = child.retain().unwrap();
    let identity = child.identity().unwrap();
    assert!(fs::rename(child.path(), temporary.path().join("child-moved")).is_err());
    assert!(fs::rename(store.path(), temporary.path().join("ancestor-moved")).is_err());
    child.revalidate().unwrap();
    retained.revalidate().unwrap();
    assert_eq!(retained.identity().unwrap(), identity);
}

#[cfg(unix)]
#[test]
fn retained_child_readers_fit_native_descriptor_limit() {
    const CHILD_MARKER: &str = "IROHA_FS_RETAINED_CHILD_LIMIT_TEST";
    if std::env::var_os(CHILD_MARKER).is_none() {
        // Isolate the real native limit from the parallel test runner. The
        // executable path is a separate argument, never shell source text.
        let result = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "ulimit -n 64; exec \"$1\" --exact tests::retained_child_readers_fit_native_descriptor_limit --nocapture",
                "iroha-fs-retained-child-test",
            ])
            .arg(std::env::current_exe().unwrap())
            .env(CHILD_MARKER, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let (_temporary, store) = store();
    let mut nested = store.retain().unwrap();
    for index in 0..12 {
        nested = nested.ensure_child(format!("ancestor-{index}")).unwrap();
    }
    for index in 0..32 {
        nested
            .write_atomic(
                format!("journal-{index}"),
                b"opaque incident",
                PublishMode::CreateNew,
            )
            .unwrap();
    }
    let mut retained = Vec::new();
    for index in 0..32 {
        retained.push(
            nested
                .open_retained_private(format!("journal-{index}"))
                .unwrap(),
        );
    }
    let path = nested.path().to_path_buf();
    drop(nested);
    drop(store);
    for file in retained {
        file.revalidate().unwrap();
        let mut bytes = [0; 15];
        read_exact_at(file.file(), &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"opaque incident");
    }
    let reader = ReaderDirectory::open(path).unwrap();
    let mut retained = Vec::new();
    for index in 0..32 {
        let file = if index % 2 == 0 {
            reader
                .open_retained_private(format!("journal-{index}"))
                .unwrap()
        } else {
            reader
                .open_retained_regular(format!("journal-{index}"))
                .unwrap()
        };
        retained.push(file);
    }
    drop(reader);
    for file in retained {
        file.revalidate().unwrap();
        let mut bytes = [0; 15];
        read_exact_at(file.file(), &mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"opaque incident");
    }
}

#[cfg(unix)]
#[test]
fn retained_child_readers_refuse_replaced_ancestor_and_foreign_child() {
    use std::os::unix::fs::PermissionsExt as _;
    let (temporary, store) = store();
    let child = store.create_child("shared-readers").unwrap();
    child
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    let reader = ReaderDirectory::open(child.path()).unwrap();
    let files = [
        child.open_retained_private("record").unwrap(),
        reader.open_retained_private("record").unwrap(),
        reader.open_retained_regular("record").unwrap(),
    ];
    for bad in ["../record", "a/record", "", ".", ".."] {
        assert!(child.open_retained_private(bad).is_err());
        assert!(reader.open_retained_private(bad).is_err());
        assert!(reader.open_retained_regular(bad).is_err());
    }
    let displaced = temporary.path().join("displaced-readers");
    fs::rename(child.path(), &displaced).unwrap();
    fs::create_dir(child.path()).unwrap();
    fs::set_permissions(child.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(child.path().join("record"), b"foreign").unwrap();
    fs::set_permissions(
        child.path().join("record"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for file in files {
        assert!(file.revalidate().is_err());
        let mut original = [0; 8];
        read_exact_at(file.file(), &mut original, 0).unwrap();
        assert_eq!(&original, b"original");
    }
    assert!(reader.open_retained_regular("record").is_err());
    assert!(reader.open_retained_private("record").is_err());
    assert!(child.open_retained_private("record").is_err());
    assert_eq!(fs::read(child.path().join("record")).unwrap(), b"foreign");
}

#[test]
fn reader_children_share_native_ancestors_and_preserve_exact_original_files() {
    let (_temporary, store) = store();
    for index in 0..32 {
        let child = store.create_child(format!("child-{index}")).unwrap();
        child
            .write_atomic("source", b"original", PublishMode::CreateNew)
            .unwrap();
    }
    let reader = ReaderDirectory::open(store.path()).unwrap();
    let mut children = Vec::new();
    let mut sources = Vec::new();
    for index in 0..32 {
        let child = reader.open_child(format!("child-{index}")).unwrap();
        let source = child.open_retained_regular("source").unwrap();
        let mut bytes = [0_u8; 8];
        assert_eq!(read_at(source.file(), &mut bytes, 0).unwrap(), 8);
        assert_eq!(&bytes, b"original");
        sources.push((source, child.snapshot().unwrap()));
        children.push(child);
    }
    for (child, (source, snapshot)) in children.iter().zip(&sources) {
        child.revalidate().unwrap();
        assert_eq!(child.snapshot().unwrap(), *snapshot);
        source.revalidate().unwrap();
    }
    for invalid in ["", ".", "..", "child-0/source"] {
        assert!(reader.open_child(invalid).is_err());
    }
    assert!(reader.open_child("absent").is_err());
    assert!(!reader.path().join("absent").exists());
    reader.revalidate().unwrap();
}

#[cfg(unix)]
#[test]
fn shared_reader_children_refuse_link_substitution_and_changed_ancestors() {
    let (temporary, store) = store();
    let original = store.create_child("original").unwrap();
    original
        .write_atomic("source", b"original", PublishMode::CreateNew)
        .unwrap();
    let reader = ReaderDirectory::open(store.path()).unwrap();
    std::os::unix::fs::symlink("original", store.path().join("indirect")).unwrap();
    assert!(reader.open_child("indirect").is_err());
    assert!(reader.open_child("original/source").is_err());
    let child = reader.open_child("original").unwrap();
    let source = child.open_retained_regular("source").unwrap();
    let saved = temporary.path().join("original-child");
    fs::rename(original.path(), &saved).unwrap();
    store
        .create_child("original")
        .unwrap()
        .write_atomic("source", b"original", PublishMode::CreateNew)
        .unwrap();
    assert!(child.revalidate().is_err());
    assert!(source.revalidate().is_err());
    let renamed_store = temporary.path().join("renamed-store");
    fs::rename(store.path(), &renamed_store).unwrap();
    assert!(reader.open_child("original").is_err());
}

#[test]
fn selected_regular_file_keeps_native_identity_bounds_and_independent_read_offsets() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("nested");
    fs::create_dir(&parent).unwrap();
    let path = temporary.path().join("source");
    fs::write(&path, b"original bytes").unwrap();
    let selected = SelectedRegularFile::capture(parent.join("../source")).unwrap();
    assert_eq!(
        selected.path(),
        temporary.path().canonicalize().unwrap().join("source")
    );
    assert_eq!(selected.len().unwrap(), 14);
    assert!(!selected.is_empty().unwrap());
    assert_eq!(selected.read(14).unwrap(), b"original bytes");
    assert_eq!(selected.read(14).unwrap(), b"original bytes");
    assert_eq!(
        selected.read(13).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    std::thread::scope(|scope| {
        let first = scope.spawn(|| selected.read(14).unwrap());
        let second = scope.spawn(|| selected.read(14).unwrap());
        assert_eq!(first.join().unwrap(), b"original bytes");
        assert_eq!(second.join().unwrap(), b"original bytes");
    });
    selected.revalidate().unwrap();
    let empty = temporary.path().join("empty");
    fs::write(&empty, []).unwrap();
    let empty = SelectedRegularFile::capture(&empty).unwrap();
    assert!(empty.is_empty().unwrap());
    assert!(empty.read(0).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn selected_regular_file_refuses_original_mutation_replacement_and_link_substitution() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    for mutation in ["edit", "replace", "link"] {
        let path = temporary.path().join(mutation);
        fs::write(&path, b"original bytes").unwrap();
        let selected = SelectedRegularFile::capture(&path).unwrap();
        match mutation {
            "edit" => fs::write(&path, b"changed bytes").unwrap(),
            "replace" => {
                fs::rename(&path, temporary.path().join("retired-replace")).unwrap();
                fs::write(&path, b"original bytes").unwrap();
            }
            "link" => {
                fs::rename(&path, temporary.path().join("retired-link")).unwrap();
                let target = temporary.path().join("link-target");
                fs::write(&target, b"original bytes").unwrap();
                symlink(&target, &path).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(selected.revalidate().is_err(), "{mutation}");
        assert!(selected.read(14).is_err(), "{mutation}");
    }
}

#[cfg(unix)]
#[test]
fn retained_directory_edges_retry_original_after_native_refusal_and_restoration() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    for ancestor in [false, true] {
        let (temporary, store) = store();
        let child = store.create_child("retained").unwrap();
        child
            .write_atomic("record", b"original", PublishMode::CreateNew)
            .unwrap();
        let retained = child.retain().unwrap();
        let original_identity = child.identity().unwrap();
        let target = if ancestor { store.path() } else { child.path() }.to_owned();
        child.revalidate().unwrap();
        retained.revalidate().unwrap();

        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            child.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            retained.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        child.revalidate().unwrap();
        retained.revalidate().unwrap();
        assert_eq!(retained.identity().unwrap(), original_identity);
        assert_eq!(retained.read("record", 8).unwrap().as_slice(), b"original");

        let displaced = temporary.path().join("original-directory");
        fs::rename(&target, &displaced).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_child = if ancestor {
            let replacement_child = target.join("retained");
            fs::create_dir(&replacement_child).unwrap();
            fs::set_permissions(&replacement_child, fs::Permissions::from_mode(0o700)).unwrap();
            replacement_child
        } else {
            target.clone()
        };
        fs::write(replacement_child.join("record"), b"original").unwrap();
        fs::set_permissions(
            replacement_child.join("record"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // Safe permissions and equal bytes do not make a new native directory
        // the original retained directory, whether it is the child or parent.
        assert_eq!(
            child.revalidate().unwrap_err().to_string(),
            changed().to_string()
        );
        assert_eq!(
            retained.revalidate().unwrap_err().to_string(),
            changed().to_string()
        );
        assert!(
            retained
                .write_atomic("effect", b"refused", PublishMode::CreateNew)
                .is_err()
        );
        assert!(!replacement_child.join("effect").exists());
        let original_child = if ancestor {
            displaced.join("retained")
        } else {
            displaced.clone()
        };
        assert!(!original_child.join("effect").exists());
        assert_eq!(
            fs::read(original_child.join("record")).unwrap(),
            b"original"
        );
        assert_eq!(
            fs::read(replacement_child.join("record")).unwrap(),
            b"original"
        );

        fs::remove_dir_all(&target).unwrap();
        symlink(&displaced, &target).unwrap();
        assert!(child.revalidate().is_err());
        assert!(retained.revalidate().is_err());
        fs::remove_file(&target).unwrap();
        fs::rename(&displaced, &target).unwrap();
        // Restore the actual original inode and retry the same owners. A prior
        // refusal neither poisons them nor authorizes the substituted name.
        child.revalidate().unwrap();
        retained.revalidate().unwrap();
        assert_eq!(child.identity().unwrap(), original_identity);
        assert_eq!(retained.identity().unwrap(), original_identity);
        assert_eq!(retained.read("record", 8).unwrap().as_slice(), b"original");
    }
}

#[test]
fn retained_private_publication_keeps_complete_identity_bounds_and_no_replace() {
    let (_temporary, parent) = store();
    let published = parent
        .publish_private_child("ready", &[("lock", b""), ("record", b"original")])
        .unwrap();
    let directory_identity = published.identity().unwrap();
    let record_identity = FileIdentity::of(&published.open_read("record").unwrap()).unwrap();
    let reopened = parent.open_child("ready").unwrap();
    assert_eq!(reopened.identity().unwrap(), directory_identity);
    assert_eq!(
        FileIdentity::of(&reopened.open_read("record").unwrap()).unwrap(),
        record_identity
    );
    assert_eq!(reopened.read("record", 8).unwrap().as_slice(), b"original");
    assert!(reopened.read("lock", 0).unwrap().is_empty());
    let refused = parent.publish_private_child("ready", &[("record", b"replacement")]);
    assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
    assert_eq!(published.identity().unwrap(), directory_identity);
    assert_eq!(
        FileIdentity::of(&published.open_read("record").unwrap()).unwrap(),
        record_identity
    );
    assert_eq!(published.read("record", 8).unwrap().as_slice(), b"original");
    for (name, files) in [
        ("../escape", vec![("record", b"bad".as_slice())]),
        ("empty", vec![]),
        (
            "duplicate",
            vec![("record", b"a".as_slice()), ("record", b"b".as_slice())],
        ),
        ("invalid-file", vec![("../record", b"bad".as_slice())]),
    ] {
        let refused = parent.publish_private_child(name, &files);
        assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }
    assert_eq!(
        parent.entries(1).unwrap(),
        [std::ffi::OsString::from("ready")]
    );
}

#[cfg(unix)]
#[test]
fn retained_private_publication_refuses_replaced_parent_and_restores_original_retry() {
    let (temporary, parent) = store();
    let retained_identity = parent.identity().unwrap();
    let original = parent
        .publish_private_child("original", &[("record", b"original bytes")])
        .unwrap();
    let original_identity = original.identity().unwrap();
    let file_identity = FileIdentity::of(&original.open_read("record").unwrap()).unwrap();
    let displaced = temporary.path().join("original-parent");
    fs::rename(parent.path(), &displaced).unwrap();
    let missing = parent.publish_private_child("new", &[("record", b"new bytes")]);
    assert!(matches!(missing, Err(error) if error.kind() == io::ErrorKind::NotFound));
    let replacement = PrivateDirectory::open_or_create(parent.path()).unwrap();
    let refused = parent.publish_private_child("new", &[("record", b"new bytes")]);
    assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::Other));
    assert!(replacement.entries(0).unwrap().is_empty());
    drop(replacement);
    fs::remove_dir(parent.path()).unwrap();
    fs::rename(displaced, parent.path()).unwrap();
    assert_eq!(parent.identity().unwrap(), retained_identity);
    assert_eq!(original.identity().unwrap(), original_identity);
    assert_eq!(
        FileIdentity::of(&original.open_read("record").unwrap()).unwrap(),
        file_identity
    );
    assert_eq!(
        original.read("record", 14).unwrap().as_slice(),
        b"original bytes"
    );
    let published = parent
        .publish_private_child("new", &[("record", b"new bytes")])
        .unwrap();
    assert_eq!(
        parent.open_child("new").unwrap().identity().unwrap(),
        published.identity().unwrap()
    );
    assert_eq!(
        published.read("record", 9).unwrap().as_slice(),
        b"new bytes"
    );
}

#[cfg(unix)]
#[test]
fn retained_private_publication_keeps_private_permissions_without_repair() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_temporary, parent) = store();
    let permissions = fs::metadata(parent.path()).unwrap().permissions();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let refused = parent.publish_private_child("new", &[("record", b"original")]);
    assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert_eq!(
        fs::metadata(parent.path()).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    fs::set_permissions(parent.path(), permissions).unwrap();
    let published = parent
        .publish_private_child("new", &[("record", b"original")])
        .unwrap();
    assert_eq!(published.read("record", 8).unwrap().as_slice(), b"original");
}

#[cfg(windows)]
#[test]
fn retained_private_publication_keeps_native_rename_refusal_and_original_retry() {
    let (temporary, parent) = store();
    let identity = parent.identity().unwrap();
    assert!(fs::rename(parent.path(), temporary.path().join("original-parent")).is_err());
    let published = parent
        .publish_private_child("new", &[("record", b"original")])
        .unwrap();
    assert_eq!(parent.identity().unwrap(), identity);
    assert_eq!(
        parent.open_child("new").unwrap().identity().unwrap(),
        published.identity().unwrap()
    );
    assert_eq!(published.read("record", 8).unwrap().as_slice(), b"original");
    assert!(
        matches!(parent.publish_private_child("new", &[("record", b"replacement")]), Err(error) if error.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(published.read("record", 8).unwrap().as_slice(), b"original");
}

#[test]
fn local_identity_projection_preserves_original_file_and_directory_through_publication() {
    let (_temporary, parent) = store();
    let staged = parent.create_child("staged").unwrap();
    staged
        .write_atomic("source", b"original", PublishMode::CreateNew)
        .unwrap();
    let directory_identity = staged.identity().unwrap().local_parts();
    let file_identity = FileIdentity::of(&staged.open_read("source").unwrap())
        .unwrap()
        .local_parts();
    let snapshot = FileSnapshot::of(&staged.open_read("source").unwrap(), true).unwrap();
    let snapshot_parts = snapshot.local_parts();
    assert_eq!(snapshot_parts.0, file_identity.0);
    assert_eq!(snapshot_parts.1, (file_identity.1, file_identity.2));
    assert_eq!(snapshot_parts.2, 8);
    staged.sync().unwrap();
    let published = staged
        .rename_to_sibling("published", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        published.identity().unwrap().local_parts(),
        directory_identity
    );
    assert_eq!(
        FileIdentity::of(&published.open_read("source").unwrap())
            .unwrap()
            .local_parts(),
        file_identity
    );
    assert_eq!(
        FileSnapshot::of(&published.open_read("source").unwrap(), true).unwrap(),
        snapshot
    );
    assert_eq!(
        FileSnapshot::of(&published.open_read("source").unwrap(), true)
            .unwrap()
            .local_parts(),
        snapshot_parts
    );
    drop(published);
    let reopened = parent.open_child("published").unwrap();
    assert_eq!(
        reopened.identity().unwrap().local_parts(),
        directory_identity
    );
    assert_eq!(
        FileIdentity::of(&reopened.open_read("source").unwrap())
            .unwrap()
            .local_parts(),
        file_identity
    );
    assert_eq!(
        FileSnapshot::of(&reopened.open_read("source").unwrap(), true).unwrap(),
        snapshot
    );
    assert_eq!(
        FileSnapshot::of(&reopened.open_read("source").unwrap(), true)
            .unwrap()
            .local_parts(),
        snapshot_parts
    );
    reopened
        .write_atomic("source", b"original", PublishMode::Replace)
        .unwrap();
    assert_ne!(
        FileIdentity::of(&reopened.open_read("source").unwrap())
            .unwrap()
            .local_parts(),
        file_identity
    );
    assert_ne!(
        FileSnapshot::of(&reopened.open_read("source").unwrap(), true)
            .unwrap()
            .local_parts(),
        snapshot_parts
    );
    assert_eq!(
        reopened.identity().unwrap().local_parts(),
        directory_identity
    );
}
