//! Actual original-file retry, replacement refusal and source-bound prepared output controls.

use super::*;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
const HANDLE: &str = "software://iroha/consensus-threshold/retained-attempt";

fn private_directory() -> (tempfile::TempDir, Directory) {
    let temporary = tempfile::Builder::new()
        .prefix(".beacon-export-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(&fs::canonicalize(temporary.path()).unwrap()).unwrap();
    (temporary, directory)
}
fn source(
    budget: &AllocationBudget,
) -> (
    ValidatedGlobalThresholdBeaconSessionV1,
    iroha_core::beacon::GlobalBeaconAggregateOwnerV1,
) {
    super::super::seat_attempt::aggregate_tests::genuine_aggregate_owner(budget)
}

#[test]
fn prepared_seat_export_admits_every_frame_before_extraction_and_preserves_canonical_files() {
    let budget = super::super::test_credential_budget();
    let (public, components) = source(&budget);
    let (temporary, directory) = private_directory();
    let mut owner = PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).unwrap();
    assert!(owner.source.is_none());
    assert!(owner.outputs.credential.belongs_to(&budget));
    assert!(owner.outputs.public.belongs_to(&budget));
    assert!(owner.outputs.provider.belongs_to(&budget));
    assert!(owner.outputs.pending.belongs_to(&budget));
    assert_eq!(owner.outputs.pending.capacity(), 96);
    assert!(components.belongs_to(&budget));
    let pointer = owner.outputs.public.as_slice().as_ptr();
    let expected_provider = Provider {
        signer_index: 1,
        validator: public.adaptive_dkg.recipient_keys[0].validator.clone(),
        handle: HANDLE.to_owned(),
        revision: 7,
        policy_digest: owner.outputs.credential.policy_digest(),
    };
    assert_eq!(
        owner.outputs.provider.as_slice(),
        json_bytes(&expected_provider).unwrap()
    );
    assert_eq!(
        owner.outputs.public.as_slice(),
        norito::encode_canonical(public.record()).unwrap()
    );
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    owner
        .accept(components)
        .unwrap_or_else(|(_, error)| panic!("accept failed: {error}"));
    owner.publish(&directory).unwrap();
    assert!(owner.complete());
    assert_eq!(owner.outputs.public.as_slice().as_ptr(), pointer);
    for (index, (name, private)) in FILES.iter().copied().enumerate() {
        let path = temporary.path().join(name);
        assert!(
            fs::read(&path).unwrap() == owner.outputs.bytes(index).unwrap(),
            "output {index} must contain the exact original bytes"
        );
        if private {
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o600);
        }
    }
    let inodes = owner
        .files
        .each_ref()
        .map(|state| state.descriptor.as_ref().unwrap().metadata().unwrap().ino());
    owner.publish(&directory).unwrap();
    assert_eq!(
        owner.files.each_ref().map(|state| state
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino()),
        inodes
    );
    drop(occupied);
    drop(owner);
    drop(public);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn actual_partial_file_refusal_retries_original_descriptor_offset_and_exact_prefix() {
    let (_temporary, directory) = private_directory();
    use rustix::fs::{Mode, OFlags};
    let file = File::from(
        rustix::fs::openat(
            &directory.file,
            "source",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .unwrap(),
    );
    let read_only = File::from(
        rustix::fs::openat(
            &directory.file,
            "source",
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap(),
    );
    let inode = file.metadata().unwrap().ino();
    let bytes = b"same original complete output";
    let mut progress = FileProgress {
        descriptor: Some(file),
        ..FileProgress::default()
    };
    let mut calls = 0;
    let result = write_remaining(
        progress.descriptor.as_ref().unwrap(),
        bytes,
        &mut progress.offset,
        |held, source, offset| {
            calls += 1;
            if calls == 1 {
                held.write_at(&source[..7], offset)
            } else {
                read_only.write_at(source, offset)
            }
        },
    );
    let ExportError::Io(original) = result.unwrap_err() else {
        panic!("actual syscall error")
    };
    assert_eq!(
        original.raw_os_error(),
        read_only.write_at(b"x", 0).unwrap_err().raw_os_error()
    );
    assert_eq!(progress.offset, 7);
    assert_eq!(
        progress
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    publish_file(&directory, "source", true, bytes, &mut progress).unwrap();
    assert_eq!(progress.offset, bytes.len());
    assert!(progress.complete);
    assert_eq!(
        progress
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    assert_eq!(fs::read(directory.path.join("source")).unwrap(), bytes);
}

#[test]
fn export_refuses_replaced_completed_name_without_reopening_or_overwriting_it() {
    let budget = super::super::test_credential_budget();
    let (public, components) = source(&budget);
    let (_temporary, directory) = private_directory();
    let mut owner = PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).unwrap();
    owner
        .accept(components)
        .unwrap_or_else(|(_, error)| panic!("accept failed: {error}"));
    encode_global_beacon_partial_signer_credential_v1(
        &mut owner.outputs.credential,
        owner
            .source
            .iter()
            .map(iroha_core::beacon::GlobalBeaconAggregateOwnerV1::credential_source),
    )
    .unwrap();
    publish_file(
        &directory,
        FILES[0].0,
        true,
        owner.outputs.bytes(0).unwrap(),
        &mut owner.files[0],
    )
    .unwrap();
    let original_inode = owner.files[0]
        .descriptor
        .as_ref()
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    let path = directory.path.join(FILES[0].0);
    fs::rename(&path, directory.path.join("retained-original")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        owner.publish(&directory),
        Err(ExportError::Custody)
    ));
    assert!(owner.terminal_custody_failure);
    assert!(matches!(
        owner.publish(&directory),
        Err(ExportError::Custody)
    ));
    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert_eq!(
        owner.files[0]
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        original_inode
    );
    assert!(
        owner.files[1..]
            .iter()
            .all(|file| file.descriptor.is_none())
    );
}

#[test]
fn pending_export_failure_retains_private_source_and_original_pool_until_explicit_drop() {
    let budget = super::super::test_credential_budget();
    let (public, components) = source(&budget);
    let (_temporary, directory) = private_directory();
    let source_bytes = components.original_backing_bytes();
    let floor = budget.reserved_bytes();
    assert!(components.belongs_to(&budget));
    let mut owner = PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).unwrap();
    owner
        .accept(components)
        .unwrap_or_else(|(_, error)| panic!("accept failed: {error}"));
    let ciphertext = owner
        .source
        .as_ref()
        .unwrap()
        .encrypted_checkpoint()
        .to_vec();
    let pointer = owner
        .source
        .as_ref()
        .unwrap()
        .encrypted_checkpoint()
        .as_ptr();
    let destination = directory.path.join(FILES[0].0);
    fs::write(&destination, b"original unrelated output destination").unwrap();
    let occupied = budget.reserved_bytes();
    let error = owner.publish(&directory).unwrap_err();
    assert!(
        matches!(&error, ExportError::Io(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let failure = (owner, error);
    assert_eq!(budget.reserved_bytes(), occupied);
    assert!(failure.0.source.is_some());
    assert!(failure.0.public.ptr_eq(&public));
    assert_eq!(
        failure
            .0
            .source
            .as_ref()
            .unwrap()
            .encrypted_checkpoint()
            .as_ptr(),
        pointer
    );
    assert_eq!(
        failure.0.source.as_ref().unwrap().encrypted_checkpoint(),
        ciphertext
    );
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"original unrelated output destination"
    );
    fs::remove_file(&destination).unwrap();
    let mut owner = failure.0;
    owner.publish(&directory).unwrap();
    assert!(owner.complete());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), floor - source_bytes);
    drop(public);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn export_preparation_refusal_keeps_original_directory_and_rejects_foreign_publication() {
    let budget = super::super::test_credential_budget();
    let (public, components) = source(&budget);
    let (_original, directory) = private_directory();
    let (_foreign, foreign) = private_directory();
    let original_inode = directory.file.metadata().unwrap().ino();
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    assert!(PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).is_err());
    assert_eq!(directory.file.metadata().unwrap().ino(), original_inode);
    drop(occupied);
    let mut owner = PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).unwrap();
    owner
        .accept(components)
        .unwrap_or_else(|(_, error)| panic!("original private source: {error}"));
    assert!(matches!(owner.publish(&foreign), Err(ExportError::Custody)));
    assert!(owner.files.iter().all(|file| file.descriptor.is_none()));
    assert!(matches!(
        owner.publish(&directory),
        Err(ExportError::Custody)
    ));
    assert_eq!(directory.file.metadata().unwrap().ino(), original_inode);
    assert_eq!(fs::read_dir(foreign.path).unwrap().count(), 0);
}

#[test]
fn restore_visible_complete_file_executes_sync_and_keeps_same_descriptor_on_retry() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, directory) = private_directory();
    let bytes = b"complete original output interrupted immediately before fsync";
    let mut writer = FileProgress::default();
    prepare_file_bytes(&directory, "restore-source", true, bytes, &mut writer).unwrap();
    assert_eq!(writer.offset, bytes.len());
    assert!(!writer.synced);
    assert!(!writer.complete());
    let inode = writer
        .descriptor
        .as_ref()
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    drop(writer);
    let mut restored = FileProgress::default();
    restore_published_file(&directory, "restore-source", true, bytes, &mut restored).unwrap();
    assert!(restored.synced);
    assert!(restored.complete());
    let fd = restored.descriptor.as_ref().unwrap().as_raw_fd();
    assert_eq!(
        restored
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    restore_published_file(&directory, "restore-source", true, bytes, &mut restored).unwrap();
    assert_eq!(restored.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(
        fs::read(directory.path.join("restore-source")).unwrap(),
        bytes
    );
    fs::rename(
        directory.path.join("restore-source"),
        directory.path.join("held-source"),
    )
    .unwrap();
    fs::write(directory.path.join("restore-source"), bytes).unwrap();
    fs::set_permissions(
        directory.path.join("restore-source"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(matches!(
        restore_published_file(&directory, "restore-source", true, bytes, &mut restored),
        Err(ExportError::Custody)
    ));
    assert_eq!(restored.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(
        restored
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
}

#[test]
fn restore_rejects_equal_named_replacement_during_actual_sync_without_losing_original_descriptor() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, directory) = private_directory();
    let bytes = b"original completed producer bytes with a fixed retained inode";
    let mut writer = FileProgress::default();
    prepare_file_bytes(&directory, "sync-source", true, bytes, &mut writer).unwrap();
    assert!(!writer.is_synced());
    assert!(!writer.complete());
    let original_inode = writer
        .descriptor
        .as_ref()
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    drop(writer);
    let path = directory.path.join("sync-source");
    let retained_path = directory.path.join("original-held-source");
    let mut progress = FileProgress::default();
    let mut replaced = false;
    let error = restore_published_file_with(
        &directory,
        "sync-source",
        true,
        bytes,
        &mut progress,
        |held| {
            held.sync_all()?;
            if !replaced {
                // The same original sync syscall executes, then the real name is
                // replaced before completion. Equal bytes must not substitute custody.
                fs::rename(&path, &retained_path)?;
                fs::write(&path, bytes)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                replaced = true;
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(error, ExportError::Custody));
    assert!(progress.is_synced());
    assert!(!progress.complete());
    let fd = progress.descriptor.as_ref().unwrap().as_raw_fd();
    assert_eq!(
        progress
            .descriptor
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        original_inode
    );
    assert_ne!(fs::metadata(&path).unwrap().ino(), original_inode);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read(&retained_path).unwrap(), bytes);
    assert!(matches!(
        restore_published_file(&directory, "sync-source", true, bytes, &mut progress),
        Err(ExportError::Custody)
    ));
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert!(!progress.complete());
}

#[test]
fn final_export_rejects_foreign_provider_handle_or_revision_without_consuming_original_aggregate_owner()
 {
    let budget = super::super::test_credential_budget();
    let (public, mut source) = source(&budget);
    let (_temporary, directory) = private_directory();
    let ciphertext = source.encrypted_checkpoint().to_vec();
    let pointer = source.encrypted_checkpoint().as_ptr();
    for (handle, revision) in [
        ("software://iroha/consensus-threshold/foreign-export", 7),
        (HANDLE, 8),
    ] {
        let mut foreign =
            PreparedSeatExport::new(&directory, &public, 1, handle, revision, &budget).unwrap();
        let retained = budget.reserved_bytes();
        let (returned, error) = match foreign.accept(source) {
            Err(failure) => failure,
            Ok(()) => panic!("foreign output provider cannot adopt original aggregate authority"),
        };
        source = returned;
        assert!(matches!(error, ExportError::Phase));
        assert!(foreign.source.is_none());
        assert!(foreign.files.iter().all(|file| file.descriptor.is_none()));
        assert!(source.belongs_to(&budget));
        assert!(source.authenticated_session().ptr_eq(&public));
        assert_eq!(source.encrypted_checkpoint().as_ptr(), pointer);
        assert_eq!(source.encrypted_checkpoint(), ciphertext);
        assert_eq!(budget.reserved_bytes(), retained);
    }
    let mut original = PreparedSeatExport::new(&directory, &public, 1, HANDLE, 7, &budget).unwrap();
    original
        .accept(source)
        .unwrap_or_else(|(_, error)| panic!("same original provider: {error}"));
    original.publish(&directory).unwrap();
    assert!(original.complete());
    drop(original);
    drop(public);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn new_publication_mode_initialization_retains_original_descriptor_before_bytes_across_refusal() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, directory) = private_directory();
    let bytes = b"same original signed public output";
    let (read, _write) = rustix::pipe::pipe().unwrap();
    let refusing = File::from(read);
    let expected = refusing.sync_all().unwrap_err().raw_os_error();
    let mut progress = FileProgress::default();
    let error = prepare_file_bytes_with_mode(
        &directory,
        "mode-source",
        false,
        bytes,
        &mut progress,
        |held, mode| {
            assert_eq!(mode, rustix::fs::Mode::from_raw_mode(0o644));
            // Reproduce a restrictive creation mode on this one exact descriptor,
            // without changing the process-wide umask or another test's files.
            rustix::fs::fchmod(held, rustix::fs::Mode::from_raw_mode(0o600))?;
            refusing.sync_all()
        },
    )
    .unwrap_err();
    let ExportError::Io(error) = error else {
        panic!("original mode-initialization I/O cause must survive")
    };
    assert_eq!(error.raw_os_error(), expected);
    let descriptor = progress.descriptor.as_ref().unwrap();
    let fd = descriptor.as_raw_fd();
    let inode = descriptor.metadata().unwrap().ino();
    assert_eq!(descriptor.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        progress.pending_mode,
        Some(rustix::fs::Mode::from_raw_mode(0o644))
    );
    assert_eq!(progress.offset, 0);
    assert!(!progress.synced);
    assert!(!progress.complete());
    assert!(
        fs::read(directory.path.join("mode-source"))
            .unwrap()
            .is_empty()
    );
    let mut calls = 0;
    prepare_file_bytes_with_mode(
        &directory,
        "mode-source",
        false,
        bytes,
        &mut progress,
        |held, mode| {
            calls += 1;
            assert_eq!(held.as_raw_fd(), fd);
            assert_eq!(held.metadata()?.ino(), inode);
            assert_eq!(held.metadata()?.len(), 0);
            rustix::fs::fchmod(held, mode).map_err(std::io::Error::from)
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(progress.pending_mode, None);
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(progress.retained_inode().unwrap(), inode);
    assert_eq!(
        fs::metadata(directory.path.join("mode-source"))
            .unwrap()
            .mode()
            & 0o7777,
        0o644
    );
    publish_file(&directory, "mode-source", false, bytes, &mut progress).unwrap();
    assert!(progress.complete());
    assert_eq!(fs::read(directory.path.join("mode-source")).unwrap(), bytes);
    fs::set_permissions(
        directory.path.join("mode-source"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let result = prepare_file_bytes_with_mode(
        &directory,
        "mode-source",
        false,
        bytes,
        &mut progress,
        |_, _| panic!("published original mode must never be repaired"),
    );
    assert!(matches!(result, Err(ExportError::Custody)));
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(progress.retained_inode().unwrap(), inode);
    assert_eq!(
        fs::metadata(directory.path.join("mode-source"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn restored_public_output_requires_exact_mode_without_initializing_existing_file() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, directory) = private_directory();
    let bytes = b"existing original signed public output";
    let path = directory.path.join("restore-mode-source");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let mut progress = FileProgress::default();
    let result = restore_published_file_with(
        &directory,
        "restore-mode-source",
        false,
        bytes,
        &mut progress,
        |_| panic!("wrong existing mode must refuse before synchronization"),
    );
    assert!(matches!(result, Err(ExportError::Custody)));
    let fd = progress.descriptor.as_ref().unwrap().as_raw_fd();
    assert_eq!(progress.retained_inode().unwrap(), inode);
    assert_eq!(progress.pending_mode, None);
    assert_eq!(progress.offset, 0);
    assert!(!progress.complete());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    // Only an explicit external owner correction enables read-only adoption.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    restore_published_file(
        &directory,
        "restore-mode-source",
        false,
        bytes,
        &mut progress,
    )
    .unwrap();
    assert!(progress.complete());
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(progress.retained_inode().unwrap(), inode);
    assert_eq!(progress.pending_mode, None);
    prepare_file_bytes_with_mode(
        &directory,
        "restore-mode-source",
        false,
        bytes,
        &mut progress,
        |_, _| panic!("restored original must never enter creation-mode initialization"),
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
}

#[test]
fn public_output_initializes_exact_original_creation_mode_before_publication_and_restore() {
    use std::os::fd::AsRawFd as _;
    let (_temporary, directory) = private_directory();
    let bytes = b"canonical public output with its exact original creation descriptor";
    // The real exclusive creation stage may have a stricter umask. Pin an actual
    // original empty 0600 descriptor at precisely that retained boundary; do not
    // change the process-wide umask or construct a restored-file initialization.
    let descriptor = File::from(
        rustix::fs::openat(
            &directory.file,
            "original-public-mode",
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap(),
    );
    let fd = descriptor.as_raw_fd();
    let inode = descriptor.metadata().unwrap().ino();
    let mut progress = FileProgress {
        descriptor: Some(descriptor),
        pending_mode: Some(rustix::fs::Mode::from_raw_mode(0o644)),
        ..FileProgress::default()
    };
    let result = publish_file(
        &directory,
        "original-public-mode",
        false,
        bytes,
        &mut progress,
    );
    assert!(
        result.is_ok(),
        "original public descriptor must initialize its exact mode before publication: {result:?}"
    );
    assert_eq!(progress.descriptor.as_ref().unwrap().as_raw_fd(), fd);
    assert_eq!(progress.retained_inode().unwrap(), inode);
    assert_eq!(progress.pending_mode, None);
    assert!(progress.complete());
    assert_eq!(
        fs::metadata(directory.path.join("original-public-mode"))
            .unwrap()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        fs::read(directory.path.join("original-public-mode")).unwrap(),
        bytes
    );
    drop(progress);
    let mut restored = FileProgress::default();
    restore_published_file(
        &directory,
        "original-public-mode",
        false,
        bytes,
        &mut restored,
    )
    .unwrap();
    assert_eq!(restored.retained_inode().unwrap(), inode);
    assert_eq!(restored.pending_mode, None);
    assert!(restored.complete());
    assert_eq!(
        fs::read(directory.path.join("original-public-mode")).unwrap(),
        bytes
    );
}
