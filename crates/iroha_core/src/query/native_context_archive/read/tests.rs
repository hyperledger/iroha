//! Real descriptor identity, bounded progress and original-pool refusal regressions.

use super::*;
use iroha_allocation::AllocationRefusal;
use std::fs;

fn hash() -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"original archive read carrier"))
}
fn canonical_path(root: &Path) -> std::path::PathBuf {
    root.join("native-contexts")
        .join(RecordName::new(2, hash(), false).as_str())
}
fn fixture(bytes: &[u8], budget: AllocationBudget) -> (tempfile::TempDir, NativeContextRead) {
    let directory = tempfile::tempdir().unwrap();
    let (root, source) = open_directory(directory.path(), true).unwrap();
    let archive = NativeContextArchive {
        root,
        directory: source,
        budget,
        maximum: NonZeroUsize::new(bytes.len()).unwrap(),
        writable: false,
    };
    fs::write(canonical_path(directory.path()), bytes).unwrap();
    let read = archive.read_job(2, hash());
    (directory, read)
}
fn complete(read: &mut NativeContextRead) -> ChargedBuffer<u8> {
    loop {
        if let Some(bytes) = read.poll().unwrap() {
            return bytes;
        }
    }
}

#[test]
fn refused_archive_read_never_reopens_the_original_selected_inode() {
    let original = vec![7; 5_000];
    let budget = AllocationBudget::new(original.len());
    let blocker = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    let (directory, mut read) = fixture(&original, budget.clone());
    assert!(!read.has_pinned_source());
    assert!(matches!(
        read.poll(),
        Err(NativeContextArchiveError::Allocation(
            ChargedBufferError::Admission(AllocationRefusal::Capacity { .. })
        ))
    ));
    assert!(read.has_pinned_source());
    assert!(read.read.file.is_some());
    assert_eq!(read.read.length, Some(original.len()));
    assert!(read.read.bytes.is_none());
    let path = canonical_path(directory.path());
    fs::rename(&path, directory.path().join("original-held-file")).unwrap();
    fs::write(&path, vec![9; original.len()]).unwrap();
    drop(blocker);
    let bytes = complete(&mut read);
    assert!(read.has_pinned_source());
    assert_eq!(bytes.as_slice(), original);
    assert!(bytes.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), original.len());
    read.recheck_namespace().unwrap();
    assert!(read.poll().is_err());
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn archive_read_keeps_partial_prefix_and_exact_allocation_until_move_or_drop() {
    let original = vec![7; 9_000];
    let budget = AllocationBudget::new(original.len());
    let (_directory, mut read) = fixture(&original, budget.clone());
    assert!(read.poll().unwrap().is_none());
    let prefix = read.read.bytes.as_ref().unwrap();
    assert_eq!(prefix.as_slice(), &original[..4096]);
    let pointer = prefix.as_slice().as_ptr();
    budget.set_limit_bytes(0);
    assert!(read.poll().unwrap().is_none());
    assert_eq!(
        read.read.bytes.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    let bytes = complete(&mut read);
    assert_eq!(bytes.as_slice(), original);
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);

    budget.set_limit_bytes(original.len());
    let (_directory, mut read) = fixture(&original, budget.clone());
    assert!(read.poll().unwrap().is_none());
    assert_eq!(budget.reserved_bytes(), original.len());
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn refused_archive_read_preserves_original_length_and_namespace_checks() {
    let original = vec![7; 128];
    for replace_directory in [false, true] {
        let budget = AllocationBudget::new(0);
        let (directory, mut read) = fixture(&original, budget.clone());
        assert!(matches!(
            read.poll(),
            Err(NativeContextArchiveError::Allocation(
                ChargedBufferError::Admission(AllocationRefusal::ExceedsLimit { .. })
            ))
        ));
        budget.set_limit_bytes(original.len());
        if replace_directory {
            fs::rename(
                directory.path().join("native-contexts"),
                directory.path().join("original-namespace"),
            )
            .unwrap();
            fs::create_dir(directory.path().join("native-contexts")).unwrap();
        } else {
            fs::write(canonical_path(directory.path()), [9]).unwrap();
        }
        assert!(read.poll().is_err());
        assert!(read.read.file.is_some());
        assert_eq!(read.read.length, Some(original.len()));
        assert!(read.read.bytes.is_none());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn archive_pool_ceiling_refusal_retries_original_owner_but_record_limit_is_permanent() {
    let original = vec![7; 128];
    let budget = AllocationBudget::new(0);
    let (_directory, mut read) = fixture(&original, budget.clone());
    let error = read.poll().err().expect("expected local pool refusal");
    assert!(matches!(
        error,
        NativeContextArchiveError::Allocation(ChargedBufferError::Admission(
            AllocationRefusal::ExceedsLimit { .. }
        ))
    ));
    assert!(error.is_local_refusal());
    assert!(read.read.file.is_some());
    assert_eq!(read.read.length, Some(original.len()));
    budget.set_limit_bytes(original.len());
    let bytes = complete(&mut read);
    assert_eq!(bytes.as_slice(), original);
    assert!(bytes.belongs_to(&budget));
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);

    let (_directory, mut read) = fixture(&original, budget.clone());
    read.archive.maximum = NonZeroUsize::new(original.len() - 1).unwrap();
    let error = read.poll().err().expect("expected permanent record limit");
    assert!(matches!(error, NativeContextArchiveError::Limit { .. }));
    assert!(!error.is_local_refusal());
    assert!(
        !NativeContextArchiveError::Allocation(ChargedBufferError::Admission(
            AllocationRefusal::DemandOverflow
        ))
        .is_local_refusal()
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn one_shot_interruption_retries_the_original_partial_read_without_reopening() {
    let original = vec![7; 9_000];
    let budget = AllocationBudget::new(original.len());
    let (directory, mut read) = fixture(&original, budget.clone());
    assert!(read.poll().unwrap().is_none());
    let pointer = read.read.bytes.as_ref().unwrap().as_slice().as_ptr();
    let path = canonical_path(directory.path());
    fs::rename(&path, directory.path().join("original-partial-read")).unwrap();
    fs::write(&path, vec![9; original.len()]).unwrap();
    let mut interrupted = false;
    let bytes = to_completion(|| {
        if !interrupted {
            interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted).into());
        }
        read.poll()
    })
    .unwrap();
    assert!(interrupted);
    assert_eq!(bytes.as_slice(), original);
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    assert!(bytes.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), original.len());
    drop(bytes);
    assert_eq!(budget.reserved_bytes(), 0);
    let error = to_completion(|| Err(io::Error::from(io::ErrorKind::PermissionDenied).into()))
        .err()
        .expect("permanent I/O failure must not be retried");
    assert!(
        matches!(error, NativeContextArchiveError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn returning_archive_cancels_pending_bytes_but_preserves_completed_byte_owner() {
    let original = vec![7; 9_000];
    let budget = AllocationBudget::new(original.len());
    let (_directory, mut read) = fixture(&original, budget.clone());
    assert!(read.poll().unwrap().is_none());
    assert_eq!(budget.reserved_bytes(), original.len());
    let archive = read.into_archive();
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "explicit pending cancellation refunds its partial owner"
    );
    archive.recheck_namespace().unwrap();
    let mut read = archive.read_job(2, hash());
    let bytes = complete(&mut read);
    let pointer = bytes.as_slice().as_ptr();
    let archive = read.into_archive();
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    assert_eq!(bytes.as_slice(), original);
    assert_eq!(budget.reserved_bytes(), original.len());
    let mut next = archive.read_job(2, hash());
    assert!(
        next.poll()
            .err()
            .expect("original pool remains occupied")
            .is_local_refusal()
    );
    assert!(
        next.read.file.is_some(),
        "refusal retains the next exact selected file"
    );
    drop(bytes);
    let bytes = complete(&mut next);
    assert_eq!(bytes.as_slice(), original);
    drop(bytes);
    drop(next);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
#[cfg(unix)]
fn original_intent_read_shares_exact_descriptor_capacity_and_prefix_custody() {
    let original = vec![0x42; 5_000];
    let budget = AllocationBudget::new(original.len());
    let (directory, read) = fixture(&original, budget.clone());
    let archive = read.into_archive();
    let path = directory
        .path()
        .join("native-contexts")
        .join(RecordName::intent(2, hash(), false).as_str());
    fs::rename(canonical_path(directory.path()), &path).unwrap();
    let mut read = archive.prepared_intent_read_job(2, hash());
    let blocker = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    assert!(matches!(
        read.poll(),
        Err(NativeContextArchiveError::Allocation(
            ChargedBufferError::Admission(AllocationRefusal::Capacity { .. })
        ))
    ));
    assert!(read.has_pinned_source());
    let metadata = read.read.file.as_ref().unwrap().metadata().unwrap();
    use std::os::unix::fs::MetadataExt as _;
    let identity = (metadata.dev(), metadata.ino());
    fs::rename(&path, directory.path().join("original-held-intent")).unwrap();
    fs::write(&path, vec![0x66; original.len()]).unwrap();
    drop(blocker);
    assert!(read.poll().unwrap().is_none());
    let pointer = read.acquired_prefix().unwrap().as_ptr();
    assert_eq!(read.acquired_prefix().unwrap(), &original[..4096]);
    let bytes = complete(&mut read);
    let retained = read.read.file.as_ref().unwrap().metadata().unwrap();
    assert_eq!((retained.dev(), retained.ino()), identity);
    assert_eq!(bytes.as_slice().as_ptr(), pointer);
    assert_eq!(
        bytes.as_slice(),
        original,
        "intent read never selects substituted pathname bytes"
    );
    assert!(bytes.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), original.len());
    drop(bytes);
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}
