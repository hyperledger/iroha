//! Original native startup I/O retries and typed terminal custody.

use super::*;
use iroha_allocation::AllocationBudget;
use std::{
    io,
    sync::{atomic::AtomicUsize, mpsc},
    time::Instant,
};

fn completion(pending: &mut PendingDriver) -> Option<StartupPoll> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observed = pending.poll();
        if !matches!(observed, StartupPoll::Pending) {
            return Some(observed);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::yield_now();
    }
}

#[test]
fn original_record_log_os_failure_retries_same_stage_and_store() {
    let directory = tempfile::tempdir().unwrap();
    let records = Arc::new(
        FileRecordStore::open(
            directory.path().join("records"),
            directory.path().join("installation.log"),
        )
        .unwrap(),
    );
    std::fs::create_dir(records.log_path()).unwrap();
    let original = Arc::clone(&records);
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed_attempts = Arc::clone(&attempts);
    let (send, receive) = mpsc::sync_channel(1);
    let budget = AllocationBudget::new(1 << 20);
    let mut pending = PendingDriver::spawn(
        Hash32([0xf1; 32]), &budget, DriverConfig::default().backoff,
        move |context| -> Result<Option<PreparedLane>, Attempt<StartupPreparationError>> {
            let _log = retry_preparation(context, || {
                let result = original.log().map_err(Attempt::Rejected);
                if observed_attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                    let native = matches!(&result, Err(Attempt::Rejected(error)) if error.raw_os_error().is_some());
                    let _ = send.send(native);
                }
                result
            }, retry_startup_io)?;
            Ok(None)
        },
    ).unwrap();
    let first = receive.recv_timeout(Duration::from_secs(5));
    let restored = std::fs::remove_dir(records.log_path());
    let result = completion(&mut pending);
    drop(pending);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(Arc::strong_count(&records), 1);
    assert!(
        first.unwrap(),
        "the first refusal must carry actual native OS provenance"
    );
    restored.unwrap();
    assert!(
        matches!(result, Some(StartupPoll::Closed)),
        "original custody log I/O must retry without replacing the startup generation"
    );
    assert!(attempts.load(Ordering::Acquire) >= 2);
    assert!(records.log().unwrap().is_empty());
}

#[derive(Debug)]
struct OriginalCustodyFailure(Arc<AtomicUsize>);
impl core::fmt::Display for OriginalCustodyFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("retained filesystem identity or custody changed")
    }
}
impl std::error::Error for OriginalCustodyFailure {}
impl Drop for OriginalCustodyFailure {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn custom_custody_other_stays_terminal_with_its_original_source() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let failure = OriginalCustodyFailure(Arc::clone(&dropped));
    let attempts = Arc::new(AtomicUsize::new(0));
    let original_attempts = Arc::clone(&attempts);
    let budget = AllocationBudget::new(1 << 20);
    let mut pending = PendingDriver::spawn(
        Hash32([0xf2; 32]),
        &budget,
        DriverConfig::default().backoff,
        move |context| -> Result<Option<PreparedLane>, Attempt<StartupPreparationError>> {
            let mut original = Some(io::Error::other(failure));
            retry_preparation::<(), io::Error>(
                context,
                || {
                    original_attempts.fetch_add(1, Ordering::AcqRel);
                    Err(Attempt::Rejected(
                        original
                            .take()
                            .expect("completed custody refusal cannot retry"),
                    ))
                },
                retry_startup_io,
            )?;
            Ok(None)
        },
    )
    .unwrap();
    let result = completion(&mut pending);
    let retained = matches!(pending.poll(), StartupPoll::Failed);
    drop(pending);
    assert_eq!(budget.reserved_bytes(), 0);
    let Some(StartupPoll::PreparationRefused(Attempt::Rejected(StartupPreparationError::Io(
        error,
    )))) = result
    else {
        panic!("terminal native source must remain typed");
    };
    let original = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<OriginalCustodyFailure>())
        .unwrap();
    assert!(Arc::ptr_eq(&original.0, &dropped));
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.raw_os_error().is_none());
    assert_eq!(
        error.to_string(),
        "retained filesystem identity or custody changed"
    );
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    assert_eq!(attempts.load(Ordering::Acquire), 1);
    assert!(retained);
    drop(error);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

#[test]
fn committed_history_retries_only_original_native_io_and_known_temporary_kinds() {
    use crate::sumeragi::driver::StartupHistoryError;
    let directory = tempfile::tempdir().unwrap();
    let physical = std::fs::File::open(directory.path().join("missing")).unwrap_err();
    assert!(physical.raw_os_error().is_some());
    let os_code = physical.raw_os_error();
    let history = StartupHistoryError::Read {
        height: 7,
        source: physical,
    };
    assert!(retry_startup_history(&history));
    let original = StartupPreparationError::from(history);
    assert!(
        matches!(original, StartupPreparationError::History(StartupHistoryError::Read { height: 7, ref source }) if source.raw_os_error() == os_code)
    );
    for kind in [
        io::ErrorKind::WouldBlock,
        io::ErrorKind::Interrupted,
        io::ErrorKind::TimedOut,
    ] {
        assert!(retry_startup_history(&StartupHistoryError::Read {
            height: 7,
            source: io::Error::from(kind)
        }));
    }
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::Unsupported,
        io::ErrorKind::Other,
    ] {
        assert!(!retry_startup_history(&StartupHistoryError::Read {
            height: 7,
            source: io::Error::new(kind, "original completed refusal")
        }));
    }
    assert!(!retry_startup_history(&StartupHistoryError::Missing {
        height: 7
    }));
}

#[test]
fn changed_original_directory_custody_is_terminal_without_native_retry() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let original_path = root.join("original");
    let moved_path = root.join("moved");
    let original = iroha_fs::OwnerDirectory::open_or_create(&original_path).unwrap();
    std::fs::rename(&original_path, &moved_path).unwrap();
    let replacement = iroha_fs::OwnerDirectory::open_or_create(&original_path).unwrap();
    let error = original.revalidate().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(
        error.to_string(),
        "retained filesystem identity or custody changed"
    );
    assert!(error.raw_os_error().is_none());
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&attempts);
    let budget = AllocationBudget::new(1 << 20);
    let mut pending = PendingDriver::spawn(
        Hash32([0xf3; 32]),
        &budget,
        DriverConfig::default().backoff,
        move |context| -> Result<Option<PreparedLane>, Attempt<StartupPreparationError>> {
            retry_preparation(
                context,
                || {
                    calls.fetch_add(1, Ordering::AcqRel);
                    original.revalidate().map_err(Attempt::Rejected)
                },
                retry_startup_io,
            )?;
            Ok(None)
        },
    )
    .unwrap();
    let result = completion(&mut pending);
    let retained = matches!(pending.poll(), StartupPoll::Failed);
    drop(pending);
    assert_eq!(budget.reserved_bytes(), 0);
    replacement.revalidate().unwrap();
    let Some(StartupPoll::PreparationRefused(Attempt::Rejected(StartupPreparationError::Io(
        error,
    )))) = result
    else {
        panic!("actual changed directory custody must remain a typed terminal refusal");
    };
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.raw_os_error().is_none());
    assert_eq!(
        error.to_string(),
        "retained filesystem identity or custody changed"
    );
    assert_eq!(
        attempts.load(Ordering::Acquire),
        1,
        "changed original directory custody must not retry as physical I/O"
    );
    assert!(retained);
}
