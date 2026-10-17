//! Mandatory authenticated-body storage, original-owner retries and source-bound reads.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::sumeragi::crypto::BlsCrypto;

use super::*;
use crate::sumeragi::{body_read::BodyReadPoll, body_record::tests::fixture};

fn open(root: &Path, source: &AvailabilitySource, budget: &AllocationBudget) -> FileBodyStore {
    FileBodyStore::open(
        root,
        &source.instance(),
        Arc::new(BlsCrypto::new()),
        BodyLimits::default(),
        budget.clone(),
    )
    .unwrap()
}

fn restored(
    store: &FileBodyStore,
    source: AvailabilitySource,
    budget: &AllocationBudget,
) -> AvailableBody {
    let mut read = store.begin_read(source.clone()).unwrap();
    assert_eq!(read.source(), &source);
    let BodyReadPoll::Ready(job) = read.poll(budget).unwrap() else {
        panic!("complete record")
    };
    assert!(matches!(read.poll(budget), Err(BodyReadError::Completed)));
    job.complete(budget, &BlsCrypto::new())
        .unwrap_or_else(|_| panic!("full signed restoration"))
}

#[test]
fn durable_record_restores_through_actual_signature_and_rs16_verification() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(23572);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let original_bytes = fs::read(store.body_path(source.height(), &source.block_hash())).unwrap();
    assert_eq!(restored(&store, source.clone(), &budget), body);
    store.put(&source.block_hash(), &body).unwrap();
    assert_eq!(
        fs::read(store.body_path(source.height(), &source.block_hash())).unwrap(),
        original_bytes
    );
    assert_eq!(store.bytes().unwrap(), original_bytes.len() as u64);
    let reopened = open(root.path(), &source, &budget);
    assert_eq!(restored(&reopened, source.clone(), &budget), body);
    reopened.prune_through(source.height()).unwrap();
    assert_eq!(reopened.bytes().unwrap(), 0);
    assert!(matches!(
        reopened.begin_read(source).unwrap().poll(&budget).unwrap(),
        BodyReadPoll::Absent
    ));
}

#[test]
fn retirement_authority_is_local_monotonic_and_never_inferred_from_absence() {
    let root = tempfile::tempdir().unwrap();
    let (_, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    assert!(!store.retirement_authorized(source.height()));
    store.prune_through(source.height()).unwrap();
    store.prune_through(source.height() - 1).unwrap();
    assert!(store.retirement_authorized(source.height()));
    assert!(!store.retirement_authorized(0));
    assert!(!store.retirement_authorized(source.height() + 1));
    assert!(!open(root.path(), &source, &budget).retirement_authorized(source.height()));
}

#[test]
fn read_refusal_keeps_source_and_foreign_pool_is_rejected_before_allocation() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    assert!(matches!(
        read.poll(&foreign),
        Err(BodyReadError::ForeignBudget)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let reserved = budget.reserved_bytes();
    budget.set_limit_bytes(reserved);
    assert!(matches!(
        read.poll(&budget).unwrap(),
        BodyReadPoll::Pending(_)
    ));
    assert_eq!(read.source(), &source);
    assert_eq!(budget.reserved_bytes(), reserved);
    budget.set_limit_bytes(1 << 25);
    let BodyReadPoll::Ready(job) = read.poll(&budget).unwrap() else {
        panic!("same job resumes")
    };
    assert_eq!(
        job.complete(&budget, &BlsCrypto::new())
            .unwrap_or_else(|_| panic!("restoration")),
        body
    );
}

#[test]
fn corrupt_record_is_an_error_and_never_absence_or_available_custody() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let path = store.body_path(source.height(), &source.block_hash());
    fs::write(&path, b"not a canonical body record").unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Decode(_))));
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Decode(_))));
    assert!(store.put(&source.block_hash(), &body).is_err());
    assert_eq!(fs::read(path).unwrap(), b"not a canonical body record");
}

#[derive(Default)]
struct FailPublishedSync(AtomicBool);
impl Faults for FailPublishedSync {
    fn before(&self, step: FsStep, path: &Path) -> io::Result<()> {
        if step == FsStep::SyncDir
            && path
                .file_name()
                .and_then(|p| p.to_str())
                .and_then(parse_height)
                .is_some()
            && self.0.load(Ordering::SeqCst)
        {
            return Err(io::Error::other("directory sync refused"));
        }
        Ok(())
    }
}

#[test]
fn publication_refusal_keeps_the_actual_original_owners_and_encoded_pointer() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(23572);
    let faults = Arc::new(FailPublishedSync::default());
    let store = FileBodyStore::open_with_faults(
        root.path(),
        &source.instance(),
        Arc::new(BlsCrypto::new()),
        BodyLimits::default(),
        budget.clone(),
        faults.clone(),
    )
    .unwrap();
    faults.0.store(true, Ordering::SeqCst);
    assert!(store.put(&source.block_hash(), &body).is_err());
    let owner_pointers = |store: &FileBodyStore| {
        let mut pending = store.pending_write.lock();
        let original = pending.as_mut().unwrap();
        let payload = original.prepared.body().payload().as_slice().as_ptr();
        let frame = original.prepared.body().availability().as_slice().as_ptr();
        let encoded = original.prepared.prepare(&budget).unwrap().as_ptr();
        (payload, frame, encoded)
    };
    let pointers = owner_pointers(&store);
    assert_eq!(pointers.0, body.payload().as_slice().as_ptr());
    assert_eq!(pointers.1, body.availability().as_slice().as_ptr());
    let reserved = budget.reserved_bytes();
    assert!(store.put(&source.block_hash(), &body).is_err());
    assert_eq!(owner_pointers(&store), pointers);
    assert_eq!(budget.reserved_bytes(), reserved);
    faults.0.store(false, Ordering::SeqCst);
    store.put(&source.block_hash(), &body).unwrap();
    assert!(store.pending_write.lock().is_none());
    assert_eq!(restored(&store, source, &budget), body);
}

#[test]
fn store_requires_the_independent_original_pool_and_source_instance() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let store = open(root.path(), &source, &foreign);
    assert!(store.put(&source.block_hash(), &body).is_err());
    assert!(store.pending_write.lock().is_none());
    assert_eq!(store.bytes().unwrap(), 0);
    let wrong_source = AvailabilitySource::new(
        Hash32([99; 32]),
        source.height(),
        source.block_hash(),
        source.config().clone(),
    )
    .unwrap();
    assert!(store.begin_read(wrong_source).is_err());
}

#[cfg(unix)]
#[test]
fn opened_body_store_refuses_replaced_instance_directory_and_retries_original() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    let original_path = store.dir().to_owned();
    let retained_path = root.path().join("original-body-instance");
    fs::rename(&original_path, &retained_path).unwrap();
    fs::create_dir(&original_path).unwrap();
    let replacement = open(root.path(), &source, &budget);
    let charged = budget.reserved_bytes();
    let pointer = body.payload().as_slice().as_ptr();
    let error = store
        .put(&source.block_hash(), &body)
        .expect_err("original body store accepted a replaced custody namespace");
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(budget.reserved_bytes(), charged);
    assert!(store.pending_write.lock().is_none());
    assert_eq!(body.payload().as_slice().as_ptr(), pointer);
    assert_eq!(fs::read_dir(&original_path).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&retained_path).unwrap().count(), 1);
    assert_eq!(replacement.bytes().unwrap(), 0);
    assert!(replacement.heights().unwrap().is_empty());
    assert_eq!(store.bytes().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(store.heights().unwrap_err().kind(), io::ErrorKind::Other);
    assert!(
        matches!(store.begin_read(source.clone()), Err(BodyReadError::Io(error)) if error.kind() == io::ErrorKind::Other)
    );
    assert_eq!(
        store.prune_through(source.height()).unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert!(!store.retirement_authorized(source.height()));
    assert!(!replacement.retirement_authorized(source.height()));
    drop(replacement);
    let foreign = root.path().join("replacement-body-instance");
    fs::rename(&original_path, &foreign).unwrap();
    fs::rename(&retained_path, &original_path).unwrap();
    store.put(&source.block_hash(), &body).unwrap();
    assert_eq!(restored(&store, source.clone(), &budget), body);
    assert_eq!(body.payload().as_slice().as_ptr(), pointer);
    assert!(store.bytes().unwrap() > 0);
    assert_eq!(store.heights().unwrap(), [source.height()]);
    assert_eq!(fs::read_dir(&foreign).unwrap().count(), 1);
    assert!(!store.retirement_authorized(source.height()));
}

#[cfg(unix)]
#[test]
fn body_store_lock_replacement_and_hardlinks_refuse_original_operations() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    let selected = store.dir.join(LOCK_NAME);
    let original = root.path().join("original-lock");
    fs::rename(&selected, &original).unwrap();
    fs::write(&selected, []).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o600)).unwrap();
    let replacement = open(root.path(), &source, &budget);
    let charged = budget.reserved_bytes();
    assert_eq!(
        store.put(&source.block_hash(), &body).unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(store.bytes().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(store.heights().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(
        store.prune_through(source.height()).unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert!(!store.retirement_authorized(source.height()));
    assert!(store.pending_write.lock().is_none());
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(replacement.bytes().unwrap(), 0);
    drop(replacement);
    fs::remove_file(&selected).unwrap();
    fs::rename(&original, &selected).unwrap();
    fs::hard_link(&selected, &original).unwrap();
    assert_eq!(
        store.put(&source.block_hash(), &body).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(store.pending_write.lock().is_none());
    fs::remove_file(&original).unwrap();
    store.put(&source.block_hash(), &body).unwrap();
    assert_eq!(restored(&store, source, &budget), body);
}

#[cfg(unix)]
struct ReplaceBodyNamespace {
    selected: PathBuf,
    original: PathBuf,
    boundary: FsStep,
    armed: AtomicBool,
}
#[cfg(unix)]
impl Faults for ReplaceBodyNamespace {
    fn before(&self, step: FsStep, _path: &Path) -> io::Result<()> {
        if step == self.boundary && self.armed.swap(false, Ordering::SeqCst) {
            fs::rename(&self.selected, &self.original)?;
            fs::create_dir(&self.selected)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
#[test]
fn body_publication_retains_original_bytes_across_root_and_height_substitution() {
    for (boundary, height_only) in [
        (FsStep::CreateDir, false),
        (FsStep::CreateTemp, false),
        (FsStep::CreateTemp, true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let (body, source, budget) = fixture(1025);
        let instance = root
            .path()
            .join("bodies")
            .join(hex::encode(source.instance().0));
        let selected = if height_only {
            instance.join(height_name(source.height()))
        } else {
            instance.clone()
        };
        let faults = Arc::new(ReplaceBodyNamespace {
            selected,
            original: root.path().join("original"),
            boundary,
            armed: AtomicBool::new(false),
        });
        let store = FileBodyStore::open_with_faults(
            root.path(),
            &source.instance(),
            Arc::new(BlsCrypto::new()),
            BodyLimits::default(),
            budget.clone(),
            faults.clone(),
        )
        .unwrap();
        faults.armed.store(true, Ordering::SeqCst);
        assert_eq!(
            store.put(&source.block_hash(), &body).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert!(!faults.armed.load(Ordering::SeqCst));
        assert_eq!(fs::read_dir(&faults.selected).unwrap().count(), 0);
        let pointer = store
            .pending_write
            .lock()
            .as_mut()
            .unwrap()
            .prepared
            .prepare(&budget)
            .unwrap()
            .as_ptr();
        let charged = budget.reserved_bytes();
        assert_eq!(
            store.put(&source.block_hash(), &body).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(fs::read_dir(&faults.selected).unwrap().count(), 0);
        // The original encoded owner remains present; repair only its exact namespace.
        assert_eq!(
            store
                .pending_write
                .lock()
                .as_ref()
                .unwrap()
                .prepared
                .body()
                .payload()
                .as_slice()
                .as_ptr(),
            body.payload().as_slice().as_ptr()
        );
        assert_eq!(budget.reserved_bytes(), charged);
        fs::remove_dir(&faults.selected).unwrap();
        fs::rename(&faults.original, &faults.selected).unwrap();
        assert_eq!(
            store
                .pending_write
                .lock()
                .as_mut()
                .unwrap()
                .prepared
                .prepare(&budget)
                .unwrap()
                .as_ptr(),
            pointer
        );
        store.put(&source.block_hash(), &body).unwrap();
        assert!(store.pending_write.lock().is_none());
        assert_eq!(restored(&store, source, &budget), body);
    }
}

#[cfg(unix)]
#[test]
fn retained_body_reader_refuses_replaced_root_and_same_byte_foreign_file_then_retries() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    let charged = budget.reserved_bytes();
    let original_root = root.path().join("original-instance");
    fs::rename(&store.dir, &original_root).unwrap();
    fs::create_dir(&store.dir).unwrap();
    assert!(
        matches!(read.poll(&budget), Err(BodyReadError::Io(error)) if error.kind()==io::ErrorKind::Other)
    );
    assert_eq!(budget.reserved_bytes(), charged);
    fs::remove_dir(&store.dir).unwrap();
    fs::rename(&original_root, &store.dir).unwrap();
    let selected = store.dir.join(height_name(source.height()));
    let original_height = root.path().join("original-height");
    fs::rename(&selected, &original_height).unwrap();
    fs::create_dir(&selected).unwrap();
    let name = hex::encode(source.block_hash().0);
    fs::copy(original_height.join(&name), selected.join(&name)).unwrap();
    assert!(
        matches!(read.poll(&budget), Err(BodyReadError::Io(error)) if error.kind()==io::ErrorKind::Other)
    );
    let retained = budget.reserved_bytes();
    assert!(
        retained > charged,
        "the exact original read backing must remain funded"
    );
    assert!(
        matches!(read.poll(&budget), Err(BodyReadError::Io(error)) if error.kind()==io::ErrorKind::Other)
    );
    assert_eq!(budget.reserved_bytes(), retained);
    fs::remove_file(selected.join(&name)).unwrap();
    fs::remove_dir(&selected).unwrap();
    fs::rename(&original_height, &selected).unwrap();
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original read must resume")
    };
    assert_eq!(read.source(), &source);
    assert_eq!(
        restoration
            .complete(&budget, &BlsCrypto::new())
            .unwrap_or_else(|(_, error)| panic!("original signed body: {error:?}")),
        body
    );
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Completed)));
}

#[test]
fn original_body_read_can_be_pruned_and_reports_only_actual_missing_source() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    let charged = budget.reserved_bytes();
    budget.set_limit_bytes(charged);
    assert!(matches!(
        read.poll(&budget).unwrap(),
        BodyReadPoll::Pending(_)
    ));
    store.prune_through(source.height()).unwrap();
    assert!(store.retirement_authorized(source.height()));
    assert_eq!(store.bytes().unwrap(), 0);
    assert!(store.heights().unwrap().is_empty());
    budget.set_limit_bytes(1 << 25);
    assert!(
        matches!(read.poll(&budget), Err(BodyReadError::Io(error)) if error.kind()==io::ErrorKind::NotFound)
    );
    assert_eq!(read.source(), &source);
    drop(read);
    assert_eq!(budget.reserved_bytes(), charged);
}

// Exercise the exact child-open/held-file-validation window without timing sleeps.
// With no operation lock, the cooperating prune completes inside that window; with
// the lock, it announces its failed nonblocking probe and then waits for the reader.
#[cfg(unix)]
fn prune_during_child_validation<T>(
    store: Arc<FileBodyStore>,
    height: u64,
    read: impl FnOnce() -> T,
) -> (T, bool) {
    use std::{sync::mpsc, time::Duration};

    let (start_tx, start_rx) = mpsc::sync_channel(0);
    let (observed_tx, observed_rx) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        start_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let probe = File::open(store.dir().join(LOCK_NAME)).unwrap();
        let blocked = match probe.try_lock() {
            Ok(()) => false,
            Err(std::fs::TryLockError::WouldBlock) => true,
            Err(error) => panic!("operation lock probe failed: {error}"),
        };
        drop(probe);
        if blocked {
            observed_tx.send(()).unwrap();
            store.prune_through(height).unwrap();
        } else {
            store.prune_through(height).unwrap();
            observed_tx.send(()).unwrap();
        }
        blocked
    });
    let result = crate::sumeragi::artifact_read::with_child_revalidation_hook(
        move || {
            start_tx.send(()).unwrap();
            observed_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        },
        read,
    );
    (result, worker.join().unwrap())
}

#[cfg(unix)]
#[test]
fn body_read_open_serializes_child_validation_with_cooperative_prune() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = Arc::new(open(root.path(), &source, &budget));
    store.put(&source.block_hash(), &body).unwrap();
    let (result, prune_waited) =
        prune_during_child_validation(store.clone(), source.height(), || {
            store.begin_read(source.clone())
        });
    let mut read = result.unwrap_or_else(|error| panic!("original open failed: {error}"));
    assert!(prune_waited, "retirement crossed original file admission");
    assert_eq!(read.source(), &source);
    assert!(store.retirement_authorized(source.height()));
    assert_eq!(store.bytes().unwrap(), 0);
    assert!(
        matches!(read.poll(&budget), Err(BodyReadError::Io(error)) if error.kind() == io::ErrorKind::NotFound),
        "a later completed prune must retain the existing explicit retirement handoff"
    );
}

#[cfg(unix)]
#[test]
fn body_read_poll_serializes_child_validation_with_cooperative_prune() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = Arc::new(open(root.path(), &source, &budget));
    store.put(&source.block_hash(), &body).unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    let (result, prune_waited) =
        prune_during_child_validation(store.clone(), source.height(), || read.poll(&budget));
    let BodyReadPoll::Ready(restoration) =
        result.unwrap_or_else(|error| panic!("original read failed: {error}"))
    else {
        panic!("the original body must finish before cooperating retirement")
    };
    assert!(prune_waited, "retirement crossed held-file validation");
    assert_eq!(read.source(), &source);
    assert!(store.retirement_authorized(source.height()));
    assert_eq!(store.bytes().unwrap(), 0);
    assert_eq!(
        restoration
            .complete(&budget, &BlsCrypto::new())
            .unwrap_or_else(|(_, error)| panic!("original signed body: {error:?}")),
        body
    );
}

#[cfg(unix)]
#[test]
fn body_read_validation_still_rejects_uncooperative_hardlinks() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let store = open(root.path(), &source, &budget);
    store.put(&source.block_hash(), &body).unwrap();
    let mut read = store.begin_read(source.clone()).unwrap();
    let original = store.body_path(source.height(), &source.block_hash());
    let extra = root.path().join("extra-body-link");
    let extra_hook = extra.clone();
    let result = crate::sumeragi::artifact_read::with_child_revalidation_hook(
        move || fs::hard_link(original, extra_hook).unwrap(),
        || read.poll(&budget),
    );
    assert!(
        matches!(result, Err(BodyReadError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    assert!(!store.retirement_authorized(source.height()));
    fs::remove_file(extra).unwrap();
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("the retained original read must recover after the same inode is repaired")
    };
    assert_eq!(
        restoration
            .complete(&budget, &BlsCrypto::new())
            .unwrap_or_else(|(_, error)| panic!("original signed body: {error:?}")),
        body
    );
}

#[test]
fn body_read_refund_callbacks_reenter_after_physical_read_lock_release() {
    use iroha_allocation::{AllocationRefusal, ChargedBuffer, release::ReleaseRegistration};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::AtomicUsize,
        task::{Context, Poll, Wake, Waker},
    };

    struct Probe {
        store: Arc<FileBodyStore>,
        calls: AtomicUsize,
        operation_free: AtomicBool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let operation = File::open(self.store.dir().join(LOCK_NAME)).unwrap();
            let free = operation.try_lock().is_ok();
            self.operation_free.store(free, Ordering::SeqCst);
            drop(operation);
            // Fail an assertion rather than deadlock if the callback ran under the lock.
            if free {
                assert!(self.store.bytes().unwrap() > 0);
            }
        }
    }

    for unwind in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (body, source, budget) = fixture(1025);
        let store = Arc::new(open(root.path(), &source, &budget));
        store.put(&source.block_hash(), &body).unwrap();
        let mut read = store.begin_read(source).unwrap();
        let refund = ChargedBuffer::<u8>::new(1, &budget).unwrap();
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let probe = Arc::new(Probe {
            store: store.clone(),
            calls: AtomicUsize::new(0),
            operation_free: AtomicBool::new(false),
        });
        let waker = Waker::from(probe.clone());
        let AllocationRefusal::Capacity { release, .. } =
            budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
        else {
            panic!("an occupied original pool supplies the release observation")
        };
        assert_eq!(
            registration.poll_wait(&release, &mut Context::from_waker(&waker)),
            Poll::Pending
        );
        let result = catch_unwind(AssertUnwindSafe(|| {
            crate::sumeragi::artifact_read::with_child_revalidation_hook(
                move || {
                    drop(refund);
                    assert!(!unwind, "original physical read unwound");
                },
                || read.poll(&budget),
            )
        }));
        if unwind {
            assert!(result.is_err());
        } else {
            assert!(matches!(result.unwrap().unwrap(), BodyReadPoll::Ready(_)));
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert!(
            probe.operation_free.load(Ordering::SeqCst),
            "original body-read refund ran under the operation lock"
        );
        assert_eq!(
            registration.poll_wait(&release, &mut Context::from_waker(&waker)),
            Poll::Ready(())
        );
    }
}

#[test]
fn distinct_body_handles_share_one_capacity_lock_and_retained_loser_retries_after_prune() {
    let root = tempfile::tempdir().unwrap();
    let (first_body, first_source, first_budget) = fixture(1025);
    let (second_body, second_source, second_budget) = fixture(3000);
    assert_eq!(first_source.instance(), second_source.instance());
    assert_ne!(first_source.block_hash(), second_source.block_hash());
    let encoded_len = |body: &AvailableBody, budget: &AllocationBudget| {
        u64::try_from(
            PreparedBodyWrite::new(body.clone())
                .prepare(budget)
                .unwrap()
                .len(),
        )
        .unwrap()
    };
    let limit =
        encoded_len(&first_body, &first_budget).max(encoded_len(&second_body, &second_budget));
    let first = FileBodyStore::open(
        root.path(),
        &first_source.instance(),
        Arc::new(BlsCrypto::new()),
        BodyLimits { max_bytes: limit },
        first_budget.clone(),
    )
    .unwrap();
    let second = FileBodyStore::open(
        root.path(),
        &second_source.instance(),
        Arc::new(BlsCrypto::new()),
        BodyLimits { max_bytes: limit },
        second_budget.clone(),
    )
    .unwrap();
    let start = std::sync::Barrier::new(2);
    let (first_result, second_result) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            start.wait();
            first.put(&first_source.block_hash(), &first_body)
        });
        let two = scope.spawn(|| {
            start.wait();
            second.put(&second_source.block_hash(), &second_body)
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let (loser, source, body, budget, failure) = if first_result.is_err() {
        (
            &first,
            first_source,
            &first_body,
            &first_budget,
            first_result,
        )
    } else {
        (
            &second,
            second_source,
            &second_body,
            &second_budget,
            second_result,
        )
    };
    assert_eq!(failure.unwrap_err().kind(), io::ErrorKind::StorageFull);
    assert!(loser.bytes().unwrap() <= limit);
    let pointer = loser
        .pending_write
        .lock()
        .as_mut()
        .unwrap()
        .prepared
        .prepare(budget)
        .unwrap()
        .as_ptr();
    let charged = budget.reserved_bytes();
    loser.prune_through(source.height()).unwrap();
    assert_eq!(loser.bytes().unwrap(), 0);
    assert_eq!(
        loser
            .pending_write
            .lock()
            .as_mut()
            .unwrap()
            .prepared
            .prepare(budget)
            .unwrap()
            .as_ptr(),
        pointer
    );
    assert_eq!(budget.reserved_bytes(), charged);
    loser.put(&source.block_hash(), body).unwrap();
    assert!(loser.pending_write.lock().is_none());
    assert_eq!(&restored(loser, source, budget), body);
}

#[test]
fn explicit_retirement_releases_only_pending_height_and_preserves_original_publication_bytes() {
    let root = tempfile::tempdir().unwrap();
    let (body, source, budget) = fixture(1025);
    let faults = Arc::new(FailPublishedSync::default());
    let store = FileBodyStore::open_with_faults(
        root.path(),
        &source.instance(),
        Arc::new(BlsCrypto::new()),
        BodyLimits::default(),
        budget.clone(),
        faults.clone(),
    )
    .unwrap();
    faults.0.store(true, Ordering::SeqCst);
    assert!(store.put(&source.block_hash(), &body).is_err());
    assert!(
        store
            .pending_write
            .lock()
            .as_ref()
            .unwrap()
            .directory
            .is_some()
    );
    let pointer = store
        .pending_write
        .lock()
        .as_mut()
        .unwrap()
        .prepared
        .prepare(&budget)
        .unwrap()
        .as_ptr();
    let charged = budget.reserved_bytes();
    faults.0.store(false, Ordering::SeqCst);
    store.prune_through(source.height()).unwrap();
    assert!(store.retirement_authorized(source.height()));
    assert!(
        store
            .pending_write
            .lock()
            .as_ref()
            .unwrap()
            .directory
            .is_none()
    );
    assert_eq!(
        store
            .pending_write
            .lock()
            .as_mut()
            .unwrap()
            .prepared
            .prepare(&budget)
            .unwrap()
            .as_ptr(),
        pointer
    );
    assert_eq!(budget.reserved_bytes(), charged);
    assert_eq!(store.bytes().unwrap(), 0);
    store.put(&source.block_hash(), &body).unwrap();
    assert_eq!(restored(&store, source, &budget), body);
}

#[test]
fn body_publication_refund_callbacks_reenter_only_after_both_original_locks_release() {
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::{
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
        sync::atomic::AtomicUsize,
        task::{Context, Poll, Wake, Waker},
    };

    struct Probe {
        store: Arc<FileBodyStore>,
        calls: AtomicUsize,
        pending_free: AtomicBool,
        operation_free: AtomicBool,
        read_bytes: AtomicU64,
        unwind: bool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let pending = self.store.pending_write.try_lock();
            let pending_free = pending.is_some();
            self.pending_free.store(pending_free, Ordering::SeqCst);
            // Probe the actual original operation lock without blocking. This path is
            // unchanged throughout this test; namespace substitution is tested above.
            let operation = File::open(self.store.dir().join(".custody.lock")).unwrap();
            let operation_free = operation.try_lock().is_ok();
            self.operation_free.store(operation_free, Ordering::SeqCst);
            drop(operation);
            drop(pending);
            // The old cleanup order must fail an assertion, never hang this test.
            if pending_free && operation_free {
                self.read_bytes
                    .store(self.store.bytes().unwrap(), Ordering::SeqCst);
            }
            if self.unwind {
                resume_unwind(Box::new("original body refund callback unwound"));
            }
        }
    }

    for unwind in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (body, source, budget) = fixture(1025);
        let original_reserved = budget.reserved_bytes();
        let original_limit = budget.limit_bytes();
        let faults = Arc::new(FailPublishedSync::default());
        let store = Arc::new(
            FileBodyStore::open_with_faults(
                root.path(),
                &source.instance(),
                Arc::new(BlsCrypto::new()),
                BodyLimits::default(),
                budget.clone(),
                faults.clone(),
            )
            .unwrap(),
        );
        faults.0.store(true, Ordering::SeqCst);
        assert!(store.put(&source.block_hash(), &body).is_err());
        let bytes = fs::read(store.body_path(source.height(), &source.block_hash())).unwrap();
        let charged = budget.reserved_bytes();
        assert!(charged > original_reserved);
        let mut registration = ReleaseRegistration::from_reservation(
            &mut budget
                .try_reserve(ReleaseRegistration::allocation_layout())
                .unwrap(),
        )
        .unwrap();
        let probe = Arc::new(Probe {
            store: store.clone(),
            calls: AtomicUsize::new(0),
            pending_free: AtomicBool::new(false),
            operation_free: AtomicBool::new(false),
            read_bytes: AtomicU64::new(0),
            unwind,
        });
        let waker = Waker::from(probe.clone());
        budget.set_limit_bytes(budget.reserved_bytes());
        let AllocationRefusal::Capacity { release, .. } = budget.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("exact original capacity refusal supplies the callback observation");
        };
        assert_eq!(
            registration.poll_wait(&release, &mut Context::from_waker(&waker)),
            Poll::Pending
        );
        faults.0.store(false, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| store.put(&source.block_hash(), &body)));
        if unwind {
            assert_eq!(
                result.unwrap_err().downcast_ref::<&'static str>(),
                Some(&"original body refund callback unwound")
            );
        } else {
            result.unwrap().unwrap();
        }
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        assert!(
            probe.pending_free.load(Ordering::SeqCst)
                && probe.operation_free.load(Ordering::SeqCst),
            "original body publication refund ran under a storage lock"
        );
        assert_eq!(
            probe.read_bytes.load(Ordering::SeqCst),
            u64::try_from(bytes.len()).unwrap()
        );
        assert!(store.pending_write.lock().is_none());
        assert_eq!(
            budget.reserved_bytes(),
            original_reserved + ReleaseRegistration::allocation_layout().size()
        );
        assert_eq!(
            registration.poll_wait(&release, &mut Context::from_waker(&waker)),
            Poll::Ready(())
        );
        assert_eq!(
            fs::read(store.body_path(source.height(), &source.block_hash())).unwrap(),
            bytes
        );
        budget.set_limit_bytes(original_limit);
        assert_eq!(restored(&store, source, &budget), body);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), original_reserved);
    }
}
