//! Publication fault boundaries and equivalent-certificate concurrency with real BLS proofs.

use super::tests::*;
use super::*;
use crate::sumeragi::{lanes::record::tests::fixture, records::FsStep};
use std::sync::atomic::{AtomicBool, Ordering};

struct FailOnce {
    step: FsStep,
    armed: AtomicBool,
}
impl Faults for FailOnce {
    fn before(&self, step: FsStep, _: &Path) -> io::Result<()> {
        if step == self.step && self.armed.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected publication refusal"));
        }
        Ok(())
    }
}

#[test]
fn each_publication_boundary_retains_original_until_durable_retry() {
    for step in [
        FsStep::CreateTemp,
        FsStep::WriteTemp,
        FsStep::WriteTempRest,
        FsStep::SyncFile,
        FsStep::Rename,
        FsStep::SyncDir,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (body, qc, source, budget, crypto) = fixture(1025);
        let faults = Arc::new(FailOnce {
            step,
            armed: AtomicBool::new(false),
        });
        let store = open(
            dir.path(),
            &source,
            Arc::new(crypto),
            &budget,
            faults.clone(),
        );
        faults.armed.store(true, Ordering::SeqCst);
        assert!(store.append(&body, &qc).is_err(), "{step:?}");
        assert_eq!(store.height(), 0);
        assert!(!store.wait_for(1, Duration::ZERO));
        assert!(store.entry(1).unwrap().is_none());
        let pointer = store
            .state
            .lock()
            .write
            .as_mut()
            .unwrap()
            .prepare(&budget)
            .unwrap()
            .as_ptr();
        assert_eq!(
            store
                .state
                .lock()
                .write
                .as_mut()
                .unwrap()
                .prepare(&budget)
                .unwrap()
                .as_ptr(),
            pointer
        );
        store.append(&body, &qc).unwrap();
        assert_eq!(store.height(), 1);
        assert_eq!(store.entry(1).unwrap().unwrap().commit_qc, qc);
    }
}

#[test]
fn recovered_visible_frame_keeps_original_owner_until_fsync_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let crypto: SharedCrypto = Arc::new(crypto);
    let publish = Arc::new(FailOnce {
        step: FsStep::SyncDir,
        armed: AtomicBool::new(false),
    });
    let store = open(
        dir.path(),
        &source,
        crypto.clone(),
        &budget,
        publish.clone(),
    );
    publish.armed.store(true, Ordering::SeqCst);
    assert!(store.append(&body, &qc).is_err());
    let path = store.dir.join(frame_name(1));
    let bytes = fs::read(&path).unwrap();
    drop(store);
    let faults = Arc::new(FailOnce {
        step: FsStep::SyncFile,
        armed: AtomicBool::new(true),
    });
    let opening = FileLaneBlockStore::begin_open_with_faults(
        dir.path(),
        &source.instance(),
        crypto.clone(),
        budget.clone(),
        schedule(&source),
        faults,
    )
    .unwrap();
    let (opening, error) = opening.complete().err().unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::Other);
    let pointer = opening
        .store
        .state
        .lock()
        .read
        .as_mut()
        .unwrap()
        .ready
        .as_mut()
        .unwrap()
        .prepare(&budget)
        .unwrap()
        .as_ptr();
    assert_eq!(
        opening
            .store
            .state
            .lock()
            .read
            .as_mut()
            .unwrap()
            .ready
            .as_mut()
            .unwrap()
            .prepare(&budget)
            .unwrap()
            .as_ptr(),
        pointer
    );
    assert_eq!(opening.validated, 0);
    assert_eq!(opening.store.height(), 0);
    assert!(
        FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            crypto,
            budget.clone(),
            schedule(&source)
        )
        .is_err()
    );
    let recovered = opening.complete().unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_eq!(recovered.height(), 1);
    assert_eq!(recovered.entry(1).unwrap().unwrap().commit_qc, qc);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn oversized_or_noncanonical_disk_population_cannot_be_recovered() {
    for noncanonical in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, source, budget, crypto) = fixture(8);
        let path = dir.path().join(hex::encode(source.instance().0));
        fs::create_dir_all(&path).unwrap();
        let frame = path.join(if noncanonical {
            "1.frame".into()
        } else {
            frame_name(1)
        });
        File::create(frame)
            .unwrap()
            .set_len(MAX_FRAME_FILE_BYTES as u64 + 1)
            .unwrap();
        let begin = FileLaneBlockStore::begin_open(
            dir.path(),
            &source.instance(),
            Arc::new(crypto),
            budget,
            schedule(&source),
        );
        if noncanonical {
            assert_eq!(begin.err().unwrap().kind(), io::ErrorKind::InvalidData);
        } else {
            assert_eq!(
                begin.unwrap().complete().err().unwrap().1.io_kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}

#[test]
fn concurrent_equivalent_certificates_preserve_one_original_durable_proof() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let other = alternative(&qc, &crypto);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    std::thread::scope(|scope| {
        let a = scope.spawn(|| store.append(&body, &qc));
        let b = scope.spawn(|| store.append(&body, &other));
        a.join().unwrap().unwrap();
        b.join().unwrap().unwrap();
    });
    let stored = store.entry(1).unwrap().unwrap().commit_qc;
    assert!(stored == qc || stored == other);
    assert_eq!(store.height(), 1);
}

fn original_queue() -> Arc<crate::queue::Queue> {
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
    Arc::new(crate::queue::Queue::test(
        iroha_config::parameters::actual::Queue::default(),
        &time,
    ))
}

#[test]
fn durable_lane_publication_wakes_original_root_after_refusal_and_idempotent_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let faults = Arc::new(FailOnce {
        step: FsStep::SyncDir,
        armed: AtomicBool::new(false),
    });
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        faults.clone(),
    );
    // No LaneTransactions or member executor participates in this actual signed store
    // publication. The runner binds the same path for observers before its member split.
    let queue = original_queue();
    let (notified, notification) = std::sync::mpsc::sync_channel(4);
    queue.set_sumeragi_wake(notified);
    store.bind_global_queue(&queue).unwrap();
    let original_charge = budget.reserved_bytes();
    assert_eq!(
        Arc::strong_count(&queue),
        1,
        "the store retains only the original weak Queue"
    );
    faults.armed.store(true, Ordering::SeqCst);
    assert!(store.append(&body, &qc).is_err());
    assert_eq!(store.height(), 0);
    assert!(
        notification.try_recv().is_err(),
        "refused lane publication cannot announce a global merge"
    );
    let original_bytes = store
        .state
        .lock()
        .write
        .as_mut()
        .unwrap()
        .prepare(&budget)
        .unwrap()
        .as_ptr();
    let retained_charge = budget.reserved_bytes();
    assert!(retained_charge > original_charge);
    faults.armed.store(true, Ordering::SeqCst);
    assert!(store.append(&body, &qc).is_err());
    assert_eq!(store.height(), 0);
    assert!(notification.try_recv().is_err());
    assert_eq!(budget.reserved_bytes(), retained_charge);
    assert_eq!(
        store
            .state
            .lock()
            .write
            .as_mut()
            .unwrap()
            .prepare(&budget)
            .unwrap()
            .as_ptr(),
        original_bytes
    );
    store.append(&body, &qc).unwrap();
    assert_eq!(store.height(), 1);
    notification
        .try_recv()
        .expect("durable lane publication must wake the original global merge owner");
    assert!(notification.try_recv().is_err());
    // The hint is readiness, never a second publication or application acknowledgement.
    let frame = fs::read(store.dir.join(frame_name(1))).unwrap();
    store.append(&body, &qc).unwrap();
    notification
        .try_recv()
        .expect("exact durable retry must reannounce the same global merge");
    assert!(notification.try_recv().is_err());
    assert_eq!(store.height(), 1);
    assert_eq!(fs::read(store.dir.join(frame_name(1))).unwrap(), frame);
    assert_eq!(store.entry(1).unwrap().unwrap().commit_qc, qc);
    drop(queue);
    // A historical store or late publisher cannot resurrect a retired Queue owner.
    store.append(&body, &qc).unwrap();
    assert_eq!(store.height(), 1);
    assert!(matches!(
        notification.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    ));
}

#[test]
fn lane_merge_wake_binding_preserves_original_queue_and_pool_across_retry() {
    let dir = tempfile::tempdir().unwrap();
    let (_body, _qc, source, budget, crypto) = fixture(1025);
    let store = open(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let charge = budget.reserved_bytes();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let foreign_queue = original_queue();
    let _foreign_pool_ticket = foreign_queue.reserve_sumeragi_start(&foreign).unwrap();
    assert!(store.global_queue.get().is_none());
    let refusal = store
        .bind_global_queue(&foreign_queue)
        .expect_err("lane merge wake must refuse a foreign cold State pool before binding");
    assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        refusal.to_string(),
        "lane merge notification belongs to another original State pool"
    );
    assert!(
        store.global_queue.get().is_none(),
        "lane merge wake must refuse a foreign cold State pool before binding"
    );
    assert_eq!(budget.reserved_bytes(), charge);
    assert_eq!(foreign.reserved_bytes(), 0);
    let queue = original_queue();
    let original = queue.reserve_sumeragi_start(&budget).unwrap();
    store.bind_global_queue(&queue).unwrap();
    store.bind_global_queue(&queue).unwrap();
    let same_pool_foreign_queue = original_queue();
    let _foreign_ticket = same_pool_foreign_queue
        .reserve_sumeragi_start(&budget)
        .unwrap();
    let refusal = store
        .bind_global_queue(&same_pool_foreign_queue)
        .expect_err("lane merge wake must retain the exact original Queue identity");
    assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        refusal.to_string(),
        "lane merge notification belongs to another original Queue"
    );
    assert!(Weak::ptr_eq(
        store.global_queue.get().unwrap(),
        &Arc::downgrade(&queue)
    ));
    assert_eq!(Arc::strong_count(&queue), 1);
    assert_eq!(budget.reserved_bytes(), charge);
    assert_eq!(foreign.reserved_bytes(), 0);
    drop(original);
    assert_eq!(
        store.bind_global_queue(&queue).unwrap_err().to_string(),
        "lane merge notification belongs to another original State pool"
    );
    assert!(Weak::ptr_eq(
        store.global_queue.get().unwrap(),
        &Arc::downgrade(&queue)
    ));
}
