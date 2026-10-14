//! Original authenticated history refunds run after their scan guard and stack frame retire.

use super::{tests::fixed_lane_chain, *};
use iroha_allocation::{
    AllocationBudget, AllocationRefusal,
    release::{ReleaseRegistration, ReleaseWait},
};
use std::{
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct HistoryRefundProbe {
    provider: Weak<NativeLaneStoreAuthorities>,
    lane: LaneId,
    incarnation: [u8; 32],
    calls: AtomicUsize,
    scan_free: AtomicBool,
    scan_empty: AtomicBool,
    reentered: AtomicBool,
}
impl Wake for HistoryRefundProbe {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let provider = self.provider.upgrade().unwrap();
        let scan = provider.scan.try_lock();
        let free = scan.is_some();
        self.scan_free.store(free, Ordering::SeqCst);
        self.scan_empty.store(
            scan.as_ref().is_some_and(|pending| pending.is_none()),
            Ordering::SeqCst,
        );
        drop(scan);
        // A broken lifetime fails the assertion below without waiting on its own mutex.
        // The correct path reenters the real producer, on the ordinary test thread stack.
        if free {
            match provider.historical_record(self.lane, self.incarnation) {
                Ok(Some(owner)) => {
                    assert!(owner.belongs_to(&provider.state.ivm_execution_budget()));
                    assert_eq!(owner.lane(), self.lane);
                }
                Ok(None) => panic!("the original active lane must retain its authority"),
                Err(error) => {
                    // Corrupt/replaced archive tests still reject their original source.
                    assert_ne!(error.io_kind(), io::ErrorKind::WouldBlock);
                }
            }
            self.reentered.store(true, Ordering::SeqCst);
        }
    }
}

struct HistoryRefundWatch {
    registration: ReleaseRegistration,
    release: ReleaseWait,
    probe: Arc<HistoryRefundProbe>,
}
impl HistoryRefundWatch {
    fn arm(
        provider: &Arc<NativeLaneStoreAuthorities>,
        lane: LaneId,
        incarnation: [u8; 32],
    ) -> Self {
        let budget = provider.state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let AllocationRefusal::Capacity { release, .. } =
            budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
        else {
            panic!("the actual history reader owns its original finite-pool refusal");
        };
        let probe = Arc::new(HistoryRefundProbe {
            provider: Arc::downgrade(provider),
            lane,
            incarnation,
            calls: AtomicUsize::new(0),
            scan_free: AtomicBool::new(false),
            scan_empty: AtomicBool::new(false),
            reentered: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        assert_eq!(
            registration.poll_wait(&release, &mut Context::from_waker(&waker)),
            Poll::Pending
        );
        let foreign = AllocationBudget::new(1);
        drop(foreign.try_reserve_bytes(1).unwrap());
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
        Self {
            registration,
            release,
            probe,
        }
    }

    fn assert_woke_after_scan_cleanup(&mut self) {
        assert_eq!(self.probe.calls.load(Ordering::SeqCst), 1);
        assert!(
            self.probe.scan_free.load(Ordering::SeqCst),
            "original history refund must wait for scan unlock"
        );
        assert!(self.probe.scan_empty.load(Ordering::SeqCst));
        assert!(self.probe.reentered.load(Ordering::SeqCst));
        assert_eq!(
            self.registration.poll_wait(
                &self.release,
                &mut Context::from_waker(&Waker::from(Arc::clone(&self.probe))),
            ),
            Poll::Ready(())
        );
    }
}

#[inline(never)]
fn retain_completed_original_scan(
    provider: &NativeLaneStoreAuthorities,
    lane: LaneId,
    incarnation: [u8; 32],
) {
    let mut scan = HistoryScan::open(&provider.state, lane, incarnation)
        .unwrap()
        .unwrap();
    scan.complete().unwrap();
    assert!(provider.scan.lock().replace(scan).is_none());
}

fn original_success_control(retain_completed: bool) {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    if retain_completed {
        retain_completed_original_scan(&provider, record.lane, record.incarnation);
        assert!(budget.reserved_bytes() > baseline);
    }
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    let owner = provider
        .historical_record(record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    watch.assert_woke_after_scan_cleanup();
    assert!(owner.belongs_to(&budget));
    assert_eq!(
        owner.config(),
        &super::super::lanes::lane_height_config(&record).unwrap()
    );
    assert!(provider.scan.lock().is_none());
    assert!(budget.reserved_bytes() > baseline);
    drop(owner);
    drop(watch);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_history_scan_progress_refunds_after_scan_unlock() {
    original_success_control(false);
}

#[test]
fn original_history_scan_finish_refunds_after_scan_unlock() {
    original_success_control(true);
}

#[test]
fn original_history_scan_cancellation_refunds_after_scan_unlock() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    retain_completed_original_scan(&provider, record.lane, record.incarnation);
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    assert!(
        provider
            .historical_record(LaneId::new(99), [99; 32])
            .unwrap()
            .is_none()
    );
    watch.assert_woke_after_scan_cleanup();
    assert!(provider.scan.lock().is_none());
    drop(watch);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_history_scan_stale_cut_refunds_after_scan_unlock() {
    let (mut chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    retain_completed_original_scan(&provider, record.lane, record.incarnation);
    let scan_bytes = budget.reserved_bytes() - baseline;
    chain.commit(Vec::new());
    let new_baseline = budget.reserved_bytes() - scan_bytes;
    let original_tip = chain.state().view().native_execution_tip();
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .expect("the retained scan belongs to the old publication");
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(error.to_string().contains("publication changed"));
    watch.assert_woke_after_scan_cleanup();
    assert!(provider.scan.lock().is_none());
    assert_eq!(chain.state().view().native_execution_tip(), original_tip);
    drop(watch);
    assert_eq!(budget.reserved_bytes(), new_baseline);
}

fn original_namespace_error_control(cancelled: bool) {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    retain_completed_original_scan(&provider, record.lane, record.incarnation);
    let path = chain.kura().store_root().join("native-contexts");
    let retained = chain.kura().store_root().join("original-native-contexts");
    std::fs::rename(&path, &retained).unwrap();
    std::fs::create_dir(&path).unwrap();
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    let (lane, incarnation) = if cancelled {
        (LaneId::new(99), [99; 32])
    } else {
        (record.lane, record.incarnation)
    };
    let error = provider.historical_record(lane, incarnation).err().unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("identity changed"));
    watch.assert_woke_after_scan_cleanup();
    assert!(provider.scan.lock().is_none());
    drop(watch);
    assert_eq!(budget.reserved_bytes(), baseline);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(retained, path).unwrap();
    let owner = provider
        .historical_record(record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    assert!(owner.belongs_to(&budget));
    drop(owner);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_history_scan_terminal_cleanup_refunds_after_scan_unlock() {
    original_namespace_error_control(false);
}

#[test]
fn original_history_scan_cancelled_error_refunds_after_scan_unlock() {
    original_namespace_error_control(true);
}

#[test]
fn original_history_scan_invalid_prefix_refunds_after_scan_unlock() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            1,
            hex::encode(chain.genesis().hash().as_ref()),
        ));
    let original = std::fs::read(&path).unwrap();
    let mut changed: crate::state::NativeExecutionProjectionV1 =
        norito::decode_canonical(&original).unwrap();
    changed
        .ordinary_writes
        .push(iroha_data_model::block::consensus::ExecKv {
            key: b"history-refund-substituted-creation-write".to_vec(),
            value: vec![1],
        });
    std::fs::write(&path, norito::encode_canonical(&changed).unwrap()).unwrap();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::InvalidData);
    watch.assert_woke_after_scan_cleanup();
    assert!(provider.scan.lock().is_none());
    drop(watch);
    assert_eq!(budget.reserved_bytes(), baseline);
    std::fs::write(path, original).unwrap();
}

#[test]
fn original_history_scan_refused_retry_refunds_after_scan_unlock() {
    let (chain, record, _epoch) = fixed_lane_chain();
    let budget = chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let limit = budget.limit_bytes();
    let provider = Arc::new(NativeLaneStoreAuthorities::new(
        Arc::clone(chain.state()),
        Arc::new(BlsCrypto::new()),
    ));
    budget.set_limit_bytes(baseline);
    let error = provider
        .historical_record(record.lane, record.incarnation)
        .err()
        .unwrap();
    assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock);
    assert!(
        provider
            .scan
            .lock()
            .as_ref()
            .unwrap()
            .matches(record.lane, &record.incarnation)
    );
    let path = chain
        .kura()
        .store_root()
        .join("native-contexts")
        .join(format!(
            "{:020}-{}.nrt",
            1,
            hex::encode(chain.genesis().hash().as_ref()),
        ));
    let retained = path.with_extension("original-refund-retry");
    std::fs::rename(&path, &retained).unwrap();
    std::fs::write(
        &path,
        b"a new pathname does not replace the original refused descriptor",
    )
    .unwrap();
    budget.set_limit_bytes(limit);
    let mut watch = HistoryRefundWatch::arm(&provider, record.lane, record.incarnation);
    let owner = provider
        .historical_record(record.lane, record.incarnation)
        .unwrap()
        .unwrap();
    watch.assert_woke_after_scan_cleanup();
    assert!(owner.belongs_to(&budget));
    assert_eq!(
        owner.config(),
        &super::super::lanes::lane_height_config(&record).unwrap()
    );
    assert!(provider.scan.lock().is_none());
    drop(owner);
    drop(watch);
    assert_eq!(budget.reserved_bytes(), baseline);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(retained, path).unwrap();
}
