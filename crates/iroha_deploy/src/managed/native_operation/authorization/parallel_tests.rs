//! One live Lease serializes actual replacement publication and fresh epoch census.

use super::*;
use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{Barrier, mpsc},
    time::Duration,
};

type Hook = Box<dyn FnOnce()>;
thread_local! {
    static CONTENTION_HOOK: RefCell<Option<Hook>> = RefCell::new(None);
    static CLAIM_LOCK_HOOK: RefCell<Option<Hook>> = RefCell::new(None);
}
/// Observe one actual contended acquisition on this test thread.
pub(super) fn after_contention() {
    if let Some(action) = CONTENTION_HOOK.with(|hook| hook.borrow_mut().take()) {
        action();
    }
}
/// Observe the actual exclusive claim boundary before its unchanged native checks.
pub(super) fn after_claim_lock() {
    if let Some(action) = CLAIM_LOCK_HOOK.with(|hook| hook.borrow_mut().take()) {
        action();
    }
}
struct HookGuard(bool);
impl HookGuard {
    fn contention(action: impl FnOnce() + 'static) -> Self {
        CONTENTION_HOOK.with(|hook| {
            assert!(hook.borrow_mut().replace(Box::new(action)).is_none());
        });
        Self(false)
    }
    fn claim(action: impl FnOnce() + 'static) -> Self {
        CLAIM_LOCK_HOOK.with(|hook| {
            assert!(hook.borrow_mut().replace(Box::new(action)).is_none());
        });
        Self(true)
    }
}
impl Drop for HookGuard {
    fn drop(&mut self) {
        if self.0 {
            CLAIM_LOCK_HOOK.with(|hook| *hook.borrow_mut() = None);
        } else {
            CONTENTION_HOOK.with(|hook| *hook.borrow_mut() = None);
        }
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    lease: Lease,
    epochs: PrivateDirectory,
    original: Vec<u8>,
    epoch_bytes: Vec<u8>,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    providers: [ProviderId; 3],
}
impl Fixture {
    fn new() -> Self {
        Self::with_profile_interval(300_000)
    }
    fn with_profile_interval(profile_interval_ms: u64) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("intent")).unwrap();
        let original = b"original generated bootstrap custody".to_vec();
        directory
            .write_atomic("original.nrt", &original, PublishMode::CreateNew)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let fees = Fees::from_options(&BoundedTransactionOptions {
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            max_total_fees: BTreeMap::from([(
                AssetDefinitionId::parse_address_literal(
                    crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
                )
                .unwrap(),
                Quantity::from(1_000u64),
            )]),
            deadline,
        })
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let providers = [1, 2, 3].map(|value| ProviderId::new([value; 32]));
        let lease = Lease::issue(
            directory,
            original.clone(),
            &fees,
            Scope::Bootstrap(providers),
            now_ms().unwrap().checked_add(profile_interval_ms).unwrap(),
            deadline,
            Arc::clone(&cancelled),
        )
        .unwrap();
        let epochs = lease.directory.open_child("epochs").unwrap();
        let epoch_bytes = epochs
            .read("0001.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap()
            .to_vec();
        Self {
            _temporary: temporary,
            lease,
            epochs,
            original,
            epoch_bytes,
            deadline,
            cancelled,
            providers,
        }
    }
    fn claim(&self) -> Option<Replacement> {
        attempts::read_record(&self.epochs, "0001-replacement.nrt").unwrap()
    }
    fn assert_original(&self, claim_present: bool) {
        assert_eq!(
            self.lease
                .directory
                .read("original.nrt", self.original.len())
                .unwrap()
                .as_slice(),
            self.original.as_slice()
        );
        assert_eq!(
            self.epochs
                .read("0001.nrt", attempts::MAX_RECORD_BYTES)
                .unwrap()
                .as_slice(),
            self.epoch_bytes.as_slice()
        );
        let expected = if claim_present {
            vec![
                OsString::from("0001-replacement.nrt"),
                OsString::from("0001.nrt"),
            ]
        } else {
            vec![OsString::from("0001.nrt")]
        };
        assert_eq!(self.epochs.entries(MAX_EPOCHS * 2).unwrap(), expected);
    }
}
fn target(value: u8) -> ReplacementTarget {
    ReplacementTarget::Dispatch {
        previous_attempt: [value; 32],
    }
}

#[test]
fn parallel_lease_distinct_claims_keep_one_original_epoch_and_one_replacement() {
    let fixture = Fixture::new();
    let barrier = Barrier::new(3);
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture.lease.claim(
                Purpose::CustodyConfigure(fixture.providers[0]),
                target(11),
                fixture.deadline,
            )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fixture.lease.claim(
                Purpose::CustodyConfigure(fixture.providers[1]),
                target(12),
                fixture.deadline,
            )
        });
        barrier.wait();
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(crate::managed::Error::Bootstrap(
                    ManagedBootstrapFailure::ReplacementLimit
                ))
            ))
            .count(),
        1
    );
    let selected = fixture.claim().unwrap();
    let (provider, expected) = if results[0].is_ok() {
        (fixture.providers[0], target(11))
    } else {
        (fixture.providers[1], target(12))
    };
    assert!(selected.purpose == Purpose::CustodyConfigure(provider) && selected.target == expected);
    assert_eq!(selected.epoch, digest(&fixture.lease.epoch).unwrap());
    fixture.assert_original(true);
    fixture.lease.check(fixture.deadline).unwrap();
}

#[test]
fn parallel_lease_identical_claims_are_idempotent_without_renewing_authority() {
    let fixture = Fixture::new();
    let barrier = Barrier::new(3);
    let purpose = Purpose::FundingApproval(fixture.providers[0]);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture.lease.claim(purpose, target(13), fixture.deadline)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fixture.lease.claim(purpose, target(13), fixture.deadline)
        });
        barrier.wait();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
    });
    let bytes = fixture
        .epochs
        .read("0001-replacement.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    fixture
        .lease
        .claim(purpose, target(13), fixture.deadline)
        .unwrap();
    assert_eq!(
        fixture
            .epochs
            .read("0001-replacement.nrt", attempts::MAX_RECORD_BYTES)
            .unwrap(),
        bytes
    );
    let selected = fixture.claim().unwrap();
    assert!(selected.purpose == purpose && selected.target == target(13));
    assert_eq!(selected.epoch, digest(&fixture.lease.epoch).unwrap());
    fixture.assert_original(true);
}

#[test]
fn parallel_lease_reader_waits_for_actual_claim_and_then_closes_stable_census() {
    let fixture = Fixture::new();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (reader_tx, reader_rx) = mpsc::channel();
    let lease = &fixture.lease;
    let purpose = Purpose::CustodyEnroll(fixture.providers[0]);
    let deadline = fixture.deadline;
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let _hook = HookGuard::claim(move || {
                locked_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            lease.claim(purpose, target(14), deadline)
        });
        locked_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let reader = scope.spawn(move || {
            let _hook = HookGuard::contention(move || waiting_tx.send(()).unwrap());
            reader_tx.send(lease.check(deadline)).unwrap();
        });
        // Actual try_read WouldBlock signals this handshake, not thread scheduling.
        waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(matches!(
            reader_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(fixture.claim().is_none());
        release_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
        reader_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
    });
    assert!(fixture.claim().unwrap().purpose == purpose);
    fixture.assert_original(true);
}

#[test]
fn parallel_lease_wait_closes_cancellation_and_original_deadline_without_publication() {
    let fixture = Fixture::new();
    let lease = &fixture.lease;
    let deadline = fixture.deadline;
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let held = lease.replacement_gate.write().unwrap();
    std::thread::scope(|scope| {
        let reader = scope.spawn(move || {
            let _hook = HookGuard::contention(move || waiting_tx.send(()).unwrap());
            result_tx.send(lease.check(deadline)).unwrap();
        });
        waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        fixture.cancelled.store(true, Ordering::Release);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::Cancelled
            ))
        ));
        reader.join().unwrap();
    });
    // The waiter returned before the exclusive owner released the actual gate.
    drop(held);
    fixture.cancelled.store(false, Ordering::Release);
    fixture.lease.check(fixture.deadline).unwrap();

    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let held = lease.replacement_gate.read().unwrap();
    let purpose = Purpose::FundingRequest(fixture.providers[0]);
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let _hook = HookGuard::contention(move || waiting_tx.send(()).unwrap());
            // Start the real caller interval in its owner, after thread launch scheduling.
            let short_deadline = Instant::now() + Duration::from_secs(1);
            result_tx
                .send(lease.claim(purpose, target(15), short_deadline))
                .unwrap();
        });
        waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::AuthorizationExpired
            ))
        ));
        writer.join().unwrap();
    });
    // Releasing the gate cannot renew the caller's original interval.
    drop(held);
    assert!(fixture.claim().is_none());
    fixture.assert_original(false);
    fixture.lease.check(fixture.deadline).unwrap();
}

#[test]
fn parallel_lease_rechecks_cancellation_after_claim_lock() {
    let fixture = Fixture::new();
    let cancelled = Arc::clone(&fixture.cancelled);
    let _hook = HookGuard::claim(move || cancelled.store(true, Ordering::Release));
    assert!(matches!(
        fixture.lease.claim(
            Purpose::ProviderIngest(fixture.providers[0]),
            target(16),
            fixture.deadline
        ),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    assert!(fixture.claim().is_none());
    fixture.assert_original(false);
    fixture.cancelled.store(false, Ordering::Release);
    fixture.lease.check(fixture.deadline).unwrap();
}

#[test]
fn parallel_lease_poison_refuses_checks_and_claims_without_changing_original_material() {
    let fixture = Fixture::new();
    let lease = &fixture.lease;
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = lease.replacement_gate.write().unwrap();
                    panic!("intentional live Lease gate poison");
                })
                .join()
                .is_err()
        );
    });
    for result in [
        lease.check(fixture.deadline).map(|_| ()),
        lease.claim(
            Purpose::Gateway(fixture.providers[0]),
            target(17),
            fixture.deadline,
        ),
    ] {
        assert!(
            matches!(result, Err(crate::managed::Error::Invalid(message)) if message == "generated authorization replacement gate poisoned")
        );
    }
    assert!(fixture.claim().is_none());
    fixture.assert_original(false);
}

#[test]
fn parallel_lease_wait_stops_at_issued_utc_ceiling_without_publication() {
    // Issue the real epoch under a five-second profile expiry, while keeping the
    // original caller/Lease monotonic interval at sixty seconds. No terms are edited.
    let fixture = Fixture::with_profile_interval(5_000);
    let lease = &fixture.lease;
    let ceiling = lease.epoch.terms.signing_deadline_unix_ms;
    assert!(now_ms().unwrap() < ceiling);
    assert!(Instant::now() < fixture.deadline);
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let purpose = Purpose::FundingRequest(fixture.providers[0]);
    let deadline = fixture.deadline;
    std::thread::scope(|scope| {
        // Keep the gate local to this closure so a failed test handshake releases it
        // during unwinding before scoped joining. Both real acquisitions must contend.
        let held = lease.replacement_gate.write().unwrap();
        let reader_waiting_tx = waiting_tx.clone();
        let reader_result_tx = result_tx.clone();
        let reader = scope.spawn(move || {
            let _hook = HookGuard::contention(move || reader_waiting_tx.send("reader").unwrap());
            reader_result_tx
                .send(("reader", lease.check(deadline).map(|_| ())))
                .unwrap();
        });
        let writer = scope.spawn(move || {
            let _hook = HookGuard::contention(move || waiting_tx.send("writer").unwrap());
            result_tx
                .send(("writer", lease.claim(purpose, target(18), deadline)))
                .unwrap();
        });
        let mut waiting = [
            waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            waiting_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        ];
        waiting.sort_unstable();
        assert_eq!(waiting, ["reader", "writer"]);
        let mut returned = Vec::new();
        for _ in 0..2 {
            let (owner, result) = result_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(matches!(
                result,
                Err(crate::managed::Error::Bootstrap(
                    ManagedBootstrapFailure::AuthorizationExpired
                ))
            ));
            returned.push(owner);
        }
        returned.sort_unstable();
        assert_eq!(returned, ["reader", "writer"]);
        // These actual waiters stop at the issued UTC ceiling while their original
        // monotonic interval remains live and the exclusive gate is still held.
        assert!(now_ms().unwrap() >= ceiling);
        assert!(Instant::now() < deadline);
        assert!(fixture.claim().is_none());
        fixture.assert_original(false);
        reader.join().unwrap();
        writer.join().unwrap();
        drop(held);
    });
    for result in [
        lease.check(deadline).map(|_| ()),
        lease.claim(purpose, target(18), deadline),
    ] {
        assert!(matches!(
            result,
            Err(crate::managed::Error::Bootstrap(
                ManagedBootstrapFailure::AuthorizationExpired
            ))
        ));
    }
    assert!(fixture.claim().is_none());
    fixture.assert_original(false);
}
