//! Native append admission, exact joining owner and terminal ownership controls.

use super::*;
use crate::sumeragi::{driver::PublicationSession, lanes::record::tests::fixture};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ObserveNative(AtomicUsize);
impl Faults for ObserveNative {
    fn before(&self, _: crate::sumeragi::records::FsStep, _: &Path) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn unbound_store(
    root: &Path,
    source: &AvailabilitySource,
    crypto: SharedCrypto,
    budget: &AllocationBudget,
    faults: Arc<dyn Faults>,
) -> Arc<FileLaneBlockStore> {
    Arc::new(
        FileLaneBlockStore::begin_open_with_faults(
            root,
            &source.instance(),
            crypto,
            budget.clone(),
            super::tests::schedule(source),
            faults,
        )
        .unwrap()
        .complete()
        .unwrap_or_else(|(_, error)| panic!("original native opening: {error}")),
    )
}

#[test]
fn native_append_without_original_joiner_refuses_before_any_write_or_tip_change() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let faults = Arc::new(ObserveNative(AtomicUsize::new(0)));
    let store = unbound_store(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        faults.clone(),
    );
    let calls = faults.0.load(Ordering::SeqCst);
    let charged = budget.reserved_bytes();
    let result = store.append(&body, &qc);
    let refused = result
        .as_ref()
        .is_err_and(|error| error.io_kind() == io::ErrorKind::InvalidData);
    let unchanged = faults.0.load(Ordering::SeqCst) == calls
        && store.height() == 0
        && store.state.lock().write.is_none()
        && store.state.lock().read.is_none()
        && !store.dir.join(frame_name(1)).exists()
        && budget.reserved_bytes() == charged;
    drop((result, store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        refused && unchanged,
        "ownerless append must refuse before any native write, retained write or tip mutation"
    );
}

#[test]
fn native_owner_binding_refuses_repeated_concurrent_and_foreign_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = unbound_store(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let publication = PublicationSession::start(store.clone(), &budget);
    let original = store.publication_owner.get().unwrap().clone();
    let exact = budget.reserved_bytes();
    let foreign = AllocationBudget::new(budget.limit_bytes());
    let foreign_result = PublicationSession::try_start(store.clone(), &foreign);
    assert!(matches!(
        foreign_result,
        Err(crate::sumeragi::driver::DriverError::RetirementIdentity)
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    let repeated = PublicationSession::try_start(store.clone(), &budget);
    let refused = matches!(&repeated, Err(crate::sumeragi::driver::DriverError::RetirementBinding(error))
        if error.kind() == io::ErrorKind::InvalidData && error.to_string() == "original publication owner is already bound");
    drop(repeated);
    // Both contenders start together while the exact original owner remains live.
    // Every attempted joiner closes naturally before any verdict is asserted.
    let barrier = std::sync::Barrier::new(3);
    let concurrent_refused = std::thread::scope(|scope| {
        let attempt = || {
            barrier.wait();
            let result = PublicationSession::try_start(store.clone(), &budget);
            let refused = matches!(&result,
                Err(crate::sumeragi::driver::DriverError::RetirementBinding(error))
                if error.kind() == io::ErrorKind::InvalidData
                    && error.to_string() == "original publication owner is already bound");
            drop(result);
            refused
        };
        let first = scope.spawn(attempt);
        let second = scope.spawn(attempt);
        barrier.wait();
        let first = first.join();
        let second = second.join();
        first.unwrap() && second.unwrap()
    });
    let wrong_thread =
        <FileLaneBlockStore as crate::sumeragi::driver::traits::RetiredPublication>::bind_owner(
            &store,
            original.clone(),
        );
    let wrong_thread_refused = wrong_thread.is_err();
    drop(wrong_thread);
    assert!(store.publication_owner.get().unwrap().same_owner(&original));
    assert_eq!(budget.reserved_bytes(), exact);
    store.append(&body, &qc).unwrap();
    assert_eq!(store.entry(1).unwrap().unwrap().commit_qc, qc);
    drop(publication);
    let stopped_charge = budget.reserved_bytes();
    let stale = PublicationSession::try_start(store.clone(), &budget);
    let stale_refused = matches!(&stale,
        Err(crate::sumeragi::driver::DriverError::RetirementBinding(error))
        if error.kind() == io::ErrorKind::InvalidData
            && error.to_string() == "original publication owner is already bound");
    drop(stale);
    assert_eq!(budget.reserved_bytes(), stopped_charge);
    assert!(store.publication_owner.get().unwrap().same_owner(&original));
    drop(original);
    drop((store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        refused && concurrent_refused && wrong_thread_refused && stale_refused,
        "a second original joining owner must fail before replacing or acknowledging a bound store"
    );
}

#[test]
fn stopped_original_owner_refuses_append_and_stays_bound_until_final_store_release() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let faults = Arc::new(ObserveNative(AtomicUsize::new(0)));
    let store = unbound_store(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        faults.clone(),
    );
    let initial = budget.reserved_bytes();
    let publication = PublicationSession::start(store.clone(), &budget);
    assert_eq!(
        budget.reserved_bytes(),
        initial + PublicationSession::admitted_bytes()
    );
    drop(publication);
    assert_eq!(
        budget.reserved_bytes(),
        initial + PublicationSession::retained_bytes()
    );
    let calls = faults.0.load(Ordering::SeqCst);
    let result = store.append(&body, &qc);
    let refused = result.is_err()
        && faults.0.load(Ordering::SeqCst) == calls
        && store.height() == 0
        && store.state.lock().write.is_none();
    drop(result);
    drop((store, body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        refused,
        "a stopped original publication owner must never admit another append"
    );
}

#[test]
fn certified_fixture_publication_owns_original_joiner_and_refunds_exact_pool() {
    let dir = tempfile::tempdir().unwrap();
    let (body, qc, source, budget, crypto) = fixture(1025);
    let store = unbound_store(
        dir.path(),
        &source,
        Arc::new(crypto),
        &budget,
        Arc::new(NoFaults),
    );
    let original = budget.reserved_bytes();
    let publication =
        crate::sumeragi::test_chain::NativeLanePublication::start(store.clone(), &budget).unwrap();
    assert_eq!(
        budget.reserved_bytes(),
        original + PublicationSession::admitted_bytes()
    );
    store.append(&body, &qc).unwrap();
    // A repeated append still belongs to the first bound joining owner.
    store.append(&body, &qc).unwrap();
    let (restored, certificate) = store.committed_body(1).unwrap().unwrap();
    assert_eq!(restored, body);
    assert_eq!(certificate, qc);
    assert!(restored.admitted_to(&budget));
    drop((restored, certificate));
    drop(publication);
    assert_eq!(Arc::strong_count(&store), 1);
    assert_eq!(
        budget.reserved_bytes(),
        original + PublicationSession::retained_bytes()
    );
    let refused = store.append(&body, &qc).unwrap_err();
    assert_eq!(refused.io_kind(), io::ErrorKind::InvalidData);
    assert_eq!(store.height(), 1);
    drop((refused, store));
    assert_eq!(budget.reserved_bytes(), original);
    drop((body, qc));
    assert_eq!(budget.reserved_bytes(), 0);
}
