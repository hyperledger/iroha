//! Proposal withdrawal preserves independent historical/native custody and exact original refunds.

use super::*;
use crate::sumeragi::lanes::{ProposalReadScope, proposal_reads::ReadInterest};
use iroha_data_model::{
    Level,
    account::AccountId,
    isi::Log,
    transaction::{FeePaymentIntent, TransactionBuilder},
};

fn transaction_fixture() -> Fixture {
    let key = KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519);
    let transaction = TransactionBuilder::new(
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"registry network",
        ))),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "original proposal read".into())])
    .sign(key.private_key());
    let fixture = Fixture::with_transactions(true, vec![transaction]);
    fixture.publish();
    fixture
}

fn refuse_batch(stores: &LaneStores, request: &ProposalReadScope) {
    let mut rows = Vec::<TransactionEntrypoint>::new();
    rows.try_reserve(1).unwrap();
    let layout = std::alloc::Layout::array::<TransactionEntrypoint>(rows.capacity()).unwrap();
    drop(rows);
    let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        stores.proposal_block(LANE, &INCARNATION, 1, request)
    });
    assert!(refused, "actual native batch destination is refused");
    assert!(matches!(result, Err(Attempt::Deferred(_))));
}

fn ready_identity(
    store: &FileLaneBlockStore,
    source: &AvailabilitySource,
    budget: &AllocationBudget,
) -> (*const u8, *const u8) {
    let slot = store.batch_read.lock();
    let original = &slot.as_ref().expect("original authenticated batch").read;
    assert_eq!(original.body.source(), source);
    assert!(original.body.admitted_to(budget));
    (
        original.body.payload().as_slice().as_ptr(),
        original.qc.signers.as_bytes().as_ptr(),
    )
}

#[test]
fn cancelled_proposal_releases_actual_ready_read_and_native_lock_without_another_driver_tick() {
    for authenticated_batch in [false, true] {
        let f = transaction_fixture();
        let budget = f.stores.budget.clone();
        let baseline = budget.reserved_bytes();
        let retired_baseline = baseline
            .checked_sub(crate::sumeragi::driver::PublicationSession::retained_bytes())
            .unwrap();
        let ceiling = budget.limit_bytes();
        let frame = fs::read(f.path()).unwrap();
        let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
        let weak = Arc::downgrade(&store);
        let mut request = ProposalReadScope::new();
        request.admit(&budget).unwrap();
        let interest = ReadInterest::proposal(&request, &budget).unwrap();
        assert_eq!(
            budget.reserved_bytes(),
            baseline + ProposalReadScope::admission_bytes()
        );
        let pressure = if authenticated_batch {
            refuse_batch(&f.stores, &request);
            let _ = ready_identity(&store, &f.source, &budget);
            None
        } else {
            let pressure = budget
                .try_reserve_bytes(ceiling - budget.reserved_bytes() - frame.len())
                .unwrap();
            assert!(matches!(
                f.stores.proposal_block(LANE, &INCARNATION, 1, &request),
                Err(Attempt::Deferred(_))
            ));
            assert_eq!(budget.reserved_bytes(), ceiling);
            assert!(store.batch_read.lock().is_none());
            Some(pressure)
        };
        drop(pressure);
        drop(store);
        drop(request);
        // This is the global Worker lifecycle hook, with no LaneRunner/Ready driver or successor.
        f.stores.release_cancelled_proposal_reads();
        f.stores.release(LANE, &INCARNATION);
        let released = weak.upgrade().is_none();
        let exact_refund =
            budget.reserved_bytes() == retired_baseline + ProposalReadScope::admission_bytes();
        let probe = FileLaneBlockStore::begin_open(
            f.stores.root(),
            &f.source.instance(),
            f.stores.crypto.clone(),
            budget.clone(),
            f.authorities.schedule.clone(),
        );
        let unlocked = probe.is_ok();
        drop(probe);
        // Mutation cleanup uses the retained observation only after preserving the causal verdict.
        interest.cancel_for_cleanup();
        f.stores.release_cancelled_proposal_reads();
        f.stores.release(LANE, &INCARNATION);
        drop(interest);
        assert_eq!(budget.reserved_bytes(), retired_baseline);
        assert_eq!(fs::read(f.path()).unwrap(), frame);
        let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(replay.block_hash, f.qc.block_hash);
        assert_eq!(replay.result, f.qc.result);
        assert!(replay.batch.is_some());
        drop((replay, f));
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            released && unlocked && exact_refund,
            "cancelled proposal reads must release original ready custody without successor traffic"
        );
    }
}

#[test]
fn historical_join_retains_exact_authenticated_body_after_proposal_cancellation() {
    let f = transaction_fixture();
    let budget = f.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    refuse_batch(&f.stores, &request);
    let identity = ready_identity(&store, &f.source, &budget);
    let original = budget.reserved_bytes();
    let result = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, 1 << 25, usize::MAX, 0, 32),
        || f.stores.block(LANE, &INCARNATION, 1),
    );
    assert!(matches!(result, Err(Attempt::Deferred(_))));
    assert_eq!(ready_identity(&store, &f.source, &budget), identity);
    // The actual historical join, rather than an Arc clone or a tip probe, promotes this slot.
    drop(request);
    f.stores.release_cancelled_proposal_reads();
    let retained = store.batch_read.lock().as_ref().map(|pending| {
        (
            pending.read.body.payload().as_slice().as_ptr(),
            pending.read.qc.signers.as_bytes().as_ptr(),
        )
    }) == Some(identity);
    let charged = budget.reserved_bytes() == original - ProposalReadScope::admission_bytes();
    // Complete the actual historical read before asserting the mutation verdict.
    let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(replay.block_hash, f.qc.block_hash);
    assert_eq!(replay.result, f.qc.result);
    assert!(replay.batch.is_some());
    drop(replay);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop((store, f));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        retained && charged,
        "historical joining must retain the exact original authenticated proposal read"
    );
}

#[test]
fn successor_proposal_cannot_consume_live_or_incompatible_original_read() {
    let f = transaction_fixture();
    let budget = f.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let mut original = ProposalReadScope::new();
    original.admit(&budget).unwrap();
    let mut successor = ProposalReadScope::new();
    successor.admit(&budget).unwrap();
    refuse_batch(&f.stores, &original);
    let identity = ready_identity(&store, &f.source, &budget);
    let charged = budget.reserved_bytes();
    let result = f.stores.proposal_block(LANE, &INCARNATION, 1, &successor);
    let live_refused = result
        .as_ref()
        .is_err_and(|error| error.io_kind() == io::ErrorKind::WouldBlock);
    let live_retained = store
        .batch_read
        .lock()
        .as_ref()
        .is_some_and(|pending| pending.read.body.payload().as_slice().as_ptr() == identity.0)
        && budget.reserved_bytes() == charged;
    drop(result);
    // Re-establish the same actual original refusal only for mutation cleanup/next cause.
    if store.batch_read.lock().is_none() {
        refuse_batch(&f.stores, &original);
    }
    drop(original);
    let result = f.stores.proposal_block(LANE, &INCARNATION, 2, &successor);
    let wrong_height_refused = result
        .as_ref()
        .is_err_and(|error| error.io_kind() == io::ErrorKind::WouldBlock);
    drop(result);
    // Compatible adoption must keep the actual original body/QC and schedule while refused.
    // The previous mismatched call's completion guard may have released the cancelled slot;
    // no different height may claim or return its bytes.
    let next = f
        .stores
        .proposal_block(LANE, &INCARNATION, 1, &successor)
        .unwrap()
        .unwrap();
    assert_eq!(next.block_hash, f.qc.block_hash);
    assert!(next.batch.is_some());
    drop((next, successor));
    f.stores.release_cancelled_proposal_reads();
    assert_eq!(budget.reserved_bytes(), baseline);
    drop((store, f));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        live_refused && live_retained && wrong_height_refused,
        "a successor proposal must not consume another live or incompatible original read"
    );
}

#[test]
fn compatible_cancelled_proposal_adoption_preserves_original_body_certificate_and_pool() {
    let f = transaction_fixture();
    let budget = f.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let store = f.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let mut original = ProposalReadScope::new();
    original.admit(&budget).unwrap();
    let mut successor = ProposalReadScope::new();
    successor.admit(&budget).unwrap();
    refuse_batch(&f.stores, &original);
    let identity = ready_identity(&store, &f.source, &budget);
    drop(original);
    let charged = budget.reserved_bytes();
    let result = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, 1 << 25, usize::MAX, 0, 32),
        || f.stores.proposal_block(LANE, &INCARNATION, 1, &successor),
    );
    assert!(matches!(result, Err(Attempt::Deferred(_))));
    assert_eq!(ready_identity(&store, &f.source, &budget), identity);
    assert_eq!(
        budget.reserved_bytes(),
        charged - ProposalReadScope::admission_bytes()
    );
    let foreign_budget = AllocationBudget::new(1 << 25);
    let mut foreign = ProposalReadScope::new();
    foreign.admit(&foreign_budget).unwrap();
    let before = budget.reserved_bytes();
    let refusal = f
        .stores
        .proposal_block(LANE, &INCARNATION, 1, &foreign)
        .unwrap_err();
    assert_eq!(refusal.io_kind(), io::ErrorKind::InvalidData);
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(ready_identity(&store, &f.source, &budget), identity);
    let completed = f
        .stores
        .proposal_block(LANE, &INCARNATION, 1, &successor)
        .unwrap()
        .unwrap();
    assert_eq!(completed.block_hash, f.qc.block_hash);
    assert!(completed.batch.is_some());
    drop((completed, successor, foreign));
    f.stores.release_cancelled_proposal_reads();
    assert_eq!(foreign_budget.reserved_bytes(), 0);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop((store, f));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cancelled_incoming_read_retires_request_only_opening_and_preserves_historical_join() {
    for historical in [false, true] {
        let f = transaction_fixture();
        let budget = f.stores.budget.clone();
        f.stores.release(LANE, &INCARNATION);
        let baseline = budget.reserved_bytes();
        let frame = fs::read(f.path()).unwrap();
        let ceiling = budget.limit_bytes();
        let mut request = ProposalReadScope::new();
        request.admit(&budget).unwrap();
        let pressure = budget
            .try_reserve_bytes(ceiling - budget.reserved_bytes() - frame.len())
            .unwrap();
        assert!(matches!(
            f.stores
                .execution_wait_for(LANE, &INCARNATION, 1, Duration::ZERO, &request),
            Err(Attempt::Deferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), ceiling);
        let opening = {
            let map = f.stores.stores.lock();
            let Some(StoreSlot::Opening(original, owners)) = map.get(&(LANE, INCARNATION)) else {
                panic!("the request retains actual unfinished native recovery");
            };
            assert!(!owners.runtime && !owners.historical);
            Arc::downgrade(original)
        };
        if historical {
            assert!(matches!(
                f.stores.store(LANE, &INCARNATION),
                Err(Attempt::Deferred(_))
            ));
        }
        drop(request);
        f.stores.release_cancelled_proposal_reads();
        let retained = opening.upgrade().is_some();
        drop(pressure);
        if historical {
            assert!(retained);
            assert_eq!(budget.reserved_bytes(), baseline + frame.len());
        } else {
            assert!(!retained);
            assert_eq!(budget.reserved_bytes(), baseline);
        }
        assert_eq!(fs::read(f.path()).unwrap(), frame);
        let replay = f.stores.block(LANE, &INCARNATION, 1).unwrap().unwrap();
        assert_eq!(replay.block_hash, f.qc.block_hash);
        assert_eq!(replay.result, f.qc.result);
        drop((replay, f));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

struct PausedFrameSchedule {
    original: Arc<dyn AvailabilitySchedule>,
    entered: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    resume: Mutex<std::sync::mpsc::Receiver<()>>,
    resumed: AtomicBool,
}
impl AvailabilitySchedule for PausedFrameSchedule {
    fn instance(&self) -> Hash32 {
        self.original.instance()
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        let entered = self.entered.lock().take();
        if let Some(entered) = entered {
            entered.send(()).map_err(io::Error::other)?;
            let resumed = self
                .resume
                .lock()
                .recv_timeout(Duration::from_secs(5))
                .is_ok();
            self.resumed.store(resumed, Ordering::SeqCst);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "original historical frame authority paused",
            )
            .into());
        }
        self.original.height_config(height)
    }
}
struct PausedFrameAuthorities(Arc<PausedFrameSchedule>);
impl LaneStoreAuthorities for PausedFrameAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        assert_eq!(
            (lane, *incarnation, instance),
            (LANE, INCARNATION, self.0.instance())
        );
        Ok(Some(LaneStoreAuthority {
            schedule: self.0.clone(),
        }))
    }
}

#[test]
fn cancelled_read_only_incoming_frame_is_released_when_original_inflight_owner_parks() {
    let f = transaction_fixture();
    let budget = f.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let frame = fs::read(f.path()).unwrap();
    let (entered, acquired) = std::sync::mpsc::sync_channel(1);
    let (resume, resumed) = std::sync::mpsc::sync_channel(1);
    let schedule = Arc::new(PausedFrameSchedule {
        original: f.authorities.schedule.clone(),
        entered: Mutex::new(Some(entered)),
        resume: Mutex::new(resumed),
        resumed: AtomicBool::new(false),
    });
    let reader = LaneFrameSource::new(
        f.dir.path().to_path_buf(),
        f.stores.network,
        f.stores.chain_id.clone(),
        f.stores.crypto.clone(),
        budget.clone(),
        Arc::new(PausedFrameAuthorities(schedule.clone())),
    );
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    let pressure = budget
        .try_reserve_bytes(ceiling - budget.reserved_bytes() - frame.len())
        .unwrap();
    assert!(matches!(
        reader.execution_block(LANE, &INCARNATION, 1, &request),
        Err(Attempt::Deferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), ceiling);
    drop(pressure);
    let (entered, cancellation_returned, result) = std::thread::scope(|threads| {
        // A historical request at another height first authenticates the original
        // pending frame; it does not promote that different-height proposal interest.
        // This real public call borrows no proposal scope, so concurrent Drop is reachable.
        let reading = threads.spawn(|| reader.block(LANE, &INCARNATION, 2));
        let entered = acquired.recv_timeout(Duration::from_secs(5)).is_ok();
        let (done, completed) = std::sync::mpsc::sync_channel(1);
        let source = &reader;
        let cancelling = threads.spawn(move || {
            drop(request);
            source.release_cancelled_proposal_reads();
            let _ = done.send(());
        });
        let returned = completed.recv_timeout(Duration::from_secs(5)).is_ok();
        let _ = resume.send(());
        let result = reading.join().unwrap();
        cancelling.join().unwrap();
        (entered, returned, result)
    });
    assert!(entered && cancellation_returned && schedule.resumed.load(Ordering::SeqCst));
    assert!(
        matches!(result, Err(ref error) if error.to_string().contains("original historical frame authority paused"))
    );
    drop(result);
    let released = budget.reserved_bytes() == baseline;
    // Record the owner-boundary result before diagnostic cleanup or later traffic.
    reader.release_cancelled_proposal_reads();
    assert_eq!(budget.reserved_bytes(), baseline);
    let replay = reader.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(replay.block_hash, f.qc.block_hash);
    assert_eq!(replay.result, f.qc.result);
    assert_eq!(fs::read(f.path()).unwrap(), frame);
    drop((replay, reader, schedule, f));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        released,
        "cancelled incoming read-only custody must retire when the original in-flight owner parks"
    );
}

// Pause only an existing physical boundary; the registry operation remains the production API.
struct SweepBoundary {
    armed: AtomicBool,
    entered: Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
    resumed: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl SweepBoundary {
    fn pause(&self) -> io::Result<()> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(entered) = self.entered.lock().take() {
            entered.send(()).map_err(io::Error::other)?;
        }
        self.resumed
            .lock()
            .recv_timeout(Duration::from_secs(30))
            .map_err(io::Error::other)
    }
}
impl crate::sumeragi::records::Faults for SweepBoundary {
    fn before(&self, step: crate::sumeragi::records::FsStep, _: &Path) -> io::Result<()> {
        if step == crate::sumeragi::records::FsStep::CreateDir {
            self.pause()?;
        }
        Ok(())
    }
}
fn sweep_boundary() -> (
    Arc<SweepBoundary>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    let (entered, received) = std::sync::mpsc::sync_channel(1);
    let (resume, resumed) = std::sync::mpsc::sync_channel(1);
    (
        Arc::new(SweepBoundary {
            armed: AtomicBool::new(false),
            entered: Mutex::new(Some(entered)),
            resumed: Mutex::new(resumed),
        }),
        received,
        resume,
    )
}
struct SweepRetiringSchedule {
    original: Arc<Schedule>,
    boundary: Arc<SweepBoundary>,
}
impl AvailabilitySchedule for SweepRetiringSchedule {
    fn instance(&self) -> Hash32 {
        self.original.instance()
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        self.original.height_config(height)
    }
}
impl Drop for SweepRetiringSchedule {
    fn drop(&mut self) {
        // A failed control must still let the genuine native callers join for diagnostic cleanup.
        let _ = self.boundary.pause();
    }
}
struct SweepAuthorities {
    original: Arc<Authorities>,
    before: (LaneId, [u8; 32], Arc<Schedule>),
    inserted: (LaneId, [u8; 32], Arc<Schedule>),
    boundary: Arc<SweepBoundary>,
}
impl LaneStoreAuthorities for SweepAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        if (lane, *incarnation) == (self.before.0, self.before.1) {
            assert_eq!(instance, self.before.2.instance);
            return Ok(Some(LaneStoreAuthority {
                schedule: Arc::new(SweepRetiringSchedule {
                    original: Arc::clone(&self.before.2),
                    boundary: Arc::clone(&self.boundary),
                }),
            }));
        }
        if (lane, *incarnation) == (self.inserted.0, self.inserted.1) {
            assert_eq!(instance, self.inserted.2.instance);
            return Ok(Some(LaneStoreAuthority {
                schedule: self.inserted.2.clone(),
            }));
        }
        self.original.authority(lane, incarnation, instance)
    }
}

#[test]
fn cancelled_original_sweep_does_not_wait_for_new_disjoint_opening() {
    let mut fixture = transaction_fixture();
    let budget = fixture.stores.budget.clone();
    let frame = fs::read(fixture.path()).unwrap();
    let before = (LaneId::new(1), [0x11; 32]);
    let inserted = (LaneId::new(1), [0x22; 32]);
    assert!(before < inserted && inserted < (LANE, INCARNATION));
    let (retiring, retired_entered, resume_retirement) = sweep_boundary();
    let (opening, opening_entered, resume_opening) = sweep_boundary();
    let before_schedule = Arc::new(Schedule {
        instance: fixture.stores.instance(before.0, &before.1),
        config: fixture.source.config().clone(),
    });
    let inserted_schedule = Arc::new(Schedule {
        instance: fixture.stores.instance(inserted.0, &inserted.1),
        config: fixture.source.config().clone(),
    });
    fixture.stores.opening_faults = Some((inserted_schedule.instance, opening.clone()));
    fixture.stores.authorities = Arc::new(SweepAuthorities {
        original: fixture.authorities.clone(),
        before: (before.0, before.1, before_schedule),
        inserted: (inserted.0, inserted.1, inserted_schedule),
        boundary: retiring.clone(),
    });
    // Initial registry membership is A<C. A is an idle actual native owner; C retains the
    // original incoming frame. No synthetic StoreSlot or copied cancellation interest is used.
    drop(fixture.stores.runtime_store(before.0, &before.1).unwrap());
    let baseline = budget.reserved_bytes();
    let store = fixture.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let original = Arc::downgrade(&store);
    let mut request = ProposalReadScope::new();
    request.admit(&budget).unwrap();
    let mut rows = Vec::<TransactionEntrypoint>::new();
    rows.try_reserve(1).unwrap();
    let layout = std::alloc::Layout::array::<TransactionEntrypoint>(rows.capacity()).unwrap();
    drop(rows);
    let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, || {
        fixture
            .stores
            .execution_block(LANE, &INCARNATION, 1, &request)
    });
    assert!(refused);
    assert!(matches!(result, Err(Attempt::Deferred(_))));
    assert!(store.has_pending_work_for_test());
    assert!(budget.reserved_bytes() > baseline);
    assert_eq!(fixture.stores.stores.lock().len(), 2);
    drop((store, request));
    retiring.armed.store(true, Ordering::SeqCst);
    opening.armed.store(true, Ordering::SeqCst);
    let (retired_entered, opened, unlocked, registered, released, exact_refund, native_unlocked) =
        std::thread::scope(|threads| {
            let stores = &fixture.stores;
            let cleanup = threads.spawn(|| stores.release_cancelled_proposal_reads());
            let retired_entered = retired_entered.recv_timeout(Duration::from_secs(5)).is_ok();
            let unlocked = stores.stores.try_lock().is_some();
            let new_runtime = threads.spawn(|| stores.runtime_store(inserted.0, &inserted.1));
            let opened = opening_entered.recv_timeout(Duration::from_secs(5)).is_ok();
            let registered = stores
                .stores
                .try_lock()
                .is_some_and(|map| matches!(map.get(&inserted), Some(StoreSlot::Opening(_, _))));
            let _ = resume_retirement.send(());
            cleanup.join().unwrap();
            // Observe the actual Worker cleanup return while the unrelated B remains in
            // physical CreateDir. No later reconciliation, new request or B completion helped C.
            let released = original.upgrade().is_none();
            let exact_refund = budget.reserved_bytes()
                == baseline - crate::sumeragi::driver::PublicationSession::retained_bytes();
            let probe = FileLaneBlockStore::begin_open(
                stores.root(),
                &fixture.source.instance(),
                stores.crypto.clone(),
                budget.clone(),
                fixture.authorities.schedule.clone(),
            );
            let native_unlocked = probe.is_ok();
            drop(probe);
            // Only after capturing the causal verdict may B finish its genuine operation.
            let _ = resume_opening.send(());
            drop(new_runtime.join().unwrap().unwrap());
            (
                retired_entered,
                opened,
                unlocked,
                registered,
                released,
                exact_refund,
                native_unlocked,
            )
        });
    fixture.stores.release_cancelled_proposal_reads();
    fixture.stores.release(inserted.0, &inserted.1);
    fixture.stores.release(LANE, &INCARNATION);
    assert_eq!(fs::read(fixture.path()).unwrap(), frame);
    let replay = fixture
        .stores
        .block(LANE, &INCARNATION, 1)
        .unwrap()
        .unwrap();
    assert_eq!(replay.block_hash, fixture.qc.block_hash);
    assert_eq!(replay.result, fixture.qc.result);
    assert!(replay.batch.is_some());
    drop((replay, fixture));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(retired_entered && opened && unlocked && registered);
    assert!(
        released && exact_refund && native_unlocked,
        "original cancelled lane cleanup cannot wait for an unrelated newly registered opening"
    );
}

#[test]
fn original_sweep_preserves_a_later_same_key_native_owner() {
    let mut fixture = transaction_fixture();
    let budget = fixture.stores.budget.clone();
    let frame = fs::read(fixture.path()).unwrap();
    let before = (LaneId::new(1), [0x11; 32]);
    let (retiring, retired_entered, resume_retirement) = sweep_boundary();
    let before_schedule = Arc::new(Schedule {
        instance: fixture.stores.instance(before.0, &before.1),
        config: fixture.source.config().clone(),
    });
    fixture.stores.authorities = Arc::new(SweepAuthorities {
        original: fixture.authorities.clone(),
        before: (before.0, before.1, before_schedule.clone()),
        // This control opens only A and the independently authenticated original C.
        inserted: (before.0, before.1, before_schedule),
        boundary: retiring.clone(),
    });
    drop(fixture.stores.runtime_store(before.0, &before.1).unwrap());
    let original = Arc::downgrade(&fixture.stores.runtime_store(LANE, &INCARNATION).unwrap());
    assert_eq!(fixture.stores.stores.lock().len(), 2);
    retiring.armed.store(true, Ordering::SeqCst);
    let (entered, unlocked, original_retired, replacement_retained) =
        std::thread::scope(|threads| {
            let stores = &fixture.stores;
            let cleanup = threads.spawn(|| stores.release_cancelled_proposal_reads());
            let entered = retired_entered.recv_timeout(Duration::from_secs(5)).is_ok();
            let unlocked = stores.stores.try_lock().is_some();
            stores.release(LANE, &INCARNATION);
            let original_retired = original.upgrade().is_none();
            let replacement = stores.runtime_store(LANE, &INCARNATION).unwrap();
            assert_eq!(replacement.height(), 1);
            let replacement_identity = Arc::downgrade(&replacement);
            drop(replacement);
            let _ = resume_retirement.send(());
            cleanup.join().unwrap();
            let replacement_retained = replacement_identity.upgrade().is_some();
            (entered, unlocked, original_retired, replacement_retained)
        });
    assert_eq!(fs::read(fixture.path()).unwrap(), frame);
    let replay = fixture
        .stores
        .block(LANE, &INCARNATION, 1)
        .unwrap()
        .unwrap();
    assert_eq!(replay.block_hash, fixture.qc.block_hash);
    assert_eq!(replay.result, fixture.qc.result);
    drop((replay, fixture));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(entered && unlocked && original_retired);
    assert!(
        replacement_retained,
        "an original lane sweep cannot retire a later same-key registration"
    );
}

#[test]
fn exhausted_registration_identity_refuses_before_new_native_custody() {
    let mut fixture = transaction_fixture();
    let budget = fixture.stores.budget.clone();
    let other = (LaneId::new(3), [0x66; 32]);
    let other_schedule = Arc::new(Schedule {
        instance: fixture.stores.instance(other.0, &other.1),
        config: fixture.source.config().clone(),
    });
    fixture.stores.authorities = Arc::new(DisjointAuthorities {
        first: fixture.authorities.clone(),
        other_lane: other.0,
        other_incarnation: other.1,
        other: other_schedule.clone(),
    });
    let original = fixture.stores.runtime_store(LANE, &INCARNATION).unwrap();
    let baseline = budget.reserved_bytes();
    let frame = fs::read(fixture.path()).unwrap();
    fixture
        .stores
        .registrations
        .store(u64::MAX, Ordering::Relaxed);
    let error = fixture.stores.runtime_store(other.0, &other.1).unwrap_err();
    assert_eq!(error.io_kind(), io::ErrorKind::Other);
    assert!(
        error
            .to_string()
            .contains("original lane registration identity exhausted")
    );
    assert!(
        !fixture
            .stores
            .root()
            .join(hex::encode(other_schedule.instance.0))
            .exists()
    );
    assert_eq!(fixture.stores.stores.lock().len(), 1);
    assert_eq!(
        fixture.stores.registrations.load(Ordering::Relaxed),
        u64::MAX
    );
    assert!(Arc::ptr_eq(
        &original,
        &fixture.stores.runtime_store(LANE, &INCARNATION).unwrap()
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), frame);
    drop((error, original, fixture));
    assert_eq!(budget.reserved_bytes(), 0);
}
