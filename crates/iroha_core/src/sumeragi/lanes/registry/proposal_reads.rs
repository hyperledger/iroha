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
