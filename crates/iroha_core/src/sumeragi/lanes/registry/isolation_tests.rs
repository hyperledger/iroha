//! Actual recovery I/O must not hold unrelated retained lane owners hostage.

use super::*;
use crate::sumeragi::records::{Faults, FsStep};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

const RECOVERY_REFUSAL: &str = "original lane recovery sync refused";

struct PausedOriginalRecovery {
    entered: Mutex<Option<SyncSender<()>>>,
    resume: Mutex<Receiver<()>>,
    refuse: bool,
}

impl Faults for PausedOriginalRecovery {
    fn before(&self, step: FsStep, _: &Path) -> io::Result<()> {
        if step != FsStep::SyncFile {
            return Ok(());
        }
        let Some(entered) = self.entered.lock().take() else {
            return Ok(());
        };
        entered.send(()).map_err(io::Error::other)?;
        // This is only a bounded harness-cleanup guard, not a liveness success threshold.
        self.resume
            .lock()
            .recv_timeout(Duration::from_secs(30))
            .map_err(io::Error::other)?;
        if self.refuse {
            return Err(io::Error::other(RECOVERY_REFUSAL));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum OriginalRecoveryControl {
    Complete,
    Historical { retire_first: bool },
    RuntimeCancellation,
}

fn retain_original_opening(
    stores: &LaneStores,
    opening: LaneStoreOpen,
    schedule: Arc<dyn AvailabilitySchedule>,
) {
    let retained = StoreOpening::new(stores.instance(LANE, &INCARNATION), schedule);
    *retained.progress.lock() = OpeningProgress::Pending(Some(opening));
    let mut original_map = stores.stores.lock();
    let registration = stores.next_registration(&mut original_map).unwrap();
    assert!(
        original_map
            .insert(
                (LANE, INCARNATION),
                StoreSlot::Opening(
                    retained,
                    OpeningOwners::new(StoreDemand::Runtime, registration)
                )
            )
            .is_none()
    );
}

struct RecoveryObservation {
    disjoint: Result<Arc<FileLaneBlockStore>, Attempt<io::Error>>,
    same_key: Result<Arc<FileLaneBlockStore>, Attempt<io::Error>>,
    historical: Option<Result<Arc<FileLaneBlockStore>, Attempt<io::Error>>>,
    independent_lock_refused: bool,
    bytes_before: usize,
    bytes_after: usize,
}

fn original_recovery_control(control: OriginalRecoveryControl) {
    let mut fixture = Fixture::new(true);
    let other_lane = LaneId::new(3);
    let other_incarnation = [0x46; 32];
    fixture.stores.authorities = Arc::new(DisjointAuthorities {
        first: fixture.authorities.clone(),
        other_lane,
        other_incarnation,
        other: Arc::new(Schedule {
            instance: fixture.stores.instance(other_lane, &other_incarnation),
            config: fixture.source.config().clone(),
        }),
    });
    fixture.publish();
    let disjoint = fixture
        .stores
        .store(other_lane, &other_incarnation)
        .unwrap();
    assert_eq!(disjoint.height(), 0);
    let original_bytes = fs::read(fixture.path()).unwrap();
    fixture.stores.release(LANE, &INCARNATION);
    let baseline = fixture.stores.budget.reserved_bytes();
    let ceiling = fixture.stores.budget.limit_bytes();
    let authority_calls = fixture.authorities.calls.load(Ordering::SeqCst);
    let (entered, acquired) = sync_channel(1);
    let (resume, resumed) = sync_channel(1);
    let opening = FileLaneBlockStore::begin_open_with_faults(
        fixture.dir.path(),
        &fixture.source.instance(),
        fixture.stores.crypto.clone(),
        fixture.stores.budget.clone(),
        fixture.authorities.schedule.clone(),
        Arc::new(PausedOriginalRecovery {
            entered: Mutex::new(Some(entered)),
            resume: Mutex::new(resumed),
            refuse: !matches!(control, OriginalRecoveryControl::Complete),
        }),
    )
    .unwrap();
    retain_original_opening(
        &fixture.stores,
        opening,
        fixture.authorities.schedule.clone(),
    );
    let (event, observation, result) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| fixture.stores.runtime_store(LANE, &INCARNATION));
        let event = acquired.recv_timeout(Duration::from_secs(30));
        let map_free = event.is_ok() && fixture.stores.stores.try_lock().is_some();
        // The nonblocking probe makes the old defect fail at our causal assertion,
        // rather than hanging the harness trying to enter the known-held map.
        let observation = map_free.then(|| {
            let bytes_before = fixture.stores.budget.reserved_bytes();
            let disjoint = fixture.stores.store(other_lane, &other_incarnation);
            let same_key = fixture.stores.runtime_store(LANE, &INCARNATION);
            let historical = if let OriginalRecoveryControl::Historical { retire_first } = control {
                if retire_first {
                    fixture
                        .stores
                        .release_retired(&SumeragiLaneState::default());
                }
                let joined = fixture.stores.store(LANE, &INCARNATION);
                fixture
                    .stores
                    .release_retired(&SumeragiLaneState::default());
                Some(joined)
            } else {
                if matches!(control, OriginalRecoveryControl::RuntimeCancellation) {
                    fixture
                        .stores
                        .release_retired(&SumeragiLaneState::default());
                }
                None
            };
            let independent_lock_refused = FileLaneBlockStore::begin_open(
                fixture.dir.path(),
                &fixture.source.instance(),
                fixture.stores.crypto.clone(),
                fixture.stores.budget.clone(),
                fixture.authorities.schedule.clone(),
            )
            .is_err();
            RecoveryObservation {
                disjoint,
                same_key,
                historical,
                independent_lock_refused,
                bytes_before,
                bytes_after: fixture.stores.budget.reserved_bytes(),
            }
        });
        // Always release/join the genuine owner before reporting any causal failure.
        let _ = resume.send(());
        (event, observation, worker.join())
    });
    event.expect("actual signed recovery reaches its original SyncFile boundary");
    let result = result.expect("original recovery worker closes naturally");
    assert!(
        observation.is_some(),
        "original lane recovery must release the shared registry before native I/O"
    );
    let observation = observation.unwrap();
    assert!(Arc::ptr_eq(&disjoint, &observation.disjoint.unwrap()));
    let same_key = observation.same_key.unwrap_err();
    assert_eq!(same_key.io_kind(), io::ErrorKind::WouldBlock);
    assert_eq!(same_key.to_string(), "original lane recovery is busy");
    assert!(observation.independent_lock_refused);
    assert!(observation.bytes_before > baseline);
    assert_eq!(observation.bytes_before, observation.bytes_after);
    assert_eq!(
        fixture.authorities.calls.load(Ordering::SeqCst),
        authority_calls
    );
    assert_eq!(fs::read(fixture.path()).unwrap(), original_bytes);
    match control {
        OriginalRecoveryControl::Complete => {
            let original = result.unwrap();
            assert_eq!(original.height(), 1);
            assert!(Arc::ptr_eq(
                &original,
                &fixture.stores.store(LANE, &INCARNATION).unwrap()
            ));
            assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
            drop(original);
            fixture.stores.release(LANE, &INCARNATION);
        }
        OriginalRecoveryControl::Historical { .. } => {
            let joined = observation.historical.unwrap().unwrap_err();
            assert_eq!(joined.io_kind(), io::ErrorKind::WouldBlock);
            assert_eq!(joined.to_string(), "original lane recovery is busy");
            let error = result.unwrap_err();
            assert_eq!(error.io_kind(), io::ErrorKind::Other);
            assert_eq!(error.to_string(), RECOVERY_REFUSAL);
            assert!(matches!(
                fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
                Some(StoreSlot::Opening(_, owners)) if owners.historical
            ));
            let retained = fixture.stores.budget.reserved_bytes();
            assert_eq!(retained, observation.bytes_before);
            fixture
                .stores
                .release_retired(&SumeragiLaneState::default());
            assert_eq!(fixture.stores.budget.reserved_bytes(), retained);
            // The exact already-prepared original retries with no spare pool capacity.
            fixture.stores.budget.set_limit_bytes(retained);
            let original = fixture.stores.store(LANE, &INCARNATION).unwrap();
            assert_eq!(original.height(), 1);
            assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
            fixture.stores.budget.set_limit_bytes(ceiling);
            drop(original);
            fixture.stores.release(LANE, &INCARNATION);
        }
        OriginalRecoveryControl::RuntimeCancellation => {
            let error = result.unwrap_err();
            assert_eq!(error.io_kind(), io::ErrorKind::Other);
            assert_eq!(error.to_string(), RECOVERY_REFUSAL);
            assert!(matches!(
                fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
                Some(StoreSlot::Opening(_, owners)) if !owners.historical
            ));
            assert_eq!(
                fixture.stores.budget.reserved_bytes(),
                observation.bytes_before
            );
            fixture
                .stores
                .release_retired(&SumeragiLaneState::default());
            assert!(
                !fixture
                    .stores
                    .stores
                    .lock()
                    .contains_key(&(LANE, INCARNATION))
            );
            assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
            let original = fixture.stores.store(LANE, &INCARNATION).unwrap();
            assert_eq!(original.height(), 1);
            drop(original);
            fixture.stores.release(LANE, &INCARNATION);
        }
    }
    assert_eq!(fixture.stores.budget.limit_bytes(), ceiling);
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), original_bytes);
    assert!(Arc::ptr_eq(
        &disjoint,
        &fixture
            .stores
            .store(other_lane, &other_incarnation)
            .unwrap()
    ));
}

#[test]
fn original_lane_recovery_allows_ready_disjoint_owner_during_native_sync() {
    original_recovery_control(OriginalRecoveryControl::Complete);
}

#[test]
fn original_lane_recovery_retains_in_flight_historical_join_through_retirement() {
    for retire_first in [false, true] {
        original_recovery_control(OriginalRecoveryControl::Historical { retire_first });
    }
}

#[test]
fn original_lane_recovery_runtime_refusal_cancels_only_after_active_owner_returns() {
    original_recovery_control(OriginalRecoveryControl::RuntimeCancellation);
}

#[test]
fn original_lane_opening_cloned_before_completion_joins_the_same_ready_store() {
    let fixture = Fixture::new(true);
    fixture.publish();
    let original_bytes = fs::read(fixture.path()).unwrap();
    fixture.stores.release(LANE, &INCARNATION);
    let baseline = fixture.stores.budget.reserved_bytes();
    let ceiling = fixture.stores.budget.limit_bytes();
    fixture
        .stores
        .budget
        .set_limit_bytes(baseline + original_bytes.len());
    let error = fixture
        .stores
        .runtime_store(LANE, &INCARNATION)
        .unwrap_err();
    assert!(matches!(error, Attempt::Deferred(_)));
    assert_eq!(
        fixture.stores.budget.reserved_bytes(),
        baseline + original_bytes.len()
    );
    let key = (LANE, INCARNATION);
    let (earlier_join, original_registration) = {
        let stores = fixture.stores.stores.lock();
        let Some(StoreSlot::Opening(original, owners)) = stores.get(&key) else {
            panic!("original runtime recovery remains retained");
        };
        assert!(!owners.historical && owners.runtime);
        (Arc::clone(original), owners.registration)
    };
    let authority_calls = fixture.authorities.calls.load(Ordering::SeqCst);
    fixture.stores.budget.set_limit_bytes(ceiling);
    let completed = fixture.stores.runtime_store(LANE, &INCARNATION).unwrap();
    assert_eq!(
        fixture
            .stores
            .stores
            .lock()
            .get(&key)
            .unwrap()
            .registration(),
        original_registration
    );
    let original = Arc::downgrade(&completed);
    assert_eq!(completed.height(), 1);
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    drop(completed);
    fixture
        .stores
        .release_retired(&SumeragiLaneState::default());
    let pinned = original
        .upgrade()
        .expect("the earlier join retains the completed native owner");
    let joined = fixture
        .stores
        .with_original_refunds(|| {
            fixture
                .stores
                .complete_store_opening(key, Arc::clone(&earlier_join))
        })
        .unwrap();
    assert!(Arc::ptr_eq(&pinned, &joined));
    assert!(Arc::ptr_eq(
        &joined,
        &fixture.stores.store(LANE, &INCARNATION).unwrap()
    ));
    assert_eq!(
        fixture.authorities.calls.load(Ordering::SeqCst),
        authority_calls
    );
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), original_bytes);
    drop((pinned, joined, earlier_join));
    fixture.stores.release(LANE, &INCARNATION);
    assert!(original.upgrade().is_none());
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    assert_eq!(fixture.stores.budget.limit_bytes(), ceiling);
    assert_eq!(fs::read(fixture.path()).unwrap(), original_bytes);
}

#[test]
fn final_inflight_incoming_opening_cleans_cancelled_request_but_keeps_historical_recovery() {
    for historical in [false, true] {
        let mut fixture = Fixture::new(true);
        fixture.publish();
        fixture.stores.release(LANE, &INCARNATION);
        let budget = fixture.stores.budget.clone();
        let baseline = budget.reserved_bytes();
        let ceiling = budget.limit_bytes();
        let bytes = fs::read(fixture.path()).unwrap();
        let mut request = ProposalReadScope::new();
        request.admit(&budget).unwrap();
        let (entered, acquired) = sync_channel(1);
        let (resume, resumed) = sync_channel(1);
        fixture.stores.opening_faults = Some((
            fixture.source.instance(),
            Arc::new(PausedOriginalRecovery {
                entered: Mutex::new(Some(entered)),
                resume: Mutex::new(resumed),
                refuse: true,
            }),
        ));
        let pressure = budget
            .try_reserve_bytes(ceiling - budget.reserved_bytes() - bytes.len())
            .unwrap();
        // The public incoming entrypoint establishes the exact request-owned recovery.
        // Capacity stops it before SyncFile without inventing a copied progress owner.
        assert!(matches!(
            fixture
                .stores
                .execution_wait_for(LANE, &INCARNATION, 1, Duration::ZERO, &request),
            Err(Attempt::Deferred(_))
        ));
        let weak = {
            let map = fixture.stores.stores.lock();
            let Some(StoreSlot::Opening(original, owners)) = map.get(&(LANE, INCARNATION)) else {
                panic!("actual request-owned native recovery");
            };
            assert!(!owners.runtime && !owners.historical);
            Arc::downgrade(original)
        };
        drop(pressure);
        let (entered, unlocked, result) = std::thread::scope(|threads| {
            let stores = &fixture.stores;
            // The independent runtime joins and resumes the same physical opening.
            // It does not borrow the original proposal scope, which may now be dropped.
            let worker = threads.spawn(|| stores.runtime_store(LANE, &INCARNATION));
            let entered = acquired.recv_timeout(Duration::from_secs(5)).is_ok();
            let unlocked = stores.stores.try_lock().is_some();
            if entered && unlocked {
                if historical {
                    assert!(stores.store(LANE, &INCARNATION).is_err());
                }
                stores.release(LANE, &INCARNATION);
                drop(request);
                stores.release_cancelled_proposal_reads();
                assert!(
                    weak.upgrade().is_some(),
                    "the actual in-flight native owner is still retained"
                );
            } else {
                drop(request);
            }
            let _ = resume.send(());
            (entered, unlocked, worker.join().unwrap())
        });
        assert!(entered && unlocked);
        assert!(matches!(result, Err(ref error) if error.to_string().contains(RECOVERY_REFUSAL)));
        drop(result);
        let correct = weak.upgrade().is_some() == historical;
        // Capture the original return boundary before diagnostic cleanup or replay.
        fixture.stores.release_cancelled_proposal_reads();
        if !historical {
            assert_eq!(budget.reserved_bytes(), baseline);
        }
        let replay = fixture
            .stores
            .block(LANE, &INCARNATION, 1)
            .unwrap()
            .unwrap();
        assert_eq!(replay.block_hash, fixture.qc.block_hash);
        assert_eq!(replay.result, fixture.qc.result);
        assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
        drop((replay, fixture));
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            correct,
            "the final incoming opening caller must acknowledge cancellation without dropping independent historical recovery"
        );
    }
}
