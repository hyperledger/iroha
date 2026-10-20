//! Joint publication keeps both original maps and identity ahead of cleanup.

use super::*;
use concread::bptree::{
    AllocationDemand, ClonePlanning, MapAdmissionError, NodeCloning, NodeFunding, PlanningError,
    Prepaid,
};
use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationReservation};
use std::{
    alloc::Layout,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll, Wake, Waker},
};

// Test-only single-map adapter: notifications follow an actual acquisition,
// never a guessed MapAdmissionError category. Production uses its joint owner.
fn acquire_test_writer<'a, K, V, M, T>(
    notification: &'a ReleaseNotification,
    map: &'a BptreeMap<K, V, M>,
    acquire: impl FnOnce(
        concread::bptree::BptreeMapWriterAcquisition<'a, K, V, M>,
    ) -> Result<
        T,
        (
            concread::bptree::BptreeMapWriterAcquisition<'a, K, V, M>,
            MapAdmissionError<AdmittedStorageError>,
        ),
    >,
) -> Result<ReleaseGuard<'a, T>, MapAdmissionError<AdmittedStorageError>>
where
    K: Key,
    V: Value,
    M: MapMode + NodeCloning<K, V>,
{
    let acquired = map.try_acquire_writer().ok_or(MapAdmissionError::Busy)?;
    notification
        .poisoning_guard(acquired)
        .try_map_preserving_release(acquire)
        .map_err(|(acquired, error)| {
            drop(acquired);
            error
        })
}

struct Records {
    live: Mutex<Vec<(usize, bool, usize)>>,
    panic_on: AtomicUsize,
}
struct Charge {
    credit: AllocationCharge,
    id: usize,
    records: Arc<Records>,
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.records.live.lock().unwrap()[self.id].1 = false;
        assert!(
            self.records
                .panic_on
                .compare_exchange(self.id, usize::MAX, SeqCst, SeqCst)
                .is_err(),
            "injected first current-map retirement panic"
        );
        let _ = self.credit.layout();
    }
}
struct Policy {
    reservation: AllocationReservation,
    records: Arc<Records>,
    component: usize,
}
impl NodeFunding for Policy {
    type Charge = Charge;
    fn take_node_charge(&mut self, layout: Layout) -> Charge {
        let mut records = self.records.live.lock().unwrap();
        let id = records.len();
        records.push((layout.size(), true, self.component));
        Charge {
            credit: self.reservation.try_split(layout).unwrap(),
            id,
            records: Arc::clone(&self.records),
        }
    }
}
impl<V: Copy> NodeCloning<u64, V> for Policy {
    fn clone_key(&mut self, key: &u64) -> u64 {
        *key
    }
    fn clone_value(&mut self, value: &V) -> V {
        *value
    }
}
impl<V: Copy> ClonePlanning<u64, V> for Policy {
    fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
    fn plan_value(_: &V, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
}

// Production closed admission requires the actual AllocationCharge. Only this
// private publication fixture wraps charges to inject retirement destruction.
fn tracked_storage(
    budget: &AllocationBudget,
    records: &Arc<Records>,
) -> Storage<u64, u64, Prepaid<Policy>> {
    let provider = |demand: AllocationDemand| {
        Ok::<_, AdmittedStorageError>(Policy {
            reservation: budget.try_reserve_bytes(demand.bytes()).unwrap(),
            records: Arc::clone(records),
            component: 0,
        })
    };
    Storage {
        publication: Publication::new(),
        revert_released: ReleaseNotification::default(),
        blocks_released: ReleaseNotification::default(),
        revert: BptreeMap::try_new_with_node_custody(provider).unwrap(),
        blocks: BptreeMap::try_new_with_node_custody(provider).unwrap(),
        allocation: None,
    }
}

struct ClosedPolicy(AllocationReservation);
impl NodeFunding for ClosedPolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> AllocationCharge {
        self.0.try_split(layout).unwrap()
    }
}
impl<V: Copy> NodeCloning<u64, V> for ClosedPolicy {
    fn clone_key(&mut self, key: &u64) -> u64 {
        *key
    }
    fn clone_value(&mut self, value: &V) -> V {
        *value
    }
}
impl<V: Copy> ClonePlanning<u64, V> for ClosedPolicy {
    fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
    fn plan_value(_: &V, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
}
impl AdmittedStoragePolicy for ClosedPolicy {
    fn from_admission(reservation: AllocationReservation) -> Self {
        Self(reservation)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, SeqCst);
    }
}

// A retirement panic after physical unlock cannot poison the release owner.
// Subsequent real contention must wait for its own original writer release.
fn assert_healthy_contention<V: Copy + Send + Sync + 'static>(
    map: &BptreeMap<u64, V, Prepaid<Policy>>,
    budget: &AllocationBudget,
    records: &Arc<Records>,
    notification: &ReleaseNotification,
) {
    let mut registration = crate::release_test_support::registration(budget);
    let provider = |demand: AllocationDemand| {
        Ok::<_, AdmittedStorageError>(Policy {
            reservation: budget.try_reserve_bytes(demand.bytes()).unwrap(),
            records: Arc::clone(records),
            component: 0,
        })
    };
    let held = acquire_test_writer(notification, map, |acquired| {
        acquired.try_write_admitted(provider)
    })
    .unwrap();
    let wait = notification.observe();
    assert!(!wait.is_poisoned());
    let refused = acquire_test_writer(notification, map, |acquired| {
        acquired.try_write_admitted::<AdmittedStorageError>(|_| {
            panic!("held writer must refuse before admission")
        })
    });
    assert!(matches!(refused, Err(MapAdmissionError::Busy)));
    assert_eq!(notification.observe(), wait);
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    let mut future = std::pin::pin!(wait.wait_for_release(&mut registration));
    assert_eq!(
        future.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Pending
    );
    drop(held);
    assert_eq!(count.0.load(SeqCst), 1);
    assert_eq!(
        future.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(())
    );
    drop(
        acquire_test_writer(notification, map, |acquired| {
            acquired.try_write_admitted(provider)
        })
        .unwrap(),
    );
}

#[test]
fn direct_and_reacquired_publication_install_whole_pair_before_charge_cleanup_panics() {
    for reacquire in [false, true] {
        let budget = AllocationBudget::new(1 << 20);
        let records = Arc::new(Records {
            live: Mutex::new(Vec::new()),
            panic_on: AtomicUsize::new(usize::MAX),
        });
        budget.with_deferred_refund_notifications(|_| {
            let storage = tracked_storage(&budget, &records);
            let provider = |component, demand: AllocationDemand| {
                Ok::<_, AdmittedStorageError>(Policy {
                    reservation: budget.try_reserve_bytes(demand.bytes()).unwrap(),
                    records: Arc::clone(&records),
                    component,
                })
            };
            let seed = storage
                .blocks
                .try_insert_admitted(7, 70, |demand| provider(0, demand))
                .unwrap_or_else(|_| panic!("seed current"));
            storage
                .blocks
                .try_write_owned(seed.0)
                .unwrap_or_else(|_| panic!("original seed current"))
                .commit();
            let seed = storage
                .revert
                .try_insert_admitted(7, None, |demand| provider(0, demand))
                .unwrap_or_else(|_| panic!("seed undo"));
            storage
                .revert
                .try_write_owned(seed.0)
                .unwrap_or_else(|_| panic!("original seed undo"))
                .commit();
            let old_current = storage.blocks.read();
            let old_undo = storage.revert.read();
            let predecessor = storage.publication.capture();
            let mut revert =
                acquire_test_writer(&storage.revert_released, &storage.revert, |acquired| {
                    acquired.try_write_admitted(|demand| provider(0, demand))
                })
                .unwrap();
            let mut blocks =
                acquire_test_writer(&storage.blocks_released, &storage.blocks, |acquired| {
                    acquired.try_write_admitted(|demand| provider(0, demand))
                })
                .unwrap();
            revert
                .try_insert_admitted(7, Some(70), |demand| provider(2, demand))
                .unwrap_or_else(|_| panic!("original undo edit"));
            let first = records.live.lock().unwrap().len();
            blocks
                .try_insert_admitted(7, 71, |demand| provider(3, demand))
                .unwrap_or_else(|_| panic!("original current edit"));
            let candidates: Vec<_> = records
                .live
                .lock()
                .unwrap()
                .iter()
                .enumerate()
                .skip(first)
                .filter(|(_, (size, live, component))| {
                    *component == 3 && *size > 0 && *size <= 32 && *live
                })
                .map(|(id, _)| id)
                .collect();
            assert_eq!(candidates.len(), 2);
            let target = candidates[0];
            let (blocks, revert) = if reacquire {
                let blocks = blocks.release_with(|writer| writer.detach());
                let revert = revert.release_with(|writer| writer.detach());
                let revert = storage.revert_released.poisoning_guard(
                    storage
                        .revert
                        .try_write_owned(revert)
                        .unwrap_or_else(|_| panic!("same original undo owner")),
                );
                let blocks = storage.blocks_released.poisoning_guard(
                    storage
                        .blocks
                        .try_write_owned(blocks)
                        .unwrap_or_else(|_| panic!("same original current owner")),
                );
                (blocks, revert)
            } else {
                (blocks, revert)
            };
            records.panic_on.store(target, SeqCst);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut next = Some(NextPublication::new());
                let mut writers = StorageWriters::new(&storage, revert, blocks);
                writers.prepare_publication(&predecessor, true);
                writers.publish_prepared(&mut next);
                drop(writers);
            }));
            assert!(result.is_err());
            assert!(!records.live.lock().unwrap()[target].1);
            assert_eq!(storage.blocks.read().get(&7), Some(&71));
            assert_eq!(storage.revert.read().get(&7), Some(&Some(70)));
            assert_eq!(
                predecessor.try_check_current::<()>(&storage.publication).0,
                Err(PublicationPreparationError::Changed)
            );
            assert_eq!(old_current.get(&7), Some(&70));
            assert_eq!(old_undo.get(&7), Some(&None));
            assert_healthy_contention(&storage.blocks, &budget, &records, &storage.blocks_released);
            assert_healthy_contention(&storage.revert, &budget, &records, &storage.revert_released);
            drop(old_current);
            drop(old_undo);
            drop(storage);
        });
        assert!(
            records
                .live
                .lock()
                .unwrap()
                .iter()
                .all(|(_, live, _)| !live)
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn refused_admitted_acquisition_signals_only_the_original_released_writer() {
    let budget = AllocationBudget::new(1 << 20);
    let mut registration = crate::release_test_support::registration(&budget);
    let records = Arc::new(Records {
        live: Mutex::new(Vec::new()),
        panic_on: AtomicUsize::new(usize::MAX),
    });
    let provider = |reservation| Policy {
        reservation,
        records: Arc::clone(&records),
        component: 0,
    };
    budget.with_deferred_refund_notifications(|_| {
        let storage = tracked_storage(&budget, &records);
        let (seed, _) = storage
            .blocks
            .try_insert_admitted(7, 70, |demand| {
                Ok::<_, ()>(provider(budget.try_reserve_bytes(demand.bytes()).unwrap()))
            })
            .unwrap_or_else(|_| panic!("seed current"));
        storage
            .blocks
            .try_write_owned(seed)
            .unwrap_or_else(|_| panic!("original seed current"))
            .commit();
        let notification = &storage.blocks_released;
        let inner_map = BptreeMap::<u64, u64>::new();
        let inner_notification = ReleaseNotification::default();
        let inner_held = inner_notification.poisoning_guard(inner_map.write());
        let inner_wait = inner_notification.observe();
        let exhausted = AllocationBudget::new(0);
        for clear in [false, true] {
            for refuse_with in 0..3 {
                let expected = notification.observe();
                let count = Arc::new(WakeCount(AtomicUsize::new(0)));
                let waker = Waker::from(Arc::clone(&count));
                let mut registered = None;
                let mut refuse = |demand: AllocationDemand| {
                    assert!(matches!(
                        storage
                            .blocks
                            .try_write_admitted::<AdmittedStorageError>(|_| panic!(
                                "original raw writer is held"
                            )),
                        Err(MapAdmissionError::Busy)
                    ));
                    let wait = notification.observe();
                    assert_eq!(wait, expected);
                    assert_eq!(
                        registration.poll_wait(&wait, &mut Context::from_waker(&waker)),
                        Poll::Pending
                    );
                    registered = Some(wait);
                    Err::<Policy, _>(match refuse_with {
                        0 => AdmittedStorageError::PolicyIdentity,
                        1 => {
                            assert!(inner_map.try_write().is_none());
                            AdmittedStorageError::Busy {
                                role: StorageRole::Undo,
                                release: inner_notification.observe(),
                            }
                        }
                        2 => AdmittedStorageError::Allocation(
                            exhausted
                                .try_reserve_bytes(demand.bytes())
                                .expect_err("actual complete demand exceeds empty budget"),
                        ),
                        _ => unreachable!(),
                    })
                };
                let refused = acquire_test_writer(notification, &storage.blocks, |acquired| {
                    if clear {
                        acquired.try_clear_admitted(&mut refuse)
                    } else {
                        acquired.try_write_admitted(&mut refuse)
                    }
                });
                match (refuse_with, refused) {
                    (0, Err(MapAdmissionError::Refused(AdmittedStorageError::PolicyIdentity)))
                    | (2, Err(MapAdmissionError::Refused(AdmittedStorageError::Allocation(_)))) => {
                    }
                    (
                        1,
                        Err(MapAdmissionError::Refused(AdmittedStorageError::Busy {
                            role: StorageRole::Undo,
                            release,
                        })),
                    ) => {
                        assert_eq!(release, inner_wait);
                        assert_eq!(inner_notification.observe(), inner_wait);
                    }
                    _ => panic!("original callback refusal changed"),
                }
                assert_eq!(count.0.load(SeqCst), 1);
                assert!(!expected.is_poisoned());
                assert_eq!(
                    registration.poll_wait(
                        registered.as_ref().expect("registered under raw writer"),
                        &mut Context::from_waker(&waker)
                    ),
                    Poll::Ready(())
                );
                registration.cancel();
                assert_eq!(storage.blocks.read().get(&7), Some(&70));
            }
        }
        drop(inner_held);
        assert_healthy_contention(&storage.blocks, &budget, &records, notification);
        assert_eq!(storage.blocks.read().get(&7), Some(&70));
        drop(storage);
    });
    assert!(
        records
            .live
            .lock()
            .unwrap()
            .iter()
            .all(|(_, live, _)| !live)
    );
    drop(registration);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prepaid_removal_matches_transaction_and_block_preimages_across_abort_and_rebalance() {
    use std::collections::{BTreeMap, BTreeSet};

    fn entries(store: &impl StorageReadOnly<u64, u64>) -> Vec<(u64, u64)> {
        store.iter().map(|(key, value)| (*key, *value)).collect()
    }
    fn touches<'a>(
        keys: impl Iterator<Item = &'a u64>,
        before: &BTreeMap<u64, u64>,
        after: &BTreeMap<u64, u64>,
    ) -> Vec<(u64, Option<u64>, Option<u64>)> {
        keys.map(|key| (*key, before.get(key).copied(), after.get(key).copied()))
            .collect()
    }
    fn row(entry: TouchedEntry<'_, u64, u64>) -> (u64, Option<u64>, Option<u64>) {
        (*entry.key, entry.before.copied(), entry.after.copied())
    }

    let budget = AllocationBudget::new(16 << 20);
    let admitted =
        Storage::<u64, u64, Prepaid<ClosedPolicy>>::try_new_admitted(budget.clone()).unwrap();
    let ordinary = Storage::<u64, u64>::default();
    let mut model = BTreeMap::<u64, u64>::new();
    for block_number in 0_u64..3 {
        let block_before = model.clone();
        let old = admitted.view();
        admitted
            .try_with_admitted_block(|prepaid| {
                let mut plain = ordinary.block();
                let mut block_touched = BTreeSet::new();
                let mut block_dirty = false;
                for phase in 0_u64..6 {
                    let transaction_before = model.clone();
                    let mut next = model.clone();
                    let mut touched = BTreeSet::new();
                    let mut dirty = false;
                    let mut left = plain.transaction();
                    let mut right = prepaid.try_transaction_admitted().unwrap();
                    let count = if phase == 0 { 4 } else { 256 };
                    for step in 0..count {
                        // First keep explicit missing-key touches; then fill, empty,
                        // refill, and mix edits to cross splits and root demotion.
                        let key = match phase {
                            0 => 2048 + step % 2,
                            1..=3 => 255 - step,
                            _ => (step * 73) % 384,
                        };
                        let insert = matches!(phase, 1 | 3) || (phase >= 4 && step % 3 == 0);
                        let expected = if insert {
                            dirty = true;
                            next.insert(key, block_number * 10_000 + phase * 1000 + step)
                        } else {
                            let previous = next.remove(&key);
                            dirty |= previous.is_some();
                            previous
                        };
                        let (actual_left, actual_right) = if insert {
                            let value = block_number * 10_000 + phase * 1000 + step;
                            (
                                left.insert(key, value),
                                right.try_insert_admitted(key, value).unwrap(),
                            )
                        } else {
                            (left.remove(key), right.try_remove_admitted(key).unwrap())
                        };
                        assert_eq!((actual_left, actual_right), (expected, expected));
                        touched.insert(key);
                        assert_eq!(
                            right.get_before_transaction(&key),
                            transaction_before.get(&key)
                        );
                        assert_eq!(right.get_before_block(&key), block_before.get(&key));
                    }
                    let expected_rows = touches(touched.iter(), &transaction_before, &next);
                    assert_eq!(
                        left.touched_entries().map(row).collect::<Vec<_>>(),
                        expected_rows
                    );
                    assert_eq!(
                        right.touched_entries().map(row).collect::<Vec<_>>(),
                        expected_rows
                    );
                    assert_eq!(
                        entries(&left),
                        next.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>()
                    );
                    assert_eq!(entries(&right), entries(&left));
                    // An aborted sibling must restore both roots, first preimages,
                    // dirty state and the parent's earlier successful touches.
                    if phase == 4 || (phase == 2 && block_number == 1) {
                        drop(left);
                        drop(right);
                    } else {
                        left.apply();
                        right.apply();
                        model = next;
                        block_touched.extend(touched);
                        block_dirty |= dirty;
                    }
                    let expected_rows = touches(block_touched.iter(), &block_before, &model);
                    assert_eq!(
                        plain.touched_entries().map(row).collect::<Vec<_>>(),
                        expected_rows
                    );
                    assert_eq!(
                        prepaid.touched_entries().map(row).collect::<Vec<_>>(),
                        expected_rows
                    );
                    assert_eq!(plain.is_dirty(), block_dirty);
                    assert_eq!(prepaid.is_dirty(), block_dirty);
                    assert_eq!(entries(prepaid), entries(&plain));
                }
                plain.commit();
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(entries(&old), block_before.into_iter().collect::<Vec<_>>());
        assert_eq!(
            entries(&admitted.view()),
            model.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>()
        );
        assert_eq!(entries(&admitted.view()), entries(&ordinary.view()));
    }
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), 0);
}

// Replacement faults use the production policy contract and its original pool.
thread_local! {
    static REPLACEMENT_REPLAN: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static REFUSED_REPLACEMENT_VALUE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static REPLACEMENT_POLICY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REPLACEMENT_EXHAUST_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    static REPLACEMENT_POOL: std::cell::RefCell<Option<AllocationBudget>> = const { std::cell::RefCell::new(None) };
    static REPLACEMENT_HELD: std::cell::RefCell<Option<AllocationReservation>> = const { std::cell::RefCell::new(None) };
}

struct ReplacementContext;
impl ReplacementContext {
    fn new(budget: &AllocationBudget) -> Self {
        REPLACEMENT_POOL.with(|pool| assert!(pool.replace(Some(budget.clone())).is_none()));
        REPLACEMENT_POLICY_CALLS.with(|calls| calls.set(0));
        Self
    }
}
impl Drop for ReplacementContext {
    fn drop(&mut self) {
        REPLACEMENT_REPLAN.with(|mode| mode.set(0));
        REFUSED_REPLACEMENT_VALUE.with(|value| value.set(None));
        REPLACEMENT_EXHAUST_AT.with(|at| at.set(usize::MAX));
        REPLACEMENT_HELD.with(|held| drop(held.take()));
        REPLACEMENT_POOL.with(|pool| drop(pool.take()));
    }
}

struct ReplacementPolicy(AllocationReservation);
impl NodeFunding for ReplacementPolicy {
    type Charge = AllocationCharge;
    fn take_node_charge(&mut self, layout: Layout) -> AllocationCharge {
        self.0.try_split(layout).unwrap()
    }
}
impl NodeCloning<u64, u64> for ReplacementPolicy {
    fn clone_key(&mut self, key: &u64) -> u64 {
        *key
    }
    fn clone_value(&mut self, value: &u64) -> u64 {
        REPLACEMENT_REPLAN.with(|mode| match mode.get() {
            1 => mode.set(2),
            3 => mode.set(4),
            _ => {}
        });
        *value
    }
}
impl ClonePlanning<u64, u64> for ReplacementPolicy {
    fn plan_key(_: &u64, demand: &mut AllocationDemand) -> Result<(), PlanningError> {
        match REPLACEMENT_REPLAN.with(|mode| mode.get()) {
            2 => Err(PlanningError::UnsupportedPayload),
            4 => demand.add_layout(Layout::new::<u64>()),
            _ => Ok(()),
        }
    }
    fn plan_value(value: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        if REFUSED_REPLACEMENT_VALUE.with(|refused| refused.get()) == Some(*value) {
            Err(PlanningError::UnsupportedPayload)
        } else {
            Ok(())
        }
    }
}
impl NodeCloning<u64, Option<u64>> for ReplacementPolicy {
    fn clone_key(&mut self, key: &u64) -> u64 {
        *key
    }
    fn clone_value(&mut self, value: &Option<u64>) -> Option<u64> {
        *value
    }
}
impl ClonePlanning<u64, Option<u64>> for ReplacementPolicy {
    fn plan_key(_: &u64, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
    fn plan_value(_: &Option<u64>, _: &mut AllocationDemand) -> Result<(), PlanningError> {
        Ok(())
    }
}
impl AdmittedStoragePolicy for ReplacementPolicy {
    fn from_admission(reservation: AllocationReservation) -> Self {
        // Each admission is a phase boundary for physical allocator fault tests.
        crate::allocation_test_support::mark_layout_trace();
        let calls = REPLACEMENT_POLICY_CALLS.with(|calls| {
            calls.set(calls.get() + 1);
            calls.get()
        });
        if REPLACEMENT_EXHAUST_AT.with(|at| at.get()) == calls {
            REPLACEMENT_POOL.with(|pool| {
                let pool = pool.borrow();
                let budget = pool.as_ref().unwrap();
                let held = budget
                    .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                    .unwrap();
                REPLACEMENT_HELD.with(|slot| assert!(slot.replace(Some(held)).is_none()));
            });
        }
        Self(reservation)
    }
    fn admission(&self) -> &AllocationReservation {
        &self.0
    }
}

type ReplacementStorage = Storage<u64, u64, Prepaid<ReplacementPolicy>>;

#[test]
fn admitted_block_abandonment_unlocks_both_writers_before_native_wakes() {
    struct Probe {
        storage: Arc<ReplacementStorage>,
        budget: AllocationBudget,
        calls: AtomicUsize,
        panic_once: std::sync::atomic::AtomicBool,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            let provider = |demand: AllocationDemand| {
                Ok::<_, ()>(ReplacementPolicy(
                    self.budget.try_reserve_bytes(demand.bytes()).unwrap(),
                ))
            };
            assert!(
                self.storage.revert.is_poisoned()
                    || self.storage.revert.try_write_admitted(provider).is_ok()
            );
            assert!(
                self.storage.blocks.is_poisoned()
                    || self.storage.blocks.try_write_admitted(provider).is_ok()
            );
            self.calls.fetch_add(1, SeqCst);
            assert!(
                !self.panic_once.swap(false, SeqCst),
                "native wake interrupted abandonment"
            );
        }
    }
    for replacement in [false, true] {
        for mode in 0..3 {
            let budget = AllocationBudget::new(1 << 20);
            let mut undo_registration = crate::release_test_support::registration(&budget);
            let mut current_registration = crate::release_test_support::registration(&budget);
            let _context = ReplacementContext::new(&budget);
            let storage = Arc::new(replacement_fixture(&budget));
            let before = replacement_rows(&storage.view());
            let undo_before: Vec<_> = storage
                .revert
                .read()
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect();
            let predecessor = storage.publication.capture();
            let probe = Arc::new(Probe {
                storage: Arc::clone(&storage),
                budget: budget.clone(),
                calls: AtomicUsize::new(0),
                panic_once: std::sync::atomic::AtomicBool::new(mode == 2),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut context = Context::from_waker(&waker);
            let mut undo = std::pin::pin!(
                storage
                    .revert_released
                    .observe()
                    .wait_for_release(&mut undo_registration)
            );
            let mut current = std::pin::pin!(
                storage
                    .blocks_released
                    .observe()
                    .wait_for_release(&mut current_registration)
            );
            assert!(undo.as_mut().poll(&mut context).is_pending());
            assert!(current.as_mut().poll(&mut context).is_pending());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let operation = |block: &mut Block<'_, _, _, _>| {
                    let mut tx = block.try_transaction_admitted().unwrap();
                    tx.try_insert_admitted(9, 99).unwrap();
                    tx.apply();
                    assert!(mode != 1, "callback interrupted abandonment");
                    Err::<(), _>(())
                };
                if replacement {
                    storage.try_with_admitted_replacement(operation)
                } else {
                    storage.try_with_admitted_block(operation)
                }
            }));
            if mode == 0 {
                assert!(matches!(result, Ok(Err(AdmittedBlockError::Callback(())))));
            } else {
                assert!(result.is_err());
            }
            let poisoned = mode == 1;
            assert_eq!(
                (storage.revert.is_poisoned(), storage.blocks.is_poisoned()),
                (poisoned, poisoned)
            );
            assert_eq!(
                (
                    storage.revert_released.observe().is_poisoned(),
                    storage.blocks_released.observe().is_poisoned()
                ),
                (poisoned, poisoned)
            );
            assert_eq!(probe.calls.load(SeqCst), 2);
            assert!(undo.as_mut().poll(&mut context).is_ready());
            assert!(current.as_mut().poll(&mut context).is_ready());
            assert_eq!(replacement_rows(&storage.view()), before);
            assert_eq!(
                storage
                    .revert
                    .read()
                    .iter()
                    .map(|(key, value)| (*key, *value))
                    .collect::<Vec<_>>(),
                undo_before
            );
            assert_eq!(
                predecessor.try_check_current::<()>(&storage.publication).0,
                Ok(())
            );
            if !poisoned {
                storage
                    .try_with_admitted_block(|_| Ok::<_, ()>(()))
                    .unwrap();
            }
        }
    }
}

fn replacement_fixture(budget: &AllocationBudget) -> ReplacementStorage {
    let storage = ReplacementStorage::try_new_admitted(budget.clone()).unwrap();
    storage
        .try_with_admitted_block(|block| {
            let mut tx = block.try_transaction_admitted().unwrap();
            for (key, value) in [(1, 10), (2, 20), (4, 40)] {
                tx.try_insert_admitted(key, value).unwrap();
            }
            tx.apply();
            Ok::<_, ()>(())
        })
        .unwrap();
    storage
        .try_with_admitted_block(|block| {
            let mut tx = block.try_transaction_admitted().unwrap();
            assert_eq!(tx.try_remove_admitted(1).unwrap(), Some(10));
            tx.try_insert_admitted(2, 21).unwrap();
            tx.try_insert_admitted(3, 30).unwrap();
            tx.apply();
            Ok::<_, ()>(())
        })
        .unwrap();
    storage
}

fn replacement_rows(storage: &impl StorageReadOnly<u64, u64>) -> Vec<(u64, u64)> {
    storage.iter().map(|(key, value)| (*key, *value)).collect()
}

#[test]
fn admitted_replacement_retains_mode_and_restored_preimages_through_callback_abort() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let storage = replacement_fixture(&budget);
    let current = storage.blocks.read();
    let undo = storage.revert.read();
    let predecessor = storage.publication.capture();
    let before = budget.reserved_bytes();
    for publish in [false, true] {
        let result = storage.try_with_admitted_replacement(|block| {
            assert_eq!(block.mode(), BlockMode::Replace);
            assert!(block.is_dirty());
            assert_eq!(replacement_rows(block), [(1, 10), (2, 20), (4, 40)]);
            assert!(block.revert_map().is_empty());
            let mut tx = block.try_transaction_admitted().unwrap();
            tx.try_insert_admitted(2, 22).unwrap();
            tx.try_insert_admitted(3, 33).unwrap();
            tx.apply();
            assert_eq!(block.get_before_block(&2), Some(&20));
            assert_eq!(block.get_before_block(&3), None);
            if publish { Ok(()) } else { Err(()) }
        });
        if publish {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(AdmittedBlockError::Callback(()))));
            assert_eq!(budget.reserved_bytes(), before);
            assert_eq!(
                predecessor.try_check_current::<()>(&storage.publication).0,
                Ok(())
            );
            assert_eq!(storage.blocks.read().get(&2), Some(&21));
            assert_eq!(storage.revert.read().get(&2), Some(&Some(20)));
        }
    }
    assert_eq!(
        replacement_rows(&storage.view()),
        [(1, 10), (2, 22), (3, 33), (4, 40)]
    );
    assert_eq!(
        storage
            .revert
            .read()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<Vec<_>>(),
        [(2, Some(20)), (3, None)]
    );
    let result = storage.try_with_admitted_replacement(|block| {
        assert_eq!(replacement_rows(block), [(1, 10), (2, 20), (4, 40)]);
        Err::<(), _>(())
    });
    assert!(matches!(result, Err(AdmittedBlockError::Callback(()))));
    assert_eq!(current.get(&2), Some(&21));
    assert_eq!(undo.get(&1), Some(&Some(10)));
    drop((current, undo));
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        retained_publication_identity_bytes()
    );
    drop(predecessor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_replacement_contention_names_only_the_original_held_writer() {
    for hold_undo in [false, true] {
        let budget = AllocationBudget::new(1 << 20);
        let mut registration = crate::release_test_support::registration(&budget);
        let _context = ReplacementContext::new(&budget);
        let storage = replacement_fixture(&budget);
        budget.with_deferred_refund_notifications(|_| {
            let provider = |demand: AllocationDemand| {
                Ok::<_, AdmittedStorageError>(ReplacementPolicy(
                    budget.try_reserve_bytes(demand.bytes()).unwrap(),
                ))
            };
            let undo = hold_undo.then(|| {
                acquire_test_writer(&storage.revert_released, &storage.revert, |acquired| {
                    acquired.try_write_admitted(provider)
                })
                .unwrap()
            });
            let current = (!hold_undo).then(|| {
                acquire_test_writer(&storage.blocks_released, &storage.blocks, |acquired| {
                    acquired.try_write_admitted(provider)
                })
                .unwrap()
            });
            let (role, expected) = if hold_undo {
                (StorageRole::Undo, storage.revert_released.observe())
            } else {
                (StorageRole::Current, storage.blocks_released.observe())
            };
            let predecessor = storage.publication.capture();
            let before = budget.reserved_bytes();
            let error = storage
                .try_with_admitted_replacement(|_| -> Result<(), ()> {
                    panic!("held writer cannot run the callback")
                })
                .unwrap_err();
            let AdmittedBlockError::Admission(AdmittedStorageError::Busy {
                role: actual,
                release,
            }) = error
            else {
                panic!("original writer lost its release dependency");
            };
            assert_eq!(actual, role);
            assert_eq!(release, expected);
            assert_eq!(budget.reserved_bytes(), before);
            assert_eq!(
                predecessor.try_check_current::<()>(&storage.publication).0,
                Ok(())
            );
            let mut future = std::pin::pin!(release.wait_for_release(&mut registration));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop((undo, current));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
            storage
                .try_with_admitted_replacement(|block| {
                    assert_eq!(replacement_rows(block), [(1, 10), (2, 20), (4, 40)]);
                    Ok::<_, ()>(())
                })
                .unwrap();
        });
        drop(storage);
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_replacement_of_empty_undo_still_records_replace_mode() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let storage = replacement_fixture(&budget);
    storage
        .try_with_admitted_block(|_| Ok::<_, ()>(()))
        .unwrap();
    let predecessor = storage.publication.capture();
    storage
        .try_with_admitted_replacement(|block| {
            assert_eq!(block.mode(), BlockMode::Replace);
            assert!(block.is_dirty());
            assert!(block.revert_map().is_empty());
            assert_eq!(block.get(&2), Some(&21));
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(
        predecessor.try_check_current::<()>(&storage.publication).0,
        Err(PublicationPreparationError::Changed)
    );
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        retained_publication_identity_bytes()
    );
    drop(predecessor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_replacement_final_undo_clear_refusal_preserves_original_pair() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let storage = replacement_fixture(&budget);
    storage
        .try_with_admitted_block(|_| Ok::<_, ()>(()))
        .unwrap();
    let predecessor = storage.publication.capture();
    let before = budget.reserved_bytes();
    REPLACEMENT_POLICY_CALLS.with(|calls| calls.set(0));
    REPLACEMENT_EXHAUST_AT.with(|at| at.set(2));
    let error = storage
        .try_with_admitted_replacement(|_| -> Result<(), ()> {
            panic!("final clear must refuse before callback")
        })
        .unwrap_err();
    assert!(matches!(
        error,
        AdmittedBlockError::Admission(AdmittedStorageError::Allocation(_))
    ));
    assert_eq!(REPLACEMENT_POLICY_CALLS.with(|calls| calls.get()), 2);
    assert_eq!(
        predecessor.try_check_current::<()>(&storage.publication).0,
        Ok(())
    );
    assert_eq!(storage.blocks.read().get(&2), Some(&21));
    assert!(storage.revert.read().is_empty());
    REPLACEMENT_HELD.with(|held| drop(held.take()));
    REPLACEMENT_EXHAUST_AT.with(|at| at.set(usize::MAX));
    assert_eq!(budget.reserved_bytes(), before);
    storage
        .try_with_admitted_replacement(|_| Ok::<_, ()>(()))
        .unwrap();
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        retained_publication_identity_bytes()
    );
    drop(predecessor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_replacement_callback_cleanup_cannot_publish_a_partial_owner() {
    struct CallbackCleanup;
    impl CallbackCleanup {
        fn retain(&self) {}
    }
    impl Drop for CallbackCleanup {
        fn drop(&mut self) {
            panic!("injected callback cleanup failure");
        }
    }
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let storage = replacement_fixture(&budget);
    let before = budget.reserved_bytes();
    let predecessor = storage.publication.capture();
    let bomb = CallbackCleanup;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = storage.try_with_admitted_replacement(move |block| {
            bomb.retain();
            block.try_insert_admitted(2, 22).unwrap();
            Ok::<_, ()>(())
        });
    }));
    assert!(result.is_err());
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        predecessor.try_check_current::<()>(&storage.publication).0,
        Ok(())
    );
    assert_eq!(storage.blocks.read().get(&2), Some(&21));
    assert_eq!(storage.revert.read().get(&2), Some(&Some(20)));
    assert!(storage.revert_released.observe().is_poisoned());
    assert!(storage.blocks_released.observe().is_poisoned());
    assert!(matches!(
        storage.try_with_admitted_replacement(|_| Ok::<_, ()>(())),
        Err(AdmittedBlockError::Admission(
            AdmittedStorageError::Poisoned { .. }
        ))
    ));
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        retained_publication_identity_bytes()
    );
    drop(predecessor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_replacement_second_plan_refusal_returns_a_healthy_original_pair() {
    for mode in [1, 3] {
        let budget = AllocationBudget::new(1 << 20);
        let _context = ReplacementContext::new(&budget);
        let storage = replacement_fixture(&budget);
        let before = budget.reserved_bytes();
        let predecessor = storage.publication.capture();
        REPLACEMENT_REPLAN.with(|state| state.set(mode));
        let error = storage
            .try_with_admitted_replacement(|_| -> Result<(), ()> {
                panic!("replanning must refuse before callback")
            })
            .unwrap_err();
        REPLACEMENT_REPLAN.with(|state| state.set(0));
        match (mode, error) {
            (
                1,
                AdmittedBlockError::Admission(AdmittedStorageError::Planning(
                    PlanningError::UnsupportedPayload,
                )),
            )
            | (3, AdmittedBlockError::Admission(AdmittedStorageError::Changed)) => {}
            (_, error) => panic!("replanning lost its original refusal: {error:?}"),
        }
        assert_eq!(budget.reserved_bytes(), before);
        assert_eq!(
            predecessor.try_check_current::<()>(&storage.publication).0,
            Ok(())
        );
        assert_eq!(storage.blocks.read().get(&2), Some(&21));
        assert_eq!(storage.revert.read().get(&2), Some(&Some(20)));
        let result = storage.try_with_admitted_replacement(|block| {
            assert_eq!(replacement_rows(block), [(1, 10), (2, 20), (4, 40)]);
            Err::<(), _>(())
        });
        assert!(matches!(result, Err(AdmittedBlockError::Callback(()))));
        drop(storage);
        assert_eq!(
            budget.reserved_bytes(),
            retained_publication_identity_bytes()
        );
        drop(predecessor);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_replacement_planning_refusal_discards_the_restored_private_prefix() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let storage = replacement_fixture(&budget);
    let before = budget.reserved_bytes();
    let predecessor = storage.publication.capture();
    let current = storage.blocks.read();
    let undo = storage.revert.read();
    REPLACEMENT_POLICY_CALLS.with(|calls| calls.set(0));
    REFUSED_REPLACEMENT_VALUE.with(|refused| refused.set(Some(20)));
    let error = storage
        .try_with_admitted_replacement(|_| -> Result<(), ()> {
            panic!("restoration must refuse before callback")
        })
        .unwrap_err();
    REFUSED_REPLACEMENT_VALUE.with(|refused| refused.set(None));
    assert!(matches!(
        error,
        AdmittedBlockError::Admission(AdmittedStorageError::Planning(
            PlanningError::UnsupportedPayload
        ))
    ));
    assert!(
        REPLACEMENT_POLICY_CALLS.with(|calls| calls.get()) > 2,
        "refusal follows a real private restoration"
    );
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(
        predecessor.try_check_current::<()>(&storage.publication).0,
        Ok(())
    );
    assert_eq!(current.get(&2), Some(&21));
    assert_eq!(undo.get(&2), Some(&Some(20)));
    let result = storage.try_with_admitted_replacement(|block| {
        assert_eq!(replacement_rows(block), [(1, 10), (2, 20), (4, 40)]);
        Err::<(), _>(())
    });
    assert!(matches!(result, Err(AdmittedBlockError::Callback(()))));
    drop((current, undo));
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        retained_publication_identity_bytes()
    );
    drop(predecessor);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_snapshot_preserves_exact_current_undo_and_replacement_history() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let source = replacement_fixture(&budget);
    source
        .try_with_admitted_block(|block| {
            block.try_remove_admitted(9).unwrap();
            block.try_insert_admitted(2, 22).unwrap();
            block.try_remove_admitted(3).unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    let snapshot = source.snapshot();
    let destination_budget = AllocationBudget::new(1 << 20);
    let mut restored =
        ReplacementStorage::try_from_snapshot_admitted(&snapshot, destination_budget.clone())
            .unwrap();
    assert_eq!(
        replacement_rows(&restored.view()),
        replacement_rows(snapshot.current())
    );
    assert_eq!(
        restored
            .revert
            .read()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<Vec<_>>(),
        snapshot
            .revert_map()
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<Vec<_>>()
    );
    assert_eq!(restored.revert.read().get(&9), Some(&None));
    assert_eq!(
        norito::json::to_json(&restored).unwrap(),
        norito::json::to_json(&source).unwrap()
    );
    {
        let history = restored.history();
        assert_eq!(history.revert_map().get(&9), Some(&None));
        assert_eq!(history.get_before_block(&3), Some(&30));
        assert_eq!(
            history
                .iter_before_block()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<_>>(),
            [(2, 21), (3, 30), (4, 40)]
        );
    }
    restored
        .try_with_admitted_replacement(|block| {
            assert_eq!(replacement_rows(block), [(2, 21), (3, 30), (4, 40)]);
            assert!(block.revert_map().is_empty());
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(source.view().get(&2), Some(&22));
    assert_eq!(snapshot.revert_map().get(&3), Some(&Some(30)));
    drop(restored);
    assert_eq!(destination_budget.reserved_bytes(), 0);
    drop(snapshot);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_snapshot_capacity_and_planning_refusals_leave_source_reusable() {
    let budget = AllocationBudget::new(1 << 20);
    let _context = ReplacementContext::new(&budget);
    let source = replacement_fixture(&budget);
    let snapshot = source.snapshot();
    let destination_budget = AllocationBudget::new(1 << 20);
    let held = destination_budget
        .try_reserve_bytes(destination_budget.limit_bytes())
        .unwrap();
    assert!(matches!(
        ReplacementStorage::try_from_snapshot_admitted(&snapshot, destination_budget.clone()),
        Err(AdmittedStorageError::Allocation(_))
    ));
    assert_eq!(destination_budget.reserved_bytes(), held.remaining_bytes());
    drop(held);
    REFUSED_REPLACEMENT_VALUE.with(|refused| refused.set(Some(30)));
    assert!(matches!(
        ReplacementStorage::try_from_snapshot_admitted(&snapshot, destination_budget.clone()),
        Err(AdmittedStorageError::Planning(
            PlanningError::UnsupportedPayload
        ))
    ));
    REFUSED_REPLACEMENT_VALUE.with(|refused| refused.set(None));
    assert_eq!(destination_budget.reserved_bytes(), 0);
    assert_eq!(
        replacement_rows(snapshot.current()),
        [(2, 21), (3, 30), (4, 40)]
    );
    assert_eq!(snapshot.revert_map().get(&1), Some(&Some(10)));
    let restored =
        ReplacementStorage::try_from_snapshot_admitted(&snapshot, destination_budget.clone())
            .unwrap();
    assert_eq!(
        replacement_rows(&restored.view()),
        replacement_rows(snapshot.current())
    );
    drop(restored);
    assert_eq!(destination_budget.reserved_bytes(), 0);
    drop(snapshot);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[path = "fresh_pair_acquisition_tests.rs"]
mod fresh_pair_acquisition;

// A captured predecessor retains owner/version identities, but no notification.
fn retained_publication_identity_bytes() -> usize {
    Publication::allocation_demand().unwrap().bytes()
        - ReleaseNotification::allocation_layout::<AllocationCharge>().size()
}

#[test]
fn admitted_initial_storage_includes_identity_notification_before_allocation() {
    let required = ReplacementStorage::initial_allocation_demand()
        .unwrap()
        .bytes();
    let budget = AllocationBudget::new(required - 1);
    let _context = ReplacementContext::new(&budget);
    assert!(matches!(
        ReplacementStorage::try_new_admitted(budget.clone()),
        Err(AdmittedStorageError::Allocation(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    budget.set_limit_bytes(required);
    let storage = ReplacementStorage::try_new_admitted(budget.clone()).unwrap();
    assert_eq!(budget.reserved_bytes(), required);
    let identity = storage.publication.capture();
    let prepared = match identity.try_prepare_current::<()>(&storage.publication) {
        Ok(prepared) => prepared,
        Err(_) => panic!("uncontended original publication identity"),
    };
    let wait = match identity.try_prepare_current::<()>(&storage.publication) {
        Err((PublicationPreparationError::Busy(wait), None)) => wait,
        _ => panic!("the actual held identity must return its own release source"),
    };
    drop(prepared.abort());
    drop(storage);
    assert_eq!(
        budget.reserved_bytes(),
        Publication::allocation_demand().unwrap().bytes()
    );
    drop(identity);
    assert_eq!(
        budget.reserved_bytes(),
        ReleaseNotification::allocation_layout::<AllocationCharge>().size()
    );
    drop(wait);
    assert_eq!(budget.reserved_bytes(), 0);
}

// Each raw writer is free: an ordinary admitted cursor opens and is abandoned.
fn assert_both_writers_free(storage: &ReplacementStorage, budget: &AllocationBudget) {
    let provider = |demand: AllocationDemand| {
        Ok::<_, ()>(ReplacementPolicy(
            budget.try_reserve_bytes(demand.bytes()).unwrap(),
        ))
    };
    budget.with_deferred_refund_notifications(|_| {
        assert!(
            storage.revert.try_write_admitted(provider).is_ok(),
            "the undo writer was released"
        );
        assert!(
            storage.blocks.try_write_admitted(provider).is_ok(),
            "the current writer was released"
        );
    });
}

#[test]
fn admitted_storage_construction_allocator_refusals_retire_every_partial_owner() {
    use crate::allocation_test_support::{refuse_layout_during, trace_layout_during};
    let notification = ReleaseNotification::allocation_layout::<AllocationCharge>();
    let identity = NextPublication::allocation_layout();
    assert_eq!(
        Publication::initial_layouts(),
        [identity, identity, notification],
        "publication owner, version and notification layouts"
    );
    let required = ReplacementStorage::initial_allocation_demand()
        .unwrap()
        .bytes();
    let budget = AllocationBudget::new(required);
    let construct = || ReplacementStorage::try_new_admitted(budget.clone());
    drop(construct().unwrap());
    let (storage, notifications) = trace_layout_during(notification, construct);
    drop(storage.unwrap());
    let (storage, identities) = trace_layout_during(identity, construct);
    drop(storage.unwrap());
    // Both map notifications precede the two map admissions. The publication
    // owner, version and notification are the last of their layouts after them.
    assert_eq!(notifications.marks[0], 2, "{notifications:?}");
    assert!(
        notifications.marked >= 2 && notifications.seen > notifications.marks[1],
        "{notifications:?}"
    );
    assert!(
        identities.marked >= 2 && identities.seen >= identities.marks[1] + 2,
        "{identities:?}"
    );
    for (layout, occurrence) in [
        (notification, 0),
        (notification, 1),
        (identity, identities.seen - 2),
        (identity, identities.seen - 1),
        (notification, notifications.seen - 1),
    ] {
        let (result, refused) = refuse_layout_during(layout, occurrence, construct);
        assert!(
            refused,
            "refusal reaches allocation {occurrence} of {layout:?}"
        );
        assert_eq!(
            result.err(),
            Some(AdmittedStorageError::Allocator { layout })
        );
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "every partial owner retires before its refund"
        );
        let retry = construct().unwrap();
        assert_eq!(budget.reserved_bytes(), required);
        drop(retry);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_snapshot_restore_successor_identity_refusal_retires_its_destination() {
    use crate::allocation_test_support::{refuse_layout_during, trace_layout_during};
    let identity = NextPublication::allocation_layout();
    let budget = AllocationBudget::new(1 << 20);
    let source = replacement_fixture(&budget);
    let snapshot = source.snapshot();
    let destination = AllocationBudget::new(1 << 20);
    let restore = || ReplacementStorage::try_from_snapshot_admitted(&snapshot, destination.clone());
    drop(restore().unwrap());
    let (restored, trace) = trace_layout_during(identity, restore);
    drop(restored.unwrap());
    // Admissions: both maps, both writers, then the first row copy. The writers'
    // successor identity is the last allocation of its layout before that copy.
    assert!(
        trace.marked >= 5 && trace.marks[4] > trace.marks[3],
        "{trace:?}"
    );
    let (result, refused) = refuse_layout_during(identity, trace.marks[4] - 1, restore);
    assert!(refused, "refusal reaches the writer successor identity");
    assert_eq!(
        result.err(),
        Some(AdmittedStorageError::Allocator { layout: identity })
    );
    assert_eq!(
        destination.reserved_bytes(),
        0,
        "both writers and the partial destination retire before refund"
    );
    let retry = restore().unwrap();
    assert_eq!(
        replacement_rows(&retry.view()),
        replacement_rows(snapshot.current())
    );
    drop(retry);
    assert_eq!(destination.reserved_bytes(), 0);
    drop(snapshot);
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn admitted_block_successor_identity_refusal_releases_both_writers_for_retry() {
    use crate::allocation_test_support::{refuse_layout_during, trace_layout_during};
    let identity = NextPublication::allocation_layout();
    for replacement in [false, true] {
        let calls = std::cell::Cell::new(0_usize);
        let run = |storage: &ReplacementStorage| {
            let operation = |_: &mut Block<'_, _, _, _>| {
                calls.set(calls.get() + 1);
                Ok::<_, ()>(())
            };
            if replacement {
                storage.try_with_admitted_replacement(operation)
            } else {
                storage.try_with_admitted_block(operation)
            }
        };
        let traced_budget = AllocationBudget::new(1 << 20);
        let traced = replacement_fixture(&traced_budget);
        let (result, trace) = trace_layout_during(identity, || run(&traced));
        result.unwrap();
        // Admissions: both writers, then the block contents. The successor
        // identity is the last allocation of its layout before the contents.
        assert!(
            trace.marked >= 3 && trace.marks[2] > trace.marks[1],
            "{trace:?}"
        );
        let budget = AllocationBudget::new(1 << 20);
        let storage = replacement_fixture(&budget);
        let rows = replacement_rows(&storage.view());
        let before = budget.reserved_bytes();
        calls.set(0);
        let (result, refused) =
            refuse_layout_during(identity, trace.marks[2] - 1, || run(&storage));
        assert!(refused, "refusal reaches the block successor identity");
        assert!(
            matches!(
                result,
                Err(AdmittedBlockError::Admission(AdmittedStorageError::Allocator { layout }))
                    if layout == identity
            ),
            "{result:?}"
        );
        assert_eq!(calls.get(), 0, "no callback runs without its successor");
        assert_eq!(budget.reserved_bytes(), before);
        assert_both_writers_free(&storage, &budget);
        assert_eq!(budget.reserved_bytes(), before);
        assert_eq!(replacement_rows(&storage.view()), rows);
        run(&storage).unwrap();
        assert_eq!(calls.get(), 1);
    }
}
