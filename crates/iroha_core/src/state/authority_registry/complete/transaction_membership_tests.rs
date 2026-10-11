//! Actual membership capture, original-pool custody and scoped proof controls.

use super::*;
use crate::state::authority_registry::leaf::CanonicalTableLeafSet;
use iroha_allocation::AllocationRefusal;
use iroha_crypto::Hash;
use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

type Key = HashOf<TransactionEntrypoint>;
fn key(n: u8) -> Key {
    Key::from_untyped_unchecked(Hash::new([n]))
}
fn commit(storage: &TransactionsStorage, height: usize, keys: &[Key]) {
    let mut block = storage.block();
    block.insert_block(
        keys.iter().copied().collect(),
        NonZeroUsize::new(height).unwrap(),
    );
    block.commit().unwrap();
}
fn limits() -> MembershipCaptureLimits {
    MembershipCaptureLimits {
        tables: LeafLimits {
            max_tables: 1,
            max_rows: 16,
            max_payload_bytes: 4096,
            max_ordered_table_bytes: 65536,
            max_streamed_value_bytes: 65536,
        },
        max_row_visits: 64,
        max_total_rows: 32,
        max_total_streamed_bytes: 131072,
        max_total_ordered_bytes: 131072,
    }
}
fn seeded() -> TransactionsStorage {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[key(1), key(2)]);
    commit(&storage, 2, &[key(2), key(3)]);
    storage
}
fn expected(
    table: &str,
    rows: &[(Key, u64)],
    budget: &AllocationBudget,
) -> CanonicalTablePairedSnapshot {
    CanonicalTableLeafSet::paired_table_from_rows(
        table,
        limits().tables,
        budget,
        rows.iter().map(|(k, v)| (k, v)),
    )
    .unwrap()
}

#[test]
fn pair_binds_shadowed_current_rollback_frontier_and_original_surface() {
    let storage = seeded();
    let budget = AllocationBudget::new(1 << 20);
    let captured = capture_from_storage(&storage, &budget, limits()).unwrap();
    assert_eq!(captured.frontier, 2);
    assert_eq!(captured.current.table_id(), CURRENT);
    assert_eq!(captured.rollback.table_id(), ROLLBACK);
    assert_eq!(captured.current.row_count(), 3);
    assert_eq!(captured.rollback.row_count(), 2);
    assert_eq!(
        captured.current.root(),
        expected(CURRENT, &[(key(3), 2), (key(1), 1), (key(2), 2)], &budget).root()
    );
    assert_eq!(
        captured.rollback.root(),
        expected(ROLLBACK, &[(key(2), 1), (key(1), 1)], &budget).root()
    );
    {
        let owner = storage.try_membership_observation().unwrap();
        assert_eq!(captured.original_surface, owner.publication_surface());
    }
    let reordered = TransactionsStorage::new();
    commit(&reordered, 1, &[key(2), key(1)]);
    commit(&reordered, 2, &[key(3), key(2)]);
    let other = capture_from_storage(&reordered, &budget, limits()).unwrap();
    assert_eq!(captured.current.root(), other.current.root());
    assert_eq!(captured.rollback.root(), other.rollback.root());
    assert_ne!(captured.original_surface, other.original_surface);
    drop(other);
    let old_root = captured.current.root();
    commit(&storage, 3, &[key(4)]);
    assert_ne!(
        captured.original_surface,
        storage.block().publication_surface()
    );
    assert_eq!(captured.current.root(), old_root);
    let proof = captured.current.prove_lookup(CURRENT, &key(2)).unwrap();
    assert!(
        CanonicalTableLeafSet::verify_paired_lookup(
            CURRENT,
            limits().tables,
            &old_root,
            &captured.current.ordered_root(),
            &key(2),
            &proof
        )
        .unwrap()
        .is_some()
    );
    assert!(
        CanonicalTableLeafSet::verify_paired_lookup(
            ROLLBACK,
            limits().tables,
            &captured.rollback.root(),
            &captured.rollback.ordered_root(),
            &key(2),
            &proof
        )
        .is_err()
    );
    assert_ne!(
        old_root,
        expected(CURRENT, &[(key(1), 1), (key(2), 1), (key(3), 2)], &budget).root()
    );
    assert_ne!(
        old_root,
        expected(CURRENT, &[(key(1), 1), (key(2), 2)], &budget).root()
    );
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn work_admission_precedes_allocation_and_pair_bounds_discard_every_prefix() {
    let storage = seeded();
    let zero = AllocationBudget::new(0);
    let held = storage.block();
    assert!(matches!(
        capture_from_storage(&storage, &zero, limits()),
        Err(MembershipCaptureError::Acquisition(
            crate::state::storage_transactions::MembershipAdmissionError::Busy(_)
        ))
    ));
    assert_eq!(zero.peak_reserved_bytes(), 0);
    drop(held);

    assert!(matches!(
        capture_from_storage(
            &storage,
            &zero,
            MembershipCaptureLimits {
                max_row_visits: 5,
                ..limits()
            }
        ),
        Err(MembershipCaptureError::Authority(
            TransactionMembershipAuthorityError::TraversalRefused {
                required: 6,
                limit: 5
            }
        ))
    ));
    assert_eq!(zero.reserved_bytes(), 0);
    let budget = AllocationBudget::new(1 << 20);
    for policy in [
        MembershipCaptureLimits {
            max_total_rows: 4,
            ..limits()
        },
        MembershipCaptureLimits {
            max_total_streamed_bytes: 1,
            ..limits()
        },
        MembershipCaptureLimits {
            max_total_ordered_bytes: 1,
            ..limits()
        },
        MembershipCaptureLimits {
            tables: LeafLimits {
                max_rows: 2,
                ..limits().tables
            },
            ..limits()
        },
    ] {
        assert!(capture_from_storage(&storage, &budget, policy).is_err());
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(storage.try_membership_observation().is_ok());
    }
    let empty = capture_from_storage(
        &TransactionsStorage::new(),
        &budget,
        MembershipCaptureLimits {
            max_row_visits: 0,
            max_total_rows: 0,
            max_total_streamed_bytes: 0,
            max_total_ordered_bytes: 0,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(empty.frontier, 0);
    assert_eq!(empty.current.row_count() + empty.rollback.row_count(), 0);
}

struct UnlockedWake {
    storage: Arc<TransactionsStorage>,
    wakes: AtomicUsize,
}
impl Wake for UnlockedWake {
    fn wake(self: Arc<Self>) {
        assert!(
            self.storage.try_membership_observation().is_ok(),
            "original physical writer released before refund callback"
        );
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn inner_refunds_notify_only_after_original_writer_unlock_on_success_error_and_unwind() {
    for mode in 0..3 {
        let storage = Arc::new(seeded());
        let budget = AllocationBudget::new(1 << 20);
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let wakes = Arc::new(UnlockedWake {
            storage: storage.clone(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut waiting = None;
        let policy = if mode == 1 {
            MembershipCaptureLimits {
                max_total_rows: 4,
                ..limits()
            }
        } else {
            limits()
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capture_observed(&storage, &budget, policy, |_, pool| {
                if waiting.is_none() {
                    let AllocationRefusal::Capacity { release, .. } =
                        pool.try_reserve_bytes(pool.limit_bytes()).unwrap_err()
                    else {
                        panic!("encoded row retains original capacity")
                    };
                    assert!(registration.poll_wait(&release, &mut context).is_pending());
                    waiting = Some(release);
                    if mode == 2 {
                        panic!("unwind after funded row")
                    }
                }
                assert_eq!(wakes.wakes.load(Ordering::SeqCst), 0);
            })
        }));
        match mode {
            0 => drop(result.unwrap().unwrap()),
            1 => assert!(matches!(
                result.unwrap(),
                Err(MembershipCaptureError::AggregateLimit)
            )),
            _ => assert!(result.is_err()),
        }
        assert!(wakes.wakes.load(Ordering::SeqCst) > 0);
        assert!(
            registration
                .poll_wait(waiting.as_ref().unwrap(), &mut context)
                .is_ready()
        );
        assert_eq!(
            budget.reserved_bytes(),
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size()
        );
        drop(registration);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn occupied_original_pool_returns_original_release_and_retry_keeps_old_borrowers() {
    let storage = Arc::new(seeded());
    let budget = AllocationBudget::new(1 << 20);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let Err(MembershipCaptureError::Table(LeafError::Admission(AllocationRefusal::Capacity {
        release,
        ..
    }))) = capture_from_storage(&storage, &budget, limits())
    else {
        panic!("exact local capacity")
    };
    let AllocationRefusal::Capacity {
        release: expected, ..
    } = budget.try_reserve_bytes(1).unwrap_err()
    else {
        panic!()
    };
    assert_eq!(release, expected);
    let wakes = Arc::new(UnlockedWake {
        storage: storage.clone(),
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    let mut waiting = release.wait_for_release(&mut registration);
    assert!(Pin::new(&mut waiting).poll(&mut context).is_pending());
    let unrelated = AllocationBudget::new(1);
    drop(unrelated.try_reserve_bytes(1).unwrap());
    assert_eq!(wakes.wakes.load(Ordering::SeqCst), 0);
    drop(occupied);
    assert!(Pin::new(&mut waiting).poll(&mut context).is_ready());
    drop(waiting);
    drop(registration);
    let retained = capture_from_storage(&storage, &budget, limits()).unwrap();
    let bytes = budget.reserved_bytes();
    budget.set_limit_bytes(0);
    assert!(capture_from_storage(&storage, &budget, limits()).is_err());
    assert_eq!(budget.reserved_bytes(), bytes);
    assert_eq!(retained.current.row_count(), 3);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn state_adapter_uses_original_pool_and_retries_odd_publication_generation() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    commit(&state.transactions, 1, &[key(1)]);
    let pool = state.ivm_execution_budget();
    let before = pool.reserved_bytes();
    let result = capture_transaction_membership_tables_once(&state, limits())
        .unwrap()
        .unwrap();
    assert_eq!(result.frontier, 1);
    assert!(pool.reserved_bytes() > before);
    drop(result);
    assert_eq!(pool.reserved_bytes(), before);
    let mut publication = state.state_view_publication();
    let guard = publication.begin();
    assert!(
        capture_transaction_membership_tables_once(&state, limits())
            .unwrap()
            .is_none()
    );
    drop(guard);
    assert!(
        capture_transaction_membership_tables_once(&state, limits())
            .unwrap()
            .is_some()
    );
}

#[test]
fn second_finalization_refusal_discards_finished_current_and_preserves_original_pool() {
    let storage = seeded();
    let pool = AllocationBudget::new(1 << 20);
    let mut expected_release = None;
    let result = capture_observed(&storage, &pool, limits(), |progress, budget| {
        if progress == CaptureProgress::CurrentFinished {
            assert!(budget.reserved_bytes() > 0);
            budget.set_limit_bytes(budget.reserved_bytes());
            let AllocationRefusal::Capacity { release, .. } =
                budget.try_reserve_bytes(1).unwrap_err()
            else {
                panic!("original occupied pool")
            };
            expected_release = Some(release);
        }
    });
    let Err(MembershipCaptureError::Table(LeafError::OrderedRange(
        iroha_crypto::NoritoKeyRangeError::Admission(AllocationRefusal::Capacity {
            release, ..
        }),
    ))) = result
    else {
        panic!("rollback owner needs original capacity after current finished")
    };
    assert_eq!(Some(release), expected_release);
    assert_eq!(pool.reserved_bytes(), 0);
    assert!(storage.try_membership_observation().is_ok());
    pool.set_limit_bytes(1 << 20);
    assert!(capture_from_storage(&storage, &pool, limits()).is_ok());
}

#[test]
fn pair_exact_stream_and_ordered_limits_cover_both_sides_before_work() {
    let storage = seeded();
    let pool = AllocationBudget::new(1 << 20);
    let per_value = 2 * u64::try_from(norito::codec::encode_adaptive(&1_u64).len()).unwrap();
    let per_row = 2 * norito::codec::encode_adaptive(&key(1)).len() + 3 * Hash::LENGTH;
    let exact_stream = 5 * per_value;
    let exact_ordered = 5 * per_row + (7 + 3) * Hash::LENGTH;
    for (stream, ordered, succeeds) in [
        (exact_stream - 1, exact_ordered, false),
        (exact_stream, exact_ordered - 1, false),
        (exact_stream, exact_ordered, true),
    ] {
        let result = capture_from_storage(
            &storage,
            &pool,
            MembershipCaptureLimits {
                max_total_streamed_bytes: stream,
                max_total_ordered_bytes: ordered,
                ..limits()
            },
        );
        if succeeds {
            let pair = result.unwrap();
            assert_eq!(pair.current.row_count() + pair.rollback.row_count(), 5);
            drop(pair);
        } else {
            assert!(matches!(
                result,
                Err(MembershipCaptureError::AggregateLimit)
            ));
        }
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(storage.try_membership_observation().is_ok());
    }
}

fn original_state() -> State {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::World};
    let state = State::new_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    commit(&state.transactions, 1, &[key(1)]);
    commit(&state.transactions, 2, &[key(2)]);
    state
}

fn original_header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(3).unwrap(),
        None,
        None,
        1,
        0,
    )
}

fn freeze_membership_fixture(block: &mut crate::state::StateBlock<'_>) {
    block.transactions.insert_block(
        [key(3)].into_iter().collect(),
        NonZeroUsize::new(3).unwrap(),
    );
    block.transactions.try_prepare_publication().unwrap();
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
}

fn original_work() -> MembershipWorkLimits {
    MembershipWorkLimits {
        max_row_visits: limits().max_row_visits,
        max_streamed_bytes: limits().max_total_streamed_bytes,
        max_ordered_bytes: limits().max_total_ordered_bytes,
    }
}

#[test]
fn original_prepared_membership_reads_staged_pair_without_a_committed_observation() {
    let state = original_state();
    let pool = state.ivm_execution_budget();
    let committed = capture_from_storage(&state.transactions, &pool, limits()).unwrap();
    assert_eq!(committed.frontier, 2);
    let committed_root = committed.current.root();
    drop(committed);
    let mut refunds = pool.deferred_refund_batch();
    let mut block = state.block(original_header());
    freeze_membership_fixture(&mut block);
    let baseline = pool.reserved_bytes();
    assert!(matches!(
        capture_from_storage(&state.transactions, &pool, limits()),
        Err(MembershipCaptureError::Acquisition(
            crate::state::storage_transactions::MembershipAdmissionError::Busy(_)
        ))
    ));
    let captured = refunds
        .with_scope(|scope| {
            super::super::table_capture::frozen::capture_original_membership_once(
                &block,
                scope,
                limits().tables,
                original_work(),
                limits().max_total_rows,
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(captured.frontier, 3);
    assert!(captured.matches_original_writer(&block.transactions));
    assert_ne!(committed_root, captured.current.root());
    let oracle = AllocationBudget::new(1 << 20);
    assert_eq!(
        captured.current.root(),
        expected(CURRENT, &[(key(1), 1), (key(2), 2), (key(3), 3)], &oracle).root()
    );
    assert_eq!(
        captured.rollback.root(),
        expected(ROLLBACK, &[(key(1), 1), (key(2), 2)], &oracle).root()
    );
    assert!(pool.reserved_bytes() > baseline);
    let (current, rollback, companion) = captured.into_group(0);
    assert_eq!(companion.frontier(), 3);
    assert_eq!(
        companion.original_surface(),
        &block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .publication_surface()
    );
    let mut nodes = [current, rollback];
    assert!(companion.matches_nodes(&nodes));
    assert!(!companion.matches_nodes(&nodes[..1]));
    nodes.swap(0, 1);
    assert!(!companion.matches_nodes(&nodes));
    nodes.swap(0, 1);
    assert!(companion.matches_nodes(&nodes));
    refunds.with_scope(|_| {
        drop(nodes);
        drop(companion);
    });
    assert_eq!(pool.reserved_bytes(), baseline);
    refunds.with_scope(|_| drop(block));
    drop(refunds);
}

#[test]
fn original_membership_refusal_retries_same_source_and_refunds_only_actual_nodes() {
    let state = original_state();
    let pool = state.ivm_execution_budget();
    let mut refunds = pool.deferred_refund_batch();
    let mut block = state.block(original_header());
    freeze_membership_fixture(&mut block);
    let identity = block
        .transactions
        .prepared_membership_writer()
        .unwrap()
        .publication_surface();
    let baseline = pool.reserved_bytes();
    let limit = pool.limit_bytes();
    let occupied = pool.try_reserve_bytes(limit - baseline).unwrap();
    let peak = pool.peak_reserved_bytes();
    let Err(error) = refunds.with_scope(|scope| {
        super::super::table_capture::frozen::capture_original_membership_once(
            &block,
            scope,
            limits().tables,
            original_work(),
            limits().max_total_rows,
        )
    }) else {
        panic!("occupied original pool must preserve its physical refusal")
    };
    let Some(MembershipCaptureError::Table(LeafError::Admission(refusal))) =
        error.membership_error()
    else {
        panic!("original typed capacity cause")
    };
    let AllocationRefusal::Capacity { release, .. } = refusal else {
        panic!("original capacity")
    };
    let AllocationRefusal::Capacity {
        release: actual, ..
    } = pool.try_reserve_bytes(1).unwrap_err()
    else {
        panic!("same occupied pool")
    };
    assert_eq!(*release, actual);
    assert_eq!(pool.peak_reserved_bytes(), peak);
    assert_eq!(
        identity,
        block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .publication_surface()
    );
    drop(occupied);
    let failed = refunds.with_scope(|scope| {
        capture_original_membership_group_once(&block, scope, limits().tables, original_work(), 1)
    });
    assert!(matches!(
        failed,
        Err(MembershipCaptureError::AggregateLimit)
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    assert_eq!(
        identity,
        block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .publication_surface()
    );
    let retained = refunds
        .with_scope(|scope| {
            capture_original_membership_group_once(
                &block,
                scope,
                limits().tables,
                original_work(),
                limits().max_total_rows,
            )
        })
        .unwrap()
        .unwrap();
    assert!(retained.matches_original_writer(&block.transactions));
    let actual_bytes = pool.reserved_bytes();
    assert!(actual_bytes > baseline);
    pool.set_limit_bytes(0);
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    limits().max_total_rows,
                )
            })
            .is_err()
    );
    assert_eq!(pool.reserved_bytes(), actual_bytes);
    assert_eq!(retained.current.row_count(), 3);
    refunds.with_scope(|_| drop(retained));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(limit);
    refunds.with_scope(|_| drop(block));
    drop(refunds);
}

#[test]
fn original_membership_scope_partial_foreign_and_released_owners_refuse() {
    use crate::state::storage_transactions::TransactionsBlockField;
    let state = original_state();
    let foreign = original_state();
    let pool = state.ivm_execution_budget();
    let mut refunds = pool.deferred_refund_batch();
    let mut block = state.block(original_header());
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    32,
                )
            })
            .unwrap()
            .is_none()
    );
    block.transactions.insert_block(
        [key(3)].into_iter().collect(),
        NonZeroUsize::new(3).unwrap(),
    );
    block.world.begin_freeze();
    block.world.finish_freeze();
    block.world.retire_frozen_cleanup();
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    32,
                )
            })
            .unwrap()
            .is_none()
    );
    block.transactions.try_prepare_publication().unwrap();
    let other_pool = AllocationBudget::new(pool.limit_bytes());
    let mut other_refunds = other_pool.deferred_refund_batch();
    let peak = pool.peak_reserved_bytes();
    assert!(matches!(
        other_refunds.with_scope(|scope| {
            capture_original_membership_group_once(
                &block,
                scope,
                limits().tables,
                original_work(),
                32,
            )
        }),
        Err(MembershipCaptureError::ForeignRefundScope)
    ));
    assert_eq!(pool.peak_reserved_bytes(), peak);
    let original = refunds
        .with_scope(|scope| {
            capture_original_membership_group_once(
                &block,
                scope,
                limits().tables,
                original_work(),
                32,
            )
        })
        .unwrap()
        .unwrap();
    let mut substituted = TransactionsBlockField::new(foreign.transactions.block());
    substituted.insert_block(
        [key(3)].into_iter().collect(),
        NonZeroUsize::new(3).unwrap(),
    );
    substituted.try_prepare_publication().unwrap();
    let held = std::mem::replace(&mut block.transactions, substituted);
    assert!(!original.matches_original_writer(&block.transactions));
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    32,
                )
            })
            .unwrap()
            .is_none()
    );
    let foreign_field = std::mem::replace(&mut block.transactions, held);
    assert!(original.matches_original_writer(&block.transactions));
    block.transactions.release_writers();
    assert!(!original.matches_original_writer(&block.transactions));
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    32,
                )
            })
            .unwrap()
            .is_none()
    );
    // Physical release retains the original predecessor loan until its owner
    // retires. Keep the existing foreign field as a temporary slot while the
    // released original field drops under its original refund scope.
    let released_field = std::mem::replace(&mut block.transactions, foreign_field);
    refunds.with_scope(|_| drop(released_field));
    // Same storage and original pool are insufficient when a field was acquired
    // in replacement mode while its actual frozen World is ordinary.
    let mut wrong_mode = TransactionsBlockField::new(state.transactions.block_and_revert());
    wrong_mode.insert_block(
        [key(3)].into_iter().collect(),
        NonZeroUsize::new(2).unwrap(),
    );
    wrong_mode.try_prepare_publication().unwrap();
    let foreign_field = std::mem::replace(&mut block.transactions, wrong_mode);
    assert!(
        block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .belongs_to(&state.transactions)
    );
    assert_eq!(
        block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .mode(),
        mv::BlockMode::Replace
    );
    assert!(
        refunds
            .with_scope(|scope| {
                capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    32,
                )
            })
            .unwrap()
            .is_none()
    );
    refunds.with_scope(|_| {
        drop(original);
        drop(block);
        drop(foreign_field);
    });
    drop(refunds);
}

struct OriginalStateWake {
    state: Arc<State>,
    wakes: AtomicUsize,
    busy: AtomicUsize,
}

impl Wake for OriginalStateWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let observation = self.state.transactions.try_membership_observation();
        self.busy
            .fetch_add(usize::from(observation.is_err()), Ordering::SeqCst);
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn original_publisher_refund_batch_keeps_success_error_and_unwind_wakes_after_writer_retirement() {
    for mode in 0..3 {
        let state = Arc::new(original_state());
        let pool = state.ivm_execution_budget();
        let mut block = state.block(original_header());
        freeze_membership_fixture(&mut block);
        let original = block
            .transactions
            .prepared_membership_writer()
            .unwrap()
            .publication_surface();
        let mut registration = crate::unit_test_support::release_registration(&pool);
        let probe = Arc::new(OriginalStateWake {
            state: state.clone(),
            wakes: AtomicUsize::new(0),
            busy: AtomicUsize::new(0),
        });
        let waker = Waker::from(probe.clone());
        let occupied = pool
            .try_reserve_bytes(pool.limit_bytes() - pool.reserved_bytes())
            .unwrap();
        let AllocationRefusal::Capacity { release, .. } = pool.try_reserve_bytes(1).unwrap_err()
        else {
            panic!("actual occupied original pool")
        };
        assert!(
            registration
                .poll_wait(&release, &mut Context::from_waker(&waker))
                .is_pending()
        );
        let mut refunds = pool.deferred_refund_batch();
        refunds.with_scope(|_| drop(occupied));
        let baseline = pool.reserved_bytes();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            refunds.with_scope(|scope| {
                let captured = capture_original_membership_group_once(
                    &block,
                    scope,
                    limits().tables,
                    original_work(),
                    if mode == 1 {
                        1
                    } else {
                        limits().max_total_rows
                    },
                );
                if mode == 1 {
                    assert!(matches!(
                        captured,
                        Err(MembershipCaptureError::AggregateLimit)
                    ));
                } else {
                    let captured = captured.unwrap().unwrap();
                    assert!(captured.matches_original_writer(&block.transactions));
                    assert!(pool.reserved_bytes() > baseline);
                    if mode == 2 {
                        panic!("unwind after actual original pair capture")
                    }
                    drop(captured);
                }
            });
        }));
        assert_eq!(attempt.is_err(), mode == 2);
        assert_eq!(pool.reserved_bytes(), baseline);
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(
            original,
            block
                .transactions
                .prepared_membership_writer()
                .unwrap()
                .publication_surface()
        );
        refunds.with_scope(|_| drop(block));
        assert_eq!(probe.wakes.load(Ordering::SeqCst), 0);
        drop(refunds);
        assert!(probe.wakes.load(Ordering::SeqCst) > 0);
        assert_eq!(probe.busy.load(Ordering::SeqCst), 0);
        assert!(
            registration
                .poll_wait(&release, &mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        drop(registration);
    }
}
