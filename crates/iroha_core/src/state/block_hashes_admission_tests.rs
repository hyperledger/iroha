//! Finite history admission precedes execution and retains actual allocation custody.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

fn hash(value: u8) -> HashOf<BlockHeader> {
    HashOf::from_untyped_unchecked(Hash::prehashed([value; Hash::LENGTH]))
}
fn empty(limit: usize) -> BlockHashes {
    BlockHashes::try_new(std::iter::empty(), AllocationBudget::new(limit)).unwrap()
}
fn demand(owner: &BlockHashes, replacement: bool) -> (usize, usize) {
    let mut observed = None;
    let count = owner.committed_height();
    let key = if replacement {
        count.saturating_sub(1)
    } else {
        count
    };
    let result = owner.map().unwrap().try_insert_admitted_with_footprint(
        key,
        hash(91),
        |existing, additional| {
            observed = Some((
                existing.bytes() + ChargedBlockHashMap::layout().size(),
                additional.bytes(),
            ));
            Err::<BlockHashPolicy, _>(())
        },
    );
    assert!(matches!(
        result,
        Err((_, concread::bptree::MapAdmissionError::Refused(())))
    ));
    observed.unwrap()
}
fn publish(mut block: BlockHashesBlock<'_>, value: u8) {
    block.push(hash(value));
    block.commit_for_tests();
}

#[test]
fn successor_reader_contention_wakes_from_original_reader_release() {
    let owner = empty(1024 * 1024);
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let mut release_slot_1 = crate::unit_test_support::release_registration(&owner.budget);
    let map = owner.map().unwrap();
    let held = map
        .try_write_admitted(|demand| {
            owner
                .budget
                .try_reserve_bytes(demand.bytes())
                .map(BlockHashPolicy)
        })
        .unwrap()
        .prepare_commit();
    let expected = map.observe_reader_release();
    let writer_release = owner.released.observe();
    let mut writer_wait =
        std::pin::pin!(writer_release.clone().wait_for_release(&mut release_slot_0));
    let error = match owner.try_next_block(false) {
        Err(error) => error,
        Ok(_) => panic!("actual reader mutex is held"),
    };
    let BlockHashAdmissionError::Busy(wait) = error else {
        panic!("reader contention must retain its original wait");
    };
    assert_eq!(wait, expected);
    assert_ne!(wait, writer_release);
    let mut wait = std::pin::pin!(wait.wait_for_release(&mut release_slot_1));
    let mut context = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    assert!(writer_wait.as_mut().poll(&mut context).is_pending());
    drop(held);
    assert!(wait.as_mut().poll(&mut context).is_ready());
    assert!(
        writer_wait.as_mut().poll(&mut context).is_pending(),
        "no Core writer release was needed"
    );
    publish(owner.try_next_block(false).unwrap(), 1);
    assert_eq!(owner.view().last(), Some(&hash(1)));
}

#[test]
fn successor_admission_signals_only_actual_writer_after_unlock() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };
    struct CheckUnlocked {
        owner: Arc<BlockHashes>,
        wakes: AtomicUsize,
    }
    impl Wake for CheckUnlocked {
        fn wake(self: Arc<Self>) {
            let _actual = self
                .owner
                .map()
                .unwrap()
                .try_acquire_writer()
                .expect("successor notification ran while writer remained locked");
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    let owner = Arc::new(empty(1024 * 1024));
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let mut release_slot_1 = crate::unit_test_support::release_registration(&owner.budget);
    let mut release_slot_2 = crate::unit_test_support::release_registration(&owner.budget);
    let counter = Arc::new(CheckUnlocked {
        owner: Arc::clone(&owner),
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut wait = std::pin::pin!(
        owner
            .released
            .observe()
            .wait_for_release(&mut release_slot_0)
    );
    assert!(wait.as_mut().poll(&mut context).is_pending());
    let held = owner
        .released
        .poisoning_guard(owner.map().unwrap().try_acquire_writer().unwrap());
    assert!(matches!(
        owner.try_next_block(false),
        Err(BlockHashAdmissionError::Busy(_))
    ));
    assert_eq!(
        counter.wakes.load(Ordering::SeqCst),
        0,
        "contention does not fabricate a release"
    );
    drop(held);
    assert_eq!(counter.wakes.load(Ordering::SeqCst), 1);

    let occupied = owner
        .budget
        .try_reserve_bytes(owner.budget.limit_bytes() - owner.budget.reserved_bytes())
        .unwrap();
    let mut wait = std::pin::pin!(
        owner
            .released
            .observe()
            .wait_for_release(&mut release_slot_1)
    );
    assert!(wait.as_mut().poll(&mut context).is_pending());
    assert!(matches!(
        owner.try_next_block(false),
        Err(BlockHashAdmissionError::Capacity(
            AllocationRefusal::Capacity { .. }
        ))
    ));
    assert_eq!(
        counter.wakes.load(Ordering::SeqCst),
        2,
        "admission refusal releases its real writer"
    );
    assert!(owner.view().is_empty());
    drop(occupied);

    let mut wait = std::pin::pin!(
        owner
            .released
            .observe()
            .wait_for_release(&mut release_slot_2)
    );
    assert!(wait.as_mut().poll(&mut context).is_pending());
    let block = owner.try_next_block(false).unwrap();
    assert_eq!(
        counter.wakes.load(Ordering::SeqCst),
        3,
        "successful detachment releases its real writer"
    );
    assert!(owner.view().is_empty());
    publish(block, 1);
}

#[test]
fn current_tree_plus_successor_is_a_permanent_bound_not_a_refund_wait() {
    let calibration = empty(1024 * 1024);
    let (existing, additional) = demand(&calibration, false);
    assert_eq!(calibration.budget.reserved_bytes(), existing);
    let owner = empty(existing + additional - 1);
    assert!(
        matches!(owner.try_next_block(false), Err(BlockHashAdmissionError::Capacity(
        AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes }
    )) if requested_bytes == existing + additional && limit_bytes == requested_bytes - 1)
    );
    assert_eq!(owner.budget.reserved_bytes(), existing);
    assert!(owner.view().is_empty());
    let exact = empty(existing + additional);
    publish(exact.try_next_block(false).unwrap(), 1);
    assert_eq!(exact.view().last(), Some(&hash(1)));
}

#[test]
fn private_successor_refund_wakes_original_capacity_wait() {
    let calibration = empty(1024 * 1024);
    let (existing, additional) = demand(&calibration, false);
    let owner = empty(
        existing
            + additional
            + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let original = owner.try_next_block(false).unwrap();
    let wait = match owner.try_next_block(false) {
        Err(BlockHashAdmissionError::Capacity(AllocationRefusal::Capacity { release, .. })) => {
            release
        }
        _ => panic!("original private successor must hold its exact finite credits"),
    };
    let mut future = std::pin::pin!(wait.wait_for_release(&mut release_slot_0));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    drop(original);
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(())
    ));
    publish(owner.try_next_block(false).unwrap(), 1);
}

#[test]
fn old_reader_refunds_only_when_its_original_generation_is_released() {
    let calibration = empty(1024 * 1024);
    let first = demand(&calibration, false);
    publish(calibration.try_next_block(false).unwrap(), 1);
    let second = demand(&calibration, false);
    let owner = empty(
        (first.0 + first.1).max(second.0 + second.1)
            + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut release_slot_0 = crate::unit_test_support::release_registration(&owner.budget);
    let old = owner.view();
    publish(owner.try_next_block(false).unwrap(), 1);
    assert!(old.is_empty());
    let wait = match owner.try_next_block(false) {
        Err(BlockHashAdmissionError::Capacity(AllocationRefusal::Capacity { release, .. })) => {
            release
        }
        _ => panic!("original old reader must retain its charged allocations"),
    };
    let mut future = std::pin::pin!(wait.wait_for_release(&mut release_slot_0));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    drop(old);
    assert!(future.as_mut().poll(&mut context).is_ready());
    publish(owner.try_next_block(false).unwrap(), 2);
    assert_eq!(
        owner.view().iter().copied().collect::<Vec<_>>(),
        [hash(1), hash(2)]
    );
}

#[test]
fn reserved_tip_is_hidden_and_cannot_publish_before_final_hash_staging() {
    let owner = BlockHashes::new(vec![hash(1), hash(2)]);
    for replacement in [false, true] {
        let mut block = owner.try_next_block(replacement).unwrap();
        let expected = if replacement {
            vec![hash(1)]
        } else {
            vec![hash(1), hash(2)]
        };
        assert_eq!(block.iter().copied().collect::<Vec<_>>(), expected);
        assert!(block.get(expected.len()).is_none());
        assert_eq!(
            block.transaction().iter().copied().collect::<Vec<_>>(),
            expected
        );
        assert!(!block.has_pending());
        let unfinished = block.detach();
        let (unfinished, refusal, _cleanup) = unfinished
            .try_prepare_publication(&owner, |_, _| -> Result<(), ()> {
                panic!("unfinished hash must refuse before installation admission")
            })
            .err()
            .expect("hidden tip cannot become visible");
        assert!(matches!(refusal, mv::PublicationPreparationError::Changed));
        assert_eq!(unfinished.pending().len(), 0);
        drop(unfinished);
        assert_eq!(
            owner.view().iter().copied().collect::<Vec<_>>(),
            [hash(1), hash(2)]
        );
    }
}

#[test]
fn prepaid_tip_fill_and_publication_need_no_further_pool_credit() {
    let owner = BlockHashes::new((0..64).map(hash).collect());
    for replacement in [false, true] {
        let old = owner.view();
        let expected_height = old.len() + usize::from(!replacement);
        let mut block = owner.try_next_block(replacement).unwrap();
        let outstanding = owner.budget.reserved_bytes();
        let remainder = owner
            .budget
            .try_reserve_bytes(owner.budget.limit_bytes() - outstanding)
            .unwrap();
        block.push(hash(111));
        let original_pointer = std::ptr::from_ref(block.last().unwrap());
        let detached = block.detach();
        let prepared = detached
            .try_prepare_publication(&owner, |_, _| Ok::<_, ()>(()))
            .unwrap_or_else(|_| panic!("all publication storage was prepaid"));
        let detached = prepared.abort().0;
        assert_eq!(
            std::ptr::from_ref(detached.last().unwrap()),
            original_pointer
        );
        let prepared = detached
            .try_prepare_publication(&owner, |_, _| Ok::<_, ()>(()))
            .unwrap_or_else(|_| panic!("abort retains original prepaid publication"));
        drop(prepared.publish());
        assert_eq!(owner.committed_height(), expected_height);
        assert_eq!(owner.view().last(), Some(&hash(111)));
        assert_eq!(
            std::ptr::from_ref(owner.view().last().unwrap()),
            original_pointer
        );
        drop(remainder);
        drop(old);
    }
}

#[test]
fn cold_history_owner_prepays_its_exact_shared_layout() {
    let control_bytes = ChargedBlockHashMap::layout().size();
    let insufficient = AllocationBudget::new(control_bytes - 1);
    let refused = BlockHashes::try_new(std::iter::empty(), insufficient.clone());
    assert!(matches!(
        refused,
        Err(BlockHashAdmissionError::Capacity(
            AllocationRefusal::ExceedsLimit {
                requested_bytes,
                ..
            }
        )) if requested_bytes == control_bytes
    ));
    assert_eq!(insufficient.reserved_bytes(), 0);

    let budget = AllocationBudget::new(1 << 20);
    let owner = BlockHashes::try_new(std::iter::empty(), budget.clone()).unwrap();
    assert!(
        budget.reserved_bytes() >= control_bytes,
        "the original owner retains its prepaid shared-allocation charge"
    );
    assert_eq!(owner.committed_height(), 0);
}

#[test]
fn cold_construction_refusal_refunds_every_partially_built_owner() {
    for bytes in [1, 4096] {
        let budget = AllocationBudget::new(bytes);
        let result = BlockHashes::try_new(
            (0..100_000)
                .map(|i| hash(u8::try_from((i) & 0xff).expect("masked fixture byte fits u8"))),
            budget.clone(),
        );
        assert!(matches!(result, Err(BlockHashAdmissionError::Capacity(_))));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

fn configured_state() -> State {
    State::new_with_pre_genesis_nexus_for_testing(
        World::default(),
        iroha_config::parameters::actual::Nexus::default(),
        crate::query::store::LiveQueryStore::start_test(),
    )
}
fn fill_original_pool(state: &State) -> iroha_allocation::AllocationReservation {
    let original = state.kura.block_hash_history_budget();
    assert_eq!(
        original.reserved_bytes(),
        state.block_hashes.budget.reserved_bytes()
    );
    original
        .try_reserve_bytes(original.limit_bytes() - original.reserved_bytes())
        .unwrap()
}

#[test]
fn state_refuses_before_world_acquisition_and_before_either_start_stage() {
    let state = configured_state();
    let occupied = fill_original_pool(&state);
    let world = state.world.block();
    let header = BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0);
    let result = state.block_with_owned_start_stages(
        header,
        |_| -> Result<(), ()> { panic!("pristine stage ran before admission") },
        |_, ()| -> Result<(), ()> { panic!("after-start stage ran before admission") },
    );
    let error = match result {
        Err(StateBlockStartError::History(error)) => error,
        _ => panic!("original configured pool must refuse before waiting for World"),
    };
    assert!(error.release_wait().is_some());
    drop(world);
    drop(occupied);
    let block = state.try_block(header).unwrap();
    assert!(block.start_of_block_effects_applied);
    assert_eq!(block.block_hashes.len(), 0);
    drop(block);
    assert_eq!(state.committed_height(), 0);
}

#[test]
fn replacement_capacity_refusal_preserves_all_da_indexes_and_durable_journal() {
    let state = configured_state();
    publish(state.block_hashes.try_next_block(false).unwrap(), 1);
    state
        .da_shard_cursors
        .write()
        .mark_lanes_canonically_reset(&BTreeSet::from([LaneId::new(0)]), 1);
    state.persist_da_shard_cursor_journal();
    *state.da_indexes_hydrated.write() = Some(Ok(()));
    let snapshot = || {
        format!(
            "{:?}{:?}{:?}{:?}{:?}",
            state.da_commitments.read(),
            state.da_confidential_compute.read(),
            state.da_receipt_cursors.read(),
            state.da_shard_cursors.read(),
            state.da_pin_intents.read()
        )
    };
    let before = snapshot();
    let path = state.da_shard_cursor_journal_path();
    let durable = std::fs::read(&path).unwrap();
    let occupied = fill_original_pool(&state);
    let result = state.block_and_revert_with_pristine_stage(
        BlockHeader::new(NonZeroU64::MIN, None, None, 2, 0),
        |_| -> Result<(), ()> { panic!("replacement start ran before admission") },
    );
    assert!(matches!(
        result,
        Err(StateBlockStartError::History(
            BlockHashAdmissionError::Capacity(AllocationRefusal::Capacity { .. })
        ))
    ));
    assert_eq!(snapshot(), before);
    assert_eq!(std::fs::read(path).unwrap(), durable);
    assert_eq!(*state.da_indexes_hydrated.read(), Some(Ok(())));
    assert_eq!(state.block_hashes.view().last(), Some(&hash(1)));
    drop(occupied);
}

#[test]
fn empty_fast_history_is_read_only_and_uses_no_mutable_tree_credit() {
    let owner = BlockHashes::new_emergency_fast_empty();
    assert!(owner.view().is_empty());
    assert!(owner.try_view().unwrap().is_empty());
    assert_eq!(owner.committed_height(), 0);
    assert_eq!(owner.budget.reserved_bytes(), 0);
    assert_eq!(owner.budget.limit_bytes(), 0);
    assert!(matches!(
        owner.try_next_block(false),
        Err(BlockHashAdmissionError::ReadOnly)
    ));
    assert!(matches!(
        owner.try_next_block(true),
        Err(BlockHashAdmissionError::ReadOnly)
    ));
}

#[test]
fn only_releasable_local_refusals_expose_an_original_wait() {
    let notification = iroha_allocation::release::ReleaseNotification::default();
    let wait = notification.observe();
    assert_eq!(
        BlockHashAdmissionError::Busy(wait.clone()).release_wait(),
        Some(&wait)
    );
    assert_eq!(
        BlockHashAdmissionError::Changed(wait.clone()).release_wait(),
        Some(&wait)
    );
    for error in [
        BlockHashAdmissionError::ReadOnly,
        BlockHashAdmissionError::Poisoned,
        BlockHashAdmissionError::Capacity(AllocationRefusal::ExceedsLimit {
            requested_bytes: 2,
            limit_bytes: 1,
        }),
        BlockHashAdmissionError::Capacity(AllocationRefusal::DemandOverflow),
    ] {
        assert!(error.release_wait().is_none());
    }
    assert!(StateBlockStartError::Stage(()).release_wait().is_none());
    assert_eq!(
        StateBlockStartError::<()>::History(BlockHashAdmissionError::Busy(wait.clone()))
            .release_wait(),
        Some(&wait)
    );
}
