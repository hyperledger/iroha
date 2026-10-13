//! Complete World visibility and terminal abandonment precede original callbacks.
use super::*;
use mv::PublicationPreparationError;
use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

struct ObserveTail {
    target: Arc<World>,
    calls: AtomicUsize,
    tail: AtomicU64,
}
impl Wake for ObserveTail {
    fn wake(self: Arc<Self>) {
        // This EBR Cell read is nonblocking. No State/World view or writer is
        // acquired, and no assertion or wait occurs inside the original Wake.
        self.tail.store(
            self.target
                .soradns_last_publish_ms
                .view()
                .get()
                .unwrap_or(0),
            Ordering::SeqCst,
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn check_world_publication(replacement: bool, completion: u8) {
    let waiter_pool = iroha_allocation::AllocationBudget::new(
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&waiter_pool);
    let world = Arc::new(World::default());
    let mut baseline = world.block();
    *baseline.soradns_last_publish_ms.get_mut() = Some(17);
    baseline.commit();
    let probe = world
        .executor_data_model
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let mut original = if replacement {
        world.block_and_revert()
    } else {
        world.block()
    };
    *original.soradns_last_publish_ms.get_mut() = Some(99);
    let (probe, error, cleanup) = probe
        .try_prepare_publication(&world.executor_data_model, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("the actual World owns this writer");
    let PublicationPreparationError::Busy(wait) = error else {
        panic!("actual original writer must be Busy")
    };
    let callback = Arc::new(ObserveTail {
        target: Arc::clone(&world),
        calls: AtomicUsize::new(0),
        tail: AtomicU64::new(0),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let mut future = wait.clone().wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    match completion {
        0 => original.commit(),
        1 => {
            original.prepare_publication();
            mv::BlockRetirement::release_writers(&mut original);
            assert_eq!(callback.calls.load(Ordering::SeqCst), 0);
            assert!(
                Pin::new(&mut future)
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            drop(original);
        }
        2 => {
            assert!(
                catch_unwind(AssertUnwindSafe(move || {
                    let mut original = original;
                    original.prepare_publication();
                    panic!("an enclosing preparation failed with every World field retained");
                }))
                .is_err()
            );
        }
        3 => {
            assert!(catch_unwind(AssertUnwindSafe(|| original.publish_prepared())).is_err());
            assert_eq!(callback.calls.load(Ordering::SeqCst), 0);
            drop(original);
        }
        _ => unreachable!(),
    }
    drop(cleanup);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        callback.tail.load(Ordering::SeqCst),
        if completion == 0 { 99 } else { 17 }
    );
    assert_eq!(
        world.soradns_last_publish_ms.view().get(),
        &Some(if completion == 0 { 99 } else { 17 })
    );
    assert_eq!(wait.is_poisoned(), completion == 2);
    if completion == 0 {
        assert!(!probe.matches_current(&world.executor_data_model));
    } else if completion != 2 {
        assert!(probe.matches_current(&world.executor_data_model));
    }
}

#[test]
fn successful_world_commit_notifies_only_after_its_original_tail_is_visible() {
    for replacement in [false, true] {
        check_world_publication(replacement, 0);
    }
}
#[test]
fn prepared_world_release_retains_callback_and_unchanged_committed_tail() {
    for replacement in [false, true] {
        check_world_publication(replacement, 1);
    }
}
#[test]
fn prepared_world_unwind_retains_every_original_until_joint_release() {
    for replacement in [false, true] {
        check_world_publication(replacement, 2);
    }
}
#[test]
fn world_refuses_publication_before_complete_original_preparation() {
    for replacement in [false, true] {
        check_world_publication(replacement, 3);
    }
}

#[test]
fn world_publication_handle_keeps_one_allocation_across_moves_and_phases() {
    // The handle contains the publication phase, the actual budgeted
    // OriginalWorldFields control owner and the original deferred-refund scope.
    // The fields owner retains its backing charge and initialization cursor.
    // Account for exactly these three declared fields and their alignment; the
    // complete World inventory must remain in the same external allocation.
    let handle_layout =
        std::alloc::Layout::new::<Option<world_acquisition::OriginalWorldFields<'_>>>()
            .extend(std::alloc::Layout::new::<block_field::AggregatePublication>())
            .expect("original World fields and publication layout")
            .0
            .extend(std::alloc::Layout::new::<
                iroha_allocation::OwnedAllocationScope,
            >())
            .expect("original World deferred-refund scope layout")
            .0
            .pad_to_align();
    assert_eq!(std::mem::size_of::<WorldBlock<'_>>(), handle_layout.size());
    assert_eq!(
        std::mem::align_of::<WorldBlock<'_>>(),
        handle_layout.align()
    );
    assert!(std::mem::size_of::<WorldBlockFields<'_>>() > std::mem::size_of::<WorldBlock<'_>>());
    let world = World::default();
    let block = world.block();
    let WorldBlock {
        publication: _,
        fields: _,
        _refund_scope: _,
    } = &block;
    let original = std::ptr::from_ref(block.fields.as_deref().unwrap());
    // Move the complete original through an enclosing owner and retain exactly
    // the same allocation while both native preparation and publication run.
    let mut enclosing = Some(block);
    let mut block = enclosing.take().unwrap();
    assert_eq!(
        std::ptr::from_ref(block.fields.as_deref().unwrap()),
        original
    );
    block.prepare_publication();
    assert_eq!(
        std::ptr::from_ref(block.fields.as_deref().unwrap()),
        original
    );
    block.publish_prepared();
    assert_eq!(
        std::ptr::from_ref(block.fields.as_deref().unwrap()),
        original
    );
    mv::BlockRetirement::release_writers(&mut block);
    assert_eq!(
        std::ptr::from_ref(block.fields.as_deref().unwrap()),
        original
    );
}

#[test]
fn world_ordinary_and_replacement_publication_fit_two_mebibyte_stack() {
    std::thread::Builder::new()
        .name("original-world-publication-stack".to_owned())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            for replacement in [false, true] {
                for completion in 0..=2 {
                    check_world_publication(replacement, completion);
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
