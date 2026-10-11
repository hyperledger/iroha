//! Actual later-field failures retain every original physical participant.

use super::publication::{FieldRefusal, PreparedWorldField, WorldPublicationError};
use super::*;
use mv::PublicationPreparationError;
use std::task::{Context, Waker};

type AfterPrepare = Box<dyn FnMut(&World) + Send + Sync>;

struct FaultField {
    original: Box<dyn RetainedWorldField>,
    after_prepare: AfterPrepare,
}

struct PreparedFaultField<'target> {
    original: Box<dyn PreparedWorldField + 'target>,
    after_prepare: AfterPrepare,
    target: &'target World,
}

impl RetainedWorldField for FaultField {
    fn summary(&self) -> FieldSummary {
        self.original.summary()
    }
    fn matches_current(&self, target: &World) -> bool {
        self.original.matches_current(target)
    }
    fn publication_slot<'target>(
        self: Box<Self>,
        target: &'target World,
    ) -> Box<dyn PreparedWorldField + 'target> {
        Box::new(PreparedFaultField {
            original: self.original.publication_slot(target),
            after_prepare: self.after_prepare,
            target,
        })
    }
}

impl PreparedWorldField for PreparedFaultField<'_> {
    fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
        self.original.try_prepare()?;
        (self.after_prepare)(self.target);
        Ok(())
    }
    fn release(&mut self) {
        self.original.release();
    }

    fn release_for_recovery(&mut self) {
        self.original.release_for_recovery();
    }
    fn abort(&mut self) -> Box<dyn RetainedWorldField> {
        self.original.abort()
    }
    fn publish(&mut self) {
        self.original.publish();
    }
}

pub(in crate::state) fn after_last_preparation(
    original: &mut DetachedWorld<()>,
    action: impl FnMut(&World) + Send + Sync + 'static,
) {
    let last = original.fields.pop().expect("actual last World field");
    original.fields.push(Box::new(FaultField {
        original: last,
        after_prepare: Box::new(action),
    }));
}

pub(in crate::state) fn arm_first_release(
    original: DetachedWorld<()>,
    target: &World,
    waker: &Waker,
    mut registration: iroha_allocation::release::ReleaseRegistration,
) -> (
    iroha_allocation::release::ReleaseWait,
    iroha_allocation::release::ReleaseRegistration,
) {
    let (_, error, cleanup) = original
        .try_prepare_publication(target, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("actual earlier World writer is held");
    drop(cleanup);
    let WorldPublicationError::Field(FieldRefusal {
        cause: PublicationPreparationError::Busy(observation),
        ..
    }) = error
    else {
        panic!("actual first-field Busy observation");
    };
    assert!(
        registration
            .poll_wait(&observation, &mut Context::from_waker(waker))
            .is_pending()
    );
    (observation, registration)
}

// Each independent original field is probed so an earlier busy/poisoned field
// cannot hide a still-held later writer. No assertion executes in callbacks.
pub(in crate::state) fn probe_fields(original: DetachedWorld<()>, target: &World) -> [usize; 3] {
    let mut counts = [0; 3];
    for field in original.fields {
        let mut slot = field.publication_slot(target);
        match slot.try_prepare() {
            Ok(()) => {
                counts[0] += 1;
                drop(slot.abort());
            }
            Err(FieldRefusal {
                cause: PublicationPreparationError::Busy(_),
                ..
            }) => counts[1] += 1,
            Err(_) => counts[2] += 1,
        }
        slot.release();
    }
    counts
}

#[test]
fn world_publication_slot_late_caught_panic_retains_every_writer_until_terminal_release() {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };
    struct Probe {
        world: Arc<World>,
        original: Mutex<Option<DetachedWorld<()>>>,
        counts: Mutex<Option<[usize; 3]>>,
        wakes: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut original) = self.original.try_lock() {
                if let Some(original) = original.take() {
                    if let Ok(mut counts) = self.counts.try_lock() {
                        *counts = Some(probe_fields(original, &self.world));
                    }
                }
            }
        }
    }
    let world = Arc::new(World::default());
    let mut registration = Some(crate::unit_test_support::release_registration(
        &iroha_allocation::AllocationBudget::new(64 * 1024),
    ));
    let capture = || {
        world
            .block()
            .try_detach_journals(
                crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
                |_| Ok::<_, ()>(()),
            )
            .unwrap()
    };
    let callback = Arc::new(Probe {
        world: Arc::clone(&world),
        original: Mutex::new(Some(capture())),
        counts: Mutex::new(None),
        wakes: AtomicUsize::new(0),
    });
    let mut observer = Some(capture());
    let held_probes = capture();
    let expected_fields =
        crate::state::authority_registry::inventory_test_support::world_overlay_names();
    assert_eq!(
        held_probes
            .fields()
            .map(|field| field.name.to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        expected_fields,
    );
    let mut original = capture();
    let wait = Arc::new(Mutex::new(None));
    let stored = Arc::clone(&wait);
    let waker = Waker::from(Arc::clone(&callback));
    after_last_preparation(&mut original, move |target| {
        *stored.lock().unwrap() = Some(arm_first_release(
            observer.take().unwrap(),
            target,
            &waker,
            registration.take().unwrap(),
        ));
        panic!("after last real World field acquired");
    });
    let mut slot = original.publication_slot::<()>(&world);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slot.try_prepare(|_, _| Ok::<_, ()>(()))
    }));
    assert!(result.is_err());
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 0);
    assert_eq!(
        probe_fields(held_probes, &world),
        [0, expected_fields.len(), 0]
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slot.recover_original())).is_err()
    );
    slot.release_writers();
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 0);
    drop(slot);
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 1);
    assert_eq!(
        *callback.counts.lock().unwrap(),
        Some([expected_fields.len(), 0, 0])
    );
    let (observation, mut registration) = wait.lock().unwrap().take().unwrap();
    assert!(
        registration
            .poll_wait(&observation, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
}
