//! Complete World acquisition, exact retry and current/undo publication controls.

use super::super::publication::{
    FieldRefusal, PreparedWorld, PreparedWorldField, WorldPublicationError,
};
use super::*;
use mv::PublicationPreparationError;

trait FieldImage {
    fn image(&self) -> String;
}

impl<K: Key, V: Value + std::fmt::Debug, M: mv::storage::StorageMode<K, V>> FieldImage
    for Storage<K, V, M>
{
    fn image(&self) -> String {
        let snapshot = self.snapshot();
        // Compare actual values and undo, excluding MV locks/owner identities.
        // Derived indexes need no invented public JSON key codecs for this test.
        format!(
            "{:?}",
            (
                snapshot.current().iter().collect::<Vec<_>>(),
                snapshot.revert_map().iter().collect::<Vec<_>>()
            )
        )
    }
}

impl<V: Value + std::fmt::Debug, C: Send + Sync + 'static> FieldImage for Cell<V, C> {
    fn image(&self) -> String {
        format!("{:?}", (&*self.view(), &*self.predecessor_view()))
    }
}

impl FieldImage for TriggerSet {
    fn image(&self) -> String {
        norito::json::to_json(self).unwrap()
    }
}

fn all_images(world: &World) -> Vec<(&'static str, String)> {
    macro_rules! field_image {
        ($world:ident, nfts) => {
            norito::json::to_json(&$world.nfts).unwrap()
        };
        ($world:ident, rwas) => {
            norito::json::to_json(&$world.rwas).unwrap()
        };
        ($world:ident, $field:ident) => {
            $world.$field.image()
        };
    }
    macro_rules! images {
        ($world:ident; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
            vec![
                $((stringify!($prefix), field_image!($world, $prefix)),)*
                $((stringify!($privacy), field_image!($world, $privacy)),)*
                $((stringify!($suffix), field_image!($world, $suffix)),)*
            ]
        };
    }
    with_world_overlay_fields!(images, world)
}

fn prepare<'a, A>(journal: DetachedWorld<A>, target: &'a World) -> PreparedWorld<'a, A, ()> {
    journal
        .try_prepare_publication(target, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("World preparation refused: {error:?}"))
}

// Release waiters fund their node from a test-local pool.
fn waiter_pool() -> iroha_allocation::AllocationBudget {
    iroha_allocation::AllocationBudget::new(64 * 1024)
}

fn physical_custody<A>(journal: &DetachedWorld<A>) -> (usize, usize, Vec<usize>) {
    (
        journal.fields.as_ptr() as usize,
        journal.fields.capacity(),
        journal
            .fields
            .iter()
            .map(|field| std::ptr::from_ref(field.as_ref()).cast::<()>() as usize)
            .collect(),
    )
}

fn prepare_field<'target>(
    original: Box<dyn RetainedWorldField>,
    target: &'target World,
) -> Result<
    Box<dyn PreparedWorldField + 'target>,
    (Box<dyn PreparedWorldField + 'target>, FieldRefusal),
> {
    let mut slot = original.publication_slot(target);
    match slot.try_prepare() {
        Ok(()) => Ok(slot),
        Err(error) => Err((slot, error)),
    }
}

fn mutate(original: &mut WorldBlock<'_>, value: u8, trigger: &str) {
    let mut child = original.transaction_without_telemetry(LaneConfig::default(), 1);
    child
        .smart_contract_state
        .insert(path("capture/value"), vec![value]);
    *child.soradns_last_publish_ms.get_mut() = Some(u64::from(value));
    child.apply();
    register_trigger(original, trigger);
    let mut aborted = original.transaction_without_telemetry(LaneConfig::default(), 1);
    aborted
        .smart_contract_state
        .insert(path("capture/aborted"), vec![99]);
}

#[test]
fn complete_world_preparation_holds_every_inventory_writer_and_matches_direct_commit() {
    let world = fixture();
    let direct = fixture();
    let before = all_images(&world);
    let reader = world.smart_contract_state.view();
    let undo = world.smart_contract_state.snapshot();
    let probes = capture(world.block()).fields;
    let mut original = world.block();
    let mut reference = direct.block();
    mutate(&mut original, 2, "world_publish");
    mutate(&mut reference, 2, "world_publish");
    let prepared = prepare(capture(original), &world);
    let expected_fields =
        crate::state::authority_registry::inventory_test_support::world_overlay_names();
    assert_eq!(probes.len(), expected_fields.len());
    assert_eq!(
        probes
            .iter()
            .map(|field| field.summary().name.to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        expected_fields,
    );
    // Probe each original field separately, so an early busy field cannot hide
    // a missing writer later in the heterogeneous World inventory.
    for probe in probes {
        let name = probe.summary().name;
        let (_, refusal) = prepare_field(probe, &world)
            .err()
            .expect("all writers held");
        assert_eq!(refusal.field, name);
        assert!(matches!(
            refusal.cause,
            PublicationPreparationError::Busy(_)
        ));
    }
    let journal = prepared.abort().0;
    assert_eq!(
        all_images(&world),
        before,
        "complete preparation and abort transfer no component"
    );
    let prepared = prepare(journal, &world);
    reference.commit();
    prepared.publish();
    assert_eq!(all_images(&world), all_images(&direct));
    assert_eq!(reader.get(&path("capture/value")), Some(&vec![1]));
    assert_eq!(undo.revert_map().get(&path("capture/value")), Some(&None));
    assert_all_writers_released(&world);
}

#[test]
fn world_publication_retains_original_busy_notification_until_aggregate_unlock() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Wake, Waker},
    };
    struct Probe {
        world: Arc<World>,
        fence: Arc<std::sync::Mutex<()>>,
        calls: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            assert!(
                self.fence.try_lock().is_ok(),
                "aggregate fence must release before callbacks"
            );
            assert_all_writers_released(&self.world);
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    let world = fixture();
    let mut registration = crate::unit_test_support::release_registration(&waiter_pool());
    let competitor = capture(world.block());
    let mut original = world.block();
    mutate(&mut original, 19, "deferred_world_wake");
    let prepared = prepare(capture(original), &world);
    let (_, error, _cleanup) = competitor
        .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
        .err()
        .unwrap();
    drop(_cleanup);
    let WorldPublicationError::Field(FieldRefusal {
        cause: PublicationPreparationError::Busy(wait),
        ..
    }) = error
    else {
        panic!("exact original World field must exclude the competitor");
    };
    let fence = Arc::new(std::sync::Mutex::new(()));
    let probe = Arc::new(Probe {
        world: Arc::clone(&world),
        fence: Arc::clone(&fence),
        calls: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut wait = wait.wait_for_release(&mut registration);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let held = fence.lock().unwrap();
    let published = prepared.publish();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(held);
    drop(published);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    assert_eq!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/value")),
        Some(&vec![19])
    );
}

#[test]
fn replacement_world_restores_untouched_tip_only_owners_and_exact_undo() {
    for touched in [false, true] {
        let world = fixture();
        let direct = fixture();
        for owner in [&world, &direct] {
            let mut tip = owner.block();
            mutate(&mut tip, 20, "discarded_world_tip");
            tip.smart_contract_state
                .insert(path("capture/tip_only"), vec![3]);
            tip.commit();
        }
        let mut original = world.block_and_revert();
        let mut reference = direct.block_and_revert();
        if touched {
            mutate(&mut original, 30, "replacement_world");
            mutate(&mut reference, 30, "replacement_world");
        }
        let journal = capture(original);
        assert_eq!(journal.mode(), BlockMode::Replace);
        let prepared = prepare(journal, &world);
        reference.commit();
        prepared.publish();
        assert_eq!(all_images(&world), all_images(&direct));
        assert!(
            world
                .smart_contract_state
                .view()
                .get(&path("capture/tip_only"))
                .is_none()
        );
        world.block_and_revert().commit();
        direct.block_and_revert().commit();
        assert_eq!(all_images(&world), all_images(&direct));
    }
}

#[test]
fn complete_world_abort_and_drop_keep_original_events_and_current_undo_cut() {
    let world = fixture();
    let before = all_images(&world);
    let mut original = world.block();
    mutate(&mut original, 7, "aborted_world");
    original.dataspace_catalog = catalog();
    original.push_pipeline_warning(
        BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0),
        "world",
        "original event",
    );
    let events = original.external_event_buf.as_ptr();
    let journal = capture(original);
    let expected = journal.fields().collect::<Vec<_>>();
    let custody = physical_custody(&journal);
    let journal = prepare(journal, &world).abort().0;
    assert_eq!(physical_custody(&journal), custody);
    assert_eq!(journal.external_events().as_ptr(), events);
    assert_eq!(journal.dataspace_catalog(), &catalog());
    assert_eq!(journal.fields().collect::<Vec<_>>(), expected);
    assert!(journal.matches_current(&world));
    assert_all_writers_released(&world);
    assert_eq!(all_images(&world), before);
    drop(prepare(journal, &world));
    assert_all_writers_released(&world);
    assert_eq!(all_images(&world), before);
}

trait WriterHold {}
impl<T> WriterHold for T {}

#[test]
fn every_busy_world_field_releases_all_earlier_writers_and_retains_complete_retry() {
    macro_rules! holders {
        (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
            [
                $((stringify!($prefix), |world: &World| -> Box<dyn WriterHold + '_> { Box::new(world.$prefix.block()) }),)*
                $((stringify!($privacy), |world: &World| -> Box<dyn WriterHold + '_> { Box::new(world.$privacy.block()) }),)*
                $((stringify!($suffix), |world: &World| -> Box<dyn WriterHold + '_> { Box::new(world.$suffix.block()) }),)*
            ]
        };
    }
    let holders: &[(&str, for<'a> fn(&'a World) -> Box<dyn WriterHold + 'a>)] =
        &with_world_overlay_fields!(holders);
    let world = fixture();
    let before = all_images(&world);
    let mut original = world.block();
    mutate(&mut original, 4, "retry_world");
    let mut journal = capture(original);
    let expected = journal.fields().collect::<Vec<_>>();
    let custody = physical_custody(&journal);
    for &(name, hold) in holders {
        let held = hold(&world);
        let (retained, error, _cleanup) = journal
            .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
            .err()
            .expect("busy original field");
        drop(_cleanup);
        let WorldPublicationError::Field(refusal) = error else {
            panic!("exact field refusal")
        };
        assert_eq!(refusal.field, name);
        assert!(matches!(
            refusal.cause,
            PublicationPreparationError::Busy(_)
        ));
        assert_eq!(refusal.trigger_component.is_some(), name == "triggers");
        journal = retained;
        assert_eq!(physical_custody(&journal), custody, "{name}");
        assert_eq!(journal.fields().collect::<Vec<_>>(), expected);
        drop(held);
        assert_all_writers_released(&world);
        assert!(journal.matches_current(&world));
    }
    assert_eq!(all_images(&world), before);
    prepare(journal, &world).publish();
    assert_eq!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/value")),
        Some(&vec![4])
    );
}

struct Installation {
    world: Arc<World>,
    dropped: Arc<AtomicBool>,
}
impl Drop for Installation {
    fn drop(&mut self) {
        assert_all_writers_released(&self.world);
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn late_world_identity_change_and_capacity_refusal_preserve_journals_and_guard_order() {
    let world = fixture();
    let journal = capture(world.block());
    let expected = journal.fields().collect::<Vec<_>>();
    let custody = physical_custody(&journal);
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&world, |_, _| Err::<(), _>("capacity"))
        .err()
        .expect("capacity refusal");
    drop(_cleanup);
    assert!(matches!(
        error,
        WorldPublicationError::Admission("capacity")
    ));
    assert_eq!(journal.fields().collect::<Vec<_>>(), expected);
    assert_eq!(physical_custody(&journal), custody);
    let last = *expected.last().unwrap();
    // Acquire/commit through the actual inventory-generated accessor, including
    // an untouched last field; equal values still rotate the exact undo owner.
    macro_rules! invalidators {
        (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
            [
                $((stringify!($prefix), |world: &World| commit_untouched_fixture_field!(world, $prefix)),)*
                $((stringify!($privacy), |world: &World| commit_untouched_fixture_field!(world, $privacy)),)*
                $((stringify!($suffix), |world: &World| commit_untouched_fixture_field!(world, $suffix)),)*
            ]
        };
    }
    let invalidators: &[(&str, fn(&World))] = &with_world_overlay_fields!(invalidators);
    let (name, invalidate) = invalidators.last().unwrap();
    assert_eq!(*name, last.name);
    let dropped = Arc::new(AtomicBool::new(false));
    let (journal, error, _cleanup) = journal
        .try_prepare_publication(&world, |_, target| {
            invalidate(target);
            Ok::<_, ()>(Installation {
                world: Arc::clone(&world),
                dropped: Arc::clone(&dropped),
            })
        })
        .err()
        .expect("last original owner changed during admission");
    drop(_cleanup);
    let WorldPublicationError::Field(refusal) = error else {
        panic!("exact changed field")
    };
    assert_eq!(refusal.field, last.name);
    assert!(matches!(
        refusal.cause,
        PublicationPreparationError::Changed
    ));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(journal.fields().collect::<Vec<_>>(), expected);
    assert_eq!(physical_custody(&journal), custody);
    assert!(!journal.matches_current(&world));
}

#[test]
fn world_publication_hands_original_extras_and_both_resource_guards_to_aggregate() {
    for operation in ["drop", "abort", "publish"] {
        let world = fixture();
        let captured = Arc::new(AtomicBool::new(false));
        let installed = Arc::new(AtomicBool::new(false));
        let mut original = world.block();
        mutate(&mut original, 9, "guarded_world");
        original.dataspace_catalog = catalog();
        original.push_pipeline_warning(
            BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0),
            "world",
            "retained original",
        );
        let events = original.external_event_buf.as_ptr();
        let journal = original
            .try_detach_journals(
                crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
                |_| Ok::<_, ()>(Reservation(Arc::clone(&captured))),
            )
            .unwrap();
        let prepared = journal
            .try_prepare_publication(&world, |_, _| {
                Ok::<_, ()>(Installation {
                    world: Arc::clone(&world),
                    dropped: Arc::clone(&installed),
                })
            })
            .unwrap_or_else(|_| panic!("prepare actual World"));
        assert!(!captured.load(Ordering::SeqCst));
        assert!(!installed.load(Ordering::SeqCst));
        match operation {
            "drop" => drop(prepared),
            "abort" => {
                let journal = prepared.abort().0;
                assert!(installed.load(Ordering::SeqCst));
                assert!(!captured.load(Ordering::SeqCst));
                assert_eq!(journal.external_events().as_ptr(), events);
                drop(journal);
            }
            "publish" => {
                let (alias_context, returned_events, retirement, admission, installation) =
                    prepared.publish();
                drop(retirement);
                assert_eq!(alias_context, catalog());
                assert_eq!(returned_events.as_ptr(), events);
                assert!(!captured.load(Ordering::SeqCst));
                assert!(!installed.load(Ordering::SeqCst));
                drop(returned_events);
                drop(admission);
                drop(installation);
            }
            _ => unreachable!(),
        }
        assert!(captured.load(Ordering::SeqCst));
        assert!(installed.load(Ordering::SeqCst));
    }
}

#[derive(Clone, Copy, Debug)]
enum UnwindBoundary {
    Prepare,
    Abort,
}

// The witness follows a real original field through preparation and rollback.
// Field order drops that original owner before observing its destruction.
struct OriginalFieldDrop(Option<Arc<AtomicBool>>);
impl Drop for OriginalFieldDrop {
    fn drop(&mut self) {
        if let Some(dropped) = &self.0 {
            dropped.store(true, Ordering::SeqCst);
        }
    }
}

struct UnwindField {
    original: Box<dyn RetainedWorldField>,
    boundary: Option<UnwindBoundary>,
    dropped: OriginalFieldDrop,
}

struct UnwindPreparedField<'target> {
    original: Box<dyn PreparedWorldField + 'target>,
    boundary: Option<UnwindBoundary>,
    dropped: OriginalFieldDrop,
}

impl RetainedWorldField for UnwindField {
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
        let Self {
            original,
            boundary,
            dropped,
        } = *self;
        Box::new(UnwindPreparedField {
            original: original.publication_slot(target),
            boundary,
            dropped,
        })
    }
}

impl PreparedWorldField for UnwindPreparedField<'_> {
    fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
        if matches!(self.boundary, Some(UnwindBoundary::Prepare)) {
            panic!("injected failure after the preceding real field acquired its writers");
        }
        self.original.try_prepare()
    }

    fn release(&mut self) {
        self.original.release();
    }

    fn release_for_recovery(&mut self) {
        self.original.release_for_recovery();
    }

    fn abort(&mut self) -> Box<dyn RetainedWorldField> {
        if matches!(self.boundary, Some(UnwindBoundary::Abort)) {
            panic!("injected failure after the preceding real field returned to retry custody");
        }
        Box::new(UnwindField {
            original: self.original.abort(),
            boundary: self.boundary,
            dropped: OriginalFieldDrop(self.dropped.0.take()),
        })
    }

    fn publish(&mut self) {
        self.original.publish();
    }
}

struct UnwindAdmission {
    field_dropped: Arc<AtomicBool>,
    // Zero means live, one means an early refund, and two means payload first.
    refund_order: Arc<AtomicUsize>,
}
impl Drop for UnwindAdmission {
    fn drop(&mut self) {
        self.refund_order.store(
            1 + usize::from(self.field_dropped.load(Ordering::SeqCst)),
            Ordering::SeqCst,
        );
    }
}

#[test]
fn world_publication_unwind_retains_both_admissions_until_original_fields_drop() {
    for boundary in [UnwindBoundary::Prepare, UnwindBoundary::Abort] {
        let world = fixture();
        let before = all_images(&world);
        let retained = world.smart_contract_state.snapshot();
        let field_dropped = Arc::new(AtomicBool::new(false));
        let capture_refund = Arc::new(AtomicUsize::new(0));
        let installation_refund = Arc::new(AtomicUsize::new(0));
        let mut journal = world
            .block()
            .try_detach_journals(
                crate::state::world_journals::resources::WorldJournalShellReservation::for_test(),
                |_| {
                    Ok::<_, ()>(UnwindAdmission {
                        field_dropped: Arc::clone(&field_dropped),
                        refund_order: Arc::clone(&capture_refund),
                    })
                },
            )
            .unwrap();
        let expected_fields =
            crate::state::authority_registry::inventory_test_support::world_overlay_names();
        assert_eq!(journal.field_count(), expected_fields.len());
        assert_eq!(
            journal
                .fields()
                .map(|field| field.name.to_owned())
                .collect::<std::collections::BTreeSet<_>>(),
            expected_fields,
        );
        // A separate read-only capture holds exact original-cut probes for every
        // real field before any unwind can poison its physical writer.
        let probe = capture(world.block());
        // Preparation retains an untouched tail; abort already restored the first
        // original field into its retry vector when the second field panics.
        let observed = match boundary {
            UnwindBoundary::Prepare => journal.fields.len() - 1,
            UnwindBoundary::Abort => 0,
        };
        let original = journal.fields.remove(observed);
        journal.fields.insert(
            observed,
            Box::new(UnwindField {
                original,
                boundary: None,
                dropped: OriginalFieldDrop(Some(Arc::clone(&field_dropped))),
            }),
        );
        let original = journal.fields.remove(1);
        journal.fields.insert(
            1,
            Box::new(UnwindField {
                original,
                boundary: Some(boundary),
                dropped: OriginalFieldDrop(None),
            }),
        );
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let prepared = journal
                .try_prepare_publication(&world, |_, _| {
                    Ok::<_, ()>(UnwindAdmission {
                        field_dropped: Arc::clone(&field_dropped),
                        refund_order: Arc::clone(&installation_refund),
                    })
                })
                .unwrap_or_else(|_| panic!("actual World should prepare before injected failure"));
            drop(prepared.abort());
        }));
        let message = unwind.expect_err("the real field boundary must exercise unwind");
        assert!(
            message
                .downcast_ref::<&str>()
                .is_some_and(|message| message.starts_with("injected failure"))
        );
        assert!(field_dropped.load(Ordering::SeqCst));
        assert_eq!(
            capture_refund.load(Ordering::SeqCst),
            2,
            "{boundary:?}: capture admission refunded before its original field"
        );
        assert_eq!(
            installation_refund.load(Ordering::SeqCst),
            2,
            "{boundary:?}: installation admission refunded before its original field"
        );
        // Unwound std mutex writers deliberately remain poisoned. Check the
        // actual nonblocking publication result rather than trying to reopen a
        // blocking World writer that requires local recovery after that panic.
        for (index, field) in probe.fields.into_iter().enumerate() {
            let name = field.summary().name;
            let poisoned = match boundary {
                UnwindBoundary::Prepare => index == 0,
                UnwindBoundary::Abort => false,
            };
            match prepare_field(field, &world) {
                Ok(mut prepared) => {
                    assert!(
                        !poisoned,
                        "{boundary:?}: unwound {name} must require recovery"
                    );
                    drop(prepared.abort());
                }
                Err((original, error)) => {
                    assert!(
                        poisoned,
                        "{boundary:?}: untouched/released {name} must remain usable"
                    );
                    assert!(
                        matches!(error.cause, PublicationPreparationError::Poisoned),
                        "{boundary:?}: {name} must be poisoned, not busy or changed"
                    );
                    drop(original);
                }
            }
        }
        let original_image = format!(
            "{:?}",
            (
                retained.current().iter().collect::<Vec<_>>(),
                retained.revert_map().iter().collect::<Vec<_>>()
            )
        );
        assert_eq!(
            original_image,
            before
                .iter()
                .find(|(name, _)| *name == "smart_contract_state")
                .unwrap()
                .1
        );
        match boundary {
            UnwindBoundary::Prepare => {
                // Only the first EBR field was acquired before this cut. Its
                // writer is poisoned, but no map reader mutex was held.
                assert_eq!(all_images(&world), before);
            }
            UnwindBoundary::Abort => {
                // Joint release precedes the fallible retry-box transfer, so a
                // later cleanup panic cannot poison already unlocked readers.
                assert_eq!(all_images(&world), before);
            }
        }
    }
}

#[test]
fn world_abort_retains_all_original_boxes_and_notifications_until_aggregate_unlock() {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Wake, Waker},
    };
    struct Probe {
        world: Arc<World>,
        fence: Arc<std::sync::Mutex<()>>,
        calls: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            assert!(
                self.fence.try_lock().is_ok(),
                "aggregate fence must release before callbacks"
            );
            assert_all_writers_released(&self.world);
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    let world = fixture();
    let mut registration = crate::unit_test_support::release_registration(&waiter_pool());
    let competitor = capture(world.block());
    let mut original = world.block();
    mutate(&mut original, 19, "deferred_world_wake");
    let prepared = prepare(capture(original), &world);
    let (_, error, _cleanup) = competitor
        .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
        .err()
        .unwrap();
    drop(_cleanup);
    let WorldPublicationError::Field(FieldRefusal {
        cause: PublicationPreparationError::Busy(wait),
        ..
    }) = error
    else {
        panic!("exact original World field must exclude the competitor");
    };
    let fence = Arc::new(std::sync::Mutex::new(()));
    let probe = Arc::new(Probe {
        world: Arc::clone(&world),
        fence: Arc::clone(&fence),
        calls: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut wait = wait.wait_for_release(&mut registration);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let held = fence.lock().unwrap();
    let published = prepared.abort();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(held);
    drop(published);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    assert_eq!(
        world
            .smart_contract_state
            .view()
            .get(&path("capture/value")),
        Some(&vec![1])
    );
}

#[test]
fn world_refusal_retains_prefix_callbacks_and_original_shells_through_enclosing_fence() {
    use std::{
        sync::Mutex,
        task::{Context, Wake, Waker},
    };
    struct Probe {
        world: Arc<World>,
        fence: Arc<Mutex<()>>,
        wakes: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            assert!(
                self.fence.try_lock().is_ok(),
                "enclosing fence precedes callback"
            );
            assert_all_writers_released(&self.world);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct PrefixWatch {
        observation: iroha_allocation::release::ReleaseWait,
        registration: iroha_allocation::release::ReleaseRegistration,
    }
    // Observe a real first-field release only after the earlier prefix has been
    // acquired. The separate original probe journal never includes this hook.
    struct ObservePrefix {
        original: Box<dyn RetainedWorldField>,
        journal: DetachedWorld<()>,
        future: Arc<Mutex<Option<PrefixWatch>>>,
        registration: Option<iroha_allocation::release::ReleaseRegistration>,
        callback: Arc<Probe>,
    }
    impl RetainedWorldField for ObservePrefix {
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
            let Self {
                original,
                journal,
                future,
                registration,
                callback,
            } = *self;
            Box::new(PreparedObservePrefix {
                original: original.publication_slot(target),
                journal: Some(journal),
                future,
                registration,
                callback,
                target,
            })
        }
    }
    struct PreparedObservePrefix<'target> {
        original: Box<dyn PreparedWorldField + 'target>,
        journal: Option<DetachedWorld<()>>,
        future: Arc<Mutex<Option<PrefixWatch>>>,
        registration: Option<iroha_allocation::release::ReleaseRegistration>,
        callback: Arc<Probe>,
        target: &'target World,
    }
    impl PreparedWorldField for PreparedObservePrefix<'_> {
        fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
            let journal = self.journal.take().expect("one original prefix probe");
            let (_, error, cleanup) = journal
                .try_prepare_publication(self.target, |_, _| Ok::<_, ()>(()))
                .err()
                .expect("earlier original field is held");
            drop(cleanup);
            let WorldPublicationError::Field(FieldRefusal {
                cause: PublicationPreparationError::Busy(wait),
                ..
            }) = error
            else {
                panic!("actual first-field lock observation");
            };
            let mut registration = self
                .registration
                .take()
                .expect("original prepaid prefix watcher");
            let waker = Waker::from(Arc::clone(&self.callback));
            assert!(
                registration
                    .poll_wait(&wait, &mut Context::from_waker(&waker))
                    .is_pending()
            );
            *self.future.lock().unwrap() = Some(PrefixWatch {
                observation: wait,
                registration,
            });
            self.original.try_prepare()
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
    let world = fixture();
    let registration = crate::unit_test_support::release_registration(&waiter_pool());
    let before = all_images(&world);
    let probe_journal = capture(world.block());
    let mut block = world.block();
    mutate(&mut block, 23, "refused_world");
    let mut journal = capture(block);
    let custody = physical_custody(&journal);
    assert!(
        journal
            .fields()
            .position(|field| field.name == "smart_contract_state")
            .unwrap()
            > 1
    );
    let fence = Arc::new(Mutex::new(()));
    let callback = Arc::new(Probe {
        world: Arc::clone(&world),
        fence: Arc::clone(&fence),
        wakes: AtomicUsize::new(0),
    });
    let future = Arc::new(Mutex::new(None));
    let original = journal.fields.remove(1);
    journal.fields.insert(
        1,
        Box::new(ObservePrefix {
            original,
            journal: probe_journal,
            future: Arc::clone(&future),
            registration: Some(registration),
            callback: Arc::clone(&callback),
        }),
    );
    let outer = fence.lock().unwrap();
    let blocked = world.smart_contract_state.block();
    let (journal, error, cleanup) = journal
        .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("late field refuses the complete original World");
    let WorldPublicationError::Field(refusal) = error else {
        panic!("late component refusal");
    };
    assert_eq!(refusal.field, "smart_contract_state");
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 0);
    assert_eq!(physical_custody(&journal), custody);
    drop(blocked);
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 0);
    drop(outer);
    drop(cleanup);
    assert_eq!(callback.wakes.load(Ordering::SeqCst), 1);
    let PrefixWatch {
        observation,
        mut registration,
    } = future.lock().unwrap().take().unwrap();
    assert!(
        registration
            .poll_wait(&observation, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert_eq!(all_images(&world), before);
    assert!(journal.matches_current(&world));
    drop(prepare(journal, &world).abort());
}
