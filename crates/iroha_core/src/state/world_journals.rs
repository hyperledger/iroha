//! Capture every original World journal without retaining its writer or an EBR reader.
//!
//! The existing overlay inventory generates exhaustive destructuring and typed
//! target accessors. Private generic wrappers retain their real MV values; the
//! flat vector erases only the heterogeneous field type, never its owner or
//! publication identity. Consuming preparation reacquires every original writer;
//! final State authorization and visibility remain the aggregate owner's duty.

use core::convert::Infallible;

use super::{
    Cell, CellBlock, Storage, StorageBlock, TriggerSet, TriggerSetBlock, World, WorldBlock,
    WorldBlockFields,
};
use crate::smartcontracts::isi::triggers::set::{DetachError, DetachedSet, SetBlockCapture};
use iroha_data_model::{events::EventBox, nexus::DataSpaceCatalog};
use mv::{
    BlockCapture, BlockMode, Key, Value,
    cell::BlockCaptureSlot as CellCaptureSlot,
    storage::{BlockCaptureSlot as StorageCaptureSlot, StorageMode},
};

#[path = "world_publication.rs"]
pub(in crate::state) mod publication;
#[path = "world_journal_resources.rs"]
pub(in crate::state) mod resources;

#[path = "world_storage_mode.rs"]
mod storage_mode;
use resources::WorldJournalShellReservation;
use storage_mode::WorldStorageMode;

/// Refusal drops the entire original overlay without publishing any component.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureError<E> {
    /// One original journal has a different acquisition mode.
    #[error("World journal {field} mode {actual:?} differs from {expected:?}")]
    InconsistentMode {
        /// Original field, or the trigger owner's internal component.
        field: &'static str,
        /// Common mode required by the original World block.
        expected: BlockMode,
        /// Mode actually retained by the mismatching component.
        actual: BlockMode,
    },
    /// Caller admission refused retention before detaching original journal values.
    #[error("World journal retention admission failed")]
    Admission(E),
}

fn widen_error<E>(error: CaptureError<Infallible>) -> CaptureError<E> {
    match error {
        CaptureError::InconsistentMode {
            field,
            expected,
            actual,
        } => CaptureError::InconsistentMode {
            field,
            expected,
            actual,
        },
        CaptureError::Admission(impossible) => match impossible {},
    }
}

fn trigger_error(error: DetachError<Infallible>) -> CaptureError<Infallible> {
    match error {
        DetachError::InconsistentMode {
            field,
            expected,
            actual,
        } => CaptureError::InconsistentMode {
            field,
            expected,
            actual,
        },
        DetachError::Admission(impossible) => match impossible {},
    }
}

/// Immutable diagnostics of one retained field, not permission to publish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::state) struct FieldSummary {
    /// Name from the sole World overlay inventory.
    pub name: &'static str,
    /// Acquisition mode of this field's original block.
    pub mode: BlockMode,
    /// Number of retained touches, including equal-value touches and deletions.
    pub touched_values: usize,
}

/// Actual original World deltas and extras, with no World reference or lifetime.
///
/// The admission must cover the flat vector, one wrapper per inventory field,
/// publication metadata, retained original current/undo allocations and future
/// installation resources. Detachment does not clone the payloads; their earlier
/// execution and nested allocations require admission before they are created.
/// No serialized-length estimate or default resource policy is supplied here.
/// Rust drops the admission last, after every retained payload and event.
///
/// TODO: compose these original journals with all other State owners, admitted
/// resources and exact finality in one consuming publisher. This owner cannot
/// reconstruct a World or authorize a decided-block refusal. Preparing World
/// writers alone does not authorize State publication.
pub(in crate::state) struct DetachedWorld<Admission> {
    mode: BlockMode,
    fields: Vec<Box<dyn RetainedWorldField>>,
    dataspace_catalog: DataSpaceCatalog,
    external_event_buf: Vec<EventBox>,
    shells: WorldJournalShellReservation,
    admission: Admission,
}

impl<Admission> DetachedWorld<Admission> {
    /// Common mode of every original World and trigger component.
    pub(in crate::state) fn mode(&self) -> BlockMode {
        self.mode
    }

    /// Number of captured names in the single World overlay inventory.
    pub(in crate::state) fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Inspect field names, acquisition modes and exact retained touch counts.
    pub(in crate::state) fn fields(&self) -> impl ExactSizeIterator<Item = FieldSummary> + '_ {
        self.fields.iter().map(|field| field.summary())
    }

    /// Inspect one named field without downcasting or exposing a mutable journal.
    pub(in crate::state) fn field(&self, name: &str) -> Option<FieldSummary> {
        self.fields().find(|field| field.name == name)
    }

    /// Borrow the exact moved block-local alias context.
    pub(in crate::state) fn dataspace_catalog(&self) -> &DataSpaceCatalog {
        &self.dataspace_catalog
    }

    /// Borrow all moved external events in their original order.
    pub(in crate::state) fn external_events(&self) -> &[EventBox] {
        &self.external_event_buf
    }

    /// Borrow the retained resource reservation.
    pub(in crate::state) fn admission(&self) -> &Admission {
        &self.admission
    }

    /// Observe all captured owner/current/undo identities against an explicit target.
    ///
    /// These separate observations are advisory, not an atomic World snapshot or
    /// an exclusive publication lease. An eventual aggregate publisher must
    /// reacquire all writers and check the exact original cut before publishing.
    pub(in crate::state) fn matches_current(&self, target: &World) -> bool {
        self.fields
            .iter()
            .all(|field| field.matches_current(target))
    }
}

// Private and non-extensible outside this module. There is no Any/downcast,
// name-based dispatch, mutable access or live read view. Only the complete
// consuming World owner can acquire and publish its private field publishers.
trait RetainedWorldField: Send + Sync {
    fn summary(&self) -> FieldSummary;
    fn matches_current(&self, target: &World) -> bool;
    fn publication_slot<'target>(
        self: Box<Self>,
        target: &'target World,
    ) -> Box<dyn publication::PreparedWorldField + 'target>;
}

trait CaptureWorldField: Sized {
    type Target;
    type Retained: RetainedWorldField + 'static;
    type Capture: WorldCaptureSlot<Target = Self::Target, Retained = Self::Retained>;

    fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>>;
    fn into_capture(self) -> Self::Capture;
}

impl<B: CaptureWorldField + super::block_field::OriginalPublicationBlock> CaptureWorldField
    for super::block_field::BlockField<B>
{
    type Target = B::Target;
    type Retained = B::Retained;
    type Capture = B::Capture;
    fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>> {
        std::ops::Deref::deref(self).capture_mode()
    }
    fn into_capture(self) -> Self::Capture {
        self.into_executing().into_capture()
    }
}

// Extraction borrows the original heap shell. Only these aggregate fields can
// relinquish their payload while leaving a safe, inert empty slot behind.
trait TakeWorldCapture: CaptureWorldField {
    fn take_capture(&mut self) -> Self::Capture;
}

impl<B: CaptureWorldField + super::block_field::OriginalPublicationBlock> TakeWorldCapture
    for super::block_field::BlockField<B>
{
    fn take_capture(&mut self) -> Self::Capture {
        self.take_executing().into_capture()
    }
}

impl TakeWorldCapture for TriggerSetBlock<'_> {
    fn take_capture(&mut self) -> Self::Capture {
        self.take_capture_slot()
    }
}

trait WorldCaptureSlot: Sized {
    type Target;
    type Retained: RetainedWorldField + 'static;

    fn capture(&mut self) -> Result<(), CaptureError<Infallible>>;
    fn release(&mut self);
    // Only after every field captured: all physical writers are already free.
    fn retain(self, name: &'static str, target: fn(&World) -> &Self::Target) -> Self::Retained;
}

struct RetainedStorage<K: Key, V: Value, M: StorageMode<K, V> = concread::bptree::Untracked> {
    name: &'static str,
    // Empty only while the same box is held by its private prepared owner.
    journal: Option<mv::storage::Detached<K, V, (), M>>,
    target: fn(&World) -> &Storage<K, V, M>,
}

impl<K: Key, V: Value, M: WorldStorageMode<K, V>> RetainedWorldField for RetainedStorage<K, V, M>
where
    M::Charge: Send + Sync + 'static,
{
    fn summary(&self) -> FieldSummary {
        let journal = self.journal.as_ref().expect("retained original journal");
        FieldSummary {
            name: self.name,
            mode: journal.mode(),
            touched_values: journal.touched_entries().len(),
        }
    }
    fn matches_current(&self, target: &World) -> bool {
        self.journal
            .as_ref()
            .expect("retained original journal")
            .matches_current((self.target)(target))
    }
    fn publication_slot<'target>(
        self: Box<Self>,
        target: &'target World,
    ) -> Box<dyn publication::PreparedWorldField + 'target> {
        publication::storage_slot(self, target)
    }
}

impl<'a, K: Key, V: Value, M: WorldStorageMode<K, V>> CaptureWorldField
    for StorageBlock<'a, K, V, M>
where
    M::Charge: Send + Sync + 'static,
{
    type Target = Storage<K, V, M>;
    type Retained = RetainedStorage<K, V, M>;
    type Capture = StorageCaptureSlot<'a, K, V, (), M>;
    fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>> {
        Ok(self.mode())
    }
    fn into_capture(self) -> Self::Capture {
        self.capture_slot()
    }
}

impl<K: Key, V: Value, M: WorldStorageMode<K, V>> WorldCaptureSlot
    for StorageCaptureSlot<'_, K, V, (), M>
where
    M::Charge: Send + Sync + 'static,
{
    type Target = Storage<K, V, M>;
    type Retained = RetainedStorage<K, V, M>;
    fn capture(&mut self) -> Result<(), CaptureError<Infallible>> {
        match self.try_capture(|_| Ok::<(), Infallible>(())) {
            Ok(()) => Ok(()),
            Err(impossible) => match impossible {},
        }
    }
    fn release(&mut self) {
        BlockCapture::release(self);
    }
    fn retain(self, name: &'static str, target: fn(&World) -> &Self::Target) -> Self::Retained {
        let (journal, cleanup) = self.into_detached();
        let retained = RetainedStorage {
            name,
            journal: Some(journal),
            target,
        };
        drop(cleanup);
        retained
    }
}

struct RetainedCell<V: Value, C: Send + Sync + 'static> {
    name: &'static str,
    // Empty only while the same box is held by its private prepared owner.
    journal: Option<mv::cell::Detached<V, (), C>>,
    target: fn(&World) -> &Cell<V, C>,
}

impl<V: Value, C: Send + Sync + 'static> RetainedWorldField for RetainedCell<V, C> {
    fn summary(&self) -> FieldSummary {
        let journal = self.journal.as_ref().expect("retained original journal");
        FieldSummary {
            name: self.name,
            mode: journal.mode(),
            touched_values: usize::from(journal.touched_value().is_some()),
        }
    }
    fn matches_current(&self, target: &World) -> bool {
        self.journal
            .as_ref()
            .expect("retained original journal")
            .matches_current((self.target)(target))
    }
    fn publication_slot<'target>(
        self: Box<Self>,
        target: &'target World,
    ) -> Box<dyn publication::PreparedWorldField + 'target> {
        publication::cell_slot(self, target)
    }
}

impl<'a, V: Value, C: Send + Sync + 'static> CaptureWorldField for CellBlock<'a, V, C> {
    type Target = Cell<V, C>;
    type Retained = RetainedCell<V, C>;
    type Capture = CellCaptureSlot<'a, V, (), C>;
    fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>> {
        Ok(self.mode())
    }
    fn into_capture(self) -> Self::Capture {
        self.capture_slot()
    }
}

impl<V: Value, C: Send + Sync + 'static> WorldCaptureSlot for CellCaptureSlot<'_, V, (), C> {
    type Target = Cell<V, C>;
    type Retained = RetainedCell<V, C>;
    fn capture(&mut self) -> Result<(), CaptureError<Infallible>> {
        match self.try_capture(|_| Ok::<(), Infallible>(())) {
            Ok(()) => Ok(()),
            Err(impossible) => match impossible {},
        }
    }
    fn release(&mut self) {
        BlockCapture::release(self);
    }
    fn retain(self, name: &'static str, target: fn(&World) -> &Self::Target) -> Self::Retained {
        let (journal, cleanup) = self.into_detached();
        let retained = RetainedCell {
            name,
            journal: Some(journal),
            target,
        };
        drop(cleanup);
        retained
    }
}

struct RetainedTriggers {
    name: &'static str,
    // Empty only while the same box is held by its private prepared owner.
    journal: Option<DetachedSet<()>>,
    target: fn(&World) -> &TriggerSet,
}

impl RetainedWorldField for RetainedTriggers {
    fn summary(&self) -> FieldSummary {
        let journal = self.journal.as_ref().expect("retained original journal");
        // The trigger owner exposes these ten immutable typed journals. Its
        // own exhaustive SetBlock destructuring remains the completeness gate.
        let touched_values = journal.data_triggers().touched_entries().len()
            + journal.pipeline_triggers().touched_entries().len()
            + journal.time_triggers().touched_entries().len()
            + journal.by_call_triggers().touched_entries().len()
            + journal.ids().touched_entries().len()
            + journal.active_data_trigger_ids().touched_entries().len()
            + journal
                .active_pipeline_trigger_ids()
                .touched_entries()
                .len()
            + journal.active_time_trigger_ids().touched_entries().len()
            + journal.active_by_call_trigger_ids().touched_entries().len()
            + journal.contracts().touched_entries().len();
        FieldSummary {
            name: self.name,
            mode: journal.mode(),
            touched_values,
        }
    }
    fn matches_current(&self, target: &World) -> bool {
        self.journal
            .as_ref()
            .expect("retained original journal")
            .matches_current((self.target)(target))
    }
    fn publication_slot<'target>(
        self: Box<Self>,
        target: &'target World,
    ) -> Box<dyn publication::PreparedWorldField + 'target> {
        publication::triggers_slot(self, target)
    }
}

impl<'a> CaptureWorldField for TriggerSetBlock<'a> {
    type Target = TriggerSet;
    type Retained = RetainedTriggers;
    type Capture = SetBlockCapture<'a, ()>;
    fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>> {
        TriggerSetBlock::capture_mode(self).map_err(trigger_error)
    }
    fn into_capture(self) -> Self::Capture {
        self.capture_slot()
    }
}

impl WorldCaptureSlot for SetBlockCapture<'_, ()> {
    type Target = TriggerSet;
    type Retained = RetainedTriggers;
    fn capture(&mut self) -> Result<(), CaptureError<Infallible>> {
        self.try_capture(|_| Ok::<(), Infallible>(()))
            .map_err(trigger_error)
    }
    fn release(&mut self) {
        Self::release(self);
    }
    fn retain(self, name: &'static str, target: fn(&World) -> &Self::Target) -> Self::Retained {
        let (journal, cleanup) = self.into_detached();
        let retained = RetainedTriggers {
            name,
            journal: Some(journal),
            target,
        };
        drop(cleanup);
        retained
    }
}

/// Opaque original World capture retained by an enclosing State owner.
/// Capture and retirement borrow this caller-owned slot; materialization is
/// allowed only after every enclosing writer has been released.
pub(in crate::state) trait WorldJournalCapture {
    /// Capture every original while the slot remains in its caller.
    fn capture(&mut self) -> Result<(), CaptureError<Infallible>>;
    /// Terminally unlock every field and retain its original cleanup.
    fn release(&mut self);
    /// Move the completed originals after all enclosing writers are free.
    fn into_journals<Admission>(self, admission: Admission) -> DetachedWorld<Admission>;
}

macro_rules! declare_world_capture {
    (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
        #[allow(non_camel_case_types)]
        struct WorldCapture<OriginalShell, $($prefix: WorldCaptureSlot,)* $($privacy: WorldCaptureSlot,)* $($suffix: WorldCaptureSlot,)*> {
            $($prefix: Option<($prefix, fn(&World) -> &<$prefix as WorldCaptureSlot>::Target)>,)* $($privacy: Option<($privacy, fn(&World) -> &<$privacy as WorldCaptureSlot>::Target)>,)* $($suffix: Option<($suffix, fn(&World) -> &<$suffix as WorldCaptureSlot>::Target)>,)*
            extras: Option<(DataSpaceCatalog, Vec<EventBox>)>,
            // Retain the emptied original allocation and its charge until all
            // enclosing writers release; moving capture cannot refund it early.
            original_shell: Option<OriginalShell>,
            shells: Option<WorldJournalShellReservation>,
            mode: BlockMode,
            refusal: Option<CaptureError<Infallible>>,
            started: bool,
            complete: bool,
        }
        #[allow(non_camel_case_types)]
        impl<OriginalShell, $($prefix: WorldCaptureSlot,)* $($privacy: WorldCaptureSlot,)* $($suffix: WorldCaptureSlot,)*>
            WorldJournalCapture for WorldCapture<OriginalShell, $($prefix,)* $($privacy,)* $($suffix,)*>
        {
            fn capture(&mut self) -> Result<(), CaptureError<Infallible>> {
                assert!(!self.started, "original World capture is one-shot");
                self.started = true;
                if let Some(error) = self.refusal.take() {
                    return Err(error);
                }
                $(self.$prefix.as_mut().expect("original World capture slot").0.capture()?;)*
                $(self.$privacy.as_mut().expect("original World capture slot").0.capture()?;)*
                $(self.$suffix.as_mut().expect("original World capture slot").0.capture()?;)*
                self.complete = true;
                Ok(())
            }
            fn release(&mut self) {
                self.started = true;
                self.complete = false;
                $(if let Some((field, _)) = self.$prefix.as_mut() { field.release(); })*
                $(if let Some((field, _)) = self.$privacy.as_mut() { field.release(); })*
                $(if let Some((field, _)) = self.$suffix.as_mut() { field.release(); })*
            }
            fn into_journals<Admission>(self, admission: Admission) -> DetachedWorld<Admission> {
                // Original payloads/notifications retire before this reservation,
                // including a wake panic during wrapper materialization.
                let admission = admission;
                let mut pending = self;
                assert!(pending.complete, "original World capture did not complete");
                const FIELD_COUNT: usize = [
                    $(stringify!($prefix),)* $(stringify!($privacy),)* $(stringify!($suffix),)*
                ].len();
                let fields = finish_world_capture(|| {
                    let mut fields: Vec<Box<dyn RetainedWorldField>> = Vec::with_capacity(FIELD_COUNT);
                    $(retain_field!(fields, pending, $prefix);)*
                    $(retain_field!(fields, pending, $privacy);)*
                    $(retain_field!(fields, pending, $suffix);)*
                    fields
                });
                let (dataspace_catalog, external_event_buf) = pending.extras.take().expect("original World extras");
                // Materialization requires every enclosing writer free. Only
                // now retire the same emptied shell and its retained control credit.
                drop(pending.original_shell.take());
                DetachedWorld { mode: pending.mode, fields, dataspace_catalog, external_event_buf, shells: pending.shells.take().expect("original shell reservation"), admission }
            }
        }
        #[allow(non_camel_case_types)]
        impl<OriginalShell, $($prefix: WorldCaptureSlot,)* $($privacy: WorldCaptureSlot,)* $($suffix: WorldCaptureSlot,)*>
            Drop for WorldCapture<OriginalShell, $($prefix,)* $($privacy,)* $($suffix,)*>
        {
            fn drop(&mut self) {
                self.release();
            }
        }
    };
}

// Borrow the original block and caller slots rather than passing another
// complete World owner by value through a deep retained-validation call stack.
#[inline(never)]
fn fill_world_capture(fill: impl FnOnce()) {
    fill()
}

// Never materialize the complete WorldBlockFields on the stack. Debug builds
// otherwise retain a temporary for every heterogeneous field simultaneously.
// This frame moves only one exact original owner into its existing caller slot.
#[inline(never)]
fn take_world_capture_field<Field: TakeWorldCapture>(
    original: &mut Field,
    pending: &mut Option<(Field::Capture, fn(&World) -> &Field::Target)>,
    target: fn(&World) -> &Field::Target,
) {
    assert!(pending.is_none(), "original World capture slot is empty");
    *pending = Some((original.take_capture(), target));
}

// Wrapper construction does not overlap native capture work. Each field also
// needs its own frame: debug builds otherwise reserve the temporaries of every
// expanded field in this large World inventory at once.
#[inline(never)]
fn finish_world_capture<R>(finish: impl FnOnce() -> R) -> R {
    finish()
}

#[inline(never)]
fn retain_world_capture_field<Slot: WorldCaptureSlot>(
    fields: &mut Vec<Box<dyn RetainedWorldField>>,
    pending: &mut Option<(Slot, fn(&World) -> &Slot::Target)>,
    name: &'static str,
) {
    let (slot, target) = pending.take().expect("original World capture slot");
    fields.push(Box::new(slot.retain(name, target)));
}

macro_rules! world_capture_mode {
    ($original:ident; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {{
        let mode = $original.parameters.mode();
        $(check_mode!($original, mode, $prefix);)*
        $(check_mode!($original, mode, $privacy);)*
        $(check_mode!($original, mode, $suffix);)*
        Ok(mode)
    }};
}

macro_rules! capture_world_fields {
    ($original:ident, $shells:ident;
        [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {{
        // These concrete metadata reads neither allocate nor run payload code.
        // Keep any inconsistent-mode verdict in the returned caller-owned slot.
        let mode = $original.parameters.mode();
        let refusal = $original.capture_mode().err();
        let mut pending = WorldCapture {
            $($prefix: None,)* $($privacy: None,)* $($suffix: None,)*
            extras: None, original_shell: None, shells: Some($shells), mode, refusal, started: false, complete: false,
        };
        fill_world_capture(|| {
            let WorldBlockFields {
                dataspace_catalog,
                $($prefix,)* $($privacy,)* $($suffix,)*
                external_event_buf,
            } = $original.fields.as_deref_mut().expect("original World block fields");
            // The exhaustive pattern binds references, not another complete
            // World. Each helper moves the exact original into its caller slot.
            $(take_world_capture_field($prefix, &mut pending.$prefix, |target: &World| &target.$prefix);)*
            $(take_world_capture_field($privacy, &mut pending.$privacy, |target: &World| &target.$privacy);)*
            $(take_world_capture_field($suffix, &mut pending.$suffix, |target: &World| &target.$suffix);)*
            // Default creates a populated catalog. An empty checked catalog is
            // allocation-free and exists only in the terminal empty shell.
            let empty_catalog = DataSpaceCatalog::new(Vec::new()).expect("empty catalog is valid");
            pending.extras = Some((
                std::mem::replace(dataspace_catalog, empty_catalog),
                std::mem::take(external_event_buf),
            ));
        });
        pending.original_shell = $original.fields.take();
        pending
    }};
}

macro_rules! check_mode {
    ($original:ident, $expected:ident, $field:ident) => {
        let actual = CaptureWorldField::capture_mode(&$original.$field).map_err(widen_error)?;
        if actual != $expected {
            return Err(CaptureError::InconsistentMode {
                field: stringify!($field),
                expected: $expected,
                actual,
            });
        }
    };
}

macro_rules! retain_field {
    ($fields:ident, $pending:ident, $field:ident) => {{
        retain_world_capture_field(&mut $fields, &mut $pending.$field, stringify!($field));
    }};
}

with_world_overlay_fields!(declare_world_capture);

impl<'world> WorldBlock<'world> {
    /// Admit and capture every original journal, then release all concrete writers.
    ///
    /// Mode checks inspect the actual original owners before the callback. The
    /// mandatory shell owner was reserved before execution. The callback admits
    /// the remaining retention and installation resources; it sees the complete
    /// immutable overlay, including block-local extras.
    /// Refusal drops all original writers without publication. Success moves
    /// extras and the original MV current/undo allocations without cloning them.
    pub(in crate::state) fn try_detach_journals<Admission, E>(
        self,
        shells: WorldJournalShellReservation,
        admit: impl FnOnce(&Self) -> Result<Admission, E>,
    ) -> Result<DetachedWorld<Admission>, CaptureError<E>> {
        // Local order releases the original World before any capacity refund,
        // including a normal admission refusal or an unwinding callback.
        let shells = shells;
        let original = self;
        original.capture_mode().map_err(widen_error)?;
        let admission = admit(&original).map_err(CaptureError::Admission)?;
        let mut pending = original.capture_slot(shells);
        pending.capture().map_err(widen_error)?;
        Ok(pending.into_journals(admission))
    }

    /// Read the complete original mode verdict without releasing any writer.
    pub(in crate::state) fn capture_mode(&self) -> Result<BlockMode, CaptureError<Infallible>> {
        with_world_overlay_fields!(world_capture_mode, self)
    }

    /// Move every original field into one opaque caller-owned capture slot.
    /// Only concrete metadata reads and inert moves occur before returning.
    pub(in crate::state) fn capture_slot(
        mut self,
        shells: WorldJournalShellReservation,
    ) -> impl WorldJournalCapture + 'world {
        with_world_overlay_fields!(capture_world_fields, self, shells)
    }
}

#[cfg(test)]
#[path = "world_journals_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "world_preparation_tests.rs"]
pub(in crate::state) mod preparation_tests;
