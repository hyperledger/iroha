//! Consume every captured World component under its exact original writers.

use super::*;
use crate::smartcontracts::isi::triggers::set::{PreparedSet, SetPublicationError};
use mv::PublicationPreparationError;
use resources::WorldJournalShellInstallation;
use std::alloc::Layout;

// These layouts describe the concrete Box pointees constructed below. Lifetimes
// do not change layout; no target owner, value, reader or writer is acquired.
pub(super) fn storage_shell_layout<K: Key, V: Value, M: WorldStorageMode<K, V>>() -> Layout {
    Layout::new::<PreparedStorage<'static, K, V, M>>()
}

pub(super) fn cell_shell_layout<V: Value, C: Send + Sync + 'static>() -> Layout {
    Layout::new::<PreparedCell<'static, V, C>>()
}

pub(super) fn triggers_shell_layout() -> Layout {
    Layout::new::<PreparedTriggers<'static>>()
}

pub(super) fn field_vector_layout(capacity: usize) -> Result<Layout, std::alloc::LayoutError> {
    Layout::array::<Box<dyn PreparedWorldField>>(capacity)
}

/// Exact local component that prevented complete World preparation.
#[derive(Debug)]
pub(in crate::state) struct FieldRefusal {
    /// Original field from the exhaustive World inventory.
    pub field: &'static str,
    /// Inner TriggerSet component, when that aggregate refused preparation.
    pub trigger_component: Option<&'static str>,
    /// Original physical refusal; never a consensus verdict.
    pub cause: PublicationPreparationError<mv::storage::AdmittedStorageError>,
}

/// Local refusal retains the original World journals in their caller-owned slot.
/// The caller must recover or terminally release the slot before awaiting a retry.
#[derive(Debug)]
pub(in crate::state) enum WorldPublicationError<E> {
    /// Complete installation resources were refused before any writer acquisition.
    Admission(E),
    /// A previous installation still owns its original delayed cleanup shells.
    ShellsNotRetired(resources::ShellsNotRetired),
    /// One exact original owner could not be prepared.
    Field(FieldRefusal),
}

pub(super) trait PreparedWorldField {
    fn try_prepare(&mut self) -> Result<(), FieldRefusal>;
    fn release(&mut self);
    fn release_for_recovery(&mut self);
    fn abort(&mut self) -> Box<dyn RetainedWorldField>;
    fn publish(&mut self);
}

enum FieldPhase<Slot, Prepared> {
    Preparing(Slot),
    Prepared(Prepared),
    Recovered,
}

struct PreparedStorage<'target, K: Key, V: Value, M: WorldStorageMode<K, V>> {
    original: Option<Box<RetainedStorage<K, V, M>>>,
    phase: FieldPhase<M::Slot<'target>, M::Prepared<'target>>,
    published: Option<M::Published<'target>>,
    aborted: Option<M::Aborted<'target>>,
    released: bool,
    normal_recovery: bool,
}

impl<K: Key, V: Value, M: WorldStorageMode<K, V>> PreparedWorldField
    for PreparedStorage<'_, K, V, M>
where
    M::Charge: Send + Sync + 'static,
{
    fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
        assert!(!self.released, "original field was terminally released");
        let name = self.original.as_ref().expect("original field box").name;
        let FieldPhase::Preparing(slot) = &mut self.phase else {
            panic!("original field preparation is one-shot");
        };
        M::try_prepare(slot).map_err(|cause| FieldRefusal {
            field: name,
            trigger_component: None,
            cause,
        })?;
        let FieldPhase::Preparing(slot) = std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original field slot");
        };
        self.phase = FieldPhase::Prepared(M::into_prepared(slot));
        Ok(())
    }

    fn release(&mut self) {
        self.released = true;
        if let FieldPhase::Preparing(slot) = &mut self.phase {
            M::release_writers(slot);
        } else if matches!(&self.phase, FieldPhase::Prepared(_)) {
            let FieldPhase::Prepared(journal) =
                std::mem::replace(&mut self.phase, FieldPhase::Recovered)
            else {
                unreachable!("original prepared field");
            };
            let (journal, retirement) = M::abort(journal);
            self.original.as_mut().expect("original field box").journal = Some(journal);
            self.aborted = Some(retirement);
        }
    }

    fn release_for_recovery(&mut self) {
        assert!(
            !self.released,
            "terminal field release is not retry authority"
        );
        if self.normal_recovery {
            return;
        }
        match &mut self.phase {
            FieldPhase::Preparing(slot) => {
                let journal = M::recover_original(slot);
                self.original.as_mut().expect("original field box").journal = Some(journal);
            }
            FieldPhase::Prepared(_) => {
                let FieldPhase::Prepared(journal) =
                    std::mem::replace(&mut self.phase, FieldPhase::Recovered)
                else {
                    unreachable!("original prepared field");
                };
                let (journal, retirement) = M::abort(journal);
                self.original.as_mut().expect("original field box").journal = Some(journal);
                self.aborted = Some(retirement);
            }
            FieldPhase::Recovered => panic!("original field was already consumed"),
        }
        self.normal_recovery = true;
    }

    fn abort(&mut self) -> Box<dyn RetainedWorldField> {
        self.release_for_recovery();
        self.released = true;
        self.original.take().expect("original field box")
    }

    fn publish(&mut self) {
        assert!(
            !self.released && matches!(&self.phase, FieldPhase::Prepared(_)),
            "complete original field"
        );
        let FieldPhase::Prepared(journal) =
            std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original prepared field");
        };
        self.published = Some(M::publish(journal));
        self.released = true;
    }
}

pub(super) fn storage_slot<'target, K: Key, V: Value, M: WorldStorageMode<K, V>>(
    mut original: Box<RetainedStorage<K, V, M>>,
    world: &'target World,
) -> Box<dyn PreparedWorldField + 'target>
where
    M::Charge: Send + Sync + 'static,
{
    let target = (original.target)(world);
    let journal = original.journal.take().expect("retained original journal");
    // Inert shell construction precedes every field's physical preparation.
    Box::new(PreparedStorage {
        original: Some(original),
        phase: FieldPhase::Preparing(M::publication_slot(journal, target)),
        published: None,
        aborted: None,
        released: false,
        normal_recovery: false,
    })
}

struct PreparedCell<'target, V: Value, C: Send + Sync + 'static> {
    original: Option<Box<RetainedCell<V, C>>>,
    phase: FieldPhase<
        mv::cell::DetachedPublicationSlot<'target, V, (), (), C>,
        mv::cell::PreparedPublication<'target, V, (), (), C>,
    >,
    published: Option<mv::cell::PublishedPublication<V, (), (), C>>,
    aborted: Option<mv::PublicationCleanup<()>>,
    released: bool,
    normal_recovery: bool,
}

impl<V: Value, C: Send + Sync + 'static> PreparedWorldField for PreparedCell<'_, V, C> {
    fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
        assert!(!self.released, "original field was terminally released");
        let name = self.original.as_ref().expect("original field box").name;
        let FieldPhase::Preparing(slot) = &mut self.phase else {
            panic!("original field preparation is one-shot");
        };
        slot.try_prepare(|_, _| Ok::<_, Infallible>(()))
            .map_err(|cause| FieldRefusal {
                field: name,
                trigger_component: None,
                cause: storage_mode::widen_untracked(cause),
            })?;
        let FieldPhase::Preparing(slot) = std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original field slot");
        };
        self.phase = FieldPhase::Prepared(slot.into_prepared());
        Ok(())
    }

    fn release(&mut self) {
        self.released = true;
        if let FieldPhase::Preparing(slot) = &mut self.phase {
            slot.release_writers();
        } else if matches!(&self.phase, FieldPhase::Prepared(_)) {
            let FieldPhase::Prepared(journal) =
                std::mem::replace(&mut self.phase, FieldPhase::Recovered)
            else {
                unreachable!("original prepared field");
            };
            let (journal, retirement) = journal.abort();
            self.original.as_mut().expect("original field box").journal = Some(journal);
            self.aborted = Some(retirement);
        }
    }

    fn release_for_recovery(&mut self) {
        assert!(
            !self.released,
            "terminal field release is not retry authority"
        );
        if self.normal_recovery {
            return;
        }
        match &mut self.phase {
            FieldPhase::Preparing(slot) => {
                let journal = slot.recover_original();
                self.original.as_mut().expect("original field box").journal = Some(journal);
            }
            FieldPhase::Prepared(_) => {
                let FieldPhase::Prepared(journal) =
                    std::mem::replace(&mut self.phase, FieldPhase::Recovered)
                else {
                    unreachable!("original prepared field");
                };
                let (journal, retirement) = journal.abort();
                self.original.as_mut().expect("original field box").journal = Some(journal);
                self.aborted = Some(retirement);
            }
            FieldPhase::Recovered => panic!("original field was already consumed"),
        }
        self.normal_recovery = true;
    }

    fn abort(&mut self) -> Box<dyn RetainedWorldField> {
        self.release_for_recovery();
        self.released = true;
        self.original.take().expect("original field box")
    }

    fn publish(&mut self) {
        assert!(
            !self.released && matches!(&self.phase, FieldPhase::Prepared(_)),
            "complete original field"
        );
        let FieldPhase::Prepared(journal) =
            std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original prepared field");
        };
        self.published = Some(journal.publish());
        self.released = true;
    }
}

pub(super) fn cell_slot<'target, V: Value, C: Send + Sync + 'static>(
    mut original: Box<RetainedCell<V, C>>,
    world: &'target World,
) -> Box<dyn PreparedWorldField + 'target> {
    let target = (original.target)(world);
    let journal = original.journal.take().expect("retained original journal");
    // Inert shell construction precedes every field's physical preparation.
    Box::new(PreparedCell {
        original: Some(original),
        phase: FieldPhase::Preparing(journal.publication_slot(target)),
        published: None,
        aborted: None,
        released: false,
        normal_recovery: false,
    })
}

struct PreparedTriggers<'target> {
    original: Option<Box<RetainedTriggers>>,
    phase: FieldPhase<
        crate::smartcontracts::isi::triggers::set::DetachedSetPublicationSlot<'target, (), ()>,
        PreparedSet<'target, (), ()>,
    >,
    published: Option<crate::smartcontracts::isi::triggers::set::PublishedSet<(), ()>>,
    aborted: Option<crate::smartcontracts::isi::triggers::set::AbortedSet<()>>,
    released: bool,
    normal_recovery: bool,
}

impl PreparedWorldField for PreparedTriggers<'_> {
    fn try_prepare(&mut self) -> Result<(), FieldRefusal> {
        assert!(!self.released, "original field was terminally released");
        let name = self.original.as_ref().expect("original field box").name;
        let FieldPhase::Preparing(slot) = &mut self.phase else {
            panic!("original field preparation is one-shot");
        };
        slot.try_prepare(|_, _| Ok::<_, Infallible>(()))
            .map_err(|error| match error {
                SetPublicationError::Admission(impossible) => match impossible {},
                SetPublicationError::Component { field, cause } => FieldRefusal {
                    field: name,
                    trigger_component: Some(field),
                    cause: storage_mode::widen_untracked(cause),
                },
            })?;
        let FieldPhase::Preparing(slot) = std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original field slot");
        };
        self.phase = FieldPhase::Prepared(slot.into_prepared());
        Ok(())
    }

    fn release(&mut self) {
        self.released = true;
        if let FieldPhase::Preparing(slot) = &mut self.phase {
            slot.release_writers();
        } else if matches!(&self.phase, FieldPhase::Prepared(_)) {
            let FieldPhase::Prepared(journal) =
                std::mem::replace(&mut self.phase, FieldPhase::Recovered)
            else {
                unreachable!("original prepared field");
            };
            let (journal, retirement) = journal.abort();
            self.original.as_mut().expect("original field box").journal = Some(journal);
            self.aborted = Some(retirement);
        }
    }

    fn release_for_recovery(&mut self) {
        assert!(
            !self.released,
            "terminal field release is not retry authority"
        );
        if self.normal_recovery {
            return;
        }
        match &mut self.phase {
            FieldPhase::Preparing(slot) => {
                let journal = slot.recover_original();
                self.original.as_mut().expect("original field box").journal = Some(journal);
            }
            FieldPhase::Prepared(_) => {
                let FieldPhase::Prepared(journal) =
                    std::mem::replace(&mut self.phase, FieldPhase::Recovered)
                else {
                    unreachable!("original prepared field");
                };
                let (journal, retirement) = journal.abort();
                self.original.as_mut().expect("original field box").journal = Some(journal);
                self.aborted = Some(retirement);
            }
            FieldPhase::Recovered => panic!("original field was already consumed"),
        }
        self.normal_recovery = true;
    }

    fn abort(&mut self) -> Box<dyn RetainedWorldField> {
        self.release_for_recovery();
        self.released = true;
        self.original.take().expect("original field box")
    }

    fn publish(&mut self) {
        assert!(
            !self.released && matches!(&self.phase, FieldPhase::Prepared(_)),
            "complete original field"
        );
        let FieldPhase::Prepared(journal) =
            std::mem::replace(&mut self.phase, FieldPhase::Recovered)
        else {
            unreachable!("checked original prepared field");
        };
        self.published = Some(journal.publish());
        self.released = true;
    }
}

pub(super) fn triggers_slot<'target>(
    mut original: Box<RetainedTriggers>,
    world: &'target World,
) -> Box<dyn PreparedWorldField + 'target> {
    let target = (original.target)(world);
    let journal = original.journal.take().expect("retained original journal");
    // Inert shell construction precedes every field's physical preparation.
    Box::new(PreparedTriggers {
        original: Some(original),
        phase: FieldPhase::Preparing(journal.publication_slot(target)),
        published: None,
        aborted: None,
        released: false,
        normal_recovery: false,
    })
}

struct PreparedWorldFields<'target>(Vec<Box<dyn PreparedWorldField + 'target>>);

impl<'target> PreparedWorldFields<'target> {
    fn release_all(&mut self) {
        for field in &mut self.0 {
            field.release();
        }
    }

    fn recover_all(&mut self) {
        // Retain every original box and notification through the full physical
        // pass. Only a subsequent normal transfer may return retry authority.
        for field in &mut self.0 {
            field.release_for_recovery();
        }
    }

    fn into_inner(mut self) -> Vec<Box<dyn PreparedWorldField + 'target>> {
        std::mem::take(&mut self.0)
    }
}
impl<'target> std::ops::Deref for PreparedWorldFields<'target> {
    type Target = Vec<Box<dyn PreparedWorldField + 'target>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for PreparedWorldFields<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for PreparedWorldFields<'_> {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// Original shells and abort cleanup retained with installation admission.
pub(in crate::state) struct AbortedWorld<'target, Installation> {
    _fields: PreparedWorldFields<'target>,
    _installation: Option<Installation>,
    _shell_installation: Option<WorldJournalShellInstallation>,
}

/// All original World writers retained together, with no State authorization.
///
/// The enclosing State owner must prepare every other component and authenticate
/// its finality/persistence authority before making any component visible.
#[must_use = "complete World preparation must be published or aborted by its State owner"]
pub(in crate::state) struct PreparedWorld<'target, Admission, Installation> {
    mode: BlockMode,
    fields: PreparedWorldFields<'target>,
    // Original field-vector allocation, kept empty until an exact rollback.
    retry: Vec<Box<dyn RetainedWorldField>>,
    dataspace_catalog: DataSpaceCatalog,
    external_event_buf: Vec<EventBox>,
    shells: WorldJournalShellReservation,
    shell_installation: WorldJournalShellInstallation,
    admission: Admission,
    installation: Installation,
}

/// Original field boxes and containers retained after physical publication.
/// Drop after all State fences, before releasing the enclosing resource guards.
pub(in crate::state) struct WorldRetirement<'target> {
    _fields: Vec<Box<dyn PreparedWorldField + 'target>>,
    _retry: Vec<Box<dyn RetainedWorldField>>,
    _shells: WorldJournalShellReservation,
    _shell_installation: WorldJournalShellInstallation,
}

#[path = "world_preparation.rs"]
mod preparation;

impl<Admission> DetachedWorld<Admission> {
    /// Prepare through the same caller-owned aggregate used by State publication.
    pub(in crate::state) fn try_prepare_publication<'target, Installation, E>(
        self,
        target: &'target World,
        admit: impl FnOnce(&Self, &World) -> Result<Installation, E>,
    ) -> Result<
        PreparedWorld<'target, Admission, Installation>,
        (
            Self,
            WorldPublicationError<E>,
            AbortedWorld<'target, Installation>,
        ),
    > {
        let mut slot = self.publication_slot(target);
        match slot.try_prepare(admit) {
            Ok(()) => Ok(slot.into_prepared()),
            Err(error) => {
                let original = slot.recover_original();
                Err((original, error, slot.into_cleanup()))
            }
        }
    }
}

impl<'target, Admission, Installation> PreparedWorld<'target, Admission, Installation> {
    /// Observe actual constructed shell sizes and both coexisting Vec capacities.
    #[cfg(test)]
    pub(super) fn observed_shell_layouts(
        &self,
    ) -> (Layout, Layout, impl ExactSizeIterator<Item = Layout> + '_) {
        (
            Layout::array::<Box<dyn RetainedWorldField>>(self.retry.capacity()).unwrap(),
            field_vector_layout(self.fields.capacity()).unwrap(),
            self.fields
                .iter()
                .map(|field| Layout::for_value(field.as_ref())),
        )
    }

    /// Release every writer and return the complete original journals and extras.
    pub(in crate::state) fn abort(
        self,
    ) -> (
        DetachedWorld<Admission>,
        AbortedWorld<'target, Installation>,
    ) {
        let installation;
        let admission;
        let Self {
            mode,
            mut fields,
            mut retry,
            dataspace_catalog,
            external_event_buf,
            shells,
            shell_installation,
            admission: retained_admission,
            installation: retained_installation,
        } = self;
        installation = retained_installation;
        admission = retained_admission;
        fields.recover_all();
        retry.extend(fields.iter_mut().map(|field| field.abort()));
        let retirement = AbortedWorld {
            _fields: fields,
            _installation: Some(installation),
            _shell_installation: Some(shell_installation),
        };
        (
            DetachedWorld {
                mode,
                fields: retry,
                dataspace_catalog,
                external_event_buf,
                shells,
                admission,
            },
            retirement,
        )
    }

    /// Consume all prepared fields, handing extras and both guards to State.
    /// Caller-owned State visibility/finality must already exclude partial reads.
    pub(in crate::state) fn publish(
        self,
    ) -> (
        DataSpaceCatalog,
        Vec<EventBox>,
        WorldRetirement<'target>,
        Admission,
        Installation,
    ) {
        let installation;
        let admission;
        let Self {
            mode: _,
            mut fields,
            retry,
            dataspace_catalog,
            external_event_buf,
            shells,
            shell_installation,
            admission: retained_admission,
            installation: retained_installation,
        } = self;
        installation = retained_installation;
        admission = retained_admission;
        for field in fields.iter_mut() {
            field.publish();
        }
        let retirement = WorldRetirement {
            _fields: fields.into_inner(),
            _retry: retry,
            _shells: shells,
            _shell_installation: shell_installation,
        };
        (
            dataspace_catalog,
            external_event_buf,
            retirement,
            admission,
            installation,
        )
    }
}
