//! Prepare all original trigger journals before publishing any component.

use super::*;
use mv::{
    PublicationPreparationError,
    storage::{PreparedPublication, PublishedPublication},
};
use std::convert::Infallible;

/// A local preparation refusal retains the entire original trigger journal.
#[derive(Debug)]
pub(crate) enum SetPublicationError<E> {
    /// Installation capacity was refused before acquiring any component writer.
    Admission(E),
    /// The exact component is busy or no longer has its captured predecessor.
    Component {
        /// Name of the original component that refused publication preparation.
        field: &'static str,
        /// Local writer/cut refusal; component admission is covered by the Set.
        cause: PublicationPreparationError<Infallible>,
    },
}

/// Ten prepared original journals, with every writer retained together.
///
/// This is not a State/finality authorization. The enclosing publisher must
/// prepare all other State components before consuming this owner.
pub(crate) struct PreparedSet<'target, Admission, Installation> {
    original: Option<AcquiredSet<'target, Admission, Installation>>,
}

// One typed participant inventory defines the exclusive acquiring/prepared phases.
macro_rules! define_set_publication_components {
    ($($field:ident: ($($ty:ty),+)),+ $(,)?) => {
        struct AcquiredSet<'target, Admission, Installation> {
            mode: mv::BlockMode,
            $($field: PreparedPublication<'target, $($ty,)+ (), ()>,)+
            admission: Admission,
            installation: Installation,
        }
        struct SetPublicationComponents<'target, Admission> {
            mode: mv::BlockMode,
            $($field: mv::storage::DetachedPublicationSlot<'target, $($ty,)+ (), ()>,)+
            // Retain the original reservation after every component's cleanup.
            admission: Option<Admission>,
        }
        impl<'target, Admission> SetPublicationComponents<'target, Admission> {
            fn new(original: DetachedSet<Admission>, target: &'target Set) -> Self {
                let DetachedSet { mode, $($field,)+ admission } = original;
                // Every move below is inert: no readiness probe, admission or payload clone.
                Self { mode, $($field: $field.publication_slot(&target.$field),)+ admission: Some(admission) }
            }
            fn try_prepare<E>(&mut self) -> Result<(), SetPublicationError<E>> {
                $(self.$field.try_prepare(|_, _| Ok::<_, Infallible>(()))
                    .map_err(|cause| SetPublicationError::Component { field: stringify!($field), cause })?;)+
                Ok(())
            }
            fn release_writers(&mut self) { $(self.$field.release_writers();)+ }
            fn recover_original(&mut self) -> DetachedSet<Admission> {
                // Each lower method unlocks and returns its original journal; actual cleanup stays in its slot.
                DetachedSet { mode: self.mode, $($field: self.$field.recover_original(),)+
                    admission: self.admission.take().expect("original capture admission"), }
            }
            fn into_prepared<Installation>(self, installation: Installation) -> PreparedSet<'target, Admission, Installation> {
                PreparedSet { original: Some(AcquiredSet { mode: self.mode,
                    $($field: self.$field.into_prepared(),)+
                    admission: self.admission.expect("original capture admission"), installation,
                }) }
            }
            fn into_cleanup(self) -> [Option<mv::PublicationCleanup<()>>; 10] {
                assert!(self.admission.is_none(), "original journals must first be recovered");
                [$(Some(self.$field.into_cleanup()),)+]
            }
        }
    };
}
define_set_publication_components! {
    data_triggers: (TriggerId, LoadedAction<DataEventFilter>),
    pipeline_triggers: (TriggerId, LoadedAction<PipelineEventFilterBox>),
    time_triggers: (TriggerId, LoadedAction<TimeEventFilter>),
    by_call_triggers: (TriggerId, LoadedAction<ExecuteTriggerEventFilter>),
    ids: (TriggerId, TriggeringEventType),
    active_data_trigger_ids: (TriggerId, ()),
    active_pipeline_trigger_ids: (TriggerId, ()),
    active_time_trigger_ids: (TriggerId, ()),
    active_by_call_trigger_ids: (TriggerId, ()),
    contracts: (HashOf<IvmBytecode>, IvmBytecodeEntry),
}

/// Original released trigger participants and their enclosing resource owners.
/// Retain through the entire State publication interval before cleanup.
pub(crate) struct PublishedSet<Admission, Installation> {
    _data_triggers: PublishedPublication<TriggerId, LoadedAction<DataEventFilter>, (), ()>,
    _pipeline_triggers:
        PublishedPublication<TriggerId, LoadedAction<PipelineEventFilterBox>, (), ()>,
    _time_triggers: PublishedPublication<TriggerId, LoadedAction<TimeEventFilter>, (), ()>,
    _by_call_triggers:
        PublishedPublication<TriggerId, LoadedAction<ExecuteTriggerEventFilter>, (), ()>,
    _ids: PublishedPublication<TriggerId, TriggeringEventType, (), ()>,
    _active_data_trigger_ids: PublishedPublication<TriggerId, (), (), ()>,
    _active_pipeline_trigger_ids: PublishedPublication<TriggerId, (), (), ()>,
    _active_time_trigger_ids: PublishedPublication<TriggerId, (), (), ()>,
    _active_by_call_trigger_ids: PublishedPublication<TriggerId, (), (), ()>,
    _contracts: PublishedPublication<HashOf<IvmBytecode>, IvmBytecodeEntry, (), ()>,
    _admission: Admission,
    _installation: Installation,
}

/// Original abort notifications retained until every enclosing writer unlocks.
pub(crate) struct AbortedSet<Installation> {
    _components: [Option<mv::PublicationCleanup<()>>; 10],
    _installation: Option<Installation>,
}

enum SetPublicationPhase<'target, Admission> {
    Original(DetachedSet<Admission>),
    Components(SetPublicationComponents<'target, Admission>),
}

/// Caller-owned original participant group, installed before any admission or readiness work.
/// Normal refusal recovers exact journals while keeping every original deferred release here.
/// Caught unwind and terminal release allow cleanup only; this grants no State authority.
#[must_use = "retain this slot until every enclosing physical writer releases"]
pub(crate) struct DetachedSetPublicationSlot<'target, Admission, Installation> {
    target: &'target Set,
    phase: Option<SetPublicationPhase<'target, Admission>>,
    attempted: bool,
    complete: bool,
    retryable: bool,
    released: bool,
    recovered: bool,
    // Must follow the complete original phase so reservation cleanup cannot precede it.
    installation: Option<Installation>,
}

impl<Admission> DetachedSet<Admission> {
    /// Inertly retain the original aggregate before any callback or physical acquisition.
    pub(crate) fn publication_slot<Installation>(
        self,
        target: &Set,
    ) -> DetachedSetPublicationSlot<'_, Admission, Installation> {
        DetachedSetPublicationSlot {
            target,
            phase: Some(SetPublicationPhase::Original(self)),
            attempted: false,
            complete: false,
            retryable: true,
            released: false,
            recovered: false,
            installation: None,
        }
    }

    /// Standalone preparation delegates to the same caller-owned slot engine.
    /// An enclosing aggregate must retain its slot before calling the borrowed method
    /// if its own physical siblings also need to survive a callee unwind.
    pub(crate) fn try_prepare_publication<Installation, E>(
        self,
        target: &Set,
        admit: impl FnOnce(&Self, &Set) -> Result<Installation, E>,
    ) -> Result<
        PreparedSet<'_, Admission, Installation>,
        (Self, SetPublicationError<E>, AbortedSet<Installation>),
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

impl<'target, Admission, Installation>
    DetachedSetPublicationSlot<'target, Admission, Installation>
{
    /// Borrow the original aggregate once, with every partial native owner remaining in this slot.
    pub(crate) fn try_prepare<E>(
        &mut self,
        admit: impl FnOnce(&DetachedSet<Admission>, &Set) -> Result<Installation, E>,
    ) -> Result<(), SetPublicationError<E>> {
        assert!(
            !self.attempted && !self.released,
            "original aggregate preparation is one-shot"
        );
        self.attempted = true;
        self.retryable = false;
        let result = self.prepare_inner(admit);
        // A caught callee panic never reaches this normal-return recovery grant.
        self.retryable = true;
        self.complete = result.is_ok();
        result
    }
    fn prepare_inner<E>(
        &mut self,
        admit: impl FnOnce(&DetachedSet<Admission>, &Set) -> Result<Installation, E>,
    ) -> Result<(), SetPublicationError<E>> {
        let Some(SetPublicationPhase::Original(original)) = &self.phase else {
            unreachable!("original group before preparation")
        };
        self.installation =
            Some(admit(original, self.target).map_err(SetPublicationError::Admission)?);
        let Some(SetPublicationPhase::Original(original)) = self.phase.take() else {
            unreachable!()
        };
        self.phase = Some(SetPublicationPhase::Components(
            SetPublicationComponents::new(original, self.target),
        ));
        let Some(SetPublicationPhase::Components(components)) = &mut self.phase else {
            unreachable!()
        };
        components.try_prepare()
    }
    /// Terminal physical-only pass. Payloads, admission and all callbacks remain caller-owned.
    pub(crate) fn release_writers(&mut self) {
        self.released = true;
        self.retryable = false;
        self.complete = false;
        if let Some(SetPublicationPhase::Components(components)) = &mut self.phase {
            components.release_writers();
        }
    }
    /// Return the same original journals after normal refusal or complete prepared abort.
    /// The empty lower slots keep actual release events until this aggregate is retired.
    pub(crate) fn recover_original(&mut self) -> DetachedSet<Admission> {
        assert!(
            self.retryable && !self.released,
            "unwound/released group grants no journal"
        );
        self.released = true;
        self.complete = false;
        self.recovered = true;
        match self.phase.as_mut().expect("original participant phase") {
            SetPublicationPhase::Components(components) => components.recover_original(),
            SetPublicationPhase::Original(_) => {
                let Some(SetPublicationPhase::Original(original)) = self.phase.take() else {
                    unreachable!()
                };
                original
            }
        }
    }
    /// Transfer actual released cleanup only after original journals have been recovered.
    pub(crate) fn into_cleanup(mut self) -> AbortedSet<Installation> {
        assert!(
            self.released && self.recovered,
            "normal original recovery required"
        );
        let components = match self.phase.take() {
            Some(SetPublicationPhase::Components(components)) => components.into_cleanup(),
            None => std::array::from_fn(|_| None),
            Some(SetPublicationPhase::Original(_)) => {
                unreachable!("original journal was recovered")
            }
        };
        AbortedSet {
            _components: components,
            _installation: self.installation.take(),
        }
    }
    /// Inertly transfer only a fully prepared original group to its existing publisher.
    pub(crate) fn into_prepared(mut self) -> PreparedSet<'target, Admission, Installation> {
        assert!(
            self.complete && !self.released,
            "all original components prepared"
        );
        self.released = true;
        let Some(SetPublicationPhase::Components(components)) = self.phase.take() else {
            unreachable!()
        };
        components.into_prepared(
            self.installation
                .take()
                .expect("original installation admission"),
        )
    }
}
impl<Admission, Installation> Drop for DetachedSetPublicationSlot<'_, Admission, Installation> {
    fn drop(&mut self) {
        self.release_writers();
    }
}

macro_rules! consume_components {
    ($original:ident, $operation:ident; [$($field:ident,)*]) => {{
        let AcquiredSet { mode, $($field,)* admission, installation } = $original;
        consume_components!(@$operation mode, admission, installation; [$($field,)*])
    }};
    (@abort $mode:ident, $admission:ident, $installation:ident; [$($field:ident,)*]) => {{
        $(let $field = $field.abort();)*
        let retirement = AbortedSet { _components: [$(Some($field.1),)*], _installation: Some($installation) };
        (DetachedSet { mode: $mode, $($field: $field.0,)* admission: $admission }, retirement)
    }};
}

impl<Admission, Installation> AcquiredSet<'_, Admission, Installation> {
    /// Release every writer, returning the original ten journals and retention guard.
    pub(crate) fn abort(self) -> (DetachedSet<Admission>, AbortedSet<Installation>) {
        consume_components!(self, abort; [
            data_triggers, pipeline_triggers, time_triggers, by_call_triggers, ids,
            active_data_trigger_ids, active_pipeline_trigger_ids, active_time_trigger_ids,
            active_by_call_trigger_ids, contracts,
        ])
    }

    /// Consume each exact prepared component and return both resource guards.
    pub(crate) fn publish(self) -> PublishedSet<Admission, Installation> {
        PublishedSet {
            _data_triggers: self.data_triggers.publish(),
            _pipeline_triggers: self.pipeline_triggers.publish(),
            _time_triggers: self.time_triggers.publish(),
            _by_call_triggers: self.by_call_triggers.publish(),
            _ids: self.ids.publish(),
            _active_data_trigger_ids: self.active_data_trigger_ids.publish(),
            _active_pipeline_trigger_ids: self.active_pipeline_trigger_ids.publish(),
            _active_time_trigger_ids: self.active_time_trigger_ids.publish(),
            _active_by_call_trigger_ids: self.active_by_call_trigger_ids.publish(),
            _contracts: self.contracts.publish(),
            _admission: self.admission,
            _installation: self.installation,
        }
    }
}

impl<Admission, Installation> PreparedSet<'_, Admission, Installation> {
    /// Release all original writers before returning journals and deferred cleanup.
    pub(crate) fn abort(mut self) -> (DetachedSet<Admission>, AbortedSet<Installation>) {
        self.original
            .take()
            .expect("original prepared triggers")
            .abort()
    }

    /// Consume the same original components under the enclosing State authority.
    pub(crate) fn publish(mut self) -> PublishedSet<Admission, Installation> {
        self.original
            .take()
            .expect("original prepared triggers")
            .publish()
    }
}

impl<Admission, Installation> Drop for PreparedSet<'_, Admission, Installation> {
    fn drop(&mut self) {
        let Some(original) = self.original.take() else {
            return;
        };
        // Both capacities outlive every original payload and callback, including
        // cleanup unwind. No component may notify while a sibling is still held.
        let admission;
        let installation;
        let AcquiredSet {
            mode: _,
            data_triggers,
            pipeline_triggers,
            time_triggers,
            by_call_triggers,
            ids,
            active_data_trigger_ids,
            active_pipeline_trigger_ids,
            active_time_trigger_ids,
            active_by_call_trigger_ids,
            contracts,
            admission: retained_admission,
            installation: retained_installation,
        } = original;
        admission = retained_admission;
        installation = retained_installation;
        let data_triggers = data_triggers.abort();
        let pipeline_triggers = pipeline_triggers.abort();
        let time_triggers = time_triggers.abort();
        let by_call_triggers = by_call_triggers.abort();
        let ids = ids.abort();
        let active_data_trigger_ids = active_data_trigger_ids.abort();
        let active_pipeline_trigger_ids = active_pipeline_trigger_ids.abort();
        let active_time_trigger_ids = active_time_trigger_ids.abort();
        let active_by_call_trigger_ids = active_by_call_trigger_ids.abort();
        let contracts = contracts.abort();
        drop((
            data_triggers,
            pipeline_triggers,
            time_triggers,
            by_call_triggers,
            ids,
            active_data_trigger_ids,
            active_pipeline_trigger_ids,
            active_time_trigger_ids,
            active_by_call_trigger_ids,
            contracts,
        ));
        drop((admission, installation));
    }
}
