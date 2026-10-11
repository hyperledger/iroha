//! Freeze inside the original typed field; retain actual release custody inline.

use super::*;

impl<B: OriginalPublicationBlock> BlockField<B> {
    /// Install the original capture slot without acquiring or releasing a writer.
    /// Every sibling must enter this phase before any calls `try_finish_freeze`.
    ///
    /// Native World admission covers the complete original shell and Cell
    /// successor inventory before execution. This transition adds no allocation.
    pub(crate) fn begin_freeze(&mut self) {
        assert!(!self.released, "field was terminally released");
        assert!(
            matches!(self.phase, Some(Phase::Executing(_))),
            "original field freeze is one-shot"
        );
        let Some(Phase::Executing(block)) = self.phase.take() else {
            unreachable!("checked original execution phase")
        };
        self.phase = Some(Phase::Capturing(block.into_freeze_capture()));
    }

    /// Capture the same original private generations and release their writers.
    /// Refusal or unwind retains the actual capture slot for terminal cleanup;
    /// neither grants permission to execute or retry the capture callback.
    ///
    /// Successful capture retains the original release notices in this field.
    /// The aggregate must release all siblings and fences before retiring them.
    pub(crate) fn try_finish_freeze<E>(
        &mut self,
        admit: impl FnOnce(&B) -> Result<(), E>,
    ) -> Result<(), E> {
        assert!(!self.released, "field was terminally released");
        let Some(Phase::Capturing(slot)) = self.phase.as_mut() else {
            panic!("original field capture was not installed")
        };
        slot.try_capture(admit)?;
        let Some(Phase::Capturing(slot)) = self.phase.take() else {
            unreachable!("completed original capture")
        };
        let (original, cleanup) = slot.into_detached();
        self.phase = Some(Phase::Frozen(original));
        self.freeze_cleanup = cleanup;
        Ok(())
    }

    /// Complete the original no-callback capture after all sibling slots exist.
    pub(crate) fn finish_freeze(&mut self) {
        let result = self.try_finish_freeze(|_| Ok::<_, core::convert::Infallible>(()));
        match result {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    /// Transfer the original journal and notices to the aggregate's exact retry
    /// cursor. This does not create a second publisher or refresh its predecessor.
    pub(crate) fn into_frozen(mut self) -> (B::Frozen, CaptureCleanup) {
        assert!(!self.released, "field was terminally released");
        assert!(
            matches!(self.phase, Some(Phase::Frozen(_))),
            "original field must be completely frozen"
        );
        let Some(Phase::Frozen(original)) = self.phase.take() else {
            unreachable!("checked original frozen phase")
        };
        (original, std::mem::take(&mut self.freeze_cleanup))
    }
}

impl<B: OriginalPublicationBlock> BlockField<B>
where
    B::Publication: mv::FrozenBlockPublication<Frozen = B::Frozen>,
{
    /// Install this original frozen journal in its existing publication slot.
    /// This private constructor must only move custody: all siblings are installed
    /// before the aggregate calls any physical preparation. On admission refusal
    /// the unchanged journal returns directly to the original readable phase.
    pub(crate) fn begin_frozen_publication<E>(
        &mut self,
        install: impl FnOnce(B::Frozen) -> Result<B::Publication, (B::Frozen, E)>,
    ) -> Result<(), E> {
        assert!(!self.released, "field was terminally released");
        assert!(
            self.retry_cleanup.is_none(),
            "previous original cleanup is still retained"
        );
        assert!(
            matches!(self.phase, Some(Phase::Frozen(_))),
            "original field is not frozen"
        );
        let Some(Phase::Frozen(original)) = self.phase.take() else {
            unreachable!()
        };
        match install(original) {
            Ok(slot) => {
                self.phase = Some(Phase::Publishing(slot));
                Ok(())
            }
            Err((original, error)) => {
                self.phase = Some(Phase::Frozen(original));
                Err(error)
            }
        }
    }

    /// Reacquire this field's exact current/undo pair; never a fresh read view.
    pub(crate) fn try_prepare_frozen_publication(
        &mut self,
    ) -> Result<(), mv::PublicationPreparationError<core::convert::Infallible>> {
        use mv::FrozenBlockPublication as _;
        assert!(!self.released, "field was terminally released");
        let Some(Phase::Publishing(slot)) = self.phase.as_mut() else {
            panic!("original frozen publication slot was not installed");
        };
        slot.try_prepare_frozen()
    }

    /// Recover the identical original payload after normal refusal or abort.
    /// Every sibling must be recovered before any cleanup is retired. An unwind
    /// remains in the caller-owned slot and permits terminal release only.
    pub(crate) fn recover_frozen_publication(&mut self) {
        use mv::FrozenBlockPublication as _;
        assert!(!self.released, "field was terminally released");
        assert!(
            self.retry_cleanup.is_none(),
            "original attempt cleanup already retained"
        );
        let Some(Phase::Publishing(slot)) = self.phase.as_mut() else {
            panic!("original frozen publication slot was not installed");
        };
        let original = slot.recover_frozen();
        let Some(Phase::Publishing(slot)) = self.phase.take() else {
            unreachable!()
        };
        self.retry_cleanup = Some(slot);
        self.phase = Some(Phase::Frozen(original));
    }

    /// Recover only installed slots after a partially completed aggregate install.
    /// Frozen siblings already retain their exact original and need no transition.
    pub(crate) fn recover_installed_frozen_publication(&mut self) {
        assert!(!self.released, "field was terminally released");
        match self.phase.as_ref() {
            Some(Phase::Frozen(_) | Phase::Reading(_)) => {}
            Some(Phase::Publishing(_)) => self.recover_frozen_publication(),
            _ => panic!("original frozen or reacquiring field required"),
        }
    }

    /// Retire actual release notices only after the entire aggregate is unlocked.
    /// This does not release a writer or replace any original frozen payload.
    pub(crate) fn retire_frozen_cleanup(&mut self) {
        assert!(!self.released, "field was terminally released");
        assert!(
            matches!(self.phase, Some(Phase::Frozen(_) | Phase::Reading(_))),
            "complete original frozen field required"
        );
        drop(self.retry_cleanup.take());
        drop(std::mem::take(&mut self.freeze_cleanup));
    }
}

#[cfg(test)]
#[path = "frozen_tests.rs"]
mod tests;

// Closed typed constructors: only exact original-owner moves are allowed here.
// The aggregate cannot inject payload callbacks while a field leaves its slot.
impl<'a, V: Value, C: Send + Sync + 'static> CellField<'a, V, C> {
    pub(crate) fn install_frozen_publication(
        &mut self,
        target: &'a mv::cell::Cell<V, C>,
    ) -> Result<(), mv::storage::AdmittedStorageError> {
        self.begin_frozen_publication(|original| {
            Ok(mv::cell::BlockPublicationSlot::from_frozen(
                original, target,
            ))
        })
    }
}
impl<'a, K: Key, V: Value> StorageField<'a, K, V> {
    pub(crate) fn install_frozen_publication(
        &mut self,
        target: &'a mv::storage::Storage<K, V>,
    ) -> Result<(), mv::storage::AdmittedStorageError> {
        self.begin_frozen_publication(|original| {
            Ok(mv::storage::BlockPublicationSlot::from_frozen(
                original, target,
            ))
        })
    }
}
