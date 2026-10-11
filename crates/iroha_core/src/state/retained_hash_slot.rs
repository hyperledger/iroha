//! Caller-owned retained hash acquisition, before preflight or admission.
use super::*;
use concread::bptree::{BptreeMapAbandonment, BptreeMapCommitSlot, BptreeMapOwnedAcquisition};
use iroha_allocation::release::{DeferredRelease, ReleaseGuard};

type Acquired<'a> =
    ReleaseGuard<'a, BptreeMapOwnedAcquisition<'a, usize, HashOf<BlockHeader>, BlockHashMode>>;
type Preparing<'a> =
    ReleaseGuard<'a, BptreeMapCommitSlot<'a, usize, HashOf<BlockHeader>, BlockHashMode>>;
type Abandoned = BptreeMapAbandonment<usize, HashOf<BlockHeader>, BlockHashMode>;

enum Phase<'a> {
    Original(DetachedBlockHashes),
    Acquired(Acquired<'a>),
    Preparing(Preparing<'a>),
    Abandoned { _work: Abandoned },
}

/// This slot must be installed in the owner of all enclosing physical fences
/// before `try_prepare` is called. Returning cleanup only on success is insufficient.
pub(crate) struct RetainedHashSlot<'a, I> {
    target: &'a BlockHashes,
    phase: Option<Phase<'a>>,
    mode: mv::BlockMode,
    visible_len: usize,
    reserved_tip: Option<usize>,
    height: usize,
    attempted: bool,
    complete: bool,
    retryable: bool,
    released: bool,
    // Payload owners precede the actual retained release events in drop order.
    installation: Option<I>,
    preflight_release: Option<DeferredRelease>,
    reader_release: Option<DeferredRelease>,
    writer_release: Option<DeferredRelease>,
}

impl<'a, I> RetainedHashSlot<'a, I> {
    pub(crate) fn new(original: DetachedBlockHashes, target: &'a BlockHashes) -> Self {
        Self {
            mode: original.mode,
            visible_len: original.visible_len,
            reserved_tip: original.reserved_tip,
            target,
            phase: Some(Phase::Original(original)),
            height: 0,
            attempted: false,
            complete: false,
            retryable: true,
            released: false,
            installation: None,
            preflight_release: None,
            reader_release: None,
            writer_release: None,
        }
    }

    fn original(&self) -> &DetachedBlockHashes {
        match self.phase.as_ref() {
            Some(Phase::Original(original)) => original,
            _ => panic!("original retained hash phase"),
        }
    }

    fn refuse<E>(
        &mut self,
        error: mv::PublicationPreparationError<E>,
    ) -> Result<(), mv::PublicationPreparationError<E>> {
        self.retryable = true;
        Err(error)
    }

    pub(crate) fn try_prepare<E>(
        &mut self,
        admit: impl FnOnce(&DetachedBlockHashes, &BlockHashes) -> Result<I, E>,
    ) -> Result<(), mv::PublicationPreparationError<E>> {
        assert!(
            !self.attempted && !self.released,
            "retained hash preparation is one-shot"
        );
        self.attempted = true;
        // A caught callee panic cannot be converted into a reusable journal.
        self.retryable = false;
        if self.reserved_tip.is_some() {
            return self.refuse(mv::PublicationPreparationError::Changed);
        }
        let target = self.target;
        let Some(map) = target.map() else {
            return self.refuse(mv::PublicationPreparationError::Changed);
        };
        let reader_wait = map.observe_reader_release();
        let observed = self.original().work.try_matches_current_retaining(map);
        let current = match observed {
            Ok((current, release)) => {
                // The actual physical reader is already free, but its callback
                // stays in the caller before admission can return or unwind.
                self.preflight_release = release;
                current
            }
            Err(error) => return self.refuse(refusal(error, reader_wait)),
        };
        if !current {
            return self.refuse(mv::PublicationPreparationError::Changed);
        }
        let installation = match admit(self.original(), target) {
            Ok(value) => value,
            Err(error) => return self.refuse(mv::PublicationPreparationError::Admission(error)),
        };
        self.installation = Some(installation);
        // Operability check retains the original owner and installation in place.
        self.height = self.original().len();
        let Some(Phase::Original(original)) = self.phase.take() else {
            unreachable!("checked original retained hash");
        };
        let writer_wait = target.released.observe();
        let acquired = match map.try_acquire_owned(original.work) {
            Ok(acquired) => target.released.poisoning_guard(acquired),
            Err((work, error)) => {
                self.phase = Some(Phase::Original(self.restore(work)));
                return self.refuse(refusal(error, writer_wait));
            }
        };
        self.phase = Some(Phase::Acquired(acquired));
        let Some(Phase::Acquired(acquired)) = self.phase.take() else {
            unreachable!()
        };
        // This native transition performs only pointer/poison checks and inert
        // moves. No cursor, allocation, user code or payload destructor runs.
        let writer = match acquired.try_map_preserving_release(|owner| owner.validate()) {
            Ok(writer) => writer,
            Err((acquired, error)) => {
                self.phase = Some(Phase::Acquired(acquired));
                return self.refuse(refusal(error, writer_wait));
            }
        };
        self.phase = Some(Phase::Preparing(
            writer.map_preserving_release(|w| w.commit_slot()),
        ));
        let wait = map.observe_reader_release();
        let Some(Phase::Preparing(slot)) = self.phase.as_mut() else {
            unreachable!()
        };
        match slot.try_prepare() {
            Ok(()) => {
                self.complete = true;
                self.retryable = true;
                Ok(())
            }
            Err(error) => self.refuse(refusal(error, wait)),
        }
    }

    fn restore(&self, work: BlockHashWork) -> DetachedBlockHashes {
        DetachedBlockHashes {
            work,
            mode: self.mode,
            visible_len: self.visible_len,
            reserved_tip: self.reserved_tip,
        }
    }

    /// Normal return only: recover exact originals, retaining all actual release
    /// events and installation in this same caller slot until outer release.
    pub(crate) fn recover_original(&mut self) -> DetachedBlockHashes {
        assert!(
            self.retryable && !self.released,
            "failed/unwound hash is not retry authority"
        );
        self.released = true;
        self.complete = false;
        match self.phase.take().expect("original retained hash") {
            Phase::Original(original) => original,
            Phase::Acquired(acquired) => {
                let (work, release) = acquired.release_deferred(|a| a.abort());
                self.writer_release = Some(release);
                self.restore(work)
            }
            Phase::Preparing(slot) => {
                let ((work, reader), writer) = slot.release_deferred(|slot| {
                    let (writer, reader) = slot.abort_retaining();
                    (writer.detach(), reader)
                });
                self.reader_release = reader;
                self.writer_release = Some(writer);
                self.restore(work)
            }
            Phase::Abandoned { .. } => unreachable!("terminal cleanup is never a journal"),
        }
    }

    /// Inert transfer after complete preparation, including the original
    /// preflight reader notification through final publication or abort.
    pub(crate) fn take_prepared(&mut self) -> PreparedBlockHashes<'a, I> {
        assert!(
            self.complete && !self.released,
            "complete original hash preparation"
        );
        let Some(Phase::Preparing(slot)) = self.phase.take() else {
            unreachable!()
        };
        self.complete = false;
        self.released = true;
        PreparedBlockHashes {
            owner: NativeLaneStateOwner {
                _family: self.target.map().expect("original map").family(),
            },
            prepared: slot.map_preserving_release(|slot| slot.into_prepared()),
            mode: self.mode,
            visible_len: self.visible_len,
            height: self.height,
            committed_height: &self.target.committed_height,
            installation: self.installation.take().expect("original installation"),
            preflight_release: self.preflight_release.take(),
        }
    }

    /// Cleanup-only retirement retains payload/events. It cannot return a journal.
    pub(crate) fn release_writers(&mut self) {
        self.released = true;
        self.retryable = false;
        self.complete = false;
        self.phase = match self.phase.take() {
            Some(Phase::Acquired(acquired)) => {
                let (work, release) = acquired.release_deferred(|a| a.abort());
                self.writer_release = Some(release);
                Some(Phase::Original(self.restore(work)))
            }
            Some(Phase::Preparing(slot)) => {
                let ((work, reader), writer) = slot.release_deferred(|slot| {
                    let (writer, reader) = slot.abort_retaining();
                    (writer.abort_retaining(), reader)
                });
                self.reader_release = reader;
                self.writer_release = Some(writer);
                Some(Phase::Abandoned { _work: work })
            }
            phase => phase,
        };
    }
}
impl<I> Drop for RetainedHashSlot<'_, I> {
    fn drop(&mut self) {
        self.release_writers();
    }
}
