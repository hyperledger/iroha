//! Keep one original field armed through execution, freeze and publication.
//!
//! The aggregate inventory owns this field before preparation starts. Execution
//! can borrow only the original Block; publication requires a private transition
//! of this owner after the aggregate has accepted the complete result.

use mv::{BlockCapture, BlockPublication, BlockRetirement, CaptureCleanup, Key, Value};
use norito::json;
use std::ops::{Deref, DerefMut};

mod sealed {
    pub trait Sealed {}
    impl<V: mv::Value, C: Send + Sync + 'static> Sealed for mv::cell::Block<'_, V, C> {}
    impl<K: mv::Key, V: mv::Value, M: mv::storage::StorageMode<K, V>> Sealed
        for mv::storage::Block<'_, K, V, M>
    {
    }
}

/// An original MV Block whose consuming transfer creates publication authority.
/// Implementations perform an inert move, without allocation or validation.
pub trait OriginalPublicationBlock: BlockRetirement + sealed::Sealed + Sized {
    /// Exact attached publication owner for this original Block.
    type Publication: BlockPublication;
    /// Exact inert capture slot retaining the original block on refusal/unwind.
    type FreezeCapture: BlockCapture<(), Block = Self, Detached = Self::Frozen>;
    /// Original private generations after their physical writers are released.
    type Frozen;
    /// Same original frozen fields while independent structural readers retain them.
    type FrozenRead;
    /// Move the original block into its capture slot without allocation.
    fn into_freeze_capture(self) -> Self::FreezeCapture;
    /// Consume execution authority without releasing any physical writer.
    fn into_publication(self) -> Self::Publication;
}

impl<'a, V: Value, C: Send + Sync + 'static> OriginalPublicationBlock
    for mv::cell::Block<'a, V, C>
{
    type Publication = mv::cell::BlockPublicationSlot<'a, V, C>;
    type FreezeCapture = mv::cell::BlockCaptureSlot<'a, V, (), C>;
    type Frozen = mv::cell::Detached<V, (), C>;
    type FrozenRead = mv::cell::FrozenDetached<V, (), C>;
    fn into_freeze_capture(self) -> Self::FreezeCapture {
        self.capture_slot()
    }
    fn into_publication(self) -> Self::Publication {
        self.publication_slot()
    }
}

impl<'a, K: Key, V: Value, M: mv::storage::StorageMode<K, V>> OriginalPublicationBlock
    for mv::storage::Block<'a, K, V, M>
{
    type Publication = mv::storage::BlockPublicationSlot<'a, K, V, M>;
    type FreezeCapture = mv::storage::BlockCaptureSlot<'a, K, V, (), M>;
    type Frozen = mv::storage::Detached<K, V, (), M>;
    type FrozenRead = mv::storage::FrozenDetached<K, V, (), M>;
    fn into_freeze_capture(self) -> Self::FreezeCapture {
        self.capture_slot()
    }
    fn into_publication(self) -> Self::Publication {
        self.publication_slot()
    }
}

/// Exact Cell field types keep aggregate lifetimes covariant. An associated
/// publication projection in the aggregate field type would make them invariant.
pub type CellField<'a, V, C = concread::ebrcell::Untracked> = BlockField<
    mv::cell::Block<'a, V, C>,
    mv::cell::BlockPublicationSlot<'a, V, C>,
    mv::cell::BlockCaptureSlot<'a, V, (), C>,
    mv::cell::Detached<V, (), C>,
    mv::cell::FrozenDetached<V, (), C>,
>;

/// Exact Storage phases retain both original map generations and covariance.
pub type StorageField<'a, K, V, M = concread::bptree::Untracked> = BlockField<
    mv::storage::Block<'a, K, V, M>,
    mv::storage::BlockPublicationSlot<'a, K, V, M>,
    mv::storage::BlockCaptureSlot<'a, K, V, (), M>,
    mv::storage::Detached<K, V, (), M>,
    mv::storage::FrozenDetached<K, V, (), M>,
>;

enum Phase<B, P, C, F, R> {
    Executing(B),
    Capturing(C),
    Frozen(F),
    // Stored in this exact field while the State publisher owns its row positions.
    Reading(R),
    Publishing(P),
}

/// One original typed field and its mutually exclusive execution/frozen phases.
///
/// Freezing retains the original private generations in this same inline field;
/// it creates no view, wrapper allocation or substitute execution authority.
/// Its enclosing original shell must cover this complete type before execution.
pub struct BlockField<
    B,
    P = <B as OriginalPublicationBlock>::Publication,
    C = <B as OriginalPublicationBlock>::FreezeCapture,
    F = <B as OriginalPublicationBlock>::Frozen,
    R = <B as OriginalPublicationBlock>::FrozenRead,
> where
    B: OriginalPublicationBlock<Publication = P, FreezeCapture = C, Frozen = F, FrozenRead = R>,
    P: BlockPublication,
    C: BlockCapture<(), Block = B, Detached = F>,
{
    phase: Option<Phase<B, P, C, F, R>>,
    released: bool,
    // Normal recovery restores Frozen above while retaining the actual attempt
    // cleanup here until every sibling and enclosing fence has unlocked.
    retry_cleanup: Option<P>,
    // After original payload custody: never notify while a sibling still owns
    // its writer. The enclosing aggregate retires these only after all release.
    freeze_cleanup: CaptureCleanup,
}

impl<B: OriginalPublicationBlock> BlockField<B> {
    pub(crate) fn new(block: B) -> Self {
        Self {
            phase: Some(Phase::Executing(block)),
            released: false,
            retry_cleanup: None,
            freeze_cleanup: CaptureCleanup::default(),
        }
    }

    /// Transfer only an untouched executing owner to the aggregate capture path.
    pub(crate) fn into_executing(mut self) -> B {
        self.take_executing()
    }

    /// Move the exact executing owner out of its heap-resident aggregate field.
    /// The emptied field has no payload or writer to release. It cannot execute,
    /// publish, or transfer again; the returned owner retains all original custody.
    pub(crate) fn take_executing(&mut self) -> B {
        assert!(!self.released, "field was terminally released");
        assert!(
            matches!(self.phase, Some(Phase::Executing(_))),
            "field already entered publication"
        );
        match self.phase.take().expect("original field") {
            Phase::Executing(block) => block,
            _ => unreachable!("checked original execution phase"),
        }
    }

    pub(crate) fn prepare_publication(&mut self) {
        assert!(!self.released, "field was terminally released");
        assert!(
            matches!(self.phase, Some(Phase::Executing(_))),
            "field publication is one-shot"
        );
        let Some(Phase::Executing(block)) = self.phase.take() else {
            unreachable!("checked original execution phase")
        };
        // Only an inert original-owner move occurs outside caller custody.
        self.phase = Some(Phase::Publishing(block.into_publication()));
        let Some(Phase::Publishing(slot)) = self.phase.as_mut() else {
            unreachable!("original publication phase")
        };
        slot.prepare_publication();
    }

    pub(crate) fn publish_prepared(&mut self) {
        assert!(!self.released, "field was terminally released");
        let Some(Phase::Publishing(slot)) = self.phase.as_mut() else {
            panic!("original field was not prepared")
        };
        slot.publish_prepared();
    }
}

impl<B: OriginalPublicationBlock> Deref for BlockField<B> {
    type Target = B;
    fn deref(&self) -> &B {
        assert!(!self.released, "field was terminally released");
        match self.phase.as_ref() {
            Some(Phase::Executing(block)) => block,
            _ => panic!("publication field has no execution authority"),
        }
    }
}
impl<B: OriginalPublicationBlock> DerefMut for BlockField<B> {
    fn deref_mut(&mut self) -> &mut B {
        assert!(!self.released, "field was terminally released");
        match self.phase.as_mut() {
            Some(Phase::Executing(block)) => block,
            _ => panic!("publication field has no execution authority"),
        }
    }
}
impl<B, P, C, F, R> BlockRetirement for BlockField<B, P, C, F, R>
where
    B: OriginalPublicationBlock<Publication = P, FreezeCapture = C, Frozen = F, FrozenRead = R>,
    P: BlockPublication,
    C: BlockCapture<(), Block = B, Detached = F>,
{
    fn release_writers(&mut self) {
        self.released = true;
        match self.phase.as_mut() {
            Some(Phase::Executing(block)) => block.release_writers(),
            Some(Phase::Capturing(slot)) => slot.release(),
            Some(Phase::Publishing(slot)) => slot.release_writers(),
            Some(Phase::Frozen(_) | Phase::Reading(_)) | None => {}
        }
    }
}
impl<B, P, C, F, R> Drop for BlockField<B, P, C, F, R>
where
    B: OriginalPublicationBlock<Publication = P, FreezeCapture = C, Frozen = F, FrozenRead = R>,
    P: BlockPublication,
    C: BlockCapture<(), Block = B, Detached = F>,
{
    fn drop(&mut self) {
        self.release_writers();
    }
}

#[path = "block_field/frozen.rs"]
mod frozen;
#[path = "block_field/original_images.rs"]
mod original_images;
#[path = "block_field/read.rs"]
mod read;
#[path = "block_field/retained_read.rs"]
mod retained_read;
pub(super) use retained_read::RetainedReadPhaseError;

#[cfg(test)]
#[path = "block_field_tests.rs"]
mod tests;

/// One aggregate's exclusive permission to prepare and publish its original fields.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AggregatePublication {
    Executing,
    Capturing,
    Frozen,
    Reacquiring,
    Preparing,
    Prepared,
    Publishing,
    Published,
    Released,
}
impl AggregatePublication {
    pub(crate) fn assert_executing(&self) {
        assert_eq!(*self, Self::Executing, "aggregate no longer executes");
    }
    pub(crate) fn begin_freeze(&mut self) {
        self.assert_executing();
        *self = Self::Capturing;
    }
    pub(crate) fn finish_freeze(&mut self) {
        assert_eq!(*self, Self::Capturing);
        *self = Self::Frozen;
    }
    pub(crate) fn begin_reacquisition(&mut self) {
        assert_eq!(*self, Self::Frozen, "original frozen aggregate required");
        *self = Self::Reacquiring;
    }
    pub(crate) fn finish_reacquisition(&mut self) {
        assert_eq!(*self, Self::Reacquiring);
        *self = Self::Prepared;
    }
    pub(crate) fn recover_reacquisition(&mut self) {
        assert!(matches!(
            *self,
            Self::Frozen | Self::Reacquiring | Self::Prepared
        ));
        *self = Self::Frozen;
    }
    pub(crate) fn assert_frozen(&self) {
        assert_eq!(
            *self,
            Self::Frozen,
            "complete original frozen aggregate required"
        );
    }
    pub(crate) fn begin_preparation(&mut self) {
        self.assert_executing();
        *self = Self::Preparing;
    }
    pub(crate) fn finish_preparation(&mut self) {
        assert_eq!(*self, Self::Preparing);
        *self = Self::Prepared;
    }
    pub(crate) fn begin_publication(&mut self) {
        assert_eq!(
            *self,
            Self::Prepared,
            "all original fields must prepare before any publishes"
        );
        *self = Self::Publishing;
    }
    pub(crate) fn finish_publication(&mut self) {
        assert_eq!(*self, Self::Publishing);
        *self = Self::Published;
    }
    pub(crate) fn release(&mut self) {
        *self = Self::Released;
    }
}
