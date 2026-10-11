//! Delegate World storage phases to the original MV storage mode.
//!
//! This module owns no map or publication algorithm. The existing World field
//! phase machine retains these exact MV slots, prepared owners and cleanup.

use super::*;
use concread::bptree::Untracked;
use mv::{PublicationPreparationError, storage::AdmittedStorageError};

type Refusal = PublicationPreparationError<AdmittedStorageError>;

pub(super) fn widen_untracked(error: PublicationPreparationError<Infallible>) -> Refusal {
    match error {
        PublicationPreparationError::Busy(wait) => PublicationPreparationError::Busy(wait),
        PublicationPreparationError::Poisoned => PublicationPreparationError::Poisoned,
        PublicationPreparationError::Changed => PublicationPreparationError::Changed,
        PublicationPreparationError::Admission(impossible) => match impossible {},
    }
}

/// Closed mode selection for the same original current/undo publication owners.
pub(super) trait WorldStorageMode<K: Key, V: Value>:
    StorageMode<K, V> + Send + Sync + 'static
{
    type Slot<'a>;
    type Prepared<'a>;
    type Published<'a>;
    type Aborted<'a>;

    fn publication_slot<'a>(
        original: mv::storage::Detached<K, V, (), Self>,
        target: &'a Storage<K, V, Self>,
    ) -> Self::Slot<'a>;
    fn try_prepare(slot: &mut Self::Slot<'_>) -> Result<(), Refusal>;
    fn release_writers(slot: &mut Self::Slot<'_>);
    fn recover_original(slot: &mut Self::Slot<'_>) -> mv::storage::Detached<K, V, (), Self>;
    fn into_prepared<'a>(slot: Self::Slot<'a>) -> Self::Prepared<'a>;
    fn abort<'a>(
        prepared: Self::Prepared<'a>,
    ) -> (mv::storage::Detached<K, V, (), Self>, Self::Aborted<'a>);
    fn publish<'a>(prepared: Self::Prepared<'a>) -> Self::Published<'a>;
}

impl<K: Key, V: Value> WorldStorageMode<K, V> for Untracked {
    type Slot<'a> = mv::storage::DetachedPublicationSlot<'a, K, V, (), ()>;
    type Prepared<'a> = mv::storage::PreparedPublication<'a, K, V, (), ()>;
    type Published<'a> = mv::storage::PublishedPublication<K, V, (), ()>;
    type Aborted<'a> = mv::PublicationCleanup<()>;

    fn publication_slot<'a>(
        original: mv::storage::Detached<K, V, ()>,
        target: &'a Storage<K, V>,
    ) -> Self::Slot<'a> {
        original.publication_slot(target)
    }
    fn try_prepare(slot: &mut Self::Slot<'_>) -> Result<(), Refusal> {
        slot.try_prepare(|_, _| Ok::<_, Infallible>(()))
            .map_err(widen_untracked)
    }
    fn release_writers(slot: &mut Self::Slot<'_>) {
        slot.release_writers();
    }
    fn recover_original(slot: &mut Self::Slot<'_>) -> mv::storage::Detached<K, V, ()> {
        slot.recover_original()
    }
    fn into_prepared<'a>(slot: Self::Slot<'a>) -> Self::Prepared<'a> {
        slot.into_prepared()
    }
    fn abort<'a>(
        prepared: Self::Prepared<'a>,
    ) -> (mv::storage::Detached<K, V, ()>, Self::Aborted<'a>) {
        prepared.abort()
    }
    fn publish<'a>(prepared: Self::Prepared<'a>) -> Self::Published<'a> {
        prepared.publish()
    }
}
