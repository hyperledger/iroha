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

// Scope construction can fail before writers exist. Keep the unchanged journal
// in this same inert slot so aggregate refusal/recovery never drops its authority.
pub(super) enum PrepaidSlot<'a, K: Key, V: Value, P>
where
    P: mv::storage::AdmittedStoragePolicy
        + concread::bptree::ClonePlanning<K, V>
        + concread::bptree::ClonePlanning<K, Option<V>>,
{
    Ready(mv::storage::AdmittedDetachedPublicationSlot<'a, 'a, K, V, (), P>),
    Refused {
        original: Option<mv::storage::Detached<K, V, (), concread::bptree::Prepaid<P>>>,
        error: AdmittedStorageError,
    },
}
impl<K: Key, V: Value, P> WorldStorageMode<K, V> for concread::bptree::Prepaid<P>
where
    P: mv::storage::AdmittedStoragePolicy
        + concread::bptree::ClonePlanning<K, V>
        + concread::bptree::ClonePlanning<K, Option<V>>
        + Send
        + Sync
        + 'static,
{
    type Slot<'a> = PrepaidSlot<'a, K, V, P>;
    type Prepared<'a> = mv::storage::AdmittedPreparedPublication<'a, 'a, K, V, (), P>;
    type Published<'a> = mv::storage::AdmittedPublishedPublication<'a, K, V, (), P>;
    type Aborted<'a> = mv::storage::AdmittedAbortedPublication<'a>;
    fn publication_slot<'a>(
        original: mv::storage::Detached<K, V, (), Self>,
        target: &'a Storage<K, V, Self>,
    ) -> Self::Slot<'a> {
        match crate::state::world_acquisition::original_storage_scope(target.allocation_budget()) {
            Err(error) => PrepaidSlot::Refused {
                original: Some(original),
                error,
            },
            Ok(scope) => match original.try_publication_slot_owned(&scope, target) {
                Ok(slot) => PrepaidSlot::Ready(slot),
                Err((original, error)) => PrepaidSlot::Refused {
                    original: Some(original),
                    error: match error {
                        PublicationPreparationError::Admission(error) => error,
                        _ => unreachable!("inert scope construction only checks source identity"),
                    },
                },
            },
        }
    }
    fn try_prepare(slot: &mut Self::Slot<'_>) -> Result<(), Refusal> {
        match slot {
            PrepaidSlot::Ready(slot) => slot.try_prepare(),
            PrepaidSlot::Refused { error, .. } => {
                Err(PublicationPreparationError::Admission(error.clone()))
            }
        }
    }
    fn release_writers(slot: &mut Self::Slot<'_>) {
        if let PrepaidSlot::Ready(slot) = slot {
            slot.release_writers();
        }
    }
    fn recover_original(slot: &mut Self::Slot<'_>) -> mv::storage::Detached<K, V, (), Self> {
        match slot {
            PrepaidSlot::Ready(slot) => slot.recover_original(),
            PrepaidSlot::Refused { original, .. } => {
                original.take().expect("original refused journal")
            }
        }
    }
    fn into_prepared<'a>(slot: Self::Slot<'a>) -> Self::Prepared<'a> {
        match slot {
            PrepaidSlot::Ready(slot) => slot.into_prepared(),
            PrepaidSlot::Refused { .. } => unreachable!("refused scope cannot become prepared"),
        }
    }
    fn abort<'a>(
        prepared: Self::Prepared<'a>,
    ) -> (mv::storage::Detached<K, V, (), Self>, Self::Aborted<'a>) {
        prepared.abort()
    }
    fn publish<'a>(prepared: Self::Prepared<'a>) -> Self::Published<'a> {
        prepared.publish()
    }
}
