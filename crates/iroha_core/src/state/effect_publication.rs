//! Joint physical custody for the State indexes changed by carrier publication.
//!
//! All probes precede visibility. A refusal retains the acquired prefix in its
//! caller-owned slot; physical release is separate from notification cleanup.
//! TODO: fund private successor projections so index mutation performs no new
//! allocation or payload retirement inside the publication interval.

use super::*;
use crate::publication_rwlock::PublicationRwLockWriteGuard;

macro_rules! effect_indexes {
    ($apply:ident) => {
        $apply! {
            latest_block_header: Option<BlockHeader>,
            da_commitments: DaCommitmentStore,
            da_confidential_compute: ConfidentialComputeStore,
            da_receipt_cursors: DaReceiptCursorIndex,
            da_shard_cursors: DaShardCursorIndex,
            da_pin_intents: DaPinStore,
            lane_manifests: LaneManifestRegistryHandle,
            lane_privacy_registry: LanePrivacyRegistryHandle,
            da_indexes_hydrated: Option<Result<(), DaIndexHydrationFailure>>,
        }
    };
}

macro_rules! define_indexes {
    ($($field:ident: $ty:ty,)*) => {
        /// Original target locks; constructing the slot acquires nothing.
        pub(in crate::state) struct StateEffectLocks<'state> {
            target: &'state State,
            $(pub(in crate::state) $field: Option<PublicationRwLockWriteGuard<'state, $ty>> ,)*
            retired: [iroha_allocation::release::DeferredReleaseBatch; 9],
            complete: bool,
            retired_manifests: Option<LaneManifestRegistryHandle>,
            retired_privacy: Option<LanePrivacyRegistryHandle>,
        }

        impl<'state> StateEffectLocks<'state> {
            /// Install an inert slot before any sibling starts preparation.
            pub(in crate::state) fn new(target: &'state State) -> Self {
                Self {
                    target,
                    $($field: None,)*
                    retired: [$(target.$field.deferred_releases(),)*],
                    complete: false,
                    retired_manifests: None,
                    retired_privacy: None,
                }
            }

            /// Retain each acquired original guard before probing its successor.
            /// The returned waiter belongs to the actual reader/writer blocker.
            /// Retry requires every previous physical guard to be released; the
            /// same slot retains all original notices and displaced resources.
            pub(in crate::state) fn try_prepare(&mut self) -> Result<(), (&'static str, iroha_allocation::release::ReleaseWait)> {
                assert!(!self.complete $( && self.$field.is_none())*, "effect indexes must be released before retry");
                self.prepare_inner()
            }

            fn prepare_inner(&mut self) -> Result<(), (&'static str, iroha_allocation::release::ReleaseWait)> {
                $(self.$field = Some(self.target.$field.try_write_or_wait()
                    .map_err(|wait| (stringify!($field), wait))?);)*
                self.complete = true;
                Ok(())
            }

            /// Release only physical guards. Every original notification and
            /// displaced registry allocation remains in this owner afterward.
            pub(in crate::state) fn release_writers(&mut self) {
                self.complete = false;
                let mut slots = self.retired.iter_mut();
                $(let retired = slots.next().expect("effect release slot");
                if let Some(guard) = self.$field.take() {
                    assert!(guard.try_release_into(retired).is_ok(), "original effect release source");
                })*
            }

            /// Original guards remain owned through the exact registry swap.
            pub(in crate::state) fn install_registries(&mut self, manifests: LaneManifestRegistryHandle, privacy: LanePrivacyRegistryHandle) {
                assert!(self.complete && self.retired_manifests.is_none() && self.retired_privacy.is_none(), "one complete registry publication");
                self.retired_manifests = Some(std::mem::replace(&mut **self.lane_manifests.as_mut().expect("prepared manifests"), manifests));
                self.retired_privacy = Some(std::mem::replace(&mut **self.lane_privacy_registry.as_mut().expect("prepared privacy"), privacy));
            }
        }

        impl Drop for StateEffectLocks<'_> {
            fn drop(&mut self) {
                self.release_writers();
            }
        }
    };
}
effect_indexes!(define_indexes);

#[cfg(test)]
#[path = "effect_publication_tests.rs"]
mod tests;

/// A borrowing physical scope; cleanup stays with the enclosing original slot.
pub(in crate::state) struct EffectLockScope<'scope, 'state>(&'scope mut StateEffectLocks<'state>);
impl<'state> StateEffectLocks<'state> {
    /// Ensure unwind releases index guards before the caller's other writers.
    pub(in crate::state) fn physical_scope(&mut self) -> EffectLockScope<'_, 'state> {
        EffectLockScope(self)
    }
}
impl<'state> std::ops::Deref for EffectLockScope<'_, 'state> {
    type Target = StateEffectLocks<'state>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
impl std::ops::DerefMut for EffectLockScope<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}
impl Drop for EffectLockScope<'_, '_> {
    fn drop(&mut self) {
        self.0.release_writers();
    }
}
