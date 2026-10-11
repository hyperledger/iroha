//! Exact effect-index release custody for lifecycle and manifest publication.

use super::*;
use crate::publication_rwlock::DeferredPublicationRwLock;

/// Retains original index releases outside the calling operation's physical fences.
/// Short read/write guards unlock normally; their notifications stay in this owner.
pub(super) struct LaneLifecycleReleases<'state> {
    pub(super) hashes: Option<iroha_allocation::release::DeferredReleaseBatch>,
    pub(super) membership: iroha_allocation::release::DeferredReleaseBatch,
    pub(super) world: view_acquisition::WorldReadReleases,
    pub(super) prepared_cache: DeferredPublicationRwLock<'state, PreparedContractCache>,
    pub(super) crypto:
        DeferredPublicationRwLock<'state, Arc<iroha_config::parameters::actual::Crypto>>,
    pub(super) nexus: DeferredPublicationRwLock<'state, iroha_config::parameters::actual::Nexus>,
    pub(super) header: DeferredPublicationRwLock<'state, Option<BlockHeader>>,
    pub(super) manifests: DeferredPublicationRwLock<'state, LaneManifestRegistryHandle>,
    pub(super) privacy: DeferredPublicationRwLock<'state, LanePrivacyRegistryHandle>,
    pub(super) commitments: DeferredPublicationRwLock<'state, DaCommitmentStore>,
    pub(super) confidential_compute: DeferredPublicationRwLock<'state, ConfidentialComputeStore>,
    pub(super) receipt_cursors: DeferredPublicationRwLock<'state, DaReceiptCursorIndex>,
    pub(super) shard_cursors: DeferredPublicationRwLock<'state, DaShardCursorIndex>,
    pub(super) pin_intents: DeferredPublicationRwLock<'state, DaPinStore>,
    pub(super) hydrated:
        DeferredPublicationRwLock<'state, Option<Result<(), DaIndexHydrationError>>>,
}

impl<'state> LaneLifecycleReleases<'state> {
    pub(super) fn new(state: &'state State) -> Self {
        Self {
            hashes: state.block_hashes.reader_release_batch(),
            membership: state.transactions.reader_release_batch(),
            world: view_acquisition::WorldReadReleases::new(&state.world),
            prepared_cache: state.pipeline_ivm_prepared_cache.defer_notifications(),
            crypto: state.crypto.defer_notifications(),
            nexus: state.nexus.defer_notifications(),
            header: state.latest_block_header.defer_notifications(),
            manifests: state.lane_manifests.defer_notifications(),
            privacy: state.lane_privacy_registry.defer_notifications(),
            commitments: state.da_commitments.defer_notifications(),
            confidential_compute: state.da_confidential_compute.defer_notifications(),
            receipt_cursors: state.da_receipt_cursors.defer_notifications(),
            shard_cursors: state.da_shard_cursors.defer_notifications(),
            pin_intents: state.da_pin_intents.defer_notifications(),
            hydrated: state.da_indexes_hydrated.defer_notifications(),
        }
    }
}

impl State {
    /// Persist from the exact retained cursor source without opening a notifying reader.
    pub(super) fn persist_lane_lifecycle_cursor_journal(
        &self,
        releases: &mut LaneLifecycleReleases<'_>,
    ) {
        let path = self.da_shard_cursor_journal_path();
        if path.as_os_str().is_empty() {
            return;
        }
        let lane_config = self
            .canonical_runtime
            .view()
            .nexus_projection(&releases.nexus.read())
            .expect("persisted canonical runtime must be valid")
            .lane_config;
        let snapshot =
            DaShardCursorJournal::from_index(&lane_config, &releases.shard_cursors.read(), &path);
        if let Err(err) = snapshot.persist() {
            warn!(?err, path = %path.display(), "failed to persist DA shard cursor journal");
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static PANIC_AFTER_MANIFEST_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Inject once after the real first projection write, never substitute its guard.
#[cfg(test)]
pub(super) fn panic_after_manifest_write_for_test() {
    PANIC_AFTER_MANIFEST_WRITE.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(super) fn after_manifest_write_for_test() {
    if PANIC_AFTER_MANIFEST_WRITE.with(|flag| flag.replace(false)) {
        panic!("injected panic after original manifest write");
    }
}
