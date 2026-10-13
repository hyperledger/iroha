//! Fixed original Kura cleanup custody across enclosing State publication attempts.

use super::*;
use iroha_allocation::release::DeferredReleaseBatch;

/// Original physical lease and four allocation-free source-bound release batches.
/// This owner must outlive every enclosing physical guard and frozen State field.
pub(crate) struct KuraPublicationSlot<'kura> {
    kura: &'kura Kura,
    lease: Option<KuraPublicationLease<'kura>>,
    releases: [DeferredReleaseBatch; 4],
}

impl AcquiredKuraPublicationFences<'_> {
    fn release_into(&mut self, releases: &mut [DeferredReleaseBatch; 4]) {
        for (guard, batch) in [
            &mut self.sidecar,
            &mut self.geometry,
            &mut self.canonical,
            &mut self.prune,
        ]
        .into_iter()
        .zip(releases)
        {
            if let Some(guard) = guard.take() {
                if cfg!(all(test, sumeragi_core_mutation = "HC274")) {
                    // Restore callbacks before the enclosing original State owners retire.
                    drop(guard);
                    continue;
                }
                assert!(
                    guard.try_release_into(batch).is_ok(),
                    "original Kura release batch"
                );
            }
        }
    }
}

/// An unfinished acquisition always retires its actual prefix into the caller's
/// original batches, including errors and unwinds inside the common acquisition.
struct Acquisition<'kura, 'releases> {
    fences: AcquiredKuraPublicationFences<'kura>,
    releases: &'releases mut [DeferredReleaseBatch; 4],
}
impl Drop for Acquisition<'_, '_> {
    fn drop(&mut self) {
        self.fences.release_into(self.releases);
    }
}

impl<'kura> KuraPublicationSlot<'kura> {
    /// Install cleanup custody without acquiring locks or allocating a new source.
    pub(crate) fn new(kura: &'kura Kura) -> Self {
        Self {
            kura,
            lease: None,
            releases: [
                kura.sidecar_lock.deferred_releases(),
                kura.lane_geometry_lock.deferred_releases(),
                kura.canonical_chain_lock.deferred_releases(),
                kura.prune_lock.deferred_releases(),
            ],
        }
    }

    /// Prepare every original Kura fence through the sole canonical acquisition.
    /// Refusal preserves its exact cause while physically releasing the prefix.
    pub(crate) fn try_prepare(&mut self) -> Result<(), KuraPublicationPreparationError> {
        assert!(
            self.lease.is_none(),
            "original Kura lease must be released before retry"
        );
        let mut acquisition = Acquisition {
            fences: AcquiredKuraPublicationFences::new(),
            releases: &mut self.releases,
        };
        let pending_canonical_bytes = self
            .kura
            .prepare_publication_fences(&mut acquisition.fences)?;
        let fences = std::mem::replace(
            &mut acquisition.fences,
            AcquiredKuraPublicationFences::new(),
        );
        self.lease = Some(KuraPublicationLease {
            kura: self.kura,
            pending_canonical_bytes,
            fences,
        });
        Ok(())
    }

    /// Borrow the one fully acquired original lease without a second physical probe.
    pub(crate) fn lease(&self) -> &KuraPublicationLease<'kura> {
        self.lease.as_ref().expect("prepared original Kura lease")
    }

    fn release_writers(&mut self) {
        if let Some(mut lease) = self.lease.take() {
            lease.fences.release_into(&mut self.releases);
        }
    }

    /// Deliver original releases only after the caller retires every enclosing
    /// physical owner. Refreshing these same-source inert batches allocates nothing.
    pub(crate) fn retire_notices(&mut self) {
        assert!(
            self.lease.is_none(),
            "original Kura physical scope must end before notification"
        );
        let fresh = [
            self.kura.sidecar_lock.deferred_releases(),
            self.kura.lane_geometry_lock.deferred_releases(),
            self.kura.canonical_chain_lock.deferred_releases(),
            self.kura.prune_lock.deferred_releases(),
        ];
        drop(std::mem::replace(&mut self.releases, fresh));
    }

    /// Retain notifications in this slot when the attempt's physical scope ends.
    pub(crate) fn physical_scope(&mut self) -> KuraPhysicalScope<'_, 'kura> {
        KuraPhysicalScope(self)
    }
}

impl Drop for KuraPublicationSlot<'_> {
    fn drop(&mut self) {
        self.release_writers();
    }
}

/// Physical attempt borrowing a cleanup owner which outlives enclosing writers.
pub(crate) struct KuraPhysicalScope<'scope, 'kura>(&'scope mut KuraPublicationSlot<'kura>);
impl<'kura> std::ops::Deref for KuraPhysicalScope<'_, 'kura> {
    type Target = KuraPublicationSlot<'kura>;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}
impl std::ops::DerefMut for KuraPhysicalScope<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}
impl Drop for KuraPhysicalScope<'_, '_> {
    fn drop(&mut self) {
        self.0.release_writers();
    }
}

#[cfg(test)]
impl Kura {
    /// Borrow the four actual publication fences for ownership/callback probes.
    pub(crate) fn publication_fences_for_test(&self) -> [(&'static str, &PublicationMutex); 4] {
        [
            ("prune_lock", &self.prune_lock),
            ("canonical_chain_lock", &self.canonical_chain_lock),
            ("lane_geometry_lock", &self.lane_geometry_lock),
            ("sidecar_lock", &self.sidecar_lock),
        ]
    }
}
