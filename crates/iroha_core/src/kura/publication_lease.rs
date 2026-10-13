//! Joint nonblocking custody of the physical Kura publication boundary.
//!
//! A lease excludes internal canonical, prune, geometry and sidecar writers.
//! It proves no source, finality or checkpoint identity by itself. The complete
//! publisher must rejoin its exact durable evidence under this boundary before
//! acquiring State writers, and release every guard before any async wait.

use super::{Error, Kura, PublicationGuard, PublicationMutex};

/// A local physical refusal, independent of the decided block's validity.
pub(crate) enum KuraPublicationPreparationError {
    /// An actual storage owner must release before another acquisition attempt.
    Busy {
        /// Original Kura mutex which prevented the joint acquisition.
        field: &'static str,
        /// Release observation captured before probing that mutex.
        wait: iroha_allocation::release::ReleaseWait,
    },
    /// The actual Kura requires storage repair, not a lock-release retry.
    Storage(Error),
}

impl std::fmt::Debug for KuraPublicationPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy { field, wait } => f
                .debug_struct("Busy")
                .field("field", field)
                .field("wait", wait)
                .finish(),
            Self::Storage(error) => f.debug_tuple("Storage").field(error).finish(),
        }
    }
}

impl From<Error> for KuraPublicationPreparationError {
    fn from(error: Error) -> Self {
        Self::Storage(error)
    }
}

/// All original Kura publication fences, acquired in the established order.
///
/// Every physical fence unlocks before any release callback, including partial
/// acquisition and unwind. This is not a receipt or State publication authority.
/// Kura methods which reacquire these locks must not be called while retained.
#[must_use = "retain the physical boundary through the authorized operation"]
pub(crate) struct KuraPublicationLease<'kura> {
    kura: &'kura Kura,
    pending_canonical_bytes: u64,
    fences: AcquiredKuraPublicationFences<'kura>,
}

/// Original partial or complete acquisition; absence never manufactures a wake.
struct AcquiredKuraPublicationFences<'kura> {
    sidecar: Option<PublicationGuard<'kura>>,
    geometry: Option<PublicationGuard<'kura>>,
    canonical: Option<PublicationGuard<'kura>>,
    prune: Option<PublicationGuard<'kura>>,
    claims: Option<&'kura super::lane_geometry::RawGeometryClaimGate>,
}

/// Original notifications after every physical Kura owner has unlocked.
#[must_use = "retain Kura cleanup through every enclosing physical owner"]
pub(crate) struct KuraPublicationCleanup {
    fences: [Option<iroha_allocation::release::DeferredRelease>; 4],
    claims: super::lane_geometry::RawGeometryReleases,
}

impl AcquiredKuraPublicationFences<'_> {
    fn new() -> Self {
        Self {
            sidecar: None,
            geometry: None,
            canonical: None,
            prune: None,
            claims: None,
        }
    }

    fn take_cleanup(&mut self) -> KuraPublicationCleanup {
        let claims = self
            .claims
            .take()
            .map(|gate| gate.end_publication())
            .unwrap_or_default();
        KuraPublicationCleanup {
            claims,
            fences: [
                self.sidecar.take().map(PublicationGuard::release_deferred),
                self.geometry.take().map(PublicationGuard::release_deferred),
                self.canonical
                    .take()
                    .map(PublicationGuard::release_deferred),
                self.prune.take().map(PublicationGuard::release_deferred),
            ],
        }
    }

    fn release_deferred(mut self) -> KuraPublicationCleanup {
        self.take_cleanup()
    }
}

impl Drop for AcquiredKuraPublicationFences<'_> {
    fn drop(&mut self) {
        // The fixed cleanup owner is built only after all four physical unlocks.
        // Empty slots cannot signal an unacquired lock.
        drop(self.take_cleanup());
    }
}

impl Kura {
    fn try_pending_canonical_capacity_bytes_under_prune_and_canonical_guards(
        &self,
    ) -> Result<u64, KuraPublicationPreparationError> {
        self.pending_canonical_capacity_bytes_under_prune_and_canonical_guards()
            .map_err(KuraPublicationPreparationError::Storage)
    }

    /// Acquire prune, canonical, geometry and sidecar ownership without waiting.
    ///
    /// Every refusal releases all earlier guards before returning. Callers with
    /// enclosing physical owners use the retained publication slot instead.
    pub(crate) fn try_publication_lease(
        &self,
    ) -> Result<KuraPublicationLease<'_>, KuraPublicationPreparationError> {
        let mut fences = AcquiredKuraPublicationFences::new();
        let pending_canonical_bytes = self.prepare_publication_fences(&mut fences)?;
        Ok(KuraPublicationLease {
            kura: self,
            pending_canonical_bytes,
            fences,
        })
    }

    fn prepare_publication_fences<'kura>(
        &'kura self,
        fences: &mut AcquiredKuraPublicationFences<'kura>,
    ) -> Result<u64, KuraPublicationPreparationError> {
        fn acquire<'kura>(
            field: &'static str,
            lock: &'kura PublicationMutex,
        ) -> Result<PublicationGuard<'kura>, KuraPublicationPreparationError> {
            lock.try_lock_or_wait()
                .map_err(|wait| KuraPublicationPreparationError::Busy { field, wait })
        }
        // Canonical poisoning is permanent for this Kura. It cannot become a
        // lock-release dependency, even when another physical owner is busy.
        self.ensure_canonical_storage_not_poisoned()
            .map_err(KuraPublicationPreparationError::Storage)?;
        fences.prune = Some(acquire("prune_lock", &self.prune_lock)?);
        // Active pruning also sets this flag while it owns prune_lock. Only
        // classify it as restart-required after acquiring that actual owner.
        self.ensure_prune_recovery_not_required()
            .map_err(KuraPublicationPreparationError::Storage)?;
        fences.canonical = Some(acquire("canonical_chain_lock", &self.canonical_chain_lock)?);
        let pending_canonical_bytes =
            self.try_pending_canonical_capacity_bytes_under_prune_and_canonical_guards()?;
        fences.geometry = Some(acquire("lane_geometry_lock", &self.lane_geometry_lock)?);
        fences.sidecar = Some(acquire("sidecar_lock", &self.sidecar_lock)?);
        self.ensure_prune_recovery_not_required()
            .map_err(KuraPublicationPreparationError::Storage)?;
        self.ensure_canonical_storage_not_poisoned()
            .map_err(KuraPublicationPreparationError::Storage)?;
        self.raw_geometry_claim.begin_publication();
        fences.claims = Some(&self.raw_geometry_claim);
        Ok(pending_canonical_bytes)
    }
}

#[cfg(test)]
impl<'kura> KuraPublicationLease<'kura> {
    /// Transfer structural catalog fixture guards into the common boundary.
    ///
    /// The fixture has resolved canonical recovery and completed authorized GC
    /// before acquiring sidecar. No fence is released or reacquired. Production
    /// geometry publication retains its original raw attempt under a lease.
    pub(super) fn from_geometry_guards(
        kura: &'kura Kura,
        sidecar: PublicationGuard<'kura>,
        geometry: PublicationGuard<'kura>,
        canonical: PublicationGuard<'kura>,
        prune: PublicationGuard<'kura>,
        pending_canonical_bytes: u64,
    ) -> Self {
        kura.raw_geometry_claim.begin_publication();
        Self {
            kura,
            pending_canonical_bytes,
            fences: AcquiredKuraPublicationFences {
                sidecar: Some(sidecar),
                geometry: Some(geometry),
                canonical: Some(canonical),
                prune: Some(prune),
                claims: Some(&kura.raw_geometry_claim),
            },
        }
    }
}

impl KuraPublicationLease<'_> {
    /// Release every physical Kura fence without invoking retry callbacks.
    /// The caller retains these original notifications through its outer fences.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect aggregate publication to retained pending-byte admission and deferred cleanup; release physical fences before notifying outer owners"
        )
    )]
    pub(crate) fn release_deferred(self) -> KuraPublicationCleanup {
        self.fences.release_deferred()
    }

    /// Pending canonical bytes captured before the inner publication fences.
    /// Prune/canonical custody keeps this snapshot valid for the lease lifetime.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect aggregate publication to retained pending-byte admission and deferred cleanup; release physical fences before notifying outer owners"
        )
    )]
    pub(super) fn pending_canonical_bytes(&self) -> u64 {
        self.pending_canonical_bytes
    }

    /// Private guarded implementations may borrow only this original physical owner.
    pub(super) fn original_kura(&self) -> &Kura {
        self.kura
    }

    /// Check original physical ownership before capturing another retained plan.
    /// This grants no source, finality or mutation authorization.
    pub(crate) fn belongs_to(&self, kura: &Kura) -> bool {
        std::ptr::eq(self.kura, kura)
    }
}

#[cfg(test)]
#[path = "publication_lease_tests.rs"]
mod tests;

mod retained;
pub(crate) use retained::KuraPublicationSlot;

/// Original source-bound notices that can outlive their Kura borrow.
/// Empty custody never defers an unrelated lease or another publication attempt.
pub(crate) struct KuraPublicationReleases {
    source: super::KuraInstanceIdentity,
    fences: [iroha_allocation::release::DeferredReleaseBatch; 4],
    claims: super::lane_geometry::RawGeometryReleases,
}
impl KuraPublicationReleases {
    pub(crate) fn new(kura: &Kura) -> Self {
        Self {
            source: kura.instance_identity(),
            fences: [
                kura.sidecar_lock.deferred_releases(),
                kura.lane_geometry_lock.deferred_releases(),
                kura.canonical_chain_lock.deferred_releases(),
                kura.prune_lock.deferred_releases(),
            ],
            claims: Default::default(),
        }
    }
    fn retain(&mut self, mut cleanup: KuraPublicationCleanup) {
        for (notice, batch) in cleanup.fences.iter_mut().zip(&mut self.fences) {
            if let Some(notice) = notice.take() {
                assert!(
                    notice.try_merge_into(batch).is_ok(),
                    "original Kura cleanup source"
                );
            }
        }
        self.claims.append(std::mem::take(&mut cleanup.claims));
    }
}

/// A standalone geometry lease transfers every notice to its original caller.
pub(crate) struct ScopedKuraPublicationLease<'kura, 'releases> {
    lease: Option<KuraPublicationLease<'kura>>,
    releases: &'releases mut KuraPublicationReleases,
}
impl<'kura, 'releases> ScopedKuraPublicationLease<'kura, 'releases> {
    pub(crate) fn new(
        lease: KuraPublicationLease<'kura>,
        releases: &'releases mut KuraPublicationReleases,
    ) -> Self {
        Self {
            lease: Some(lease),
            releases,
        }
    }
}
impl<'kura> std::ops::Deref for ScopedKuraPublicationLease<'kura, '_> {
    type Target = KuraPublicationLease<'kura>;
    fn deref(&self) -> &Self::Target {
        self.lease.as_ref().expect("original scoped Kura lease")
    }
}
impl Drop for ScopedKuraPublicationLease<'_, '_> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.releases.retain(lease.release_deferred());
        }
    }
}
