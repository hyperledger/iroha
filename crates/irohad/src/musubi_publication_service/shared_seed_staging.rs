//! One process-owned seed lease shared by ingress and finalized storage coordination.
//!
//! The service retains staging authority while the coordinator receives only a read capability.
//! That capability authenticates the registration through the daemon reader before exposing the
//! exact retained plan and CAR. It never creates pins, submits transactions, or enables ingress.
//! TODO: bind the qualified paid-pin transaction signer and replication coordinator to this
//! capability after their policy, finalized-state, and durable-journal inputs are complete.
use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReadErrorV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
};
use iroha_data_model::{
    musubi::{MusubiArchiveCommitmentV1, MusubiSeedIngressReceiptBindingV1},
    sorafs::capacity::ProviderId,
};
use iroha_musubi_service::{
    MusubiPublicationServiceBackendErrorV1, MusubiSeedIngressBackendV1, MusubiSeedStagingBackendV1,
    MusubiSeedStagingErrorV1,
};
use sorafs_car::CarBuildPlan;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Exact native-read or local custody failure while acquiring a finalized seed lease.
///
/// Native allocation refusals keep their original retry owner; local bytes never turn an
/// unavailable native observation into successful registration evidence.
#[derive(Debug)]
pub enum MusubiPublicationFinalizedSeedReadErrorV1 {
    /// The original native registration read failed, including its retained allocation deferral.
    Finality(MusubiPublicationFinalizedArchiveRegistrationReadErrorV1),
    /// The local seed owner or its exclusive bounded read lease refused.
    Custody(MusubiSeedStagingErrorV1),
}

/// Read-only handoff of finalized, exact staged bytes to a deployment coordinator.
///
/// The daemon constructs this only beside its service-owned seed lease. A caller-supplied receipt
/// or journal response cannot bypass the reader's current State/Kura finality check.
pub struct MusubiPublicationFinalizedSeedReadCapabilityV1 {
    seed: Arc<Mutex<MusubiSeedStagingBackendV1>>,
    reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    provider: ProviderId,
    active_read: Arc<AtomicBool>,
}
impl MusubiPublicationFinalizedSeedReadCapabilityV1 {
    /// Identity of the seed provider whose exact bytes this capability can read.
    #[must_use]
    pub const fn provider_id(&self) -> ProviderId {
        self.provider
    }

    /// Recover the exact plan and CAR only for a currently finalized archive registration.
    ///
    /// # Errors
    /// Refuses absent, substituted, or locally future finality and unavailable seed custody.
    pub fn read_finalized_seed(
        &self,
        query: &MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    ) -> Result<MusubiPublicationFinalizedSeedReadLeaseV1, MusubiPublicationFinalizedSeedReadErrorV1>
    {
        use MusubiPublicationFinalizedSeedReadErrorV1::{Custody, Finality};
        self.active_read
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Custody(MusubiSeedStagingErrorV1::Capacity))?;
        let reservation = SeedReadReservationV1(Arc::clone(&self.active_read));
        let archive = self.reader.read_current_archive(query).map_err(Finality)?;
        let seed = self
            .seed
            .lock()
            .map_err(|_| Custody(MusubiSeedStagingErrorV1::Unavailable))?;
        let (plan, car) = seed
            .read_staged_car(&archive.staging_receipt, &archive.commitment)
            .map_err(Custody)?;
        Ok(MusubiPublicationFinalizedSeedReadLeaseV1 {
            plan,
            car,
            _seed: Arc::clone(&self.seed),
            _reservation: reservation,
        })
    }
}

/// One bounded finalized seed materialization held until the coordinator releases it.
///
/// The CAR and plan are borrowed from this non-clone lease. At most one read can be outstanding
/// for this seed owner; downstream copies still require separate active memory admission.
pub struct MusubiPublicationFinalizedSeedReadLeaseV1 {
    plan: CarBuildPlan,
    car: Vec<u8>,
    _seed: Arc<Mutex<MusubiSeedStagingBackendV1>>,
    _reservation: SeedReadReservationV1,
}
impl std::fmt::Debug for MusubiPublicationFinalizedSeedReadLeaseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MusubiPublicationFinalizedSeedReadLeaseV1")
            .field("car_bytes", &self.car.len())
            .finish_non_exhaustive()
    }
}
impl MusubiPublicationFinalizedSeedReadLeaseV1 {
    /// Exact validated build plan.
    #[must_use]
    pub fn plan(&self) -> &CarBuildPlan {
        &self.plan
    }
    /// Exact complete CAR body, bounded by the first-release maximum.
    #[must_use]
    pub fn car(&self) -> &[u8] {
        &self.car
    }
}
struct SeedReadReservationV1(Arc<AtomicBool>);
impl Drop for SeedReadReservationV1 {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Service-side staging lease sharing only its finality-gated read owner.
pub(super) struct SharedSeedStagingBackendV1 {
    seed: Arc<Mutex<MusubiSeedStagingBackendV1>>,
    provider: ProviderId,
}
impl SharedSeedStagingBackendV1 {
    pub(super) fn share(
        seed: MusubiSeedStagingBackendV1,
        reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    ) -> (Self, MusubiPublicationFinalizedSeedReadCapabilityV1) {
        let provider = MusubiSeedIngressBackendV1::provider_id(&seed);
        let seed = Arc::new(Mutex::new(seed));
        (
            Self {
                seed: Arc::clone(&seed),
                provider,
            },
            MusubiPublicationFinalizedSeedReadCapabilityV1 {
                seed,
                reader,
                provider,
                active_read: Arc::new(AtomicBool::new(false)),
            },
        )
    }
}
impl MusubiSeedIngressBackendV1 for SharedSeedStagingBackendV1 {
    fn provider_id(&self) -> ProviderId {
        self.provider
    }

    fn stage_exact_car(
        &mut self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        self.seed
            .lock()
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)?
            .stage_exact_car(operation_id, binding, commitment, plan, car)
    }

    fn verify_staged_car(
        &self,
        operation_id: [u8; 32],
        binding: &MusubiSeedIngressReceiptBindingV1,
        commitment: &MusubiArchiveCommitmentV1,
        plan: &CarBuildPlan,
        car: &[u8],
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        self.seed
            .lock()
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Retryable)?
            .verify_staged_car(operation_id, binding, commitment, plan, car)
    }
}
