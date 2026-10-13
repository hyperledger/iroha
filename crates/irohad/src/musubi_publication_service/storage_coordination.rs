//! Mandatory finalized-registration preflight for private storage coordination.
//!
//! The deployment-selected coordinator still owns pin/replication effects, but cannot receive a
//! request whose archive registration has not been independently joined to the daemon's exact
//! finalized State/Kura history. This adapter does not itself implement pinning or enable stock
//! private publication.
use super::{
    MusubiPublicationFinalizedArchiveRegistrationQueryV1,
    MusubiPublicationFinalizedArchiveRegistrationReadErrorV1,
    MusubiPublicationFinalizedArchiveRegistrationReaderV1,
};
use iroha_musubi_service::{
    MusubiPublicationServiceBackendErrorV1, MusubiStorageCoordinationBackendV1,
    MusubiStorageCoordinationRequestV1, MusubiStorageCoordinationResponseV1,
};

/// Finality gate around one deployment-selected effectful coordinator.
pub(super) struct FinalizedRegistrationCheckedStorageBackendV1 {
    reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
    delegate: Box<dyn MusubiStorageCoordinationBackendV1>,
}

impl FinalizedRegistrationCheckedStorageBackendV1 {
    /// Retain the exact daemon reader and the qualified deployment coordinator.
    pub(super) fn new(
        reader: MusubiPublicationFinalizedArchiveRegistrationReaderV1,
        delegate: Box<dyn MusubiStorageCoordinationBackendV1>,
    ) -> Self {
        Self { reader, delegate }
    }
}

impl FinalizedRegistrationCheckedStorageBackendV1 {
    fn verify_archive(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        request
            .validate()
            .map_err(|_| MusubiPublicationServiceBackendErrorV1::Permanent)?;
        let evidence = &request.finalized_registration;
        let query = MusubiPublicationFinalizedArchiveRegistrationQueryV1 {
            version: evidence.version,
            network_id: evidence.network_id,
            transaction_hash: evidence.transaction_hash,
            snapshot: evidence.snapshot,
            registration: evidence.registration.clone(),
            expected_policy_revision: request.expected_policy_revision,
        };
        let archive = self
            .reader
            .read_current_archive(&query)
            .map_err(|error| match error {
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::LocallyAhead
                | MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Deferred(_) => {
                    MusubiPublicationServiceBackendErrorV1::Retryable
                }
                MusubiPublicationFinalizedArchiveRegistrationReadErrorV1::Invalid => {
                    MusubiPublicationServiceBackendErrorV1::Permanent
                }
            })?;
        if archive.registration_projection() != evidence.registration {
            return Err(MusubiPublicationServiceBackendErrorV1::Permanent);
        }
        Ok(())
    }
}
impl MusubiStorageCoordinationBackendV1 for FinalizedRegistrationCheckedStorageBackendV1 {
    fn verify_current_registration(
        &self,
        request: &MusubiStorageCoordinationRequestV1,
    ) -> Result<(), MusubiPublicationServiceBackendErrorV1> {
        self.verify_archive(request)?;
        self.delegate.verify_current_registration(request)
    }

    fn coordinate_storage(
        &mut self,
        request: &iroha_musubi_service::VerifiedStorageCoordinationRequestV1<'_>,
    ) -> Result<MusubiStorageCoordinationResponseV1, MusubiPublicationServiceBackendErrorV1> {
        if std::time::Instant::now() >= request.deadline() {
            return Err(MusubiPublicationServiceBackendErrorV1::Retryable);
        }
        // Fresh dispatch must honor both native finality and the delegate
        // preflight, just as replay does, before any storage effect is invoked.
        self.verify_current_registration(request.request())?;
        if std::time::Instant::now() >= request.deadline() {
            return Err(MusubiPublicationServiceBackendErrorV1::Retryable);
        }
        self.delegate.coordinate_storage(request)
    }
}
