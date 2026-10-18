//! Reuse the certificate owners on a bounded worker without persisting restricted artifacts.

use super::*;

pub(super) trait SettlementPhases: Send + Sync {
    fn run(
        &self,
        phase: usize,
        journal: WorkflowJournalV1,
        read_only: bool,
    ) -> WorkflowFuture<'_, std::result::Result<Option<Vec<u8>>, PrivateSettlementError>>;
}

pub(super) struct OnlinePhases {
    client: Client,
    request: PrivateSettlementRequest,
    worker: Arc<tokio::sync::Semaphore>,
}
impl OnlinePhases {
    pub fn new(
        client: Client,
        request: PrivateSettlementRequest,
        worker: Arc<tokio::sync::Semaphore>,
    ) -> Self {
        Self {
            client,
            request,
            worker,
        }
    }
}
impl SettlementPhases for OnlinePhases {
    fn run(
        &self,
        phase: usize,
        journal: WorkflowJournalV1,
        read_only: bool,
    ) -> WorkflowFuture<'_, std::result::Result<Option<Vec<u8>>, PrivateSettlementError>> {
        Box::pin(async move {
            let permit = self
                .worker
                .clone()
                .try_acquire_owned()
                .map_err(|_| PrivateSettlementError::Worker)?;
            let client = self.client.clone();
            let request = self.request.clone();
            // The original worker owns its permit and prepared-artifact Arc even if its
            // awaiting call is dropped. No unbounded blocking task queue is created.
            run_private_settlement_worker(permit, move || {
                run(&client, &request, phase, &journal, read_only)
            })
            .await?
        })
    }
}

fn encode<T: norito::NoritoSerialize>(
    value: &T,
) -> std::result::Result<Option<Vec<u8>>, PrivateSettlementError> {
    let bytes = norito::encode_canonical(value)?;
    if bytes.len() > CERTIFICATE_TRANSCRIPT_BYTES as usize {
        return Err(PrivateSettlementError::Binding);
    }
    Ok(Some(bytes))
}
pub(super) fn run(
    client: &Client,
    request: &PrivateSettlementRequest,
    phase: usize,
    journal: &WorkflowJournalV1,
    read_only: bool,
) -> std::result::Result<Option<Vec<u8>>, PrivateSettlementError> {
    if phase == AVAILABILITY {
        // A missing local certificate checkpoint has never authorized promotion. Provisional
        // uploads may exist, so report Waiting rather than inventing external absence.
        if read_only {
            return Ok(None);
        }
        let certificates = request
            .0
            .materials
            .iter()
            .zip(&request.0.endpoints)
            .map(|(material, endpoints)| {
                client.certify_private_settlement_leg_availability_v1(endpoints, material)
            })
            .collect::<Result<Vec<_>>>()
            .map_err(PrivateSettlementError::Protocol)?;
        request.manifest_with(&certificates)?;
        return encode(&certificates);
    }
    let availability =
        transcript::<Vec<PrivateSettlementSidecarAvailabilityV1>>(journal, AVAILABILITY)?;
    let manifest = request.manifest_with(&availability)?;
    if phase == PREPARE {
        if !read_only {
            // This exact all-leg certificate snapshot is already durable in the preceding
            // round. Promotion must never recollect availability or change signer subsets.
            client
                .promote_private_settlement_legs_v1(
                    &request.0.materials,
                    &availability,
                    &request.0.endpoints,
                )
                .map_err(PrivateSettlementError::Protocol)?;
        }
        let mut certificates = Vec::with_capacity(request.0.materials.len());
        for (material, endpoints) in request.0.materials.iter().zip(&request.0.endpoints) {
            let recovered = if read_only {
                client.recover_private_settlement_prepare_certificate_v1(
                    endpoints,
                    &manifest,
                    material.payload_digest()?,
                    &material.committee_authority,
                )
            } else {
                client
                    .recover_or_certify_private_settlement_prepare_v1(
                        endpoints,
                        &manifest,
                        material.payload_digest()?,
                        &material.committee_authority,
                    )
                    .map(Some)
            }
            .map_err(PrivateSettlementError::Protocol)?;
            let Some(certificate) = recovered else {
                return Ok(None);
            };
            certificates.push(certificate);
        }
        // Reuse the complete barrier validator before recording the public certificates.
        Client::build_private_settlement_prepare_barrier_v1(
            manifest,
            &request
                .0
                .materials
                .iter()
                .map(|m| m.committee_authority.clone())
                .collect::<Vec<_>>(),
            request
                .0
                .materials
                .iter()
                .map(|m| m.delta.clone())
                .collect(),
            certificates.clone(),
        )
        .map_err(PrivateSettlementError::Protocol)?;
        return encode(&certificates);
    }
    if phase == COMMIT {
        let barrier = request.barrier(journal)?;
        let mut certificates = Vec::with_capacity(request.0.materials.len());
        for (material, endpoints) in request.0.materials.iter().zip(&request.0.endpoints) {
            let recovered = if read_only {
                client.recover_private_settlement_commit_certificate_v1(
                    endpoints,
                    material.payload_digest()?,
                    &barrier,
                    &material.committee_authority,
                )
            } else {
                client
                    .recover_or_certify_private_settlement_commit_v1(
                        endpoints,
                        material.payload_digest()?,
                        &barrier,
                        &material.committee_authority,
                    )
                    .map(Some)
            }
            .map_err(PrivateSettlementError::Protocol)?;
            let Some(certificate) = recovered else {
                return Ok(None);
            };
            certificates.push(certificate);
        }
        build_private_settlement_commit_bundle_v1(&barrier, &certificates)
            .map_err(PrivateSettlementError::Protocol)?;
        return encode(&certificates);
    }
    Err(PrivateSettlementError::Binding)
}
