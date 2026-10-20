//! Complete retained Kura authentication: original frame, full QC, and signed body restoration.
use super::body_read::StoredBodyReadPoll;
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use certificate_read::{CertificateRead, CertificateReadError, DecodedCertificate};
use iroha_sumeragi::availability::BodyRestoration;

enum Phase {
    Certificate(CertificateRead),
    Decoded(DecodedCertificate),
    Projecting(body_read::StoredBodyRead),
    Restoring(BodyRestoration, Qc),
    Consumed,
}
pub(super) struct CommittedRead {
    height: u64,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    schedule: Arc<dyn AvailabilitySchedule>,

    phase: Phase,
}
impl CommittedRead {
    pub(super) fn new(
        block: iroha_data_model::block::SharedSignedBlock,
        height: u64,
        budget: AllocationBudget,
        crypto: SharedCrypto,
        schedule: Arc<dyn AvailabilitySchedule>,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Self {
        Self {
            height,
            phase: Phase::Certificate(CertificateRead::new(block, budget.clone())),
            budget,
            crypto,
            root_scope,
            schedule,
        }
    }
    pub(super) fn height(&self) -> u64 {
        self.height
    }
    /// Observe a refused original certificate read without progressing or replacing its owner.
    #[cfg(test)]
    pub(super) fn retained_certificate_owners_for_test(
        &self,
    ) -> Option<(*const SignedBlock, Option<*const u8>)> {
        match &self.phase {
            Phase::Certificate(job) => Some(job.retained_owners_for_test()),
            _ => None,
        }
    }
    /// Decode and authenticate finality once while retaining the source on local refusal.
    /// Existing payload work is left intact when a metadata caller joins a refused body read.
    fn authenticated_certificate(
        &mut self,
    ) -> Result<Option<(DecodedCertificate, AvailabilitySource)>, Attempt<io::Error>> {
        loop {
            match std::mem::replace(&mut self.phase, Phase::Consumed) {
                Phase::Certificate(job) => match job.complete(&self.budget) {
                    Ok(decoded) => self.phase = Phase::Decoded(decoded),
                    Err((job, error)) => {
                        self.phase = Phase::Certificate(job);
                        return Err(match error {
                            CertificateReadError::Admission(error) => {
                                super::super::storage_attempt::byte(error)
                            }
                            CertificateReadError::Decode(error) => {
                                BodyReadError::from_decode(error).into_attempt()
                            }
                            CertificateReadError::Canonical(original) => {
                                crate::execution_attempt::canonical_decode_attempt_error(
                                    original,
                                    |error| io::Error::new(io::ErrorKind::InvalidData, error),
                                )
                            }
                            error => io::Error::new(io::ErrorKind::InvalidData, error).into(),
                        });
                    }
                },
                Phase::Decoded(decoded) => {
                    match certified_source(
                        &*self.schedule,
                        &*self.crypto,
                        self.height,
                        &decoded.header,
                        &decoded.commit_qc,
                    ) {
                        Ok(source) => return Ok(Some((decoded, source))),
                        Err(error) => {
                            self.phase = Phase::Decoded(decoded);
                            return Err(error);
                        }
                    }
                }
                Phase::Consumed => return Err(invalid("committed read already consumed").into()),
                phase => {
                    self.phase = phase;
                    return Ok(None);
                }
            }
        }
    }

    /// Authenticate metadata without allocating a proposal payload or regenerating RS16 rows.
    /// The signed table proves authenticity only; it never grants available-body custody.
    pub(super) fn poll_metadata(&mut self) -> Result<SyncEntry, Attempt<io::Error>> {
        let Some((decoded, source)) = self.authenticated_certificate()? else {
            // A previous full-body reader already owns projection/restoration buffers. Finish
            // that original work rather than discarding it when a metadata request arrives.
            return self.poll().map(|(body, commit_qc)| SyncEntry {
                manifest: PayloadManifest {
                    header: body.header().clone(),
                    availability: body.availability().clone(),
                },
                commit_qc,
            });
        };
        if let Err(error) = self.validate_metadata(&decoded, &source) {
            self.phase = Phase::Decoded(decoded);
            return Err(error);
        }
        Ok(SyncEntry {
            manifest: PayloadManifest {
                header: decoded.header,
                availability: decoded.availability,
            },
            commit_qc: decoded.commit_qc,
        })
    }

    fn validate_metadata(
        &self,
        decoded: &DecodedCertificate,
        source: &AvailabilitySource,
    ) -> Result<(), Attempt<io::Error>> {
        body_read::validate_decoded(source, decoded, &*self.crypto, self.root_scope)
            .map_err(BodyReadError::into_attempt)?;
        let header = &decoded.header;
        if header.skipped_leaders.len() > source.config().committee.n() {
            return Err(invalid("stored header exceeds the historical committee").into());
        }
        iroha_sumeragi::availability::verify_manifest(
            source.instance(),
            source.config(),
            header,
            &decoded.availability,
            &self.budget,
            &*self.crypto,
        )
        .map_err(|error| invalid(format!("invalid committed availability: {error:?}")))?;
        // Bind the stored proposal to the certified header with the native chain hash. This
        // streams canonical bytes into the hasher; it retains no full payload or RS16 scratch.
        let payload_len = decoded
            .source
            .resultless_proposal_wire_len()
            .map_err(|error| BodyReadError::from_decode(error).into_attempt())?;
        let mut codec_error = None;
        let payload_hash = iroha_crypto::Hash::new_from_writer(|writer| {
            writer.write_all(iroha_sumeragi::preimage::TAG_PAY)?;
            decoded
                .source
                .write_resultless_proposal_wire(writer)
                .map_err(|error| {
                    codec_error = Some(error);
                    io::Error::other("canonical proposal encoding failed")
                })
        });
        if let Some(error) = codec_error {
            return Err(BodyReadError::from_decode(error).into_attempt());
        }
        let payload_hash = payload_hash.map_err(|error| invalid(error.to_string()))?;
        if header.payload_len == 0
            || u32::try_from(payload_len).ok() != Some(header.payload_len)
            || Hash32(*payload_hash.as_ref()) != header.payload_hash
        {
            return Err(invalid("stored proposal differs from its certified header").into());
        }
        Ok(())
    }

    pub(super) fn poll(&mut self) -> Result<(AvailableBody, Qc), Attempt<io::Error>> {
        if let Some((decoded, source)) = self.authenticated_certificate()? {
            self.phase = Phase::Projecting(body_read::StoredBodyRead::from_decoded(
                source,
                decoded,
                self.budget.clone(),
                self.crypto.clone(),
                self.root_scope,
            ));
        }
        loop {
            match std::mem::replace(&mut self.phase, Phase::Consumed) {
                Phase::Projecting(mut job) => match job.poll_with_qc(&self.budget) {
                    Ok(StoredBodyReadPoll::Ready(restoration, qc)) => {
                        self.phase = Phase::Restoring(restoration, qc)
                    }
                    Ok(StoredBodyReadPoll::Pending(error)) => {
                        self.phase = Phase::Projecting(job);
                        return Err(super::super::storage_attempt::byte(error));
                    }
                    Err(error) => {
                        self.phase = Phase::Projecting(job);
                        // Keep the original operational category and typed cause so the
                        // outer Kura read slot retains this exact owner across local refusal.
                        return Err(error.into_attempt());
                    }
                },
                Phase::Restoring(job, qc) => match job.complete(&self.budget, &*self.crypto) {
                    Ok(body) => return Ok((body, qc)),
                    Err((job, error)) => {
                        self.phase = Phase::Restoring(job, qc);
                        return Err(super::super::storage_attempt::restoration(error));
                    }
                },
                Phase::Certificate(_) | Phase::Decoded(_) | Phase::Consumed => {
                    return Err(invalid("committed read already consumed").into());
                }
            }
        }
    }
}
/// A claimed QC never supplies its own authority. Full verification precedes source construction.
pub(super) fn certified_source(
    schedule: &dyn AvailabilitySchedule,
    crypto: &dyn iroha_sumeragi::crypto::Crypto,

    height: u64,
    header: &BlockHeader,
    qc: &Qc,
) -> Result<AvailabilitySource, Attempt<io::Error>> {
    let instance = schedule.instance();
    if header.height != height || header.instance != instance || qc.height != height {
        return Err(invalid("committed source height or instance mismatch").into());
    }
    let config = schedule
        .height_config(height)?
        .ok_or_else(|| busy("authenticated historical authority unavailable"))?;
    if !Verifier::new(crypto, &instance, &config.epoch.id, &config.committee)
        .verify_commit_qc(qc, Some(header))
    {
        return Err(invalid("original commit certificate does not verify").into());
    }
    AvailabilitySource::new(instance, height, qc.block_hash, config)
        .map_err(|error| invalid(format!("invalid committed source: {error:?}")).into())
}

#[cfg(test)]
#[path = "committed_read_tests.rs"]
mod tests;
