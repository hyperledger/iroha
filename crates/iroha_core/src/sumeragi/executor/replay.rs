//! Exact startup completion acknowledgement after the original execution owner retires.

use super::super::commitment::{
    CertificatePart, MAX_RESULT_PREIMAGE_BYTES, ResultPreimageError, encode_certificate_part,
};
use super::*;
use crate::state::native_execution_tip::NativeExecutionTip;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_crypto::Hash;
use iroha_sumeragi::availability::AvailabilitySource;
use iroha_sumeragi::types::{ChainParams, Committee, EpochConfig, HeightConfig};

/// Complete original source identity without retaining its retired configuration graph.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReplaySource {
    instance: Hash32,
    height: u64,
    block_hash: Hash32,
    epoch: EpochConfig,
    params: ChainParams,
    committee_digest: Hash,
}

impl ReplaySource {
    fn capture(source: &AvailabilitySource) -> Self {
        let HeightConfig {
            epoch,
            committee,
            params,
        } = source.config();
        Self {
            instance: source.instance(),
            height: source.height(),
            block_hash: source.block_hash(),
            epoch: **epoch,
            params: *params,
            committee_digest: committee_digest(committee),
        }
    }
}

/// Stream the canonical counted and length-prefixed committee preimage without scratch.
fn committee_digest(committee: &Committee) -> Hash {
    Hash::new_from_writer(|writer| {
        writer.write_all(iroha_sumeragi::preimage::TAG_COMMITTEE)?;
        writer.write_all(
            &u32::try_from(committee.n())
                .expect("validated committee size fits u32")
                .to_be_bytes(),
        )?;
        for key in committee.members() {
            let bytes = key.as_bytes();
            writer.write_all(
                &u16::try_from(bytes.len())
                    .expect("validated public key length fits u16")
                    .to_be_bytes(),
            )?;
            writer.write_all(bytes)?;
        }
        Ok(())
    })
    .expect("incremental hash writer cannot fail")
}

/// Only the original serialized worker can move its completed authority into this receipt.
/// There is no decoder, clone, retained witness, result preimage or executed block here.
pub(super) struct CompletedReplay {
    source: ReplaySource,
    tip: NativeExecutionTip,
    header: Hash,
    qc: Hash,
    availability: Hash,
    payload: Hash,
}

fn encode(
    part: CertificatePart<'_>,
    budget: &AllocationBudget,
) -> Result<ChargedBuffer<u8>, ResultPreimageError> {
    encode_certificate_part(part, budget, MAX_RESULT_PREIMAGE_BYTES)
}

impl Worker<'_> {
    pub(super) fn replay(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<(), PublicationError> {
        match catch_unwind(AssertUnwindSafe(|| {
            self.replay_with_encoder(block, qc, encode)
        })) {
            Ok(result) => result,
            Err(_) => {
                let reason = "startup replay completion panicked; recovery required".to_owned();
                self.recovery = Some(reason.clone());
                Err(PublicationError::RecoveryRequired(reason))
            }
        }
    }

    fn replay_with_encoder(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
        mut encode: impl FnMut(
            CertificatePart<'_>,
            &AllocationBudget,
        ) -> Result<ChargedBuffer<u8>, ResultPreimageError>,
    ) -> Result<(), PublicationError> {
        if let Some(reason) = &self.recovery {
            return Err(PublicationError::RecoveryRequired(reason.clone()));
        }
        let budget = self.state.ivm_execution_budget();
        require_body_admission(block, &budget)?;
        if let Some(completed) = &self.completed_replay
            && completed.tip.height() == block.header().height
        {
            let current_tip = {
                let view = self.state.try_view_once()?;
                view.native_execution_tip() == Some(completed.tip)
                    && view.latest_block_hash() == Some(completed.tip.iroha_hash())
                    && view.height() as u64 == completed.tip.height()
            };
            if self.pending_commit.is_some()
                || !current_tip
                || self.applied != (completed.tip.height(), completed.tip.core_hash())
            {
                return Err(PublicationError::Retryable(
                    "replay completion is not the current fully applied native tip".into(),
                ));
            }
            return completed.acknowledge(block, qc, &budget, &mut encode);
        }
        match self.prepare_with_origin(block, qc, CommitTelemetryOrigin::HistoricalReplay)? {
            Some(result) if result == qc.result => {}
            Some(_) => {
                return Err(PublicationError::Retryable(
                    "replayed block diverges from its certified result".into(),
                ));
            }
            None => {
                return Err(PublicationError::Retryable(
                    "replayed block no longer executes".into(),
                ));
            }
        }
        self.commit(block, qc)?;
        // The same serialized request includes archive completion and retirement. No driver
        // request can replace the original Published owner between those operations.
        if let Err(error) = self.retire_completed_replay(block, qc) {
            if let PublicationError::RecoveryRequired(reason) = &error {
                self.recovery = Some(reason.clone());
            }
            return Err(error);
        }
        Ok(())
    }

    fn retire_completed_replay(
        &mut self,
        block: &AvailableBody,
        qc: &Qc,
    ) -> Result<(), PublicationError> {
        let invalid = |reason: &str| PublicationError::RecoveryRequired(reason.to_owned());
        if self.pending_commit.is_some() || self.finishing.is_some() {
            return Err(invalid(
                "replay execution has not completed all publication effects",
            ));
        }
        let (tip, latest_hash, height) = {
            let view = self.state.try_view_once()?;
            (
                view.native_execution_tip()
                    .ok_or_else(|| invalid("replay has no original native execution tip"))?,
                view.latest_block_hash(),
                view.height(),
            )
        };
        let live = self
            .live
            .as_ref()
            .ok_or_else(|| invalid("replay lost its original published execution"))?;
        let PublicationPhase::Published {
            staged,
            qc: original,
        } = &live.phase
        else {
            return Err(invalid("replay execution is not published"));
        };
        if original != qc
            || live.header != *block.header()
            || live.availability != *block.availability()
            || live.source != *block.source()
            || live.telemetry_origin != Some(CommitTelemetryOrigin::HistoricalReplay)
            || live.overlay.is_some()
            || self.applied != (tip.height(), tip.core_hash())
            || tip.height() != live.height
            || tip.core_hash() != live.block_hash
            || tip.result() != live.result
            || tip.iroha_hash() != staged.executed.hash()
            || latest_hash != Some(tip.iroha_hash())
            || height as u64 != tip.height()
        {
            return Err(invalid(
                "replay completion differs from its original published source",
            ));
        }
        let certificate = staged
            .executed
            .commit_certificate()
            .ok_or_else(|| invalid("published replay lost its certificate"))?;
        if !certificate.admitted_to(&self.state.ivm_execution_budget()) {
            return Err(invalid(
                "published replay certificate lost original pool custody",
            ));
        }
        let header = Hash::new(certificate.consensus_header());
        let qc = Hash::new(certificate.commit_qc());
        let availability = Hash::new(certificate.availability());
        let payload = Hash::new(block.payload().as_slice());
        let live = self.live.take().expect("same serialized published owner");
        self.completed_replay = Some(CompletedReplay {
            source: ReplaySource::capture(&live.source),
            tip,
            header,
            qc,
            availability,
            payload,
        });
        self.context.staging.clear();
        Ok(())
    }
}

impl CompletedReplay {
    fn acknowledge(
        &self,
        block: &AvailableBody,
        qc: &Qc,
        budget: &AllocationBudget,
        encode: &mut impl FnMut(
            CertificatePart<'_>,
            &AllocationBudget,
        ) -> Result<ChargedBuffer<u8>, ResultPreimageError>,
    ) -> Result<(), PublicationError> {
        if !cfg!(all(test, sumeragi_core_mutation = "HC94"))
            && self.source != ReplaySource::capture(block.source())
        {
            return Err(PublicationError::Retryable(
                "replay completion differs from the complete original source configuration".into(),
            ));
        }
        // Scratch belongs to the original State pool and is released after each digest.
        // A local refusal changes neither this completion nor any execution state.
        let mut digest = |part| {
            encode(part, budget)
                .map(|bytes| Hash::new(bytes.as_slice()))
                .map_err(|error| {
                    if cfg!(all(test, sumeragi_core_mutation = "HC79")) {
                        PublicationError::Retryable(error.to_string())
                    } else {
                        preparation::encoding_failure(&error)
                    }
                })
        };
        let header = digest(CertificatePart::Header(block.header()))?;
        let qc = digest(CertificatePart::Qc(qc))?;
        let availability = digest(CertificatePart::Availability(block.availability()))?;
        if !cfg!(all(test, sumeragi_core_mutation = "HC57"))
            && (self.payload != Hash::new(block.payload().as_slice())
                || self.header != header
                || self.qc != qc
                || self.availability != availability)
        {
            return Err(PublicationError::Retryable("replay completion differs from the exact original certificate, availability or source".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
