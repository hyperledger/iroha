//! Direct quorum-certified execution results for light clients.
//!
//! A signed genesis fixes the first epoch's complete authority and height interval.
//! Each incumbent boundary quorum certifies the next interval and ordered roster.
//! Intermediate ordinary blocks are unnecessary: honest Commit voters already validate
//! execution, availability and the lag-two schedule before signing the result. This reader
//! authenticates that consensus decision; it does not manufacture full-block custody.

use super::*;
use crate::sumeragi::epoch::ValidatorEpochContextV1;

mod checkpoint;
pub use checkpoint::{MAX_COMMIT_CHECKPOINT_BYTES, SumeragiCommitCheckpointV1};

const MAX_COMMIT_HEADER_BYTES: usize = 64 * 1024;
const MAX_COMMIT_QC_BYTES: usize = 4 * 1024;

/// Maximum canonical original certificate frame for one bounded epoch-sync response.
/// This power-of-two ceiling covers the existing 64 KiB header, 4 KiB QC and 64 KiB result
/// limits plus canonical struct/vector/schema framing. The individual component limits
/// still apply; this is a transport allocation bound, not an enlarged consensus result.
pub const MAX_COMMIT_CERTIFICATE_BYTES_V1: usize = 256 * 1024;

/// Original native header, `CommitQC` and signed execution-result preimage, without a block body.
/// The ordered signing roster comes exclusively from independently authenticated epochs.
#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, iroha_schema::IntoSchema, norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiCommitCertificateV1")]
pub struct SumeragiCommitCertificateV1 {
    /// Canonical native consensus header named by the quorum certificate.
    pub consensus_header: Vec<u8>,
    /// Canonical exact-quorum BLS Commit certificate.
    pub commit_qc: Vec<u8>,
    /// Complete canonical native execution result, including its counted event root.
    pub result_preimage: Vec<u8>,
}

impl SumeragiCommitCertificateV1 {
    /// Encode bounded canonical original components without authenticating their signatures.
    ///
    /// # Errors
    /// Rejects noncanonical native components, malformed execution or an oversized frame.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, FinalityError> {
        self.originals()?;
        need(
            norito::canonical_frame_len(self).map_err(malformed)?
                <= MAX_COMMIT_CERTIFICATE_BYTES_V1,
            "compact certificate frame exceeds bound",
        )?;
        norito::encode_canonical(self).map_err(malformed)
    }

    /// Decode bounded canonical original DATA; only native BLS verification grants authority.
    ///
    /// # Errors
    /// Rejects oversized or noncanonical outer/inner frames and malformed native execution.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FinalityError> {
        need(
            !bytes.is_empty() && bytes.len() <= MAX_COMMIT_CERTIFICATE_BYTES_V1,
            "compact certificate frame exceeds bound",
        )?;
        let certificate: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(malformed)?;
        certificate.originals()?;
        Ok(certificate)
    }

    /// Unauthenticated header height, usable only as an original-data lookup selector.
    ///
    /// # Errors
    /// Rejects missing, oversized or noncanonical native header data.
    pub fn height(&self) -> Result<u64, FinalityError> {
        Ok(self.header()?.height)
    }

    /// Unauthenticated numeric epoch, usable only to look up already selected authority.
    ///
    /// # Errors
    /// Rejects missing, oversized or noncanonical native header data.
    pub fn epoch_id(&self) -> Result<u64, FinalityError> {
        Ok(self.header()?.epoch.epoch)
    }

    fn header(&self) -> Result<CoreHeader, FinalityError> {
        self.validate_shape()?;
        norito::decode_canonical_with_limits(
            &self.consensus_header,
            norito::canonical_decode_limits(self.consensus_header.len()),
        )
        .map_err(malformed)
    }

    fn originals(&self) -> Result<(CoreHeader, Qc, ExecutionResultCommitment), FinalityError> {
        let header = self.header()?;
        let qc = norito::decode_canonical_with_limits(
            &self.commit_qc,
            norito::canonical_decode_limits(self.commit_qc.len()),
        )
        .map_err(malformed)?;
        let commitment =
            ExecutionResultCommitment::decode(&self.result_preimage).map_err(malformed)?;
        Ok((header, qc, commitment))
    }

    /// Retain the original certificate from an independently verified non-genesis block.
    ///
    /// # Errors
    /// Genesis has no `CommitQC`; malformed or oversized original components are rejected.
    pub fn from_verified(block: &VerifiedSumeragiBlock) -> Result<Self, FinalityError> {
        need(block.height() >= 2, "genesis has no Commit certificate")?;
        let certificate = block.block().commit_certificate().ok_or_else(|| {
            FinalityError("verified block has no embedded Commit certificate".into())
        })?;
        let value = Self {
            consensus_header: certificate.consensus_header().to_vec(),
            commit_qc: certificate.commit_qc().to_vec(),
            result_preimage: certificate.result_preimage().to_vec(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    /// Check finite component lengths without authenticating any signed statement.
    ///
    /// # Errors
    /// Missing or oversized components are rejected before native decoding.
    pub fn validate_shape(&self) -> Result<(), FinalityError> {
        for (bytes, limit) in [
            (&self.consensus_header, MAX_COMMIT_HEADER_BYTES),
            (&self.commit_qc, MAX_COMMIT_QC_BYTES),
            (&self.result_preimage, MAX_RESULT_PREIMAGE_BYTES),
        ] {
            need(
                !bytes.is_empty() && bytes.len() <= limit,
                "compact certificate component exceeds its bound",
            )?;
        }
        Ok(())
    }
}

/// Quorum-certified execution under a genesis-rooted, height-authorized committee.
/// No public constructor or decoder can manufacture this capability.
#[derive(Debug, Clone)]
pub struct VerifiedSumeragiCommitV1 {
    network: NetworkId,
    chain: String,
    core_hash: Hash32,
    commitment: ExecutionResultCommitment,
}

impl VerifiedSumeragiCommitV1 {
    /// Original certified execution height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.commitment.height
    }

    /// Native consensus block identity authenticated by the BLS certificate.
    #[must_use]
    pub const fn core_hash(&self) -> Hash32 {
        self.core_hash
    }

    /// Certified execution, including its original counted event commitment.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionCommitment {
        &self.commitment.execution
    }

    /// Complete certified schedule and execution result.
    #[must_use]
    pub const fn commitment(&self) -> &ExecutionResultCommitment {
        &self.commitment
    }

    /// Match the independently selected global network and chain.
    ///
    /// # Errors
    /// A different network or chain is rejected.
    pub fn verify_global_scope(
        &self,
        network: NetworkId,
        chain: &str,
    ) -> Result<(), FinalityError> {
        need(
            self.network == network && self.chain == chain,
            "compact certificate global scope differs",
        )
    }
}

/// Native BLS light reader with authenticated epoch authority, never caller-selected rosters.
///
/// Ordinary Commit results need no history replay within their signed epoch interval.
/// Crossing an interval requires its exact final-height Commit result under the incumbent
/// quorum. Certified parameters and selection outputs rely on ordinary honest-validator
/// execution, just like the successful Load event; this is not VM reexecution.
#[derive(Debug, Clone)]
pub struct SumeragiCommitVerifierV1 {
    genesis_hash: HashOf<BlockHeader>,
    network: NetworkId,
    chain: String,
    instance: Hash32,
    initial: ValidatorEpochContextV1,
    epochs: BTreeMap<u64, ValidatorEpochContextV1>,
}

impl SumeragiCommitVerifierV1 {
    /// Select the original signed global genesis and any independently verified epoch decisions.
    /// The supplied owner must already have authenticated and selected its genesis.
    ///
    /// # Errors
    /// Private roots or an inconsistent signed genesis context are rejected.
    pub fn new(native: &SumeragiFinalityVerifier) -> Result<Self, FinalityError> {
        need(
            matches!(
                native.root_scope(),
                crate::block::consensus::SumeragiRootScope::Global
            ),
            "compact global finality requires global signed genesis",
        )?;
        let mut epochs = BTreeMap::new();
        let initial = native.initial_epoch();
        initial.validate().map_err(malformed)?;
        epochs.insert(initial.authorization.epoch, initial.clone());
        for decision in native.decisions.values() {
            epochs.insert(
                decision.schedule.current.authorization.epoch,
                decision.schedule.current.clone(),
            );
            if let Some(boundary) = &decision.schedule.boundary {
                epochs.insert(boundary.next.authorization.epoch, boundary.next.clone());
            }
        }
        Ok(Self {
            genesis_hash: native.genesis.hash(),
            network: initial.network_id,
            chain: native.chain_id().into(),
            instance: native.instance(),
            initial: initial.clone(),
            epochs,
        })
    }

    /// Independently selected genesis-derived network.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Independently selected chain label.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain
    }

    /// Verify one incumbent boundary and export only its authenticated successor epoch.
    ///
    /// The returned checkpoint may be restored only after native manifest custody selects
    /// its exact bytes. An ordinary certificate cannot advance synchronization. Failure leaves
    /// this reader unchanged, including when certificate verification succeeds without a boundary.
    ///
    /// # Errors
    /// Rejects malformed or forged certificates, omitted authority and non-boundary results.
    pub fn verify_epoch_boundary(
        &mut self,
        certificate: &SumeragiCommitCertificateV1,
    ) -> Result<SumeragiCommitCheckpointV1, FinalityError> {
        let mut candidate = self.clone();
        let verified = candidate.verify(certificate)?;
        let boundary = verified
            .commitment()
            .schedule
            .boundary
            .as_ref()
            .ok_or_else(|| FinalityError("epoch synchronization requires a boundary".into()))?;
        need(
            verified.height()
                == verified
                    .commitment()
                    .schedule
                    .current
                    .authorization
                    .last_height,
            "epoch synchronization height differs from incumbent boundary",
        )?;
        let checkpoint = candidate.export_epoch_checkpoint(boundary.next.authorization.epoch)?;
        *self = candidate;
        Ok(checkpoint)
    }

    /// Authenticate one exact `CommitQC` and install only its certified boundary successor.
    ///
    /// # Errors
    /// Missing epoch transitions, stale or substituted rosters, wrong scope, height/result
    /// bindings, noncanonical bytes, malformed schedules and invalid exact-quorum BLS fail.
    /// A failure leaves all retained authority unchanged.
    pub fn verify(
        &mut self,
        proof: &SumeragiCommitCertificateV1,
    ) -> Result<VerifiedSumeragiCommitV1, FinalityError> {
        let (header, qc, commitment) = proof.originals()?;
        let offered = &commitment.schedule.current;
        let selected = self
            .epochs
            .get(&offered.authorization.epoch)
            .ok_or_else(|| FinalityError("missing certified predecessor epoch boundary".into()))?;
        need(
            selected == offered,
            "certificate roster differs from authenticated epoch authority",
        )?;
        need(
            header.height >= 2
                && header.height >= selected.authorization.first_height
                && header.height <= selected.authorization.last_height,
            "certificate height is outside authenticated epoch authority",
        )?;
        let epoch = core_epoch(selected).map_err(malformed)?;
        let validators: Vec<_> = selected
            .committee
            .iter()
            .map(|member| FinalityValidator {
                public_key: member.validator.public_key().clone(),
                proof_of_possession: member.proof_of_possession.clone(),
            })
            .collect();
        let (crypto, committee) = ProofCrypto::new(&validators)?;
        let core_hash = header.hash(&crypto);
        need(
            (&header.instance, &header.epoch) == (&self.instance, &epoch.id)
                && (&qc.instance, &qc.epoch) == (&self.instance, &epoch.id)
                && qc.kind == VoteKind::Commit
                && qc.height == header.height
                && qc.block_hash == core_hash
                && qc.result == result_of_preimage(&proof.result_preimage)
                && commitment.height == header.height,
            "compact certificate does not bind the selected instance, epoch and execution",
        )?;
        iroha_sumeragi::crypto::Verifier::new(&crypto, &self.instance, &epoch.id, &committee)
            .verify_qc(&qc)
            .map_err(|error| FinalityError(format!("commit certificate: {error:?}")))?;
        if let Some(boundary) = &commitment.schedule.boundary {
            if let Some(previous) = self.epochs.get(&boundary.next.authorization.epoch) {
                need(
                    previous == &boundary.next,
                    "conflicting certified epoch successor",
                )?;
            }
            self.epochs
                .insert(boundary.next.authorization.epoch, boundary.next.clone());
        }
        Ok(VerifiedSumeragiCommitV1 {
            network: self.network,
            chain: self.chain.clone(),
            core_hash,
            commitment,
        })
    }
}

#[cfg(all(test, feature = "transparent_api"))]
mod tests;
