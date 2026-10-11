//! Compact restart trust for an independently authenticated current-consensus prefix.
//!
//! Importing this DTO is an explicit trust-root operation. Its selected genesis and schedule
//! commitments must be authenticated outside the response being verified (for example, by an
//! operator-selected local checkpoint). A peer response must never become its own checkpoint.
use super::*;

/// Maximum canonical checkpoint: one signed genesis, one current proof and bounded committees.
pub const MAX_FINALITY_CHECKPOINT_BYTES: usize = 2 * MAX_FINALITY_BLOCK_BYTES + 4 * 1024 * 1024;

#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema, iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::CheckpointDecision")]
struct CheckpointDecision {
    height: u64,
    block_hash: HashOf<BlockHeader>,
    core_hash: [u8; 32],
    result: [u8; 32],
    committee_digest: [u8; 32],
    schedule: ScheduleOutcome,
    beacon: Option<crate::consensus::FinalizedGlobalThresholdBeaconPulseV1>,
    executed_hash: Hash,
    executed_len: u64,
}
impl CheckpointDecision {
    fn capture(height: u64, value: &Decision) -> Self {
        Self {
            height,
            block_hash: value.block_hash,
            core_hash: value.core_hash.0,
            result: value.result.0,
            committee_digest: value.committee_digest,
            schedule: value.schedule.clone(),
            beacon: value.beacon,
            executed_hash: value.executed_hash,
            executed_len: value.executed_len,
        }
    }
    fn decision(&self) -> Decision {
        Decision {
            block_hash: self.block_hash,
            core_hash: Hash32(self.core_hash),
            result: Hash32(self.result),
            committee_digest: self.committee_digest,
            schedule: self.schedule.clone(),
            beacon: self.beacon,
            executed_hash: self.executed_hash,
            executed_len: self.executed_len,
        }
    }
}

/// Canonical compact checkpoint exported from an authenticated prefix.
///
/// It retains the tip and at most two predecessor decisions needed for exact-tip and epoch-bound
/// successor verification. Private fields prevent accidental construction from an unverified
/// proof; decoding still yields an untrusted DTO. Independent local selection authenticates its
/// genesis, chain label and retained schedule commitments before `from_trusted_checkpoint`.
#[derive(
    Debug, Clone, PartialEq, Eq, Encode, Decode, norito::NoritoSchema, iroha_schema::IntoSchema,
)]
#[norito_schema(name = "iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint")]
pub struct SumeragiFinalityCheckpoint {
    network_id: NetworkId,
    chain_id: String,
    genesis_wire: Vec<u8>,
    genesis_committee: Vec<FinalityValidator>,
    decisions: Vec<CheckpointDecision>,
    tip: SumeragiFinalityProof,
}
impl SumeragiFinalityCheckpoint {
    /// Network identity derived from the independently selected signed genesis.
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }
    /// Independently selected current-consensus chain label.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Checkpoint height; import must authenticate this decoded claim before use.
    pub fn height(&self) -> u64 {
        self.tip.height()
    }
    /// Checkpoint block hash; import must authenticate this decoded claim before use.
    pub fn block_hash(&self) -> HashOf<BlockHeader> {
        self.tip.block_header.hash()
    }
    /// Retained proof of the checkpoint's exact certified decision.
    pub const fn tip(&self) -> &SumeragiFinalityProof {
        &self.tip
    }

    /// Build bounded restart DATA around independently authenticated decision witnesses.
    ///
    /// This is a data builder, not a trust-root authenticator. It retains this exact selected
    /// genesis and chain, and interprets at most three consecutive complete proof originals.
    /// Before importing its output, the actual Node must compare EVERY decoded decision to
    /// the original consensus-visible committed execution, including the complete schedule,
    /// result, beacon and executed-wire commitment. Offered proofs cannot provide that source.
    /// The supplied tip may be historical; no current time or live effect is granted.
    ///
    /// # Errors
    /// Refuses empty/excessive/discontinuous witnesses, foreign roots or invalid framing.
    pub fn with_independently_authenticated_decision_data(
        &self,
        proofs: &[SumeragiFinalityProof],
    ) -> Result<Self, FinalityError> {
        self.validate_bounds()?;
        let tip = proofs
            .last()
            .ok_or_else(|| FinalityError("native decision data is empty".into()))?;
        need(
            tip.height() >= self.height()
                && proofs.len() == usize::try_from(tip.height().min(3)).map_err(malformed)?,
            "native decision data omits the exact bounded parent set",
        )?;
        let first = tip.height().saturating_sub(2).max(1);
        let mut decisions = Vec::with_capacity(proofs.len());
        for (offset, proof) in proofs.iter().enumerate() {
            need(
                proof.height() == first + u64::try_from(offset).map_err(malformed)?,
                "native decision data is discontinuous",
            )?;
            let decoded = proof.decode_checked()?;
            if proof.height() == 1 {
                need(
                    decoded
                        .block
                        .canonical_resultless_proposal()
                        .map_err(malformed)?
                        .encode_wire()
                        .map_err(malformed)?
                        == self.genesis_wire,
                    "native decision data replaces the selected genesis",
                )?;
            }
            decisions.push(CheckpointDecision::capture(
                proof.height(),
                &SumeragiFinalityVerifier::decision(&decoded),
            ));
        }
        let value = Self {
            network_id: self.network_id,
            chain_id: self.chain_id.clone(),
            genesis_wire: self.genesis_wire.clone(),
            genesis_committee: self.genesis_committee.clone(),
            decisions,
            tip: tip.clone(),
        };
        value.validate_bounds()?;
        Ok(value)
    }

    /// Encode this checkpoint in the sole canonical layout with finite resource bounds.
    ///
    /// # Errors
    /// Malformed bounds or encoding failure; this does not authenticate decoded trust roots.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FinalityError> {
        if norito::core::decode_limits_active() {
            // An enclosing owner keeps the original independent scopes and charges.
            self.validate_bounds()?;
        } else {
            // Reuse only exact immutable epoch values within these bounds checks. End
            // the workspace before encoding; no verdict or workspace leaves this call.
            let mut validation = EpochValidationScope::new();
            self.validate_bounds_with_validation(Some(&mut validation))?;
        }
        norito::encode_canonical(self).map_err(malformed)
    }
    /// Decode bounded canonical material; independent checkpoint selection is still required.
    ///
    /// # Errors
    /// Empty, oversized, noncanonical or structurally malformed checkpoint.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FinalityError> {
        Self::decode_canonical_with_validation(bytes, None)
    }

    /// Decode the original canonical frame with pure context work borrowed by one operation.
    /// Every byte and allocation still uses the original finite decoder. An active enclosing
    /// decoder owner ignores this workspace and preserves the independent bounds validation.
    ///
    /// # Errors
    /// Exactly the same frame, structural and resource failures as [`Self::decode_canonical`].
    pub fn decode_canonical_with_validation(
        bytes: &[u8],
        validation: Option<&mut EpochValidationScope>,
    ) -> Result<Self, FinalityError> {
        // Sample before entering the native decoder's own input-derived scope.
        let validation = if norito::core::decode_limits_active() {
            None
        } else {
            validation
        };
        need(
            !bytes.is_empty() && bytes.len() <= MAX_FINALITY_CHECKPOINT_BYTES,
            "checkpoint frame exceeds bound",
        )?;
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(malformed)?;
        value.validate_bounds_with_validation(validation)?;
        Ok(value)
    }
    fn validate_bounds(&self) -> Result<(), FinalityError> {
        self.validate_bounds_with_validation(None)
    }

    fn validate_bounds_with_validation(
        &self,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<(), FinalityError> {
        need(
            !self.chain_id.is_empty() && self.chain_id.len() <= 1024,
            "checkpoint chain label exceeds bound",
        )?;
        need(
            !self.genesis_wire.is_empty() && self.genesis_wire.len() <= MAX_FINALITY_BLOCK_BYTES,
            "checkpoint genesis exceeds bound",
        )?;
        need(
            !self.tip.block_wire.is_empty()
                && self.tip.block_wire.len() <= MAX_FINALITY_BLOCK_BYTES,
            "checkpoint tip exceeds bound",
        )?;
        need(
            !self.genesis_committee.is_empty()
                && self.genesis_committee.len() <= iroha_sumeragi::types::MAX_COMMITTEE_SIZE,
            "checkpoint genesis committee exceeds bound",
        )?;
        need(
            !self.tip.committee.is_empty()
                && self.tip.committee.len() <= iroha_sumeragi::types::MAX_COMMITTEE_SIZE,
            "checkpoint tip committee exceeds bound",
        )?;
        need(
            self.height() > 0
                && self.height() < u64::MAX
                && self.decisions.len() == self.height().min(3) as usize,
            "checkpoint requires an extensible tip and two predecessor commitments",
        )?;
        let first = self.height().saturating_sub(2).max(1);
        for (offset, decision) in self.decisions.iter().enumerate() {
            need(
                decision.height == first + offset as u64
                    && decision.core_hash != [0; 32]
                    && decision.result != [0; 32]
                    && decision.committee_digest != [0; 32]
                    && decision.schedule.height == decision.height
                    && validation
                        .as_deref_mut()
                        .map_or_else(
                            || decision.schedule.validate(),
                            |validation| decision.schedule.validate_with_validation(validation),
                        )
                        .is_ok()
                    && decision.executed_len > 0
                    && decision.executed_len <= MAX_FINALITY_BLOCK_BYTES as u64,
                "checkpoint commitments are malformed or discontinuous",
            )?;
        }
        need(
            norito::canonical_frame_len(self).map_err(malformed)? <= MAX_FINALITY_CHECKPOINT_BYTES,
            "checkpoint exceeds canonical byte bound",
        )
    }
}

impl SumeragiFinalityVerifier {
    /// Export only the tip of this already authenticated prefix and its bounded restart context.
    ///
    /// # Errors
    /// Missing prefix, a non-tip proof, substituted decision or invalid certificate.
    pub fn export_checkpoint(
        &self,
        tip: &SumeragiFinalityProof,
    ) -> Result<SumeragiFinalityCheckpoint, FinalityError> {
        need(
            self.decisions.last_key_value().map(|(height, _)| *height) == Some(tip.height()),
            "checkpoint must export the authenticated tip",
        )?;
        // This producer owns pure epoch work only until its checkpoint is returned.
        // Active caller admission keeps the original independent verification recipe.
        let mut validation =
            (!norito::core::decode_limits_active()).then(EpochValidationScope::new);
        // The original witness still undergoes every certificate, prefix and decision check.
        if let Some(validation) = validation.as_mut() {
            self.verify_retained_decision_with_validation(tip, Some(validation))?;
        } else {
            self.verify_retained_decision(tip)?;
        }
        let first = tip.height().saturating_sub(2).max(1);
        let checkpoint = SumeragiFinalityCheckpoint {
            network_id: NetworkId::from_genesis_hash(self.genesis.hash()),
            chain_id: self.chain_id.clone(),
            genesis_wire: self
                .genesis
                .canonical_resultless_proposal()
                .map_err(malformed)?
                .encode_wire()
                .map_err(malformed)?,
            genesis_committee: self.genesis_committee.clone(),
            decisions: self
                .decisions
                .range(first..)
                .map(|(height, decision)| CheckpointDecision::capture(*height, decision))
                .collect(),
            tip: tip.clone(),
        };
        if let Some(validation) = validation.as_mut() {
            checkpoint.validate_bounds_with_validation(Some(validation))?;
        } else {
            checkpoint.validate_bounds()?;
        }
        // The result is the same DTO, not a retained epoch workspace or current-state grant.
        drop(validation);
        Ok(checkpoint)
    }

    /// Import an independently authenticated local checkpoint as the new trust root.
    ///
    /// The caller must authenticate the selected file's genesis and retained schedule/result
    /// commitments independently of any new proof response. This checks internal consistency
    /// and re-verifies the tip certificate; it cannot establish the provenance of that selection.
    /// A remote checkpoint or one copied from the response is never an acceptable argument.
    ///
    /// # Errors
    /// Bounds, network/chain/genesis mismatch, discontinuous commitments, substituted tip,
    /// committee, invalid proof of possession or failed certificate authentication. Original
    /// genesis decoder resource fields are retained for the caller's locality classification.
    pub fn from_trusted_checkpoint(
        checkpoint: &SumeragiFinalityCheckpoint,
        network: &NetworkId,
        chain_id: &str,
    ) -> Result<Self, super::FinalityReadError> {
        Self::from_trusted_checkpoint_with_consumer(
            checkpoint,
            network,
            chain_id,
            |_, verifier, _| verifier,
        )
    }

    /// Import an independently authenticated checkpoint and retain its exact verified tip.
    ///
    /// This performs the same complete import as [`Self::from_trusted_checkpoint`] and returns
    /// the tip capability produced by that verification. It authenticates historical execution;
    /// current authority, freshness and newly supplied witnesses require their own checks.
    /// The checkpoint must be selected independently of any responding peer's proof.
    ///
    /// # Errors
    /// Bounds, selected network/chain/genesis mismatch, inconsistent retained commitments or an
    /// invalid tip certificate. Canonical decode resource errors retain their original fields.
    pub fn from_trusted_checkpoint_with_tip(
        checkpoint: &SumeragiFinalityCheckpoint,
        network: &NetworkId,
        chain_id: &str,
    ) -> Result<(Self, VerifiedSumeragiBlock), super::FinalityReadError> {
        Self::from_trusted_checkpoint_with_consumer(
            checkpoint,
            network,
            chain_id,
            |_, verifier, tip| (verifier, tip),
        )
    }

    /// Authenticate an owned or borrowed selected checkpoint before consuming its exact tip.
    ///
    /// This independent entry uses the single canonical producer. The consumer runs once after
    /// the complete signed-genesis, retained-decision and native tip authentication succeeds;
    /// it receives the original source owner, resumed verifier and already authenticated tip.
    /// Discarding consumers can return a small owner without returning the full decoded graph.
    /// The original source borrow ends before an owned checkpoint is moved to the consumer.
    /// Historical authentication supplies neither current authority nor a fresh quorum.
    ///
    /// The checkpoint must be independently selected. A response-selected trust root is
    /// invalid. No consumer runs on refusal, and no checkpoint or verified graph is cloned
    /// to invoke it. An owned input is consumed on either success or refusal.
    ///
    /// # Errors
    /// Exactly the original import bounds, network/chain/genesis, retained commitment and
    /// certificate failures. Original canonical decode resource fields are retained.
    #[inline(never)]
    pub fn from_trusted_checkpoint_with_consumer<C, T>(
        checkpoint: C,
        network: &NetworkId,
        chain_id: &str,
        consume: impl FnOnce(C, Self, VerifiedSumeragiBlock) -> T,
    ) -> Result<T, super::FinalityReadError>
    where
        C: std::borrow::Borrow<SumeragiFinalityCheckpoint>,
    {
        Self::from_trusted_checkpoint_with_validation_consumer(
            checkpoint, network, chain_id, None, consume,
        )
    }

    /// Authenticate a selected checkpoint while borrowing exact pure epoch work from its owner.
    /// This is the single canonical producer behind independent and operation-scoped imports.
    /// The two-slot workspace carries no proof, certificate, source or authority verdict.
    /// Each entry independently ignores it under an active enclosing decoder owner, preserving
    /// the original scopes, physical decode charges and refusal ordering. Native genesis and
    /// the workspace borrow end before the consumer; an external workspace remains owned by
    /// the enclosing operation, while an independent import drops its local workspace here.
    ///
    /// # Errors
    /// Exactly the same signed source, bounds, network, retained decision, certificate and
    /// canonical resource failures as [`Self::from_trusted_checkpoint_with_consumer`].
    #[inline(never)]
    pub fn from_trusted_checkpoint_with_validation_consumer<C, T>(
        checkpoint: C,
        network: &NetworkId,
        chain_id: &str,
        shared_validation: Option<&mut EpochValidationScope>,
        consume: impl FnOnce(C, Self, VerifiedSumeragiBlock) -> T,
    ) -> Result<T, super::FinalityReadError>
    where
        C: std::borrow::Borrow<SumeragiFinalityCheckpoint>,
    {
        // No caller callback runs until native authentication is complete. Intrinsic decoder
        // scopes retain their original work; only an owner active at this entry disables reuse.
        let active_owner = norito::core::decode_limits_active();
        let mut local_validation =
            (!active_owner && shared_validation.is_none()).then(EpochValidationScope::new);
        let mut validation = if active_owner {
            None
        } else {
            shared_validation.or(local_validation.as_mut())
        };
        let selected = checkpoint.borrow();
        selected.validate_bounds_with_validation(validation.as_deref_mut())?;
        need(
            selected.network_id == *network && selected.chain_id == chain_id,
            "checkpoint differs from independently selected network or chain",
        )?;
        let genesis = norito::core::with_decode_limits_scope(
            norito::canonical_decode_limits(selected.genesis_wire.len()),
            || decode_framed_signed_block(&selected.genesis_wire),
        )
        .map_err(|error| match error.kind() {
            norito::core::DecodeAttemptErrorKind::Allocator
            | norito::core::DecodeAttemptErrorKind::EnclosingLimit => {
                super::FinalityReadError::DecodeResource(error)
            }
            norito::core::DecodeAttemptErrorKind::Invalid => {
                super::FinalityReadError::Invalid(malformed(error))
            }
        })?;
        need(
            genesis.header().is_genesis()
                && genesis.hash().as_ref() == network.as_bytes()
                && genesis
                    .canonical_resultless_proposal()
                    .map_err(malformed)?
                    .encode_wire()
                    .map_err(malformed)?
                    == selected.genesis_wire,
            "checkpoint genesis differs from selected network or canonical root",
        )?;
        let mut verifier = Self::new_with_validation(
            &genesis,
            chain_id,
            selected.genesis_committee.clone(),
            validation.as_deref(),
        )?;
        verifier.decisions = selected
            .decisions
            .iter()
            .map(|decision| (decision.height, decision.decision()))
            .collect();
        for decision in selected
            .decisions
            .iter()
            .filter(|decision| decision.height <= 2)
        {
            need(
                decision.committee_digest == verifier.genesis_committee_digest,
                "checkpoint initial committee differs from genesis selection",
            )?;
            if decision.height == 1 {
                need(
                    decision.block_hash == genesis.hash()
                        && decision.core_hash == *genesis.hash().as_ref()
                        && decision.schedule.current == verifier.genesis_epoch,
                    "checkpoint genesis commitment differs from selected signed root",
                )?;
            }
        }
        // Retain the capability produced by this complete single-witness verification.
        let tip = verifier.verify_retained_decision_with_validation(&selected.tip, validation)?;
        drop(genesis);
        // End borrowed access before the consumer. Independent imports also release their
        // bounded pure workspace here; a borrowed workspace remains with its operation owner.
        drop(local_validation);
        Ok(consume(checkpoint, verifier, tip))
    }
}

#[cfg(all(test, feature = "transparent_api"))]
mod epoch_validation_tests;
#[cfg(all(test, feature = "transparent_api"))]
mod producer_validation_tests;
#[cfg(all(test, feature = "transparent_api"))]
mod tests;
