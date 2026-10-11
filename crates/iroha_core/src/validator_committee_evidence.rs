//! Offline verification of incumbent-authorized pending committee custody.
//!
//! The configured chain and signed-genesis network are supplied independently. A lifecycle certificate authorizes the exact
//! transcript but does not prove transaction inclusion or activate its target committee.

use crate::state::StateView;
use crate::sumeragi::{
    certified_chain::{CertifiedBlock, CertifiedChain},
    native_journal::{NativeJournalError, with_verified_native_journal},
};
use crate::{
    beacon::{
        FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconSessionError,
        RetainedFinalizedGlobalThresholdBeaconSessionV1, ValidatedGlobalThresholdBeaconSessionV1,
    },
    state::{
        World, validator_committee::verify_progress, verify_threshold_key_lifecycle_certificate_v1,
    },
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::sumeragi::epoch::{
    BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorGenerationV1,
};
use iroha_data_model::{
    NetworkId,
    isi::consensus_keys::{ThresholdKeyLifecycleActionV1, ThresholdKeyLifecycleCertificateV1},
    nexus::{
        ValidatorCommitteePreparationV1, ValidatorCommitteeStatusV1, ValidatorCommitteeTransitionV1,
    },
    sumeragi::finality::{NativeFinalityJournal, NativeFinalityLimits},
};
use iroha_model_base::chain::ChainId;
use norito::{NoritoDeserialize, NoritoSerialize};

/// Join an observed transition to the exact independently certified native selecting boundary.
///
/// Both blocks must come from the same independently authenticated chain reader. This verifies
/// the immutable selection binding; it grants no execution, custody or activation authority.
///
/// # Errors
/// Rejects a changed network, target, height, predecessor, frozen preparation or preparing epoch.
pub fn validate_validator_committee_selection_binding_v1(
    selection: &ValidatorCommitteeTransitionV1,
    selecting: &CertifiedBlock,
    latest: &CertifiedBlock,
    target_epoch: u64,
) -> Result<(), String> {
    selection.validate()?;
    let preparation = &selection.preparation;
    if preparation.target_epoch != target_epoch
        || preparation.network_id != latest.commitment().schedule.current.network_id
        || selecting.commitment().schedule.current.network_id != preparation.network_id
        || selecting.height() != preparation.selection_height
        || selecting.height() > latest.height()
        || selecting.block().header().prev_block_hash() != Some(preparation.selection_anchor)
    {
        return Err("committee selection native finality binding differs".into());
    }
    let boundary = selecting
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or("selecting native result lacks the frozen committee boundary")?;
    if boundary.preparation.as_ref() != Some(preparation)
        || boundary.selection_anchor != preparation.selection_anchor
    {
        return Err("committee preparation differs from selecting native result".into());
    }
    preparation.validate_against_preparing_authorization(&boundary.next.authorization)
}

/// Maximum encoded public evidence size, independent of caller transport limits.
pub const COMMITTEE_PROVISIONING_EVIDENCE_MAX_BYTES_V1: usize = 64 * 1024 * 1024;
/// Maximum contiguous finality artifacts admitted in one offline operation.
pub const COMMITTEE_PROVISIONING_FINALITY_MAX_COUNT_V1: usize = 65_536;

/// Finalized selection proof used before any target DKG transcript exists.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::validator_committee_evidence::ValidatorCommitteeSelectionEvidenceV1"
)]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeSelectionEvidenceV1 {
    /// Selection observation whose immutable preparation must match finality.
    pub status: ValidatorCommitteeStatusV1,
    /// Contiguous canonical finality from independently pinned signed genesis.
    pub finality_journal: NativeFinalityJournal,
}

/// Authority to run the exact selected DKG, without credential or activation authority.
pub struct VerifiedValidatorCommitteeSelectionV1 {
    preparation: ValidatorCommitteePreparationV1,
    incumbent_authority: ValidatorGenerationV1,
    incumbent_beacon: InstalledBeaconEpochBindingV1,
    observed_height: u64,
}
impl VerifiedValidatorCommitteeSelectionV1 {
    /// Immutable target, generation and DKG session binding certified at selection.
    pub fn preparation(&self) -> &ValidatorCommitteePreparationV1 {
        &self.preparation
    }
    /// Current validator generation whose exact quorum owns the preparation epoch.
    pub fn incumbent_authority(&self) -> &ValidatorGenerationV1 {
        &self.incumbent_authority
    }
    /// Current installed beacon session, never replaced by this selection proof.
    pub fn incumbent_beacon(&self) -> InstalledBeaconEpochBindingV1 {
        self.incumbent_beacon
    }
    /// Latest authenticated height before the preparation cutoff.
    pub fn observed_height(&self) -> u64 {
        self.observed_height
    }
}

/// Verify a frozen E+2 roster from independently anchored finality during E+1.
///
/// The result only authorizes private DKG preparation for the immutable target.
/// It neither authenticates unfinalized progress fields nor installs credentials.
///
/// # Errors
/// Rejects foreign networks or attempts, non-contiguous finality, changed
/// election inputs, invalid committee BLS possession, and expired preparation.
pub fn verify_validator_committee_selection_evidence_v1(
    evidence: &ValidatorCommitteeSelectionEvidenceV1,
    chain_id: &ChainId,
    network: NetworkId,
    target_epoch: u64,
    transition_id: [u8; 32],
    limits: NativeFinalityLimits,
    budget: &AllocationBudget,
) -> Result<VerifiedValidatorCommitteeSelectionV1, NativeJournalError> {
    check_evidence_size(evidence, limits)?;
    with_verified_native_journal(
        (&evidence.finality_journal).into(),
        chain_id,
        &network,
        limits,
        budget,
        |reader| {
            verify_selection_observation(
                &evidence.status,
                &evidence.finality_journal,
                reader,
                network,
                target_epoch,
                transition_id,
            )
        },
    )
}

fn check_evidence_size<T: norito::core::SerializePayload>(
    evidence: &T,
    limits: NativeFinalityLimits,
) -> Result<(), String> {
    limits.validate()?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes = norito::core::encoded_payload_len(evidence).map_err(|error| error.to_string())?;
    if bytes > limits.journal_bytes || bytes > COMMITTEE_PROVISIONING_EVIDENCE_MAX_BYTES_V1 {
        return Err("committee evidence exceeds its configured aggregate bound".into());
    }
    Ok(())
}

fn verify_selection_observation(
    status: &ValidatorCommitteeStatusV1,
    journal: &NativeFinalityJournal,
    reader: &CertifiedChain<'_, StateView<'_>>,
    network: NetworkId,
    target_epoch: u64,
    transition_id: [u8; 32],
) -> Result<VerifiedValidatorCommitteeSelectionV1, NativeJournalError> {
    let selected = status
        .selected
        .as_ref()
        .ok_or("selection evidence lacks a frozen committee")?;
    let preparation = &selected.transition.preparation;
    preparation.validate()?;
    if transition_id == [0; 32]
        || status.network_id != network
        || preparation.network_id != network
        || status.target_epoch != target_epoch
        || preparation.target_epoch != target_epoch
        || preparation.transition_id()? != transition_id
        || journal.blocks.len() > COMMITTEE_PROVISIONING_FINALITY_MAX_COUNT_V1
    {
        return Err("selection evidence differs from its exact network, attempt or bounds".into());
    }
    let selecting_index = usize::try_from(preparation.selection_height)
        .ok()
        .and_then(|height| height.checked_sub(1))
        .ok_or("invalid selection height")?;
    if journal.blocks.last() != Some(&status.latest_finality)
        || journal.blocks.get(selecting_index) != Some(&selected.selecting_finality)
    {
        return Err("committee status attachments differ from the exact native journal".into());
    }
    let latest_height =
        u64::try_from(journal.blocks.len()).map_err(|_| "journal height overflow")?;
    let latest = reader
        .certified(latest_height)
        .map_err(NativeJournalError::History)?;
    let selecting = reader
        .certified(preparation.selection_height)
        .map_err(NativeJournalError::History)?;
    validate_validator_committee_selection_binding_v1(
        &selected.transition,
        &selecting,
        &latest,
        target_epoch,
    )?;
    let current = &latest.commitment().schedule.current;
    let boundary = selecting
        .commitment()
        .schedule
        .boundary
        .as_ref()
        .ok_or("selecting native result lacks its certified boundary")?;
    if latest_height <= preparation.selection_height
        || latest_height >= preparation.first_height.saturating_sub(1)
        || current.authorization.epoch
            != preparation
                .selection_epoch
                .checked_add(1)
                .ok_or("epoch overflow")?
        || selecting.commitment().schedule.current.authorization.epoch
            != preparation.selection_epoch
        || selecting.block().header().prev_block_hash() != Some(preparation.selection_anchor)
        || boundary.selection_anchor != preparation.selection_anchor
        || boundary.preparation.as_ref() != Some(preparation)
        || boundary.next != *current
    {
        return Err(
            "selection observations differ from incumbent-certified native E+1 finality".into(),
        );
    }
    preparation.validate_against_preparing_authorization(&current.authorization)?;
    let BeaconEpochBindingV1::Installed(incumbent_beacon) = current.authorization.beacon else {
        return Err("selection DKG requires an installed incumbent beacon".into());
    };
    Ok(VerifiedValidatorCommitteeSelectionV1 {
        preparation: preparation.clone(),
        incumbent_authority: current.generation(),
        incumbent_beacon,
        observed_height: latest_height,
    })
}

/// Public custody evidence; its claimed context never supplies the verifier's trust root.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    NoritoSerialize,
    NoritoDeserialize,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_core::validator_committee_evidence::ValidatorCommitteeProvisioningEvidenceV1"
)]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeProvisioningEvidenceV1 {
    /// Exact selected committee and cryptographically checkable progress observations.
    pub status: ValidatorCommitteeStatusV1,
    /// Contiguous canonical finality from signed genesis through the observed tip.
    pub finality_journal: NativeFinalityJournal,
    /// Exact incumbent quorum authorization for the pending public beacon transcript.
    pub beacon_finalization: ThresholdKeyLifecycleCertificateV1,
}

/// Verified authorization to prepare custody, with no committee activation authority.
pub struct VerifiedValidatorCommitteeProvisioningV1 {
    transition: ValidatorCommitteeTransitionV1,
    session: ValidatedGlobalThresholdBeaconSessionV1,
    incumbent_authority: ValidatorGenerationV1,
    incumbent_beacon: InstalledBeaconEpochBindingV1,
    observed_height: u64,
}
impl VerifiedValidatorCommitteeProvisioningV1 {
    /// Exact immutable attempt whose pending secrets may be provisioned.
    pub fn transition(&self) -> &ValidatorCommitteeTransitionV1 {
        &self.transition
    }
    /// Complete authorized target transcript for importing the private share.
    pub fn session(&self) -> &ValidatedGlobalThresholdBeaconSessionV1 {
        &self.session
    }
    /// Current authenticated generation; incumbent members must retain their current share.
    pub fn incumbent_authority(&self) -> &ValidatorGenerationV1 {
        &self.incumbent_authority
    }
    /// Exact active session which pending provisioning may never replace.
    pub fn incumbent_beacon(&self) -> InstalledBeaconEpochBindingV1 {
        self.incumbent_beacon
    }
    /// Latest height in the independently authenticated supplied chain.
    pub fn observed_height(&self) -> u64 {
        self.observed_height
    }
}

/// Public proof rejection is distinct from refusal by the caller's original session resources.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorCommitteeProvisioningEvidenceError {
    /// A public evidence, finality or authorization check failed.
    #[error("{0}")]
    Invalid(String),
    /// Complete session authentication or original-pool admission failed.
    #[error(transparent)]
    Session(#[from] GlobalThresholdBeaconSessionError),
    /// Original authenticated journal decoder, history or block-control failure.
    #[error(transparent)]
    Journal(#[from] NativeJournalError),
}
impl From<String> for ValidatorCommitteeProvisioningEvidenceError {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}
impl From<&str> for ValidatorCommitteeProvisioningEvidenceError {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.to_owned())
    }
}

/// Verify a bounded public custody envelope from independently configured chain and signed-genesis network.
///
/// # Errors
/// Rejects changed network/attempt/chain, expired preparation, substituted transcript,
/// invalid actual-possession proofs, or missing exact incumbent quorum authorization.
/// Session admission retains the original caller resource refusal; success retains that pool.
pub fn verify_validator_committee_provisioning_evidence_v1(
    evidence: &ValidatorCommitteeProvisioningEvidenceV1,
    chain_id: &ChainId,
    network: NetworkId,
    target_epoch: u64,
    transition_id: [u8; 32],
    limits: NativeFinalityLimits,
    session_budget: &AllocationBudget,
) -> Result<VerifiedValidatorCommitteeProvisioningV1, ValidatorCommitteeProvisioningEvidenceError> {
    check_evidence_size(evidence, limits)?;
    // TODO: the journal source and nested decoded public graphs still need retained pool
    // ledgers. Typed errors and admitted block/session controls do not fund those graphs.
    with_verified_native_journal(
        (&evidence.finality_journal).into(),
        chain_id,
        &network,
        limits,
        session_budget,
        |reader| {
            Ok(
                (|| -> Result<_, ValidatorCommitteeProvisioningEvidenceError> {
                    let selected = verify_selection_observation(
                        &evidence.status,
                        &evidence.finality_journal,
                        reader,
                        network,
                        target_epoch,
                        transition_id,
                    )?;
                    let status = &evidence.status;
                    let transition = &status
                        .selected
                        .as_ref()
                        .ok_or("missing selected attempt")?
                        .transition;
                    transition.validate()?;
                    let preparation = &transition.preparation;
                    if transition.outcome.is_some() || transition.credentials.is_none() {
                        return Err("custody evidence is not a complete pending attempt".into());
                    }
                    let certificate = &evidence.beacon_finalization;
                    let incumbent_beacon = selected.incumbent_beacon;
                    if certificate.action != ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey
                        || certificate.expected_active_session_id
                            != Some(incumbent_beacon.session_id)
                        || certificate.effective_height <= preparation.selection_height
                        || certificate.effective_height >= preparation.first_height - 1
                        || certificate.effective_height > selected.observed_height
                    {
                        return Err(
                            "pending beacon certificate differs from its preparing authority"
                                .into(),
                        );
                    }
                    let finalizing = reader
                        .certified(certificate.effective_height)
                        .map_err(NativeJournalError::History)?;
                    let latest = reader
                        .certified(selected.observed_height)
                        .map_err(NativeJournalError::History)?;
                    let current = &latest.commitment().schedule.current;
                    if finalizing.commitment().schedule.current != *current {
                        return Err(
                            "pending beacon certificate names a different native epoch".into()
                        );
                    }
                    let peers = current
                        .committee
                        .iter()
                        .map(|seat| seat.validator.clone())
                        .collect::<Vec<_>>();
                    verify_threshold_key_lifecycle_certificate_v1(
                        certificate,
                        &network,
                        certificate.effective_height,
                        &peers,
                    )
                    .map_err(|error| error.to_string())?;
                    let record: FinalizedGlobalThresholdBeaconKeySessionRecordV1 =
                        norito::decode_canonical_for_admission(
                            &certificate.public_state,
                            norito::canonical_decode_limits(certificate.public_state.len()),
                        )
                        .map_err(
                            iroha_data_model::sumeragi::finality::NativeFinalityDecodeError::from,
                        )
                        .map_err(NativeJournalError::Decode)?;
                    let retained = RetainedFinalizedGlobalThresholdBeaconSessionV1::admit(
                        &record,
                        session_budget,
                    )?;
                    if record.activated_at_height.is_some()
                        || record.retired_at_height.is_some()
                        || record.session.network_id != network
                        || record.session.session_id != certificate.session_id
                        || record.session.transcript_hash != certificate.transcript_hash
                        || status.pending_beacon_session.as_ref() != Some(&record.session)
                        || record.session.adaptive_dkg.finalized_at_height
                            > certificate.effective_height
                    {
                        return Err(
                            "pending beacon transcript differs from its exact certificate".into(),
                        );
                    }
                    let mut world = World::new();
                    let session = retained.session.clone();
                    world
                        .global_beacon_key_sessions
                        .insert(session.session_id, retained);
                    verify_progress(&world.view(), transition)?;
                    Ok(VerifiedValidatorCommitteeProvisioningV1 {
                        transition: transition.clone(),
                        session,
                        incumbent_authority: selected.incumbent_authority,
                        incumbent_beacon,
                        observed_height: selected.observed_height,
                    })
                })(),
            )
        },
    )
    .map_err(ValidatorCommitteeProvisioningEvidenceError::Journal)?
}

#[cfg(test)]
#[path = "validator_committee_evidence/tests.rs"]
mod tests;
