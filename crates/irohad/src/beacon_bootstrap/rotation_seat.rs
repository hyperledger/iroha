//! One-shot, proof-clocked rotation DKG custody for one exact target seat.

use super::*;
fn exact_rotation_seat_session(
    proof: &RotationProofArgs,
    selected: &VerifiedValidatorCommitteeSelectionV1,
) -> Result<(GlobalThresholdBeaconDkgSessionV1, Vec<PeerId>, u64)> {
    let preparation = selected.preparation();
    let roster = preparation
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    let observed_height = selected.observed_height();
    let commitments_end_height = observed_height.checked_add(1).ok_or(Error::Height)?;
    let deliveries_end_height = observed_height.checked_add(2).ok_or(Error::Height)?;
    let acceptances_end_height = observed_height.checked_add(3).ok_or(Error::Height)?;
    let cutoff = preparation
        .first_height
        .checked_sub(1)
        .ok_or(Error::Height)?;
    if acceptances_end_height >= cutoff {
        return Err(Error::Height);
    }
    Ok((
        GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: proof.network_id,
            session_id: preparation
                .beacon_session_id()
                .map_err(|_| Error::InvalidInput)?,
            attempt_id: preparation
                .transition_id()
                .map_err(|_| Error::InvalidInput)?,
            authority_generation: preparation.authority_generation,
            roster_hash: global_threshold_beacon_roster_hash_v1(&roster),
            committee_size: u16::try_from(roster.len()).map_err(|_| Error::InvalidInput)?,
            threshold: u16::try_from((roster.len() - 1) / 3 + 1)
                .map_err(|_| Error::InvalidInput)?,
            start_height: observed_height,
            commitments_end_height,
            deliveries_end_height,
            acceptances_end_height,
        },
        roster,
        cutoff,
    ))
}

/// Fixture entry into the canonical prepared producer, with an explicit original pool.
#[cfg(test)]
pub(super) fn encode_local_seat_credential(
    public: &ValidatedGlobalThresholdBeaconSessionV1,
    signer_index: u16,
    components: Zeroizing<[[u8; 32]; 3]>,
    handle: &str,
    revision: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<(
    [u8; 32],
    iroha_core::beacon::credential::SecretConsensusThresholdCredentialV1,
)> {
    use iroha_core::beacon::credential::{
        GlobalBeaconCredentialEncodeErrorV1, PreparedGlobalBeaconCredentialV1,
        RuntimeGlobalBeaconShareProvisioningV1,
    };
    let digest = global_beacon_partial_signer_public_inventory_digest_v1(
        public.network_id,
        &[(public.record(), signer_index)],
    )
    .map_err(|error| Error::Export(seat_export::ExportError::Credential(error.into())))?;
    let mut prepared = PreparedGlobalBeaconCredentialV1::new(
        public.network_id,
        handle,
        revision,
        digest,
        [(public, signer_index)],
        budget,
    )
    .map_err(|error| Error::Export(seat_export::ExportError::Credential(error)))?;
    let inventory = [RuntimeGlobalBeaconShareProvisioningV1::new(
        public.clone(),
        signer_index,
        components,
    )];
    encode_global_beacon_partial_signer_credential_v1(
        &mut prepared,
        inventory
            .iter()
            .map(RuntimeGlobalBeaconShareProvisioningV1::credential_source),
    )
    .map_err(|error| Error::Export(seat_export::ExportError::Credential(error)))?;
    let credential = prepared.into_credential().map_err(
        |(_, error): (_, GlobalBeaconCredentialEncodeErrorV1)| {
            Error::Export(seat_export::ExportError::Credential(error))
        },
    )?;
    Ok((digest, credential))
}

/// Run a local dealer/recipient without ever constructing another seat's secret.
///
/// A supervisor must pin `attempt_root` to its durable private root. The
/// daemon derives the child name from the exact attempt and seat. Creating
/// that child before key generation is exclusive; a crash leaves it present
/// and this attempt must be cancelled by current-quorum retention, never rerolled.
#[allow(
    unsafe_code,
    reason = "the supervisor passes separate inherited public finality and signed-DKG frame FIFOs"
)]
pub(super) fn provision_rotation_seat_command(
    proof: &RotationProofArgs,
    signer_index: u16,
    key_fd: Option<i32>,
    config_fd: Option<i32>,
    public_fd: i32,
    finality_fd: i32,
    provider_handle: &str,
    provider_revision: u64,
    attempt_root: &Path,
    timeout_ms: u64,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let (key_descriptor, from_config) = match (key_fd, config_fd) {
        (Some(198), None) => (198, false),
        (None, Some(198)) => (198, true),
        _ => return Err(Error::InvalidInput),
    };
    if public_fd < 3
        || finality_fd < 3
        || public_fd == finality_fd
        || matches!(public_fd, 198 | 199 | 200)
        || matches!(finality_fd, 198 | 199 | 200)
        || provider_revision == 0
        || iroha_config::parameters::validate_production_runtime_handle(provider_handle).is_err()
        || timeout_ms == 0
        || timeout_ms > MAX_TIMEOUT_MS
    {
        return Err(Error::InvalidInput);
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or(Error::Deadline)?;
    let public_input = unsafe { BorrowedFd::borrow_raw(public_fd) };
    let finality_input = unsafe { BorrowedFd::borrow_raw(finality_fd) };
    for fd in [public_input, finality_input] {
        let metadata = rustix::fs::fstat(fd).map_err(|_| Error::InvalidInput)?;
        if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Fifo {
            return Err(Error::InvalidInput);
        }
    }
    let (evidence, selected) = read_verified_rotation_selection(proof, budget)?;
    let transition = &evidence
        .status
        .selected
        .as_ref()
        .ok_or(Error::InvalidInput)?
        .transition;
    if transition.credentials.is_some()
        || !transition.readiness.is_empty()
        || transition.outcome.is_some()
        || evidence.status.pending_beacon_session.is_some()
    {
        return Err(Error::InvalidInput);
    }
    let (session, roster, cutoff) = exact_rotation_seat_session(proof, &selected)?;
    if signer_index == 0 || usize::from(signer_index) > roster.len() {
        return Err(Error::InvalidInput);
    }
    let file = crate::taira_runtime_signer::take_inherited_private_file(key_descriptor)
        .map_err(|_| Error::InvalidCustody)?;
    let signer = if from_config {
        load_lifecycle_config(file, &session.network_id)?
    } else {
        load_lifecycle_key(file)?
    };
    if signer.public_key() != roster[usize::from(signer_index - 1)].public_key() {
        return Err(Error::InvalidCustody);
    }
    let verifier = rotation_phase_verifier(proof, &evidence, budget)?;
    let authority =
        iroha_core::beacon::AuthenticatedGlobalBeaconDkgAttemptV1::rotation(&selected, &verifier)?;
    if authority.session() != session || authority.cutoff() != cutoff {
        return Err(Error::InvalidInput);
    }
    // SAFETY: fd numbers are distinct, inherited FIFO identities were checked
    // above, and this command transfers each source once into the retained owner.
    use std::os::fd::FromRawFd as _;
    let attempt = seat_attempt::SeatDkgAttempt::new(
        authority,
        &roster,
        signer_index,
        signer,
        unsafe { File::from_raw_fd(public_fd) },
        unsafe { File::from_raw_fd(finality_fd) },
        verifier,
        provider_handle,
        provider_revision,
        attempt_root,
        deadline,
        budget,
    )?;
    attempt.resume().map_err(Error::PendingAttempt)
}

/// Assemble the all-seat public result without collecting any private shares.
pub(super) fn assemble_rotation_dkg_command(
    proof: &RotationProofArgs,
    public_session_path: &Path,
    phase_proof_paths: &[PathBuf],
    provider_paths: &[PathBuf],
    certificate_height: u64,
    output: &Path,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<()> {
    let (evidence, selected) = read_verified_rotation_selection(proof, budget)?;
    let preparation = selected.preparation();
    let (expected_session, _, cutoff) = exact_rotation_seat_session(proof, &selected)?;
    let bytes = read_public_bytes_bounded(public_session_path, MAX_PUBLIC_BYTES)?;
    let public: GlobalThresholdBeaconKeySessionV1 =
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .map_err(|_| Error::Crypto)?;
    let finalized_height = public.adaptive_dkg.finalized_at_height;
    if public.adaptive_dkg.session != expected_session
        || finalized_height != expected_session.acceptances_end_height
        || provider_paths.len() != preparation.committee.len()
        || certificate_height <= finalized_height
        || certificate_height >= cutoff
    {
        return Err(Error::InvalidInput);
    }
    let limits = proof.finality_limits.checked()?;
    let phase_proofs = phase_proof_paths
        .iter()
        .map(|path| {
            let bytes = read_public_bytes_bounded(path, limits.journal_bytes)?;
            NativeFinalityJournal::decode(&bytes, limits).map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_rotation_phase_chain(
        proof,
        &evidence,
        selected.observed_height(),
        finalized_height,
        cutoff,
        &phase_proofs,
        budget,
    )?;
    let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(public, budget)
        .map_err(Error::from)?;
    let mut providers = provider_paths
        .iter()
        .map(|path| read_json::<Provider>(path))
        .collect::<Result<Vec<_>>>()?;
    providers.sort_by_key(|provider| provider.signer_index);
    let authorization_roster = selected
        .incumbent_authority()
        .validators
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let certificate = draft_rotation_certificate(
        &authorization_roster,
        selected.incumbent_beacon().session_id,
        &record,
        finalized_height,
        certificate_height,
    )?;
    let bundle = RotationPublicBundle {
        schema: "iroha.validator-committee.rotation-dkg.v1".into(),
        preparation: preparation.clone(),
        dkg_session: record.session.adaptive_dkg.session,
        finalized_observed_height: finalized_height,
        phase_proofs,
        record,
        finalization_draft: certificate,
        providers,
    };
    validate_rotation_bundle(&bundle, proof, &evidence, &selected, budget)?;
    write_new(output, &json_bytes(&bundle)?, false)
}
