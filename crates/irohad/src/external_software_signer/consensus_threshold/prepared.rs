//! Append-only supervisor credentials for a frozen target committee.

use super::*;
use iroha_data_model::nexus::ValidatorCommitteeTransitionV1;
use iroha_model_base::peer::PeerId;

/// Complete restart credential retaining incumbent custody alongside one pending target share.
///
/// This value exposes no debug or clone implementation. Its secret frame is zeroized on drop;
/// persist it only through the existing owner-only supervisor credential publication corridor.
pub struct RuntimePreparedGlobalBeaconCredentialV1 {
    /// Strictly advanced public provider revision for this complete inventory.
    pub revision: u64,
    /// Public inventory digest to install with the matching provider revision.
    pub policy_digest: [u8; 32],
    /// Canonical secret credential containing every retained share and the exact pending share.
    pub credential: SecretConsensusThresholdCredentialV1,
}

/// Build a restart credential by appending one exact prepared target share.
///
/// The caller obtains `transition` from authenticated finalized preparation state. This function
/// checks its complete structural bindings, exact DKG attempt and authority generation,
/// and actual private share, preserves every existing session byte-for-byte semantically,
/// and never selects an active session. Consensus separately
/// authenticates preparation and activation; possession of this credential authorizes neither.
/// A newly joining node supplies no retained credential. Existing nodes must supply their current
/// complete frame and exact public provider binding. Failed appends leave that borrowed frame
/// untouched. Repeated or conflicting session insertion is rejected, never an implicit replacement.
///
/// # Errors
/// Rejects malformed or terminal attempts, wrong target seats/transcripts, stale provider revisions,
/// invalid prior credentials, duplicate sessions, invalid private shares or inventory overflow.
pub fn prepare_global_beacon_transition_credential_v1(
    retained: Option<(&[u8], &IrohaRuntimeProviderBindingV1)>,
    handle: &str,
    revision: u64,
    transition: &ValidatorCommitteeTransitionV1,
    local_validator: &PeerId,
    pending: &RuntimeGlobalBeaconShareProvisioningV1,
    budget: &AllocationBudget,
) -> Result<RuntimePreparedGlobalBeaconCredentialV1, RuntimeConsensusThresholdSignerCredentialErrorV1>
{
    use RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected;
    let retained = retained
        .map(|(bytes, configured)| {
            if configured.handle() != handle
                || configured.revision().is_none_or(|old| revision <= old)
            {
                return Err(Rejected);
            }
            decode_global_beacon_credential_shares_v1(
                bytes,
                &transition.preparation.network_id,
                configured,
                budget,
            )
            .map(|shares| (shares, configured))
        })
        .transpose()?;
    prepare_global_beacon_transition_from_retained_v1(
        retained
            .as_ref()
            .map(|(shares, binding)| (shares.as_slice(), *binding)),
        handle,
        revision,
        transition,
        local_validator,
        pending,
        budget,
    )
}

/// Shared append path retaining the caller's already admitted current inventory.
pub(super) fn prepare_global_beacon_transition_from_retained_v1(
    retained: Option<(
        &[RuntimeGlobalBeaconShareProvisioningV1],
        &IrohaRuntimeProviderBindingV1,
    )>,
    handle: &str,
    revision: u64,
    transition: &ValidatorCommitteeTransitionV1,
    local_validator: &PeerId,
    pending: &RuntimeGlobalBeaconShareProvisioningV1,
    budget: &AllocationBudget,
) -> Result<RuntimePreparedGlobalBeaconCredentialV1, RuntimeConsensusThresholdSignerCredentialErrorV1>
{
    use RuntimeConsensusThresholdSignerCredentialErrorV1::Rejected;

    if !pending.belongs_to(budget)
        || retained
            .as_ref()
            .is_some_and(|(entries, _)| entries.iter().any(|entry| !entry.belongs_to(budget)))
    {
        return Err(RuntimeConsensusThresholdSignerCredentialErrorV1::Session(
            GlobalThresholdBeaconSessionError::ForeignReservation,
        ));
    }
    transition.validate().map_err(|_| Rejected)?;
    if transition.outcome.is_some() {
        return Err(Rejected);
    }
    let credentials = transition.credentials.as_ref().ok_or(Rejected)?;
    let network_id = transition.preparation.network_id;
    let index = transition
        .preparation
        .committee
        .iter()
        .position(|seat| &seat.validator == local_validator)
        .and_then(|index| u16::try_from(index).ok())
        .and_then(|index| index.checked_add(1))
        .ok_or(Rejected)?;
    let peers = || {
        transition
            .preparation
            .committee
            .iter()
            .map(|seat| &seat.validator)
    };
    let pending_session = pending.public_session();
    let dkg_session = &pending_session.adaptive_dkg.session;
    let preparation_cutoff = transition
        .preparation
        .first_height
        .checked_sub(1)
        .ok_or(Rejected)?;
    if pending.signer_index() != index
        || pending_session.network_id != network_id
        || pending_session.session_id != credentials.beacon.session_id
        || pending_session.transcript_hash != credentials.beacon.transcript_hash
        || dkg_session.attempt_id
            != transition
                .preparation
                .transition_id()
                .map_err(|_| Rejected)?
        || dkg_session.authority_generation != transition.preparation.authority_generation
        || dkg_session.start_height <= transition.preparation.selection_height
        || pending_session.adaptive_dkg.finalized_at_height >= preparation_cutoff
        || pending_session.roster_hash
            != iroha_core::beacon::global_threshold_beacon_roster_hash_iter_v1(peers())
        || usize::from(pending_session.committee_size) != transition.preparation.committee.len()
    {
        return Err(Rejected);
    }
    if let Some((retained, configured)) = &retained {
        if configured.handle() != handle || configured.revision().is_none_or(|old| revision <= old)
        {
            return Err(Rejected);
        }
        // The caller admitted this complete inventory once; canonical encoding borrows
        // these exact sealed owners alongside the same-pool pending session.
        if retained
            .iter()
            .any(|entry| entry.public_session().session_id == pending_session.session_id)
        {
            return Err(Rejected);
        }
    }
    let inventory = || {
        retained
            .iter()
            .flat_map(|(shares, _)| shares.iter())
            .chain(std::iter::once(pending))
    };
    let policy_digest = global_beacon_partial_signer_inventory_digest_v1(network_id, inventory())?;
    let mut prepared = PreparedGlobalBeaconCredentialV1::new(
        network_id,
        handle,
        revision,
        policy_digest,
        inventory().map(|share| (share.authenticated_session(), share.signer_index())),
        budget,
    )?;
    encode_global_beacon_partial_signer_credential_v1(
        &mut prepared,
        inventory().map(RuntimeGlobalBeaconShareProvisioningV1::credential_source),
    )?;
    let credential = prepared.into_credential().map_err(|(_, error)| error)?;
    Ok(RuntimePreparedGlobalBeaconCredentialV1 {
        revision,
        policy_digest,
        credential,
    })
}
