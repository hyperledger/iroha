//! Consensus operation handlers for authenticated broker dispatch.

use super::*;

pub(super) fn qualify_consensus_signer(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let slot = request.binding.slot;
    let global_beacon_partial_signer_slot =
        IrohaRuntimeProviderSlotV1::GlobalBeaconPartialSigner.wire_id();
    let qualification = if slot == global_beacon_partial_signer_slot {
        let signer = broker_backend!(state, global_beacon_partial_signer);
        let qualification = signer.qualification().map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::StaleOrRevoked,
        })?;
        if !consensus_signer_qualification_matches(&request.binding, signer.handle(), qualification)
        {
            return Err(BrokerError::StaleOrRevoked);
        }
        qualification
    } else {
        let signer = broker_backend!(state, parliament_tle_partial_release_signer);
        let qualification = signer.qualification().map_err(|error| match error {
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Unavailable => {
                BrokerError::Unavailable
            }
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected => {
                BrokerError::StaleOrRevoked
            }
        })?;
        if !consensus_signer_qualification_matches(&request.binding, signer.handle(), qualification)
        {
            return Err(BrokerError::StaleOrRevoked);
        }
        qualification
    };
    if qualification.test_marked
        || qualification.revision == 0
        || qualification.policy_digest == [0; 32]
    {
        return Err(BrokerError::StaleOrRevoked);
    }
    encode_canonical(
        &QualificationResultWireV1 {
            revision: qualification.revision,
            policy_digest: qualification.policy_digest,
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}

pub(super) fn global_beacon_partial_sign(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let requalify =
        || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);
    let (_, mut aggregator) =
        decode_global_beacon_partial_sign_request(&request.payload, &state.network_id)?;
    let backend = broker_backend!(state, global_beacon_partial_signer);
    let partial = backend
        .sign_partial(aggregator.session(), aggregator.payload())
        .map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::Rejected,
        })?;
    aggregator
        .accept_partial(partial)
        .map_err(|_| BrokerError::StaleOrRevoked)?;
    requalify()?;
    encode_canonical(
        &GlobalBeaconPartialSignResultWireV1 { partial },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}

pub(super) fn parliament_tle_partial_release_sign(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let requalify =
        || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);
    let (_, projection) =
        decode_parliament_tle_partial_release_sign_request(&request.payload, &state.network_id)?;
    let backend = broker_backend!(state, parliament_tle_partial_release_signer);
    let partial = backend
        .sign_projected_partial_release(&projection)
        .map_err(|error| match error {
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Unavailable => {
                BrokerError::Unavailable
            }
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected => {
                BrokerError::Rejected
            }
        })?;
    verify_parliament_tle_partial_release_result(&projection, &partial)
        .map_err(|_| BrokerError::StaleOrRevoked)?;
    requalify()?;
    encode_canonical(
        &ParliamentTlePartialReleaseSignResultWireV1 { partial },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}

pub(super) fn parliament_tle_capability_attest(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let requalify =
        || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);
    let (request, session) =
        decode_parliament_tle_capability_attest_request(&request.payload, &state.network_id)?;
    let backend = broker_backend!(state, parliament_tle_partial_release_signer);
    let attestation = backend
        .attest_partial_release_capability(&session, request.participant_index)
        .map_err(|error| match error {
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Unavailable => {
                BrokerError::Unavailable
            }
            ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Rejected => {
                BrokerError::Rejected
            }
        })?;
    if !attestation.matches(&session, request.participant_index) {
        return Err(BrokerError::StaleOrRevoked);
    }
    requalify()?;
    encode_canonical(
        &ParliamentTleCapabilityAttestResultWireV1 {
            key_session_id: attestation.key_session_id(),
            transcript_hash: attestation.transcript_hash(),
            participant_index: attestation.participant_index(),
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}

pub(super) fn global_beacon_capability_attest(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let requalify =
        || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);
    let (request, session) =
        decode_global_beacon_capability_attest_request(&request.payload, &state.network_id)?;
    let backend = broker_backend!(state, global_beacon_partial_signer);
    let attestation = backend
        .attest_partial_signing_capability(&session, request.signer_index)
        .map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::Rejected,
        })?;
    if !attestation.matches(&session, request.signer_index) {
        return Err(BrokerError::StaleOrRevoked);
    }
    requalify()?;
    encode_canonical(
        &GlobalBeaconCapabilityAttestResultWireV1 {
            session_id: attestation.session_id(),
            transcript_hash: attestation.transcript_hash(),
            signer_index: attestation.signer_index(),
        },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}

pub(super) fn global_beacon_seat_readiness(
    state: &BrokerServerStateV1,
    request: &OperationRequestV1,
) -> Result<Vec<u8>, BrokerError> {
    let (prepared, session) =
        decode_global_beacon_seat_readiness_request(&request.payload, &state.network_id)?;
    let (challenge, index) =
        iroha_core::beacon::seat_readiness::global_threshold_beacon_seat_readiness_challenge_v1(
            &session,
            &prepared.authority,
            &prepared.context,
        )
        .map_err(|_| BrokerError::Rejected)?;
    let backend = broker_backend!(state, global_beacon_partial_signer);
    let capability = backend
        .attest_partial_signing_capability(&session, index)
        .map_err(|error| match error {
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => BrokerError::Unavailable,
            GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::Rejected,
        })?;
    if !capability.matches(&session, index) {
        return Err(BrokerError::Rejected);
    }
    let partial =
        backend
            .sign_partial(&session, challenge.as_ref())
            .map_err(|error| match error {
                GlobalBeaconPartialSignerBrokerBackendErrorV1::Unavailable => {
                    BrokerError::Unavailable
                }
                GlobalBeaconPartialSignerBrokerBackendErrorV1::Rejected => BrokerError::Rejected,
            })?;
    iroha_core::beacon::seat_readiness::verify_global_threshold_beacon_seat_readiness_v1(
        &session,
        &prepared.authority,
        &prepared.context,
        &partial,
    )
    .map_err(|_| BrokerError::StaleOrRevoked)?;
    qualify_server_binding(state, &request.binding, request.provider_metadata_digest)?;
    encode_canonical(
        &GlobalBeaconPartialSignResultWireV1 { partial },
        MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,
    )
}
