//! Participant-certificate construction and validation for private settlement.
//!
//! The transparent Native AMX certificate path deliberately remains separate.
//! This module gives `AtomicPrivateSettlementV1` its own purpose-separated BLS
//! transcript and fixed four-validator, exact-three-signer quorum rules.

use iroha_crypto::{Algorithm, Hash, Signature};
use iroha_data_model::{
    consensus::ConsensusKeyRole,
    nexus::{
        AtomicPrivateSettlementV1, PRIVATE_SETTLEMENT_BLS_BYTES_V1,
        PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1, PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1,
        PrivateSettlementAuthorityCatalogV1, PrivateSettlementCommitteeAuthorityV1,
        PrivateSettlementDeltaV1, PrivateSettlementPhaseBodyV1,
        PrivateSettlementPhaseCertificateV1, PrivateSettlementPhaseV1,
        PrivateSettlementPhaseVoteV1, PrivateSettlementPrepareBarrierV1,
        PrivateSettlementReceiptV1, PrivateSettlementRouteV1,
    },
    sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneState},
};
use iroha_model_base::peer::PeerId;
#[cfg(test)]
use std::collections::BTreeMap;
use thiserror::Error;

use crate::state::{StateReadOnly, WorldReadOnly, peer_has_live_consensus_key_for_role};

/// Reserved digest carried by Prepare bodies before the all-leg barrier exists.
pub(crate) fn private_settlement_reserved_prepared_bundle_digest_v1() -> Hash {
    Hash::prehashed([0; Hash::LENGTH])
}

/// Commit to the complete all-Prepare barrier in canonical leg order.
///
/// This is deliberately a canonical digest primitive, not a second admission
/// path. Callers must validate each authority, delta, and Prepare certificate
/// before treating the returned digest as certified protocol evidence. The
/// data-model digest includes every signed Prepare body but normalizes away the
/// signer bitmap and aggregate signature, so quorum-equivalent exact 3-of-4
/// certificates cannot fork the bundle during crash recovery.
pub(crate) fn private_settlement_prepared_bundle_digest_v1(
    manifest: &AtomicPrivateSettlementV1,
    authority_catalog: &PrivateSettlementAuthorityCatalogV1,
    deltas: &[PrivateSettlementDeltaV1],
    prepare_certificates: &[PrivateSettlementPhaseCertificateV1],
) -> Result<Hash, PrivateSettlementProtocolErrorV1> {
    let leg_count = manifest.legs.len();
    if authority_catalog.validate_for_manifest(manifest).is_err()
        || deltas.len() != leg_count
        || prepare_certificates.len() != leg_count
    {
        return Err(PrivateSettlementProtocolErrorV1::Binding);
    }
    PrivateSettlementPrepareBarrierV1 {
        version: iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest: manifest.clone(),
        authority_catalog: authority_catalog.clone(),
        deltas: deltas.to_vec(),
        prepare_certificates: prepare_certificates.to_vec(),
        prepared_bundle_digest: private_settlement_reserved_prepared_bundle_digest_v1(),
    }
    .computed_prepared_bundle_digest()
    .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)
}

#[cfg(test)]
/// Construct the canonical, self-digesting complete all-Prepare barrier.
pub(crate) fn private_settlement_prepare_barrier_v1(
    manifest: AtomicPrivateSettlementV1,
    authority_catalog: Vec<PrivateSettlementCommitteeAuthorityV1>,
    deltas: Vec<PrivateSettlementDeltaV1>,
    prepare_certificates: Vec<PrivateSettlementPhaseCertificateV1>,
) -> Result<PrivateSettlementPrepareBarrierV1, PrivateSettlementProtocolErrorV1> {
    let authority_catalog =
        PrivateSettlementAuthorityCatalogV1::from_leg_authorities(&manifest, &authority_catalog)
            .map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
    let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
        &manifest,
        &authority_catalog,
        &deltas,
        &prepare_certificates,
    )?;
    let barrier = PrivateSettlementPrepareBarrierV1 {
        version: iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        manifest,
        authority_catalog,
        deltas,
        prepare_certificates,
        prepared_bundle_digest,
    };
    validate_private_settlement_prepare_barrier_v1(&barrier)?;
    Ok(barrier)
}

/// Verify every component and self-digest of an exact complete Prepare barrier.
pub(crate) fn validate_private_settlement_prepare_barrier_v1(
    barrier: &PrivateSettlementPrepareBarrierV1,
) -> Result<(), PrivateSettlementProtocolErrorV1> {
    barrier
        .validate_shape()
        .map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
    for (index, ((delta, certificate), manifest_leg)) in barrier
        .deltas
        .iter()
        .zip(&barrier.prepare_certificates)
        .zip(&barrier.manifest.legs)
        .enumerate()
    {
        let ordinal = u8::try_from(index).map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
        let authority = barrier
            .authority_catalog
            .authority_for_leg(&barrier.manifest, index)
            .map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
        validate_authority_cryptography_v1(&authority)?;
        let expected = private_settlement_phase_body_v1(
            &barrier.manifest,
            delta,
            &authority,
            PrivateSettlementPhaseV1::Prepare,
            private_settlement_reserved_prepared_bundle_digest_v1(),
        )?;
        if manifest_leg.ordinal != ordinal || certificate.body != expected {
            return Err(PrivateSettlementProtocolErrorV1::Binding);
        }
        verify_private_settlement_phase_certificate_v1(certificate, ordinal, &authority)?;
    }
    let recomputed = private_settlement_prepared_bundle_digest_v1(
        &barrier.manifest,
        &barrier.authority_catalog,
        &barrier.deltas,
        &barrier.prepare_certificates,
    )?;
    if barrier.prepared_bundle_digest != recomputed {
        return Err(PrivateSettlementProtocolErrorV1::Binding);
    }
    Ok(())
}

fn phase_signature_preimage_v1(
    body: &PrivateSettlementPhaseBodyV1,
) -> Result<Vec<u8>, PrivateSettlementProtocolErrorV1> {
    body.signature_preimage()
        .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)
}

pub(super) fn validate_authority_cryptography_v1(
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementProtocolErrorV1> {
    iroha_data_model::nexus::validate_private_settlement_authority_cryptography_v1(authority)
        .map_err(|_| PrivateSettlementProtocolErrorV1::Authority)
}

/// Uniform failure returned when a private-settlement roster is not the exact
/// state-anchored participant authority at its declared context height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("private-settlement committee authority is not authoritative")]
pub struct PrivateSettlementCommitteeAuthorityErrorV1;

/// Resolve the sole native incarnation authorized at the requested global anchor.
///
/// Physical lane catalogs describe deployment and never grant execution authority.
/// Pool mutation and participant certificates share this exact committed-record check.
pub(crate) fn native_private_settlement_route_v1(
    lanes: &SumeragiLaneState,
    route: PrivateSettlementRouteV1,
    authority_height: u64,
) -> Result<&SumeragiLaneRecord, PrivateSettlementCommitteeAuthorityErrorV1> {
    iroha_data_model::nexus::private_settlement_native_route_v1(lanes, route, authority_height)
        .map_err(|_| PrivateSettlementCommitteeAuthorityErrorV1)
}

/// Validate one private-settlement authority against the consensus state.
///
/// This is the authorization boundary behind restricted upload, Prepare, and
/// global receipt application. In addition to validating the supplied BLS
/// keys and proofs of possession, it requires the exact canonical ordered
/// validator roster and PoPs pinned by the native committed lane record at
/// `authority_context_height`, the exact active lane incarnation, and the V1
/// four-validator/`f = 1` geometry. Every member must also hold a live
/// purpose-specific [`ConsensusKeyRole::Committee`] key at that height.
/// A self-signed caller-selected or global-validator-only committee can
/// therefore never authorize a private state transition.
///
/// # Errors
///
/// Returns one redacted error when the route, incarnation, geometry, ordered
/// roster, or roster cryptography is not authoritative.
pub fn validate_private_settlement_committee_authority_v1(
    state: &impl StateReadOnly,
    authority_context_height: u64,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementCommitteeAuthorityErrorV1> {
    iroha_data_model::nexus::validate_private_settlement_committee_assignment_v1(
        state.world().sumeragi_lanes(),
        authority,
        authority_context_height,
    )
    .map_err(|_| PrivateSettlementCommitteeAuthorityErrorV1)?;
    if authority.validators.iter().any(|peer| {
        !peer_has_live_consensus_key_for_role(
            state.world(),
            peer,
            authority_context_height,
            ConsensusKeyRole::Committee,
        )
    }) {
        return Err(PrivateSettlementCommitteeAuthorityErrorV1);
    }
    Ok(())
}

/// Produce one purpose-separated BLS vote after caller-side Prepare checks.
#[expect(
    clippy::large_types_passed_by_value,
    reason = "the complete phase body is transferred into the signed vote"
)]
pub(crate) fn sign_private_settlement_phase_vote_v1(
    body: PrivateSettlementPhaseBodyV1,
    signer: &iroha_crypto::KeyPair,
) -> Result<PrivateSettlementPhaseVoteV1, PrivateSettlementProtocolErrorV1> {
    if signer.public_key().try_algorithm().ok() != Some(Algorithm::BlsNormal) {
        return Err(PrivateSettlementProtocolErrorV1::Vote);
    }
    let signature = Signature::try_new(signer.private_key(), &phase_signature_preimage_v1(&body)?)
        .map_err(|_| PrivateSettlementProtocolErrorV1::Vote)?;
    Ok(PrivateSettlementPhaseVoteV1 {
        version: iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        body,
        signer: PeerId::from(signer.public_key().clone()),
        signature: signature.payload().to_vec(),
    })
}

/// Construct the sole phase body admissible for one manifest leg.
pub(crate) fn private_settlement_phase_body_v1(
    manifest: &AtomicPrivateSettlementV1,
    delta: &PrivateSettlementDeltaV1,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    phase: PrivateSettlementPhaseV1,
    prepared_bundle_digest: Hash,
) -> Result<PrivateSettlementPhaseBodyV1, PrivateSettlementProtocolErrorV1> {
    manifest
        .validate()
        .map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
    delta
        .validate_public_shape()
        .map_err(|_| PrivateSettlementProtocolErrorV1::Binding)?;
    validate_authority_cryptography_v1(authority)?;
    let manifest_leg = manifest
        .legs
        .get(usize::from(delta.leg_ordinal))
        .ok_or(PrivateSettlementProtocolErrorV1::Binding)?;
    let delta_digest = delta
        .digest()
        .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)?;
    let reserved_digest = private_settlement_reserved_prepared_bundle_digest_v1();
    if delta.bundle_id != manifest.bundle_id
        || delta.route != manifest_leg.route
        || delta.pool_id != manifest_leg.pool_id
        || delta.asset_binding_commitment != manifest_leg.asset_binding_commitment
        || delta.audit_policy_digest != manifest_leg.audit_policy_digest
        || delta_digest != manifest_leg.delta_digest
        || authority.route != manifest_leg.route
        || match phase {
            PrivateSettlementPhaseV1::Prepare => prepared_bundle_digest != reserved_digest,
            PrivateSettlementPhaseV1::Commit => prepared_bundle_digest == reserved_digest,
        }
    {
        return Err(PrivateSettlementProtocolErrorV1::Binding);
    }
    Ok(PrivateSettlementPhaseBodyV1 {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        manifest_digest: manifest
            .manifest_digest()
            .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)?,
        leg_ordinal: delta.leg_ordinal,
        route: manifest_leg.route,
        delta_digest,
        authority_digest: authority
            .digest()
            .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)?,
        prepared_bundle_digest,
        phase,
        authority_context_height: manifest.authority_context_height,
        expiry_height: manifest.expiry_height,
    })
}

#[cfg(test)]
/// Aggregate valid votes into an exact-three-of-four phase certificate.
#[expect(
    clippy::large_types_passed_by_value,
    reason = "the returned certificate owns the validated phase body"
)]
pub(crate) fn aggregate_private_settlement_phase_votes_v1(
    body: PrivateSettlementPhaseBodyV1,
    authority_catalog_index: u8,
    authority: &PrivateSettlementCommitteeAuthorityV1,
    votes: &[PrivateSettlementPhaseVoteV1],
) -> Result<PrivateSettlementPhaseCertificateV1, PrivateSettlementProtocolErrorV1> {
    if votes.len() != usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(PrivateSettlementProtocolErrorV1::Quorum);
    }
    validate_authority_cryptography_v1(authority)?;
    let authority_digest = authority
        .digest()
        .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)?;
    if body.route != authority.route || body.authority_digest != authority_digest {
        return Err(PrivateSettlementProtocolErrorV1::Binding);
    }
    let preimage = phase_signature_preimage_v1(&body)?;
    let mut indexed = BTreeMap::<usize, Vec<u8>>::new();
    for vote in votes {
        if vote.validate_shape().is_err()
            || vote.body != body
            || vote.signature.len() != PRIVATE_SETTLEMENT_BLS_BYTES_V1
        {
            return Err(PrivateSettlementProtocolErrorV1::Vote);
        }
        let index = authority
            .validators
            .iter()
            .position(|validator| validator == &vote.signer)
            .ok_or(PrivateSettlementProtocolErrorV1::Vote)?;
        if indexed.contains_key(&index) {
            return Err(PrivateSettlementProtocolErrorV1::Vote);
        }
        let signature = Signature::try_from_bytes(&vote.signature)
            .map_err(|_| PrivateSettlementProtocolErrorV1::Vote)?;
        signature
            .verify(vote.signer.public_key(), &preimage)
            .map_err(|_| PrivateSettlementProtocolErrorV1::Vote)?;
        indexed.insert(index, vote.signature.clone());
    }
    if indexed.len() != usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(PrivateSettlementProtocolErrorV1::Quorum);
    }

    let mut signers_bitmap = 0_u8;
    let signatures = indexed
        .into_iter()
        .map(|(index, signature)| {
            signers_bitmap |= 1_u8 << index;
            signature
        })
        .collect::<Vec<_>>();
    let signature_refs = signatures.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let aggregate_signature = iroha_crypto::bls_normal_aggregate_signatures(&signature_refs)
        .map_err(|_| PrivateSettlementProtocolErrorV1::Vote)?;
    let certificate = PrivateSettlementPhaseCertificateV1 {
        body,
        authority_catalog_index,
        signers_bitmap,
        aggregate_signature,
    };
    verify_private_settlement_phase_certificate_v1(
        &certificate,
        authority_catalog_index,
        authority,
    )?;
    Ok(certificate)
}

/// Verify one exact-three-of-four participant phase certificate.
pub(crate) fn verify_private_settlement_phase_certificate_v1(
    certificate: &PrivateSettlementPhaseCertificateV1,
    expected_authority_catalog_index: u8,
    authority: &PrivateSettlementCommitteeAuthorityV1,
) -> Result<(), PrivateSettlementProtocolErrorV1> {
    certificate
        .validate_shape()
        .map_err(|_| PrivateSettlementProtocolErrorV1::Certificate)?;
    validate_authority_cryptography_v1(authority)?;
    let authority_digest = authority
        .digest()
        .map_err(|_| PrivateSettlementProtocolErrorV1::CanonicalEncoding)?;
    if certificate.authority_catalog_index != expected_authority_catalog_index
        || certificate.body.route != authority.route
        || certificate.body.authority_digest != authority_digest
    {
        return Err(PrivateSettlementProtocolErrorV1::Binding);
    }

    let mut signer_keys = Vec::with_capacity(usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1));
    let mut signer_pops = Vec::with_capacity(usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1));
    for index in 0..PRIVATE_SETTLEMENT_COMMITTEE_VALIDATORS_V1 {
        if certificate.signers_bitmap & (1_u8 << index) == 0 {
            continue;
        }
        let validator = authority
            .validators
            .get(index)
            .ok_or(PrivateSettlementProtocolErrorV1::Certificate)?;
        let pop = authority
            .validator_pops
            .get(index)
            .ok_or(PrivateSettlementProtocolErrorV1::Certificate)?;
        signer_keys.push(validator.public_key());
        signer_pops.push(pop.as_slice());
    }
    if signer_keys.len() != usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1) {
        return Err(PrivateSettlementProtocolErrorV1::Quorum);
    }
    let preimage = phase_signature_preimage_v1(&certificate.body)?;
    iroha_crypto::bls_normal_verify_preaggregated_same_message(
        &preimage,
        &certificate.aggregate_signature,
        &signer_keys,
        &signer_pops,
    )
    .map_err(|_| PrivateSettlementProtocolErrorV1::Certificate)
}

/// Validate every receipt binding, authority PoP, and phase aggregate.
pub(crate) fn verify_private_settlement_receipt_v1(
    receipt: &PrivateSettlementReceiptV1,
) -> Result<(), PrivateSettlementProtocolErrorV1> {
    receipt
        .validate_shape()
        .map_err(|_| PrivateSettlementProtocolErrorV1::Receipt)?;
    let deltas = receipt
        .legs
        .iter()
        .map(|leg| leg.delta.clone())
        .collect::<Vec<_>>();
    let prepare_certificates = receipt
        .legs
        .iter()
        .map(|leg| leg.prepare.clone())
        .collect::<Vec<_>>();
    let prepared_bundle_digest = private_settlement_prepared_bundle_digest_v1(
        &receipt.manifest,
        &receipt.authority_catalog,
        &deltas,
        &prepare_certificates,
    )?;
    for (index, leg) in receipt.legs.iter().enumerate() {
        let catalog_index =
            u8::try_from(index).map_err(|_| PrivateSettlementProtocolErrorV1::Receipt)?;
        let authority = receipt
            .authority_catalog
            .authority_for_leg(&receipt.manifest, index)
            .map_err(|_| PrivateSettlementProtocolErrorV1::Receipt)?;
        for (phase, certificate) in [
            (PrivateSettlementPhaseV1::Prepare, &leg.prepare),
            (PrivateSettlementPhaseV1::Commit, &leg.commit),
        ] {
            let expected = private_settlement_phase_body_v1(
                &receipt.manifest,
                &leg.delta,
                &authority,
                phase,
                match phase {
                    PrivateSettlementPhaseV1::Prepare => {
                        private_settlement_reserved_prepared_bundle_digest_v1()
                    }
                    PrivateSettlementPhaseV1::Commit => prepared_bundle_digest,
                },
            )?;
            if certificate.body != expected {
                return Err(PrivateSettlementProtocolErrorV1::Binding);
            }
            verify_private_settlement_phase_certificate_v1(certificate, catalog_index, &authority)?;
        }
    }
    Ok(())
}

/// Redacted protocol error safe for logs and public API responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub(crate) enum PrivateSettlementProtocolErrorV1 {
    /// Canonical Norito encoding failed.
    #[error("private-settlement protocol encoding failed")]
    CanonicalEncoding,
    /// Committee authority or proofs of possession are invalid.
    #[error("private-settlement committee authority is invalid")]
    Authority,
    /// Manifest, route, delta, authority, or phase binding differs.
    #[error("private-settlement certificate binding is invalid")]
    Binding,
    /// An individual phase vote is malformed, duplicated, or unauthenticated.
    #[error("private-settlement phase vote is invalid")]
    Vote,
    /// Fewer than the exact certificate quorum supplied valid votes.
    #[error("private-settlement phase quorum is unavailable")]
    Quorum,
    /// Aggregate certificate shape or signature is invalid.
    #[error("private-settlement phase certificate is invalid")]
    Certificate,
    /// Final receipt shape or cryptography is invalid.
    #[error("private-settlement receipt is invalid")]
    Receipt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{HashOf, KeyPair};
    use iroha_data_model::{NetworkId, block::BlockHeader, nexus::PrivateSettlementRouteV1};
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};

    fn fixture() -> (
        PrivateSettlementCommitteeAuthorityV1,
        Vec<KeyPair>,
        PrivateSettlementPhaseBodyV1,
    ) {
        let route = PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(7),
            lane_id: LaneId::new(3),
            lane_incarnation: Hash::new(b"incarnation"),
        };
        let keys = (0_u8..4)
            .map(|index| KeyPair::from_seed(vec![0xA0 + index; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .map(|key| PeerId::from(key.public_key().clone()))
            .collect::<Vec<_>>();
        let authority = PrivateSettlementCommitteeAuthorityV1 {
            route,
            validator_set_hash: HashOf::new(&validators),
            validators,
            validator_pops: keys
                .iter()
                .map(|key| {
                    iroha_crypto::bls_normal_pop_prove(key.private_key()).expect("validator PoP")
                })
                .collect(),
        };
        let body = PrivateSettlementPhaseBodyV1 {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"network")),
            ),
            bundle_id: Hash::new(b"bundle"),
            manifest_digest: Hash::new(b"manifest"),
            leg_ordinal: 0,
            route,
            delta_digest: Hash::new(b"delta"),
            authority_digest: authority.digest().expect("authority digest"),
            prepared_bundle_digest: private_settlement_reserved_prepared_bundle_digest_v1(),
            phase: PrivateSettlementPhaseV1::Prepare,
            authority_context_height: 10,
            expiry_height: 50,
        };
        (authority, keys, body)
    }

    fn votes(
        body: &PrivateSettlementPhaseBodyV1,
        authority: &PrivateSettlementCommitteeAuthorityV1,
        keys: &[KeyPair],
        indexes: &[usize],
    ) -> Vec<PrivateSettlementPhaseVoteV1> {
        let preimage = phase_signature_preimage_v1(body).expect("phase preimage");
        indexes
            .iter()
            .map(|index| PrivateSettlementPhaseVoteV1 {
                version: iroha_data_model::nexus::ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
                body: *body,
                signer: authority.validators[*index].clone(),
                signature: Signature::try_new(keys[*index].private_key(), &preimage)
                    .expect("phase signature")
                    .payload()
                    .to_vec(),
            })
            .collect()
    }

    #[test]
    fn three_of_four_votes_build_and_verify_a_purpose_separated_certificate() {
        let (authority, keys, body) = fixture();
        let certificate = aggregate_private_settlement_phase_votes_v1(
            body,
            0,
            &authority,
            &votes(&body, &authority, &keys, &[0, 1, 3]),
        )
        .expect("phase certificate");
        assert_eq!(certificate.signers_bitmap, 0b1011);
        verify_private_settlement_phase_certificate_v1(&certificate, 0, &authority)
            .expect("certificate verifies");
    }

    #[test]
    fn quorum_and_substitution_fail_closed() {
        let (authority, keys, body) = fixture();
        assert_eq!(
            aggregate_private_settlement_phase_votes_v1(
                body,
                0,
                &authority,
                &votes(&body, &authority, &keys, &[0, 1]),
            ),
            Err(PrivateSettlementProtocolErrorV1::Quorum)
        );
        let duplicate = votes(&body, &authority, &keys, &[0, 1, 2]);
        let duplicate = vec![
            duplicate[0].clone(),
            duplicate[0].clone(),
            duplicate[2].clone(),
        ];
        assert_eq!(
            aggregate_private_settlement_phase_votes_v1(body, 0, &authority, &duplicate),
            Err(PrivateSettlementProtocolErrorV1::Vote)
        );
        let mut malformed = votes(&body, &authority, &keys, &[0, 1, 2]);
        malformed[1].signature[0] ^= 1;
        assert_eq!(
            aggregate_private_settlement_phase_votes_v1(body, 0, &authority, &malformed),
            Err(PrivateSettlementProtocolErrorV1::Vote)
        );

        assert_eq!(
            aggregate_private_settlement_phase_votes_v1(
                body,
                0,
                &authority,
                &votes(&body, &authority, &keys, &[0, 1, 2, 3]),
            ),
            Err(PrivateSettlementProtocolErrorV1::Quorum),
            "four votes are not an exact three-of-four transport quorum"
        );
        let mut certificate = aggregate_private_settlement_phase_votes_v1(
            body,
            0,
            &authority,
            &votes(&body, &authority, &keys, &[0, 1, 2]),
        )
        .expect("three valid votes");
        assert_eq!(certificate.signers_bitmap.count_ones(), 3);
        certificate.body.delta_digest = Hash::new(b"substituted delta");
        assert_eq!(
            verify_private_settlement_phase_certificate_v1(&certificate, 0, &authority),
            Err(PrivateSettlementProtocolErrorV1::Certificate)
        );
    }

    #[test]
    fn commit_qcs_accept_quorum_equivalent_prepare_recovery() {
        let (_, mut receipt, fixture) = crate::private_settlement::global_state::tests::fixture();
        let leg_index = 1_usize;
        let body = receipt.legs[leg_index].prepare.body;
        let authority = receipt
            .authority_catalog
            .authority_for_leg(&receipt.manifest, leg_index)
            .expect("fixture authority");
        let alternate_votes = fixture.validator_keys[1..]
            .iter()
            .map(|key| sign_private_settlement_phase_vote_v1(body, key).expect("phase vote"))
            .collect::<Vec<_>>();
        let alternate_prepare = aggregate_private_settlement_phase_votes_v1(
            body,
            u8::try_from(leg_index).expect("fixture leg ordinal"),
            &authority,
            &alternate_votes,
        )
        .expect("alternate valid Prepare QC");
        assert_ne!(alternate_prepare, receipt.legs[leg_index].prepare);
        verify_private_settlement_phase_certificate_v1(
            &alternate_prepare,
            u8::try_from(leg_index).expect("fixture leg ordinal"),
            &authority,
        )
        .expect("substituted Prepare QC is independently valid");

        receipt.legs[leg_index].prepare = alternate_prepare;
        verify_private_settlement_receipt_v1(&receipt).expect(
            "a different valid three-of-four signer subset over the same body is equivalent",
        );
    }

    #[test]
    fn prepared_bundle_digest_commits_to_statements_not_signature_encoding() {
        let (_, receipt, fixture) = crate::private_settlement::global_state::tests::fixture();
        let deltas = receipt
            .legs
            .iter()
            .map(|leg| leg.delta.clone())
            .collect::<Vec<_>>();
        let prepares = receipt
            .legs
            .iter()
            .map(|leg| leg.prepare.clone())
            .collect::<Vec<_>>();
        let digest = private_settlement_prepared_bundle_digest_v1(
            &receipt.manifest,
            &receipt.authority_catalog,
            &deltas,
            &prepares,
        )
        .expect("prepared bundle digest");

        let mut manifest = receipt.manifest.clone();
        manifest.expiry_height += 1;
        assert_eq!(
            private_settlement_prepared_bundle_digest_v1(
                &manifest,
                &receipt.authority_catalog,
                &deltas,
                &prepares,
            ),
            Err(PrivateSettlementProtocolErrorV1::Binding),
            "a manifest whose derived bundle id no longer matches must fail before hashing"
        );

        let mut authorities = receipt.authority_catalog.clone();
        authorities.rosters[0].validator_pops[0][0] ^= 1;
        assert_ne!(
            private_settlement_prepared_bundle_digest_v1(
                &receipt.manifest,
                &authorities,
                &deltas,
                &prepares,
            )
            .expect("changed-authority digest"),
            digest
        );

        let mut changed_deltas = deltas.clone();
        changed_deltas[1].proof_digest = Hash::new(b"changed proof");
        assert_ne!(
            private_settlement_prepared_bundle_digest_v1(
                &receipt.manifest,
                &receipt.authority_catalog,
                &changed_deltas,
                &prepares,
            )
            .expect("changed-delta digest"),
            digest
        );

        let mut changed_prepares = prepares.clone();
        changed_prepares[1].body.manifest_digest = Hash::new(b"changed manifest binding");
        assert_ne!(
            private_settlement_prepared_bundle_digest_v1(
                &receipt.manifest,
                &receipt.authority_catalog,
                &deltas,
                &changed_prepares,
            )
            .expect("changed-Prepare-statement digest"),
            digest
        );

        let leg_index = 1_usize;
        let body = prepares[leg_index].body;
        let alternate_votes = fixture.validator_keys[1..]
            .iter()
            .map(|key| sign_private_settlement_phase_vote_v1(body, key).expect("phase vote"))
            .collect::<Vec<_>>();
        let alternate = aggregate_private_settlement_phase_votes_v1(
            body,
            u8::try_from(leg_index).expect("fixture leg ordinal"),
            &receipt
                .authority_catalog
                .authority_for_leg(&receipt.manifest, leg_index)
                .expect("fixture authority"),
            &alternate_votes,
        )
        .expect("alternate valid Prepare QC");
        let mut alternate_prepares = prepares.clone();
        alternate_prepares[leg_index] = alternate;
        assert_eq!(
            private_settlement_prepared_bundle_digest_v1(
                &receipt.manifest,
                &receipt.authority_catalog,
                &deltas,
                &alternate_prepares,
            )
            .expect("quorum-equivalent Prepare digest"),
            digest,
            "signer-set and aggregate-signature encoding are not logical bundle content"
        );
        let mut incomplete_catalog = receipt.authority_catalog.clone();
        incomplete_catalog.leg_roster_indices.pop();
        assert_eq!(
            private_settlement_prepared_bundle_digest_v1(
                &receipt.manifest,
                &incomplete_catalog,
                &deltas,
                &prepares,
            ),
            Err(PrivateSettlementProtocolErrorV1::Binding)
        );
    }

    #[test]
    fn prepare_barrier_rejects_incomplete_and_cross_leg_substitution() {
        let (_, receipt, _) = crate::private_settlement::global_state::tests::fixture();
        let deltas = receipt
            .legs
            .iter()
            .map(|leg| leg.delta.clone())
            .collect::<Vec<_>>();
        let prepares = receipt
            .legs
            .iter()
            .map(|leg| leg.prepare.clone())
            .collect::<Vec<_>>();
        let authorities = (0..receipt.manifest.legs.len())
            .map(|index| {
                receipt
                    .authority_catalog
                    .authority_for_leg(&receipt.manifest, index)
                    .expect("fixture authority")
            })
            .collect();
        let barrier = private_settlement_prepare_barrier_v1(
            receipt.manifest.clone(),
            authorities,
            deltas,
            prepares,
        )
        .expect("valid barrier");
        validate_private_settlement_prepare_barrier_v1(&barrier).expect("barrier verifies");

        let mut incomplete = barrier.clone();
        incomplete.prepare_certificates.pop();
        assert_eq!(
            validate_private_settlement_prepare_barrier_v1(&incomplete),
            Err(PrivateSettlementProtocolErrorV1::Binding)
        );

        let mut substituted = barrier;
        substituted.prepare_certificates.swap(0, 1);
        assert_eq!(
            validate_private_settlement_prepare_barrier_v1(&substituted),
            Err(PrivateSettlementProtocolErrorV1::Binding)
        );
    }
}
