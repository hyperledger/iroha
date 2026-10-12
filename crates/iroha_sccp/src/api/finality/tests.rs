//! Native API certificate authority and exact-quorum regressions.

use super::*;
use crate::v1::finality::{
    FLAG_ACTIVE, FLAG_ROTATION, QcFixedV1, SccpFinalityHeaderFieldsV1, commit_preimage,
    outer_result,
};
use iroha_crypto::{
    Algorithm, KeyPair,
    bls::consensus::{aggregate, sign_preimage},
};
use iroha_data_model::{
    sccp::{
        committee::{SccpGenerationCauseV1, SccpGenerationEndV1},
        params::SccpParametersV1,
    },
    sumeragi_finality::certified_result::committee_root,
};

const NETWORK: [u8; 32] = [1; 32];
const INSTANCE: [u8; 32] = [2; 32];

fn fixture(rotation: bool, signers: u32) -> (SccpCertificateV1, SccpCommitteeGenerationV1) {
    fixture_at(rotation, signers, 101)
}

fn fixture_at(
    rotation: bool,
    signers: u32,
    timestamp_ms: u64,
) -> (SccpCertificateV1, SccpCommitteeGenerationV1) {
    let mut members: Vec<_> = (1..=4)
        .map(|seed| {
            let pair = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            let raw: [u8; 48] = pair.public_key().to_bytes().1.try_into().unwrap();
            (raw, pair)
        })
        .collect();
    members.sort_by_key(|member| member.0);
    let keys: Vec<_> = members.iter().map(|member| member.0).collect();
    let parameters = SccpParametersV1::taira_default();
    let generation = SccpCommitteeGenerationV1 {
        generation: 1,
        committee_root: committee_root(&keys).unwrap(),
        keys,
        members: vec![None; 4],
        cause: SccpGenerationCauseV1::Genesis,
        start_height: 1,
        start_timestamp_ms: 100,
        start_lc: 100,
        validity_ms: parameters.committee_validity_ms,
        deadline_ms: 100 + parameters.committee_validity_ms,
        grace_ms: parameters.forgery_evidence_grace_ms,
        progress_cap_ms: parameters.destination_progress_cap_ms,
        liable_until_lc: 100
            + parameters.committee_validity_ms
            + parameters.forgery_evidence_grace_ms,
        dest_cleared_lc: None,
        end: rotation.then_some(SccpGenerationEndV1 {
            end_height: 2,
            end_timestamp_ms: timestamp_ms,
            next_committee_root: [8; 32],
            successor_validity_ms: parameters.committee_validity_ms,
        }),
    };
    generation.validate().unwrap();
    let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: NETWORK,
        height: 2,
        timestamp_ms,
        flags: FLAG_ACTIVE | if rotation { FLAG_ROTATION } else { 0 },
        generation: 1,
        committee_root: generation.committee_root,
        validity_ms: if rotation {
            parameters.committee_validity_ms
        } else {
            0
        },
        next_committee_root: if rotation { [8; 32] } else { [0; 32] },
        ..SccpFinalityHeaderFieldsV1::default()
    })
    .unwrap();
    let qc = QcFixedV1 {
        epoch: 4,
        epoch_context: [3; 32],
        view: 5,
        block_hash: [4; 32],
        result_body: [5; 32],
        signers,
    };
    let preimage = commit_preimage(
        &INSTANCE,
        &qc,
        header.height(),
        &outer_result(&header, &qc.result_body).0,
    );
    let shares = members
        .iter()
        .enumerate()
        .filter(|(index, _)| signers & (1 << index) != 0)
        .map(|(_, member)| sign_preimage(member.1.private_key(), &preimage).unwrap());
    (
        SccpCertificateV1 {
            height: 2,
            qc: qc.encode(),
            aggregate_signature: aggregate(shares).unwrap(),
            header: *header.as_bytes(),
            committee: generation.keys.clone(),
        },
        generation,
    )
}

fn verify(
    certificate: &SccpCertificateV1,
    generation: &SccpCommitteeGenerationV1,
) -> Result<VerifiedCertificateV1, ApiCertificateError> {
    verify_native_certificate(certificate, &NETWORK, &INSTANCE, generation)
}

#[test]
fn native_certificates_require_original_authority_and_exact_quorum() {
    for rotation in [false, true] {
        let (certificate, generation) = fixture(rotation, 7);
        let verified = verify(&certificate, &generation).unwrap();
        assert_eq!(verified.header.height(), certificate.height);
        assert_eq!(verified.header.is_rotation(), rotation);
        assert_eq!(
            verify_native_certificate(&certificate, &NETWORK, &[9; 32], &generation),
            Err(ApiCertificateError::Certificate(
                CertificateError::Signature
            ))
        );
        assert_eq!(
            verify_native_certificate(&certificate, &[9; 32], &INSTANCE, &generation),
            Err(ApiCertificateError::Network)
        );
    }
    for signers in [3, 15] {
        let (certificate, generation) = fixture(false, signers);
        assert_eq!(
            verify(&certificate, &generation),
            Err(ApiCertificateError::Certificate(
                CertificateError::SignerCount
            ))
        );
    }
}

#[test]
fn untrusted_outer_claims_cannot_replace_retained_generation() {
    let (certificate, generation) = fixture(false, 7);
    let mut changed = certificate.clone();
    changed.height += 1;
    assert_eq!(
        verify(&changed, &generation),
        Err(ApiCertificateError::Height)
    );
    changed = certificate.clone();
    changed.committee.swap(0, 1);
    assert_eq!(
        verify(&changed, &generation),
        Err(ApiCertificateError::Committee)
    );
    let mut authority = generation.clone();
    authority.generation += 1;
    assert_eq!(
        verify(&certificate, &authority),
        Err(ApiCertificateError::Generation)
    );
    authority = generation.clone();
    authority.committee_root[0] ^= 1;
    assert_eq!(
        verify(&certificate, &authority),
        Err(ApiCertificateError::Generation)
    );
    changed = certificate.clone();
    changed.header = *SccpFinalityHeaderV1::inactive(NETWORK, 2, 101)
        .unwrap()
        .as_bytes();
    assert_eq!(
        verify(&changed, &generation),
        Err(ApiCertificateError::Inactive)
    );
    changed.header[0] ^= 1;
    assert!(matches!(
        verify(&changed, &generation),
        Err(ApiCertificateError::Certificate(_))
    ));
    changed = certificate;
    changed.aggregate_signature[1] ^= 1;
    assert!(matches!(
        verify(&changed, &generation),
        Err(ApiCertificateError::Certificate(_))
    ));
}

#[test]
fn tenure_and_rotation_are_bound_to_original_lifecycle() {
    let (certificate, generation) = fixture(true, 7);
    for field in 0..3 {
        let mut authority = generation.clone();
        match field {
            0 => authority.start_height = 3,
            1 => authority.start_timestamp_ms = 102,
            _ => authority.end.as_mut().unwrap().end_height = 1,
        }
        assert_eq!(
            verify(&certificate, &authority),
            Err(ApiCertificateError::Tenure)
        );
    }
    for field in 0..4 {
        let mut authority = generation.clone();
        match field {
            0 => authority.end = None,
            1 => authority.end.as_mut().unwrap().end_height = 3,
            2 => authority.end.as_mut().unwrap().next_committee_root = [9; 32],
            _ => authority.end.as_mut().unwrap().successor_validity_ms += 1,
        }
        assert_eq!(
            verify(&certificate, &authority),
            Err(ApiCertificateError::Rotation)
        );
    }
}

#[test]
fn genuine_heartbeat_after_destination_deadline_still_has_native_finality() {
    // G2 signs the outgoing generation's first heartbeat block even after a long idle gap.
    // A destination's local Live/expiry decision is a separate pre-submission check.
    let time = 101 + SccpParametersV1::taira_default().committee_validity_ms;
    let (certificate, generation) = fixture_at(true, 7, time);
    assert!(time > generation.deadline_ms);
    assert_eq!(
        verify(&certificate, &generation)
            .unwrap()
            .header
            .timestamp_ms(),
        time
    );
}
