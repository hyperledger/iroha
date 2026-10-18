//! Cross-checks of the anonymous-ballot data model against the standalone proof crate
//! `iroha_parliament_ballot_proof`, a dev-dependency only.

use iroha_parliament_ballot_proof::{
    credential::{
        RegistrationContext, body_digest, proposal_digest, registration_digest, scope_digest,
    },
    framing::{
        self as proof_framing, BODY_CONTEXT_MAX_BYTES, BodyContext, COMMITMENT_BYTES, Commitment,
        DIGEST_BYTES, Digest64, NULLIFIER_BYTES, OPAQUE_FIELD_MAX_BYTES, OpaqueField,
    },
    profile::{P16, Profile, Role, Row},
    sealed_list,
};

use super::{
    BallotProofBytesV1, CredentialCommitmentV1, Digest512, NullifierV1, ProofProfileIdV1,
    RegistrationProofBytesV1, SealedCredentialListV1,
    digests::{authority_binding_v1, proposal_digest_v1},
    framing::{enc, frame_bytes, frame_digest},
    test_fixtures::{account, assignment, body_context, commitment, commitments, proposal},
};
use crate::governance::types::BodyInstanceId;

#[test]
fn the_frame_and_its_digest_equal_the_proof_crate() {
    let long = vec![0x42_u8; 70_000];
    let empty: &[u8] = b"";
    let index = 3_u32.to_le_bytes();
    let seats = 4_u16.to_le_bytes();
    let cases: [(&[u8], Vec<&[u8]>); 5] = [
        (b"", vec![]),
        (b"AB", vec![b"xyz", empty, b"q"]),
        (b"PARL/ENVELOPE/v1", vec![&long]),
        (b"PARL/CORPUS-APPEND/v1", vec![&[7; 64], &index, &[9; 64]]),
        (
            b"PARL/REGMAP/v1",
            vec![&[1; 64], &[2; 64], &[3; 64], &seats, &long],
        ),
    ];
    for (tag, fields) in cases {
        assert_eq!(
            frame_bytes(tag, &fields).expect("frame"),
            proof_framing::frame_bytes(tag, &fields).expect("frame")
        );
        assert_eq!(
            frame_digest(tag, &fields).expect("frame").as_bytes(),
            &proof_framing::frame_digest(tag, &fields).expect("frame").0
        );
    }
}

#[test]
fn the_v1_profile_and_proof_lengths_are_the_compiled_candidate_row() {
    let candidate = Profile::new(Row::Candidate).expect("embedded tables");
    assert_eq!(
        ProofProfileIdV1::V1.as_bytes(),
        candidate.descriptor_digest().as_bytes()
    );
    let comparator = Profile::new(Row::Comparator).expect("embedded tables");
    assert_ne!(
        ProofProfileIdV1::V1.as_bytes(),
        comparator.descriptor_digest().as_bytes()
    );
    assert_eq!(
        BallotProofBytesV1::LENGTH,
        Row::Candidate.proof_bytes(Role::Vote)
    );
    assert_eq!(
        RegistrationProofBytesV1::LENGTH,
        Row::Candidate.proof_bytes(Role::Registration)
    );
    assert_eq!(Digest512::LENGTH, DIGEST_BYTES);
    assert_eq!(CredentialCommitmentV1::LENGTH, COMMITMENT_BYTES);
    assert_eq!(NullifierV1::LENGTH, NULLIFIER_BYTES);
}

#[test]
fn typed_encodings_are_valid_opaque_proof_inputs() {
    let context = body_context();
    let encoded_context = enc(&context).expect("enc");
    assert!(encoded_context.len() <= BODY_CONTEXT_MAX_BYTES);
    let body_context_input = BodyContext::new(&encoded_context).expect("within the bound");
    let authority = authority_binding_v1(&account()).expect("binding");
    let inputs = [
        enc(&context.network_id).expect("enc"),
        enc(&authority).expect("enc"),
        enc(&assignment(1)).expect("enc"),
        enc(&context.governance_attempt_id).expect("enc"),
        enc(&context.election_attempt_id).expect("enc"),
        enc(&context.body_role).expect("enc"),
        enc(&BodyInstanceId::new([0x03; 32])).expect("enc"),
    ];
    for input in &inputs {
        assert!(input.len() <= OPAQUE_FIELD_MAX_BYTES, "{}", input.len());
    }
    let opaque = |bytes: &[u8]| OpaqueField::new(bytes).expect("within the bound");
    // B through the proof crate equals the profile frame computed here with `P16`.
    let b = body_digest(&body_context_input).expect("B");
    assert_eq!(
        frame_digest(b"PARL/BODY/v1", &[&P16, &encoded_context])
            .expect("frame")
            .as_bytes(),
        &b.0
    );
    // A registration digest and a scope accept the typed encodings as they are.
    let registration = RegistrationContext {
        network_id: opaque(&inputs[0]),
        authority: opaque(&inputs[1]),
        assignment_id: opaque(&inputs[2]),
        governance_attempt_id: opaque(&inputs[3]),
        election_attempt_id: opaque(&inputs[4]),
        body_role: opaque(&inputs[5]),
    };
    let descriptor = Digest64(*ProofProfileIdV1::V1.as_bytes());
    let commitment = Commitment(commitment(1).into_bytes());
    assert!(
        registration_digest(
            &descriptor,
            &body_context_input,
            &registration,
            &b,
            &commitment
        )
        .is_ok()
    );
    let proposal = proposal_digest_v1(&proposal()).expect("proposal digest");
    assert!(
        scope_digest(
            &opaque(&inputs[0]),
            &Digest64(*proposal.as_bytes()),
            &opaque(&inputs[3]),
            &opaque(&inputs[6]),
        )
        .is_ok()
    );
}

#[test]
fn the_proposal_digest_equals_the_proof_crate_helper() {
    let proposal = proposal();
    assert_eq!(
        proposal_digest_v1(&proposal).expect("digest").as_bytes(),
        &proposal_digest(&enc(&proposal).expect("enc"))
            .expect("digest")
            .0
    );
}

#[test]
fn sealed_list_validation_agrees_with_the_proof_crate() {
    let to_proof = |entries: &[CredentialCommitmentV1]| -> Vec<Commitment> {
        entries
            .iter()
            .map(|entry| Commitment(entry.into_bytes()))
            .collect()
    };
    let mut swapped = commitments(6);
    swapped.swap(2, 3);
    let mut repeated = commitments(6);
    repeated[5] = repeated[4];
    let mut last_byte = commitments(3);
    let mut bytes = last_byte[2].into_bytes();
    bytes[127] = 0;
    last_byte[2] = CredentialCommitmentV1::new(bytes);
    let cases = [
        commitments(2),
        commitments(3),
        commitments(1_000),
        commitments(1_001),
        swapped,
        repeated,
        last_byte,
        vec![commitment(0), commitment(0xffff), commitment(0x8000)],
    ];
    let body = Digest512::new([0x33; 64]);
    for entries in cases {
        let ours = SealedCredentialListV1::new(ProofProfileIdV1::V1, body, entries.clone());
        let theirs = sealed_list::SealedList::new(to_proof(&entries));
        assert_eq!(ours.is_ok(), theirs.is_ok(), "{} entries", entries.len());
        if let (Ok(list), Ok(proof_list)) = (ours, theirs) {
            // `R` comes from the proof crate over exactly the list's commitments.
            let r = proof_list.digest(&Digest64(*body.as_bytes())).expect("R");
            let mut concat = Vec::new();
            for entry in &list.commitments {
                concat.extend_from_slice(entry.as_bytes());
            }
            assert_eq!(
                frame_digest(
                    b"PARL/LIST/v1",
                    &[&P16, body.as_bytes(), &list.seats.to_le_bytes(), &concat]
                )
                .expect("frame")
                .as_bytes(),
                &r.0
            );
        }
    }
}
