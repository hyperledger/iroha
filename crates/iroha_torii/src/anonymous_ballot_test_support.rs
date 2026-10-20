//! Codec-only anonymous fixtures; these bytes do not assert a valid proof or stamp.

use iroha_data_model::{
    NetworkId,
    governance::anonymous_ballot::{
        AdmissionNonceV1, AdmissionStampV1, AnonymousBallotEnvelopeV1, AnonymousBallotV1,
        BallotChoiceV1, BallotProofBytesV1, BallotScopeV1, CanonicalAnonymousBallotEnvelopeV1,
        NullifierV1, ProofProfileIdV1, VoteAuthorizationV1,
    },
    transaction::signed::TransactionEntrypoint,
};

pub(crate) fn entrypoint(network_id: NetworkId) -> TransactionEntrypoint {
    let envelope = AnonymousBallotEnvelopeV1 {
        network_id,
        ballot: AnonymousBallotV1 {
            scope: BallotScopeV1::new([0x44; 64]),
            vote: BallotChoiceV1::Aye,
            nullifier: NullifierV1::new([0x33; 128]),
            auth_v: VoteAuthorizationV1::new([0x55; 64]),
            profile_id: ProofProfileIdV1::V1,
            stamp: AdmissionStampV1 {
                nonce: AdmissionNonceV1::new([0x66; 32]),
            },
            proof: BallotProofBytesV1::new(vec![0x6b; BallotProofBytesV1::LENGTH]).unwrap(),
        },
    };
    TransactionEntrypoint::AnonymousBallot(
        CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope).unwrap(),
    )
}
