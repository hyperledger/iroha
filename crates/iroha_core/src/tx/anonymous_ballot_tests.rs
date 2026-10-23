//! Signerless representation and local-unavailable controls, without proof-validity claims.

use super::*;
use crate::queue::TransactionRoutingView as _;
use crate::sumeragi::lanes::{TransactionCheck as _, global::StatelessChecks};
use iroha_data_model::governance::anonymous_ballot::{
    AdmissionNonceV1, AdmissionStampV1, AnonymousBallotEnvelopeV1, AnonymousBallotV1,
    BallotChoiceV1, BallotProofBytesV1, BallotScopeV1, CanonicalAnonymousBallotEnvelopeV1,
    NullifierV1, ProofProfileIdV1, VoteAuthorizationV1,
};

/// Canonical structural input only: these public proof bytes and nonce are not valid evidence.
pub(crate) fn entrypoint() -> TransactionEntrypoint {
    let envelope = AnonymousBallotEnvelopeV1 {
        network_id: crate::unit_test_support::synthetic_network_id("anonymous representation"),
        ballot: AnonymousBallotV1 {
            scope: BallotScopeV1::new([0x44; 64]),
            vote: BallotChoiceV1::Aye,
            nullifier: NullifierV1::new([7; 128]),
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

#[test]
fn signerless_representation_has_no_signed_authority_or_metadata_cache() {
    let entry = entrypoint();
    let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(&entry));
    assert!(accepted.authority_opt().is_none());
    assert!(accepted.external().is_none());
    assert!(accepted.metadata().is_none());
    assert!(accepted.time_to_live().is_none());
    assert!(accepted.prepared_metadata().is_none());
    assert!(accepted.stateless_cache_metadata().is_none());
    assert!(accepted.signed_bytes().is_none());
    assert!(exact_signed_transaction_hash(&entry).is_none());
    assert!(accepted.is_anonymous_ballot());
    assert_eq!(accepted.hash_as_entrypoint(), entry.hash());
    assert_eq!(
        accepted.entrypoint_bytes().as_slice(),
        norito::encode_canonical(&entry).unwrap()
    );
    let TransactionEntrypoint::AnonymousBallot(carrier) = &entry else {
        unreachable!()
    };
    assert_eq!(
        accepted.encoded_len(),
        norito::encode_canonical(carrier).unwrap().len()
    );
}

#[test]
fn signerless_admission_and_lane_check_remain_locally_unavailable() {
    let entry = entrypoint();
    let network = crate::unit_test_support::synthetic_network_id("anonymous representation");
    for signature_prechecked in [false, true] {
        assert!(matches!(
            AcceptedTransaction::accept_borrowed_entrypoint_at_time(
                &entry,
                &network,
                Duration::ZERO,
                TransactionParameters::default(),
                &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                    iroha_crypto::Algorithm::Ed25519,
                ])
                .expect("explicit signerless structural fixture policy"),
                Duration::ZERO,
                signature_prechecked,
            ),
            Err(AcceptTransactionFail::AnonymousBallotUnavailable)
        ));
    }
    assert!(matches!(StatelessChecks::new(network).check(&entry, 0),
        Err(ExecutionAttemptError::Deferred(reason))
            if reason.reason() == ivm::error::ExecutionDeferral::VerifierInitializationUnavailable));
    let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(&entry));
    assert!(matches!(crate::queue::Queue::compute_proposal_gas_cost(
        &accepted, &iroha_config::parameters::actual::ConfidentialGas { proof_base: 1, per_public_input: 1, per_proof_byte: 1, per_nullifier: 1, per_commitment: 1 },
    ), Err(ExecutionAttemptError::Deferred(reason))
        if reason.reason() == ivm::error::ExecutionDeferral::VerifierInitializationUnavailable));
}
#[test]
fn unavailable_admission_cannot_be_projected_into_a_committed_rejection() {
    let ExecutionAttemptError::Deferred(refusal) =
        execution_attempt_from_admission_failure(AcceptTransactionFail::AnonymousBallotUnavailable)
    else {
        panic!("unavailable anonymous admission cannot become a completed rejection");
    };
    assert_eq!(
        refusal.reason(),
        ivm::error::ExecutionDeferral::VerifierInitializationUnavailable
    );
    let malformed = TransactionLimitError {
        reason: "actual completed limit check".into(),
    };
    let ExecutionAttemptError::Rejected(retained) = execution_attempt_from_admission_failure(
        AcceptTransactionFail::TransactionLimit(malformed.clone()),
    ) else {
        panic!("completed limit verdict must remain a rejection");
    };
    assert_eq!(retained, TransactionRejectionReason::LimitCheck(malformed));
}
