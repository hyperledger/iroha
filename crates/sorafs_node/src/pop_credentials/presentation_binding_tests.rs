//! Exact recipient binding for proof API authentication and authorization consumption.

use super::*;
use sorafs_manifest::pop_credentials::{
    POP_CREDENTIAL_TREE_DEPTH_V1, POP_MEMBERSHIP_PROOF_VERSION_V1, POP_REVOCATION_TREE_DEPTH_V1,
    PopEligibilityClassV1, PopMembershipProofSystemV1, PopMembershipVerifierMaterialV1,
};
use std::sync::Arc;

#[derive(Debug)]
struct BindingAuthenticator;

impl PopCredentialApiAuthenticator for BindingAuthenticator {
    fn authenticate(
        &self,
        _credential: &[u8],
        _action: PopCredentialApiActionV1,
        _binding: [u8; 32],
        _epoch: u64,
    ) -> Result<PopAuthenticatedPrincipalV1, String> {
        Ok(PopAuthenticatedPrincipalV1 {
            principal_digest: [0x31; 32],
            expires_at_epoch: 101,
            request_authority: PopRequestAuthorityV1::CallerSignedTransaction,
        })
    }
}

// This serializable fixture exercises request binding only; it is not a cryptographic proof.
fn authentication_proof() -> PopMembershipProofV1 {
    PopMembershipProofV1 {
        version: POP_MEMBERSHIP_PROOF_VERSION_V1,
        eligibility_class: PopEligibilityClassV1::General,
        commitment_root: [0x11; 32],
        commitment_tree_version: 1,
        revocation_root: [0x12; 32],
        revocation_list_version: 1,
        nullifier: [0x13; 32],
        challenge_digest: [0x14; 32],
        verifier_context: "moderation.assignment.v1".to_owned(),
        presentation_binding_digest: [0x15; 32],
        proof_system: PopMembershipProofSystemV1::NativePipaRV1,
        verifier_material: PopMembershipVerifierMaterialV1 {
            circuit_id: "sorafs-pop-membership-pipa-r-v1".to_owned(),
            circuit_k: 14,
            credential_tree_depth: POP_CREDENTIAL_TREE_DEPTH_V1,
            revocation_tree_depth: POP_REVOCATION_TREE_DEPTH_V1,
            parameter_digest: [0x16; 32],
            verifying_key_digest: [0x17; 32],
        },
        proof_bytes: vec![0x18; 64],
        expires_at_epoch: 200,
    }
}

#[test]
fn wallet_proof_authorization_cannot_move_to_another_recipient() {
    let api = PopCredentialApiV1::new(Arc::new(BindingAuthenticator));
    let authorization = api
        .authorize_prove_membership(b"credential", [1; 32], [2; 32], "context", [3; 32], 100)
        .expect("authenticate original recipient");
    let original = wallet_prove_api_binding([1; 32], [2; 32], "context", [3; 32]);
    assert_eq!(
        api.verify_authorization(
            &authorization,
            PopCredentialApiActionV1::ProveMembership,
            original,
            100,
            false,
        ),
        Ok(())
    );
    assert_eq!(
        api.consume_authorization(
            authorization,
            PopCredentialApiActionV1::ProveMembership,
            wallet_prove_api_binding([1; 32], [2; 32], "context", [4; 32]),
            100,
            false,
        ),
        Err(PopCredentialServiceError::Unauthorized)
    );
}

#[test]
fn verification_authorization_binds_both_proof_and_expected_recipient() {
    let api = PopCredentialApiV1::new(Arc::new(BindingAuthenticator));
    let proof = authentication_proof();
    let authorization = api
        .authorize_verify_membership(
            b"credential",
            &proof,
            proof.challenge_digest,
            &proof.verifier_context,
            proof.presentation_binding_digest,
            100,
        )
        .expect("authenticate original proof and recipient");
    let binding = |candidate: &PopMembershipProofV1, recipient| {
        verify_membership_api_binding(
            candidate,
            proof.challenge_digest,
            &proof.verifier_context,
            recipient,
        )
        .expect("canonical authentication binding")
    };
    assert_eq!(
        api.verify_authorization(
            &authorization,
            PopCredentialApiActionV1::VerifyMembership,
            binding(&proof, proof.presentation_binding_digest),
            100,
            false,
        ),
        Ok(())
    );
    let mut substituted = proof.clone();
    substituted.presentation_binding_digest = [0x21; 32];
    for changed in [
        binding(&proof, substituted.presentation_binding_digest),
        binding(&substituted, proof.presentation_binding_digest),
        binding(&substituted, substituted.presentation_binding_digest),
    ] {
        assert_eq!(
            api.verify_authorization(
                &authorization,
                PopCredentialApiActionV1::VerifyMembership,
                changed,
                100,
                false,
            ),
            Err(PopCredentialServiceError::Unauthorized)
        );
    }
    assert_eq!(substituted.nullifier, proof.nullifier);
}

#[test]
fn proof_authorization_rejects_zero_recipient_bindings() {
    let api = PopCredentialApiV1::new(Arc::new(BindingAuthenticator));
    let proof = authentication_proof();
    let expected = Err(PopCredentialServiceError::InvalidInput {
        field: "presentation_binding_digest",
    });
    assert_eq!(
        api.authorize_prove_membership(b"credential", [1; 32], [2; 32], "context", [0; 32], 100),
        expected
    );
    assert_eq!(
        api.authorize_verify_membership(
            b"credential",
            &proof,
            proof.challenge_digest,
            &proof.verifier_context,
            [0; 32],
            100,
        ),
        expected
    );
}
