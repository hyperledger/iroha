//! The registration statement of a binding seat's credential and its verification
//! (design §3.2).
//!
//! A binding seat's acceptance carries [`CredentialRegistrationV1`]: the commitment `C`, the
//! authorization value `auth` and the proof `pi_reg`. The statement binds the authoritative
//! body context, the network, the registering account's authority binding, the assignment,
//! the attempt identifiers, the role, `B` and `C`; `D_reg` is recomputed by the proof crate
//! with the candidate descriptor. The proof shows that one secret opens `C` and produces
//! `auth`. It does not show authority, invitation, eligibility, freshness or uniqueness,
//! which the pending Core integration must check independently.

use iroha_data_model::{
    account::AccountId,
    governance::{
        anonymous_ballot::{
            BallotBodyContextV1, CredentialCommitmentV1, CredentialRegistrationV1,
            RegistrationAuthorizationV1, digests::authority_binding_v1,
        },
        types::AssignmentId,
    },
};
use iroha_parliament_ballot_proof::{
    profile::{ProfileError, Role},
    proving::{StatementError, VerifyError},
    registration::{self, RegistrationStatement},
};

use crate::{
    PROOF_ROW_V1,
    inputs::{ProofInputErrorV1, ProofValueV1, body_context_input_v1, registration_context_v1},
};

/// Why a registration does not verify, or could not be verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationErrorV1 {
    /// A typed input could not become a proof input.
    #[error(transparent)]
    Inputs(#[from] ProofInputErrorV1),
    /// The proof does not have the candidate row's exact registration length.
    #[error("a registration proof is {expected} bytes, got {actual}")]
    ProofLength {
        /// The exact length.
        expected: usize,
        /// The length supplied.
        actual: usize,
    },
    /// The proof does not verify for the statement.
    #[error("the registration proof is rejected")]
    Rejected,
    /// The statement could not be built: a local failure, not a fault of the registration.
    #[error("the registration statement could not be built: {0}")]
    Statement(StatementError),
    /// The proof backend failed (its `VerifyError::Backend`): a local inability to verify,
    /// not a rejection.
    #[error("the proof backend cannot verify registrations: {0}")]
    Backend(VerifyError),
}

impl From<VerifyError> for RegistrationErrorV1 {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::Rejected => Self::Rejected,
            VerifyError::ProofLength { expected, actual } => Self::ProofLength { expected, actual },
            VerifyError::Statement(StatementError::Profile(error)) => {
                Self::Inputs(ProofInputErrorV1::Profile(error))
            }
            VerifyError::Statement(error) => Self::Statement(error),
            backend @ VerifyError::Backend(_) => Self::Backend(backend),
        }
    }
}

impl RegistrationErrorV1 {
    /// Whether the failure is local (the node could not verify) rather than a fault of the
    /// registration.
    pub const fn is_local(&self) -> bool {
        matches!(
            self,
            Self::Statement(_)
                | Self::Backend(_)
                | Self::Inputs(
                    ProofInputErrorV1::Profile(_)
                        | ProofInputErrorV1::ProfileIdentity
                        | ProofInputErrorV1::Codec(_)
                )
        )
    }
}

/// The registration statement of `commitment` and `authorization` for the seat
/// `assignment_id` of the body, registered by `authority`.
///
/// # Errors
/// [`RegistrationErrorV1::Inputs`] for a non-binding body or an encoding failure.
pub fn registration_statement_v1(
    body_context: &BallotBodyContextV1,
    authority: &AccountId,
    assignment_id: &AssignmentId,
    commitment: &CredentialCommitmentV1,
    authorization: &RegistrationAuthorizationV1,
) -> Result<RegistrationStatement, RegistrationErrorV1> {
    let binding = authority_binding_v1(authority).map_err(ProofInputErrorV1::from)?;
    let statement = RegistrationStatement::new(
        body_context_input_v1(body_context)?,
        registration_context_v1(body_context, &binding, assignment_id)?,
        commitment.to_proof(),
        authorization.to_proof(),
    )
    .map_err(|error| match error {
        StatementError::Profile(error) => RegistrationErrorV1::Inputs(error.into()),
        error => RegistrationErrorV1::Statement(error),
    })?;
    Ok(statement)
}

/// Verify `registration` for the seat `assignment_id` of the body, registered by
/// `authority`, with the real registration relation on the candidate row.
///
/// The proof length is checked before anything is hashed; `B` and `D_reg` are recomputed
/// from the typed inputs, never taken from the caller.
///
/// # Errors
/// [`RegistrationErrorV1::ProofLength`] or [`RegistrationErrorV1::Rejected`] for an invalid
/// registration; the local variants ([`RegistrationErrorV1::is_local`]) when the node could
/// not verify.
pub fn verify_registration_v1(
    body_context: &BallotBodyContextV1,
    authority: &AccountId,
    assignment_id: &AssignmentId,
    registration: &CredentialRegistrationV1,
) -> Result<(), RegistrationErrorV1> {
    let proof = registration.proof.as_bytes();
    let expected = PROOF_ROW_V1.proof_bytes(Role::Registration);
    if proof.len() != expected {
        return Err(RegistrationErrorV1::ProofLength {
            expected,
            actual: proof.len(),
        });
    }
    let statement = registration_statement_v1(
        body_context,
        authority,
        assignment_id,
        &registration.commitment,
        &registration.authorization,
    )?;
    registration::verify(PROOF_ROW_V1, &statement, proof).map_err(RegistrationErrorV1::from)
}

/// Map a profile-compilation failure of the proof crate.
impl From<ProfileError> for RegistrationErrorV1 {
    fn from(error: ProfileError) -> Self {
        Self::Inputs(ProofInputErrorV1::Profile(error))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use iroha_data_model::governance::{
        anonymous_ballot::{BallotAuthorityBindingV1, RegistrationProofBytesV1},
        types::ParliamentBody,
    };
    use iroha_parliament_ballot_proof::{credential::CredentialSecret, proving::ProvingTape};

    use super::*;
    use crate::{
        inputs::proof_profile_v1,
        test_support::{account, body_context, secret_bytes, tape},
    };

    fn assignment() -> AssignmentId {
        AssignmentId::new([0x31; 32])
    }

    /// One honest registration of member 0, proved once with a fixed tape.
    fn registration() -> CredentialRegistrationV1 {
        static REGISTRATION: OnceLock<CredentialRegistrationV1> = OnceLock::new();
        REGISTRATION
            .get_or_init(|| {
                let profile = proof_profile_v1().expect("profile");
                let secret = CredentialSecret::from_bytes(&secret_bytes(0));
                let binding = authority_binding_v1(&account()).expect("binding");
                let statement = RegistrationStatement::for_secret(
                    &profile,
                    &secret,
                    body_context_input_v1(&body_context()).expect("body"),
                    registration_context_v1(&body_context(), &binding, &assignment())
                        .expect("context"),
                )
                .expect("statement");
                let proof = registration::prove(
                    PROOF_ROW_V1,
                    &statement,
                    &secret,
                    ProvingTape::from_bytes(&tape(0x21)),
                )
                .expect("honest proof");
                CredentialRegistrationV1 {
                    commitment: CredentialCommitmentV1::from_proof(statement.commitment()),
                    authorization: RegistrationAuthorizationV1::from_proof(statement.auth()),
                    proof: RegistrationProofBytesV1::new(proof).expect("exact length"),
                }
            })
            .clone()
    }

    #[test]
    fn an_honest_registration_verifies_through_the_typed_inputs() {
        let registration = registration();
        assert_eq!(
            verify_registration_v1(&body_context(), &account(), &assignment(), &registration),
            Ok(())
        );
        let statement = registration_statement_v1(
            &body_context(),
            &account(),
            &assignment(),
            &registration.commitment,
            &registration.authorization,
        )
        .expect("statement");
        assert_eq!(
            statement.body_context().as_bytes(),
            body_context_input_v1(&body_context())
                .expect("body")
                .as_bytes()
        );
        assert_eq!(statement.commitment(), &registration.commitment.to_proof());
    }

    #[test]
    fn a_registration_is_bound_to_every_statement_input() {
        let registration = registration();
        let rejected = Err(RegistrationErrorV1::Rejected);
        let other_account = AccountId::new(
            "ed0120E2ECD69DA5833EC10FB3DFAED83A07E5B9CBE9BC39484F0F7DDEC8B46253428B"
                .parse()
                .expect("public key"),
        );
        assert_eq!(
            verify_registration_v1(
                &body_context(),
                &other_account,
                &assignment(),
                &registration
            ),
            rejected
        );
        assert_eq!(
            verify_registration_v1(
                &body_context(),
                &account(),
                &AssignmentId::new([0x32; 32]),
                &registration
            ),
            rejected
        );
        let mut other_body = body_context();
        other_body.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(
            verify_registration_v1(&other_body, &account(), &assignment(), &registration),
            rejected
        );
        let mut other_network = body_context();
        other_network.network_id = crate::test_support::other_network_id();
        assert_eq!(
            verify_registration_v1(&other_network, &account(), &assignment(), &registration),
            rejected
        );
        let mut changed = registration.clone();
        let mut commitment = changed.commitment.into_bytes();
        commitment[0] ^= 1;
        changed.commitment = CredentialCommitmentV1::new(commitment);
        assert_eq!(
            verify_registration_v1(&body_context(), &account(), &assignment(), &changed),
            rejected
        );
        let mut changed = registration.clone();
        let mut auth = changed.authorization.into_bytes();
        auth[63] ^= 0x80;
        changed.authorization = RegistrationAuthorizationV1::new(auth);
        assert_eq!(
            verify_registration_v1(&body_context(), &account(), &assignment(), &changed),
            rejected
        );
        let mut changed = registration;
        let mut proof = changed.proof.into_bytes();
        proof[12_345] ^= 0x04;
        changed.proof = RegistrationProofBytesV1::new(proof).expect("exact length");
        assert_eq!(
            verify_registration_v1(&body_context(), &account(), &assignment(), &changed),
            rejected
        );
    }

    #[test]
    fn public_bodies_and_backend_failures_are_typed() {
        let mut public = body_context();
        public.body_role = ParliamentBody::ReviewPanel;
        let error = registration_statement_v1(
            &public,
            &account(),
            &assignment(),
            &CredentialCommitmentV1::new([1; 128]),
            &RegistrationAuthorizationV1::new([2; 64]),
        )
        .expect_err("public body");
        assert!(matches!(
            error,
            RegistrationErrorV1::Inputs(ProofInputErrorV1::NotBindingBody { .. })
        ));
        assert!(!error.is_local());
        assert_eq!(
            RegistrationErrorV1::from(VerifyError::ProofLength {
                expected: 1,
                actual: 2
            }),
            RegistrationErrorV1::ProofLength {
                expected: 1,
                actual: 2
            }
        );
        let statement =
            RegistrationErrorV1::from(VerifyError::Statement(StatementError::ListDigest));
        assert_eq!(
            statement,
            RegistrationErrorV1::Statement(StatementError::ListDigest)
        );
        assert!(statement.is_local());
        let profile = RegistrationErrorV1::from(ProfileError::DescriptorLength { actual: 1 });
        assert!(profile.is_local());
        assert!(!RegistrationErrorV1::Rejected.is_local());
        let _ = BallotAuthorityBindingV1::LENGTH;
    }
}
