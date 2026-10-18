//! Canonical proof inputs and the `P16`-bound digests of the typed ballot values
//! (integration decision 7).
//!
//! The proof crate takes its public inputs as bounded opaque byte strings and binds the
//! construction domain `P16` into `B`, `R`, `scope`, `policy_hash`, `D_reg` and `D_v`. This
//! module produces exactly those inputs from the data-model values:
//!
//! | Proof input | Typed value | Bound |
//! | --- | --- | --- |
//! | `Enc(body_context)` | [`BallotBodyContextV1`] | 4,096 bytes |
//! | `Enc(network_id)` | [`NetworkId`] | 256 bytes |
//! | `Enc(authority)` | [`BallotAuthorityBindingV1`] of the registering account | 256 bytes |
//! | `Enc(assignment_id)` | [`AssignmentId`] | 256 bytes |
//! | `Enc(governance_attempt_id)` | [`GovernanceAttemptId`] | 256 bytes |
//! | `Enc(election_attempt_id)` | [`BodyElectionAttemptId`] | 256 bytes |
//! | `Enc(body_role)` | [`ParliamentBody`], the Policy or Confirmation Jury only | 256 bytes |
//! | `Enc(body_instance_id)` | [`BodyInstanceId`] | 256 bytes |
//!
//! `Enc` is the data model's pinned canonical frame
//! ([`iroha_data_model::governance::anonymous_ballot::framing::enc`]). `B`, `R`, `scope` and
//! `policy_hash` are computed by the proof crate's own functions; nothing here re-implements
//! them. [`ProofValueV1`] converts the fixed-length data-model values to and from the proof
//! crate's types without loss.

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    governance::{
        anonymous_ballot::{
            AnonymousBallotCodecErrorV1, BallotAuthorityBindingV1, BallotBodyContextV1,
            BallotChoiceV1, BallotContextErrorV1, BallotScopeV1, CredentialCommitmentV1, Digest512,
            FrozenBallotPolicyV1, NullifierV1, ProofProfileIdV1, RegistrationAuthorizationV1,
            SealedCredentialListV1, SealedRegistrationPairV1, VoteAuthorizationV1,
            digests::{authority_binding_v1, registration_mapping_digest_v1},
            framing::enc,
        },
        types::{
            AssignmentId, BodyElectionAttemptId, BodyInstanceId, GovernanceAttemptId,
            ParliamentBody,
        },
    },
};
use iroha_parliament_ballot_proof::{
    credential::{self, RegistrationContext},
    framing::{BodyContext, Commitment, Digest64, FramingError, Nullifier, OpaqueField},
    profile::{Profile, ProfileError},
    sealed_list::{ListError, SealedList},
    vote::Vote,
};

use crate::PROOF_ROW_V1;

/// Why a typed value could not become a proof input or a `P16`-bound digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofInputErrorV1 {
    /// Only the Policy and Confirmation Juries cast anonymous ballots.
    #[error("{body:?} is not a binding jury")]
    NotBindingBody {
        /// The body supplied.
        body: ParliamentBody,
    },
    /// A pinned `Enc` frame could not be produced.
    #[error(transparent)]
    Codec(#[from] AnonymousBallotCodecErrorV1),
    /// An encoding exceeds its opaque-input bound, or a frame could not be built.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// The proof crate refuses the sealed list.
    #[error(transparent)]
    List(#[from] ListError),
    /// A data-model structure is invalid.
    #[error(transparent)]
    Structure(#[from] BallotContextErrorV1),
    /// The proof backend could not compile the candidate descriptor.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The compiled candidate descriptor digest is not [`ProofProfileIdV1::V1`].
    #[error("the compiled candidate descriptor digest is not the V1 profile identifier")]
    ProfileIdentity,
}

/// Lossless conversion of a fixed-length data-model value to and from the proof crate's
/// type of the same bytes.
pub trait ProofValueV1: Sized {
    /// The proof crate's type.
    type Proof;

    /// The proof crate's value of exactly these bytes.
    fn to_proof(&self) -> Self::Proof;

    /// The data-model value of exactly these bytes.
    fn from_proof(value: &Self::Proof) -> Self;
}

/// [`ProofValueV1`] for the 64-byte values, which the proof crate types as [`Digest64`].
macro_rules! digest_value {
    ($($name:ty),+ $(,)?) => {$(
        impl ProofValueV1 for $name {
            type Proof = Digest64;

            fn to_proof(&self) -> Digest64 {
                Digest64(*self.as_bytes())
            }

            fn from_proof(value: &Digest64) -> Self {
                Self::new(value.0)
            }
        }
    )+};
}

digest_value!(
    Digest512,
    BallotScopeV1,
    VoteAuthorizationV1,
    RegistrationAuthorizationV1,
    ProofProfileIdV1,
);

impl ProofValueV1 for CredentialCommitmentV1 {
    type Proof = Commitment;

    fn to_proof(&self) -> Commitment {
        Commitment(*self.as_bytes())
    }

    fn from_proof(value: &Commitment) -> Self {
        Self::new(value.0)
    }
}

impl ProofValueV1 for NullifierV1 {
    type Proof = Nullifier;

    fn to_proof(&self) -> Nullifier {
        Nullifier(*self.as_bytes())
    }

    fn from_proof(value: &Nullifier) -> Self {
        Self::new(value.0)
    }
}

impl ProofValueV1 for BallotChoiceV1 {
    type Proof = Vote;

    fn to_proof(&self) -> Vote {
        match self {
            Self::Aye => Vote::Aye,
            Self::Nay => Vote::Nay,
            Self::Abstain => Vote::Abstain,
        }
    }

    fn from_proof(value: &Vote) -> Self {
        match value {
            Vote::Aye => Self::Aye,
            Vote::Nay => Self::Nay,
            Vote::Abstain => Self::Abstain,
        }
    }
}

/// Compile the V1 proof profile (the candidate row) and check that its descriptor digest
/// is the public profile identifier [`ProofProfileIdV1::V1`].
///
/// # Errors
/// [`ProofInputErrorV1::Profile`] if the backend lacks its tables and
/// [`ProofInputErrorV1::ProfileIdentity`] if the compiled descriptor is another one.
pub fn proof_profile_v1() -> Result<Profile, ProofInputErrorV1> {
    let profile = Profile::new(PROOF_ROW_V1)?;
    if profile.descriptor_digest().as_bytes() == ProofProfileIdV1::V1.as_bytes() {
        Ok(profile)
    } else {
        Err(ProofInputErrorV1::ProfileIdentity)
    }
}

/// Refuse every body but the two binding juries.
fn require_binding_body(body: ParliamentBody) -> Result<(), ProofInputErrorV1> {
    if matches!(
        body,
        ParliamentBody::PolicyJury | ParliamentBody::ConfirmationJury
    ) {
        Ok(())
    } else {
        Err(ProofInputErrorV1::NotBindingBody { body })
    }
}

/// `Enc(value)` as an opaque input of at most 256 bytes.
fn opaque_input<T: norito::NoritoSerialize>(value: &T) -> Result<OpaqueField, ProofInputErrorV1> {
    Ok(OpaqueField::new(&enc(value)?)?)
}

/// `Enc(body_context)`, the body-context input of at most 4,096 bytes.
///
/// # Errors
/// [`ProofInputErrorV1::NotBindingBody`] for a body other than a binding jury, or a codec
/// or bound failure.
pub fn body_context_input_v1(
    body_context: &BallotBodyContextV1,
) -> Result<BodyContext, ProofInputErrorV1> {
    require_binding_body(body_context.body_role)?;
    Ok(BodyContext::new(&enc(body_context)?)?)
}

/// `Enc(network_id)`.
///
/// # Errors
/// A codec or bound failure, which a network identity never causes.
pub fn network_id_input_v1(network_id: &NetworkId) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(network_id)
}

/// `Enc(authority)`: the frame of the nominal 64-byte authority binding.
///
/// # Errors
/// A codec or bound failure, which a binding never causes.
pub fn authority_input_v1(
    binding: &BallotAuthorityBindingV1,
) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(binding)
}

/// `Enc(authority)` of the registering account: the frame of
/// `authority_binding_v1(account)`, never a truncated account fingerprint.
///
/// # Errors
/// A codec failure of the account or the binding.
pub fn account_authority_input_v1(account: &AccountId) -> Result<OpaqueField, ProofInputErrorV1> {
    authority_input_v1(&authority_binding_v1(account)?)
}

/// `Enc(assignment_id)`.
///
/// # Errors
/// A codec or bound failure, which an identifier never causes.
pub fn assignment_input_v1(assignment_id: &AssignmentId) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(assignment_id)
}

/// `Enc(governance_attempt_id)`.
///
/// # Errors
/// A codec or bound failure, which an identifier never causes.
pub fn governance_attempt_input_v1(
    governance_attempt_id: &GovernanceAttemptId,
) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(governance_attempt_id)
}

/// `Enc(election_attempt_id)`.
///
/// # Errors
/// A codec or bound failure, which an identifier never causes.
pub fn election_attempt_input_v1(
    election_attempt_id: &BodyElectionAttemptId,
) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(election_attempt_id)
}

/// `Enc(body_role)`, restricted to the Policy and Confirmation Juries.
///
/// # Errors
/// [`ProofInputErrorV1::NotBindingBody`] for any other body.
pub fn body_role_input_v1(body_role: ParliamentBody) -> Result<OpaqueField, ProofInputErrorV1> {
    require_binding_body(body_role)?;
    opaque_input(&body_role)
}

/// `Enc(body_instance_id)`, the scope input of the sealed body.
///
/// # Errors
/// A codec or bound failure, which an identifier never causes.
pub fn body_instance_input_v1(
    body_instance_id: &BodyInstanceId,
) -> Result<OpaqueField, ProofInputErrorV1> {
    opaque_input(body_instance_id)
}

/// The six opaque registration inputs besides the body context, in `m_reg` order: the
/// network, authority, election and role come from the authoritative body context; the
/// authority is the binding of the registering account.
///
/// # Errors
/// [`ProofInputErrorV1::NotBindingBody`] for a non-binding body, or an encoding failure.
pub fn registration_context_v1(
    body_context: &BallotBodyContextV1,
    authority: &BallotAuthorityBindingV1,
    assignment_id: &AssignmentId,
) -> Result<RegistrationContext, ProofInputErrorV1> {
    Ok(RegistrationContext {
        network_id: network_id_input_v1(&body_context.network_id)?,
        authority: authority_input_v1(authority)?,
        assignment_id: assignment_input_v1(assignment_id)?,
        governance_attempt_id: governance_attempt_input_v1(&body_context.governance_attempt_id)?,
        election_attempt_id: election_attempt_input_v1(&body_context.election_attempt_id)?,
        body_role: body_role_input_v1(body_context.body_role)?,
    })
}

/// `B = SHA3-512(Frame("PARL/BODY/v1"; P16, Enc(body_context)))`, through the proof crate.
///
/// # Errors
/// As [`body_context_input_v1`].
pub fn body_digest_v1(body_context: &BallotBodyContextV1) -> Result<Digest512, ProofInputErrorV1> {
    let digest = credential::body_digest(&body_context_input_v1(body_context)?)?;
    Ok(Digest512::from_proof(&digest))
}

/// The proof crate's validated list of `list`'s commitments, in their order.
///
/// # Errors
/// [`ProofInputErrorV1::Structure`] or [`ProofInputErrorV1::List`] for an invalid list.
pub fn proof_list_v1(list: &SealedCredentialListV1) -> Result<SealedList, ProofInputErrorV1> {
    list.validate()?;
    Ok(SealedList::new(
        list.commitments
            .iter()
            .map(ProofValueV1::to_proof)
            .collect(),
    )?)
}

/// `R = SHA3-512(Frame("PARL/LIST/v1"; P16, B, u16_le(S), concat(L)))` of a sealed list,
/// through the proof crate, with `B` the list's own body-context digest.
///
/// # Errors
/// As [`proof_list_v1`].
pub fn list_digest_v1(list: &SealedCredentialListV1) -> Result<Digest512, ProofInputErrorV1> {
    let sealed = proof_list_v1(list)?;
    let digest = sealed.digest(&list.body_context_digest.to_proof())?;
    Ok(Digest512::from_proof(&digest))
}

/// The registration-mapping digest of a sealed list and its `(assignment_id, C)` pairs, with
/// `R` computed through the proof crate (integration decision 3).
///
/// # Errors
/// As [`list_digest_v1`], and [`ProofInputErrorV1::Structure`] for a mapping that is not
/// exactly the sealed list.
pub fn registration_mapping_v1(
    list: &SealedCredentialListV1,
    pairs: &[SealedRegistrationPairV1],
) -> Result<Digest512, ProofInputErrorV1> {
    let list_digest = list_digest_v1(list)?;
    Ok(registration_mapping_digest_v1(list, &list_digest, pairs)?)
}

/// `scope = SHA3-512(Frame("PARL/SCOPE/v1"; P16, Enc(network_id), proposal_digest,
/// Enc(governance_attempt_id), Enc(body_instance_id)))`, through the proof crate.
///
/// # Errors
/// An encoding failure, which these identifiers never cause.
pub fn scope_v1(
    network_id: &NetworkId,
    proposal_digest: &Digest512,
    governance_attempt_id: &GovernanceAttemptId,
    body_instance_id: &BodyInstanceId,
) -> Result<BallotScopeV1, ProofInputErrorV1> {
    let digest = credential::scope_digest(
        &network_id_input_v1(network_id)?,
        &proposal_digest.to_proof(),
        &governance_attempt_input_v1(governance_attempt_id)?,
        &body_instance_input_v1(body_instance_id)?,
    )?;
    Ok(BallotScopeV1::from_proof(&digest))
}

/// `policy_hash = SHA3-512(Frame("PARL/POLICY/v1"; P16, Enc(policy)))`, through the proof
/// crate. It hashes the policy it is given; [`crate::context`] validates it.
///
/// # Errors
/// An encoding failure.
pub fn policy_hash_v1(policy: &FrozenBallotPolicyV1) -> Result<Digest512, ProofInputErrorV1> {
    let digest = credential::policy_hash(&enc(policy)?)?;
    Ok(Digest512::from_proof(&digest))
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::anonymous_ballot::framing::{decode_enc, frame_digest};
    use iroha_parliament_ballot_proof::{
        framing::{BODY_CONTEXT_MAX_BYTES, OPAQUE_FIELD_MAX_BYTES},
        profile::P16,
    };

    use super::*;
    use crate::test_support::{
        account, body_context, body_instance_id, commitment_of, policy, proposal_digest,
        sealed_list, secret_bytes,
    };

    #[test]
    fn fixed_values_convert_without_loss() {
        let digest = Digest512::new(core::array::from_fn(|i| u8::try_from(i).expect("small")));
        assert_eq!(digest.to_proof().0, *digest.as_bytes());
        assert_eq!(Digest512::from_proof(&digest.to_proof()), digest);
        let scope = BallotScopeV1::new([0x44; 64]);
        assert_eq!(BallotScopeV1::from_proof(&scope.to_proof()), scope);
        let auth_v = VoteAuthorizationV1::new([0x55; 64]);
        assert_eq!(VoteAuthorizationV1::from_proof(&auth_v.to_proof()), auth_v);
        let auth = RegistrationAuthorizationV1::new([0x56; 64]);
        assert_eq!(
            RegistrationAuthorizationV1::from_proof(&auth.to_proof()),
            auth
        );
        assert_eq!(
            ProofProfileIdV1::from_proof(&ProofProfileIdV1::V1.to_proof()),
            ProofProfileIdV1::V1
        );
        let commitment = CredentialCommitmentV1::new([0x77; 128]);
        assert_eq!(commitment.to_proof().0, [0x77; 128]);
        assert_eq!(
            CredentialCommitmentV1::from_proof(&commitment.to_proof()),
            commitment
        );
        let nullifier = NullifierV1::new([0x12; 128]);
        assert_eq!(NullifierV1::from_proof(&nullifier.to_proof()), nullifier);
        for choice in BallotChoiceV1::ALL {
            assert_eq!(choice.to_proof().byte(), choice.proof_code());
            assert_eq!(BallotChoiceV1::from_proof(&choice.to_proof()), choice);
        }
    }

    #[test]
    fn the_profile_is_the_compiled_candidate_row() {
        let profile = proof_profile_v1().expect("candidate profile");
        assert_eq!(profile.row(), PROOF_ROW_V1);
        assert_eq!(
            ProofProfileIdV1::from_proof(profile.descriptor_digest()),
            ProofProfileIdV1::V1
        );
    }

    #[test]
    fn opaque_inputs_are_the_pinned_frames_within_their_bounds() {
        let context = body_context();
        let encoded = body_context_input_v1(&context).expect("body context");
        assert_eq!(encoded.as_bytes(), &enc(&context).expect("enc")[..]);
        assert!(encoded.as_bytes().len() <= BODY_CONTEXT_MAX_BYTES);
        assert_eq!(
            decode_enc::<BallotBodyContextV1>(encoded.as_bytes()),
            Ok(context)
        );
        let binding = authority_binding_v1(&account()).expect("binding");
        let inputs = [
            network_id_input_v1(&context.network_id).expect("network"),
            authority_input_v1(&binding).expect("authority"),
            account_authority_input_v1(&account()).expect("account authority"),
            assignment_input_v1(&AssignmentId::new([1; 32])).expect("assignment"),
            governance_attempt_input_v1(&context.governance_attempt_id).expect("attempt"),
            election_attempt_input_v1(&context.election_attempt_id).expect("election"),
            body_role_input_v1(context.body_role).expect("role"),
            body_instance_input_v1(&body_instance_id()).expect("instance"),
        ];
        for input in &inputs {
            assert!(input.as_bytes().len() <= OPAQUE_FIELD_MAX_BYTES);
        }
        assert_eq!(inputs[1], inputs[2]);
        assert_eq!(inputs[1].as_bytes(), &enc(&binding).expect("enc")[..]);
        assert_eq!(
            inputs[0].as_bytes(),
            &enc(&context.network_id).expect("enc")[..]
        );
        let registration = registration_context_v1(&context, &binding, &AssignmentId::new([1; 32]))
            .expect("registration context");
        assert_eq!(
            registration.fields(),
            [
                inputs[0].as_bytes(),
                inputs[1].as_bytes(),
                inputs[3].as_bytes(),
                inputs[4].as_bytes(),
                inputs[5].as_bytes(),
                inputs[6].as_bytes(),
            ]
        );
    }

    #[test]
    fn only_binding_juries_have_role_inputs() {
        assert!(body_role_input_v1(ParliamentBody::ConfirmationJury).is_ok());
        assert_eq!(
            body_role_input_v1(ParliamentBody::ReviewPanel),
            Err(ProofInputErrorV1::NotBindingBody {
                body: ParliamentBody::ReviewPanel
            })
        );
        let mut public = body_context();
        public.body_role = ParliamentBody::AgendaCouncil;
        assert!(matches!(
            body_context_input_v1(&public),
            Err(ProofInputErrorV1::NotBindingBody { .. })
        ));
        assert!(body_digest_v1(&public).is_err());
        let binding = BallotAuthorityBindingV1::new([9; 64]);
        assert!(registration_context_v1(&public, &binding, &AssignmentId::new([1; 32])).is_err());
    }

    #[test]
    fn the_p16_digests_are_the_proof_crate_frames() {
        let context = body_context();
        let encoded = enc(&context).expect("enc");
        let body = body_digest_v1(&context).expect("B");
        assert_eq!(
            body,
            frame_digest(b"PARL/BODY/v1", &[&P16, &encoded]).expect("frame")
        );
        let list = sealed_list();
        let list_digest = list_digest_v1(&list).expect("R");
        let mut concat = Vec::new();
        for entry in &list.commitments {
            concat.extend_from_slice(entry.as_bytes());
        }
        assert_eq!(
            list_digest,
            frame_digest(
                b"PARL/LIST/v1",
                &[
                    &P16,
                    list.body_context_digest.as_bytes(),
                    &list.seats.to_le_bytes(),
                    &concat
                ]
            )
            .expect("frame")
        );
        assert_eq!(
            proof_list_v1(&list).expect("list").size(),
            usize::from(list.seats)
        );
        let scope = scope_v1(
            &context.network_id,
            &proposal_digest(),
            &context.governance_attempt_id,
            &body_instance_id(),
        )
        .expect("scope");
        assert_eq!(
            scope.as_bytes(),
            frame_digest(
                b"PARL/SCOPE/v1",
                &[
                    &P16,
                    &enc(&context.network_id).expect("enc"),
                    proposal_digest().as_bytes(),
                    &enc(&context.governance_attempt_id).expect("enc"),
                    &enc(&body_instance_id()).expect("enc"),
                ]
            )
            .expect("frame")
            .as_bytes()
        );
        let policy = policy();
        assert_eq!(
            policy_hash_v1(&policy).expect("policy hash"),
            frame_digest(b"PARL/POLICY/v1", &[&P16, &enc(&policy).expect("enc")]).expect("frame")
        );
        // Every input moves its digest.
        let mut other = context;
        other.election_attempt_id = BodyElectionAttemptId::new([0x23; 32]);
        assert_ne!(body_digest_v1(&other).expect("B"), body);
        assert_ne!(
            scope_v1(
                &context.network_id,
                &proposal_digest(),
                &context.governance_attempt_id,
                &BodyInstanceId::new([0x04; 32]),
            )
            .expect("scope"),
            scope
        );
        let mut changed = policy;
        changed.binding.vote_notice_ms += 1;
        assert_ne!(
            policy_hash_v1(&changed).expect("policy hash"),
            policy_hash_v1(&self::policy()).expect("policy hash")
        );
    }

    #[test]
    fn the_registration_mapping_uses_the_proof_crate_list_digest() {
        let list = sealed_list();
        let pairs: Vec<SealedRegistrationPairV1> = (0_u8..4)
            .map(|member| SealedRegistrationPairV1 {
                assignment_id: AssignmentId::new([member + 1; 32]),
                commitment: commitment_of(&secret_bytes(member)),
            })
            .collect();
        let digest = registration_mapping_v1(&list, &pairs).expect("mapping");
        assert_eq!(
            digest,
            registration_mapping_digest_v1(&list, &list_digest_v1(&list).expect("R"), &pairs)
                .expect("mapping")
        );
        assert!(registration_mapping_v1(&list, &pairs[..3]).is_err());
    }
}
