//! The authenticated ballot context and the immutable scoped verification context
//! (design §3.5 "validated list", integration decision 4).
//!
//! Core integration must derive [`AuthenticatedBallotContextV1`] from authenticated state:
//! the body context, the proposal digest, `B`, `R`, `S`, the complete ordered commitments, the profile, the
//! frozen policy and its `policy_hash`. [`build_context_v1`] assembles it from those inputs
//! and computes every derived field through the proof crate; [`check_context_v1`] recomputes
//! every derived field of a context received from elsewhere, so no supplied digest is ever
//! trusted.
//!
//! [`ScopedBallotContextV1`] is the verification context of design §3.5 option 2: an
//! immutable context constructed by those checks, bound to its body instance and therefore
//! to its scope, holding the proof crate's validated list and the context's canonical
//! encoding, computed once per scope for every stamp check. Every verifier, the admission
//! pipeline, the block decision, the corpus, the full verifier and the wallet take it.

use core::fmt;

use iroha_data_model::{
    NetworkId,
    governance::{
        anonymous_ballot::{
            AuthenticatedBallotContextV1, BallotBodyContextV1, BallotContextErrorV1, BallotScopeV1,
            Digest512, EncodedBallotContextV1, FrozenBallotPolicyV1, ProofProfileIdV1,
            SealedCredentialListV1,
        },
        types::BodyInstanceId,
    },
};
use iroha_parliament_ballot_proof::{framing::Digest64, sealed_list::SealedList};

use crate::inputs::{
    ProofInputErrorV1, ProofValueV1, body_digest_v1, list_digest_v1, policy_hash_v1, proof_list_v1,
    proof_profile_v1, scope_v1,
};

/// Why a ballot context cannot be built or is not authentic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContextErrorV1 {
    /// A proof input or `P16`-bound digest could not be produced.
    #[error(transparent)]
    Inputs(#[from] ProofInputErrorV1),
    /// The body context, list, policy or context is structurally invalid.
    #[error(transparent)]
    Structure(#[from] BallotContextErrorV1),
    /// Two authenticated inputs disagree (for example the list's body digest is not the
    /// body's `B`).
    #[error("the authenticated inputs disagree on {field}")]
    Mismatch {
        /// The disagreeing field.
        field: &'static str,
    },
    /// A received context carries a derived field that is not the recomputed value.
    #[error("the context's {field} is not the value recomputed from its inputs")]
    Derived {
        /// The field.
        field: &'static str,
    },
}

/// The proof crate's representation of a checked context.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProofParts {
    body_digest: Digest64,
    policy_hash: Digest64,
    list: SealedList,
}

/// Check `context` completely and return the proof crate's values of it.
fn derive_checked(context: &AuthenticatedBallotContextV1) -> Result<ProofParts, ContextErrorV1> {
    context.validate()?;
    let body_digest = body_digest_v1(&context.body_context)?;
    if body_digest != context.body_context_digest {
        return Err(ContextErrorV1::Derived {
            field: "body_context_digest",
        });
    }
    let list = proof_list_v1(&context.sealed_list()?)?;
    let list_digest = list
        .digest(&body_digest.to_proof())
        .map_err(ProofInputErrorV1::from)?;
    if Digest512::from_proof(&list_digest) != context.list_digest {
        return Err(ContextErrorV1::Derived {
            field: "list_digest",
        });
    }
    let policy_hash = policy_hash_v1(&context.policy)?;
    if policy_hash != context.policy_hash {
        return Err(ContextErrorV1::Derived {
            field: "policy_hash",
        });
    }
    Ok(ProofParts {
        body_digest: body_digest.to_proof(),
        policy_hash: policy_hash.to_proof(),
        list,
    })
}

/// Build the authenticated context of one binding body from its authoritative inputs:
/// the body context, the full proposal's `proposal_digest`, the sealed list and the frozen
/// policy. `B`, `R` and `policy_hash` are computed through the proof crate; `S` is the
/// list's length.
///
/// # Errors
/// [`ContextErrorV1::Structure`] for an invalid body context, list, policy or context
/// (including one above the 163,840-byte cap), [`ContextErrorV1::Mismatch`] when the list
/// was sealed for another body or the policy belongs to another role, and
/// [`ContextErrorV1::Inputs`] for an encoding failure.
pub fn build_context_v1(
    body_context: BallotBodyContextV1,
    proposal_digest: Digest512,
    list: &SealedCredentialListV1,
    policy: FrozenBallotPolicyV1,
) -> Result<AuthenticatedBallotContextV1, ContextErrorV1> {
    body_context.validate()?;
    list.validate()?;
    policy.validate().map_err(BallotContextErrorV1::from)?;
    if policy.body_role != body_context.body_role {
        return Err(ContextErrorV1::Mismatch { field: "body_role" });
    }
    let body_context_digest = body_digest_v1(&body_context)?;
    if list.body_context_digest != body_context_digest {
        return Err(ContextErrorV1::Mismatch {
            field: "body_context_digest",
        });
    }
    let list_digest = list_digest_v1(list)?;
    let policy_hash = policy_hash_v1(&policy)?;
    let context = AuthenticatedBallotContextV1 {
        body_context,
        proposal_digest,
        body_context_digest,
        list_digest,
        seats: list.seats,
        commitments: list.commitments.clone(),
        profile_id: ProofProfileIdV1::V1,
        policy,
        policy_hash,
    };
    context.validate()?;
    Ok(context)
}

/// Check a received context: its structure, its frozen policy, and every derived field
/// (`B`, `R`, `S` and `policy_hash`) recomputed through the proof crate.
///
/// # Errors
/// [`ContextErrorV1::Structure`] for an invalid structure, [`ContextErrorV1::Derived`] for
/// a derived field that is not the recomputed value, or [`ContextErrorV1::Inputs`].
pub fn check_context_v1(context: &AuthenticatedBallotContextV1) -> Result<(), ContextErrorV1> {
    derive_checked(context).map(|_| ())
}

/// The immutable verification context of one scope: a checked authenticated context bound
/// to its body instance, whose scope is recomputed from
/// `(network_id, proposal_digest, governance_attempt_id, body_instance_id)`.
///
/// It can only be constructed by the complete checks of [`Self::new`] (or
/// [`Self::build`]), which also confirm that the compiled proof row is the V1 profile.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedBallotContextV1 {
    scope: BallotScopeV1,
    body_instance_id: BodyInstanceId,
    context: AuthenticatedBallotContextV1,
    encoded: EncodedBallotContextV1,
    proof: ProofParts,
}

impl fmt::Debug for ScopedBallotContextV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedBallotContextV1")
            .field("scope", &self.scope)
            .field("body_instance_id", &self.body_instance_id)
            .field("body_role", &self.context.body_context.body_role)
            .field("seats", &self.context.seats)
            .field("list_digest", &self.context.list_digest)
            .field("policy_hash", &self.context.policy_hash)
            .finish_non_exhaustive()
    }
}

impl ScopedBallotContextV1 {
    /// Check `context` completely, bind it to the sealed `body_instance_id` and encode it
    /// once for the scope's stamp checks.
    ///
    /// # Errors
    /// As [`check_context_v1`], and [`ProofInputErrorV1::ProfileIdentity`] (inside
    /// [`ContextErrorV1::Inputs`]) if the compiled row is not the V1 profile.
    pub fn new(
        context: AuthenticatedBallotContextV1,
        body_instance_id: BodyInstanceId,
    ) -> Result<Self, ContextErrorV1> {
        proof_profile_v1()?;
        let proof = derive_checked(&context)?;
        let scope = scope_v1(
            &context.body_context.network_id,
            &context.proposal_digest,
            &context.body_context.governance_attempt_id,
            &body_instance_id,
        )?;
        let encoded = EncodedBallotContextV1::new(&context).map_err(ProofInputErrorV1::from)?;
        Ok(Self {
            scope,
            body_instance_id,
            context,
            encoded,
            proof,
        })
    }

    /// [`build_context_v1`] followed by [`Self::new`].
    ///
    /// # Errors
    /// As [`build_context_v1`] and [`Self::new`].
    pub fn build(
        body_context: BallotBodyContextV1,
        proposal_digest: Digest512,
        body_instance_id: BodyInstanceId,
        list: &SealedCredentialListV1,
        policy: FrozenBallotPolicyV1,
    ) -> Result<Self, ContextErrorV1> {
        Self::new(
            build_context_v1(body_context, proposal_digest, list, policy)?,
            body_instance_id,
        )
    }

    /// The recomputed ballot scope.
    pub fn scope(&self) -> &BallotScopeV1 {
        &self.scope
    }

    /// The sealed body instance.
    pub fn body_instance_id(&self) -> &BodyInstanceId {
        &self.body_instance_id
    }

    /// The checked authenticated context.
    pub fn context(&self) -> &AuthenticatedBallotContextV1 {
        &self.context
    }

    /// `Enc(context)`, encoded once at construction, for the scope's stamp checks.
    pub fn encoded_context(&self) -> &EncodedBallotContextV1 {
        &self.encoded
    }

    /// The network the body belongs to.
    pub fn network_id(&self) -> &NetworkId {
        &self.context.body_context.network_id
    }

    /// The authoritative body context.
    pub fn body_context(&self) -> &BallotBodyContextV1 {
        &self.context.body_context
    }

    /// The frozen policy snapshot.
    pub fn policy(&self) -> &FrozenBallotPolicyV1 {
        &self.context.policy
    }

    /// Sealed seats `S`.
    pub fn seats(&self) -> u16 {
        self.context.seats
    }

    /// Sealed-list digest `R`.
    pub fn list_digest(&self) -> &Digest512 {
        &self.context.list_digest
    }

    /// `policy_hash` of the frozen policy.
    pub fn policy_hash(&self) -> &Digest512 {
        &self.context.policy_hash
    }

    /// The proof profile, always [`ProofProfileIdV1::V1`].
    pub fn profile_id(&self) -> &ProofProfileIdV1 {
        &self.context.profile_id
    }

    /// The context, consuming the wrapper.
    pub fn into_context(self) -> AuthenticatedBallotContextV1 {
        self.context
    }

    /// `B` as the proof crate types it.
    pub(crate) fn proof_body_digest(&self) -> &Digest64 {
        &self.proof.body_digest
    }

    /// `policy_hash` as the proof crate types it.
    pub(crate) fn proof_policy_hash(&self) -> &Digest64 {
        &self.proof.policy_hash
    }

    /// The proof crate's validated list.
    pub(crate) fn proof_list(&self) -> &SealedList {
        &self.proof.list
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::{
        anonymous_ballot::{CredentialCommitmentV1, FrozenBallotPolicyErrorV1},
        types::ParliamentBody,
    };

    use super::*;
    use crate::{
        inputs::scope_v1,
        test_support::{
            body_context, body_instance_id, policy, proposal_digest, scoped_context, sealed_list,
        },
    };

    fn built() -> AuthenticatedBallotContextV1 {
        build_context_v1(body_context(), proposal_digest(), &sealed_list(), policy())
            .expect("fixture context")
    }

    #[test]
    fn a_built_context_carries_the_recomputed_digests() {
        let context = built();
        assert_eq!(
            context.body_context_digest,
            body_digest_v1(&body_context()).expect("B")
        );
        assert_eq!(
            context.list_digest,
            list_digest_v1(&sealed_list()).expect("R")
        );
        assert_eq!(
            context.policy_hash,
            policy_hash_v1(&policy()).expect("hash")
        );
        assert_eq!(context.seats, sealed_list().seats);
        assert_eq!(context.commitments, sealed_list().commitments);
        assert_eq!(context.profile_id, ProofProfileIdV1::V1);
        assert_eq!(check_context_v1(&context), Ok(()));
    }

    #[test]
    fn building_refuses_disagreeing_inputs() {
        let mut list = sealed_list();
        list.body_context_digest = Digest512::new([0x33; 64]);
        assert_eq!(
            build_context_v1(body_context(), proposal_digest(), &list, policy()),
            Err(ContextErrorV1::Mismatch {
                field: "body_context_digest"
            })
        );
        let mut confirmation = policy();
        confirmation.body_role = ParliamentBody::ConfirmationJury;
        assert_eq!(
            build_context_v1(
                body_context(),
                proposal_digest(),
                &sealed_list(),
                confirmation
            ),
            Err(ContextErrorV1::Mismatch { field: "body_role" })
        );
        let mut weak = policy();
        weak.binding.stamp_difficulty_bits = 20;
        assert!(matches!(
            build_context_v1(body_context(), proposal_digest(), &sealed_list(), weak),
            Err(ContextErrorV1::Structure(BallotContextErrorV1::Policy(
                FrozenBallotPolicyErrorV1::Parameter(_)
            )))
        ));
        let mut public = body_context();
        public.body_role = ParliamentBody::ReviewPanel;
        assert!(matches!(
            build_context_v1(public, proposal_digest(), &sealed_list(), policy()),
            Err(ContextErrorV1::Structure(
                BallotContextErrorV1::NotBindingBody { .. }
            ))
        ));
    }

    #[test]
    fn checking_recomputes_every_derived_field() {
        let context = built();
        let mut changed = context.clone();
        changed.body_context_digest = Digest512::new([1; 64]);
        assert_eq!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Derived {
                field: "body_context_digest"
            })
        );
        let mut changed = context.clone();
        changed.list_digest = Digest512::new([2; 64]);
        assert_eq!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Derived {
                field: "list_digest"
            })
        );
        let mut changed = context.clone();
        changed.policy_hash = Digest512::new([3; 64]);
        assert_eq!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Derived {
                field: "policy_hash"
            })
        );
        // A policy changed without its hash, a list changed without R, S without the list.
        let mut changed = context.clone();
        changed.policy.binding.vote_notice_ms += 1;
        assert_eq!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Derived {
                field: "policy_hash"
            })
        );
        let mut changed = context.clone();
        let last = changed.commitments.len() - 1;
        changed.commitments[last] = CredentialCommitmentV1::new([0xff; 128]);
        assert_eq!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Derived {
                field: "list_digest"
            })
        );
        let mut changed = context;
        changed.seats += 1;
        assert!(matches!(
            check_context_v1(&changed),
            Err(ContextErrorV1::Structure(
                BallotContextErrorV1::SeatCount { .. }
            ))
        ));
    }

    #[test]
    fn a_scoped_context_binds_the_recomputed_scope() {
        let scoped = scoped_context();
        let expected = scope_v1(
            &body_context().network_id,
            &proposal_digest(),
            &body_context().governance_attempt_id,
            &body_instance_id(),
        )
        .expect("scope");
        assert_eq!(scoped.scope(), &expected);
        assert_eq!(scoped.body_instance_id(), &body_instance_id());
        assert_eq!(scoped.context(), &built());
        assert_eq!(scoped.network_id(), &body_context().network_id);
        assert_eq!(scoped.body_context(), &body_context());
        assert_eq!(scoped.policy(), &policy());
        assert_eq!(scoped.seats(), 4);
        assert_eq!(scoped.list_digest(), &built().list_digest);
        assert_eq!(scoped.policy_hash(), &built().policy_hash);
        assert_eq!(scoped.profile_id(), &ProofProfileIdV1::V1);
        assert_eq!(
            scoped.proof_body_digest(),
            &built().body_context_digest.to_proof()
        );
        assert_eq!(scoped.proof_policy_hash(), &built().policy_hash.to_proof());
        assert_eq!(scoped.proof_list().size(), 4);
        assert_eq!(
            scoped.encoded_context(),
            &EncodedBallotContextV1::new(&built()).expect("encoded")
        );
        assert_eq!(
            scoped.encoded_context().stamp_difficulty_bits(),
            policy().binding.stamp_difficulty_bits
        );
        let debug = format!("{scoped:?}");
        assert!(debug.contains("ScopedBallotContextV1") && debug.contains("seats"));
        // Another instance is another scope; a tampered context is refused.
        let other =
            ScopedBallotContextV1::new(built(), BodyInstanceId::new([0x04; 32])).expect("context");
        assert_ne!(other.scope(), scoped.scope());
        let mut tampered = built();
        tampered.list_digest = Digest512::new([0; 64]);
        assert!(ScopedBallotContextV1::new(tampered, body_instance_id()).is_err());
        assert_eq!(
            ScopedBallotContextV1::clone(&scoped).into_context(),
            built()
        );
    }
}
