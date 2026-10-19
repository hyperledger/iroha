//! Ballot statements, proof verification, the ordered admission checks and the shared
//! block-execution decision (design §3.5–§3.6, integration decisions 1 and 9).
//!
//! - [`vote_statement_v1`] builds the proof statement of a ballot from its scope's checked
//!   context: `B`, `R`, `S`, the complete list and `policy_hash` come from the context, the
//!   scope, nullifier, `auth_v` and vote from the ballot; the proof crate recomputes `D_v`.
//! - [`verify_ballot_proof_v1`] runs the real vote relation on the candidate row.
//! - [`precheck_admission_v1`] performs the seven queue-admission checks in their stated
//!   order; [`AdmittedBallotV1::verify_proof`] is the separate expensive step, and
//!   [`VerifiedBallotV1::recheck`] repeats the state checks before insertion.
//! - [`decide_block_ballot_v1`] is the block-execution decision used by the full verifier
//!   and intended for Core integration: an invalid encoding, network, unknown scope,
//!   profile, stamp or proof invalidates the block; a valid ballot of a known scope is fully
//!   verified first, then
//!   a ballot outside the casting window is rejected before a duplicate is, and otherwise it
//!   is accepted.
//!
//! A local inability to verify (a backend or encoding failure on this node) is
//! [`VerificationUnavailableV1`], never an invalid ballot or proof.

mod admission;
mod block;

use iroha_data_model::governance::anonymous_ballot::{
    AnonymousBallotCodecErrorV1, AnonymousBallotEnvelopeV1, AnonymousBallotV1,
};
use iroha_parliament_ballot_proof::{
    proving::VerifyError,
    vote::{self, VoteStatement},
};

pub use self::{
    admission::{
        AdmissionErrorV1, AdmissionRejectionV1, AdmissionScopeV1, AdmissionStateV1,
        AdmittedBallotV1, CastingWindowStatusV1, VerifiedBallotV1, precheck_admission_v1,
    },
    block::{
        BlockBallotDecisionV1, BlockBallotStateV1, BlockBallotValidityV1, BlockInvalidReasonV1,
        ValidBlockBallotV1, check_block_ballot_v1, decide_block_ballot_v1, decide_valid_ballot_v1,
    },
};
use crate::{PROOF_ROW_V1, context::ScopedBallotContextV1, inputs::ProofValueV1};

/// A local inability to verify a ballot: the node failed, not the ballot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationUnavailableV1 {
    /// The proof verifier could not run (its backend or its statement construction
    /// failed); carries the proof crate's error.
    #[error("the proof verifier cannot run: {0}")]
    Verifier(VerifyError),
    /// A stamp or envelope digest could not be computed.
    #[error("a ballot digest could not be computed: {0}")]
    Codec(AnonymousBallotCodecErrorV1),
    /// The caller's state answered a scope lookup with another scope's context.
    #[error("the state returned the context of another scope")]
    ScopeLookup,
}

/// Why a ballot's proof check did not accept it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BallotProofErrorV1 {
    /// The envelope names another network than the context.
    #[error("the envelope's network is not the context's network")]
    WrongNetwork,
    /// The ballot's scope is not the context's scope.
    #[error("the ballot's scope is not the context's scope")]
    WrongScope,
    /// The ballot names another proof profile.
    #[error("the ballot names another proof profile")]
    WrongProfile,
    /// The proof does not have the candidate row's exact vote length.
    #[error("a ballot proof is {expected} bytes, got {actual}")]
    ProofLength {
        /// The exact length.
        expected: usize,
        /// The length supplied.
        actual: usize,
    },
    /// The proof does not verify for the ballot's statement.
    #[error("the ballot proof is rejected")]
    Rejected,
    /// The node could not verify.
    #[error(transparent)]
    Unavailable(#[from] VerificationUnavailableV1),
}

/// The authoritative casting window of one scope at block execution (design §3.4,
/// integration decision 9).
///
/// Casting opens in the block-start pass of the opening block `h_open`, so ballots in that
/// block are inside. The `EstablishCastingClock` prelude of `h_open + 1` sets `closing_ms`
/// before that block's transactions; from then on the window is half-open: a block whose
/// timestamp is at or beyond `closing_ms` is outside, even while the closure transition is
/// deferred. The closure runs at the block start of its height, so transactions in that
/// block and later are outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CastingWindowV1 {
    /// Height `h_open` of the opening block (`s0.height`).
    pub opening_height: u64,
    /// `closing_ms`, established at `h_open + 1`; `None` before that block.
    pub closing_ms: Option<u64>,
    /// Height whose block-start pass closed the ballot, once it has run.
    pub closure_height: Option<u64>,
}

impl CastingWindowV1 {
    /// Whether a ballot executed in the block at `height` with block time `timestamp_ms` is
    /// inside the window. A height after `h_open` without an established casting clock is
    /// outside: the clock is mandatory at `h_open + 1`.
    pub const fn is_open_at(&self, height: u64, timestamp_ms: u64) -> bool {
        if height < self.opening_height {
            return false;
        }
        if let Some(closure_height) = self.closure_height
            && height >= closure_height
        {
            return false;
        }
        if height == self.opening_height {
            return true;
        }
        match self.closing_ms {
            Some(closing_ms) => timestamp_ms < closing_ms,
            None => false,
        }
    }
}

/// The vote statement of `ballot` under its scope's checked context.
///
/// # Errors
/// [`BallotProofErrorV1::WrongScope`] or [`BallotProofErrorV1::WrongProfile`] if the ballot
/// does not belong to the context, and [`BallotProofErrorV1::Unavailable`] if the statement
/// cannot be built.
pub fn vote_statement_v1(
    context: &ScopedBallotContextV1,
    ballot: &AnonymousBallotV1,
) -> Result<VoteStatement, BallotProofErrorV1> {
    if ballot.scope != *context.scope() {
        return Err(BallotProofErrorV1::WrongScope);
    }
    if !ballot.profile_id.is_v1() {
        return Err(BallotProofErrorV1::WrongProfile);
    }
    VoteStatement::new(
        *context.proof_body_digest(),
        ballot.scope.to_proof(),
        context.proof_list(),
        ballot.nullifier.to_proof(),
        ballot.auth_v.to_proof(),
        ballot.vote.to_proof(),
        *context.proof_policy_hash(),
    )
    .map_err(|error| VerificationUnavailableV1::Verifier(VerifyError::Statement(error)).into())
}

/// Verify the ballot proof of `envelope` against its scope's checked context with the real
/// vote relation on the candidate row. The proof's exact length is checked before anything
/// is hashed; `D_v` is recomputed from the complete statement.
///
/// # Errors
/// [`BallotProofErrorV1::WrongNetwork`], [`BallotProofErrorV1::WrongScope`],
/// [`BallotProofErrorV1::WrongProfile`], [`BallotProofErrorV1::ProofLength`] or
/// [`BallotProofErrorV1::Rejected`] for a ballot that does not verify, and
/// [`BallotProofErrorV1::Unavailable`] when the node could not verify.
pub fn verify_ballot_proof_v1(
    context: &ScopedBallotContextV1,
    envelope: &AnonymousBallotEnvelopeV1,
) -> Result<(), BallotProofErrorV1> {
    if envelope.network_id != *context.network_id() {
        return Err(BallotProofErrorV1::WrongNetwork);
    }
    let statement = vote_statement_v1(context, &envelope.ballot)?;
    match vote::verify(PROOF_ROW_V1, &statement, envelope.ballot.proof.as_bytes()) {
        Ok(()) => Ok(()),
        Err(VerifyError::Rejected) => Err(BallotProofErrorV1::Rejected),
        Err(VerifyError::ProofLength { expected, actual }) => {
            Err(BallotProofErrorV1::ProofLength { expected, actual })
        }
        Err(error) => Err(VerificationUnavailableV1::Verifier(error).into()),
    }
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::{
        anonymous_ballot::{
            BallotChoiceV1, BallotProofBytesV1, NullifierV1, ProofProfileIdV1, VoteAuthorizationV1,
        },
        types::BodyInstanceId,
    };
    use iroha_parliament_ballot_proof::proving::StatementError;

    use super::*;
    use crate::test_support::{
        AYE_0, NAY_1, body_context, body_instance_id, fixture_envelope, forged_envelope,
        other_network_id, policy, proposal_digest, scoped_context, sealed_list,
    };

    #[test]
    fn the_window_opens_at_the_opening_block_and_closes_half_open() {
        let opened = CastingWindowV1 {
            opening_height: 100,
            closing_ms: None,
            closure_height: None,
        };
        assert!(!opened.is_open_at(99, 0));
        assert!(opened.is_open_at(100, 5));
        // Without the mandatory casting clock no later block is inside.
        assert!(!opened.is_open_at(101, 6));
        let clocked = CastingWindowV1 {
            closing_ms: Some(1_000),
            ..opened
        };
        assert!(clocked.is_open_at(100, 2_000));
        assert!(clocked.is_open_at(101, 999));
        assert!(!clocked.is_open_at(101, 1_000));
        assert!(!clocked.is_open_at(150, 1_500));
        let closed = CastingWindowV1 {
            closure_height: Some(120),
            ..clocked
        };
        assert!(closed.is_open_at(119, 999));
        assert!(!closed.is_open_at(120, 999));
        assert!(!closed.is_open_at(121, 0));
    }

    #[test]
    fn an_honest_ballot_proof_verifies_and_binds_its_statement() {
        let context = scoped_context();
        let envelope = fixture_envelope(AYE_0);
        assert_eq!(verify_ballot_proof_v1(&context, &envelope), Ok(()));
        let statement = vote_statement_v1(&context, &envelope.ballot).expect("statement");
        assert_eq!(statement.size, 4);
        assert_eq!(statement.vote, 0);
        assert_eq!(statement.list_digest, context.list_digest().to_proof());
        // The vote, the nullifier and the authorization value are bound by the proof.
        let rejected = Err(BallotProofErrorV1::Rejected);
        let mut changed = envelope.clone();
        changed.ballot.vote = BallotChoiceV1::Nay;
        assert_eq!(verify_ballot_proof_v1(&context, &changed), rejected);
        let mut changed = envelope.clone();
        let mut nullifier = changed.ballot.nullifier.into_bytes();
        nullifier[127] ^= 1;
        changed.ballot.nullifier = NullifierV1::new(nullifier);
        assert_eq!(verify_ballot_proof_v1(&context, &changed), rejected);
        let mut changed = envelope.clone();
        let mut auth_v = changed.ballot.auth_v.into_bytes();
        auth_v[0] ^= 0x80;
        changed.ballot.auth_v = VoteAuthorizationV1::new(auth_v);
        assert_eq!(verify_ballot_proof_v1(&context, &changed), rejected);
        // A flipped proof byte, with or without a valid stamp, does not verify.
        assert_eq!(
            verify_ballot_proof_v1(&context, &forged_envelope()),
            rejected
        );
        let mut changed = envelope;
        let mut proof = changed.ballot.proof.into_bytes();
        proof[BallotProofBytesV1::LENGTH - 5] ^= 0x10;
        changed.ballot.proof = BallotProofBytesV1::new(proof).expect("exact length");
        assert_eq!(verify_ballot_proof_v1(&context, &changed), rejected);
    }

    #[test]
    fn a_ballot_is_bound_to_its_network_scope_profile_list_and_policy() {
        let context = scoped_context();
        let envelope = fixture_envelope(NAY_1);
        let mut changed = envelope.clone();
        changed.network_id = other_network_id();
        assert_eq!(
            verify_ballot_proof_v1(&context, &changed),
            Err(BallotProofErrorV1::WrongNetwork)
        );
        let mut changed = envelope.clone();
        changed.ballot.profile_id = ProofProfileIdV1::new([0; 64]);
        assert_eq!(
            verify_ballot_proof_v1(&context, &changed),
            Err(BallotProofErrorV1::WrongProfile)
        );
        // Replayed into another body instance's scope (same list and policy).
        let other_instance =
            ScopedBallotContextV1::new(context.context().clone(), BodyInstanceId::new([0x04; 32]))
                .expect("context");
        assert_eq!(
            verify_ballot_proof_v1(&other_instance, &envelope),
            Err(BallotProofErrorV1::WrongScope)
        );
        let mut moved = envelope.clone();
        moved.ballot.scope = *other_instance.scope();
        assert_eq!(
            verify_ballot_proof_v1(&other_instance, &moved),
            Err(BallotProofErrorV1::Rejected)
        );
        // A context with another sealed list or another policy for the same scope.
        let mut longer = sealed_list();
        // Greater than every SHAKE-derived commitment of the fixture roster.
        longer.commitments.push(
            iroha_data_model::governance::anonymous_ballot::CredentialCommitmentV1::new(
                [0xff; 128],
            ),
        );
        longer.seats += 1;
        let other_list = ScopedBallotContextV1::build(
            body_context(),
            proposal_digest(),
            body_instance_id(),
            &longer,
            policy(),
        )
        .expect("context");
        assert_eq!(other_list.scope(), context.scope());
        assert_eq!(
            verify_ballot_proof_v1(&other_list, &envelope),
            Err(BallotProofErrorV1::Rejected)
        );
        let mut slower = policy();
        slower.binding.vote_notice_ms += 1;
        let other_policy = ScopedBallotContextV1::build(
            body_context(),
            proposal_digest(),
            body_instance_id(),
            &sealed_list(),
            slower,
        )
        .expect("context");
        assert_eq!(
            verify_ballot_proof_v1(&other_policy, &envelope),
            Err(BallotProofErrorV1::Rejected)
        );
    }

    #[test]
    fn local_failures_are_not_rejections() {
        let error = BallotProofErrorV1::from(VerificationUnavailableV1::Verifier(
            VerifyError::Statement(StatementError::ListDigest),
        ));
        assert!(matches!(error, BallotProofErrorV1::Unavailable(_)));
        assert!(!error.to_string().is_empty());
        assert!(
            !VerificationUnavailableV1::ScopeLookup
                .to_string()
                .is_empty()
        );
    }
}
