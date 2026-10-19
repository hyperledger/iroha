//! The block-execution decision of one anonymous-ballot input, used by the full verifier
//! and ready for Core integration (design §3.6 "Block validation", integration decision 1).
//!
//! Decision order:
//!
//! 1. size, canonical framing and exact fields, network, known scope, exact profile, stamp
//!    and proof: any failure invalidates the block ([`BlockBallotDecisionV1::BlockInvalid`]);
//!    a ballot of a known scope is therefore fully verified before anything else is decided;
//! 2. the casting window at this block: outside it the ballot is recorded as
//!    [`AnonymousBallotRejectionV1::OutsideCastingWindow`], before the duplicate check, so a
//!    closed-window replay is always that rejection;
//! 3. an earlier accepted ballot holding `(scope, nullifier)` in canonical execution order:
//!    [`AnonymousBallotRejectionV1::DuplicateNullifier`];
//! 4. otherwise [`BlockBallotDecisionV1::Accepted`], with the compact corpus entry to append.

use std::{num::NonZeroU64, sync::Arc};

use iroha_data_model::{
    NetworkId,
    governance::anonymous_ballot::{
        ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, AnonymousBallotCodecErrorV1,
        AnonymousBallotCorpusEntryV1, AnonymousBallotEnvelopeV1, AnonymousBallotRejectionV1,
        BallotScopeV1, Digest512, NullifierV1,
        digests::{envelope_digest_v1, verify_stamp_encoded_v1},
    },
};

use super::{BallotProofErrorV1, VerificationUnavailableV1, verify_ballot_proof_v1};
use crate::context::ScopedBallotContextV1;

/// The committed state the block decision reads. The full verifier implements it; Core
/// integration remains pending. Answers reflect every earlier input of the same block
/// in canonical order.
pub trait BlockBallotStateV1 {
    /// The genesis-bound identity of the executing network.
    fn network_id(&self) -> NetworkId;

    /// The checked context of `scope`, or `None` if no sealed binding body has that scope.
    fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>>;

    /// Whether `scope`'s casting window is open at this block (see
    /// [`super::CastingWindowV1`]).
    fn casting_open(&self, scope: &BallotScopeV1) -> bool;

    /// Whether a ballot with `(scope, nullifier)` was accepted earlier in canonical order.
    fn nullifier_accepted(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool;
}

/// Why an anonymous-ballot input makes its block invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockInvalidReasonV1 {
    /// The input exceeds the envelope cap.
    #[error("the envelope has {actual} bytes; at most {max} are valid")]
    Oversize {
        /// Bytes carried.
        actual: usize,
        /// The envelope cap.
        max: usize,
    },
    /// The input is not one canonical envelope frame with exact fixed fields.
    #[error("the envelope is not one canonical frame with exact fields: {reason}")]
    Malformed {
        /// The decoder's reason.
        reason: String,
    },
    /// The envelope names another network.
    #[error("the envelope names another network")]
    WrongNetwork,
    /// No sealed binding body has the ballot's scope.
    #[error("the ballot's scope is unknown")]
    UnknownScope,
    /// The ballot names another proof profile.
    #[error("the ballot names another proof profile")]
    UnknownProfile,
    /// The stamp's work digest does not reach the frozen difficulty.
    #[error("the admission stamp does not reach the frozen difficulty")]
    InsufficientStamp,
    /// The proof does not have the candidate row's exact length.
    #[error("a ballot proof is {expected} bytes, got {actual}")]
    ProofLength {
        /// The exact length.
        expected: usize,
        /// The length carried.
        actual: usize,
    },
    /// The proof does not verify.
    #[error("the ballot proof is rejected")]
    ProofRejected,
}

/// A ballot whose encoding, network, scope, profile, stamp and proof are valid at this
/// block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidBlockBallotV1 {
    envelope: AnonymousBallotEnvelopeV1,
    envelope_digest: Digest512,
}

impl ValidBlockBallotV1 {
    /// The decoded envelope.
    pub fn envelope(&self) -> &AnonymousBallotEnvelopeV1 {
        &self.envelope
    }

    /// `envelope_digest` of the exact input bytes.
    pub fn envelope_digest(&self) -> &Digest512 {
        &self.envelope_digest
    }

    /// The ballot's identity `(scope, nullifier)`.
    pub fn identity(&self) -> (BallotScopeV1, NullifierV1) {
        self.envelope.ballot.identity()
    }
}

/// The validity part of the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBallotValidityV1 {
    /// Every validity check passed, the proof included.
    Valid(Box<ValidBlockBallotV1>),
    /// The input makes its block invalid.
    Invalid(BlockInvalidReasonV1),
}

/// The decision for one anonymous-ballot input of a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBallotDecisionV1 {
    /// The ballot is accepted: append this entry to the scope's corpus, insert its
    /// nullifier and increment its count, as one rollback-safe operation.
    Accepted(Box<AnonymousBallotCorpusEntryV1>),
    /// The ballot's proof is valid, but it is recorded as rejected and changes nothing.
    Rejected(AnonymousBallotRejectionV1),
    /// The block carrying this input is invalid.
    BlockInvalid(BlockInvalidReasonV1),
}

impl BlockBallotDecisionV1 {
    /// Whether the input invalidates its block.
    pub const fn is_block_invalid(&self) -> bool {
        matches!(self, Self::BlockInvalid(_))
    }
}

/// Check the validity of one input: size, canonical framing, network, known scope, exact
/// profile, stamp (the data model's `verify_stamp_encoded_v1` against the scope's context,
/// encoded once per scope; it decides exactly as `verify_stamp_v1`) and the proof.
///
/// # Errors
/// [`VerificationUnavailableV1`] when the node cannot decide, including a local
/// decode resource refusal. Such a refusal does not establish input invalidity.
pub fn check_block_ballot_v1<S: BlockBallotStateV1 + ?Sized>(
    state: &S,
    envelope_bytes: &[u8],
) -> Result<BlockBallotValidityV1, VerificationUnavailableV1> {
    let invalid = |reason| Ok(BlockBallotValidityV1::Invalid(reason));
    if envelope_bytes.len() > ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 {
        return invalid(BlockInvalidReasonV1::Oversize {
            actual: envelope_bytes.len(),
            max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
        });
    }
    let envelope = match AnonymousBallotEnvelopeV1::decode_canonical_bounded(envelope_bytes) {
        Ok(envelope) => envelope,
        Err(error @ AnonymousBallotCodecErrorV1::DecodeUnavailable(_)) => {
            return Err(VerificationUnavailableV1::Codec(error));
        }
        Err(error) => {
            return invalid(BlockInvalidReasonV1::Malformed {
                reason: error.to_string(),
            });
        }
    };
    if envelope.network_id != state.network_id() {
        return invalid(BlockInvalidReasonV1::WrongNetwork);
    }
    let Some(context) = state.scope_context(&envelope.ballot.scope) else {
        return invalid(BlockInvalidReasonV1::UnknownScope);
    };
    if context.scope() != &envelope.ballot.scope {
        return Err(VerificationUnavailableV1::ScopeLookup);
    }
    if !envelope.ballot.profile_id.is_v1() {
        return invalid(BlockInvalidReasonV1::UnknownProfile);
    }
    let stamp = verify_stamp_encoded_v1(
        &envelope.authorization(),
        context.encoded_context(),
        &envelope.ballot.stamp.nonce,
    )
    .map_err(VerificationUnavailableV1::Codec)?;
    if !stamp {
        return invalid(BlockInvalidReasonV1::InsufficientStamp);
    }
    match verify_ballot_proof_v1(&context, &envelope) {
        Ok(()) => {}
        Err(BallotProofErrorV1::Rejected) => return invalid(BlockInvalidReasonV1::ProofRejected),
        Err(BallotProofErrorV1::ProofLength { expected, actual }) => {
            return invalid(BlockInvalidReasonV1::ProofLength { expected, actual });
        }
        Err(BallotProofErrorV1::Unavailable(error)) => return Err(error),
        // Network, scope and profile were checked above against this context.
        Err(
            BallotProofErrorV1::WrongNetwork
            | BallotProofErrorV1::WrongScope
            | BallotProofErrorV1::WrongProfile,
        ) => return Err(VerificationUnavailableV1::ScopeLookup),
    }
    let envelope_digest =
        envelope_digest_v1(envelope_bytes).map_err(VerificationUnavailableV1::Codec)?;
    Ok(BlockBallotValidityV1::Valid(Box::new(ValidBlockBallotV1 {
        envelope,
        envelope_digest,
    })))
}

/// Decide a fully verified ballot: outside the window it is rejected before the duplicate
/// check; a duplicate is rejected; otherwise it is accepted with the corpus entry at
/// `(height, input_index)`.
pub fn decide_valid_ballot_v1(
    ballot: &ValidBlockBallotV1,
    casting_open: bool,
    nullifier_accepted: bool,
    height: NonZeroU64,
    input_index: u32,
) -> BlockBallotDecisionV1 {
    if !casting_open {
        return BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::OutsideCastingWindow);
    }
    if nullifier_accepted {
        return BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier);
    }
    let ballot_fields = &ballot.envelope.ballot;
    BlockBallotDecisionV1::Accepted(Box::new(AnonymousBallotCorpusEntryV1 {
        scope: ballot_fields.scope,
        vote: ballot_fields.vote,
        nullifier: ballot_fields.nullifier,
        auth_v: ballot_fields.auth_v,
        profile_id: ballot_fields.profile_id,
        stamp: ballot_fields.stamp,
        envelope_digest: ballot.envelope_digest,
        height: height.get(),
        input_index,
    }))
}

/// Decide one anonymous-ballot input of the block at `height`, at position `input_index` of
/// its global network-input projection: [`check_block_ballot_v1`], then
/// [`decide_valid_ballot_v1`] with the state's window and duplicate answers.
///
/// # Errors
/// [`VerificationUnavailableV1`] when the node cannot decide; the caller must then neither
/// accept nor reject the block on this input's account.
pub fn decide_block_ballot_v1<S: BlockBallotStateV1 + ?Sized>(
    state: &S,
    envelope_bytes: &[u8],
    height: NonZeroU64,
    input_index: u32,
) -> Result<BlockBallotDecisionV1, VerificationUnavailableV1> {
    match check_block_ballot_v1(state, envelope_bytes)? {
        BlockBallotValidityV1::Invalid(reason) => Ok(BlockBallotDecisionV1::BlockInvalid(reason)),
        BlockBallotValidityV1::Valid(ballot) => {
            let (scope, nullifier) = ballot.identity();
            Ok(decide_valid_ballot_v1(
                &ballot,
                state.casting_open(&scope),
                state.nullifier_accepted(&scope, &nullifier),
                height,
                input_index,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeSet};

    use iroha_data_model::governance::anonymous_ballot::{
        AdmissionNonceV1, BallotScopeV1, ProofProfileIdV1,
    };

    use super::*;
    use crate::test_support::{
        AYE_0, NAY_0, NAY_1, canonical_bytes, fixture_bytes, fixture_envelope, forged_envelope,
        network_id, other_network_id, scoped_context,
    };

    /// One known scope, its window and the nullifiers accepted so far.
    struct State {
        open: bool,
        accepted: RefCell<BTreeSet<NullifierV1>>,
    }

    impl State {
        fn new(open: bool) -> Self {
            Self {
                open,
                accepted: RefCell::new(BTreeSet::new()),
            }
        }

        /// Decide and apply an acceptance to this in-memory test state.
        fn execute(&self, bytes: &[u8], height: u64, index: u32) -> BlockBallotDecisionV1 {
            let decision = decide_block_ballot_v1(
                self,
                bytes,
                NonZeroU64::new(height).expect("nonzero"),
                index,
            )
            .expect("decidable");
            if let BlockBallotDecisionV1::Accepted(entry) = &decision {
                self.accepted.borrow_mut().insert(entry.nullifier);
            }
            decision
        }
    }

    impl BlockBallotStateV1 for State {
        fn network_id(&self) -> NetworkId {
            network_id()
        }

        fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>> {
            let context = scoped_context();
            (context.scope() == scope).then_some(context)
        }

        fn casting_open(&self, _scope: &BallotScopeV1) -> bool {
            self.open
        }

        fn nullifier_accepted(&self, _scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool {
            self.accepted.borrow().contains(nullifier)
        }
    }

    #[test]
    fn an_open_ballot_is_accepted_with_its_corpus_entry() {
        let state = State::new(true);
        let bytes = fixture_bytes(AYE_0);
        let decision = state.execute(&bytes, 100, 3);
        let BlockBallotDecisionV1::Accepted(entry) = decision else {
            panic!("accepted");
        };
        let envelope = fixture_envelope(AYE_0);
        assert_eq!(entry.scope, envelope.ballot.scope);
        assert_eq!(entry.vote, envelope.ballot.vote);
        assert_eq!(entry.nullifier, envelope.ballot.nullifier);
        assert_eq!(entry.auth_v, envelope.ballot.auth_v);
        assert_eq!(entry.profile_id, ProofProfileIdV1::V1);
        assert_eq!(entry.stamp, envelope.ballot.stamp);
        assert_eq!(
            entry.envelope_digest,
            envelope_digest_v1(&bytes).expect("digest")
        );
        assert_eq!(entry.position(), (100, 3));
    }

    #[test]
    fn caller_decode_shortage_does_not_invalidate_a_ballot_or_mutate_state() {
        use iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1;
        use norito::core::{DecodeLocalRefusalKind, DecodeResourceError};

        let state = State::new(true);
        let bytes = fixture_bytes(AYE_0);
        let proof_bytes = BallotProofBytesV1::LENGTH;
        // The second case has the same numeric ceiling as the schema but an
        // already consumed byte. Classification must retain the failing scope.
        for (limit, prior) in [(0, 0), (proof_bytes, 1)] {
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, usize::MAX);
            let result = norito::with_decode_limits_scope(limits, || {
                norito::core::reserve_decode_allocation(prior).expect("prior caller charge");
                decide_block_ballot_v1(&state, &bytes, NonZeroU64::new(100).unwrap(), 0)
            });
            let Err(VerificationUnavailableV1::Codec(
                AnonymousBallotCodecErrorV1::DecodeUnavailable(refusal),
            )) = result
            else {
                panic!("a caller budget shortage is local unavailability");
            };
            assert_eq!(refusal.kind(), DecodeLocalRefusalKind::EnclosingLimit);
            assert_eq!(
                refusal.resource_error(),
                DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(prior + proof_bytes).unwrap(),
                    limit: u64::try_from(limit).unwrap(),
                }
            );
            assert!(state.accepted.borrow().is_empty());
        }
        // A malformed header is still a protocol failure, even with no local budget.
        let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
        let malformed =
            norito::with_decode_limits_scope(zero, || check_block_ballot_v1(&state, &[]));
        assert!(matches!(
            malformed,
            Ok(BlockBallotValidityV1::Invalid(
                BlockInvalidReasonV1::Malformed { .. }
            ))
        ));
        assert!(matches!(
            check_block_ballot_v1(&state, &bytes),
            Ok(BlockBallotValidityV1::Valid(_))
        ));
        assert!(state.accepted.borrow().is_empty());
    }

    #[test]
    fn the_first_ballot_in_canonical_order_wins_its_nullifier() {
        let state = State::new(true);
        assert!(matches!(
            state.execute(&fixture_bytes(AYE_0), 100, 0),
            BlockBallotDecisionV1::Accepted(_)
        ));
        let duplicate =
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier);
        // The conflicting choice under the same nullifier, in the same block.
        assert_eq!(state.execute(&fixture_bytes(NAY_0), 100, 1), duplicate);
        // An identical carrier at another position.
        assert_eq!(state.execute(&fixture_bytes(AYE_0), 101, 0), duplicate);
        // Another nullifier is unaffected.
        assert!(matches!(
            state.execute(&fixture_bytes(NAY_1), 101, 1),
            BlockBallotDecisionV1::Accepted(_)
        ));
    }

    #[test]
    fn the_window_is_checked_before_duplicates() {
        let state = State::new(false);
        state
            .accepted
            .borrow_mut()
            .insert(fixture_envelope(AYE_0).ballot.nullifier);
        let late =
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::OutsideCastingWindow);
        assert_eq!(state.execute(&fixture_bytes(AYE_0), 200, 0), late);
        assert_eq!(state.execute(&fixture_bytes(NAY_1), 200, 1), late);
    }

    #[test]
    fn invalid_inputs_invalidate_the_block_even_when_late_or_duplicate() {
        let state = State::new(false);
        state
            .accepted
            .borrow_mut()
            .insert(fixture_envelope(NAY_1).ballot.nullifier);
        let invalid = |bytes: &[u8]| match state.execute(bytes, 300, 0) {
            BlockBallotDecisionV1::BlockInvalid(reason) => reason,
            other => panic!("expected an invalid block, got {other:?}"),
        };
        // A well-stamped forged proof: only proof verification catches it.
        assert_eq!(
            invalid(&canonical_bytes(&forged_envelope())),
            BlockInvalidReasonV1::ProofRejected
        );
        let envelope = fixture_envelope(AYE_0);
        let mut changed = envelope.clone();
        changed.network_id = other_network_id();
        assert_eq!(
            invalid(&canonical_bytes(&changed)),
            BlockInvalidReasonV1::WrongNetwork
        );
        let mut changed = envelope.clone();
        changed.ballot.scope = BallotScopeV1::new([0x45; 64]);
        assert_eq!(
            invalid(&canonical_bytes(&changed)),
            BlockInvalidReasonV1::UnknownScope
        );
        let mut changed = envelope.clone();
        changed.ballot.profile_id = ProofProfileIdV1::new([1; 64]);
        assert_eq!(
            invalid(&canonical_bytes(&changed)),
            BlockInvalidReasonV1::UnknownProfile
        );
        let mut changed = envelope;
        changed.ballot.stamp.nonce = AdmissionNonceV1::new([0; 32]);
        assert_eq!(
            invalid(&canonical_bytes(&changed)),
            BlockInvalidReasonV1::InsufficientStamp
        );
        let mut trailing = fixture_bytes(AYE_0);
        trailing.push(0);
        assert!(matches!(
            invalid(&trailing),
            BlockInvalidReasonV1::Malformed { .. }
        ));
        let oversize = vec![0_u8; ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1];
        assert!(matches!(
            invalid(&oversize),
            BlockInvalidReasonV1::Oversize { .. }
        ));
        assert!(
            BlockBallotDecisionV1::BlockInvalid(BlockInvalidReasonV1::ProofRejected)
                .is_block_invalid()
        );
        assert!(
            !BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier)
                .is_block_invalid()
        );
    }

    #[test]
    fn validity_is_reported_without_a_window_or_duplicate_decision() {
        let state = State::new(false);
        let BlockBallotValidityV1::Valid(valid) =
            check_block_ballot_v1(&state, &fixture_bytes(NAY_1)).expect("decidable")
        else {
            panic!("valid");
        };
        assert_eq!(valid.envelope(), &fixture_envelope(NAY_1));
        assert_eq!(
            valid.envelope_digest(),
            &envelope_digest_v1(&fixture_bytes(NAY_1)).expect("digest")
        );
        let height = NonZeroU64::new(9).expect("nonzero");
        assert!(matches!(
            decide_valid_ballot_v1(&valid, true, false, height, 4),
            BlockBallotDecisionV1::Accepted(entry) if entry.position() == (9, 4)
        ));
        assert_eq!(
            decide_valid_ballot_v1(&valid, true, true, height, 4),
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::DuplicateNullifier)
        );
        assert_eq!(
            decide_valid_ballot_v1(&valid, false, true, height, 4),
            BlockBallotDecisionV1::Rejected(AnonymousBallotRejectionV1::OutsideCastingWindow)
        );
    }
}
