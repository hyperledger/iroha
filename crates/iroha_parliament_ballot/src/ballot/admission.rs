//! The signerless queue-admission prechecks, in the order of design §3.6 and integration
//! decision 1:
//!
//! 1. outer size at most 262,144 bytes;
//! 2. one canonical envelope frame with exact fixed fields, naming the executing network;
//! 3. a known scope whose casting window is open or locally due;
//! 4. exactly the V1 profile;
//! 5. a stamp that reaches the scope's frozen difficulty;
//! 6. the nullifier unused in committed state;
//! 7. no verified pending ballot holding `(scope, nullifier)`.
//!
//! A submission failing several checks reports the earliest. Only after every check passes
//! does the caller reserve work and bytes and run the expensive proof verification
//! ([`AdmittedBallotV1::verify_proof`]); a nullifier is never reserved for unverified work.
//! After verification the caller repeats the state checks atomically with insertion
//! ([`VerifiedBallotV1::recheck`]). Gossip carries only verified ballots, and receivers run
//! the same pipeline.

use std::sync::Arc;

use iroha_data_model::{
    NetworkId,
    governance::anonymous_ballot::{
        ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, AnonymousBallotEnvelopeV1, BallotScopeV1,
        CanonicalAnonymousBallotEnvelopeV1, Digest512, NullifierV1,
        digests::{
            leading_zero_bits_v1, stamp_meets_difficulty_v1, stamp_payload_digest_encoded_v1,
            stamp_work_digest_v1,
        },
    },
};

use super::{BallotProofErrorV1, VerificationUnavailableV1, verify_ballot_proof_v1};
use crate::context::ScopedBallotContextV1;

/// Casting-window status of a known scope when a submission arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CastingWindowStatusV1 {
    /// Sealed; casting is not yet due by committed state or the local clock.
    NotYetDue,
    /// Due to open by the node's local clock; committed state has not opened it yet.
    /// Execution rechecks against committed state.
    LocallyDue,
    /// Open in committed state.
    Open,
    /// `closing_ms` has passed or the closure has run.
    Closed,
}

impl CastingWindowStatusV1 {
    /// Whether queue admission accepts ballots of a scope in this status.
    pub const fn admits(self) -> bool {
        matches!(self, Self::LocallyDue | Self::Open)
    }
}

/// The authenticated context of a known scope and its window status at admission.
#[derive(Debug, Clone)]
pub struct AdmissionScopeV1 {
    /// The scope's checked verification context.
    pub context: Arc<ScopedBallotContextV1>,
    /// Its casting-window status now.
    pub window: CastingWindowStatusV1,
}

/// The state lookups queue admission needs, implemented by the node.
pub trait AdmissionStateV1 {
    /// The genesis-bound identity of the executing network.
    fn network_id(&self) -> NetworkId;

    /// The context and window status of `scope`, or `None` if no sealed binding body has
    /// that scope.
    fn scope(&self, scope: &BallotScopeV1) -> Option<AdmissionScopeV1>;

    /// Whether committed state already accepted a ballot with `(scope, nullifier)`.
    fn nullifier_committed(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool;

    /// Whether a verified pending ballot already holds `(scope, nullifier)`.
    fn verified_pending_holder(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool;
}

/// Why queue admission refused a submission, by the check that refused it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionRejectionV1 {
    /// Check 1: the submission exceeds the envelope cap.
    #[error("the envelope has {actual} bytes; at most {max} are admitted")]
    Oversize {
        /// Bytes submitted.
        actual: usize,
        /// The envelope cap.
        max: usize,
    },
    /// Check 2: the bytes are not one canonical envelope frame with exact fixed fields.
    #[error("the envelope is not one canonical frame with exact fields: {reason}")]
    Malformed {
        /// The decoder's reason.
        reason: String,
    },
    /// Check 2: the envelope names another network.
    #[error("the envelope names another network")]
    WrongNetwork,
    /// Check 3: no sealed binding body has the ballot's scope.
    #[error("the ballot's scope is unknown")]
    UnknownScope,
    /// Check 3: the scope's casting window is not yet due.
    #[error("the scope's casting window is not open")]
    CastingNotOpen,
    /// Check 3: the scope's casting window has closed.
    #[error("the scope's casting window is closed")]
    CastingClosed,
    /// Check 4: the ballot names another proof profile.
    #[error("the ballot names another proof profile")]
    UnknownProfile,
    /// Check 5: the stamp's work digest does not reach the frozen difficulty.
    #[error("the admission stamp does not reach the frozen difficulty")]
    InsufficientStamp,
    /// Check 6: committed state already accepted the nullifier in this scope.
    #[error("the nullifier is already accepted in this scope")]
    NullifierCommitted,
    /// Check 7: a verified pending ballot already holds the nullifier.
    #[error("a verified pending ballot already holds this nullifier")]
    NullifierPending,
}

impl AdmissionRejectionV1 {
    /// The number of the admission check (1 to 7) that refused the submission.
    pub const fn check(&self) -> u8 {
        match self {
            Self::Oversize { .. } => 1,
            Self::Malformed { .. } | Self::WrongNetwork => 2,
            Self::UnknownScope | Self::CastingNotOpen | Self::CastingClosed => 3,
            Self::UnknownProfile => 4,
            Self::InsufficientStamp => 5,
            Self::NullifierCommitted => 6,
            Self::NullifierPending => 7,
        }
    }

    /// A stable machine-readable code for HTTP and queue error responses.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Oversize { .. } => "anonymous_ballot_oversize",
            Self::Malformed { .. } => "anonymous_ballot_malformed",
            Self::WrongNetwork => "anonymous_ballot_wrong_network",
            Self::UnknownScope => "anonymous_ballot_unknown_scope",
            Self::CastingNotOpen => "anonymous_ballot_casting_not_open",
            Self::CastingClosed => "anonymous_ballot_casting_closed",
            Self::UnknownProfile => "anonymous_ballot_unknown_profile",
            Self::InsufficientStamp => "anonymous_ballot_insufficient_stamp",
            Self::NullifierCommitted => "anonymous_ballot_nullifier_committed",
            Self::NullifierPending => "anonymous_ballot_nullifier_pending",
        }
    }
}

/// Why a submission was not admitted: a rejection of the submission, or a local inability
/// to check it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionErrorV1 {
    /// The submission failed an admission check.
    #[error(transparent)]
    Rejected(#[from] AdmissionRejectionV1),
    /// The node could not check it.
    #[error(transparent)]
    Unavailable(#[from] VerificationUnavailableV1),
}

/// A submission that passed the seven ordered checks. Its proof is not verified yet.
#[derive(Debug, Clone)]
pub struct AdmittedBallotV1 {
    envelope: AnonymousBallotEnvelopeV1,
    canonical: CanonicalAnonymousBallotEnvelopeV1,
    envelope_digest: Digest512,
    payload_digest: Digest512,
    work_bits: u32,
    context: Arc<ScopedBallotContextV1>,
}

impl AdmittedBallotV1 {
    /// The ballot's identity `(scope, nullifier)`.
    pub fn identity(&self) -> (BallotScopeV1, NullifierV1) {
        self.envelope.ballot.identity()
    }

    /// The decoded envelope.
    pub fn envelope(&self) -> &AnonymousBallotEnvelopeV1 {
        &self.envelope
    }

    /// The exact canonical bytes that were submitted.
    pub fn canonical(&self) -> &CanonicalAnonymousBallotEnvelopeV1 {
        &self.canonical
    }

    /// `envelope_digest`: the key for coalescing byte-identical in-flight submissions.
    pub fn envelope_digest(&self) -> &Digest512 {
        &self.envelope_digest
    }

    /// The stamp payload digest, the tie-breaker of the ingress priority.
    pub fn payload_digest(&self) -> &Digest512 {
        &self.payload_digest
    }

    /// Leading zero bits of the stamp's work digest: the ingress priority. It has no
    /// consensus significance.
    pub fn work_bits(&self) -> u32 {
        self.work_bits
    }

    /// The scope's verification context.
    pub fn context(&self) -> &Arc<ScopedBallotContextV1> {
        &self.context
    }

    /// Verify the proof against the scope's authenticated context: the expensive step,
    /// after the caller reserved its work and bytes.
    ///
    /// # Errors
    /// As [`verify_ballot_proof_v1`].
    pub fn verify_proof(self) -> Result<VerifiedBallotV1, BallotProofErrorV1> {
        verify_ballot_proof_v1(&self.context, &self.envelope)?;
        Ok(VerifiedBallotV1 { admitted: self })
    }
}

/// An admitted submission whose proof verified.
#[derive(Debug, Clone)]
pub struct VerifiedBallotV1 {
    admitted: AdmittedBallotV1,
}

impl VerifiedBallotV1 {
    /// The ballot's identity `(scope, nullifier)`.
    pub fn identity(&self) -> (BallotScopeV1, NullifierV1) {
        self.admitted.identity()
    }

    /// The decoded envelope.
    pub fn envelope(&self) -> &AnonymousBallotEnvelopeV1 {
        &self.admitted.envelope
    }

    /// The exact canonical bytes, for the pending pool and for gossip.
    pub fn canonical(&self) -> &CanonicalAnonymousBallotEnvelopeV1 {
        &self.admitted.canonical
    }

    /// `envelope_digest` of the canonical bytes.
    pub fn envelope_digest(&self) -> &Digest512 {
        &self.admitted.envelope_digest
    }

    /// Leading zero bits of the stamp's work digest.
    pub fn work_bits(&self) -> u32 {
        self.admitted.work_bits
    }

    /// Repeat checks 3, 6 and 7 against the current state. The caller runs this atomically
    /// with inserting the ballot as the verified pending holder of its identity.
    ///
    /// # Errors
    /// The [`AdmissionRejectionV1`] of the first check that now fails.
    pub fn recheck<S: AdmissionStateV1 + ?Sized>(
        &self,
        state: &S,
    ) -> Result<(), AdmissionRejectionV1> {
        let (scope, nullifier) = self.identity();
        let Some(known) = state.scope(&scope) else {
            return Err(AdmissionRejectionV1::UnknownScope);
        };
        window_admits(known.window)?;
        nullifier_free(state, &scope, &nullifier)
    }
}

/// Check 3's window rule.
fn window_admits(window: CastingWindowStatusV1) -> Result<(), AdmissionRejectionV1> {
    match window {
        CastingWindowStatusV1::NotYetDue => Err(AdmissionRejectionV1::CastingNotOpen),
        CastingWindowStatusV1::Closed => Err(AdmissionRejectionV1::CastingClosed),
        CastingWindowStatusV1::LocallyDue | CastingWindowStatusV1::Open => Ok(()),
    }
}

/// Checks 6 and 7.
fn nullifier_free<S: AdmissionStateV1 + ?Sized>(
    state: &S,
    scope: &BallotScopeV1,
    nullifier: &NullifierV1,
) -> Result<(), AdmissionRejectionV1> {
    if state.nullifier_committed(scope, nullifier) {
        return Err(AdmissionRejectionV1::NullifierCommitted);
    }
    if state.verified_pending_holder(scope, nullifier) {
        return Err(AdmissionRejectionV1::NullifierPending);
    }
    Ok(())
}

/// Run the seven admission checks on submitted `bytes`, in order.
///
/// The stamp decision is the data model's: `work_digest` from the payload digest of the
/// authorization with the scope's context (encoded once per scope,
/// `stamp_payload_digest_encoded_v1`) and the nonce, accepted iff `stamp_meets_difficulty_v1`
/// at the context's frozen difficulty; this is exactly `verify_stamp_v1`, decomposed so that
/// the work bits and payload digest are computed once for the ingress priority.
///
/// # Errors
/// [`AdmissionErrorV1::Rejected`] with the earliest failing check, or
/// [`AdmissionErrorV1::Unavailable`] when the node cannot check the submission.
pub fn precheck_admission_v1<S: AdmissionStateV1 + ?Sized>(
    bytes: &[u8],
    state: &S,
) -> Result<AdmittedBallotV1, AdmissionErrorV1> {
    // 1. Outer size, before any decoding.
    if bytes.len() > ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 {
        return Err(AdmissionRejectionV1::Oversize {
            actual: bytes.len(),
            max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1,
        }
        .into());
    }
    // 2. One canonical frame with exact fixed fields, naming this network.
    let envelope = AnonymousBallotEnvelopeV1::decode_canonical_bounded(bytes).map_err(|error| {
        AdmissionRejectionV1::Malformed {
            reason: error.to_string(),
        }
    })?;
    if envelope.network_id != state.network_id() {
        return Err(AdmissionRejectionV1::WrongNetwork.into());
    }
    // 3. A known scope with an open or locally due window.
    let (scope, nullifier) = envelope.ballot.identity();
    let Some(known) = state.scope(&scope) else {
        return Err(AdmissionRejectionV1::UnknownScope.into());
    };
    if known.context.scope() != &scope {
        return Err(VerificationUnavailableV1::ScopeLookup.into());
    }
    window_admits(known.window)?;
    // 4. Exactly the V1 profile.
    if !envelope.ballot.profile_id.is_v1() {
        return Err(AdmissionRejectionV1::UnknownProfile.into());
    }
    // 5. The stamp, against the scope's authenticated context.
    let encoded = known.context.encoded_context();
    let payload_digest = stamp_payload_digest_encoded_v1(&envelope.authorization(), encoded)
        .map_err(VerificationUnavailableV1::Codec)?;
    let work = stamp_work_digest_v1(&payload_digest, &envelope.ballot.stamp.nonce)
        .map_err(VerificationUnavailableV1::Codec)?;
    if !stamp_meets_difficulty_v1(&work, encoded.stamp_difficulty_bits()) {
        return Err(AdmissionRejectionV1::InsufficientStamp.into());
    }
    // 6. and 7. The nullifier is neither committed nor held by a verified pending ballot.
    nullifier_free(state, &scope, &nullifier)?;
    let canonical = CanonicalAnonymousBallotEnvelopeV1::from_canonical_bytes(bytes.to_vec())
        .map_err(VerificationUnavailableV1::Codec)?;
    let envelope_digest = canonical
        .digest()
        .map_err(VerificationUnavailableV1::Codec)?;
    Ok(AdmittedBallotV1 {
        envelope,
        canonical,
        envelope_digest,
        payload_digest,
        work_bits: leading_zero_bits_v1(&work),
        context: known.context,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use iroha_data_model::governance::anonymous_ballot::{
        AdmissionNonceV1, BallotChoiceV1, ProofProfileIdV1,
        digests::{stamp_payload_digest_v1, verify_stamp_v1},
    };

    use super::*;
    use crate::test_support::{
        AYE_0, NAY_1, canonical_bytes, fixture_bytes, fixture_envelope, forged_envelope,
        network_id, other_network_id, scoped_context,
    };

    /// A node state with one known scope.
    struct State {
        network: NetworkId,
        known: Option<AdmissionScopeV1>,
        committed: BTreeSet<NullifierV1>,
        pending: BTreeSet<NullifierV1>,
    }

    impl State {
        fn open() -> Self {
            Self {
                network: network_id(),
                known: Some(AdmissionScopeV1 {
                    context: scoped_context(),
                    window: CastingWindowStatusV1::Open,
                }),
                committed: BTreeSet::new(),
                pending: BTreeSet::new(),
            }
        }

        fn with_window(window: CastingWindowStatusV1) -> Self {
            let mut state = Self::open();
            if let Some(known) = &mut state.known {
                known.window = window;
            }
            state
        }
    }

    impl AdmissionStateV1 for State {
        fn network_id(&self) -> NetworkId {
            self.network
        }

        fn scope(&self, scope: &BallotScopeV1) -> Option<AdmissionScopeV1> {
            self.known
                .as_ref()
                .filter(|known| known.context.scope() == scope)
                .cloned()
        }

        fn nullifier_committed(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool {
            self.scope(scope).is_some() && self.committed.contains(nullifier)
        }

        fn verified_pending_holder(&self, scope: &BallotScopeV1, nullifier: &NullifierV1) -> bool {
            self.scope(scope).is_some() && self.pending.contains(nullifier)
        }
    }

    fn rejection(bytes: &[u8], state: &State) -> AdmissionRejectionV1 {
        match precheck_admission_v1(bytes, state) {
            Err(AdmissionErrorV1::Rejected(rejection)) => rejection,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn an_honest_ballot_passes_every_check_and_then_verifies() {
        let state = State::open();
        let bytes = fixture_bytes(AYE_0);
        let admitted = precheck_admission_v1(&bytes, &state).expect("admitted");
        let envelope = fixture_envelope(AYE_0);
        assert_eq!(admitted.envelope(), &envelope);
        assert_eq!(admitted.canonical().as_bytes(), &bytes[..]);
        assert_eq!(
            admitted.identity(),
            (envelope.ballot.scope, envelope.ballot.nullifier)
        );
        assert_eq!(
            admitted.envelope_digest(),
            &admitted.canonical().digest().expect("digest")
        );
        assert!(admitted.work_bits() >= 28);
        assert_eq!(
            admitted.payload_digest(),
            &stamp_payload_digest_v1(&envelope.authorization(), scoped_context().context())
                .expect("payload")
        );
        // The decomposed stamp decision is the data model's `verify_stamp_v1`.
        assert!(
            verify_stamp_v1(
                &envelope.authorization(),
                scoped_context().context(),
                &envelope.ballot.stamp.nonce
            )
            .expect("stamp")
        );
        assert!(Arc::ptr_eq(admitted.context(), &scoped_context()));
        let verified = admitted.verify_proof().expect("verified");
        assert_eq!(verified.identity().1, envelope.ballot.nullifier);
        assert_eq!(verified.envelope(), &envelope);
        assert_eq!(verified.canonical().as_bytes(), &bytes[..]);
        assert!(verified.work_bits() >= 28);
        assert_eq!(
            verified.envelope_digest(),
            &verified.canonical().digest().expect("digest")
        );
        assert_eq!(verified.recheck(&state), Ok(()));
        // The atomic recheck sees a ballot that became pending or committed meanwhile, and
        // a window that closed.
        let mut pending = State::open();
        pending.pending.insert(envelope.ballot.nullifier);
        assert_eq!(
            verified.recheck(&pending),
            Err(AdmissionRejectionV1::NullifierPending)
        );
        let mut committed = State::open();
        committed.committed.insert(envelope.ballot.nullifier);
        assert_eq!(
            verified.recheck(&committed),
            Err(AdmissionRejectionV1::NullifierCommitted)
        );
        assert_eq!(
            verified.recheck(&State::with_window(CastingWindowStatusV1::Closed)),
            Err(AdmissionRejectionV1::CastingClosed)
        );
        let unknown = State {
            known: None,
            ..State::open()
        };
        assert_eq!(
            verified.recheck(&unknown),
            Err(AdmissionRejectionV1::UnknownScope)
        );
    }

    #[test]
    fn a_locally_due_window_admits_and_others_do_not() {
        let bytes = fixture_bytes(NAY_1);
        assert!(
            precheck_admission_v1(
                &bytes,
                &State::with_window(CastingWindowStatusV1::LocallyDue)
            )
            .is_ok()
        );
        assert_eq!(
            rejection(
                &bytes,
                &State::with_window(CastingWindowStatusV1::NotYetDue)
            ),
            AdmissionRejectionV1::CastingNotOpen
        );
        assert_eq!(
            rejection(&bytes, &State::with_window(CastingWindowStatusV1::Closed)),
            AdmissionRejectionV1::CastingClosed
        );
        assert!(CastingWindowStatusV1::Open.admits());
        assert!(!CastingWindowStatusV1::NotYetDue.admits());
    }

    #[test]
    fn a_well_stamped_forged_proof_is_admitted_and_then_rejected_by_verification() {
        let state = State::open();
        let admitted =
            precheck_admission_v1(&canonical_bytes(&forged_envelope()), &state).expect("admitted");
        assert_eq!(
            admitted.verify_proof().map(|verified| verified.identity()),
            Err(BallotProofErrorV1::Rejected)
        );
    }

    #[test]
    fn every_tampered_field_fails_its_check() {
        let state = State::open();
        let envelope = fixture_envelope(AYE_0);
        let tampered = |change: &dyn Fn(&mut AnonymousBallotEnvelopeV1)| {
            let mut changed = envelope.clone();
            change(&mut changed);
            rejection(&canonical_bytes(&changed), &state)
        };
        assert_eq!(
            tampered(&|e| e.network_id = other_network_id()),
            AdmissionRejectionV1::WrongNetwork
        );
        assert_eq!(
            tampered(&|e| e.ballot.scope = BallotScopeV1::new([0x45; 64])),
            AdmissionRejectionV1::UnknownScope
        );
        assert_eq!(
            tampered(&|e| e.ballot.profile_id = ProofProfileIdV1::new([0; 64])),
            AdmissionRejectionV1::UnknownProfile
        );
        // The stamp covers every other field, the proof bytes included.
        assert_eq!(
            tampered(&|e| e.ballot.vote = BallotChoiceV1::Abstain),
            AdmissionRejectionV1::InsufficientStamp
        );
        assert_eq!(
            tampered(&|e| e.ballot.nullifier = NullifierV1::new([9; 128])),
            AdmissionRejectionV1::InsufficientStamp
        );
        assert_eq!(
            tampered(&|e| {
                e.ballot.auth_v =
                    iroha_data_model::governance::anonymous_ballot::VoteAuthorizationV1::new(
                        [9; 64],
                    );
            }),
            AdmissionRejectionV1::InsufficientStamp
        );
        assert_eq!(
            tampered(&|e| e.ballot.stamp.nonce = AdmissionNonceV1::new([0; 32])),
            AdmissionRejectionV1::InsufficientStamp
        );
        assert_eq!(
            tampered(&|e| {
                let mut proof = e.ballot.proof.clone().into_bytes();
                proof[0] ^= 1;
                e.ballot.proof =
                    iroha_data_model::governance::anonymous_ballot::BallotProofBytesV1::new(proof)
                        .expect("exact length");
            }),
            AdmissionRejectionV1::InsufficientStamp
        );
    }

    #[test]
    fn malformed_and_oversize_submissions_fail_first() {
        let state = State::open();
        let bytes = fixture_bytes(AYE_0);
        let mut oversize = bytes.clone();
        oversize.resize(ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1, 0);
        assert_eq!(
            rejection(&oversize, &state),
            AdmissionRejectionV1::Oversize {
                actual: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 1,
                max: ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1
            }
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            rejection(&trailing, &state),
            AdmissionRejectionV1::Malformed { .. }
        ));
        let mut checksum = bytes.clone();
        checksum[31] ^= 1;
        assert!(matches!(
            rejection(&checksum, &state),
            AdmissionRejectionV1::Malformed { .. }
        ));
        assert!(matches!(
            rejection(&bytes[..bytes.len() - 1], &state),
            AdmissionRejectionV1::Malformed { .. }
        ));
        assert!(matches!(
            rejection(&[], &state),
            AdmissionRejectionV1::Malformed { .. }
        ));
    }

    #[test]
    fn the_earliest_failing_check_is_reported() {
        let envelope = fixture_envelope(AYE_0);
        // Every later check fails too: foreign network, unknown scope, foreign profile,
        // spent stamp; and the state reports the nullifier committed and pending.
        let mut worst = envelope.clone();
        worst.network_id = other_network_id();
        worst.ballot.scope = BallotScopeV1::new([0x45; 64]);
        worst.ballot.profile_id = ProofProfileIdV1::new([0; 64]);
        worst.ballot.stamp.nonce = AdmissionNonceV1::new([0; 32]);
        let mut state = State::with_window(CastingWindowStatusV1::Closed);
        state.committed.insert(envelope.ballot.nullifier);
        state.pending.insert(envelope.ballot.nullifier);
        let reported = |changed: &AnonymousBallotEnvelopeV1, state: &State| {
            rejection(&canonical_bytes(changed), state)
        };
        assert_eq!(reported(&worst, &state), AdmissionRejectionV1::WrongNetwork);
        worst.network_id = envelope.network_id;
        assert_eq!(reported(&worst, &state), AdmissionRejectionV1::UnknownScope);
        worst.ballot.scope = envelope.ballot.scope;
        assert_eq!(
            reported(&worst, &state),
            AdmissionRejectionV1::CastingClosed
        );
        state.known = State::open().known;
        assert_eq!(
            reported(&worst, &state),
            AdmissionRejectionV1::UnknownProfile
        );
        worst.ballot.profile_id = envelope.ballot.profile_id;
        assert_eq!(
            reported(&worst, &state),
            AdmissionRejectionV1::InsufficientStamp
        );
        worst.ballot.stamp = envelope.ballot.stamp;
        assert_eq!(
            reported(&worst, &state),
            AdmissionRejectionV1::NullifierCommitted
        );
        state.committed.clear();
        assert_eq!(
            reported(&worst, &state),
            AdmissionRejectionV1::NullifierPending
        );
        state.pending.clear();
        assert!(precheck_admission_v1(&canonical_bytes(&worst), &state).is_ok());
        // Oversize precedes everything.
        let mut oversize = canonical_bytes(&worst);
        oversize.resize(ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + 7, 0xff);
        assert_eq!(rejection(&oversize, &state).check(), 1);
    }

    #[test]
    fn rejections_have_stable_check_numbers_and_codes() {
        let all = [
            AdmissionRejectionV1::Oversize { actual: 1, max: 0 },
            AdmissionRejectionV1::Malformed {
                reason: String::new(),
            },
            AdmissionRejectionV1::WrongNetwork,
            AdmissionRejectionV1::UnknownScope,
            AdmissionRejectionV1::CastingNotOpen,
            AdmissionRejectionV1::CastingClosed,
            AdmissionRejectionV1::UnknownProfile,
            AdmissionRejectionV1::InsufficientStamp,
            AdmissionRejectionV1::NullifierCommitted,
            AdmissionRejectionV1::NullifierPending,
        ];
        assert_eq!(
            all.iter()
                .map(AdmissionRejectionV1::check)
                .collect::<Vec<_>>(),
            [1, 2, 2, 3, 3, 3, 4, 5, 6, 7]
        );
        let codes: BTreeSet<_> = all.iter().map(AdmissionRejectionV1::code).collect();
        assert_eq!(codes.len(), all.len());
        assert!(
            codes
                .iter()
                .all(|code| code.starts_with("anonymous_ballot_"))
        );
        assert!(
            all.iter()
                .all(|rejection| !rejection.to_string().is_empty())
        );
    }

    #[test]
    fn a_state_answering_with_another_scope_is_a_local_failure() {
        /// Answers every lookup with the fixture scope's context.
        struct Confused;
        impl AdmissionStateV1 for Confused {
            fn network_id(&self) -> NetworkId {
                network_id()
            }
            fn scope(&self, _scope: &BallotScopeV1) -> Option<AdmissionScopeV1> {
                Some(AdmissionScopeV1 {
                    context: scoped_context(),
                    window: CastingWindowStatusV1::Open,
                })
            }
            fn nullifier_committed(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
                false
            }
            fn verified_pending_holder(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
                false
            }
        }
        let mut envelope = fixture_envelope(AYE_0);
        envelope.ballot.scope = BallotScopeV1::new([0x45; 64]);
        assert_eq!(
            precheck_admission_v1(&canonical_bytes(&envelope), &Confused).map(|a| a.work_bits()),
            Err(AdmissionErrorV1::Unavailable(
                VerificationUnavailableV1::ScopeLookup
            ))
        );
    }
}
