//! Preparing registrations and ballots, and the originated or relayed submission.

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};

use iroha_data_model::{
    account::AccountId,
    governance::{
        anonymous_ballot::{
            AdmissionStampV1, AnonymousBallotAuthorizationV1, AnonymousBallotEnvelopeV1,
            AnonymousBallotV1, BallotProofBytesV1, BallotScopeV1,
            CanonicalAnonymousBallotEnvelopeV1, CredentialCommitmentV1, CredentialRegistrationV1,
            NullifierV1, RegistrationAuthorizationV1, RegistrationProofBytesV1,
            digests::authority_binding_v1,
        },
        types::AssignmentId,
    },
};
use iroha_parliament_ballot_proof::{
    credential::CredentialSecret,
    proving::{ProveError, ProvingTape},
    registration::{self, RegistrationStatement},
    vote::{self, VoteStatement},
};

use super::{
    WalletErrorV1, credential::CredentialHandleV1, disclosure::BallotDisclosureAcknowledgementV1,
};
use crate::{
    PROOF_ROW_V1,
    context::ScopedBallotContextV1,
    entropy::{EntropySource, OsEntropy},
    inputs::{
        ProofInputErrorV1, ProofValueV1, body_context_input_v1, proof_profile_v1,
        registration_context_v1,
    },
    stamp::mine_stamp_with,
};

/// Most proving invocations of one preparation. Each consumes its own fresh tape and counts
/// as a fresh proof generation under the per-credential transcript ceiling.
pub const MAX_PROVING_ATTEMPTS_V1: u8 = 4;

/// Local options of a ballot preparation. They change how fast it runs, never what it
/// produces: any stamp that reaches the frozen difficulty is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotPreparationOptionsV1 {
    /// Threads of the stamp search.
    pub stamp_threads: NonZeroUsize,
}

impl Default for BallotPreparationOptionsV1 {
    fn default() -> Self {
        Self {
            stamp_threads: std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
        }
    }
}

/// Whether a submission originates a choice or relays an envelope prepared elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubmissionOriginV1 {
    /// This wallet proved the locked choice of its own credential.
    OriginatedChoice,
    /// An already prepared envelope relayed unchanged; relaying confers no authority and
    /// cannot change any field of the statement.
    Relay,
}

/// A canonical envelope ready for signerless submission, with its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotSubmissionV1 {
    envelope: CanonicalAnonymousBallotEnvelopeV1,
    origin: SubmissionOriginV1,
}

impl BallotSubmissionV1 {
    /// Relay an envelope prepared elsewhere: the bytes must be exactly one canonical envelope
    /// frame. No credential or acknowledgement is involved.
    ///
    /// # Errors
    /// [`WalletErrorV1::Codec`] for any other bytes.
    pub fn relay_v1(bytes: Vec<u8>) -> Result<Self, WalletErrorV1> {
        Ok(Self {
            envelope: CanonicalAnonymousBallotEnvelopeV1::from_canonical_bytes(bytes)?,
            origin: SubmissionOriginV1::Relay,
        })
    }

    /// Whether this submission originates a choice or relays one.
    pub fn origin(&self) -> SubmissionOriginV1 {
        self.origin
    }

    /// The canonical envelope.
    pub fn envelope(&self) -> &CanonicalAnonymousBallotEnvelopeV1 {
        &self.envelope
    }

    /// The exact bytes to submit.
    pub fn as_bytes(&self) -> &[u8] {
        self.envelope.as_bytes()
    }

    /// The ballot identity `(scope, nullifier)`, by which acceptance is confirmed in the
    /// scope's public corpus.
    ///
    /// # Errors
    /// [`WalletErrorV1::Codec`], which a constructed submission never causes.
    pub fn identity(&self) -> Result<(BallotScopeV1, NullifierV1), WalletErrorV1> {
        Ok(self.envelope.envelope()?.ballot.identity())
    }

    /// The canonical envelope, consuming the submission.
    pub fn into_envelope(self) -> CanonicalAnonymousBallotEnvelopeV1 {
        self.envelope
    }
}

/// Prove with a fresh tape per invocation: an exhausted counter range retries the unchanged
/// statement with an entirely fresh tape, at most [`MAX_PROVING_ATTEMPTS_V1`] times. A tape
/// is drawn only when an invocation starts, and an entropy failure ends the preparation
/// without a proof.
pub fn prove_with_fresh_tapes<E, F>(
    entropy: &mut E,
    cancel: &AtomicBool,
    mut prove: F,
) -> Result<Vec<u8>, WalletErrorV1>
where
    E: EntropySource,
    F: FnMut(ProvingTape) -> Result<Vec<u8>, ProveError>,
{
    for _ in 0..MAX_PROVING_ATTEMPTS_V1 {
        if cancel.load(Ordering::Relaxed) {
            return Err(WalletErrorV1::Cancelled);
        }
        let tape = ProvingTape::fill_with(|buffer| entropy.fill(buffer))?;
        match prove(tape) {
            Ok(proof) => return Ok(proof),
            Err(ProveError::GrindingExhausted { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(WalletErrorV1::ProvingExhausted {
        attempts: MAX_PROVING_ATTEMPTS_V1,
    })
}

/// The production registration prover on the candidate row.
pub fn registration_prover(
    statement: &RegistrationStatement,
    secret: &CredentialSecret,
    tape: ProvingTape,
) -> Result<Vec<u8>, ProveError> {
    registration::prove(PROOF_ROW_V1, statement, secret, tape)
}

/// The production vote prover on the candidate row.
pub fn vote_prover(
    statement: &VoteStatement,
    secret: &CredentialSecret,
    position: u16,
    tape: ProvingTape,
) -> Result<Vec<u8>, ProveError> {
    vote::prove(PROOF_ROW_V1, statement, secret, position, tape)
}

/// Prepare the registration of `handle`'s credential for the seat `assignment_id`, registered
/// by `authority`: `C`, `auth` and a proof made with a fresh tape from the operating system.
///
/// # Errors
/// [`WalletErrorV1::Entropy`] without a random source, [`WalletErrorV1::ProvingExhausted`]
/// after [`MAX_PROVING_ATTEMPTS_V1`] exhausted invocations, and input or prover errors.
pub fn prepare_registration_v1(
    handle: &CredentialHandleV1,
    authority: &AccountId,
    assignment_id: &AssignmentId,
) -> Result<CredentialRegistrationV1, WalletErrorV1> {
    prepare_registration_with(
        handle,
        authority,
        assignment_id,
        &AtomicBool::new(false),
        &mut OsEntropy,
        registration_prover,
    )
}

/// [`prepare_registration_v1`] with injected entropy, prover and cancellation flag.
pub fn prepare_registration_with<E, P>(
    handle: &CredentialHandleV1,
    authority: &AccountId,
    assignment_id: &AssignmentId,
    cancel: &AtomicBool,
    entropy: &mut E,
    mut prove: P,
) -> Result<CredentialRegistrationV1, WalletErrorV1>
where
    E: EntropySource,
    P: FnMut(&RegistrationStatement, &CredentialSecret, ProvingTape) -> Result<Vec<u8>, ProveError>,
{
    let profile = proof_profile_v1()?;
    let binding = authority_binding_v1(authority).map_err(ProofInputErrorV1::from)?;
    let statement = RegistrationStatement::for_secret(
        &profile,
        handle.secret(),
        body_context_input_v1(handle.body_context())?,
        registration_context_v1(handle.body_context(), &binding, assignment_id)?,
    )?;
    let proof = prove_with_fresh_tapes(entropy, cancel, |tape| {
        prove(&statement, handle.secret(), tape)
    })?;
    if cancel.load(Ordering::Relaxed) {
        return Err(WalletErrorV1::Cancelled);
    }
    Ok(CredentialRegistrationV1 {
        commitment: CredentialCommitmentV1::from_proof(statement.commitment()),
        authorization: RegistrationAuthorizationV1::from_proof(statement.auth()),
        proof: RegistrationProofBytesV1::new(proof)?,
    })
}

/// Prepare the ballot of `handle`'s persisted choice lock in `context`'s scope: check the
/// credential, the acknowledgement and the lock, find the credential's position in the
/// sealed list, prove the locked statement with a fresh tape, mine the stamp at the frozen
/// difficulty and return the canonical envelope as an originated submission.
///
/// `cancel` is checked before every proving invocation and the stamp search observes it
/// cooperatively; once it is set no result is returned.
///
/// # Errors
/// [`WalletErrorV1::ForeignBody`], [`WalletErrorV1::DisclosureMismatch`],
/// [`WalletErrorV1::NotOnSealedList`], [`WalletErrorV1::ChoiceNotLocked`],
/// [`WalletErrorV1::ChoiceNotPersisted`], [`WalletErrorV1::ChoiceRecordMismatch`],
/// [`WalletErrorV1::Entropy`], [`WalletErrorV1::ProvingExhausted`],
/// [`WalletErrorV1::Cancelled`] and prover, stamp or codec errors.
pub fn prepare_ballot_v1(
    handle: &CredentialHandleV1,
    context: &ScopedBallotContextV1,
    acknowledgement: &BallotDisclosureAcknowledgementV1,
    options: BallotPreparationOptionsV1,
    cancel: &AtomicBool,
) -> Result<BallotSubmissionV1, WalletErrorV1> {
    prepare_ballot_with(
        handle,
        context,
        acknowledgement,
        options,
        cancel,
        &mut OsEntropy,
        vote_prover,
    )
}

/// [`prepare_ballot_v1`] with injected entropy and prover.
pub fn prepare_ballot_with<E, P>(
    handle: &CredentialHandleV1,
    context: &ScopedBallotContextV1,
    acknowledgement: &BallotDisclosureAcknowledgementV1,
    options: BallotPreparationOptionsV1,
    cancel: &AtomicBool,
    entropy: &mut E,
    mut prove: P,
) -> Result<BallotSubmissionV1, WalletErrorV1>
where
    E: EntropySource,
    P: FnMut(&VoteStatement, &CredentialSecret, u16, ProvingTape) -> Result<Vec<u8>, ProveError>,
{
    handle.check_ballot(context, acknowledgement)?;
    let intent = handle.persisted_lock(context)?;
    let position = handle.position(context)?;
    let statement = handle.statement(context, intent.vote)?;
    let proof = prove_with_fresh_tapes(entropy, cancel, |tape| {
        prove(&statement, handle.secret(), position, tape)
    })?;
    let authorization = AnonymousBallotAuthorizationV1 {
        network_id: intent.network_id,
        scope: intent.scope,
        vote: intent.vote,
        nullifier: intent.nullifier,
        auth_v: intent.auth_v,
        profile_id: intent.profile_id,
        proof: BallotProofBytesV1::new(proof)?,
    };
    let mined = mine_stamp_with(
        &authorization,
        context.context(),
        options.stamp_threads,
        cancel,
        entropy,
    )?;
    let envelope = AnonymousBallotEnvelopeV1 {
        network_id: authorization.network_id,
        ballot: AnonymousBallotV1 {
            scope: authorization.scope,
            vote: authorization.vote,
            nullifier: authorization.nullifier,
            auth_v: authorization.auth_v,
            profile_id: authorization.profile_id,
            stamp: AdmissionStampV1 {
                nonce: mined.stamp.nonce,
            },
            proof: authorization.proof,
        },
    };
    let envelope = CanonicalAnonymousBallotEnvelopeV1::from_envelope(&envelope)?;
    // The publication boundary of the synchronous call: a cancellation requested by now
    // discards the result.
    if cancel.load(Ordering::Relaxed) {
        return Err(WalletErrorV1::Cancelled);
    }
    Ok(BallotSubmissionV1 {
        envelope,
        origin: SubmissionOriginV1::OriginatedChoice,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        num::{NonZeroU64, NonZeroUsize},
        sync::Arc,
    };

    use iroha_data_model::{
        NetworkId,
        governance::{
            GovernanceAnchorV1,
            anonymous_ballot::{BallotChoiceV1, BallotScopeV1},
        },
    };

    use super::*;
    use crate::{
        ballot::{
            AdmissionScopeV1, AdmissionStateV1, BlockBallotDecisionV1, BlockBallotStateV1,
            CastingWindowStatusV1, decide_block_ballot_v1, precheck_admission_v1,
        },
        corpus::{ClosureAnchorsV1, CorpusAccumulatorV1, build_closure_record_v1},
        entropy::ScriptedEntropy,
        registration::verify_registration_v1,
        test_support::{
            AYE_0, FIXTURE_BALLOTS, account, body_context, fixture_bytes, network_id,
            proposal_content_id, scoped_context, secret_bytes, tape,
        },
        wallet::{BallotDisclosureV1, DisclosureStatementV1},
    };

    fn one_thread() -> BallotPreparationOptionsV1 {
        BallotPreparationOptionsV1 {
            stamp_threads: NonZeroUsize::MIN,
        }
    }

    /// Member 0's handle with its Aye choice locked and confirmed persisted.
    fn locked_member_0() -> (CredentialHandleV1, BallotDisclosureAcknowledgementV1) {
        let context = scoped_context();
        let acknowledgement = BallotDisclosureV1::for_context_v1(&context)
            .acknowledge(&DisclosureStatementV1::ALL)
            .expect("acknowledged");
        let mut handle =
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(0), None).expect("handle");
        let intent = handle
            .lock_choice_v1(&context, BallotChoiceV1::Aye, &acknowledgement)
            .expect("locked");
        handle
            .confirm_choice_persisted_v1(&intent.record_bytes().expect("record"))
            .expect("confirmed");
        (handle, acknowledgement)
    }

    /// The fixture tape of `AYE_0` and its pinned stamp nonce, as the entropy script.
    fn fixture_script(extra_tapes: usize) -> ScriptedEntropy {
        let ballot = FIXTURE_BALLOTS[AYE_0];
        let mut chunks: Vec<_> = (0..extra_tapes).map(|_| Some(vec![0xee; 112])).collect();
        chunks.push(Some(tape(ballot.tape).to_vec()));
        chunks.push(Some(ballot.nonce.to_vec()));
        ScriptedEntropy::new(chunks)
    }

    /// A node with the fixture scope open and nothing accepted yet.
    struct Node {
        accepted: Cell<bool>,
    }

    impl AdmissionStateV1 for Node {
        fn network_id(&self) -> NetworkId {
            network_id()
        }
        fn scope(&self, scope: &BallotScopeV1) -> Option<AdmissionScopeV1> {
            let context = scoped_context();
            (context.scope() == scope).then_some(AdmissionScopeV1 {
                context,
                window: CastingWindowStatusV1::Open,
            })
        }
        fn nullifier_committed(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
            self.accepted.get()
        }
        fn verified_pending_holder(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
            false
        }
    }

    impl BlockBallotStateV1 for Node {
        fn network_id(&self) -> NetworkId {
            network_id()
        }
        fn scope_context(&self, scope: &BallotScopeV1) -> Option<Arc<ScopedBallotContextV1>> {
            let context = scoped_context();
            (context.scope() == scope).then_some(context)
        }
        fn casting_open(&self, _: &BallotScopeV1) -> bool {
            true
        }
        fn nullifier_accepted(&self, _: &BallotScopeV1, _: &NullifierV1) -> bool {
            self.accepted.get()
        }
    }

    #[test]
    fn a_wallet_ballot_goes_through_admission_execution_corpus_and_closure() {
        let context = scoped_context();
        let (handle, acknowledgement) = locked_member_0();
        let mut entropy = fixture_script(0);
        let submission = prepare_ballot_with(
            &handle,
            &context,
            &acknowledgement,
            one_thread(),
            &AtomicBool::new(false),
            &mut entropy,
            vote_prover,
        )
        .expect("prepared");
        // With the fixture tape and start nonce the wallet reproduces the independently
        // proved fixture byte for byte.
        assert_eq!(entropy.calls, 2);
        assert_eq!(submission.origin(), SubmissionOriginV1::OriginatedChoice);
        assert_eq!(submission.as_bytes(), &fixture_bytes(AYE_0)[..]);
        let lock = handle.choice_lock().expect("locked");
        assert_eq!(submission.identity(), Ok(lock.identity()));
        // Queue admission, the separate proof verification and the atomic recheck.
        let node = Node {
            accepted: Cell::new(false),
        };
        let admitted = precheck_admission_v1(submission.as_bytes(), &node).expect("admitted");
        let verified = admitted.verify_proof().expect("verified");
        assert_eq!(verified.recheck(&node), Ok(()));
        // Block execution accepts it into the corpus.
        let decision = decide_block_ballot_v1(
            &node,
            verified.canonical().as_bytes(),
            NonZeroU64::new(100).expect("nonzero"),
            0,
        )
        .expect("decidable");
        let BlockBallotDecisionV1::Accepted(entry) = decision else {
            panic!("accepted");
        };
        let mut corpus = CorpusAccumulatorV1::new(&context).expect("corpus");
        assert_eq!(corpus.append(&entry), Ok(0));
        node.accepted.set(true);
        // A resubmission is now refused at admission and rejected at execution.
        assert!(precheck_admission_v1(submission.as_bytes(), &node).is_err());
        let duplicate = decide_block_ballot_v1(
            &node,
            submission.as_bytes(),
            NonZeroU64::new(101).expect("nonzero"),
            0,
        )
        .expect("decidable");
        assert!(matches!(duplicate, BlockBallotDecisionV1::Rejected(_)));
        // One ballot of four seats closes NoQuorum.
        let anchors = ClosureAnchorsV1 {
            opening: GovernanceAnchorV1 {
                height: 100,
                position: 0,
                timestamp_ms: 1_000_000,
            },
            casting_clock_height: 101,
            casting_clock_timestamp_ms: 1_001_000,
            closure: GovernanceAnchorV1 {
                height: 102,
                position: 0,
                timestamp_ms: 87_401_000,
            },
        };
        let record = build_closure_record_v1(
            &context,
            proposal_content_id(),
            iroha_data_model::governance::anonymous_ballot::Digest512::new([4; 64]),
            &anchors,
            &corpus,
        )
        .expect("record");
        assert_eq!(record.accepted_ballots, 1);
        assert_eq!(
            record.outcome,
            iroha_data_model::governance::anonymous_ballot::BallotOutcomeV1::NoQuorum
        );
    }

    #[test]
    fn an_exhausted_invocation_retries_the_same_statement_with_a_fresh_tape() {
        let context = scoped_context();
        let (handle, acknowledgement) = locked_member_0();
        let mut entropy = fixture_script(1);
        let mut statements = Vec::new();
        let mut invocations = 0;
        let submission = prepare_ballot_with(
            &handle,
            &context,
            &acknowledgement,
            one_thread(),
            &AtomicBool::new(false),
            &mut entropy,
            |statement: &VoteStatement, secret: &CredentialSecret, position, tape| {
                invocations += 1;
                statements.push(statement.clone());
                if invocations == 1 {
                    // The first invocation consumes its tape and exhausts.
                    drop(tape);
                    Err(ProveError::GrindingExhausted { last: 0x000f_ffff })
                } else {
                    vote_prover(statement, secret, position, tape)
                }
            },
        )
        .expect("prepared");
        assert_eq!(invocations, 2);
        assert_eq!(statements[0], statements[1]);
        assert_eq!(entropy.calls, 3);
        assert_eq!(submission.as_bytes(), &fixture_bytes(AYE_0)[..]);
    }

    #[test]
    fn exhaustion_entropy_failure_and_cancellation_produce_no_ballot() {
        let context = scoped_context();
        let (handle, acknowledgement) = locked_member_0();
        let never = |_: &VoteStatement, _: &CredentialSecret, _: u16, _: ProvingTape| {
            Err(ProveError::GrindingExhausted { last: 0x000f_ffff })
        };
        let mut entropy = ScriptedEntropy::new(vec![Some(vec![1; 112]); 4]);
        assert_eq!(
            prepare_ballot_with(
                &handle,
                &context,
                &acknowledgement,
                one_thread(),
                &AtomicBool::new(false),
                &mut entropy,
                never,
            ),
            Err(WalletErrorV1::ProvingExhausted {
                attempts: MAX_PROVING_ATTEMPTS_V1
            })
        );
        assert_eq!(entropy.calls, usize::from(MAX_PROVING_ATTEMPTS_V1));
        // No entropy: the prover is never invoked.
        let mut failing = ScriptedEntropy::new([None]);
        let unreachable = |_: &VoteStatement, _: &CredentialSecret, _: u16, _: ProvingTape| {
            panic!("no tape, no proving")
        };
        assert!(matches!(
            prepare_ballot_with(
                &handle,
                &context,
                &acknowledgement,
                one_thread(),
                &AtomicBool::new(false),
                &mut failing,
                unreachable,
            ),
            Err(WalletErrorV1::Entropy(_))
        ));
        // A cancellation requested before proving stops it.
        assert_eq!(
            prepare_ballot_v1(
                &handle,
                &context,
                &acknowledgement,
                one_thread(),
                &AtomicBool::new(true)
            ),
            Err(WalletErrorV1::Cancelled)
        );
    }

    #[test]
    fn the_lock_must_be_persisted_and_the_acknowledgement_must_match() {
        let context = scoped_context();
        let acknowledgement = BallotDisclosureV1::for_context_v1(&context)
            .acknowledge(&DisclosureStatementV1::ALL)
            .expect("acknowledged");
        let mut handle =
            CredentialHandleV1::import_v1(body_context(), &secret_bytes(1), None).expect("handle");
        let unreachable = |_: &VoteStatement, _: &CredentialSecret, _: u16, _: ProvingTape| {
            panic!("refused before proving")
        };
        let attempt = |handle: &CredentialHandleV1, acknowledgement| {
            prepare_ballot_with(
                handle,
                &context,
                acknowledgement,
                one_thread(),
                &AtomicBool::new(false),
                &mut ScriptedEntropy::new([]),
                unreachable,
            )
        };
        assert_eq!(
            attempt(&handle, &acknowledgement),
            Err(WalletErrorV1::ChoiceNotLocked)
        );
        handle
            .lock_choice_v1(&context, BallotChoiceV1::Nay, &acknowledgement)
            .expect("locked");
        assert_eq!(
            attempt(&handle, &acknowledgement),
            Err(WalletErrorV1::ChoiceNotPersisted)
        );
        let other = ScopedBallotContextV1::new(
            context.context().clone(),
            iroha_data_model::governance::types::BodyInstanceId::new([5; 32]),
        )
        .expect("context");
        let elsewhere = BallotDisclosureV1::for_context_v1(&other)
            .acknowledge(&DisclosureStatementV1::ALL)
            .expect("acknowledged");
        assert_eq!(
            attempt(&handle, &elsewhere),
            Err(WalletErrorV1::DisclosureMismatch)
        );
    }

    #[test]
    fn relaying_is_distinguishable_from_originating() {
        let relayed = BallotSubmissionV1::relay_v1(fixture_bytes(AYE_0)).expect("relayed");
        assert_eq!(relayed.origin(), SubmissionOriginV1::Relay);
        assert_eq!(relayed.as_bytes(), &fixture_bytes(AYE_0)[..]);
        assert_eq!(relayed.envelope().as_bytes(), &fixture_bytes(AYE_0)[..]);
        assert!(relayed.identity().is_ok());
        assert_eq!(
            relayed.clone().into_envelope().as_bytes(),
            &fixture_bytes(AYE_0)[..]
        );
        let mut altered = fixture_bytes(AYE_0);
        altered.push(0);
        assert!(matches!(
            BallotSubmissionV1::relay_v1(altered),
            Err(WalletErrorV1::Codec(_))
        ));
        assert!(BallotPreparationOptionsV1::default().stamp_threads.get() >= 1);
    }

    #[test]
    fn a_registration_is_proved_with_a_fresh_tape_and_verifies() {
        let handle = CredentialHandleV1::generate_v1(body_context()).expect("credential");
        let assignment = AssignmentId::new([0x41; 32]);
        let registration =
            prepare_registration_v1(&handle, &account(), &assignment).expect("registration");
        assert_eq!(&registration.commitment, handle.commitment());
        assert_eq!(
            verify_registration_v1(&body_context(), &account(), &assignment, &registration),
            Ok(())
        );
        // Every exhausted invocation retries the unchanged statement with a fresh tape, up to
        // the bound.
        let mut statements: Vec<RegistrationStatement> = Vec::new();
        assert_eq!(
            prepare_registration_with(
                &handle,
                &account(),
                &assignment,
                &AtomicBool::new(false),
                &mut OsEntropy,
                |statement: &RegistrationStatement, _: &CredentialSecret, tape: ProvingTape| {
                    statements.push(statement.clone());
                    drop(tape);
                    Err(ProveError::GrindingExhausted { last: 0x000f_ffff })
                },
            ),
            Err(WalletErrorV1::ProvingExhausted {
                attempts: MAX_PROVING_ATTEMPTS_V1
            })
        );
        assert_eq!(statements.len(), usize::from(MAX_PROVING_ATTEMPTS_V1));
        assert!(statements.windows(2).all(|pair| pair[0] == pair[1]));
        // No entropy, no registration.
        assert!(matches!(
            prepare_registration_with(
                &handle,
                &account(),
                &assignment,
                &AtomicBool::new(false),
                &mut ScriptedEntropy::new([None]),
                |_: &RegistrationStatement,
                 _: &CredentialSecret,
                 _: ProvingTape|
                 -> Result<Vec<u8>, ProveError> { panic!("no tape, no proving") },
            ),
            Err(WalletErrorV1::Entropy(_))
        ));
    }
}
