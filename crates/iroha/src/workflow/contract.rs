//! Closed vocabularies, bounds and transition tables of the durable workflow contract.
//!
//! This module is the Rust source of `fixtures/zk/workflow_v1/state_machine.json`. A test
//! renders [`state_machine_json`] and fails when the tracked file differs, so the JSON that the
//! other SDK families read cannot drift from the tables the Rust engine executes.

use norito::{
    derive::{Decode, Encode},
    json::{Map, Value},
};

/// Schema identifier of the machine-readable state machine.
pub const STATE_MACHINE_SCHEMA_V1: &str = "iroha.durable_workflow.state_machine.v1";
/// Layout version stored in every journal.
pub const WORKFLOW_JOURNAL_VERSION_V1: u16 = 1;
/// The only atomicity a workflow offers: each transaction is atomic, the sequence is not.
pub const WORKFLOW_ATOMICITY_V1: &str = "per_transaction_only";

/// Maximum number of steps in one plan.
pub const MAX_WORKFLOW_STEPS_V1: usize = 64;
/// Maximum byte length of an instance, step, driver or custody label.
pub const MAX_WORKFLOW_LABEL_BYTES_V1: usize = 64;
/// Maximum byte length of the account binding strings.
pub const MAX_WORKFLOW_BINDING_BYTES_V1: usize = 256;
/// Maximum number of transaction identities one step may ever open.
pub const MAX_TRANSACTION_IDENTITIES_PER_STEP_V1: u8 = 8;
/// Maximum number of counted dispatches of one signed transaction identity.
///
/// A dispatch counts unless it is proven not to have admitted the bytes while no
/// earlier dispatch of the identity may have been admitted. The bound therefore
/// covers the dispatch that may have been admitted and every retransmission.
pub const MAX_DISPATCHES_PER_IDENTITY_V1: u8 = 8;
/// Maximum canonical signed transaction (and unsigned payload) size kept in a journal.
///
/// Equal to the committed `max_tx_bytes` default recorded in `specs/zk_resource_contract.json`.
pub const MAX_WORKFLOW_TRANSACTION_BYTES_V1: usize = 10_485_760;
/// Maximum public transcript size of one off-chain round.
pub const MAX_ROUND_TRANSCRIPT_BYTES_V1: usize = 1_048_576;
/// Maximum number of participants one round may report.
pub const MAX_ROUND_PARTICIPANTS_V1: usize = 1_024;
/// Maximum number of custody handles one round may return.
pub const MAX_CUSTODY_HANDLES_PER_ROUND_V1: usize = 64;
/// Maximum byte length of one opaque custody reference.
pub const MAX_CUSTODY_REFERENCE_BYTES_V1: usize = 128;
/// Maximum byte length of a retained diagnostic string.
pub const MAX_WORKFLOW_DETAIL_BYTES_V1: usize = 512;
/// Maximum canonical journal record size.
pub const MAX_WORKFLOW_JOURNAL_BYTES_V1: usize = 16 * 1_048_576;

/// Worst-case record bytes outside the steps: frame header, journal digest, identity with
/// maximal binding texts, status, failure, timestamps and the fixed 200-byte
/// native payment completion locator (plus its canonical field framing).
pub const JOURNAL_FIXED_RECORD_BYTES_V1: usize = 2_048;
/// Worst-case record bytes of one step without identities, participants, custody or bytes.
pub const STEP_FIXED_RECORD_BYTES_V1: usize = 512;
/// Worst-case record bytes of one transaction identity with maximal terminal evidence.
pub const IDENTITY_RECORD_BYTES_V1: usize = 768;
/// Worst-case record bytes of the transaction the current step retains.
pub const RETAINED_TRANSACTION_RECORD_BYTES_V1: usize = MAX_WORKFLOW_TRANSACTION_BYTES_V1 + 32;
/// Record bytes of one round participant.
pub const PARTICIPANT_RECORD_BYTES_V1: usize = 65;
/// Worst-case record bytes of one custody handle.
pub const CUSTODY_HANDLE_RECORD_BYTES_V1: usize = 224;
/// Record bytes a transcript adds to its own length.
pub const TRANSCRIPT_FRAMING_RECORD_BYTES_V1: usize = 32;
// The largest single-step plans fit: one retained transaction, or one maximal round.
const _: () = assert!(
    MAX_WORKFLOW_JOURNAL_BYTES_V1
        > JOURNAL_FIXED_RECORD_BYTES_V1
            + STEP_FIXED_RECORD_BYTES_V1
            + IDENTITY_RECORD_BYTES_V1 * MAX_TRANSACTION_IDENTITIES_PER_STEP_V1 as usize
            + RETAINED_TRANSACTION_RECORD_BYTES_V1
);
const _: () = assert!(
    MAX_WORKFLOW_JOURNAL_BYTES_V1
        > JOURNAL_FIXED_RECORD_BYTES_V1
            + STEP_FIXED_RECORD_BYTES_V1
            + PARTICIPANT_RECORD_BYTES_V1 * MAX_ROUND_PARTICIPANTS_V1
            + CUSTODY_HANDLE_RECORD_BYTES_V1 * MAX_CUSTODY_HANDLES_PER_ROUND_V1
            + MAX_ROUND_TRANSCRIPT_BYTES_V1
            + TRANSCRIPT_FRAMING_RECORD_BYTES_V1
);

macro_rules! contract_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $id:literal,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Encode, Decode)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// Every value, in contract order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Stable identifier used by the contract, fixtures and progress reports.
            #[must_use]
            pub const fn id(self) -> &'static str {
                match self {
                    $(Self::$variant => $id,)+
                }
            }

            /// Parse a stable contract identifier.
            #[must_use]
            pub fn from_id(id: &str) -> Option<Self> {
                match id {
                    $($id => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(self.id())
            }
        }
    };
}

contract_enum! {
    /// Separately named multi-round processes. The kind is bound into the workflow identity.
    pub enum WorkflowKindV1 {
        /// Issuer or pool bootstrap: administrative transactions and issuer rounds.
        IssuerBootstrap => "issuer_bootstrap",
        /// Distributed key generation among a committee.
        Dkg => "dkg",
        /// Threshold share collection followed by the opening transaction.
        ThresholdOpening => "threshold_opening",
        /// One native payment carrier with independently verified business completion.
        NativePayment => "native_payment",
        /// One supervised authenticated AMX relay carrier with its exact durable identity.
        AmxRelay => "amx_relay",
        /// Prepared confidential artifacts, durable certificates and two verified carriers.
        PrivateSettlement => "private_settlement",
    }
}

contract_enum! {
    /// What one step does.
    pub enum StepKindV1 {
        /// One signed ledger transaction; atomic by itself.
        Transaction => "transaction",
        /// One off-chain round among participants.
        OffchainRound => "offchain_round",
    }
}

contract_enum! {
    /// Status of the whole workflow.
    pub enum WorkflowStatusV1 {
        /// Not terminal; a run may make progress.
        InProgress => "in_progress",
        /// Terminal: every step is finalized or completed.
        Completed => "completed",
        /// Cancellation was requested while a step may still have external effect.
        Cancelling => "cancelling",
        /// Terminal: cancelled; earlier progress is not rolled back.
        Cancelled => "cancelled",
        /// Terminal: a step failed for good; earlier progress is not rolled back.
        Failed => "failed",
    }
}

impl WorkflowStatusV1 {
    /// Whether no later call can change the workflow.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

contract_enum! {
    /// Durable state of one transaction operation.
    ///
    /// The reducer over these states is independent of workflows; a single
    /// operation of the one-call SDK core uses the same table.
    pub enum TransactionStateV1 {
        /// Nothing has been done.
        Planned => "planned",
        /// A transaction identity slot is open; nothing is computed yet.
        Prepared => "prepared",
        /// The capability driver is proving and building the payload.
        Proving => "proving",
        /// The exact unsigned payload is persisted.
        ReadyToSign => "ready_to_sign",
        /// The signed bytes and their identity are persisted; no dispatch of them counts.
        Signed => "signed",
        /// The dispatch ordinal is persisted; the bytes may have left the client.
        Submitting => "submitting",
        /// A dispatch may have been admitted and nothing authoritative is known.
        OutcomeUnknown => "outcome_unknown",
        /// The network has acknowledged or shown the transaction; finality is not established.
        Pending => "pending",
        /// Authoritative state-resolved success.
        Finalized => "finalized",
        /// The identity can never apply: refused on its only counted dispatch, rejected or expired.
        Rejected => "rejected",
        /// Cancelled while no dispatch could have been admitted.
        CancelledBeforeSubmission => "cancelled_before_submission",
    }
}

impl TransactionStateV1 {
    /// Whether a dispatch of the current identity may still commit.
    #[must_use]
    pub const fn may_still_commit(self) -> bool {
        matches!(
            self,
            Self::Submitting | Self::OutcomeUnknown | Self::Pending
        )
    }

    /// Whether the state holds the canonical signed bytes.
    #[must_use]
    pub const fn holds_signed_bytes(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::Submitting | Self::OutcomeUnknown | Self::Pending
        )
    }
}

contract_enum! {
    /// Inputs of the transaction reducer.
    pub enum TransactionEventV1 {
        /// Open the first or a replacement transaction identity.
        OpenAttempt => "open_attempt",
        /// The driver starts proving and building.
        BuildStarted => "build_started",
        /// The driver failed before any payload existed.
        BuildFailed => "build_failed",
        /// The driver returned the exact unsigned payload.
        PayloadBuilt => "payload_built",
        /// The account context signed the payload.
        Signed => "signed",
        /// Persist the next dispatch ordinal before sending.
        DispatchIntent => "dispatch_intent",
        /// The submission owner acknowledged admission.
        DispatchAccepted => "dispatch_accepted",
        /// The submission owner proved the transaction is already queued or committed.
        DispatchAlreadyKnown => "dispatch_already_known",
        /// The dispatch result cannot be established.
        DispatchAmbiguous => "dispatch_ambiguous",
        /// A persisted dispatch ordinal has no recorded result.
        DispatchInterrupted => "dispatch_interrupted",
        /// A validated definite refusal of this dispatch.
        DispatchRefused => "dispatch_refused",
        /// This dispatch did not admit the bytes and they may be sent again. With no earlier
        /// possible admission the dispatch ordinal is released.
        DispatchNotAdmitted => "dispatch_not_admitted",
        /// A read showed the transaction in the pipeline without authoritative finality.
        ObservedInPipeline => "observed_in_pipeline",
        /// Authoritative state-resolved `Applied`.
        ReconciledApplied => "reconciled_applied",
        /// Authoritative state-resolved `Rejected`.
        ReconciledRejected => "reconciled_rejected",
        /// Authoritative state-resolved `Expired`.
        ReconciledExpired => "reconciled_expired",
        /// Cancellation of an operation that cannot have been admitted.
        Cancel => "cancel",
    }
}

contract_enum! {
    /// Guards of transaction transitions.
    pub enum TransactionGuardV1 {
        /// Always allowed.
        Always => "always",
        /// The step may still open a transaction identity.
        IdentitiesRemaining => "identities_remaining",
        /// Explicit authorization, a fresh exact-absence read and a dispatch left in the bound.
        RetransmissionAuthorized => "retransmission_authorized_after_exact_absence",
        /// No dispatch of this identity may have been admitted.
        NoPossibleAdmission => "no_possible_admission",
        /// An earlier dispatch of this identity may have been admitted.
        PossibleAdmission => "possible_admission",
    }
}

contract_enum! {
    /// Durable state of one off-chain round.
    pub enum RoundStateV1 {
        /// Nothing has been done.
        Planned => "planned",
        /// The round identity is persisted; the driver may have produced external effects.
        RoundStarted => "round_started",
        /// The round runs and waits for participants; the received set is persisted.
        RoundWaiting => "round_waiting",
        /// The public transcript and custody references are persisted.
        RoundCompleted => "round_completed",
        /// The round failed for good.
        RoundFailed => "round_failed",
    }
}

impl RoundStateV1 {
    /// Whether the round may have unresolved external effects.
    #[must_use]
    pub const fn is_unresolved(self) -> bool {
        matches!(self, Self::RoundStarted | Self::RoundWaiting)
    }
}

contract_enum! {
    /// Inputs of the round reducer.
    pub enum RoundEventV1 {
        /// Persist the round identity before the driver starts the round.
        Intent => "round_intent",
        /// The driver reports the round is waiting for participants.
        Waiting => "round_waiting",
        /// The driver returned the transcript and custody references.
        Completed => "round_completed",
        /// The driver reports a terminal failure.
        Failed => "round_failed",
        /// Read-only recovery proved the round never started (cancellation only).
        NotStarted => "round_not_started",
        /// Persist the restart of a round that recovery proved never started, before the
        /// driver starts it under the same identity.
        RestartIntent => "round_restart_intent",
    }
}

contract_enum! {
    /// Guards of round transitions.
    pub enum RoundGuardV1 {
        /// Allowed whatever the workflow status.
        Always => "always",
        /// Allowed only while the workflow is not cancelling: the row starts an effect.
        NotCancelling => "not_cancelling",
        /// Allowed only while the workflow is cancelling.
        WhileCancelling => "while_cancelling",
    }
}

impl RoundGuardV1 {
    /// Evaluate the guard for a workflow that is or is not cancelling.
    #[must_use]
    pub const fn holds(self, cancelling: bool) -> bool {
        match self {
            Self::Always => true,
            Self::NotCancelling => !cancelling,
            Self::WhileCancelling => cancelling,
        }
    }
}

contract_enum! {
    /// Inputs of the workflow status table.
    pub enum WorkflowEventV1 {
        /// Every step is finalized or completed.
        AllStepsDone => "all_steps_done",
        /// A step failed for good.
        StepFailed => "step_failed",
        /// Cancellation while the current step cannot have external effect.
        CancelResolved => "cancel_without_unresolved_effect",
        /// Cancellation while the current step may still have external effect.
        CancelUnresolved => "cancel_with_unresolved_effect",
        /// The unresolved step of a cancelling workflow resolved.
        UnresolvedEffectResolved => "unresolved_effect_resolved",
    }
}

contract_enum! {
    /// Terminal evidence retained for one transaction identity.
    pub enum AttemptEvidenceKindV1 {
        /// Authoritative state-resolved `Applied`.
        Applied => "applied",
        /// Validated definite refusal of the only dispatch.
        AdmissionRefused => "admission_refused",
        /// Authoritative state-resolved `Rejected`.
        LedgerRejected => "ledger_rejected",
        /// Authoritative state-resolved `Expired`.
        LedgerExpired => "ledger_expired",
    }
}

contract_enum! {
    /// Typed error codes: the shared operation set and three workflow extensions.
    pub enum WorkflowErrorCode {
        /// A request, plan or driver result is malformed.
        InvalidInput => "InvalidInput",
        /// Bytes are not the canonical encoding of their value.
        NonCanonicalEncoding => "NonCanonicalEncoding",
        /// The capability or step kind is not implemented by the supplied driver or node.
        UnsupportedOperation => "UnsupportedOperation",
        /// A value is bound to another network, authority, plan, step, round or identity.
        BindingMismatch => "BindingMismatch",
        /// A declared bound was exceeded; the error carries actual and maximum.
        ResourceLimitExceeded => "ResourceLimitExceeded",
        /// A locally verified proof is invalid.
        ProofInvalid => "ProofInvalid",
        /// The authority lacks a permission or capability.
        AuthorizationDenied => "AuthorizationDenied",
        /// The transaction expired by authoritative ledger state.
        Expired => "Expired",
        /// The ledger rejected a replay.
        ReplayRejected => "ReplayRejected",
        /// A local resource (storage, prover, custody, transport before dispatch) is unavailable.
        LocalResourceUnavailable => "LocalResourceUnavailable",
        /// A required evidence read did not complete with a classified result.
        /// This is not proof rejection, local capacity, or a ledger outcome; retain custody.
        EvidenceUnavailable => "EvidenceUnavailable",
        /// A dispatch may have been admitted and nothing authoritative is known.
        SubmissionOutcomeUnknown => "SubmissionOutcomeUnknown",
        /// The transaction is known to the network and not yet final.
        FinalityPending => "FinalityPending",
        /// The transaction identity was refused or rejected.
        Rejected => "Rejected",
        /// The current step was cancelled before any dispatch could have been admitted.
        CancelledBeforeSubmission => "CancelledBeforeSubmission",
        /// Workflow extension: the stored journal failed digest, canonical or invariant checks.
        StorageCorrupted => "StorageCorrupted",
        /// Workflow extension: another runner owns the workflow or won a journal write.
        JournalConflict => "JournalConflict",
        /// Workflow extension: an off-chain round is waiting for participants or recovery.
        RoundPending => "RoundPending",
    }
}

impl WorkflowErrorCode {
    /// Whether the code belongs to the shared single-operation set.
    #[must_use]
    pub const fn is_shared_operation_code(self) -> bool {
        !matches!(
            self,
            Self::StorageCorrupted | Self::JournalConflict | Self::RoundPending
        )
    }
}

contract_enum! {
    /// Stage that produced an error.
    ///
    /// One vocabulary serves durable workflows and the one-call operation contract
    /// (`specs/zk_operation_contract.md`), whose advanced calls report `plan` (prepare),
    /// `prove`, `local_verify`, `build`, `sign`, `submit`, and `reconcile` and `finality`
    /// (await finality). A workflow driver proves and builds in one payload call, so a
    /// workflow reports neither `local_verify` nor `build`; only workflows report `round`.
    pub enum WorkflowStage {
        /// Validating the plan or operation request: driver identity, account binding and bounds.
        Plan => "plan",
        /// Loading and verifying the journal.
        Load => "load",
        /// Persisting a journal record.
        Store => "store",
        /// Proving. A workflow driver's payload call, which also builds, and the checks of
        /// its result report this stage.
        Prove => "prove",
        /// Verifying a generated proof locally before anything is built or signed.
        /// Local acceptance is diagnostic, never ledger authorization.
        LocalVerify => "local_verify",
        /// Building the exact canonical unsigned payload from locally verified proofs.
        Build => "build",
        /// Signing a payload, or assembling and verifying an external signature.
        Sign => "sign",
        /// Dispatching signed bytes.
        Submit => "submit",
        /// Read-only reconciliation of a transaction identity.
        Reconcile => "reconcile",
        /// Authenticating the finality of a committed outcome selected by reconciliation.
        Finality => "finality",
        /// Running or recovering an off-chain round.
        Round => "round",
        /// Applying a cancellation.
        Cancel => "cancel",
    }
}

/// One row of the transaction transition table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionTransitionV1 {
    /// State before the event.
    pub from: TransactionStateV1,
    /// The event.
    pub event: TransactionEventV1,
    /// Condition under which this row applies.
    pub guard: TransactionGuardV1,
    /// State after the event.
    pub to: TransactionStateV1,
}

const fn tx(
    from: TransactionStateV1,
    event: TransactionEventV1,
    guard: TransactionGuardV1,
    to: TransactionStateV1,
) -> TransactionTransitionV1 {
    TransactionTransitionV1 {
        from,
        event,
        guard,
        to,
    }
}

/// The complete transaction transition table. Any pair not listed is an invalid transition.
pub const TRANSACTION_TRANSITIONS_V1: &[TransactionTransitionV1] = {
    use TransactionEventV1 as E;
    use TransactionGuardV1 as G;
    use TransactionStateV1 as S;
    &[
        tx(S::Planned, E::OpenAttempt, G::Always, S::Prepared),
        tx(
            S::Rejected,
            E::OpenAttempt,
            G::IdentitiesRemaining,
            S::Prepared,
        ),
        tx(S::Prepared, E::BuildStarted, G::Always, S::Proving),
        tx(S::Proving, E::BuildFailed, G::Always, S::Prepared),
        tx(S::Proving, E::PayloadBuilt, G::Always, S::ReadyToSign),
        tx(S::ReadyToSign, E::Signed, G::Always, S::Signed),
        tx(S::Signed, E::DispatchIntent, G::Always, S::Submitting),
        tx(
            S::OutcomeUnknown,
            E::DispatchIntent,
            G::RetransmissionAuthorized,
            S::Submitting,
        ),
        tx(
            S::Pending,
            E::DispatchIntent,
            G::RetransmissionAuthorized,
            S::Submitting,
        ),
        tx(S::Submitting, E::DispatchAccepted, G::Always, S::Pending),
        tx(
            S::Submitting,
            E::DispatchAlreadyKnown,
            G::Always,
            S::Pending,
        ),
        tx(
            S::Submitting,
            E::DispatchAmbiguous,
            G::Always,
            S::OutcomeUnknown,
        ),
        tx(
            S::Submitting,
            E::DispatchInterrupted,
            G::Always,
            S::OutcomeUnknown,
        ),
        tx(
            S::Submitting,
            E::DispatchRefused,
            G::NoPossibleAdmission,
            S::Rejected,
        ),
        tx(
            S::Submitting,
            E::DispatchRefused,
            G::PossibleAdmission,
            S::OutcomeUnknown,
        ),
        tx(
            S::Submitting,
            E::DispatchNotAdmitted,
            G::NoPossibleAdmission,
            S::Signed,
        ),
        tx(
            S::Submitting,
            E::DispatchNotAdmitted,
            G::PossibleAdmission,
            S::OutcomeUnknown,
        ),
        tx(
            S::OutcomeUnknown,
            E::ObservedInPipeline,
            G::Always,
            S::Pending,
        ),
        tx(
            S::OutcomeUnknown,
            E::ReconciledApplied,
            G::Always,
            S::Finalized,
        ),
        tx(S::Pending, E::ReconciledApplied, G::Always, S::Finalized),
        tx(
            S::OutcomeUnknown,
            E::ReconciledRejected,
            G::Always,
            S::Rejected,
        ),
        tx(S::Pending, E::ReconciledRejected, G::Always, S::Rejected),
        tx(
            S::OutcomeUnknown,
            E::ReconciledExpired,
            G::Always,
            S::Rejected,
        ),
        tx(S::Pending, E::ReconciledExpired, G::Always, S::Rejected),
        tx(
            S::Planned,
            E::Cancel,
            G::Always,
            S::CancelledBeforeSubmission,
        ),
        tx(
            S::Prepared,
            E::Cancel,
            G::Always,
            S::CancelledBeforeSubmission,
        ),
        tx(
            S::Proving,
            E::Cancel,
            G::Always,
            S::CancelledBeforeSubmission,
        ),
        tx(
            S::ReadyToSign,
            E::Cancel,
            G::Always,
            S::CancelledBeforeSubmission,
        ),
        tx(
            S::Signed,
            E::Cancel,
            G::Always,
            S::CancelledBeforeSubmission,
        ),
    ]
};

/// Facts a caller supplies so the reducer can evaluate guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field is one independent guard fact of the transition table"
)]
pub struct TransactionGuardFactsV1 {
    /// The step may still open a transaction identity.
    pub identities_remaining: bool,
    /// The current identity has a counted dispatch left in its bound.
    pub dispatches_remaining: bool,
    /// The caller authorized retransmission and the latest read returned exact absence.
    pub retransmission_authorized: bool,
    /// An earlier dispatch of the current identity may have been admitted.
    pub possible_admission: bool,
}

impl TransactionGuardV1 {
    /// Evaluate the guard against the supplied facts.
    #[must_use]
    pub const fn holds(self, facts: TransactionGuardFactsV1) -> bool {
        match self {
            Self::Always => true,
            Self::IdentitiesRemaining => facts.identities_remaining,
            Self::RetransmissionAuthorized => {
                facts.retransmission_authorized && facts.dispatches_remaining
            }
            Self::NoPossibleAdmission => !facts.possible_admission,
            Self::PossibleAdmission => facts.possible_admission,
        }
    }
}

/// Look up the state after `event` in `from`, or `None` when the table has no such row.
#[must_use]
pub fn transaction_transition(
    from: TransactionStateV1,
    event: TransactionEventV1,
    facts: TransactionGuardFactsV1,
) -> Option<TransactionStateV1> {
    TRANSACTION_TRANSITIONS_V1
        .iter()
        .find(|row| row.from == from && row.event == event && row.guard.holds(facts))
        .map(|row| row.to)
}

/// One row of the round transition table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTransitionV1 {
    /// State before the event.
    pub from: RoundStateV1,
    /// The event.
    pub event: RoundEventV1,
    /// Condition on the workflow status under which this row applies.
    pub guard: RoundGuardV1,
    /// State after the event.
    pub to: RoundStateV1,
}

const fn round(
    from: RoundStateV1,
    event: RoundEventV1,
    guard: RoundGuardV1,
    to: RoundStateV1,
) -> RoundTransitionV1 {
    RoundTransitionV1 {
        from,
        event,
        guard,
        to,
    }
}

/// The complete round transition table.
///
/// The two intents are the only rows that precede an external effect, and they
/// are never taken by a cancelling workflow.
pub const ROUND_TRANSITIONS_V1: &[RoundTransitionV1] = {
    use RoundEventV1 as E;
    use RoundGuardV1 as G;
    use RoundStateV1 as S;
    &[
        round(S::Planned, E::Intent, G::NotCancelling, S::RoundStarted),
        round(
            S::RoundStarted,
            E::RestartIntent,
            G::NotCancelling,
            S::RoundStarted,
        ),
        round(S::RoundStarted, E::Waiting, G::Always, S::RoundWaiting),
        round(S::RoundWaiting, E::Waiting, G::Always, S::RoundWaiting),
        round(S::RoundStarted, E::Completed, G::Always, S::RoundCompleted),
        round(S::RoundWaiting, E::Completed, G::Always, S::RoundCompleted),
        round(S::RoundStarted, E::Failed, G::Always, S::RoundFailed),
        round(S::RoundWaiting, E::Failed, G::Always, S::RoundFailed),
        round(
            S::RoundStarted,
            E::NotStarted,
            G::WhileCancelling,
            S::Planned,
        ),
    ]
};

/// Look up the round state after `event` in `from`.
#[must_use]
pub fn round_transition(
    from: RoundStateV1,
    event: RoundEventV1,
    cancelling: bool,
) -> Option<RoundStateV1> {
    ROUND_TRANSITIONS_V1
        .iter()
        .find(|row| row.from == from && row.event == event && row.guard.holds(cancelling))
        .map(|row| row.to)
}

/// One row of the workflow status table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowTransitionV1 {
    /// Status before the event.
    pub from: WorkflowStatusV1,
    /// The event.
    pub event: WorkflowEventV1,
    /// Status after the event.
    pub to: WorkflowStatusV1,
}

/// The complete workflow status table. Terminal statuses have no outgoing row.
pub const WORKFLOW_TRANSITIONS_V1: &[WorkflowTransitionV1] = {
    use WorkflowEventV1 as E;
    use WorkflowStatusV1 as S;
    &[
        WorkflowTransitionV1 {
            from: S::InProgress,
            event: E::AllStepsDone,
            to: S::Completed,
        },
        WorkflowTransitionV1 {
            from: S::InProgress,
            event: E::StepFailed,
            to: S::Failed,
        },
        WorkflowTransitionV1 {
            from: S::InProgress,
            event: E::CancelResolved,
            to: S::Cancelled,
        },
        WorkflowTransitionV1 {
            from: S::InProgress,
            event: E::CancelUnresolved,
            to: S::Cancelling,
        },
        WorkflowTransitionV1 {
            from: S::Cancelling,
            event: E::UnresolvedEffectResolved,
            to: S::Cancelled,
        },
        WorkflowTransitionV1 {
            from: S::Cancelling,
            event: E::AllStepsDone,
            to: S::Completed,
        },
    ]
};

/// Look up the workflow status after `event` in `from`.
#[must_use]
pub fn workflow_transition(
    from: WorkflowStatusV1,
    event: WorkflowEventV1,
) -> Option<WorkflowStatusV1> {
    WORKFLOW_TRANSITIONS_V1
        .iter()
        .find(|row| row.from == from && row.event == event)
        .map(|row| row.to)
}

/// Rules every SDK family implements; each is exercised by a scenario fixture.
pub const WORKFLOW_RULES_V1: &[(&str, &str)] = &[
    (
        "per_transaction_atomicity_only",
        "Each transaction step is one atomic ledger transaction. A workflow is never atomic across steps: finalized steps and irreversible rounds are not rolled back by failure, cancellation or interruption, and every result reports them.",
    ),
    (
        "persist_before_effect",
        "The dispatch ordinal (`submitting`), the round identity (`round_started`) and every restart of a round (`round_restart_intent`) are durably stored, by compare-and-swap, before the corresponding external effect starts. A runner that loses the compare-and-swap starts no effect.",
    ),
    (
        "reconcile_before_decide",
        "A step found in `submitting`, `outcome_unknown` or `pending` is first reconciled by a read-only query on its persisted signed-transaction identity. Only then does the workflow continue, retry or stop.",
    ),
    (
        "authoritative_outcomes_only",
        "Only state-resolved global `Applied`, `Rejected` or `Expired` closes a transaction identity. Exact absence, queue or cache hints, read failures and local deadlines never close it, and expiry is never inferred from a local clock.",
    ),
    (
        "no_replacement_while_unresolved",
        "A replacement transaction identity is opened only after the previous identity is authoritatively rejected or expired, or was refused on its only counted dispatch, only when the caller explicitly asks and only while the step has identities remaining.",
    ),
    (
        "identical_bytes_only",
        "The only permitted re-dispatch of an unresolved identity is the exact persisted bytes, explicitly authorized for the call, after a fresh exact-absence read, at most once per call and within the dispatch bound. A dispatch proven not to have admitted the bytes, while no earlier dispatch may have, does not count toward the bound: a never-admitted identity stays dispatchable.",
    ),
    (
        "definite_refusal_is_first_dispatch_only",
        "A validated definite refusal closes an identity only when no earlier dispatch of the same bytes may have been admitted; otherwise the identity stays unknown.",
    ),
    (
        "cancellation_is_sticky_and_never_rolls_back",
        "A cancellation that is stored before a dispatch or round intent prevents that dispatch or round start; an intent stored first may take effect afterwards and is reconciled. A build or signature under way when the cancellation is stored is discarded, never stored or sent. While a step may still have external effect the workflow is `cancelling` and only read-only reconciliation runs. When the cancellation takes effect the first unfinished transaction step that is not closed becomes `cancelled_before_submission` and holds no bytes.",
    ),
    (
        "rounds_recover_under_one_identity",
        "A round found started or waiting is recovered under its persisted identity and bound context; a restart never creates a fresh round. Participants are strictly ascending and never shrink.",
    ),
    (
        "plan_fits_the_journal",
        "A plan whose worst-case journal record over every reachable prefix of its steps exceeds the record bound is refused before any journal exists; a round never stores a transcript above the bound its step declares.",
    ),
    (
        "no_secret_in_journal",
        "The journal holds step identity, transaction identities, signed bytes while they may be dispatched, public round transcripts and custody references. No interface accepts secret material, and a terminal workflow holds no transaction bytes.",
    ),
    (
        "corruption_is_reported_not_repaired",
        "A journal that exceeds the record bound or fails its digest, canonical encoding or invariants yields `StorageCorrupted` without a progress snapshot. A valid journal of another workflow yields `BindingMismatch`.",
    ),
];

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn object(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_owned(), value);
    }
    Value::Object(map)
}

fn ids<T: Copy>(values: &[T], id: fn(T) -> &'static str) -> Value {
    Value::Array(values.iter().map(|value| text(id(*value))).collect())
}

/// Render the tables of this module as the machine-readable state machine.
#[must_use]
pub fn state_machine_json() -> Value {
    let transaction_states = TransactionStateV1::ALL
        .iter()
        .map(|state| {
            object(vec![
                ("id", text(state.id())),
                ("may_still_commit", Value::Bool(state.may_still_commit())),
                (
                    "holds_signed_bytes",
                    Value::Bool(state.holds_signed_bytes()),
                ),
            ])
        })
        .collect();
    let transaction_transitions = TRANSACTION_TRANSITIONS_V1
        .iter()
        .map(|row| {
            object(vec![
                ("from", text(row.from.id())),
                ("event", text(row.event.id())),
                ("guard", text(row.guard.id())),
                ("to", text(row.to.id())),
            ])
        })
        .collect();
    let round_states = RoundStateV1::ALL
        .iter()
        .map(|state| {
            object(vec![
                ("id", text(state.id())),
                ("unresolved", Value::Bool(state.is_unresolved())),
            ])
        })
        .collect();
    let round_transitions = ROUND_TRANSITIONS_V1
        .iter()
        .map(|row| {
            object(vec![
                ("from", text(row.from.id())),
                ("event", text(row.event.id())),
                ("guard", text(row.guard.id())),
                ("to", text(row.to.id())),
            ])
        })
        .collect();
    let statuses = WorkflowStatusV1::ALL
        .iter()
        .map(|status| {
            object(vec![
                ("id", text(status.id())),
                ("terminal", Value::Bool(status.is_terminal())),
            ])
        })
        .collect();
    let workflow_transitions = WORKFLOW_TRANSITIONS_V1
        .iter()
        .map(|row| {
            object(vec![
                ("from", text(row.from.id())),
                ("event", text(row.event.id())),
                ("to", text(row.to.id())),
            ])
        })
        .collect();
    let error_codes = WorkflowErrorCode::ALL
        .iter()
        .map(|code| {
            object(vec![
                ("id", text(code.id())),
                (
                    "shared_operation_code",
                    Value::Bool(code.is_shared_operation_code()),
                ),
            ])
        })
        .collect();
    let rules = WORKFLOW_RULES_V1
        .iter()
        .map(|(id, statement)| object(vec![("id", text(id)), ("statement", text(statement))]))
        .collect();
    let limit = |value: usize| Value::from(value as u64);
    object(vec![
        ("schema", text(STATE_MACHINE_SCHEMA_V1)),
        (
            "journal_version",
            Value::from(u64::from(WORKFLOW_JOURNAL_VERSION_V1)),
        ),
        ("atomicity", text(WORKFLOW_ATOMICITY_V1)),
        (
            "workflow_kinds",
            ids(WorkflowKindV1::ALL, WorkflowKindV1::id),
        ),
        ("step_kinds", ids(StepKindV1::ALL, StepKindV1::id)),
        ("workflow_statuses", Value::Array(statuses)),
        (
            "workflow_events",
            ids(WorkflowEventV1::ALL, WorkflowEventV1::id),
        ),
        ("workflow_transitions", Value::Array(workflow_transitions)),
        ("transaction_states", Value::Array(transaction_states)),
        (
            "transaction_events",
            ids(TransactionEventV1::ALL, TransactionEventV1::id),
        ),
        (
            "transaction_guards",
            ids(TransactionGuardV1::ALL, TransactionGuardV1::id),
        ),
        (
            "transaction_transitions",
            Value::Array(transaction_transitions),
        ),
        ("round_states", Value::Array(round_states)),
        ("round_events", ids(RoundEventV1::ALL, RoundEventV1::id)),
        ("round_guards", ids(RoundGuardV1::ALL, RoundGuardV1::id)),
        ("round_transitions", Value::Array(round_transitions)),
        (
            "attempt_evidence",
            ids(AttemptEvidenceKindV1::ALL, AttemptEvidenceKindV1::id),
        ),
        ("error_codes", Value::Array(error_codes)),
        ("stages", ids(WorkflowStage::ALL, WorkflowStage::id)),
        (
            "limits",
            object(vec![
                ("max_steps", limit(MAX_WORKFLOW_STEPS_V1)),
                ("max_label_bytes", limit(MAX_WORKFLOW_LABEL_BYTES_V1)),
                ("max_binding_bytes", limit(MAX_WORKFLOW_BINDING_BYTES_V1)),
                (
                    "max_transaction_identities_per_step",
                    limit(usize::from(MAX_TRANSACTION_IDENTITIES_PER_STEP_V1)),
                ),
                (
                    "max_dispatches_per_identity",
                    limit(usize::from(MAX_DISPATCHES_PER_IDENTITY_V1)),
                ),
                (
                    "max_transaction_bytes",
                    limit(MAX_WORKFLOW_TRANSACTION_BYTES_V1),
                ),
                (
                    "max_round_transcript_bytes",
                    limit(MAX_ROUND_TRANSCRIPT_BYTES_V1),
                ),
                ("max_round_participants", limit(MAX_ROUND_PARTICIPANTS_V1)),
                (
                    "max_custody_handles_per_round",
                    limit(MAX_CUSTODY_HANDLES_PER_ROUND_V1),
                ),
                (
                    "max_custody_reference_bytes",
                    limit(MAX_CUSTODY_REFERENCE_BYTES_V1),
                ),
                ("max_detail_bytes", limit(MAX_WORKFLOW_DETAIL_BYTES_V1)),
                ("max_journal_bytes", limit(MAX_WORKFLOW_JOURNAL_BYTES_V1)),
            ]),
        ),
        (
            "journal_bound_terms",
            object(vec![
                ("journal_fixed_bytes", limit(JOURNAL_FIXED_RECORD_BYTES_V1)),
                ("step_fixed_bytes", limit(STEP_FIXED_RECORD_BYTES_V1)),
                ("identity_bytes", limit(IDENTITY_RECORD_BYTES_V1)),
                (
                    "retained_transaction_bytes",
                    limit(RETAINED_TRANSACTION_RECORD_BYTES_V1),
                ),
                ("participant_bytes", limit(PARTICIPANT_RECORD_BYTES_V1)),
                (
                    "custody_handle_bytes",
                    limit(CUSTODY_HANDLE_RECORD_BYTES_V1),
                ),
                (
                    "transcript_framing_bytes",
                    limit(TRANSCRIPT_FRAMING_RECORD_BYTES_V1),
                ),
            ]),
        ),
        ("rules", Value::Array(rules)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_FACTS: TransactionGuardFactsV1 = TransactionGuardFactsV1 {
        identities_remaining: false,
        dispatches_remaining: false,
        retransmission_authorized: false,
        possible_admission: false,
    };

    #[test]
    fn contract_identifiers_round_trip_and_are_unique() {
        fn check<T: Copy + PartialEq + core::fmt::Debug>(
            all: &[T],
            id: fn(T) -> &'static str,
            parse: fn(&str) -> Option<T>,
        ) {
            for (index, value) in all.iter().enumerate() {
                assert_eq!(parse(id(*value)), Some(*value));
                assert!(all[..index].iter().all(|other| id(*other) != id(*value)));
            }
            assert_eq!(parse("not-a-contract-id"), None);
        }
        check(
            WorkflowKindV1::ALL,
            WorkflowKindV1::id,
            WorkflowKindV1::from_id,
        );
        check(StepKindV1::ALL, StepKindV1::id, StepKindV1::from_id);
        check(
            WorkflowStatusV1::ALL,
            WorkflowStatusV1::id,
            WorkflowStatusV1::from_id,
        );
        check(
            TransactionStateV1::ALL,
            TransactionStateV1::id,
            TransactionStateV1::from_id,
        );
        check(
            TransactionEventV1::ALL,
            TransactionEventV1::id,
            TransactionEventV1::from_id,
        );
        check(
            TransactionGuardV1::ALL,
            TransactionGuardV1::id,
            TransactionGuardV1::from_id,
        );
        check(RoundStateV1::ALL, RoundStateV1::id, RoundStateV1::from_id);
        check(RoundEventV1::ALL, RoundEventV1::id, RoundEventV1::from_id);
        check(RoundGuardV1::ALL, RoundGuardV1::id, RoundGuardV1::from_id);
        check(
            WorkflowEventV1::ALL,
            WorkflowEventV1::id,
            WorkflowEventV1::from_id,
        );
        check(
            AttemptEvidenceKindV1::ALL,
            AttemptEvidenceKindV1::id,
            AttemptEvidenceKindV1::from_id,
        );
        check(
            WorkflowErrorCode::ALL,
            WorkflowErrorCode::id,
            WorkflowErrorCode::from_id,
        );
        check(
            WorkflowStage::ALL,
            WorkflowStage::id,
            WorkflowStage::from_id,
        );
        assert_eq!(WorkflowKindV1::Dkg.to_string(), "dkg");
    }

    #[test]
    fn evidence_unavailable_has_one_canonical_code_and_codec() {
        let code = WorkflowErrorCode::EvidenceUnavailable;
        assert_eq!(code.id(), "EvidenceUnavailable");
        assert!(code.is_shared_operation_code());
        // Contract enums are nested payloads of the framed workflow journal.
        // Exercise the same declared framing without inventing a standalone
        // production schema for each nested enum.
        #[derive(Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
        #[norito_schema(name = "iroha::workflow::tests::ErrorCodeRecord")]
        struct ErrorCodeRecord {
            code: WorkflowErrorCode,
        }
        let record = ErrorCodeRecord { code };
        let frame = norito::encode_canonical(&record).unwrap();
        assert_eq!(
            norito::decode_canonical::<ErrorCodeRecord>(&frame).unwrap(),
            record
        );
    }

    #[test]
    fn error_codes_are_the_shared_set_plus_three_workflow_extensions() {
        let shared = [
            "InvalidInput",
            "NonCanonicalEncoding",
            "UnsupportedOperation",
            "BindingMismatch",
            "ResourceLimitExceeded",
            "ProofInvalid",
            "AuthorizationDenied",
            "Expired",
            "ReplayRejected",
            "LocalResourceUnavailable",
            "EvidenceUnavailable",
            "SubmissionOutcomeUnknown",
            "FinalityPending",
            "Rejected",
            "CancelledBeforeSubmission",
        ];
        let actual_shared = WorkflowErrorCode::ALL
            .iter()
            .filter(|code| code.is_shared_operation_code())
            .map(|code| code.id())
            .collect::<Vec<_>>();
        assert_eq!(actual_shared, shared);
        let extensions = WorkflowErrorCode::ALL
            .iter()
            .filter(|code| !code.is_shared_operation_code())
            .map(|code| code.id())
            .collect::<Vec<_>>();
        assert_eq!(
            extensions,
            ["StorageCorrupted", "JournalConflict", "RoundPending"]
        );
    }

    #[test]
    fn stages_are_the_shared_vocabulary_in_pipeline_order() {
        // The operation pipeline prepare -> prove -> local_verify -> build -> sign ->
        // submit -> await_finality reports these stages in this order; workflows add
        // `round`, and every durable call may report the journal stages and `cancel`.
        assert_eq!(
            WorkflowStage::ALL
                .iter()
                .map(|stage| stage.id())
                .collect::<Vec<_>>(),
            [
                "plan",
                "load",
                "store",
                "prove",
                "local_verify",
                "build",
                "sign",
                "submit",
                "reconcile",
                "finality",
                "round",
                "cancel",
            ]
        );
        let rendered = state_machine_json();
        let stages = rendered
            .as_object()
            .and_then(|root| root.get("stages"))
            .and_then(Value::as_array)
            .expect("stages");
        assert_eq!(stages.len(), WorkflowStage::ALL.len());
        assert_eq!(WorkflowStage::LocalVerify.to_string(), "local_verify");
    }

    #[test]
    fn transaction_table_is_deterministic_and_total_over_its_guards() {
        // No two rows may apply to the same facts.
        for facts in all_facts() {
            for from in TransactionStateV1::ALL {
                for event in TransactionEventV1::ALL {
                    let matching = TRANSACTION_TRANSITIONS_V1
                        .iter()
                        .filter(|row| {
                            row.from == *from && row.event == *event && row.guard.holds(facts)
                        })
                        .count();
                    assert!(matching <= 1, "{from} {event} is ambiguous");
                }
            }
        }
        // Every state and event is used, and every row is reachable from `planned`.
        for state in TransactionStateV1::ALL {
            assert!(
                TRANSACTION_TRANSITIONS_V1
                    .iter()
                    .any(|row| row.from == *state || row.to == *state)
            );
        }
        for event in TransactionEventV1::ALL {
            assert!(
                TRANSACTION_TRANSITIONS_V1
                    .iter()
                    .any(|row| row.event == *event)
            );
        }
        let mut reachable = vec![TransactionStateV1::Planned];
        let mut changed = true;
        while changed {
            changed = false;
            for row in TRANSACTION_TRANSITIONS_V1 {
                if reachable.contains(&row.from) && !reachable.contains(&row.to) {
                    reachable.push(row.to);
                    changed = true;
                }
            }
        }
        assert_eq!(reachable.len(), TransactionStateV1::ALL.len());
    }

    fn all_facts() -> Vec<TransactionGuardFactsV1> {
        (0_u8..16)
            .map(|bits| TransactionGuardFactsV1 {
                identities_remaining: bits & 1 != 0,
                dispatches_remaining: bits & 2 != 0,
                retransmission_authorized: bits & 4 != 0,
                possible_admission: bits & 8 != 0,
            })
            .collect()
    }

    #[test]
    fn no_dispatch_leaves_an_unresolved_identity_without_reconciliation() {
        // A never-admitted identity is always dispatchable: no fact can strand it in `signed`.
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Signed,
                TransactionEventV1::DispatchIntent,
                NO_FACTS,
            ),
            Some(TransactionStateV1::Submitting)
        );
        // The only rows that enter `submitting` are the persisted dispatch intents.
        for row in TRANSACTION_TRANSITIONS_V1 {
            if row.to == TransactionStateV1::Submitting {
                assert_eq!(row.event, TransactionEventV1::DispatchIntent);
                assert!(matches!(
                    row.from,
                    TransactionStateV1::Signed
                        | TransactionStateV1::OutcomeUnknown
                        | TransactionStateV1::Pending
                ));
                // Only never-admitted bytes go out without explicit authorization.
                assert_eq!(
                    row.guard == TransactionGuardV1::RetransmissionAuthorized,
                    row.from != TransactionStateV1::Signed
                );
            }
            // A state that may still commit is never cancelled, reopened or rebuilt.
            if row.from.may_still_commit() {
                assert!(!matches!(
                    row.event,
                    TransactionEventV1::OpenAttempt
                        | TransactionEventV1::Cancel
                        | TransactionEventV1::BuildStarted
                        | TransactionEventV1::PayloadBuilt
                        | TransactionEventV1::Signed
                ));
            }
        }
        // Without authorization an unknown identity is never dispatched again.
        assert_eq!(
            transaction_transition(
                TransactionStateV1::OutcomeUnknown,
                TransactionEventV1::DispatchIntent,
                TransactionGuardFactsV1 {
                    dispatches_remaining: true,
                    ..NO_FACTS
                },
            ),
            None
        );
        assert_eq!(
            transaction_transition(
                TransactionStateV1::OutcomeUnknown,
                TransactionEventV1::DispatchIntent,
                TransactionGuardFactsV1 {
                    dispatches_remaining: true,
                    retransmission_authorized: true,
                    ..NO_FACTS
                },
            ),
            Some(TransactionStateV1::Submitting)
        );
        // The same holds for an acknowledged identity the network no longer shows.
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Pending,
                TransactionEventV1::DispatchIntent,
                TransactionGuardFactsV1 {
                    dispatches_remaining: true,
                    ..NO_FACTS
                },
            ),
            None
        );
        // Authorization never exceeds the dispatch bound.
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Pending,
                TransactionEventV1::DispatchIntent,
                TransactionGuardFactsV1 {
                    retransmission_authorized: true,
                    ..NO_FACTS
                },
            ),
            None
        );
    }

    #[test]
    fn a_refusal_closes_an_identity_only_on_its_first_possible_admission() {
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Submitting,
                TransactionEventV1::DispatchRefused,
                NO_FACTS,
            ),
            Some(TransactionStateV1::Rejected)
        );
        let earlier = TransactionGuardFactsV1 {
            possible_admission: true,
            ..NO_FACTS
        };
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Submitting,
                TransactionEventV1::DispatchRefused,
                earlier,
            ),
            Some(TransactionStateV1::OutcomeUnknown)
        );
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Submitting,
                TransactionEventV1::DispatchNotAdmitted,
                NO_FACTS,
            ),
            Some(TransactionStateV1::Signed)
        );
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Submitting,
                TransactionEventV1::DispatchNotAdmitted,
                earlier,
            ),
            Some(TransactionStateV1::OutcomeUnknown)
        );
        // A replacement identity needs a closed one and a remaining slot.
        assert_eq!(
            transaction_transition(
                TransactionStateV1::Rejected,
                TransactionEventV1::OpenAttempt,
                NO_FACTS,
            ),
            None
        );
    }

    #[test]
    fn round_and_workflow_tables_have_no_exit_from_terminal_states() {
        for row in ROUND_TRANSITIONS_V1 {
            assert!(!matches!(
                row.from,
                RoundStateV1::RoundCompleted | RoundStateV1::RoundFailed
            ));
        }
        assert_eq!(
            round_transition(RoundStateV1::RoundStarted, RoundEventV1::NotStarted, false),
            None
        );
        assert_eq!(
            round_transition(RoundStateV1::RoundStarted, RoundEventV1::NotStarted, true),
            Some(RoundStateV1::Planned)
        );
        assert_eq!(
            round_transition(RoundStateV1::Planned, RoundEventV1::Completed, true),
            None
        );
        // The two intents precede an external effect and are refused while cancelling.
        for (from, event) in [
            (RoundStateV1::Planned, RoundEventV1::Intent),
            (RoundStateV1::RoundStarted, RoundEventV1::RestartIntent),
        ] {
            assert_eq!(
                round_transition(from, event, false),
                Some(RoundStateV1::RoundStarted)
            );
            assert_eq!(round_transition(from, event, true), None);
        }
        for row in ROUND_TRANSITIONS_V1 {
            let starts_an_effect = matches!(
                row.event,
                RoundEventV1::Intent | RoundEventV1::RestartIntent
            );
            assert_eq!(row.guard == RoundGuardV1::NotCancelling, starts_an_effect);
        }
        // A round that is waiting has started: it is never restarted.
        assert_eq!(
            round_transition(
                RoundStateV1::RoundWaiting,
                RoundEventV1::RestartIntent,
                false
            ),
            None
        );
        assert!(RoundGuardV1::Always.holds(true) && RoundGuardV1::Always.holds(false));
        assert!(RoundGuardV1::WhileCancelling.holds(true));
        assert!(!RoundGuardV1::WhileCancelling.holds(false));
        assert!(RoundGuardV1::NotCancelling.holds(false));
        assert!(!RoundGuardV1::NotCancelling.holds(true));
        for row in WORKFLOW_TRANSITIONS_V1 {
            assert!(!row.from.is_terminal());
        }
        assert_eq!(
            workflow_transition(WorkflowStatusV1::Cancelled, WorkflowEventV1::AllStepsDone),
            None
        );
        assert_eq!(
            workflow_transition(WorkflowStatusV1::Cancelling, WorkflowEventV1::AllStepsDone),
            Some(WorkflowStatusV1::Completed)
        );
        assert!(RoundStateV1::RoundWaiting.is_unresolved());
        assert!(!RoundStateV1::RoundCompleted.is_unresolved());
    }

    #[test]
    fn guards_read_only_their_own_fact() {
        let all = TransactionGuardFactsV1 {
            identities_remaining: true,
            dispatches_remaining: true,
            retransmission_authorized: true,
            possible_admission: true,
        };
        assert!(TransactionGuardV1::Always.holds(NO_FACTS));
        assert!(TransactionGuardV1::IdentitiesRemaining.holds(all));
        assert!(!TransactionGuardV1::IdentitiesRemaining.holds(NO_FACTS));
        assert!(TransactionGuardV1::NoPossibleAdmission.holds(NO_FACTS));
        assert!(!TransactionGuardV1::NoPossibleAdmission.holds(all));
        assert!(TransactionGuardV1::PossibleAdmission.holds(all));
        // Retransmission also needs a remaining dispatch.
        assert!(
            !TransactionGuardV1::RetransmissionAuthorized.holds(TransactionGuardFactsV1 {
                dispatches_remaining: false,
                ..all
            })
        );
        assert!(TransactionStateV1::Pending.may_still_commit());
        assert!(!TransactionStateV1::Signed.may_still_commit());
        assert!(TransactionStateV1::Signed.holds_signed_bytes());
        assert!(!TransactionStateV1::Finalized.holds_signed_bytes());
        assert!(WorkflowStatusV1::Failed.is_terminal());
        assert!(!WorkflowStatusV1::Cancelling.is_terminal());
    }

    #[test]
    fn transaction_bound_equals_the_committed_default_transaction_cap() {
        // The journal bound is a client-side copy of the committed default. A change of
        // that default must be a deliberate change of this contract and its fixtures.
        let committed = iroha_data_model::parameter::system::TransactionParameters::default();
        assert_eq!(
            committed.max_tx_bytes.get(),
            MAX_WORKFLOW_TRANSACTION_BYTES_V1 as u64
        );
    }

    #[test]
    fn rendered_state_machine_names_every_table_and_rule() {
        let rendered = state_machine_json();
        let root = rendered.as_object().expect("object");
        assert_eq!(
            root.get("schema").and_then(Value::as_str),
            Some(STATE_MACHINE_SCHEMA_V1)
        );
        assert_eq!(
            root.get("atomicity").and_then(Value::as_str),
            Some("per_transaction_only")
        );
        assert_eq!(
            root.get("transaction_transitions")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(TRANSACTION_TRANSITIONS_V1.len())
        );
        assert_eq!(
            root.get("rules").and_then(Value::as_array).map(Vec::len),
            Some(WORKFLOW_RULES_V1.len())
        );
        let terms = root
            .get("journal_bound_terms")
            .and_then(Value::as_object)
            .expect("journal bound terms");
        assert_eq!(
            terms.get("participant_bytes").and_then(Value::as_u64),
            Some(PARTICIPANT_RECORD_BYTES_V1 as u64)
        );
        assert_eq!(terms.len(), 7);
        assert_eq!(
            root.get("round_guards")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(RoundGuardV1::ALL.len())
        );
        for (index, (id, statement)) in WORKFLOW_RULES_V1.iter().enumerate() {
            assert!(!statement.is_empty());
            assert!(
                WORKFLOW_RULES_V1[..index]
                    .iter()
                    .all(|(other, _)| other != id)
            );
        }
    }
}
