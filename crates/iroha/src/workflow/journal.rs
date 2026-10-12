//! Canonical durable journal, the workflow-independent transaction reducer and progress reports.
//!
//! A journal is one canonical Norito record per workflow. It holds the workflow
//! identity, every step descriptor and state, every transaction identity a step
//! ever opened, the signed bytes of the identity that may still be dispatched,
//! public round transcripts and custody references. It never holds a secret:
//! no input type of this module carries one.

use iroha_crypto::Hash;
use norito::{
    derive::{Decode, Encode},
    json::{Map, Value},
};

use super::{
    contract::{
        AttemptEvidenceKindV1, CUSTODY_HANDLE_RECORD_BYTES_V1, IDENTITY_RECORD_BYTES_V1,
        JOURNAL_FIXED_RECORD_BYTES_V1, MAX_CUSTODY_HANDLES_PER_ROUND_V1,
        MAX_CUSTODY_REFERENCE_BYTES_V1, MAX_DISPATCHES_PER_IDENTITY_V1, MAX_ROUND_PARTICIPANTS_V1,
        MAX_ROUND_TRANSCRIPT_BYTES_V1, MAX_TRANSACTION_IDENTITIES_PER_STEP_V1,
        MAX_WORKFLOW_BINDING_BYTES_V1, MAX_WORKFLOW_DETAIL_BYTES_V1, MAX_WORKFLOW_JOURNAL_BYTES_V1,
        MAX_WORKFLOW_LABEL_BYTES_V1, MAX_WORKFLOW_STEPS_V1, MAX_WORKFLOW_TRANSACTION_BYTES_V1,
        PARTICIPANT_RECORD_BYTES_V1, RETAINED_TRANSACTION_RECORD_BYTES_V1, RoundEventV1,
        RoundStateV1, STEP_FIXED_RECORD_BYTES_V1, StepKindV1, TRANSCRIPT_FRAMING_RECORD_BYTES_V1,
        TransactionEventV1, TransactionGuardFactsV1, TransactionStateV1, WORKFLOW_ATOMICITY_V1,
        WORKFLOW_JOURNAL_VERSION_V1, WorkflowErrorCode, WorkflowEventV1, WorkflowKindV1,
        WorkflowStage, WorkflowStatusV1, round_transition, transaction_transition,
        workflow_transition,
    },
    error::WorkflowError,
};

/// A 32-byte Iroha hash (Blake2b-256 with the hash marker bit set) or opaque 32-byte digest.
pub type Digest32 = [u8; 32];

/// Domain separator of the plan digest.
pub const PLAN_DIGEST_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:plan:v1\0";
/// Domain separator of the workflow identifier.
pub const WORKFLOW_ID_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:id:v1\0";
/// Domain separator of the journal digest.
pub const JOURNAL_DIGEST_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:journal:v1\0";
/// Domain separator of a round identity.
pub const ROUND_ID_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:round:v1\0";
/// Domain separator of a round transcript digest.
pub const TRANSCRIPT_DIGEST_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:transcript:v1\0";
/// Domain separator of the stored-record digest used for compare-and-swap.
pub const RECORD_DIGEST_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:record:v1\0";
/// Domain separator of the authority text an account context binds.
pub const AUTHORITY_BINDING_DOMAIN_V1: &[u8] = b"iroha:durable-workflow:authority:v1\0";

/// Hash `domain || chunks...` with the Iroha hash.
#[must_use]
pub fn domain_digest(domain: &[u8], chunks: &[&[u8]]) -> Digest32 {
    let mut all = Vec::with_capacity(chunks.len() + 1);
    all.push(domain);
    all.extend_from_slice(chunks);
    *Hash::new_from_chunks(&all).as_ref()
}

/// Digest of one stored record; the storage compare-and-swap token.
#[must_use]
pub fn record_digest(record: &[u8]) -> Digest32 {
    domain_digest(RECORD_DIGEST_DOMAIN_V1, &[record])
}

/// The authority text an account context binds a workflow to.
///
/// 64 lowercase hexadecimal characters: the domain-separated Iroha hash of the
/// canonical account address payload. The text has one length for every
/// controller (single key of any algorithm, or multisignature) and depends on no
/// chain discriminant or other ambient formatting state, so one account always
/// yields one workflow identifier.
#[must_use]
pub fn authority_binding_text(canonical_account_address: &[u8]) -> String {
    hex::encode(domain_digest(
        AUTHORITY_BINDING_DOMAIN_V1,
        &[canonical_account_address],
    ))
}

fn canonical<T: norito::NoritoSerialize>(
    value: &T,
    stage: WorkflowStage,
) -> Result<Vec<u8>, WorkflowError> {
    norito::encode_canonical(value).map_err(|error| canonical_error(error, stage))
}

fn canonical_error(error: norito::Error, stage: WorkflowStage) -> WorkflowError {
    // A writer has no decoder scope. Preserve its actual allocator error without
    // manufacturing a decode attempt or inferring refusal from diagnostic text.
    let code = if matches!(error, norito::Error::AllocationFailed { .. }) {
        WorkflowErrorCode::LocalResourceUnavailable
    } else {
        WorkflowErrorCode::InvalidInput
    };
    WorkflowError::new(code, stage, format!("canonical encoding failed: {error}"))
}

fn journal_record_error(
    mut error: WorkflowError,
    stage: WorkflowStage,
    invalid_code: WorkflowErrorCode,
    context: &str,
) -> WorkflowError {
    if error.code != WorkflowErrorCode::LocalResourceUnavailable {
        error.code = invalid_code;
    }
    error.stage = stage;
    error.detail = format!("{context}: {}", error.detail);
    error
}

fn bounded_detail(detail: &str) -> String {
    let mut end = detail.len().min(MAX_WORKFLOW_DETAIL_BYTES_V1);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_owned()
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_WORKFLOW_LABEL_BYTES_V1
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

/// Canonical network and authority texts are opaque here: only length, control characters and
/// whitespace are checked. An account context binds [`authority_binding_text`].
fn valid_binding(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORKFLOW_BINDING_BYTES_V1
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Identifier of one workflow instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkflowId(Digest32);

impl WorkflowId {
    /// Wrap an identifier read from a journal or a handle.
    #[must_use]
    pub const fn from_bytes(bytes: Digest32) -> Self {
        Self(bytes)
    }

    /// The 32 identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &Digest32 {
        &self.0
    }

    /// Lowercase hexadecimal form, used as the storage key.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl core::fmt::Display for WorkflowId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

/// Identity and schema of the capability driver a plan is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DriverIdentityV1 {
    /// Stable capability driver name.
    pub id: String,
    /// Version of the driver's step and transcript schema.
    pub schema_version: u32,
}

/// One planned step.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct StepDescriptorV1 {
    /// Step name, unique in the plan.
    pub label: String,
    /// Transaction or off-chain round.
    pub kind: StepKindV1,
    /// Digest of the step's proof-free intent (transaction) or input context (round).
    pub intent_digest: Digest32,
    /// Whether completing the step cannot be undone. Always true for a transaction.
    pub irreversible: bool,
    /// Transaction identities the step may open; zero for a round.
    pub max_transaction_identities: u8,
    /// Participants a completed round must report; zero for a transaction.
    pub participants_required: u32,
    /// Custody references a completed round must return; zero for a transaction.
    pub custody_handles_required: u32,
    /// Largest public transcript a completed round may return; zero for a transaction.
    pub max_transcript_bytes: u32,
}

impl StepDescriptorV1 {
    /// A transaction step with exactly one transaction identity.
    #[must_use]
    pub fn transaction(label: impl Into<String>, intent_digest: Digest32) -> Self {
        Self {
            label: label.into(),
            kind: StepKindV1::Transaction,
            intent_digest,
            irreversible: true,
            max_transaction_identities: 1,
            participants_required: 0,
            custody_handles_required: 0,
            max_transcript_bytes: 0,
        }
    }

    /// Allow replacement identities after an authoritative rejection.
    #[must_use]
    pub fn with_max_transaction_identities(mut self, maximum: u8) -> Self {
        self.max_transaction_identities = maximum;
        self
    }

    /// An off-chain round step whose transcript may use the whole transcript bound.
    #[must_use]
    pub fn offchain_round(
        label: impl Into<String>,
        context_digest: Digest32,
        irreversible: bool,
        participants_required: u32,
        custody_handles_required: u32,
    ) -> Self {
        Self {
            label: label.into(),
            kind: StepKindV1::OffchainRound,
            intent_digest: context_digest,
            irreversible,
            max_transaction_identities: 0,
            participants_required,
            custody_handles_required,
            max_transcript_bytes: MAX_ROUND_TRANSCRIPT_BYTES_V1 as u32,
        }
    }

    /// Declare the largest transcript this round returns.
    ///
    /// A plan with several rounds declares their real transcript sizes so that its
    /// worst-case journal fits the record bound; see [`WorkflowPlanV1::journal_bytes_bound`].
    #[must_use]
    pub fn with_max_transcript_bytes(mut self, maximum: u32) -> Self {
        self.max_transcript_bytes = maximum;
        self
    }

    /// Worst-case record bytes of this step once it is finalized or completed.
    fn done_record_bytes(&self) -> usize {
        STEP_FIXED_RECORD_BYTES_V1
            + match self.kind {
                StepKindV1::Transaction => {
                    IDENTITY_RECORD_BYTES_V1 * usize::from(self.max_transaction_identities)
                }
                StepKindV1::OffchainRound => {
                    PARTICIPANT_RECORD_BYTES_V1 * MAX_ROUND_PARTICIPANTS_V1
                        + CUSTODY_HANDLE_RECORD_BYTES_V1 * self.custody_handles_required as usize
                        + self.max_transcript_bytes as usize
                        + TRANSCRIPT_FRAMING_RECORD_BYTES_V1
                }
            }
    }

    /// Worst-case record bytes of this step while it is the current step.
    fn peak_record_bytes(&self) -> usize {
        self.done_record_bytes()
            + match self.kind {
                // The current transaction step retains its payload or its signed bytes.
                StepKindV1::Transaction => RETAINED_TRANSACTION_RECORD_BYTES_V1,
                StepKindV1::OffchainRound => 0,
            }
    }

    fn validate(&self) -> Result<(), String> {
        if !valid_label(&self.label) {
            return Err(format!("step label `{}` is not a valid label", self.label));
        }
        match self.kind {
            StepKindV1::Transaction => {
                if !self.irreversible {
                    return Err("a transaction step is always irreversible".to_owned());
                }
                if self.max_transaction_identities == 0
                    || self.max_transaction_identities > MAX_TRANSACTION_IDENTITIES_PER_STEP_V1
                {
                    return Err("transaction identity bound is out of range".to_owned());
                }
                if self.participants_required != 0
                    || self.custody_handles_required != 0
                    || self.max_transcript_bytes != 0
                {
                    return Err(
                        "a transaction step declares no participants, custody or transcript"
                            .to_owned(),
                    );
                }
            }
            StepKindV1::OffchainRound => {
                if self.max_transaction_identities != 0 {
                    return Err("a round step opens no transaction identity".to_owned());
                }
                if self.participants_required as usize > MAX_ROUND_PARTICIPANTS_V1
                    || self.custody_handles_required as usize > MAX_CUSTODY_HANDLES_PER_ROUND_V1
                {
                    return Err("round participant or custody bound is out of range".to_owned());
                }
                if self.max_transcript_bytes == 0
                    || self.max_transcript_bytes as usize > MAX_ROUND_TRANSCRIPT_BYTES_V1
                {
                    return Err("round transcript bound is out of range".to_owned());
                }
            }
        }
        Ok(())
    }
}

/// The immutable plan of one workflow.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::workflow::WorkflowPlanV1")]
pub struct WorkflowPlanV1 {
    /// Separately named process.
    pub kind: WorkflowKindV1,
    /// Caller-chosen instance label distinguishing workflows of one account.
    pub instance: String,
    /// Capability driver the plan is bound to.
    pub driver: DriverIdentityV1,
    /// Digest of the driver's immutable request context.
    pub request_context_digest: Digest32,
    /// Ordered steps.
    pub steps: Vec<StepDescriptorV1>,
}

/// A plan without its kind: what a separately named workflow call receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowRequest {
    /// Caller-chosen instance label distinguishing workflows of one account.
    pub instance: String,
    /// Capability driver the plan is bound to.
    pub driver: DriverIdentityV1,
    /// Digest of the driver's immutable request context.
    pub request_context_digest: Digest32,
    /// Ordered steps.
    pub steps: Vec<StepDescriptorV1>,
}

impl WorkflowRequest {
    /// Bind the request to the kind of the named call that received it.
    #[must_use]
    pub fn into_plan(self, kind: WorkflowKindV1) -> WorkflowPlanV1 {
        WorkflowPlanV1 {
            kind,
            instance: self.instance,
            driver: self.driver,
            request_context_digest: self.request_context_digest,
            steps: self.steps,
        }
    }
}

impl WorkflowPlanV1 {
    /// Worst-case canonical record size of any journal this plan can reach.
    ///
    /// Steps run in order, so a reachable journal has a prefix of finalized or
    /// completed steps, one current step and untouched steps after it. Only the
    /// current transaction step retains transaction bytes, and only completed
    /// rounds hold transcripts. The bound is the fixed journal overhead plus the
    /// maximum, over every position of the current step, of: the completed size of
    /// each earlier step, the peak size of the current step and the fixed size of
    /// each later step. The terms are the `*_RECORD_BYTES_V1` constants of the
    /// contract; a test encodes maximal reachable journals against this bound.
    #[must_use]
    pub fn journal_bytes_bound(&self) -> usize {
        let later_fixed =
            |index: usize| STEP_FIXED_RECORD_BYTES_V1 * (self.steps.len() - index - 1);
        let mut earlier_done = 0_usize;
        let mut worst = 0_usize;
        for (index, step) in self.steps.iter().enumerate() {
            worst = worst.max(
                earlier_done
                    .saturating_add(step.peak_record_bytes())
                    .saturating_add(later_fixed(index)),
            );
            earlier_done = earlier_done.saturating_add(step.done_record_bytes());
        }
        JOURNAL_FIXED_RECORD_BYTES_V1.saturating_add(worst)
    }

    /// Check labels, bounds, per-kind step rules and that the journal can always be stored.
    ///
    /// # Errors
    /// `InvalidInput` for malformed labels or step rules and `ResourceLimitExceeded`
    /// for too many steps or a worst-case journal above the record bound.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        let invalid = |detail: String| {
            WorkflowError::new(WorkflowErrorCode::InvalidInput, WorkflowStage::Plan, detail)
        };
        if !valid_label(&self.instance) {
            return Err(invalid("workflow instance label is not valid".to_owned()));
        }
        if !valid_label(&self.driver.id) {
            return Err(invalid("driver identity is not a valid label".to_owned()));
        }
        if self.steps.is_empty() {
            return Err(invalid("a workflow needs at least one step".to_owned()));
        }
        if self.steps.len() > MAX_WORKFLOW_STEPS_V1 {
            return Err(WorkflowError::limit(
                WorkflowStage::Plan,
                "step count",
                self.steps.len(),
                MAX_WORKFLOW_STEPS_V1,
            ));
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate()
                .map_err(|detail| invalid(detail).with_step(index))?;
            if self.steps[..index]
                .iter()
                .any(|other| other.label == step.label)
            {
                return Err(
                    invalid(format!("step label `{}` is repeated", step.label)).with_step(index)
                );
            }
        }
        // A plan that could outgrow the record is refused here, before any journal exists
        // and before any irreversible step runs.
        if self.kind == WorkflowKindV1::NativePayment
            && (self.steps.len() != 1 || self.steps[0].kind != StepKindV1::Transaction)
        {
            return Err(invalid(
                "native payment requires exactly one transaction step".into(),
            ));
        }
        let bound = self.journal_bytes_bound();
        if bound > MAX_WORKFLOW_JOURNAL_BYTES_V1 {
            return Err(WorkflowError::limit(
                WorkflowStage::Plan,
                "worst-case journal record bytes",
                bound,
                MAX_WORKFLOW_JOURNAL_BYTES_V1,
            ));
        }
        Ok(())
    }

    /// Domain-separated digest of the canonical plan.
    ///
    /// # Errors
    /// Fails only when the plan cannot be encoded.
    pub fn digest(&self) -> Result<Digest32, WorkflowError> {
        Ok(domain_digest(
            PLAN_DIGEST_DOMAIN_V1,
            &[&canonical(self, WorkflowStage::Plan)?],
        ))
    }
}

/// Network and authority of the account context that runs a workflow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowBindingV1 {
    /// Canonical text of the network identity.
    pub network: String,
    /// Canonical, ambient-independent text of the account authority; see
    /// [`authority_binding_text`].
    pub authority: String,
}

/// Everything a workflow identifier commits to.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::workflow::WorkflowIdentityV1")]
pub struct WorkflowIdentityV1 {
    /// Separately named process.
    pub kind: WorkflowKindV1,
    /// Canonical text of the network identity.
    pub network: String,
    /// Canonical text of the account authority.
    pub authority: String,
    /// Caller-chosen instance label.
    pub instance: String,
    /// Capability driver the plan is bound to.
    pub driver: DriverIdentityV1,
    /// Digest of the driver's immutable request context.
    pub request_context_digest: Digest32,
    /// Digest of the canonical plan.
    pub plan_digest: Digest32,
}

impl WorkflowIdentityV1 {
    /// Bind a validated plan to an account context.
    ///
    /// # Errors
    /// Returns the plan validation error or `InvalidInput` for a malformed binding.
    pub fn new(plan: &WorkflowPlanV1, binding: &WorkflowBindingV1) -> Result<Self, WorkflowError> {
        plan.validate()?;
        if !valid_binding(&binding.network) || !valid_binding(&binding.authority) {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Plan,
                "account binding is empty, too long or contains control or whitespace characters",
            ));
        }
        Ok(Self {
            kind: plan.kind,
            network: binding.network.clone(),
            authority: binding.authority.clone(),
            instance: plan.instance.clone(),
            driver: plan.driver.clone(),
            request_context_digest: plan.request_context_digest,
            plan_digest: plan.digest()?,
        })
    }

    /// The workflow identifier: a domain-separated digest of this identity.
    ///
    /// # Errors
    /// Fails only when the identity cannot be encoded.
    pub fn workflow_id(&self) -> Result<WorkflowId, WorkflowError> {
        Ok(WorkflowId(domain_digest(
            WORKFLOW_ID_DOMAIN_V1,
            &[&canonical(self, WorkflowStage::Plan)?],
        )))
    }
}

/// Identity of one signed transaction, as the ledger reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Encode, Decode)]
pub struct TransactionIdentityV1 {
    /// Hash of the signed transaction; the status lookup key.
    pub signed_transaction_hash: Digest32,
    /// Hash of the transaction as an entrypoint.
    pub entrypoint_hash: Digest32,
}

/// Terminal evidence of one transaction identity.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct AttemptEvidenceV1 {
    /// What was established.
    pub kind: AttemptEvidenceKindV1,
    /// Block height reported with the terminal status, when present.
    pub block_height: Option<u64>,
    /// Bounded diagnostic from the ledger or submission owner.
    pub detail: String,
}

/// One transaction identity a step opened.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TransactionAttemptV1 {
    /// One-based ordinal of the identity within its step.
    pub ordinal: u8,
    /// Set once the payload is signed.
    pub identity: Option<TransactionIdentityV1>,
    /// Number of counted dispatches of this identity, bounded by the dispatch bound.
    ///
    /// The ordinal is persisted by the dispatch intent, before the bytes are sent. It
    /// is released again only when that dispatch is proven not to have admitted the
    /// bytes while no dispatch of the identity may have been admitted.
    pub dispatch_ordinal: u8,
    /// Dispatches that may have been admitted (accepted, ambiguous or interrupted).
    pub possible_admissions: u8,
    /// Terminal evidence; present exactly when the identity is closed.
    pub evidence: Option<AttemptEvidenceV1>,
}

/// Durable record of one transaction operation: the unit the one-call SDK core reuses.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TransactionOperationV1 {
    /// Current state.
    pub state: TransactionStateV1,
    /// Every identity ever opened, oldest first; the last is current.
    pub attempts: Vec<TransactionAttemptV1>,
    /// Exact unsigned payload; present only in `ready_to_sign`.
    pub unsigned_payload: Option<Vec<u8>>,
    /// Canonical signed bytes; present only while the identity may be dispatched.
    pub signed_transaction: Option<Vec<u8>>,
}

/// Input of the transaction reducer, carrying the data the event persists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionInputV1 {
    /// Open the first or a replacement identity.
    OpenAttempt,
    /// The driver starts proving and building.
    BuildStarted,
    /// The driver failed before a payload existed.
    BuildFailed,
    /// The driver returned the exact unsigned payload.
    PayloadBuilt {
        /// Canonical unsigned payload bytes.
        payload: Vec<u8>,
    },
    /// The account context signed the payload.
    Signed {
        /// Canonical signed transaction bytes.
        signed_transaction: Vec<u8>,
        /// Identity recomputed from those bytes.
        identity: TransactionIdentityV1,
    },
    /// Persist the next dispatch ordinal.
    DispatchIntent {
        /// The caller authorized retransmission and the latest read was exact absence.
        retransmission_after_exact_absence: bool,
    },
    /// Admission acknowledged.
    DispatchAccepted,
    /// The transaction is already queued or committed.
    DispatchAlreadyKnown,
    /// The dispatch result cannot be established.
    DispatchAmbiguous,
    /// A persisted dispatch ordinal has no recorded result.
    DispatchInterrupted,
    /// Validated definite refusal.
    DispatchRefused {
        /// Refusal diagnostic.
        detail: String,
    },
    /// Not admitted; the same bytes may be sent again.
    DispatchNotAdmitted,
    /// Seen in the pipeline without authoritative finality.
    ObservedInPipeline,
    /// Authoritative `Applied`.
    ReconciledApplied {
        /// Reported block height.
        block_height: Option<u64>,
    },
    /// Authoritative `Rejected`.
    ReconciledRejected {
        /// Rejection diagnostic.
        detail: String,
    },
    /// Authoritative `Expired`.
    ReconciledExpired,
    /// Cancel an operation that cannot have been admitted.
    Cancel,
}

impl TransactionInputV1 {
    /// The table event of this input.
    #[must_use]
    pub const fn event(&self) -> TransactionEventV1 {
        match self {
            Self::OpenAttempt => TransactionEventV1::OpenAttempt,
            Self::BuildStarted => TransactionEventV1::BuildStarted,
            Self::BuildFailed => TransactionEventV1::BuildFailed,
            Self::PayloadBuilt { .. } => TransactionEventV1::PayloadBuilt,
            Self::Signed { .. } => TransactionEventV1::Signed,
            Self::DispatchIntent { .. } => TransactionEventV1::DispatchIntent,
            Self::DispatchAccepted => TransactionEventV1::DispatchAccepted,
            Self::DispatchAlreadyKnown => TransactionEventV1::DispatchAlreadyKnown,
            Self::DispatchAmbiguous => TransactionEventV1::DispatchAmbiguous,
            Self::DispatchInterrupted => TransactionEventV1::DispatchInterrupted,
            Self::DispatchRefused { .. } => TransactionEventV1::DispatchRefused,
            Self::DispatchNotAdmitted => TransactionEventV1::DispatchNotAdmitted,
            Self::ObservedInPipeline => TransactionEventV1::ObservedInPipeline,
            Self::ReconciledApplied { .. } => TransactionEventV1::ReconciledApplied,
            Self::ReconciledRejected { .. } => TransactionEventV1::ReconciledRejected,
            Self::ReconciledExpired => TransactionEventV1::ReconciledExpired,
            Self::Cancel => TransactionEventV1::Cancel,
        }
    }
}

impl Default for TransactionOperationV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionOperationV1 {
    /// A planned operation with no identity.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: TransactionStateV1::Planned,
            attempts: Vec::new(),
            unsigned_payload: None,
            signed_transaction: None,
        }
    }

    /// The current transaction identity slot.
    #[must_use]
    pub fn current(&self) -> Option<&TransactionAttemptV1> {
        self.attempts.last()
    }

    /// The signed identity of the current slot, once signed.
    #[must_use]
    pub fn current_identity(&self) -> Option<TransactionIdentityV1> {
        self.current().and_then(|attempt| attempt.identity)
    }

    /// Guard facts derived from the record and the caller's authorization.
    #[must_use]
    pub fn guard_facts(
        &self,
        max_identities: u8,
        retransmission_authorized: bool,
    ) -> TransactionGuardFactsV1 {
        let current = self.current();
        TransactionGuardFactsV1 {
            identities_remaining: self.attempts.len() < usize::from(max_identities),
            dispatches_remaining: current
                .is_some_and(|attempt| attempt.dispatch_ordinal < MAX_DISPATCHES_PER_IDENTITY_V1),
            retransmission_authorized,
            possible_admission: current.is_some_and(|attempt| attempt.possible_admissions > 0),
        }
    }

    /// Apply one input under the transition table.
    ///
    /// Nothing changes when the input is rejected.
    ///
    /// # Errors
    /// `InvalidInput` for a pair the table does not list, `ResourceLimitExceeded` for
    /// oversized bytes and `BindingMismatch` for a replacement that repeats an identity.
    pub fn apply(
        &mut self,
        input: TransactionInputV1,
        max_identities: u8,
    ) -> Result<TransactionStateV1, WorkflowError> {
        let event = input.event();
        let retransmission = matches!(
            input,
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: true
            }
        );
        let facts = self.guard_facts(max_identities, retransmission);
        let Some(next) = transaction_transition(self.state, event, facts) else {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Store,
                format!(
                    "transaction event `{event}` is not valid in state `{}`",
                    self.state
                ),
            ));
        };
        let closing = |kind, block_height, detail: &str| AttemptEvidenceV1 {
            kind,
            block_height,
            detail: bounded_detail(detail),
        };
        match input {
            TransactionInputV1::OpenAttempt => {
                let ordinal = u8::try_from(self.attempts.len() + 1).map_err(|_| {
                    WorkflowError::limit(
                        WorkflowStage::Store,
                        "transaction identities",
                        self.attempts.len() + 1,
                        usize::from(max_identities),
                    )
                })?;
                self.attempts.push(TransactionAttemptV1 {
                    ordinal,
                    identity: None,
                    dispatch_ordinal: 0,
                    possible_admissions: 0,
                    evidence: None,
                });
            }
            TransactionInputV1::PayloadBuilt { payload } => {
                check_transaction_bytes(payload.len(), WorkflowStage::Prove)?;
                self.unsigned_payload = Some(payload);
            }
            TransactionInputV1::Signed {
                signed_transaction,
                identity,
            } => {
                check_transaction_bytes(signed_transaction.len(), WorkflowStage::Sign)?;
                if self.attempts.iter().any(|attempt| {
                    attempt.identity.is_some_and(|earlier| {
                        earlier.signed_transaction_hash == identity.signed_transaction_hash
                    })
                }) {
                    return Err(WorkflowError::new(
                        WorkflowErrorCode::BindingMismatch,
                        WorkflowStage::Sign,
                        "a replacement transaction repeats an earlier identity of this step",
                    ));
                }
                self.unsigned_payload = None;
                self.signed_transaction = Some(signed_transaction);
                self.current_mut()?.identity = Some(identity);
            }
            TransactionInputV1::DispatchIntent { .. } => {
                self.current_mut()?.dispatch_ordinal += 1;
            }
            TransactionInputV1::DispatchAccepted
            | TransactionInputV1::DispatchAlreadyKnown
            | TransactionInputV1::DispatchAmbiguous
            | TransactionInputV1::DispatchInterrupted => {
                self.current_mut()?.possible_admissions += 1;
            }
            TransactionInputV1::DispatchRefused { detail } => {
                if next == TransactionStateV1::Rejected {
                    self.current_mut()?.evidence = Some(closing(
                        AttemptEvidenceKindV1::AdmissionRefused,
                        None,
                        &detail,
                    ));
                    self.signed_transaction = None;
                }
            }
            TransactionInputV1::ReconciledApplied { block_height } => {
                self.current_mut()?.evidence =
                    Some(closing(AttemptEvidenceKindV1::Applied, block_height, ""));
                self.signed_transaction = None;
            }
            TransactionInputV1::ReconciledRejected { detail } => {
                self.current_mut()?.evidence = Some(closing(
                    AttemptEvidenceKindV1::LedgerRejected,
                    None,
                    &detail,
                ));
                self.signed_transaction = None;
            }
            TransactionInputV1::ReconciledExpired => {
                self.current_mut()?.evidence =
                    Some(closing(AttemptEvidenceKindV1::LedgerExpired, None, ""));
                self.signed_transaction = None;
            }
            TransactionInputV1::Cancel => {
                // Bytes that were never admitted are dropped so they can never be sent.
                self.unsigned_payload = None;
                self.signed_transaction = None;
            }
            TransactionInputV1::DispatchNotAdmitted => {
                // Nothing was admitted by this dispatch and nothing can have been admitted
                // before it: the ordinal is released, so a never-admitted identity never
                // runs out of dispatches. After a possible admission the ordinal stays
                // consumed, like that of every retransmission.
                if next == TransactionStateV1::Signed {
                    let current = self.current_mut()?;
                    current.dispatch_ordinal = current.dispatch_ordinal.saturating_sub(1);
                }
            }
            TransactionInputV1::BuildStarted
            | TransactionInputV1::BuildFailed
            | TransactionInputV1::ObservedInPipeline => {}
        }
        self.state = next;
        Ok(next)
    }

    fn current_mut(&mut self) -> Result<&mut TransactionAttemptV1, WorkflowError> {
        self.attempts.last_mut().ok_or_else(|| {
            WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Store,
                "the transaction record has no identity slot for its state",
            )
        })
    }

    /// Whether the step can never open another identity after its last one closed.
    #[must_use]
    pub fn identities_exhausted(&self, max_identities: u8) -> bool {
        self.state == TransactionStateV1::Rejected
            && self.attempts.len() >= usize::from(max_identities)
    }

    /// Check every structural invariant of the record.
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate(&self, max_identities: u8) -> Result<(), String> {
        use TransactionStateV1 as S;
        if self.attempts.len() > usize::from(max_identities) {
            return Err("more transaction identities than the step allows".to_owned());
        }
        // A step cancelled while still planned never opened an identity slot.
        let may_have_no_slot = matches!(self.state, S::Planned | S::CancelledBeforeSubmission);
        if (self.state == S::Planned && !self.attempts.is_empty())
            || (self.attempts.is_empty() && !may_have_no_slot)
        {
            return Err("identity slots disagree with the state".to_owned());
        }
        if self.unsigned_payload.is_some() != (self.state == S::ReadyToSign) {
            return Err("unsigned payload presence disagrees with the state".to_owned());
        }
        if self.signed_transaction.is_some() != self.state.holds_signed_bytes() {
            return Err("signed bytes presence disagrees with the state".to_owned());
        }
        for bytes in [&self.unsigned_payload, &self.signed_transaction]
            .into_iter()
            .flatten()
        {
            if bytes.is_empty() || bytes.len() > MAX_WORKFLOW_TRANSACTION_BYTES_V1 {
                return Err("retained transaction bytes are out of bounds".to_owned());
            }
        }
        for (index, attempt) in self.attempts.iter().enumerate() {
            if usize::from(attempt.ordinal) != index + 1 {
                return Err("identity ordinals are not sequential".to_owned());
            }
            if attempt.dispatch_ordinal > MAX_DISPATCHES_PER_IDENTITY_V1
                || attempt.possible_admissions > attempt.dispatch_ordinal
            {
                return Err("dispatch counters are out of bounds".to_owned());
            }
            if attempt
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.detail.len() > MAX_WORKFLOW_DETAIL_BYTES_V1)
            {
                return Err("evidence detail is out of bounds".to_owned());
            }
            if let Some(identity) = attempt.identity
                && self.attempts[..index].iter().any(|earlier| {
                    earlier.identity.is_some_and(|other| {
                        other.signed_transaction_hash == identity.signed_transaction_hash
                    })
                })
            {
                return Err("a transaction identity is repeated".to_owned());
            }
            if index + 1 < self.attempts.len() {
                let closed = attempt.identity.is_some()
                    && attempt
                        .evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.kind != AttemptEvidenceKindV1::Applied);
                if !closed {
                    return Err("an earlier identity is not closed by a refusal".to_owned());
                }
            }
        }
        let Some(current) = self.current() else {
            return Ok(());
        };
        let evidence = current.evidence.as_ref().map(|evidence| evidence.kind);
        let consistent = match self.state {
            S::Planned => false,
            S::Prepared | S::Proving | S::ReadyToSign => {
                current.identity.is_none() && current.dispatch_ordinal == 0 && evidence.is_none()
            }
            // No dispatch of a `signed` identity counts: each was released as not admitted.
            S::Signed => {
                current.identity.is_some()
                    && current.dispatch_ordinal == 0
                    && current.possible_admissions == 0
                    && evidence.is_none()
            }
            S::Submitting => {
                current.identity.is_some()
                    && current.dispatch_ordinal >= 1
                    && current.possible_admissions < current.dispatch_ordinal
                    && evidence.is_none()
            }
            S::OutcomeUnknown | S::Pending => {
                current.identity.is_some() && current.possible_admissions >= 1 && evidence.is_none()
            }
            S::Finalized => {
                current.identity.is_some()
                    && current.possible_admissions >= 1
                    && evidence == Some(AttemptEvidenceKindV1::Applied)
            }
            S::Rejected => {
                current.identity.is_some()
                    && match evidence {
                        // A refusal closes an identity only on its one counted dispatch.
                        Some(AttemptEvidenceKindV1::AdmissionRefused) => {
                            current.possible_admissions == 0 && current.dispatch_ordinal == 1
                        }
                        Some(
                            AttemptEvidenceKindV1::LedgerRejected
                            | AttemptEvidenceKindV1::LedgerExpired,
                        ) => current.possible_admissions >= 1,
                        _ => false,
                    }
            }
            S::CancelledBeforeSubmission => current.possible_admissions == 0 && evidence.is_none(),
        };
        if consistent {
            Ok(())
        } else {
            Err(format!(
                "current identity slot is inconsistent with state `{}`",
                self.state
            ))
        }
    }
}

fn check_transaction_bytes(length: usize, stage: WorkflowStage) -> Result<(), WorkflowError> {
    if length == 0 {
        return Err(WorkflowError::new(
            WorkflowErrorCode::InvalidInput,
            stage,
            "transaction bytes are empty",
        ));
    }
    if length > MAX_WORKFLOW_TRANSACTION_BYTES_V1 {
        return Err(WorkflowError::limit(
            stage,
            "transaction bytes",
            length,
            MAX_WORKFLOW_TRANSACTION_BYTES_V1,
        ));
    }
    Ok(())
}

/// Opaque reference to secret material that stays in the caller's custody.
///
/// The reference identifies a key or share inside a platform keystore or
/// custody service. It is never the secret itself.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CustodyHandleV1 {
    /// Role of the referenced material, unique within its round.
    pub label: String,
    /// Opaque bounded reference.
    pub reference: Vec<u8>,
}

/// Durable record of one off-chain round.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RoundRecordV1 {
    /// Current state.
    pub state: RoundStateV1,
    /// Round identity; set when the round intent is persisted.
    pub round_id: Option<Digest32>,
    /// Number of start intents persisted for this round, saturating: 1 after the first
    /// intent, one more for every restart intent, zero exactly while `planned`.
    pub start_ordinal: u32,
    /// Participants received so far, strictly ascending.
    pub participants: Vec<Digest32>,
    /// Public transcript of the completed round.
    pub transcript: Option<Vec<u8>>,
    /// Digest binding the transcript to the round identity.
    pub transcript_digest: Option<Digest32>,
    /// Custody references of the completed round.
    pub custody_handles: Vec<CustodyHandleV1>,
    /// Terminal failure code of a failed round.
    pub failure: Option<WorkflowErrorCode>,
}

/// Input of the round reducer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundInputV1 {
    /// Persist the round identity before the driver starts the round.
    Intent {
        /// Round identity derived from the workflow identifier and step index.
        round_id: Digest32,
    },
    /// The round waits for participants.
    Waiting {
        /// Participants received so far.
        participants: Vec<Digest32>,
    },
    /// The round completed.
    Completed {
        /// Final participant set.
        participants: Vec<Digest32>,
        /// Public transcript.
        transcript: Vec<u8>,
        /// Custody references.
        custody_handles: Vec<CustodyHandleV1>,
    },
    /// The round failed for good.
    Failed {
        /// Typed failure reported by the driver.
        code: WorkflowErrorCode,
    },
    /// Read-only recovery proved the round never started.
    NotStarted,
    /// Persist the restart of a round that recovery proved never started.
    RestartIntent,
}

impl RoundInputV1 {
    /// The table event of this input.
    #[must_use]
    pub const fn event(&self) -> RoundEventV1 {
        match self {
            Self::Intent { .. } => RoundEventV1::Intent,
            Self::Waiting { .. } => RoundEventV1::Waiting,
            Self::Completed { .. } => RoundEventV1::Completed,
            Self::Failed { .. } => RoundEventV1::Failed,
            Self::NotStarted => RoundEventV1::NotStarted,
            Self::RestartIntent => RoundEventV1::RestartIntent,
        }
    }
}

/// Identity of the round of `step_index` in `workflow_id`.
#[must_use]
pub fn round_identity(workflow_id: &WorkflowId, step_index: u32) -> Digest32 {
    domain_digest(
        ROUND_ID_DOMAIN_V1,
        &[workflow_id.as_bytes(), &step_index.to_le_bytes()],
    )
}

/// Digest binding a public transcript to its round identity.
#[must_use]
pub fn transcript_digest(round_id: &Digest32, transcript: &[u8]) -> Digest32 {
    domain_digest(TRANSCRIPT_DIGEST_DOMAIN_V1, &[round_id, transcript])
}

fn check_participants(persisted: &[Digest32], reported: &[Digest32]) -> Result<(), WorkflowError> {
    if reported.len() > MAX_ROUND_PARTICIPANTS_V1 {
        return Err(WorkflowError::limit(
            WorkflowStage::Round,
            "round participants",
            reported.len(),
            MAX_ROUND_PARTICIPANTS_V1,
        ));
    }
    if reported.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WorkflowError::new(
            WorkflowErrorCode::NonCanonicalEncoding,
            WorkflowStage::Round,
            "round participants are duplicated or not in ascending order",
        ));
    }
    if persisted
        .iter()
        .any(|participant| reported.binary_search(participant).is_err())
    {
        return Err(WorkflowError::new(
            WorkflowErrorCode::BindingMismatch,
            WorkflowStage::Round,
            "a participant recorded earlier is missing; a withdrawal must be reported as a round failure",
        ));
    }
    Ok(())
}

impl Default for RoundRecordV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRecordV1 {
    /// A planned round.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: RoundStateV1::Planned,
            round_id: None,
            start_ordinal: 0,
            participants: Vec::new(),
            transcript: None,
            transcript_digest: None,
            custody_handles: Vec::new(),
            failure: None,
        }
    }

    /// Apply one input under the round table and the step's declared bounds.
    ///
    /// Nothing changes when the input is rejected.
    ///
    /// # Errors
    /// `InvalidInput` for a pair the table does not list or a malformed completion,
    /// `NonCanonicalEncoding` for duplicated or reordered participants,
    /// `BindingMismatch` for a shrinking participant set, `ResourceLimitExceeded` for
    /// exceeded bounds and `LocalResourceUnavailable` for missing custody references.
    pub fn apply(
        &mut self,
        input: RoundInputV1,
        descriptor: &StepDescriptorV1,
        cancelling: bool,
    ) -> Result<RoundStateV1, WorkflowError> {
        let event = input.event();
        let Some(next) = round_transition(self.state, event, cancelling) else {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Round,
                format!(
                    "round event `{event}` is not valid in state `{}`",
                    self.state
                ),
            ));
        };
        match input {
            RoundInputV1::Intent { round_id } => {
                self.round_id = Some(round_id);
                self.start_ordinal = 1;
            }
            RoundInputV1::RestartIntent => {
                self.start_ordinal = self.start_ordinal.saturating_add(1);
            }
            RoundInputV1::Waiting { participants } => {
                check_participants(&self.participants, &participants)?;
                self.participants = participants;
            }
            RoundInputV1::Completed {
                participants,
                transcript,
                custody_handles,
            } => {
                check_participants(&self.participants, &participants)?;
                if participants.len() < descriptor.participants_required as usize {
                    return Err(WorkflowError::new(
                        WorkflowErrorCode::InvalidInput,
                        WorkflowStage::Round,
                        format!(
                            "a completed round reports {} of {} required participants",
                            participants.len(),
                            descriptor.participants_required
                        ),
                    ));
                }
                if transcript.is_empty() {
                    return Err(WorkflowError::new(
                        WorkflowErrorCode::InvalidInput,
                        WorkflowStage::Round,
                        "a completed round has an empty transcript",
                    ));
                }
                // The bound the step declared is the one the plan's journal bound relies on.
                if transcript.len() > descriptor.max_transcript_bytes as usize {
                    return Err(WorkflowError::limit(
                        WorkflowStage::Round,
                        "round transcript bytes",
                        transcript.len(),
                        descriptor.max_transcript_bytes as usize,
                    ));
                }
                check_custody_handles(&custody_handles, descriptor)?;
                let Some(round_id) = self.round_id else {
                    return Err(WorkflowError::new(
                        WorkflowErrorCode::InvalidInput,
                        WorkflowStage::Round,
                        "the round record has no identity for its state",
                    ));
                };
                self.transcript_digest = Some(transcript_digest(&round_id, &transcript));
                self.participants = participants;
                self.transcript = Some(transcript);
                self.custody_handles = custody_handles;
            }
            RoundInputV1::Failed { code } => self.failure = Some(code),
            RoundInputV1::NotStarted => {
                self.round_id = None;
                self.start_ordinal = 0;
                self.participants.clear();
            }
        }
        self.state = next;
        Ok(next)
    }

    /// Check every structural invariant of the record.
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate(
        &self,
        descriptor: &StepDescriptorV1,
        expected_round_id: &Digest32,
    ) -> Result<(), String> {
        use RoundStateV1 as S;
        if (self.state == S::Planned) != self.round_id.is_none() {
            return Err("round identity presence disagrees with the state".to_owned());
        }
        if (self.state == S::Planned) != (self.start_ordinal == 0) {
            return Err("round start ordinal disagrees with the state".to_owned());
        }
        if self.round_id.is_some_and(|id| &id != expected_round_id) {
            return Err("round identity does not belong to this workflow step".to_owned());
        }
        if self.participants.len() > MAX_ROUND_PARTICIPANTS_V1
            || self.participants.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("round participants are not canonical".to_owned());
        }
        if self.state == S::Planned && !self.participants.is_empty() {
            return Err("a planned round has participants".to_owned());
        }
        if (self.state == S::RoundFailed) != self.failure.is_some() {
            return Err("round failure presence disagrees with the state".to_owned());
        }
        if self.state == S::RoundCompleted {
            let (Some(round_id), Some(transcript), Some(digest)) =
                (self.round_id, &self.transcript, self.transcript_digest)
            else {
                return Err("a completed round lacks its transcript".to_owned());
            };
            if transcript.is_empty()
                || transcript.len() > descriptor.max_transcript_bytes as usize
                || transcript_digest(&round_id, transcript) != digest
            {
                return Err("round transcript does not match its digest".to_owned());
            }
            if self.participants.len() < descriptor.participants_required as usize {
                return Err("a completed round lacks required participants".to_owned());
            }
            check_custody_handles(&self.custody_handles, descriptor)
                .map_err(|error| error.detail)?;
        } else if self.transcript.is_some()
            || self.transcript_digest.is_some()
            || !self.custody_handles.is_empty()
        {
            return Err("an incomplete round holds a transcript or custody".to_owned());
        }
        Ok(())
    }
}

fn check_custody_handles(
    handles: &[CustodyHandleV1],
    descriptor: &StepDescriptorV1,
) -> Result<(), WorkflowError> {
    let required = descriptor.custody_handles_required as usize;
    if handles.len() < required {
        return Err(WorkflowError::new(
            WorkflowErrorCode::LocalResourceUnavailable,
            WorkflowStage::Round,
            format!(
                "the round returned {} of {required} required custody references",
                handles.len()
            ),
        ));
    }
    if handles.len() > required {
        return Err(WorkflowError::new(
            WorkflowErrorCode::InvalidInput,
            WorkflowStage::Round,
            format!(
                "the round returned {} custody references, {required} declared",
                handles.len()
            ),
        ));
    }
    for (index, handle) in handles.iter().enumerate() {
        if !valid_label(&handle.label)
            || handles[..index]
                .iter()
                .any(|other| other.label == handle.label)
        {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Round,
                "custody labels must be valid and unique",
            ));
        }
        if handle.reference.is_empty() {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Round,
                "a custody reference is empty",
            ));
        }
        if handle.reference.len() > MAX_CUSTODY_REFERENCE_BYTES_V1 {
            return Err(WorkflowError::limit(
                WorkflowStage::Round,
                "custody reference bytes",
                handle.reference.len(),
                MAX_CUSTODY_REFERENCE_BYTES_V1,
            ));
        }
    }
    Ok(())
}

/// One step: its descriptor and exactly one record matching its kind.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct StepRecordV1 {
    /// The planned step.
    pub descriptor: StepDescriptorV1,
    /// Present exactly for a transaction step.
    pub transaction: Option<TransactionOperationV1>,
    /// Present exactly for a round step.
    pub round: Option<RoundRecordV1>,
}

impl StepRecordV1 {
    fn new(descriptor: StepDescriptorV1) -> Self {
        let (transaction, round) = match descriptor.kind {
            StepKindV1::Transaction => (Some(TransactionOperationV1::new()), None),
            StepKindV1::OffchainRound => (None, Some(RoundRecordV1::new())),
        };
        Self {
            descriptor,
            transaction,
            round,
        }
    }

    /// Whether the step is finalized or completed.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.transaction
            .as_ref()
            .is_some_and(|operation| operation.state == TransactionStateV1::Finalized)
            || self
                .round
                .as_ref()
                .is_some_and(|round| round.state == RoundStateV1::RoundCompleted)
    }

    /// Whether the step may still have an external effect nobody has confirmed.
    #[must_use]
    pub fn is_unresolved(&self) -> bool {
        self.transaction
            .as_ref()
            .is_some_and(|operation| operation.state.may_still_commit())
            || self
                .round
                .as_ref()
                .is_some_and(|round| round.state.is_unresolved())
    }

    fn is_untouched(&self) -> bool {
        self.transaction
            .as_ref()
            .is_some_and(|operation| operation.state == TransactionStateV1::Planned)
            || self
                .round
                .as_ref()
                .is_some_and(|round| round.state == RoundStateV1::Planned)
    }

    /// Stable identifier of the step's state.
    #[must_use]
    pub fn state_id(&self) -> &'static str {
        match (&self.transaction, &self.round) {
            (Some(operation), _) => operation.state.id(),
            (None, Some(round)) => round.state.id(),
            (None, None) => "invalid",
        }
    }
}

/// Bounded locator of an independently verified native payment business outcome.
///
/// This is untrusted after decoding: online recovery must re-fetch the original
/// certified block and repeat exact intent, fee and finality verification. It is
/// never a constructor for an opaque verified receipt, nor the current carrier status.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::workflow::NativePaymentCompletionV1")]
pub(crate) struct NativePaymentCompletionV1 {
    pub network: Digest32,
    pub request_digest: Digest32,
    pub transaction_hash: Digest32,
    pub block_height: u64,
    pub block_hash: Digest32,
    pub context_id: Digest32,
    pub receipt_digest: Digest32,
}

/// The durable journal of one workflow.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::workflow::WorkflowJournalV1")]
pub struct WorkflowJournalV1 {
    /// Journal layout version; the only supported value is 1.
    pub version: u16,
    /// Number of the stored record; starts at 1 and grows by one per store.
    pub sequence: u64,
    /// Workflow identifier; equals the digest of `identity`.
    pub workflow_id: Digest32,
    /// Everything the identifier commits to.
    pub identity: WorkflowIdentityV1,
    /// Workflow status.
    pub status: WorkflowStatusV1,
    /// Whether cancellation was requested.
    pub cancel_requested: bool,
    /// Error code of a failed workflow.
    pub failure_code: Option<WorkflowErrorCode>,
    /// Step that failed.
    pub failure_step: Option<u32>,
    /// Local creation time in Unix milliseconds. Informational; never used for validity.
    pub created_at_ms: u64,
    /// Local time of the latest record. Informational; never used for validity.
    pub updated_at_ms: u64,
    /// Steps in plan order.
    pub steps: Vec<StepRecordV1>,
    /// Independently verified business completion; decoded metadata requires re-verification.
    pub(crate) native_payment_completion: Option<NativePaymentCompletionV1>,
}

/// The stored record: the journal and the digest of its canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha::workflow::WorkflowJournalRecordV1")]
pub struct WorkflowJournalRecordV1 {
    /// The journal, including its version and sequence.
    pub journal: WorkflowJournalV1,
    /// Domain-separated digest of the canonical journal.
    pub digest: Digest32,
}

fn corrupted(detail: impl Into<String>) -> WorkflowError {
    WorkflowError::new(
        WorkflowErrorCode::StorageCorrupted,
        WorkflowStage::Load,
        detail,
    )
}

impl WorkflowJournalV1 {
    /// The first journal of a workflow: every step planned, sequence zero.
    ///
    /// The sequence becomes 1 when the record is first stored.
    ///
    /// # Errors
    /// Returns the plan or identity error.
    pub fn new(
        plan: &WorkflowPlanV1,
        binding: &WorkflowBindingV1,
        now_ms: u64,
    ) -> Result<Self, WorkflowError> {
        let identity = WorkflowIdentityV1::new(plan, binding)?;
        Ok(Self {
            version: WORKFLOW_JOURNAL_VERSION_V1,
            sequence: 0,
            workflow_id: *identity.workflow_id()?.as_bytes(),
            identity,
            status: WorkflowStatusV1::InProgress,
            cancel_requested: false,
            failure_code: None,
            failure_step: None,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            steps: plan.steps.iter().cloned().map(StepRecordV1::new).collect(),
            native_payment_completion: None,
        })
    }

    /// The workflow identifier.
    #[must_use]
    pub const fn id(&self) -> WorkflowId {
        WorkflowId(self.workflow_id)
    }

    /// The plan this journal was created from.
    #[must_use]
    pub fn plan(&self) -> WorkflowPlanV1 {
        WorkflowPlanV1 {
            kind: self.identity.kind,
            instance: self.identity.instance.clone(),
            driver: self.identity.driver.clone(),
            request_context_digest: self.identity.request_context_digest,
            steps: self
                .steps
                .iter()
                .map(|step| step.descriptor.clone())
                .collect(),
        }
    }

    /// Index of the first step that is not finalized or completed.
    #[must_use]
    pub fn current_step(&self) -> Option<usize> {
        self.steps.iter().position(|step| !step.is_done())
    }

    fn step_failure(&self, index: usize) -> Option<WorkflowErrorCode> {
        let step = &self.steps[index];
        if let Some(operation) = &step.transaction {
            if !operation.identities_exhausted(step.descriptor.max_transaction_identities) {
                return None;
            }
            let expired = operation
                .current()
                .and_then(|attempt| attempt.evidence.as_ref())
                .is_some_and(|evidence| evidence.kind == AttemptEvidenceKindV1::LedgerExpired);
            return Some(if expired {
                WorkflowErrorCode::Expired
            } else {
                WorkflowErrorCode::Rejected
            });
        }
        step.round.as_ref().and_then(|round| round.failure)
    }

    /// Re-derive the workflow status from the steps, under the workflow status table.
    pub fn settle(&mut self) {
        let current = self.current_step();
        let event = match (self.status, current) {
            (WorkflowStatusV1::InProgress | WorkflowStatusV1::Cancelling, None) => {
                Some(WorkflowEventV1::AllStepsDone)
            }
            (WorkflowStatusV1::InProgress, Some(index)) => self.step_failure(index).map(|code| {
                self.failure_code = Some(code);
                self.failure_step = u32::try_from(index).ok();
                WorkflowEventV1::StepFailed
            }),
            (WorkflowStatusV1::Cancelling, Some(index)) => {
                (!self.steps[index].is_unresolved()).then(|| {
                    // The cancellation takes effect now: the first unfinished step is never
                    // submitted. It may be the in-flight step itself, back in `signed`
                    // after a dispatch that admitted nothing, or the untouched next step.
                    self.cancel_unsubmitted(index);
                    WorkflowEventV1::UnresolvedEffectResolved
                })
            }
            _ => None,
        };
        if let Some(next) = event.and_then(|event| workflow_transition(self.status, event)) {
            self.status = next;
        }
    }

    /// Move the transaction step `index` to `cancelled_before_submission`, dropping its
    /// payload or signed bytes. A closed (`rejected`) identity and a round are left as they are.
    ///
    /// Only called for a step that is neither done nor unresolved.
    fn cancel_unsubmitted(&mut self, index: usize) {
        let step = &mut self.steps[index];
        let maximum = step.descriptor.max_transaction_identities;
        if let Some(operation) = &mut step.transaction
            && operation.state != TransactionStateV1::Rejected
        {
            operation
                .apply(TransactionInputV1::Cancel, maximum)
                .expect("every state that cannot commit accepts cancellation");
        }
    }

    /// Apply a transaction input to step `index` and settle the workflow status.
    ///
    /// # Errors
    /// Returns the reducer error; `InvalidInput` when the step is not a transaction.
    pub fn apply_transaction(
        &mut self,
        index: usize,
        input: TransactionInputV1,
    ) -> Result<TransactionStateV1, WorkflowError> {
        let step = self.steps.get_mut(index).ok_or_else(|| not_a_step(index))?;
        let maximum = step.descriptor.max_transaction_identities;
        let operation = step.transaction.as_mut().ok_or_else(|| not_a_step(index))?;
        let state = operation
            .apply(input, maximum)
            .map_err(|error| error.with_step(index))?;
        self.settle();
        Ok(state)
    }

    /// Apply a round input to step `index` and settle the workflow status.
    ///
    /// # Errors
    /// Returns the reducer error; `InvalidInput` when the step is not a round.
    pub fn apply_round(
        &mut self,
        index: usize,
        input: RoundInputV1,
    ) -> Result<RoundStateV1, WorkflowError> {
        let cancelling = self.status == WorkflowStatusV1::Cancelling;
        let step = self.steps.get_mut(index).ok_or_else(|| not_a_step(index))?;
        let round = step.round.as_mut().ok_or_else(|| not_a_step(index))?;
        let state = round
            .apply(input, &step.descriptor, cancelling)
            .map_err(|error| error.with_step(index))?;
        self.settle();
        Ok(state)
    }

    /// Record a cancellation request. Returns whether the journal changed.
    ///
    /// A workflow whose current step may still have external effect becomes
    /// `cancelling`; otherwise it becomes `cancelled` and a transaction step that
    /// cannot have been admitted becomes `cancelled_before_submission`. The same
    /// happens to the first unfinished step when a `cancelling` workflow resolves
    /// (see [`Self::settle`]). Nothing is rolled back.
    pub fn request_cancel(&mut self) -> bool {
        if self.status != WorkflowStatusV1::InProgress {
            return false;
        }
        let Some(index) = self.current_step() else {
            return false;
        };
        self.cancel_requested = true;
        let event = if self.steps[index].is_unresolved() {
            WorkflowEventV1::CancelUnresolved
        } else {
            self.cancel_unsubmitted(index);
            WorkflowEventV1::CancelResolved
        };
        self.status = workflow_transition(self.status, event)
            .expect("an in-progress workflow accepts cancellation");
        true
    }

    /// Check every invariant of the journal.
    ///
    /// # Errors
    /// Returns the first violated invariant, preserving local encoding refusal.
    pub fn validate(&self) -> Result<(), WorkflowError> {
        let invalid = |detail: String| {
            WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Store,
                detail,
            )
        };
        if self.version != WORKFLOW_JOURNAL_VERSION_V1 {
            return Err(invalid(format!(
                "unsupported journal version {}",
                self.version
            )));
        }
        let plan = self.plan();
        plan.validate()?;
        if !valid_binding(&self.identity.network) || !valid_binding(&self.identity.authority) {
            return Err(invalid("account binding is malformed".to_owned()));
        }
        if plan.digest()? != self.identity.plan_digest {
            return Err(invalid(
                "plan digest does not match the step descriptors".to_owned(),
            ));
        }
        let id = self.identity.workflow_id()?;
        if id.as_bytes() != &self.workflow_id {
            return Err(invalid(
                "workflow identifier does not match its identity".to_owned(),
            ));
        }
        if let Some(completion) = &self.native_payment_completion {
            if self.identity.kind != WorkflowKindV1::NativePayment
                || completion.block_height < 2
                || completion.request_digest != self.identity.request_context_digest
                || self
                    .identity
                    .network
                    .parse::<iroha_data_model::NetworkId>()
                    .ok()
                    .map(|network| *network.as_bytes())
                    != Some(completion.network)
            {
                return Err(invalid(
                    "native payment completion differs from its workflow binding".into(),
                ));
            }
        }
        let current = self.current_step();
        for (index, step) in self.steps.iter().enumerate() {
            let step_index =
                u32::try_from(index).map_err(|_| invalid("step index overflow".to_owned()))?;
            match (step.descriptor.kind, &step.transaction, &step.round) {
                (StepKindV1::Transaction, Some(operation), None) => operation
                    .validate(step.descriptor.max_transaction_identities)
                    .map_err(|detail| invalid(format!("step {index}: {detail}")))?,
                (StepKindV1::OffchainRound, None, Some(round)) => round
                    .validate(&step.descriptor, &round_identity(&id, step_index))
                    .map_err(|detail| invalid(format!("step {index}: {detail}")))?,
                _ => {
                    return Err(invalid(format!(
                        "step {index}: record does not match its kind"
                    )));
                }
            }
            if current.is_some_and(|current| index > current) && !step.is_untouched() {
                return Err(invalid(format!(
                    "step {index} progressed before step {current:?}"
                )));
            }
        }
        let cancelled_step = self.steps.iter().any(|step| {
            step.transaction.as_ref().is_some_and(|operation| {
                operation.state == TransactionStateV1::CancelledBeforeSubmission
            })
        });
        if cancelled_step && self.status != WorkflowStatusV1::Cancelled {
            return Err(invalid(
                "a step is cancelled while the workflow is not".to_owned(),
            ));
        }
        // Bytes are kept only while they may still be signed or dispatched.
        let holds_bytes = self.steps.iter().any(|step| {
            step.transaction.as_ref().is_some_and(|operation| {
                operation.unsigned_payload.is_some() || operation.signed_transaction.is_some()
            })
        });
        if self.status.is_terminal() && holds_bytes {
            return Err(invalid(
                "a terminal workflow holds transaction bytes".to_owned(),
            ));
        }
        let unresolved = current.is_some_and(|index| self.steps[index].is_unresolved());
        let failure = current.and_then(|index| self.step_failure(index));
        // In a cancelled workflow the first unfinished transaction step was never
        // submitted, or its identity is closed.
        let current_unsubmitted = current.is_some_and(|index| {
            self.steps[index]
                .transaction
                .as_ref()
                .is_none_or(|operation| {
                    matches!(
                        operation.state,
                        TransactionStateV1::CancelledBeforeSubmission
                            | TransactionStateV1::Rejected
                    )
                })
        });
        let consistent = match self.status {
            WorkflowStatusV1::Completed => current.is_none(),
            WorkflowStatusV1::InProgress => {
                current.is_some() && !self.cancel_requested && failure.is_none()
            }
            WorkflowStatusV1::Cancelling => self.cancel_requested && unresolved,
            WorkflowStatusV1::Cancelled => {
                self.cancel_requested && !unresolved && current_unsubmitted
            }
            WorkflowStatusV1::Failed => {
                failure.is_some()
                    && failure == self.failure_code
                    && self.failure_step == current.and_then(|index| u32::try_from(index).ok())
            }
        };
        if !consistent {
            return Err(invalid(format!(
                "workflow status `{}` disagrees with its steps",
                self.status
            )));
        }
        if (self.status == WorkflowStatusV1::Failed) != self.failure_code.is_some()
            || self.failure_code.is_some() != self.failure_step.is_some()
        {
            return Err(invalid(
                "failure fields disagree with the workflow status".to_owned(),
            ));
        }
        Ok(())
    }

    /// Domain-separated digest of the canonical journal, covering version and sequence.
    ///
    /// # Errors
    /// Fails only when the journal cannot be encoded.
    pub fn digest(&self) -> Result<Digest32, WorkflowError> {
        Ok(domain_digest(
            JOURNAL_DIGEST_DOMAIN_V1,
            &[&canonical(self, WorkflowStage::Store)?],
        ))
    }

    /// Encode the canonical stored record. An invalid journal is never encoded.
    ///
    /// # Errors
    /// `InvalidInput` for a journal that violates an invariant or has sequence zero and
    /// `ResourceLimitExceeded` when the record exceeds the journal bound.
    pub fn encode_record(&self) -> Result<Vec<u8>, WorkflowError> {
        if self.sequence == 0 {
            return Err(WorkflowError::new(
                WorkflowErrorCode::InvalidInput,
                WorkflowStage::Store,
                "a stored journal has a nonzero sequence",
            ));
        }
        self.validate().map_err(|error| {
            journal_record_error(
                error,
                WorkflowStage::Store,
                WorkflowErrorCode::InvalidInput,
                "journal validation before storage",
            )
        })?;
        let record = WorkflowJournalRecordV1 {
            digest: self.digest()?,
            journal: self.clone(),
        };
        let bytes = canonical(&record, WorkflowStage::Store)?;
        if bytes.len() > MAX_WORKFLOW_JOURNAL_BYTES_V1 {
            return Err(WorkflowError::limit(
                WorkflowStage::Store,
                "journal record bytes",
                bytes.len(),
                MAX_WORKFLOW_JOURNAL_BYTES_V1,
            ));
        }
        Ok(bytes)
    }

    /// Decode and verify one stored record.
    ///
    /// The length is bounded before decoding, the encoding must be canonical, the
    /// journal digest and every identifier are recomputed and all invariants are
    /// checked. Nothing is repaired.
    ///
    /// # Errors
    /// `StorageCorrupted` for completed invalidity, or resumable
    /// `LocalResourceUnavailable` when the original decoder cannot finish.
    pub fn decode_record(bytes: &[u8]) -> Result<Self, WorkflowError> {
        if bytes.len() > MAX_WORKFLOW_JOURNAL_BYTES_V1 {
            return Err(corrupted(format!(
                "journal record is {} bytes, maximum {MAX_WORKFLOW_JOURNAL_BYTES_V1}",
                bytes.len()
            )));
        }
        let record: WorkflowJournalRecordV1 =
            norito::core::classify_decode_attempt(|| norito::decode_canonical(bytes)).map_err(
                |error| match error.kind() {
                    norito::core::DecodeAttemptErrorKind::Allocator
                    | norito::core::DecodeAttemptErrorKind::EnclosingLimit => WorkflowError::new(
                        WorkflowErrorCode::LocalResourceUnavailable,
                        WorkflowStage::Load,
                        "the original journal decoder could not finish within local resources",
                    ),
                    norito::core::DecodeAttemptErrorKind::Invalid => {
                        corrupted(format!("journal record is not canonical: {error}"))
                    }
                },
            )?;
        let journal = record.journal;
        if journal.sequence == 0 {
            return Err(corrupted("journal sequence is zero"));
        }
        let digest = journal.digest().map_err(|error| {
            journal_record_error(
                error,
                WorkflowStage::Load,
                WorkflowErrorCode::StorageCorrupted,
                "journal digest verification",
            )
        })?;
        if digest != record.digest {
            return Err(corrupted("journal digest does not match its contents"));
        }
        journal.validate().map_err(|error| {
            journal_record_error(
                error,
                WorkflowStage::Load,
                WorkflowErrorCode::StorageCorrupted,
                "journal invariant verification",
            )
        })?;
        Ok(journal)
    }

    /// The explicit progress and partial-completion report of this journal.
    #[must_use]
    pub fn progress(&self) -> WorkflowProgressV1 {
        let mut partial = PartialCompletionV1::default();
        let mut steps = Vec::with_capacity(self.steps.len());
        for (index, step) in self.steps.iter().enumerate() {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let failed = step
                .transaction
                .as_ref()
                .is_some_and(|operation| operation.state == TransactionStateV1::Rejected)
                || step
                    .round
                    .as_ref()
                    .is_some_and(|round| round.state == RoundStateV1::RoundFailed);
            if step.is_done() {
                partial.confirmed_steps.push(index);
                if step.descriptor.irreversible {
                    partial.irreversible_steps.push(index);
                }
            } else if step.is_unresolved() {
                partial.unresolved_steps.push(index);
            } else if failed {
                partial.failed_steps.push(index);
            } else {
                partial.not_started_steps.push(index);
            }
            let round = step.round.as_ref();
            steps.push(StepProgressV1 {
                index,
                label: step.descriptor.label.clone(),
                kind: step.descriptor.kind,
                state: step.state_id(),
                irreversible: step.descriptor.irreversible,
                identities: step
                    .transaction
                    .as_ref()
                    .map(|operation| operation.attempts.clone())
                    .unwrap_or_default(),
                participants_received: round.map_or(0, |round| {
                    u32::try_from(round.participants.len()).unwrap_or(u32::MAX)
                }),
                participants_required: step.descriptor.participants_required,
                transcript_digest: round.and_then(|round| round.transcript_digest),
                custody_handles: round.map_or(0, |round| {
                    u32::try_from(round.custody_handles.len()).unwrap_or(u32::MAX)
                }),
                round_start_intents: round.map_or(0, |round| round.start_ordinal),
            });
        }
        WorkflowProgressV1 {
            workflow_id: self.id(),
            kind: self.identity.kind,
            status: self.status,
            sequence: self.sequence,
            cancel_requested: self.cancel_requested,
            atomicity: WORKFLOW_ATOMICITY_V1,
            current_step: self
                .current_step()
                .and_then(|index| u32::try_from(index).ok()),
            failure_code: self.failure_code,
            steps,
            partial_completion: partial,
        }
    }
}

fn not_a_step(index: usize) -> WorkflowError {
    WorkflowError::new(
        WorkflowErrorCode::InvalidInput,
        WorkflowStage::Store,
        "the step does not exist or has another kind",
    )
    .with_step(index)
}

/// Progress of one step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepProgressV1 {
    /// Zero-based step index.
    pub index: u32,
    /// Step label.
    pub label: String,
    /// Step kind.
    pub kind: StepKindV1,
    /// Stable identifier of the step state.
    pub state: &'static str,
    /// Whether completing the step cannot be undone.
    pub irreversible: bool,
    /// Every transaction identity the step opened, with its dispatch counters and evidence.
    pub identities: Vec<TransactionAttemptV1>,
    /// Participants a round has received.
    pub participants_received: u32,
    /// Participants a round requires.
    pub participants_required: u32,
    /// Transcript digest of a completed round.
    pub transcript_digest: Option<Digest32>,
    /// Number of custody references of a completed round.
    pub custody_handles: u32,
    /// Start intents persisted for a round: the first start and every restart.
    pub round_start_intents: u32,
}

/// Explicit statement of what a workflow has and has not done.
///
/// Confirmed progress and unresolved possible effects are separate lists, and
/// `rolled_back_steps` is always empty: a workflow rolls nothing back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_field_names,
    reason = "the field names are the keys of the contract's progress report"
)]
pub struct PartialCompletionV1 {
    /// Steps whose transaction is finalized or whose round completed.
    pub confirmed_steps: Vec<u32>,
    /// Confirmed steps that cannot be undone.
    pub irreversible_steps: Vec<u32>,
    /// Steps that may still have an external effect nobody has confirmed.
    pub unresolved_steps: Vec<u32>,
    /// Steps whose transaction identity was closed by a refusal or whose round failed.
    pub failed_steps: Vec<u32>,
    /// Steps with no possible external effect.
    pub not_started_steps: Vec<u32>,
    /// Always empty.
    pub rolled_back_steps: Vec<u32>,
}

/// Snapshot of one validated journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowProgressV1 {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Separately named process.
    pub kind: WorkflowKindV1,
    /// Workflow status.
    pub status: WorkflowStatusV1,
    /// Sequence of the journal record this snapshot was taken from.
    pub sequence: u64,
    /// Whether cancellation was requested.
    pub cancel_requested: bool,
    /// Always `per_transaction_only`.
    pub atomicity: &'static str,
    /// First step that is not finalized or completed.
    pub current_step: Option<u32>,
    /// Error code of a failed workflow.
    pub failure_code: Option<WorkflowErrorCode>,
    /// Every step in plan order.
    pub steps: Vec<StepProgressV1>,
    /// What is confirmed, unresolved, failed and untouched.
    pub partial_completion: PartialCompletionV1,
}

impl WorkflowProgressV1 {
    /// Whether some step has confirmed or unresolved effect while the workflow is not completed.
    #[must_use]
    pub fn is_partially_complete(&self) -> bool {
        self.status != WorkflowStatusV1::Completed
            && (!self.partial_completion.confirmed_steps.is_empty()
                || !self.partial_completion.unresolved_steps.is_empty())
    }

    /// Render the snapshot as the JSON the shared scenario fixtures compare against.
    #[must_use]
    pub fn to_json(&self) -> Value {
        fn indexes(values: &[u32]) -> Value {
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::from(u64::from(*value)))
                    .collect(),
            )
        }
        fn object(entries: Vec<(&str, Value)>) -> Value {
            let mut map = Map::new();
            for (key, value) in entries {
                map.insert(key.to_owned(), value);
            }
            Value::Object(map)
        }
        let text = |value: &str| Value::String(value.to_owned());
        let optional_hex =
            |value: Option<Digest32>| value.map_or(Value::Null, |bytes| text(&hex::encode(bytes)));
        let steps =
            self.steps
                .iter()
                .map(|step| {
                    let identities =
                        step.identities
                            .iter()
                            .map(|attempt| {
                                object(vec![
                                    ("ordinal", Value::from(u64::from(attempt.ordinal))),
                                    (
                                        "signed_transaction_hash",
                                        optional_hex(
                                            attempt
                                                .identity
                                                .map(|identity| identity.signed_transaction_hash),
                                        ),
                                    ),
                                    (
                                        "dispatches",
                                        Value::from(u64::from(attempt.dispatch_ordinal)),
                                    ),
                                    (
                                        "possible_admissions",
                                        Value::from(u64::from(attempt.possible_admissions)),
                                    ),
                                    (
                                        "evidence",
                                        attempt.evidence.as_ref().map_or(Value::Null, |evidence| {
                                            text(evidence.kind.id())
                                        }),
                                    ),
                                ])
                            })
                            .collect();
                    object(vec![
                        ("index", Value::from(u64::from(step.index))),
                        ("label", text(&step.label)),
                        ("kind", text(step.kind.id())),
                        ("state", text(step.state)),
                        ("irreversible", Value::Bool(step.irreversible)),
                        ("identities", Value::Array(identities)),
                        (
                            "participants_received",
                            Value::from(u64::from(step.participants_received)),
                        ),
                        (
                            "participants_required",
                            Value::from(u64::from(step.participants_required)),
                        ),
                        ("transcript_digest", optional_hex(step.transcript_digest)),
                        (
                            "custody_handles",
                            Value::from(u64::from(step.custody_handles)),
                        ),
                        (
                            "round_start_intents",
                            Value::from(u64::from(step.round_start_intents)),
                        ),
                    ])
                })
                .collect();
        let partial = &self.partial_completion;
        object(vec![
            ("workflow_id", text(&self.workflow_id.to_hex())),
            ("kind", text(self.kind.id())),
            ("status", text(self.status.id())),
            ("sequence", Value::from(self.sequence)),
            ("cancel_requested", Value::Bool(self.cancel_requested)),
            ("atomicity", text(self.atomicity)),
            (
                "current_step",
                self.current_step
                    .map_or(Value::Null, |index| Value::from(u64::from(index))),
            ),
            (
                "failure_code",
                self.failure_code
                    .map_or(Value::Null, |code| text(code.id())),
            ),
            (
                "partially_complete",
                Value::Bool(self.is_partially_complete()),
            ),
            ("steps", Value::Array(steps)),
            (
                "partial_completion",
                object(vec![
                    ("confirmed_steps", indexes(&partial.confirmed_steps)),
                    ("irreversible_steps", indexes(&partial.irreversible_steps)),
                    ("unresolved_steps", indexes(&partial.unresolved_steps)),
                    ("failed_steps", indexes(&partial.failed_steps)),
                    ("not_started_steps", indexes(&partial.not_started_steps)),
                    ("rolled_back_steps", indexes(&partial.rolled_back_steps)),
                ]),
            ),
        ])
    }
}

#[cfg(test)]
mod original_writer_error_tests {
    //! Writer failures retain their category at journal validation boundaries.
    use super::*;

    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha::workflow::tests::RefusingWriter")]
    struct RefusingWriter(bool);
    impl norito::SerializePayload for RefusingWriter {
        fn serialize(&self, _: &mut norito::core::Encoder<'_>) -> Result<(), norito::Error> {
            Err(if self.0 {
                norito::Error::AllocationFailed { bytes: 17 }
            } else {
                norito::Error::Message("allocation failed; bytes 17".into())
            })
        }
    }

    #[test]
    fn original_writer_allocation_failure_stays_retryable_through_store_and_read() {
        for stage in [WorkflowStage::Store, WorkflowStage::Load] {
            let code = if stage == WorkflowStage::Store {
                WorkflowErrorCode::InvalidInput
            } else {
                WorkflowErrorCode::StorageCorrupted
            };
            let error = canonical(&RefusingWriter(true), stage).unwrap_err();
            let error = journal_record_error(error, stage, code, "original writer");
            assert_eq!(error.code, WorkflowErrorCode::LocalResourceUnavailable);
            assert_eq!(error.stage, stage);
            assert!(error.is_resumable());
            assert!(error.progress.is_none());
            // Similar diagnostic words do not confer allocator provenance.
            let invalid = canonical(&RefusingWriter(false), stage).unwrap_err();
            let invalid = journal_record_error(invalid, stage, code, "completed invalidity");
            assert_eq!(invalid.code, code);
        }
    }
}
