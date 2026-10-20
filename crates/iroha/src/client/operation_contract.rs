//! Machine-readable form of the shared one-call and prepared operation contract (S.1).
//!
//! `specs/zk_operation_contract.md` is the normative contract and
//! `fixtures/zk/operation_v1/` holds its SDK-neutral fixtures. [`operation_contract_json`]
//! renders `contract.json` from the Rust tables it states: the stage, state and error
//! vocabularies of [`crate::workflow::contract`], the composition bounds of the data model,
//! the committed transaction defaults and the closed dispatch table of the client's single
//! submission owner. A test fails when the tracked file differs, so the contract the six SDK
//! families read cannot drift from those owners.
//!
//! This version is provisional, pending the plan author's review; the specification links
//! the decisions it follows. It names the prepared and built artifacts and lists their fields
//! but defines no canonical encoding for them: their Norito types and byte vectors belong to
//! the transport-free operation core.
//!
//! TODO(S1-A2): move these tables into the transport-free operation core crate together with
//! the single-operation reducer, and add the canonical artifact types and their vectors.
//! TODO(S1-A3): implement `execute_operation` and the advanced calls over these tables and run
//! the shared scenarios against the Rust client.

use iroha_data_model::{
    parameter::system::TransactionParameters,
    transaction::signed_attachments::{
        SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1, SIGNED_ATTACHMENTS_MAX_ACTIONS_V1,
        SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1, SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
    },
};
use norito::json::{Map, Value};

use super::{
    SIGNED_TRANSACTION_HASH_HEADER, TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE,
    TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE, TRANSACTION_ENTRYPOINT_HASH_HEADER,
    TRANSACTION_SUBMISSION_RESPONSE_MAX_BYTES,
    transaction_dispatch_error::{DEFINITE_DISPATCH_ROWS, DefiniteDispatchResult},
};
use crate::{
    http::StatusCode,
    workflow::contract::{
        TransactionEventV1, TransactionStateV1, WorkflowErrorCode, WorkflowStage,
    },
};

/// Schema identifier of the machine-readable operation contract.
pub const OPERATION_CONTRACT_SCHEMA_V1: &str = "iroha.zk_operation.contract.v1";
/// Review state of this contract version.
pub const OPERATION_CONTRACT_REVIEW_V1: &str = "provisional_pending_plan_author_review";
/// The provisional decisions this version follows: a local handoff record of the delivery
/// plan, kept outside the tracked tree.
pub const OPERATION_CONTRACT_DECISIONS_V1: &str =
    "dist/zk-delivery-handoff/claude/s1/provisional-decisions-2026-10-19.md";
/// Name of the high-level call every SDK family exposes.
pub const ONE_CALL_V1: &str = "execute_operation";
/// Provisional name of the proof-free, unsigned artifact `prepare` returns.
///
/// Distinct from the Torii onboarding and faucet "prepared-operation V1" contract.
pub const PREPARED_OPERATION_ARTIFACT_V1: &str = "PreparedZkOperationV1";
/// Provisional name of the complete, unsigned artifact `build` returns.
pub const BUILT_OPERATION_ARTIFACT_V1: &str = "BuiltZkOperationV1";
/// The shared transaction reducer an operation runs: its states, events and transitions.
pub const OPERATION_REDUCER_V1: &str = "fixtures/zk/workflow_v1/state_machine.json";

/// One call of an operation: an advanced stage of the prepared form.
///
/// [`ONE_CALL_V1`] runs all of them in [`Self::ALL`] order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperationCallV1 {
    /// Validate the request and every composition bound, create the durable operation and
    /// open its transaction identity.
    Prepare,
    /// Generate the proofs of the composed actions for their public statements.
    Prove,
    /// Verify the generated proofs locally before anything is built or signed.
    LocalVerify,
    /// Build the exact canonical unsigned payload and persist it.
    Build,
    /// Sign with the account's opaque signer, or assemble and verify an external signature,
    /// and persist the signed bytes with their identity.
    Sign,
    /// Persist the dispatch ordinal, then dispatch the exact signed bytes once.
    Submit,
    /// Read the committed outcome of the identity and, by default, authenticate its finality.
    AwaitFinality,
}

impl OperationCallV1 {
    /// Every advanced call, in pipeline order.
    pub const ALL: &'static [Self] = &[
        Self::Prepare,
        Self::Prove,
        Self::LocalVerify,
        Self::Build,
        Self::Sign,
        Self::Submit,
        Self::AwaitFinality,
    ];

    /// Stable identifier used by the contract and the fixtures.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Prove => "prove",
            Self::LocalVerify => "local_verify",
            Self::Build => "build",
            Self::Sign => "sign",
            Self::Submit => "submit",
            Self::AwaitFinality => "await_finality",
        }
    }

    /// Parse a stable call identifier.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|call| call.id() == id)
    }

    /// Stages the errors of this call report, besides the journal stages
    /// ([`OPERATION_JOURNAL_STAGES_V1`]).
    #[must_use]
    pub const fn stages(self) -> &'static [WorkflowStage] {
        match self {
            Self::Prepare => &[WorkflowStage::Plan],
            Self::Prove => &[WorkflowStage::Prove],
            Self::LocalVerify => &[WorkflowStage::LocalVerify],
            Self::Build => &[WorkflowStage::Build],
            Self::Sign => &[WorkflowStage::Sign],
            Self::Submit => &[WorkflowStage::Submit],
            Self::AwaitFinality => &[WorkflowStage::Reconcile, WorkflowStage::Finality],
        }
    }

    /// Events of the shared transaction reducer this call may apply.
    #[must_use]
    pub const fn events(self) -> &'static [TransactionEventV1] {
        use TransactionEventV1 as E;
        match self {
            Self::Prepare => &[E::OpenAttempt],
            Self::Prove => &[E::BuildStarted, E::BuildFailed],
            Self::LocalVerify => &[E::BuildFailed],
            Self::Build => &[E::PayloadBuilt, E::BuildFailed],
            Self::Sign => &[E::Signed],
            Self::Submit => &[
                E::DispatchIntent,
                E::DispatchAccepted,
                E::DispatchAlreadyKnown,
                E::DispatchRefused,
                E::DispatchNotAdmitted,
                E::DispatchAmbiguous,
            ],
            Self::AwaitFinality => &[
                E::DispatchInterrupted,
                E::ObservedInPipeline,
                E::ReconciledApplied,
                E::ReconciledRejected,
                E::ReconciledExpired,
            ],
        }
    }
}

/// Stages any call of a durable operation may report: journal load and store.
pub const OPERATION_JOURNAL_STAGES_V1: &[WorkflowStage] =
    &[WorkflowStage::Load, WorkflowStage::Store];

/// Calls of the durable handle [`ONE_CALL_V1`] returns, with the stages their errors report
/// besides the journal stages. `run` resumes the one-call from the stored state.
pub const OPERATION_HANDLE_CALLS_V1: &[(&str, &[WorkflowStage])] = &[
    ("run", &[]),
    (
        "recover",
        &[WorkflowStage::Reconcile, WorkflowStage::Finality],
    ),
    ("cancel", &[WorkflowStage::Cancel]),
    ("progress", &[]),
];

/// Reducer events a cancellation applies.
pub const OPERATION_CANCEL_EVENTS_V1: &[TransactionEventV1] = &[TransactionEventV1::Cancel];

/// Whether `state` is one of the durable states an operation reports after `prepare`.
///
/// These are the states of the shared transaction reducer except its initial `planned`, in
/// which a journal exists and no identity slot is open yet.
#[must_use]
pub const fn is_operation_state(state: TransactionStateV1) -> bool {
    !matches!(state, TransactionStateV1::Planned)
}

/// What each shared error code means for one operation, in [`WorkflowErrorCode::ALL`] order.
pub const OPERATION_ERROR_MEANINGS_V1: &[(WorkflowErrorCode, &str)] = &[
    (
        WorkflowErrorCode::InvalidInput,
        "The request, a driver result or an external artifact is malformed.",
    ),
    (
        WorkflowErrorCode::NonCanonicalEncoding,
        "Bytes are not the canonical encoding of their value.",
    ),
    (
        WorkflowErrorCode::UnsupportedOperation,
        "The capability, the node or the requested mode is not supported, including a driver that would upload private material.",
    ),
    (
        WorkflowErrorCode::BindingMismatch,
        "A value is bound to another network, authority, intent, payload or identity, including an external signature that does not verify.",
    ),
    (
        WorkflowErrorCode::ResourceLimitExceeded,
        "A declared bound was exceeded; the error carries the bound, the action index when one action crosses it, the actual value and the maximum.",
    ),
    (
        WorkflowErrorCode::ProofInvalid,
        "A generated proof failed local verification; nothing was built, signed or dispatched.",
    ),
    (
        WorkflowErrorCode::AuthorizationDenied,
        "The authority lacks a permission, or the signer refused or lacks the capability.",
    ),
    (
        WorkflowErrorCode::Expired,
        "The transaction expired by authoritative ledger state.",
    ),
    (
        WorkflowErrorCode::ReplayRejected,
        "The ledger rejected the transaction as a replay.",
    ),
    (
        WorkflowErrorCode::LocalResourceUnavailable,
        "A local resource (storage, prover, verifier, custody, transport before dispatch) or node backpressure prevented progress; nothing was admitted.",
    ),
    (
        WorkflowErrorCode::EvidenceUnavailable,
        "A required evidence read did not complete with a classified result. It establishes no proof failure, ledger outcome or local capacity; the identity is kept.",
    ),
    (
        WorkflowErrorCode::SubmissionOutcomeUnknown,
        "A dispatch may have been admitted and nothing authoritative is known; the error carries the transaction identity.",
    ),
    (
        WorkflowErrorCode::FinalityPending,
        "The transaction is known to the network and its outcome is not yet established; the error carries the transaction identity.",
    ),
    (
        WorkflowErrorCode::Rejected,
        "The transaction identity was refused on its only possible admission or rejected by the ledger.",
    ),
    (
        WorkflowErrorCode::CancelledBeforeSubmission,
        "The operation was cancelled before any dispatch could have been admitted.",
    ),
];

/// Journal extension codes a durable operation also reports. It never runs off-chain
/// rounds, so the workflow extension `RoundPending` does not apply.
pub const OPERATION_JOURNAL_CODES_V1: &[WorkflowErrorCode] = &[
    WorkflowErrorCode::StorageCorrupted,
    WorkflowErrorCode::JournalConflict,
];

/// One field of the typed error every SDK family returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorFieldV1 {
    /// Field name.
    pub name: &'static str,
    /// Logical type.
    pub ty: &'static str,
    /// Whether every error carries the field.
    pub always: bool,
    /// Codes whose errors always carry the field; for other codes it is present when the
    /// value exists.
    pub required_for: &'static [WorkflowErrorCode],
    /// What the field holds.
    pub meaning: &'static str,
}

/// Fields of the typed operation error, in order.
pub const OPERATION_ERROR_FIELDS_V1: &[ErrorFieldV1] = &[
    ErrorFieldV1 {
        name: "code",
        ty: "error code",
        always: true,
        required_for: &[],
        meaning: "One code of `error_codes` or `journal_error_codes`.",
    },
    ErrorFieldV1 {
        name: "stage",
        ty: "stage",
        always: true,
        required_for: &[],
        meaning: "The stage that produced the error.",
    },
    ErrorFieldV1 {
        name: "action_index",
        ty: "u32",
        always: false,
        required_for: &[],
        meaning: "Zero-based index of the composed action the error concerns, when one action is identifiable.",
    },
    ErrorFieldV1 {
        name: "bound",
        ty: "string",
        always: false,
        required_for: &[WorkflowErrorCode::ResourceLimitExceeded],
        meaning: "Identifier of the exceeded bound: an id of `batch_limits`, or the documented identifier of another declared bound.",
    },
    ErrorFieldV1 {
        name: "actual",
        ty: "u64",
        always: false,
        required_for: &[WorkflowErrorCode::ResourceLimitExceeded],
        meaning: "The value that exceeded the bound.",
    },
    ErrorFieldV1 {
        name: "maximum",
        ty: "u64",
        always: false,
        required_for: &[WorkflowErrorCode::ResourceLimitExceeded],
        meaning: "The largest permitted value.",
    },
    ErrorFieldV1 {
        name: "transaction",
        ty: "transaction identity",
        always: false,
        required_for: &[
            WorkflowErrorCode::SubmissionOutcomeUnknown,
            WorkflowErrorCode::FinalityPending,
        ],
        meaning: "Signed-transaction hash and entrypoint hash of the operation's identity, whenever one exists.",
    },
    ErrorFieldV1 {
        name: "detail",
        ty: "string",
        always: true,
        required_for: &[],
        meaning: "Diagnostic without secret material.",
    },
    ErrorFieldV1 {
        name: "progress",
        ty: "operation progress",
        always: false,
        required_for: &[],
        meaning: "Status and state of the last journal record the call validated; absent only when no trustworthy journal could be read.",
    },
];

/// One field of a provisional artifact or record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactFieldV1 {
    /// Field name.
    pub name: &'static str,
    /// Type: an existing data-model type, a record of this contract or a primitive.
    pub ty: &'static str,
    /// What the field holds.
    pub meaning: &'static str,
}

/// A provisional artifact or record of the prepared form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactV1 {
    /// Provisional type name.
    pub name: &'static str,
    /// The call that returns it, or `None` for a record nested in an artifact.
    pub returned_by: Option<OperationCallV1>,
    /// What it is.
    pub meaning: &'static str,
    /// Its fields, in order.
    pub fields: &'static [ArtifactFieldV1],
}

/// The prepared and built artifacts, in pipeline order.
pub const OPERATION_ARTIFACTS_V1: &[ArtifactV1] = &[
    ArtifactV1 {
        name: PREPARED_OPERATION_ARTIFACT_V1,
        returned_by: Some(OperationCallV1::Prepare),
        meaning: "The proof-free, unsigned form of one operation or of one batch composed into one transaction. Public: it holds no private material.",
        fields: &[
            ArtifactFieldV1 {
                name: "payload",
                ty: "TransactionPayload",
                meaning: "The unsigned payload with every proof-free field fixed: domain, authority, creation time, lifetime, a nonce from the secure random source, fee payment, metadata, the canonical instructions of every composed action in order, and the ordered intent descriptor with its declared attachment slots. Generated proof bytes, their lengths and hashes and the statement digests are absent.",
            },
            ArtifactFieldV1 {
                name: "intent_digest",
                ty: "OrderedIntentDigestV1",
                meaning: "`TransactionPayload::ordered_intent_digest_v1` of `payload`.",
            },
            ArtifactFieldV1 {
                name: "statements",
                ty: "Vec<ActionStatementDigestV1>",
                meaning: "The public statement digest of each declared action in action order (`TransactionPayload::action_statement_digests_v1`); the proof of action i binds entry i.",
            },
            ArtifactFieldV1 {
                name: "attachment_slots",
                ty: "Vec<AttachmentSlotV1>",
                meaning: "Every declared attachment occurrence in index order.",
            },
            ArtifactFieldV1 {
                name: "resource_quote",
                ty: "Vec<ResourceQuoteEntryV1>",
                meaning: "One entry per bound of `batch_limits`, in that order.",
            },
            ArtifactFieldV1 {
                name: "parameters",
                ty: "ParameterSnapshotV1",
                meaning: "The committed parameters the quote used.",
            },
        ],
    },
    ArtifactV1 {
        name: BUILT_OPERATION_ARTIFACT_V1,
        returned_by: Some(OperationCallV1::Build),
        meaning: "The complete, unsigned transaction an internal or external signer signs. Public: it holds no private material.",
        fields: &[
            ArtifactFieldV1 {
                name: "intent_digest",
                ty: "OrderedIntentDigestV1",
                meaning: "The ordered intent digest of the prepared artifact; building never changes it.",
            },
            ArtifactFieldV1 {
                name: "signing_bytes",
                ty: "Vec<u8>",
                meaning: "`TransactionBuilder::encode_payload`: the canonical complete payload, every attachment occurrence and statement digest bound, which an external signer receives.",
            },
            ArtifactFieldV1 {
                name: "signing_prehash",
                ty: "Hash",
                meaning: "`TransactionBuilder::payload_hash` of the same payload: the prehash every transaction signature signs.",
            },
            ArtifactFieldV1 {
                name: "entrypoint_hash",
                ty: "HashOf<TransactionEntrypoint>",
                meaning: "`TransactionBuilder::hash_as_entrypoint`: the transaction identity before any signature, equal to the signed transaction's entrypoint hash.",
            },
            ArtifactFieldV1 {
                name: "resource_usage",
                ty: "Vec<ResourceQuoteEntryV1>",
                meaning: "The exact measured value of every bound of `batch_limits` except the signed transaction size, which `sign` measures.",
            },
        ],
    },
];

/// Records nested in the artifacts.
pub const OPERATION_RECORDS_V1: &[ArtifactV1] = &[
    ArtifactV1 {
        name: "AttachmentSlotV1",
        returned_by: None,
        meaning: "One declared attachment occurrence of the prepared form.",
        fields: &[
            ArtifactFieldV1 {
                name: "index",
                ty: "u32",
                meaning: "Position of the occurrence in the transaction.",
            },
            ArtifactFieldV1 {
                name: "action_index",
                ty: "u32",
                meaning: "The declared action that references the occurrence.",
            },
            ArtifactFieldV1 {
                name: "kind",
                ty: "AttachmentKindV1",
                meaning: "A generated proof or admitted key material.",
            },
            ArtifactFieldV1 {
                name: "role",
                ty: "AttachmentRoleV1",
                meaning: "The role the occurrence plays for its action.",
            },
            ArtifactFieldV1 {
                name: "expected_length",
                ty: "u64",
                meaning: "The exact length of key material; for a generated proof its canonical padded length when the proof format fixes one, else the largest length the capability can generate.",
            },
        ],
    },
    ArtifactV1 {
        name: "ResourceQuoteEntryV1",
        returned_by: None,
        meaning: "The value of one composition bound.",
        fields: &[
            ArtifactFieldV1 {
                name: "bound",
                ty: "string",
                meaning: "An id of `batch_limits`.",
            },
            ArtifactFieldV1 {
                name: "value",
                ty: "u64",
                meaning: "In a quote: exact for counts, an upper bound for bytes. In a measurement: exact.",
            },
            ArtifactFieldV1 {
                name: "maximum",
                ty: "u64",
                meaning: "The bound's maximum: the constant, or the committed parameter of the snapshot.",
            },
        ],
    },
    ArtifactV1 {
        name: "ParameterSnapshotV1",
        returned_by: None,
        meaning: "The committed parameters a quote used.",
        fields: &[
            ArtifactFieldV1 {
                name: "block_height",
                ty: "u64",
                meaning: "Height of the committed block the parameters were read at.",
            },
            ArtifactFieldV1 {
                name: "max_tx_bytes",
                ty: "u64",
                meaning: "Committed `Parameters.transaction.max_tx_bytes`.",
            },
            ArtifactFieldV1 {
                name: "max_decompressed_bytes",
                ty: "u64",
                meaning: "Committed `Parameters.transaction.max_decompressed_bytes`.",
            },
            ArtifactFieldV1 {
                name: "max_includable_transaction_bytes",
                ty: "u64",
                meaning: "`Parameters::max_includable_transaction_bytes` for the transaction's inclusion route.",
            },
        ],
    },
];

/// One composition bound of a batch, checked in [`batch_limits`] order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimitV1 {
    /// Bound identifier, equal to its id in `specs/zk_resource_contract.json`.
    pub id: &'static str,
    /// The maximum: the constant, or the committed default of a committed parameter.
    pub maximum: u64,
    /// `count` or `bytes`.
    pub unit: &'static str,
    /// Whether the maximum is a committed chain parameter that the parameter snapshot reads.
    pub committed: bool,
    /// Source file of the owner.
    pub path: &'static str,
    /// Owning constant or default function.
    pub symbol: &'static str,
    /// Stages that check the bound: a prepare-time quote, then exact measurements.
    pub checked_at: &'static [WorkflowStage],
    /// What is measured.
    pub measures: &'static str,
}

const SIGNED_ATTACHMENTS_SOURCE: &str =
    "crates/iroha_data_model/src/transaction/signed_attachments.rs";
const PARAMETERS_SOURCE: &str = "crates/iroha_data_model/src/parameter/system.rs";

/// Every composition bound of one transaction, in checking order.
///
/// A request over any of them is refused at `prepare`; no call splits it into several
/// transactions.
#[must_use]
pub fn batch_limits() -> Vec<BatchLimitV1> {
    let committed = TransactionParameters::default();
    let count = |value: usize| value as u64;
    vec![
        BatchLimitV1 {
            id: "attachment.max_actions",
            maximum: count(SIGNED_ATTACHMENTS_MAX_ACTIONS_V1),
            unit: "count",
            committed: false,
            path: SIGNED_ATTACHMENTS_SOURCE,
            symbol: "SIGNED_ATTACHMENTS_MAX_ACTIONS_V1",
            checked_at: &[WorkflowStage::Plan],
            measures: "Declared attachment-backed actions of the composed transaction.",
        },
        BatchLimitV1 {
            id: "attachment.max_occurrences",
            maximum: count(SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1),
            unit: "count",
            committed: false,
            path: SIGNED_ATTACHMENTS_SOURCE,
            symbol: "SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1",
            checked_at: &[WorkflowStage::Plan],
            measures: "Declared attachment occurrences of the composed transaction.",
        },
        BatchLimitV1 {
            id: "attachment.occurrence_max_bytes",
            maximum: count(SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1),
            unit: "bytes",
            committed: false,
            path: SIGNED_ATTACHMENTS_SOURCE,
            symbol: "SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1",
            checked_at: &[WorkflowStage::Plan, WorkflowStage::Build],
            measures: "Length of one attachment occurrence: its expected length at prepare, its generated length at build.",
        },
        BatchLimitV1 {
            id: "attachment.signed_frame_max_bytes",
            maximum: count(SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1),
            unit: "bytes",
            committed: false,
            path: SIGNED_ATTACHMENTS_SOURCE,
            symbol: "SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1",
            checked_at: &[WorkflowStage::Plan, WorkflowStage::Build],
            measures: "Complete canonical Norito frame of the ordered intent descriptor and its occurrences: quoted from the expected lengths at prepare, exact at build.",
        },
        BatchLimitV1 {
            id: "transaction.max_decompressed_bytes",
            maximum: committed.max_decompressed_bytes.get(),
            unit: "bytes",
            committed: true,
            path: PARAMETERS_SOURCE,
            symbol: "max_decompressed_bytes",
            checked_at: &[WorkflowStage::Plan, WorkflowStage::Build],
            measures: "Sum of the attachment occurrence lengths.",
        },
        BatchLimitV1 {
            id: "transaction.max_tx_bytes",
            maximum: committed.max_tx_bytes.get(),
            unit: "bytes",
            committed: true,
            path: PARAMETERS_SOURCE,
            symbol: "max_tx_bytes",
            checked_at: &[WorkflowStage::Plan, WorkflowStage::Sign],
            measures: "Framed canonical signed transaction, checked by `Parameters::check_signed_transaction_bytes` against the includable maximum of its route: quoted with the authority's largest signature at prepare, exact after signing.",
        },
    ]
}

/// How a transaction identity's outcome is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FinalityModeV1 {
    /// Default: only an outcome authenticated by the finality verifier closes an identity.
    Authenticated,
    /// Explicit and weaker: the queried Torii's state-resolved status closes an identity.
    ToriiStatus,
}

impl FinalityModeV1 {
    /// Every mode, the default first.
    pub const ALL: &'static [Self] = &[Self::Authenticated, Self::ToriiStatus];

    /// Stable identifier used by the contract and the fixtures.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::ToriiStatus => "torii_status",
        }
    }

    /// Whether the one-call uses this mode unless the caller selects another.
    #[must_use]
    pub const fn is_default(self) -> bool {
        matches!(self, Self::Authenticated)
    }

    /// Whether this mode trusts the queried Torii for the outcome.
    #[must_use]
    pub const fn trusts_torii(self) -> bool {
        matches!(self, Self::ToriiStatus)
    }

    /// Whether a state-resolved `Expired` status closes an identity in this mode.
    ///
    /// No authenticated evidence of expiry exists, so in the authenticated mode such a
    /// status is a hint that changes nothing.
    #[must_use]
    pub const fn closes_on_expired_status(self) -> bool {
        matches!(self, Self::ToriiStatus)
    }

    /// Evidence that closes an identity in this mode.
    #[must_use]
    pub const fn closing_evidence(self) -> &'static str {
        match self {
            Self::Authenticated => {
                "A finality proof that `iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier`, rooted in the caller's independently selected genesis, verifies to bind the exact signed transaction and its applied or rejected execution output to a finalized block. A status read only selects the candidate outcome."
            }
            Self::ToriiStatus => {
                "The queried Torii's state-resolved global `Applied`, `Rejected` or `Expired` status of the exact identity. The caller trusts that Torii."
            }
        }
    }
}

/// Classes of one dispatch of signed bytes, as the client's single submission owner
/// establishes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DispatchClassV1 {
    /// Torii acknowledged admission.
    Accepted,
    /// A validated row proves the exact transaction is already queued or committed.
    AlreadyKnown,
    /// A validated row proves this dispatch did not admit the transaction.
    Refused,
    /// Validated backpressure: not admitted, and the same bytes may be sent again.
    Deferred,
    /// The dispatch failed before any byte left the client.
    NotDispatched,
    /// Nothing proves whether the dispatch was admitted.
    Ambiguous,
}

impl DispatchClassV1 {
    /// Every class.
    pub const ALL: &'static [Self] = &[
        Self::Accepted,
        Self::AlreadyKnown,
        Self::Refused,
        Self::Deferred,
        Self::NotDispatched,
        Self::Ambiguous,
    ];

    /// Stable identifier used by the contract and the fixtures.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AlreadyKnown => "already_known",
            Self::Refused => "refused",
            Self::Deferred => "deferred",
            Self::NotDispatched => "not_dispatched",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// The reducer event the class applies to the `submitting` identity.
    #[must_use]
    pub const fn event(self) -> TransactionEventV1 {
        match self {
            Self::Accepted => TransactionEventV1::DispatchAccepted,
            Self::AlreadyKnown => TransactionEventV1::DispatchAlreadyKnown,
            Self::Refused => TransactionEventV1::DispatchRefused,
            Self::Deferred | Self::NotDispatched => TransactionEventV1::DispatchNotAdmitted,
            Self::Ambiguous => TransactionEventV1::DispatchAmbiguous,
        }
    }

    /// The code a call reports when this class ends it while no earlier dispatch of the same
    /// bytes may have been admitted.
    ///
    /// A validated refusal then closes the identity (`Rejected`) and backpressure keeps it
    /// dispatchable (`LocalResourceUnavailable`). A failure before any byte left reports the
    /// code of its cause, and the other classes continue with reconciliation.
    #[must_use]
    pub const fn error_code(self) -> Option<WorkflowErrorCode> {
        match self {
            Self::Refused => Some(WorkflowErrorCode::Rejected),
            Self::Deferred => Some(WorkflowErrorCode::LocalResourceUnavailable),
            Self::Accepted | Self::AlreadyKnown | Self::NotDispatched | Self::Ambiguous => None,
        }
    }

    /// How the class is established.
    #[must_use]
    pub const fn established_by(self) -> &'static str {
        match self {
            Self::Accepted => "HTTP 200 or 202.",
            Self::AlreadyKnown | Self::Refused | Self::Deferred => {
                "A response validated against one row of `definite_rows` with this class."
            }
            Self::NotDispatched => {
                "A local failure before any byte left the client, reported by the code of its cause."
            }
            Self::Ambiguous => {
                "Everything else: transport failure, timeout, 5xx, an oversized or undecodable body, an unlisted code, any outcome-unknown claim."
            }
        }
    }

    /// The class of one validated row of the closed dispatch table.
    const fn of_definite(result: DefiniteDispatchResult) -> Self {
        match result {
            DefiniteDispatchResult::AlreadyKnown => Self::AlreadyKnown,
            DefiniteDispatchResult::Refused => Self::Refused,
            DefiniteDispatchResult::Deferred => Self::Deferred,
        }
    }
}

/// Private material that stays in the caller's custody.
pub const PRIVATE_MATERIAL_V1: &[&str] = &[
    "signing_key",
    "witness",
    "share",
    "decryption_key",
    "randomness",
];

/// Custody and randomness rules every SDK family keeps by default.
pub const CUSTODY_RULES_V1: &[(&str, &str)] = &[
    (
        "opaque_signer_handles",
        "The default signer is an opaque handle or a platform signer, so a private key never crosses the native boundary or enters managed memory. Raw-key entry points are explicit test or advanced APIs, named as such.",
    ),
    (
        "secure_randomness",
        "Transaction nonces and proof randomness come from the platform's cryptographically secure random source. Caller-supplied randomness is an explicit test or advanced option, named as such.",
    ),
    (
        "no_private_material_upload",
        "No call sends private material to Torii, a prover service or any other remote party, and no artifact, journal record, error or diagnostic contains it. A capability driver that needs to upload private material is refused with `UnsupportedOperation` before any network effect.",
    ),
    (
        "public_artifacts_only",
        "The prepared and built artifacts, the journal and the signed transaction hold only public data and opaque custody references.",
    ),
    (
        "zeroize_private_material",
        "Private material the SDK holds in memory is erased after use where the platform allows; a family whose managed types cannot be erased documents that limitation.",
    ),
];

/// Rules every SDK family implements; each is exercised by a scenario fixture.
pub const OPERATION_RULES_V1: &[(&str, &str)] = &[
    (
        "prepare_refuses_over_bound_batches",
        "A batch is one signed atomic transaction. `prepare` refuses a request over any bound of `batch_limits` with `ResourceLimitExceeded` carrying stage `plan`, the bound, the index of the first action that crosses it, the actual value and the maximum, before any proof, journal or external effect exists. No call splits a batch into several transactions, and no split helper exists.",
    ),
    (
        "local_verification_before_signing",
        "Every generated proof is verified locally before the payload is built and signed. A local failure is `ProofInvalid` at stage `local_verify`: the proof is discarded, nothing is built, signed or dispatched, and the operation returns to `prepared`. Local acceptance is diagnostic, never ledger authorization.",
    ),
    (
        "persist_before_dispatch",
        "The exact signed bytes and their identity are durable before the dispatch ordinal, and the dispatch ordinal is durable before any byte is sent. A resumed operation dispatches the persisted bytes; it never proves, builds or signs an identity again once it is signed.",
    ),
    (
        "reconcile_read_only_first",
        "An operation found in `submitting`, `outcome_unknown` or `pending` is first reconciled by a read-only query on its persisted identity. `recover` performs only such reads and never proves, builds, signs or dispatches.",
    ),
    (
        "no_clock_closes_an_identity",
        "A submission timeout is `SubmissionOutcomeUnknown` with the transaction identity, never a guessed outcome. Exact absence, a failed read, the local observation bound, a local clock and Torii-reported time never close an identity, and no fresh nonce is created automatically.",
    ),
    (
        "identical_bytes_only",
        "The only re-dispatch of an identity that may still commit is its exact persisted bytes, under the explicit retransmission policy and after a fresh exact-absence read.",
    ),
    (
        "cancellation_never_recalls",
        "Cancellation before any dispatch could have been admitted ends the operation `cancelled_before_submission` and drops its payload or signed bytes. After a possible admission it only stops observation: the operation is `cancelling`, only read-only reconciliation runs and the actual outcome is reported.",
    ),
    (
        "external_signature_verified_before_persisting",
        "An external signature is assembled with the exact built signing bytes and verified against the authority before it is persisted. A mismatch is `BindingMismatch` at stage `sign`: nothing is persisted or dispatched and the built payload stays `ready_to_sign`.",
    ),
    (
        "custody_stays_local",
        "Private material stays in the caller's custody behind opaque handles. No call accepts it into an artifact or the journal or sends it to a remote party; a capability driver that needs to upload it is refused with `UnsupportedOperation` at the stage that asked, before any network effect.",
    ),
    (
        "authenticated_finality_by_default",
        "In the default `authenticated` mode only an outcome the finality verifier authenticates closes an identity, and a status read selects the candidate only. The `torii_status` mode is explicit and weaker: the queried Torii's state-resolved global outcome closes the identity.",
    ),
    (
        "dispatch_classified_by_closed_table",
        "A dispatch is classified from its HTTP status, canonical error envelope and reject-code header by `dispatch_classification`, never from text. A validated refusal closes an identity only when no earlier dispatch of the same bytes may have been admitted; backpressure and failures before any byte left keep the signed identity dispatchable.",
    ),
];

/// Rules of identity closure shared by every finality mode.
pub const IDENTITY_CLOSURE_RULES_V1: &[(&str, &str)] = &[
    (
        "no_clock_closes_an_identity",
        "No clock closes an identity: neither the local observation bound, nor a local clock, nor Torii-reported time. Expiry is never inferred from any clock.",
    ),
    (
        "absence_is_not_an_outcome",
        "Exact absence, a failed read and a response not bound to the identity change nothing.",
    ),
    (
        "identical_bytes_only",
        "Retransmission sends the exact persisted bytes only under an explicit idempotent policy, after a fresh exact-absence read, within the dispatch bound of the identity.",
    ),
    (
        "no_automatic_replacement",
        "A new transaction identity is opened only after the previous one is closed and only when the caller explicitly asks; no fresh nonce is created automatically.",
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

fn stage_ids(stages: &[WorkflowStage]) -> Value {
    Value::Array(stages.iter().map(|stage| text(stage.id())).collect())
}

fn code_ids(codes: &[WorkflowErrorCode]) -> Value {
    Value::Array(codes.iter().map(|code| text(code.id())).collect())
}

fn statements(rules: &[(&str, &str)]) -> Value {
    Value::Array(
        rules
            .iter()
            .map(|(id, statement)| object(vec![("id", text(id)), ("statement", text(statement))]))
            .collect(),
    )
}

fn artifacts(list: &[ArtifactV1]) -> Value {
    Value::Array(
        list.iter()
            .map(|artifact| {
                let fields = artifact
                    .fields
                    .iter()
                    .map(|field| {
                        object(vec![
                            ("name", text(field.name)),
                            ("type", text(field.ty)),
                            ("meaning", text(field.meaning)),
                        ])
                    })
                    .collect();
                object(vec![
                    ("name", text(artifact.name)),
                    (
                        "returned_by",
                        artifact
                            .returned_by
                            .map_or(Value::Null, |call| text(call.id())),
                    ),
                    ("meaning", text(artifact.meaning)),
                    ("fields", Value::Array(fields)),
                ])
            })
            .collect(),
    )
}

fn dispatch_classification() -> Value {
    let classes = DispatchClassV1::ALL
        .iter()
        .map(|class| {
            object(vec![
                ("id", text(class.id())),
                ("event", text(class.event().id())),
                (
                    "error_code",
                    class
                        .error_code()
                        .map_or(Value::Null, |code| text(code.id())),
                ),
                ("established_by", text(class.established_by())),
            ])
        })
        .collect();
    let rows = DEFINITE_DISPATCH_ROWS
        .iter()
        .map(|row| {
            object(vec![
                ("status", Value::from(u64::from(row.status))),
                ("envelope_code", text(row.envelope_code)),
                ("reject_code", text(row.reject_code)),
                (
                    "details_repeat_reject_code",
                    Value::Bool(row.details_repeat_reject_code),
                ),
                ("class", text(DispatchClassV1::of_definite(row.result).id())),
            ])
        })
        .collect();
    let status = |code: StatusCode| Value::from(u64::from(code.as_u16()));
    object(vec![
        (
            "owner",
            text(
                "crates/iroha/src/client.rs: AccountClient::dispatch_prepared_transaction_payload",
            ),
        ),
        (
            "acknowledged_statuses",
            Value::Array(vec![status(StatusCode::OK), status(StatusCode::ACCEPTED)]),
        ),
        (
            "max_response_bytes",
            Value::from(TRANSACTION_SUBMISSION_RESPONSE_MAX_BYTES as u64),
        ),
        (
            "validated",
            text(
                "Exactly one canonical error envelope (Norito or JSON, byte-identical to its re-encoding), exactly one `x-iroha-reject-code` header, the envelope details repeat the reject code exactly when the row says so, and status, envelope code and reject code equal one row. A response that claims an unknown outcome is never a row.",
            ),
        ),
        (
            "outcome_unknown_evidence",
            object(vec![
                ("status", status(StatusCode::SERVICE_UNAVAILABLE)),
                (
                    "envelope_code",
                    text(TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_ENVELOPE_CODE),
                ),
                (
                    "reject_code",
                    text(TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE),
                ),
                (
                    "identity_headers",
                    Value::Array(vec![
                        text(TRANSACTION_ENTRYPOINT_HASH_HEADER),
                        text(SIGNED_TRANSACTION_HASH_HEADER),
                    ]),
                ),
                ("class", text(DispatchClassV1::Ambiguous.id())),
            ]),
        ),
        ("classes", Value::Array(classes)),
        ("definite_rows", Value::Array(rows)),
        ("identity_closure", statements(IDENTITY_CLOSURE_RULES_V1)),
    ])
}

/// Render the tables of this module as the machine-readable operation contract.
#[must_use]
pub fn operation_contract_json() -> Value {
    let calls = OperationCallV1::ALL
        .iter()
        .map(|call| {
            object(vec![
                ("id", text(call.id())),
                ("stages", stage_ids(call.stages())),
                (
                    "events",
                    Value::Array(call.events().iter().map(|event| text(event.id())).collect()),
                ),
            ])
        })
        .collect();
    let handle = OPERATION_HANDLE_CALLS_V1
        .iter()
        .map(|(id, stages)| object(vec![("id", text(id)), ("stages", stage_ids(stages))]))
        .collect();
    let states = TransactionStateV1::ALL
        .iter()
        .filter(|state| is_operation_state(**state))
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
    let error_codes = OPERATION_ERROR_MEANINGS_V1
        .iter()
        .map(|(code, meaning)| object(vec![("id", text(code.id())), ("meaning", text(meaning))]))
        .collect();
    let error_fields = OPERATION_ERROR_FIELDS_V1
        .iter()
        .map(|field| {
            object(vec![
                ("name", text(field.name)),
                ("type", text(field.ty)),
                ("always", Value::Bool(field.always)),
                ("required_for", code_ids(field.required_for)),
                ("meaning", text(field.meaning)),
            ])
        })
        .collect();
    let limits = batch_limits()
        .iter()
        .map(|limit| {
            object(vec![
                ("id", text(limit.id)),
                ("maximum", Value::from(limit.maximum)),
                ("unit", text(limit.unit)),
                ("committed", Value::Bool(limit.committed)),
                ("path", text(limit.path)),
                ("symbol", text(limit.symbol)),
                ("checked_at", stage_ids(limit.checked_at)),
                ("measures", text(limit.measures)),
            ])
        })
        .collect();
    let modes = FinalityModeV1::ALL
        .iter()
        .map(|mode| {
            object(vec![
                ("id", text(mode.id())),
                ("default", Value::Bool(mode.is_default())),
                ("trusts_torii", Value::Bool(mode.trusts_torii())),
                (
                    "closes_on_expired_status",
                    Value::Bool(mode.closes_on_expired_status()),
                ),
                ("closing_evidence", text(mode.closing_evidence())),
            ])
        })
        .collect();
    object(vec![
        ("schema", text(OPERATION_CONTRACT_SCHEMA_V1)),
        (
            "review",
            object(vec![
                ("state", text(OPERATION_CONTRACT_REVIEW_V1)),
                ("decisions", text(OPERATION_CONTRACT_DECISIONS_V1)),
            ]),
        ),
        ("specification", text("specs/zk_operation_contract.md")),
        (
            "one_call",
            object(vec![
                ("id", text(ONE_CALL_V1)),
                (
                    "runs",
                    Value::Array(
                        OperationCallV1::ALL
                            .iter()
                            .map(|call| text(call.id()))
                            .collect(),
                    ),
                ),
                ("durable", Value::Bool(true)),
                ("returns", text("a durable handle")),
            ]),
        ),
        ("calls", Value::Array(calls)),
        ("handle_calls", Value::Array(handle)),
        ("journal_stages", stage_ids(OPERATION_JOURNAL_STAGES_V1)),
        (
            "reducer",
            object(vec![
                ("table", text(OPERATION_REDUCER_V1)),
                ("initial_state", text(TransactionStateV1::Planned.id())),
                (
                    "cancel_events",
                    Value::Array(
                        OPERATION_CANCEL_EVENTS_V1
                            .iter()
                            .map(|event| text(event.id()))
                            .collect(),
                    ),
                ),
            ]),
        ),
        ("durable_states", Value::Array(states)),
        ("error_codes", Value::Array(error_codes)),
        ("journal_error_codes", code_ids(OPERATION_JOURNAL_CODES_V1)),
        ("error_fields", Value::Array(error_fields)),
        ("artifacts", artifacts(OPERATION_ARTIFACTS_V1)),
        ("records", artifacts(OPERATION_RECORDS_V1)),
        (
            "batch",
            object(vec![
                ("atomicity", text("one_signed_transaction")),
                ("split", text("never")),
                (
                    "over_bound",
                    text(WorkflowErrorCode::ResourceLimitExceeded.id()),
                ),
                ("over_bound_stage", text(WorkflowStage::Plan.id())),
            ]),
        ),
        ("batch_limits", Value::Array(limits)),
        (
            "local_verification",
            object(vec![
                ("policy", text("verify_before_build_and_sign")),
                ("failure_code", text(WorkflowErrorCode::ProofInvalid.id())),
                ("failure_stage", text(WorkflowStage::LocalVerify.id())),
                ("failure_dispatches", Value::Bool(false)),
                (
                    "failure_returns_to",
                    text(TransactionStateV1::Prepared.id()),
                ),
                ("authority", text("diagnostic_only")),
            ]),
        ),
        (
            "custody",
            object(vec![
                (
                    "private_material",
                    Value::Array(PRIVATE_MATERIAL_V1.iter().copied().map(text).collect()),
                ),
                ("rules", statements(CUSTODY_RULES_V1)),
                (
                    "upload_refusal_code",
                    text(WorkflowErrorCode::UnsupportedOperation.id()),
                ),
            ]),
        ),
        ("finality_modes", Value::Array(modes)),
        ("dispatch_classification", dispatch_classification()),
        ("rules", statements(OPERATION_RULES_V1)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::contract::{TRANSACTION_TRANSITIONS_V1, state_machine_json};

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/zk/operation_v1")
            .join(name)
    }

    fn pretty(value: &Value) -> String {
        let mut rendered = norito::json::to_string_pretty(value).expect("JSON");
        rendered.push('\n');
        rendered
    }

    #[test]
    fn tracked_contract_equals_the_rust_tables() {
        let tracked = std::fs::read_to_string(fixture_path("contract.json")).expect("tracked");
        assert_eq!(
            tracked,
            pretty(&operation_contract_json()),
            "fixtures/zk/operation_v1/contract.json differs from client/operation_contract.rs; \
             regenerate with `cargo test -p iroha --lib client::operation_contract -- --ignored`"
        );
    }

    #[test]
    #[ignore = "writes fixtures/zk/operation_v1/contract.json"]
    fn regenerate_operation_contract() {
        std::fs::write(
            fixture_path("contract.json"),
            pretty(&operation_contract_json()),
        )
        .expect("write");
    }

    #[test]
    fn calls_follow_the_pipeline_and_report_shared_stages() {
        assert_eq!(
            OperationCallV1::ALL
                .iter()
                .map(|call| call.id())
                .collect::<Vec<_>>(),
            [
                "prepare",
                "prove",
                "local_verify",
                "build",
                "sign",
                "submit",
                "await_finality"
            ]
        );
        for call in OperationCallV1::ALL {
            assert_eq!(OperationCallV1::from_id(call.id()), Some(*call));
            assert!(!call.stages().is_empty());
            assert!(!call.stages().contains(&WorkflowStage::Round));
            for stage in OPERATION_JOURNAL_STAGES_V1 {
                assert!(!call.stages().contains(stage), "{call:?} repeats {stage}");
            }
        }
        assert_eq!(OperationCallV1::from_id("execute"), None);
        // The calls report the pipeline stages in order: every stage but the journal, round
        // and cancel stages belongs to exactly one call.
        let reported = OperationCallV1::ALL
            .iter()
            .flat_map(|call| call.stages().iter().copied())
            .collect::<Vec<_>>();
        let expected = WorkflowStage::ALL
            .iter()
            .copied()
            .filter(|stage| {
                !OPERATION_JOURNAL_STAGES_V1.contains(stage)
                    && !matches!(stage, WorkflowStage::Round | WorkflowStage::Cancel)
            })
            .collect::<Vec<_>>();
        assert_eq!(reported, expected);
        for (id, stages) in OPERATION_HANDLE_CALLS_V1 {
            assert!(!id.is_empty());
            assert!(!stages.contains(&WorkflowStage::Round));
        }
    }

    #[test]
    fn call_events_are_rows_of_the_shared_reducer() {
        let mut applied = Vec::new();
        for call in OperationCallV1::ALL {
            for event in call.events() {
                assert!(
                    TRANSACTION_TRANSITIONS_V1
                        .iter()
                        .any(|row| row.event == *event),
                    "{event} has no row"
                );
                applied.push(*event);
            }
        }
        applied.extend_from_slice(OPERATION_CANCEL_EVENTS_V1);
        for event in TransactionEventV1::ALL {
            assert!(applied.contains(event), "no call applies {event}");
        }
        // Prepare opens the identity; the advanced stages before signing can only return the
        // slot to `prepared`; nothing before `submit` sends anything.
        assert_eq!(
            OperationCallV1::Prepare.events(),
            &[TransactionEventV1::OpenAttempt]
        );
        for call in [
            OperationCallV1::Prove,
            OperationCallV1::LocalVerify,
            OperationCallV1::Build,
            OperationCallV1::Sign,
        ] {
            assert!(
                !call
                    .events()
                    .iter()
                    .any(|event| event.id().starts_with("dispatch"))
            );
        }
    }

    #[test]
    fn durable_states_are_the_reducer_states_after_prepare() {
        let states = TransactionStateV1::ALL
            .iter()
            .filter(|state| is_operation_state(**state))
            .map(|state| state.id())
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            [
                "prepared",
                "proving",
                "ready_to_sign",
                "signed",
                "submitting",
                "outcome_unknown",
                "pending",
                "finalized",
                "rejected",
                "cancelled_before_submission",
            ]
        );
        assert!(!is_operation_state(TransactionStateV1::Planned));
    }

    #[test]
    fn error_codes_are_the_fifteen_shared_codes_in_contract_order() {
        let shared = WorkflowErrorCode::ALL
            .iter()
            .copied()
            .filter(|code| code.is_shared_operation_code())
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 15);
        assert_eq!(
            OPERATION_ERROR_MEANINGS_V1
                .iter()
                .map(|(code, _)| *code)
                .collect::<Vec<_>>(),
            shared
        );
        assert!(
            OPERATION_ERROR_MEANINGS_V1
                .iter()
                .all(|(_, meaning)| !meaning.is_empty())
        );
        for code in OPERATION_JOURNAL_CODES_V1 {
            assert!(!code.is_shared_operation_code());
            assert_ne!(*code, WorkflowErrorCode::RoundPending);
        }
    }

    #[test]
    fn bound_errors_carry_stage_action_actual_and_maximum() {
        let field = |name: &str| {
            OPERATION_ERROR_FIELDS_V1
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("no field {name}"))
        };
        assert!(field("code").always && field("stage").always && field("detail").always);
        for name in ["bound", "actual", "maximum"] {
            assert_eq!(
                field(name).required_for,
                &[WorkflowErrorCode::ResourceLimitExceeded]
            );
        }
        assert!(!field("action_index").always);
        for code in [
            WorkflowErrorCode::SubmissionOutcomeUnknown,
            WorkflowErrorCode::FinalityPending,
        ] {
            assert!(field("transaction").required_for.contains(&code));
        }
        for (index, field) in OPERATION_ERROR_FIELDS_V1.iter().enumerate() {
            assert!(
                OPERATION_ERROR_FIELDS_V1[..index]
                    .iter()
                    .all(|other| other.name != field.name)
            );
        }
    }

    #[test]
    fn batch_limits_are_the_data_model_bounds_and_committed_defaults() {
        let limits = batch_limits();
        let maximum = |id: &str| {
            limits
                .iter()
                .find(|limit| limit.id == id)
                .unwrap_or_else(|| panic!("no bound {id}"))
                .maximum
        };
        assert_eq!(maximum("attachment.max_actions"), 16);
        assert_eq!(maximum("attachment.max_occurrences"), 16);
        assert_eq!(maximum("attachment.occurrence_max_bytes"), 9_437_184);
        assert_eq!(maximum("attachment.signed_frame_max_bytes"), 9_502_720);
        assert_eq!(maximum("transaction.max_decompressed_bytes"), 10_485_760);
        assert_eq!(maximum("transaction.max_tx_bytes"), 10_485_760);
        // The frame bound is one ceiling-sized occurrence plus a 64 KiB allowance.
        assert_eq!(
            maximum("attachment.signed_frame_max_bytes"),
            maximum("attachment.occurrence_max_bytes") + 64 * 1024
        );
        let committed = TransactionParameters::default();
        assert_eq!(
            maximum("transaction.max_tx_bytes"),
            committed.max_tx_bytes.get()
        );
        for limit in &limits {
            assert!(
                limit.checked_at.contains(&WorkflowStage::Plan),
                "{}",
                limit.id
            );
            assert!(matches!(limit.unit, "count" | "bytes"));
            assert_eq!(limit.committed, limit.path == PARAMETERS_SOURCE);
        }
    }

    #[test]
    fn exactly_one_default_finality_mode_and_it_is_authenticated() {
        let defaults = FinalityModeV1::ALL
            .iter()
            .filter(|mode| mode.is_default())
            .collect::<Vec<_>>();
        assert_eq!(defaults, [&FinalityModeV1::Authenticated]);
        assert!(!FinalityModeV1::Authenticated.trusts_torii());
        assert!(!FinalityModeV1::Authenticated.closes_on_expired_status());
        assert!(FinalityModeV1::ToriiStatus.trusts_torii());
        assert!(FinalityModeV1::ToriiStatus.closes_on_expired_status());
        assert!(
            FinalityModeV1::Authenticated
                .closing_evidence()
                .contains("SumeragiFinalityVerifier")
        );
    }

    #[test]
    fn dispatch_rows_are_the_closed_table_of_the_submission_owner() {
        let rendered = operation_contract_json();
        let classification = rendered
            .as_object()
            .and_then(|root| root.get("dispatch_classification"))
            .and_then(Value::as_object)
            .expect("dispatch classification");
        let rows = classification
            .get("definite_rows")
            .and_then(Value::as_array)
            .expect("rows");
        assert_eq!(rows.len(), DEFINITE_DISPATCH_ROWS.len());
        for (row, rendered) in DEFINITE_DISPATCH_ROWS.iter().zip(rows) {
            let rendered = rendered.as_object().expect("row");
            assert_eq!(
                rendered.get("status").and_then(Value::as_u64),
                Some(u64::from(row.status))
            );
            assert_eq!(
                rendered.get("reject_code").and_then(Value::as_str),
                Some(row.reject_code)
            );
            assert_eq!(
                rendered.get("class").and_then(Value::as_str),
                Some(DispatchClassV1::of_definite(row.result).id())
            );
        }
        // Only a refusal closes an identity, and only the not-admitted classes report a code of
        // their own; every class names an event of the reducer, and the outcome-unknown
        // evidence is ambiguous, never a row.
        assert_eq!(
            DispatchClassV1::ALL
                .iter()
                .filter_map(|class| class.error_code().map(|code| (class.id(), code.id())))
                .collect::<Vec<_>>(),
            [
                ("refused", "Rejected"),
                ("deferred", "LocalResourceUnavailable")
            ]
        );
        for class in DispatchClassV1::ALL {
            assert!(TRANSACTION_TRANSITIONS_V1.iter().any(
                |row| row.event == class.event() && row.from == TransactionStateV1::Submitting
            ));
        }
        assert!(
            DEFINITE_DISPATCH_ROWS
                .iter()
                .all(|row| row.reject_code != TRANSACTION_DISPATCH_OUTCOME_UNKNOWN_REJECT_CODE)
        );
    }

    #[test]
    fn rules_and_vocabularies_are_unique_and_stated() {
        for rules in [
            OPERATION_RULES_V1,
            CUSTODY_RULES_V1,
            IDENTITY_CLOSURE_RULES_V1,
        ] {
            for (index, (id, statement)) in rules.iter().enumerate() {
                assert!(!statement.is_empty());
                assert!(rules[..index].iter().all(|(other, _)| other != id));
            }
        }
        for (index, kind) in PRIVATE_MATERIAL_V1.iter().enumerate() {
            assert!(
                PRIVATE_MATERIAL_V1[..index]
                    .iter()
                    .all(|other| other != kind)
            );
        }
        for list in [OPERATION_ARTIFACTS_V1, OPERATION_RECORDS_V1] {
            for artifact in list {
                assert!(!artifact.fields.is_empty());
                for (index, field) in artifact.fields.iter().enumerate() {
                    assert!(
                        artifact.fields[..index]
                            .iter()
                            .all(|other| other.name != field.name)
                    );
                    assert!(!field.meaning.is_empty() && !field.ty.is_empty());
                }
            }
        }
        assert_eq!(
            OPERATION_ARTIFACTS_V1
                .iter()
                .map(|artifact| (artifact.name, artifact.returned_by))
                .collect::<Vec<_>>(),
            [
                ("PreparedZkOperationV1", Some(OperationCallV1::Prepare)),
                ("BuiltZkOperationV1", Some(OperationCallV1::Build)),
            ]
        );
    }

    #[test]
    fn rendered_contract_uses_only_the_shared_vocabularies() {
        let machine = state_machine_json();
        let machine = machine.as_object().expect("state machine");
        let vocabulary = |key: &str| {
            machine
                .get(key)
                .and_then(Value::as_array)
                .expect("vocabulary")
                .iter()
                .map(|entry| entry.as_str().expect("identifier").to_owned())
                .collect::<Vec<_>>()
        };
        let stages = vocabulary("stages");
        let events = vocabulary("transaction_events");
        let rendered = operation_contract_json();
        let root = rendered.as_object().expect("contract");
        let list = |call: &Value, key: &str| {
            call.as_object()
                .and_then(|call| call.get(key))
                .and_then(Value::as_array)
                .expect("list")
                .iter()
                .map(|entry| entry.as_str().expect("identifier").to_owned())
                .collect::<Vec<_>>()
        };
        for call in root.get("calls").and_then(Value::as_array).expect("calls") {
            for stage in list(call, "stages") {
                assert!(stages.contains(&stage), "unknown stage {stage}");
            }
            for event in list(call, "events") {
                assert!(events.contains(&event), "unknown event {event}");
            }
        }
        assert_eq!(
            root.get("schema").and_then(Value::as_str),
            Some(OPERATION_CONTRACT_SCHEMA_V1)
        );
        assert_eq!(
            root.get("rules").and_then(Value::as_array).map(Vec::len),
            Some(OPERATION_RULES_V1.len())
        );
    }
}
