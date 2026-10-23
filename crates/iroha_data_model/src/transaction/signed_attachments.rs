//! Ordered proof-free intent descriptors and signed inline attachment occurrences.
//!
//! A signed transaction carries large proofs and admitted key material as
//! **inline attachment occurrences** inside its signed payload, next to an
//! **ordered descriptor** of the actions that use them
//! ([`SignedAttachmentsV1`], the ninth [`TransactionPayload`] field).
//!
//! Two bindings are deliberately separate:
//!
//! - the transaction signature covers the complete canonical payload, every
//!   occurrence byte included, so no proof enters through a hash-only
//!   reference;
//! - a proof binds only the *normalized ordered intent*: the same payload with
//!   every generated value removed (occurrence bytes, the length and hash of
//!   every generated proof, and each action's derived statement digest). The
//!   proof therefore never hashes itself.
//!
//! The hashing order is fixed:
//!
//! 1. declare the ordered actions and their attachment slots;
//! 2. compute the ordered intent digest of the normalized payload
//!    ([`TransactionPayload::ordered_intent_digest_v1`]);
//! 3. derive each action's statement digest from that digest, the action
//!    ordinal, operation, role, authority, invocation binding and public-input
//!    digest ([`ActionIntentV1::statement_digest_for_v1`]) and generate the
//!    proof for it;
//! 4. record the occurrence bytes with their exact lengths and hashes;
//! 5. sign the complete canonical payload.
//!
//! Descriptor checks reject a stale or foreign binding before any proof is
//! verified. Cryptographic replay rejection additionally requires verifying
//! the proof against the recomputed statement; the transaction-level proof
//! carrier ([`ActionOperationV1::TransactionProof`]) keeps the limited
//! semantics of attachment preverification and does not establish that
//! binding.
//!
//! [`TransactionPayload`]: crate::transaction::TransactionPayload
//! [`TransactionPayload::ordered_intent_digest_v1`]: crate::transaction::TransactionPayload::ordered_intent_digest_v1

use crate::{account::AccountId, proof::ProofAttachment};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use iroha_schema::IntoSchema;
use norito::core::DecodeFromSlice as _;
use norito::{
    codec::{Decode, Encode},
    core as ncore,
};
use thiserror::Error;

/// Largest byte length of one signed attachment occurrence.
///
/// This is the zk-X509 proof ceiling, so a ceiling-sized native proof travels
/// as one occurrence of raw proof bytes. For a wrapped carrier the wrapper
/// counts toward this length.
pub const SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1: usize = 9 * 1024 * 1024;
/// Largest number of attachment occurrences in one signed transaction.
pub const SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1: usize = 16;
/// Largest number of declared attachment-backed actions in one signed transaction.
///
/// This bounds the descriptor only; it does not replace the ordinary
/// instruction limit of the executable.
pub const SIGNED_ATTACHMENTS_MAX_ACTIONS_V1: usize = 16;
/// Largest complete canonical Norito frame of [`SignedAttachmentsV1`].
///
/// One ceiling-sized occurrence plus a 64 KiB aggregate allowance for the
/// descriptor and all Norito framing. The allowance is not a guarantee that
/// every maximal metadata combination fits. Sixteen maximal occurrences are
/// impossible: the cardinality and the aggregate byte bound are independent.
/// The complete signed transaction is still measured against the committed
/// transaction byte limit.
pub const SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1: usize =
    SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 + 64 * 1024;
/// Largest number of child-invocation ordinals in a contract invocation binding.
///
/// Equal to the nested contract-call depth the IVM host admits.
pub const ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1: usize = 32;
/// Largest byte length of an instruction wire identifier named by an action.
pub const ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1: usize = 128;

/// An untrusted selector of one slot of one signed attachment-backed action.
///
/// This is the canonical request layout, never an authorization or host handle.
/// The runtime must bind it to the original signed owner and actual invocation,
/// check the operation/role/inputs, and consume the selected occurrence once.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::ActionAttachmentRefV1")]
pub struct ActionAttachmentRefV1 {
    /// Exact zero-based ordinal in the signed action list.
    pub action_index: u32,
    /// Exact zero-based slot in that action's reference list.
    pub slot_index: u32,
}

/// Domain separator of the public-input digest of a wrapped proof carrier.
pub const PROOF_CARRIER_PUBLIC_INPUTS_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.transaction.proof-carrier-public-inputs-digest.v1";
/// Domain separator of the statement digest of one ordered action.
pub const ACTION_STATEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"iroha.transaction.action-statement-digest.v1";

macro_rules! define_attachment_digest {
    ($(#[$meta:meta])* $name:ident, $schema_name:literal) => {
        $(#[$meta])*
        #[derive(norito::NoritoSchema)]
        #[norito_schema(name = $schema_name)]
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Decode,
            Encode,
            IntoSchema,
        )]
        #[repr(transparent)]
        #[norito(decode_from_slice)]
        #[derive(crate::DeriveJsonSerialize, crate::DeriveJsonDeserialize)]
        pub struct $name(
            /// The exact 32-byte digest value.
            #[norito(json = "crate::json_helpers::fixed_bytes")]
            pub [u8; 32],
        );
        impl $name {
            /// The all-zero value used in the normalized intent projection.
            pub const ZERO: Self = Self([0; 32]);
            /// Construct a digest from exactly 32 bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Borrow the exact digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// Consume the digest and return its exact bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
            /// Return `true` when every digest byte is zero.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }
    };
}

define_attachment_digest!(
    /// BLAKE3 hash of the exact bytes of one attachment occurrence.
    AttachmentContentHashV1,
    "iroha_data_model::transaction::signed_attachments::AttachmentContentHashV1"
);
define_attachment_digest!(
    /// Digest of the proof-free public inputs (normalized arguments) of one action.
    ActionPublicInputsDigestV1,
    "iroha_data_model::transaction::signed_attachments::ActionPublicInputsDigestV1"
);
define_attachment_digest!(
    /// Digest of the statement one action's proof binds.
    ActionStatementDigestV1,
    "iroha_data_model::transaction::signed_attachments::ActionStatementDigestV1"
);
define_attachment_digest!(
    /// Digest of the normalized proof-free ordered intent of one transaction.
    OrderedIntentDigestV1,
    "iroha_data_model::transaction::signed_attachments::OrderedIntentDigestV1"
);

impl AttachmentContentHashV1 {
    /// Hash the exact bytes of an attachment occurrence.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

/// Type of the bytes one attachment occurrence carries.
///
/// The canonical variant tags are `0` (`Proof`) and `1` (`KeyMaterial`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::AttachmentKindV1")]
pub enum AttachmentKindV1 {
    /// A generated proof. Its bytes, length and hash are produced after the
    /// ordered intent digest exists and are excluded from the normalized intent.
    Proof,
    /// Independently supplied key material admitted with the transaction. Its
    /// length and hash are part of the normalized intent.
    KeyMaterial,
}

impl AttachmentKindV1 {
    /// Whether the occurrence is generated from the ordered intent digest.
    #[must_use]
    pub const fn is_generated(self) -> bool {
        matches!(self, Self::Proof)
    }
}

/// Role one attachment plays for the action that references it.
///
/// The canonical variant tags follow the declaration order, starting at `0`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::AttachmentRoleV1")]
pub enum AttachmentRoleV1 {
    /// The proof of the action's statement.
    ActionProof,
    /// Verifying key material the action admits.
    VerifyingKey,
    /// A wrapped proof that also carries a lane privacy witness.
    LanePrivacyProof,
    /// The execution proof of a proved IVM executable.
    ExecutionProof,
}

impl AttachmentRoleV1 {
    /// Whether an occurrence of `kind` may play this role.
    #[must_use]
    pub const fn admits_kind(self, kind: AttachmentKindV1) -> bool {
        matches!(
            (self, kind),
            (
                Self::ActionProof | Self::LanePrivacyProof | Self::ExecutionProof,
                AttachmentKindV1::Proof
            ) | (Self::VerifyingKey, AttachmentKindV1::KeyMaterial)
        )
    }
}

/// Operation tag of one declared action.
///
/// The canonical variant tags follow the declaration order, starting at `0`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::ActionOperationV1")]
pub enum ActionOperationV1 {
    /// A native instruction, named by its registered canonical wire identifier.
    ///
    /// Registration alone does not establish support: admission additionally
    /// applies the role, authority, attachment-format and statement-binding
    /// rules of the operation.
    NativeInstruction(String),
    /// A transaction-level proof carrier: one wrapped [`ProofAttachment`]
    /// preverified at admission, optionally with a lane privacy witness.
    TransactionProof,
    /// The execution proof carrier of the transaction's proved IVM executable.
    IvmProvedExecution,
}

/// Role class of one declared action.
///
/// The canonical variant tags follow the declaration order, starting at `0`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::ActionRoleV1")]
pub enum ActionRoleV1 {
    /// Verifies a proof and applies the effect it authorizes.
    ProofEffect,
    /// Verifies a proof for its typed statement and applies no effect.
    ProofVerification,
    /// An administrative operation subject to its ordinary permissions.
    Administrative,
    /// A plain state effect without a proof.
    Effect,
}

/// Authority one declared action executes under.
///
/// The canonical variant tags follow the declaration order, starting at `0`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(
    name = "iroha_data_model::transaction::signed_attachments::ActionAuthorityBindingV1"
)]
pub enum ActionAuthorityBindingV1 {
    /// The transaction signer.
    TransactionAuthority,
    /// The effective subject account of the contract that issues the action.
    ContractSubject(AccountId),
    /// A protocol-specific authorized actor.
    Account(AccountId),
}

/// Invocation one declared action belongs to.
///
/// The canonical variant tags follow the declaration order, starting at `0`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(
    name = "iroha_data_model::transaction::signed_attachments::ActionInvocationBindingV1"
)]
pub enum ActionInvocationBindingV1 {
    /// The transaction itself. Only transaction-level carriers use this binding.
    Transaction,
    /// The direct instruction at this position of an instruction list or batch.
    Direct {
        /// Zero-based position of the instruction in the executable.
        instruction_index: u32,
    },
    /// A contract invocation.
    Contract {
        /// Batch position of the root contract call, or zero for a standalone
        /// contract or IVM executable.
        root_index: u32,
        /// Zero-based child-invocation ordinals from the root; empty for the root.
        call_path: Vec<u32>,
    },
}

/// Completed reference from an action to one attachment occurrence.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito(decode_from_slice)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::AttachmentReferenceV1")]
pub struct AttachmentReferenceV1 {
    /// Position of the occurrence in the transaction.
    pub index: u32,
    /// Declared type of the occurrence.
    pub kind: AttachmentKindV1,
    /// Role the occurrence plays for this action.
    pub role: AttachmentRoleV1,
    /// Exact byte length of the occurrence.
    pub length: u64,
    /// BLAKE3 hash of the occurrence bytes.
    pub content_hash: AttachmentContentHashV1,
}

/// One ordered action of the signed intent descriptor.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(reuse_archived)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::ActionIntentV1")]
pub struct ActionIntentV1 {
    /// Committed ordinal; equal to the action's position.
    pub action_index: u32,
    /// Operation tag.
    pub operation: ActionOperationV1,
    /// Role class of the action.
    pub role: ActionRoleV1,
    /// Authority the action executes under.
    pub authority: ActionAuthorityBindingV1,
    /// Invocation the action belongs to.
    pub invocation: ActionInvocationBindingV1,
    /// Digest of the action's proof-free public inputs.
    pub public_inputs_digest: ActionPublicInputsDigestV1,
    /// Digest of the statement the action's proof binds. Derived from the
    /// ordered intent digest; zero in the normalized intent projection.
    pub statement_digest: ActionStatementDigestV1,
    /// Attachment references in slot order.
    pub attachments: Vec<AttachmentReferenceV1>,
}

/// One signed inline attachment occurrence.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(reuse_archived)]
#[norito_schema(
    name = "iroha_data_model::transaction::signed_attachments::SignedAttachmentOccurrenceV1"
)]
pub struct SignedAttachmentOccurrenceV1 {
    /// Position of this occurrence in the transaction.
    pub index: u32,
    /// Type of the bytes.
    pub kind: AttachmentKindV1,
    /// Exact byte length of `bytes`.
    pub length: u64,
    /// BLAKE3 hash of `bytes`.
    pub content_hash: AttachmentContentHashV1,
    /// The attachment bytes.
    pub bytes: Vec<u8>,
}

/// Ordered intent descriptor and signed inline attachment occurrences of one transaction.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito(reuse_archived)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::SignedAttachmentsV1")]
pub struct SignedAttachmentsV1 {
    /// Declared actions in execution order.
    actions: Vec<ActionIntentV1>,
    /// Attachment occurrences in reference order.
    occurrences: Vec<SignedAttachmentOccurrenceV1>,
}

/// Closed operation rule one action violates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Error)]
pub enum ActionRuleViolationV1 {
    /// The operation does not admit the declared role class.
    #[error("the operation does not admit the declared role")]
    Role,
    /// The operation does not admit the declared authority binding.
    #[error("the operation does not admit the declared authority binding")]
    Authority,
    /// The operation does not admit the declared invocation binding.
    #[error("the operation does not admit the declared invocation binding")]
    Invocation,
    /// The operation requires a different number of attachments.
    #[error("the operation requires a different number of attachments")]
    AttachmentCount,
    /// The operation does not admit the role of one of its attachments.
    #[error("the operation does not admit the role of one of its attachments")]
    AttachmentRole,
}

/// A signed-attachment schema violation or its original local codec refusal.
///
/// Decoding, the validated constructors and transaction admission report the
/// same typed value. A local refusal leaves validation unfinished and is not a
/// semantic verdict about the signed source.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignedAttachmentErrorV1 {
    /// The actual codec operation could not complete under its enclosing local resources.
    /// This retains the original observer and must not become a semantic rejection.
    #[error(transparent)]
    LocalResource(ncore::DecodeLocalRefusal),
    /// The attachment field is present without any declared action.
    #[error("signed attachments declare no action")]
    NoActions,
    /// More actions are declared than the first-release maximum.
    #[error("signed attachments declare {actual} actions, more than the maximum of {maximum}")]
    TooManyActions {
        /// Declared action count.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// More occurrences are carried than the first-release maximum.
    #[error("signed attachments carry {actual} occurrences, more than the maximum of {maximum}")]
    TooManyOccurrences {
        /// Carried occurrence count.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// The complete canonical frame exceeds its first-release maximum.
    #[error("signed attachment frame is {actual} bytes, more than the maximum of {maximum} bytes")]
    FrameTooLarge {
        /// Complete canonical frame size.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// Canonical encoding of the attachment frame, an action statement or the
    /// normalized intent failed.
    #[error("canonical encoding of the signed attachment data failed")]
    CanonicalEncodingFailed,
    /// An action's committed ordinal differs from its position (reorder).
    #[error("action at position {position} declares ordinal {action_index}")]
    ActionOutOfOrder {
        /// Position in the descriptor.
        position: usize,
        /// Declared ordinal.
        action_index: u32,
    },
    /// An occurrence's index differs from its position (reorder).
    #[error("attachment occurrence at position {position} declares index {index}")]
    OccurrenceOutOfOrder {
        /// Position in the transaction.
        position: usize,
        /// Declared index.
        index: u32,
    },
    /// An occurrence carries no bytes.
    #[error("attachment occurrence {index} is empty")]
    EmptyOccurrence {
        /// Occurrence index.
        index: u32,
    },
    /// An occurrence exceeds the per-occurrence byte maximum.
    #[error(
        "attachment occurrence {index} is {actual} bytes, more than the maximum of {maximum} bytes"
    )]
    OccurrenceTooLarge {
        /// Occurrence index.
        index: u32,
        /// Actual byte length.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// An occurrence declares a length other than that of its bytes.
    #[error("attachment occurrence {index} declares {declared} bytes but carries {actual}")]
    OccurrenceLengthMismatch {
        /// Occurrence index.
        index: u32,
        /// Declared length.
        declared: u64,
        /// Actual byte length.
        actual: usize,
    },
    /// An occurrence declares a hash other than that of its bytes.
    #[error("attachment occurrence {index} declares a hash other than that of its bytes")]
    OccurrenceHashMismatch {
        /// Occurrence index.
        index: u32,
    },
    /// Two proof occurrences carry identical bytes (a proof replayed inside one transaction).
    #[error("attachment occurrences {first} and {second} carry the same proof bytes")]
    DuplicateProofContent {
        /// Index of the first occurrence.
        first: u32,
        /// Index of the repeated occurrence.
        second: u32,
    },
    /// An action names an instruction wire identifier that is empty, too long or not ASCII.
    #[error("action {action_index} names a malformed instruction wire identifier")]
    MalformedOperation {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action's contract invocation path is deeper than the maximum.
    #[error(
        "action {action_index} declares an invocation path of {actual} calls, more than the maximum of {maximum}"
    )]
    CallPathTooDeep {
        /// Action ordinal.
        action_index: u32,
        /// Declared path length.
        actual: usize,
        /// First-release maximum.
        maximum: usize,
    },
    /// An action declares more references than the transaction can carry occurrences.
    #[error(
        "action {action_index} declares {actual} attachment references, more than the maximum of {maximum}"
    )]
    TooManyReferences {
        /// Action ordinal.
        action_index: u32,
        /// Declared reference count.
        actual: usize,
        /// First-release occurrence maximum.
        maximum: usize,
    },
    /// An action's public-input digest is zero.
    #[error("action {action_index} declares a zero public-input digest")]
    ZeroPublicInputsDigest {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action's statement digest is zero.
    #[error("action {action_index} declares a zero statement digest")]
    ZeroStatementDigest {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action references an occurrence the transaction does not carry (omission).
    #[error("action {action_index} references missing attachment occurrence {index}")]
    MissingOccurrence {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
    },
    /// An occurrence is referenced more than once (duplicate declaration).
    #[error(
        "attachment occurrence {index} is referenced more than once (again by action {action_index})"
    )]
    DuplicateReference {
        /// Action ordinal of the repeated reference.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
    },
    /// References do not enumerate the occurrences in order (reorder).
    #[error(
        "action {action_index} references attachment occurrence {index} where {expected} is next"
    )]
    ReferenceOutOfOrder {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
        /// Occurrence index the canonical order requires.
        expected: u32,
    },
    /// A reference declares a type other than that of its occurrence.
    #[error("action {action_index} declares another type for attachment occurrence {index}")]
    ReferenceKindMismatch {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
    },
    /// A reference declares a role its occurrence's type cannot play.
    #[error("action {action_index} declares a role attachment occurrence {index} cannot play")]
    ReferenceRoleMismatch {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
    },
    /// A reference declares a length other than that of its occurrence (substitution).
    #[error(
        "action {action_index} declares {declared} bytes for attachment occurrence {index}, which carries {actual}"
    )]
    ReferenceLengthMismatch {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
        /// Length the reference declares.
        declared: u64,
        /// Length the occurrence declares.
        actual: u64,
    },
    /// A reference declares a hash other than that of its occurrence (substitution).
    #[error("action {action_index} declares another hash for attachment occurrence {index}")]
    ReferenceHashMismatch {
        /// Action ordinal.
        action_index: u32,
        /// Referenced occurrence index.
        index: u32,
    },
    /// No action references an occurrence (unused declaration).
    #[error("attachment occurrence {index} is not referenced by any action")]
    UnreferencedOccurrence {
        /// Occurrence index.
        index: u32,
    },
    /// An action violates the closed rules of its operation.
    #[error("action {action_index}: {rule}")]
    OperationRule {
        /// Action ordinal.
        action_index: u32,
        /// Violated rule.
        rule: ActionRuleViolationV1,
    },
    /// An action names an instruction wire identifier that is not registered.
    #[error("action {action_index} names an unregistered instruction wire identifier")]
    UnregisteredOperation {
        /// Action ordinal.
        action_index: u32,
    },
    /// No executor route consumes the attachments of this operation.
    #[error(
        "action {action_index}: attachment-backed execution of this operation is not supported"
    )]
    UnsupportedOperation {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action's invocation binding names nothing in the executable.
    #[error("action {action_index} binds an invocation the executable does not contain")]
    InvocationOutOfRange {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action's invocation binding names an executable item of another kind or operation.
    #[error("action {action_index} binds an invocation of another kind or operation")]
    InvocationTargetMismatch {
        /// Action ordinal.
        action_index: u32,
    },
    /// Two actions bind the same direct instruction.
    #[error("action {action_index} binds a direct instruction another action already binds")]
    DuplicateInvocation {
        /// Action ordinal of the repeated binding.
        action_index: u32,
    },
    /// An execution proof carrier is declared for an executable that is not a
    /// proved IVM executable, or more than once.
    #[error("action {action_index} declares an execution proof the executable does not admit")]
    ExecutionCarrierNotAdmitted {
        /// Action ordinal.
        action_index: u32,
    },
    /// A wrapped proof carrier is not one canonical proof attachment.
    #[error("attachment occurrence {index} is not a canonical proof attachment: {reason}")]
    MalformedProofCarrier {
        /// Occurrence index.
        index: u32,
        /// Decoder or structural reason.
        reason: String,
    },
    /// A wrapped proof carrier's role disagrees with its lane privacy witness.
    #[error(
        "attachment occurrence {index} declares a role that disagrees with its lane privacy witness"
    )]
    ProofCarrierRoleMismatch {
        /// Occurrence index.
        index: u32,
    },
    /// An action's public-input digest differs from the digest of its actual
    /// proof-free arguments.
    #[error(
        "action {action_index} declares a public-input digest other than that of its arguments"
    )]
    PublicInputsMismatch {
        /// Action ordinal.
        action_index: u32,
    },
    /// An action's statement digest differs from the one derived from the
    /// transaction's ordered intent: the binding is stale or belongs to another
    /// transaction, network, authority, nonce or order.
    #[error("action {action_index} declares a statement digest of another ordered intent")]
    StatementBindingMismatch {
        /// Action ordinal.
        action_index: u32,
        /// Digest derived from this transaction.
        expected: ActionStatementDigestV1,
        /// Digest the action declares.
        actual: ActionStatementDigestV1,
    },
}

impl SignedAttachmentErrorV1 {
    /// Consume an original local refusal without reconstructing its scope identity.
    ///
    /// # Errors
    /// Returns the unchanged semantic error when this is not a local refusal.
    pub fn into_local_refusal(self) -> Result<ncore::DecodeLocalRefusal, Self> {
        match self {
            Self::LocalResource(original) => Ok(original),
            error => Err(error),
        }
    }

    /// Return the canonical decoder error while preserving an original local cause.
    #[must_use]
    pub fn into_norito_error(self) -> ncore::Error {
        match self {
            Self::LocalResource(original) => original.into_error(),
            error => ncore::Error::Message(error.to_string()),
        }
    }

    pub(super) fn from_encoding_attempt(original: ncore::DecodeAttemptError) -> Self {
        original
            .into_local_refusal()
            .map_or_else(|_| Self::CanonicalEncodingFailed, Self::LocalResource)
    }
}

/// Convert a position to the `u32` ordinal the wire carries.
///
/// Positions are bounded by the first-release count maxima, so the conversion
/// saturates only for values validation rejects anyway.
fn ordinal(position: usize) -> u32 {
    u32::try_from(position).unwrap_or(u32::MAX)
}

impl ActionOperationV1 {
    /// The instruction wire identifier of a native instruction operation.
    #[must_use]
    pub fn instruction_wire_id(&self) -> Option<&str> {
        match self {
            Self::NativeInstruction(wire_id) => Some(wire_id),
            Self::TransactionProof | Self::IvmProvedExecution => None,
        }
    }

    /// Whether the operation is a transaction-level wrapped proof carrier.
    #[must_use]
    pub const fn is_proof_carrier(&self) -> bool {
        matches!(self, Self::TransactionProof | Self::IvmProvedExecution)
    }

    fn is_well_formed(&self) -> bool {
        match self {
            Self::NativeInstruction(wire_id) => {
                !wire_id.is_empty()
                    && wire_id.len() <= ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1
                    && wire_id.bytes().all(|byte| byte.is_ascii_graphic())
            }
            Self::TransactionProof | Self::IvmProvedExecution => true,
        }
    }
}

impl ActionInvocationBindingV1 {
    fn call_path_len(&self) -> usize {
        match self {
            Self::Contract { call_path, .. } => call_path.len(),
            Self::Transaction | Self::Direct { .. } => 0,
        }
    }
}

/// Canonical statement one action's proof binds.
///
/// The statement digest is the domain-separated BLAKE3 hash of this record's
/// canonical Norito frame.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::transaction::signed_attachments::ActionStatementV1")]
pub struct ActionStatementV1 {
    /// Digest of the normalized ordered intent of the transaction.
    pub intent_digest: OrderedIntentDigestV1,
    /// Committed ordinal of the action.
    pub action_index: u32,
    /// Operation tag.
    pub operation: ActionOperationV1,
    /// Role class of the action.
    pub role: ActionRoleV1,
    /// Authority the action executes under.
    pub authority: ActionAuthorityBindingV1,
    /// Invocation the action belongs to.
    pub invocation: ActionInvocationBindingV1,
    /// Digest of the action's proof-free public inputs.
    pub public_inputs_digest: ActionPublicInputsDigestV1,
}

impl ActionStatementV1 {
    /// Digest of this statement.
    ///
    /// `BLAKE3(domain || u64le(len) || frame)` over the canonical Norito frame.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn digest(&self) -> Result<ActionStatementDigestV1, SignedAttachmentErrorV1> {
        let encoded = ncore::classify_decode_attempt(|| norito::encode_canonical(self))
            .map_err(SignedAttachmentErrorV1::from_encoding_attempt)?;
        Ok(ActionStatementDigestV1(domain_separated_digest(
            ACTION_STATEMENT_DIGEST_DOMAIN_V1,
            &encoded,
        )?))
    }
}

/// `BLAKE3(domain || u64le(len) || bytes)`.
pub(crate) fn domain_separated_digest(
    domain: &[u8],
    bytes: &[u8],
) -> Result<[u8; 32], SignedAttachmentErrorV1> {
    let length =
        u64::try_from(bytes.len()).map_err(|_| SignedAttachmentErrorV1::CanonicalEncodingFailed)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(*hasher.finalize().as_bytes())
}

impl ActionIntentV1 {
    /// Statement the action's proof binds under the given ordered intent digest.
    #[must_use]
    pub fn statement_for_v1(&self, intent_digest: OrderedIntentDigestV1) -> ActionStatementV1 {
        ActionStatementV1 {
            intent_digest,
            action_index: self.action_index,
            operation: self.operation.clone(),
            role: self.role,
            authority: self.authority.clone(),
            invocation: self.invocation.clone(),
            public_inputs_digest: self.public_inputs_digest,
        }
    }

    /// Statement digest the action's proof binds under the given ordered intent digest.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding of the statement fails.
    pub fn statement_digest_for_v1(
        &self,
        intent_digest: OrderedIntentDigestV1,
    ) -> Result<ActionStatementDigestV1, SignedAttachmentErrorV1> {
        self.statement_for_v1(intent_digest).digest()
    }

    /// The closed operation rule this action violates, if any.
    ///
    /// The rules do not depend on the rest of the transaction.
    #[must_use]
    pub fn rule_violation(&self) -> Option<ActionRuleViolationV1> {
        match &self.operation {
            ActionOperationV1::TransactionProof => self.carrier_rule_violation(
                ActionRoleV1::ProofVerification,
                &[
                    AttachmentRoleV1::ActionProof,
                    AttachmentRoleV1::LanePrivacyProof,
                ],
            ),
            ActionOperationV1::IvmProvedExecution => self.carrier_rule_violation(
                ActionRoleV1::ProofEffect,
                &[AttachmentRoleV1::ExecutionProof],
            ),
            ActionOperationV1::NativeInstruction(_) => {
                let authority_admitted = match (&self.invocation, &self.authority) {
                    (ActionInvocationBindingV1::Transaction, _) => {
                        return Some(ActionRuleViolationV1::Invocation);
                    }
                    (
                        ActionInvocationBindingV1::Direct { .. },
                        ActionAuthorityBindingV1::TransactionAuthority
                        | ActionAuthorityBindingV1::Account(_),
                    )
                    | (
                        ActionInvocationBindingV1::Contract { .. },
                        ActionAuthorityBindingV1::ContractSubject(_)
                        | ActionAuthorityBindingV1::Account(_),
                    ) => true,
                    _ => false,
                };
                if !authority_admitted {
                    return Some(ActionRuleViolationV1::Authority);
                }
                self.attachments
                    .iter()
                    .any(|reference| {
                        !matches!(
                            reference.role,
                            AttachmentRoleV1::ActionProof | AttachmentRoleV1::VerifyingKey
                        )
                    })
                    .then_some(ActionRuleViolationV1::AttachmentRole)
            }
        }
    }

    fn carrier_rule_violation(
        &self,
        role: ActionRoleV1,
        attachment_roles: &[AttachmentRoleV1],
    ) -> Option<ActionRuleViolationV1> {
        if self.role != role {
            return Some(ActionRuleViolationV1::Role);
        }
        if self.authority != ActionAuthorityBindingV1::TransactionAuthority {
            return Some(ActionRuleViolationV1::Authority);
        }
        if self.invocation != ActionInvocationBindingV1::Transaction {
            return Some(ActionRuleViolationV1::Invocation);
        }
        let [reference] = self.attachments.as_slice() else {
            return Some(ActionRuleViolationV1::AttachmentCount);
        };
        (!attachment_roles.contains(&reference.role))
            .then_some(ActionRuleViolationV1::AttachmentRole)
    }
}

impl SignedAttachmentOccurrenceV1 {
    /// Build the occurrence at `index` from its bytes, recording their exact
    /// length and hash.
    #[must_use]
    pub fn new(index: u32, kind: AttachmentKindV1, bytes: Vec<u8>) -> Self {
        Self {
            index,
            kind,
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            content_hash: AttachmentContentHashV1::of(&bytes),
            bytes,
        }
    }

    /// The completed reference an action in the given role records for this occurrence.
    #[must_use]
    pub const fn reference(&self, role: AttachmentRoleV1) -> AttachmentReferenceV1 {
        AttachmentReferenceV1 {
            index: self.index,
            kind: self.kind,
            role,
            length: self.length,
            content_hash: self.content_hash,
        }
    }
}

/// Public-input digest of a wrapped proof carrier.
///
/// The digest covers the proof attachment with its proof bytes cleared and
/// its envelope hash removed, so the backend, the verifying-key identity and
/// commitment and the lane privacy witness are intent-bound while the
/// generated proof is not.
///
/// # Errors
///
/// Returns an error when canonical encoding fails.
pub fn proof_carrier_public_inputs_digest_v1(
    attachment: &ProofAttachment,
) -> Result<ActionPublicInputsDigestV1, SignedAttachmentErrorV1> {
    let mut proof_free = attachment.clone();
    proof_free.proof.bytes.clear();
    proof_free.envelope_hash = None;
    let encoded = ncore::classify_decode_attempt(|| norito::encode_canonical(&proof_free))
        .map_err(SignedAttachmentErrorV1::from_encoding_attempt)?;
    Ok(ActionPublicInputsDigestV1(domain_separated_digest(
        PROOF_CARRIER_PUBLIC_INPUTS_DIGEST_DOMAIN_V1,
        &encoded,
    )?))
}

/// One attachment slot of a planned action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAttachmentV1 {
    /// Type of the bytes.
    pub kind: AttachmentKindV1,
    /// Role the attachment plays for its action.
    pub role: AttachmentRoleV1,
    /// The attachment bytes. A generated proof may stay empty until the
    /// statement digest it binds is known.
    pub bytes: Vec<u8>,
}

/// One action of an attachment plan, before ordinals, lengths and hashes are assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedActionV1 {
    /// Operation tag.
    pub operation: ActionOperationV1,
    /// Role class of the action.
    pub role: ActionRoleV1,
    /// Authority the action executes under.
    pub authority: ActionAuthorityBindingV1,
    /// Invocation the action belongs to.
    pub invocation: ActionInvocationBindingV1,
    /// Digest of the action's proof-free public inputs.
    pub public_inputs_digest: ActionPublicInputsDigestV1,
    /// Attachment slots in order.
    pub attachments: Vec<PlannedAttachmentV1>,
}

impl PlannedActionV1 {
    /// Plan the transaction-level carrier of one proof attachment.
    ///
    /// The attachment role is [`AttachmentRoleV1::LanePrivacyProof`] exactly
    /// when the attachment carries a lane privacy witness.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is structurally invalid or cannot
    /// be encoded canonically.
    pub fn transaction_proof(
        attachment: &ProofAttachment,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let role = if attachment.lane_privacy.is_some() {
            AttachmentRoleV1::LanePrivacyProof
        } else {
            AttachmentRoleV1::ActionProof
        };
        Self::proof_carrier(
            ActionOperationV1::TransactionProof,
            ActionRoleV1::ProofVerification,
            role,
            attachment,
        )
    }

    /// Plan the execution proof carrier of a proved IVM executable.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is structurally invalid, carries a
    /// lane privacy witness or cannot be encoded canonically.
    pub fn ivm_proved_execution(
        attachment: &ProofAttachment,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        if attachment.lane_privacy.is_some() {
            return Err(SignedAttachmentErrorV1::ProofCarrierRoleMismatch { index: 0 });
        }
        Self::proof_carrier(
            ActionOperationV1::IvmProvedExecution,
            ActionRoleV1::ProofEffect,
            AttachmentRoleV1::ExecutionProof,
            attachment,
        )
    }

    /// Plan the transaction-level carrier of one proof attachment without
    /// checking the attachment's structure.
    ///
    /// Decoding and admission refuse a malformed carrier; this constructor
    /// exists for exercising those rejections.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment cannot be encoded canonically.
    pub fn transaction_proof_unvalidated(
        attachment: &ProofAttachment,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let role = if attachment.lane_privacy.is_some() {
            AttachmentRoleV1::LanePrivacyProof
        } else {
            AttachmentRoleV1::ActionProof
        };
        Self::wrap_proof_carrier(
            ActionOperationV1::TransactionProof,
            ActionRoleV1::ProofVerification,
            role,
            attachment,
        )
    }

    fn proof_carrier(
        operation: ActionOperationV1,
        role: ActionRoleV1,
        attachment_role: AttachmentRoleV1,
        attachment: &ProofAttachment,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        if let Some((field, message)) = attachment.structural_error() {
            return Err(SignedAttachmentErrorV1::MalformedProofCarrier {
                index: 0,
                reason: format!("{field} {message}"),
            });
        }
        Self::wrap_proof_carrier(operation, role, attachment_role, attachment)
    }

    fn wrap_proof_carrier(
        operation: ActionOperationV1,
        role: ActionRoleV1,
        attachment_role: AttachmentRoleV1,
        attachment: &ProofAttachment,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let bytes = ncore::classify_decode_attempt(|| norito::encode_canonical(attachment))
            .map_err(SignedAttachmentErrorV1::from_encoding_attempt)?;
        Ok(Self {
            operation,
            role,
            authority: ActionAuthorityBindingV1::TransactionAuthority,
            invocation: ActionInvocationBindingV1::Transaction,
            public_inputs_digest: proof_carrier_public_inputs_digest_v1(attachment)?,
            attachments: vec![PlannedAttachmentV1 {
                kind: AttachmentKindV1::Proof,
                role: attachment_role,
                bytes,
            }],
        })
    }
}

/// Ordered plan of attachment-backed actions.
///
/// A plan assigns nothing derived. [`Self::declare`] assigns ordinals, lengths
/// and hashes; the statement digests are bound to a concrete transaction by
/// [`TransactionPayload::bind_attachment_statements_v1`].
///
/// [`TransactionPayload::bind_attachment_statements_v1`]: crate::transaction::TransactionPayload::bind_attachment_statements_v1
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedAttachmentPlanV1 {
    actions: Vec<PlannedActionV1>,
}

impl SignedAttachmentPlanV1 {
    /// An empty plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Plan one transaction-level proof carrier per attachment, in order.
    ///
    /// # Errors
    ///
    /// Returns an error when an attachment is structurally invalid or cannot
    /// be encoded canonically.
    pub fn transaction_proofs(
        attachments: &[ProofAttachment],
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let mut plan = Self::new();
        for attachment in attachments {
            plan.push_action(PlannedActionV1::transaction_proof(attachment)?);
        }
        Ok(plan)
    }

    /// Append one action. Its ordinal is its position.
    pub fn push_action(&mut self, action: PlannedActionV1) -> &mut Self {
        self.actions.push(action);
        self
    }

    /// Borrow the planned actions in order.
    #[must_use]
    pub fn actions(&self) -> &[PlannedActionV1] {
        &self.actions
    }

    /// Assign ordinals, occurrence indices, lengths and hashes.
    ///
    /// The result is not validated and its statement digests are zero: a
    /// generated proof slot may still be empty. It is what the ordered intent
    /// digest is computed over before the proofs exist.
    #[must_use]
    pub fn declare(self) -> SignedAttachmentsV1 {
        let mut actions = Vec::with_capacity(self.actions.len());
        let mut occurrences = Vec::new();
        for (position, action) in self.actions.into_iter().enumerate() {
            let mut references = Vec::with_capacity(action.attachments.len());
            for slot in action.attachments {
                let occurrence = SignedAttachmentOccurrenceV1::new(
                    ordinal(occurrences.len()),
                    slot.kind,
                    slot.bytes,
                );
                references.push(occurrence.reference(slot.role));
                occurrences.push(occurrence);
            }
            actions.push(ActionIntentV1 {
                action_index: ordinal(position),
                operation: action.operation,
                role: action.role,
                authority: action.authority,
                invocation: action.invocation,
                public_inputs_digest: action.public_inputs_digest,
                statement_digest: ActionStatementDigestV1::ZERO,
                attachments: references,
            });
        }
        SignedAttachmentsV1 {
            actions,
            occurrences,
        }
    }
}

impl SignedAttachmentsV1 {
    /// Build a validated value from its ordered parts.
    ///
    /// # Errors
    ///
    /// Returns the first schema violation, in the order [`Self::validate_v1`] checks.
    pub fn try_from_parts(
        actions: Vec<ActionIntentV1>,
        occurrences: Vec<SignedAttachmentOccurrenceV1>,
    ) -> Result<Self, SignedAttachmentErrorV1> {
        let value = Self {
            actions,
            occurrences,
        };
        value.validate_v1()?;
        Ok(value)
    }

    /// Build a value from its ordered parts without validating it.
    ///
    /// Decoding and transaction admission validate every value; this
    /// constructor exists for staged construction before proofs are generated
    /// and for exercising those rejections.
    #[must_use]
    pub const fn from_parts_unvalidated(
        actions: Vec<ActionIntentV1>,
        occurrences: Vec<SignedAttachmentOccurrenceV1>,
    ) -> Self {
        Self {
            actions,
            occurrences,
        }
    }

    /// Borrow the declared actions in execution order.
    #[must_use]
    pub fn actions(&self) -> &[ActionIntentV1] {
        &self.actions
    }

    /// Borrow the attachment occurrences in reference order.
    #[must_use]
    pub fn occurrences(&self) -> &[SignedAttachmentOccurrenceV1] {
        &self.occurrences
    }

    /// Borrow the action with the given committed ordinal.
    #[must_use]
    pub fn action(&self, action_index: u32) -> Option<&ActionIntentV1> {
        self.actions
            .get(usize::try_from(action_index).ok()?)
            .filter(|action| action.action_index == action_index)
    }

    /// Borrow the occurrence with the given index.
    #[must_use]
    pub fn occurrence(&self, index: u32) -> Option<&SignedAttachmentOccurrenceV1> {
        self.occurrences
            .get(usize::try_from(index).ok()?)
            .filter(|occurrence| occurrence.index == index)
    }

    /// Consume the value and return its ordered parts.
    #[must_use]
    pub fn into_parts(self) -> (Vec<ActionIntentV1>, Vec<SignedAttachmentOccurrenceV1>) {
        (self.actions, self.occurrences)
    }

    /// Sum of the byte lengths of all occurrences.
    #[must_use]
    pub fn total_occurrence_bytes(&self) -> usize {
        self.occurrences.iter().fold(0_usize, |total, occurrence| {
            total.saturating_add(occurrence.bytes.len())
        })
    }

    /// Record the bytes of one occurrence and update its length and hash in
    /// the occurrence and in the reference that names it.
    ///
    /// # Errors
    ///
    /// Returns [`SignedAttachmentErrorV1::MissingOccurrence`] when no occurrence
    /// has that index.
    pub fn set_occurrence_bytes(
        &mut self,
        index: u32,
        bytes: Vec<u8>,
    ) -> Result<(), SignedAttachmentErrorV1> {
        let missing = SignedAttachmentErrorV1::MissingOccurrence {
            action_index: 0,
            index,
        };
        let position = usize::try_from(index).map_err(|_| missing.clone())?;
        let occurrence = self.occurrences.get_mut(position).ok_or(missing)?;
        *occurrence = SignedAttachmentOccurrenceV1::new(index, occurrence.kind, bytes);
        let (length, content_hash) = (occurrence.length, occurrence.content_hash);
        for reference in self
            .actions
            .iter_mut()
            .flat_map(|action| action.attachments.iter_mut())
            .filter(|reference| reference.index == index)
        {
            reference.length = length;
            reference.content_hash = content_hash;
        }
        Ok(())
    }

    /// The normalized proof-free projection of this value.
    ///
    /// Every occurrence loses its bytes; every generated proof also loses its
    /// length and hash, in the occurrence and in its reference; every action
    /// loses its derived statement digest. Key material keeps its length and
    /// hash. Ordinals, types, roles, operations, authority and invocation
    /// bindings and public-input digests are unchanged.
    ///
    /// The occurrence bytes are never copied: the projection is built from the
    /// occurrence headers alone, so computing an intent digest needs no
    /// scratch proportional to the attachment bytes.
    #[must_use]
    pub fn normalized_for_intent_v1(&self) -> Self {
        let occurrences = self
            .occurrences
            .iter()
            .map(|occurrence| {
                let generated = occurrence.kind.is_generated();
                SignedAttachmentOccurrenceV1 {
                    index: occurrence.index,
                    kind: occurrence.kind,
                    length: if generated { 0 } else { occurrence.length },
                    content_hash: if generated {
                        AttachmentContentHashV1::ZERO
                    } else {
                        occurrence.content_hash
                    },
                    bytes: Vec::new(),
                }
            })
            .collect();
        let mut actions = self.actions.clone();
        for action in &mut actions {
            action.statement_digest = ActionStatementDigestV1::ZERO;
            for reference in &mut action.attachments {
                if reference.kind.is_generated() {
                    reference.length = 0;
                    reference.content_hash = AttachmentContentHashV1::ZERO;
                }
            }
        }
        Self {
            actions,
            occurrences,
        }
    }

    /// Set every action's statement digest from the given ordered intent digest.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding of a statement fails.
    pub fn bind_statements_v1(
        &mut self,
        intent_digest: OrderedIntentDigestV1,
    ) -> Result<(), SignedAttachmentErrorV1> {
        for action in &mut self.actions {
            action.statement_digest = action.statement_digest_for_v1(intent_digest)?;
        }
        Ok(())
    }

    /// Compare every action's statement digest with the one derived from the
    /// given ordered intent digest.
    ///
    /// # Errors
    ///
    /// Returns [`SignedAttachmentErrorV1::StatementBindingMismatch`] for the
    /// first action whose binding is stale or foreign.
    pub fn validate_statement_bindings_v1(
        &self,
        intent_digest: OrderedIntentDigestV1,
    ) -> Result<(), SignedAttachmentErrorV1> {
        for action in &self.actions {
            let expected = action.statement_digest_for_v1(intent_digest)?;
            if action.statement_digest != expected {
                return Err(SignedAttachmentErrorV1::StatementBindingMismatch {
                    action_index: action.action_index,
                    expected,
                    actual: action.statement_digest,
                });
            }
        }
        Ok(())
    }

    /// The wrapped proof attachment an action's carrier occurrence holds.
    ///
    /// Returns `Ok(None)` for an action that is not a wrapped proof carrier.
    ///
    /// # Errors
    ///
    /// Returns an error when the occurrence is missing or is not one canonical,
    /// structurally valid proof attachment.
    pub fn proof_carrier_v1(
        &self,
        action: &ActionIntentV1,
    ) -> Result<Option<ProofAttachment>, SignedAttachmentErrorV1> {
        if !action.operation.is_proof_carrier() {
            return Ok(None);
        }
        let reference =
            action
                .attachments
                .first()
                .ok_or(SignedAttachmentErrorV1::OperationRule {
                    action_index: action.action_index,
                    rule: ActionRuleViolationV1::AttachmentCount,
                })?;
        let occurrence =
            self.occurrence(reference.index)
                .ok_or(SignedAttachmentErrorV1::MissingOccurrence {
                    action_index: action.action_index,
                    index: reference.index,
                })?;
        let attachment = ncore::classify_decode_attempt(|| {
            norito::decode_canonical::<ProofAttachment>(&occurrence.bytes)
        })
        .map_err(|original| match original.into_local_refusal() {
            Ok(original) => SignedAttachmentErrorV1::LocalResource(original),
            Err(original) => SignedAttachmentErrorV1::MalformedProofCarrier {
                index: occurrence.index,
                reason: original.error().to_string(),
            },
        })?;
        if let Some((field, message)) = attachment.structural_error() {
            return Err(SignedAttachmentErrorV1::MalformedProofCarrier {
                index: occurrence.index,
                reason: format!("{field} {message}"),
            });
        }
        Ok(Some(attachment))
    }

    /// The wrapped proof attachments of every carrier action, in action order.
    ///
    /// # Errors
    ///
    /// Returns an error when a carrier occurrence is missing or malformed.
    pub fn proof_carriers_v1(
        &self,
    ) -> Result<Vec<(&ActionIntentV1, ProofAttachment)>, SignedAttachmentErrorV1> {
        let mut carriers = Vec::new();
        for action in &self.actions {
            if let Some(attachment) = self.proof_carrier_v1(action)? {
                carriers.push((action, attachment));
            }
        }
        Ok(carriers)
    }

    /// Validate every wrapped proof carrier against its declaration.
    ///
    /// The role must agree with the presence of a lane privacy witness and the
    /// declared public-input digest must be the digest of the actual
    /// proof-free attachment.
    ///
    /// # Errors
    ///
    /// Returns the first carrier violation.
    pub fn validate_proof_carriers_v1(&self) -> Result<(), SignedAttachmentErrorV1> {
        for (action, attachment) in self.proof_carriers_v1()? {
            let Some(reference) = action.attachments.first() else {
                continue;
            };
            let lane_role = reference.role == AttachmentRoleV1::LanePrivacyProof;
            if lane_role != attachment.lane_privacy.is_some() {
                return Err(SignedAttachmentErrorV1::ProofCarrierRoleMismatch {
                    index: reference.index,
                });
            }
            if action.public_inputs_digest != proof_carrier_public_inputs_digest_v1(&attachment)? {
                return Err(SignedAttachmentErrorV1::PublicInputsMismatch {
                    action_index: action.action_index,
                });
            }
        }
        Ok(())
    }

    fn canonical_frame_len_from_payload_len(payload_len: usize) -> Option<usize> {
        let alignment = ncore::archived_payload_align::<Self>();
        let remainder = ncore::Header::SIZE % alignment;
        let padding = if remainder == 0 {
            0
        } else {
            alignment - remainder
        };
        ncore::Header::SIZE
            .checked_add(padding)?
            .checked_add(payload_len)
    }

    /// Size of the complete canonical Norito frame of this value: the header,
    /// alignment padding and the bare payload with all framing.
    ///
    /// # Errors
    ///
    /// Returns an error when the counting serialization pass fails.
    pub fn canonical_frame_len_v1(&self) -> Result<usize, SignedAttachmentErrorV1> {
        let _canonical_flags = ncore::DecodeFlagsGuard::enter(ncore::default_encode_flags());
        ncore::classify_decode_attempt(|| ncore::encoded_frame_len(self))
            .map_err(SignedAttachmentErrorV1::from_encoding_attempt)
    }

    /// Validate everything that does not depend on the rest of the transaction.
    ///
    /// Checked in this order: counts; each occurrence's index, size, declared
    /// length and declared hash; repeated proof bytes; each action's ordinal,
    /// operation shape, invocation depth and digests; the reference–occurrence
    /// bijection (missing, duplicate and out-of-order references, then type,
    /// role, length and hash agreement); the closed operation rules;
    /// unreferenced occurrences; the frame size.
    ///
    /// # Errors
    ///
    /// Returns the first violation.
    pub fn validate_v1(&self) -> Result<(), SignedAttachmentErrorV1> {
        if self.actions.is_empty() {
            return Err(SignedAttachmentErrorV1::NoActions);
        }
        if self.actions.len() > SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 {
            return Err(SignedAttachmentErrorV1::TooManyActions {
                actual: self.actions.len(),
                maximum: SIGNED_ATTACHMENTS_MAX_ACTIONS_V1,
            });
        }
        if self.occurrences.len() > SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 {
            return Err(SignedAttachmentErrorV1::TooManyOccurrences {
                actual: self.occurrences.len(),
                maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
            });
        }
        self.validate_occurrences()?;
        self.validate_actions()?;
        let frame_len = self.canonical_frame_len_v1()?;
        if frame_len > SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 {
            return Err(SignedAttachmentErrorV1::FrameTooLarge {
                actual: frame_len,
                maximum: SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1,
            });
        }
        Ok(())
    }

    fn validate_occurrences(&self) -> Result<(), SignedAttachmentErrorV1> {
        for (position, occurrence) in self.occurrences.iter().enumerate() {
            let index = occurrence.index;
            if index != ordinal(position) {
                return Err(SignedAttachmentErrorV1::OccurrenceOutOfOrder { position, index });
            }
            if occurrence.bytes.is_empty() {
                return Err(SignedAttachmentErrorV1::EmptyOccurrence { index });
            }
            if occurrence.bytes.len() > SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 {
                return Err(SignedAttachmentErrorV1::OccurrenceTooLarge {
                    index,
                    actual: occurrence.bytes.len(),
                    maximum: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
                });
            }
            if u64::try_from(occurrence.bytes.len()).ok() != Some(occurrence.length) {
                return Err(SignedAttachmentErrorV1::OccurrenceLengthMismatch {
                    index,
                    declared: occurrence.length,
                    actual: occurrence.bytes.len(),
                });
            }
            if occurrence.content_hash != AttachmentContentHashV1::of(&occurrence.bytes) {
                return Err(SignedAttachmentErrorV1::OccurrenceHashMismatch { index });
            }
        }
        for (position, occurrence) in self.occurrences.iter().enumerate() {
            if !occurrence.kind.is_generated() {
                continue;
            }
            if let Some(first) = self.occurrences[..position].iter().find(|earlier| {
                earlier.kind.is_generated() && earlier.content_hash == occurrence.content_hash
            }) {
                return Err(SignedAttachmentErrorV1::DuplicateProofContent {
                    first: first.index,
                    second: occurrence.index,
                });
            }
        }
        Ok(())
    }

    fn validate_actions(&self) -> Result<(), SignedAttachmentErrorV1> {
        let mut referenced = vec![false; self.occurrences.len()];
        let mut next_reference = 0_usize;
        for (position, action) in self.actions.iter().enumerate() {
            let action_index = action.action_index;
            if action_index != ordinal(position) {
                return Err(SignedAttachmentErrorV1::ActionOutOfOrder {
                    position,
                    action_index,
                });
            }
            if !action.operation.is_well_formed() {
                return Err(SignedAttachmentErrorV1::MalformedOperation { action_index });
            }
            let call_path_len = action.invocation.call_path_len();
            if call_path_len > ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 {
                return Err(SignedAttachmentErrorV1::CallPathTooDeep {
                    action_index,
                    actual: call_path_len,
                    maximum: ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1,
                });
            }
            if action.public_inputs_digest.is_zero() {
                return Err(SignedAttachmentErrorV1::ZeroPublicInputsDigest { action_index });
            }
            if action.statement_digest.is_zero() {
                return Err(SignedAttachmentErrorV1::ZeroStatementDigest { action_index });
            }
            if action.attachments.len() > SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 {
                return Err(SignedAttachmentErrorV1::TooManyReferences {
                    action_index,
                    actual: action.attachments.len(),
                    maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
                });
            }
            for reference in &action.attachments {
                let index = reference.index;
                let occurrence = usize::try_from(index)
                    .ok()
                    .and_then(|slot| self.occurrences.get(slot).map(|found| (slot, found)));
                let Some((slot, occurrence)) = occurrence else {
                    return Err(SignedAttachmentErrorV1::MissingOccurrence {
                        action_index,
                        index,
                    });
                };
                if referenced[slot] {
                    return Err(SignedAttachmentErrorV1::DuplicateReference {
                        action_index,
                        index,
                    });
                }
                if slot != next_reference {
                    return Err(SignedAttachmentErrorV1::ReferenceOutOfOrder {
                        action_index,
                        index,
                        expected: ordinal(next_reference),
                    });
                }
                referenced[slot] = true;
                next_reference = slot.saturating_add(1);
                if reference.kind != occurrence.kind {
                    return Err(SignedAttachmentErrorV1::ReferenceKindMismatch {
                        action_index,
                        index,
                    });
                }
                if !reference.role.admits_kind(reference.kind) {
                    return Err(SignedAttachmentErrorV1::ReferenceRoleMismatch {
                        action_index,
                        index,
                    });
                }
                if reference.length != occurrence.length {
                    return Err(SignedAttachmentErrorV1::ReferenceLengthMismatch {
                        action_index,
                        index,
                        declared: reference.length,
                        actual: occurrence.length,
                    });
                }
                if reference.content_hash != occurrence.content_hash {
                    return Err(SignedAttachmentErrorV1::ReferenceHashMismatch {
                        action_index,
                        index,
                    });
                }
            }
            if let Some(rule) = action.rule_violation() {
                return Err(SignedAttachmentErrorV1::OperationRule { action_index, rule });
            }
        }
        if let Some(unreferenced) = referenced.iter().position(|seen| !seen) {
            return Err(SignedAttachmentErrorV1::UnreferencedOccurrence {
                index: ordinal(unreferenced),
            });
        }
        Ok(())
    }
}

/// Borrow one length-prefixed struct field without charging an owned allocation.
fn take_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    max_len: usize,
) -> Result<&'a [u8], ncore::Error> {
    let tail = bytes.get(*offset..).ok_or(ncore::Error::LengthMismatch)?;
    let (len, header) = ncore::inspect_len_from_slice(tail)?;
    if len > max_len {
        return Err(ncore::Error::LengthMismatch);
    }
    let start = offset
        .checked_add(header)
        .ok_or(ncore::Error::LengthMismatch)?;
    let end = start.checked_add(len).ok_or(ncore::Error::LengthMismatch)?;
    let field = bytes.get(start..end).ok_or(ncore::Error::LengthMismatch)?;
    *offset = end;
    Ok(field)
}

/// Decode one complete field slice.
fn decode_exact_field<'a, T: ncore::DecodeFromSlice<'a>>(
    field: &'a [u8],
) -> Result<T, ncore::Error> {
    let (value, used) = T::decode_from_slice(field)?;
    if used != field.len() {
        return Err(ncore::Error::LengthMismatch);
    }
    Ok(value)
}

fn schema_error(error: &SignedAttachmentErrorV1) -> ncore::Error {
    match error {
        SignedAttachmentErrorV1::LocalResource(original) => original.clone().into_error(),
        error => ncore::Error::Message(error.to_string()),
    }
}

/// Inspect variable action fields before their string or vector decoders allocate.
fn preflight_action_fields(
    action_index: u32,
    operation: &[u8],
    invocation: &[u8],
    references: &[u8],
) -> Result<(), ncore::Error> {
    let (operation_tag, mut operation_offset) = u32::decode_from_slice(operation)?;
    if operation_tag == 0 {
        let wire_id = take_field(operation, &mut operation_offset, operation.len())?;
        let (length, _) = ncore::inspect_len_from_slice(wire_id)?;
        if length > ACTION_OPERATION_MAX_WIRE_ID_BYTES_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::MalformedOperation {
                action_index,
            }));
        }
    }
    let (invocation_tag, mut invocation_offset) = u32::decode_from_slice(invocation)?;
    if invocation_tag == 2 {
        let _root = take_field(invocation, &mut invocation_offset, invocation.len())?;
        let path = take_field(invocation, &mut invocation_offset, invocation.len())?;
        let (depth, _) = ncore::inspect_seq_len_slice(path)?;
        if depth > ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::CallPathTooDeep {
                action_index,
                actual: depth,
                maximum: ACTION_INVOCATION_MAX_CALL_PATH_DEPTH_V1,
            }));
        }
    }
    let (count, _) = ncore::inspect_seq_len_slice(references)?;
    if count > SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 {
        return Err(schema_error(&SignedAttachmentErrorV1::TooManyReferences {
            action_index,
            actual: count,
            maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
        }));
    }
    Ok(())
}

impl<'de> norito::DeserializePayload<'de> for ActionIntentV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("ActionIntentV1 deserialization requires a canonical bounded archive")
    }

    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        decode_exact_field::<Self>(bytes)
    }
}

impl<'a> ncore::DecodeFromSlice<'a> for ActionIntentV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let mut offset = 0_usize;
        let mut fields = [&[][..]; 8];
        for field in &mut fields {
            *field = take_field(bytes, &mut offset, bytes.len())?;
        }
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        let action_index = decode_exact_field::<u32>(fields[0])?;
        // The enclosing frame limit is not a bound on these allocations: a
        // valid frame could otherwise spend its entire proof allowance on a
        // wire identifier, invocation path or reference table. Inspect their
        // protocol bounds before any owned action field is decoded.
        preflight_action_fields(action_index, fields[1], fields[4], fields[7])?;
        Ok((
            Self {
                action_index,
                operation: decode_exact_field(fields[1])?,
                role: decode_exact_field(fields[2])?,
                authority: decode_exact_field(fields[3])?,
                invocation: decode_exact_field(fields[4])?,
                public_inputs_digest: decode_exact_field(fields[5])?,
                statement_digest: decode_exact_field(fields[6])?,
                attachments: decode_exact_field(fields[7])?,
            },
            offset,
        ))
    }
}

impl<'de> norito::DeserializePayload<'de> for SignedAttachmentOccurrenceV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect(
            "SignedAttachmentOccurrenceV1 deserialization requires a canonical bounded archive",
        )
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        decode_exact_field::<Self>(bytes)
    }
}

impl<'a> ncore::DecodeFromSlice<'a> for SignedAttachmentOccurrenceV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        let mut offset = 0_usize;
        let index = decode_exact_field::<u32>(take_field(bytes, &mut offset, bytes.len())?)?;
        let kind =
            decode_exact_field::<AttachmentKindV1>(take_field(bytes, &mut offset, bytes.len())?)?;
        let length = decode_exact_field::<u64>(take_field(bytes, &mut offset, bytes.len())?)?;
        let content_hash = decode_exact_field::<AttachmentContentHashV1>(take_field(
            bytes,
            &mut offset,
            bytes.len(),
        )?)?;
        let byte_field = take_field(bytes, &mut offset, bytes.len())?;
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        // Inspect the declared byte count before `Vec<u8>` can reserve storage.
        let (declared, _) = ncore::inspect_seq_len_slice(byte_field)?;
        if declared > SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::OccurrenceTooLarge {
                index,
                actual: declared,
                maximum: SIGNED_ATTACHMENT_OCCURRENCE_MAX_BYTES_V1,
            }));
        }
        let data = decode_exact_field::<Vec<u8>>(byte_field)?;
        Ok((
            Self {
                index,
                kind,
                length,
                content_hash,
                bytes: data,
            },
            offset,
        ))
    }
}

impl<'de> norito::DeserializePayload<'de> for SignedAttachmentsV1 {
    fn deserialize(archived: &'de ncore::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("SignedAttachmentsV1 deserialization requires a canonical bounded archive")
    }
    fn try_deserialize(archived: &'de ncore::Archived<Self>) -> Result<Self, ncore::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let bytes = ncore::payload_slice_from_ptr(ptr)?;
        decode_exact_field::<Self>(bytes)
    }
}

impl<'a> ncore::DecodeFromSlice<'a> for SignedAttachmentsV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), ncore::Error> {
        // Refuse an oversized frame before any field is parsed or allocated.
        let frame_len = Self::canonical_frame_len_from_payload_len(bytes.len())
            .ok_or(ncore::Error::LengthMismatch)?;
        if frame_len > SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::FrameTooLarge {
                actual: frame_len,
                maximum: SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1,
            }));
        }
        let mut offset = 0_usize;
        let action_field = take_field(bytes, &mut offset, bytes.len())?;
        let occurrence_field = take_field(bytes, &mut offset, bytes.len())?;
        if offset != bytes.len() {
            return Err(ncore::Error::LengthMismatch);
        }
        // Inspect both fixed sequence counts before a vector reserves storage
        // or an attacker-sized element span is visited.
        let (action_count, _) = ncore::inspect_seq_len_slice(action_field)?;
        if action_count == 0 {
            return Err(schema_error(&SignedAttachmentErrorV1::NoActions));
        }
        if action_count > SIGNED_ATTACHMENTS_MAX_ACTIONS_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::TooManyActions {
                actual: action_count,
                maximum: SIGNED_ATTACHMENTS_MAX_ACTIONS_V1,
            }));
        }
        let (occurrence_count, _) = ncore::inspect_seq_len_slice(occurrence_field)?;
        if occurrence_count > SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1 {
            return Err(schema_error(&SignedAttachmentErrorV1::TooManyOccurrences {
                actual: occurrence_count,
                maximum: SIGNED_ATTACHMENTS_MAX_OCCURRENCES_V1,
            }));
        }
        let actions = decode_exact_field::<Vec<ActionIntentV1>>(action_field)?;
        let occurrences =
            decode_exact_field::<Vec<SignedAttachmentOccurrenceV1>>(occurrence_field)?;
        let value = Self {
            actions,
            occurrences,
        };
        value.validate_v1().map_err(|error| schema_error(&error))?;
        Ok((value, offset))
    }
}

fn json_error(message: &'static str) -> norito::json::Error {
    norito::json::Error::InvalidField {
        field: "SignedAttachmentsV1".into(),
        message: message.into(),
    }
}

/// Decode the canonical padded standard base64 spelling of one complete frame.
fn decode_canonical_base64_frame(
    encoded: &str,
) -> Result<SignedAttachmentsV1, norito::json::Error> {
    let maximum_encoded = SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1
        .div_ceil(3)
        .saturating_mul(4);
    if encoded.is_empty() || encoded.len() > maximum_encoded || !encoded.len().is_multiple_of(4) {
        return Err(json_error("base64 token has a non-canonical length"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| json_error("expected canonical padded standard base64"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(json_error("base64 token is not in its canonical spelling"));
    }
    if bytes.len() > SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1 {
        return Err(json_error(
            "decoded frame exceeds the first-release byte limit",
        ));
    }
    ncore::classify_decode_attempt(|| norito::decode_canonical::<SignedAttachmentsV1>(&bytes))
        .map_err(|original| norito::json::Error::from_decode_resource(original.into_error()))
}

impl norito::json::JsonSerialize for SignedAttachmentsV1 {
    fn json_serialize(&self, out: &mut String) {
        norito::json::write_canonical_base64_json(self, out);
    }
    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_canonical_base64_json_to(self, out)
    }
}

impl norito::json::JsonDeserialize for SignedAttachmentsV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let maximum_encoded = SIGNED_ATTACHMENTS_MAX_CANONICAL_FRAME_BYTES_V1
            .div_ceil(3)
            .saturating_mul(4);
        parser.skip_ws();
        let start = parser.position();
        let token_len = parser.skip_string_bounded(maximum_encoded)?;
        let end = parser.position();
        let encoded = parser
            .input()
            .get(start.saturating_add(1)..end.saturating_sub(1))
            .ok_or_else(|| json_error("invalid JSON string bounds"))?;
        if encoded.len() != token_len || encoded.as_bytes().contains(&b'\\') {
            return Err(json_error(
                "base64 token must use its unescaped canonical spelling",
            ));
        }
        decode_canonical_base64_frame(encoded)
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let encoded = value
            .as_str()
            .ok_or_else(|| json_error("expected canonical base64 string"))?;
        decode_canonical_base64_frame(encoded)
    }
}

#[cfg(test)]
#[path = "signed_attachments/tests.rs"]
mod tests;
