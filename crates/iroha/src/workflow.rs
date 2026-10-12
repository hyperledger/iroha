//! Durable multi-round workflows: bootstrap, key generation and threshold opening.
//!
//! A workflow is an ordered sequence of ledger transactions and off-chain
//! rounds. Each transaction is atomic by itself; **the sequence is not**. A
//! finalized transaction or an irreversible round is never rolled back by a
//! later failure, cancellation or interruption, and every result states what is
//! confirmed, what may still take effect and what never started.
//!
//! The normative contract is `specs/zk_durable_workflow.md`. Its machine-readable
//! form and the scenario fixtures every SDK family runs are under
//! `fixtures/zk/workflow_v1/`; [`contract::state_machine_json`] is their source.
//!
//! The resume rule: a step found in `submitting`, `outcome_unknown` or `pending`
//! is first reconciled by a read-only query on its persisted transaction
//! identity. Only an authoritative state-resolved outcome closes an identity.
//! A submission timeout is an unknown outcome until that read resolves it, a
//! step is never submitted under a new identity while the previous one may still
//! commit, and a local clock never decides that a transaction expired. A signed
//! transaction that provably was never admitted (node backpressure, or a failure
//! before any byte left the client) stays dispatchable however often that happens.
//!
//! This module is transport-free. [`crate::client::AccountClient`] supplies the
//! account context and ledger through the existing signing, submission and
//! global-status owners and exposes the separately named calls
//! `bootstrap_workflow`, `dkg_workflow` and `threshold_opening_workflow`.
//! Capability logic comes from a [`WorkflowDriver`]; this module contains no
//! key-generation or threshold cryptography.

pub mod contract;
mod engine;
mod error;
mod journal;
mod storage;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod testing;

pub use contract::{
    AttemptEvidenceKindV1, RoundStateV1, StepKindV1, TransactionStateV1, WorkflowErrorCode,
    WorkflowKindV1, WorkflowStage, WorkflowStatusV1,
};
pub use engine::{
    BuiltStepPayload, CommittedOutcome, DispatchOutcome, RoundContext, RoundRecovery, RoundReport,
    RoundStatusReport, SignedStepTransaction, StepContext, StepFailure, SystemWorkflowClock,
    WorkflowAccount, WorkflowClock, WorkflowDriver, WorkflowEngine, WorkflowFuture, WorkflowHandle,
    WorkflowLedger, WorkflowObserver, WorkflowRunOptions,
};
pub use error::{WorkflowBounds, WorkflowError};
pub use journal::{
    AUTHORITY_BINDING_DOMAIN_V1, AttemptEvidenceV1, CustodyHandleV1, Digest32, DriverIdentityV1,
    JOURNAL_DIGEST_DOMAIN_V1, PLAN_DIGEST_DOMAIN_V1, PartialCompletionV1, RECORD_DIGEST_DOMAIN_V1,
    ROUND_ID_DOMAIN_V1, RoundInputV1, RoundRecordV1, StepDescriptorV1, StepProgressV1,
    StepRecordV1, TRANSCRIPT_DIGEST_DOMAIN_V1, TransactionAttemptV1, TransactionIdentityV1,
    TransactionInputV1, TransactionOperationV1, WORKFLOW_ID_DOMAIN_V1, WorkflowBindingV1,
    WorkflowId, WorkflowIdentityV1, WorkflowJournalRecordV1, WorkflowJournalV1, WorkflowPlanV1,
    WorkflowProgressV1, WorkflowRequest, authority_binding_text, domain_digest, record_digest,
    round_identity, transcript_digest,
};
pub use storage::{
    FileWorkflowStorage, MemoryWorkflowStorage, WorkflowRunnerLease, WorkflowStorage,
    WorkflowStorageDurability, WorkflowStorageError, WorkflowStorageErrorKind,
};

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod journal_tests;
#[cfg(test)]
mod scenario_tests;
