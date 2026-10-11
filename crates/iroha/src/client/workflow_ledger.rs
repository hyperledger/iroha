//! Durable workflows of an account context, over the existing signing, submission and
//! global-status owners, and the separately named workflow calls.
//!
//! Nothing here opens a second transport or finality path: signing is
//! [`AccountClient::sign_transaction`], dispatch is the classified submission
//! owner behind [`AccountClient::submit_prepared_transaction_payload`], and the
//! committed outcome is the exact global status read with the canonical
//! state-resolved finality rules.

use std::sync::Arc;

use bytes::Bytes;
use iroha_crypto::Hash;
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};

use super::{
    AccountClient, HashOf, PipelineTransactionStatusResponse, PreflightFailure, PreparedDispatch,
    PreparedTransactionPayload, SignedTransaction, TransactionFinalityFailure, TransactionPayload,
    TxConfirmationStatus, validate_global_pipeline_status_response,
};
use crate::{
    Error as SdkError, TransactionSigningError,
    account_address::AccountAddress,
    workflow::{
        CommittedOutcome, DispatchOutcome, SignedStepTransaction, StepFailure, SystemWorkflowClock,
        TransactionIdentityV1, WorkflowAccount, WorkflowBindingV1, WorkflowEngine, WorkflowError,
        WorkflowErrorCode, WorkflowFuture, WorkflowHandle, WorkflowKindV1, WorkflowLedger,
        WorkflowRequest, WorkflowStage, WorkflowStorage, authority_binding_text,
    },
};

/// Account context and ledger of durable workflows, bound to one [`AccountClient`].
///
/// The unsigned payload of a transaction step is the canonical Norito frame of
/// [`TransactionPayload`]; the signed bytes are the canonical versioned
/// [`SignedTransaction`].
#[derive(Clone, Debug)]
pub struct AccountWorkflowContext {
    account: AccountClient,
    binding: WorkflowBindingV1,
}

impl AccountWorkflowContext {
    /// Bind the workflow context to an immutable account context.
    ///
    /// The binding is computed once, here. `network` is the canonical network
    /// identity text. `authority` is [`authority_binding_text`] of the canonical
    /// account address payload: it does not depend on the chain discriminant that
    /// account literals are rendered with, nor on any other process state, so the
    /// same account always resumes the same workflows.
    ///
    /// # Errors
    /// `InvalidInput` when the authority has no canonical address payload. Nothing
    /// is created in that case and no other text is bound instead.
    pub fn new(account: AccountClient) -> Result<Self, WorkflowError> {
        let address = AccountAddress::from_account_id(account.authority())
            .and_then(|address| address.canonical_bytes())
            .map_err(|error| {
                WorkflowError::new(
                    WorkflowErrorCode::InvalidInput,
                    WorkflowStage::Plan,
                    format!("the account authority has no canonical address payload: {error}"),
                )
            })?;
        let binding = WorkflowBindingV1 {
            network: account.network_id().to_string(),
            authority: authority_binding_text(&address),
        };
        Ok(Self { account, binding })
    }
}

fn identity_of(transaction: &SignedTransaction) -> TransactionIdentityV1 {
    TransactionIdentityV1 {
        signed_transaction_hash: *Hash::from(transaction.hash()).as_ref(),
        entrypoint_hash: *Hash::from(transaction.hash_as_entrypoint()).as_ref(),
    }
}

fn signed_hash(identity: &TransactionIdentityV1) -> HashOf<SignedTransaction> {
    HashOf::from_untyped_unchecked(Hash::prehashed(identity.signed_transaction_hash))
}

fn decode_signed(signed_transaction: &[u8]) -> Result<SignedTransaction, StepFailure> {
    let non_canonical = || {
        StepFailure::new(
            WorkflowErrorCode::NonCanonicalEncoding,
            "bytes are not one canonical versioned signed transaction",
        )
    };
    let transaction =
        SignedTransaction::decode_all_versioned(signed_transaction).map_err(|_| non_canonical())?;
    if transaction.encode_versioned().as_slice() != signed_transaction {
        return Err(non_canonical());
    }
    Ok(transaction)
}

pub(super) fn signing_failure(error: &SdkError) -> StepFailure {
    let code = match error {
        SdkError::TransactionSigning(
            TransactionSigningError::NetworkMismatch { .. }
            | TransactionSigningError::AuthorityMismatch { .. }
            | TransactionSigningError::KeyMismatch { .. },
        ) => WorkflowErrorCode::BindingMismatch,
        // TODO: Sign workflow steps of a multisignature authority through the external
        // threshold-signing form of the prepared operation once S.1 provides it.
        SdkError::TransactionSigning(
            TransactionSigningError::DirectSigningUnavailable { .. }
            | TransactionSigningError::AuthorityNotDirect { .. },
        ) => WorkflowErrorCode::UnsupportedOperation,
        SdkError::TransactionSigning(TransactionSigningError::InvalidPayload { .. }) => {
            WorkflowErrorCode::InvalidInput
        }
        _ => WorkflowErrorCode::LocalResourceUnavailable,
    };
    StepFailure::new(code, error.to_string())
}

/// Classify one exact global status response with the canonical finality rules.
///
/// Only a state-resolved `Applied`, `Rejected` or `Expired` is authoritative.
/// Every other bound response shows the transaction without closing it, and a
/// response that cannot be bound to the requested hash and scope is a failed read.
fn committed_outcome_of(
    hash: HashOf<SignedTransaction>,
    response: PipelineTransactionStatusResponse,
) -> CommittedOutcome {
    let status = match validate_global_pipeline_status_response(&response, hash) {
        Ok(status) => status,
        Err(error) => {
            return CommittedOutcome::ReadFailed {
                detail: format!("{error:#}"),
            };
        }
    };
    if response.resolved_from != "state" {
        return CommittedOutcome::ObservedNotFinal;
    }
    match status {
        TxConfirmationStatus::Applied => CommittedOutcome::Applied {
            block_height: response.status.block_height,
        },
        TxConfirmationStatus::Rejected(_) | TxConfirmationStatus::Expired => {
            let expired = matches!(status, TxConfirmationStatus::Expired);
            match TransactionFinalityFailure::from_response(hash, response) {
                Ok(Some(_)) if expired => CommittedOutcome::Expired,
                Ok(Some(failure)) => CommittedOutcome::Rejected {
                    detail: failure.to_string(),
                },
                Ok(None) => CommittedOutcome::ObservedNotFinal,
                Err(error) => CommittedOutcome::ReadFailed {
                    detail: format!("{error:#}"),
                },
            }
        }
        TxConfirmationStatus::Queued
        | TxConfirmationStatus::Approved(_)
        | TxConfirmationStatus::Committed => CommittedOutcome::ObservedNotFinal,
    }
}

impl WorkflowAccount for AccountWorkflowContext {
    fn binding(&self) -> WorkflowBindingV1 {
        self.binding.clone()
    }

    fn sign<'a>(
        &'a self,
        unsigned_payload: &'a [u8],
    ) -> WorkflowFuture<'a, Result<SignedStepTransaction, StepFailure>> {
        Box::pin(async move {
            let payload: TransactionPayload =
                norito::decode_canonical(unsigned_payload).map_err(|error| {
                    StepFailure::new(
                        WorkflowErrorCode::NonCanonicalEncoding,
                        format!("unsigned payload is not a canonical transaction payload: {error}"),
                    )
                })?;
            let transaction = self
                .account
                .sign_transaction(payload)
                .map_err(|error| signing_failure(&error))?;
            Ok(SignedStepTransaction {
                signed_transaction: transaction.encode_versioned(),
                identity: identity_of(&transaction),
            })
        })
    }

    fn identify(&self, signed_transaction: &[u8]) -> Result<TransactionIdentityV1, StepFailure> {
        decode_signed(signed_transaction).map(|transaction| identity_of(&transaction))
    }
}

impl WorkflowLedger for AccountWorkflowContext {
    fn dispatch<'a>(
        &'a self,
        signed_transaction: &'a [u8],
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, DispatchOutcome> {
        Box::pin(async move {
            let payload = PreparedTransactionPayload {
                bytes: Bytes::copy_from_slice(signed_transaction),
                hash: signed_hash(identity),
            };
            match self
                .account
                .dispatch_prepared_transaction_payload(&payload)
                .await
            {
                PreparedDispatch::Accepted => DispatchOutcome::Accepted,
                PreparedDispatch::AlreadyKnown(_) => DispatchOutcome::AlreadyKnown,
                PreparedDispatch::Refused(report) => DispatchOutcome::Refused {
                    detail: format!("{report:#}"),
                },
                // Node backpressure: not admitted, and the same bytes may be sent again.
                PreparedDispatch::Deferred(report) => DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::LocalResourceUnavailable,
                    detail: format!("{report:#}"),
                },
                PreparedDispatch::NotDispatched { cause, report } => DispatchOutcome::NotAdmitted {
                    code: match cause {
                        PreflightFailure::CompatibilityProbe => {
                            WorkflowErrorCode::LocalResourceUnavailable
                        }
                        PreflightFailure::IncompatibleNode => {
                            WorkflowErrorCode::UnsupportedOperation
                        }
                        PreflightFailure::NonCanonicalPayload => {
                            WorkflowErrorCode::NonCanonicalEncoding
                        }
                        PreflightFailure::RequestBuild => WorkflowErrorCode::InvalidInput,
                    },
                    detail: format!("{report:#}"),
                },
                PreparedDispatch::Ambiguous(report) => DispatchOutcome::Ambiguous {
                    detail: format!("{report:#}"),
                },
            }
        })
    }

    fn committed_outcome<'a>(
        &'a self,
        identity: &'a TransactionIdentityV1,
    ) -> WorkflowFuture<'a, CommittedOutcome> {
        Box::pin(async move {
            let hash = signed_hash(identity);
            match self
                .account
                .client()
                .fetch_transaction_status_response_global(hash)
                .await
            {
                Ok(Some(response)) => committed_outcome_of(hash, response),
                Ok(None) => CommittedOutcome::ExactAbsence,
                Err(error) => CommittedOutcome::ReadFailed {
                    detail: format!("{error:#}"),
                },
            }
        })
    }
}

impl AccountClient {
    /// The durable workflow engine of this account context over caller-supplied storage.
    ///
    /// The engine signs with this context, dispatches through its classified
    /// submission owner and reconciles through its global status reads.
    ///
    /// # Errors
    /// `InvalidInput` when the authority has no canonical address payload.
    pub fn workflow_engine(
        &self,
        storage: Arc<dyn WorkflowStorage>,
    ) -> Result<WorkflowEngine, WorkflowError> {
        let context = Arc::new(AccountWorkflowContext::new(self.clone())?);
        let account: Arc<dyn WorkflowAccount> = context.clone();
        Ok(WorkflowEngine::new(
            storage,
            account,
            context,
            Arc::new(SystemWorkflowClock::new()),
        ))
    }

    fn named_workflow(
        &self,
        kind: WorkflowKindV1,
        request: WorkflowRequest,
        storage: Arc<dyn WorkflowStorage>,
    ) -> Result<WorkflowHandle, WorkflowError> {
        self.workflow_engine(storage)?
            .workflow(request.into_plan(kind))
    }

    /// Durable handle of an issuer or pool bootstrap workflow.
    ///
    /// The steps are separate transactions and issuer rounds. Finalized steps are
    /// not rolled back; the handle reports partial completion explicitly. The same
    /// request, account and storage return the same workflow after a restart.
    ///
    /// # Errors
    /// Returns the plan or binding validation error.
    pub fn bootstrap_workflow(
        &self,
        request: WorkflowRequest,
        storage: Arc<dyn WorkflowStorage>,
    ) -> Result<WorkflowHandle, WorkflowError> {
        self.named_workflow(WorkflowKindV1::IssuerBootstrap, request, storage)
    }

    /// Durable handle of a distributed key generation workflow.
    ///
    /// The key-generation rounds and their cryptography belong to the supplied
    /// capability driver; this call owns only ordering, durability and recovery.
    ///
    /// # Errors
    /// Returns the plan or binding validation error.
    pub fn dkg_workflow(
        &self,
        request: WorkflowRequest,
        storage: Arc<dyn WorkflowStorage>,
    ) -> Result<WorkflowHandle, WorkflowError> {
        self.named_workflow(WorkflowKindV1::Dkg, request, storage)
    }

    /// Durable handle of a threshold opening workflow: share collection, then the opening
    /// transaction.
    ///
    /// # Errors
    /// Returns the plan or binding validation error.
    pub fn threshold_opening_workflow(
        &self,
        request: WorkflowRequest,
        storage: Arc<dyn WorkflowStorage>,
    ) -> Result<WorkflowHandle, WorkflowError> {
        self.named_workflow(WorkflowKindV1::ThresholdOpening, request, storage)
    }
}
