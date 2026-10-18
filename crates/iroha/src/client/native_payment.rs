//! One durable native payment over the existing signing, workflow and finality owners.

use super::{
    AccountClient, AccountTransactionDraft, AccountWorkflowContext, VerifiedPaymentReceipt,
};
use crate::workflow::{
    BuiltStepPayload, Digest32, DriverIdentityV1, NativePaymentCompletionV1, StepContext,
    StepDescriptorV1, StepFailure, SystemWorkflowClock, WorkflowAccount, WorkflowDriver,
    WorkflowEngine, WorkflowError, WorkflowErrorCode, WorkflowFuture, WorkflowHandle, WorkflowId,
    WorkflowKindV1, WorkflowPlanV1, WorkflowProgressV1, WorkflowRunOptions, WorkflowStorage,
    WorkflowStorageDurability, domain_digest,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    asset::AssetBalanceScope,
    block::consensus::SumeragiRootScope,
    isi::{SettleAtomic, SettlementInstructionBox},
    sumeragi_finality::SumeragiFinalityVerifier,
    transaction::{FeeChargeKind, FeePaymentIntent, SignedTransaction, TransactionEntrypoint},
};
use iroha_model_base::metadata::Metadata;
use std::{
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

mod carrier;
mod observation;
mod session;
pub use session::NativePaymentSession;
pub use observation::NativePaymentObservationError;
use observation::{NativePaymentLedger, OnlinePaymentSource, PaymentSource};
#[cfg(test)]
mod online_tests;
#[cfg(test)]
mod tests;

/// Independently retained complete native payment and exact carrier fee authorization.
#[derive(Clone, Debug)]
pub struct NativePaymentRequest {
    intent: SettleAtomic,
    fee_payment: FeePaymentIntent,
    digest: Digest32,
}

impl NativePaymentRequest {
    /// Bind one Global asset debit to its payer-scoped payment identity and exact fees.
    ///
    /// The direct account authority must equal the namespace owner and sole debit owner.
    /// The original request must be retained independently and supplied again on restart.
    /// # Errors
    /// Invalid intent, unsupported movement scope/fee kind, or canonical encoding refusal.
    pub fn new(
        intent: SettleAtomic,
        fee_payment: FeePaymentIntent,
    ) -> Result<Self, NativePaymentError> {
        intent
            .validate()
            .map_err(NativePaymentError::InvalidRequest)?;
        let movements = intent
            .movements
            .resolve()
            .map_err(NativePaymentError::InvalidRequest)?;
        let movements = movements.as_slice();
        if movements.len() != 1
            || movements[0].source.scope() != &AssetBalanceScope::Global
            || movements[0].source.account() != intent.settlement_id.owner()
        {
            return Err(NativePaymentError::InvalidRequest(
                "native payment requires one Global movement owned by the payment namespace",
            ));
        }
        if fee_payment
            .charge_limits()
            .iter()
            .any(|limit| limit.kind == FeeChargeKind::PipelineGas)
        {
            return Err(NativePaymentError::InvalidRequest(
                "native payment cannot authenticate PipelineGas charges",
            ));
        }
        let bytes = norito::encode_canonical(&(intent.clone(), fee_payment.clone()))
            .map_err(NativePaymentObservationError::Encoding)?;
        let digest = domain_digest(b"iroha:native-payment:request:v1\0", &[&bytes]);
        Ok(Self {
            intent,
            fee_payment,
            digest,
        })
    }

    /// Complete independently selected terms, including network, payer, reference and expiry.
    #[must_use]
    pub const fn intent(&self) -> &SettleAtomic {
        &self.intent
    }

    /// Independently selected signed fee authorization; recovery requires exact equality.
    #[must_use]
    pub const fn fee_payment(&self) -> &FeePaymentIntent {
        &self.fee_payment
    }

    fn plan(&self) -> Result<WorkflowPlanV1, NativePaymentError> {
        let id = norito::encode_canonical(&self.intent.settlement_id)
            .map_err(NativePaymentObservationError::Encoding)?;
        Ok(WorkflowPlanV1 {
            kind: WorkflowKindV1::NativePayment,
            instance: hex::encode(domain_digest(b"iroha:native-payment:instance:v1\0", &[&id])),
            driver: driver_identity(),
            request_context_digest: self.digest,
            steps: vec![StepDescriptorV1::transaction("payment", self.digest)],
        })
    }
}

/// Local observation policy. These limits never change payment validity or consensus.
#[derive(Clone, Copy, Debug)]
pub struct NativePaymentRunOptions {
    /// Existing journal observation and exact-byte retransmission policy.
    pub workflow: WorkflowRunOptions,
    /// Maximum full proof reads in this call, including authenticated-prefix catch-up.
    /// Exhaustion leaves all durable transaction identities unresolved and is retryable.
    pub max_finality_proof_reads: NonZeroU16,
}
impl Default for NativePaymentRunOptions {
    fn default() -> Self {
        Self {
            workflow: WorkflowRunOptions::default(),
            max_finality_proof_reads: NonZeroU16::new(64).expect("nonzero"),
        }
    }
}

/// A verified business outcome and the independent state of this workflow's carrier.
#[derive(Debug)]
pub struct NativePaymentSettlement {
    /// Independently authenticated original successful carrier and exact payment/fee receipt.
    pub receipt: VerifiedPaymentReceipt,
    /// Carrier journal progress, which may remain rejected or unsubmitted after original recovery.
    pub carrier: WorkflowProgressV1,
}

/// Read-only recovery result. Absence of a receipt means only that success was not established.
#[derive(Debug)]
pub struct NativePaymentRecovery {
    /// Existing carrier progress, if a journal has been created.
    pub carrier: Option<WorkflowProgressV1>,
    /// Present only after fresh independent verification of the original successful block.
    pub receipt: Option<VerifiedPaymentReceipt>,
}

/// Why a payment call could not return a verified successful business outcome.
/// Original error and journal graphs move into error-owned boxes to keep the result shell small.
#[derive(Debug, thiserror::Error)]
pub enum NativePaymentError {
    /// No retained original carrier or verified successful business receipt exists.
    /// A new paid attempt requires the explicit `submit` call and reviewed exact fee intent.
    #[error("new payment attempt requires explicit submission authorization")]
    NewAttemptAuthorizationRequired {
        /// Original local progress, if a journal exists without a signed carrier.
        progress: Option<Box<WorkflowProgressV1>>,
    },
    /// The independently supplied request or account context is unsupported.
    #[error("invalid native payment request: {0}")]
    InvalidRequest(&'static str),
    /// Existing storage, signing, dispatch or journal failure, retaining carrier progress.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// A read/verification failure retains its original typed cause and partial carrier state.
    #[error("native payment observation failed: {cause}")]
    Observation {
        /// Original typed transport, decoder, proof or local-resource failure.
        #[source]
        cause: Box<NativePaymentObservationError>,
        /// Current independently loaded carrier journal progress, when available.
        progress: Option<Box<WorkflowProgressV1>>,
    },
    /// The call established no successful payment; no fresh identity was authorized.
    #[error("native payment success has not yet been independently verified")]
    Unresolved {
        /// Exact durable carrier progress.
        progress: Option<Box<WorkflowProgressV1>>,
    },
}
impl From<NativePaymentObservationError> for NativePaymentError {
    fn from(cause: NativePaymentObservationError) -> Self {
        Self::Observation {
            cause: Box::new(cause),
            progress: None,
        }
    }
}

/// A resumable direct native payment using the existing durable workflow journal.
///
/// Only an independently verified receipt completes the business intent. A status,
/// replay locator or decoded journal never constructs a receipt. Recovery re-fetches
/// the certified original block from the caller's pinned genesis-rooted verifier;
/// it needs no subsequent block or unrelated traffic. No proof blobs are persisted.
/// A local read limit, failed read or status-only expiry cannot close a carrier.
/// Before signing or dispatch, restored carrier bytes must match the independently
/// retained complete intent and fees, with empty carrier metadata and no attachments.
pub struct NativePaymentOperation {
    handle: WorkflowHandle,
    resume_handle: WorkflowHandle,
    resume_driver: carrier::ResumePaymentDriver,
    driver: Arc<dyn WorkflowDriver>,
    ledger: Arc<NativePaymentLedger>,
    call: tokio::sync::Mutex<()>,
}
impl core::fmt::Debug for NativePaymentOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativePaymentOperation")
            .field("workflow_id", &self.id())
            .finish_non_exhaustive()
    }
}

impl AccountClient {
    /// Prepare a durable direct payment with independently selected genesis trust.
    ///
    /// Recreate this handle with the same request and durable storage after restart.
    /// This cold operation retains up to 64 authenticated decisions, independently
    /// of the per-call proof-read limit. Use [`Self::native_payment_with_session`] for
    /// sequential payments sharing an explicitly bounded original prefix.
    /// The verifier must come from independently authenticated signed genesis (or
    /// an independently retained authenticated checkpoint), never the queried node.
    /// # Errors
    /// Wrong payer/network/root, volatile storage, or invalid workflow binding.
    pub fn native_payment(
        &self,
        request: NativePaymentRequest,
        storage: Arc<dyn WorkflowStorage>,
        verifier: SumeragiFinalityVerifier,
    ) -> Result<NativePaymentOperation, NativePaymentError> {
        // The cold operation uses the existing short-history observation scale.
        // Retained decisions and each call's proof reads remain independent budgets.
        let session = NativePaymentSession::new(
            verifier,
            std::num::NonZeroUsize::new(64).expect("nonzero local history capacity"),
        )?;
        self.native_payment_with_session(request, storage, session)
    }

    /// Prepare a durable payment sharing an independently authenticated local prefix.
    ///
    /// The session retains no endpoint or signer. Every operation binds this exact
    /// account/network/chain to the original Global genesis owner before creating a
    /// journal; per-operation transport deadlines and proof-read limits remain intact.
    /// Retired historical decisions require cold recovery of the same request/storage,
    /// never a replacement carrier or a remote checkpoint selected as trust.
    /// # Errors
    /// Wrong payer/network/chain/root, unavailable local owner, volatile storage, or
    /// invalid workflow binding. No signing, observation or journal creation precedes
    /// these original binding checks.
    pub fn native_payment_with_session(
        &self,
        request: NativePaymentRequest,
        storage: Arc<dyn WorkflowStorage>,
        session: NativePaymentSession,
    ) -> Result<NativePaymentOperation, NativePaymentError> {
        let selected = session.verifier()?;
        if *self.network_id() != request.intent.network_id
            || self.authority() != request.intent.settlement_id.owner()
            || selected.initial_epoch().network_id != request.intent.network_id
            || selected.root_scope() != SumeragiRootScope::Global
            || selected.chain_id() != self.client().chain.as_ref()
        {
            return Err(NativePaymentError::InvalidRequest(
                "account, payment and independently selected Global trust root differ",
            ));
        }
        drop(selected);
        let context = Arc::new(AccountWorkflowContext::new(self.clone())?);
        let driver = Arc::new(NativePaymentDriver {
            account: self.clone(),
            request: request.clone(),
        });
        NativePaymentOperation::create(
            request,
            storage,
            session,
            context.clone(),
            context,
            Arc::new(OnlinePaymentSource(self.clone())),
            driver,
        )
    }
}

impl NativePaymentOperation {
    fn create(
        request: NativePaymentRequest,
        storage: Arc<dyn WorkflowStorage>,
        session: NativePaymentSession,
        account: Arc<dyn WorkflowAccount>,
        dispatch: Arc<dyn crate::workflow::WorkflowLedger>,
        source: Arc<dyn PaymentSource>,
        driver: Arc<dyn WorkflowDriver>,
    ) -> Result<Self, NativePaymentError> {
        if storage.durability() != WorkflowStorageDurability::Durable {
            return Err(NativePaymentError::InvalidRequest(
                "native payment requires durable workflow storage",
            ));
        }
        let plan = request.plan()?;
        let account = Arc::new(carrier::NativePaymentAccount::new(account, request.clone()));
        let ledger = Arc::new(NativePaymentLedger::new(
            request, session, dispatch, source,
        ));
        let resume_account = Arc::new(carrier::ResumePaymentAccount::new(
            account.binding(),
            ledger.request.clone(),
        ));
        let resume_driver = carrier::ResumePaymentDriver::new(driver.identity());
        let resume_engine = WorkflowEngine::new(
            storage.clone(),
            resume_account,
            ledger.clone(),
            Arc::new(SystemWorkflowClock::new()),
        );
        let resume_handle = resume_engine.workflow(plan.clone())?;
        let engine = WorkflowEngine::new(
            storage,
            account,
            ledger.clone(),
            Arc::new(SystemWorkflowClock::new()),
        );
        Ok(Self {
            handle: engine.workflow(plan)?,
            resume_handle,
            resume_driver,
            driver,
            ledger,
            call: tokio::sync::Mutex::new(()),
        })
    }

    /// Stable identity of the exact journal plan and account binding.
    #[must_use]
    pub fn id(&self) -> WorkflowId {
        self.handle.id()
    }

    fn observation_error(&self, cause: NativePaymentObservationError) -> NativePaymentError {
        NativePaymentError::Observation {
            cause: Box::new(cause),
            progress: self.handle.progress().ok().flatten().map(Box::new),
        }
    }

    fn finish_verified(
        &self,
        receipt: VerifiedPaymentReceipt,
    ) -> Result<NativePaymentSettlement, NativePaymentError> {
        let completion = completion(&receipt, self.ledger.request.digest)
            .map_err(|e| self.observation_error(e))?;
        let carrier = self.handle.record_native_payment_completion(&completion)?;
        Ok(NativePaymentSettlement { receipt, carrier })
    }

    async fn existing_receipt(&self) -> Result<Option<VerifiedPaymentReceipt>, NativePaymentError> {
        let journal = self.handle.journal_snapshot()?;
        let marker = journal
            .as_ref()
            .and_then(|journal| journal.native_payment_completion.as_ref());
        let receipt = self
            .ledger
            .recover_business(marker)
            .await
            .map_err(|e| self.observation_error(e))?;
        if let Some(marker) = marker {
            let Some(receipt) = &receipt else {
                return Err(
                    self.observation_error(NativePaymentObservationError::CompletionMismatch)
                );
            };
            if &completion(receipt, self.ledger.request.digest)
                .map_err(|e| self.observation_error(e))?
                != marker
            {
                return Err(
                    self.observation_error(NativePaymentObservationError::CompletionMismatch)
                );
            }
        }
        Ok(receipt)
    }

    /// Explicitly authorize submission of a paid attempt using the exact retained fee intent.
    ///
    /// This may create and sign a new carrier when this gateway has no original journal.
    /// An earlier rejected attempt can already have paid a fee. Replacing a known rejected
    /// local carrier additionally requires `retry_rejected_step`; its default remains false.
    /// Existing successful business settlement is independently recovered before any signing.
    /// Use `resume` for unknown-outcome recovery with no new carrier authorization.
    /// # Errors
    /// Original typed read/verification failures, journal errors or unresolved success.
    pub async fn submit(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentSettlement, NativePaymentError> {
        self.advance(options, true).await
    }

    /// Resume only an original retained signed carrier, without building or signing a new one.
    ///
    /// A fresh gateway may recover an independently verified original success. Otherwise an
    /// absent/unsigned journal requires explicit `submit` authorization. Rejected identities
    /// are never replaced here, even if options request replacement. Exact-byte retransmission
    /// keeps the existing exact-absence and unknown-outcome reconciliation rules.
    /// # Errors
    /// `NewAttemptAuthorizationRequired` without an original carrier or verified success;
    /// otherwise the original typed journal, observation or terminal rejection failure.
    pub async fn resume(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentSettlement, NativePaymentError> {
        self.advance(options, false).await
    }

    async fn advance(
        &self,
        options: &NativePaymentRunOptions,
        authorize_submission: bool,
    ) -> Result<NativePaymentSettlement, NativePaymentError> {
        let _call = self.call.lock().await;
        self.ledger
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        if let Some(receipt) = self.existing_receipt().await? {
            return self.finish_verified(receipt);
        }
        let result = if authorize_submission {
            self.handle
                .run(self.driver.as_ref(), &options.workflow)
                .await
        } else {
            let journal = self.handle.journal_snapshot()?;
            if journal
                .as_ref()
                .and_then(|journal| journal.steps.first())
                .and_then(|step| step.transaction.as_ref())
                .and_then(|transaction| transaction.attempts.last())
                .and_then(|attempt| attempt.identity.as_ref())
                .is_none()
            {
                return Err(NativePaymentError::NewAttemptAuthorizationRequired {
                    progress: journal.as_ref().map(|journal| Box::new(journal.progress())),
                });
            }
            let mut resume_options = options.workflow;
            resume_options.retry_rejected_step = false;
            self.resume_handle
                .run(&self.resume_driver, &resume_options)
                .await
        };
        let original_error = self.ledger.take_error()?;
        if let Some(receipt) = self.ledger.take_receipt()? {
            return self.finish_verified(receipt);
        }
        let recovery = self.existing_receipt().await;
        if let Ok(Some(receipt)) = recovery {
            return self.finish_verified(receipt);
        }
        if let Some(cause) = original_error {
            return Err(self.observation_error(cause));
        }
        recovery?;
        match result {
            Err(error) => Err(error.into()),
            Ok(progress) => Err(NativePaymentError::Unresolved {
                progress: Some(Box::new(progress)),
            }),
        }
    }

    /// Recover without building, signing or dispatching; verify any stored completion again.
    /// # Errors
    /// Journal or original typed read/verification failures. No failure authorizes another identity.
    pub async fn recover(
        &self,
        options: &NativePaymentRunOptions,
    ) -> Result<NativePaymentRecovery, NativePaymentError> {
        let _call = self.call.lock().await;
        self.ledger
            .begin_call(options.max_finality_proof_reads.get() as usize)?;
        if let Some(receipt) = self.existing_receipt().await? {
            let settled = self.finish_verified(receipt)?;
            return Ok(NativePaymentRecovery {
                carrier: Some(settled.carrier),
                receipt: Some(settled.receipt),
            });
        }
        let carrier_result = if self.handle.progress()?.is_some() {
            self.handle
                .recover(Some(self.driver.as_ref()), &options.workflow)
                .await
                .map(Some)
        } else {
            Ok(None)
        };
        let original_error = self.ledger.take_error()?;
        let recovery = match self.ledger.take_receipt()? {
            Some(receipt) => Ok(Some(receipt)),
            None => self.existing_receipt().await,
        };
        if let Ok(Some(receipt)) = recovery {
            let settled = self.finish_verified(receipt)?;
            return Ok(NativePaymentRecovery {
                carrier: Some(settled.carrier),
                receipt: Some(settled.receipt),
            });
        }
        if let Some(cause) = original_error {
            return Err(self.observation_error(cause));
        }
        recovery?;
        carrier_result?;
        Ok(NativePaymentRecovery {
            carrier: self.handle.progress()?,
            receipt: None,
        })
    }
}

fn driver_identity() -> DriverIdentityV1 {
    DriverIdentityV1 {
        id: "native_payment".into(),
        schema_version: 1,
    }
}
struct NativePaymentDriver {
    account: AccountClient,
    request: NativePaymentRequest,
}
impl WorkflowDriver for NativePaymentDriver {
    fn identity(&self) -> DriverIdentityV1 {
        driver_identity()
    }
    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            if context.descriptor.intent_digest != self.request.digest {
                return Err(StepFailure::new(
                    WorkflowErrorCode::BindingMismatch,
                    "native payment request changed",
                ));
            }
            let draft = AccountTransactionDraft::new(
                vec![iroha_data_model::isi::InstructionBox::from(
                    SettlementInstructionBox::Atomic(self.request.intent.clone()),
                )],
                self.request.fee_payment.clone(),
                Metadata::default(),
            );
            let payload = self
                .account
                .prepare_transaction(draft)
                .map_err(|error| super::workflow_ledger::signing_failure(&error))?;
            let unsigned_payload = norito::encode_canonical(&payload).map_err(|error| {
                StepFailure::new(
                    if matches!(error, norito::Error::AllocationFailed { .. }) {
                        WorkflowErrorCode::LocalResourceUnavailable
                    } else {
                        WorkflowErrorCode::InvalidInput
                    },
                    error.to_string(),
                )
            })?;
            Ok(BuiltStepPayload {
                intent_digest: self.request.digest,
                unsigned_payload,
            })
        })
    }
}

fn completion(
    receipt: &VerifiedPaymentReceipt,
    request_digest: Digest32,
) -> Result<NativePaymentCompletionV1, NativePaymentObservationError> {
    let bytes = norito::encode_canonical(&(
        receipt.settlement().clone(),
        receipt.nexus_fee_receipt().cloned(),
    ))
    .map_err(NativePaymentObservationError::Encoding)?;
    Ok(NativePaymentCompletionV1 {
        network: *receipt.network().as_bytes(),
        request_digest,
        transaction_hash: *Hash::from(receipt.transaction_hash()).as_ref(),
        block_height: receipt.settlement().block_height,
        block_hash: *Hash::from(receipt.settlement().block_hash).as_ref(),
        context_id: *receipt.context_id().as_ref(),
        receipt_digest: domain_digest(b"iroha:native-payment:receipt:v1\0", &[&bytes]),
    })
}
