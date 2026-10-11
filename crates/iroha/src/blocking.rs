//! Explicit blocking facade for the asynchronous Iroha SDK transport.

// TODO: Move the remaining synchronous read/query operations out
// of `client::Client`, then expose their canonical forms only through this facade.

pub mod account_bootstrap;
mod collections;
pub mod configuration;
pub mod consensus;
pub mod data_availability;
pub mod funding;
pub mod kagemusha;
pub mod musubi;
pub mod nexus;
pub mod sccp;
pub mod status;
pub mod streams;
mod subscriptions;
pub use collections::CollectionIter;
pub use subscriptions::{AccountSubscriptions, Subscriptions};

use std::{future::Future, sync::Arc};

use eyre::{Result, WrapErr, eyre};
use iroha_crypto::{HashOf, KeyPair, PrivateKey};
use iroha_data_model::{
    Identifiable,
    account::AccountId,
    alias_setup::{
        AliasLifecycleTransactionPlanV1, AliasSetupPlanRequestV1, AliasTransactionPlanV1,
    },
    isi::{InstructionBox, register::RegisterBox},
    smart_contract::{ContractAddress, ContractAlias},
    transaction::{FeePaymentIntent, SignedTransaction},
};
use iroha_model_base::metadata::Metadata;
use iroha_torii_shared::{
    FeeQuoteResponse, validation_fee_api::ValidationFeeProposalDraftRequestV1,
};
use thiserror::Error;

use crate::{
    client::{
        AccountClient as AsyncAccountClient, Client as AsyncClient, ContractCallDraftIntent,
        FeeQuoteRequest, OperatorClient as AsyncOperatorClient, PreparedTransactionPayload,
        SorafsPinRegisterArgs, TransactionWaitOptions, TransactionWaitOutcome,
        validate_validation_fee_draft_response,
    },
    config::Config,
    http::HttpTransport,
};

/// Tokio runtime kind in which a blocking SDK call was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncRuntimeFlavor {
    /// A Tokio current-thread runtime.
    CurrentThread,
    /// A Tokio multi-thread runtime.
    MultiThread,
    /// A future Tokio runtime kind unknown to this SDK release.
    Unknown,
}

impl std::fmt::Display for AsyncRuntimeFlavor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CurrentThread => "current-thread",
            Self::MultiThread => "multi-thread",
            Self::Unknown => "unknown",
        })
    }
}

/// Structured failure returned when a blocking SDK call cannot run safely.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BlockingCallError {
    /// The caller is already executing inside a Tokio runtime.
    #[error("blocking Iroha SDK call rejected inside a Tokio {flavor} runtime")]
    AsyncRuntime {
        /// Runtime kind observed by the SDK.
        flavor: AsyncRuntimeFlavor,
    },
    /// The facade runtime has already shut down.
    #[error("blocking Iroha SDK runtime is unavailable")]
    RuntimeUnavailable,
}

impl BlockingCallError {
    /// Return the runtime kind for an async-context rejection.
    #[must_use]
    pub const fn async_runtime_flavor(self) -> Option<AsyncRuntimeFlavor> {
        match self {
            Self::AsyncRuntime { flavor } => Some(flavor),
            Self::RuntimeUnavailable => None,
        }
    }
}

pub(crate) fn reject_inside_async_runtime() -> std::result::Result<(), BlockingCallError> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Ok(());
    };
    let flavor = match handle.runtime_flavor() {
        tokio::runtime::RuntimeFlavor::CurrentThread => AsyncRuntimeFlavor::CurrentThread,
        tokio::runtime::RuntimeFlavor::MultiThread => AsyncRuntimeFlavor::MultiThread,
        _ => AsyncRuntimeFlavor::Unknown,
    };
    Err(BlockingCallError::AsyncRuntime { flavor })
}

#[derive(Debug)]
struct RuntimeOwner {
    runtime: Option<tokio::runtime::Runtime>,
    #[cfg(test)]
    runs: std::sync::atomic::AtomicUsize,
}

impl RuntimeOwner {
    fn new() -> crate::Result<Self> {
        // Shared async clients can reuse HTTP connections opened by this facade
        // from another runtime. Their I/O drivers must keep running between
        // block_on calls; a current-thread runtime parks those drivers.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("iroha-sdk-blocking")
            .enable_all()
            .build()
            .map_err(|error| crate::Error::BlockingRuntimeConstruction {
                details: error.to_string(),
            })?;
        Ok(Self {
            runtime: Some(runtime),
            #[cfg(test)]
            runs: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn block_on<F: Future>(&self, future: F) -> std::result::Result<F::Output, BlockingCallError> {
        reject_inside_async_runtime()?;
        // Tokio supports concurrent Runtime::block_on calls.
        // A pending stream must not hold a lock over unrelated operations. This
        // borrow keeps the owner alive; only exclusive Drop takes the runtime.
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(BlockingCallError::RuntimeUnavailable)?;
        #[cfg(test)]
        self.runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(runtime.block_on(future))
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        let runtime = self.runtime.take();
        if let Some(runtime) = runtime {
            // This never blocks and is safe even if the final facade handle is
            // dropped while another Tokio runtime is entered.
            runtime.shutdown_background();
        }
    }
}

/// Blocking client context backed by one reusable owned Tokio runtime.
///
/// One worker continues driving connections and tasks between blocking calls,
/// including connections reused by the borrowed asynchronous client. This does
/// not drive connections previously opened on another caller-owned runtime.
#[derive(Clone, Debug)]
pub struct Client {
    inner: AsyncClient,
    account: AsyncAccountClient,
    runtime: Arc<RuntimeOwner>,
}

/// Immutable blocking account context backed by one reusable owned runtime.
#[derive(Clone, Debug)]
pub struct AccountClient {
    inner: AsyncAccountClient,
    runtime: Arc<RuntimeOwner>,
}

impl AccountClient {
    /// Read a committed current wallet head for independent finality verification.
    /// # Errors
    /// Returns authentication, response-validation, transport or runtime errors.
    pub fn retail_fee_statement_head(
        &self,
        account: &AccountId,
    ) -> Result<crate::client::RetailFeeCurrentHeadResponseV1> {
        self.runtime
            .block_on(self.inner.retail_fee_statement_head(account))?
    }
    /// Read and verify a contiguous page from a previously authenticated receipt cursor.
    /// # Errors
    /// Returns cursor, chain-verification, authentication, transport or runtime errors.
    pub fn retail_fee_statement_page(
        &self,
        account: &AccountId,
        request: &crate::client::RetailFeeStatementRequestV1,
    ) -> Result<crate::client::RetailFeeStatementResponseV1> {
        self.runtime
            .block_on(self.inner.retail_fee_statement_page(account, request))?
    }
    /// Read evaluated retail monthly status using this bound account and reusable runtime.
    /// # Errors
    /// Returns canonical authentication, transport, response validation, or runtime errors.
    pub fn retail_fee_status(
        &self,
        account: &AccountId,
    ) -> Result<crate::client::RetailFeeStatusResponseV1> {
        self.runtime
            .block_on(self.inner.retail_fee_status(account))?
    }
    /// Quote an exact ordered retail payment intent using this bound account.
    /// # Errors
    /// Returns canonical authentication, transport, intent validation, or runtime errors.
    pub fn retail_fee_quote(
        &self,
        request: &iroha_data_model::validation_fee::RetailFeeQuoteRequestV1,
    ) -> Result<crate::client::RetailFeeQuoteResponseV1> {
        self.runtime
            .block_on(self.inner.retail_fee_quote(request))?
    }
    /// Read bounded receipt membership evidence for independent checkpoint verification.
    /// # Errors
    /// Returns page validation, authentication, transport, or runtime errors.
    pub fn retail_fee_receipts(
        &self,
        account: &AccountId,
        after_receipt_id: Option<&str>,
        limit: u32,
    ) -> Result<crate::client::RetailFeeReceiptsResponseV1> {
        self.runtime.block_on(
            self.inner
                .retail_fee_receipts(account, after_receipt_id, limit),
        )?
    }
    /// Own a blocking facade for an already validated asynchronous account context.
    ///
    /// # Errors
    /// Returns a structured error if the owned runtime cannot be constructed.
    pub fn from_client(client: AsyncAccountClient) -> crate::Result<Self> {
        let runtime = RuntimeOwner::new()?;
        Ok(Self {
            inner: client,
            runtime: Arc::new(runtime),
        })
    }
}

impl Client {
    /// Construct an isolated blocking client context.
    ///
    /// # Errors
    /// Returns an error if account authority binding fails or the owned runtime
    /// cannot be created.
    pub fn new(configuration: Config) -> Result<Self> {
        Self::from_client(AsyncClient::builder(configuration).build()?)
    }

    /// Construct an isolated blocking context with a custom HTTP transport.
    ///
    /// # Errors
    /// Returns an error if account authority binding fails or the owned runtime
    /// cannot be created.
    pub fn with_http_transport(
        configuration: Config,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self> {
        Self::from_client(
            AsyncClient::builder(configuration)
                .http_transport(transport)
                .build()?,
        )
    }

    /// Wrap an asynchronous client context in the explicit blocking facade.
    ///
    /// # Errors
    /// Returns an error if account authority binding fails or the owned runtime
    /// cannot be created.
    pub fn from_client(client: AsyncClient) -> Result<Self> {
        let account = client
            .account_client()
            .wrap_err("failed to bind blocking account authority")?;
        Ok(Self {
            inner: client,
            account,
            runtime: Arc::new(RuntimeOwner::new()?),
        })
    }

    /// Clone this exact context with one absolute HTTP deadline and its original runtime owner.
    ///
    /// Connection pools and compatibility state remain shared with the source. The immutable
    /// account context is freshly bound to the bounded asynchronous client. Reapplying a deadline
    /// can only shorten it; dropping either view leaves the other view's I/O driver alive.
    /// CPU work and polling sleeps require their own bounds.
    ///
    /// # Errors
    /// Returns an error if account authority binding fails. An elapsed deadline is retained and
    /// causes subsequent HTTP dispatch to fail without contacting the transport.
    pub fn with_request_deadline(&self, deadline: std::time::Instant) -> Result<Self> {
        let inner = self.inner.with_request_deadline(deadline);
        let account = inner
            .account_client()
            .wrap_err("failed to bind blocking account authority")?;
        Ok(Self {
            inner,
            account,
            runtime: Arc::clone(&self.runtime),
        })
    }

    /// Borrow the underlying asynchronous client for local transaction builders
    /// and context inspection.
    #[must_use]
    pub const fn client(&self) -> &AsyncClient {
        &self.inner
    }

    /// Borrow the immutable asynchronous account context.
    #[must_use]
    pub const fn account_client(&self) -> &AsyncAccountClient {
        &self.account
    }

    /// Bind an explicit operator authority to this blocking context.
    ///
    /// # Errors
    /// Returns an error when the endpoint, network, or authority configuration
    /// is invalid.
    pub fn operator_client(&self, key_pair: KeyPair) -> Result<OperatorClient> {
        Ok(OperatorClient {
            inner: self.inner.operator_client(key_pair)?,
            runtime: Arc::clone(&self.runtime),
        })
    }

    /// Submit one signed transaction and return after Torii accepts it.
    ///
    /// # Errors
    /// Returns compatibility, signing, transport, rejection, ambiguity, or
    /// [`BlockingCallError`] failures.
    pub fn submit_transaction(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<HashOf<SignedTransaction>> {
        self.runtime
            .block_on(self.account.submit_transaction(transaction))?
    }

    /// Submit one signed transaction and wait for state-resolved `Applied` finality.
    ///
    /// Queue-plan ambiguity is retained while finality is reconciled and attached
    /// to an unresolved confirmation error without replaying the transaction.
    ///
    /// # Errors
    /// Returns compatibility, transport, rejection, expiry, timeout, ambiguity,
    /// or [`BlockingCallError`] failures.
    pub fn submit_transaction_and_wait(
        &self,
        transaction: &SignedTransaction,
    ) -> Result<HashOf<SignedTransaction>> {
        self.runtime
            .block_on(self.account.submit_transaction_and_wait(transaction))?
    }

    /// Register one `SoraFS` pin manifest through the account-bound workflow.
    ///
    /// # Errors
    /// Returns local validation, fee quote, signing, transport, Torii rejection,
    /// or [`BlockingCallError`] failures.
    pub fn post_sorafs_pin_register(
        &self,
        params: SorafsPinRegisterArgs<'_>,
    ) -> Result<norito::json::Value> {
        self.runtime
            .block_on(self.account.post_sorafs_pin_register(params))?
    }

    /// Quote the exact fee intent for one unsigned transaction payload.
    ///
    /// # Errors
    /// Returns authorization, binding, transport, response, or
    /// [`BlockingCallError`] failures.
    pub fn quote_fees(&self, request: FeeQuoteRequest<'_>) -> Result<FeeQuoteResponse> {
        self.runtime.block_on(self.account.quote_fees(request))?
    }

    /// Build, submit, and wait for one instruction to reach `Applied` finality.
    ///
    /// # Errors
    /// Returns building, fee, signing, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit<I>(
        &self,
        instruction: I,
        fee_payment: FeePaymentIntent,
    ) -> Result<HashOf<SignedTransaction>>
    where
        I: Into<InstructionBox>,
    {
        self.submit_all(core::iter::once(instruction), fee_payment)
    }

    /// Build, submit, and wait for instructions to reach `Applied` finality.
    ///
    /// # Errors
    /// Returns building, fee, signing, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_all<I>(
        &self,
        instructions: impl IntoIterator<Item = I>,
        fee_payment: FeePaymentIntent,
    ) -> Result<HashOf<SignedTransaction>>
    where
        I: Into<InstructionBox>,
    {
        self.submit_all_with_metadata(instructions, fee_payment, Metadata::default())
    }

    /// Build, submit, and wait for one instruction with transaction metadata.
    ///
    /// # Errors
    /// Returns building, fee, signing, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_with_metadata<I>(
        &self,
        instruction: I,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
    ) -> Result<HashOf<SignedTransaction>>
    where
        I: Into<InstructionBox>,
    {
        self.submit_all_with_metadata(core::iter::once(instruction), fee_payment, metadata)
    }

    /// Build, submit, and wait for instructions with transaction metadata.
    ///
    /// # Errors
    /// Returns building, fee, signing, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_all_with_metadata<I>(
        &self,
        instructions: impl IntoIterator<Item = I>,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
    ) -> Result<HashOf<SignedTransaction>>
    where
        I: Into<InstructionBox>,
    {
        const MULTISIG_SIGNATORY: &str = "MULTISIG_SIGNATORY";
        reject_inside_async_runtime()?;
        let instructions: Vec<InstructionBox> = instructions.into_iter().map(Into::into).collect();
        for instruction in &instructions {
            if let Some(RegisterBox::Role(register_role)) =
                instruction.as_any().downcast_ref::<RegisterBox>()
                && {
                    let name = register_role.object().id().name().as_ref();
                    name == MULTISIG_SIGNATORY
                        || name
                            .strip_prefix(MULTISIG_SIGNATORY)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                }
            {
                return Err(eyre!(
                    "reserved multisig role names may not be registered by clients"
                ));
            }
        }
        let mut payload =
            self.account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    instructions,
                    fee_payment,
                    metadata,
                ))?;
        let quote = self.runtime.block_on(
            self.account
                .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload }),
        )??;
        crate::client::apply_fee_quote_intent(&mut payload, quote.intent)
            .wrap_err("apply exact fee quote to transaction payload")?;
        let transaction = self.account.sign_transaction(payload)?;
        self.submit_transaction_and_wait(&transaction)
    }

    /// Send a canonical-account-signed alias setup planning request.
    ///
    /// Uses this facade's owned runtime for asynchronous HTTP transport.
    ///
    /// # Errors
    /// Returns request signing, transport, or [`BlockingCallError`] failures.
    pub fn post_alias_setup_plan(
        &self,
        request: &AliasSetupPlanRequestV1,
    ) -> Result<crate::http::Response<Vec<u8>>> {
        self.runtime
            .block_on(self.inner.post_alias_setup_plan(request))?
    }

    /// Request and verify an alias setup plan against the complete request.
    ///
    /// # Errors
    /// Returns request, transport, plan verification, or [`BlockingCallError`] failures.
    pub fn plan_alias_setup(
        &self,
        request: &AliasSetupPlanRequestV1,
    ) -> Result<AliasTransactionPlanV1> {
        self.runtime
            .block_on(self.inner.plan_alias_setup(request))?
    }

    /// Verify and submit one alias setup plan, then wait for `Applied` finality.
    ///
    /// # Errors
    /// Returns plan verification, building, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_alias_setup_plan(
        &self,
        plan: &AliasTransactionPlanV1,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
    ) -> Result<HashOf<SignedTransaction>> {
        let instructions = self.inner.verify_alias_setup_plan(plan)?;
        self.submit_all_with_metadata(instructions, fee_payment, metadata)
            .wrap_err("submit and confirm verified alias setup plan")
    }

    /// Verify and submit one alias lifecycle plan, then wait for `Applied` finality.
    ///
    /// A verified no-op returns `None` without creating a transaction.
    ///
    /// # Errors
    /// Returns plan verification, building, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_alias_lifecycle_plan(
        &self,
        plan: &AliasLifecycleTransactionPlanV1,
        fee_payment: FeePaymentIntent,
        metadata: Metadata,
    ) -> Result<Option<HashOf<SignedTransaction>>> {
        let Some(instruction) = self.inner.verify_alias_lifecycle_plan(plan)? else {
            return Ok(None);
        };
        self.submit_all_with_metadata([instruction], fee_payment, metadata)
            .map(Some)
            .wrap_err("submit and confirm verified alias lifecycle plan")
    }

    /// Draft, verify, submit, and confirm one native validation-fee proposal.
    ///
    /// # Errors
    /// Returns draft validation, building, submission, finality, or
    /// [`BlockingCallError`] failures.
    pub fn submit_validation_fee_proposal(
        &self,
        request: &ValidationFeeProposalDraftRequestV1,
        fee_payment: FeePaymentIntent,
    ) -> Result<HashOf<SignedTransaction>> {
        let response = self.inner.post_validation_fee_proposal_draft(request)?;
        let instruction = validate_validation_fee_draft_response(&response, request)?;
        self.submit(instruction, fee_payment)
    }

    /// Submit one prepared transaction payload and return after acceptance.
    ///
    /// # Errors
    /// Returns compatibility, transport, rejection, ambiguity, or
    /// [`BlockingCallError`] failures.
    pub fn submit_prepared_transaction_payload(
        &self,
        payload: &PreparedTransactionPayload,
    ) -> Result<HashOf<SignedTransaction>> {
        self.runtime
            .block_on(self.account.submit_prepared_transaction_payload(payload))?
    }

    /// Submit prepared transaction payloads as one batch.
    ///
    /// # Errors
    /// Returns compatibility, transport, rejection, acknowledgement, or
    /// [`BlockingCallError`] failures.
    pub fn submit_prepared_transaction_payload_batch(
        &self,
        payloads: &[PreparedTransactionPayload],
    ) -> Result<Vec<HashOf<SignedTransaction>>> {
        self.runtime.block_on(
            self.account
                .submit_prepared_transaction_payload_batch(payloads),
        )?
    }

    /// Prepare, verify, and optionally sign and submit one contract call.
    ///
    /// # Errors
    /// Returns request, draft-validation, signing, submission, or
    /// [`BlockingCallError`] failures.
    #[expect(
        clippy::too_many_arguments,
        reason = "the facade preserves the exact contract-call request binding"
    )]
    pub fn post_contract_call_json(
        &self,
        authority: &AccountId,
        private_key: Option<&PrivateKey>,
        contract_address: Option<&ContractAddress>,
        contract_alias: Option<&ContractAlias>,
        entrypoint: &str,
        payload: Option<&norito::json::Value>,
        caller_metadata: Option<&Metadata>,
        creation_time_ms: Option<u64>,
        transaction_ttl_ms: Option<u64>,
        fee_payment: &FeePaymentIntent,
        draft_intent: &ContractCallDraftIntent,
    ) -> Result<norito::json::Value> {
        self.runtime.block_on(self.account.post_contract_call_json(
            authority,
            private_key,
            contract_address,
            contract_alias,
            entrypoint,
            payload,
            caller_metadata,
            creation_time_ms,
            transaction_ttl_ms,
            fee_payment,
            draft_intent,
        ))?
    }

    /// Wait for a transaction to reach state-resolved `Applied` finality.
    ///
    /// # Errors
    /// Returns status, rejection, expiry, timeout, transport, or
    /// [`BlockingCallError`] failures.
    pub fn wait_for_transaction_applied(
        &self,
        hash: HashOf<SignedTransaction>,
        options: TransactionWaitOptions,
    ) -> Result<TransactionWaitOutcome> {
        self.runtime
            .block_on(self.inner.wait_until_transaction_applied(hash, options))?
    }

    /// Wait for the configured peer's exact local, state-resolved `Applied` observation.
    ///
    /// No global fanout is used; local rejection/expiry does not constitute global finality
    /// failure evidence. The native shared waiter retains one absolute request deadline.
    ///
    /// # Errors
    /// Returns status, binding, local terminal observation, deadline, transport, or
    /// [`BlockingCallError`] failures.
    pub fn wait_for_transaction_applied_local(
        &self,
        hash: HashOf<SignedTransaction>,
        options: TransactionWaitOptions,
    ) -> Result<TransactionWaitOutcome> {
        self.runtime.block_on(
            self.inner
                .wait_until_transaction_applied_local(hash, options),
        )?
    }

    /// Refresh the context-local node compatibility decision.
    ///
    /// # Errors
    /// Returns a typed compatibility, capability-probe, or
    /// [`BlockingCallError`] failure.
    pub fn refresh_capabilities(&self) -> Result<()> {
        self.runtime.block_on(self.inner.refresh_capabilities())?
    }
}

/// Explicit blocking facade for an immutable operator authority context.
#[derive(Clone, Debug)]
pub struct OperatorClient {
    inner: AsyncOperatorClient,
    runtime: Arc<RuntimeOwner>,
}

impl OperatorClient {
    /// Own a blocking facade for an already bound asynchronous operator context.
    ///
    /// Account credentials are not required or inspected. Clones share the
    /// facade's owned runtime and immutable operator context.
    ///
    /// # Errors
    /// Returns a structured error if the owned runtime cannot be constructed.
    pub fn from_client(client: AsyncOperatorClient) -> crate::Result<Self> {
        Ok(Self {
            inner: client,
            runtime: Arc::new(RuntimeOwner::new()?),
        })
    }

    /// Inspect node-local proof retention configuration and live counters.
    ///
    /// # Errors
    /// Returns signing, transport, response-validation, or
    /// [`BlockingCallError`] failures.
    pub fn get_proof_retention_status(&self) -> Result<iroha_torii_shared::ProofRetentionStatus> {
        self.runtime
            .block_on(self.inner.get_proof_retention_status())?
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use iroha_data_model::transaction::FeePaymentIntent;
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_service_model::soranet::{AnonymityPolicy, RolloutPhase};
    use iroha_test_samples::gen_account_in;
    use iroha_torii_shared::{PipelineTransactionStatus, PipelineTransactionStatusResponse};

    use super::*;
    use crate::{
        client::test_network_id,
        http::{Response, TransportFuture, TransportRequest},
    };

    fn config_factory() -> Config {
        let (account, key_pair) = gen_account_in("wonderland");
        Config {
            chain: ChainId::from("00000000-0000-0000-0000-000000000000"),
            network_id: test_network_id(),
            account,
            account_chain_discriminant: iroha_torii_shared::MINAMOTO_CHAIN_DISCRIMINANT,
            key_pair,
            basic_auth: None,
            api_token: None,
            torii_api_url: "http://127.0.0.1:8080".parse().expect("test URL"),
            torii_request_timeout: crate::config::DEFAULT_TORII_REQUEST_TIMEOUT,
            transaction_ttl: std::time::Duration::from_secs(5),
            transaction_status_timeout: std::time::Duration::from_secs(10),
            transaction_add_nonce: false,
            sorafs_alias_cache: crate::client::default_alias_policy(),
            sorafs_anonymity_policy: AnonymityPolicy::GuardPq,
            sorafs_rollout_phase: RolloutPhase::Canary,
        }
    }

    #[derive(Debug)]
    struct AsyncAcceptTransport {
        async_sends: Arc<AtomicUsize>,
        runtime_threads: Arc<Mutex<Vec<std::thread::ThreadId>>>,
    }

    impl HttpTransport for AsyncAcceptTransport {
        fn send_blocking(&self, _request: TransportRequest) -> Result<Response<Vec<u8>>> {
            panic!("blocking facade must use only the asynchronous transport")
        }

        fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
            self.async_sends.fetch_add(1, Ordering::Relaxed);
            self.runtime_threads
                .lock()
                .expect("runtime thread log")
                .push(std::thread::current().id());
            let response = match request.url.path() {
                "/v1/node/capabilities" => Response::builder()
                    .status(http::StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(crate::client::compatible_capabilities_body().into_bytes())
                    .expect("capability response"),
                "/v1/pipeline/transactions/status" => {
                    let hash = request
                        .url
                        .query_pairs()
                        .find_map(|(key, value)| (key == "hash").then(|| value.into_owned()))
                        .expect("status request hash");
                    let payload = PipelineTransactionStatusResponse::new(
                        hash,
                        PipelineTransactionStatus {
                            kind: "Applied".to_owned(),
                            block_height: Some(7),
                        },
                        "global".to_owned(),
                        "state".to_owned(),
                    );
                    let body = norito::json::to_string(
                        &norito::json::to_value(&payload).expect("status response value"),
                    )
                    .expect("status response body");
                    Response::builder()
                        .status(http::StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(body.into_bytes())
                        .expect("status response")
                }
                "/v1/fees/quote" => {
                    let request: iroha_torii_shared::FeeQuoteRequest =
                        norito::json::from_slice(&request.body).expect("fee quote request body");
                    let payload = request.payload;
                    let quote = FeeQuoteResponse {
                        intent: payload.fee_payment_intent().clone(),
                        observation: iroha_torii_shared::FeeQuoteObservation {
                            ledger_time_ms: 1,
                            next_block_height: 1,
                            route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                        },
                        components: Vec::new(),
                        capacities: Vec::new(),
                        decision: iroha_torii_shared::FeeQuoteDecision::Accepted {
                            debit_source: iroha_data_model::nexus::FeeDebitSource::Account(
                                payload.authority().clone(),
                            ),
                            program_revision: None,
                        },
                    };
                    Response::builder()
                        .status(http::StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(norito::json::to_vec(&quote).expect("fee quote response body"))
                        .expect("fee quote response")
                }
                _ => Response::new(Vec::new()),
            };
            Box::pin(async move { Ok(response) })
        }
    }

    fn accepting_client() -> (
        Client,
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<std::thread::ThreadId>>>,
    ) {
        let async_sends = Arc::new(AtomicUsize::new(0));
        let runtime_threads = Arc::new(Mutex::new(Vec::new()));
        let async_client = AsyncClient::builder(config_factory())
            .http_transport(Arc::new(AsyncAcceptTransport {
                async_sends: Arc::clone(&async_sends),
                runtime_threads: Arc::clone(&runtime_threads),
            }))
            .build()
            .expect("valid client configuration");
        (
            Client::from_client(async_client).expect("blocking client"),
            async_sends,
            runtime_threads,
        )
    }

    #[test]
    fn one_owned_runtime_is_reused_across_calls_and_clones() {
        let (client, async_sends, runtime_threads) = accepting_client();
        let clone = client.clone();
        assert!(Arc::ptr_eq(&client.runtime, &clone.runtime));
        let transaction = {
            let account = client.account_client();
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    Vec::<iroha_data_model::isi::InstructionBox>::new(),
                    FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build transaction");

        client
            .refresh_capabilities()
            .expect("blocking capability refresh");
        client
            .submit_transaction(&transaction)
            .expect("first blocking submission");
        clone
            .submit_transaction(&transaction)
            .expect("second blocking submission");

        assert_eq!(
            async_sends.load(Ordering::Relaxed),
            3,
            "one compatibility probe and two transaction submissions expected"
        );
        assert_eq!(
            client.runtime.runs.load(Ordering::Relaxed),
            3,
            "refresh and both submissions must enter the shared runtime"
        );
        let threads = runtime_threads.lock().expect("runtime thread log");
        assert_eq!(threads.len(), 3);
        assert!(threads.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn deadline_views_keep_original_driver_alive_in_both_lifetime_directions() {
        use std::{sync::mpsc, time::Duration};

        struct NotifyDrop(mpsc::Sender<()>);
        impl Drop for NotifyDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let (source, _, _) = accepting_client();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let temporary = source.with_request_deadline(deadline).unwrap();
        assert!(Arc::ptr_eq(&source.runtime, &temporary.runtime));
        assert!(
            source
                .inner
                .http_transport
                .shares_pools_with(&temporary.inner.http_transport)
        );
        let owner = Arc::downgrade(&source.runtime);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (first_tx, first_rx) = tokio::sync::oneshot::channel();
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        #[allow(clippy::async_yields_async)]
        let task = temporary
            .runtime
            .block_on(async move {
                let task = tokio::spawn(async move {
                    let _notify_drop = NotifyDrop(dropped_tx);
                    started_tx.send(()).unwrap();
                    first_rx.await.unwrap();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    progress_tx.send(1).unwrap();
                    second_rx.await.unwrap();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    progress_tx.send(2).unwrap();
                    std::future::pending::<()>().await;
                });
                started_rx.await.unwrap();
                task
            })
            .unwrap();
        drop(temporary);
        first_tx.send(()).unwrap();
        assert_eq!(
            progress_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            1,
            "the source must keep driving work opened by the temporary view"
        );
        let retained = source.with_request_deadline(deadline).unwrap();
        assert!(Arc::ptr_eq(&source.runtime, &retained.runtime));
        drop(source);
        assert!(owner.upgrade().is_some());
        second_tx.send(()).unwrap();
        assert_eq!(
            progress_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            2,
            "the deadline view must keep driving work after its source drops"
        );
        assert!(matches!(
            dropped_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(retained);
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(owner.upgrade().is_none());
        let external = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(
            external
                .block_on(async { tokio::time::timeout(Duration::from_secs(2), task).await })
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
    }

    #[test]
    fn deadline_views_preserve_account_dispatch_bounds_and_leave_source_unchanged() {
        use std::time::{Duration, Instant};

        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-deadline-fixture".to_owned(), "retained".to_owned());
        let asynchronous = AsyncClient::builder(config_factory())
            .headers(headers)
            .build()
            .unwrap()
            .with_test_http_transport(crate::http_default::DefaultHttpTransport::mock(Arc::new(
                move |request| {
                    let body = if request.url.path() == "/v1/node/capabilities" {
                        crate::client::compatible_capabilities_body().into_bytes()
                    } else {
                        Vec::new()
                    };
                    observed.lock().unwrap().push(request);
                    Ok(Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .unwrap())
                },
            )));
        let source = Client::from_client(asynchronous).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let bounded = source.with_request_deadline(deadline).unwrap();
        let repeated = bounded
            .with_request_deadline(deadline + Duration::from_secs(30))
            .unwrap();
        let shortened_deadline = deadline - Duration::from_secs(10);
        let shortened = repeated.with_request_deadline(shortened_deadline).unwrap();
        for view in [&bounded, &repeated, &shortened] {
            assert!(Arc::ptr_eq(&source.runtime, &view.runtime));
            assert!(
                source
                    .inner
                    .http_transport
                    .shares_pools_with(&view.inner.http_transport)
            );
            assert!(Arc::ptr_eq(
                &source.inner.data_model_compatibility,
                &view.inner.data_model_compatibility
            ));
            assert!(Arc::ptr_eq(
                &source.inner.compatibility_probe,
                &view.inner.compatibility_probe
            ));
            assert_eq!(source.account.authority(), view.account.authority());
            assert_eq!(source.account.network_id(), view.account.network_id());
            assert_eq!(source.account.endpoint(), view.account.endpoint());
            assert_eq!(
                source.account.signing_capability(),
                view.account.signing_capability()
            );
            assert_eq!(
                source.inner.key_pair().public_key(),
                view.inner.key_pair().public_key()
            );
            assert_eq!(source.inner.headers(), view.inner.headers());
        }
        assert_eq!(source.inner.http_transport.deadline(), None);
        assert_eq!(bounded.inner.http_transport.deadline(), Some(deadline));
        assert_eq!(repeated.inner.http_transport.deadline(), Some(deadline));
        assert_eq!(
            shortened.inner.http_transport.deadline(),
            Some(shortened_deadline)
        );
        let transaction = shortened
            .account
            .prepare_transaction(crate::client::AccountTransactionDraft::new(
                Vec::<iroha_data_model::isi::InstructionBox>::new(),
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| shortened.account.sign_transaction(payload))
            .unwrap();
        shortened.submit_transaction(&transaction).unwrap();
        {
            let requests = requests.lock().unwrap();
            assert_eq!(
                requests.len(),
                2,
                "fresh compatibility probe and account submission"
            );
            assert_eq!(requests[0].url.path(), "/v1/node/capabilities");
            assert_eq!(
                requests[1].url.path(),
                iroha_torii_shared::route_catalog::pipeline::TRANSACTION.path()
            );
            for request in requests.iter() {
                let timeout = request.timeout.expect("bounded account dispatch");
                assert!(!timeout.is_zero() && timeout <= Duration::from_secs(20));
                assert!(
                    request
                        .headers
                        .iter()
                        .any(|(name, value)| name == "x-deadline-fixture" && value == "retained")
                );
            }
        }
        let expired = source.with_request_deadline(Instant::now()).unwrap();
        assert!(expired.refresh_capabilities().is_err());
        assert!(expired.submit_transaction(&transaction).is_err());
        assert_eq!(
            requests.lock().unwrap().len(),
            2,
            "expired dispatch never reaches HTTP"
        );
        drop(expired);
        source.refresh_capabilities().unwrap();
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].timeout,
            Some(source.inner.torii_request_timeout())
        );
        assert_eq!(source.inner.http_transport.deadline(), None);
        assert_eq!(bounded.inner.http_transport.deadline(), Some(deadline));
    }

    #[test]
    fn fee_quote_uses_the_blocking_facades_owned_async_runtime() {
        let (client, async_sends, _) = accepting_client();
        let payload = client
            .account_client()
            .prepare_transaction(crate::client::AccountTransactionDraft::new(
                Vec::<iroha_data_model::isi::InstructionBox>::new(),
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .expect("build exact fee quote payload");

        let quote = client
            .quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload })
            .expect("blocking facade fee quote");

        assert_eq!(quote.intent, payload.fee_payment_intent().clone());
        assert_eq!(async_sends.load(Ordering::Relaxed), 1);
        assert_eq!(client.runtime.runs.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn submit_transaction_and_wait_returns_the_exact_applied_hash() {
        let (client, async_sends, _) = accepting_client();
        let transaction = {
            let account = client.account_client();
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    Vec::<iroha_data_model::isi::InstructionBox>::new(),
                    FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build transaction");
        let expected = transaction.hash();

        let actual = client
            .submit_transaction_and_wait(&transaction)
            .expect("transaction reaches state-resolved Applied finality");

        assert_eq!(actual, expected);
        assert_eq!(
            async_sends.load(Ordering::Relaxed),
            3,
            "one capability probe, one submission, and one status poll expected"
        );
    }

    #[test]
    fn borrowed_async_client_reuses_keepalive_connection_between_blocking_calls() {
        use std::{
            io::{self, Read, Write},
            net::TcpListener,
            time::{Duration, Instant},
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let mut config = config_factory();
        config.torii_api_url = format!(
            "http://{}/",
            listener.local_addr().expect("listener address")
        )
        .parse()
        .expect("loopback URL");
        config.torii_request_timeout = Duration::from_secs(2);
        let client = Client::new(config).expect("blocking client");
        let external = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("external async runtime");
        let server = std::thread::spawn(move || -> io::Result<usize> {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(true)?;
            let mut requests = 0;
            for _ in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    if Instant::now() >= deadline {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let mut byte = [0_u8; 1];
                    match stream.read(&mut byte) {
                        Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                        Ok(_) => headers.push(byte[0]),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                    if headers.len() > 16 * 1024 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                }
                assert!(headers.starts_with(b"GET /v1/node/capabilities HTTP/1.1\r\n"));
                requests += 1;
                stream.set_nonblocking(false)?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                // A complete non-success response keeps compatibility uncached
                // while allowing the drained connection to return to the pool.
                stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                )?;
                stream.set_nonblocking(true)?;
            }
            Ok(requests)
        });

        let blocking_result = client.refresh_capabilities();
        let async_result = external.block_on(client.client().refresh_capabilities());
        let requests = server.join().expect("loopback server joined");
        for response in [blocking_result, async_result] {
            let error = response.expect_err("server returns a deliberate HTTP rejection");
            let probe = error
                .downcast_ref::<crate::client::CapabilityProbeError>()
                .expect("typed capability probe error");
            assert!(
                probe.details().contains("503 Service Unavailable"),
                "request must receive the server response, not a transport timeout: {probe}"
            );
        }
        assert_eq!(
            requests.expect("both requests reach the original connection"),
            2,
            "the borrowed async client must reuse the live pooled connection"
        );
    }

    #[test]
    fn background_tasks_progress_with_a_clone_and_cancel_after_final_owner_drop() {
        use std::{sync::mpsc, time::Duration};

        struct NotifyDrop(mpsc::Sender<()>);
        impl Drop for NotifyDrop {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }

        let (client, _, _) = accepting_client();
        let clone = client.clone();
        assert!(Arc::ptr_eq(&client.runtime, &clone.runtime));
        let owner = Arc::downgrade(&client.runtime);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (dropped_tx, dropped_rx) = mpsc::channel();
        // The async block deliberately hands the spawned task's handle out of `block_on`.
        #[allow(clippy::async_yields_async)]
        let task = client
            .runtime
            .block_on(async move {
                let task = tokio::spawn(async move {
                    let _notify_drop = NotifyDrop(dropped_tx);
                    started_tx.send(()).expect("report task started");
                    release_rx.await.expect("release background task");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    progress_tx.send(()).expect("report background progress");
                    std::future::pending::<()>().await;
                });
                started_rx.await.expect("background task started");
                task
            })
            .expect("start on the owned runtime");
        drop(client);
        assert!(owner.upgrade().is_some(), "clone retains the same runtime");
        release_tx.send(()).expect("release after block_on returns");
        progress_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the owned worker must drive tasks and timers between calls");
        assert!(matches!(
            dropped_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        let external = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("external async runtime");
        let completion = external.block_on(async {
            // Final-owner drop must also remain safe inside another runtime.
            drop(clone);
            tokio::time::timeout(Duration::from_secs(2), task).await
        });
        assert!(
            owner.upgrade().is_none(),
            "the final runtime owner was released"
        );
        assert!(
            completion
                .expect("shutdown cancels the background task promptly")
                .expect_err("pending task must be cancelled")
                .is_cancelled()
        );
        dropped_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("shutdown drops the pending task and releases its resources");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn alias_setup_blocking_facade_rejects_runtime_and_inherited_blocking_context() {
        let (client, async_sends, _) = accepting_client();
        let assert_rejected = |client: &Client| {
            let request = AliasSetupPlanRequestV1::new(Vec::new());
            for error in [
                client.post_alias_setup_plan(&request).unwrap_err(),
                client.plan_alias_setup(&request).unwrap_err(),
            ] {
                assert_eq!(
                    error
                        .downcast_ref::<BlockingCallError>()
                        .unwrap()
                        .async_runtime_flavor(),
                    Some(AsyncRuntimeFlavor::CurrentThread),
                );
            }
        };
        assert_rejected(&client);
        let clone = client.clone();
        tokio::task::spawn_blocking(move || assert_rejected(&clone))
            .await
            .expect("inherited runtime guard returns an error without panic");
        assert_eq!(async_sends.load(Ordering::Relaxed), 0);
        assert_eq!(client.runtime.runs.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn blocking_facade_rejects_async_runtime_and_drops_safely() {
        let (client, async_sends, _) = accepting_client();
        let transaction = {
            let account = client.account_client();
            account
                .prepare_transaction(crate::client::AccountTransactionDraft::new(
                    Vec::<iroha_data_model::isi::InstructionBox>::new(),
                    FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build transaction");
        let error = client
            .submit_transaction(&transaction)
            .expect_err("blocking call inside Tokio must reject");
        let typed = error
            .downcast_ref::<BlockingCallError>()
            .expect("typed blocking-call error");
        assert_eq!(
            typed.async_runtime_flavor(),
            Some(AsyncRuntimeFlavor::CurrentThread)
        );
        assert_eq!(async_sends.load(Ordering::Relaxed), 0);
        drop(client);
    }
}
