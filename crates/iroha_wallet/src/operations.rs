//! Account balances and exact, quoted native operations with durable submission evidence.
use eyre::{Result, WrapErr as _, eyre};
use iroha::{
    blocking::{Client, funding::BalanceReport},
    client::{
        AccountTransactionDraft, Client as NativeClient, FeeQuoteRequest,
        decode_and_verify_alias_setup_plan_for_request,
    },
    config::Config,
    data_model::{
        NetworkId,
        account::{AccountId, address::ChainDiscriminantGuard},
        alias_setup::{AliasPlanDispositionV1, AliasSetupPlanRequestV1, AliasTransactionPlanV1},
        asset::{AssetDefinitionId, AssetId},
        isi::{InstructionBox, Transfer},
        prelude::{SignedTransaction, TransactionEntrypoint},
        transaction::{Executable, FeePaymentIntent},
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_operation_journal::Journal;
use iroha_primitives::numeric::Quantity;
use iroha_torii_shared::FeeQuoteResponse;
#[cfg(test)]
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};
use norito::json::{JsonDeserialize, JsonSerialize, Value};
#[cfg(test)]
use std::time::Duration;
use std::{
    collections::BTreeMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "operations_preparation.rs"]
mod preparation;
pub use preparation::{NativePreparationPhase, RetiredNativeRequest, VerifiedNativePreparation};

#[path = "operations_amx_registration.rs"]
mod amx_registration;
pub use amx_registration::AmxDataspaceRegistrationRequest;
#[path = "operations_bounded.rs"]
mod bounded;
#[path = "operations_alias.rs"]
mod bounded_alias;
#[path = "operations_gateway_setup.rs"]
mod gateway_setup;
#[path = "operations_musubi_namespace.rs"]
mod musubi_namespace;
#[path = "operations_private_root.rs"]
mod private_root;
#[path = "operations_provider_capacity.rs"]
mod provider_capacity;
#[path = "operations_provider_credit.rs"]
mod provider_credit;
#[path = "operations_provider_ingest.rs"]
mod provider_ingest;
#[path = "operations_reputation_policy.rs"]
mod reputation_policy;
#[path = "operations_reserve_account.rs"]
mod reserve_account;
#[path = "operations_reserve_movement_decision.rs"]
mod reserve_movement_decision;
#[path = "operations_reserve_policy.rs"]
mod reserve_policy;
#[path = "operations_reserve_top_up.rs"]
mod reserve_top_up;
#[cfg(test)]
#[path = "operations_setup_test_support.rs"]
mod setup_test_support;
#[path = "operations_stream_token_custody.rs"]
mod stream_token_custody;
use bounded_alias::AliasFeeBounds;
pub use gateway_setup::{InitialGatewaySetupRequest, InitialGatewaySetupSelection};
use iroha_data_model::private_dataspace::{
    PrivateDataspaceAnchor, PrivateDataspaceAnchorState, PrivateDataspaceRegistration,
};
pub use musubi_namespace::{
    MusubiNamespaceBindingParent, MusubiNamespaceBindingRequest, MusubiNamespaceBindingSelection,
};
use private_root::BoundedTerms;
pub use private_root::{
    BoundedTransactionOptions, PrivateRootAnchorRequest, PrivateRootRegistrationRequest,
};
pub use provider_capacity::{
    ProviderCapacityDeclarationRequest, ProviderCapacityDeclarationSelection,
};
pub use provider_credit::{ProviderCreditUpsertRequest, ProviderCreditUpsertSelection};
pub use provider_ingest::InitialProviderIngestAuthorityRequest;
pub use reputation_policy::{InitialReputationPolicyRequest, InitialReputationPolicySelection};
pub use reserve_account::{ReserveAccountRegistrationRequest, ReserveAccountRegistrationSelection};
pub use reserve_movement_decision::{
    ReserveMovementDecisionRequest, ReserveMovementDecisionSelection,
};
pub use reserve_policy::{InitialReservePolicyRequest, InitialReservePolicySelection};
pub use reserve_top_up::{ReserveTopUpRequest, ReserveTopUpSelection};
pub use stream_token_custody::{
    StreamTokenCustodyConfigureRequest, StreamTokenCustodyEnrollRequest,
    StreamTokenCustodySelection,
};

/// Canonical XOR asset definition used by Taira's native fee economy.
pub const XOR_ASSET_DEFINITION: &str = "6TEAJqbb8oEPmLncoNiMRbLEK6tw";

/// Observed lifecycle state, never inferred from a successful submission alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    /// The exact signed operation is durable and has never been dispatched.
    Prepared,
    /// An authenticated onboarding response requires current-state proof.
    ProofRequired,
    /// Exact committed wire agrees with the configured node's state-resolved application.
    /// Independent parent anchoring additionally requires the attachment service's verified proof.
    Applied,
    /// The requested account or alias state already agrees with authenticated native evidence.
    AlreadyPresent,
    /// The queried node does not currently observe the exact transaction.
    Absent,
    /// An attempted or observed operation remains unresolved.
    Pending,
    /// Canonical terminal rejection was observed.
    Rejected,
    /// The unattempted deadline elapsed locally or canonical terminal expiry was observed.
    Expired,
    /// The requested alias currently identifies a different account.
    AliasConflict,
}
impl OperationStatus {
    /// Stable public status spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::ProofRequired => "ProofRequired",
            Self::Applied => "Applied",
            Self::AlreadyPresent => "AlreadyPresent",
            Self::Absent => "Absent",
            Self::Pending => "Pending",
            Self::Rejected => "Rejected",
            Self::Expired => "Expired",
            Self::AliasConflict => "AliasConflict",
        }
    }
    /// Whether verified operation completion permits a caller to advance its workflow.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Applied | Self::AlreadyPresent)
    }
}

/// Presentation-free account-operation evidence.
#[derive(Clone, Debug)]
pub struct OperationReport {
    /// Exact observed lifecycle state.
    pub status: OperationStatus,
    /// Public native evidence; contains no keys or runtime authorization material.
    pub data: Value,
}
impl OperationReport {
    /// Require verified completion before advancing to another operation.
    ///
    /// # Errors
    /// Returns an error for pending, absent, prepared, rejected, expired or conflicting evidence.
    pub fn require_complete(&self) -> Result<()> {
        if self.status.is_complete() {
            return Ok(());
        }
        eyre::bail!(
            "wallet operation is {}; recover the same journal before advancing",
            self.status.as_str()
        )
    }
}

/// One XOR transfer with an explicit caller-selected authority or sponsor fee policy.
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// Canonical receiving account.
    pub destination: AccountId,
    /// Exact positive XOR quantity.
    pub amount: Quantity,
    /// Explicit payer, sponsor revision and gas bound; maxima come from the SDK quote.
    pub fee_payment: FeePaymentIntent,
}

/// Expected native operation selected by the calling command before journal recovery or submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeOperationKind {
    /// Exact XOR transfer to another account.
    Transfer,
    /// Indivisible paid alias setup planned and verified by the SDK.
    AliasSetup,
    /// Exact explicit administrative AMX tracker registration on the selected Global root.
    AmxDataspaceRegistration,
    /// Exact owner-bound compact private-root registration.
    PrivateRootRegistration,
    /// Exact next compact private-root certificate against retained parent cursor state.
    PrivateRootAnchor,
    /// One exact governed StreamToken custody policy configuration.
    StreamTokenCustodyConfigure,
    /// One independently attested StreamToken custody enrollment.
    StreamTokenCustodyEnroll,
    /// One exact initial revision-one reserve governance policy.
    InitialReservePolicy,
    /// One exact initial provider reserve partition under its selected policy.
    ReserveAccountRegistration,
    /// One provider-owned TopUp movement request; approval and asset transfer are separate.
    ReserveTopUpRequest,
    /// One generic manager decision; movement provider, kind and amount are resolved natively.
    ReserveMovementDecision,
    /// One governed credit record replacement with explicit native absence/current row CAS.
    ProviderCreditUpsert,
    /// One provider-owner capacity declaration, with native replacement semantics and no CAS.
    ProviderCapacityDeclaration,
    /// Exact initial Configure followed by the selected gateway Operate and Check grants.
    InitialGatewaySetup,
    /// Sole initial recorder Set with the complete selected active gateway delivery template.
    InitialReputationPolicy,
    /// Sole owner-signed revision-one ingest authority Set with native absence CAS.
    InitialProviderIngestAuthority,
    /// Sole immutable Musubi namespace binding, authorized by its actual current native owner.
    MusubiNamespaceBinding,
}

enum OperationExpectation<'a> {
    AmxRegistration(amx_registration::AmxRegistrationExpectation<'a>),
    MusubiNamespace(musubi_namespace::MusubiNamespaceExpectation<'a>),
    Transfer(&'a TransferRequest),
    Alias(&'a AliasSetupPlanRequestV1, &'a FeePaymentIntent),
    ProviderIngest(provider_ingest::ProviderIngestExpectation<'a>),
    GatewaySetup(gateway_setup::GatewaySetupExpectation<'a>),
    ReputationPolicy(reputation_policy::ReputationPolicyExpectation<'a>),
    PrivateRoot(private_root::BoundedOperationExpectation<'a>),
    Custody(stream_token_custody::CustodyExpectation<'a>),
    ReservePolicy(reserve_policy::ReservePolicyExpectation<'a>),
    ReserveAccount(reserve_account::ReserveAccountExpectation<'a>),
    ReserveTopUp(reserve_top_up::ReserveTopUpExpectation<'a>),
    ReserveMovementDecision(reserve_movement_decision::ReserveMovementDecisionExpectation<'a>),
    ProviderCredit(provider_credit::ProviderCreditExpectation<'a>),
    ProviderCapacity(provider_capacity::ProviderCapacityExpectation<'a>),
}
impl OperationExpectation<'_> {
    fn verify(&self, record: &preparation::Selection<'_>) -> Result<()> {
        match self {
            Self::AmxRegistration(expected) => expected.verify(record),
            Self::MusubiNamespace(expected) => expected.verify(record),
            Self::Transfer(expected) => {
                let NativeOperation::Transfer {
                    destination,
                    amount,
                } = record.operation
                else {
                    eyre::bail!("different transfer preparation purpose");
                };
                eyre::ensure!(
                    destination == &expected.destination
                        && amount == &expected.amount
                        && record.requested_fee == &expected.fee_payment,
                    "changed original transfer request"
                );
                Ok(())
            }
            Self::Alias(expected, fee) => {
                let NativeOperation::AliasSetup {
                    request,
                    bounds: AliasFeeBounds::Quoted,
                    ..
                } = record.operation
                else {
                    eyre::bail!("different alias preparation purpose");
                };
                eyre::ensure!(
                    request == *expected && record.requested_fee == *fee,
                    "changed original alias request"
                );
                Ok(())
            }
            Self::ProviderIngest(expected) => expected.verify(record),
            Self::GatewaySetup(expected) => expected.verify(record),
            Self::ReputationPolicy(expected) => expected.verify(record),
            Self::PrivateRoot(expected) => expected.verify(record),
            Self::Custody(expected) => expected.verify(record),
            Self::ReservePolicy(expected) => expected.verify(record),
            Self::ReserveAccount(expected) => expected.verify(record),
            Self::ReserveTopUp(expected) => expected.verify(record),
            Self::ReserveMovementDecision(expected) => expected.verify(record),
            Self::ProviderCredit(expected) => expected.verify(record),
            Self::ProviderCapacity(expected) => expected.verify(record),
        }
    }
}

/// Account-authorized shared native wallet operations.
pub struct AccountService {
    config: Config,
    client: Client,
    deadline: Option<std::time::Instant>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl AccountService {
    /// Bind a native client to one exact configured network, account and signing key.
    ///
    /// # Errors
    /// Rejects embedded endpoint credentials, an invalid signer, or invalid SDK configuration.
    pub fn new(config: Config) -> Result<Self> {
        validate_config(&config)?;
        let client = Client::new(config.clone())?;
        Ok(Self {
            config,
            client,
            deadline: None,
            cancellation: None,
        })
    }
    /// Bind the caller's existing cancellation signal to all subsequent paid work.
    ///
    /// Set this signal once when cancelling; callers must never reset it. Deadline-bounded
    /// copies preserve the same signal. Cancellation is checked cooperatively before retaining
    /// payloads, signing and dispatch; read-only canonical inspection remains available.
    ///
    /// # Errors
    /// Refuses replacing an existing cancellation binding with a different signal.
    pub fn with_cancellation(
        mut self,
        cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self> {
        eyre::ensure!(
            self.cancellation
                .as_ref()
                .is_none_or(|original| std::sync::Arc::ptr_eq(original, &cancellation)),
            "wallet cancellation signal cannot be replaced"
        );
        self.cancellation = Some(cancellation);
        Ok(self)
    }
    /// Read this account's exact XOR balance without preparing a transaction.
    ///
    /// # Errors
    /// Returns authentication, routing, account/asset-definition absence or query errors.
    pub fn xor_balance(&self) -> Result<BalanceReport> {
        self.client.balance(&AssetId::new(
            XOR_ASSET_DEFINITION.parse()?,
            self.config.account.clone(),
        ))
    }
    /// Inspect an exact transfer preparation without signing or network I/O.
    /// # Errors
    /// Refuses changed request or unsafe/malformed retained custody.
    pub fn inspect_transfer_preparation(
        &self,
        journal: &Path,
        expected: &TransferRequest,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::Transfer,
            Some(OperationExpectation::Transfer(expected)),
        )
    }
    /// Retire an exact transfer request only before its first retained payload.
    /// # Errors
    /// Refuses missing, changed or later-stage histories and unknown journal material.
    pub fn retire_transfer_unprepared(
        &self,
        journal: &Path,
        expected: &TransferRequest,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::Transfer,
            OperationExpectation::Transfer(expected),
        )
    }
    /// Inspect an exact ordinarily quoted alias preparation without calling its planner.
    /// # Errors
    /// Refuses changed plan/request, fee selection or unsafe/malformed custody.
    pub fn inspect_alias_preparation(
        &self,
        journal: &Path,
        request: &AliasSetupPlanRequestV1,
        fee: &FeePaymentIntent,
    ) -> Result<VerifiedNativePreparation> {
        self.inspect_preparation(
            journal,
            NativeOperationKind::AliasSetup,
            Some(OperationExpectation::Alias(request, fee)),
        )
    }
    /// Retire an ordinarily quoted alias request only before a payload or dispatch exists.
    /// # Errors
    /// Refuses missing, changed or later-stage histories and unknown journal material.
    pub fn retire_alias_unprepared(
        &self,
        journal: &Path,
        request: &AliasSetupPlanRequestV1,
        fee: &FeePaymentIntent,
    ) -> Result<RetiredNativeRequest> {
        self.retire_preparation(
            journal,
            NativeOperationKind::AliasSetup,
            OperationExpectation::Alias(request, fee),
        )
    }
    /// Retain a transfer request and quoted payload, then persist its signature before submission.
    ///
    /// # Errors
    /// Returns invalid quantity/fee, quote/signing, expired original terms or journal failures.
    pub fn prepare_transfer(
        &self,
        request: &TransferRequest,
        journal: &Path,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        validate_transfer_request(request, &self.config.account)?;
        if let Some(report) = self.finish_existing_preparation(
            journal,
            NativeOperationKind::Transfer,
            Some(OperationExpectation::Transfer(request)),
        )? {
            return Ok(report);
        }
        self.prepare_native(
            NativeOperation::Transfer {
                destination: request.destination.clone(),
                amount: request.amount.clone(),
            },
            request.fee_payment.clone(),
            journal,
        )
    }
    /// Verify one paid native alias setup plan, quote its exact indivisible instruction vector and save it.
    ///
    /// # Errors
    /// Rejects changed authority/network/request terms, expired plans, invalid fees and unsafe journals.
    pub fn prepare_alias(
        &self,
        request: &AliasSetupPlanRequestV1,
        fee_payment: FeePaymentIntent,
        journal: &Path,
    ) -> Result<OperationReport> {
        if let Some(report) = self.finish_existing_preparation(
            journal,
            NativeOperationKind::AliasSetup,
            Some(OperationExpectation::Alias(request, &fee_payment)),
        )? {
            return Ok(report);
        }
        self.prepare_alias_with_bounds(request, fee_payment, AliasFeeBounds::Quoted, journal)
    }

    fn prepare_alias_with_bounds(
        &self,
        request: &AliasSetupPlanRequestV1,
        fee_payment: FeePaymentIntent,
        bounds: AliasFeeBounds,
        journal: &Path,
    ) -> Result<OperationReport> {
        let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
        self.ensure_deadline()?;
        fee_payment.validate()?;
        let plan = self.client.plan_alias_setup(request)?;
        self.client
            .client()
            .verify_alias_setup_plan_for_request(request, &plan)?;
        if !plan.body.resources.is_empty()
            && plan
                .body
                .resources
                .iter()
                .all(|resource| resource.disposition == AliasPlanDispositionV1::NoOp)
        {
            return Ok(OperationReport {
                status: OperationStatus::AlreadyPresent,
                data: norito::json!({
                    "schema": "iroha.wallet.native-transaction-result.v1", "operation": "alias_setup", "status": "AlreadyPresent",
                    "network_id": (self.config.network_id.to_string()), "chain_discriminant": (self.config.account_chain_discriminant),
                    "account_id": (self.config.account.to_string()), "request": (request), "plan": (plan),
                    "transaction_hash": null, "journal": null,
                }),
            });
        }
        self.prepare_native(
            NativeOperation::AliasSetup {
                request: request.clone(),
                plan: Box::new(plan),
                bounds,
            },
            fee_payment,
            journal,
        )
    }
    fn ensure_deadline(&self) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
        {
            eyre::bail!("wallet operation cancelled");
        }
        if self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            eyre::bail!("wallet operation deadline elapsed");
        }
        Ok(())
    }

    /// Submit a wholly unattempted saved transfer or alias operation once, then verify its wire.
    ///
    /// An existing attempt is reconciled by hash without another submission.
    /// Bounded operations require their request-bound submission methods.
    ///
    /// # Errors
    /// Returns invalid/unsafe journal or untrusted observation errors. Unresolved dispatch returns Pending.
    pub fn submit(&self, journal: &Path, expected: NativeOperationKind) -> Result<OperationReport> {
        self.run_transaction(journal, expected, true, None)
    }
    /// Read-only reconciliation of a native preparation without rebuilding, quoting or signing.
    ///
    /// Bounded operations require their request-bound recovery methods.
    ///
    /// # Errors
    /// Returns changed identity, unsafe evidence or malformed status/committed-wire errors.
    pub fn resume(&self, journal: &Path, expected: NativeOperationKind) -> Result<OperationReport> {
        self.run_transaction(journal, expected, false, None)
    }
    fn run_transaction(
        &self,
        path: &Path,
        expected: NativeOperationKind,
        submit: bool,
        expectation: Option<private_root::BoundedOperationExpectation<'_>>,
    ) -> Result<OperationReport> {
        self.run_transaction_with_expectation(
            path,
            expected,
            submit,
            expectation.map(OperationExpectation::PrivateRoot),
        )
    }
    fn run_transaction_with_expectation(
        &self,
        path: &Path,
        expected: NativeOperationKind,
        submit: bool,
        expectation: Option<OperationExpectation<'_>>,
    ) -> Result<OperationReport> {
        norito::core::with_decode_limits_scope(preparation::LIMITS, || {
            let _profile = ChainDiscriminantGuard::enter(self.config.account_chain_discriminant);
            let journal = Journal::open(path)?;
            let retained = preparation::Retained::read(&journal, &self.config)?;
            retained.verify_selection(expected, expectation.as_ref())?;
            if let Some(report) = retained.partial_report(&journal)? {
                eyre::ensure!(
                    !submit,
                    "explicit preparation must finish the original payload before submission"
                );
                return Ok(report);
            }
            let (record, transaction) = retained.into_record()?;
            let mut before = observe_transaction(self.client.client(), &transaction)?;
            if before.status == OperationStatus::Absent {
                if journal.submission_recorded(&record)? {
                    before.status = OperationStatus::Pending;
                } else if transaction_expired(&transaction)? {
                    before.status = OperationStatus::Expired;
                }
            }
            if !submit || before.status != OperationStatus::Absent {
                return Ok(transfer_report(
                    &journal,
                    &record,
                    before.status,
                    before.evidence.as_ref(),
                ));
            }
            self.client.refresh_capabilities().wrap_err(
                "wallet transaction submission compatibility; saved operation remains unattempted",
            )?;
            self.ensure_deadline()?;
            if transaction_expired(&transaction)? {
                return Ok(transfer_report(
                    &journal,
                    &record,
                    OperationStatus::Expired,
                    None,
                ));
            }
            if !journal.record_submission(&record)? {
                return Ok(transfer_report(
                    &journal,
                    &record,
                    OperationStatus::Pending,
                    None,
                ));
            }
            // Cancellation during durable marker publication leaves an ambiguous retained attempt;
            // it never grants a replacement dispatch on recovery.
            self.ensure_deadline()?;
            // The marker is durable before the only dispatch. Its existence permanently prevents replay.
            let _submission = self.client.submit_transaction_and_wait(&transaction);
            let after =
                observe_transaction(self.client.client(), &transaction).unwrap_or(Observation {
                    status: OperationStatus::Pending,
                    evidence: None,
                });
            let status = if after.status == OperationStatus::Absent {
                OperationStatus::Pending
            } else {
                after.status
            };
            if status == OperationStatus::Applied {
                journal.write_applied_evidence(&after.evidence)?;
            }
            Ok(transfer_report(
                &journal,
                &record,
                status,
                after.evidence.as_ref(),
            ))
        })
    }
}

#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct TransactionJournal {
    schema: String,
    torii_url: String,
    chain_id: String,
    network_id: NetworkId,
    chain_discriminant: u16,
    account_id: AccountId,
    operation: NativeOperation,
    requested_fee: FeePaymentIntent,
    quote: FeeQuoteResponse,
    transaction_hash: String,
    signed_transaction_hex: String,
    deadline_ms: u64,
}
impl TransactionJournal {
    fn verify(&self, config: &Config) -> Result<SignedTransaction> {
        if self.schema != "iroha.wallet.native-transaction.v1"
            || self.torii_url != config.torii_api_url.as_str()
            || self.chain_id != config.chain.to_string()
            || self.network_id != config.network_id
            || self.chain_discriminant != config.account_chain_discriminant
            || self.account_id != config.account
            || self.signed_transaction_hex.len() > 2 * 1024 * 1024
        {
            eyre::bail!(
                "transfer journal differs from the exact wallet, endpoint or network, or exceeds its bound"
            );
        }
        let bytes = preparation::decode_hex(&self.signed_transaction_hex, 1024 * 1024)?;
        let transaction: SignedTransaction = iroha_version::codec::decode_exact_versioned(&bytes)?;
        transaction.verify_signature()?;
        eyre::ensure!(
            transaction.multisig_signatures().is_none()
                && preparation::encode_signed(&transaction)? == bytes
                && transaction_deadline(&transaction)? == self.deadline_ms
                && transaction.try_hash_as_entrypoint()?.to_string() == self.transaction_hash,
            "signed journal differs from its exact sole signature, wire or transaction identity"
        );
        preparation::verify_payload(
            preparation::Selection {
                operation: &self.operation,
                requested_fee: &self.requested_fee,
                deadline_ms: self.deadline_ms,
            },
            &self.quote,
            transaction.payload(),
            config,
        )?;
        Ok(transaction)
    }
}
fn verify_quote_limits(requested: &FeePaymentIntent, quote: &FeeQuoteResponse) -> Result<()> {
    verify_fee_intent_limits(requested, &quote.intent)
}

/// Require the original payer/gas selection and every explicitly authorized component maximum.
///
/// # Errors
/// Rejects invalid intents, changed payer or gas, and unlisted or increased fee components.
pub(crate) fn verify_fee_intent_limits(
    requested: &FeePaymentIntent,
    actual: &FeePaymentIntent,
) -> Result<()> {
    requested.validate()?;
    actual.validate()?;
    if !requested.has_same_payer_and_gas_bound(actual) {
        eyre::bail!("fee quote changed the selected payer, sponsor revision or gas bound");
    }
    if !requested.charge_limits().is_empty() {
        for quoted in actual.charge_limits() {
            let retained = requested
                .charge_limits()
                .iter()
                .find(|limit| {
                    limit.kind() == quoted.kind()
                        && limit.asset_definition_id() == quoted.asset_definition_id()
                })
                .ok_or_else(|| {
                    eyre!("fee quote added a component outside the explicit caller limits")
                })?;
            if quoted.max_amount() > retained.max_amount() {
                eyre::bail!("fee quote increased an explicit caller maximum");
            }
        }
    }
    Ok(())
}

fn validate_transfer_request(request: &TransferRequest, authority: &AccountId) -> Result<()> {
    eyre::ensure!(
        request.fee_payment.charge_limits().len() <= 16,
        "transfer fee authorization exceeds sixteen entries"
    );
    request.fee_payment.validate()?;
    if request.amount.is_zero() || &request.destination == authority {
        eyre::bail!("transfer requires a positive amount and a different destination account");
    }
    Ok(())
}
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum NativeOperation {
    AmxDataspaceRegistration {
        parent_chain_id: String,
        registration: Box<PrivateDataspaceRegistration>,
        deadline_unix_ms: u64,
        terms: BoundedTerms,
    },
    MusubiNamespaceBinding {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    InitialProviderIngestAuthority {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    InitialGatewaySetup {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    InitialReputationPolicy {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    Transfer {
        destination: AccountId,
        amount: Quantity,
    },
    AliasSetup {
        request: AliasSetupPlanRequestV1,
        plan: Box<AliasTransactionPlanV1>,
        bounds: AliasFeeBounds,
    },
    PrivateRootRegistration {
        alias: String,
        expected_ownership_generation: u64,
        registration: Box<PrivateDataspaceRegistration>,
        terms: BoundedTerms,
    },
    PrivateRootAnchor {
        state: Box<PrivateDataspaceAnchorState>,
        anchor: Box<PrivateDataspaceAnchor>,
        terms: BoundedTerms,
    },
    StreamTokenCustodyConfigure {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    StreamTokenCustodyEnroll {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    InitialReservePolicy {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    ReserveAccountRegistration {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    ReserveTopUpRequest {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    ReserveMovementDecision {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    ProviderCreditUpsert {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
    ProviderCapacityDeclaration {
        plan: Vec<u8>,
        terms: BoundedTerms,
    },
}
impl NativeOperation {
    fn bounded_terms(&self) -> Option<&BoundedTerms> {
        match self {
            Self::AmxDataspaceRegistration { terms, .. }
            | Self::PrivateRootRegistration { terms, .. }
            | Self::PrivateRootAnchor { terms, .. } => Some(terms),
            Self::MusubiNamespaceBinding { terms, .. }
            | Self::StreamTokenCustodyConfigure { terms, .. }
            | Self::StreamTokenCustodyEnroll { terms, .. }
            | Self::InitialReservePolicy { terms, .. }
            | Self::ReserveAccountRegistration { terms, .. }
            | Self::ReserveTopUpRequest { terms, .. }
            | Self::ReserveMovementDecision { terms, .. }
            | Self::ProviderCreditUpsert { terms, .. }
            | Self::ProviderCapacityDeclaration { terms, .. }
            | Self::InitialGatewaySetup { terms, .. }
            | Self::InitialReputationPolicy { terms, .. }
            | Self::InitialProviderIngestAuthority { terms, .. } => Some(terms),
            Self::AliasSetup {
                bounds: AliasFeeBounds::Bounded(terms),
                ..
            } => Some(terms),
            Self::Transfer { .. } | Self::AliasSetup { .. } => None,
        }
    }
    fn principal(&self, authority: &AccountId) -> Result<BTreeMap<AssetId, Quantity>> {
        match self {
            Self::AmxDataspaceRegistration { .. }
            | Self::MusubiNamespaceBinding { .. }
            | Self::PrivateRootRegistration { .. }
            | Self::PrivateRootAnchor { .. }
            | Self::StreamTokenCustodyConfigure { .. }
            | Self::StreamTokenCustodyEnroll { .. }
            | Self::InitialReservePolicy { .. }
            | Self::ReserveAccountRegistration { .. }
            // A TopUp request pays fees only. Manager approval owns the later asset transfer.
            | Self::ReserveTopUpRequest { .. }
            // A manager decision pays only its own fees. Native execution owns the selected
            // movement's provider/custody debit; it is never charged as manager principal here.
            | Self::ReserveMovementDecision { .. }
            // Governed credit projection has no asset transfer; its signer pays only fees.
            | Self::ProviderCreditUpsert { .. }
            // Capacity declares already-backed stake; the owner pays no principal here.
            | Self::ProviderCapacityDeclaration { .. }
            // Setup and scoped permission grants move no principal; the manager pays fees.
            | Self::InitialGatewaySetup { .. }
            | Self::InitialReputationPolicy { .. }
            // Ingest Set is owner-signed and pays only that owner's fees.
            | Self::InitialProviderIngestAuthority { .. } => Ok(BTreeMap::new()),
            Self::Transfer { amount, .. } => Ok(BTreeMap::from([(
                AssetId::new(XOR_ASSET_DEFINITION.parse()?, authority.clone()),
                amount.clone(),
            )])),
            Self::AliasSetup { plan, .. } => {
                let mut result = BTreeMap::new();
                for total in &plan.body.totals_by_asset {
                    add_quantity(
                        &mut result,
                        &AssetId::new(total.payment_asset.clone(), authority.clone()),
                        &total.amount,
                    )?;
                }
                Ok(result)
            }
        }
    }
    fn kind(&self) -> NativeOperationKind {
        match self {
            Self::AmxDataspaceRegistration { .. } => NativeOperationKind::AmxDataspaceRegistration,
            Self::MusubiNamespaceBinding { .. } => NativeOperationKind::MusubiNamespaceBinding,
            Self::InitialGatewaySetup { .. } => NativeOperationKind::InitialGatewaySetup,
            Self::InitialReputationPolicy { .. } => NativeOperationKind::InitialReputationPolicy,
            Self::InitialProviderIngestAuthority { .. } => {
                NativeOperationKind::InitialProviderIngestAuthority
            }
            Self::Transfer { .. } => NativeOperationKind::Transfer,
            Self::AliasSetup { .. } => NativeOperationKind::AliasSetup,
            Self::PrivateRootRegistration { .. } => NativeOperationKind::PrivateRootRegistration,
            Self::PrivateRootAnchor { .. } => NativeOperationKind::PrivateRootAnchor,
            Self::StreamTokenCustodyConfigure { .. } => {
                NativeOperationKind::StreamTokenCustodyConfigure
            }
            Self::StreamTokenCustodyEnroll { .. } => NativeOperationKind::StreamTokenCustodyEnroll,
            Self::InitialReservePolicy { .. } => NativeOperationKind::InitialReservePolicy,
            Self::ReserveTopUpRequest { .. } => NativeOperationKind::ReserveTopUpRequest,
            Self::ReserveMovementDecision { .. } => NativeOperationKind::ReserveMovementDecision,
            Self::ProviderCreditUpsert { .. } => NativeOperationKind::ProviderCreditUpsert,
            Self::ProviderCapacityDeclaration { .. } => {
                NativeOperationKind::ProviderCapacityDeclaration
            }
            Self::ReserveAccountRegistration { .. } => {
                NativeOperationKind::ReserveAccountRegistration
            }
        }
    }
    fn instructions(&self, config: &Config) -> Result<Vec<InstructionBox>> {
        match self {
            Self::AmxDataspaceRegistration {
                parent_chain_id,
                registration,
                deadline_unix_ms,
                terms,
            } => {
                terms.validate()?;
                eyre::ensure!(
                    terms.deadline_ms <= *deadline_unix_ms,
                    "AMX registration changed its original UTC authorization"
                );
                Ok(vec![amx_registration::instruction(
                    config,
                    parent_chain_id,
                    registration,
                    *deadline_unix_ms,
                )?])
            }
            Self::MusubiNamespaceBinding { plan, terms } => {
                terms.validate()?;
                musubi_namespace::instructions(config, plan, terms.deadline_ms)
            }
            Self::InitialProviderIngestAuthority { plan, terms } => {
                terms.validate()?;
                provider_ingest::instructions(config, plan, terms.deadline_ms)
            }
            Self::InitialGatewaySetup { plan, terms } => {
                terms.validate()?;
                gateway_setup::instructions(config, plan, terms.deadline_ms)
            }
            Self::InitialReputationPolicy { plan, terms } => {
                terms.validate()?;
                reputation_policy::instructions(config, plan, terms.deadline_ms)
            }
            Self::ProviderCapacityDeclaration { plan, terms } => {
                terms.validate()?;
                provider_capacity::instructions(config, plan, terms.deadline_ms)
            }
            Self::ProviderCreditUpsert { plan, terms } => {
                terms.validate()?;
                provider_credit::instructions(config, plan, terms.deadline_ms)
            }
            Self::ReserveMovementDecision { plan, terms } => {
                terms.validate()?;
                reserve_movement_decision::instructions(config, plan, terms.deadline_ms)
            }
            Self::ReserveTopUpRequest { plan, terms } => {
                terms.validate()?;
                reserve_top_up::instructions(config, plan, terms.deadline_ms)
            }
            Self::ReserveAccountRegistration { plan, terms } => {
                terms.validate()?;
                reserve_account::instructions(config, plan, terms.deadline_ms)
            }
            Self::InitialReservePolicy { plan, terms } => {
                terms.validate()?;
                reserve_policy::instructions(config, plan, terms.deadline_ms)
            }
            Self::StreamTokenCustodyConfigure { plan, terms }
            | Self::StreamTokenCustodyEnroll { plan, terms } => {
                terms.validate()?;
                stream_token_custody::instructions(config, plan, self.kind(), terms.deadline_ms)
            }
            Self::PrivateRootRegistration {
                alias,
                expected_ownership_generation,
                registration,
                terms,
            } => {
                terms.validate()?;
                Ok(vec![private_root::registration_instruction(
                    config,
                    alias,
                    *expected_ownership_generation,
                    registration,
                )?])
            }
            Self::PrivateRootAnchor {
                state,
                anchor,
                terms,
            } => {
                terms.validate()?;
                Ok(vec![private_root::anchor_instruction(
                    config, state, anchor,
                )?])
            }
            Self::Transfer {
                destination,
                amount,
            } => {
                if amount.is_zero() || destination == &config.account {
                    eyre::bail!(
                        "transfer requires a positive amount and a different destination account"
                    );
                }
                Ok(vec![
                    Transfer::asset_quantity(
                        AssetId::new(XOR_ASSET_DEFINITION.parse()?, config.account.clone()),
                        amount.clone(),
                        destination.clone(),
                    )
                    .into(),
                ])
            }
            Self::AliasSetup {
                request,
                plan,
                bounds,
            } => {
                if let AliasFeeBounds::Bounded(terms) = bounds {
                    terms.validate()?;
                }
                if plan.body.network_id != config.network_id
                    || plan.body.authority != config.account
                {
                    eyre::bail!("alias plan differs from the exact wallet authority or network");
                }
                // Recovery checks the retained request and plan without applying today's clock to historical evidence.
                decode_and_verify_alias_setup_plan_for_request(request, plan)
            }
        }
    }
}
fn transfer_report(
    journal: &Journal,
    record: &TransactionJournal,
    status: OperationStatus,
    evidence: Option<&Value>,
) -> OperationReport {
    let (kind, operation) = match &record.operation {
        NativeOperation::AmxDataspaceRegistration {
            registration,
            terms,
            ..
        } => (
            "amx_dataspace_registration",
            norito::json!({"dataspace": (registration.scope.dataspace_id()), "instance": (hex::encode(registration.instance)), "terms": terms}),
        ),
        NativeOperation::MusubiNamespaceBinding { terms, .. } => {
            ("musubi_namespace_binding", norito::json!({"terms": terms}))
        }
        NativeOperation::InitialProviderIngestAuthority { terms, .. } => (
            "initial_provider_ingest_authority",
            norito::json!({"terms": terms}),
        ),
        NativeOperation::InitialGatewaySetup { terms, .. } => {
            ("initial_gateway_setup", norito::json!({"terms": terms}))
        }
        NativeOperation::InitialReputationPolicy { terms, .. } => {
            ("initial_reputation_policy", norito::json!({"terms": terms}))
        }
        NativeOperation::ProviderCapacityDeclaration { terms, .. } => (
            "provider_capacity_declaration",
            norito::json!({"terms": terms}),
        ),
        NativeOperation::ProviderCreditUpsert { terms, .. } => {
            ("provider_credit_upsert", norito::json!({"terms": terms}))
        }
        NativeOperation::ReserveMovementDecision { terms, .. } => {
            ("reserve_movement_decision", norito::json!({"terms": terms}))
        }
        NativeOperation::ReserveTopUpRequest { terms, .. } => (
            "reserve_top_up_request",
            norito::json!({"terms": terms, "request_kind": "top_up", "transfers_reserve_assets": false}),
        ),
        NativeOperation::ReserveAccountRegistration { terms, .. } => (
            "reserve_account_registration",
            norito::json!({"terms": terms}),
        ),
        NativeOperation::InitialReservePolicy { terms, .. } => {
            ("initial_reserve_policy", norito::json!({"terms": terms}))
        }
        NativeOperation::StreamTokenCustodyConfigure { terms, .. } => (
            "stream_token_custody_configure",
            norito::json!({"terms": terms}),
        ),
        NativeOperation::StreamTokenCustodyEnroll { terms, .. } => (
            "stream_token_custody_enroll",
            norito::json!({"terms": terms}),
        ),
        NativeOperation::PrivateRootRegistration {
            alias,
            expected_ownership_generation,
            registration,
            terms,
        } => (
            "private_root_registration",
            norito::json!({"alias": alias, "expected_ownership_generation": expected_ownership_generation, "registration": registration, "terms": terms}),
        ),
        NativeOperation::PrivateRootAnchor {
            state,
            anchor,
            terms,
        } => (
            "private_root_anchor",
            norito::json!({"registration": (state.registration()), "previous_cursor": (state.cursor()), "anchor": anchor, "terms": terms}),
        ),
        NativeOperation::Transfer {
            destination,
            amount,
        } => (
            "transfer",
            norito::json!({"destination": (destination.to_string()), "asset_definition": XOR_ASSET_DEFINITION, "amount": (amount.to_string())}),
        ),
        NativeOperation::AliasSetup {
            request,
            plan,
            bounds,
        } => (
            "alias_setup",
            norito::json!({"request": (request), "plan": (plan), "fee_bounds": bounds}),
        ),
    };
    let mut data = norito::json!({
        "schema": "iroha.wallet.native-transaction-result.v1", "operation": kind, "status": (status.as_str()),
        "network_id": (record.network_id.to_string()), "chain_discriminant": (record.chain_discriminant),
        "account_id": (record.account_id.to_string()), "transaction_hash": (record.transaction_hash),
        "fee_quote": (record.quote), "deadline_ms": (record.deadline_ms), "journal": (journal.path().display().to_string()), "evidence": evidence,
    });
    if let (Some(target), Some(fields)) = (data.as_object_mut(), operation.as_object()) {
        target.extend(fields.clone());
    }
    OperationReport { status, data }
}
pub(crate) fn validate_config(config: &Config) -> Result<()> {
    iroha::account_bootstrap::validate_endpoint(&config.torii_api_url)?;
    if config.account.try_signatory() != Some(config.key_pair.public_key()) {
        eyre::bail!("wallet account must match the configured native signing key");
    }
    Ok(())
}
pub(crate) fn current_unix_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .map_err(|error| eyre!(error))
}
fn transaction_deadline(transaction: &SignedTransaction) -> Result<u64> {
    let ttl = transaction
        .time_to_live()
        .ok_or_else(|| eyre!("wallet transactions require an exact execution deadline"))?;
    let expiry = transaction
        .creation_time()
        .checked_add(ttl)
        .ok_or_else(|| eyre!("wallet transaction deadline overflow"))?;
    u64::try_from(expiry.as_millis()).map_err(|error| eyre!(error))
}
fn transaction_expired(transaction: &SignedTransaction) -> Result<bool> {
    Ok(current_unix_ms()? >= transaction_deadline(transaction)?)
}
fn add_quantity<K: Ord + Clone>(
    required: &mut BTreeMap<K, Quantity>,
    asset: &K,
    amount: &Quantity,
) -> Result<()> {
    let total = required.entry(asset.clone()).or_insert_with(Quantity::zero);
    *total = total.checked_add(amount)?;
    Ok(())
}
pub(crate) struct Observation {
    pub(crate) status: OperationStatus,
    pub(crate) evidence: Option<Value>,
}
pub(crate) fn observe_transaction(
    client: &NativeClient,
    transaction: &SignedTransaction,
) -> Result<Observation> {
    let hash = transaction.hash();
    let Some(status) = client.get_transaction_status_response_global(hash)? else {
        return Ok(Observation {
            status: OperationStatus::Absent,
            evidence: None,
        });
    };
    if status.hash != hex::encode(hash.as_ref()) || status.scope != "global" {
        eyre::bail!("transaction status differs from the saved exact hash or global scope");
    }
    if matches!(status.status.kind.as_str(), "Rejected" | "Expired")
        && status.resolved_from == "state"
    {
        return Ok(Observation {
            status: if status.status.kind == "Expired" {
                OperationStatus::Expired
            } else {
                OperationStatus::Rejected
            },
            evidence: None,
        });
    }
    if status.status.kind != "Applied" || status.resolved_from != "state" {
        if !matches!(
            status.status.kind.as_str(),
            "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired"
        ) {
            eyre::bail!("transaction status uses an unsupported first-release state");
        }
        return Ok(Observation {
            status: OperationStatus::Pending,
            evidence: None,
        });
    }
    let block_height = status
        .status
        .block_height
        .filter(|height| *height > 0)
        .ok_or_else(|| eyre!("Applied status has no committed block height"))?;
    let details = match client
        .get_transaction_details(transaction.hash_as_entrypoint())
        .wrap_err("read exact committed transaction evidence")
    {
        Ok(details) => details,
        Err(error) if typed_not_found(&error) => {
            return Ok(Observation {
                status: OperationStatus::Pending,
                evidence: None,
            });
        }
        Err(error) => return Err(error),
    };
    let TransactionEntrypoint::External(committed) = details.transaction.entrypoint() else {
        eyre::bail!("Applied evidence is not an external transaction");
    };
    if details.transaction.result().is_err()
        || committed.hash() != hash
        || committed.encode_wire_v1()? != transaction.encode_wire_v1()?
    {
        eyre::bail!("Applied evidence differs from the exact saved transaction");
    }
    Ok(Observation {
        status: OperationStatus::Applied,
        evidence: Some(norito::json!({
            "kind": "exact_committed_transaction", "block_height": block_height,
            "entrypoint_hash": (transaction.hash_as_entrypoint().to_string()),
        })),
    })
}
pub(crate) fn typed_not_found(error: &eyre::Report) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<iroha::query::QueryError>(),
            Some(iroha::query::QueryError::Validation(
                iroha::data_model::ValidationFail::QueryFailed(
                    iroha::data_model::query::error::QueryExecutionFail::NotFound
                )
            ))
        )
    })
}

#[cfg(test)]
#[path = "operations_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "operations_cancellation_tests.rs"]
mod cancellation_tests;
