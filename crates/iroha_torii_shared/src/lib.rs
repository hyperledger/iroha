//! Constant values used in Torii that might be re-used by client libraries as well.
use iroha_data_model::{
    account::{AccountAlias, AccountId, OpaqueAccountId},
    asset::{AssetDefinitionId, AssetId},
    nexus::{FeeDebitSource, FeeSponsorProgramId, UniversalAccountId},
    prelude::Quantity,
    query::CommittedTransaction,
    transaction::{FeeChargeKind, FeePaymentIntent, TransactionPayload},
};
use iroha_model_base::topology::DataSpaceId;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
/// Public account-bootstrap network and signing policy.
pub mod account_capabilities;
/// Public faucet identity and exact issuance policy.
pub mod account_faucet_policy;
/// Typed account-alias absence selectors and planning error codes.
pub mod aliases;
/// Scoped canonical account/fee authority originals for an existing native ledger-wide reader.
pub mod authority_originals;
/// Typed non-success observations for challenge-bound bridge finality.
pub mod bridge_attestation;
/// Exact progress bindings for challenge-bound finality attestation reads.
pub mod bridge_finality;
/// Byte-exact canonical query form shared by canonical-request signers and verifiers.
pub mod canonical_request_form;
/// Canonical bounded signing preimage shared by request-witness signers and verifiers.
pub mod canonical_request_witness;
/// Canonical node configuration snapshots and operator update records.
pub mod configuration;
/// File-extension media types shared by the content publisher, Torii, and the SoraFS site gateway.
pub mod content_mime;
/// Shared data-availability helpers (sampling, assignment).
pub mod da;
/// Public Torii DTOs for certificate-only governance proposal drafts.
pub mod governance_proposal_api;
/// Canonical requests and responses for the authenticated KAGEMUSHA enrollment service.
pub mod kagemusha_enrollment;
/// The list-query language (filter, sort, projection, pagination) shared by Torii, SDKs and CLI.
pub mod list_query;
/// Shared MCP wire constants for Torii and repository clients.
pub mod mcp;
/// Original multisig execution records at a certified native World cut.
pub mod multisig_execution_evidence;
/// Public Torii DTOs for authenticated SORA Parliament draft and read routes.
pub mod parliament_api;
/// Stable cross-SDK signing transcript for exact prepared transactions.
pub mod prepared_transaction;
/// Public and restricted DTOs for atomic private cross-dataspace settlement.
pub mod private_settlement_api;
/// Shared QR Code encoder used by Torii and CLI device-handoff flows.
pub mod qr;
/// Complete native alias/SNS originals for an existing signed ledger-wide reader.
pub mod resource_names_state;
/// Canonical Torii route metadata and projection helpers.
pub mod route_catalog;
/// Typed absence response for authoritative SNS registration lookups.
pub mod sns;
/// Canonical gateway-compliance control projections and exact request bindings.
pub mod sorafs_gateway_compliance_api;
/// Canonical wire types for the authenticated SoraFS hedging and billing API.
pub mod sorafs_hedging_billing_api;
/// Canonical wire types for externally signed SoraFS moderation recovery.
pub mod sorafs_moderation_api;
/// Canonical node status response and capability snapshots.
pub mod status;
/// Canonical subscription preparation, query and draft records.
pub mod subscriptions;
/// Canonical response envelopes for the Sumeragi evidence audit API.
pub mod sumeragi_evidence_api;
/// Public Torii DTOs for Parliament-governed validation-fee policy state.
pub mod validation_fee_api;
/// Response header binding a hosted Soracloud response to the served service name.
pub const SORACLOUD_SERVED_SERVICE_NAME_HEADER: &str = "x-iroha-soracloud-served-service-name";
/// Response header binding a hosted Soracloud response to the served service version.
pub const SORACLOUD_SERVED_SERVICE_VERSION_HEADER: &str =
    "x-iroha-soracloud-served-service-version";
/// Response header binding a hosted Soracloud response to the served replica slot.
pub const SORACLOUD_SERVED_REPLICA_SLOT_HEADER: &str = "x-iroha-soracloud-served-replica-slot";
/// Response header binding a hosted Soracloud response to the authoritative process generation.
pub const SORACLOUD_SERVED_PROCESS_GENERATION_HEADER: &str =
    "x-iroha-soracloud-served-process-generation";
/// Response header binding a hosted Soracloud response to the materialized bundle hash.
pub const SORACLOUD_SERVED_MATERIALIZED_BUNDLE_HASH_HEADER: &str =
    "x-iroha-soracloud-served-materialized-bundle-hash";
/// Required WebSocket subprotocol for canonical Norito event and block streams.
pub const NORITO_V1_WEBSOCKET_SUBPROTOCOL: &str = "iroha-norito-v1";
/// Canonical request body for account-signed `POST /v1/fees/quote`.
///
/// The draft fixes every non-fee transaction field and selects the payer,
/// sponsor-program revision, and gas bound. Before signing, replace only its
/// `fee_payment` field with the response's fixed-point [`FeePaymentIntent`].
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteRequest")]
pub struct FeeQuoteRequest {
    /// Exact canonical unsigned transaction payload to evaluate.
    pub payload: TransactionPayload,
}
/// Ledger observation used for a deterministic fee quote.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteObservation")]
pub struct FeeQuoteObservation {
    /// Creation time of the latest committed block, in Unix milliseconds.
    pub ledger_time_ms: u64,
    /// Height at which this payload would next be admitted.
    pub next_block_height: u64,
    /// Dataspace selected by canonical transaction routing.
    pub route_dataspace_id: DataSpaceId,
}
/// One canonically ordered maximum fee component.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteComponent")]
pub struct FeeQuoteComponent {
    /// Fee component represented by this bound.
    pub kind: FeeChargeKind,
    /// Exact asset definition in which this component is charged.
    pub asset_definition_id: AssetDefinitionId,
    /// Maximum deterministic charge at the observed state.
    pub max_amount: Quantity,
}
/// Remaining sponsor-program capacity for one fee asset.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteCapacity")]
pub struct FeeQuoteCapacity {
    /// Asset definition governed by this capacity snapshot.
    pub asset_definition_id: AssetDefinitionId,
    /// Current isolated program-vault balance.
    pub vault_balance: Quantity,
    /// Balance that must remain after settlement.
    pub reserve_floor: Quantity,
    /// Remaining program capacity in the observed block window.
    pub block_remaining: Quantity,
    /// Remaining program capacity in the observed program epoch.
    pub program_epoch_remaining: Quantity,
    /// Remaining beneficiary capacity in the observed beneficiary epoch.
    pub beneficiary_epoch_remaining: Quantity,
}
/// Successful deterministic fee-admission decision.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(
    tag = "status",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteDecision")]
pub enum FeeQuoteDecision {
    /// The payload is admissible at the observed state.
    #[norito(rename = "accepted")]
    Accepted {
        /// Exact account or isolated program vault that will be debited.
        debit_source: FeeDebitSource,
        /// Exact active immutable sponsor revision, when sponsored.
        ///
        /// The slot is mandatory in the first-release JSON shape; authority-paid
        /// quotes encode it as `null` rather than accepting an omitted legacy field.
        #[norito(required)]
        program_revision: Option<u64>,
    },
}
/// Successful response returned by account-signed `POST /v1/fees/quote`.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeQuoteResponse")]
pub struct FeeQuoteResponse {
    /// Exact signature-bound intent evaluated by Core.
    pub intent: FeePaymentIntent,
    /// Ledger observation that fixes the state-dependent result.
    pub observation: FeeQuoteObservation,
    /// Canonically ordered maximum charge components.
    pub components: Vec<FeeQuoteComponent>,
    /// Canonically ordered sponsor capacities; empty for authority payment.
    pub capacities: Vec<FeeQuoteCapacity>,
    /// Successful admission decision and selected debit source.
    pub decision: FeeQuoteDecision,
}
impl FeeQuoteResponse {
    /// Validate this quote against the unsigned payload used to request it.
    ///
    /// The quoted intent may replace the draft's charge limits, but it must
    /// preserve the selected payer, sponsor revision, and executable gas bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the quote is malformed, changes a draft-bound fee
    /// selection, or is inconsistent with the payload authority.
    pub fn validate_for_draft(&self, payload: &TransactionPayload) -> Result<(), String> {
        payload
            .fee_payment_intent()
            .validate()
            .map_err(|error| format!("invalid draft fee payment intent: {error}"))?;
        if !self
            .intent
            .has_same_payer_and_gas_bound(payload.fee_payment_intent())
        {
            return Err(
                "fee quote changed the draft payer, sponsor revision, or gas bound".to_owned(),
            );
        }
        self.validate_for_authority(payload.authority())
    }

    /// Validate this quote against a payload containing the exact quoted intent.
    ///
    /// # Errors
    ///
    /// Returns an error when the signed payload does not contain the quote's
    /// exact fee intent, or when any response field is semantically inconsistent.
    pub fn validate_for_signed_payload(&self, payload: &TransactionPayload) -> Result<(), String> {
        if &self.intent != payload.fee_payment_intent() {
            return Err("fee quote intent differs from the signed payload".to_owned());
        }
        self.validate_for_authority(payload.authority())
    }

    /// Validate standalone quoted fee terms for one exact transaction authority.
    ///
    /// This checks component maxima, payer identity, sponsor revision and capacity consistency.
    /// Signing still requires the draft or signed-payload validator to bind the executable intent.
    ///
    /// # Errors
    /// Returns an error for a malformed quote or an inconsistent payer or capacity.
    pub fn validate_for_authority(
        &self,
        authority: &iroha_data_model::account::AccountId,
    ) -> Result<(), String> {
        self.intent
            .validate()
            .map_err(|error| format!("invalid fee quote intent: {error}"))?;
        if self.observation.next_block_height == 0 {
            return Err("fee quote next_block_height must be non-zero".to_owned());
        }

        let charge_limits = self.intent.charge_limits();
        let components_match = self.components.len() == charge_limits.len()
            && self
                .components
                .iter()
                .zip(charge_limits)
                .all(|(component, limit)| {
                    component.kind == limit.kind()
                        && &component.asset_definition_id == limit.asset_definition_id()
                        && &component.max_amount == limit.max_amount()
                });
        if !components_match {
            return Err("fee quote components differ from the quoted intent".to_owned());
        }

        match self.intent.sponsor_program() {
            None => {
                match &self.decision {
                    FeeQuoteDecision::Accepted {
                        debit_source: FeeDebitSource::Account(account),
                        program_revision: None,
                    } if account == authority => {}
                    _ => {
                        return Err(
                            "authority-paid fee quote has an inconsistent admission decision"
                                .to_owned(),
                        );
                    }
                }
                if !self.capacities.is_empty() {
                    return Err("authority-paid fee quote must not contain capacities".to_owned());
                }
                Ok(())
            }
            Some((program_id, program_revision)) => {
                match &self.decision {
                    FeeQuoteDecision::Accepted {
                        debit_source: FeeDebitSource::SponsorProgram(decision_program_id),
                        program_revision: Some(decision_revision),
                    } if decision_program_id == program_id
                        && *decision_revision == program_revision => {}
                    _ => {
                        return Err(
                            "sponsored fee quote has an inconsistent admission decision".to_owned()
                        );
                    }
                }
                self.validate_sponsor_capacities()
            }
        }
    }

    fn validate_sponsor_capacities(&self) -> Result<(), String> {
        if self.capacities.is_empty() != self.components.is_empty() {
            return Err(
                "sponsored fee quote capacities must be empty exactly when components are empty"
                    .to_owned(),
            );
        }

        let mut aggregate_by_asset = std::collections::BTreeMap::new();
        for component in &self.components {
            let aggregate = aggregate_by_asset
                .entry(component.asset_definition_id.clone())
                .or_insert_with(Quantity::zero);
            *aggregate = aggregate
                .checked_add(&component.max_amount)
                .map_err(|error| {
                    format!(
                        "fee quote component aggregate for {} is invalid: {error}",
                        component.asset_definition_id
                    )
                })?;
        }
        if self.capacities.len() != aggregate_by_asset.len() {
            return Err(
                "sponsored fee quote must contain one capacity per component asset".to_owned(),
            );
        }

        for (capacity, (asset_definition_id, aggregate)) in
            self.capacities.iter().zip(&aggregate_by_asset)
        {
            if &capacity.asset_definition_id != asset_definition_id {
                return Err(
                    "sponsored fee quote capacities are duplicated, unrelated, or not in canonical asset order"
                        .to_owned(),
                );
            }
            let required_vault_balance = capacity
                .reserve_floor
                .checked_add(aggregate)
                .map_err(|error| {
                    format!(
                        "fee quote required vault balance for {asset_definition_id} is invalid: {error}"
                    )
                })?;
            if capacity.vault_balance < required_vault_balance {
                return Err(format!(
                    "fee quote vault capacity for {asset_definition_id} does not cover its reserve and aggregate charge"
                ));
            }
            for (window, remaining) in [
                ("block", &capacity.block_remaining),
                ("program epoch", &capacity.program_epoch_remaining),
                ("beneficiary epoch", &capacity.beneficiary_epoch_remaining),
            ] {
                if remaining < aggregate {
                    return Err(format!(
                        "fee quote {window} capacity for {asset_definition_id} does not cover its aggregate charge"
                    ));
                }
            }
        }
        Ok(())
    }
}
/// Canonical request body for exact sponsor-program lookup.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeSponsorProgramByIdRequest")]
pub struct FeeSponsorProgramByIdRequest {
    /// Canonical `sponsor/program` literal.
    pub program_id: String,
}
impl FeeSponsorProgramByIdRequest {
    /// Construct a lookup request from a typed program identifier.
    #[must_use]
    pub fn new(program_id: &FeeSponsorProgramId) -> Self {
        Self {
            program_id: program_id.to_string(),
        }
    }
}

/// Canonical selector for one sponsor-program enrollment, without enumeration.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeSponsorEnrollmentByIdRequest")]
pub struct FeeSponsorEnrollmentByIdRequest {
    /// Exact canonical `sponsor/program` literal.
    pub program_id: String,
    /// Exact canonical beneficiary account literal.
    pub beneficiary: String,
}
impl FeeSponsorEnrollmentByIdRequest {
    /// Construct an exact enrollment selector from native identities.
    #[must_use]
    pub fn new(program_id: &FeeSponsorProgramId, beneficiary: &AccountId) -> Self {
        Self {
            program_id: program_id.to_string(),
            beneficiary: beneficiary.to_string(),
        }
    }
}

/// Current exact enrollment at the same native World view as read authorization.
///
/// `None` means absence only for this key in an existing program. A missing
/// program or unauthorized request returns an error, never this absence response.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeSponsorEnrollmentByIdResponse")]
pub struct FeeSponsorEnrollmentByIdResponse {
    /// Exact requested program and beneficiary, including on an absent result.
    pub key: iroha_data_model::nexus::FeeSponsorEnrollmentKey,
    /// Original native row, whose key equals `key`, or explicit current absence.
    /// The field is mandatory; only an explicit JSON null establishes absence.
    #[norito(required)]
    pub enrollment: Option<iroha_data_model::nexus::FeeSponsorEnrollment>,
}

/// Queue pressure snapshot returned with transaction queue rejections.
#[derive(JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::QueueErrorSnapshot")]
pub struct QueueErrorSnapshot {
    /// Queue state label (`healthy` or `saturated`).
    pub state: String,
    /// Current queued transaction count.
    pub queued: u64,
    /// Configured queue capacity.
    pub capacity: u64,
    /// Whether the queue is currently saturated.
    pub saturated: bool,
}
/// AXT rejection metadata returned with validation failures when available.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, Default,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::AxtErrorDetails")]
pub struct AxtErrorDetails {
    /// Stable AXT rejection code.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Human-readable AXT rejection label.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// AXT policy snapshot version used to reject the request.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub snapshot_version: Option<u64>,
    /// Dataspace id involved in the rejection.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub dataspace: Option<u64>,
    /// Lane id involved in the rejection.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub lane: Option<u32>,
    /// Exact active handle era a client must use for retry.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub active_handle_era: Option<u64>,
    /// Exact next handle counter a client must use for retry.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub next_handle_counter: Option<u64>,
}
/// Structured fee-payment rejection metadata returned to authorized callers.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, Default,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::FeeErrorDetails")]
pub struct FeeErrorDetails {
    /// Stable snake-case [`iroha_data_model::nexus::FeeRejectionCode`] label.
    pub code: String,
    /// Whether retrying after a state or capacity change can succeed unchanged.
    pub retryable: bool,
    /// Exact sponsor program selected by the signed transaction, when applicable.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
    /// Exact sponsor-program revision selected by the signed transaction.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub program_revision: Option<u64>,
    /// Canonical fee asset involved in the rejection.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub asset_definition_id: Option<String>,
    /// Deterministic amount required at the observation state.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub required: Option<String>,
    /// Deterministic amount available at the observation state.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub available: Option<String>,
    /// Stable matching rule identifier, when disclosure is authorized.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Consensus height at which this decision was evaluated.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub observation_height: Option<u64>,
    /// Concrete repair or retry guidance.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}
/// Structured metadata carried by [`ErrorEnvelope`].
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, Default,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::ErrorDetails")]
pub struct ErrorDetails {
    /// Canonical deterministic IVM fault, excluding application errors and local refusals.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub ivm_fault: Option<iroha_data_model::executor::fault::IvmFaultV1>,
    /// Public surface layer that produced the error (for example `cli`, `torii`, or `mcp`).
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    /// ISO-20022-style or Torii-local rejection code when available.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub reject_code: Option<String>,
    /// Queue pressure snapshot at transaction rejection time.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub queue: Option<QueueErrorSnapshot>,
    /// Suggested retry delay in seconds for transient errors.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
    /// Endpoint associated with throttling or version failures.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Field associated with validation or decode failures.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Expected field value, status, profile, or discriminant.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// Actual field value, status, profile, or discriminant.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    /// Network profile involved in the error.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// I105 chain discriminant involved in the error.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub chain_discriminant: Option<u16>,
    /// Canonical transaction-entrypoint hash involved in admission failures.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub entrypoint_hash: Option<String>,
    /// Signed transaction hash involved in finality/status failures.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Exact scoped pipeline-status absence for its named HTTP 404 error.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub pipeline_transaction_status_not_found: Option<PipelineTransactionStatusNotFoundV1>,
    /// Closed request-bound failure from the finality attestation endpoint.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub finality_attestation_failure: Option<bridge_attestation::FinalityAttestationFailure>,
    /// Last observed transaction status when a finality wait failed.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    /// Actionable debugging hint for callers.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// AXT rejection metadata when validation failed under AXT policy.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub axt: Option<AxtErrorDetails>,
    /// Fee-payment rejection metadata when admission or settlement failed.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub fee: Option<FeeErrorDetails>,
    /// Native alias planning report for a rejected or pending plan.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub alias_setup_report: Option<iroha_data_model::alias_setup::AliasSetupReportV1>,
    /// Exact alias selector that was absent from authoritative ledger state.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub account_alias_not_found: Option<aliases::AccountAliasNotFoundV1>,
    /// Exact account and optional scope filters whose account lookup was absent.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub account_aliases_by_account_not_found: Option<aliases::AccountAliasesByAccountNotFoundV1>,
    /// Exact missing SNS registration selector for `sns_registration_not_found` HTTP 404.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub sns_registration_not_found: Option<sns::SnsRegistrationNotFoundV1>,
    /// Exact missing asset selector for `query_asset_not_found` HTTP 404.
    ///
    /// This reports a completed authoritative lookup, not a cryptographic proof.
    /// Clients must check the status, error code, and requested asset identity together.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub query_asset_not_found: Option<AssetId>,
}
impl ErrorDetails {
    /// Return whether this details payload carries any structured fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ivm_fault.is_none()
            && self.layer.is_none()
            && self.reject_code.is_none()
            && self.queue.is_none()
            && self.retry_after_seconds.is_none()
            && self.endpoint.is_none()
            && self.field.is_none()
            && self.expected.is_none()
            && self.actual.is_none()
            && self.profile.is_none()
            && self.chain_discriminant.is_none()
            && self.entrypoint_hash.is_none()
            && self.tx_hash.is_none()
            && self.pipeline_transaction_status_not_found.is_none()
            && self.finality_attestation_failure.is_none()
            && self.last_status.is_none()
            && self.hint.is_none()
            && self.axt.is_none()
            && self.fee.is_none()
            && self.alias_setup_report.is_none()
            && self.account_alias_not_found.is_none()
            && self.account_aliases_by_account_not_found.is_none()
            && self.sns_registration_not_found.is_none()
            && self.query_asset_not_found.is_none()
    }
}
/// Stable public network profile metadata used by clients and Torii helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProfile {
    /// Profile name accepted by public tooling.
    pub name: &'static str,
    /// I105 chain discriminant assigned to this public network.
    pub chain_discriminant: u16,
}
/// Taira public testnet profile name.
pub const NETWORK_PROFILE_TAIRA: &str = "taira";
/// Minamoto public network profile name.
pub const NETWORK_PROFILE_MINAMOTO: &str = "minamoto";
/// Taira public testnet I105 chain discriminant.
pub const TAIRA_CHAIN_DISCRIMINANT: u16 = 369;
/// Minamoto public network I105 chain discriminant.
pub const MINAMOTO_CHAIN_DISCRIMINANT: u16 = 753;
/// Public network profiles accepted by developer-facing tools.
pub const NETWORK_PROFILES: &[NetworkProfile] = &[
    NetworkProfile {
        name: NETWORK_PROFILE_TAIRA,
        chain_discriminant: TAIRA_CHAIN_DISCRIMINANT,
    },
    NetworkProfile {
        name: NETWORK_PROFILE_MINAMOTO,
        chain_discriminant: MINAMOTO_CHAIN_DISCRIMINANT,
    },
];
/// Resolve a public network profile by name.
#[must_use]
pub fn network_profile(name: &str) -> Option<&'static NetworkProfile> {
    NETWORK_PROFILES
        .iter()
        .find(|profile| profile.name.eq_ignore_ascii_case(name.trim()))
}
/// Resolve a public network profile by I105 chain discriminant.
#[must_use]
pub fn network_profile_for_discriminant(discriminant: u16) -> Option<&'static NetworkProfile> {
    NETWORK_PROFILES
        .iter()
        .find(|profile| profile.chain_discriminant == discriminant)
}
/// Return a comma-separated list of supported public network profile names.
#[must_use]
pub fn network_profile_names() -> String {
    NETWORK_PROFILES
        .iter()
        .map(|profile| profile.name)
        .collect::<Vec<_>>()
        .join(", ")
}
/// Stable code for exact scoped pipeline transaction status absence.
pub const PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE: &str =
    "pipeline_transaction_status_not_found";
/// Maximum complete scoped pipeline status absence envelope size.
pub const PIPELINE_TRANSACTION_STATUS_NOT_FOUND_MAX_BYTES: usize = 4096;
/// Exact lookup identity for absent pipeline status; not proof of ledger non-inclusion.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::PipelineTransactionStatusNotFoundV1")]
pub struct PipelineTransactionStatusNotFoundV1 {
    /// Canonical lowercase signed-transaction hash requested by the caller.
    pub hash: String,
    /// Exact lookup scope: `local` or `global`.
    pub scope: String,
}
impl PipelineTransactionStatusNotFoundV1 {
    /// Construct the exact public lookup identity.
    #[must_use]
    pub fn new(
        hash: &iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
        scope: &str,
    ) -> Self {
        Self {
            hash: hash.to_string(),
            scope: scope.to_owned(),
        }
    }
    /// Require a canonical native hash and one supported scope.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self.scope.as_str(), "local" | "global")
            && self
                .hash
                .parse::<iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>>()
                .is_ok_and(|hash| hash.to_string() == self.hash)
    }
    /// Bind this observation to the caller's exact hash and scope.
    #[must_use]
    pub fn matches(
        &self,
        hash: &iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
        scope: &str,
    ) -> bool {
        matches!(scope, "local" | "global") && self.scope == scope && self.hash == hash.to_string()
    }
}

/// Canonical Torii error envelope returned for HTTP API failures.
#[derive(JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::ErrorEnvelope")]
pub struct ErrorEnvelope {
    /// Stable error code string.
    pub code: String,
    /// Human-readable error detail.
    pub message: String,
    /// Optional machine-readable context for this error.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}
impl ErrorEnvelope {
    /// Construct a new error envelope.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }
    /// Attach structured details to an error envelope.
    #[must_use]
    pub fn with_details(mut self, details: ErrorDetails) -> Self {
        self.details = Some(details);
        self
    }
    /// Stable error code string.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }
    /// Human-readable error detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
/// Maximum distinct proof backends that one retention-status response may summarize.
///
/// This first-release protocol ceiling bounds node-local aggregation and response memory. Torii
/// fails the request with HTTP 422 when the proof registry contains more distinct backends.
pub const PROOF_RETENTION_STATUS_MAX_BACKENDS: usize = 256;
/// Per-backend proof retention snapshot.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::ProofRetentionBackendStatus")]
pub struct ProofRetentionBackendStatus {
    /// Backend identifier (e.g., `halo2/ipa`).
    pub backend: String,
    /// Total proof records currently tracked for this backend.
    pub records: u64,
    /// Proof records that would be pruned if retention runs now.
    pub prunable: u64,
    /// Oldest verification height (if recorded).
    pub oldest_height: Option<u64>,
    /// Newest verification height (if recorded).
    pub newest_height: Option<u64>,
}
/// Proof retention configuration and live counters.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::ProofRetentionStatus")]
pub struct ProofRetentionStatus {
    /// Configured per-backend cap (0 = unlimited).
    pub cap_per_backend: usize,
    /// Grace window (blocks) retained before pruning by age.
    pub grace_blocks: u64,
    /// Maximum removals per enforcement pass (0 = unlimited).
    pub prune_batch: usize,
    /// Aggregate proof count across all backends.
    pub total_records: u64,
    /// Aggregate proof count that would be pruned if enforcement runs now.
    pub total_prunable: u64,
    /// Per-backend retention snapshots.
    pub backends: Vec<ProofRetentionBackendStatus>,
}
/// Typed status payload returned by `/v1/pipeline/transactions/status`.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::PipelineTransactionStatusResponse")]
pub struct PipelineTransactionStatusResponse {
    /// Canonical signed transaction hash (64 lowercase hex digits with the Iroha marker set).
    pub hash: String,
    /// Current pipeline status details.
    pub status: PipelineTransactionStatus,
    /// Read scope applied by Torii (`local` or `global`).
    pub scope: String,
    /// Source used to resolve the status (`cache`, `queue`, `state`).
    pub resolved_from: String,
}
/// Compact trigger completion included in authenticated detail and historical evidence.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::TriggerCompletionSummary")]
pub struct TriggerCompletionSummary {
    /// Trigger identifier.
    pub trigger_id: String,
    /// Entrypoint hash for this trigger execution.
    pub trigger_execution_hash: String,
    /// Step index within the entrypoint execution.
    pub step_index: u32,
    /// `Success` or `Failure`.
    pub outcome: String,
    /// Failure message when present.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
/// Historical trigger completion record returned by `/v1/triggers/completed`.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::TriggerCompletionRecord")]
pub struct TriggerCompletionRecord {
    /// Block height containing this trigger completion.
    pub block_height: u64,
    /// Entrypoint/result index in the block when it can be resolved.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub entrypoint_index: Option<u64>,
    /// Compact completion payload.
    pub completion: TriggerCompletionSummary,
    /// Evidence source. Always `execution_output`: completions are read only from the
    /// block's persisted execution outputs.
    pub source: String,
}
/// Historical trigger completion query response.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::TriggerCompletionListResponse")]
pub struct TriggerCompletionListResponse {
    /// Latest committed block height observed by the serving node.
    pub latest_height: u64,
    /// First block height scanned.
    pub from_height: u64,
    /// Last block height scanned.
    pub to_height: u64,
    /// Number of block heights inspected.
    pub scanned_blocks: u64,
    /// Maximum number of records requested.
    pub limit: u64,
    /// Matching completion records, newest block first.
    pub completions: Vec<TriggerCompletionRecord>,
}
/// Status details embedded in [`PipelineTransactionStatusResponse`].
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::PipelineTransactionStatus")]
pub struct PipelineTransactionStatus {
    /// Stable pipeline status kind (`Queued`, `Approved`, `Committed`, `Applied`, `Rejected`, `Expired`).
    pub kind: String,
    /// Block height reported for the status when available.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}
/// Authenticated detailed transaction response.
///
/// This payload is never returned by the public pipeline-status endpoint. It is available only
/// after canonical signed-query admission and an involved-account or operator authorization check.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::PipelineTransactionDetailsResponse")]
#[norito(deny_unknown_fields)]
pub struct PipelineTransactionDetailsResponse {
    /// Exact requested network entrypoint hash, including the outer sealed-reveal identity.
    pub hash: String,
    /// Exact Network input and sole full typed output, including its result, receipts,
    /// and owned callback completions. Separate Pipeline/Time outputs require their own
    /// authenticated output proofs; this response never infers their association.
    pub transaction: CommittedTransaction,
}
impl PipelineTransactionStatusResponse {
    /// Construct a public status-only response.
    #[must_use]
    pub fn new(
        hash: String,
        status: PipelineTransactionStatus,
        scope: String,
        resolved_from: String,
    ) -> Self {
        Self {
            hash,
            status,
            scope,
            resolved_from,
        }
    }
}
/// Canonical account-read payload returned by `GET /v1/accounts/{account_id}`.
#[derive(
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::AccountReadResponse")]
pub struct AccountReadResponse {
    /// Canonical account identifier (domainless I105 literal).
    pub account_id: AccountId,
    /// Stable account label when assigned.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub label: Option<AccountAlias>,
    /// Universal account identifier bound to this account when registered in Nexus.
    #[norito(default)]
    #[norito(skip_serializing_if = "Option::is_none")]
    pub uaid: Option<UniversalAccountId>,
    /// Opaque identifiers mapped to the account UAID.
    #[norito(default)]
    #[norito(skip_serializing_if = "Vec::is_empty")]
    pub opaque_ids: Vec<OpaqueAccountId>,
}
/// Maximum encoded response size for one atomic onboarding-state observation.
pub const ACCOUNT_ONBOARDING_CURRENT_STATE_RESPONSE_MAX_BYTES: usize = 4 * 1024;

/// Exact first-release request for one atomic account-onboarding state observation.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::AccountOnboardingCurrentStateRequestV1")]
pub struct AccountOnboardingCurrentStateRequestV1 {
    /// Request layout version. The only accepted value is `1`.
    pub version: u8,
    /// Canonical domainless I105 account identifier whose existence must be observed.
    pub account_id: String,
    /// Exact canonical account alias whose active target must be observed.
    pub alias: String,
}
impl AccountOnboardingCurrentStateRequestV1 {
    /// Current and only first-release request layout.
    pub const VERSION: u8 = 1;
    /// Construct one exact request from canonical typed identities.
    #[must_use]
    pub fn new(
        account_id: &AccountId,
        alias: &iroha_data_model::alias_setup::AccountAliasName,
    ) -> Self {
        Self {
            version: Self::VERSION,
            account_id: account_id.to_string(),
            alias: alias.to_string(),
        }
    }
    /// Validate the closed V1 layout and return its exact typed identities.
    ///
    /// # Errors
    /// Returns an error for an unsupported version or a non-canonical identity literal.
    pub fn validate_exact(
        &self,
    ) -> Result<(AccountId, iroha_data_model::alias_setup::AccountAliasName), String> {
        if self.version != Self::VERSION {
            return Err(format!(
                "unsupported account onboarding current-state request version {}; expected {}",
                self.version,
                Self::VERSION,
            ));
        }
        let parsed_account = AccountId::parse_encoded(&self.account_id)
            .map_err(|error| format!("invalid canonical account_id: {error}"))?;
        if parsed_account.to_string() != self.account_id {
            return Err("account_id must use its exact canonical I105 literal".to_owned());
        }
        let account_id = parsed_account;
        let alias = self
            .alias
            .parse::<iroha_data_model::alias_setup::AccountAliasName>()
            .map_err(|error| format!("invalid canonical account alias: {error}"))?;
        if alias.to_string() != self.alias {
            return Err("alias must use its exact canonical literal".to_owned());
        }
        Ok((account_id, alias))
    }
}
/// One internally consistent first-release account-onboarding state observation.
///
/// Every consensus-derived field is read from one committed state snapshot. A target account in
/// `alias_target_account_id` has therefore also been proven to exist by the active-alias resolver.
#[derive(
    JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize, Debug, Clone, PartialEq, Eq,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::AccountOnboardingCurrentStateResponseV1")]
pub struct AccountOnboardingCurrentStateResponseV1 {
    /// Response layout version. The only accepted value is `1`.
    pub version: u8,
    /// Exact genesis-derived network that owns the observed state.
    pub network_id: iroha_data_model::NetworkId,
    /// Canonical requested account identifier.
    pub account_id: String,
    /// Canonical requested account alias.
    pub alias: String,
    /// Whether the exact requested account exists in the observed state.
    pub account_exists: bool,
    /// Exact active alias target, or `null` when the alias has no active target.
    #[norito(required)]
    pub alias_target_account_id: Option<String>,
    /// Nonzero committed block height anchoring the observation.
    pub observed_block_height: u64,
    /// Exact committed block hash anchoring the observation.
    pub observed_block_hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader>,
}
impl AccountOnboardingCurrentStateResponseV1 {
    /// Current and only first-release response layout.
    pub const VERSION: u8 = 1;
    /// Validate the response against one exact request and expected network.
    ///
    /// # Errors
    /// Returns an error for any substituted identity, unsupported version, zero height, or
    /// non-canonical alias target.
    pub fn validate_for(
        &self,
        request: &AccountOnboardingCurrentStateRequestV1,
        expected_network_id: &iroha_data_model::NetworkId,
    ) -> Result<(std::num::NonZeroU64, Option<AccountId>), String> {
        let (requested_account, _) = request.validate_exact()?;
        if self.version != Self::VERSION {
            return Err(format!(
                "unsupported account onboarding current-state response version {}; expected {}",
                self.version,
                Self::VERSION,
            ));
        }
        if &self.network_id != expected_network_id {
            return Err("account onboarding current-state response changed network_id".to_owned());
        }
        if self.account_id != request.account_id || self.alias != request.alias {
            return Err(
                "account onboarding current-state response does not bind the exact request"
                    .to_owned(),
            );
        }
        let observed_block_height = std::num::NonZeroU64::new(self.observed_block_height)
            .ok_or_else(|| {
                "account onboarding current-state response has a zero committed height".to_owned()
            })?;
        let alias_target = self
            .alias_target_account_id
            .as_deref()
            .map(|literal| {
                let parsed = AccountId::parse_encoded(literal)
                    .map_err(|error| format!("invalid alias target account_id: {error}"))?;
                if parsed.to_string() != literal {
                    return Err("alias target must use its exact canonical I105 literal".to_owned());
                }
                Ok(parsed)
            })
            .transpose()?;
        if alias_target.as_ref() == Some(&requested_account) && !self.account_exists {
            return Err(
                "alias target cannot equal an account reported absent in the same state snapshot"
                    .to_owned(),
            );
        }
        Ok((observed_block_height, alias_target))
    }
}
#[cfg(test)]
mod tests {
    use super::{
        AccountOnboardingCurrentStateRequestV1, AccountOnboardingCurrentStateResponseV1,
        AccountReadResponse, ErrorDetails, ErrorEnvelope, FeeErrorDetails, FeeQuoteCapacity,
        FeeQuoteComponent, FeeQuoteDecision, FeeQuoteObservation, FeeQuoteResponse,
        FeeSponsorProgramByIdRequest, MINAMOTO_CHAIN_DISCRIMINANT, NETWORK_PROFILE_MINAMOTO,
        NETWORK_PROFILE_TAIRA, PipelineTransactionStatus, PipelineTransactionStatusResponse,
        QueueErrorSnapshot, TAIRA_CHAIN_DISCRIMINANT, network_profile,
        network_profile_for_discriminant,
    };
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::{AccountAlias, AccountAliasDomain, AccountId},
        alias_setup::AccountAliasName,
        asset::{AssetDefinitionId, AssetId},
        block::BlockHeader,
        nexus::{FeeDebitSource, FeeSponsorProgramId},
        prelude::Quantity,
        transaction::{
            FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder, TransactionPayload,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use iroha_model_base::topology::DataSpaceId;
    use std::num::NonZeroU64;

    fn checked_test_keypair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("Torii shared test fixture key derivation should succeed")
    }
    fn fee_quote_test_asset(name: &str) -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "universal").expect("valid fee domain"),
            name.parse().expect("valid fee asset name"),
        )
    }
    fn fee_quote_test_payload(
        authority: AccountId,
        fee_payment: FeePaymentIntent,
    ) -> TransactionPayload {
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"fee-quote-validation-network",
            )));
        TransactionBuilder::new(network_id, authority, fee_payment)
            .payload()
            .clone()
    }
    fn fee_quote_components(intent: &FeePaymentIntent) -> Vec<FeeQuoteComponent> {
        intent
            .charge_limits()
            .iter()
            .map(|limit| FeeQuoteComponent {
                kind: limit.kind(),
                asset_definition_id: limit.asset_definition_id().clone(),
                max_amount: limit.max_amount().clone(),
            })
            .collect()
    }
    fn fee_quote_capacity(
        asset_definition_id: AssetDefinitionId,
        aggregate: Quantity,
    ) -> FeeQuoteCapacity {
        let reserve_floor = Quantity::from(2_u32);
        let vault_balance = reserve_floor
            .checked_add(&aggregate)
            .expect("small fixture quantities add exactly");
        FeeQuoteCapacity {
            asset_definition_id,
            vault_balance,
            reserve_floor,
            block_remaining: aggregate.clone(),
            program_epoch_remaining: aggregate.clone(),
            beneficiary_epoch_remaining: aggregate,
        }
    }
    fn sponsored_fee_quote_fixture() -> (
        TransactionPayload,
        FeeQuoteResponse,
        FeeSponsorProgramId,
        [AssetDefinitionId; 2],
    ) {
        let authority = AccountId::new(checked_test_keypair(0x31).public_key().clone());
        let sponsor = AccountId::new(checked_test_keypair(0x32).public_key().clone());
        let program_id = FeeSponsorProgramId::new(
            sponsor,
            "retail".parse().expect("valid sponsor-program name"),
        );
        let mut assets = [fee_quote_test_asset("alpha"), fee_quote_test_asset("beta")];
        assets.sort();
        let intent = FeePaymentIntent::sponsor(
            program_id.clone(),
            7,
            vec![
                FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    assets[1].clone(),
                    Quantity::from(3_u32),
                ),
                FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    assets[0].clone(),
                    Quantity::from(5_u32),
                ),
            ],
            NonZeroU64::new(50),
        );
        let payload = fee_quote_test_payload(authority, intent.clone());
        let quote = FeeQuoteResponse {
            components: fee_quote_components(&intent),
            intent,
            observation: FeeQuoteObservation {
                ledger_time_ms: 42,
                next_block_height: 7,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            capacities: vec![
                fee_quote_capacity(assets[0].clone(), Quantity::from(5_u32)),
                fee_quote_capacity(assets[1].clone(), Quantity::from(3_u32)),
            ],
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(program_id.clone()),
                program_revision: Some(7),
            },
        };
        (payload, quote, program_id, assets)
    }
    fn authority_fee_quote_fixture() -> (TransactionPayload, FeeQuoteResponse) {
        let authority = AccountId::new(checked_test_keypair(0x33).public_key().clone());
        let intent = FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_quote_test_asset("authority"),
                Quantity::from(4_u32),
            )],
            None,
        );
        let payload = fee_quote_test_payload(authority.clone(), intent.clone());
        let quote = FeeQuoteResponse {
            components: fee_quote_components(&intent),
            intent,
            observation: FeeQuoteObservation {
                ledger_time_ms: 42,
                next_block_height: 7,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            capacities: Vec::new(),
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(authority),
                program_revision: None,
            },
        };
        (payload, quote)
    }
    fn assert_fee_quote_rejected_by_both(
        quote: &FeeQuoteResponse,
        payload: &TransactionPayload,
        case: &str,
    ) {
        assert!(
            quote.validate_for_draft(payload).is_err(),
            "draft validator accepted {case}"
        );
        assert!(
            quote.validate_for_signed_payload(payload).is_err(),
            "signed-payload validator accepted {case}"
        );
    }
    #[test]
    fn fee_quote_standalone_authority_validation_matches_payload_semantics() {
        let (payload, quote) = authority_fee_quote_fixture();
        quote
            .validate_for_authority(payload.authority())
            .expect("matching authority quote");
        let foreign = AccountId::new(checked_test_keypair(0x36).public_key().clone());
        assert!(quote.validate_for_authority(&foreign).is_err());
        let (payload, quote, _, _) = sponsored_fee_quote_fixture();
        quote
            .validate_for_authority(payload.authority())
            .expect("matching sponsor quote");
        let mut malformed = quote;
        malformed.capacities.clear();
        assert!(
            malformed
                .validate_for_authority(payload.authority())
                .is_err()
        );
    }
    #[test]
    fn onboarding_current_state_contract_is_closed_and_exact() {
        let account_id = AccountId::new(checked_test_keypair(0x25).public_key().clone());
        let alias = "merchant@banka.paynet"
            .parse::<AccountAliasName>()
            .expect("canonical onboarding alias");
        let request = AccountOnboardingCurrentStateRequestV1::new(&account_id, &alias);
        assert_eq!(
            request.validate_exact().expect("exact request"),
            (account_id.clone(), alias.clone())
        );
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"onboarding-current-state-network",
            )));
        let response = AccountOnboardingCurrentStateResponseV1 {
            version: AccountOnboardingCurrentStateResponseV1::VERSION,
            network_id,
            account_id: account_id.to_string(),
            alias: alias.to_string(),
            account_exists: true,
            alias_target_account_id: Some(account_id.to_string()),
            observed_block_height: 7,
            observed_block_hash: HashOf::from_untyped_unchecked(Hash::new(
                b"onboarding-current-state-block",
            )),
        };
        let (height, target) = response
            .validate_for(&request, &network_id)
            .expect("exact response");
        assert_eq!(height.get(), 7);
        assert_eq!(target, Some(account_id));

        let mut missing_nullable_target =
            norito::json::to_value(&response).expect("encode onboarding current-state response");
        missing_nullable_target
            .as_object_mut()
            .expect("response object")
            .remove("alias_target_account_id");
        assert!(
            norito::json::from_value::<AccountOnboardingCurrentStateResponseV1>(
                missing_nullable_target,
            )
            .is_err(),
            "alias_target_account_id must be present even when its value is null"
        );

        let mut unknown_field =
            norito::json::to_value(&request).expect("encode onboarding current-state request");
        unknown_field
            .as_object_mut()
            .expect("request object")
            .insert("legacy_account".to_owned(), "forbidden".into());
        assert!(
            norito::json::from_value::<AccountOnboardingCurrentStateRequestV1>(unknown_field)
                .is_err(),
            "the first-release request must reject compatibility fields"
        );
    }
    #[test]
    fn onboarding_current_state_validation_rejects_substitution_and_zero_height() {
        let account_id = AccountId::new(checked_test_keypair(0x26).public_key().clone());
        let alias = "merchant@paynet"
            .parse::<AccountAliasName>()
            .expect("canonical onboarding alias");
        let request = AccountOnboardingCurrentStateRequestV1::new(&account_id, &alias);
        let network_id =
            NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                b"onboarding-current-state-validation-network",
            )));
        let mut response = AccountOnboardingCurrentStateResponseV1 {
            version: AccountOnboardingCurrentStateResponseV1::VERSION,
            network_id,
            account_id: account_id.to_string(),
            alias: alias.to_string(),
            account_exists: true,
            alias_target_account_id: None,
            observed_block_height: 0,
            observed_block_hash: HashOf::from_untyped_unchecked(Hash::new(
                b"onboarding-current-state-validation-block",
            )),
        };
        assert!(response.validate_for(&request, &network_id).is_err());
        response.observed_block_height = 1;
        response.alias.push('x');
        assert!(response.validate_for(&request, &network_id).is_err());
    }
    #[test]
    fn error_envelope_new_sets_fields() {
        let envelope = ErrorEnvelope::new("test_code", "test message");
        assert_eq!(envelope.code(), "test_code");
        assert_eq!(envelope.message(), "test message");
    }
    #[test]
    fn privacy_issuance_error_fixture_matches_authoritative_norito_serializer() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(
            "../../../fixtures/privacy/bootle_lantern_issuance_client_v1.json"
        ))
        .expect("privacy issuance cross-SDK fixture must parse");
        let rows = fixture
            .get("errors")
            .and_then(norito::json::Value::as_object)
            .and_then(|errors| errors.get("responses"))
            .and_then(norito::json::Value::as_array)
            .expect("privacy issuance fixture error rows");
        let mut checked = 0_usize;
        let mut mismatches = Vec::new();
        for row in rows {
            let status = row
                .get("status")
                .and_then(norito::json::Value::as_u64)
                .expect("privacy issuance fixture status");
            if status == 406 {
                continue;
            }
            let code = row
                .get("code")
                .and_then(norito::json::Value::as_str)
                .expect("privacy issuance fixture error code");
            let fixture_hex = row
                .get("body_hex")
                .and_then(norito::json::Value::as_str)
                .expect("Norito privacy issuance fixture body_hex");
            let canonical = norito::to_bytes(&ErrorEnvelope::new(code, code))
                .expect("authoritative ErrorEnvelope serialization");
            let canonical_hex = hex::encode(canonical);
            if fixture_hex != canonical_hex {
                mismatches.push(format!("status {status}: {canonical_hex}"));
            }
            checked += 1;
        }
        assert_eq!(checked, 7, "every non-406 error row must use Norito");
        assert!(
            mismatches.is_empty(),
            "stale privacy issuance body_hex; replace only with these authoritative serializer outputs:\n{}",
            mismatches.join("\n"),
        );
    }
    #[test]
    fn fee_program_selector_and_quote_response_roundtrip_canonically() {
        let account = AccountId::new(checked_test_keypair(0x24).public_key().clone());
        let program_id = FeeSponsorProgramId::new(
            account.clone(),
            "retail".parse().expect("canonical sponsor-program name"),
        );
        let selector = FeeSponsorProgramByIdRequest::new(&program_id);
        let selector_json = norito::json::to_vec(&selector).expect("encode program selector");
        let decoded_selector: FeeSponsorProgramByIdRequest =
            norito::json::from_slice(&selector_json).expect("decode program selector");
        assert_eq!(decoded_selector, selector);
        assert_eq!(decoded_selector.program_id, program_id.to_string());
        let quote = FeeQuoteResponse {
            intent: FeePaymentIntent::authority(Vec::new(), None),
            observation: FeeQuoteObservation {
                ledger_time_ms: 42,
                next_block_height: 7,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            components: Vec::new(),
            capacities: Vec::new(),
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(account),
                program_revision: None,
            },
        };
        let quote_json = norito::json::to_vec(&quote).expect("encode typed fee quote");
        let decoded_quote: FeeQuoteResponse =
            norito::json::from_slice(&quote_json).expect("decode typed fee quote");
        assert_eq!(decoded_quote, quote);

        let quote_text = std::str::from_utf8(&quote_json).expect("fee quote JSON is UTF-8");
        let duplicate_root = quote_text.replacen('{', r#"{"components":[],"#, 1);
        let duplicate_nested = quote_text.replacen(
            r#""next_block_height":7"#,
            r#""next_block_height":7,"\u006eext_block_height":7"#,
            1,
        );
        for (path, duplicate) in [
            ("components", duplicate_root),
            ("observation.next_block_height", duplicate_nested),
        ] {
            assert_ne!(duplicate, quote_text, "duplicate fixture for {path}");
            let error = norito::json::from_slice::<FeeQuoteResponse>(duplicate.as_bytes())
                .expect_err("duplicate fee quote response key must be rejected");
            assert!(
                error.to_string().contains("duplicate field"),
                "unexpected duplicate-key error for {path}: {error}"
            );
        }

        let mut missing_revision =
            norito::json::to_value(&quote).expect("encode exact fee quote object");
        assert_eq!(
            missing_revision
                .as_object()
                .and_then(|root| root.get("decision"))
                .and_then(norito::json::Value::as_object)
                .and_then(|decision| decision.get("value"))
                .and_then(norito::json::Value::as_object)
                .and_then(|value| value.get("program_revision")),
            Some(&norito::json::Value::Null),
            "authority quotes must encode the mandatory nullable revision slot"
        );
        missing_revision
            .as_object_mut()
            .and_then(|root| root.get_mut("decision"))
            .and_then(norito::json::Value::as_object_mut)
            .and_then(|decision| decision.get_mut("value"))
            .and_then(norito::json::Value::as_object_mut)
            .expect("fee quote decision value")
            .remove("program_revision");
        assert!(
            norito::json::from_value::<FeeQuoteResponse>(missing_revision).is_err(),
            "fee quotes must reject the pre-release omitted revision slot"
        );

        for path in [
            &["retired_v0"][..],
            &["observation", "retired_v0"][..],
            &["decision", "retired_v0"][..],
            &["decision", "value", "retired_v0"][..],
        ] {
            let mut unknown =
                norito::json::to_value(&quote).expect("encode exact fee quote object");
            let mut object = unknown.as_object_mut().expect("fee quote object");
            for segment in &path[..path.len() - 1] {
                object = object
                    .get_mut(*segment)
                    .and_then(norito::json::Value::as_object_mut)
                    .expect("nested fee quote object");
            }
            object.insert(
                path[path.len() - 1].to_owned(),
                norito::json::Value::from("forbidden"),
            );
            assert!(
                norito::json::from_value::<FeeQuoteResponse>(unknown).is_err(),
                "first-release fee quote accepted unknown path {}",
                path.join("."),
            );
        }
    }

    #[test]
    fn fee_enrollment_point_read_roundtrips_present_and_absent() {
        use super::{FeeSponsorEnrollmentByIdRequest, FeeSponsorEnrollmentByIdResponse};
        use iroha_data_model::nexus::{FeeSponsorEnrollment, FeeSponsorEnrollmentKey};

        let sponsor = AccountId::new(checked_test_keypair(0x25).public_key().clone());
        let beneficiary = AccountId::new(checked_test_keypair(0x26).public_key().clone());
        let program_id = FeeSponsorProgramId::new(sponsor, "dpn".parse().unwrap());
        let request = FeeSponsorEnrollmentByIdRequest::new(&program_id, &beneficiary);
        let request_json = norito::json::to_vec(&request).unwrap();
        assert_eq!(
            norito::json::from_slice::<FeeSponsorEnrollmentByIdRequest>(&request_json).unwrap(),
            request
        );
        let request_bytes = norito::to_bytes(&request).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<FeeSponsorEnrollmentByIdRequest>(&request_bytes).unwrap(),
            request
        );
        let key = FeeSponsorEnrollmentKey {
            program_id,
            beneficiary,
        };
        for enrollment in [
            None,
            Some(FeeSponsorEnrollment {
                key: key.clone(),
                enrolled_at_height: 19,
            }),
        ] {
            let response = FeeSponsorEnrollmentByIdResponse {
                key: key.clone(),
                enrollment,
            };
            let bytes = norito::to_bytes(&response).unwrap();
            assert_eq!(
                norito::decode_from_bytes::<FeeSponsorEnrollmentByIdResponse>(&bytes).unwrap(),
                response
            );
            let json = norito::json::to_vec(&response).unwrap();
            assert_eq!(
                norito::json::from_slice::<FeeSponsorEnrollmentByIdResponse>(&json).unwrap(),
                response
            );
        }
        let key_json = norito::json::to_string(&key).unwrap();
        let absent_json = norito::json::to_value(&FeeSponsorEnrollmentByIdResponse {
            key: key.clone(),
            enrollment: None,
        })
        .unwrap();
        assert_eq!(
            absent_json.get("enrollment"),
            Some(&norito::json::Value::Null),
            "absence is an explicit value, never an omitted observation"
        );
        for incomplete in [
            format!(r#"{{"key":{key_json}}}"#),
            format!(r#"{{"enrollment":null}}"#),
            format!(r#"{{"key":{key_json},"enrollment":null,"extra":true}}"#),
            format!(r#"{{"key":{key_json},"enrollment":null,"enrollment":null}}"#),
        ] {
            assert!(
                norito::json::from_str::<FeeSponsorEnrollmentByIdResponse>(&incomplete).is_err()
            );
        }
        for json in [
            format!(
                r#"{{"program_id":"{}","beneficiary":"{}","extra":true}}"#,
                request.program_id, request.beneficiary
            ),
            format!(
                r#"{{"program_id":"{}","beneficiary":"{}","beneficiary":"{}"}}"#,
                request.program_id, request.beneficiary, request.beneficiary
            ),
        ] {
            assert!(norito::json::from_str::<FeeSponsorEnrollmentByIdRequest>(&json).is_err());
        }
    }

    #[test]
    fn fee_quote_draft_validation_rejects_payer_revision_and_gas_substitution() {
        let (payload, quote, program_id, _) = sponsored_fee_quote_fixture();
        quote
            .validate_for_draft(&payload)
            .expect("matching sponsored draft quote");

        let charge_limits = payload.fee_payment_intent().charge_limits().to_vec();
        let other_program_id = FeeSponsorProgramId::new(
            AccountId::new(checked_test_keypair(0x34).public_key().clone()),
            "other".parse().expect("valid sponsor-program name"),
        );
        let substitutions = [
            (
                "payer kind",
                FeePaymentIntent::authority(charge_limits.clone(), NonZeroU64::new(50)),
            ),
            (
                "sponsor program",
                FeePaymentIntent::sponsor(
                    other_program_id,
                    7,
                    charge_limits.clone(),
                    NonZeroU64::new(50),
                ),
            ),
            (
                "sponsor revision",
                FeePaymentIntent::sponsor(
                    program_id.clone(),
                    8,
                    charge_limits.clone(),
                    NonZeroU64::new(50),
                ),
            ),
            (
                "gas bound",
                FeePaymentIntent::sponsor(
                    program_id.clone(),
                    7,
                    charge_limits.clone(),
                    NonZeroU64::new(51),
                ),
            ),
        ];
        for (case, fee_payment) in substitutions {
            let substituted = fee_quote_test_payload(payload.authority().clone(), fee_payment);
            assert!(
                quote.validate_for_draft(&substituted).is_err(),
                "draft validator accepted a substituted {case}"
            );
        }

        let mut invalid_limits = charge_limits;
        invalid_limits[0] = FeeChargeLimit::new(
            quote.components[0].kind,
            quote.components[0].asset_definition_id.clone(),
            Quantity::zero(),
        );
        let invalid_intent =
            FeePaymentIntent::sponsor(program_id, 7, invalid_limits, NonZeroU64::new(50));
        let invalid_draft =
            fee_quote_test_payload(payload.authority().clone(), invalid_intent.clone());
        assert!(
            quote.validate_for_draft(&invalid_draft).is_err(),
            "draft validator accepted an invalid draft fee intent"
        );

        let mut invalid_quote = quote.clone();
        invalid_quote.intent = invalid_intent;
        invalid_quote.components = fee_quote_components(&invalid_quote.intent);
        assert!(
            invalid_quote.validate_for_draft(&payload).is_err(),
            "draft validator accepted an invalid response intent"
        );
    }
    #[test]
    fn fee_quote_signed_validation_rejects_limit_substitution() {
        let (payload, quote, program_id, _) = sponsored_fee_quote_fixture();
        quote
            .validate_for_signed_payload(&payload)
            .expect("matching signed fee intent");

        let mut substituted_limits = quote.intent.charge_limits().to_vec();
        substituted_limits[0] = FeeChargeLimit::new(
            quote.components[0].kind,
            quote.components[0].asset_definition_id.clone(),
            Quantity::from(4_u32),
        );
        let substituted = fee_quote_test_payload(
            payload.authority().clone(),
            FeePaymentIntent::sponsor(program_id, 7, substituted_limits, NonZeroU64::new(50)),
        );
        quote
            .validate_for_draft(&substituted)
            .expect("draft validation permits quote-selected charge limits");
        assert!(
            quote.validate_for_signed_payload(&substituted).is_err(),
            "signed validator accepted substituted charge limits"
        );
    }
    #[test]
    fn fee_quote_validation_rejects_observation_component_and_decision_mutations() {
        let (payload, quote, _, _) = sponsored_fee_quote_fixture();

        let mut zero_height = quote.clone();
        zero_height.observation.next_block_height = 0;
        assert_fee_quote_rejected_by_both(&zero_height, &payload, "a zero observation height");

        let mut changed_component = quote.clone();
        changed_component.components[0].max_amount = Quantity::from(4_u32);
        assert_fee_quote_rejected_by_both(&changed_component, &payload, "a changed component");
        let mut reordered_components = quote.clone();
        reordered_components.components.swap(0, 1);
        assert_fee_quote_rejected_by_both(&reordered_components, &payload, "reordered components");

        let other_program_id = FeeSponsorProgramId::new(
            AccountId::new(checked_test_keypair(0x35).public_key().clone()),
            "other".parse().expect("valid sponsor-program name"),
        );
        let sponsor_program_id = quote
            .intent
            .sponsor_program()
            .expect("sponsored fixture")
            .0
            .clone();
        let sponsor_decision_mutations = [
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(other_program_id),
                program_revision: Some(7),
            },
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(sponsor_program_id.clone()),
                program_revision: Some(8),
            },
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(sponsor_program_id.clone()),
                program_revision: None,
            },
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(payload.authority().clone()),
                program_revision: None,
            },
        ];
        for decision in sponsor_decision_mutations {
            let mut changed_decision = quote.clone();
            changed_decision.decision = decision;
            assert_fee_quote_rejected_by_both(
                &changed_decision,
                &payload,
                "a mismatched sponsor decision",
            );
        }

        let (authority_payload, authority_quote) = authority_fee_quote_fixture();
        authority_quote
            .validate_for_draft(&authority_payload)
            .expect("matching authority-paid draft quote");
        authority_quote
            .validate_for_signed_payload(&authority_payload)
            .expect("matching authority-paid quote");
        let wrong_account = AccountId::new(checked_test_keypair(0x36).public_key().clone());
        let authority_decision_mutations = [
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(wrong_account),
                program_revision: None,
            },
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::Account(authority_payload.authority().clone()),
                program_revision: Some(1),
            },
            FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(sponsor_program_id),
                program_revision: Some(7),
            },
        ];
        for decision in authority_decision_mutations {
            let mut changed_decision = authority_quote.clone();
            changed_decision.decision = decision;
            assert_fee_quote_rejected_by_both(
                &changed_decision,
                &authority_payload,
                "a mismatched authority decision",
            );
        }
        let mut authority_with_capacity = authority_quote;
        authority_with_capacity.capacities.push(fee_quote_capacity(
            fee_quote_test_asset("authority"),
            Quantity::from(4_u32),
        ));
        assert_fee_quote_rejected_by_both(
            &authority_with_capacity,
            &authority_payload,
            "an authority-paid capacity",
        );
    }
    #[test]
    fn fee_quote_validation_rejects_capacity_mutation_matrix() {
        let (payload, quote, _, assets) = sponsored_fee_quote_fixture();
        quote
            .validate_for_signed_payload(&payload)
            .expect("canonical sponsor capacities");

        let mut mutations = Vec::new();
        let mut empty = quote.clone();
        empty.capacities.clear();
        mutations.push(("empty", empty));

        let mut duplicate = quote.clone();
        duplicate.capacities[1].asset_definition_id =
            duplicate.capacities[0].asset_definition_id.clone();
        mutations.push(("duplicate", duplicate));

        let mut unsorted = quote.clone();
        unsorted.capacities.swap(0, 1);
        mutations.push(("unsorted", unsorted));

        let mut unrelated = quote.clone();
        unrelated.capacities[1].asset_definition_id = fee_quote_test_asset("unrelated");
        mutations.push(("unrelated", unrelated));

        let mut insufficient_vault = quote.clone();
        insufficient_vault.capacities[0].vault_balance = Quantity::from(6_u32);
        mutations.push(("insufficient vault", insufficient_vault));

        let mut insufficient_block = quote.clone();
        insufficient_block.capacities[0].block_remaining = Quantity::zero();
        mutations.push(("insufficient block budget", insufficient_block));

        let mut insufficient_program_epoch = quote.clone();
        insufficient_program_epoch.capacities[0].program_epoch_remaining = Quantity::zero();
        mutations.push((
            "insufficient program-epoch budget",
            insufficient_program_epoch,
        ));

        let mut insufficient_beneficiary_epoch = quote.clone();
        insufficient_beneficiary_epoch.capacities[0].beneficiary_epoch_remaining = Quantity::zero();
        mutations.push((
            "insufficient beneficiary-epoch budget",
            insufficient_beneficiary_epoch,
        ));

        for (case, mutation) in mutations {
            assert_fee_quote_rejected_by_both(
                &mutation,
                &payload,
                &format!("{case} sponsor capacities"),
            );
        }
        assert!(
            assets[0] < assets[1],
            "fixture assets must have strict order"
        );
    }
    #[test]
    fn fee_quote_validation_aggregates_shared_asset_components_once() {
        let authority = AccountId::new(checked_test_keypair(0x37).public_key().clone());
        let sponsor = AccountId::new(checked_test_keypair(0x38).public_key().clone());
        let program_id = FeeSponsorProgramId::new(
            sponsor,
            "shared".parse().expect("valid sponsor-program name"),
        );
        let asset_definition_id = fee_quote_test_asset("shared");
        let intent = FeePaymentIntent::sponsor(
            program_id.clone(),
            3,
            vec![
                FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    asset_definition_id.clone(),
                    Quantity::from(3_u32),
                ),
                FeeChargeLimit::new(
                    FeeChargeKind::PipelineGas,
                    asset_definition_id.clone(),
                    Quantity::from(5_u32),
                ),
            ],
            None,
        );
        let payload = fee_quote_test_payload(authority, intent.clone());
        let quote = FeeQuoteResponse {
            components: fee_quote_components(&intent),
            intent,
            observation: FeeQuoteObservation {
                ledger_time_ms: 42,
                next_block_height: 7,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            capacities: vec![fee_quote_capacity(
                asset_definition_id,
                Quantity::from(8_u32),
            )],
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(program_id),
                program_revision: Some(3),
            },
        };
        quote
            .validate_for_draft(&payload)
            .expect("one shared-asset draft capacity covers the aggregate");
        quote
            .validate_for_signed_payload(&payload)
            .expect("one shared-asset capacity covers the aggregate");
        assert_eq!(quote.capacities.len(), 1);

        for field in ["vault", "block", "program_epoch", "beneficiary_epoch"] {
            let mut insufficient = quote.clone();
            match field {
                "vault" => insufficient.capacities[0].vault_balance = Quantity::from(7_u32),
                "block" => insufficient.capacities[0].block_remaining = Quantity::from(5_u32),
                "program_epoch" => {
                    insufficient.capacities[0].program_epoch_remaining = Quantity::from(5_u32);
                }
                "beneficiary_epoch" => {
                    insufficient.capacities[0].beneficiary_epoch_remaining = Quantity::from(5_u32);
                }
                _ => unreachable!("closed field matrix"),
            }
            assert_fee_quote_rejected_by_both(
                &insufficient,
                &payload,
                &format!("{field} capacity covering individual components but not their aggregate"),
            );
        }
    }
    #[test]
    fn fee_quote_validation_preserves_fee_free_sponsor_quotes() {
        let authority = AccountId::new(checked_test_keypair(0x39).public_key().clone());
        let sponsor = AccountId::new(checked_test_keypair(0x3a).public_key().clone());
        let program_id = FeeSponsorProgramId::new(
            sponsor,
            "fee_free".parse().expect("valid sponsor-program name"),
        );
        let intent = FeePaymentIntent::sponsor(program_id.clone(), 2, Vec::new(), None);
        let payload = fee_quote_test_payload(authority, intent.clone());
        let quote = FeeQuoteResponse {
            intent,
            observation: FeeQuoteObservation {
                ledger_time_ms: 42,
                next_block_height: 7,
                route_dataspace_id: DataSpaceId::UNIVERSAL,
            },
            components: Vec::new(),
            capacities: Vec::new(),
            decision: FeeQuoteDecision::Accepted {
                debit_source: FeeDebitSource::SponsorProgram(program_id),
                program_revision: Some(2),
            },
        };
        quote
            .validate_for_draft(&payload)
            .expect("fee-free sponsored draft quote");
        quote
            .validate_for_signed_payload(&payload)
            .expect("fee-free sponsored signed quote");

        let mut unrelated_capacity = quote;
        unrelated_capacity.capacities.push(fee_quote_capacity(
            fee_quote_test_asset("unrelated"),
            Quantity::zero(),
        ));
        assert_fee_quote_rejected_by_both(
            &unrelated_capacity,
            &payload,
            "a fee-free quote with an unrelated capacity",
        );
    }
    #[test]
    fn error_envelope_roundtrip_preserves_queue_details() {
        let envelope = ErrorEnvelope::new("queue_full", "transaction queue is at capacity")
            .with_details(ErrorDetails {
                reject_code: Some("TX_QUEUE_FULL".to_owned()),
                queue: Some(QueueErrorSnapshot {
                    state: "saturated".to_owned(),
                    queued: 24,
                    capacity: 24,
                    saturated: true,
                }),
                retry_after_seconds: Some(1),
                ..Default::default()
            });
        let bytes = norito::to_bytes(&envelope).expect("encode error envelope");
        let decoded: ErrorEnvelope =
            norito::decode_from_bytes(&bytes).expect("decode error envelope");
        assert_eq!(decoded.code, "queue_full");
        assert_eq!(decoded.message, "transaction queue is at capacity");
        let details = decoded.details.expect("error details");
        assert_eq!(details.reject_code.as_deref(), Some("TX_QUEUE_FULL"));
        assert_eq!(details.retry_after_seconds, Some(1));
        let queue = details.queue.expect("queue details");
        assert_eq!(queue.state, "saturated");
        assert_eq!(queue.queued, 24);
        assert_eq!(queue.capacity, 24);
        assert!(queue.saturated);
    }
    #[test]
    fn error_envelope_roundtrip_preserves_public_debug_details() {
        let envelope = ErrorEnvelope::new("transaction_finality_failed", "finality failed")
            .with_details(ErrorDetails {
                layer: Some("mcp".to_owned()),
                endpoint: Some("/v1/pipeline/transactions/status".to_owned()),
                field: Some("status.kind".to_owned()),
                expected: Some("Applied".to_owned()),
                actual: Some("Rejected".to_owned()),
                profile: Some(NETWORK_PROFILE_TAIRA.to_owned()),
                chain_discriminant: Some(TAIRA_CHAIN_DISCRIMINANT),
                entrypoint_hash: Some("cd".repeat(32)),
                tx_hash: Some("ab".repeat(32)),
                last_status: Some("Rejected".to_owned()),
                hint: Some("inspect transaction rejection reason".to_owned()),
                ..Default::default()
            });
        let bytes = norito::to_bytes(&envelope).expect("encode error envelope");
        let decoded: ErrorEnvelope =
            norito::decode_from_bytes(&bytes).expect("decode error envelope");
        let details = decoded.details.expect("error details");
        assert_eq!(details.layer.as_deref(), Some("mcp"));
        assert_eq!(
            details.endpoint.as_deref(),
            Some("/v1/pipeline/transactions/status")
        );
        assert_eq!(details.expected.as_deref(), Some("Applied"));
        assert_eq!(details.actual.as_deref(), Some("Rejected"));
        assert_eq!(details.profile.as_deref(), Some(NETWORK_PROFILE_TAIRA));
        assert_eq!(details.chain_discriminant, Some(TAIRA_CHAIN_DISCRIMINANT));
        assert_eq!(
            details.entrypoint_hash.as_deref(),
            Some("cd".repeat(32).as_str())
        );
        assert_eq!(details.tx_hash.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(details.last_status.as_deref(), Some("Rejected"));
        assert_eq!(
            details.hint.as_deref(),
            Some("inspect transaction rejection reason")
        );
    }
    #[test]
    fn error_envelope_roundtrip_preserves_fee_details() {
        let envelope = ErrorEnvelope::new("fee_payment_rejected", "fee payment rejected")
            .with_details(ErrorDetails {
                fee: Some(FeeErrorDetails {
                    code: "vault_insufficient".to_owned(),
                    retryable: true,
                    program_id: Some("sponsor/default".to_owned()),
                    program_revision: Some(3),
                    asset_definition_id: Some("xor#fees".to_owned()),
                    required: Some("10".to_owned()),
                    available: Some("4".to_owned()),
                    observation_height: Some(42),
                    remediation: Some("fund the program vault".to_owned()),
                    ..Default::default()
                }),
                ..Default::default()
            });
        let bytes = norito::to_bytes(&envelope).expect("encode fee error envelope");
        let decoded: ErrorEnvelope =
            norito::decode_from_bytes(&bytes).expect("decode fee error envelope");
        let fee = decoded
            .details
            .and_then(|details| details.fee)
            .expect("fee error details");
        assert_eq!(fee.code, "vault_insufficient");
        assert!(fee.retryable);
        assert_eq!(fee.program_revision, Some(3));
        assert_eq!(fee.required.as_deref(), Some("10"));
        assert_eq!(fee.available.as_deref(), Some("4"));
        assert_eq!(fee.observation_height, Some(42));
    }
    #[test]
    fn error_envelope_preserves_the_bounded_runtime_fault() {
        use iroha_data_model::executor::fault::{
            IvmFaultKindV1, IvmFaultPositionV1, IvmFaultSiteV1, IvmFaultV1, IvmInvocationSelectorV1,
        };
        let fault = IvmFaultV1 {
            kind: IvmFaultKindV1::ReentrantCall,
            site: IvmFaultSiteV1 {
                code_hash: iroha_crypto::Hash::new(b"contract"),
                selector: IvmInvocationSelectorV1::Entrypoint(2),
                position: IvmFaultPositionV1::Execute { pc_offset: 12 },
            },
        };
        let envelope =
            ErrorEnvelope::new("ivm_fault", fault.to_string()).with_details(ErrorDetails {
                ivm_fault: Some(fault),
                ..Default::default()
            });
        let native = norito::to_bytes(&envelope).unwrap();
        let json = norito::json::to_vec(&envelope).unwrap();
        for decoded in [
            norito::decode_from_bytes::<ErrorEnvelope>(&native).unwrap(),
            norito::json::from_slice::<ErrorEnvelope>(&json).unwrap(),
        ] {
            let details = decoded.details.unwrap();
            assert!(!details.is_empty());
            assert_eq!(details.ivm_fault, Some(fault));
        }
    }

    #[test]
    fn error_envelope_roundtrip_preserves_exact_asset_absence() {
        let account = AccountId::new(checked_test_keypair(0x38).public_key().clone());
        let asset = AssetId::new(fee_quote_test_asset("missing"), account);
        let envelope =
            ErrorEnvelope::new("query_asset_not_found", "The requested asset is absent.")
                .with_details(ErrorDetails {
                    query_asset_not_found: Some(asset.clone()),
                    ..Default::default()
                });
        let native = norito::to_bytes(&envelope).expect("encode asset absence envelope");
        let json = norito::json::to_vec(&envelope).expect("encode asset absence JSON");
        for decoded in [
            norito::decode_canonical_with_limits::<ErrorEnvelope>(
                &native,
                norito::canonical_decode_limits(native.len()),
            )
            .expect("decode canonical asset absence envelope"),
            norito::json::from_slice::<ErrorEnvelope>(&json).expect("decode asset absence JSON"),
        ] {
            assert_eq!(decoded.code(), "query_asset_not_found");
            let details = decoded.details.expect("required exact asset selector");
            assert!(!details.is_empty());
            assert_eq!(details.query_asset_not_found, Some(asset.clone()));
        }
        let value = norito::json::from_slice::<norito::json::Value>(&json)
            .expect("inspect declared absence JSON schema");
        let details = value
            .get("details")
            .and_then(norito::json::Value::as_object)
            .expect("details object");
        assert_eq!(details.len(), 1);
        assert_eq!(
            details.get("query_asset_not_found"),
            Some(&norito::json::to_value(&asset).expect("typed AssetId JSON")),
        );
        let mut trailing = native;
        trailing.push(0);
        assert!(
            norito::decode_canonical_with_limits::<ErrorEnvelope>(
                &trailing,
                norito::canonical_decode_limits(trailing.len()),
            )
            .is_err()
        );
    }
    #[test]
    fn error_envelope_asset_absence_json_rejects_untyped_and_duplicate_selectors() {
        for selector in ["{}", "[]", "0", "true", "\"not-an-asset\""] {
            let json = format!(
                r#"{{"code":"query_asset_not_found","message":"absent","details":{{"query_asset_not_found":{selector}}}}}"#
            );
            assert!(
                norito::json::from_str::<ErrorEnvelope>(&json).is_err(),
                "{json}"
            );
        }
        let json = r#"{"code":"query_asset_not_found","message":"absent","details":{"query_asset_not_found":null,"query_asset_not_found":null}}"#;
        assert!(norito::json::from_str::<ErrorEnvelope>(json).is_err());
    }
    #[test]
    fn error_envelope_json_rejects_unknown_members_and_duplicates() {
        let decoded: ErrorEnvelope = norito::json::from_str(
            r#"{"code":"bad_request","message":"invalid","details":{"field":"amount"}}"#,
        )
        .expect("decode envelope with its declared members");
        assert_eq!(decoded.code(), "bad_request");
        assert_eq!(
            decoded
                .details
                .as_ref()
                .and_then(|details| details.field.as_deref()),
            Some("amount")
        );
        let canonical = norito::json::to_string(&decoded).expect("re-encode closed envelope");
        assert!(!canonical.contains("unknown"));
        assert!(!canonical.contains("secret"));
        for json in [
            r#"{"code":"bad_request","message":"invalid","unknown":"discarded","details":{"field":"amount","unknown_nested":{"secret":true}}}"#,
            r#"{"code":"bad_request","message":"invalid","details":{"field":"amount","unknown_nested":{"secret":true}}}"#,
        ] {
            let error = norito::json::from_str::<ErrorEnvelope>(json)
                .expect_err("unknown error members must fail closed at either boundary");
            assert!(matches!(error, norito::json::Error::UnknownField { .. }));
        }
        for json in [
            r#"{"code":"bad_request","code":"conflict","message":"invalid"}"#,
            r#"{"code":"bad_request","message":"invalid","details":{"field":"amount","field":"asset"}}"#,
        ] {
            let error = norito::json::from_str::<ErrorEnvelope>(json)
                .expect_err("duplicate declared error member must fail");
            assert!(
                error.to_string().contains("duplicate field"),
                "unexpected duplicate-member error: {error}"
            );
        }
    }
    #[test]
    fn error_envelope_json_rejects_untyped_details_values() {
        for details in ["[]", "\"dynamic\"", "1", "true"] {
            let json =
                format!(r#"{{"code":"bad_request","message":"invalid","details":{details}}}"#);
            norito::json::from_str::<ErrorEnvelope>(&json)
                .expect_err("details must be the declared typed record or null");
        }
    }
    #[test]
    fn error_envelope_json_rejects_unknown_fields_recursively() {
        for json in [
            r#"{"code":"bad_request","message":"invalid","retired":null}"#,
            r#"{"code":"bad_request","message":"invalid","details":{"retired":null}}"#,
            r#"{"code":"bad_request","message":"invalid","details":{"fee":{"retired":null}}}"#,
            r#"{"code":"sns_registration_not_found","message":"missing","details":{"sns_registration_not_found":{"suffix_id":4099,"label":"dpn","retired":null}}}"#,
        ] {
            norito::json::from_str::<ErrorEnvelope>(json)
                .expect_err("error envelopes must reject unknown members at every owned boundary");
        }
    }
    #[test]
    fn error_details_is_empty_tracks_optional_fields() {
        let mut details = ErrorDetails::default();
        assert!(details.is_empty());
        details.queue = Some(QueueErrorSnapshot {
            state: "saturated".to_owned(),
            queued: 24,
            capacity: 24,
            saturated: true,
        });
        assert!(!details.is_empty());
        details = ErrorDetails::default();
        details.last_status = Some("Expired".to_owned());
        assert!(!details.is_empty());
        details = ErrorDetails::default();
        details.entrypoint_hash = Some("cd".repeat(32));
        assert!(!details.is_empty());
        details = ErrorDetails::default();
        details.fee = Some(FeeErrorDetails {
            code: "invalid_fee_intent".to_owned(),
            ..Default::default()
        });
        assert!(!details.is_empty());
        details = ErrorDetails::default();
        details.sns_registration_not_found = Some(crate::sns::SnsRegistrationNotFoundV1::new(
            iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID,
            "dpn".to_owned(),
        ));
        assert!(!details.is_empty());
        details.sns_registration_not_found = None;
        assert!(details.is_empty());
        let account = AccountId::new(checked_test_keypair(0x39).public_key().clone());
        details.query_asset_not_found =
            Some(AssetId::new(fee_quote_test_asset("missing"), account));
        assert!(!details.is_empty());
        details.query_asset_not_found = None;
        assert!(details.is_empty());
    }
    #[test]
    fn network_profile_registry_resolves_public_discriminants() {
        assert_eq!(
            network_profile(NETWORK_PROFILE_TAIRA).map(|profile| profile.chain_discriminant),
            Some(TAIRA_CHAIN_DISCRIMINANT)
        );
        assert_eq!(
            network_profile(NETWORK_PROFILE_MINAMOTO).map(|profile| profile.chain_discriminant),
            Some(MINAMOTO_CHAIN_DISCRIMINANT)
        );
        assert_eq!(
            network_profile_for_discriminant(TAIRA_CHAIN_DISCRIMINANT).map(|profile| profile.name),
            Some(NETWORK_PROFILE_TAIRA)
        );
    }
    #[test]
    fn pipeline_transaction_status_roundtrip_is_status_only() {
        use crate::{
            PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE, PipelineTransactionStatusNotFoundV1,
        };
        let hash=iroha_crypto::HashOf::<iroha_data_model::transaction::SignedTransaction>::from_untyped_unchecked(iroha_crypto::Hash::prehashed([0xab;iroha_crypto::Hash::LENGTH]));
        for scope in ["local", "global"] {
            let absence = PipelineTransactionStatusNotFoundV1::new(&hash, scope);
            assert!(absence.is_valid());
            assert!(absence.matches(&hash, scope));
            assert!(!absence.matches(&hash, if scope == "local" { "global" } else { "local" }));
            let envelope = ErrorEnvelope::new(
                PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                "Missing status.",
            )
            .with_details(ErrorDetails {
                pipeline_transaction_status_not_found: Some(absence.clone()),
                ..ErrorDetails::default()
            });
            assert!(!envelope.details.as_ref().unwrap().is_empty());
            let json = norito::json::to_vec(&envelope).expect("JSON");
            let wire = norito::to_bytes(&envelope).expect("native");
            for decoded in [
                norito::json::from_slice::<ErrorEnvelope>(&json).expect("JSONdecode"),
                norito::decode_from_bytes::<ErrorEnvelope>(&wire).expect("native decode"),
            ] {
                assert_eq!(decoded.code(), PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE);
                assert_eq!(
                    decoded
                        .details
                        .unwrap()
                        .pipeline_transaction_status_not_found,
                    Some(absence.clone())
                );
            }
        }
        for invalid in [
            r"{}",
            r#"{"hash":"abc","scope":"global","extra":0}"#,
            r#"{"hash":"abc","scope":"global","scope":"local"}"#,
        ] {
            assert!(
                norito::json::from_str::<PipelineTransactionStatusNotFoundV1>(invalid).is_err()
            );
        }
        assert!(
            !PipelineTransactionStatusNotFoundV1 {
                hash: hash.to_string().to_uppercase(),
                scope: "global".to_owned()
            }
            .is_valid()
        );
        assert!(!PipelineTransactionStatusNotFoundV1::new(&hash, "other").is_valid());
        let payload = PipelineTransactionStatusResponse::new(
            "ab".repeat(32),
            PipelineTransactionStatus {
                kind: "Rejected".to_owned(),
                block_height: Some(42),
            },
            "global".to_owned(),
            "state".to_owned(),
        );
        let encoded = norito::to_bytes(&payload).expect("encode status payload");
        let decoded: PipelineTransactionStatusResponse =
            norito::decode_from_bytes(&encoded).expect("decode status payload");
        assert_eq!(decoded, payload);
        let json = norito::json::to_json(&payload).expect("encode public status JSON");
        for forbidden in [
            "rejection_reason",
            "diagnostics",
            "trigger_completions",
            "batch_transfer_outcomes",
            "summary",
            "authority",
            "destination",
            "amount",
            "instructions",
        ] {
            assert!(
                !json.contains(forbidden),
                "public status leaked forbidden field `{forbidden}`: {json}"
            );
        }
    }
    fn canonical_details_fixture(rejected: bool) -> super::PipelineTransactionDetailsResponse {
        use iroha_data_model::{
            block::execution_output::{
                ExecutionOutputV1, InvocationCompletionV1, NetworkExecutionOutputV1,
            },
            events::trigger_completed::TriggerCompletedOutcome,
            transaction::{
                TransactionEntrypoint, TransactionResult, error::TransactionRejectionReason,
            },
        };
        let key = checked_test_keypair(0x48);
        let entrypoint = TransactionEntrypoint::External(
            TransactionBuilder::new(
                NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                    b"details fixture network",
                ))),
                AccountId::new(key.public_key().clone()),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .try_sign(key.private_key())
            .unwrap(),
        );
        let result = if rejected {
            TransactionResult::new(Err(TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted("fixture refusal".into()),
            )))
        } else {
            TransactionResult::new(Ok(Vec::new()))
        };
        let output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result,
            completions: if rejected {
                Vec::new()
            } else {
                vec![InvocationCompletionV1 {
                    callback_index: 0,
                    trigger_id: "owned-completion".parse().unwrap(),
                    outcome: TriggerCompletedOutcome::Success,
                }]
            },
        });
        let block_hash = HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            Hash::new(b"details fixture carrier"),
        );
        let entrypoint_proof =
            iroha_crypto::MerkleProof::<TransactionEntrypoint>::from_audit_path(0, Vec::new());
        let output_proof =
            iroha_crypto::MerkleProof::<ExecutionOutputV1>::from_audit_path(0, Vec::new());
        // Exercise the public decoder without relying on another crate's transparent_api feature.
        let transaction: iroha_data_model::query::CommittedTransaction =
            norito::json::from_value(norito::json!({
                "block_hash": block_hash,
                "entrypoint_hash": (entrypoint.hash()),
                "entrypoint": entrypoint,
                "entrypoint_proof": entrypoint_proof,
                "output_hash": (HashOf::new(&output)),
                "output": output,
                "output_proof": output_proof,
            }))
            .expect("public canonical committed transaction fixture");
        super::PipelineTransactionDetailsResponse {
            hash: transaction.entrypoint_hash().to_string(),
            transaction,
        }
    }

    #[test]
    fn transaction_details_roundtrip_has_one_full_network_output_owner() {
        for rejected in [false, true] {
            let details = canonical_details_fixture(rejected);
            let bytes = norito::to_bytes(&details).unwrap();
            assert_eq!(
                norito::core::Header::read(bytes.as_slice()).unwrap().schema,
                norito::schema::identity::frame_hash::<super::PipelineTransactionDetailsResponse>()
            );
            let decoded: super::PipelineTransactionDetailsResponse =
                norito::decode_from_bytes(&bytes).unwrap();
            assert_eq!(decoded, details);
            assert_eq!(decoded.transaction.result().is_err(), rejected);
            assert_eq!(
                decoded.transaction.output().completions().len(),
                usize::from(!rejected)
            );
            decoded
                .transaction
                .output()
                .validate_structure(1, std::slice::from_ref(decoded.transaction.entrypoint()))
                .expect("details fixture obeys the canonical Network rollback contract");
            let json = norito::json::to_value(&details).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 2);
            assert!(
                !json
                    .as_object()
                    .unwrap()
                    .contains_key("trigger_completions")
            );
            assert_eq!(
                norito::json::from_value::<super::PipelineTransactionDetailsResponse>(json)
                    .unwrap(),
                details
            );
            for end in 0..bytes.len() {
                assert!(
                    norito::decode_from_bytes::<super::PipelineTransactionDetailsResponse>(
                        &bytes[..end]
                    )
                    .is_err()
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(
                norito::decode_from_bytes::<super::PipelineTransactionDetailsResponse>(&trailing)
                    .is_err()
            );
        }
    }

    #[test]
    fn transaction_details_rejects_retired_parallel_completion_layout() {
        #[derive(norito::NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(name = "iroha_torii_shared::PipelineTransactionDetailsResponse")]
        struct RetiredDetails {
            hash: String,
            transaction: iroha_data_model::query::CommittedTransaction,
            trigger_completions: Vec<super::TriggerCompletionSummary>,
        }
        let details = canonical_details_fixture(false);
        for completions in [
            Vec::new(),
            vec![super::TriggerCompletionSummary {
                trigger_id: "retired-completion".into(),
                trigger_execution_hash: details.hash.clone(),
                step_index: 0,
                outcome: "Success".into(),
                message: None,
            }],
        ] {
            let retired = RetiredDetails {
                hash: details.hash.clone(),
                transaction: details.transaction.clone(),
                trigger_completions: completions.clone(),
            };
            assert!(
                norito::decode_from_bytes::<super::PipelineTransactionDetailsResponse>(
                    &norito::to_bytes(&retired).unwrap()
                )
                .is_err()
            );
            let mut json = norito::json::to_value(&details).unwrap();
            json.as_object_mut().unwrap().insert(
                "trigger_completions".into(),
                norito::json::to_value(&completions).unwrap(),
            );
            assert!(
                norito::json::from_value::<super::PipelineTransactionDetailsResponse>(json)
                    .is_err()
            );
        }
    }

    #[test]
    fn account_read_response_fixture_uses_checked_key_derivation() {
        let key_pair = checked_test_keypair(0x23);
        let expected = KeyPair::try_from_seed(vec![0x23; 32], Algorithm::Ed25519)
            .expect("direct checked Torii shared fixture key derivation");
        assert_eq!(key_pair.public_key(), expected.public_key());
        assert!(KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err());
    }
    #[test]
    fn account_read_response_roundtrip_preserves_subject_metadata() {
        let key_pair = checked_test_keypair(0x23);
        let response = AccountReadResponse {
            account_id: AccountId::new(key_pair.public_key().clone()),
            label: Some(AccountAlias::new(
                "alice".parse::<Name>().expect("valid label"),
                Some(AccountAliasDomain::new(
                    "wonderland".parse::<Name>().expect("valid alias domain"),
                )),
                DataSpaceId::UNIVERSAL,
            )),
            uaid: None,
            opaque_ids: Vec::new(),
        };
        let encoded = norito::to_bytes(&response).expect("encode account response");
        let decoded: AccountReadResponse =
            norito::decode_from_bytes(&encoded).expect("decode account response");
        assert_eq!(decoded, response);
    }
}
/// Iroha Connect protocol types (WalletConnect‑style overlay).
///
/// These are Norito‑encoded wire types used over Torii WebSockets and the
/// Iroha P2P relay for pairing dApps and wallets. This module contains only
/// data structures and no transport/server logic.
pub mod connect;
/// Shared retry utilities for Connect clients (reconnect policy, jitter tables).
pub mod connect_retry;
/// Helper SDK for sealing/opening Connect frames and key derivation.
pub mod connect_sdk;

#[cfg(test)]
mod captured_identity_tests;

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<
            super::AccountOnboardingCurrentStateRequestV1,
        >("iroha_torii_shared::AccountOnboardingCurrentStateRequestV1");
        crate::captured_identity_tests::assert_bidirectional::<
            super::AccountOnboardingCurrentStateResponseV1,
        >("iroha_torii_shared::AccountOnboardingCurrentStateResponseV1");
        crate::captured_identity_tests::assert_bidirectional::<super::AccountReadResponse>(
            "iroha_torii_shared::AccountReadResponse",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::AxtErrorDetails>(
            "iroha_torii_shared::AxtErrorDetails",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::ErrorDetails>(
            "iroha_torii_shared::ErrorDetails",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::ErrorEnvelope>(
            "iroha_torii_shared::ErrorEnvelope",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeErrorDetails>(
            "iroha_torii_shared::FeeErrorDetails",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteCapacity>(
            "iroha_torii_shared::FeeQuoteCapacity",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteComponent>(
            "iroha_torii_shared::FeeQuoteComponent",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteDecision>(
            "iroha_torii_shared::FeeQuoteDecision",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteObservation>(
            "iroha_torii_shared::FeeQuoteObservation",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteRequest>(
            "iroha_torii_shared::FeeQuoteRequest",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeQuoteResponse>(
            "iroha_torii_shared::FeeQuoteResponse",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::FeeSponsorProgramByIdRequest>(
            "iroha_torii_shared::FeeSponsorProgramByIdRequest",
        );
        crate::captured_identity_tests::assert_bidirectional::<
            super::PipelineTransactionDetailsResponse,
        >("iroha_torii_shared::PipelineTransactionDetailsResponse");
        crate::captured_identity_tests::assert_bidirectional::<super::PipelineTransactionStatus>(
            "iroha_torii_shared::PipelineTransactionStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<
            super::PipelineTransactionStatusResponse,
        >("iroha_torii_shared::PipelineTransactionStatusResponse");
        crate::captured_identity_tests::assert_bidirectional::<super::ProofRetentionBackendStatus>(
            "iroha_torii_shared::ProofRetentionBackendStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::ProofRetentionStatus>(
            "iroha_torii_shared::ProofRetentionStatus",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::QueueErrorSnapshot>(
            "iroha_torii_shared::QueueErrorSnapshot",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::TriggerCompletionListResponse>(
            "iroha_torii_shared::TriggerCompletionListResponse",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::TriggerCompletionRecord>(
            "iroha_torii_shared::TriggerCompletionRecord",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::TriggerCompletionSummary>(
            "iroha_torii_shared::TriggerCompletionSummary",
        );
    }
}

#[cfg(test)]
mod native_page_consumer_tests;

#[cfg(test)]
mod service_checked_writer_test_support;
