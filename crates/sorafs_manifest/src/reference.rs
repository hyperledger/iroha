//! Reference validation outcomes for SoraFS operator tooling.
//!
//! This module backs the first SF-11 validator slice. It reuses the canonical
//! SoraFS Norito models and reports deterministic, machine-readable outcomes
//! that can be consumed by CLIs, CI, and dashboards.
// Reference validators intentionally return the full structured outcome as the
// error so FFI/CLI callers can render identical diagnostics without side state.
#![allow(clippy::result_large_err)]
use crate::{
    AdmissionRecord, AdvertValidationError, BillingLineDirectionV1, BillingLineItemKindV1,
    BillingLineItemV1, BillingStatementV1, ByteRangeV1, GovernanceDagBlockV1,
    GovernanceDagBlockValidationError, GovernanceDagChainValidationError,
    GovernanceDagHeadChainValidationError, GovernanceDagHeadV1, GovernanceDagHeadValidationError,
    GovernanceLogNodeV1, GovernanceLogPayloadV1, GovernanceLogSignatureVerificationError,
    GovernanceLogValidationError, GovernanceSignatureAlgorithm, HedgingFeedStatusV1,
    HedgingPriceFeedV1, HedgingReferencePriceDecisionV1, HedgingValidationError,
    ORDERBOOK_CANCEL_VERSION_V1, ORDERBOOK_ORDER_VERSION_V1, OrderCancelReasonV1, OrderCancelV1,
    OrderRequestV1, OrderSideV1, OrderTierV1, OrderbookSignatureV1, OrderbookValidationError,
    PDP_CHALLENGE_MAX_CANONICAL_BYTES_V1, PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1,
    PDP_MAX_HOT_LEAVES_PER_SEGMENT_SAMPLE_V1, PDP_MAX_MERKLE_PATH_DEPTH_V1,
    PDP_MAX_SEGMENT_SAMPLES_V1, PDP_MAX_TOTAL_HOT_LEAF_SAMPLES_V1,
    PDP_PROOF_MAX_CANONICAL_BYTES_V1, PdpChallengeV1, PdpChallengeValidationError, PdpCommitmentV1,
    PdpCommitmentValidationError, PdpProofV1, PdpProofValidationError, PdpVerificationError,
    PopCommitmentRootV1, PopCredentialV1, PopCredentialValidationError, PopEligibilityClassV1,
    PopEnrollmentRequestV1, PopIssuedCredentialBundleV1, PopMembershipProofSystemV1,
    PopMembershipProofV1, PopRenewalRequestV1, PopRevocationListV1, PopSignatureAlgorithmV1,
    PopSignatureV1, PorChallengeV1, PorChallengeValidationError, PorProofV1,
    PorProofValidationError, PotrReceiptV1, PotrReceiptValidationError, ProofStreamTier,
    ProviderAdmissionEnvelopeError, ProviderAdmissionEnvelopeV1, ProviderAdmissionRenewalError,
    ProviderAdmissionRenewalV1, ProviderAdmissionRevocationError, ProviderAdmissionRevocationV1,
    ProviderAdmissionValidationError, ProviderAdvertV1, RepairAuditEventV1,
    RepairEscalationApprovalV1, RepairEscalationPolicyV1, RepairEvidenceV1, RepairReportV1,
    RepairSlashProposalV1, RepairTaskEventV1, RepairTaskRecordV1, RepairTaskStateV1,
    RepairValidationError, ReplicationOrderSignatureVerificationError, ReplicationOrderV1,
    ReplicationOrderValidationError, SETTLEMENT_RECEIPT_VERSION_V1, SettlementChannelStatusV1,
    SettlementChannelV1, SettlementReceiptV1, SignatureAlgorithm, SignedReplicationOrderV1,
    SignedReplicationOrderValidationError, TradeEventV1, XorQuantity, decode_billing_line_item_v1,
    decode_billing_statement_v1, decode_hedging_price_feed_v1,
    decode_hedging_reference_price_decision_v1, decode_order_cancel_v1, decode_order_request_v1,
    decode_provider_advert_v1, decode_settlement_channel_v1, decode_settlement_receipt_v1,
    decode_trade_event_v1, sign_order_cancel_ed25519_v1, sign_order_request_ed25519_v1,
    sign_settlement_receipt_ed25519_v1, validate_governance_dag_head_against_chain_v1,
    verify_envelope_untrusted_signers, verify_order_cancel_signature_v1,
    verify_order_request_signature_v1, verify_pdp_bundle_v1, verify_pdp_witnesses_v1,
    verify_pop_commitment_root_signature_v1, verify_pop_credential_signature_v1,
    verify_pop_revocation_list_signature_v1, verify_settlement_receipt_signature_v1,
};
use ed25519_dalek::SigningKey;
use iroha_crypto::Hash;
use iroha_primitives::numeric::Quantity;
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
use std::collections::BTreeSet;
use thiserror::Error;
/// Current schema version for [`ValidationOutcomeV1`].
pub const VALIDATION_OUTCOME_VERSION_V1: u8 = 1;
/// Error-catalogue document referenced by emitted outcomes.
pub const REFERENCE_SDK_ERRORS_DOC_URL: &str = "https://docs.iroha.tech/";
const STATUS_OK: &str = "Ok";
const STATUS_ERROR: &str = "Error";
const CATEGORY_VALIDATION: &str = "validation";
const CATEGORY_POLICY: &str = "policy";
const CATEGORY_SIGNATURE: &str = "signature";
const CATEGORY_NORITO: &str = "norito";
const CATEGORY_INTERNAL: &str = "internal";
/// Maximum complete Norito frame accepted by the PoP structural reference validator.
pub const POP_REFERENCE_PAYLOAD_MAX_BYTES_V1: usize = 2 * 1024 * 1024;
const PDP_STRUCTURAL_OK_CODE: &str = "SFS-PDP-DIAG-000";
const PDP_TRUST_REQUIRED_CODE: &str = "SFS-PDP-004";
const PDP_REFERENCE_DECODE_MAX_DEPTH_V1: usize = 64;
const CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1: usize = 4 * 1024;
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "sorafs_manifest::reference::CancelAssetLockWireV1",
    frame = "iroha_data_model::isi::escrow::CancelAssetLock"
)]
#[derive(Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize)]
struct CancelAssetLockWireV1 {
    escrow_id: Hash,
    expected_remaining_amount: Quantity,
}
/// Structured key/value context attached to validation outcomes.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::reference::ValidationContextFieldV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
pub struct ValidationContextFieldV1 {
    /// Context key.
    pub key: String,
    /// Context value.
    pub value: String,
}
impl ValidationContextFieldV1 {
    /// Creates a validation context field.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}
/// Input metadata attached to validation outcomes.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::reference::ValidationInputV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
pub struct ValidationInputV1 {
    /// Input kind, for example `provider_advert`.
    pub kind: String,
    /// Human-readable input path or label.
    pub path: String,
}
impl ValidationInputV1 {
    /// Creates input metadata for an outcome.
    #[must_use]
    pub fn new(kind: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            path: path.into(),
        }
    }
}
/// Deterministic validation result for SF-11 reference tooling.
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "sorafs_manifest::reference::ValidationOutcomeV1")]
#[derive(
    Debug, Clone, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, JsonSerialize, JsonDeserialize,
)]
pub struct ValidationOutcomeV1 {
    /// `Ok` for accepted payloads, `Error` for rejected payloads.
    pub status: String,
    /// Stable machine-readable outcome code.
    pub code: String,
    /// Error category such as `validation`, `policy`, `signature`, or `norito`.
    pub category: String,
    /// Human-readable diagnostic.
    pub message: String,
    /// Suggested operator action for rejected inputs.
    pub action: Option<String>,
    /// Documentation path for the code catalogue.
    pub docs_url: Option<String>,
    /// Labels suitable for telemetry dimensions.
    pub telemetry_tags: Vec<String>,
    /// Structured context fields.
    pub context: Vec<ValidationContextFieldV1>,
    /// Inputs considered by the validator.
    pub inputs: Vec<ValidationInputV1>,
    /// Outcome schema version.
    pub version: u8,
    /// UNIX timestamp when the outcome was generated.
    pub generated_at: u64,
}
impl ValidationOutcomeV1 {
    /// Creates a successful validation outcome.
    #[must_use]
    pub fn ok(
        code: impl Into<String>,
        message: impl Into<String>,
        telemetry_tags: Vec<String>,
        context: Vec<ValidationContextFieldV1>,
        inputs: Vec<ValidationInputV1>,
        generated_at: u64,
    ) -> Self {
        Self {
            status: STATUS_OK.to_owned(),
            code: code.into(),
            category: CATEGORY_VALIDATION.to_owned(),
            message: message.into(),
            action: None,
            docs_url: Some(REFERENCE_SDK_ERRORS_DOC_URL.to_owned()),
            telemetry_tags,
            context,
            inputs,
            version: VALIDATION_OUTCOME_VERSION_V1,
            generated_at,
        }
    }
    /// Creates a rejected validation outcome.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn error(
        code: impl Into<String>,
        category: impl Into<String>,
        message: impl Into<String>,
        action: impl Into<String>,
        telemetry_tags: Vec<String>,
        context: Vec<ValidationContextFieldV1>,
        inputs: Vec<ValidationInputV1>,
        generated_at: u64,
    ) -> Self {
        Self {
            status: STATUS_ERROR.to_owned(),
            code: code.into(),
            category: category.into(),
            message: message.into(),
            action: Some(action.into()),
            docs_url: Some(REFERENCE_SDK_ERRORS_DOC_URL.to_owned()),
            telemetry_tags,
            context,
            inputs,
            version: VALIDATION_OUTCOME_VERSION_V1,
            generated_at,
        }
    }
    /// Returns true when this outcome represents an accepted payload.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}
/// Payload kinds accepted by the fixture bundle cross-link validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureBundlePayloadKindV1 {
    /// [`ProviderAdvertV1`] payload.
    ProviderAdvert,
    /// [`ProviderAdmissionEnvelopeV1`] payload.
    ProviderAdmissionEnvelope,
    /// [`ReplicationOrderV1`] payload.
    ReplicationOrder,
    /// [`PdpCommitmentV1`] payload.
    PdpCommitment,
    /// [`PdpChallengeV1`] payload.
    PdpChallenge,
    /// [`PdpProofV1`] payload.
    PdpProof,
    /// [`PorChallengeV1`] payload.
    PorChallenge,
    /// [`PorProofV1`] payload.
    PorProof,
    /// [`PotrReceiptV1`] payload.
    PotrReceipt,
    /// [`RepairEvidenceV1`] payload.
    RepairEvidence,
    /// [`RepairReportV1`] payload.
    RepairReport,
    /// [`RepairTaskRecordV1`] payload.
    RepairTaskRecord,
    /// [`RepairSlashProposalV1`] payload.
    RepairSlashProposal,
    /// [`RepairTaskEventV1`] payload.
    RepairTaskEvent,
    /// [`OrderRequestV1`] orderbook payload.
    OrderbookOrderRequest,
    /// [`OrderCancelV1`] orderbook payload.
    OrderbookOrderCancel,
    /// [`TradeEventV1`] orderbook payload.
    OrderbookTradeEvent,
    /// [`SettlementChannelV1`] orderbook payload.
    OrderbookSettlementChannel,
    /// [`SettlementReceiptV1`] orderbook payload.
    OrderbookSettlementReceipt,
}
impl FixtureBundlePayloadKindV1 {
    fn input_kind(self) -> &'static str {
        match self {
            Self::ProviderAdvert => "provider_advert",
            Self::ProviderAdmissionEnvelope => "provider_admission_envelope",
            Self::ReplicationOrder => "replication_order",
            Self::PdpCommitment => "pdp_commitment",
            Self::PdpChallenge => "pdp_challenge",
            Self::PdpProof => "pdp_proof",
            Self::PorChallenge => "por_challenge",
            Self::PorProof => "por_proof",
            Self::PotrReceipt => "potr_receipt",
            Self::RepairEvidence => "repair_evidence",
            Self::RepairReport => "repair_report",
            Self::RepairTaskRecord => "repair_task_record",
            Self::RepairSlashProposal => "repair_slash_proposal",
            Self::RepairTaskEvent => "repair_task_event",
            Self::OrderbookOrderRequest => "orderbook_order_request",
            Self::OrderbookOrderCancel => "orderbook_order_cancel",
            Self::OrderbookTradeEvent => "orderbook_trade_event",
            Self::OrderbookSettlementChannel => "settlement_channel",
            Self::OrderbookSettlementReceipt => "settlement_receipt",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::ProviderAdvert => "ProviderAdvertV1",
            Self::ProviderAdmissionEnvelope => "ProviderAdmissionEnvelopeV1",
            Self::ReplicationOrder => "ReplicationOrderV1",
            Self::PdpCommitment => "PdpCommitmentV1",
            Self::PdpChallenge => "PdpChallengeV1",
            Self::PdpProof => "PdpProofV1",
            Self::PorChallenge => "PorChallengeV1",
            Self::PorProof => "PorProofV1",
            Self::PotrReceipt => "PotrReceiptV1",
            Self::RepairEvidence => "RepairEvidenceV1",
            Self::RepairReport => "RepairReportV1",
            Self::RepairTaskRecord => "RepairTaskRecordV1",
            Self::RepairSlashProposal => "RepairSlashProposalV1",
            Self::RepairTaskEvent => "RepairTaskEventV1",
            Self::OrderbookOrderRequest => "OrderRequestV1",
            Self::OrderbookOrderCancel => "OrderCancelV1",
            Self::OrderbookTradeEvent => "TradeEventV1",
            Self::OrderbookSettlementChannel => "SettlementChannelV1",
            Self::OrderbookSettlementReceipt => "SettlementReceiptV1",
        }
    }
}
/// A Norito payload included in a fixture-directory bundle validation run.
pub struct FixtureBundlePayloadV1<'payload> {
    /// Payload kind.
    pub kind: FixtureBundlePayloadKindV1,
    /// Human-readable input path or label.
    pub label: String,
    /// Norito bytes for the payload.
    pub bytes: &'payload [u8],
}
impl<'payload> FixtureBundlePayloadV1<'payload> {
    /// Creates a fixture bundle payload reference.
    #[must_use]
    pub fn new(
        kind: FixtureBundlePayloadKindV1,
        label: impl Into<String>,
        bytes: &'payload [u8],
    ) -> Self {
        Self {
            kind,
            label: label.into(),
            bytes,
        }
    }
}
#[derive(Debug, Default)]
struct FixtureBundleLinks {
    manifest_digest: Option<([u8; 32], String)>,
    order_assignment_providers: BTreeSet<[u8; 32]>,
    linked_providers: Vec<FixtureBundleProviderLink>,
    linkable_artifacts: BTreeSet<String>,
}
#[derive(Debug)]
struct FixtureBundleProviderLink {
    kind: &'static str,
    label: String,
    provider_id: [u8; 32],
    requires_order_assignment: bool,
}
impl FixtureBundleLinks {
    fn observe_manifest(
        &mut self,
        digest: [u8; 32],
        label: &str,
        inputs: Vec<ValidationInputV1>,
        generated_at: u64,
    ) -> Result<(), ValidationOutcomeV1> {
        self.linkable_artifacts.insert(label.to_owned());
        if let Some((expected, expected_label)) = &self.manifest_digest {
            if expected != &digest {
                return Err(bundle_error(
                    "SFS-BND-002",
                    CATEGORY_VALIDATION,
                    "fixture bundle manifest digest mismatch",
                    "Regenerate the bundle so replication orders, PoR/PoTR receipts, and repair payloads name the same manifest digest.",
                    vec![
                        ValidationContextFieldV1::new(
                            "expected_manifest_digest_hex",
                            hex::encode(expected),
                        ),
                        ValidationContextFieldV1::new(
                            "expected_manifest_source",
                            expected_label.clone(),
                        ),
                        ValidationContextFieldV1::new(
                            "actual_manifest_digest_hex",
                            hex::encode(digest),
                        ),
                        ValidationContextFieldV1::new("actual_manifest_source", label.to_owned()),
                    ],
                    inputs,
                    generated_at,
                ));
            }
        } else {
            self.manifest_digest = Some((digest, label.to_owned()));
        }
        Ok(())
    }
    fn observe_provider(
        &mut self,
        kind: &'static str,
        label: &str,
        provider_id: [u8; 32],
        requires_order_assignment: bool,
    ) {
        self.linkable_artifacts.insert(label.to_owned());
        self.linked_providers.push(FixtureBundleProviderLink {
            kind,
            label: label.to_owned(),
            provider_id,
            requires_order_assignment,
        });
    }
    fn finish(
        self,
        inputs: Vec<ValidationInputV1>,
        generated_at: u64,
    ) -> Result<Vec<ValidationContextFieldV1>, ValidationOutcomeV1> {
        let linkable_artifacts = self.linkable_artifacts.len();
        if linkable_artifacts < 2 {
            return Err(bundle_error(
                "SFS-BND-001",
                CATEGORY_VALIDATION,
                "fixture bundle must contain at least two linkable SoraFS artifacts",
                "Point --bundle at a fixture directory containing at least two known SoraFS artifacts such as an order plus PoR proof, or an advert plus admission envelope.",
                vec![ValidationContextFieldV1::new(
                    "linkable_artifacts",
                    linkable_artifacts.to_string(),
                )],
                inputs,
                generated_at,
            ));
        }
        if self.order_assignment_providers.is_empty() {
            if let Some(first) = self.linked_providers.first() {
                for link in self.linked_providers.iter().skip(1) {
                    if link.provider_id != first.provider_id {
                        return Err(provider_mismatch_error(
                            "provider_id does not match the first provider-bearing artifact",
                            first.provider_id,
                            &first.label,
                            link,
                            inputs,
                            generated_at,
                        ));
                    }
                }
            }
        } else {
            let mut first_provider_only_link: Option<&FixtureBundleProviderLink> = None;
            for link in &self.linked_providers {
                if link.requires_order_assignment
                    && !self.order_assignment_providers.contains(&link.provider_id)
                {
                    return Err(provider_mismatch_error(
                        "provider_id is not assigned by the replication order",
                        *self
                            .order_assignment_providers
                            .iter()
                            .next()
                            .expect("order assignment set is non-empty"),
                        "replication_order.assignments",
                        link,
                        inputs,
                        generated_at,
                    ));
                } else if !link.requires_order_assignment {
                    if let Some(first) = first_provider_only_link {
                        if link.provider_id != first.provider_id {
                            return Err(provider_mismatch_error(
                                "provider_id does not match the first provider-admission artifact",
                                first.provider_id,
                                &first.label,
                                link,
                                inputs,
                                generated_at,
                            ));
                        }
                    } else {
                        first_provider_only_link = Some(link);
                    }
                }
            }
        }
        let mut context = vec![
            ValidationContextFieldV1::new("artifact_count", inputs.len().to_string()),
            ValidationContextFieldV1::new("linkable_artifacts", linkable_artifacts.to_string()),
            ValidationContextFieldV1::new(
                "linked_provider_count",
                self.linked_providers.len().to_string(),
            ),
            ValidationContextFieldV1::new(
                "order_assignment_count",
                self.order_assignment_providers.len().to_string(),
            ),
        ];
        if let Some((manifest_digest, manifest_source)) = self.manifest_digest {
            context.push(ValidationContextFieldV1::new(
                "manifest_digest_hex",
                hex::encode(manifest_digest),
            ));
            context.push(ValidationContextFieldV1::new(
                "manifest_source",
                manifest_source,
            ));
        }
        if !self.order_assignment_providers.is_empty() {
            let providers = self
                .order_assignment_providers
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(",");
            context.push(ValidationContextFieldV1::new(
                "order_assignment_provider_ids_hex",
                providers,
            ));
        }
        Ok(context)
    }
}
/// Validates a fixture-directory payload set and checks manifest/provider links.
#[must_use]
pub fn validate_fixture_bundle_payloads(
    payloads: &[FixtureBundlePayloadV1<'_>],
    now: u64,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs: Vec<_> = payloads
        .iter()
        .map(|payload| ValidationInputV1::new(payload.kind.input_kind(), payload.label.clone()))
        .collect();
    let mut links = FixtureBundleLinks::default();
    for payload in payloads {
        if let Err(outcome) =
            validate_fixture_bundle_payload(payload, &mut links, now, generated_at)
        {
            return remap_bundle_payload_error(outcome, inputs, generated_at);
        }
    }
    let pdp_commitment = payloads
        .iter()
        .find(|payload| payload.kind == FixtureBundlePayloadKindV1::PdpCommitment);
    let pdp_challenge = payloads
        .iter()
        .find(|payload| payload.kind == FixtureBundlePayloadKindV1::PdpChallenge);
    let pdp_proof = payloads
        .iter()
        .find(|payload| payload.kind == FixtureBundlePayloadKindV1::PdpProof);
    let mut pdp_witness_diagnostic = false;
    if let (Some(commitment), Some(challenge), Some(proof)) =
        (pdp_commitment, pdp_challenge, pdp_proof)
    {
        let outcome = validate_pdp_commitment_challenge_proof_bytes(
            commitment.bytes,
            challenge.bytes,
            proof.bytes,
            commitment.label.clone(),
            challenge.label.clone(),
            proof.label.clone(),
            generated_at,
        );
        if !outcome.is_ok() {
            return remap_bundle_payload_error(outcome, inputs, generated_at);
        }
        pdp_witness_diagnostic = true;
    } else {
        if let (Some(challenge), Some(proof)) = (pdp_challenge, pdp_proof) {
            let outcome = validate_pdp_challenge_proof_bytes(
                challenge.bytes,
                proof.bytes,
                challenge.label.clone(),
                proof.label.clone(),
                generated_at,
            );
            if !outcome.is_ok() {
                return remap_bundle_payload_error(outcome, inputs, generated_at);
            }
        }
        if let (Some(commitment), Some(challenge)) = (pdp_commitment, pdp_challenge) {
            let outcome = validate_pdp_commitment_challenge_bytes(
                commitment.bytes,
                challenge.bytes,
                commitment.label.clone(),
                challenge.label.clone(),
                generated_at,
            );
            if !outcome.is_ok() {
                return remap_bundle_payload_error(outcome, inputs, generated_at);
            }
        }
    }
    if let (Some(challenge), Some(proof)) = (
        payloads
            .iter()
            .find(|payload| payload.kind == FixtureBundlePayloadKindV1::PorChallenge),
        payloads
            .iter()
            .find(|payload| payload.kind == FixtureBundlePayloadKindV1::PorProof),
    ) {
        let outcome = validate_por_challenge_proof_bytes(
            challenge.bytes,
            proof.bytes,
            challenge.label.clone(),
            proof.label.clone(),
            generated_at,
        );
        if !outcome.is_ok() {
            return remap_bundle_payload_error(outcome, inputs, generated_at);
        }
    }
    let mut context = match links.finish(inputs.clone(), generated_at) {
        Ok(context) => context,
        Err(outcome) => return outcome,
    };
    if pdp_witness_diagnostic {
        context.extend([
            ValidationContextFieldV1::new(
                "verification_scope",
                "exhaustive_pdp_witness_diagnostic_without_admission",
            ),
            ValidationContextFieldV1::new("production_acceptance", "false"),
            ValidationContextFieldV1::new("admission_trust", "not_evaluated"),
        ]);
        return ValidationOutcomeV1::ok(
            PDP_STRUCTURAL_OK_CODE,
            "fixture bundle cross-links and PDP witnesses accepted for diagnostics; production PDP admission was not evaluated",
            vec![
                "sorafs.reference.bundle".to_owned(),
                "sorafs.reference.pdp".to_owned(),
                format!("sorafs.reference.code.{PDP_STRUCTURAL_OK_CODE}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "fixture bundle cross-links accepted",
        vec![
            "sorafs.reference.bundle".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn validate_fixture_bundle_payload(
    payload: &FixtureBundlePayloadV1<'_>,
    links: &mut FixtureBundleLinks,
    now: u64,
    generated_at: u64,
) -> Result<(), ValidationOutcomeV1> {
    match payload.kind {
        FixtureBundlePayloadKindV1::ProviderAdvert => {
            let advert = decode_bundle_payload::<ProviderAdvertV1>(payload, generated_at)?;
            let mut context = advert_context(&advert);
            if let Err(error) = advert.validate_with_body(now) {
                let code = advert_validation_code(&error);
                let category = advert_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "validation_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("provider advert validation failed: {error}"),
                    "Regenerate the advert from governed provider metadata and retry validation.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            if let Err(error) = advert.verify_signature() {
                context.push(ValidationContextFieldV1::new(
                    "signature_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    "SFS-SIG-001",
                    CATEGORY_SIGNATURE,
                    format!("provider advert signature validation failed: {error}"),
                    "Resign the canonical advert envelope with the governed provider Ed25519 key.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                advert.body.provider_id,
                false,
            );
        }
        FixtureBundlePayloadKindV1::ProviderAdmissionEnvelope => {
            let envelope =
                decode_bundle_payload::<ProviderAdmissionEnvelopeV1>(payload, generated_at)?;
            let mut context = provider_admission_context(&envelope);
            if let Err(error) = verify_envelope_untrusted_signers(&envelope) {
                let code = provider_admission_envelope_code(&error);
                let category = provider_admission_envelope_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "validation_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("provider admission envelope validation failed: {error}"),
                    "Regenerate the admission envelope from governed provider metadata and council signatures.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                envelope.proposal.provider_id,
                false,
            );
        }
        FixtureBundlePayloadKindV1::ReplicationOrder => {
            let order = decode_bundle_payload::<ReplicationOrderV1>(payload, generated_at)?;
            let mut context = replication_order_context(&order);
            if let Err(error) = order.validate() {
                let code = replication_order_validation_code(&error);
                let category = replication_order_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "validation_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("replication order validation failed: {error}"),
                    "Regenerate the replication order from governed manifest and provider assignments.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                order.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            for assignment in &order.assignments {
                links
                    .order_assignment_providers
                    .insert(assignment.provider_id);
            }
        }
        FixtureBundlePayloadKindV1::PdpCommitment => {
            let commitment = decode_pdp_commitment_reference(payload.bytes).map_err(|error| {
                bundle_decode_error(payload.kind, &payload.label, error, generated_at)
            })?;
            let mut context = pdp_commitment_context(&commitment);
            if let Err(error) = commitment.validate() {
                let code = pdp_commitment_validation_code(&error);
                let category = pdp_commitment_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "commitment_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("PDP commitment validation failed: {error}"),
                    "Regenerate the PDP commitment from the canonical manifest chunk profile and commitment tree roots.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                commitment.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
        }
        FixtureBundlePayloadKindV1::PdpChallenge => {
            let challenge = decode_pdp_challenge_reference(payload.bytes).map_err(|error| {
                bundle_decode_error(payload.kind, &payload.label, error, generated_at)
            })?;
            let mut context = pdp_challenge_context(&challenge);
            if let Err(error) = challenge.validate() {
                let code = pdp_challenge_validation_code(&error);
                let category = pdp_challenge_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "challenge_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("PDP challenge validation failed: {error}"),
                    "Regenerate the PDP challenge from the canonical commitment, provider, epoch, and randomness inputs.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                challenge.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                challenge.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::PdpProof => {
            let proof = decode_pdp_proof_reference(payload.bytes).map_err(|error| {
                bundle_decode_error(payload.kind, &payload.label, error, generated_at)
            })?;
            let mut context = pdp_proof_context(&proof);
            if let Err(error) = proof.validate() {
                let code = pdp_proof_validation_code(&error);
                let category = pdp_proof_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "proof_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("PDP proof validation failed: {error}"),
                    "Regenerate the PDP proof from the challenged segments, hot-leaf witnesses, and provider signature.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                proof.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                proof.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::PorChallenge => {
            let challenge =
                crate::por::decode_por_challenge_v1(payload.bytes).map_err(|error| {
                    bundle_decode_error(
                        payload.kind,
                        &payload.label,
                        error.to_string(),
                        generated_at,
                    )
                })?;
            let mut context = vec![
                ValidationContextFieldV1::new(
                    "challenge_id_hex",
                    hex::encode(challenge.challenge_id),
                ),
                ValidationContextFieldV1::new(
                    "manifest_digest_hex",
                    hex::encode(challenge.manifest_digest),
                ),
                ValidationContextFieldV1::new(
                    "provider_id_hex",
                    hex::encode(challenge.provider_id),
                ),
            ];
            if let Err(error) = challenge.validate() {
                let code = por_challenge_validation_code(&error);
                let category = por_challenge_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "challenge_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("PoR challenge validation failed: {error}"),
                    "Regenerate the PoR challenge from the canonical manifest, provider, epoch, and randomness inputs.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                challenge.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                challenge.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::PorProof => {
            let proof = crate::por::decode_por_proof_v1(payload.bytes).map_err(|error| {
                bundle_decode_error(
                    payload.kind,
                    &payload.label,
                    error.to_string(),
                    generated_at,
                )
            })?;
            let mut context = vec![
                ValidationContextFieldV1::new("challenge_id_hex", hex::encode(proof.challenge_id)),
                ValidationContextFieldV1::new(
                    "manifest_digest_hex",
                    hex::encode(proof.manifest_digest),
                ),
                ValidationContextFieldV1::new("provider_id_hex", hex::encode(proof.provider_id)),
                ValidationContextFieldV1::new("proof_samples", proof.samples.len().to_string()),
            ];
            if let Err(error) = proof.validate() {
                let code = por_proof_validation_code(&error);
                context.push(ValidationContextFieldV1::new(
                    "proof_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    CATEGORY_VALIDATION,
                    format!("PoR proof validation failed: {error}"),
                    "Regenerate the PoR proof from the challenged chunks and canonical authentication path.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                proof.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                proof.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::PotrReceipt => {
            let receipt = decode_bundle_payload::<PotrReceiptV1>(payload, generated_at)?;
            let mut context = potr_context(&receipt);
            if let Err(error) = receipt.validate() {
                let code = potr_receipt_validation_code(&error);
                let category = potr_receipt_validation_category(&error);
                context.push(ValidationContextFieldV1::new(
                    "receipt_error",
                    error.to_string(),
                ));
                return Err(bundle_error(
                    code,
                    category,
                    format!("PoTR receipt validation failed: {error}"),
                    "Regenerate the PoTR receipt from the canonical timed retrieval observation and signer material.",
                    context,
                    vec![ValidationInputV1::new(
                        payload.kind.input_kind(),
                        payload.label.clone(),
                    )],
                    generated_at,
                ));
            }
            links.observe_manifest(
                receipt.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                receipt.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::RepairEvidence => {
            let evidence = decode_bundle_payload::<RepairEvidenceV1>(payload, generated_at)?;
            validate_repair_bundle_value(evidence.validate(), &evidence, payload, generated_at)?;
            links.observe_manifest(
                evidence.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                evidence.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::RepairReport => {
            let report = decode_bundle_payload::<RepairReportV1>(payload, generated_at)?;
            validate_repair_bundle_value(report.validate(), &report, payload, generated_at)?;
            links.observe_manifest(
                report.evidence.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                report.evidence.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::RepairTaskRecord => {
            let task = decode_bundle_payload::<RepairTaskRecordV1>(payload, generated_at)?;
            validate_repair_bundle_value(task.validate(), &task, payload, generated_at)?;
            links.observe_manifest(
                task.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                task.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::RepairSlashProposal => {
            let proposal = decode_bundle_payload::<RepairSlashProposalV1>(payload, generated_at)?;
            validate_repair_bundle_value(proposal.validate(), &proposal, payload, generated_at)?;
            links.observe_manifest(
                proposal.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                proposal.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::RepairTaskEvent => {
            let event = decode_bundle_payload::<RepairTaskEventV1>(payload, generated_at)?;
            validate_repair_bundle_value(event.validate(), &event, payload, generated_at)?;
            links.observe_manifest(
                event.manifest_digest,
                &payload.label,
                vec![ValidationInputV1::new(
                    payload.kind.input_kind(),
                    payload.label.clone(),
                )],
                generated_at,
            )?;
            links.observe_provider(
                payload.kind.input_kind(),
                &payload.label,
                event.provider_id,
                true,
            );
        }
        FixtureBundlePayloadKindV1::OrderbookOrderRequest => validate_orderbook_bundle_payload(
            OrderbookValidationPayloadKindV1::OrderRequest,
            payload,
            generated_at,
        )?,
        FixtureBundlePayloadKindV1::OrderbookOrderCancel => validate_orderbook_bundle_payload(
            OrderbookValidationPayloadKindV1::OrderCancel,
            payload,
            generated_at,
        )?,
        FixtureBundlePayloadKindV1::OrderbookTradeEvent => validate_orderbook_bundle_payload(
            OrderbookValidationPayloadKindV1::TradeEvent,
            payload,
            generated_at,
        )?,
        FixtureBundlePayloadKindV1::OrderbookSettlementChannel => {
            validate_orderbook_bundle_payload(
                OrderbookValidationPayloadKindV1::SettlementChannel,
                payload,
                generated_at,
            )?
        }
        FixtureBundlePayloadKindV1::OrderbookSettlementReceipt => {
            validate_orderbook_bundle_payload(
                OrderbookValidationPayloadKindV1::SettlementReceipt,
                payload,
                generated_at,
            )?
        }
    }
    Ok(())
}
fn validate_orderbook_bundle_payload(
    kind: OrderbookValidationPayloadKindV1,
    payload: &FixtureBundlePayloadV1<'_>,
    generated_at: u64,
) -> Result<(), ValidationOutcomeV1> {
    let outcome =
        validate_orderbook_payload_bytes(kind, payload.bytes, payload.label.clone(), generated_at);
    if outcome.is_ok() {
        Ok(())
    } else {
        Err(outcome)
    }
}
fn validate_repair_bundle_value<T>(
    result: Result<(), RepairValidationError>,
    value: &T,
    payload: &FixtureBundlePayloadV1<'_>,
    generated_at: u64,
) -> Result<(), ValidationOutcomeV1>
where
    T: std::fmt::Debug,
{
    if let Err(error) = result {
        let code = repair_validation_code(&error);
        let category = repair_validation_category(&error);
        return Err(bundle_error(
            code,
            category,
            format!("repair payload validation failed: {error}"),
            "Regenerate the repair payload from canonical scheduler or auditor state.",
            vec![
                ValidationContextFieldV1::new("schema", payload.kind.schema()),
                ValidationContextFieldV1::new("validation_error", error.to_string()),
                ValidationContextFieldV1::new("payload", format!("{value:?}")),
            ],
            vec![ValidationInputV1::new(
                payload.kind.input_kind(),
                payload.label.clone(),
            )],
            generated_at,
        ));
    }
    Ok(())
}
fn decode_bundle_payload<T>(
    payload: &FixtureBundlePayloadV1<'_>,
    generated_at: u64,
) -> Result<T, ValidationOutcomeV1>
where
    T: norito::NoritoSerialize + for<'decode> norito::NoritoDeserialize<'decode>,
{
    decode_reference_frame::<T>(payload.bytes).map_err(|error| {
        bundle_decode_error(
            payload.kind,
            &payload.label,
            error.to_string(),
            generated_at,
        )
    })
}
fn bundle_decode_error(
    kind: FixtureBundlePayloadKindV1,
    label: &str,
    error: String,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    bundle_error(
        "SFS-NORITO-001",
        CATEGORY_NORITO,
        format!("failed to decode {} Norito payload: {error}", kind.schema()),
        "Re-encode the fixture payload with the canonical SoraFS Norito schema.",
        vec![ValidationContextFieldV1::new("schema", kind.schema())],
        vec![ValidationInputV1::new(kind.input_kind(), label.to_owned())],
        generated_at,
    )
}
fn bundle_error(
    code: impl Into<String>,
    category: impl Into<String>,
    message: impl Into<String>,
    action: impl Into<String>,
    context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let code = code.into();
    let mut tags = vec!["sorafs.reference.bundle".to_owned()];
    tags.push(format!("sorafs.reference.code.{code}"));
    ValidationOutcomeV1::error(
        code,
        category,
        message,
        action,
        tags,
        context,
        inputs,
        generated_at,
    )
}
fn remap_bundle_payload_error(
    outcome: ValidationOutcomeV1,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    if outcome.code == "SFS-BND-002" || outcome.code == "SFS-BND-003" {
        return outcome;
    }
    let mut context = outcome.context;
    context.push(ValidationContextFieldV1::new(
        "payload_code",
        outcome.code.clone(),
    ));
    context.push(ValidationContextFieldV1::new(
        "payload_message",
        outcome.message,
    ));
    bundle_error(
        "SFS-BND-001",
        outcome.category,
        "fixture bundle payload validation failed",
        "Fix the invalid payload named in the bundle outcome before rerunning cross-link validation.",
        context,
        inputs,
        generated_at,
    )
}
fn provider_mismatch_error(
    reason: &str,
    expected_provider: [u8; 32],
    expected_source: &str,
    actual: &FixtureBundleProviderLink,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    bundle_error(
        "SFS-BND-003",
        CATEGORY_VALIDATION,
        "fixture bundle provider assignment mismatch",
        "Regenerate the bundle so provider-bearing artifacts either share the same provider or appear in the replication order assignments.",
        vec![
            ValidationContextFieldV1::new("provider_mismatch_reason", reason),
            ValidationContextFieldV1::new(
                "expected_provider_id_hex",
                hex::encode(expected_provider),
            ),
            ValidationContextFieldV1::new("expected_provider_source", expected_source),
            ValidationContextFieldV1::new(
                "actual_provider_id_hex",
                hex::encode(actual.provider_id),
            ),
            ValidationContextFieldV1::new("actual_provider_source", actual.label.clone()),
            ValidationContextFieldV1::new("actual_provider_kind", actual.kind),
        ],
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`GovernanceLogNodeV1`] and emits a reference outcome.
#[must_use]
pub fn validate_governance_log_node_bytes(
    bytes: &[u8],
    label: impl Into<String>,
    expected_node_cid: Option<&[u8]>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let label = label.into();
    let inputs = vec![ValidationInputV1::new("governance_log_node", label.clone())];
    let node = match decode_reference_frame::<GovernanceLogNodeV1>(bytes) {
        Ok(node) => node,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode governance log node Norito payload: {error}"),
                "Re-encode the governance log node with the canonical SoraFS Norito schema.",
                vec![
                    "sorafs.reference.governance".to_owned(),
                    "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                ],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "GovernanceLogNodeV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = governance_log_node_context(&node);
    if let Some(expected_node_cid) = expected_node_cid
        && node.node_cid.as_slice() != expected_node_cid
    {
        context.push(ValidationContextFieldV1::new(
            "expected_node_cid_hex",
            bounded_governance_cid_hex(expected_node_cid),
        ));
        context.push(ValidationContextFieldV1::new(
            "expected_node_cid_len",
            expected_node_cid.len().to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-GOV-003",
            CATEGORY_VALIDATION,
            "governance log node CID does not match the expected CID",
            "Pass the node CID that belongs to this governance log node or regenerate the fixture from the canonical node payload.",
            vec![
                "sorafs.reference.governance".to_owned(),
                "sorafs.reference.code.SFS-GOV-003".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = node.validate() {
        let code = governance_log_validation_code(&error);
        let category = governance_log_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("governance log node validation failed: {error}"),
            "Regenerate the governance log node from canonical payload bytes, publisher metadata, and governed signature material.",
            vec![
                "sorafs.reference.governance".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = node.verify_publisher_signature() {
        context.push(ValidationContextFieldV1::new(
            "signature_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            governance_signature_verification_code(&error),
            governance_signature_verification_category(&error),
            format!("governance log publisher signature validation failed: {error}"),
            "Resign the governance log node with the governed publisher key and canonical node signing bytes.",
            vec![
                "sorafs.reference.governance".to_owned(),
                format!(
                    "sorafs.reference.code.{}",
                    governance_signature_verification_code(&error)
                ),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let GovernanceLogPayloadV1::ProviderAdvert(advert) = &node.payload
        && let Err(error) = advert.verify_signature()
    {
        context.push(ValidationContextFieldV1::new(
            "signature_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-SIG-001",
            CATEGORY_SIGNATURE,
            format!("governance provider advert signature validation failed: {error}"),
            "Resign the embedded canonical advert envelope with the governed provider Ed25519 key.",
            vec![
                "sorafs.reference.governance".to_owned(),
                "sorafs.reference.code.SFS-SIG-001".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "governance log node accepted",
        vec![
            "sorafs.reference.governance".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`GovernanceDagBlockV1`] and emits a reference outcome.
#[must_use]
pub fn validate_governance_dag_block_bytes(
    bytes: &[u8],
    label: impl Into<String>,
    expected_block_cid: Option<&[u8]>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let label = label.into();
    let inputs = vec![ValidationInputV1::new(
        "governance_dag_block",
        label.clone(),
    )];
    let block = match decode_reference_frame::<GovernanceDagBlockV1>(bytes) {
        Ok(block) => block,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode governance DAG block Norito payload: {error}"),
                "Re-encode the governance DAG block with the canonical SoraFS Norito schema.",
                vec![
                    "sorafs.reference.governance_dag.block".to_owned(),
                    "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                ],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "GovernanceDagBlockV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = governance_dag_block_context(&block);
    if let Some(expected_block_cid) = expected_block_cid
        && block.block_cid.as_slice() != expected_block_cid
    {
        context.push(ValidationContextFieldV1::new(
            "expected_block_cid_hex",
            bounded_governance_cid_hex(expected_block_cid),
        ));
        context.push(ValidationContextFieldV1::new(
            "expected_block_cid_len",
            expected_block_cid.len().to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-GOV-004",
            CATEGORY_VALIDATION,
            "governance DAG block CID does not match the expected CID",
            "Pass the block CID that belongs to this governance DAG block or regenerate the block from canonical payload bytes.",
            vec![
                "sorafs.reference.governance_dag.block".to_owned(),
                "sorafs.reference.code.SFS-GOV-004".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = block.validate() {
        let code = governance_dag_block_validation_code(&error);
        let category = governance_dag_block_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("governance DAG block validation failed: {error}"),
            "Regenerate the governance DAG block from canonical log-node bytes, parent linkage, publisher metadata, and governed signature material.",
            vec![
                "sorafs.reference.governance_dag.block".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "governance DAG block accepted",
        vec![
            "sorafs.reference.governance_dag.block".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a signed [`GovernanceDagHeadV1`] against Norito-encoded blocks.
#[must_use]
pub fn validate_governance_dag_head_chain_bytes(
    head_bytes: &[u8],
    head_label: impl Into<String>,
    block_payloads: &[(&[u8], String)],
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let head_label = head_label.into();
    let mut inputs = vec![ValidationInputV1::new(
        "governance_dag_head",
        head_label.clone(),
    )];
    for (_, label) in block_payloads {
        inputs.push(ValidationInputV1::new(
            "governance_dag_block",
            label.clone(),
        ));
    }
    let head = match decode_reference_frame::<GovernanceDagHeadV1>(head_bytes) {
        Ok(head) => head,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode governance DAG head Norito payload: {error}"),
                "Re-encode the governance DAG head with the canonical SoraFS Norito schema.",
                vec![
                    "sorafs.reference.governance_dag.head".to_owned(),
                    "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                ],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "GovernanceDagHeadV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut blocks = Vec::with_capacity(block_payloads.len());
    for (bytes, label) in block_payloads {
        match decode_reference_frame::<GovernanceDagBlockV1>(bytes) {
            Ok(block) => blocks.push(block),
            Err(error) => {
                return ValidationOutcomeV1::error(
                    "SFS-NORITO-001",
                    CATEGORY_NORITO,
                    format!(
                        "failed to decode governance DAG block Norito payload `{label}`: {error}"
                    ),
                    "Re-encode every governance DAG block with the canonical SoraFS Norito schema before validating the head chain.",
                    vec![
                        "sorafs.reference.governance_dag.head".to_owned(),
                        "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                    ],
                    vec![
                        ValidationContextFieldV1::new("schema", "GovernanceDagBlockV1"),
                        ValidationContextFieldV1::new("block_label", label.clone()),
                    ],
                    inputs,
                    generated_at,
                );
            }
        }
    }
    let mut context = governance_dag_head_context(&head);
    context.push(ValidationContextFieldV1::new(
        "block_payload_count",
        blocks.len().to_string(),
    ));
    for (index, block) in blocks.iter().enumerate() {
        context.push(ValidationContextFieldV1::new(
            format!("block_{index}_cid_hex"),
            bounded_governance_cid_hex(&block.block_cid),
        ));
    }
    if let Err(error) = validate_governance_dag_head_against_chain_v1(&head, &blocks) {
        let code = governance_dag_head_chain_validation_code(&error);
        let category = governance_dag_head_chain_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("governance DAG head-chain validation failed: {error}"),
            "Regenerate the governance DAG blocks and signed head manifest from one canonical parent-linked chain.",
            vec![
                "sorafs.reference.governance_dag.head".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "governance DAG head accepted",
        vec![
            "sorafs.reference.governance_dag.head".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn governance_log_node_context(node: &GovernanceLogNodeV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "GovernanceLogNodeV1"),
        ValidationContextFieldV1::new("version", node.version.to_string()),
        ValidationContextFieldV1::new(
            "node_cid",
            bounded_governance_bytes(&node.node_cid, crate::GOVERNANCE_DAG_CID_BYTES_V1),
        ),
        ValidationContextFieldV1::new("node_cid_hex", bounded_governance_cid_hex(&node.node_cid)),
        ValidationContextFieldV1::new("node_cid_len", node.node_cid.len().to_string()),
        ValidationContextFieldV1::new("timestamp", node.timestamp.to_string()),
        ValidationContextFieldV1::new(
            "publisher_peer_id",
            bounded_governance_bytes(
                &node.publisher_peer_id,
                crate::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1,
            ),
        ),
        ValidationContextFieldV1::new(
            "publisher_peer_id_len",
            node.publisher_peer_id.len().to_string(),
        ),
        ValidationContextFieldV1::new("payload_kind", governance_payload_kind(&node.payload)),
        ValidationContextFieldV1::new(
            "publisher_signature_algorithm",
            governance_signature_algorithm_label(node.publisher_signature.algorithm),
        ),
        ValidationContextFieldV1::new(
            "publisher_public_key_len",
            node.publisher_signature.public_key.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "publisher_signature_len",
            node.publisher_signature.signature.len().to_string(),
        ),
    ];
    if let Some(prev_cid) = &node.prev_cid {
        context.push(ValidationContextFieldV1::new(
            "prev_cid",
            bounded_governance_bytes(prev_cid, crate::GOVERNANCE_DAG_CID_BYTES_V1),
        ));
        context.push(ValidationContextFieldV1::new(
            "prev_cid_hex",
            bounded_governance_cid_hex(prev_cid),
        ));
        context.push(ValidationContextFieldV1::new(
            "prev_cid_len",
            prev_cid.len().to_string(),
        ));
    }
    if let Some(provenance) = &node.submission_provenance {
        context.push(ValidationContextFieldV1::new(
            "submission_publisher_account_digest_hex",
            hex::encode(provenance.publisher_account_digest),
        ));
        context.push(ValidationContextFieldV1::new(
            "submission_origin",
            provenance.origin.label(),
        ));
    }
    context
}
fn governance_dag_block_context(block: &GovernanceDagBlockV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "GovernanceDagBlockV1"),
        ValidationContextFieldV1::new("version", block.version.to_string()),
        ValidationContextFieldV1::new(
            "block_cid_hex",
            bounded_governance_cid_hex(&block.block_cid),
        ),
        ValidationContextFieldV1::new("block_cid_len", block.block_cid.len().to_string()),
        ValidationContextFieldV1::new("sequence", block.sequence.to_string()),
        ValidationContextFieldV1::new("timestamp", block.timestamp.to_string()),
        ValidationContextFieldV1::new(
            "publisher_peer_id",
            bounded_governance_bytes(
                &block.publisher_peer_id,
                crate::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1,
            ),
        ),
        ValidationContextFieldV1::new(
            "publisher_peer_id_len",
            block.publisher_peer_id.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "node_cid_hex",
            bounded_governance_cid_hex(&block.node.node_cid),
        ),
        ValidationContextFieldV1::new("node_cid_len", block.node.node_cid.len().to_string()),
        ValidationContextFieldV1::new(
            "node_payload_kind",
            governance_payload_kind(&block.node.payload),
        ),
        ValidationContextFieldV1::new(
            "block_signature_algorithm",
            governance_signature_algorithm_label(block.block_signature.algorithm),
        ),
        ValidationContextFieldV1::new(
            "block_public_key_len",
            block.block_signature.public_key.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "block_signature_len",
            block.block_signature.signature.len().to_string(),
        ),
    ];
    if let Some(prev) = &block.prev_block_cid {
        context.push(ValidationContextFieldV1::new(
            "prev_block_cid_hex",
            bounded_governance_cid_hex(prev),
        ));
        context.push(ValidationContextFieldV1::new(
            "prev_block_cid_len",
            prev.len().to_string(),
        ));
    }
    context
}
fn governance_dag_head_context(head: &GovernanceDagHeadV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "GovernanceDagHeadV1"),
        ValidationContextFieldV1::new("version", head.version.to_string()),
        ValidationContextFieldV1::new(
            "head_block_cid_hex",
            bounded_governance_cid_hex(&head.head_block_cid),
        ),
        ValidationContextFieldV1::new("head_block_cid_len", head.head_block_cid.len().to_string()),
        ValidationContextFieldV1::new("block_count", head.block_count.to_string()),
        ValidationContextFieldV1::new("generated_at", head.generated_at.to_string()),
        ValidationContextFieldV1::new(
            "publisher_peer_id",
            bounded_governance_bytes(
                &head.publisher_peer_id,
                crate::GOVERNANCE_DAG_PUBLISHER_PEER_ID_MAX_BYTES_V1,
            ),
        ),
        ValidationContextFieldV1::new(
            "publisher_peer_id_len",
            head.publisher_peer_id.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "head_signature_algorithm",
            governance_signature_algorithm_label(head.head_signature.algorithm),
        ),
        ValidationContextFieldV1::new(
            "head_public_key_len",
            head.head_signature.public_key.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "head_signature_len",
            head.head_signature.signature.len().to_string(),
        ),
    ];
    if let Some(checkpoint) = &head.checkpoint_cid {
        context.push(ValidationContextFieldV1::new(
            "checkpoint_cid_hex",
            bounded_governance_cid_hex(checkpoint),
        ));
        context.push(ValidationContextFieldV1::new(
            "checkpoint_cid_len",
            checkpoint.len().to_string(),
        ));
    }
    context
}
fn bounded_governance_cid_hex(bytes: &[u8]) -> String {
    if bytes.len() == crate::GOVERNANCE_DAG_CID_BYTES_V1 {
        hex::encode(bytes)
    } else {
        format!("<invalid-length:{}>", bytes.len())
    }
}
fn bounded_governance_bytes(bytes: &[u8], maximum: usize) -> String {
    if bytes.len() <= maximum {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        format!("<oversized:{}>", bytes.len())
    }
}
fn order_request_context(order: &OrderRequestV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "OrderRequestV1"),
        ValidationContextFieldV1::new("version", order.version.to_string()),
        ValidationContextFieldV1::new("order_id_hex", hex::encode(order.order_id)),
        ValidationContextFieldV1::new("side", order_side_label(order.side)),
        ValidationContextFieldV1::new("tier", order_tier_label(order.tier)),
        ValidationContextFieldV1::new("price_per_gib", order.price_per_gib.to_string()),
        ValidationContextFieldV1::new("quantity_gib", order.quantity_gib.to_string()),
        ValidationContextFieldV1::new("remaining_gib", order.remaining_gib.to_string()),
        ValidationContextFieldV1::new("owner_account_len", order.owner_account.len().to_string()),
        ValidationContextFieldV1::new("expiry_unix", order.expiry_unix.to_string()),
        ValidationContextFieldV1::new("nonce", order.nonce.to_string()),
        ValidationContextFieldV1::new("maker_fee_bps", order.maker_fee_bps.to_string()),
        ValidationContextFieldV1::new("taker_fee_bps", order.taker_fee_bps.to_string()),
    ];
    append_orderbook_signature_context(&mut context, &order.signature);
    context
}
fn order_cancel_context(cancel: &OrderCancelV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "OrderCancelV1"),
        ValidationContextFieldV1::new("version", cancel.version.to_string()),
        ValidationContextFieldV1::new("order_id_hex", hex::encode(cancel.order_id)),
        ValidationContextFieldV1::new("owner_account_len", cancel.owner_account.len().to_string()),
        ValidationContextFieldV1::new("reason", order_cancel_reason_label(cancel.reason)),
        ValidationContextFieldV1::new("nonce", cancel.nonce.to_string()),
    ];
    append_orderbook_signature_context(&mut context, &cancel.signature);
    context
}
fn trade_event_context(trade: &TradeEventV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "TradeEventV1"),
        ValidationContextFieldV1::new("version", trade.version.to_string()),
        ValidationContextFieldV1::new("trade_id_hex", hex::encode(trade.trade_id)),
        ValidationContextFieldV1::new("maker_order_id_hex", hex::encode(trade.maker_order_id)),
        ValidationContextFieldV1::new("taker_order_id_hex", hex::encode(trade.taker_order_id)),
        ValidationContextFieldV1::new("tier", order_tier_label(trade.tier)),
        ValidationContextFieldV1::new("price_per_gib", trade.price_per_gib.to_string()),
        ValidationContextFieldV1::new("filled_gib", trade.filled_gib.to_string()),
        ValidationContextFieldV1::new("maker_fee", trade.maker_fee.to_string()),
        ValidationContextFieldV1::new("taker_fee", trade.taker_fee.to_string()),
        ValidationContextFieldV1::new("timestamp_unix", trade.timestamp_unix.to_string()),
    ]
}
fn settlement_channel_context(channel: &SettlementChannelV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "SettlementChannelV1"),
        ValidationContextFieldV1::new("version", channel.version.to_string()),
        ValidationContextFieldV1::new("channel_id_hex", hex::encode(channel.channel_id)),
        ValidationContextFieldV1::new("trade_id_hex", hex::encode(channel.trade_id)),
        ValidationContextFieldV1::new("buyer_account_len", channel.buyer_account.len().to_string()),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(channel.provider_id)),
        ValidationContextFieldV1::new("total_bytes", channel.total_bytes.to_string()),
        ValidationContextFieldV1::new("remaining_bytes", channel.remaining_bytes.to_string()),
        ValidationContextFieldV1::new("xor_locked", channel.xor_locked.to_string()),
        ValidationContextFieldV1::new("status", settlement_channel_status_label(channel.status)),
        ValidationContextFieldV1::new("opened_at_unix", channel.opened_at_unix.to_string()),
        ValidationContextFieldV1::new("updated_at_unix", channel.updated_at_unix.to_string()),
    ]
}
fn settlement_receipt_context(receipt: &SettlementReceiptV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "SettlementReceiptV1"),
        ValidationContextFieldV1::new("version", receipt.version.to_string()),
        ValidationContextFieldV1::new("receipt_id_hex", hex::encode(receipt.receipt_id)),
        ValidationContextFieldV1::new("channel_id_hex", hex::encode(receipt.channel_id)),
        ValidationContextFieldV1::new("trade_id_hex", hex::encode(receipt.trade_id)),
        ValidationContextFieldV1::new("range_start", receipt.range.start.to_string()),
        ValidationContextFieldV1::new("range_end", receipt.range.end.to_string()),
        ValidationContextFieldV1::new("chunk_hash_hex", hex::encode(receipt.chunk_hash)),
        ValidationContextFieldV1::new("bytes_delivered", receipt.bytes_delivered.to_string()),
        ValidationContextFieldV1::new("xor_debited", receipt.xor_debited.to_string()),
        ValidationContextFieldV1::new("provider_credit", receipt.provider_credit.to_string()),
        ValidationContextFieldV1::new("fee_amount", receipt.fee_amount.to_string()),
        ValidationContextFieldV1::new("issued_at_unix", receipt.issued_at_unix.to_string()),
    ];
    append_orderbook_signature_context(&mut context, &receipt.settlement_signature);
    context
}
fn append_orderbook_signature_context(
    context: &mut Vec<ValidationContextFieldV1>,
    signature: &crate::OrderbookSignatureV1,
) {
    context.push(ValidationContextFieldV1::new(
        "signature_algorithm",
        signature_algorithm_label(signature.algorithm),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_public_key_len",
        signature.public_key.len().to_string(),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_len",
        signature.signature.len().to_string(),
    ));
}
fn hedging_price_feed_context(feed: &HedgingPriceFeedV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "HedgingPriceFeedV1"),
        ValidationContextFieldV1::new("version", feed.version.to_string()),
        ValidationContextFieldV1::new("feed_id", feed.feed_id.clone()),
        ValidationContextFieldV1::new("source", feed.source.clone()),
        ValidationContextFieldV1::new("observed_at_unix", feed.observed_at_unix.to_string()),
        ValidationContextFieldV1::new("xor_usd_price", feed.xor_usd_price.to_string()),
        ValidationContextFieldV1::new("weight_bps", feed.weight_bps.to_string()),
        ValidationContextFieldV1::new("evidence_digest_hex", hex::encode(feed.evidence_digest)),
        ValidationContextFieldV1::new("status", hedging_feed_status_label(feed.status)),
    ]
}
fn hedging_reference_price_decision_context(
    decision: &HedgingReferencePriceDecisionV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "HedgingReferencePriceDecisionV1"),
        ValidationContextFieldV1::new("version", decision.version.to_string()),
        ValidationContextFieldV1::new("decision_id_hex", hex::encode(decision.decision_id)),
        ValidationContextFieldV1::new("effective_at_unix", decision.effective_at_unix.to_string()),
        ValidationContextFieldV1::new("xor_usd_price", decision.xor_usd_price.to_string()),
        ValidationContextFieldV1::new("max_feed_age_secs", decision.max_feed_age_secs.to_string()),
        ValidationContextFieldV1::new(
            "max_divergence_bps",
            decision.max_divergence_bps.to_string(),
        ),
        ValidationContextFieldV1::new("feed_count", decision.feeds.len().to_string()),
        ValidationContextFieldV1::new("degraded", decision.degraded.to_string()),
        ValidationContextFieldV1::new(
            "degradation_reason_count",
            decision.degradation_reasons.len().to_string(),
        ),
    ]
}
fn billing_line_item_context(line: &BillingLineItemV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "BillingLineItemV1"),
        ValidationContextFieldV1::new("version", line.version.to_string()),
        ValidationContextFieldV1::new("line_id_hex", hex::encode(line.line_id)),
        ValidationContextFieldV1::new("kind", billing_line_kind_label(line.kind)),
        ValidationContextFieldV1::new("direction", billing_line_direction_label(line.direction)),
        ValidationContextFieldV1::new("source_id", line.source_id.clone()),
        ValidationContextFieldV1::new("xor_amount", line.xor_amount.to_string()),
        ValidationContextFieldV1::new("usd_amount", line.usd_amount.to_string()),
        ValidationContextFieldV1::new("quantity_units", line.quantity_units.to_string()),
        ValidationContextFieldV1::new("note_present", line.note.is_some().to_string()),
    ]
}
fn billing_statement_context(statement: &BillingStatementV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "BillingStatementV1"),
        ValidationContextFieldV1::new("version", statement.version.to_string()),
        ValidationContextFieldV1::new("statement_id_hex", hex::encode(statement.statement_id)),
        ValidationContextFieldV1::new("account_id_len", statement.account_id.len().to_string()),
        ValidationContextFieldV1::new("period_start_unix", statement.period_start_unix.to_string()),
        ValidationContextFieldV1::new("period_end_unix", statement.period_end_unix.to_string()),
        ValidationContextFieldV1::new("due_at_unix", statement.due_at_unix.to_string()),
        ValidationContextFieldV1::new(
            "reference_decision_id_hex",
            hex::encode(statement.reference_price.decision_id),
        ),
        ValidationContextFieldV1::new("line_count", statement.lines.len().to_string()),
        ValidationContextFieldV1::new("total_debit_xor", statement.total_debit_xor.to_string()),
        ValidationContextFieldV1::new("total_credit_xor", statement.total_credit_xor.to_string()),
        ValidationContextFieldV1::new("net_due_xor", statement.net_due_xor.to_string()),
        ValidationContextFieldV1::new("total_debit_usd", statement.total_debit_usd.to_string()),
        ValidationContextFieldV1::new("total_credit_usd", statement.total_credit_usd.to_string()),
        ValidationContextFieldV1::new("net_due_usd", statement.net_due_usd.to_string()),
        ValidationContextFieldV1::new(
            "previous_statement_present",
            statement.previous_statement_id.is_some().to_string(),
        ),
    ]
}
fn hedging_feed_status_label(status: HedgingFeedStatusV1) -> String {
    match status {
        HedgingFeedStatusV1::Ok => "ok",
        HedgingFeedStatusV1::Degraded => "degraded",
        HedgingFeedStatusV1::Rejected => "rejected",
    }
    .to_owned()
}
fn billing_line_direction_label(direction: BillingLineDirectionV1) -> String {
    match direction {
        BillingLineDirectionV1::Debit => "debit",
        BillingLineDirectionV1::Credit => "credit",
    }
    .to_owned()
}
fn billing_line_kind_label(kind: BillingLineItemKindV1) -> String {
    match kind {
        BillingLineItemKindV1::Storage => "storage",
        BillingLineItemKindV1::Egress => "egress",
        BillingLineItemKindV1::ReserveRent => "reserve_rent",
        BillingLineItemKindV1::SettlementFee => "settlement_fee",
        BillingLineItemKindV1::Penalty => "penalty",
        BillingLineItemKindV1::IncentiveCredit => "incentive_credit",
        BillingLineItemKindV1::Adjustment => "adjustment",
    }
    .to_owned()
}
fn pop_credential_context(credential: &PopCredentialV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "PopCredentialV1"),
        ValidationContextFieldV1::new("version", credential.version.to_string()),
        ValidationContextFieldV1::new("credential_id_hex", hex::encode(credential.credential_id)),
        ValidationContextFieldV1::new(
            "holder_commitment_hex",
            hex::encode(credential.holder_commitment),
        ),
        ValidationContextFieldV1::new(
            "eligibility_class",
            pop_eligibility_class_label(credential.eligibility_class),
        ),
        ValidationContextFieldV1::new("issuer_id", credential.issuer_id.clone()),
        ValidationContextFieldV1::new("issued_at_epoch", credential.issued_at_epoch.to_string()),
        ValidationContextFieldV1::new("expires_at_epoch", credential.expires_at_epoch.to_string()),
        ValidationContextFieldV1::new("renewal_at_epoch", credential.renewal_at_epoch.to_string()),
        ValidationContextFieldV1::new(
            "revocation_nonce_hex",
            hex::encode(credential.revocation_nonce),
        ),
        ValidationContextFieldV1::new(
            "commitment_root_hex",
            hex::encode(credential.commitment_root),
        ),
        ValidationContextFieldV1::new(
            "commitment_tree_version",
            credential.commitment_tree_version.to_string(),
        ),
        ValidationContextFieldV1::new(
            "revocation_list_version",
            credential.revocation_list_version.to_string(),
        ),
        ValidationContextFieldV1::new("attribute_count", credential.attributes.len().to_string()),
    ];
    append_pop_signature_context(&mut context, &credential.issuer_signature);
    context
}
fn pop_commitment_root_context(root: &PopCommitmentRootV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "PopCommitmentRootV1"),
        ValidationContextFieldV1::new("version", root.version.to_string()),
        ValidationContextFieldV1::new("root_digest_hex", hex::encode(root.root_digest)),
        ValidationContextFieldV1::new("tree_size", root.tree_size.to_string()),
        ValidationContextFieldV1::new("tree_depth", root.tree_depth.to_string()),
        ValidationContextFieldV1::new("tree_version", root.tree_version.to_string()),
        ValidationContextFieldV1::new("issuer_id", root.issuer_id.clone()),
        ValidationContextFieldV1::new("published_at_epoch", root.published_at_epoch.to_string()),
        ValidationContextFieldV1::new(
            "previous_root_present",
            root.previous_root_digest.is_some().to_string(),
        ),
        ValidationContextFieldV1::new(
            "governance_event_digest_hex",
            hex::encode(root.governance_event_digest),
        ),
    ];
    append_pop_signature_context(&mut context, &root.publisher_signature);
    context
}
fn pop_revocation_list_context(revocations: &PopRevocationListV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("schema", "PopRevocationListV1"),
        ValidationContextFieldV1::new("version", revocations.version.to_string()),
        ValidationContextFieldV1::new("list_version", revocations.list_version.to_string()),
        ValidationContextFieldV1::new(
            "commitment_root_hex",
            hex::encode(revocations.commitment_root),
        ),
        ValidationContextFieldV1::new(
            "revocation_root_hex",
            hex::encode(revocations.revocation_root),
        ),
        ValidationContextFieldV1::new(
            "revocation_tree_depth",
            revocations.revocation_tree_depth.to_string(),
        ),
        ValidationContextFieldV1::new("issuer_id", revocations.issuer_id.clone()),
        ValidationContextFieldV1::new(
            "published_at_epoch",
            revocations.published_at_epoch.to_string(),
        ),
        ValidationContextFieldV1::new("entry_count", revocations.entries.len().to_string()),
    ];
    append_pop_signature_context(&mut context, &revocations.publisher_signature);
    context
}
fn pop_issued_credential_bundle_context(
    bundle: &PopIssuedCredentialBundleV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PopIssuedCredentialBundleV1"),
        ValidationContextFieldV1::new("version", bundle.version.to_string()),
        ValidationContextFieldV1::new(
            "credential_id_hex",
            hex::encode(bundle.credential.credential_id),
        ),
        ValidationContextFieldV1::new("issuer_id", bundle.credential.issuer_id.clone()),
        ValidationContextFieldV1::new(
            "commitment_root_hex",
            hex::encode(bundle.commitment_root.root_digest),
        ),
        ValidationContextFieldV1::new(
            "commitment_tree_version",
            bundle.commitment_root.tree_version.to_string(),
        ),
        ValidationContextFieldV1::new(
            "revocation_list_version",
            bundle.revocation_list.list_version.to_string(),
        ),
        ValidationContextFieldV1::new(
            "revocation_entry_count",
            bundle.revocation_list.entries.len().to_string(),
        ),
    ]
}
fn pop_enrollment_request_context(
    request: &PopEnrollmentRequestV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PopEnrollmentRequestV1"),
        ValidationContextFieldV1::new("version", request.version.to_string()),
        ValidationContextFieldV1::new("request_id_hex", hex::encode(request.request_id)),
        ValidationContextFieldV1::new("applicant_id", request.applicant_id.clone()),
        ValidationContextFieldV1::new(
            "requested_class",
            pop_eligibility_class_label(request.requested_class),
        ),
        ValidationContextFieldV1::new(
            "requested_attribute_count",
            request.requested_attributes.len().to_string(),
        ),
        ValidationContextFieldV1::new(
            "attestation_digest_hex",
            hex::encode(request.attestation_digest),
        ),
        ValidationContextFieldV1::new("submitted_at_epoch", request.submitted_at_epoch.to_string()),
        ValidationContextFieldV1::new("expires_at_epoch", request.expires_at_epoch.to_string()),
    ]
}
fn pop_renewal_request_context(request: &PopRenewalRequestV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PopRenewalRequestV1"),
        ValidationContextFieldV1::new("version", request.version.to_string()),
        ValidationContextFieldV1::new("request_id_hex", hex::encode(request.request_id)),
        ValidationContextFieldV1::new(
            "previous_credential_id_hex",
            hex::encode(request.previous_credential_id),
        ),
        ValidationContextFieldV1::new(
            "holder_commitment_hex",
            hex::encode(request.holder_commitment),
        ),
        ValidationContextFieldV1::new(
            "rotation_commitment_hex",
            hex::encode(request.rotation_commitment),
        ),
        ValidationContextFieldV1::new(
            "requested_expires_at_epoch",
            request.requested_expires_at_epoch.to_string(),
        ),
        ValidationContextFieldV1::new("submitted_at_epoch", request.submitted_at_epoch.to_string()),
        ValidationContextFieldV1::new(
            "attestation_digest_hex",
            hex::encode(request.attestation_digest),
        ),
    ]
}
fn pop_membership_proof_context(proof: &PopMembershipProofV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PopMembershipProofV1"),
        ValidationContextFieldV1::new("version", proof.version.to_string()),
        ValidationContextFieldV1::new(
            "eligibility_class",
            pop_eligibility_class_label(proof.eligibility_class),
        ),
        ValidationContextFieldV1::new("commitment_root_hex", hex::encode(proof.commitment_root)),
        ValidationContextFieldV1::new(
            "commitment_tree_version",
            proof.commitment_tree_version.to_string(),
        ),
        ValidationContextFieldV1::new("revocation_root_hex", hex::encode(proof.revocation_root)),
        ValidationContextFieldV1::new(
            "revocation_list_version",
            proof.revocation_list_version.to_string(),
        ),
        ValidationContextFieldV1::new("nullifier_hex", hex::encode(proof.nullifier)),
        ValidationContextFieldV1::new("challenge_digest_hex", hex::encode(proof.challenge_digest)),
        ValidationContextFieldV1::new("verifier_context", proof.verifier_context.clone()),
        ValidationContextFieldV1::new(
            "presentation_binding_digest_hex",
            hex::encode(proof.presentation_binding_digest),
        ),
        ValidationContextFieldV1::new(
            "proof_system",
            pop_membership_proof_system_label(proof.proof_system),
        ),
        ValidationContextFieldV1::new(
            "membership_circuit_id",
            proof.verifier_material.circuit_id.clone(),
        ),
        ValidationContextFieldV1::new(
            "membership_parameter_digest_hex",
            hex::encode(proof.verifier_material.parameter_digest),
        ),
        ValidationContextFieldV1::new(
            "membership_verifying_key_digest_hex",
            hex::encode(proof.verifier_material.verifying_key_digest),
        ),
        ValidationContextFieldV1::new("proof_bytes_len", proof.proof_bytes.len().to_string()),
        ValidationContextFieldV1::new("expires_at_epoch", proof.expires_at_epoch.to_string()),
    ]
}
fn append_pop_signature_context(
    context: &mut Vec<ValidationContextFieldV1>,
    signature: &PopSignatureV1,
) {
    context.push(ValidationContextFieldV1::new(
        "signature_algorithm",
        pop_signature_algorithm_label(signature.algorithm),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_public_key_len",
        signature.public_key.len().to_string(),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_len",
        signature.signature.len().to_string(),
    ));
}
fn pop_eligibility_class_label(class: PopEligibilityClassV1) -> &'static str {
    match class {
        PopEligibilityClassV1::General => "general",
        PopEligibilityClassV1::Regional => "regional",
        PopEligibilityClassV1::Expert => "expert",
        PopEligibilityClassV1::Emergency => "emergency",
        PopEligibilityClassV1::Observer => "observer",
    }
}
fn pop_signature_algorithm_label(algorithm: PopSignatureAlgorithmV1) -> &'static str {
    match algorithm {
        PopSignatureAlgorithmV1::Ed25519 => "ed25519",
    }
}
fn pop_membership_proof_system_label(system: PopMembershipProofSystemV1) -> &'static str {
    match system {
        PopMembershipProofSystemV1::NativePipaRV1 => "native_pipa_r_v1",
    }
}
fn order_side_label(side: OrderSideV1) -> &'static str {
    match side {
        OrderSideV1::Bid => "bid",
        OrderSideV1::Ask => "ask",
    }
}
fn order_tier_label(tier: OrderTierV1) -> &'static str {
    match tier {
        OrderTierV1::Hot => "hot",
        OrderTierV1::Warm => "warm",
        OrderTierV1::Archive => "archive",
    }
}
fn order_cancel_reason_label(reason: OrderCancelReasonV1) -> &'static str {
    match reason {
        OrderCancelReasonV1::OwnerRequested => "owner_requested",
        OrderCancelReasonV1::Expired => "expired",
        OrderCancelReasonV1::Governance => "governance",
        OrderCancelReasonV1::Replaced => "replaced",
    }
}
fn settlement_channel_status_label(status: SettlementChannelStatusV1) -> &'static str {
    match status {
        SettlementChannelStatusV1::Open => "open",
        SettlementChannelStatusV1::Closing => "closing",
        SettlementChannelStatusV1::Closed => "closed",
        SettlementChannelStatusV1::Breached => "breached",
        SettlementChannelStatusV1::Refunded => "refunded",
    }
}
fn governance_payload_kind(payload: &GovernanceLogPayloadV1) -> &'static str {
    match payload {
        GovernanceLogPayloadV1::ProviderAdvert(_) => "provider_advert",
        GovernanceLogPayloadV1::ReplicationOrder(_) => "replication_order",
        GovernanceLogPayloadV1::PorProof(_) => "por_proof",
        GovernanceLogPayloadV1::PdpArchive(_) => "pdp_archive",
        GovernanceLogPayloadV1::AuditVerdict(_) => "audit_verdict",
        GovernanceLogPayloadV1::DealSettlement(_) => "deal_settlement",
        GovernanceLogPayloadV1::SignedReputationSnapshot(_) => "reputation_snapshot",
        GovernanceLogPayloadV1::ModerationBallotEvent(_) => "moderation_ballot_event",
        GovernanceLogPayloadV1::AppealFinanceReport(_) => "appeal_finance_report",
        GovernanceLogPayloadV1::AppealFinanceWeeklyRollup(_) => "appeal_finance_weekly_rollup",
        GovernanceLogPayloadV1::AppealFinanceSettlementReceipt(_) => {
            "appeal_finance_settlement_receipt"
        }
        GovernanceLogPayloadV1::OrderbookSettlementReceipt(_) => "orderbook_settlement_receipt",
        GovernanceLogPayloadV1::ExternalPayload(_) => "external_payload",
        GovernanceLogPayloadV1::PorChallengePublication(_) => "por_challenge_publication",
        GovernanceLogPayloadV1::PorWeeklyReport(_) => "por_weekly_report",
    }
}
fn governance_signature_algorithm_label(algorithm: GovernanceSignatureAlgorithm) -> &'static str {
    match algorithm {
        GovernanceSignatureAlgorithm::Ed25519 => "ed25519",
        GovernanceSignatureAlgorithm::Dilithium3 => "dilithium3",
    }
}
fn governance_log_validation_code(error: &GovernanceLogValidationError) -> &'static str {
    match error {
        GovernanceLogValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        GovernanceLogValidationError::InvalidSignature
        | GovernanceLogValidationError::InvalidSignaturePublicKeyLength { .. }
        | GovernanceLogValidationError::InvalidSignatureLength { .. } => "SFS-SIG-005",
        GovernanceLogValidationError::CidEncoding { .. } => "SFS-INT-001",
        GovernanceLogValidationError::InvalidNodeCid => "SFS-GOV-003",
        GovernanceLogValidationError::Advert(error) => advert_validation_code(error),
        GovernanceLogValidationError::ReplicationOrder(error) => {
            replication_order_validation_code(error)
        }
        GovernanceLogValidationError::PorProof(error) => por_proof_validation_code(error),
        GovernanceLogValidationError::PdpArchive(_)
        | GovernanceLogValidationError::PdpArchiveDecisionAfterNode { .. }
        | GovernanceLogValidationError::AuditVerdict(_)
        | GovernanceLogValidationError::DealSettlement(_)
        | GovernanceLogValidationError::SignedReputationSnapshot(_)
        | GovernanceLogValidationError::ModerationBallotEvent(_)
        | GovernanceLogValidationError::AppealFinanceReport(_)
        | GovernanceLogValidationError::AppealFinanceWeeklyRollup(_)
        | GovernanceLogValidationError::AppealFinanceSettlementReceipt(_)
        | GovernanceLogValidationError::OrderbookSettlementReceipt(_)
        | GovernanceLogValidationError::ExternalPayload(_)
        | GovernanceLogValidationError::PorChallengePublication(_)
        | GovernanceLogValidationError::PorWeeklyReport(_)
        | GovernanceLogValidationError::CanonicalPayloadLengthUnavailable
        | GovernanceLogValidationError::PayloadTooLarge { .. }
        | GovernanceLogValidationError::CanonicalNodeLengthUnavailable
        | GovernanceLogValidationError::NodeTooLarge { .. }
        | GovernanceLogValidationError::InvalidNodeCidLength { .. }
        | GovernanceLogValidationError::InvalidPrevCidLength { .. }
        | GovernanceLogValidationError::MissingPublisherPeerId
        | GovernanceLogValidationError::PublisherPeerIdTooLong { .. }
        | GovernanceLogValidationError::MissingSubmissionProvenance { .. }
        | GovernanceLogValidationError::UnexpectedSubmissionProvenance { .. }
        | GovernanceLogValidationError::SubmissionOriginMismatch { .. } => "SFS-GOV-001",
    }
}
fn governance_log_validation_category(error: &GovernanceLogValidationError) -> &'static str {
    match error {
        GovernanceLogValidationError::UnsupportedVersion { .. } => CATEGORY_VALIDATION,
        GovernanceLogValidationError::InvalidSignature
        | GovernanceLogValidationError::InvalidSignaturePublicKeyLength { .. }
        | GovernanceLogValidationError::InvalidSignatureLength { .. } => CATEGORY_SIGNATURE,
        GovernanceLogValidationError::CidEncoding { .. } => CATEGORY_INTERNAL,
        GovernanceLogValidationError::Advert(error) => advert_validation_category(error),
        GovernanceLogValidationError::ReplicationOrder(error) => {
            replication_order_validation_category(error)
        }
        GovernanceLogValidationError::PorProof(_) => CATEGORY_VALIDATION,
        GovernanceLogValidationError::PdpArchive(_)
        | GovernanceLogValidationError::PdpArchiveDecisionAfterNode { .. }
        | GovernanceLogValidationError::AuditVerdict(_)
        | GovernanceLogValidationError::DealSettlement(_)
        | GovernanceLogValidationError::SignedReputationSnapshot(_)
        | GovernanceLogValidationError::ModerationBallotEvent(_)
        | GovernanceLogValidationError::AppealFinanceReport(_)
        | GovernanceLogValidationError::AppealFinanceWeeklyRollup(_)
        | GovernanceLogValidationError::AppealFinanceSettlementReceipt(_)
        | GovernanceLogValidationError::OrderbookSettlementReceipt(_)
        | GovernanceLogValidationError::ExternalPayload(_)
        | GovernanceLogValidationError::PorChallengePublication(_)
        | GovernanceLogValidationError::PorWeeklyReport(_)
        | GovernanceLogValidationError::CanonicalPayloadLengthUnavailable
        | GovernanceLogValidationError::PayloadTooLarge { .. }
        | GovernanceLogValidationError::CanonicalNodeLengthUnavailable
        | GovernanceLogValidationError::NodeTooLarge { .. }
        | GovernanceLogValidationError::InvalidNodeCidLength { .. }
        | GovernanceLogValidationError::InvalidPrevCidLength { .. }
        | GovernanceLogValidationError::MissingPublisherPeerId
        | GovernanceLogValidationError::PublisherPeerIdTooLong { .. }
        | GovernanceLogValidationError::MissingSubmissionProvenance { .. }
        | GovernanceLogValidationError::UnexpectedSubmissionProvenance { .. }
        | GovernanceLogValidationError::SubmissionOriginMismatch { .. }
        | GovernanceLogValidationError::InvalidNodeCid => CATEGORY_VALIDATION,
    }
}
fn governance_signature_verification_code(
    error: &GovernanceLogSignatureVerificationError,
) -> &'static str {
    match error {
        GovernanceLogSignatureVerificationError::PayloadEncoding { .. } => "SFS-INT-001",
        GovernanceLogSignatureVerificationError::UnsupportedAlgorithm(_)
        | GovernanceLogSignatureVerificationError::InvalidPublicKeyLength { .. }
        | GovernanceLogSignatureVerificationError::InvalidSignatureLength { .. }
        | GovernanceLogSignatureVerificationError::InvalidPublicKey { .. }
        | GovernanceLogSignatureVerificationError::Verification { .. } => "SFS-SIG-005",
    }
}
fn governance_signature_verification_category(
    error: &GovernanceLogSignatureVerificationError,
) -> &'static str {
    match error {
        GovernanceLogSignatureVerificationError::PayloadEncoding { .. } => CATEGORY_INTERNAL,
        _ => CATEGORY_SIGNATURE,
    }
}
fn governance_dag_block_validation_code(error: &GovernanceDagBlockValidationError) -> &'static str {
    match error {
        GovernanceDagBlockValidationError::CanonicalLengthUnavailable
        | GovernanceDagBlockValidationError::BlockTooLarge { .. }
        | GovernanceDagBlockValidationError::UnsupportedVersion { .. }
        | GovernanceDagBlockValidationError::InvalidBlockCidLength { .. }
        | GovernanceDagBlockValidationError::InvalidPrevBlockCidLength { .. }
        | GovernanceDagBlockValidationError::RootHasParent
        | GovernanceDagBlockValidationError::NonRootMissingParent
        | GovernanceDagBlockValidationError::RootNodeHasParent
        | GovernanceDagBlockValidationError::NonRootNodeMissingParent
        | GovernanceDagBlockValidationError::MissingPublisherPeerId
        | GovernanceDagBlockValidationError::PublisherPeerIdTooLong { .. }
        | GovernanceDagBlockValidationError::NodeTimestampAfterBlock
        | GovernanceDagBlockValidationError::Node(_) => "SFS-GOV-005",
        GovernanceDagBlockValidationError::InvalidSignature
        | GovernanceDagBlockValidationError::NonEd25519BlockSignature
        | GovernanceDagBlockValidationError::NonEd25519NodeSignature
        | GovernanceDagBlockValidationError::NodePublisherPeerMismatch
        | GovernanceDagBlockValidationError::NodePublisherKeyMismatch
        | GovernanceDagBlockValidationError::NodeSignature(_)
        | GovernanceDagBlockValidationError::BlockSignature(_) => "SFS-SIG-006",
        GovernanceDagBlockValidationError::CidEncoding { .. } => "SFS-INT-001",
        GovernanceDagBlockValidationError::InvalidBlockCid => "SFS-GOV-004",
    }
}
fn governance_dag_block_validation_category(
    error: &GovernanceDagBlockValidationError,
) -> &'static str {
    match error {
        GovernanceDagBlockValidationError::InvalidSignature
        | GovernanceDagBlockValidationError::NonEd25519BlockSignature
        | GovernanceDagBlockValidationError::NonEd25519NodeSignature
        | GovernanceDagBlockValidationError::NodePublisherPeerMismatch
        | GovernanceDagBlockValidationError::NodePublisherKeyMismatch
        | GovernanceDagBlockValidationError::NodeSignature(_)
        | GovernanceDagBlockValidationError::BlockSignature(_) => CATEGORY_SIGNATURE,
        GovernanceDagBlockValidationError::CidEncoding { .. } => CATEGORY_INTERNAL,
        _ => CATEGORY_VALIDATION,
    }
}
fn governance_dag_head_validation_code(error: &GovernanceDagHeadValidationError) -> &'static str {
    match error {
        GovernanceDagHeadValidationError::UnsupportedVersion { .. }
        | GovernanceDagHeadValidationError::InvalidHeadBlockCidLength { .. }
        | GovernanceDagHeadValidationError::EmptyBlockCount
        | GovernanceDagHeadValidationError::MissingGeneratedAt
        | GovernanceDagHeadValidationError::MissingPublisherPeerId
        | GovernanceDagHeadValidationError::PublisherPeerIdTooLong { .. }
        | GovernanceDagHeadValidationError::InvalidCheckpointCidLength { .. } => "SFS-GOV-007",
        GovernanceDagHeadValidationError::NonEd25519HeadSignature
        | GovernanceDagHeadValidationError::InvalidSignature
        | GovernanceDagHeadValidationError::HeadSignature(_) => "SFS-SIG-007",
    }
}
fn governance_dag_head_validation_category(
    error: &GovernanceDagHeadValidationError,
) -> &'static str {
    match error {
        GovernanceDagHeadValidationError::NonEd25519HeadSignature
        | GovernanceDagHeadValidationError::InvalidSignature
        | GovernanceDagHeadValidationError::HeadSignature(_) => CATEGORY_SIGNATURE,
        _ => CATEGORY_VALIDATION,
    }
}
fn governance_dag_chain_validation_code(error: &GovernanceDagChainValidationError) -> &'static str {
    match error {
        GovernanceDagChainValidationError::InvalidBlock { source, .. } => {
            governance_dag_block_validation_code(source)
        }
        GovernanceDagChainValidationError::Empty
        | GovernanceDagChainValidationError::DuplicateBlockCid { .. }
        | GovernanceDagChainValidationError::DuplicateNodeCid { .. }
        | GovernanceDagChainValidationError::SequenceGap { .. }
        | GovernanceDagChainValidationError::SequenceOverflow { .. }
        | GovernanceDagChainValidationError::TimestampRegression { .. }
        | GovernanceDagChainValidationError::NodeTimestampRegression { .. }
        | GovernanceDagChainValidationError::NonCanonicalOrder { .. }
        | GovernanceDagChainValidationError::NodeParentMismatch { .. }
        | GovernanceDagChainValidationError::ExpectedHeadMismatch => "SFS-GOV-006",
        GovernanceDagChainValidationError::PublisherPeerMismatch { .. }
        | GovernanceDagChainValidationError::PublisherKeyMismatch { .. } => "SFS-SIG-006",
    }
}
fn governance_dag_chain_validation_category(
    error: &GovernanceDagChainValidationError,
) -> &'static str {
    match error {
        GovernanceDagChainValidationError::InvalidBlock { source, .. } => {
            governance_dag_block_validation_category(source)
        }
        GovernanceDagChainValidationError::PublisherPeerMismatch { .. }
        | GovernanceDagChainValidationError::PublisherKeyMismatch { .. } => CATEGORY_SIGNATURE,
        _ => CATEGORY_VALIDATION,
    }
}
fn governance_dag_head_chain_validation_code(
    error: &GovernanceDagHeadChainValidationError,
) -> &'static str {
    match error {
        GovernanceDagHeadChainValidationError::Head(error) => {
            governance_dag_head_validation_code(error)
        }
        GovernanceDagHeadChainValidationError::Chain(error) => {
            governance_dag_chain_validation_code(error)
        }
        GovernanceDagHeadChainValidationError::PublisherPeerMismatch
        | GovernanceDagHeadChainValidationError::PublisherKeyMismatch => "SFS-SIG-007",
        GovernanceDagHeadChainValidationError::BlockCountMismatch { .. }
        | GovernanceDagHeadChainValidationError::BlockCountOverflow
        | GovernanceDagHeadChainValidationError::UnexpectedCheckpoint
        | GovernanceDagHeadChainValidationError::MissingCheckpoint
        | GovernanceDagHeadChainValidationError::CheckpointMismatch
        | GovernanceDagHeadChainValidationError::CheckpointWindowLength { .. }
        | GovernanceDagHeadChainValidationError::InvalidCheckpointBlockCount { .. }
        | GovernanceDagHeadChainValidationError::CheckpointStartSequence { .. }
        | GovernanceDagHeadChainValidationError::HeadTimestampBeforeTip { .. } => "SFS-GOV-008",
    }
}
fn governance_dag_head_chain_validation_category(
    error: &GovernanceDagHeadChainValidationError,
) -> &'static str {
    match error {
        GovernanceDagHeadChainValidationError::Head(error) => {
            governance_dag_head_validation_category(error)
        }
        GovernanceDagHeadChainValidationError::Chain(error) => {
            governance_dag_chain_validation_category(error)
        }
        GovernanceDagHeadChainValidationError::PublisherPeerMismatch
        | GovernanceDagHeadChainValidationError::PublisherKeyMismatch => CATEGORY_SIGNATURE,
        GovernanceDagHeadChainValidationError::BlockCountMismatch { .. }
        | GovernanceDagHeadChainValidationError::BlockCountOverflow
        | GovernanceDagHeadChainValidationError::UnexpectedCheckpoint
        | GovernanceDagHeadChainValidationError::MissingCheckpoint
        | GovernanceDagHeadChainValidationError::CheckpointMismatch
        | GovernanceDagHeadChainValidationError::CheckpointWindowLength { .. }
        | GovernanceDagHeadChainValidationError::InvalidCheckpointBlockCount { .. }
        | GovernanceDagHeadChainValidationError::CheckpointStartSequence { .. }
        | GovernanceDagHeadChainValidationError::HeadTimestampBeforeTip { .. } => {
            CATEGORY_VALIDATION
        }
    }
}
/// Repair payload kinds supported by the reference validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairValidationPayloadKindV1 {
    /// [`RepairEvidenceV1`] payload.
    Evidence,
    /// [`RepairReportV1`] payload.
    Report,
    /// [`RepairTaskRecordV1`] payload.
    TaskRecord,
    /// [`RepairSlashProposalV1`] payload.
    SlashProposal,
    /// [`RepairEscalationPolicyV1`] payload.
    EscalationPolicy,
    /// [`RepairEscalationApprovalV1`] payload.
    EscalationApproval,
    /// [`RepairTaskEventV1`] payload.
    TaskEvent,
    /// [`RepairAuditEventV1`] payload.
    AuditEvent,
}
impl RepairValidationPayloadKindV1 {
    fn input_kind(self) -> &'static str {
        match self {
            Self::Evidence => "repair_evidence",
            Self::Report => "repair_report",
            Self::TaskRecord => "repair_task_record",
            Self::SlashProposal => "repair_slash_proposal",
            Self::EscalationPolicy => "repair_escalation_policy",
            Self::EscalationApproval => "repair_escalation_approval",
            Self::TaskEvent => "repair_task_event",
            Self::AuditEvent => "repair_audit_event",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::Evidence => "RepairEvidenceV1",
            Self::Report => "RepairReportV1",
            Self::TaskRecord => "RepairTaskRecordV1",
            Self::SlashProposal => "RepairSlashProposalV1",
            Self::EscalationPolicy => "RepairEscalationPolicyV1",
            Self::EscalationApproval => "RepairEscalationApprovalV1",
            Self::TaskEvent => "RepairTaskEventV1",
            Self::AuditEvent => "RepairAuditEventV1",
        }
    }
    fn success_message(self) -> &'static str {
        match self {
            Self::Evidence => "repair evidence accepted",
            Self::Report => "repair report accepted",
            Self::TaskRecord => "repair task record accepted",
            Self::SlashProposal => "repair slash proposal accepted",
            Self::EscalationPolicy => "repair escalation policy accepted",
            Self::EscalationApproval => "repair escalation approval accepted",
            Self::TaskEvent => "repair task event accepted",
            Self::AuditEvent => "repair audit event accepted",
        }
    }
}
/// Orderbook payload kinds supported by the reference validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderbookValidationPayloadKindV1 {
    /// [`OrderRequestV1`] payload.
    OrderRequest,
    /// [`OrderCancelV1`] payload.
    OrderCancel,
    /// [`TradeEventV1`] payload.
    TradeEvent,
    /// [`SettlementChannelV1`] payload.
    SettlementChannel,
    /// [`SettlementReceiptV1`] payload.
    SettlementReceipt,
}
impl OrderbookValidationPayloadKindV1 {
    fn input_kind(self) -> &'static str {
        match self {
            Self::OrderRequest => "orderbook_order_request",
            Self::OrderCancel => "orderbook_order_cancel",
            Self::TradeEvent => "orderbook_trade_event",
            Self::SettlementChannel => "settlement_channel",
            Self::SettlementReceipt => "settlement_receipt",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::OrderRequest => "OrderRequestV1",
            Self::OrderCancel => "OrderCancelV1",
            Self::TradeEvent => "TradeEventV1",
            Self::SettlementChannel => "SettlementChannelV1",
            Self::SettlementReceipt => "SettlementReceiptV1",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::OrderRequest => "order_request",
            Self::OrderCancel => "order_cancel",
            Self::TradeEvent => "trade_event",
            Self::SettlementChannel => "settlement_channel",
            Self::SettlementReceipt => "settlement_receipt",
        }
    }
    fn success_message(self) -> &'static str {
        match self {
            Self::OrderRequest => "orderbook order request accepted",
            Self::OrderCancel => "orderbook cancel request accepted",
            Self::TradeEvent => "orderbook trade event accepted",
            Self::SettlementChannel => "settlement channel accepted",
            Self::SettlementReceipt => "settlement receipt accepted",
        }
    }
}
/// PoP credential payload kinds supported by the reference validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopValidationPayloadKindV1 {
    /// [`PopCredentialV1`] payload with issuer signature verification.
    Credential,
    /// [`PopCommitmentRootV1`] payload with publisher signature verification.
    CommitmentRoot,
    /// [`PopRevocationListV1`] payload with publisher signature verification.
    RevocationList,
    /// [`PopIssuedCredentialBundleV1`] payload with issuer publication verification.
    IssuedCredentialBundle,
    /// [`PopEnrollmentRequestV1`] payload.
    EnrollmentRequest,
    /// [`PopRenewalRequestV1`] payload.
    RenewalRequest,
    /// [`PopMembershipProofV1`] payload.
    MembershipProof,
}
impl PopValidationPayloadKindV1 {
    fn input_kind(self) -> &'static str {
        match self {
            Self::Credential => "pop_credential",
            Self::CommitmentRoot => "pop_commitment_root",
            Self::RevocationList => "pop_revocation_list",
            Self::IssuedCredentialBundle => "pop_issued_credential_bundle",
            Self::EnrollmentRequest => "pop_enrollment_request",
            Self::RenewalRequest => "pop_renewal_request",
            Self::MembershipProof => "pop_membership_proof",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::Credential => "PopCredentialV1",
            Self::CommitmentRoot => "PopCommitmentRootV1",
            Self::RevocationList => "PopRevocationListV1",
            Self::IssuedCredentialBundle => "PopIssuedCredentialBundleV1",
            Self::EnrollmentRequest => "PopEnrollmentRequestV1",
            Self::RenewalRequest => "PopRenewalRequestV1",
            Self::MembershipProof => "PopMembershipProofV1",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::CommitmentRoot => "commitment_root",
            Self::RevocationList => "revocation_list",
            Self::IssuedCredentialBundle => "issued_credential_bundle",
            Self::EnrollmentRequest => "enrollment_request",
            Self::RenewalRequest => "renewal_request",
            Self::MembershipProof => "membership_proof",
        }
    }
    fn success_message(self) -> &'static str {
        match self {
            Self::Credential => "PoP credential accepted",
            Self::CommitmentRoot => "PoP commitment root accepted",
            Self::RevocationList => "PoP revocation list accepted",
            Self::IssuedCredentialBundle => "PoP issued credential bundle accepted",
            Self::EnrollmentRequest => "PoP enrollment request accepted",
            Self::RenewalRequest => "PoP renewal request accepted",
            Self::MembershipProof => "PoP membership proof accepted",
        }
    }
}
/// SoraFS hedging and billing payload kinds supported by the reference validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HedgingValidationPayloadKindV1 {
    /// [`HedgingPriceFeedV1`] payload.
    PriceFeed,
    /// [`HedgingReferencePriceDecisionV1`] payload.
    ReferencePriceDecision,
    /// [`BillingLineItemV1`] payload.
    BillingLineItem,
    /// [`BillingStatementV1`] payload.
    BillingStatement,
}
impl HedgingValidationPayloadKindV1 {
    fn input_kind(self) -> &'static str {
        match self {
            Self::PriceFeed => "hedging_price_feed",
            Self::ReferencePriceDecision => "hedging_reference_price_decision",
            Self::BillingLineItem => "billing_line_item",
            Self::BillingStatement => "billing_statement",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::PriceFeed => "HedgingPriceFeedV1",
            Self::ReferencePriceDecision => "HedgingReferencePriceDecisionV1",
            Self::BillingLineItem => "BillingLineItemV1",
            Self::BillingStatement => "BillingStatementV1",
        }
    }
    fn tag(self) -> &'static str {
        match self {
            Self::PriceFeed => "price_feed",
            Self::ReferencePriceDecision => "reference_price_decision",
            Self::BillingLineItem => "billing_line_item",
            Self::BillingStatement => "billing_statement",
        }
    }
    fn success_message(self) -> &'static str {
        match self {
            Self::PriceFeed => "hedging price feed accepted",
            Self::ReferencePriceDecision => "hedging reference-price decision accepted",
            Self::BillingLineItem => "billing line item accepted",
            Self::BillingStatement => "billing statement accepted",
        }
    }
}
/// Validates a Norito-encoded orderbook payload and emits a reference outcome.
#[must_use]
pub fn validate_orderbook_payload_bytes(
    kind: OrderbookValidationPayloadKindV1,
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input_label = input_label.into();
    let inputs = vec![ValidationInputV1::new(
        kind.input_kind(),
        input_label.clone(),
    )];
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => match decode_order_request_v1(bytes) {
            Ok(payload) => validate_orderbook_payload_value(
                kind,
                verify_order_request_signature_v1(&payload),
                order_request_context(&payload),
                inputs,
                generated_at,
            ),
            Err(error) => orderbook_decode_error(kind, error.to_string(), inputs, generated_at),
        },
        OrderbookValidationPayloadKindV1::OrderCancel => match decode_order_cancel_v1(bytes) {
            Ok(payload) => validate_orderbook_payload_value(
                kind,
                verify_order_cancel_signature_v1(&payload),
                order_cancel_context(&payload),
                inputs,
                generated_at,
            ),
            Err(error) => orderbook_decode_error(kind, error.to_string(), inputs, generated_at),
        },
        OrderbookValidationPayloadKindV1::TradeEvent => match decode_trade_event_v1(bytes) {
            Ok(payload) => validate_orderbook_payload_value(
                kind,
                payload.validate(),
                trade_event_context(&payload),
                inputs,
                generated_at,
            ),
            Err(error) => orderbook_decode_error(kind, error.to_string(), inputs, generated_at),
        },
        OrderbookValidationPayloadKindV1::SettlementChannel => {
            match decode_settlement_channel_v1(bytes) {
                Ok(payload) => validate_orderbook_payload_value(
                    kind,
                    payload.validate(),
                    settlement_channel_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => orderbook_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        OrderbookValidationPayloadKindV1::SettlementReceipt => {
            match decode_settlement_receipt_v1(bytes) {
                Ok(payload) => validate_orderbook_payload_value(
                    kind,
                    verify_settlement_receipt_signature_v1(&payload),
                    settlement_receipt_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => orderbook_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
    }
}
/// Validates a Norito-encoded SoraFS hedging/billing payload and emits a reference outcome.
#[must_use]
pub fn validate_hedging_payload_bytes(
    kind: HedgingValidationPayloadKindV1,
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input_label = input_label.into();
    let inputs = vec![ValidationInputV1::new(
        kind.input_kind(),
        input_label.clone(),
    )];
    match kind {
        HedgingValidationPayloadKindV1::PriceFeed => match decode_hedging_price_feed_v1(bytes) {
            Ok(payload) => validate_hedging_payload_value(
                kind,
                payload.validate(),
                hedging_price_feed_context(&payload),
                inputs,
                generated_at,
            ),
            Err(error) => hedging_decode_error(kind, error.to_string(), inputs, generated_at),
        },
        HedgingValidationPayloadKindV1::ReferencePriceDecision => {
            match decode_hedging_reference_price_decision_v1(bytes) {
                Ok(payload) => validate_hedging_payload_value(
                    kind,
                    payload.validate(),
                    hedging_reference_price_decision_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => hedging_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        HedgingValidationPayloadKindV1::BillingLineItem => {
            match decode_billing_line_item_v1(bytes) {
                Ok(payload) => validate_hedging_payload_value(
                    kind,
                    payload.validate(),
                    billing_line_item_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => hedging_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        HedgingValidationPayloadKindV1::BillingStatement => {
            match decode_billing_statement_v1(bytes) {
                Ok(payload) => validate_hedging_payload_value(
                    kind,
                    payload.validate(),
                    billing_statement_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => hedging_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
    }
}
/// Error returned while signing already-encoded orderbook payload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OrderbookPayloadSigningError {
    /// Ed25519 signing key material has the wrong length.
    #[error("Ed25519 signing key must be 32 bytes, got {length}")]
    InvalidSigningKeyLength {
        /// Observed signing-key byte length.
        length: usize,
    },
    /// Ed25519 signing key material is all zero.
    #[error("Ed25519 signing key material must not be all zero")]
    InvalidSigningKeyMaterial,
    /// Payload kind is not a user-signed orderbook input.
    #[error("orderbook payload kind {kind:?} cannot be signed")]
    UnsupportedPayloadKind {
        /// Unsupported payload kind.
        kind: OrderbookValidationPayloadKindV1,
    },
    /// Norito payload decoding failed.
    #[error("failed to decode {schema}: {reason}")]
    Decode {
        /// Expected payload schema.
        schema: &'static str,
        /// Decode failure reason.
        reason: String,
    },
    /// Payload signing failed.
    #[error("failed to sign {schema}: {reason}")]
    Sign {
        /// Expected payload schema.
        schema: &'static str,
        /// Signing failure reason.
        reason: String,
    },
    /// Signed Norito payload encoding failed.
    #[error("failed to encode signed {schema}: {reason}")]
    Encode {
        /// Expected payload schema.
        schema: &'static str,
        /// Encode failure reason.
        reason: String,
    },
}
/// Field-level input for building a signed [`OrderRequestV1`] payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderbookOrderRequestFieldsV1 {
    /// Bid or ask.
    pub side: OrderSideV1,
    /// Storage tier priced by the order.
    pub tier: OrderTierV1,
    /// Exact XOR price per GiB.
    pub price_per_gib: XorQuantity,
    /// Total GiB requested/offered.
    pub quantity_gib: u64,
    /// Remaining GiB after partial fills.
    pub remaining_gib: u64,
    /// Canonical owner account bytes.
    pub owner_account: Vec<u8>,
    /// Exact provider registry identity for asks; absent for bids.
    pub provider_id: Option<[u8; 32]>,
    /// Unix timestamp (seconds) after which the order expires.
    pub expiry_unix: u64,
    /// Owner nonce used to prevent replay.
    pub nonce: u64,
    /// Maker fee in basis points.
    pub maker_fee_bps: u16,
    /// Taker fee in basis points.
    pub taker_fee_bps: u16,
}
/// Field-level input for building a signed [`OrderCancelV1`] payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderbookOrderCancelFieldsV1 {
    /// Order being cancelled.
    pub order_id: [u8; 32],
    /// Canonical owner account bytes.
    pub owner_account: Vec<u8>,
    /// Cancellation reason.
    pub reason: OrderCancelReasonV1,
    /// Owner nonce used to prevent replay.
    pub nonce: u64,
}
/// Field-level input for building a signed [`SettlementReceiptV1`] payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderbookSettlementReceiptFieldsV1 {
    /// Unique receipt identifier.
    pub receipt_id: [u8; 32],
    /// Channel being settled.
    pub channel_id: [u8; 32],
    /// Trade associated with the channel.
    pub trade_id: [u8; 32],
    /// Delivered range start offset, inclusive.
    pub range_start: u64,
    /// Delivered range end offset, exclusive.
    pub range_end: u64,
    /// Chunk/content digest for the delivered range.
    pub chunk_hash: [u8; 32],
    /// Delivered byte count.
    pub bytes_delivered: u64,
    /// Exact XOR debited from buyer escrow.
    pub xor_debited: XorQuantity,
    /// Exact XOR credited to the provider.
    pub provider_credit: XorQuantity,
    /// Exact XOR retained as fee.
    pub fee_amount: XorQuantity,
    /// Unix timestamp (seconds) when the receipt was issued.
    pub issued_at_unix: u64,
}
fn empty_sdk_orderbook_signature() -> OrderbookSignatureV1 {
    OrderbookSignatureV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: Vec::new(),
        signature: Vec::new(),
    }
}
fn encode_signed_orderbook_builder_payload<T: norito::core::NoritoSerialize>(
    schema: &'static str,
    value: &T,
) -> Result<Vec<u8>, OrderbookPayloadSigningError> {
    encode_signed_orderbook_payload(schema, value)
}
/// Build, sign, validate, and encode a field-level order request payload.
pub fn build_signed_orderbook_order_request_bytes_ed25519_v1(
    fields: OrderbookOrderRequestFieldsV1,
    signing_key_bytes: &[u8],
) -> Result<Vec<u8>, OrderbookPayloadSigningError> {
    let schema = OrderbookValidationPayloadKindV1::OrderRequest.schema();
    crate::orderbook::validate_owner_account_v1(&fields.owner_account).map_err(|err| {
        OrderbookPayloadSigningError::Sign {
            schema,
            reason: err.to_string(),
        }
    })?;
    let signing_key = orderbook_signing_key_from_bytes(signing_key_bytes)?;
    let order_id = crate::derive_orderbook_order_id_v1(&fields.owner_account, fields.nonce);
    let payload = OrderRequestV1 {
        version: ORDERBOOK_ORDER_VERSION_V1,
        order_id,
        side: fields.side,
        tier: fields.tier,
        price_per_gib: fields.price_per_gib,
        quantity_gib: fields.quantity_gib,
        remaining_gib: fields.remaining_gib,
        owner_account: fields.owner_account,
        provider_id: fields.provider_id,
        expiry_unix: fields.expiry_unix,
        nonce: fields.nonce,
        maker_fee_bps: fields.maker_fee_bps,
        taker_fee_bps: fields.taker_fee_bps,
        signature: empty_sdk_orderbook_signature(),
    };
    let signed = sign_order_request_ed25519_v1(payload, &signing_key).map_err(|err| {
        OrderbookPayloadSigningError::Sign {
            schema,
            reason: err.to_string(),
        }
    })?;
    encode_signed_orderbook_builder_payload(schema, &signed)
}
/// Build, sign, validate, and encode a field-level order-cancel payload.
pub fn build_signed_orderbook_order_cancel_bytes_ed25519_v1(
    fields: OrderbookOrderCancelFieldsV1,
    signing_key_bytes: &[u8],
) -> Result<Vec<u8>, OrderbookPayloadSigningError> {
    let schema = OrderbookValidationPayloadKindV1::OrderCancel.schema();
    crate::orderbook::validate_owner_account_v1(&fields.owner_account).map_err(|err| {
        OrderbookPayloadSigningError::Sign {
            schema,
            reason: err.to_string(),
        }
    })?;
    let signing_key = orderbook_signing_key_from_bytes(signing_key_bytes)?;
    let payload = OrderCancelV1 {
        version: ORDERBOOK_CANCEL_VERSION_V1,
        order_id: fields.order_id,
        owner_account: fields.owner_account,
        reason: fields.reason,
        nonce: fields.nonce,
        signature: empty_sdk_orderbook_signature(),
    };
    let signed = sign_order_cancel_ed25519_v1(payload, &signing_key).map_err(|err| {
        OrderbookPayloadSigningError::Sign {
            schema,
            reason: err.to_string(),
        }
    })?;
    encode_signed_orderbook_builder_payload(schema, &signed)
}
/// Build, sign, validate, and encode a field-level settlement receipt payload.
pub fn build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(
    fields: OrderbookSettlementReceiptFieldsV1,
    signing_key_bytes: &[u8],
) -> Result<Vec<u8>, OrderbookPayloadSigningError> {
    let signing_key = orderbook_signing_key_from_bytes(signing_key_bytes)?;
    let payload = SettlementReceiptV1 {
        version: SETTLEMENT_RECEIPT_VERSION_V1,
        receipt_id: fields.receipt_id,
        channel_id: fields.channel_id,
        trade_id: fields.trade_id,
        range: ByteRangeV1 {
            start: fields.range_start,
            end: fields.range_end,
        },
        chunk_hash: fields.chunk_hash,
        bytes_delivered: fields.bytes_delivered,
        xor_debited: fields.xor_debited,
        provider_credit: fields.provider_credit,
        fee_amount: fields.fee_amount,
        issued_at_unix: fields.issued_at_unix,
        settlement_signature: empty_sdk_orderbook_signature(),
    };
    let schema = OrderbookValidationPayloadKindV1::SettlementReceipt.schema();
    let signed = sign_settlement_receipt_ed25519_v1(payload, &signing_key).map_err(|err| {
        OrderbookPayloadSigningError::Sign {
            schema,
            reason: err.to_string(),
        }
    })?;
    encode_signed_orderbook_builder_payload(schema, &signed)
}
/// Signs an already-encoded mutable orderbook payload and returns signed Norito bytes.
///
/// This helper accepts `OrderRequestV1`, `OrderCancelV1`, and `SettlementReceiptV1` payloads.
/// Runtime-generated trade events, settlement channels are intentionally not accepted because they
/// are not directly signed by SDK users.
pub fn sign_orderbook_payload_bytes_ed25519_v1(
    kind: OrderbookValidationPayloadKindV1,
    bytes: &[u8],
    signing_key_bytes: &[u8],
) -> Result<Vec<u8>, OrderbookPayloadSigningError> {
    let signing_key = orderbook_signing_key_from_bytes(signing_key_bytes)?;
    match kind {
        OrderbookValidationPayloadKindV1::OrderRequest => {
            let schema = kind.schema();
            let payload = decode_order_request_v1(bytes).map_err(|err| {
                OrderbookPayloadSigningError::Decode {
                    schema,
                    reason: err.to_string(),
                }
            })?;
            let signed = sign_order_request_ed25519_v1(payload, &signing_key).map_err(|err| {
                OrderbookPayloadSigningError::Sign {
                    schema,
                    reason: err.to_string(),
                }
            })?;
            encode_signed_orderbook_payload(schema, &signed)
        }
        OrderbookValidationPayloadKindV1::OrderCancel => {
            let schema = kind.schema();
            let payload = decode_order_cancel_v1(bytes).map_err(|err| {
                OrderbookPayloadSigningError::Decode {
                    schema,
                    reason: err.to_string(),
                }
            })?;
            let signed = sign_order_cancel_ed25519_v1(payload, &signing_key).map_err(|err| {
                OrderbookPayloadSigningError::Sign {
                    schema,
                    reason: err.to_string(),
                }
            })?;
            encode_signed_orderbook_payload(schema, &signed)
        }
        OrderbookValidationPayloadKindV1::SettlementReceipt => {
            let schema = kind.schema();
            let payload = decode_settlement_receipt_v1(bytes).map_err(|err| {
                OrderbookPayloadSigningError::Decode {
                    schema,
                    reason: err.to_string(),
                }
            })?;
            let signed =
                sign_settlement_receipt_ed25519_v1(payload, &signing_key).map_err(|err| {
                    OrderbookPayloadSigningError::Sign {
                        schema,
                        reason: err.to_string(),
                    }
                })?;
            encode_signed_orderbook_payload(schema, &signed)
        }
        other => Err(OrderbookPayloadSigningError::UnsupportedPayloadKind { kind: other }),
    }
}
fn orderbook_signing_key_from_bytes(
    bytes: &[u8],
) -> Result<SigningKey, OrderbookPayloadSigningError> {
    if bytes.len() != 32 {
        return Err(OrderbookPayloadSigningError::InvalidSigningKeyLength {
            length: bytes.len(),
        });
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(OrderbookPayloadSigningError::InvalidSigningKeyMaterial);
    }
    let mut signing_key = [0u8; 32];
    signing_key.copy_from_slice(bytes);
    Ok(SigningKey::from_bytes(&signing_key))
}
fn encode_signed_orderbook_payload<T>(
    schema: &'static str,
    payload: &T,
) -> Result<Vec<u8>, OrderbookPayloadSigningError>
where
    T: norito::core::NoritoSerialize,
{
    norito::encode_canonical(payload).map_err(|err| OrderbookPayloadSigningError::Encode {
        schema,
        reason: err.to_string(),
    })
}
fn validate_orderbook_payload_value(
    kind: OrderbookValidationPayloadKindV1,
    result: Result<(), OrderbookValidationError>,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    if let Err(error) = result {
        let code = orderbook_validation_code(&error);
        let category = orderbook_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("{} validation failed: {error}", kind.schema()),
            "Regenerate the orderbook payload from canonical orderbook or settlement state and retry validation.",
            vec![
                "sorafs.reference.orderbook".to_owned(),
                format!("sorafs.reference.orderbook.{}", kind.tag()),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        kind.success_message(),
        vec![
            "sorafs.reference.orderbook".to_owned(),
            format!("sorafs.reference.orderbook.{}", kind.tag()),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn orderbook_decode_error(
    kind: OrderbookValidationPayloadKindV1,
    error: String,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    ValidationOutcomeV1::error(
        "SFS-NORITO-001",
        CATEGORY_NORITO,
        format!("failed to decode {} Norito payload: {error}", kind.schema()),
        "Re-encode the orderbook payload with the canonical SoraFS Norito schema.",
        vec![
            "sorafs.reference.orderbook".to_owned(),
            format!("sorafs.reference.orderbook.{}", kind.tag()),
            "sorafs.reference.code.SFS-NORITO-001".to_owned(),
        ],
        vec![ValidationContextFieldV1::new("schema", kind.schema())],
        inputs,
        generated_at,
    )
}
fn validate_hedging_payload_value(
    kind: HedgingValidationPayloadKindV1,
    result: Result<(), HedgingValidationError>,
    context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    if let Err(error) = result {
        return hedging_validation_error_outcome(kind, error, context, inputs, generated_at);
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        kind.success_message(),
        vec![
            "sorafs.reference.hedging".to_owned(),
            format!("sorafs.reference.hedging.{}", kind.tag()),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn hedging_decode_error(
    kind: HedgingValidationPayloadKindV1,
    error: String,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    ValidationOutcomeV1::error(
        "SFS-NORITO-001",
        CATEGORY_NORITO,
        format!("failed to decode {} Norito payload: {error}", kind.schema()),
        "Re-encode the hedging or billing payload with the canonical SoraFS Norito schema.",
        vec![
            "sorafs.reference.hedging".to_owned(),
            format!("sorafs.reference.hedging.{}", kind.tag()),
            "sorafs.reference.code.SFS-NORITO-001".to_owned(),
        ],
        vec![ValidationContextFieldV1::new("schema", kind.schema())],
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded PoP credential payload and emits a reference outcome.
///
/// Membership-proof validation checks canonical wire shape and bounded metadata,
/// including the required presentation binding. It does not verify the PIPA-R
/// transcript, authenticate a recipient, or consume a replay nullifier.
#[must_use]
pub fn validate_pop_payload_bytes(
    kind: PopValidationPayloadKindV1,
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new(kind.input_kind(), input_label);
    let inputs = vec![input];
    match kind {
        PopValidationPayloadKindV1::Credential => {
            match decode_pop_reference_payload::<PopCredentialV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    verify_pop_credential_signature_v1(&payload),
                    pop_credential_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::CommitmentRoot => {
            match decode_pop_reference_payload::<PopCommitmentRootV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    verify_pop_commitment_root_signature_v1(&payload),
                    pop_commitment_root_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::RevocationList => {
            match decode_pop_reference_payload::<PopRevocationListV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    verify_pop_revocation_list_signature_v1(&payload),
                    pop_revocation_list_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::IssuedCredentialBundle => {
            match decode_pop_reference_payload::<PopIssuedCredentialBundleV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    payload.validate(),
                    pop_issued_credential_bundle_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::EnrollmentRequest => {
            match decode_pop_reference_payload::<PopEnrollmentRequestV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    payload.validate(),
                    pop_enrollment_request_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::RenewalRequest => {
            match decode_pop_reference_payload::<PopRenewalRequestV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    payload.validate(),
                    pop_renewal_request_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
        PopValidationPayloadKindV1::MembershipProof => {
            match decode_pop_reference_payload::<PopMembershipProofV1>(bytes) {
                Ok(payload) => validate_pop_payload_value(
                    kind,
                    payload.validate(),
                    pop_membership_proof_context(&payload),
                    inputs,
                    generated_at,
                ),
                Err(error) => pop_decode_error(kind, error.to_string(), inputs, generated_at),
            }
        }
    }
}
fn decode_pop_reference_payload<T>(bytes: &[u8]) -> Result<T, String>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > POP_REFERENCE_PAYLOAD_MAX_BYTES_V1 {
        return Err(format!(
            "PoP payload exceeds {} byte reference-validator limit",
            POP_REFERENCE_PAYLOAD_MAX_BYTES_V1
        ));
    }
    let limits = norito::DecodeLimits::new(
        POP_REFERENCE_PAYLOAD_MAX_BYTES_V1,
        POP_REFERENCE_PAYLOAD_MAX_BYTES_V1,
        POP_REFERENCE_PAYLOAD_MAX_BYTES_V1.saturating_mul(2),
        POP_REFERENCE_PAYLOAD_MAX_BYTES_V1.saturating_mul(4),
        64,
    );
    norito::decode_canonical_with_limits(bytes, limits).map_err(|error| {
        if matches!(error, norito::Error::NonCanonicalEncoding) {
            "PoP payload is not the canonical Norito encoding".to_owned()
        } else {
            error.to_string()
        }
    })
}
fn validate_pop_payload_value(
    kind: PopValidationPayloadKindV1,
    result: Result<(), PopCredentialValidationError>,
    context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    if let Err(error) = result {
        return pop_validation_error_outcome(kind, error, context, inputs, generated_at);
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        kind.success_message(),
        vec![
            "sorafs.reference.pop".to_owned(),
            format!("sorafs.reference.pop.{}", kind.tag()),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn pop_decode_error(
    kind: PopValidationPayloadKindV1,
    error: String,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    ValidationOutcomeV1::error(
        "SFS-NORITO-001",
        CATEGORY_NORITO,
        format!("failed to decode {} Norito payload: {error}", kind.schema()),
        "Re-encode the PoP payload with the canonical SoraFS Norito schema.",
        vec![
            "sorafs.reference.pop".to_owned(),
            format!("sorafs.reference.pop.{}", kind.tag()),
            "sorafs.reference.code.SFS-NORITO-001".to_owned(),
        ],
        vec![ValidationContextFieldV1::new("schema", kind.schema())],
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`ProviderAdvertV1`] and emits a reference outcome.
#[must_use]
pub fn validate_provider_advert_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    now: u64,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new("provider_advert", input_label);
    let inputs = vec![input];
    let advert = match decode_provider_advert_v1(bytes) {
        Ok(advert) => advert,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ProviderAdvertV1 Norito payload: {error}"),
                "Re-encode the provider advert with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.advert".to_owned()],
                vec![ValidationContextFieldV1::new("schema", "ProviderAdvertV1")],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = advert_context(&advert);
    if let Err(error) = advert.validate_with_body(now) {
        let code = advert_validation_code(&error);
        let category = advert_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("provider advert validation failed: {error}"),
            "Regenerate the advert from governed provider metadata and retry validation.",
            vec![
                "sorafs.reference.advert".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = advert.verify_signature() {
        context.push(ValidationContextFieldV1::new(
            "signature_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-SIG-001",
            CATEGORY_SIGNATURE,
            format!("provider advert signature validation failed: {error}"),
            "Resign the canonical advert envelope with the governed provider Ed25519 key.",
            vec![
                "sorafs.reference.advert".to_owned(),
                "sorafs.reference.code.SFS-SIG-001".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "provider advert accepted",
        vec![
            "sorafs.reference.advert".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded repair payload and emits a reference outcome.
#[must_use]
pub fn validate_repair_payload_bytes(
    kind: RepairValidationPayloadKindV1,
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new(kind.input_kind(), input_label);
    let inputs = vec![input];
    macro_rules! decode_repair_payload {
        ($payload_type:ty) => {
            match decode_reference_frame::<$payload_type>(bytes) {
                Ok(payload) => payload,
                Err(error) => {
                    return ValidationOutcomeV1::error(
                        "SFS-NORITO-001",
                        CATEGORY_NORITO,
                        format!("failed to decode {} Norito payload: {error}", kind.schema()),
                        "Re-encode the repair payload with the canonical SoraFS Norito schema.",
                        vec!["sorafs.reference.repair".to_owned()],
                        vec![ValidationContextFieldV1::new("schema", kind.schema())],
                        inputs,
                        generated_at,
                    );
                }
            }
        };
    }
    let context = match kind {
        RepairValidationPayloadKindV1::Evidence => {
            let evidence = decode_repair_payload!(RepairEvidenceV1);
            let context = repair_evidence_context(&evidence);
            if let Err(error) = evidence.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::Report => {
            let report = decode_repair_payload!(RepairReportV1);
            let context = repair_report_context(&report);
            if let Err(error) = report.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::TaskRecord => {
            let task = decode_repair_payload!(RepairTaskRecordV1);
            let context = repair_task_context(&task);
            if let Err(error) = task.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::SlashProposal => {
            let proposal = decode_repair_payload!(RepairSlashProposalV1);
            let context = repair_slash_proposal_context(&proposal);
            if let Err(error) = proposal.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::EscalationPolicy => {
            let policy = decode_repair_payload!(RepairEscalationPolicyV1);
            let context = repair_escalation_policy_context(&policy);
            if let Err(error) = policy.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::EscalationApproval => {
            let approval = decode_repair_payload!(RepairEscalationApprovalV1);
            let context = repair_escalation_approval_context(&approval);
            if let Err(error) = approval.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::TaskEvent => {
            let event = decode_repair_payload!(RepairTaskEventV1);
            let context = repair_task_event_context(&event);
            if let Err(error) = event.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
        RepairValidationPayloadKindV1::AuditEvent => {
            let event = decode_repair_payload!(RepairAuditEventV1);
            let mut context = repair_task_event_context(&event.payload);
            context.push(ValidationContextFieldV1::new(
                "audit_sequence",
                event.header.sequence.to_string(),
            ));
            context.push(ValidationContextFieldV1::new(
                "audit_signer",
                event.header.signer.clone(),
            ));
            context.push(ValidationContextFieldV1::new(
                "payload_digest_hex",
                hex::encode(event.header.payload_digest),
            ));
            if let Err(error) = event.validate() {
                return repair_validation_error_outcome(error, context, inputs, generated_at);
            }
            context
        }
    };
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        kind.success_message(),
        vec![
            "sorafs.reference.repair".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
// One canonical uncompressed V1 outer frame; each caller retains its semantic/signature errors.
fn decode_reference_frame<T>(bytes: &[u8]) -> Result<T, norito::Error>
where
    T: norito::NoritoSerialize + for<'decode> norito::NoritoDeserialize<'decode>,
{
    norito::decode_canonical::<T>(bytes)
}
/// Validates a canonical appeal-finance `CancelAssetLock` V1 Norito payload.
#[must_use]
pub fn validate_appeal_finance_cancel_asset_lock_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![ValidationInputV1::new("cancel_asset_lock", input_label)];
    let instruction = match decode_cancel_asset_lock_reference(bytes) {
        Ok(instruction) => instruction,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode CancelAssetLock Norito payload: {error}"),
                "Re-encode the cancellation with the canonical appeal-finance CancelAssetLock V1 schema.",
                vec![
                    "sorafs.reference.appeal_finance".to_owned(),
                    "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                ],
                vec![ValidationContextFieldV1::new("schema", "CancelAssetLock")],
                inputs,
                generated_at,
            );
        }
    };
    let context = vec![
        ValidationContextFieldV1::new("schema", "CancelAssetLock"),
        ValidationContextFieldV1::new("escrow_id_hex", hex::encode(instruction.escrow_id.as_ref())),
        ValidationContextFieldV1::new(
            "expected_remaining_amount",
            instruction.expected_remaining_amount.to_string(),
        ),
        ValidationContextFieldV1::new("canonical_bytes", bytes.len().to_string()),
    ];
    if instruction.expected_remaining_amount.is_zero() {
        return ValidationOutcomeV1::error(
            "SFS-VAL-001",
            CATEGORY_VALIDATION,
            "CancelAssetLock expected_remaining_amount must be greater than zero",
            "Submit the exact positive remaining quantity from fresh committed escrow state.",
            vec![
                "sorafs.reference.appeal_finance".to_owned(),
                "sorafs.reference.code.SFS-VAL-001".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "appeal-finance CancelAssetLock payload accepted",
        vec![
            "sorafs.reference.appeal_finance".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn decode_cancel_asset_lock_reference(bytes: &[u8]) -> Result<CancelAssetLockWireV1, String> {
    if bytes.len() > CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1 {
        return Err(format!(
            "CancelAssetLock payload is {} bytes; maximum canonical size is {}",
            bytes.len(),
            CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1
        ));
    }
    let limits = norito::DecodeLimits::new(
        16,
        CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1,
        CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1,
        CANCEL_ASSET_LOCK_REFERENCE_MAX_BYTES_V1.saturating_mul(2),
        8,
    );
    norito::decode_canonical_with_limits(bytes, limits).map_err(|error| match error {
        norito::Error::NonCanonicalEncoding => {
            "CancelAssetLock payload is not the exact canonical Norito encoding".to_owned()
        }
        other => other.to_string(),
    })
}
/// Validates a Norito-encoded [`ReplicationOrderV1`] and emits a reference outcome.
#[must_use]
pub fn validate_replication_order_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new("replication_order", input_label);
    let inputs = vec![input];
    let order = match decode_reference_frame::<ReplicationOrderV1>(bytes) {
        Ok(order) => order,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ReplicationOrderV1 Norito payload: {error}"),
                "Re-encode the replication order with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.order".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ReplicationOrderV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = replication_order_context(&order);
    if let Err(error) = order.validate() {
        let code = replication_order_validation_code(&error);
        let category = replication_order_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("replication order validation failed: {error}"),
            "Regenerate the replication order from governed manifest and provider assignments.",
            vec![
                "sorafs.reference.order".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "replication order accepted",
        vec![
            "sorafs.reference.order".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`SignedReplicationOrderV1`] and emits a reference outcome.
#[must_use]
pub fn validate_signed_replication_order_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new("signed_replication_order", input_label);
    let inputs = vec![input];
    let envelope = match decode_reference_frame::<SignedReplicationOrderV1>(bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode SignedReplicationOrderV1 Norito payload: {error}"),
                "Re-encode the signed replication order with the canonical SoraFS Norito schema.",
                vec![
                    "sorafs.reference.order".to_owned(),
                    "sorafs.reference.code.SFS-NORITO-001".to_owned(),
                ],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "SignedReplicationOrderV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = signed_replication_order_context(&envelope);
    if let Err(error) = envelope.validate() {
        let code = signed_replication_order_validation_code(&error);
        let category = signed_replication_order_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "validation_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("signed replication order validation failed: {error}"),
            "Regenerate the signed replication order from governed order bytes and signature material.",
            vec![
                "sorafs.reference.order".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = envelope.verify_signature() {
        context.push(ValidationContextFieldV1::new(
            "signature_error",
            error.to_string(),
        ));
        let code = replication_order_signature_verification_code(&error);
        return ValidationOutcomeV1::error(
            code,
            replication_order_signature_verification_category(&error),
            format!("signed replication order signature validation failed: {error}"),
            "Resign the replication order with the governed issuer Ed25519 key and canonical order signing bytes.",
            vec![
                "sorafs.reference.order".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "signed replication order accepted",
        vec![
            "sorafs.reference.order".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`ProviderAdmissionEnvelopeV1`] and emits a reference outcome.
#[must_use]
pub fn validate_provider_admission_envelope_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new("provider_admission_envelope", input_label);
    let inputs = vec![input];
    let envelope = match decode_reference_frame::<ProviderAdmissionEnvelopeV1>(bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ProviderAdmissionEnvelopeV1 Norito payload: {error}"),
                "Re-encode the provider admission envelope with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.admission".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ProviderAdmissionEnvelopeV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = provider_admission_context(&envelope);
    match verify_envelope_untrusted_signers(&envelope) {
        Ok(advert_digest) => {
            context.push(ValidationContextFieldV1::new(
                "verified_advert_body_digest_hex",
                hex::encode(advert_digest),
            ));
            context.push(ValidationContextFieldV1::new(
                "council_signer_trust",
                "not_evaluated_reference_only",
            ));
            ValidationOutcomeV1::ok(
                "SFS-OK-000",
                "provider admission envelope integrity valid; council trust not evaluated",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    "sorafs.reference.code.SFS-OK-000".to_owned(),
                ],
                context,
                inputs,
                generated_at,
            )
        }
        Err(error) => {
            let code = provider_admission_envelope_code(&error);
            let category = provider_admission_envelope_category(&error);
            context.push(ValidationContextFieldV1::new(
                "validation_error",
                error.to_string(),
            ));
            ValidationOutcomeV1::error(
                code,
                category,
                format!("provider admission envelope validation failed: {error}"),
                "Regenerate the admission envelope from governed provider metadata and council signatures.",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    format!("sorafs.reference.code.{code}"),
                ],
                context,
                inputs,
                generated_at,
            )
        }
    }
}
/// Validates a Norito-encoded provider admission renewal against a previous envelope.
#[must_use]
pub fn validate_provider_admission_renewal_bytes(
    previous_envelope_bytes: &[u8],
    renewal_bytes: &[u8],
    previous_envelope_label: impl Into<String>,
    renewal_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("provider_admission_envelope", previous_envelope_label),
        ValidationInputV1::new("provider_admission_renewal", renewal_label),
    ];
    let previous_envelope = match decode_reference_frame::<ProviderAdmissionEnvelopeV1>(
        previous_envelope_bytes,
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!(
                    "failed to decode previous ProviderAdmissionEnvelopeV1 Norito payload: {error}"
                ),
                "Re-encode the previous provider admission envelope with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.admission".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ProviderAdmissionEnvelopeV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let renewal = match decode_reference_frame::<ProviderAdmissionRenewalV1>(renewal_bytes) {
        Ok(renewal) => renewal,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ProviderAdmissionRenewalV1 Norito payload: {error}"),
                "Re-encode the provider admission renewal with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.admission".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ProviderAdmissionRenewalV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = provider_admission_renewal_context(&renewal);
    let previous_record = match AdmissionRecord::new_untrusted_signers(previous_envelope) {
        Ok(record) => record,
        Err(error) => {
            let code = provider_admission_envelope_code(&error);
            let category = provider_admission_envelope_category(&error);
            context.push(ValidationContextFieldV1::new(
                "previous_envelope_error",
                error.to_string(),
            ));
            return ValidationOutcomeV1::error(
                code,
                category,
                format!("previous provider admission envelope validation failed: {error}"),
                "Regenerate the previous admission envelope from governed provider metadata and council signatures.",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    format!("sorafs.reference.code.{code}"),
                ],
                context,
                inputs,
                generated_at,
            );
        }
    };
    match previous_record.apply_renewal_untrusted_signers(&renewal) {
        Ok(updated_record) => {
            context.push(ValidationContextFieldV1::new(
                "updated_advert_body_digest_hex",
                hex::encode(updated_record.advert_body_digest()),
            ));
            context.push(ValidationContextFieldV1::new(
                "council_signer_trust",
                "not_evaluated_reference_only",
            ));
            ValidationOutcomeV1::ok(
                "SFS-OK-000",
                "provider admission renewal integrity valid; council trust not evaluated",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    "sorafs.reference.code.SFS-OK-000".to_owned(),
                ],
                context,
                inputs,
                generated_at,
            )
        }
        Err(error) => {
            let code = provider_admission_renewal_code(&error);
            let category = provider_admission_renewal_category(&error);
            context.push(ValidationContextFieldV1::new(
                "renewal_error",
                error.to_string(),
            ));
            ValidationOutcomeV1::error(
                code,
                category,
                format!("provider admission renewal validation failed: {error}"),
                "Regenerate the renewal from the previous admission envelope, updated governed envelope, and council signatures.",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    format!("sorafs.reference.code.{code}"),
                ],
                context,
                inputs,
                generated_at,
            )
        }
    }
}
/// Validates a Norito-encoded provider admission revocation against an envelope.
#[must_use]
pub fn validate_provider_admission_revocation_bytes(
    envelope_bytes: &[u8],
    revocation_bytes: &[u8],
    envelope_label: impl Into<String>,
    revocation_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("provider_admission_envelope", envelope_label),
        ValidationInputV1::new("provider_admission_revocation", revocation_label),
    ];
    let envelope = match decode_reference_frame::<ProviderAdmissionEnvelopeV1>(envelope_bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ProviderAdmissionEnvelopeV1 Norito payload: {error}"),
                "Re-encode the provider admission envelope with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.admission".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ProviderAdmissionEnvelopeV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let revocation = match decode_reference_frame::<ProviderAdmissionRevocationV1>(revocation_bytes)
    {
        Ok(revocation) => revocation,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode ProviderAdmissionRevocationV1 Norito payload: {error}"),
                "Re-encode the provider admission revocation with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.admission".to_owned()],
                vec![ValidationContextFieldV1::new(
                    "schema",
                    "ProviderAdmissionRevocationV1",
                )],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = provider_admission_revocation_context(&revocation);
    let record = match AdmissionRecord::new_untrusted_signers(envelope) {
        Ok(record) => record,
        Err(error) => {
            let code = provider_admission_envelope_code(&error);
            let category = provider_admission_envelope_category(&error);
            context.push(ValidationContextFieldV1::new(
                "envelope_error",
                error.to_string(),
            ));
            return ValidationOutcomeV1::error(
                code,
                category,
                format!("provider admission envelope validation failed: {error}"),
                "Regenerate the admission envelope from governed provider metadata and council signatures.",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    format!("sorafs.reference.code.{code}"),
                ],
                context,
                inputs,
                generated_at,
            );
        }
    };
    match record.verify_revocation_untrusted_signers(&revocation) {
        Ok(()) => {
            context.push(ValidationContextFieldV1::new(
                "council_signer_trust",
                "not_evaluated_reference_only",
            ));
            ValidationOutcomeV1::ok(
                "SFS-OK-000",
                "provider admission revocation integrity valid; council trust not evaluated",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    "sorafs.reference.code.SFS-OK-000".to_owned(),
                ],
                context,
                inputs,
                generated_at,
            )
        }
        Err(error) => {
            let code = provider_admission_revocation_code(&error);
            let category = provider_admission_revocation_category(&error);
            context.push(ValidationContextFieldV1::new(
                "revocation_error",
                error.to_string(),
            ));
            ValidationOutcomeV1::error(
                code,
                category,
                format!("provider admission revocation validation failed: {error}"),
                "Regenerate the revocation from the governed admission envelope digest and council signatures.",
                vec![
                    "sorafs.reference.admission".to_owned(),
                    format!("sorafs.reference.code.{code}"),
                ],
                context,
                inputs,
                generated_at,
            )
        }
    }
}
/// Diagnoses a Norito-encoded [`PdpCommitmentV1`] without authorizing acceptance.
#[must_use]
pub fn validate_pdp_commitment_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input_label = input_label.into();
    let inputs = vec![ValidationInputV1::new(
        "pdp_commitment",
        input_label.clone(),
    )];
    let commitment = match decode_pdp_commitment_reference(bytes) {
        Ok(commitment) => commitment,
        Err(error) => {
            return pdp_decode_error(
                "PdpCommitmentV1",
                "pdp commitment",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let mut context = pdp_commitment_context(&commitment);
    if let Err(error) = commitment.validate() {
        let code = pdp_commitment_validation_code(&error);
        let category = pdp_commitment_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "commitment_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP commitment validation failed: {error}"),
            "Regenerate the PDP commitment from the canonical manifest chunk profile and commitment tree roots.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_structural_ok(
        "PDP commitment is structurally valid",
        context,
        inputs,
        generated_at,
    )
}
/// Diagnoses a Norito-encoded [`PdpChallengeV1`] without authorizing acceptance.
#[must_use]
pub fn validate_pdp_challenge_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input_label = input_label.into();
    let inputs = vec![ValidationInputV1::new("pdp_challenge", input_label.clone())];
    let challenge = match decode_pdp_challenge_reference(bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return pdp_decode_error(
                "PdpChallengeV1",
                "pdp challenge",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let mut context = pdp_challenge_context(&challenge);
    if let Err(error) = challenge.validate() {
        let code = pdp_challenge_validation_code(&error);
        let category = pdp_challenge_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "challenge_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP challenge validation failed: {error}"),
            "Regenerate the PDP challenge from the canonical commitment, provider, epoch, and randomness inputs.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_structural_ok(
        "PDP challenge is structurally valid",
        context,
        inputs,
        generated_at,
    )
}
/// Diagnoses a Norito-encoded [`PdpProofV1`] without admission or root verification.
#[must_use]
pub fn validate_pdp_proof_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input_label = input_label.into();
    let inputs = vec![ValidationInputV1::new("pdp_proof", input_label.clone())];
    let proof = match decode_pdp_proof_reference(bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return pdp_decode_error(
                "PdpProofV1",
                "pdp proof",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let mut context = pdp_proof_context(&proof);
    if let Err(error) = proof.validate() {
        let code = pdp_proof_validation_code(&error);
        let category = pdp_proof_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "proof_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP proof validation failed: {error}"),
            "Regenerate the PDP proof from the challenged segments, hot-leaf witnesses, and provider signature.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_structural_ok(
        "PDP proof is structurally valid; signer admission and Merkle roots were not evaluated",
        context,
        inputs,
        generated_at,
    )
}
/// Validates Norito-encoded PDP commitment and challenge payload binding.
#[must_use]
pub fn validate_pdp_commitment_challenge_bytes(
    commitment_bytes: &[u8],
    challenge_bytes: &[u8],
    commitment_label: impl Into<String>,
    challenge_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("pdp_commitment", commitment_label),
        ValidationInputV1::new("pdp_challenge", challenge_label),
    ];
    let commitment = match decode_pdp_commitment_reference(commitment_bytes) {
        Ok(commitment) => commitment,
        Err(error) => {
            return pdp_decode_error(
                "PdpCommitmentV1",
                "pdp commitment",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let challenge = match decode_pdp_challenge_reference(challenge_bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return pdp_decode_error(
                "PdpChallengeV1",
                "pdp challenge",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let mut context = pdp_commitment_challenge_context(&commitment, &challenge);
    if let Err(error) = commitment.validate() {
        let code = pdp_commitment_validation_code(&error);
        let category = pdp_commitment_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "commitment_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP commitment validation failed: {error}"),
            "Regenerate the PDP commitment from the canonical manifest chunk profile and commitment tree roots.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = challenge.validate() {
        let code = pdp_challenge_validation_code(&error);
        let category = pdp_challenge_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "challenge_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP challenge validation failed: {error}"),
            "Regenerate the PDP challenge from the canonical commitment, provider, epoch, and randomness inputs.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    let commitment_digest = match commitment.commitment_digest() {
        Ok(digest) => digest,
        Err(error) => {
            context.push(ValidationContextFieldV1::new(
                "commitment_digest_error",
                error.to_string(),
            ));
            return pdp_binding_error(
                "PDP commitment digest could not be derived canonically",
                "Regenerate the commitment with the canonical PDP schema.",
                context,
                inputs,
                generated_at,
            );
        }
    };
    if challenge.commitment_digest != commitment_digest {
        return pdp_binding_error(
            "PDP challenge commitment digest does not match commitment",
            "Regenerate the challenge for the exact canonical commitment being validated.",
            context,
            inputs,
            generated_at,
        );
    }
    if commitment.manifest_digest != challenge.manifest_digest {
        return pdp_binding_error(
            "PDP challenge manifest digest does not match commitment",
            "Regenerate the challenge for the exact manifest digest named by the commitment.",
            context,
            inputs,
            generated_at,
        );
    }
    if commitment.chunk_profile != challenge.chunk_profile {
        return pdp_binding_error(
            "PDP challenge chunk profile does not match commitment",
            "Regenerate the challenge using the chunk profile embedded in the commitment.",
            context,
            inputs,
            generated_at,
        );
    }
    if challenge.samples.len() > usize::from(commitment.sample_window) {
        context.push(ValidationContextFieldV1::new(
            "sample_window_error",
            "challenge samples exceed commitment sample_window",
        ));
        return ValidationOutcomeV1::error(
            "SFS-PDP-001",
            CATEGORY_VALIDATION,
            "PDP challenge sample window exceeds the commitment",
            "Regenerate the challenge with at most the commitment sample_window samples, or reseal the commitment with a larger governed sample window.",
            pdp_tags("SFS-PDP-001"),
            context,
            inputs,
            generated_at,
        );
    }
    if commitment.sealed_at > challenge.issued_at_unix {
        context.push(ValidationContextFieldV1::new(
            "seal_order_error",
            "commitment sealed after challenge issuance",
        ));
        return ValidationOutcomeV1::error(
            "SFS-POL-002",
            CATEGORY_POLICY,
            "PDP challenge predates the commitment seal",
            "Issue the challenge only after the exact commitment has been sealed.",
            pdp_tags("SFS-POL-002"),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_structural_ok(
        "PDP commitment/challenge binding is structurally valid",
        context,
        inputs,
        generated_at,
    )
}
/// Exhaustively diagnoses PDP witnesses without evaluating governed admission.
#[must_use]
pub fn validate_pdp_commitment_challenge_proof_bytes(
    commitment_bytes: &[u8],
    challenge_bytes: &[u8],
    proof_bytes: &[u8],
    commitment_label: impl Into<String>,
    challenge_label: impl Into<String>,
    proof_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let commitment_label = commitment_label.into();
    let challenge_label = challenge_label.into();
    let proof_label = proof_label.into();
    let inputs = vec![
        ValidationInputV1::new("pdp_commitment", commitment_label),
        ValidationInputV1::new("pdp_challenge", challenge_label),
        ValidationInputV1::new("pdp_proof", proof_label),
    ];
    let commitment = match decode_pdp_commitment_reference(commitment_bytes) {
        Ok(commitment) => commitment,
        Err(error) => {
            return pdp_decode_error(
                "PdpCommitmentV1",
                "pdp commitment",
                error,
                inputs,
                generated_at,
            );
        }
    };
    let challenge = match decode_pdp_challenge_reference(challenge_bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return pdp_decode_error(
                "PdpChallengeV1",
                "pdp challenge",
                error,
                inputs,
                generated_at,
            );
        }
    };
    let proof = match decode_pdp_proof_reference(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return pdp_decode_error("PdpProofV1", "pdp proof", error, inputs, generated_at);
        }
    };
    let mut context = pdp_commitment_challenge_context(&commitment, &challenge);
    context.extend(pdp_proof_context(&proof));
    context.push(ValidationContextFieldV1::new(
        "witness_verification",
        "sampled_bytes_signature_and_both_merkle_roots",
    ));
    if let Err(error) = verify_pdp_witnesses_v1(&commitment, &challenge, &proof) {
        let (code, category) = pdp_verification_code_and_category(&error);
        context.push(ValidationContextFieldV1::new(
            "verification_error",
            error.to_string(),
        ));
        context.push(ValidationContextFieldV1::new(
            "production_acceptance",
            "false",
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP exhaustive witness verification failed: {error}"),
            "Reject the payload set and regenerate the commitment, challenge, or proof; active governed admission must still be evaluated separately after witness verification succeeds.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_diagnostic_ok(
        "PDP sampled bytes, signature, geometry, coverage, and both Merkle roots are valid; production admission was not evaluated",
        "exhaustive_pdp_witness_diagnostic_without_admission",
        context,
        inputs,
        generated_at,
    )
}
/// Exhaustively verifies canonical PDP bytes against an active governed admission record.
///
/// `active_admission` must come from the caller's current council-verified, revocation-aware
/// admission registry. Unlike the structural reference validators, this function hashes sampled
/// bytes, verifies every Merkle path against both roots, verifies the provider signature, and binds
/// the signer to the immutable admission record.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn validate_pdp_commitment_challenge_proof_with_admission_bytes(
    commitment_bytes: &[u8],
    challenge_bytes: &[u8],
    proof_bytes: &[u8],
    commitment_label: impl Into<String>,
    challenge_label: impl Into<String>,
    proof_label: impl Into<String>,
    active_admission: &AdmissionRecord,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("pdp_commitment", commitment_label),
        ValidationInputV1::new("pdp_challenge", challenge_label),
        ValidationInputV1::new("pdp_proof", proof_label),
    ];
    let commitment = match decode_pdp_commitment_reference(commitment_bytes) {
        Ok(commitment) => commitment,
        Err(error) => {
            return pdp_decode_error(
                "PdpCommitmentV1",
                "pdp commitment",
                error,
                inputs,
                generated_at,
            );
        }
    };
    let challenge = match decode_pdp_challenge_reference(challenge_bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return pdp_decode_error(
                "PdpChallengeV1",
                "pdp challenge",
                error,
                inputs,
                generated_at,
            );
        }
    };
    let proof = match decode_pdp_proof_reference(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return pdp_decode_error("PdpProofV1", "pdp proof", error, inputs, generated_at);
        }
    };
    let mut context = pdp_commitment_challenge_context(&commitment, &challenge);
    context.extend(pdp_proof_context(&proof));
    context.extend([
        ValidationContextFieldV1::new(
            "admission_provider_id_hex",
            hex::encode(active_admission.provider_id()),
        ),
        ValidationContextFieldV1::new(
            "admission_envelope_digest_hex",
            hex::encode(active_admission.envelope_digest()),
        ),
        ValidationContextFieldV1::new(
            "admission_council_verified",
            active_admission.is_council_verified().to_string(),
        ),
        ValidationContextFieldV1::new("verification_scope", "exhaustive_production"),
    ]);
    let verified = match verify_pdp_bundle_v1(&commitment, &challenge, &proof, active_admission) {
        Ok(verified) => verified,
        Err(error) => {
            let (code, category) = pdp_verification_code_and_category(&error);
            context.push(ValidationContextFieldV1::new(
                "verification_error",
                error.to_string(),
            ));
            context.push(ValidationContextFieldV1::new(
                "production_acceptance",
                "false",
            ));
            return ValidationOutcomeV1::error(
                code,
                category,
                format!("PDP exhaustive verification failed: {error}"),
                "Reject the proof and resolve the commitment, challenge, proof, or active admission mismatch before retrying.",
                pdp_tags(code),
                context,
                inputs,
                generated_at,
            );
        }
    };
    context.extend([
        ValidationContextFieldV1::new("production_acceptance", "true"),
        ValidationContextFieldV1::new(
            "verified_proof_digest_hex",
            hex::encode(verified.proof_digest()),
        ),
        ValidationContextFieldV1::new(
            "verified_sampled_segments",
            verified.sampled_segments().to_string(),
        ),
        ValidationContextFieldV1::new(
            "verified_sampled_hot_leaves",
            verified.sampled_hot_leaves().to_string(),
        ),
        ValidationContextFieldV1::new(
            "verified_sampled_bytes",
            verified.sampled_bytes().to_string(),
        ),
    ]);
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "PDP commitment/challenge/proof accepted by exhaustive admission-bound verification",
        pdp_tags("SFS-OK-000"),
        context,
        inputs,
        generated_at,
    )
}
/// Validates Norito-encoded PDP challenge/proof payloads and their pair binding.
#[must_use]
pub fn validate_pdp_challenge_proof_bytes(
    challenge_bytes: &[u8],
    proof_bytes: &[u8],
    challenge_label: impl Into<String>,
    proof_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("pdp_challenge", challenge_label),
        ValidationInputV1::new("pdp_proof", proof_label),
    ];
    let challenge = match decode_pdp_challenge_reference(challenge_bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return pdp_decode_error(
                "PdpChallengeV1",
                "pdp challenge",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let proof = match decode_pdp_proof_reference(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return pdp_decode_error(
                "PdpProofV1",
                "pdp proof",
                error.to_string(),
                inputs,
                generated_at,
            );
        }
    };
    let mut context = pdp_challenge_proof_context(&challenge, &proof);
    if let Err(error) = challenge.validate() {
        let code = pdp_challenge_validation_code(&error);
        let category = pdp_challenge_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "challenge_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP challenge validation failed: {error}"),
            "Regenerate the PDP challenge from the canonical commitment, provider, epoch, and randomness inputs.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = proof.validate() {
        let code = pdp_proof_validation_code(&error);
        let category = pdp_proof_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "proof_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PDP proof validation failed: {error}"),
            "Regenerate the PDP proof from the challenged segments, hot-leaf witnesses, and provider signature.",
            pdp_tags(code),
            context,
            inputs,
            generated_at,
        );
    }
    if proof.commitment_digest != challenge.commitment_digest {
        return pdp_binding_error(
            "PDP proof commitment digest does not match challenge",
            "Regenerate the proof for the exact commitment digest named by the challenge.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.challenge_id != challenge.challenge_id {
        return pdp_binding_error(
            "PDP proof challenge_id does not match challenge",
            "Regenerate the proof for the exact challenge identifier being validated.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.manifest_digest != challenge.manifest_digest {
        return pdp_binding_error(
            "PDP proof manifest digest does not match challenge",
            "Regenerate the proof for the manifest digest named by the challenge.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.provider_id != challenge.provider_id {
        return pdp_binding_error(
            "PDP proof provider_id does not match challenge",
            "Regenerate the proof with the provider identity named by the challenge.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.epoch_id != challenge.epoch_id {
        return pdp_binding_error(
            "PDP proof epoch_id does not match challenge",
            "Regenerate the proof for the challenge epoch being validated.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.issued_at_unix < challenge.issued_at_unix
        || proof.issued_at_unix > challenge.response_deadline_unix
    {
        context.push(ValidationContextFieldV1::new(
            "deadline_error",
            "proof issued outside challenge response window",
        ));
        return ValidationOutcomeV1::error(
            "SFS-POL-002",
            CATEGORY_POLICY,
            "PDP proof timestamp falls outside the challenge response window",
            "Reject the proof and regenerate it while the exact challenge is active.",
            pdp_tags("SFS-POL-002"),
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = validate_pdp_proof_coverage(&challenge, &proof) {
        context.push(ValidationContextFieldV1::new("coverage_error", error));
        return ValidationOutcomeV1::error(
            "SFS-PDP-001",
            CATEGORY_VALIDATION,
            "PDP proof sample coverage does not match the challenge",
            "Regenerate the proof with exactly the segment and hot-leaf witnesses requested by the challenge.",
            pdp_tags("SFS-PDP-001"),
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = proof.verify_signature() {
        context.push(ValidationContextFieldV1::new(
            "proof_signature_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-SIG-008",
            CATEGORY_SIGNATURE,
            format!("PDP proof signature verification failed: {error}"),
            "Reject the proof and require a canonical domain-separated provider signature.",
            pdp_tags("SFS-SIG-008"),
            context,
            inputs,
            generated_at,
        );
    }
    pdp_structural_ok(
        "PDP challenge/proof binding and proof signature are structurally valid; signer admission and Merkle roots were not evaluated",
        context,
        inputs,
        generated_at,
    )
}
/// Validates Norito-encoded PoR challenge/proof payloads and their pair binding.
#[must_use]
pub fn validate_por_challenge_proof_bytes(
    challenge_bytes: &[u8],
    proof_bytes: &[u8],
    challenge_label: impl Into<String>,
    proof_label: impl Into<String>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let inputs = vec![
        ValidationInputV1::new("por_challenge", challenge_label),
        ValidationInputV1::new("por_proof", proof_label),
    ];
    let challenge = match crate::por::decode_por_challenge_payload_v1(challenge_bytes) {
        Ok(challenge) => challenge,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode PorChallengeV1 Norito payload: {error}"),
                "Re-encode the PoR challenge with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.por".to_owned()],
                vec![ValidationContextFieldV1::new("schema", "PorChallengeV1")],
                inputs,
                generated_at,
            );
        }
    };
    let proof = match crate::por::decode_por_proof_payload_v1(proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode PorProofV1 Norito payload: {error}"),
                "Re-encode the PoR proof with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.por".to_owned()],
                vec![ValidationContextFieldV1::new("schema", "PorProofV1")],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = por_context(&challenge, &proof);
    if let Err(error) = challenge.validate() {
        let code = por_challenge_validation_code(&error);
        let category = por_challenge_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "challenge_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PoR challenge validation failed: {error}"),
            "Regenerate the PoR challenge from the canonical manifest, provider, epoch, and randomness inputs.",
            vec![
                "sorafs.reference.por".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = proof.validate() {
        let code = por_proof_validation_code(&error);
        context.push(ValidationContextFieldV1::new(
            "proof_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            CATEGORY_VALIDATION,
            format!("PoR proof validation failed: {error}"),
            "Regenerate the PoR proof from the challenged chunks and canonical authentication path.",
            vec![
                "sorafs.reference.por".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if proof.challenge_id != challenge.challenge_id {
        return por_binding_error(
            "SFS-POR-003",
            "proof challenge_id does not match challenge",
            "Regenerate the proof for the exact challenge identifier being validated.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.manifest_digest != challenge.manifest_digest {
        return por_binding_error(
            "SFS-POR-003",
            "proof manifest digest does not match challenge",
            "Regenerate the proof for the manifest digest named by the challenge.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.provider_id != challenge.provider_id {
        return por_binding_error(
            "SFS-POR-003",
            "proof provider_id does not match challenge",
            "Regenerate the proof with the provider identity named by the challenge.",
            context,
            inputs,
            generated_at,
        );
    }
    if proof.submitted_at < challenge.issued_at || proof.submitted_at > challenge.deadline_at {
        context.push(ValidationContextFieldV1::new(
            "deadline_error",
            "proof submitted outside challenge validity window",
        ));
        return ValidationOutcomeV1::error(
            "SFS-POL-002",
            CATEGORY_POLICY,
            "PoR proof timestamp falls outside the challenge validity window",
            "Reject the proof and regenerate it while the exact challenge is active.",
            vec![
                "sorafs.reference.por".to_owned(),
                "sorafs.reference.code.SFS-POL-002".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    let proof_indices: Vec<u64> = proof
        .samples
        .iter()
        .map(|sample| sample.sample_index)
        .collect();
    if challenge.sample_indices != proof_indices {
        context.push(ValidationContextFieldV1::new(
            "sample_coverage_error",
            "proof samples do not match challenge sample indices",
        ));
        return ValidationOutcomeV1::error(
            "SFS-POR-001",
            CATEGORY_VALIDATION,
            "PoR proof sample coverage does not match the challenge",
            "Regenerate the proof with exactly the sample indices requested by the challenge.",
            vec![
                "sorafs.reference.por".to_owned(),
                "sorafs.reference.code.SFS-POR-001".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Err(error) = proof.verify_signature() {
        context.push(ValidationContextFieldV1::new(
            "proof_signature_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            "SFS-SIG-008",
            CATEGORY_SIGNATURE,
            format!("PoR proof signature verification failed: {error}"),
            "Reject the proof and require the provider to sign the canonical domain-separated PoR proof payload.",
            vec![
                "sorafs.reference.por".to_owned(),
                "sorafs.reference.code.SFS-SIG-008".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    context.push(ValidationContextFieldV1::new(
        "proof_digest_hex",
        hex::encode(proof.proof_digest()),
    ));
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "PoR challenge/proof accepted",
        vec![
            "sorafs.reference.por".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
/// Validates a Norito-encoded [`PotrReceiptV1`] and emits a reference outcome.
#[must_use]
pub fn validate_potr_receipt_bytes(
    bytes: &[u8],
    input_label: impl Into<String>,
    expected_tier: Option<ProofStreamTier>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let input = ValidationInputV1::new("potr_receipt", input_label);
    let inputs = vec![input];
    let receipt = match decode_reference_frame::<PotrReceiptV1>(bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            return ValidationOutcomeV1::error(
                "SFS-NORITO-001",
                CATEGORY_NORITO,
                format!("failed to decode PotrReceiptV1 Norito payload: {error}"),
                "Re-encode the PoTR receipt with the canonical SoraFS Norito schema.",
                vec!["sorafs.reference.potr".to_owned()],
                vec![ValidationContextFieldV1::new("schema", "PotrReceiptV1")],
                inputs,
                generated_at,
            );
        }
    };
    let mut context = potr_context(&receipt);
    if let Err(error) = receipt.validate() {
        let code = potr_receipt_validation_code(&error);
        let category = potr_receipt_validation_category(&error);
        context.push(ValidationContextFieldV1::new(
            "receipt_error",
            error.to_string(),
        ));
        return ValidationOutcomeV1::error(
            code,
            category,
            format!("PoTR receipt validation failed: {error}"),
            "Regenerate the PoTR receipt from the canonical timed retrieval observation and signer material.",
            vec![
                "sorafs.reference.potr".to_owned(),
                format!("sorafs.reference.code.{code}"),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    if let Some(expected_tier) = expected_tier
        && receipt.tier != expected_tier
    {
        context.push(ValidationContextFieldV1::new(
            "expected_tier",
            proof_stream_tier_label(expected_tier),
        ));
        context.push(ValidationContextFieldV1::new(
            "tier_error",
            "receipt tier does not match requested profile",
        ));
        return ValidationOutcomeV1::error(
            "SFS-POTR-002",
            CATEGORY_VALIDATION,
            "PoTR receipt tier does not match the requested profile",
            "Validate the receipt against the tier profile that was requested, or rerun the retrieval for the requested tier.",
            vec![
                "sorafs.reference.potr".to_owned(),
                "sorafs.reference.code.SFS-POTR-002".to_owned(),
            ],
            context,
            inputs,
            generated_at,
        );
    }
    ValidationOutcomeV1::ok(
        "SFS-OK-000",
        "PoTR receipt accepted",
        vec![
            "sorafs.reference.potr".to_owned(),
            "sorafs.reference.code.SFS-OK-000".to_owned(),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn advert_context(advert: &ProviderAdvertV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(advert.body.provider_id)),
        ValidationContextFieldV1::new("profile_id", advert.body.profile_id.clone()),
        ValidationContextFieldV1::new("issued_at", advert.issued_at.to_string()),
        ValidationContextFieldV1::new("expires_at", advert.expires_at.to_string()),
        ValidationContextFieldV1::new("ttl_secs", advert.ttl().to_string()),
        ValidationContextFieldV1::new(
            "signature_algorithm",
            format!("{:?}", advert.signature.algorithm),
        ),
    ]
}
fn pdp_tags(code: &str) -> Vec<String> {
    vec![
        "sorafs.reference.pdp".to_owned(),
        format!("sorafs.reference.code.{code}"),
    ]
}
fn decode_pdp_commitment_reference(bytes: &[u8]) -> Result<PdpCommitmentV1, String> {
    decode_pdp_reference_payload(
        bytes,
        "PdpCommitmentV1",
        PDP_COMMITMENT_MAX_CANONICAL_BYTES_V1,
        256,
    )
}
fn decode_pdp_challenge_reference(bytes: &[u8]) -> Result<PdpChallengeV1, String> {
    decode_pdp_reference_payload(
        bytes,
        "PdpChallengeV1",
        PDP_CHALLENGE_MAX_CANONICAL_BYTES_V1,
        PDP_MAX_SEGMENT_SAMPLES_V1.max(PDP_MAX_HOT_LEAVES_PER_SEGMENT_SAMPLE_V1),
    )
}
fn decode_pdp_proof_reference(bytes: &[u8]) -> Result<PdpProofV1, String> {
    decode_pdp_reference_payload(
        bytes,
        "PdpProofV1",
        PDP_PROOF_MAX_CANONICAL_BYTES_V1,
        usize::try_from(crate::PDP_HOT_LEAF_SIZE_V1)
            .unwrap_or(PDP_MAX_TOTAL_HOT_LEAF_SAMPLES_V1)
            .max(PDP_MAX_TOTAL_HOT_LEAF_SAMPLES_V1)
            .max(PDP_MAX_MERKLE_PATH_DEPTH_V1),
    )
}
fn decode_pdp_reference_payload<T>(
    bytes: &[u8],
    schema: &'static str,
    maximum_bytes: usize,
    maximum_sequence_elements: usize,
) -> Result<T, String>
where
    for<'de> T: norito::core::NoritoDeserialize<'de> + norito::core::NoritoSerialize,
{
    if bytes.len() > maximum_bytes {
        return Err(format!(
            "{schema} payload is {} bytes; maximum canonical size is {maximum_bytes}",
            bytes.len()
        ));
    }
    let limits = norito::DecodeLimits::new(
        maximum_sequence_elements,
        maximum_bytes,
        maximum_bytes,
        maximum_bytes.saturating_mul(2),
        PDP_REFERENCE_DECODE_MAX_DEPTH_V1,
    );
    norito::decode_canonical_with_limits(bytes, limits).map_err(|error| match error {
        norito::Error::NonCanonicalEncoding => {
            format!("{schema} payload is not the exact canonical Norito encoding")
        }
        other => other.to_string(),
    })
}
fn pdp_decode_error(
    schema: &'static str,
    label: &'static str,
    error: String,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    ValidationOutcomeV1::error(
        "SFS-NORITO-001",
        CATEGORY_NORITO,
        format!("failed to decode {schema} Norito payload: {error}"),
        format!("Re-encode the {label} with the canonical SoraFS Norito schema."),
        pdp_tags("SFS-NORITO-001"),
        vec![ValidationContextFieldV1::new("schema", schema)],
        inputs,
        generated_at,
    )
}
fn pdp_binding_error(
    message: impl Into<String>,
    action: impl Into<String>,
    context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    ValidationOutcomeV1::error(
        "SFS-PDP-003",
        CATEGORY_VALIDATION,
        message,
        action,
        pdp_tags("SFS-PDP-003"),
        context,
        inputs,
        generated_at,
    )
}
fn pdp_structural_ok(
    message: impl Into<String>,
    context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    pdp_diagnostic_ok(
        message,
        "structural_diagnostic_only",
        context,
        inputs,
        generated_at,
    )
}
fn pdp_diagnostic_ok(
    message: impl Into<String>,
    verification_scope: impl Into<String>,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    context.push(ValidationContextFieldV1::new(
        "verification_scope",
        verification_scope,
    ));
    context.push(ValidationContextFieldV1::new(
        "production_acceptance",
        "false",
    ));
    context.push(ValidationContextFieldV1::new(
        "admission_trust",
        "not_evaluated",
    ));
    ValidationOutcomeV1::ok(
        PDP_STRUCTURAL_OK_CODE,
        message,
        pdp_tags(PDP_STRUCTURAL_OK_CODE),
        context,
        inputs,
        generated_at,
    )
}
fn pdp_commitment_context(commitment: &PdpCommitmentV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PdpCommitmentV1"),
        ValidationContextFieldV1::new("version", commitment.version.to_string()),
        ValidationContextFieldV1::new(
            "manifest_digest_hex",
            hex::encode(commitment.manifest_digest),
        ),
        ValidationContextFieldV1::new(
            "chunk_profile",
            chunk_profile_label(&commitment.chunk_profile),
        ),
        ValidationContextFieldV1::new(
            "commitment_root_hot_hex",
            hex::encode(commitment.commitment_root_hot),
        ),
        ValidationContextFieldV1::new(
            "commitment_root_segment_hex",
            hex::encode(commitment.commitment_root_segment),
        ),
        ValidationContextFieldV1::new("hash_algorithm", commitment.hash_algorithm.as_str()),
        ValidationContextFieldV1::new("hot_tree_height", commitment.hot_tree_height.to_string()),
        ValidationContextFieldV1::new(
            "segment_tree_height",
            commitment.segment_tree_height.to_string(),
        ),
        ValidationContextFieldV1::new("sample_window", commitment.sample_window.to_string()),
        ValidationContextFieldV1::new("sealed_at", commitment.sealed_at.to_string()),
    ]
}
fn pdp_challenge_context(challenge: &PdpChallengeV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PdpChallengeV1"),
        ValidationContextFieldV1::new("version", challenge.version.to_string()),
        ValidationContextFieldV1::new("challenge_id_hex", hex::encode(challenge.challenge_id)),
        ValidationContextFieldV1::new(
            "manifest_digest_hex",
            hex::encode(challenge.manifest_digest),
        ),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(challenge.provider_id)),
        ValidationContextFieldV1::new(
            "chunk_profile",
            chunk_profile_label(&challenge.chunk_profile),
        ),
        ValidationContextFieldV1::new("seed_hex", hex::encode(challenge.seed)),
        ValidationContextFieldV1::new("epoch_id", challenge.epoch_id.to_string()),
        ValidationContextFieldV1::new("drand_round", challenge.drand_round.to_string()),
        ValidationContextFieldV1::new(
            "response_deadline_unix",
            challenge.response_deadline_unix.to_string(),
        ),
        ValidationContextFieldV1::new("sample_count", challenge.samples.len().to_string()),
        ValidationContextFieldV1::new(
            "hot_leaf_count",
            challenge
                .samples
                .iter()
                .map(|sample| sample.hot_leaf_indices.len())
                .sum::<usize>()
                .to_string(),
        ),
    ]
}
fn pdp_proof_context(proof: &PdpProofV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("schema", "PdpProofV1"),
        ValidationContextFieldV1::new("version", proof.version.to_string()),
        ValidationContextFieldV1::new("challenge_id_hex", hex::encode(proof.challenge_id)),
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(proof.manifest_digest)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(proof.provider_id)),
        ValidationContextFieldV1::new("epoch_id", proof.epoch_id.to_string()),
        ValidationContextFieldV1::new("proof_leaf_count", proof.proof_leaves.len().to_string()),
        ValidationContextFieldV1::new(
            "hot_leaf_proof_count",
            proof
                .proof_leaves
                .iter()
                .map(|leaf| leaf.hot_leaves.len())
                .sum::<usize>()
                .to_string(),
        ),
        ValidationContextFieldV1::new("signature_len", proof.signature.signature.len().to_string()),
        ValidationContextFieldV1::new("issued_at_unix", proof.issued_at_unix.to_string()),
    ]
}
fn pdp_commitment_challenge_context(
    commitment: &PdpCommitmentV1,
    challenge: &PdpChallengeV1,
) -> Vec<ValidationContextFieldV1> {
    let mut context = pdp_commitment_context(commitment);
    context.extend([
        ValidationContextFieldV1::new("challenge_id_hex", hex::encode(challenge.challenge_id)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(challenge.provider_id)),
        ValidationContextFieldV1::new(
            "challenge_manifest_digest_hex",
            hex::encode(challenge.manifest_digest),
        ),
        ValidationContextFieldV1::new(
            "challenge_chunk_profile",
            chunk_profile_label(&challenge.chunk_profile),
        ),
        ValidationContextFieldV1::new("challenge_epoch_id", challenge.epoch_id.to_string()),
        ValidationContextFieldV1::new(
            "challenge_sample_count",
            challenge.samples.len().to_string(),
        ),
    ]);
    context
}
fn pdp_challenge_proof_context(
    challenge: &PdpChallengeV1,
    proof: &PdpProofV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("challenge_id_hex", hex::encode(challenge.challenge_id)),
        ValidationContextFieldV1::new("proof_challenge_id_hex", hex::encode(proof.challenge_id)),
        ValidationContextFieldV1::new(
            "manifest_digest_hex",
            hex::encode(challenge.manifest_digest),
        ),
        ValidationContextFieldV1::new(
            "proof_manifest_digest_hex",
            hex::encode(proof.manifest_digest),
        ),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(challenge.provider_id)),
        ValidationContextFieldV1::new("proof_provider_id_hex", hex::encode(proof.provider_id)),
        ValidationContextFieldV1::new("epoch_id", challenge.epoch_id.to_string()),
        ValidationContextFieldV1::new("proof_epoch_id", proof.epoch_id.to_string()),
        ValidationContextFieldV1::new("sample_count", challenge.samples.len().to_string()),
        ValidationContextFieldV1::new("proof_leaf_count", proof.proof_leaves.len().to_string()),
        ValidationContextFieldV1::new(
            "response_deadline_unix",
            challenge.response_deadline_unix.to_string(),
        ),
        ValidationContextFieldV1::new("issued_at_unix", proof.issued_at_unix.to_string()),
    ]
}
fn validate_pdp_proof_coverage(
    challenge: &PdpChallengeV1,
    proof: &PdpProofV1,
) -> Result<(), String> {
    if challenge.samples.len() != proof.proof_leaves.len() {
        return Err(format!(
            "proof has {} segment witnesses; challenge requires {}",
            proof.proof_leaves.len(),
            challenge.samples.len()
        ));
    }
    for (sample, segment) in challenge.samples.iter().zip(&proof.proof_leaves) {
        if sample.segment_index != segment.segment_index {
            return Err(format!(
                "proof segment {} does not match challenged segment {} at the same canonical position",
                segment.segment_index, sample.segment_index
            ));
        }
        if sample.hot_leaf_indices.len() != segment.hot_leaves.len() {
            return Err(format!(
                "proof segment {} has {} hot leaves; challenge requires {}",
                sample.segment_index,
                segment.hot_leaves.len(),
                sample.hot_leaf_indices.len()
            ));
        }
        for (&expected, actual) in sample.hot_leaf_indices.iter().zip(&segment.hot_leaves) {
            if expected != actual.leaf_index {
                return Err(format!(
                    "proof segment {} hot leaf {} does not match challenged leaf {} at the same canonical position",
                    sample.segment_index, actual.leaf_index, expected
                ));
            }
        }
    }
    Ok(())
}
fn chunk_profile_label(profile: &crate::ChunkingProfileV1) -> String {
    format!("{}.{}@{}", profile.namespace, profile.name, profile.semver)
}
fn por_context(challenge: &PorChallengeV1, proof: &PorProofV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("challenge_id_hex", hex::encode(challenge.challenge_id)),
        ValidationContextFieldV1::new(
            "manifest_digest_hex",
            hex::encode(challenge.manifest_digest),
        ),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(challenge.provider_id)),
        ValidationContextFieldV1::new("chunking_profile", challenge.chunking_profile.clone()),
        ValidationContextFieldV1::new("sample_tier", challenge.sample_tier.to_string()),
        ValidationContextFieldV1::new("sample_count", challenge.sample_count.to_string()),
        ValidationContextFieldV1::new("proof_samples", proof.samples.len().to_string()),
        ValidationContextFieldV1::new("issued_at", challenge.issued_at.to_string()),
        ValidationContextFieldV1::new("deadline_at", challenge.deadline_at.to_string()),
        ValidationContextFieldV1::new("submitted_at", proof.submitted_at.to_string()),
    ]
}
fn potr_context(receipt: &PotrReceiptV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(receipt.manifest_digest)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(receipt.provider_id)),
        ValidationContextFieldV1::new("tier", proof_stream_tier_label(receipt.tier)),
        ValidationContextFieldV1::new("deadline_ms", receipt.deadline_ms.to_string()),
        ValidationContextFieldV1::new("latency_ms", receipt.latency_ms.to_string()),
        ValidationContextFieldV1::new("status", format!("{:?}", receipt.status)),
        ValidationContextFieldV1::new("requested_at_ms", receipt.requested_at_ms.to_string()),
        ValidationContextFieldV1::new("responded_at_ms", receipt.responded_at_ms.to_string()),
        ValidationContextFieldV1::new("recorded_at_ms", receipt.recorded_at_ms.to_string()),
        ValidationContextFieldV1::new("range_start", receipt.range_start.to_string()),
        ValidationContextFieldV1::new("range_end", receipt.range_end.to_string()),
    ]
}
fn proof_stream_tier_label(tier: ProofStreamTier) -> &'static str {
    match tier {
        ProofStreamTier::Hot => "hot",
        ProofStreamTier::Warm => "warm",
        ProofStreamTier::Archive => "archive",
    }
}
fn provider_admission_context(
    envelope: &ProviderAdmissionEnvelopeV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new(
            "provider_id_hex",
            hex::encode(envelope.proposal.provider_id),
        ),
        ValidationContextFieldV1::new("profile_id", envelope.proposal.profile_id.clone()),
        ValidationContextFieldV1::new("proposal_digest_hex", hex::encode(envelope.proposal_digest)),
        ValidationContextFieldV1::new(
            "advert_body_digest_hex",
            hex::encode(envelope.advert_body_digest),
        ),
        ValidationContextFieldV1::new("issued_at", envelope.issued_at.to_string()),
        ValidationContextFieldV1::new("retention_epoch", envelope.retention_epoch.to_string()),
        ValidationContextFieldV1::new(
            "council_signatures",
            envelope.council_signatures.len().to_string(),
        ),
        ValidationContextFieldV1::new("endpoints", envelope.proposal.endpoints.len().to_string()),
        ValidationContextFieldV1::new(
            "jurisdiction_code",
            envelope.proposal.jurisdiction_code.clone(),
        ),
    ]
}
fn provider_admission_renewal_context(
    renewal: &ProviderAdmissionRenewalV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(renewal.provider_id)),
        ValidationContextFieldV1::new(
            "previous_envelope_digest_hex",
            hex::encode(renewal.previous_envelope_digest),
        ),
        ValidationContextFieldV1::new(
            "renewal_envelope_digest_hex",
            hex::encode(renewal.envelope_digest),
        ),
        ValidationContextFieldV1::new("renewal_issued_at", renewal.envelope.issued_at.to_string()),
        ValidationContextFieldV1::new(
            "renewal_retention_epoch",
            renewal.envelope.retention_epoch.to_string(),
        ),
        ValidationContextFieldV1::new(
            "renewal_council_signatures",
            renewal.envelope.council_signatures.len().to_string(),
        ),
        ValidationContextFieldV1::new("notes_present", renewal.notes.is_some().to_string()),
    ]
}
fn provider_admission_revocation_context(
    revocation: &ProviderAdmissionRevocationV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(revocation.provider_id)),
        ValidationContextFieldV1::new(
            "envelope_digest_hex",
            hex::encode(revocation.envelope_digest),
        ),
        ValidationContextFieldV1::new("revoked_at", revocation.revoked_at.to_string()),
        ValidationContextFieldV1::new(
            "council_signatures",
            revocation.council_signatures.len().to_string(),
        ),
        ValidationContextFieldV1::new("reason", revocation.reason.clone()),
        ValidationContextFieldV1::new("notes_present", revocation.notes.is_some().to_string()),
    ]
}
fn replication_order_context(order: &ReplicationOrderV1) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("order_id_hex", hex::encode(order.order_id)),
        ValidationContextFieldV1::new("manifest_cid_hex", hex::encode(&order.manifest_cid)),
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(order.manifest_digest)),
        ValidationContextFieldV1::new("chunking_profile", order.chunking_profile.clone()),
        ValidationContextFieldV1::new("target_replicas", order.target_replicas.to_string()),
        ValidationContextFieldV1::new("assignments", order.assignments.len().to_string()),
        ValidationContextFieldV1::new("issued_at", order.issued_at.to_string()),
        ValidationContextFieldV1::new("deadline_at", order.deadline_at.to_string()),
    ]
}
fn signed_replication_order_context(
    envelope: &SignedReplicationOrderV1,
) -> Vec<ValidationContextFieldV1> {
    let mut context = replication_order_context(&envelope.order);
    context.push(ValidationContextFieldV1::new(
        "schema",
        "SignedReplicationOrderV1",
    ));
    context.push(ValidationContextFieldV1::new(
        "signed_order_version",
        envelope.version.to_string(),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_algorithm",
        signature_algorithm_label(envelope.signature.algorithm),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_public_key_len",
        envelope.signature.public_key.len().to_string(),
    ));
    context.push(ValidationContextFieldV1::new(
        "signature_len",
        envelope.signature.signature.len().to_string(),
    ));
    context
}
fn signature_algorithm_label(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::MultiSig => "multi-sig",
    }
}
fn repair_evidence_context(evidence: &RepairEvidenceV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(evidence.manifest_digest)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(evidence.provider_id)),
        ValidationContextFieldV1::new("cause", repair_cause_label(evidence)),
    ];
    if let Some(por_history_id) = evidence.por_history_id {
        context.push(ValidationContextFieldV1::new(
            "por_history_id",
            por_history_id.to_string(),
        ));
    }
    context
}
fn repair_report_context(report: &RepairReportV1) -> Vec<ValidationContextFieldV1> {
    let mut context = repair_evidence_context(&report.evidence);
    context.push(ValidationContextFieldV1::new(
        "ticket_id",
        report.ticket_id.to_string(),
    ));
    context.push(ValidationContextFieldV1::new(
        "auditor_account",
        report.auditor_account.clone(),
    ));
    context.push(ValidationContextFieldV1::new(
        "submitted_at_unix",
        report.submitted_at_unix.to_string(),
    ));
    context
}
fn repair_task_context(task: &RepairTaskRecordV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("ticket_id", task.ticket_id.to_string()),
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(task.manifest_digest)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(task.provider_id)),
        ValidationContextFieldV1::new("auditor_account", task.auditor_account.clone()),
        ValidationContextFieldV1::new("state", repair_task_state_label(&task.state)),
    ];
    if let Some(por_history_id) = task.por_history_id {
        context.push(ValidationContextFieldV1::new(
            "por_history_id",
            por_history_id.to_string(),
        ));
    }
    if let Some(deadline) = task.sla_deadline_unix {
        context.push(ValidationContextFieldV1::new(
            "sla_deadline_unix",
            deadline.to_string(),
        ));
    }
    context.push(ValidationContextFieldV1::new(
        "slash_proposal_digest_present",
        task.slash_proposal_digest.is_some().to_string(),
    ));
    context
}
fn repair_slash_proposal_context(
    proposal: &RepairSlashProposalV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("ticket_id", proposal.ticket_id.to_string()),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(proposal.provider_id)),
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(proposal.manifest_digest)),
        ValidationContextFieldV1::new("auditor_account", proposal.auditor_account.clone()),
        ValidationContextFieldV1::new("proposed_penalty", proposal.proposed_penalty.to_string()),
        ValidationContextFieldV1::new("submitted_at_unix", proposal.submitted_at_unix.to_string()),
        ValidationContextFieldV1::new("approval_present", proposal.approval.is_some().to_string()),
    ]
}
fn repair_escalation_policy_context(
    policy: &RepairEscalationPolicyV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("quorum_bps", policy.quorum_bps.to_string()),
        ValidationContextFieldV1::new("minimum_voters", policy.minimum_voters.to_string()),
        ValidationContextFieldV1::new(
            "dispute_window_secs",
            policy.dispute_window_secs.to_string(),
        ),
        ValidationContextFieldV1::new("appeal_window_secs", policy.appeal_window_secs.to_string()),
        ValidationContextFieldV1::new("max_penalty", policy.max_penalty.to_string()),
    ]
}
fn repair_escalation_approval_context(
    approval: &RepairEscalationApprovalV1,
) -> Vec<ValidationContextFieldV1> {
    vec![
        ValidationContextFieldV1::new("approve_votes", approval.approve_votes.to_string()),
        ValidationContextFieldV1::new("reject_votes", approval.reject_votes.to_string()),
        ValidationContextFieldV1::new("abstain_votes", approval.abstain_votes.to_string()),
        ValidationContextFieldV1::new("approved_at_unix", approval.approved_at_unix.to_string()),
        ValidationContextFieldV1::new("finalized_at_unix", approval.finalized_at_unix.to_string()),
    ]
}
fn repair_task_event_context(event: &RepairTaskEventV1) -> Vec<ValidationContextFieldV1> {
    let mut context = vec![
        ValidationContextFieldV1::new("ticket_id", event.ticket_id.to_string()),
        ValidationContextFieldV1::new("manifest_digest_hex", hex::encode(event.manifest_digest)),
        ValidationContextFieldV1::new("provider_id_hex", hex::encode(event.provider_id)),
        ValidationContextFieldV1::new("status", event.status.to_string()),
        ValidationContextFieldV1::new("occurred_at_unix", event.occurred_at_unix.to_string()),
    ];
    if let Some(actor) = &event.actor {
        context.push(ValidationContextFieldV1::new("actor", actor.clone()));
    }
    context
}
fn repair_cause_label(evidence: &RepairEvidenceV1) -> String {
    match &evidence.cause {
        crate::RepairCauseV1::PorFailure(_) => "por_failure",
        crate::RepairCauseV1::PdpFailure(_) => "pdp_failure",
        crate::RepairCauseV1::LatencySla(_) => "latency_sla",
        crate::RepairCauseV1::ReplicaShortfall(_) => "replica_shortfall",
        crate::RepairCauseV1::Manual(_) => "manual",
    }
    .to_owned()
}
fn repair_task_state_label(state: &RepairTaskStateV1) -> String {
    match state {
        RepairTaskStateV1::Queued(_) => "queued",
        RepairTaskStateV1::InProgress(_) => "in_progress",
        RepairTaskStateV1::Completed(_) => "completed",
        RepairTaskStateV1::Failed(_) => "failed",
        RepairTaskStateV1::Escalated(_) => "escalated",
    }
    .to_owned()
}
fn por_binding_error(
    code: &'static str,
    message: &'static str,
    action: &'static str,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    context.push(ValidationContextFieldV1::new("binding_error", message));
    ValidationOutcomeV1::error(
        code,
        CATEGORY_VALIDATION,
        format!("PoR challenge/proof binding failed: {message}"),
        action,
        vec![
            "sorafs.reference.por".to_owned(),
            format!("sorafs.reference.code.{code}"),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn repair_validation_error_outcome(
    error: RepairValidationError,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let code = repair_validation_code(&error);
    let category = repair_validation_category(&error);
    context.push(ValidationContextFieldV1::new(
        "validation_error",
        error.to_string(),
    ));
    ValidationOutcomeV1::error(
        code,
        category,
        format!("repair payload validation failed: {error}"),
        repair_validation_action(code),
        vec![
            "sorafs.reference.repair".to_owned(),
            format!("sorafs.reference.code.{code}"),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn repair_validation_action(code: &str) -> &'static str {
    match code {
        "SFS-NORITO-001" => "Re-encode the repair payload with the canonical SoraFS Norito schema.",
        "SFS-VAL-001" => {
            "Regenerate the repair payload from a manifest/provider record with non-zero canonical digests."
        }
        "SFS-VAL-002" => "Regenerate the repair payload with the supported V1 schema.",
        "SFS-REP-001" => {
            "Attach complete repair evidence with non-zero PoR samples, latency, or replica shortfall details."
        }
        "SFS-REP-002" => {
            "Regenerate the repair evidence, report, task record, slash proposal, escalation policy, escalation approval, task event, or audit event from canonical scheduler and governed repair state."
        }
        "SFS-POL-005" => {
            "Correct the repair timestamps or SLA/deadline ordering before submitting the payload."
        }
        "SFS-GOV-002" => {
            "Regenerate the repair escalation or slash governance payload from the governed policy state."
        }
        "SFS-INT-001" => {
            "Retry validation after checking the local validator build and Norito encoder."
        }
        _ => "Regenerate the repair payload from canonical SoraFS state and retry validation.",
    }
}
fn pop_validation_error_outcome(
    kind: PopValidationPayloadKindV1,
    error: PopCredentialValidationError,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let code = pop_validation_code(&error);
    let category = pop_validation_category(&error);
    let error_key = if category == CATEGORY_SIGNATURE {
        "signature_error"
    } else {
        "validation_error"
    };
    context.push(ValidationContextFieldV1::new(error_key, error.to_string()));
    ValidationOutcomeV1::error(
        code,
        category,
        format!("{} validation failed: {error}", kind.schema()),
        pop_validation_action(code),
        vec![
            "sorafs.reference.pop".to_owned(),
            format!("sorafs.reference.pop.{}", kind.tag()),
            format!("sorafs.reference.code.{code}"),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn pop_validation_action(code: &str) -> &'static str {
    match code {
        "SFS-NORITO-001" => "Re-encode the PoP payload with the canonical SoraFS Norito schema.",
        "SFS-VAL-001" => {
            "Regenerate the PoP payload from canonical issuer or juror-client state with non-zero digests and valid text fields."
        }
        "SFS-VAL-002" => "Regenerate the PoP payload with the supported V1 schema.",
        "SFS-POP-001" => {
            "Regenerate the PoP proof or publication from the same active credential, commitment root, and revocation list snapshot."
        }
        "SFS-POL-010" => {
            "Refresh the PoP credential, proof, or revocation snapshot before submitting the payload."
        }
        "SFS-SIG-009" => {
            "Resign the PoP credential, commitment root, or revocation list with the governed issuer Ed25519 key."
        }
        "SFS-INT-001" => {
            "Retry validation after checking the local validator build and Norito encoder."
        }
        _ => "Regenerate the PoP payload from canonical SoraFS state and retry validation.",
    }
}
fn hedging_validation_error_outcome(
    kind: HedgingValidationPayloadKindV1,
    error: HedgingValidationError,
    mut context: Vec<ValidationContextFieldV1>,
    inputs: Vec<ValidationInputV1>,
    generated_at: u64,
) -> ValidationOutcomeV1 {
    let code = hedging_validation_code(&error);
    let category = hedging_validation_category(&error);
    let error_key = if category == CATEGORY_INTERNAL {
        "internal_error"
    } else {
        "validation_error"
    };
    context.push(ValidationContextFieldV1::new(error_key, error.to_string()));
    ValidationOutcomeV1::error(
        code,
        category,
        format!("{} validation failed: {error}", kind.schema()),
        hedging_validation_action(code),
        vec![
            "sorafs.reference.hedging".to_owned(),
            format!("sorafs.reference.hedging.{}", kind.tag()),
            format!("sorafs.reference.code.{code}"),
        ],
        context,
        inputs,
        generated_at,
    )
}
fn hedging_validation_action(code: &str) -> &'static str {
    match code {
        "SFS-NORITO-001" => {
            "Re-encode the hedging or billing payload with the canonical SoraFS Norito schema."
        }
        "SFS-VAL-001" => {
            "Regenerate the hedging or billing payload from canonical feed, pricing, or statement state with non-zero ids, digests, prices, and amounts."
        }
        "SFS-VAL-002" => "Regenerate the hedging or billing payload with the supported V1 schema.",
        "SFS-POL-020" => {
            "Refresh the feed, decision, or billing window so timestamps and feed policy match the active SoraFS hedging policy."
        }
        "SFS-HDG-001" => {
            "Replay the reference-price or billing statement calculation and regenerate ids, totals, and USD equivalents from canonical inputs."
        }
        "SFS-INT-001" => {
            "Retry validation after checking the local validator build, Norito encoder, and amount ranges."
        }
        _ => {
            "Regenerate the hedging or billing payload from canonical SoraFS state and retry validation."
        }
    }
}
fn advert_validation_code(error: &AdvertValidationError) -> &'static str {
    match error {
        AdvertValidationError::UnsupportedVersion(_) => "SFS-VAL-002",
        AdvertValidationError::UnknownProfileHandle { .. }
        | AdvertValidationError::MissingProfileAliases
        | AdvertValidationError::InvalidProfileAlias
        | AdvertValidationError::MissingRequiredAlias { .. }
        | AdvertValidationError::DuplicateProfileAlias { .. } => "SFS-VAL-003",
        AdvertValidationError::InvalidTimestamps
        | AdvertValidationError::TtlOutOfRange { .. }
        | AdvertValidationError::IssuedInFuture { .. }
        | AdvertValidationError::Expired { .. } => "SFS-POL-001",
        _ => "SFS-VAL-004",
    }
}
fn orderbook_validation_code(error: &OrderbookValidationError) -> &'static str {
    match error {
        OrderbookValidationError::UnsupportedOrderVersion { .. }
        | OrderbookValidationError::UnsupportedCancelVersion { .. }
        | OrderbookValidationError::UnsupportedTradeVersion { .. }
        | OrderbookValidationError::UnsupportedChannelVersion { .. }
        | OrderbookValidationError::UnsupportedReceiptVersion { .. } => "SFS-VAL-002",
        OrderbookValidationError::InvalidOrderId
        | OrderbookValidationError::InvalidMakerOrderId
        | OrderbookValidationError::InvalidTakerOrderId
        | OrderbookValidationError::InvalidTradeId
        | OrderbookValidationError::InvalidChannelId
        | OrderbookValidationError::InvalidReceiptId
        | OrderbookValidationError::InvalidChunkHash
        | OrderbookValidationError::InvalidProviderId
        | OrderbookValidationError::EmptyOwnerAccount
        | OrderbookValidationError::OwnerAccountTooLong { .. } => "SFS-VAL-001",
        OrderbookValidationError::InvalidTimestamp
        | OrderbookValidationError::ZeroNonce
        | OrderbookValidationError::InvalidFeeBps { .. }
        | OrderbookValidationError::ExpiredOrder { .. }
        | OrderbookValidationError::SettlementChannelNotOpen { .. } => "SFS-POL-007",
        OrderbookValidationError::InvalidSignature
        | OrderbookValidationError::InvalidPublicKeyLength { .. }
        | OrderbookValidationError::InvalidSignatureLength { .. }
        | OrderbookValidationError::UnsupportedSignatureAlgorithm { .. }
        | OrderbookValidationError::InvalidPublicKey { .. }
        | OrderbookValidationError::SignaturePayloadEncoding { .. }
        | OrderbookValidationError::SignatureVerification { .. } => "SFS-SIG-007",
        OrderbookValidationError::SettlementImbalance { .. }
        | OrderbookValidationError::ReceiptExceedsChannelBytes { .. }
        | OrderbookValidationError::ReceiptExceedsRemainingBytes { .. }
        | OrderbookValidationError::ReceiptExceedsEscrow { .. }
        | OrderbookValidationError::Amount(_) => "SFS-OBK-002",
        _ => "SFS-OBK-001",
    }
}
fn pop_validation_code(error: &PopCredentialValidationError) -> &'static str {
    match error {
        PopCredentialValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PopCredentialValidationError::InvalidDigest { .. }
        | PopCredentialValidationError::EmptyText { .. }
        | PopCredentialValidationError::InvalidText { .. }
        | PopCredentialValidationError::DuplicateAttribute { .. }
        | PopCredentialValidationError::DuplicateRequestedAttribute { .. }
        | PopCredentialValidationError::DuplicateDigest { .. }
        | PopCredentialValidationError::InvalidVersionCounter { .. }
        | PopCredentialValidationError::InvalidTreeDepth { .. }
        | PopCredentialValidationError::InvalidMerklePathDepth { .. }
        | PopCredentialValidationError::ResourceLimitExceeded { .. }
        | PopCredentialValidationError::InvalidScalarEncoding { .. }
        | PopCredentialValidationError::InvalidRevocationNonceEncoding
        | PopCredentialValidationError::UnsortedRevocationList
        | PopCredentialValidationError::DuplicateRevocationNonce => "SFS-VAL-001",
        PopCredentialValidationError::InvalidTimestamp { .. }
        | PopCredentialValidationError::InvalidValidityWindow { .. }
        | PopCredentialValidationError::InvalidRenewalEpoch { .. }
        | PopCredentialValidationError::ExpiredCredential { .. }
        | PopCredentialValidationError::ExpiredProof { .. }
        | PopCredentialValidationError::StaleRevocationList { .. }
        | PopCredentialValidationError::RevocationListVersionMismatch { .. }
        | PopCredentialValidationError::RevokedCredential
        | PopCredentialValidationError::ReplayedProof
        | PopCredentialValidationError::ReplayCacheLimitExceeded
        | PopCredentialValidationError::ChallengeMismatch
        | PopCredentialValidationError::VerifierContextMismatch
        | PopCredentialValidationError::PresentationBindingMismatch => "SFS-POL-010",
        PopCredentialValidationError::ProofHolderCommitmentMismatch
        | PopCredentialValidationError::WrongCommitmentRoot
        | PopCredentialValidationError::RevocationRootMismatch
        | PopCredentialValidationError::CommitmentTreeVersionMismatch
        | PopCredentialValidationError::IssuerMismatch
        | PopCredentialValidationError::IssuerKeyMismatch
        | PopCredentialValidationError::CredentialRevocationListMismatch
        | PopCredentialValidationError::InvalidVerifierMaterial { .. }
        | PopCredentialValidationError::InvalidMembershipProof { .. } => "SFS-POP-001",
        PopCredentialValidationError::InvalidPublicKeyLength { .. }
        | PopCredentialValidationError::InvalidSignatureLength { .. }
        | PopCredentialValidationError::InvalidPublicKey { .. }
        | PopCredentialValidationError::SignatureVerification { .. } => "SFS-SIG-009",
        PopCredentialValidationError::SignaturePayloadEncoding { .. }
        | PopCredentialValidationError::ProofBackend { .. } => "SFS-INT-001",
    }
}
fn hedging_validation_code(error: &HedgingValidationError) -> &'static str {
    match error {
        HedgingValidationError::UnsupportedPriceFeedVersion { .. }
        | HedgingValidationError::UnsupportedReferencePriceDecisionVersion { .. }
        | HedgingValidationError::UnsupportedBillingLineVersion { .. }
        | HedgingValidationError::UnsupportedBillingStatementVersion { .. } => "SFS-VAL-002",
        HedgingValidationError::InvalidText { .. }
        | HedgingValidationError::TextTooLong { .. }
        | HedgingValidationError::ResourceLimitExceeded { .. }
        | HedgingValidationError::NonCanonicalOrder { .. }
        | HedgingValidationError::InvalidDigest { .. }
        | HedgingValidationError::InvalidTimestamp { .. }
        | HedgingValidationError::InvalidBasisPoints { .. }
        | HedgingValidationError::NoPriceFeeds
        | HedgingValidationError::DuplicateFeedId { .. }
        | HedgingValidationError::DuplicateFeedSource { .. }
        | HedgingValidationError::InvalidFeedWeightSum { .. }
        | HedgingValidationError::ZeroMaxFeedAge
        | HedgingValidationError::ZeroReferencePrice
        | HedgingValidationError::DuplicateDegradationReason
        | HedgingValidationError::ZeroBillingAmount
        | HedgingValidationError::ZeroBillingQuantity
        | HedgingValidationError::BillingLineDirectionMismatch
        | HedgingValidationError::ZeroUsdAmount
        | HedgingValidationError::NegativeAmount
        | HedgingValidationError::AmountScaleOverflow { .. }
        | HedgingValidationError::InexactAmountPrecision
        | HedgingValidationError::EmptyAccountId
        | HedgingValidationError::NoBillingLines
        | HedgingValidationError::DuplicateLineId
        | HedgingValidationError::DuplicateBillingSource { .. }
        | HedgingValidationError::SelfReferentialStatement => "SFS-VAL-001",
        HedgingValidationError::RejectedFeed { .. }
        | HedgingValidationError::FutureFeed { .. }
        | HedgingValidationError::StaleFeed { .. }
        | HedgingValidationError::InvalidPeriod
        | HedgingValidationError::InvalidDueAt
        | HedgingValidationError::ReferencePriceOutsidePeriod { .. }
        | HedgingValidationError::PreviousStatementMismatch
        | HedgingValidationError::StatementAccountMismatch
        | HedgingValidationError::NonContiguousStatementPeriod { .. }
        | HedgingValidationError::UnexpectedInitialStatementPredecessor
        | HedgingValidationError::CreditsExceedDebits => "SFS-POL-020",
        HedgingValidationError::ReferencePriceMismatch { .. }
        | HedgingValidationError::DegradationMismatch
        | HedgingValidationError::BillingTotalsMismatch
        | HedgingValidationError::BillingLineUsdMismatch { .. }
        | HedgingValidationError::DigestMismatch { .. } => "SFS-HDG-001",
        HedgingValidationError::AmountOverflow
        | HedgingValidationError::AmountUnderflow
        | HedgingValidationError::Numeric(_)
        | HedgingValidationError::LengthOverflow
        | HedgingValidationError::AllocationFailed { .. }
        | HedgingValidationError::Norito(_) => "SFS-INT-001",
    }
}
fn repair_validation_code(error: &RepairValidationError) -> &'static str {
    match error {
        RepairValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        RepairValidationError::EmptyString {
            field: "manifest_digest" | "provider_id" | "challenge_id",
        } => "SFS-VAL-001",
        RepairValidationError::InvalidSamples
        | RepairValidationError::InvalidLatency
        | RepairValidationError::InvalidMissingChunks => "SFS-REP-001",
        RepairValidationError::InvalidTimestamp { .. }
        | RepairValidationError::InvalidTimestampOrder { .. } => "SFS-POL-005",
        RepairValidationError::InvalidPenalty
        | RepairValidationError::InvalidQuorumBps { .. }
        | RepairValidationError::InvalidMinimumVoters
        | RepairValidationError::InvalidVoteCount => "SFS-GOV-002",
        _ => "SFS-REP-002",
    }
}
fn pdp_commitment_validation_code(error: &PdpCommitmentValidationError) -> &'static str {
    match error {
        PdpCommitmentValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PdpCommitmentValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PdpCommitmentValidationError::InvalidChunkProfile(_) => "SFS-VAL-003",
        PdpCommitmentValidationError::InvalidSampleWindow { .. } => "SFS-PDP-001",
        PdpCommitmentValidationError::InvalidSealedAt => "SFS-POL-002",
        _ => "SFS-PDP-002",
    }
}
fn pdp_challenge_validation_code(error: &PdpChallengeValidationError) -> &'static str {
    match error {
        PdpChallengeValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PdpChallengeValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PdpChallengeValidationError::InvalidChunkProfile(_) => "SFS-VAL-003",
        PdpChallengeValidationError::InvalidDeadline { .. } => "SFS-POL-002",
        PdpChallengeValidationError::EmptySampleSet
        | PdpChallengeValidationError::TooManySegments { .. }
        | PdpChallengeValidationError::NonCanonicalSegmentOrder
        | PdpChallengeValidationError::EmptyHotLeafSet { .. }
        | PdpChallengeValidationError::TooManyHotLeaves { .. }
        | PdpChallengeValidationError::HotLeafIndexOutOfRange { .. }
        | PdpChallengeValidationError::NonCanonicalHotLeafOrder { .. }
        | PdpChallengeValidationError::TooManyHotLeavesTotal { .. } => "SFS-PDP-001",
        PdpChallengeValidationError::InvalidChallengeId
        | PdpChallengeValidationError::InvalidCommitmentDigest
        | PdpChallengeValidationError::InvalidProviderId
        | PdpChallengeValidationError::InvalidSeed
        | PdpChallengeValidationError::InvalidEpoch
        | PdpChallengeValidationError::InvalidDrandRound
        | PdpChallengeValidationError::ChallengeIdMismatch
        | PdpChallengeValidationError::CanonicalEncoding => "SFS-PDP-002",
    }
}
fn pdp_proof_validation_code(error: &PdpProofValidationError) -> &'static str {
    match error {
        PdpProofValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PdpProofValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PdpProofValidationError::InvalidSignature(_) => "SFS-SIG-008",
        PdpProofValidationError::InvalidIssuedAt => "SFS-POL-002",
        PdpProofValidationError::EmptyProofSet
        | PdpProofValidationError::TooManySegments { .. }
        | PdpProofValidationError::NonCanonicalSegmentOrder
        | PdpProofValidationError::InvalidSegmentLength { .. }
        | PdpProofValidationError::InvalidSegmentOffset { .. }
        | PdpProofValidationError::MissingHotLeafProofs { .. }
        | PdpProofValidationError::TooManyHotLeafProofs { .. }
        | PdpProofValidationError::HotLeafIndexOutOfRange { .. }
        | PdpProofValidationError::NonCanonicalHotLeafOrder { .. }
        | PdpProofValidationError::InvalidLeafLength { .. }
        | PdpProofValidationError::LeafByteLengthMismatch { .. }
        | PdpProofValidationError::InvalidLeafOffset { .. }
        | PdpProofValidationError::MerklePathTooDeep { .. }
        | PdpProofValidationError::TooManyHotLeavesTotal { .. } => "SFS-PDP-001",
        PdpProofValidationError::InvalidCommitmentDigest
        | PdpProofValidationError::InvalidChallengeId
        | PdpProofValidationError::InvalidProviderId
        | PdpProofValidationError::InvalidEpoch
        | PdpProofValidationError::GeometryOverflow
        | PdpProofValidationError::CanonicalEncoding => "SFS-PDP-002",
    }
}
fn pdp_verification_code_and_category(
    error: &PdpVerificationError,
) -> (&'static str, &'static str) {
    match error {
        PdpVerificationError::Commitment(error) => (
            pdp_commitment_validation_code(error),
            pdp_commitment_validation_category(error),
        ),
        PdpVerificationError::Challenge(error) => (
            pdp_challenge_validation_code(error),
            pdp_challenge_validation_category(error),
        ),
        PdpVerificationError::Proof(error) => (
            pdp_proof_validation_code(error),
            pdp_proof_validation_category(error),
        ),
        PdpVerificationError::AdmissionNotCouncilVerified
        | PdpVerificationError::AdmissionProviderMismatch => {
            (PDP_TRUST_REQUIRED_CODE, CATEGORY_POLICY)
        }
        PdpVerificationError::AdmissionKeyMismatch | PdpVerificationError::Signature(_) => {
            ("SFS-SIG-008", CATEGORY_SIGNATURE)
        }
        PdpVerificationError::AdmissionNotActiveAtChallenge { .. }
        | PdpVerificationError::ChallengeBeyondAdmission { .. }
        | PdpVerificationError::AdmissionExpiredAtProof { .. }
        | PdpVerificationError::ProofOutsideChallengeWindow { .. }
        | PdpVerificationError::CommitmentSealedAfterChallenge { .. } => {
            ("SFS-POL-002", CATEGORY_POLICY)
        }
        PdpVerificationError::CommitmentDigestEncoding { .. }
        | PdpVerificationError::ProofDigestEncoding { .. }
        | PdpVerificationError::CoverageOverflow => ("SFS-INT-001", CATEGORY_INTERNAL),
        PdpVerificationError::SampleWindowExceeded { .. }
        | PdpVerificationError::SegmentCoverageCountMismatch { .. }
        | PdpVerificationError::SegmentCoverageMismatch { .. }
        | PdpVerificationError::HotLeafCoverageCountMismatch { .. }
        | PdpVerificationError::HotLeafCoverageMismatch { .. }
        | PdpVerificationError::SegmentOutOfRange { .. }
        | PdpVerificationError::HotLeafOutOfRange { .. }
        | PdpVerificationError::SegmentGeometryMismatch { .. }
        | PdpVerificationError::HotLeafGeometryMismatch { .. }
        | PdpVerificationError::GeometryOverflow
        | PdpVerificationError::SegmentHotPath { .. }
        | PdpVerificationError::GlobalHotPath { .. }
        | PdpVerificationError::SegmentPath { .. } => ("SFS-PDP-001", CATEGORY_VALIDATION),
        _ => ("SFS-PDP-003", CATEGORY_VALIDATION),
    }
}
fn por_challenge_validation_code(error: &PorChallengeValidationError) -> &'static str {
    match error {
        PorChallengeValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PorChallengeValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PorChallengeValidationError::UnknownChunkerHandle { .. } => "SFS-VAL-003",
        PorChallengeValidationError::InvalidDeadline { .. } => "SFS-POL-002",
        PorChallengeValidationError::ZeroSampleCount
        | PorChallengeValidationError::SampleCountMismatch { .. } => "SFS-POR-001",
        _ => "SFS-VAL-008",
    }
}
fn por_proof_validation_code(error: &PorProofValidationError) -> &'static str {
    match error {
        PorProofValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PorProofValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PorProofValidationError::MissingSamples => "SFS-POR-001",
        _ => "SFS-VAL-009",
    }
}
fn potr_receipt_validation_code(error: &PotrReceiptValidationError) -> &'static str {
    match error {
        PotrReceiptValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        PotrReceiptValidationError::InvalidManifestDigest => "SFS-VAL-001",
        PotrReceiptValidationError::LatencyExceedsDeadline { .. } => "SFS-POTR-001",
        PotrReceiptValidationError::InvalidSignature { .. } => "SFS-SIG-003",
        _ => "SFS-VAL-010",
    }
}
fn provider_admission_envelope_code(error: &ProviderAdmissionEnvelopeError) -> &'static str {
    match error {
        ProviderAdmissionEnvelopeError::NonInitialEvent { .. } => "SFS-VAL-007",
        ProviderAdmissionEnvelopeError::Validation(error) => {
            provider_admission_validation_code(error)
        }
        ProviderAdmissionEnvelopeError::Signature(_) => "SFS-SIG-002",
        ProviderAdmissionEnvelopeError::Serialization { .. } => "SFS-INT-001",
    }
}
fn provider_admission_renewal_code(error: &ProviderAdmissionRenewalError) -> &'static str {
    match error {
        ProviderAdmissionRenewalError::UnsupportedVersion { .. } => "SFS-VAL-002",
        ProviderAdmissionRenewalError::Envelope(error) => provider_admission_envelope_code(error),
        ProviderAdmissionRenewalError::EnvelopeDigestMismatch { .. }
        | ProviderAdmissionRenewalError::PreviousDigestMismatch { .. }
        | ProviderAdmissionRenewalError::SignedPredecessorMismatch
        | ProviderAdmissionRenewalError::AdmissionRevisionMismatch
        | ProviderAdmissionRenewalError::PolicyLineageMismatch
        | ProviderAdmissionRenewalError::NetworkMismatch { .. }
        | ProviderAdmissionRenewalError::ProviderMismatch { .. } => "SFS-VAL-007",
        ProviderAdmissionRenewalError::RetentionNotExtended { .. }
        | ProviderAdmissionRenewalError::IssuedAtRegression { .. } => "SFS-POL-004",
        ProviderAdmissionRenewalError::UntrustedBaseRecord
        | ProviderAdmissionRenewalError::ProfileIdChanged { .. }
        | ProviderAdmissionRenewalError::ProfileAliasesChanged
        | ProviderAdmissionRenewalError::CapabilitiesChanged
        | ProviderAdmissionRenewalError::AdvertKeyChanged
        | ProviderAdmissionRenewalError::PorVrfKeyChanged => "SFS-VAL-006",
    }
}
fn provider_admission_revocation_code(error: &ProviderAdmissionRevocationError) -> &'static str {
    match error {
        ProviderAdmissionRevocationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        ProviderAdmissionRevocationError::ProviderMismatch { .. }
        | ProviderAdmissionRevocationError::NetworkMismatch { .. }
        | ProviderAdmissionRevocationError::SignedPredecessorMismatch
        | ProviderAdmissionRevocationError::AdmissionRevisionMismatch
        | ProviderAdmissionRevocationError::PolicyLineageMismatch
        | ProviderAdmissionRevocationError::EnvelopeDigestMismatch { .. } => "SFS-VAL-007",
        ProviderAdmissionRevocationError::InvalidNetworkId
        | ProviderAdmissionRevocationError::InvalidPolicyBinding
        | ProviderAdmissionRevocationError::InvalidEventLineage
        | ProviderAdmissionRevocationError::ReasonEmpty => "SFS-VAL-006",
        ProviderAdmissionRevocationError::MissingSignatures
        | ProviderAdmissionRevocationError::Signature(_) => "SFS-SIG-002",
        ProviderAdmissionRevocationError::Serialization(_) => "SFS-INT-001",
    }
}
fn provider_admission_validation_code(error: &ProviderAdmissionValidationError) -> &'static str {
    match error {
        ProviderAdmissionValidationError::UnsupportedProposalVersion { .. }
        | ProviderAdmissionValidationError::UnsupportedEnvelopeVersion { .. } => "SFS-VAL-002",
        ProviderAdmissionValidationError::UnknownChunkerHandle { .. }
        | ProviderAdmissionValidationError::NonCanonicalProfileHandle { .. }
        | ProviderAdmissionValidationError::MissingCanonicalAlias { .. }
        | ProviderAdmissionValidationError::InvalidProfileAliases
        | ProviderAdmissionValidationError::UnknownProfileAlias { .. } => "SFS-VAL-003",
        ProviderAdmissionValidationError::ProposalDigestMismatch
        | ProviderAdmissionValidationError::AdvertDigestMismatch => "SFS-VAL-007",
        ProviderAdmissionValidationError::MissingCouncilSignatures => "SFS-SIG-002",
        ProviderAdmissionValidationError::InvalidRetentionEpoch { .. } => "SFS-POL-004",
        _ => "SFS-VAL-006",
    }
}
fn replication_order_validation_code(error: &ReplicationOrderValidationError) -> &'static str {
    match error {
        ReplicationOrderValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        ReplicationOrderValidationError::InvalidManifestDigest => "SFS-VAL-001",
        ReplicationOrderValidationError::InvalidManifestCidLength { .. }
        | ReplicationOrderValidationError::InertManifestCid
        | ReplicationOrderValidationError::MalformedManifestCid { .. } => "SFS-VAL-005",
        ReplicationOrderValidationError::UnknownChunkerHandle { .. }
        | ReplicationOrderValidationError::NonCanonicalProfileHandle { .. } => "SFS-VAL-003",
        ReplicationOrderValidationError::InvalidDeadline
        | ReplicationOrderValidationError::SlaInvalid(_) => "SFS-POL-003",
        _ => "SFS-VAL-005",
    }
}
fn signed_replication_order_validation_code(
    error: &SignedReplicationOrderValidationError,
) -> &'static str {
    match error {
        SignedReplicationOrderValidationError::UnsupportedVersion { .. } => "SFS-VAL-002",
        SignedReplicationOrderValidationError::Order(error) => {
            replication_order_validation_code(error)
        }
        SignedReplicationOrderValidationError::InvalidSignature => "SFS-SIG-006",
    }
}
fn replication_order_signature_verification_code(
    error: &ReplicationOrderSignatureVerificationError,
) -> &'static str {
    match error {
        ReplicationOrderSignatureVerificationError::PayloadEncoding { .. } => "SFS-INT-001",
        ReplicationOrderSignatureVerificationError::UnsupportedAlgorithm(_)
        | ReplicationOrderSignatureVerificationError::InvalidPublicKeyLength { .. }
        | ReplicationOrderSignatureVerificationError::InvalidSignatureLength { .. }
        | ReplicationOrderSignatureVerificationError::InvalidPublicKey { .. }
        | ReplicationOrderSignatureVerificationError::Verification { .. } => "SFS-SIG-006",
    }
}
fn repair_validation_category(error: &RepairValidationError) -> &'static str {
    match error {
        RepairValidationError::InvalidTimestamp { .. }
        | RepairValidationError::InvalidTimestampOrder { .. }
        | RepairValidationError::InvalidPenalty
        | RepairValidationError::InvalidQuorumBps { .. }
        | RepairValidationError::InvalidMinimumVoters
        | RepairValidationError::InvalidVoteCount => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn pdp_commitment_validation_category(error: &PdpCommitmentValidationError) -> &'static str {
    match error {
        PdpCommitmentValidationError::InvalidSealedAt => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn pdp_challenge_validation_category(error: &PdpChallengeValidationError) -> &'static str {
    match error {
        PdpChallengeValidationError::InvalidDeadline { .. } => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn pdp_proof_validation_category(error: &PdpProofValidationError) -> &'static str {
    match error {
        PdpProofValidationError::InvalidSignature(_) => CATEGORY_SIGNATURE,
        _ => CATEGORY_VALIDATION,
    }
}
fn advert_validation_category(error: &AdvertValidationError) -> &'static str {
    match error {
        AdvertValidationError::InvalidTimestamps
        | AdvertValidationError::TtlOutOfRange { .. }
        | AdvertValidationError::IssuedInFuture { .. }
        | AdvertValidationError::Expired { .. } => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn orderbook_validation_category(error: &OrderbookValidationError) -> &'static str {
    match error {
        OrderbookValidationError::InvalidTimestamp
        | OrderbookValidationError::ZeroNonce
        | OrderbookValidationError::InvalidFeeBps { .. }
        | OrderbookValidationError::ExpiredOrder { .. }
        | OrderbookValidationError::SettlementChannelNotOpen { .. } => CATEGORY_POLICY,
        OrderbookValidationError::InvalidSignature
        | OrderbookValidationError::InvalidPublicKeyLength { .. }
        | OrderbookValidationError::InvalidSignatureLength { .. }
        | OrderbookValidationError::UnsupportedSignatureAlgorithm { .. }
        | OrderbookValidationError::InvalidPublicKey { .. }
        | OrderbookValidationError::SignaturePayloadEncoding { .. }
        | OrderbookValidationError::SignatureVerification { .. } => CATEGORY_SIGNATURE,
        _ => CATEGORY_VALIDATION,
    }
}
fn pop_validation_category(error: &PopCredentialValidationError) -> &'static str {
    match error {
        PopCredentialValidationError::InvalidTimestamp { .. }
        | PopCredentialValidationError::InvalidValidityWindow { .. }
        | PopCredentialValidationError::InvalidRenewalEpoch { .. }
        | PopCredentialValidationError::ExpiredCredential { .. }
        | PopCredentialValidationError::ExpiredProof { .. }
        | PopCredentialValidationError::StaleRevocationList { .. }
        | PopCredentialValidationError::RevocationListVersionMismatch { .. }
        | PopCredentialValidationError::RevokedCredential
        | PopCredentialValidationError::ReplayedProof
        | PopCredentialValidationError::ReplayCacheLimitExceeded
        | PopCredentialValidationError::ChallengeMismatch
        | PopCredentialValidationError::VerifierContextMismatch
        | PopCredentialValidationError::PresentationBindingMismatch => CATEGORY_POLICY,
        PopCredentialValidationError::InvalidPublicKeyLength { .. }
        | PopCredentialValidationError::InvalidSignatureLength { .. }
        | PopCredentialValidationError::InvalidPublicKey { .. }
        | PopCredentialValidationError::SignatureVerification { .. } => CATEGORY_SIGNATURE,
        PopCredentialValidationError::SignaturePayloadEncoding { .. }
        | PopCredentialValidationError::ProofBackend { .. } => CATEGORY_INTERNAL,
        _ => CATEGORY_VALIDATION,
    }
}
fn hedging_validation_category(error: &HedgingValidationError) -> &'static str {
    match error {
        HedgingValidationError::RejectedFeed { .. }
        | HedgingValidationError::FutureFeed { .. }
        | HedgingValidationError::StaleFeed { .. }
        | HedgingValidationError::InvalidPeriod
        | HedgingValidationError::InvalidDueAt => CATEGORY_POLICY,
        HedgingValidationError::AmountOverflow
        | HedgingValidationError::AmountUnderflow
        | HedgingValidationError::Norito(_) => CATEGORY_INTERNAL,
        _ => CATEGORY_VALIDATION,
    }
}
fn por_challenge_validation_category(error: &PorChallengeValidationError) -> &'static str {
    match error {
        PorChallengeValidationError::InvalidDeadline { .. } => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn potr_receipt_validation_category(error: &PotrReceiptValidationError) -> &'static str {
    match error {
        PotrReceiptValidationError::LatencyExceedsDeadline { .. } => CATEGORY_POLICY,
        PotrReceiptValidationError::InvalidSignature { .. } => CATEGORY_SIGNATURE,
        _ => CATEGORY_VALIDATION,
    }
}
fn provider_admission_envelope_category(error: &ProviderAdmissionEnvelopeError) -> &'static str {
    match error {
        ProviderAdmissionEnvelopeError::NonInitialEvent { .. } => CATEGORY_VALIDATION,
        ProviderAdmissionEnvelopeError::Validation(error) => {
            provider_admission_validation_category(error)
        }
        ProviderAdmissionEnvelopeError::Signature(_) => CATEGORY_SIGNATURE,
        ProviderAdmissionEnvelopeError::Serialization { .. } => CATEGORY_INTERNAL,
    }
}
fn provider_admission_renewal_category(error: &ProviderAdmissionRenewalError) -> &'static str {
    match error {
        ProviderAdmissionRenewalError::Envelope(error) => {
            provider_admission_envelope_category(error)
        }
        ProviderAdmissionRenewalError::RetentionNotExtended { .. }
        | ProviderAdmissionRenewalError::IssuedAtRegression { .. } => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn provider_admission_revocation_category(
    error: &ProviderAdmissionRevocationError,
) -> &'static str {
    match error {
        ProviderAdmissionRevocationError::MissingSignatures
        | ProviderAdmissionRevocationError::Signature(_) => CATEGORY_SIGNATURE,
        ProviderAdmissionRevocationError::Serialization(_) => CATEGORY_INTERNAL,
        _ => CATEGORY_VALIDATION,
    }
}
fn provider_admission_validation_category(
    error: &ProviderAdmissionValidationError,
) -> &'static str {
    match error {
        ProviderAdmissionValidationError::MissingCouncilSignatures => CATEGORY_SIGNATURE,
        ProviderAdmissionValidationError::InvalidRetentionEpoch { .. } => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn replication_order_validation_category(error: &ReplicationOrderValidationError) -> &'static str {
    match error {
        ReplicationOrderValidationError::InvalidDeadline
        | ReplicationOrderValidationError::SlaInvalid(_) => CATEGORY_POLICY,
        _ => CATEGORY_VALIDATION,
    }
}
fn signed_replication_order_validation_category(
    error: &SignedReplicationOrderValidationError,
) -> &'static str {
    match error {
        SignedReplicationOrderValidationError::UnsupportedVersion { .. } => CATEGORY_VALIDATION,
        SignedReplicationOrderValidationError::Order(error) => {
            replication_order_validation_category(error)
        }
        SignedReplicationOrderValidationError::InvalidSignature => CATEGORY_SIGNATURE,
    }
}
fn replication_order_signature_verification_category(
    error: &ReplicationOrderSignatureVerificationError,
) -> &'static str {
    match error {
        ReplicationOrderSignatureVerificationError::PayloadEncoding { .. } => CATEGORY_INTERNAL,
        _ => CATEGORY_SIGNATURE,
    }
}
#[cfg(test)]
mod tests {
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signer, SigningKey};
    use iroha_crypto::{Algorithm, KeyPair, Signature as IrohaSignature};
    use norito::{
        NoritoDeserialize as Deserialize, NoritoSerialize as Serialize, decode_from_bytes, to_bytes,
    };
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::{
        AdvertEndpoint, AdvertSignature, AvailabilityTier, CapabilityTlv, CapabilityType,
        EndpointKind, EndpointMetadata, EndpointMetadataKey, PathDiversityPolicy,
        PotrSignatureAlgorithm, PotrSignatureV1, ProviderAdvertBodyV1, ProviderCapabilityRangeV1,
        QosHints, REFRESH_RECOMMENDATION_SECS, REPAIR_EVIDENCE_VERSION_V1, RendezvousTopic,
        RepairCauseV1, RepairEvidenceV1, RepairPdpFailureCauseV1, RepairPdpFailureKindV1,
        RepairPorFailureCauseV1, RepairTaskRecordV1, SignatureAlgorithm, StakePointer,
    };
    use FixtureBundlePayloadKindV1 as BundleKind;
    use HedgingValidationPayloadKindV1 as HedgingKind;
    use OrderbookValidationPayloadKindV1 as OrderbookKind;
    use PopValidationPayloadKindV1 as PopKind;
    use RepairValidationPayloadKindV1 as RepairKind;
    type Outcome = ValidationOutcomeV1;

    fn encoded(value: &impl Serialize) -> Vec<u8> {
        to_bytes(value).expect("encode reference-test payload")
    }

    fn fixture_bytes(path: &str) -> Vec<u8> {
        let absolute = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        fs::read(absolute).unwrap_or_else(|error| panic!("read `{path}`: {error}"))
    }

    fn fixture<T>(path: &str) -> T
    where
        for<'de> T: Deserialize<'de> + norito::NoritoSerialize,
    {
        decode_from_bytes(&fixture_bytes(path))
            .unwrap_or_else(|error| panic!("decode `{path}`: {error}"))
    }

    fn governance_fixture_bytes(name: &str) -> Vec<u8> {
        fixture_bytes(&format!("fixtures/sorafs_manifest/governance/{name}"))
    }

    fn committed_governance_chain_outcome(head_name: &str, block_names: &[&str]) -> Outcome {
        let head = governance_fixture_bytes(head_name);
        let blocks = block_names
            .iter()
            .map(|name| governance_fixture_bytes(name))
            .collect::<Vec<_>>();
        let inputs = blocks
            .iter()
            .zip(block_names)
            .map(|(bytes, name)| (bytes.as_slice(), (*name).to_owned()))
            .collect::<Vec<_>>();
        validate_governance_dag_head_chain_bytes(&head, head_name, &inputs, 123)
    }

    fn assert_committed_governance_outcome(outcome: &Outcome, expected_name: &str) {
        let actual = format!(
            "{}\n",
            norito::json::to_string_pretty(outcome).expect("encode outcome JSON")
        );
        let expected = String::from_utf8(governance_fixture_bytes(expected_name))
            .expect("outcome fixture is UTF-8");
        assert_eq!(actual, expected);
    }

    fn assert_success(outcome: &Outcome) {
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(outcome.code, "SFS-OK-000", "{outcome:?}");
    }

    fn assert_failure(outcome: &Outcome, code: &str, category: &str) {
        assert!(!outcome.is_ok(), "{outcome:?}");
        assert_eq!(outcome.code, code, "{outcome:?}");
        assert_eq!(outcome.category, category, "{outcome:?}");
    }

    fn assert_roundtrip(outcome: &Outcome) {
        let roundtrip: Outcome =
            decode_from_bytes(&encoded(outcome)).expect("decode validation outcome");
        assert_eq!(&roundtrip, outcome);
    }

    fn assert_field(context: &[ValidationContextFieldV1], key: &str, value: impl AsRef<str>) {
        let value = value.as_ref();
        assert!(
            context
                .iter()
                .any(|field| field.key == key && field.value == value),
            "missing `{key}={value}` from {context:?}"
        );
    }

    fn field<'a>(context: &'a [ValidationContextFieldV1], key: &str) -> Option<&'a str> {
        context
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.value.as_str())
    }

    fn assert_context(outcome: &Outcome, key: &str, value: impl AsRef<str>) {
        assert_field(&outcome.context, key, value);
    }

    fn fixture_bundle_outcome(
        payloads: &[(BundleKind, &str, Vec<u8>)],
        now: u64,
        generated_at: u64,
    ) -> Outcome {
        let inputs = payloads
            .iter()
            .map(|(kind, label, bytes)| FixtureBundlePayloadV1::new(*kind, *label, bytes))
            .collect::<Vec<_>>();
        validate_fixture_bundle_payloads(&inputs, now, generated_at)
    }

    fn governance_chain_outcome(
        blocks: &[GovernanceDagBlockV1],
        head: &GovernanceDagHeadV1,
        generated_at: u64,
    ) -> Outcome {
        let head_bytes = encoded(head);
        let block_bytes = blocks.iter().map(encoded).collect::<Vec<_>>();
        let block_inputs = block_bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| (bytes.as_slice(), format!("governance-block-{index}.to")))
            .collect::<Vec<_>>();
        validate_governance_dag_head_chain_bytes(
            &head_bytes,
            "governance-head.to",
            &block_inputs,
            generated_at,
        )
    }

    fn advert_outcome(
        advert: &ProviderAdvertV1,
        path: &str,
        now: u64,
        generated_at: u64,
    ) -> Outcome {
        validate_provider_advert_bytes(&encoded(advert), path, now, generated_at)
    }

    fn admission_outcome(
        envelope: &ProviderAdmissionEnvelopeV1,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_provider_admission_envelope_bytes(&encoded(envelope), path, generated_at)
    }

    fn por_outcome(
        challenge: &PorChallengeV1,
        proof: &PorProofV1,
        challenge_path: &str,
        proof_path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_por_challenge_proof_bytes(
            &encoded(challenge),
            &encoded(proof),
            challenge_path,
            proof_path,
            generated_at,
        )
    }

    fn potr_outcome(
        receipt: &PotrReceiptV1,
        path: &str,
        expected_tier: Option<ProofStreamTier>,
        generated_at: u64,
    ) -> Outcome {
        validate_potr_receipt_bytes(&encoded(receipt), path, expected_tier, generated_at)
    }

    fn repair_outcome(
        kind: RepairKind,
        payload: &impl Serialize,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_repair_payload_bytes(kind, &encoded(payload), path, generated_at)
    }

    fn hedging_outcome(
        kind: HedgingKind,
        payload: &impl Serialize,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_hedging_payload_bytes(kind, &encoded(payload), path, generated_at)
    }

    fn pop_outcome(
        kind: PopKind,
        payload: &impl Serialize,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_pop_payload_bytes(kind, &encoded(payload), path, generated_at)
    }

    fn orderbook_outcome(
        kind: OrderbookKind,
        payload: &impl Serialize,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_orderbook_payload_bytes(kind, &encoded(payload), path, generated_at)
    }

    fn assert_signed_order_request(bytes: &[u8], public_key: &[u8]) {
        let order: OrderRequestV1 = decode_from_bytes(bytes).expect("decode signed order request");
        assert_eq!(order.signature.public_key, public_key);
        crate::verify_order_request_signature_v1(&order).expect("valid order signature");
    }

    fn assert_signed_order_cancel(bytes: &[u8], public_key: &[u8]) {
        let cancel: OrderCancelV1 = decode_from_bytes(bytes).expect("decode signed order cancel");
        assert_eq!(cancel.signature.public_key, public_key);
        crate::verify_order_cancel_signature_v1(&cancel).expect("valid cancel signature");
    }

    fn assert_signed_settlement_receipt(bytes: &[u8], public_key: &[u8]) {
        let receipt: SettlementReceiptV1 =
            decode_from_bytes(bytes).expect("decode signed settlement receipt");
        assert_eq!(receipt.settlement_signature.public_key, public_key);
        crate::verify_settlement_receipt_signature_v1(&receipt).expect("valid receipt signature");
    }

    fn verifying_key(seed: &[u8; 32]) -> Vec<u8> {
        SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    fn micro_xor(value: u128) -> crate::XorQuantity {
        crate::XorQuantity::try_from_micro(value).expect("legacy micro-XOR value is representable")
    }

    fn minimal_order_request_fields(owner_account: Vec<u8>) -> OrderbookOrderRequestFieldsV1 {
        OrderbookOrderRequestFieldsV1 {
            side: OrderSideV1::Bid,
            tier: OrderTierV1::Hot,
            price_per_gib: micro_xor(1),
            quantity_gib: 1,
            remaining_gib: 1,
            owner_account,
            provider_id: None,
            expiry_unix: 1,
            nonce: 1,
            maker_fee_bps: 0,
            taker_fee_bps: 0,
        }
    }

    fn order_cancel_fields(
        order_id: [u8; 32],
        owner_account: Vec<u8>,
        nonce: u64,
    ) -> OrderbookOrderCancelFieldsV1 {
        OrderbookOrderCancelFieldsV1 {
            order_id,
            owner_account,
            reason: OrderCancelReasonV1::OwnerRequested,
            nonce,
        }
    }

    fn settlement_receipt_fields(provider_credit: u128) -> OrderbookSettlementReceiptFieldsV1 {
        OrderbookSettlementReceiptFieldsV1 {
            receipt_id: [0x07; 32],
            channel_id: [0x05; 32],
            trade_id: [0x04; 32],
            range_start: 10,
            range_end: 42,
            chunk_hash: [0x08; 32],
            bytes_delivered: 32,
            xor_debited: micro_xor(100),
            provider_credit: micro_xor(provider_credit),
            fee_amount: micro_xor(10),
            issued_at_unix: 1_800_000_200,
        }
    }

    fn replication_order_outcome(
        order: &ReplicationOrderV1,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_replication_order_bytes(&encoded(order), path, generated_at)
    }

    fn signed_replication_order_outcome(
        order: &SignedReplicationOrderV1,
        path: &str,
        generated_at: u64,
    ) -> Outcome {
        validate_signed_replication_order_bytes(&encoded(order), path, generated_at)
    }
    fn admission_envelope() -> ProviderAdmissionEnvelopeV1 {
        fixture("fixtures/sorafs_manifest/provider_admission/envelope_v1.to")
    }
    fn admission_renewal_bytes() -> Vec<u8> {
        fixture_bytes("fixtures/sorafs_manifest/provider_admission/renewal_v1.to")
    }
    fn admission_revocation_bytes() -> Vec<u8> {
        fixture_bytes("fixtures/sorafs_manifest/provider_admission/revocation_v1.to")
    }
    fn por_challenge() -> PorChallengeV1 {
        fixture("fixtures/sorafs_manifest/por/challenge_v1.to")
    }
    fn por_proof() -> PorProofV1 {
        fixture("fixtures/sorafs_manifest/por/proof_v1.to")
    }
    fn governance_node() -> GovernanceLogNodeV1 {
        fixture("fixtures/sorafs_manifest/governance/node_v1.to")
    }

    fn ed25519_governance_signature(
        payload: &[u8],
        seed: &[u8; 32],
    ) -> crate::GovernanceLogSignatureV1 {
        let key = SigningKey::from_bytes(seed);
        crate::GovernanceLogSignatureV1 {
            algorithm: GovernanceSignatureAlgorithm::Ed25519,
            public_key: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(payload).to_bytes().to_vec(),
        }
    }
    fn ed25519_signed_governance_node() -> GovernanceLogNodeV1 {
        let mut node = governance_node();
        let payload_bytes = node
            .signature_payload_bytes()
            .expect("encode governance signature payload");
        node.publisher_signature = ed25519_governance_signature(&payload_bytes, &[0xA6; 32]);
        node
    }
    fn dilithium3_signed_governance_node() -> GovernanceLogNodeV1 {
        let mut node = governance_node();
        let key_pair = KeyPair::try_from_seed(vec![0xD6; 32], Algorithm::MlDsa)
            .expect("generate ML-DSA governance keypair");
        let payload_bytes = node
            .signature_payload_bytes()
            .expect("encode governance signature payload");
        let signature = IrohaSignature::try_new(key_pair.private_key(), &payload_bytes)
            .expect("sign governance payload with ML-DSA key");
        let (algorithm, public_key) = key_pair
            .public_key()
            .try_to_bytes()
            .expect("encode ML-DSA public key");
        assert_eq!(algorithm, Algorithm::MlDsa);
        node.publisher_signature = crate::GovernanceLogSignatureV1 {
            algorithm: GovernanceSignatureAlgorithm::Dilithium3,
            public_key: public_key.to_vec(),
            signature: signature.payload().to_vec(),
        };
        node
    }
    fn empty_ed25519_governance_signature() -> crate::GovernanceLogSignatureV1 {
        crate::GovernanceLogSignatureV1 {
            algorithm: GovernanceSignatureAlgorithm::Ed25519,
            public_key: Vec::new(),
            signature: Vec::new(),
        }
    }
    fn sign_governance_dag_block(block: &mut GovernanceDagBlockV1, seed: &[u8; 32]) {
        let payload_bytes = block
            .signature_payload_bytes()
            .expect("encode governance DAG block signing payload");
        block.block_signature = ed25519_governance_signature(&payload_bytes, seed);
    }
    fn sign_governance_dag_head(head: &mut GovernanceDagHeadV1, seed: &[u8; 32]) {
        let payload_bytes = head
            .signature_payload_bytes()
            .expect("encode governance DAG head signing payload");
        head.head_signature = ed25519_governance_signature(&payload_bytes, seed);
    }
    fn signed_governance_dag_block(
        prev_block_cid: Option<Vec<u8>>,
        prev_node_cid: Option<Vec<u8>>,
        sequence: u64,
        timestamp: u64,
    ) -> GovernanceDagBlockV1 {
        let mut node = ed25519_signed_governance_node();
        node.prev_cid = prev_node_cid;
        node.timestamp = timestamp;
        let publisher_peer_id = b"12D3KooWGovernanceDagPublisher".to_vec();
        node.publisher_peer_id.clone_from(&publisher_peer_id);
        node.node_cid = node
            .recompute_node_cid()
            .expect("derive governance DAG node CID");
        let node_payload = node
            .signature_payload_bytes()
            .expect("encode governance node signing payload");
        node.publisher_signature = ed25519_governance_signature(&node_payload, &[0xC7; 32]);

        let block_cid = crate::governance_dag_block_cid_v1(
            prev_block_cid.as_deref(),
            sequence,
            timestamp + 10,
            &publisher_peer_id,
            &node,
        )
        .expect("derive governance DAG block CID");
        let mut block = GovernanceDagBlockV1 {
            version: crate::GOVERNANCE_DAG_BLOCK_VERSION_V1,
            block_cid,
            prev_block_cid,
            sequence,
            timestamp: timestamp + 10,
            publisher_peer_id,
            node,
            block_signature: empty_ed25519_governance_signature(),
        };
        sign_governance_dag_block(&mut block, &[0xC7; 32]);
        block
    }
    fn signed_governance_dag_chain() -> (Vec<GovernanceDagBlockV1>, GovernanceDagHeadV1) {
        let first = signed_governance_dag_block(None, None, 0, 1_700_000_300);
        let second = signed_governance_dag_block(
            Some(first.block_cid.clone()),
            Some(first.node.node_cid.clone()),
            1,
            1_700_000_360,
        );
        let blocks = vec![first, second];
        let mut head = GovernanceDagHeadV1 {
            version: crate::GOVERNANCE_DAG_HEAD_VERSION_V1,
            head_block_cid: blocks
                .last()
                .expect("chain has a head block")
                .block_cid
                .clone(),
            block_count: blocks.len() as u64,
            generated_at: 1_700_001_000,
            publisher_peer_id: b"12D3KooWGovernanceDagPublisher".to_vec(),
            checkpoint_cid: None,
            head_signature: empty_ed25519_governance_signature(),
        };
        sign_governance_dag_head(&mut head, &[0xC7; 32]);
        (blocks, head)
    }
    fn assert_bounded_governance_outcome(outcome: &ValidationOutcomeV1) {
        assert!(!outcome.is_ok(), "{outcome:?}");
        let json = norito::json::to_string(outcome).expect("encode validation outcome JSON");
        assert!(
            json.len() < 16 * 1024,
            "malformed governance input amplified to {} outcome bytes",
            json.len()
        );
    }

    fn orderbook_order_request() -> OrderRequestV1 {
        fixture("fixtures/sorafs_manifest/orderbook/order_request_v1.to")
    }
    fn orderbook_order_cancel() -> OrderCancelV1 {
        let mut cancel: OrderCancelV1 =
            fixture("fixtures/sorafs_manifest/orderbook/order_cancel_v1.to");
        let order = orderbook_order_request();
        cancel.order_id = order.order_id;
        cancel.owner_account = order.owner_account;
        cancel.nonce = 9;
        sign_order_cancel_ed25519_v1(cancel, &SigningKey::from_bytes(&[0xB7; 32]))
            .expect("sign orderbook cancel fixture")
    }
    fn orderbook_settlement_receipt() -> SettlementReceiptV1 {
        let mut receipt: SettlementReceiptV1 =
            fixture("fixtures/sorafs_manifest/orderbook/settlement_receipt_v1.to");
        receipt.issued_at_unix = 1_800_000_010;
        sign_settlement_receipt_ed25519_v1(receipt, &SigningKey::from_bytes(&[0xB7; 32]))
            .expect("sign orderbook settlement receipt fixture")
    }
    fn orderbook_trade_event() -> TradeEventV1 {
        let mut trade: TradeEventV1 =
            fixture("fixtures/sorafs_manifest/orderbook/trade_event_v1.to");
        trade.maker_order_id = [0x71; 32];
        trade.filled_gib = 2;
        trade.maker_fee = micro_xor(2_500);
        trade.taker_fee = micro_xor(3_750);
        trade.timestamp_unix = 1_800_000_005;
        trade
    }
    fn hedging_digest(label: &str) -> [u8; 32] {
        *blake3::hash(label.as_bytes()).as_bytes()
    }
    fn hedging_feed(feed_id: &str, price: &str, observed_at_unix: u64) -> HedgingPriceFeedV1 {
        HedgingPriceFeedV1 {
            version: crate::HEDGING_PRICE_FEED_VERSION_V1,
            feed_id: feed_id.to_owned(),
            source: format!("{feed_id}-source"),
            observed_at_unix,
            xor_usd_price: price.parse().expect("canonical USD/XOR price"),
            weight_bps: 5_000,
            evidence_digest: hedging_digest(feed_id),
            status: HedgingFeedStatusV1::Ok,
        }
    }
    fn hedging_reference_decision() -> HedgingReferencePriceDecisionV1 {
        crate::derive_reference_price_decision_v1(
            1_800,
            vec![
                hedging_feed("primary", "2", 1_790),
                hedging_feed("secondary", "2", 1_785),
            ],
            120,
            500,
        )
        .expect("reference decision")
    }
    fn billing_statement() -> BillingStatementV1 {
        let reference_price = hedging_reference_decision();
        let storage = crate::build_billing_line_item_v1(
            BillingLineItemKindV1::Storage,
            BillingLineDirectionV1::Debit,
            "deal-storage",
            "10".parse::<XorQuantity>().expect("canonical XOR amount"),
            &reference_price.xor_usd_price,
            86_400,
            Some("weekly storage".to_owned()),
        )
        .expect("storage line");
        let credit = crate::build_billing_line_item_v1(
            BillingLineItemKindV1::IncentiveCredit,
            BillingLineDirectionV1::Credit,
            "provider-credit",
            "1".parse::<XorQuantity>().expect("canonical XOR amount"),
            &reference_price.xor_usd_price,
            1,
            None,
        )
        .expect("credit line");
        crate::build_billing_statement_v1(
            b"buyer-account".to_vec(),
            1_000,
            1_800,
            2_000,
            reference_price,
            vec![storage, credit],
            None,
        )
        .expect("billing statement")
    }
    fn pop_digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }
    fn pop_scalar(value: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }
    fn pop_nonce(value: u128) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&value.to_le_bytes());
        bytes
    }
    fn pop_empty_signature() -> crate::PopSignatureV1 {
        crate::PopSignatureV1 {
            algorithm: crate::PopSignatureAlgorithmV1::Ed25519,
            public_key: vec![1; PUBLIC_KEY_LENGTH],
            signature: vec![2; SIGNATURE_LENGTH],
        }
    }
    fn pop_credential() -> crate::PopCredentialV1 {
        crate::PopCredentialV1 {
            version: crate::POP_CREDENTIAL_VERSION_V1,
            credential_id: pop_scalar(0x11),
            holder_commitment: pop_scalar(0x12),
            eligibility_class: crate::PopEligibilityClassV1::General,
            attributes: vec![crate::PopCredentialAttributeV1 {
                key: "residency".to_owned(),
                value_commitment: pop_digest(0x13),
            }],
            issuer_id: "issuer.sorafs".to_owned(),
            issued_at_epoch: 100,
            expires_at_epoch: 1_000,
            renewal_at_epoch: 800,
            revocation_nonce: pop_nonce(0x14),
            commitment_root: pop_scalar(0x15),
            commitment_tree_version: 7,
            revocation_list_version: 3,
            issuer_signature: pop_empty_signature(),
        }
    }
    fn pop_commitment_root() -> crate::PopCommitmentRootV1 {
        crate::PopCommitmentRootV1 {
            version: crate::POP_COMMITMENT_ROOT_VERSION_V1,
            root_digest: pop_scalar(0x15),
            tree_size: 32,
            tree_depth: crate::pop_credentials::POP_CREDENTIAL_TREE_DEPTH_V1,
            tree_version: 7,
            issuer_id: "issuer.sorafs".to_owned(),
            published_at_epoch: 120,
            previous_root_digest: Some(pop_digest(0x16)),
            governance_event_digest: pop_digest(0x17),
            publisher_signature: pop_empty_signature(),
        }
    }
    fn pop_revocations() -> crate::PopRevocationListV1 {
        crate::PopRevocationListV1 {
            version: crate::POP_REVOCATION_LIST_VERSION_V1,
            list_version: 3,
            commitment_root: pop_scalar(0x15),
            revocation_root: crate::pop_credentials::pop_revocation_root_v1(&[])
                .expect("empty revocation root"),
            revocation_tree_depth: crate::pop_credentials::POP_REVOCATION_TREE_DEPTH_V1,
            issuer_id: "issuer.sorafs".to_owned(),
            published_at_epoch: 130,
            entries: Vec::new(),
            publisher_signature: pop_empty_signature(),
        }
    }
    fn pop_enrollment() -> crate::PopEnrollmentRequestV1 {
        crate::PopEnrollmentRequestV1 {
            version: crate::POP_ENROLLMENT_REQUEST_VERSION_V1,
            request_id: pop_digest(0x21),
            applicant_id: "alice@sora".to_owned(),
            requested_class: crate::PopEligibilityClassV1::General,
            requested_attributes: vec!["residency".to_owned()],
            attestation_digest: pop_digest(0x22),
            submitted_at_epoch: 100,
            expires_at_epoch: 200,
        }
    }
    fn pop_renewal() -> crate::PopRenewalRequestV1 {
        crate::PopRenewalRequestV1 {
            version: crate::POP_RENEWAL_REQUEST_VERSION_V1,
            request_id: pop_digest(0x31),
            previous_credential_id: pop_digest(0x11),
            holder_commitment: pop_digest(0x12),
            rotation_commitment: pop_digest(0x32),
            requested_expires_at_epoch: 2_000,
            submitted_at_epoch: 900,
            attestation_digest: pop_digest(0x33),
        }
    }
    fn pop_membership_proof() -> crate::PopMembershipProofV1 {
        let proof = crate::PopMembershipProofV1 {
            version: crate::POP_MEMBERSHIP_PROOF_VERSION_V1,
            eligibility_class: crate::PopEligibilityClassV1::General,
            commitment_root: pop_scalar(0x15),
            commitment_tree_version: 7,
            revocation_root: crate::pop_credentials::pop_revocation_root_v1(&[])
                .expect("empty revocation root"),
            revocation_list_version: 3,
            nullifier: pop_scalar(0x42),
            challenge_digest: pop_digest(0x43),
            verifier_context: "jury-case-1".to_owned(),
            presentation_binding_digest: pop_digest(0x46),
            proof_system: crate::PopMembershipProofSystemV1::NativePipaRV1,
            verifier_material: crate::pop_credentials::PopMembershipVerifierMaterialV1 {
                circuit_id: "sorafs-pop-membership-pipa-r-v1".to_owned(),
                circuit_k: 14,
                credential_tree_depth: crate::pop_credentials::POP_CREDENTIAL_TREE_DEPTH_V1,
                revocation_tree_depth: crate::pop_credentials::POP_REVOCATION_TREE_DEPTH_V1,
                parameter_digest: pop_digest(0x44),
                verifying_key_digest: pop_digest(0x45),
            },
            proof_bytes: vec![0xAA; 64],
            expires_at_epoch: 2_000,
        };
        proof.validate().expect("validate PoP proof payload");
        proof
    }
    #[test]
    fn pop_presentation_binding_is_in_validation_context_and_policy_errors() {
        let proof = pop_membership_proof();
        let context = pop_membership_proof_context(&proof);
        assert_eq!(
            context
                .iter()
                .filter(|field| field.key == "presentation_binding_digest_hex")
                .collect::<Vec<_>>(),
            vec![&ValidationContextFieldV1::new(
                "presentation_binding_digest_hex",
                hex::encode(proof.presentation_binding_digest)
            )],
        );
        let error = PopCredentialValidationError::PresentationBindingMismatch;
        assert_eq!(pop_validation_code(&error), "SFS-POL-010");
        assert_eq!(pop_validation_category(&error), CATEGORY_POLICY);
    }
    fn signed_pop_material() -> (
        crate::PopCredentialV1,
        crate::PopCommitmentRootV1,
        crate::PopRevocationListV1,
    ) {
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let credential =
            crate::sign_pop_credential_ed25519_v1(pop_credential(), &key).expect("sign credential");
        let root = crate::sign_pop_commitment_root_ed25519_v1(pop_commitment_root(), &key)
            .expect("sign commitment root");
        let revocations = crate::sign_pop_revocation_list_ed25519_v1(pop_revocations(), &key)
            .expect("sign revocations");
        (credential, root, revocations)
    }
    fn issued_pop_bundle() -> crate::PopIssuedCredentialBundleV1 {
        crate::issue_pop_credential_bundle_ed25519_v1(
            pop_credential(),
            pop_commitment_root(),
            pop_revocations(),
            &SigningKey::from_bytes(&[0x55; 32]),
        )
        .expect("issue PoP bundle")
    }
    fn potr_receipt() -> PotrReceiptV1 {
        let mut receipt: PotrReceiptV1 = fixture("fixtures/sorafs_manifest/potr/receipt_v1.to");
        receipt.manifest_digest = [0x11; 32];
        receipt.provider_id = [0x22; 32];
        receipt.note = Some("ok".to_owned());
        resign_potr_receipt(&mut receipt);
        receipt
    }
    fn resign_potr_receipt(receipt: &mut PotrReceiptV1) {
        let gateway_key = KeyPair::try_from_seed(vec![0x11; 32], Algorithm::Ed25519)
            .expect("fixture gateway key");
        let provider_key =
            KeyPair::try_from_seed(vec![0x31; 32], Algorithm::MlDsa).expect("fixture provider key");
        *receipt = crate::sign_potr_receipt_v1(receipt.clone(), &gateway_key, &provider_key)
            .expect("re-sign PoTR fixture");
    }
    fn repair_evidence() -> RepairEvidenceV1 {
        RepairEvidenceV1 {
            version: REPAIR_EVIDENCE_VERSION_V1,
            manifest_digest: [0x31; 32],
            provider_id: [0x32; 32],
            por_history_id: Some(7),
            cause: RepairCauseV1::PorFailure(RepairPorFailureCauseV1 {
                challenge_id: [0x33; 32],
                failed_samples: 2,
                proof_digest: Some([0x34; 32]),
            }),
            evidence_json: None,
            notes: Some("auditor confirmed repair trigger".to_owned()),
        }
    }
    fn repair_task_record() -> RepairTaskRecordV1 {
        let mut task: RepairTaskRecordV1 = fixture("fixtures/sorafs_manifest/repair/task_v1.to");
        task.ticket_id = crate::RepairTicketId("REP-351".to_owned());
        task.manifest_digest = [0x31; 32];
        task.provider_id = [0x32; 32];
        task.por_history_id = Some(7);
        task
    }
    fn signed_advert(now: u64) -> ProviderAdvertV1 {
        let body = ProviderAdvertBodyV1 {
            provider_id: [0x11; 32],
            profile_id: "sorafs.sf1@1.0.0".to_owned(),
            profile_aliases: Some(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()]),
            stake: StakePointer {
                pool_id: [0x22; 32],
                stake_amount: micro_xor(1_000_000),
            },
            qos: QosHints {
                availability: AvailabilityTier::Hot,
                max_retrieval_latency_ms: 1_500,
                max_concurrent_streams: 32,
            },
            capabilities: vec![
                CapabilityTlv {
                    cap_type: CapabilityType::ToriiGateway,
                    payload: Vec::new(),
                },
                CapabilityTlv {
                    cap_type: CapabilityType::ChunkRangeFetch,
                    payload: ProviderCapabilityRangeV1 {
                        max_chunk_span: 32,
                        min_granularity: 8,
                        supports_sparse_offsets: true,
                        requires_alignment: false,
                        supports_merkle_proof: true,
                    }
                    .to_bytes()
                    .expect("encode range capability"),
                },
            ],
            endpoints: vec![AdvertEndpoint {
                kind: EndpointKind::Torii,
                host_pattern: "storage.example.com".to_owned(),
                metadata: vec![EndpointMetadata {
                    key: EndpointMetadataKey::Region,
                    value: b"global".to_vec(),
                }],
            }],
            rendezvous_topics: vec![RendezvousTopic {
                topic: "sorafs.sf1.primary".to_owned(),
                region: "global".to_owned(),
            }],
            path_policy: PathDiversityPolicy {
                min_guard_weight: 10,
                max_same_asn_per_path: 1,
                max_same_pool_per_path: 1,
            },
            notes: None,
            stream_budget: None,
            transport_hints: None,
        };
        let signing_key = SigningKey::from_bytes(&[0xA5; 32]);
        let mut advert = ProviderAdvertV1 {
            version: crate::PROVIDER_ADVERT_VERSION_V1,
            network_id: [0xA1; 32],
            issued_at: now,
            expires_at: now + REFRESH_RECOMMENDATION_SECS,
            body,
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                signature: vec![0; 64],
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        };
        let payload = advert
            .signature_payload_bytes()
            .expect("encode advert signature envelope");
        advert.signature.signature = signing_key.sign(&payload).to_bytes().to_vec();
        advert
    }
    fn replication_order() -> ReplicationOrderV1 {
        fixture("fixtures/sorafs_manifest/replication_order/order_v1.to")
    }
    fn signed_replication_order() -> SignedReplicationOrderV1 {
        let signing_key = SigningKey::from_bytes(&[0xA7; 32]);
        let mut envelope = SignedReplicationOrderV1 {
            version: crate::SIGNED_REPLICATION_ORDER_VERSION_V1,
            order: replication_order(),
            signature: crate::ReplicationOrderSignatureV1 {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                signature: vec![0; 64],
            },
        };
        let payload_bytes = envelope
            .signature_payload_bytes()
            .expect("encode signed replication order payload");
        let signature = signing_key.sign(&payload_bytes);
        envelope.signature.signature = signature.to_bytes().to_vec();
        envelope
    }
    #[test]
    fn validation_context_field_new_sets_fields() {
        let field = ValidationContextFieldV1::new("provider", "alpha");
        assert_eq!(field.key, "provider");
        assert_eq!(field.value, "alpha");
    }
    #[test]
    fn validation_input_new_sets_fields() {
        let input = ValidationInputV1::new("provider_advert", "advert.to");
        assert_eq!(input.kind, "provider_advert");
        assert_eq!(input.path, "advert.to");
    }
    #[test]
    fn validation_outcome_ok_reports_success() {
        let outcome = ValidationOutcomeV1::ok(
            "SFS-OK-000",
            "accepted",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            42,
        );
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(outcome.version, VALIDATION_OUTCOME_VERSION_V1);
        assert_eq!(outcome.generated_at, 42);
    }
    #[test]
    fn validation_outcome_error_reports_failure() {
        let outcome = ValidationOutcomeV1::error(
            "SFS-VAL-004",
            "validation",
            "failed",
            "fix input",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            42,
        );
        assert!(!outcome.is_ok());
        assert_eq!(outcome.action.as_deref(), Some("fix input"));
    }
    #[test]
    fn pdp_reference_context_and_categories_match_fixed_signature_model() {
        let context = pdp_proof_context(&PdpProofV1 {
            version: crate::PDP_PROOF_VERSION_V1,
            commitment_digest: [0x11; 32],
            challenge_id: [0x22; 32],
            manifest_digest: [0x33; 32],
            provider_id: [0x44; 32],
            epoch_id: 1,
            proof_leaves: Vec::new(),
            issued_at_unix: 1,
            signature: crate::PdpEd25519SignatureV1 {
                public_key: [0x55; PUBLIC_KEY_LENGTH],
                signature: [0x66; SIGNATURE_LENGTH],
            },
        });
        assert_field(&context, "signature_len", SIGNATURE_LENGTH.to_string());

        assert_eq!(
            pdp_challenge_validation_category(&PdpChallengeValidationError::InvalidDeadline {
                issued_at: 2,
                deadline_at: 2,
            }),
            CATEGORY_POLICY
        );
        assert_eq!(
            pdp_proof_validation_category(&PdpProofValidationError::InvalidSignature(
                crate::PdpSignatureVerificationError::InvalidSignature {
                    reason: "fixture".to_owned(),
                },
            )),
            CATEGORY_SIGNATURE
        );
        assert_eq!(
            pdp_proof_validation_category(&PdpProofValidationError::InvalidIssuedAt),
            CATEGORY_VALIDATION
        );
    }
    #[test]
    fn untrusted_admission_renewal_maps_to_structural_validation() {
        let error = ProviderAdmissionRenewalError::UntrustedBaseRecord;
        assert_eq!(provider_admission_renewal_code(&error), "SFS-VAL-006");
        assert_eq!(
            provider_admission_renewal_category(&error),
            CATEGORY_VALIDATION
        );
    }
    #[test]
    fn validate_fixture_bundle_payloads_accepts_linked_advert_and_order() {
        let payloads = [
            (
                BundleKind::ProviderAdvert,
                "advert.to",
                encoded(&signed_advert(1_700_000_000)),
            ),
            (
                BundleKind::ReplicationOrder,
                "order.to",
                encoded(&replication_order()),
            ),
        ];
        let outcome = fixture_bundle_outcome(&payloads, 1_700_000_001, 42);
        assert_success(&outcome);
        assert_context(&outcome, "linkable_artifacts", "2");
    }
    #[test]
    fn validate_fixture_bundle_payloads_accepts_orderbook_payloads_with_linked_artifacts() {
        let payloads = [
            (
                BundleKind::ProviderAdvert,
                "advert.to",
                encoded(&signed_advert(1_700_000_000)),
            ),
            (
                BundleKind::ReplicationOrder,
                "order.to",
                encoded(&replication_order()),
            ),
            (
                BundleKind::OrderbookOrderRequest,
                "orderbook/order_request_v1.to",
                encoded(&orderbook_order_request()),
            ),
            (
                BundleKind::OrderbookSettlementReceipt,
                "orderbook/settlement_receipt_v1.to",
                encoded(&orderbook_settlement_receipt()),
            ),
        ];
        let outcome = fixture_bundle_outcome(&payloads, 1_700_000_001, 46);
        assert_success(&outcome);
        assert_context(&outcome, "artifact_count", "4");
        assert_context(&outcome, "linkable_artifacts", "2");
        assert_eq!(
            outcome
                .inputs
                .iter()
                .find(|input| input.kind == "settlement_receipt")
                .map(|input| input.path.as_str()),
            Some("orderbook/settlement_receipt_v1.to")
        );
    }
    #[test]
    fn validate_fixture_bundle_payloads_rejects_single_linkable_artifact() {
        let payloads = [(
            BundleKind::ReplicationOrder,
            "order.to",
            encoded(&replication_order()),
        )];
        let outcome = fixture_bundle_outcome(&payloads, 1_700_000_001, 43);
        assert_failure(&outcome, "SFS-BND-001", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_fixture_bundle_payloads_rejects_manifest_digest_mismatch() {
        let order = replication_order();
        let mut receipt = potr_receipt();
        receipt.manifest_digest = [0x99; 32];
        receipt.provider_id = [0x10; 32];
        resign_potr_receipt(&mut receipt);
        let payloads = [
            (BundleKind::ReplicationOrder, "order.to", encoded(&order)),
            (BundleKind::PotrReceipt, "receipt.to", encoded(&receipt)),
        ];
        let outcome = fixture_bundle_outcome(&payloads, 1_700_000_001, 44);
        assert_failure(&outcome, "SFS-BND-002", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_fixture_bundle_payloads_rejects_provider_assignment_mismatch() {
        let order = replication_order();
        let mut receipt = potr_receipt();
        receipt.manifest_digest = order.manifest_digest;
        receipt.provider_id = [0x99; 32];
        resign_potr_receipt(&mut receipt);
        let payloads = [
            (BundleKind::ReplicationOrder, "order.to", encoded(&order)),
            (BundleKind::PotrReceipt, "receipt.to", encoded(&receipt)),
        ];
        let outcome = fixture_bundle_outcome(&payloads, 1_700_000_001, 45);
        assert_failure(&outcome, "SFS-BND-003", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_governance_log_node_bytes_accepts_fixture() {
        let node = governance_node();
        let outcome = validate_governance_log_node_bytes(
            &encoded(&node),
            "governance-node.to",
            Some(node.node_cid.as_slice()),
            46,
        );
        assert_success(&outcome);
        assert_context(&outcome, "payload_kind", "por_proof");
    }
    #[test]
    fn governance_log_node_context_exposes_signed_submission_provenance() {
        let mut node = governance_node();
        node.submission_provenance = Some(crate::GovernanceDagSubmissionProvenanceV1 {
            publisher_account_digest: crate::governance_dag_submission_account_digest_v1(
                b"canonical-norito-reference-publisher",
            ),
            origin: crate::GovernanceDagSubmissionOriginV1::AppealFinanceReport,
        });
        let context = governance_log_node_context(&node);
        assert_field(
            &context,
            "submission_publisher_account_digest_hex",
            hex::encode(crate::governance_dag_submission_account_digest_v1(
                b"canonical-norito-reference-publisher",
            )),
        );
        assert_field(&context, "submission_origin", "appeal_finance_report");
    }
    #[test]
    fn validate_governance_log_node_bytes_verifies_ed25519_publisher_signature() {
        let node = ed25519_signed_governance_node();
        let outcome =
            validate_governance_log_node_bytes(&encoded(&node), "governance-node.to", None, 47);
        assert_success(&outcome);

        let mut tampered = node;
        tampered.publisher_peer_id.extend_from_slice(b"-tampered");
        tampered.node_cid = tampered
            .recompute_node_cid()
            .expect("recompute tampered governance node CID");
        let outcome = validate_governance_log_node_bytes(
            &encoded(&tampered),
            "tampered-governance-node.to",
            None,
            48,
        );
        assert_failure(&outcome, "SFS-SIG-005", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_governance_log_node_bytes_verifies_dilithium3_publisher_signature() {
        let node = dilithium3_signed_governance_node();
        let outcome =
            validate_governance_log_node_bytes(&encoded(&node), "governance-node.to", None, 47);
        assert_success(&outcome);

        let mut tampered = node;
        tampered.timestamp += 1;
        tampered.node_cid = tampered
            .recompute_node_cid()
            .expect("recompute tampered governance node CID");
        let outcome = validate_governance_log_node_bytes(
            &encoded(&tampered),
            "tampered-governance-node.to",
            None,
            48,
        );
        assert_failure(&outcome, "SFS-SIG-005", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_governance_log_node_bytes_rejects_malformed_norito() {
        let outcome = validate_governance_log_node_bytes(b"not norito", "bad-node.to", None, 47);
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_governance_log_node_bytes_rejects_cid_mismatch() {
        let node = governance_node();
        let outcome = validate_governance_log_node_bytes(
            &encoded(&node),
            "governance-node.to",
            Some(b"bafywronggovernancenode"),
            48,
        );
        assert_failure(&outcome, "SFS-GOV-003", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_governance_log_node_bytes_rejects_structural_failure() {
        let mut node = governance_node();
        node.node_cid.clear();
        let outcome = validate_governance_log_node_bytes(&encoded(&node), "bad-node.to", None, 49);
        assert_failure(&outcome, "SFS-GOV-001", CATEGORY_VALIDATION);
    }
    #[test]
    fn governance_reference_outcomes_bound_malformed_cid_and_peer_context() {
        const ADVERSARIAL_BYTES: usize = 256 * 1024;
        let mut node = governance_node();
        node.node_cid = vec![0xA5; ADVERSARIAL_BYTES];
        let outcome =
            validate_governance_log_node_bytes(&encoded(&node), "oversized-node.to", None, 49);
        assert_bounded_governance_outcome(&outcome);
        let mut block = signed_governance_dag_block(None, None, 0, 1_700_000_300);
        block.publisher_peer_id = vec![0x5A; ADVERSARIAL_BYTES];
        let outcome =
            validate_governance_dag_block_bytes(&encoded(&block), "oversized-block.to", None, 49);
        assert_bounded_governance_outcome(&outcome);
        let (blocks, mut head) = signed_governance_dag_chain();
        head.checkpoint_cid = Some(vec![0xC3; ADVERSARIAL_BYTES]);
        let head_bytes = encoded(&head);
        let block_bytes = blocks.iter().map(encoded).collect::<Vec<_>>();
        let block_inputs = block_bytes
            .iter()
            .enumerate()
            .map(|(index, bytes)| (bytes.as_slice(), format!("block-{index}.to")))
            .collect::<Vec<_>>();
        let outcome = validate_governance_dag_head_chain_bytes(
            &head_bytes,
            "oversized-head.to",
            &block_inputs,
            49,
        );
        assert_bounded_governance_outcome(&outcome);
    }
    #[test]
    fn pdp_archive_governance_errors_have_stable_reference_mappings() {
        let errors = [
            GovernanceLogValidationError::PdpArchive(
                crate::PdpGovernanceArchiveValidationError::InvalidIdentity,
            ),
            GovernanceLogValidationError::PdpArchiveDecisionAfterNode {
                decided_at: 2,
                node_timestamp: 1,
            },
        ];
        for error in errors {
            assert_eq!(governance_log_validation_code(&error), "SFS-GOV-001");
            assert_eq!(
                governance_log_validation_category(&error),
                CATEGORY_VALIDATION
            );
        }
    }
    #[test]
    fn submission_provenance_errors_have_stable_reference_mappings() {
        use crate::GovernanceDagSubmissionOriginV1;
        let errors = [
            GovernanceLogValidationError::MissingSubmissionProvenance {
                expected: GovernanceDagSubmissionOriginV1::AppealFinanceReport,
            },
            GovernanceLogValidationError::UnexpectedSubmissionProvenance {
                found: GovernanceDagSubmissionOriginV1::TransparencyTokenIssuance,
            },
            GovernanceLogValidationError::SubmissionOriginMismatch {
                expected: GovernanceDagSubmissionOriginV1::AppealFinanceWeeklyRollup,
                found: GovernanceDagSubmissionOriginV1::PrivacyAggregatePublishDue,
            },
        ];
        for error in errors {
            assert_eq!(governance_log_validation_code(&error), "SFS-GOV-001");
            assert_eq!(
                governance_log_validation_category(&error),
                CATEGORY_VALIDATION
            );
        }
    }
    #[test]
    fn validate_governance_dag_block_bytes_accepts_signed_block() {
        let block = signed_governance_dag_block(None, None, 0, 1_700_000_300);
        let outcome = validate_governance_dag_block_bytes(
            &encoded(&block),
            "governance-block.to",
            Some(&block.block_cid),
            50,
        );
        assert_success(&outcome);
        assert_context(&outcome, "schema", "GovernanceDagBlockV1");
    }
    #[test]
    fn validate_governance_dag_block_bytes_rejects_cid_mismatch() {
        let block = signed_governance_dag_block(None, None, 0, 1_700_000_300);
        let outcome = validate_governance_dag_block_bytes(
            &encoded(&block),
            "governance-block.to",
            Some(&[0xFF; 32]),
            51,
        );
        assert_failure(&outcome, "SFS-GOV-004", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_governance_dag_head_chain_bytes_accepts_signed_head() {
        let (blocks, head) = signed_governance_dag_chain();
        assert_success(&governance_chain_outcome(&blocks, &head, 52));
    }
    #[test]
    fn validate_governance_dag_head_chain_bytes_rejects_block_count_mismatch() {
        let (blocks, mut head) = signed_governance_dag_chain();
        head.block_count += 1;
        sign_governance_dag_head(&mut head, &[0xC7; 32]);
        let outcome = governance_chain_outcome(&blocks, &head, 53);
        assert_failure(&outcome, "SFS-GOV-008", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_governance_dag_head_chain_bytes_rejects_head_before_tip() {
        let (blocks, mut head) = signed_governance_dag_chain();
        head.generated_at = blocks
            .last()
            .expect("fixture has tip")
            .timestamp
            .checked_sub(1)
            .expect("fixture tip timestamp is positive");
        sign_governance_dag_head(&mut head, &[0xC7; 32]);
        let outcome = governance_chain_outcome(&blocks, &head, 53);
        assert_failure(&outcome, "SFS-GOV-008", CATEGORY_VALIDATION);
    }
    #[test]
    fn committed_governance_dag_outcome_matches_reference_validator() {
        let outcome = committed_governance_chain_outcome(
            "dag_head_v1.to",
            &["dag_block_0_v1.to", "dag_block_1_v1.to"],
        );
        assert_committed_governance_outcome(&outcome, "dag_head_validation_outcome_v1.json");
    }
    #[test]
    fn committed_governance_dag_negative_outcomes_match_reference_validator() {
        let bad_block_signature = governance_fixture_bytes("dag_block_bad_signature_v1.to");
        let outcome = validate_governance_dag_block_bytes(
            &bad_block_signature,
            "dag_block_bad_signature_v1.to",
            None,
            123,
        );
        assert_failure(&outcome, "SFS-SIG-006", CATEGORY_SIGNATURE);
        assert_committed_governance_outcome(
            &outcome,
            "dag_block_bad_signature_validation_outcome_v1.json",
        );

        let trailing_bytes = governance_fixture_bytes("dag_block_trailing_bytes_v1.to");
        let outcome = validate_governance_dag_block_bytes(
            &trailing_bytes,
            "dag_block_trailing_bytes_v1.to",
            None,
            123,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
        assert_committed_governance_outcome(
            &outcome,
            "dag_block_trailing_bytes_validation_outcome_v1.json",
        );

        let outcome = committed_governance_chain_outcome(
            "dag_head_bad_signature_v1.to",
            &["dag_block_0_v1.to", "dag_block_1_v1.to"],
        );
        assert_failure(&outcome, "SFS-SIG-007", CATEGORY_SIGNATURE);
        assert_committed_governance_outcome(
            &outcome,
            "dag_head_bad_signature_validation_outcome_v1.json",
        );

        let outcome = committed_governance_chain_outcome(
            "dag_head_bad_predecessor_v1.to",
            &["dag_block_0_v1.to", "dag_block_1_bad_predecessor_v1.to"],
        );
        assert_failure(&outcome, "SFS-GOV-006", CATEGORY_VALIDATION);
        assert_committed_governance_outcome(
            &outcome,
            "dag_head_bad_predecessor_validation_outcome_v1.json",
        );
    }
    #[test]
    fn validate_governance_dag_head_chain_bytes_rejects_noncanonical_order() {
        let (blocks, head) = signed_governance_dag_chain();
        let reversed = blocks.into_iter().rev().collect::<Vec<_>>();
        let outcome = governance_chain_outcome(&reversed, &head, 54);
        assert_failure(&outcome, "SFS-GOV-006", CATEGORY_VALIDATION);
        assert!(
            field(&outcome.context, "validation_error")
                .is_some_and(|value| value.contains("canonical root-to-head order"))
        );
    }
    #[test]
    fn validate_provider_advert_bytes_accepts_signed_advert() {
        let outcome = advert_outcome(
            &signed_advert(1_700_000_000),
            "advert.to",
            1_700_000_001,
            1_700_000_002,
        );
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_provider_advert_bytes_rejects_malformed_norito() {
        let outcome = validate_provider_advert_bytes(b"not norito", "bad.to", 1, 2);
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_provider_advert_bytes_rejects_policy_failure() {
        let mut advert = signed_advert(1_700_000_000);
        advert.expires_at = advert.issued_at + crate::MAX_ADVERT_TTL_SECS + 1;
        let outcome = advert_outcome(&advert, "expired.to", 1_700_000_001, 3);
        assert_failure(&outcome, "SFS-POL-001", CATEGORY_POLICY);
    }
    #[test]
    fn validate_provider_advert_bytes_rejects_bad_signature() {
        let mut advert = signed_advert(1_700_000_000);
        advert.signature.signature[0] ^= 0x01;
        let outcome = advert_outcome(&advert, "bad-signature.to", 1_700_000_001, 4);
        assert_failure(&outcome, "SFS-SIG-001", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_accepts_fixture() {
        let outcome = admission_outcome(&admission_envelope(), "envelope.to", 7);
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_provider_admission_renewal_bytes_accepts_fixture() {
        let envelope = admission_envelope();
        let renewal_bytes = admission_renewal_bytes();
        let outcome = validate_provider_admission_renewal_bytes(
            &encoded(&envelope),
            &renewal_bytes,
            "envelope.to",
            "renewal.to",
            7,
        );
        assert_success(&outcome);
        assert_eq!(
            field(&outcome.context, "renewal_envelope_digest_hex").map(str::len),
            Some(64)
        );
    }
    #[test]
    fn validate_provider_admission_renewal_bytes_rejects_malformed_renewal() {
        let envelope = admission_envelope();
        let outcome = validate_provider_admission_renewal_bytes(
            &encoded(&envelope),
            b"not norito",
            "envelope.to",
            "bad-renewal.to",
            8,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_provider_admission_revocation_bytes_accepts_fixture() {
        let envelope = admission_envelope();
        let revocation_bytes = admission_revocation_bytes();
        let outcome = validate_provider_admission_revocation_bytes(
            &encoded(&envelope),
            &revocation_bytes,
            "envelope.to",
            "revocation.to",
            9,
        );
        assert_success(&outcome);
        assert_eq!(
            field(&outcome.context, "envelope_digest_hex").map(str::len),
            Some(64)
        );
    }
    #[test]
    fn validate_provider_admission_revocation_bytes_rejects_malformed_revocation() {
        let envelope = admission_envelope();
        let outcome = validate_provider_admission_revocation_bytes(
            &encoded(&envelope),
            b"not norito",
            "envelope.to",
            "bad-revocation.to",
            10,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_malformed_norito() {
        let outcome =
            validate_provider_admission_envelope_bytes(b"not norito", "bad-envelope.to", 8);
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_digest_mismatch() {
        let mut envelope = admission_envelope();
        envelope.proposal_digest[0] ^= 0x01;
        let outcome = admission_outcome(&envelope, "bad-digest.to", 9);
        assert_failure(&outcome, "SFS-VAL-007", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_signature_failure() {
        let mut envelope = admission_envelope();
        envelope.council_signatures[0].signature[0] ^= 0x01;
        let outcome = admission_outcome(&envelope, "bad-signature.to", 10);
        assert_failure(&outcome, "SFS-SIG-002", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_retention_policy() {
        let mut envelope = admission_envelope();
        envelope.issued_at = envelope.retention_epoch + 1;
        let outcome = admission_outcome(&envelope, "bad-retention.to", 11);
        assert_failure(&outcome, "SFS-POL-004", CATEGORY_POLICY);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_structural_failure() {
        let mut envelope = admission_envelope();
        envelope.proposal.provider_id = [0; 32];
        let outcome = admission_outcome(&envelope, "bad-structure.to", 12);
        assert_failure(&outcome, "SFS-VAL-006", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_provider_admission_envelope_bytes_rejects_chunker_failure() {
        let mut envelope = admission_envelope();
        envelope.proposal.profile_id = "unknown.profile@1.0.0".to_owned();
        let outcome = admission_outcome(&envelope, "bad-chunker.to", 13);
        assert_failure(&outcome, "SFS-VAL-003", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_accepts_fixtures() {
        let challenge = por_challenge();
        let outcome = por_outcome(&challenge, &por_proof(), "challenge.to", "proof.to", 14);
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_malformed_challenge() {
        let proof = por_proof();
        let outcome = validate_por_challenge_proof_bytes(
            b"not norito",
            &encoded(&proof),
            "bad-challenge.to",
            "proof.to",
            15,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_binding_mismatch() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.challenge_id[0] ^= 0x01;
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "bad-proof.to", 16);
        assert_failure(&outcome, "SFS-POR-003", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_late_proof() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.submitted_at = challenge.deadline_at + 1;
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "late-proof.to", 17);
        assert_failure(&outcome, "SFS-POL-002", CATEGORY_POLICY);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_preissued_proof() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.submitted_at = challenge.issued_at - 1;
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "preissued-proof.to", 17);
        assert_failure(&outcome, "SFS-POL-002", CATEGORY_POLICY);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_sample_coverage_mismatch() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.samples[0].sample_index = challenge.sample_indices[0] + 10_000;
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "bad-coverage.to", 18);
        assert_failure(&outcome, "SFS-POR-001", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_reordered_samples() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.samples.swap(0, 1);
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "reordered-proof.to", 18);
        assert_failure(&outcome, "SFS-POR-001", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_forged_signature() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.signature.signature[0] ^= 0x80;
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "forged-proof.to", 18);
        assert_failure(&outcome, "SFS-SIG-008", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_challenge_structure_failure() {
        let mut challenge = por_challenge();
        let proof = por_proof();
        challenge.chunking_profile = "unknown.profile@1.0.0".to_owned();
        let bytes = norito::encode_canonical(&challenge).unwrap();
        assert!(crate::por::decode_por_challenge_v1(&bytes).is_err());
        assert_eq!(
            crate::por::decode_por_challenge_payload_v1(&bytes).unwrap(),
            challenge
        );
        let outcome = por_outcome(&challenge, &proof, "bad-challenge.to", "proof.to", 19);
        assert_failure(&outcome, "SFS-VAL-003", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_por_challenge_proof_bytes_rejects_proof_structure_failure() {
        let challenge = por_challenge();
        let mut proof = por_proof();
        proof.auth_path.clear();
        let bytes = norito::encode_canonical(&proof).unwrap();
        assert!(crate::por::decode_por_proof_v1(&bytes).is_err());
        assert_eq!(
            crate::por::decode_por_proof_payload_v1(&bytes).unwrap(),
            proof
        );
        let outcome = por_outcome(&challenge, &proof, "challenge.to", "bad-proof.to", 20);
        assert_failure(&outcome, "SFS-VAL-009", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_potr_receipt_bytes_accepts_valid_receipt() {
        let outcome = potr_outcome(
            &potr_receipt(),
            "receipt.to",
            Some(ProofStreamTier::Hot),
            21,
        );
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_potr_receipt_bytes_rejects_malformed_norito() {
        let outcome = validate_potr_receipt_bytes(b"not norito", "bad-receipt.to", None, 22);
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_potr_receipt_bytes_rejects_late_success_receipt() {
        let mut receipt = potr_receipt();
        receipt.latency_ms = receipt.deadline_ms + 1;
        receipt.responded_at_ms = receipt.requested_at_ms + u64::from(receipt.latency_ms);
        receipt.recorded_at_ms = receipt.responded_at_ms + 100;
        let outcome = potr_outcome(&receipt, "late-receipt.to", None, 23);
        assert_failure(&outcome, "SFS-POTR-001", CATEGORY_POLICY);
    }
    #[test]
    fn validate_potr_receipt_bytes_rejects_invalid_signature() {
        let mut receipt = potr_receipt();
        receipt.gateway_signature = Some(PotrSignatureV1 {
            algorithm: PotrSignatureAlgorithm::Ed25519,
            public_key: vec![0u8; 16],
            signature: vec![0u8; 32],
        });
        let outcome = potr_outcome(&receipt, "bad-signature.to", None, 24);
        assert_failure(&outcome, "SFS-SIG-003", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_potr_receipt_bytes_rejects_tier_mismatch() {
        let outcome = potr_outcome(
            &potr_receipt(),
            "wrong-tier.to",
            Some(ProofStreamTier::Warm),
            25,
        );
        assert_failure(&outcome, "SFS-POTR-002", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_potr_receipt_bytes_rejects_structural_failure() {
        let mut receipt = potr_receipt();
        receipt.range_start = receipt.range_end + 1;
        let outcome = potr_outcome(&receipt, "bad-range.to", None, 26);
        assert_failure(&outcome, "SFS-VAL-010", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_repair_payload_bytes_accepts_task_record() {
        let outcome = repair_outcome(
            RepairKind::TaskRecord,
            &repair_task_record(),
            "repair-task.to",
            27,
        );
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_repair_payload_bytes_rejects_alternate_norito_layout() {
        let task = repair_task_record();
        let bytes = {
            let _flags = norito::core::DecodeFlagsGuard::enter(
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN,
            );
            encoded(&task)
        };
        assert_ne!(bytes, encoded(&task), "fixture must distinguish layouts");
        assert!(matches!(
            decode_reference_frame::<RepairTaskRecordV1>(&bytes),
            Err(norito::Error::NonCanonicalEncoding)
        ));
        let outcome = validate_repair_payload_bytes(
            RepairKind::TaskRecord,
            &bytes,
            "alternate-layout-repair-task.to",
            28,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_repair_payload_bytes_uses_stable_pdp_failure_label() {
        let mut evidence = repair_evidence();
        evidence.cause = RepairCauseV1::PdpFailure(RepairPdpFailureCauseV1 {
            challenge_id: [0x41; 32],
            epoch_id: 9,
            failed_samples: 1,
            proof_digest: Some([0x42; 32]),
            failure_kind: RepairPdpFailureKindV1::InvalidProof,
        });
        let outcome = repair_outcome(
            RepairKind::Evidence,
            &evidence,
            "pdp-repair-evidence.to",
            28,
        );
        assert_success(&outcome);
        assert_context(&outcome, "cause", "pdp_failure");
    }
    #[test]
    fn validate_repair_payload_bytes_rejects_malformed_norito() {
        let outcome = validate_repair_payload_bytes(
            RepairKind::TaskRecord,
            b"not norito",
            "bad-repair-task.to",
            29,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_repair_payload_bytes_rejects_evidence_failure() {
        let mut evidence = repair_evidence();
        evidence.cause = RepairCauseV1::PorFailure(RepairPorFailureCauseV1 {
            challenge_id: [0x33; 32],
            failed_samples: 0,
            proof_digest: None,
        });
        let outcome = repair_outcome(RepairKind::Evidence, &evidence, "bad-evidence.to", 30);
        assert_failure(&outcome, "SFS-REP-001", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_hedging_payload_bytes_accepts_billing_statement() {
        let statement = billing_statement();
        let outcome = hedging_outcome(
            HedgingKind::BillingStatement,
            &statement,
            "billing-statement.to",
            31,
        );
        assert_success(&outcome);
        assert_context(
            &outcome,
            "statement_id_hex",
            hex::encode(statement.statement_id),
        );
    }
    #[test]
    fn billing_context_preserves_exact_sub_micro_xor_values() {
        let exact: XorQuantity = "0.0000001"
            .parse()
            .expect("canonical sub-micro XOR quantity");
        let mut statement = billing_statement();
        let mut line = statement.lines[0].clone();
        line.xor_amount = exact.clone();
        let line_context = billing_line_item_context(&line);
        assert_field(&line_context, "xor_amount", "0.0000001");

        statement.total_debit_xor = exact.clone();
        statement.total_credit_xor = exact.clone();
        statement.net_due_xor = exact;
        let statement_context = billing_statement_context(&statement);
        for key in ["total_debit_xor", "total_credit_xor", "net_due_xor"] {
            assert_field(&statement_context, key, "0.0000001");
        }
    }
    #[test]
    fn validate_hedging_payload_bytes_rejects_malformed_norito() {
        let outcome = validate_hedging_payload_bytes(
            HedgingKind::BillingStatement,
            b"not norito",
            "bad-billing-statement.to",
            32,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_hedging_payload_bytes_rejects_oversized_and_noncanonical_archives() {
        let oversized = vec![0_u8; crate::HEDGING_SMALL_PAYLOAD_MAX_CANONICAL_BYTES_V1 + 1];
        let outcome = validate_hedging_payload_bytes(
            HedgingKind::PriceFeed,
            &oversized,
            "oversized-feed.to",
            32,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
        assert!(outcome.message.contains("maximum canonical size"));

        let mut noncanonical = encoded(&hedging_feed("primary", "1", 1_790));
        noncanonical.push(0);
        let outcome = validate_hedging_payload_bytes(
            HedgingKind::PriceFeed,
            &noncanonical,
            "noncanonical-feed.to",
            32,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn validate_hedging_payload_bytes_rejects_stale_decision_feed() {
        let mut decision = hedging_reference_decision();
        decision.feeds[0].observed_at_unix = 1_000;
        decision.decision_id =
            crate::reference_price_decision_id_v1(&decision).expect("derive tampered decision id");
        let outcome = hedging_outcome(
            HedgingKind::ReferencePriceDecision,
            &decision,
            "stale-decision.to",
            33,
        );
        assert_failure(&outcome, "SFS-POL-020", CATEGORY_POLICY);
    }
    // Textual inclusion preserves the original reference test-module paths.
    include!("reference/tests/pop_validation.rs");
    #[test]
    fn validate_orderbook_payload_bytes_accepts_order_request() {
        let order = orderbook_order_request();
        let outcome = orderbook_outcome(
            OrderbookKind::OrderRequest,
            &order,
            "orderbook-order.to",
            32,
        );
        assert_success(&outcome);
        assert_context(&outcome, "order_id_hex", hex::encode(order.order_id));
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_orderbook_payload_bytes_accepts_signed_cancel_and_receipt() {
        let cases = [
            (
                OrderbookKind::OrderCancel,
                encoded(&orderbook_order_cancel()),
                "orderbook-cancel.to",
            ),
            (
                OrderbookKind::SettlementReceipt,
                encoded(&orderbook_settlement_receipt()),
                "settlement-receipt.to",
            ),
        ];
        for (kind, bytes, label) in cases {
            let outcome = validate_orderbook_payload_bytes(kind, &bytes, label, 32);
            assert_success(&outcome);
        }
    }
    #[test]
    fn sign_orderbook_payload_bytes_ed25519_v1_signs_mutable_payloads() {
        let seed = [0xB7; 32];
        let expected_public_key = verifying_key(&seed);

        let signed_order_bytes = sign_orderbook_payload_bytes_ed25519_v1(
            OrderbookKind::OrderRequest,
            &encoded(&orderbook_order_request()),
            &seed,
        )
        .expect("sign order request bytes");
        assert_signed_order_request(&signed_order_bytes, &expected_public_key);

        let signed_cancel_bytes = sign_orderbook_payload_bytes_ed25519_v1(
            OrderbookKind::OrderCancel,
            &encoded(&orderbook_order_cancel()),
            &seed,
        )
        .expect("sign order cancel bytes");
        assert_signed_order_cancel(&signed_cancel_bytes, &expected_public_key);

        let signed_receipt_bytes = sign_orderbook_payload_bytes_ed25519_v1(
            OrderbookKind::SettlementReceipt,
            &encoded(&orderbook_settlement_receipt()),
            &seed,
        )
        .expect("sign settlement receipt bytes");
        assert_signed_settlement_receipt(&signed_receipt_bytes, &expected_public_key);
    }
    #[test]
    fn build_signed_orderbook_payload_bytes_ed25519_v1_builds_field_level_payloads() {
        let seed = [0xB7; 32];
        let expected_public_key = verifying_key(&seed);

        let owner_account = vec![0x03; 32];
        let order_nonce = 1;
        let order_id = crate::derive_orderbook_order_id_v1(&owner_account, order_nonce);
        let order_bytes = build_signed_orderbook_order_request_bytes_ed25519_v1(
            OrderbookOrderRequestFieldsV1 {
                side: OrderSideV1::Bid,
                tier: OrderTierV1::Hot,
                price_per_gib: "1.5".parse().expect("canonical XOR quantity"),
                quantity_gib: 10,
                remaining_gib: 10,
                owner_account: owner_account.clone(),
                provider_id: None,
                expiry_unix: 1_800_000_000,
                nonce: order_nonce,
                maker_fee_bps: 5,
                taker_fee_bps: 10,
            },
            &seed,
        )
        .expect("build signed order request");
        assert_signed_order_request(&order_bytes, &expected_public_key);

        let cancel_bytes = build_signed_orderbook_order_cancel_bytes_ed25519_v1(
            order_cancel_fields(order_id, owner_account, 2),
            &seed,
        )
        .expect("build signed order cancel");
        assert_signed_order_cancel(&cancel_bytes, &expected_public_key);

        let receipt_bytes = build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(
            settlement_receipt_fields(90),
            &seed,
        )
        .expect("build signed settlement receipt");
        assert_signed_settlement_receipt(&receipt_bytes, &expected_public_key);
    }
    #[test]
    fn field_level_orderbook_builders_accept_owner_account_at_v1_byte_ceiling() {
        let seed = [0xB7; 32];
        let owner_account = vec![0x44; crate::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1];
        let order_id = crate::derive_orderbook_order_id_v1(&owner_account, 1);
        let order_bytes = build_signed_orderbook_order_request_bytes_ed25519_v1(
            minimal_order_request_fields(owner_account.clone()),
            &seed,
        )
        .expect("maximum-length owner request must build");
        let order: OrderRequestV1 =
            decode_from_bytes(&order_bytes).expect("decode maximum-length owner request");
        assert_eq!(order.owner_account, owner_account);
        let cancel_bytes = build_signed_orderbook_order_cancel_bytes_ed25519_v1(
            order_cancel_fields(order_id, order.owner_account, 2),
            &seed,
        )
        .expect("maximum-length owner cancel must build");
        let cancel: OrderCancelV1 =
            decode_from_bytes(&cancel_bytes).expect("decode maximum-length owner cancel");
        assert_eq!(
            cancel.owner_account.len(),
            crate::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1
        );
    }
    #[test]
    fn field_level_orderbook_builders_reject_oversized_owner_before_key_or_id_use() {
        let owner_account = vec![0x44; crate::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1];
        let request_err = build_signed_orderbook_order_request_bytes_ed25519_v1(
            minimal_order_request_fields(owner_account.clone()),
            &[0xB7; 31],
        )
        .expect_err("oversized request owner must fail before signing-key parsing");
        assert!(
            matches!(request_err, OrderbookPayloadSigningError::Sign { reason, .. }
            if reason.contains("exceeds maximum 256 bytes"))
        );
        let cancel_err = build_signed_orderbook_order_cancel_bytes_ed25519_v1(
            order_cancel_fields([0x11; 32], owner_account, 1),
            &[0xB7; 31],
        )
        .expect_err("oversized cancel owner must fail before signing-key parsing");
        assert!(
            matches!(cancel_err, OrderbookPayloadSigningError::Sign { reason, .. }
            if reason.contains("exceeds maximum 256 bytes"))
        );
    }
    #[test]
    fn build_signed_orderbook_payload_bytes_ed25519_v1_rejects_invalid_fields() {
        let err = build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(
            settlement_receipt_fields(91),
            &[0xB7; 32],
        )
        .expect_err("imbalanced settlement receipt must fail");
        assert!(matches!(err, OrderbookPayloadSigningError::Sign { .. }));
    }
    #[test]
    fn sign_orderbook_payload_bytes_ed25519_v1_rejects_bad_key_material() {
        assert_eq!(
            sign_orderbook_payload_bytes_ed25519_v1(
                OrderbookKind::OrderRequest,
                &encoded(&orderbook_order_request()),
                &[0xB7; 31],
            ),
            Err(OrderbookPayloadSigningError::InvalidSigningKeyLength { length: 31 })
        );
        assert_eq!(
            sign_orderbook_payload_bytes_ed25519_v1(
                OrderbookKind::OrderRequest,
                &encoded(&orderbook_order_request()),
                &[0; 32],
            ),
            Err(OrderbookPayloadSigningError::InvalidSigningKeyMaterial)
        );
    }
    #[test]
    fn sign_orderbook_payload_bytes_ed25519_v1_rejects_runtime_generated_payloads() {
        assert_eq!(
            sign_orderbook_payload_bytes_ed25519_v1(
                OrderbookKind::TradeEvent,
                &encoded(&orderbook_trade_event()),
                &[0xB7; 32],
            ),
            Err(OrderbookPayloadSigningError::UnsupportedPayloadKind {
                kind: OrderbookKind::TradeEvent
            })
        );
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_malformed_norito() {
        let outcome = validate_orderbook_payload_bytes(
            OrderbookKind::SettlementReceipt,
            b"not norito",
            "bad-receipt.to",
            33,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
    }
    #[test]
    fn orderbook_reference_and_signing_paths_reject_oversized_archive() {
        let archive = vec![0_u8; crate::ORDERBOOK_PAYLOAD_MAX_CANONICAL_BYTES_V1 + 1];
        let outcome = validate_orderbook_payload_bytes(
            OrderbookKind::OrderRequest,
            &archive,
            "oversized-order.to",
            33,
        );
        assert_failure(&outcome, "SFS-NORITO-001", CATEGORY_NORITO);
        assert!(outcome.message.contains("maximum canonical size"));
        assert!(matches!(
            sign_orderbook_payload_bytes_ed25519_v1(
                OrderbookKind::OrderRequest,
                &archive,
                &[0xB7; 32],
            ),
            Err(OrderbookPayloadSigningError::Decode { reason, .. })
                if reason.contains("maximum canonical size")
        ));
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_policy_failure() {
        let mut order = orderbook_order_request();
        order.nonce = 0;
        let outcome = orderbook_outcome(
            OrderbookKind::OrderRequest,
            &order,
            "bad-orderbook-order.to",
            34,
        );
        assert_failure(&outcome, "SFS-POL-007", CATEGORY_POLICY);
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_oversized_request_and_cancel_owners() {
        let owner_account = vec![0x45; crate::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 + 1];
        let mut order = orderbook_order_request();
        order.owner_account.clone_from(&owner_account);
        order.order_id = crate::derive_orderbook_order_id_v1(&owner_account, order.nonce);
        let order_outcome = orderbook_outcome(
            OrderbookKind::OrderRequest,
            &order,
            "oversized-owner-order.to",
            34,
        );
        assert_failure(&order_outcome, "SFS-VAL-001", CATEGORY_VALIDATION);
        assert!(order_outcome.message.contains("exceeds maximum 256 bytes"));
        let mut cancel = orderbook_order_cancel();
        cancel.owner_account = owner_account;
        let cancel_outcome = orderbook_outcome(
            OrderbookKind::OrderCancel,
            &cancel,
            "oversized-owner-cancel.to",
            34,
        );
        assert_failure(&cancel_outcome, "SFS-VAL-001", CATEGORY_VALIDATION);
        assert!(cancel_outcome.message.contains("exceeds maximum 256 bytes"));
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_signature_failure() {
        let mut order = orderbook_order_request();
        order.signature.signature[0] ^= 1;
        let outcome = orderbook_outcome(
            OrderbookKind::OrderRequest,
            &order,
            "bad-orderbook-signature.to",
            35,
        );
        assert_failure(&outcome, "SFS-SIG-007", CATEGORY_SIGNATURE);
    }
    #[test]
    fn orderbook_signature_errors_share_the_canonical_outcome_mapping() {
        let errors = [
            OrderbookValidationError::InvalidSignature,
            OrderbookValidationError::InvalidPublicKeyLength { length: 31 },
            OrderbookValidationError::InvalidSignatureLength { length: 63 },
            OrderbookValidationError::UnsupportedSignatureAlgorithm {
                algorithm: SignatureAlgorithm::MultiSig,
            },
            OrderbookValidationError::InvalidPublicKey {
                reason: "invalid point".to_owned(),
            },
            OrderbookValidationError::SignaturePayloadEncoding {
                reason: "encoding failed".to_owned(),
            },
            OrderbookValidationError::SignatureVerification {
                reason: "forged signature".to_owned(),
            },
        ];
        for error in errors {
            assert_eq!(orderbook_validation_code(&error), "SFS-SIG-007");
            assert_eq!(
                orderbook_validation_category(&error),
                CATEGORY_SIGNATURE,
                "{error:?}"
            );
        }
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_cancel_and_receipt_signature_failures() {
        let mut cancel = orderbook_order_cancel();
        cancel.signature.signature[0] ^= 1;
        let cancel_outcome = orderbook_outcome(
            OrderbookKind::OrderCancel,
            &cancel,
            "bad-orderbook-cancel-signature.to",
            35,
        );
        assert_failure(&cancel_outcome, "SFS-SIG-007", CATEGORY_SIGNATURE);

        let mut receipt = orderbook_settlement_receipt();
        receipt.settlement_signature.signature[0] ^= 1;
        let receipt_outcome = orderbook_outcome(
            OrderbookKind::SettlementReceipt,
            &receipt,
            "bad-orderbook-receipt-signature.to",
            35,
        );
        assert_failure(&receipt_outcome, "SFS-SIG-007", CATEGORY_SIGNATURE);
    }
    #[test]
    fn validate_orderbook_payload_bytes_rejects_settlement_imbalance() {
        let mut receipt = orderbook_settlement_receipt();
        receipt.provider_credit = micro_xor(91);
        let outcome = orderbook_outcome(
            OrderbookKind::SettlementReceipt,
            &receipt,
            "bad-orderbook-receipt.to",
            36,
        );
        assert_failure(&outcome, "SFS-OBK-002", CATEGORY_VALIDATION);
    }
    #[test]
    fn validate_replication_order_bytes_accepts_valid_order() {
        let outcome = replication_order_outcome(&replication_order(), "order.to", 1_700_000_002);
        assert_success(&outcome);
        assert_roundtrip(&outcome);
    }
    #[test]
    fn validate_appeal_finance_cancel_asset_lock_bytes_accepts_canonical_fixture() {
        let bytes =
            fixture_bytes("fixtures/sorafs_manifest/appeal_finance/cancel_asset_lock_v1.to");
        let outcome =
            validate_appeal_finance_cancel_asset_lock_bytes(&bytes, "cancel_asset_lock_v1.to", 41);
        assert_success(&outcome);
        assert_eq!(field(&outcome.context, "canonical_bytes"), Some("85"));
    }
    include!("reference/tests/replication_and_cancel_validation.rs");
    include!("reference/tests/canonical_signed_frames.rs");
    include!("reference/tests/bounded_frames.rs");
}

#[cfg(test)]
include!("reference/captured_owner_identity_tests.rs");
