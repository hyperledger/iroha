//! Public Torii DTOs for Parliament-governed validation-fee policy state.
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    governance::types::{
        GovernanceCertificateV1, ProposalKind, ValidationFeePayoutLifecycleProposal,
        ValidationFeePolicyProposal,
    },
    sumeragi_finality::{
        SumeragiFinalityCheckpoint, SumeragiFinalityProof, SumeragiFinalityVerifier,
        verify_checkpoint_page,
    },
    validation_fee::{
        ValidationFeeParliamentAuthorizationV1, ValidationFeePolicyRegistryEntryV1,
        ValidationFeePolicyRegistryV1, ValidationFeePolicySnapshotStatusV1, ValidationFeePolicyV1,
        ValidationFeePolicyWitnessProofV1, ValidationFeeTreasuryPayoutBindingV1,
    },
};
use norito::derive::{JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize};
/// Current validation-fee proof request/response layout.
pub const VALIDATION_FEE_POLICY_PROOF_VERSION_V1: u16 = 1;
/// Stable public JSON schema name for a locally verified policy projection.
pub const VALIDATION_FEE_VERIFIED_POLICY_PROJECTION_SCHEMA_NAME: &str =
    "iroha.validation_fee.verified_policy_projection.v1";
/// Current validation-fee proposal read/draft layout.
pub const VALIDATION_FEE_PROPOSAL_API_VERSION_V1: u16 = 1;
/// Default number of validation-fee proposals returned by one list request.
pub const VALIDATION_FEE_PROPOSAL_PAGE_DEFAULT_LIMIT_V1: u32 = 50;
/// Hard maximum number of validation-fee proposals returned by one list request.
pub const VALIDATION_FEE_PROPOSAL_PAGE_MAX_LIMIT_V1: u32 = 100;
/// Maximum encoded length of a validation-fee proposal continuation cursor.
pub const VALIDATION_FEE_PROPOSAL_CURSOR_MAX_ENCODED_LEN_V1: usize = 96;
/// Maximum number of consecutive finality proofs, including the trusted checkpoint proof.
pub const VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_PROOFS: usize = 64;
/// Maximum canonical bytes occupied by the bounded finality chain.
pub const VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_CHAIN_BYTES: usize = 3 * 1024 * 1024;
/// Defensive maximum for a complete proof response.
pub const VALIDATION_FEE_POLICY_PROOF_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Select the farthest consecutive tip that fits one checkpoint-promotion page.
#[must_use]
pub fn validation_fee_policy_proof_page_tip(
    trusted_checkpoint_height: u64,
    observed_ledger_tip_height: u64,
) -> Option<u64> {
    if trusted_checkpoint_height == 0 || trusted_checkpoint_height > observed_ledger_tip_height {
        return None;
    }
    let span = u64::try_from(VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_PROOFS - 1)
        .expect("validation-fee finality proof bound fits u64");
    Some(observed_ledger_tip_height.min(trusted_checkpoint_height.saturating_add(span)))
}
/// Request a current validation-fee registry snapshot from a caller-pinned checkpoint.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    JsonDeserialize,
    JsonSerialize,
    NoritoDeserialize,
    NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeCurrentPolicyProofRequestV1"
)]
pub struct ValidationFeeCurrentPolicyProofRequestV1 {
    /// Request layout version.
    pub version: u16,
    /// Height of the externally trusted checkpoint which must begin the returned chain.
    pub trusted_checkpoint_height: u64,
}
/// A complete registry snapshot authenticated by a block execution commitment and finality chain.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeCurrentPolicyProofV1")]
pub struct ValidationFeeCurrentPolicyProofV1 {
    /// Response layout version.
    pub version: u16,
    /// Canonical complete protected registry, or `None` before first enactment.
    #[norito(required)]
    pub registry: Option<ValidationFeePolicyRegistryV1>,
    /// Fixed synthetic ordinary-write witness for the registry snapshot.
    pub policy_witness: ValidationFeePolicyWitnessProofV1,
    /// Consecutive finality proofs beginning at the caller's checkpoint.
    pub finality_chain: Vec<SumeragiFinalityProof>,
    /// Context id at the evaluated tip, suitable for durable checkpoint promotion.
    pub evaluated_context_id: Hash,
    /// Height whose post-execution policy state was evaluated.
    pub evaluated_block_height: u64,
    /// Canonical lowercase hash of the evaluated committed block.
    pub evaluated_block_hash: String,
    /// Ledger tip observed when this bounded page was assembled.
    pub observed_ledger_tip_height: u64,
    /// Whether another checkpoint-promotion request is required to reach the observed tip.
    pub more_available: bool,
}
/// Minimal policy state returned only after local finality, witness, registry,
/// and immutable deployment-binding verification.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeVerifiedPolicyProjectionV1"
)]
pub struct ValidationFeeVerifiedPolicyProjectionV1 {
    /// Stable projection schema name.
    pub schema: String,
    /// Projection layout version.
    pub version: u16,
    /// Canonical exact genesis-derived network identity proven by finality and every policy.
    pub network_id: String,
    /// Lowercase hash of policy version one.
    pub policy_chain_genesis_hash: String,
    /// Lowercase hash of the complete immutable registry history.
    pub registry_hash: String,
    /// Latest enacted policy version, including a future scheduled successor.
    pub head_policy_version: u64,
    /// Lowercase hash of the latest enacted policy.
    pub head_policy_hash: String,
    /// JSON-safe complete policy/evidence projection effective at the evaluated height.
    pub current_policy: Option<ValidationFeeVerifiedCurrentPolicyV1>,
    /// Independently enacted conversion operations at the evaluated height.
    pub conversion_policy: Option<ValidationFeeVerifiedConversionPolicyV1>,
    /// Caller-pinned checkpoint height at which local finality verification began.
    pub trusted_checkpoint_height: u64,
    /// Lowercase caller-pinned checkpoint context id.
    pub trusted_checkpoint_context_id: String,
    /// Finalized evaluated block height.
    pub evaluated_block_height: u64,
    /// Lowercase evaluated block context id suitable for checkpoint promotion.
    pub evaluated_context_id: String,
    /// Lowercase evaluated block hash.
    pub evaluated_block_hash: String,
    /// Ledger tip observed when Torii assembled this page.
    pub observed_ledger_tip_height: u64,
    /// Whether another bounded proof page is required.
    pub more_available: bool,
}
/// Exact JSON-safe mobile policy shape derived only from a verified registry entry.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeVerifiedCurrentPolicyV1"
)]
pub struct ValidationFeeVerifiedCurrentPolicyV1 {
    /// Canonical decimal policy version.
    #[norito(rename = "activePolicyVersion")]
    pub active_policy_version: String,
    /// Canonical lowercase Iroha policy hash.
    #[norito(rename = "activePolicyHash")]
    pub active_policy_hash: String,
    /// Canonical public fee-asset definition address.
    #[norito(rename = "feeAssetDefinitionId")]
    pub fee_asset_definition_id: String,
    /// Fee-asset decimal scale.
    #[norito(rename = "feeScale")]
    pub fee_scale: u8,
    /// Exact fee minor units as a canonical decimal string.
    #[norito(rename = "feeMinorUnits")]
    pub fee_minor_units: String,
    /// Exact charging mode.
    #[norito(rename = "chargingMode")]
    pub charging_mode: String,
    /// First active height as a canonical decimal string.
    #[norito(rename = "effectiveFromHeight")]
    pub effective_from_height: String,
    /// Required Parliament-enacted retail monthly tariff.
    pub retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1,
    /// Activation Honiara month boundary in epoch milliseconds.
    pub effective_from_ms: u64,
    /// Public notice timestamp bound into the policy.
    pub notice_published_at_ms: u64,
    /// Authorization for the retail tariff, independent of conversion operations.
    pub parliament: ValidationFeeVerifiedParliamentProposalV1,
    /// Immutable reward custody committed by the retail policy.
    pub reward_custody: iroha_data_model::validation_fee::ValidationFeeRewardCustodyV1,
}
/// Independently governed conversion policy derived from the authenticated registry.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeVerifiedConversionPolicyV1"
)]
pub struct ValidationFeeVerifiedConversionPolicyV1 {
    /// Monotonic independent conversion revision.
    pub revision: u64,
    /// Complete conversion, feed and payout parameters.
    pub binding: ValidationFeeTreasuryPayoutBindingV1,
    /// Complete authorization for the conversion enactment.
    pub authority: ValidationFeeVerifiedParliamentProposalV1,
    /// Canonical Iroha hash sealing this conversion binding.
    pub lifecycle_seal_hash: String,
}
/// Complete JSON-safe authorization for one enacted Parliament proposal.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeVerifiedParliamentProposalV1"
)]
pub struct ValidationFeeVerifiedParliamentProposalV1 {
    /// Exact proposal kind expected by mobile runtime configuration.
    pub proposal_kind: String,
    /// Canonical transaction authority bound into the proposal preimage.
    pub proposal_operator: AccountId,
    /// Raw native proposal fingerprint in canonical lowercase hexadecimal.
    pub proposal_id: String,
    /// Fingerprint of the exact typed proposal preimage.
    pub payload_hash: String,
    /// Canonical identifier of the complete Parliament certificate.
    pub governance_certificate_id: String,
    /// Complete certificate required for independent structural validation.
    pub governance_certificate: GovernanceCertificateV1,
    /// Height of the final body result, at which the certificate was atomically finalized.
    pub certified_at_height: String,
    /// Exact certified height at which enactment was due and occurred.
    pub enacted_at_height: String,
}
fn verified_parliament_proposal(
    proposal_kind: &str,
    authorization: &ValidationFeeParliamentAuthorizationV1,
) -> Result<ValidationFeeVerifiedParliamentProposalV1, String> {
    if let Some(reason) = authorization.invariant_error() {
        return Err(format!(
            "validation-fee Parliament authorization is invalid: {reason}"
        ));
    }
    let proposal_id = hex::encode(authorization.proposal_fingerprint);
    Ok(ValidationFeeVerifiedParliamentProposalV1 {
        proposal_kind: proposal_kind.to_owned(),
        proposal_operator: authorization.proposal_operator.clone(),
        proposal_id: proposal_id.clone(),
        payload_hash: hex::encode(authorization.proposal_fingerprint),
        governance_certificate_id: hex::encode(authorization.governance_certificate_id.as_bytes()),
        governance_certificate: authorization.governance_certificate.clone(),
        certified_at_height: authorization
            .governance_certificate
            .certified_at_height
            .to_string(),
        enacted_at_height: authorization.enacted_at_height.to_string(),
    })
}
fn verified_current_policy(
    entry: &ValidationFeePolicyRegistryEntryV1,
) -> Result<Option<ValidationFeeVerifiedCurrentPolicyV1>, String> {
    Ok(Some(ValidationFeeVerifiedCurrentPolicyV1 {
        active_policy_version: entry.policy.policy_version.to_string(),
        active_policy_hash: hex::encode(entry.policy_hash),
        fee_asset_definition_id: entry.policy.ds_asset_id.to_string(),
        fee_scale: entry.policy.ds_scale,
        fee_minor_units: iroha_data_model::fastpq::normalized_numeric_to_u64(
            entry.policy.fee.as_numeric(),
            2,
        )
        .ok_or("institutional fee is not exact SBD cents")?
        .to_string(),
        charging_mode: "RETAIL_MONTHLY_ALLOWANCE".to_owned(),
        retail_schedule: entry.policy.retail_schedule.clone(),
        effective_from_ms: entry.policy.effective_from_ms,
        notice_published_at_ms: entry.policy.notice_published_at_ms,
        effective_from_height: entry
            .parliament_authorization
            .enacted_at_height
            .checked_add(1)
            .ok_or("finalized policy availability height overflow")?
            .to_string(),
        parliament: verified_parliament_proposal(
            "ValidationFeePolicyV1",
            &entry.parliament_authorization,
        )?,
        reward_custody: entry.policy.reward_custody.clone(),
    }))
}
impl ValidationFeeCurrentPolicyProofV1 {
    /// Verify the canonical registry, ordinary-write witness, and checkpoint-to-tip finality chain.
    ///
    /// # Errors
    ///
    /// Returns a stable explanation when any portable binding is malformed or inconsistent.
    pub fn verify_against(
        &self,
        network_id: NetworkId,
        trusted_checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<SumeragiFinalityCheckpoint, String> {
        if self.version != VALIDATION_FEE_POLICY_PROOF_VERSION_V1
            || trusted_checkpoint.height() == 0
            || self.evaluated_block_height == 0
            || self.observed_ledger_tip_height < self.evaluated_block_height
            || self.more_available
                != (self.evaluated_block_height < self.observed_ledger_tip_height)
        {
            return Err("unsupported validation-fee proof version or invalid trust anchor".into());
        }
        require_canonical_iroha_hash("validation-fee network id", network_id.as_bytes())?;
        let evaluated_block_hash =
            exact_lower_hex_32("evaluated_block_hash", &self.evaluated_block_hash)?;
        require_canonical_iroha_hash("evaluated block hash", &evaluated_block_hash)?;
        if self.finality_chain.is_empty()
            || self.finality_chain.len() > VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_PROOFS
        {
            return Err("validation-fee finality chain is empty or exceeds 64 proofs".into());
        }
        let page = verify_checkpoint_page(
            network_id,
            trusted_checkpoint,
            &self.finality_chain,
            VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_PROOFS,
            VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_CHAIN_BYTES,
        )
        .map_err(|error| format!("native finality page failed: {error}"))?;
        let evaluated = page.tip();
        if evaluated.height() != self.evaluated_block_height
            || evaluated.header().hash().as_ref() != &evaluated_block_hash
            || self.evaluated_context_id != evaluated.context_id()
        {
            return Err(
                "native finality page tip does not match the evaluated application block".into(),
            );
        }
        // The verified page already validated the complete native result commitment.
        // Application witnesses below stay bound to that same authenticated tip.
        if !self
            .policy_witness
            .verify(evaluated.execution().ordinary_writes_root)
        {
            return Err("validation-fee synthetic write proof is invalid".into());
        }
        let commitment = self.policy_witness.commitment()?;
        let evaluated_timestamp_ms = u64::try_from(evaluated.header().creation_time().as_millis())
            .map_err(|_| "evaluated block timestamp overflow".to_owned())?;
        if commitment.evaluated_height != evaluated.height()
            || commitment.evaluated_timestamp_ms != evaluated_timestamp_ms
        {
            return Err("validation-fee snapshot height or timestamp differs from finality".into());
        }
        match (&commitment.status, &self.registry) {
            (ValidationFeePolicySnapshotStatusV1::Unconfigured, None) => {}
            (ValidationFeePolicySnapshotStatusV1::Invalid(_), _) => {
                return Err("protected validation-fee registry is invalid".into());
            }
            (ValidationFeePolicySnapshotStatusV1::Available(available), Some(registry)) => {
                registry
                    .validate()
                    .map_err(|error| format!("validation-fee registry is invalid: {error}"))?;
                if registry
                    .registered_policies
                    .iter()
                    .any(|entry| entry.policy.network_id != network_id)
                {
                    return Err("validation-fee registry targets a different network".into());
                }
                if registry
                    .snapshot_hash()
                    .map_err(|error| format!("validation-fee registry hash failed: {error}"))?
                    != available.registry_hash
                    || registry.head().map(|entry| entry.policy_hash) != available.head_policy_hash
                    || registry
                        .scheduled_entry_at_height(evaluated.height())
                        .map(|entry| entry.policy_hash)
                        != available.scheduled_policy_hash
                    || registry
                        .effective_entry_at(evaluated.height(), evaluated_timestamp_ms)
                        .map(|entry| entry.policy_hash)
                        != available.effective_policy_hash
                {
                    return Err(
                        "validation-fee registry differs from its finalized snapshot commitment"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "validation-fee registry presence differs from its snapshot status".into(),
                );
            }
        }
        Ok(page.into_checkpoint())
    }
    /// Return the policy effective at the finalized evaluation height.
    #[must_use]
    pub fn current_policy(&self) -> Option<&ValidationFeePolicyV1> {
        self.registry
            .as_ref()?
            .effective_entry_at(
                self.evaluated_block_height,
                u64::try_from(
                    self.finality_chain
                        .last()?
                        .block_header
                        .creation_time()
                        .as_millis(),
                )
                .ok()?,
            )
            .map(|entry| &entry.policy)
    }
    /// Verify the proof and project it under an immutable deployment binding.
    ///
    /// This is deliberately stricter than [`Self::verify_against`]: an unconfigured registry is
    /// rejected because it cannot authenticate the caller-pinned policy-chain genesis hash.
    ///
    /// # Errors
    ///
    /// Returns an error for any proof failure, absent registry, deployment
    /// network mismatch, or policy-chain genesis mismatch.
    pub fn verify_with_immutable_binding(
        &self,
        network_id: NetworkId,
        policy_chain_genesis_hash: [u8; 32],
        trusted_checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<
        (
            ValidationFeeVerifiedPolicyProjectionV1,
            SumeragiFinalityCheckpoint,
        ),
        String,
    > {
        let promoted = self.verify_against(network_id, trusted_checkpoint)?;
        let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
            trusted_checkpoint,
            &network_id,
            trusted_checkpoint.chain_id(),
        )
        .map_err(|error| error.to_string())?;
        let trusted = verifier
            .verify_same_decision(trusted_checkpoint.tip(), trusted_checkpoint.tip())
            .map_err(|error| error.to_string())?;
        require_canonical_iroha_hash(
            "validation-fee immutable binding policy-chain genesis hash",
            &policy_chain_genesis_hash,
        )?;
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| "validation-fee registry is not configured".to_owned())?;
        let head = registry
            .head()
            .ok_or_else(|| "validation-fee registry is empty".to_owned())?;
        let genesis_policy_hash = registry
            .genesis_policy_hash()
            .ok_or_else(|| "validation-fee registry has no pricing genesis anchor".to_owned())?;
        if genesis_policy_hash != policy_chain_genesis_hash {
            return Err("validation-fee policy-chain genesis hash mismatch".into());
        }
        let registry_hash = registry
            .snapshot_hash()
            .map_err(|error| format!("validation-fee registry hash failed: {error}"))?;
        let evaluated_time_ms = u64::try_from(
            self.finality_chain
                .last()
                .ok_or("empty verified finality chain")?
                .block_header
                .creation_time()
                .as_millis(),
        )
        .map_err(|_| "ledger timestamp overflow")?;
        let current_policy = registry
            .effective_entry_at(self.evaluated_block_height, evaluated_time_ms)
            .map(verified_current_policy)
            .transpose()?
            .flatten();
        Ok((
            ValidationFeeVerifiedPolicyProjectionV1 {
                schema: VALIDATION_FEE_VERIFIED_POLICY_PROJECTION_SCHEMA_NAME.to_owned(),
                version: VALIDATION_FEE_POLICY_PROOF_VERSION_V1,
                network_id: network_id.to_string(),
                policy_chain_genesis_hash: hex::encode(policy_chain_genesis_hash),
                registry_hash: hex::encode(registry_hash),
                head_policy_version: head.policy.policy_version,
                head_policy_hash: hex::encode(head.policy_hash),
                current_policy,
                conversion_policy: registry
                    .payout_policies
                    .effective_entry_at_height(self.evaluated_block_height)
                    .map(|entry| {
                        Ok::<_, String>(ValidationFeeVerifiedConversionPolicyV1 {
                            revision: entry.revision,
                            binding: entry.payout_binding.clone(),
                            authority: verified_parliament_proposal(
                                "ValidationFeePayoutLifecycleV1",
                                &entry.parliament_authorization,
                            )?,
                            lifecycle_seal_hash: hex::encode(entry.lifecycle_seal),
                        })
                    })
                    .transpose()?,
                trusted_checkpoint_height: trusted_checkpoint.height(),
                trusted_checkpoint_context_id: hex::encode(trusted.context_id().as_ref()),
                evaluated_block_height: self.evaluated_block_height,
                evaluated_context_id: hex::encode(self.evaluated_context_id.as_ref()),
                evaluated_block_hash: self.evaluated_block_hash.clone(),
                observed_ledger_tip_height: self.observed_ledger_tip_height,
                more_available: self.more_available,
            },
            promoted,
        ))
    }
}
/// Validation-fee governance proposal status exposed by the typed read API.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, NoritoDeserialize, NoritoSerialize, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalStatusV1")]
pub enum ValidationFeeProposalStatusV1 {
    /// Parliament processing is active or certified for future execution.
    Proposed,
    /// Parliament reached a terminal rejection.
    Rejected,
    /// The proposal payload was enacted.
    Enacted,
    /// A concurrently enacted successor made this policy predecessor stale.
    Superseded,
    /// The certified proposal effect failed atomically.
    ExecutionFailed,
}
impl norito::json::FastJsonWrite for ValidationFeeProposalStatusV1 {
    fn write_json(&self, out: &mut String) {
        let label = match self {
            Self::Proposed => "Proposed",
            Self::Rejected => "Rejected",
            Self::Enacted => "Enacted",
            Self::Superseded => "Superseded",
            Self::ExecutionFailed => "ExecutionFailed",
        };
        norito::json::write_json_string(label, out);
    }
}
impl norito::json::JsonDeserialize for ValidationFeeProposalStatusV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        match parser.parse_string()?.as_str() {
            "Proposed" => Ok(Self::Proposed),
            "Rejected" => Ok(Self::Rejected),
            "Enacted" => Ok(Self::Enacted),
            "Superseded" => Ok(Self::Superseded),
            "ExecutionFailed" => Ok(Self::ExecutionFailed),
            other => Err(norito::json::Error::InvalidField {
                field: "status".to_owned(),
                message: format!("unknown governance proposal status `{other}`"),
            }),
        }
    }
}
/// One complete typed validation-fee proposal read from protected governance state.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalRecordV1")]
pub struct ValidationFeeProposalRecordV1 {
    /// Bonded citizen who created the proposal.
    pub proposer: AccountId,
    /// Exact native validation-fee proposal kind and payload.
    pub kind: ProposalKind,
    /// Height at which the proposal was created.
    #[norito(json = "first_release_exact_json_u64_number")]
    pub created_height: u64,
    /// Current proposal status.
    pub status: ValidationFeeProposalStatusV1,
}
mod first_release_exact_json_u64_number {
    use norito::json::{
        self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser,
    };

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Norito field serializers receive values by shared reference"
    )]
    pub fn serialize(value: &u64, out: &mut String) {
        value.json_serialize(out);
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "Norito bounded field serializers receive values by shared reference"
    )]
    pub fn serialize_bounded(
        value: &u64,
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        value.json_serialize_to(out)
    }

    pub fn deserialize(parser: &mut Parser<'_>) -> Result<u64, json::Error> {
        let value = u64::json_deserialize(parser)?;
        if value > iroha_data_model::parliament_types::FIRST_RELEASE_MAX_EXACT_JSON_U64 {
            return Err(json::Error::InvalidField {
                field: "created_height".to_owned(),
                message:
                    "governance proposal creation height exceeds the exact JSON integer maximum"
                        .to_owned(),
            });
        }
        Ok(value)
    }
}
fn validation_fee_proposal_default_page_limit() -> u32 {
    VALIDATION_FEE_PROPOSAL_PAGE_DEFAULT_LIMIT_V1
}
/// Bounded query for one canonical validation-fee proposal page.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalListQueryV1")]
pub struct ValidationFeeProposalListQueryV1 {
    /// Opaque continuation token returned by the preceding page.
    #[norito(default)]
    pub cursor: Option<String>,
    /// Requested record limit. Values outside `1..=100` are rejected.
    #[norito(default = "validation_fee_proposal_default_page_limit")]
    pub limit: u32,
}
impl Default for ValidationFeeProposalListQueryV1 {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: VALIDATION_FEE_PROPOSAL_PAGE_DEFAULT_LIMIT_V1,
        }
    }
}
const VALIDATION_FEE_PROPOSAL_CURSOR_MAGIC_V1: [u8; 8] = *b"vfprop01";
const VALIDATION_FEE_PROPOSAL_CURSOR_BYTES_V1: usize = 8 + 8 + 32;
/// Encode one proposal-order key as a collection-bound canonical cursor.
#[must_use]
pub fn encode_validation_fee_proposal_cursor_v1(
    created_height: u64,
    proposal_id: [u8; 32],
) -> String {
    let mut frame = [0_u8; VALIDATION_FEE_PROPOSAL_CURSOR_BYTES_V1];
    frame[..8].copy_from_slice(&VALIDATION_FEE_PROPOSAL_CURSOR_MAGIC_V1);
    frame[8..16].copy_from_slice(&created_height.to_be_bytes());
    frame[16..].copy_from_slice(&proposal_id);
    hex::encode(frame)
}
/// Decode and validate one canonical validation-fee proposal cursor.
///
/// # Errors
///
/// Returns a stable validation message when the cursor is oversized, non-canonical, belongs to
/// another collection/version, or has the wrong fixed-width payload.
pub fn decode_validation_fee_proposal_cursor_v1(encoded: &str) -> Result<(u64, [u8; 32]), String> {
    if encoded.is_empty() || encoded.len() > VALIDATION_FEE_PROPOSAL_CURSOR_MAX_ENCODED_LEN_V1 {
        return Err(
            "cursor must be a non-empty canonical lowercase-hex token within 96 bytes".into(),
        );
    }
    if !encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("cursor must use canonical lowercase hexadecimal".to_owned());
    }
    let frame = hex::decode(encoded)
        .map_err(|_| "cursor must use canonical lowercase hexadecimal".to_owned())?;
    if frame.len() != VALIDATION_FEE_PROPOSAL_CURSOR_BYTES_V1 || hex::encode(&frame) != encoded {
        return Err("cursor has a non-canonical or invalid fixed-width frame".into());
    }
    if frame[..8] != VALIDATION_FEE_PROPOSAL_CURSOR_MAGIC_V1 {
        return Err("cursor belongs to another collection or API version".into());
    }
    let created_height = u64::from_be_bytes(
        frame[8..16]
            .try_into()
            .expect("validated cursor height has fixed width"),
    );
    let proposal_id = frame[16..]
        .try_into()
        .expect("validated proposal id has fixed width");
    Ok((created_height, proposal_id))
}
/// Canonically ordered bounded page of validation-fee proposals.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalListV1")]
pub struct ValidationFeeProposalListV1 {
    /// Response layout version.
    pub version: u16,
    /// Effective bounded page size requested by the caller.
    pub limit: u32,
    /// Records ordered by creation height then proposal id.
    pub proposals: Vec<ValidationFeeProposalRecordV1>,
    /// Opaque continuation token, or `None` after the final page.
    pub next_cursor: Option<String>,
}
/// Exact validation-fee proposal detail response.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalDetailV1")]
pub struct ValidationFeeProposalDetailV1 {
    /// Response layout version.
    pub version: u16,
    /// Exact proposal record.
    pub proposal: ValidationFeeProposalRecordV1,
    /// Latest committed height used for this projection.
    pub current_height: String,
    /// Complete successful Parliament certificate, when certified.
    pub governance_certificate: Option<GovernanceCertificateV1>,
}
/// Strict empty query for one validation-fee proposal detail projection.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    NoritoDeserialize,
    NoritoSerialize,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalDetailQueryV1"
)]
pub struct ValidationFeeProposalDetailQueryV1 {}
impl norito::json::JsonSerialize for ValidationFeeProposalDetailQueryV1 {
    fn json_serialize(&self, out: &mut String) {
        out.push_str("{}");
    }

    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        norito::json::write_validated_json_to("{}", out)
    }
}
impl norito::json::JsonDeserialize for ValidationFeeProposalDetailQueryV1 {
    fn json_deserialize(
        parser: &mut norito::json::Parser<'_>,
    ) -> Result<Self, norito::json::Error> {
        let value =
            <norito::json::Value as norito::json::JsonDeserialize>::json_deserialize(parser)?;
        match value {
            norito::json::Value::Object(fields) if fields.is_empty() => Ok(Self {}),
            norito::json::Value::Object(_) => Err(norito::json::Error::Message(
                "validation-fee proposal detail query rejects unknown fields".to_owned(),
            )),
            _ => Err(norito::json::Error::Message(
                "validation-fee proposal detail query must be an empty object".to_owned(),
            )),
        }
    }
}
/// Exact native validation-fee payload requested from the draft endpoint.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(tag = "kind", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalDraftPayloadV1"
)]
pub enum ValidationFeeProposalDraftPayloadV1 {
    /// Draft a policy proposal.
    Policy {
        /// Complete policy payload.
        policy: ValidationFeePolicyV1,
    },
    /// Draft an exact payout lifecycle proposal.
    PayoutLifecycle {
        /// Complete immutable payout binding.
        payout_binding: ValidationFeeTreasuryPayoutBindingV1,
    },
}
impl ValidationFeeProposalDraftPayloadV1 {
    /// Convert the public payload into the exact native proposal kind.
    #[must_use]
    pub fn proposal_kind(&self, proposal_operator: &AccountId) -> ProposalKind {
        match self {
            Self::Policy { policy } => {
                ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
                    proposal_operator: proposal_operator.clone(),
                    policy: policy.clone(),
                })
            }
            Self::PayoutLifecycle { payout_binding } => {
                ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                    proposal_operator: proposal_operator.clone(),
                    payout_binding: payout_binding.clone(),
                })
            }
        }
    }
}
/// Strict request for one locally signable native validation-fee proposal instruction.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalDraftRequestV1"
)]
pub struct ValidationFeeProposalDraftRequestV1 {
    /// Request layout version.
    pub version: u16,
    /// Canonical transaction authority that will execute the drafted instruction.
    ///
    /// The signed transaction must use this exact authority or Core will derive
    /// a different operator-bound proposal fingerprint.
    pub proposal_operator: AccountId,
    /// Exact proposal payload.
    pub proposal: ValidationFeeProposalDraftPayloadV1,
}
/// Canonical framed native instruction returned for local signing and submission.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalInstructionDraftV1"
)]
pub struct ValidationFeeProposalInstructionDraftV1 {
    /// Registered instruction wire identifier.
    pub wire_id: String,
    /// Lowercase hexadecimal canonical framed instruction bytes.
    pub payload_hex: String,
}
/// Strict response binding a draft to its exact native proposal and instruction.
#[derive(
    Debug, Clone, PartialEq, Eq, JsonDeserialize, JsonSerialize, NoritoDeserialize, NoritoSerialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii_shared::validation_fee_api::ValidationFeeProposalDraftResponseV1"
)]
pub struct ValidationFeeProposalDraftResponseV1 {
    /// Response layout version.
    pub version: u16,
    /// Canonical transaction authority bound into `proposal_kind` and `proposal_id`.
    pub proposal_operator: AccountId,
    /// Lowercase deterministic proposal fingerprint.
    pub proposal_id: String,
    /// Exact native proposal kind produced by this draft.
    pub proposal_kind: ProposalKind,
    /// Exactly one canonical native proposal instruction.
    pub tx_instructions: Vec<ValidationFeeProposalInstructionDraftV1>,
}
fn exact_lower_hex_32(label: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal digits"
        ));
    }
    let bytes = hex::decode(value).map_err(|error| format!("{label} is invalid: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly 32 bytes"))
}
fn require_canonical_iroha_hash(label: &str, value: &[u8; 32]) -> Result<(), String> {
    if value[31] & 1 == 0 {
        return Err(format!(
            "{label} must carry the canonical Iroha hash marker"
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "validation_fee_compaction_tests.rs"]
mod compaction_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::governance::types::{
        BallotAttemptId, BeaconPulseId, BeaconSessionId, BodyElectionAttemptId, BodyInstanceId,
        GovernanceAttemptId, GovernanceCertificateId, GovernanceExpectedHeadPresentV1,
        GovernanceExpectedHeadV1, ParliamentAggregateOutcomeV1, ParliamentAggregateTallyV1,
        ParliamentBallotCertificateBindingV1, ParliamentBody, ParliamentBodyCertificateBindingV1,
        ProposalContentId, RiskTierV1, SortitionRequestV1, TleKeySessionId, TleSessionId,
        parliament_ballot_result_root_v1,
    };
    pub(super) fn fixture_account(seed: u8) -> AccountId {
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("derive deterministic validation-fee fixture account");
        AccountId::new(key_pair.public_key().clone())
    }
    pub(super) fn parliament_authorization(
        proposal_fingerprint: [u8; 32],
        enacted_at_height: u64,
    ) -> ValidationFeeParliamentAuthorizationV1 {
        let base = enacted_at_height
            .checked_sub(1_024)
            .expect("certificate lifecycle");
        let root = |marker: u8| [marker; 32];
        let proposal_content_id = ProposalContentId::new(proposal_fingerprint);
        let governance_attempt_sequence = 0;
        let governance_attempt_id =
            GovernanceAttemptId::derive_v1(proposal_content_id, governance_attempt_sequence);
        let election_attempt_sequence = 0;
        let election_attempt_id = BodyElectionAttemptId::derive_v1(
            governance_attempt_id,
            ParliamentBody::PolicyJury,
            election_attempt_sequence,
        );
        let beacon_session_id = BeaconSessionId::new(root(2));
        let sortition_request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            ParliamentBody::PolicyJury,
            root(1),
            500,
            500,
            base + 1,
            base + 2,
            beacon_session_id,
            None,
        )
        .expect("canonical Policy Jury request");
        let roster_root = root(4);
        let body_instance_id = BodyInstanceId::derive_v1(election_attempt_id, roster_root);
        let ballot_attempt_sequence = 0;
        let ballot_attempt_id =
            BallotAttemptId::derive_v1(body_instance_id, ballot_attempt_sequence);
        let release_beacon_session_id = BeaconSessionId::new(root(7));
        let tle_key_session_id = TleKeySessionId::new(root(8));
        let release_height = base + 1_021;
        let tle_session_id = TleSessionId::derive_v1(
            ballot_attempt_id,
            tle_key_session_id,
            release_beacon_session_id,
            release_height,
        );
        let opening_root = root(16);
        let tally = ParliamentAggregateTallyV1 {
            original_seats: 500,
            accepted_ballots: 334,
            aye: 200,
            nay: 100,
            abstain: 34,
        };
        let outcome = ParliamentAggregateOutcomeV1::Approved;
        let result_height = base + 1_022;
        let result_root = parliament_ballot_result_root_v1(
            governance_attempt_id,
            body_instance_id,
            ballot_attempt_id,
            opening_root,
            tally,
            outcome,
            result_height,
        );
        let governance_certificate = GovernanceCertificateV1 {
            proposal_content_id,
            governance_attempt_id,
            governance_attempt_sequence,
            risk_tier: RiskTierV1::Standard,
            body_bindings: vec![ParliamentBodyCertificateBindingV1 {
                body_instance_id,
                election_attempt_id,
                election_attempt_sequence,
                sortition_request_id: sortition_request.id,
                sortition_request,
                body: ParliamentBody::PolicyJury,
                original_seats: tally.original_seats,
                beacon_session_id,
                beacon_pulse_id: BeaconPulseId::new(root(3)),
                roster_root,
                assignment_root: root(5),
                result_root,
                result_height,
                public_finding: None,
                ballot: Some(ParliamentBallotCertificateBindingV1 {
                    ballot_attempt_id,
                    ballot_attempt_sequence,
                    tle_session_id,
                    tle_key_session_id,
                    registration_root: root(9),
                    dropout_root: root(10),
                    survivor_root: root(11),
                    corpus_root: root(12),
                    no_recovery_root: root(13),
                    timed_commitment_root: root(14),
                    release_beacon_session_id,
                    registered_at_height: base + 3,
                    registration_close_height: base + 504,
                    survivor_freeze_height: base + 1_004,
                    commitment_close_height: base + 1_020,
                    registration_closed_at_height: base + 504,
                    survivors_frozen_at_height: base + 1_004,
                    commitment_closed_at_height: base + 1_020,
                    max_ballot_retries: 3,
                    max_corpus_entries: 500,
                    release_height,
                    opening_deadline_height: result_height,
                    release_pulse_id: BeaconPulseId::new(root(15)),
                    opening_height: release_height,
                    opening_root,
                    tally,
                    outcome,
                }),
            }],
            policy_version: 1,
            effect_preimage_hash: root(19),
            expected_head: GovernanceExpectedHeadV1::Present(GovernanceExpectedHeadPresentV1 {
                subject_id: root(17),
                version: 1,
                head_root: root(18),
            }),
            certified_at_height: result_height,
            enact_at_height: enacted_at_height,
        };
        let governance_certificate_id = GovernanceCertificateId::derive_v1(&governance_certificate);
        ValidationFeeParliamentAuthorizationV1 {
            proposal_operator: fixture_account(3),
            proposal_fingerprint,
            governance_certificate_id,
            governance_certificate,
            enacted_at_height,
        }
    }
    #[test]
    fn iroha_hash_validation_requires_the_canonical_marker() {
        require_canonical_iroha_hash("checkpoint", &[0x03; 32])
            .expect("odd-ending Iroha hash is canonical");
        assert_eq!(
            require_canonical_iroha_hash("checkpoint", &[0x02; 32]),
            Err("checkpoint must carry the canonical Iroha hash marker".to_owned())
        );
        assert_eq!(
            require_canonical_iroha_hash("checkpoint", &[0; 32]),
            Err("checkpoint must carry the canonical Iroha hash marker".to_owned())
        );
    }
    #[test]
    fn verified_parliament_projection_retains_full_canonical_certificate() {
        let proposal_id = [0x02; 32];
        let authorization = parliament_authorization(proposal_id, u64::MAX);
        let projected = verified_parliament_proposal("ValidationFeePolicyV1", &authorization)
            .expect("project verified Parliament authorization");
        assert_eq!(projected.proposal_id, projected.payload_hash);
        assert_eq!(
            projected.governance_certificate_id,
            hex::encode(authorization.governance_certificate_id.as_bytes())
        );
        assert_eq!(
            projected.governance_certificate,
            authorization.governance_certificate
        );
        assert_eq!(projected.enacted_at_height, u64::MAX.to_string());
        let json = norito::json::to_string(&projected).expect("serialize JSON-safe projection");
        assert!(json.contains(r#""proposal_kind":"ValidationFeePolicyV1""#));
        assert!(json.contains(r#""governance_certificate_id":"#));
        assert!(json.contains(r#""governance_certificate":"#));
        assert!(!json.contains("plainElectorate"));
        assert!(!json.contains("referendum"));
        let roundtrip: ValidationFeeVerifiedParliamentProposalV1 =
            norito::json::from_str(&json).expect("roundtrip JSON-safe projection");
        assert_eq!(roundtrip, projected);
    }
    #[test]
    fn verified_parliament_projection_rejects_noncanonical_certificate_identity() {
        let mut authorization = parliament_authorization([0x02; 32], 2_048);
        verified_parliament_proposal("ValidationFeePolicyV1", &authorization)
            .expect("canonical certificate authorization");
        authorization.governance_certificate_id = GovernanceCertificateId::new([0xAA; 32]);
        assert!(
            verified_parliament_proposal("ValidationFeePolicyV1", &authorization).is_err(),
            "a certificate identifier not derived from the retained certificate must reject"
        );
    }
    #[test]
    fn checkpoint_promotion_pages_reach_a_distant_tip_without_gaps() {
        let observed_tip = 250;
        let mut checkpoint = 1;
        let mut pages = Vec::new();
        while checkpoint < observed_tip {
            let next = validation_fee_policy_proof_page_tip(checkpoint, observed_tip)
                .expect("valid checkpoint page");
            assert!(next > checkpoint);
            assert!(next - checkpoint < VALIDATION_FEE_POLICY_PROOF_MAX_FINALITY_PROOFS as u64);
            pages.push((checkpoint, next));
            checkpoint = next;
        }
        assert_eq!(pages, vec![(1, 64), (64, 127), (127, 190), (190, 250)]);
    }
    #[test]
    fn proposal_cursor_roundtrip_is_canonical_and_collection_bound() {
        let proposal_id = [0xA5; 32];
        let encoded = encode_validation_fee_proposal_cursor_v1(42, proposal_id);
        assert_eq!(
            encoded.len(),
            VALIDATION_FEE_PROPOSAL_CURSOR_MAX_ENCODED_LEN_V1
        );
        assert_eq!(
            decode_validation_fee_proposal_cursor_v1(&encoded),
            Ok((42, proposal_id))
        );
        let mut wrong_collection = hex::decode(&encoded).expect("decode valid cursor fixture");
        wrong_collection[0] ^= 0x01;
        let wrong_collection = hex::encode(wrong_collection);
        assert!(
            decode_validation_fee_proposal_cursor_v1(&wrong_collection)
                .expect_err("collection marker mismatch must fail")
                .contains("another collection")
        );
        assert!(decode_validation_fee_proposal_cursor_v1(&encoded.to_uppercase()).is_err());
        assert!(decode_validation_fee_proposal_cursor_v1("").is_err());
    }
    #[test]
    fn proposal_status_json_is_the_exact_five_pascal_case_strings() {
        for (status, label) in [
            (ValidationFeeProposalStatusV1::Proposed, "Proposed"),
            (ValidationFeeProposalStatusV1::Rejected, "Rejected"),
            (ValidationFeeProposalStatusV1::Enacted, "Enacted"),
            (ValidationFeeProposalStatusV1::Superseded, "Superseded"),
            (
                ValidationFeeProposalStatusV1::ExecutionFailed,
                "ExecutionFailed",
            ),
        ] {
            let json = norito::json::to_string(&status).expect("serialize proposal status");
            assert_eq!(json, format!("\"{label}\""));
            assert_eq!(
                norito::json::from_str::<ValidationFeeProposalStatusV1>(&json)
                    .expect("deserialize proposal status"),
                status
            );
        }
        for retired in [
            r#""Approved""#,
            r#""PROPOSED""#,
            r#"{"status":"PROPOSED","value":null}"#,
        ] {
            assert!(
                norito::json::from_str::<ValidationFeeProposalStatusV1>(retired).is_err(),
                "retired status representation must reject: {retired}"
            );
        }
    }
    #[test]
    fn proposal_created_height_json_rejects_inexact_numbers() {
        let maximum = iroha_data_model::parliament_types::FIRST_RELEASE_MAX_EXACT_JSON_U64;
        let maximum_json = maximum.to_string();
        let mut parser = norito::json::Parser::new(&maximum_json);
        assert_eq!(
            first_release_exact_json_u64_number::deserialize(&mut parser)
                .expect("the exact JSON integer maximum is valid"),
            maximum
        );
        let hostile_json = (maximum + 1).to_string();
        let mut parser = norito::json::Parser::new(&hostile_json);
        assert!(
            first_release_exact_json_u64_number::deserialize(&mut parser).is_err(),
            "one above the exact JSON integer maximum must reject"
        );
    }
    #[test]
    fn proposal_list_query_defaults_to_a_bounded_page() {
        let query: ValidationFeeProposalListQueryV1 =
            norito::json::from_str("{}").expect("decode default proposal page query");
        assert_eq!(query, ValidationFeeProposalListQueryV1::default());
        assert_eq!(query.limit, VALIDATION_FEE_PROPOSAL_PAGE_DEFAULT_LIMIT_V1);
    }
}

/// Native evaluated quote; the complete assessment is copied into signed transaction metadata.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeQuoteResponseV1 {
    /// Exact canonical request evaluated by the ledger.
    pub request: iroha_data_model::validation_fee::RetailFeeQuoteRequestV1,
    /// Consensus-revalidated assessment.
    pub assessment: iroha_data_model::validation_fee::RetailFeeAssessmentV1,
    /// Hash of the active Parliament policy, for verified policy comparison.
    pub policy_hash_hex: String,
    /// Finalized state height used to evaluate this quote.
    pub ledger_finalised_height: u64,
}
/// Authenticated monthly status; unenrolled accounts use institutional per-payment pricing.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeStatusResponseV1 {
    /// Protected enrollment and current logically settled monthly state.
    pub account_state: Option<iroha_data_model::validation_fee::RetailFeeAccountStateV1>,
    /// Active verified policy hash.
    pub policy_hash_hex: String,
    /// Finalized state height used for this projection.
    pub ledger_finalised_height: u64,
    /// Governing per-payment rate for unenrolled institutional sending accounts.
    pub institutional_fee_minor: u64,
    /// Active retail tariff.
    pub retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1,
    /// Current estimated full-month maintenance based on the observed average.
    pub estimated_maintenance_minor: u64,
    /// Next Parliament revision awaiting its notified calendar boundary.
    pub forthcoming_policy: Option<ValidationFeePolicyV1>,
}

/// Bounded immutable receipt-page selector.
#[derive(Debug, Clone, Default, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeReceiptsQueryV1 {
    /// Continue after this lowercase hexadecimal receipt identifier.
    #[norito(default)]
    pub after_receipt_id: Option<String>,
    /// Page size, default 50 and maximum 100.
    #[norito(default)]
    pub limit: Option<u32>,
}
/// Authenticated immutable receipt projection from one finalized state snapshot.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeReceiptsResponseV1 {
    /// Native receipts in canonical receipt-id order.
    pub receipts: Vec<iroha_data_model::validation_fee::RetailFeeReceiptV1>,
    /// Compact native membership proof aligned one-to-one with `receipts`.
    pub receipt_proofs: Vec<iroha_data_model::fee_evidence::FeeEvidenceRecordProofV1>,
    /// Unique finalized block proofs in height order; verify against an independent checkpoint.
    pub finality_proofs: Vec<SumeragiFinalityProof>,
    /// Snapshot height used for this page.
    pub ledger_finalised_height: u64,
    /// Resume token when a full page was returned.
    pub next_receipt_id: Option<String>,
    /// Distinguishes an evaluated projection from independently verified witness evidence.
    pub assurance: String,
}

/// Authenticated current wallet head and its exact finalized execution commitment.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeCurrentHeadResponseV1 {
    /// Membership in the cumulative wallet-head root committed by this finalized block.
    pub proof: iroha_data_model::fee_evidence::RetailFeeCurrentHeadProofV1,
    /// Exact finalized block; independently anchor it before verifying the head.
    pub finality_proof: SumeragiFinalityProof,
}
/// Immutable history page selected by a previously verified receipt frontier.
#[derive(
    Debug,
    Clone,
    JsonSerialize,
    JsonDeserialize,
    NoritoSerialize,
    NoritoDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_torii_shared::validation_fee_api::RetailFeeStatementRequestV1")]
pub struct RetailFeeStatementRequestV1 {
    /// Cursor derived only from a verified head or the preceding verified page.
    pub cursor: iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1,
    /// Maximum receipts, from one through one hundred.
    pub limit: u32,
}
/// Complete contiguous backwards receipt page; verify before retaining its successor cursor.
#[derive(Debug, Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct RetailFeeStatementResponseV1 {
    /// Exact caller-supplied authenticated frontier, echoed unchanged.
    pub cursor: iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1,
    /// Only this wallet's immutable linked receipts, in descending sequence order.
    pub page: iroha_data_model::fee_evidence::RetailFeeReceiptPageV1,
    /// Recompute this cursor with the native page verifier before persisting it.
    pub next_cursor: iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1,
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        macro_rules! check {
            ($ty:ident) => {
                crate::captured_identity_tests::assert_bidirectional::<super::$ty>(concat!(
                    "iroha_torii_shared::validation_fee_api::",
                    stringify!($ty)
                ));
            };
        }
        check!(ValidationFeeCurrentPolicyProofRequestV1);
        check!(ValidationFeeCurrentPolicyProofV1);
        check!(ValidationFeeProposalDetailQueryV1);
        check!(ValidationFeeProposalDetailV1);
        check!(ValidationFeeProposalDraftPayloadV1);
        check!(ValidationFeeProposalDraftRequestV1);
        check!(ValidationFeeProposalDraftResponseV1);
        check!(ValidationFeeProposalInstructionDraftV1);
        check!(ValidationFeeProposalListQueryV1);
        check!(ValidationFeeProposalListV1);
        check!(ValidationFeeProposalRecordV1);
        check!(ValidationFeeProposalStatusV1);
        check!(ValidationFeeVerifiedCurrentPolicyV1);
        check!(ValidationFeeVerifiedParliamentProposalV1);
        check!(ValidationFeeVerifiedPolicyProjectionV1);
    }
}
