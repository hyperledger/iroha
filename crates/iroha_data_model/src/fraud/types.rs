//! Fraud data model primitives and Norito schemas.
//!
//! These structs provide a deterministic interface between the ledger and
//! out-of-process risk engines. They are minimal yet feature-complete enough
//! to cover synchronous scoring, signed assessments, and governance exports.

use crate::governance::types::GovernanceParameters;
use crate::{account::AccountId, asset::AssetId};
use norito::codec::{Decode, Encode};
use std::{string::String, vec::Vec};
/// Operation that triggered a fraud screening request.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::RiskOperation")]
pub enum RiskOperation {
    /// Transfer of a fungible asset between accounts.
    TransferAsset {
        /// Asset instance being transferred (if known ahead of execution).
        asset: Option<AssetId>,
    },
    /// Registration or onboarding of a new account.
    RegisterAccount,
    /// Custom host-defined action encoded as a lower-case slug.
    Custom(String),
}
/// Rich context supplied with a [`RiskQuery`].
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::RiskContext")]
pub struct RiskContext {
    /// Identifier of the PSP tenant submitting the query.
    pub tenant_id: String,
    /// Optional session identifier for correlation across services.
    pub session_id: Option<String>,
    /// Free-form reason code (e.g., "`manual_review`", "velocity").
    pub reason: Option<String>,
}
/// Feature inputs provided to the risk engine.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::FeatureInput")]
pub struct FeatureInput {
    /// Deterministic key describing the feature.
    pub key: String,
    /// Blake2b-32 hash of the feature payload to avoid leaking PII on-chain.
    pub value_hash: [u8; 32],
}
/// Ledger-facing query emitted before a transaction is executed.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::RiskQuery")]
pub struct RiskQuery {
    /// Stable query identifier supplied by the API gateway.
    pub query_id: [u8; 32],
    /// Account being scored.
    pub subject: AccountId,
    /// Operation that triggered the request.
    pub operation: RiskOperation,
    /// Optional additional asset context.
    pub related_asset: Option<AssetId>,
    /// Deterministic feature hashes forwarded to the feature aggregator.
    pub features: Vec<FeatureInput>,
    /// Milliseconds since Unix epoch when the query was generated.
    pub issued_at_ms: u64,
    /// Additional contextual metadata.
    pub context: RiskContext,
}
/// Recommended action for a [`FraudAssessment`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::AssessmentDecision")]
pub enum AssessmentDecision {
    /// Continue processing without delay.
    Allow,
    /// Route to manual review.
    Review,
    /// Abort the transaction immediately.
    Deny,
}
/// Individual rule outcome contributing to the overall score.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Ord, PartialOrd, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::RuleOutcome")]
pub struct RuleOutcome {
    /// Stable identifier of the rule evaluated by the engine.
    pub rule_id: String,
    /// Signed score delta applied by the rule (in basis points).
    pub score_delta_bps: i16,
    /// Human-readable rationale anchored in observability dashboards.
    pub rationale: Option<String>,
}
/// Response returned by the risk engine.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::FraudAssessment")]
pub struct FraudAssessment {
    /// Identifier of the query this assessment answers.
    pub query_id: [u8; 32],
    /// Deterministic engine identifier (e.g., "risk-engine-eu1").
    pub engine_id: String,
    /// Overall risk score expressed in basis points (0-10_000).
    pub risk_score_bps: u16,
    /// Confidence level expressed in basis points (0-10_000).
    pub confidence_bps: u16,
    /// Decision to enforce on the ledger side.
    pub decision: AssessmentDecision,
    /// Deterministically ordered rule outcomes.
    pub rule_outcomes: Vec<RuleOutcome>,
    /// Milliseconds since Unix epoch when the assessment was generated.
    pub generated_at_ms: u64,
    /// Optional signature over the assessment payload (Norito encoding).
    pub signature: Option<Vec<u8>>,
}
impl FraudAssessment {
    /// Construct a new assessment ensuring deterministic rule ordering.
    pub fn new(mut rule_outcomes: Vec<RuleOutcome>, rest: FraudAssessmentParts) -> Self {
        rule_outcomes.sort();
        Self {
            query_id: rest.query_id,
            engine_id: rest.engine_id,
            risk_score_bps: rest.risk_score_bps,
            confidence_bps: rest.confidence_bps,
            decision: rest.decision,
            rule_outcomes,
            generated_at_ms: rest.generated_at_ms,
            signature: rest.signature,
        }
    }
}
/// Helper struct for [`FraudAssessment::new`] to keep argument lists readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudAssessmentParts {
    /// Identifier of the query answered by the assessment.
    pub query_id: [u8; 32],
    /// Identifier of the scoring engine producing the assessment.
    pub engine_id: String,
    /// Overall risk score in basis points.
    pub risk_score_bps: u16,
    /// Confidence level in basis points.
    pub confidence_bps: u16,
    /// Decision emitted by the risk engine.
    pub decision: AssessmentDecision,
    /// Milliseconds since Unix epoch when the assessment was generated.
    pub generated_at_ms: u64,
    /// Optional detached signature over the Norito-encoded assessment.
    pub signature: Option<Vec<u8>>,
}
/// Aggregated export for governance and auditor tooling.

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::GovernanceExport")]
pub struct GovernanceExport {
    /// Timestamp when the export was produced.
    pub generated_at_ms: u64,
    /// Parameters active at the time of export.
    pub parameters: GovernanceParameters,
    /// Risk scoring model version promoted through the pipeline.
    pub model_version: String,
    /// Blake2b-32 digest of the policy bundle handed to auditors.
    pub policy_digest: [u8; 32],
    /// Aggregated decision counts.
    pub aggregates: Vec<DecisionAggregate>,
}
/// Summary of decisions used for governance exports.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::fraud::types::DecisionAggregate")]
pub struct DecisionAggregate {
    /// Decision captured in the export.
    pub decision: AssessmentDecision,
    /// Count of occurrences.
    pub count: u64,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::id::AssetDefinitionId;
    use iroha_crypto::KeyPair;
    use iroha_model_base::domain::DomainId;
    fn checked_random_keypair() -> KeyPair {
        KeyPair::try_random().expect("generate checked fraud fixture keypair")
    }
    #[test]
    fn risk_query_encodes() {
        let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let account_id = AccountId::new(checked_random_keypair().public_key().clone());
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let asset_id = AssetId::of(asset_def, account_id.clone());
        let query = RiskQuery {
            query_id: [0xAA; 32],
            subject: account_id,
            operation: RiskOperation::TransferAsset {
                asset: Some(asset_id.clone()),
            },
            related_asset: Some(asset_id),
            features: vec![FeatureInput {
                key: "velocity.window_5m".to_string(),
                value_hash: [0x11; 32],
            }],
            issued_at_ms: 1_700_000_000_000,
            context: RiskContext {
                tenant_id: "psp-eu".to_string(),
                session_id: Some("sess-123".to_string()),
                reason: Some("velocity".to_string()),
            },
        };
        assert!(!Encode::encode(&query).is_empty());
    }
    #[test]
    fn assessment_orders_rules() {
        let outcome_a = RuleOutcome {
            rule_id: "rule.zeta".to_string(),
            score_delta_bps: 50,
            rationale: None,
        };
        let outcome_b = RuleOutcome {
            rule_id: "rule.alpha".to_string(),
            score_delta_bps: -10,
            rationale: Some("velocity".to_string()),
        };
        let parts = FraudAssessmentParts {
            query_id: [0xBB; 32],
            engine_id: "risk-engine-eu1".to_string(),
            risk_score_bps: 6400,
            confidence_bps: 8200,
            decision: AssessmentDecision::Review,
            generated_at_ms: 1_700_000_100_000,
            signature: None,
        };
        let assessment = FraudAssessment::new(vec![outcome_a.clone(), outcome_b.clone()], parts);
        let ids: Vec<_> = assessment
            .rule_outcomes
            .iter()
            .map(|o| o.rule_id.as_str())
            .collect();
        assert_eq!(ids, vec!["rule.alpha", "rule.zeta"]);
        assert!(!Encode::encode(&assessment).is_empty());
    }
    #[test]
    fn governance_export_encodes() {
        let _domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let account_id = AccountId::new(checked_random_keypair().public_key().clone());
        let asset_def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let voting_asset = AssetId::of(asset_def, account_id);
        let params = GovernanceParameters {
            voting_asset,
            base_lock_period_blocks: 1440,
            count_abstain_in_turnout: true,
            approval_threshold: 0,
            quorum_threshold: 0,
            max_active_referenda: 5,
            fast_track_max_reduction_blocks: 12,
            window_slack_blocks: 24,
            deposit_base: 1000_u64.into(),
            deposit_per_byte: 5_u64.into(),
            deposit_per_block: 50_u64.into(),
        };
        let export = GovernanceExport {
            generated_at_ms: 1_700_000_200_000,
            parameters: params,
            model_version: "risk-model-v1".to_string(),
            policy_digest: [0xEE; 32],
            aggregates: vec![DecisionAggregate {
                decision: AssessmentDecision::Allow,
                count: 42,
            }],
        };
        assert!(!Encode::encode(&export).is_empty());
    }
}

#[cfg(test)]
mod captured_types_schema_tests;
