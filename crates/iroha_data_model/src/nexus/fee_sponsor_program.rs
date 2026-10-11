//! On-chain Nexus fee sponsor program model.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use crate::{account::AccountId, asset::AssetDefinitionId, smart_contract::ContractAddress};
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{collections::BTreeSet, fmt, num::NonZeroU64, str::FromStr};
/// Error returned while parsing [`FeeSponsorProgramId`] literals.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum FeeSponsorProgramIdParseError {
    /// The program literal must use `sponsor/program`.
    #[error("fee sponsor program literal must use `sponsor/program`")]
    InvalidFormat,
    /// Sponsor account literal is invalid.
    #[error("invalid sponsor account: {0}")]
    InvalidSponsor(String),
    /// Program name is invalid.
    #[error("invalid program name: {0}")]
    InvalidName(String),
}
/// Stable on-chain identifier for one fee sponsor program.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramId")]
pub struct FeeSponsorProgramId {
    /// Sponsor account that owns the program.
    pub sponsor: AccountId,
    /// Sponsor-local program name.
    pub name: Name,
}
impl FeeSponsorProgramId {
    /// Construct a sponsor program identifier.
    #[must_use]
    pub const fn new(sponsor: AccountId, name: Name) -> Self {
        Self { sponsor, name }
    }
}
impl fmt::Display for FeeSponsorProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.sponsor, self.name)
    }
}
impl FromStr for FeeSponsorProgramId {
    type Err = FeeSponsorProgramIdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sponsor, name) = s
            .split_once('/')
            .ok_or(FeeSponsorProgramIdParseError::InvalidFormat)?;
        if s.trim() != s || sponsor.trim() != sponsor || name.trim() != name || name.contains('/') {
            return Err(FeeSponsorProgramIdParseError::InvalidFormat);
        }
        let sponsor_literal = sponsor;
        let sponsor = AccountId::parse_encoded(sponsor_literal)
            .map_err(|err| FeeSponsorProgramIdParseError::InvalidSponsor(err.to_string()))?;
        if sponsor.to_string() != sponsor_literal {
            return Err(FeeSponsorProgramIdParseError::InvalidFormat);
        }
        let name = Name::from_str(name)
            .map_err(|err| FeeSponsorProgramIdParseError::InvalidName(err.to_string()))?;
        Ok(Self::new(sponsor, name))
    }
}
/// Primary key for one immutable sponsor-program revision.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramRevisionKey"
)]
pub struct FeeSponsorProgramRevisionKey {
    /// Program owning the immutable revision.
    pub program_id: FeeSponsorProgramId,
    /// Monotonic sponsor-program revision number.
    pub revision: u64,
}
impl FeeSponsorProgramRevisionKey {
    /// Construct an immutable sponsor-program revision key.
    #[must_use]
    pub const fn new(program_id: FeeSponsorProgramId, revision: u64) -> Self {
        Self {
            program_id,
            revision,
        }
    }
}
/// Consensus-visible lifecycle of a fee sponsor program.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramLifecycle")]
pub enum FeeSponsorProgramLifecycle {
    /// Program is being provisioned and has never sponsored transactions.
    Staged,
    /// Previously active program is deliberately stopped.
    Paused,
    /// Program may sponsor transactions under its active revision.
    Active,
    /// Program rejects new sponsorship while its balances and receipts are drained.
    Closing,
    /// Program is a permanent tombstone and its identifier cannot be reused.
    Closed,
}
/// Accounts eligible to use a fee sponsor program.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "mode", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorEligibility")]
pub enum FeeSponsorEligibility {
    /// Only explicitly enrolled accounts may use the program.
    EnrolledOnly,
    /// Enrolled accounts and accounts routed through this exact default may use it.
    EnrolledOrRouteDefault,
}
/// Effect of a sponsor rule when it matches a signed operation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "effect", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorRuleEffect")]
pub enum FeeSponsorRuleEffect {
    /// Permit the matched operation unless a deny rule also matches it.
    Allow,
    /// Reject the matched operation even if an allow rule matches it.
    Deny,
}
/// Exact selector payload for one native instruction.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorNativeInstructionSelector"
)]
pub struct FeeSponsorNativeInstructionSelector {
    /// Exact registered instruction wire ID.
    pub wire_id: String,
    /// Exact transferred asset definition, when the instruction is an asset transfer.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub asset_definition_id: Option<AssetDefinitionId>,
}
/// Multisig operation that a sponsor rule may authorize.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "operation", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorMultisigOperation")]
pub enum FeeSponsorMultisigOperation {
    /// Propose a transaction for an existing multisig account.
    Propose,
    /// Approve an existing proposal for a multisig account.
    Approve,
    /// Cancel an existing proposal for a multisig account.
    Cancel,
    /// Register a new multisig account.
    Register,
}
/// Exact selector for explicitly enumerated multisig operations and target accounts.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorMultisigSelector")]
pub struct FeeSponsorMultisigSelector {
    /// Non-empty, strictly ordered set of explicitly allowed operations.
    pub operations: Vec<FeeSponsorMultisigOperation>,
    /// Non-empty, strictly ordered set of exact target account IDs.
    pub account_ids: Vec<AccountId>,
}
/// Exact selector payload for one deployed contract and code version.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorContractSelector")]
pub struct FeeSponsorContractSelector {
    /// Exact target address.
    pub contract_address: ContractAddress,
    /// Exact expected deployed code hash.
    pub code_hash: Hash,
    /// Non-empty set of exact allowed entrypoint names.
    #[norito(default)]
    pub entrypoints: Vec<String>,
}
/// Exact selector payload for one IVM bytecode hash.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorIvmSelector")]
pub struct FeeSponsorIvmSelector {
    /// Hash of the signed IVM bytecode.
    pub code_hash: Hash,
}
/// Exact selector for one class of signed transaction operation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorRuleSelector")]
pub enum FeeSponsorRuleSelector {
    /// One native instruction wire ID, optionally restricted to an asset definition.
    NativeInstruction(FeeSponsorNativeInstructionSelector),
    /// Explicit multisig operations restricted to exact target accounts.
    Multisig(FeeSponsorMultisigSelector),
    /// One deployed contract and code version, optionally restricted to entrypoints.
    ContractCall(FeeSponsorContractSelector),
    /// One exact raw IVM program hash.
    Ivm(FeeSponsorIvmSelector),
    /// One exact proved-IVM program hash.
    IvmProved(FeeSponsorIvmSelector),
    /// Propose or approve the exact canonical native multisig contract-call envelope.
    ///
    /// Both the submitting beneficiary and the registered target controller must be
    /// explicitly enrolled in this program. The complete inner envelope must bind
    /// this exact live contract, code hash, and one enumerated entrypoint. Arbitrary
    /// instructions, nested multisig, cancellation, and registration are excluded.
    EnrolledMultisigContractCall(FeeSponsorContractSelector),
}
/// One stable, ordered sponsor-program rule.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorRule")]
pub struct FeeSponsorRule {
    /// Revision-local stable rule identifier used in diagnostics.
    pub id: Name,
    /// Allow or deny effect.
    pub effect: FeeSponsorRuleEffect,
    /// Exact signed-intent selectors matched by this rule.
    pub selectors: Vec<FeeSponsorRuleSelector>,
}
impl FeeSponsorRule {
    /// Construct a rule with no selectors.
    #[must_use]
    pub const fn new(id: Name, effect: FeeSponsorRuleEffect) -> Self {
        Self {
            id,
            effect,
            selectors: Vec::new(),
        }
    }
}
/// Deterministic spending limits for one fee asset.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorAssetBudget")]
pub struct FeeSponsorAssetBudget {
    /// Canonical fee asset governed by these limits.
    pub asset_definition_id: AssetDefinitionId,
    /// Maximum combined charge for one transaction.
    pub per_transaction: Quantity,
    /// Maximum combined charge in one block.
    pub per_block: Quantity,
    /// Maximum combined program charge in one epoch.
    pub per_program_epoch: Quantity,
    /// Maximum charge for one beneficiary in one epoch.
    pub per_beneficiary_epoch: Quantity,
    /// Amount that must remain available after admission.
    pub reserve_floor: Quantity,
    /// Number of consensus blocks in one budget epoch.
    pub epoch_length_blocks: NonZeroU64,
}
/// Immutable rules and budgets for one sponsor-program revision.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramRevision")]
pub struct FeeSponsorProgramRevision {
    /// Program owning this revision.
    pub program_id: FeeSponsorProgramId,
    /// Monotonically increasing revision number; zero is invalid.
    pub revision: u64,
    /// Beneficiary eligibility mode.
    pub eligibility: FeeSponsorEligibility,
    /// Ordered signed-intent rules. Deny matches override allow matches.
    pub rules: Vec<FeeSponsorRule>,
    /// Per-asset deterministic spending limits.
    pub asset_budgets: Vec<FeeSponsorAssetBudget>,
}
/// Error returned when a sponsor-program revision violates canonical invariants.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum FeeSponsorProgramRevisionError {
    /// Revision zero is reserved and cannot be staged.
    #[error("fee sponsor program revision must be nonzero")]
    ZeroRevision,
    /// A new revision must be greater than the program's latest revision.
    #[error("fee sponsor program revision {revision} must be greater than {latest}")]
    NonMonotonicRevision {
        /// Proposed revision.
        revision: u64,
        /// Latest persisted revision.
        latest: u64,
    },
    /// A revision must contain at least one rule.
    #[error("fee sponsor program revision must contain at least one rule")]
    NoRules,
    /// At least one rule must explicitly allow signed intent.
    #[error("fee sponsor program revision must contain at least one allow rule")]
    NoAllowRule,
    /// Rule identifiers must be unique within a revision.
    #[error("duplicate fee sponsor rule id `{0}`")]
    DuplicateRuleId(Name),
    /// Empty selector sets cannot act as implicit wildcards.
    #[error("fee sponsor rule `{0}` must contain at least one exact selector")]
    EmptyRuleSelectors(Name),
    /// Exact selectors must not be repeated within one rule.
    #[error("fee sponsor rule `{0}` contains a duplicate selector")]
    DuplicateRuleSelector(Name),
    /// Native instruction wire IDs must be nonempty, unpadded canonical strings.
    #[error("fee sponsor rule `{0}` contains an invalid native instruction wire id")]
    InvalidInstructionWireId(Name),
    /// Multisig selectors must enumerate at least one operation.
    #[error("fee sponsor rule `{0}` contains a multisig selector without operations")]
    EmptyMultisigOperations(Name),
    /// Multisig operations must be unique and strictly ordered.
    #[error("fee sponsor rule `{0}` contains non-canonical multisig operations")]
    NonCanonicalMultisigOperations(Name),
    /// Multisig selectors must enumerate at least one exact account ID.
    #[error("fee sponsor rule `{0}` contains a multisig selector without account ids")]
    EmptyMultisigAccounts(Name),
    /// Multisig account IDs must be unique and strictly ordered.
    #[error("fee sponsor rule `{0}` contains non-canonical multisig account ids")]
    NonCanonicalMultisigAccounts(Name),
    /// Contract selectors must enumerate at least one exact entrypoint.
    #[error("fee sponsor rule `{0}` contains a contract selector without exact entrypoints")]
    EmptyContractEntrypoints(Name),
    /// Contract entrypoint names must be nonempty and unique.
    #[error(
        "fee sponsor rule `{rule_id}` contains an invalid or duplicate entrypoint `{entrypoint}`"
    )]
    InvalidContractEntrypoint {
        /// Rule containing the invalid entrypoint.
        rule_id: Name,
        /// Empty or duplicate entrypoint value.
        entrypoint: String,
    },
    /// A revision must declare at least one fee-asset budget.
    #[error("fee sponsor program revision must contain at least one asset budget")]
    NoAssetBudgets,
    /// Asset budgets must be strictly ordered by canonical asset-definition ID.
    #[error("fee sponsor asset budgets must be unique and canonically ordered")]
    NonCanonicalAssetBudgets,
    /// Every admission limit other than the reserve floor must be positive.
    #[error("fee sponsor budget for `{0}` contains a zero spending limit")]
    ZeroBudgetLimit(AssetDefinitionId),
    /// Nested spending limits must not exceed their enclosing limits.
    #[error("fee sponsor budget limits for `{0}` are inconsistent")]
    InconsistentBudgetLimits(AssetDefinitionId),
}
impl FeeSponsorProgramRevision {
    /// Validate self-contained, consensus-visible revision invariants.
    ///
    /// Selector existence checks that depend on live instruction, contract, or
    /// asset registries remain the responsibility of stateful admission.
    ///
    /// # Errors
    ///
    /// Returns a precise [`FeeSponsorProgramRevisionError`] for the first
    /// non-canonical revision, rule, selector, or asset-budget invariant.
    pub fn validate(&self) -> Result<(), FeeSponsorProgramRevisionError> {
        if self.revision == 0 {
            return Err(FeeSponsorProgramRevisionError::ZeroRevision);
        }
        if self.rules.is_empty() {
            return Err(FeeSponsorProgramRevisionError::NoRules);
        }
        if !self
            .rules
            .iter()
            .any(|rule| rule.effect == FeeSponsorRuleEffect::Allow)
        {
            return Err(FeeSponsorProgramRevisionError::NoAllowRule);
        }
        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            if !rule_ids.insert(rule.id.clone()) {
                return Err(FeeSponsorProgramRevisionError::DuplicateRuleId(
                    rule.id.clone(),
                ));
            }
            if rule.selectors.is_empty() {
                return Err(FeeSponsorProgramRevisionError::EmptyRuleSelectors(
                    rule.id.clone(),
                ));
            }
            let mut selectors = BTreeSet::new();
            for selector in &rule.selectors {
                if !selectors.insert(selector) {
                    return Err(FeeSponsorProgramRevisionError::DuplicateRuleSelector(
                        rule.id.clone(),
                    ));
                }
                match selector {
                    FeeSponsorRuleSelector::NativeInstruction(selector)
                        if selector.wire_id.is_empty()
                            || selector.wire_id.trim() != selector.wire_id =>
                    {
                        return Err(FeeSponsorProgramRevisionError::InvalidInstructionWireId(
                            rule.id.clone(),
                        ));
                    }
                    FeeSponsorRuleSelector::Multisig(selector) => {
                        if selector.operations.is_empty() {
                            return Err(FeeSponsorProgramRevisionError::EmptyMultisigOperations(
                                rule.id.clone(),
                            ));
                        }
                        if selector
                            .operations
                            .windows(2)
                            .any(|pair| pair[0] >= pair[1])
                        {
                            return Err(
                                FeeSponsorProgramRevisionError::NonCanonicalMultisigOperations(
                                    rule.id.clone(),
                                ),
                            );
                        }
                        if selector.account_ids.is_empty() {
                            return Err(FeeSponsorProgramRevisionError::EmptyMultisigAccounts(
                                rule.id.clone(),
                            ));
                        }
                        if selector
                            .account_ids
                            .windows(2)
                            .any(|pair| pair[0] >= pair[1])
                        {
                            return Err(
                                FeeSponsorProgramRevisionError::NonCanonicalMultisigAccounts(
                                    rule.id.clone(),
                                ),
                            );
                        }
                    }
                    FeeSponsorRuleSelector::ContractCall(selector)
                    | FeeSponsorRuleSelector::EnrolledMultisigContractCall(selector) => {
                        if selector.entrypoints.is_empty() {
                            return Err(FeeSponsorProgramRevisionError::EmptyContractEntrypoints(
                                rule.id.clone(),
                            ));
                        }
                        let mut previous: Option<&str> = None;
                        for entrypoint in &selector.entrypoints {
                            if entrypoint.is_empty()
                                || entrypoint.trim() != entrypoint
                                || previous.is_some_and(|previous| previous >= entrypoint.as_str())
                            {
                                return Err(
                                    FeeSponsorProgramRevisionError::InvalidContractEntrypoint {
                                        rule_id: rule.id.clone(),
                                        entrypoint: entrypoint.clone(),
                                    },
                                );
                            }
                            previous = Some(entrypoint);
                        }
                    }
                    _ => {}
                }
            }
        }
        if self.asset_budgets.is_empty() {
            return Err(FeeSponsorProgramRevisionError::NoAssetBudgets);
        }
        if self
            .asset_budgets
            .windows(2)
            .any(|pair| pair[0].asset_definition_id >= pair[1].asset_definition_id)
        {
            return Err(FeeSponsorProgramRevisionError::NonCanonicalAssetBudgets);
        }
        for budget in &self.asset_budgets {
            if budget.per_transaction.is_zero()
                || budget.per_block.is_zero()
                || budget.per_program_epoch.is_zero()
                || budget.per_beneficiary_epoch.is_zero()
            {
                return Err(FeeSponsorProgramRevisionError::ZeroBudgetLimit(
                    budget.asset_definition_id.clone(),
                ));
            }
            if budget.per_transaction > budget.per_block
                || budget.per_block > budget.per_program_epoch
                || budget.per_beneficiary_epoch > budget.per_program_epoch
            {
                return Err(FeeSponsorProgramRevisionError::InconsistentBudgetLimits(
                    budget.asset_definition_id.clone(),
                ));
            }
        }
        Ok(())
    }
    /// Validate this revision as the strict successor of `latest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the revision is internally invalid or does not
    /// advance monotonically beyond the latest enacted revision.
    pub fn validate_successor_of(
        &self,
        latest: Option<u64>,
    ) -> Result<(), FeeSponsorProgramRevisionError> {
        self.validate()?;
        if let Some(latest) = latest
            && self.revision <= latest
        {
            return Err(FeeSponsorProgramRevisionError::NonMonotonicRevision {
                revision: self.revision,
                latest,
            });
        }
        Ok(())
    }
}
/// Persisted delayed activation of one immutable sponsor-program revision.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramActivation")]
pub struct FeeSponsorProgramActivation {
    /// Revision that will become active.
    pub revision: u64,
    /// Earliest consensus height at which the switch may take effect.
    ///
    /// Consensus postpones the switch until every older-revision spend lease has expired.
    pub activate_at_height: u64,
}
/// Sponsor-owned lifecycle record for a fee sponsor program.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgram")]
pub struct FeeSponsorProgram {
    /// Stable program identifier.
    pub id: FeeSponsorProgramId,
    /// Immutable registered account that receives every vault withdrawal.
    pub payout_account: AccountId,
    /// Current lifecycle state.
    pub lifecycle: FeeSponsorProgramLifecycle,
    /// Active immutable revision, if any.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub active_revision: Option<u64>,
    /// Staged immutable revision awaiting activation, if any.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub staged_revision: Option<u64>,
    /// Delayed activation scheduled for a staged immutable revision.
    #[norito(skip_serializing_if = "Option::is_none")]
    #[norito(default)]
    pub scheduled_activation: Option<FeeSponsorProgramActivation>,
}
impl FeeSponsorProgram {
    /// Construct a staged, fail-closed program with an immutable payout account and no revisions.
    #[must_use]
    pub const fn new(id: FeeSponsorProgramId, payout_account: AccountId) -> Self {
        Self {
            id,
            payout_account,
            lifecycle: FeeSponsorProgramLifecycle::Staged,
            active_revision: None,
            staged_revision: None,
            scheduled_activation: None,
        }
    }
}
/// Primary key for an enrolled sponsor-program beneficiary.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorEnrollmentKey")]
pub struct FeeSponsorEnrollmentKey {
    /// Program granting eligibility.
    pub program_id: FeeSponsorProgramId,
    /// Canonical beneficiary account.
    pub beneficiary: AccountId,
}
/// Persisted sponsor-program enrollment.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorEnrollment")]
pub struct FeeSponsorEnrollment {
    /// Enrollment primary key.
    pub key: FeeSponsorEnrollmentKey,
    /// Consensus height at which enrollment took effect.
    pub enrolled_at_height: u64,
}
/// Primary key for one program-isolated fee-asset vault allocation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorVaultKey")]
pub struct FeeSponsorVaultKey {
    /// Program owning the allocation.
    pub program_id: FeeSponsorProgramId,
    /// Canonical allocated asset definition.
    pub asset_definition_id: AssetDefinitionId,
}
/// Persisted program-isolated vault allocation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorVault")]
pub struct FeeSponsorVault {
    /// Vault primary key.
    pub key: FeeSponsorVaultKey,
    /// Amount allocated to this exact program and asset.
    pub balance: Quantity,
}
/// Block-scoped sponsor budget window.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorBlockBudgetWindow")]
pub struct FeeSponsorBlockBudgetWindow {
    /// Consensus block height.
    pub height: u64,
}
/// Program-wide epoch sponsor budget window.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorProgramEpochBudgetWindow"
)]
pub struct FeeSponsorProgramEpochBudgetWindow {
    /// Height-derived epoch number.
    pub epoch: u64,
}
/// Beneficiary-scoped epoch sponsor budget window.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorBeneficiaryEpochBudgetWindow"
)]
pub struct FeeSponsorBeneficiaryEpochBudgetWindow {
    /// Height-derived epoch number.
    pub epoch: u64,
    /// Canonical beneficiary account.
    pub beneficiary: AccountId,
}
/// Deterministic accounting window for a sponsor budget counter.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorBudgetWindow")]
pub enum FeeSponsorBudgetWindow {
    /// Aggregate capacity consumed in one exact consensus block.
    Block(FeeSponsorBlockBudgetWindow),
    /// Aggregate program capacity consumed in one deterministic epoch.
    ProgramEpoch(FeeSponsorProgramEpochBudgetWindow),
    /// Capacity consumed by one beneficiary in one deterministic epoch.
    BeneficiaryEpoch(FeeSponsorBeneficiaryEpochBudgetWindow),
}
/// Key for a durable program budget counter.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorBudgetCounterKey")]
pub struct FeeSponsorBudgetCounterKey {
    /// Program whose capacity was consumed.
    pub program_id: FeeSponsorProgramId,
    /// Canonical charged asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact block, program-epoch, or beneficiary-epoch accounting window.
    pub window: FeeSponsorBudgetWindow,
}
/// Durable amount charged against one sponsor budget counter.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeSponsorBudgetCounter")]
pub struct FeeSponsorBudgetCounter {
    /// Counter primary key.
    pub key: FeeSponsorBudgetCounterKey,
    /// Actual deterministic fees charged in the keyed epoch.
    pub spent: Quantity,
}
/// Funding source recorded by fee receipts and settlement records.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeDebitSource")]
pub enum FeeDebitSource {
    /// Charge the transaction authority's ordinary account balance.
    Account(AccountId),
    /// Charge a program-isolated protocol vault allocation.
    SponsorProgram(FeeSponsorProgramId),
}
/// Stable machine-readable reason why sponsor-program admission failed.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "code", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::nexus::fee_sponsor_program::FeeRejectionCode")]
pub enum FeeRejectionCode {
    /// Signed fee intent is absent or malformed.
    InvalidFeeIntent,
    /// Referenced sponsor program does not exist.
    ProgramNotFound,
    /// Referenced immutable revision does not exist.
    RevisionNotFound,
    /// Referenced revision is not currently active.
    RevisionNotActive,
    /// Program lifecycle does not accept new sponsorship.
    ProgramNotActive,
    /// Beneficiary is neither enrolled nor eligible through the exact route default.
    BeneficiaryNotEligible,
    /// Signed intent contains an operation not allowed by the revision.
    OperationNotAllowed,
    /// Signed intent matches an explicit deny rule.
    OperationDenied,
    /// Signed gas declaration is missing or invalid.
    InvalidGasLimit,
    /// Required fee asset has no budget in the revision.
    FeeAssetNotCovered,
    /// Deterministic charge exceeds the transaction's signed limit.
    SignedLimitExceeded,
    /// Deterministic charge exceeds the program's per-transaction limit.
    ProgramTransactionLimitExceeded,
    /// Block-level program capacity is exhausted.
    ProgramBlockBudgetExhausted,
    /// Epoch-level program capacity is exhausted.
    ProgramEpochBudgetExhausted,
    /// Epoch-level beneficiary capacity is exhausted.
    BeneficiaryEpochBudgetExhausted,
    /// Program vault cannot cover the charge while preserving its reserve floor.
    VaultInsufficient,
    /// The authority payer's ordinary balance cannot cover the deterministic charge.
    AuthorityPayerInsufficient,
    /// Cross-lane verified spend capacity is absent or exhausted.
    RelayCapacityUnavailable,
    /// On-chain program or route state violates a required invariant.
    InvalidProgramConfiguration,
}
impl FeeRejectionCode {
    /// Every stable public rejection code in canonical declaration order.
    pub const ALL: [Self; 19] = [
        Self::InvalidFeeIntent,
        Self::ProgramNotFound,
        Self::RevisionNotFound,
        Self::RevisionNotActive,
        Self::ProgramNotActive,
        Self::BeneficiaryNotEligible,
        Self::OperationNotAllowed,
        Self::OperationDenied,
        Self::InvalidGasLimit,
        Self::FeeAssetNotCovered,
        Self::SignedLimitExceeded,
        Self::ProgramTransactionLimitExceeded,
        Self::ProgramBlockBudgetExhausted,
        Self::ProgramEpochBudgetExhausted,
        Self::BeneficiaryEpochBudgetExhausted,
        Self::VaultInsufficient,
        Self::AuthorityPayerInsufficient,
        Self::RelayCapacityUnavailable,
        Self::InvalidProgramConfiguration,
    ];
    /// Return the stable lower-snake-case wire and telemetry label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFeeIntent => "invalid_fee_intent",
            Self::ProgramNotFound => "program_not_found",
            Self::RevisionNotFound => "revision_not_found",
            Self::RevisionNotActive => "revision_not_active",
            Self::ProgramNotActive => "program_not_active",
            Self::BeneficiaryNotEligible => "beneficiary_not_eligible",
            Self::OperationNotAllowed => "operation_not_allowed",
            Self::OperationDenied => "operation_denied",
            Self::InvalidGasLimit => "invalid_gas_limit",
            Self::FeeAssetNotCovered => "fee_asset_not_covered",
            Self::SignedLimitExceeded => "signed_limit_exceeded",
            Self::ProgramTransactionLimitExceeded => "program_transaction_limit_exceeded",
            Self::ProgramBlockBudgetExhausted => "program_block_budget_exhausted",
            Self::ProgramEpochBudgetExhausted => "program_epoch_budget_exhausted",
            Self::BeneficiaryEpochBudgetExhausted => "beneficiary_epoch_budget_exhausted",
            Self::VaultInsufficient => "vault_insufficient",
            Self::AuthorityPayerInsufficient => "authority_payer_insufficient",
            Self::RelayCapacityUnavailable => "relay_capacity_unavailable",
            Self::InvalidProgramConfiguration => "invalid_program_configuration",
        }
    }
}
impl fmt::Display for FeeRejectionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
/// Error returned when a public fee rejection code label is unknown.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("unknown fee rejection code `{0}`")]
pub struct FeeRejectionCodeParseError(pub String);
impl FromStr for FeeRejectionCode {
    type Err = FeeRejectionCodeParseError;
    fn from_str(label: &str) -> Result<Self, Self::Err> {
        let code = match label {
            "invalid_fee_intent" => Self::InvalidFeeIntent,
            "program_not_found" => Self::ProgramNotFound,
            "revision_not_found" => Self::RevisionNotFound,
            "revision_not_active" => Self::RevisionNotActive,
            "program_not_active" => Self::ProgramNotActive,
            "beneficiary_not_eligible" => Self::BeneficiaryNotEligible,
            "operation_not_allowed" => Self::OperationNotAllowed,
            "operation_denied" => Self::OperationDenied,
            "invalid_gas_limit" => Self::InvalidGasLimit,
            "fee_asset_not_covered" => Self::FeeAssetNotCovered,
            "signed_limit_exceeded" => Self::SignedLimitExceeded,
            "program_transaction_limit_exceeded" => Self::ProgramTransactionLimitExceeded,
            "program_block_budget_exhausted" => Self::ProgramBlockBudgetExhausted,
            "program_epoch_budget_exhausted" => Self::ProgramEpochBudgetExhausted,
            "beneficiary_epoch_budget_exhausted" => Self::BeneficiaryEpochBudgetExhausted,
            "vault_insufficient" => Self::VaultInsufficient,
            "authority_payer_insufficient" => Self::AuthorityPayerInsufficient,
            "relay_capacity_unavailable" => Self::RelayCapacityUnavailable,
            "invalid_program_configuration" => Self::InvalidProgramConfiguration,
            other => return Err(FeeRejectionCodeParseError(other.to_owned())),
        };
        Ok(code)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    fn sponsor_account() -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![0x53; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        AccountId::new(keypair.public_key().clone())
    }
    fn fixture_account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        AccountId::new(keypair.public_key().clone())
    }
    fn program_id() -> FeeSponsorProgramId {
        FeeSponsorProgramId::new(
            sponsor_account(),
            "retail_transfers".parse().expect("valid program name"),
        )
    }
    fn sample_revision() -> FeeSponsorProgramRevision {
        FeeSponsorProgramRevision {
            program_id: program_id(),
            revision: 1,
            eligibility: FeeSponsorEligibility::EnrolledOnly,
            rules: vec![FeeSponsorRule {
                id: "allow_transfer".parse().expect("valid rule name"),
                effect: FeeSponsorRuleEffect::Allow,
                selectors: vec![FeeSponsorRuleSelector::NativeInstruction(
                    FeeSponsorNativeInstructionSelector {
                        wire_id: "iroha.transfer".to_owned(),
                        asset_definition_id: None,
                    },
                )],
            }],
            asset_budgets: vec![FeeSponsorAssetBudget {
                asset_definition_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
                    .parse()
                    .expect("canonical asset definition id"),
                per_transaction: "1".parse().expect("valid quantity"),
                per_block: "10".parse().expect("valid quantity"),
                per_program_epoch: "100".parse().expect("valid quantity"),
                per_beneficiary_epoch: "5".parse().expect("valid quantity"),
                reserve_floor: "0.1".parse().expect("valid quantity"),
                epoch_length_blocks: NonZeroU64::new(100).unwrap(),
            }],
        }
    }
    #[test]
    fn program_id_display_roundtrips() {
        let id = program_id();
        let literal = id.to_string();
        assert_eq!(literal.parse::<FeeSponsorProgramId>().unwrap(), id);
    }
    #[test]
    fn program_id_parse_rejects_padding_and_extra_segments() {
        let sponsor = sponsor_account();
        let literal = format!("{sponsor}/retail_transfers");
        for padded in [
            format!(" {literal}"),
            format!("{literal} "),
            format!("{sponsor} /retail_transfers"),
            format!("{sponsor}/ retail_transfers"),
        ] {
            assert_eq!(
                padded.parse::<FeeSponsorProgramId>(),
                Err(FeeSponsorProgramIdParseError::InvalidFormat),
                "padded literal must be rejected exactly: {padded:?}"
            );
        }
        assert_eq!(
            format!("{literal}/extra").parse::<FeeSponsorProgramId>(),
            Err(FeeSponsorProgramIdParseError::InvalidFormat)
        );
    }
    #[test]
    fn program_id_parse_rejects_invalid_literals() {
        assert_eq!(
            "missing-separator".parse::<FeeSponsorProgramId>(),
            Err(FeeSponsorProgramIdParseError::InvalidFormat)
        );
        assert!(matches!(
            "not-an-account/default".parse::<FeeSponsorProgramId>(),
            Err(FeeSponsorProgramIdParseError::InvalidSponsor(_))
        ));
        assert!(matches!(
            format!("{}/", sponsor_account()).parse::<FeeSponsorProgramId>(),
            Err(FeeSponsorProgramIdParseError::InvalidName(_))
        ));
    }
    #[test]
    fn program_constructor_is_fail_closed() {
        let id = program_id();
        let program = FeeSponsorProgram::new(id.clone(), id.sponsor.clone());
        assert_eq!(program.id, id);
        assert_eq!(program.payout_account, program.id.sponsor);
        assert_eq!(program.lifecycle, FeeSponsorProgramLifecycle::Staged);
        assert_eq!(program.active_revision, None);
        assert_eq!(program.staged_revision, None);
        assert_eq!(program.scheduled_activation, None);
    }

    #[test]
    fn program_json_requires_immutable_payout_account() {
        let id = program_id();
        let program = FeeSponsorProgram::new(id.clone(), id.sponsor.clone());
        let mut value = norito::json::to_value(&program).expect("serialize sponsor program");
        value
            .as_object_mut()
            .expect("sponsor program object")
            .remove("payout_account")
            .expect("payout account is encoded");
        assert!(
            norito::json::from_value::<FeeSponsorProgram>(value).is_err(),
            "the first-release program wire must not default an omitted payout account"
        );
    }

    #[test]
    fn program_json_rejects_unknown_lifecycle_fields() {
        let id = program_id();
        let program = FeeSponsorProgram::new(id.clone(), id.sponsor);
        let mut value = norito::json::to_value(&program).expect("serialize sponsor program");
        value
            .as_object_mut()
            .expect("sponsor program object")
            .get_mut("lifecycle")
            .expect("lifecycle is encoded")
            .as_object_mut()
            .expect("lifecycle envelope")
            .insert("legacy".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<FeeSponsorProgram>(value).is_err(),
            "unknown lifecycle-envelope fields must fail closed"
        );
    }
    #[test]
    fn program_state_and_revision_roundtrip_binary_and_json() {
        let id = program_id();
        let program = FeeSponsorProgram::new(id.clone(), id.sponsor);
        let revision = sample_revision();
        let bytes = revision.encode();
        assert_eq!(
            FeeSponsorProgramRevision::decode(&mut bytes.as_slice()).unwrap(),
            revision
        );
        let json = norito::json::to_json(&revision).expect("serialize revision");
        assert_eq!(
            norito::json::from_str::<FeeSponsorProgramRevision>(&json)
                .expect("deserialize revision"),
            revision
        );
        let program_bytes = program.encode();
        assert_eq!(
            FeeSponsorProgram::decode(&mut program_bytes.as_slice()).unwrap(),
            program
        );
    }
    #[test]
    fn enrolled_multisig_contract_selector_roundtrips_and_requires_exact_entrypoints() {
        let contract = FeeSponsorContractSelector {
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                .parse()
                .expect("contract address"),
            code_hash: Hash::new(b"enrolled-multisig-contract"),
            entrypoints: vec!["approve".into(), "request".into()],
        };
        let selector = FeeSponsorRuleSelector::EnrolledMultisigContractCall(contract.clone());
        let bytes = norito::to_bytes(&selector).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<FeeSponsorRuleSelector>(&bytes).unwrap(),
            selector
        );
        let json = norito::json::to_json(&selector).unwrap();
        assert!(json.contains("enrolled_multisig_contract_call"));
        assert_eq!(
            norito::json::from_str::<FeeSponsorRuleSelector>(&json).unwrap(),
            selector
        );
        let mut revision = sample_revision();
        revision.rules[0].selectors = vec![selector];
        assert_eq!(revision.validate(), Ok(()));
        for entrypoints in [
            vec![],
            vec!["request".into(), "approve".into()],
            vec!["approve".into(), "approve".into()],
            vec![" approve".into()],
        ] {
            let mut bad = contract.clone();
            bad.entrypoints = entrypoints;
            revision.rules[0].selectors =
                vec![FeeSponsorRuleSelector::EnrolledMultisigContractCall(bad)];
            assert!(revision.validate().is_err());
        }
    }
    #[test]
    fn multisig_selector_roundtrips_binary_and_json() {
        let mut account_ids = vec![fixture_account(0x31), fixture_account(0x32)];
        account_ids.sort();
        let selector = FeeSponsorRuleSelector::Multisig(FeeSponsorMultisigSelector {
            operations: vec![
                FeeSponsorMultisigOperation::Propose,
                FeeSponsorMultisigOperation::Approve,
                FeeSponsorMultisigOperation::Cancel,
            ],
            account_ids,
        });
        let bytes = selector.encode();
        assert_eq!(
            FeeSponsorRuleSelector::decode(&mut bytes.as_slice()).unwrap(),
            selector
        );
        let json = norito::json::to_json(&selector).expect("serialize multisig selector");
        assert!(json.contains("\"kind\":\"multisig\""), "{json}");
        assert!(json.contains("\"operation\":\"propose\""), "{json}");
        assert!(json.contains("\"operation\":\"approve\""), "{json}");
        assert!(json.contains("\"operation\":\"cancel\""), "{json}");
        assert_eq!(
            norito::json::from_str::<FeeSponsorRuleSelector>(&json)
                .expect("deserialize multisig selector"),
            selector
        );
    }
    #[test]
    fn multisig_selector_validation_requires_canonical_explicit_sets() {
        let mut account_ids = vec![fixture_account(0x41), fixture_account(0x42)];
        account_ids.sort();
        let selector = FeeSponsorMultisigSelector {
            operations: vec![
                FeeSponsorMultisigOperation::Propose,
                FeeSponsorMultisigOperation::Approve,
                FeeSponsorMultisigOperation::Cancel,
            ],
            account_ids,
        };
        let mut revision = sample_revision();
        revision.rules[0].selectors = vec![FeeSponsorRuleSelector::Multisig(selector.clone())];
        assert_eq!(revision.validate(), Ok(()));
        let mut invalid = revision.clone();
        let FeeSponsorRuleSelector::Multisig(selector) = &mut invalid.rules[0].selectors[0] else {
            panic!("fixture selector must be multisig")
        };
        selector.operations.clear();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::EmptyMultisigOperations(_))
        ));
        let mut invalid = revision.clone();
        let FeeSponsorRuleSelector::Multisig(selector) = &mut invalid.rules[0].selectors[0] else {
            panic!("fixture selector must be multisig")
        };
        selector.operations = vec![
            FeeSponsorMultisigOperation::Approve,
            FeeSponsorMultisigOperation::Propose,
        ];
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::NonCanonicalMultisigOperations(_))
        ));
        let mut invalid = revision.clone();
        let FeeSponsorRuleSelector::Multisig(selector) = &mut invalid.rules[0].selectors[0] else {
            panic!("fixture selector must be multisig")
        };
        selector.account_ids.clear();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::EmptyMultisigAccounts(_))
        ));
        let mut invalid = revision;
        let FeeSponsorRuleSelector::Multisig(selector) = &mut invalid.rules[0].selectors[0] else {
            panic!("fixture selector must be multisig")
        };
        selector.account_ids.reverse();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::NonCanonicalMultisigAccounts(_))
        ));
    }
    #[test]
    fn revision_validation_is_fail_closed_and_monotonic() {
        let revision = sample_revision();
        assert_eq!(revision.validate(), Ok(()));
        assert_eq!(revision.validate_successor_of(None), Ok(()));
        assert_eq!(revision.validate_successor_of(Some(0)), Ok(()));
        assert_eq!(
            revision.validate_successor_of(Some(1)),
            Err(FeeSponsorProgramRevisionError::NonMonotonicRevision {
                revision: 1,
                latest: 1,
            })
        );
        let mut invalid = revision.clone();
        invalid.rules[0].selectors.clear();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::EmptyRuleSelectors(_))
        ));
        let mut invalid = revision.clone();
        let duplicate = invalid.rules[0].selectors[0].clone();
        invalid.rules[0].selectors.push(duplicate);
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::DuplicateRuleSelector(_))
        ));
        let mut invalid = revision.clone();
        let FeeSponsorRuleSelector::NativeInstruction(selector) =
            &mut invalid.rules[0].selectors[0]
        else {
            panic!("sample selector must be native")
        };
        selector.wire_id = " iroha.transfer".to_owned();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::InvalidInstructionWireId(_))
        ));
        let mut invalid = revision.clone();
        invalid.rules[0].selectors = vec![FeeSponsorRuleSelector::ContractCall(
            FeeSponsorContractSelector {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .expect("fixture contract address"),
                code_hash: Hash::new(b"fee-sponsor-contract"),
                entrypoints: Vec::new(),
            },
        )];
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::EmptyContractEntrypoints(_))
        ));
        let mut invalid = revision.clone();
        invalid.rules[0].selectors = vec![FeeSponsorRuleSelector::ContractCall(
            FeeSponsorContractSelector {
                contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
                    .parse()
                    .expect("fixture contract address"),
                code_hash: Hash::new(b"fee-sponsor-contract"),
                entrypoints: vec!["zeta".to_owned(), "alpha".to_owned()],
            },
        )];
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::InvalidContractEntrypoint { .. })
        ));
        let mut invalid = revision.clone();
        invalid.asset_budgets[0].per_transaction = Quantity::zero();
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::ZeroBudgetLimit(_))
        ));
        let mut invalid = revision;
        invalid.rules.push(invalid.rules[0].clone());
        assert!(matches!(
            invalid.validate(),
            Err(FeeSponsorProgramRevisionError::DuplicateRuleId(_))
        ));
    }
    #[test]
    fn vault_and_enrollment_keys_are_program_isolated() {
        let id = program_id();
        let beneficiary = sponsor_account();
        let enrollment = FeeSponsorEnrollment {
            key: FeeSponsorEnrollmentKey {
                program_id: id.clone(),
                beneficiary,
            },
            enrolled_at_height: 7,
        };
        let json = norito::json::to_json(&enrollment).expect("serialize enrollment");
        assert_eq!(
            norito::json::from_str::<FeeSponsorEnrollment>(&json).unwrap(),
            enrollment
        );
        let vault = FeeSponsorVault {
            key: FeeSponsorVaultKey {
                program_id: id,
                asset_definition_id: "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
                    .parse()
                    .expect("canonical asset definition id"),
            },
            balance: "12.5".parse().expect("valid quantity"),
        };
        let bytes = vault.encode();
        assert_eq!(
            FeeSponsorVault::decode(&mut bytes.as_slice()).unwrap(),
            vault
        );
    }
    #[test]
    fn rejection_code_labels_are_stable_and_roundtrip() {
        let expected = [
            "invalid_fee_intent",
            "program_not_found",
            "revision_not_found",
            "revision_not_active",
            "program_not_active",
            "beneficiary_not_eligible",
            "operation_not_allowed",
            "operation_denied",
            "invalid_gas_limit",
            "fee_asset_not_covered",
            "signed_limit_exceeded",
            "program_transaction_limit_exceeded",
            "program_block_budget_exhausted",
            "program_epoch_budget_exhausted",
            "beneficiary_epoch_budget_exhausted",
            "vault_insufficient",
            "authority_payer_insufficient",
            "relay_capacity_unavailable",
            "invalid_program_configuration",
        ];
        assert_eq!(
            FeeRejectionCode::ALL.map(FeeRejectionCode::as_str),
            expected
        );
        for (code, label) in FeeRejectionCode::ALL.into_iter().zip(expected) {
            assert_eq!(code.to_string(), label);
            assert_eq!(label.parse::<FeeRejectionCode>(), Ok(code));
        }
        assert!("policy_not_found".parse::<FeeRejectionCode>().is_err());
    }
}

#[cfg(test)]
mod captured_fee_sponsor_program_schema_tests;
