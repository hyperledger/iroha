//! Sora Name Service data structures for registrar APIs.

/// Independently authenticated current native SNS leases at a selected certified World cut.
pub mod lease;
/// Deterministic policy pricing used by consensus and native clients.
pub mod pricing;

use crate::account::{AccountAddress, AccountId};
use crate::{DeriveJsonDeserialize, DeriveJsonSerialize};
use blake3::Hasher;
use derive_more::Display;
use iroha_crypto::PublicKey;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use thiserror::Error;
/// Unique identifier assigned to a top-level suffix (e.g., `.sora`).
pub type SuffixId = u16;
/// Fixed suffix id for full account-alias lease records.
pub const ACCOUNT_ALIAS_SUFFIX_ID: SuffixId = 0x1001;
/// Fixed suffix id for domain-name lease records.
pub const DOMAIN_NAME_SUFFIX_ID: SuffixId = 0x1002;
/// Fixed suffix id for dataspace-alias lease records.
pub const DATASPACE_ALIAS_SUFFIX_ID: SuffixId = 0x1003;
/// Reserved dataspace alias of the universal dataspace (`DataSpaceId::UNIVERSAL`).
pub const RESERVED_UNIVERSAL_DATASPACE_ALIAS: &str = "universal";
/// Derive the deterministic dataspace id for a SNS dataspace alias.
///
/// The identity is the full dataspace-alias name hash, so every peer and light client derives
/// the same id without a catalog. The reserved universal alias maps to the universal dataspace.
/// Returns `None` when the alias is not a canonical SNS label.
#[must_use]
pub fn dataspace_id_for_alias(alias: &str) -> Option<iroha_model_base::topology::DataSpaceId> {
    use iroha_model_base::topology::DataSpaceId;
    let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias.trim()).ok()?;
    if selector.label == RESERVED_UNIVERSAL_DATASPACE_ALIAS {
        return Some(DataSpaceId::UNIVERSAL);
    }
    Some(DataSpaceId::from_hash(&selector.name_hash()))
}
/// Canonical native World storage key for an exact SNS record selector.
#[must_use]
pub fn record_storage_key(selector: &NameSelectorV1) -> iroha_model_base::state_path::StatePath {
    format!(
        "sns/records/{}/{}",
        selector.suffix_id,
        hex::encode(selector.name_hash())
    )
    .parse()
    .expect("canonical SNS storage key is a valid StatePath")
}
/// Canonical selector payload for SNS names.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameSelectorV1")]
pub struct NameSelectorV1 {
    /// Selector encoding version (currently `1`).
    pub version: u8,
    /// Registered suffix identifier.
    pub suffix_id: SuffixId,
    /// Lowercase, NFC-normalised label.
    pub label: String,
}
impl NameSelectorV1 {
    /// Current selector version.
    pub const VERSION: u8 = 1;
    /// Construct a selector by canonicalising the provided label.
    ///
    /// # Errors
    ///
    /// Returns [`NameSelectorError::InvalidLabel`] when the label fails the canonicalization
    /// rules (length, character set, or Unicode normalization).
    pub fn new(suffix_id: SuffixId, label: impl Into<String>) -> Result<Self, NameSelectorError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(NameSelectorError::InvalidLabel(
                "label must not be empty".into(),
            ));
        }
        let canonical = name::canonicalize_domain_label(&label).map_err(|err| {
            NameSelectorError::InvalidLabel(format!(
                "failed to canonicalize label: {}",
                err.reason()
            ))
        })?;
        Ok(Self {
            version: Self::VERSION,
            suffix_id,
            label: canonical,
        })
    }
    /// Compute the deterministic name hash used as the registry key.
    #[must_use]
    pub fn name_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&[self.version]);
        hasher.update(&self.suffix_id.to_be_bytes());
        hasher.update(self.label.as_bytes());
        *hasher.finalize().as_bytes()
    }
    /// Borrow the normalised label.
    #[must_use]
    pub fn normalized_label(&self) -> &str {
        &self.label
    }
}
/// Errors raised while constructing [`NameSelectorV1`].
#[derive(Debug, Display, Error)]
pub enum NameSelectorError {
    /// Provided label failed canonicalization or validation.
    #[display("{_0}")]
    InvalidLabel(String),
}
/// Record describing the canonical ownership state of a SNS name.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameRecordV1")]
pub struct NameRecordV1 {
    /// Canonical selector for the registered label.
    pub selector: NameSelectorV1,
    /// Deterministic name hash (blake3 of the selector payload).
    pub name_hash: [u8; 32],
    /// Account that currently controls the registration.
    pub owner: AccountId,
    /// Required monotonic ownership generation used to invalidate signed delegations after
    /// transfer. The first-release wire layout never infers a missing generation.
    pub ownership_generation: u64,
    /// Controller descriptors (accounts, resolver templates, or external payloads).
    pub controllers: Vec<NameControllerV1>,
    /// Lifecycle state (active, grace, frozen, etc.).
    pub status: NameStatus,
    /// Pricing tier identifier returned by the registrar.
    pub pricing_class: u8,
    /// Timestamp (milliseconds since UNIX epoch) when the registration was created.
    pub registered_at_ms: u64,
    /// Timestamp when the paid term ends.
    pub expires_at_ms: u64,
    /// Timestamp when the grace window ends.
    pub grace_expires_at_ms: u64,
    /// Timestamp when the redemption window ends.
    pub redemption_expires_at_ms: u64,
    /// Arbitrary registrar metadata (text records, resolver hints, etc.).
    pub metadata: Metadata,
    /// Optional auction state for premium or Dutch reopen flows.
    pub auction: Option<NameAuctionStateV1>,
}
impl NameRecordV1 {
    /// Construct a new record with the supplied parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        selector: NameSelectorV1,
        owner: AccountId,
        controllers: Vec<NameControllerV1>,
        pricing_class: u8,
        registered_at_ms: u64,
        expires_at_ms: u64,
        grace_expires_at_ms: u64,
        redemption_expires_at_ms: u64,
        metadata: Metadata,
    ) -> Self {
        let name_hash = selector.name_hash();
        Self {
            selector,
            name_hash,
            owner,
            ownership_generation: 1,
            controllers,
            status: NameStatus::Active,
            pricing_class,
            registered_at_ms,
            expires_at_ms,
            grace_expires_at_ms,
            redemption_expires_at_ms,
            metadata,
            auction: None,
        }
    }
    /// Replace the owner and advance the authoritative ownership generation.
    pub fn transfer_owner(&mut self, owner: AccountId) {
        if self.owner != owner {
            self.ownership_generation = self.ownership_generation.saturating_add(1);
        }
        self.owner = owner;
    }
}
/// Lifecycle state of a SNS registration.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "detail", no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sns::NameStatus")]
pub enum NameStatus {
    /// Registration is active and fully paid.
    Active,
    /// Grace period after expiry (still serves traffic).
    GracePeriod,
    /// Redemption period after grace expiration (requires penalty payment).
    Redemption,
    /// Registration is frozen until the supplied timestamp.
    Frozen(NameFrozenStateV1),
    /// Registration has been permanently retired.
    Tombstoned(NameTombstoneStateV1),
}
/// Details captured when a registration is frozen.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameFrozenStateV1")]
pub struct NameFrozenStateV1 {
    /// Reason recorded by governance/guardian.
    pub reason: String,
    /// Timestamp (ms) when the freeze lifts automatically.
    pub until_ms: u64,
}
/// Details captured when a registration is tombstoned.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameTombstoneStateV1")]
pub struct NameTombstoneStateV1 {
    /// Reason recorded by governance/guardian.
    pub reason: String,
}
/// Canonical representation of token amounts used by SNS pricing.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::TokenValue")]
pub struct TokenValue {
    /// Settlement asset-holding identifier (`<asset-definition-id>#<account-id>`).
    pub asset_id: String,
    /// Exact non-negative amount expressed in the asset's native precision.
    pub amount: Quantity,
}
impl TokenValue {
    /// Construct a new token amount.
    #[must_use]
    pub fn new(asset_id: impl Into<String>, amount: Quantity) -> Self {
        Self {
            asset_id: asset_id.into(),
            amount,
        }
    }
}
/// Auction metadata recorded for pending or running auctions.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameAuctionStateV1")]
pub struct NameAuctionStateV1 {
    /// Auction flavour.
    pub kind: AuctionKind,
    /// Timestamp when bidding opened.
    pub opened_at_ms: u64,
    /// Timestamp when bidding closes.
    pub closes_at_ms: u64,
    /// Minimum acceptable price.
    pub floor_price: TokenValue,
    /// Highest sealed bid hash (commitment reference).
    pub highest_commitment: Option<[u8; 32]>,
    /// Settlement transaction hash once the auction closes.
    pub settlement_tx: Option<Json>,
}
/// Supported auction kinds.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sns::AuctionKind")]
pub enum AuctionKind {
    /// 72h commit / 24h reveal sealed-bid auction.
    VickreyCommitReveal,
    /// Dutch reopen (descending price) for expired names.
    DutchReopen,
}
/// Controller descriptor referencing account addresses or resolver templates.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::NameControllerV1")]
pub struct NameControllerV1 {
    /// Controller classification.
    pub controller_type: ControllerType,
    /// Optional canonical account address bound to the controller.
    pub account_address: Option<AccountAddress>,
    /// Optional resolver template identifier.
    pub resolver_template_id: Option<String>,
    /// Free-form metadata payload describing UX hints.
    pub payload: Metadata,
}
impl NameControllerV1 {
    /// Convenience helper for single-account controllers.
    pub fn account(address: &AccountAddress) -> Self {
        Self {
            controller_type: ControllerType::Account,
            account_address: Some(address.clone()),
            resolver_template_id: None,
            payload: Metadata::default(),
        }
    }
}
/// Supported controller categories.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "kind", content = "detail", no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sns::ControllerType")]
pub enum ControllerType {
    /// Single account address controller.
    Account,
    /// Multisig controller (see `AccountController::Multisig`).
    Multisig,
    /// Resolver template (pre-baked DNS/SoraFS template).
    ResolverTemplate,
    /// External link / application-defined payload.
    ExternalLink,
}
/// Steward-advertised pricing tier definition.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::PriceTierV1")]
pub struct PriceTierV1 {
    /// Tier identifier.
    pub tier_id: u8,
    /// RE2-compatible regex describing eligible labels.
    pub label_regex: String,
    /// Base one-year price used for calculations, in SNS payment units.
    pub base_price: TokenValue,
    /// Auction mode triggered by this tier.
    pub auction_kind: AuctionKind,
    /// Optional Dutch floor when `auction_kind` = Dutch.
    pub dutch_floor: Option<TokenValue>,
    /// Minimum purchase duration allowed by this tier.
    pub min_duration_years: u8,
    /// Maximum purchase duration allowed by this tier.
    pub max_duration_years: u8,
}
/// Reserved label assignment controlled by governance.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::ReservedNameV1")]
pub struct ReservedNameV1 {
    /// Canonical lowercase label.
    pub normalized_label: String,
    /// Optional owner assigned by governance.
    pub assigned_to: Option<AccountId>,
    /// Optional release timestamp (ms since epoch).
    pub release_at_ms: Option<u64>,
    /// Notes captured with the reservation.
    pub note: String,
}
/// Basis-point split describing how funds are routed.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::SuffixFeeSplitV1")]
pub struct SuffixFeeSplitV1 {
    /// Treasury share (basis points).
    pub treasury_bps: u16,
    /// Steward share (basis points).
    pub steward_bps: u16,
    /// Referral carve-out ceiling (basis points).
    pub referral_max_bps: u16,
    /// Escrow allocation (basis points).
    pub escrow_bps: u16,
}
/// Policy lifecycle state.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
)]
#[norito(tag = "status", content = "detail", no_fast_from_json)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::sns::SuffixStatus")]
pub enum SuffixStatus {
    /// Policy active and available for registration.
    Active,
    /// Temporarily paused (maintenance or governance review).
    Paused,
    /// Permanently revoked.
    Revoked,
}
/// Minimal suffix policy definition consumed by the registrar.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::sns::SuffixPolicyV1")]
pub struct SuffixPolicyV1 {
    /// Assigned identifier.
    pub suffix_id: SuffixId,
    /// Human-readable suffix (without leading dot).
    pub suffix: String,
    /// Steward account responsible for operations.
    pub steward: AccountId,
    /// Current lifecycle status.
    pub status: SuffixStatus,
    /// Minimum term that can be purchased.
    pub min_term_years: u8,
    /// Maximum term that can be purchased.
    pub max_term_years: u8,
    /// Grace window (days).
    pub grace_period_days: u16,
    /// Redemption window (days).
    pub redemption_period_days: u16,
    /// Referral ceiling expressed in basis points.
    pub referral_cap_bps: u16,
    /// Reserved labels enforced by governance.
    pub reserved_labels: Vec<ReservedNameV1>,
    /// Asset holding required for settlement (`<asset-definition-id>#<account-id>`).
    pub payment_asset_id: String,
    /// Pricing tiers advertised by the steward.
    pub pricing: Vec<PriceTierV1>,
    /// Treasury/steward/referral split.
    pub fee_split: SuffixFeeSplitV1,
    /// Escrow account used for fund distribution.
    pub fund_splitter_account: AccountId,
    /// Policy version (increments on change).
    pub policy_version: u16,
    /// Free-form metadata (KPI covenants, annex references).
    pub metadata: Metadata,
}
impl SuffixPolicyV1 {
    /// Returns the canonical lowercase suffix string.
    #[must_use]
    pub fn suffix_key(&self) -> String {
        self.suffix.to_lowercase()
    }
}
/// Convenience helpers for building example payloads inside docs/tests.
pub mod fixtures {
    use super::*;
    /// Deterministic steward account used in fixtures/tests.
    pub fn steward_account() -> AccountId {
        // Use a known-valid ed25519 point so parsing is stable in tests.
        let key: PublicKey =
            "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
                .parse()
                .expect("valid steward key literal");
        AccountId::new(key)
    }
    /// Deterministic default policy fixture used in docs/tests.
    pub fn default_policy() -> SuffixPolicyV1 {
        let steward = steward_account();
        let payment_asset_id = format!("61CtjvNd9T3THAR65GsMVHr82Bjc#{steward}");
        SuffixPolicyV1 {
            suffix_id: 0x0001,
            suffix: "sora".to_string(),
            steward: steward.clone(),
            status: SuffixStatus::Active,
            min_term_years: 1,
            max_term_years: 5,
            grace_period_days: 30,
            redemption_period_days: 60,
            referral_cap_bps: 500,
            reserved_labels: vec![ReservedNameV1 {
                normalized_label: "treasury".to_string(),
                assigned_to: Some(steward.clone()),
                release_at_ms: None,
                note: "Protocol reserved".to_string(),
            }],
            payment_asset_id: payment_asset_id.clone(),
            pricing: vec![PriceTierV1 {
                tier_id: 0,
                label_regex: "^[a-z0-9]{3,}$".to_string(),
                base_price: TokenValue::new(
                    payment_asset_id,
                    "0.5".parse().expect("canonical fixture price"),
                ),
                auction_kind: AuctionKind::VickreyCommitReveal,
                dutch_floor: None,
                min_duration_years: 1,
                max_duration_years: 5,
            }],
            fee_split: SuffixFeeSplitV1 {
                treasury_bps: 7000,
                steward_bps: 3000,
                referral_max_bps: 1000,
                escrow_bps: 0,
            },
            fund_splitter_account: steward,
            policy_version: 1,
            metadata: Metadata::default(),
        }
    }
}
/// Re-export commonly used SNS types.
pub mod prelude {
    pub use super::{
        AuctionKind, ControllerType, NameAuctionStateV1, NameControllerV1, NameRecordV1,
        NameSelectorError, NameSelectorV1, NameStatus, PriceTierV1, ReservedNameV1,
        SuffixFeeSplitV1, SuffixId, SuffixPolicyV1, SuffixStatus, TokenValue, fixtures,
    };
}
#[cfg(test)]
mod tests {

    use super::{DOMAIN_NAME_SUFFIX_ID, NameRecordV1, NameSelectorV1};
    use super::{TokenValue, fixtures};

    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::Numeric;
    use norito::codec::{Decode, Encode};
    #[derive(Encode, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::sns::tests::ForgedTokenValue")]
    struct ForgedTokenValue {
        asset_id: String,
        amount: Numeric,
    }
    #[test]
    fn token_value_new_assigns_fields() {
        let value = TokenValue::new("61CtjvNd9T3THAR65GsMVHr82Bjc", 120_u64.into());
        assert_eq!(value.asset_id, "61CtjvNd9T3THAR65GsMVHr82Bjc");
        assert_eq!(value.amount, 120_u64.into());
    }
    #[test]
    fn sns_token_values_reject_negative_numeric_payloads() {
        let encoded = ForgedTokenValue {
            asset_id: "xor#universal".to_owned(),
            amount: Numeric::new(-1_i32, 0),
        }
        .encode();
        assert!(TokenValue::decode(&mut encoded.as_slice()).is_err());
    }
    #[test]
    fn default_policy_exposes_pricing_and_reserved_names() {
        let policy = fixtures::default_policy();
        assert!(!policy.pricing.is_empty(), "expected pricing tiers");
        assert!(
            !policy.reserved_labels.is_empty(),
            "expected reserved labels"
        );
        assert_eq!(policy.status, super::SuffixStatus::Active);
    }
    #[test]
    fn default_policy_uses_settlement_holding_for_pricing() {
        let policy = fixtures::default_policy();
        assert_eq!(
            policy.payment_asset_id,
            format!("61CtjvNd9T3THAR65GsMVHr82Bjc#{}", policy.steward)
        );
        assert_eq!(
            policy.pricing[0].base_price.asset_id,
            policy.payment_asset_id
        );
    }

    #[test]
    fn name_record_json_requires_ownership_generation() {
        let selector = NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, "owner.universal")
            .expect("canonical domain-name selector");
        let record = NameRecordV1::new(
            selector,
            fixtures::steward_account(),
            Vec::new(),
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        let mut value = norito::json::to_value(&record).expect("serialize SNS name record");
        value
            .as_object_mut()
            .expect("name record object")
            .remove("ownership_generation")
            .expect("ownership generation is encoded");
        assert!(
            norito::json::from_value::<NameRecordV1>(value).is_err(),
            "the first-release SNS record must reject a missing ownership generation"
        );
    }

    #[cfg(test)]
    mod captured_sns_schema_tests;
}

#[cfg(test)]
mod captured_sns_schema_tests;
