//! Settlement instructions and typed successful receipts.
pub use self::model::SettlementId;
mod atomic;
mod id;
mod payment_projection;
pub use payment_projection::{
    AtomicPaymentProjectionError, project_atomic_payment_receipt_unverified,
};
#[cfg(test)]
mod id_tests;
use super::*;
use crate::{
    NetworkId,
    block::BlockHeader,
    oracle::{FeedConfigVersion, FeedEvent, FeedId, FeedSlot, ObservationValue},
    prelude::{AccountId, AssetDefinitionId},
};
pub use atomic::{
    ATOMIC_SETTLEMENT_MAX_ESCROWS, ATOMIC_SETTLEMENT_MAX_MOVEMENTS, ATOMIC_SETTLEMENT_MIN_LEGS,
    AtomicSettlementEscrow, AtomicSettlementEscrows, AtomicSettlementMovement,
    AtomicSettlementMovements, ResolvedSettlementMovement, ResolvedSettlementMovements,
    SettleAtomic,
};
use derive_more::{Constructor, Display};
use getset::{CopyGetters, Getters};
use iroha_crypto::{Hash, HashOf, derive_non_signing_ed25519_public_key};
use iroha_data_model_derive::model;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use norito::derive::{JsonDeserialize, JsonSerialize};
use std::collections::{BTreeMap, BTreeSet};
const FX_CORRIDOR_ESCROW_ACCOUNT_DOMAIN_V1: &[u8] = b"iroha:fx-corridor:escrow-account:v1";
#[model]
mod model {
    use super::*;
    /// Owner-qualified business reference consumed when a settlement commits successfully.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::isi::settlement::model::SettlementId")]
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        IntoSchema,
        JsonSerialize,
        JsonDeserialize,
    )]
    #[display("{reference}${owner}")]
    #[getset(get = "pub")]
    #[norito(deny_unknown_fields)]
    pub struct SettlementId {
        /// Explicit participating debit owner whose namespace contains this reference.
        pub owner: AccountId,
        /// Stable original business reference, independent of payment terms or carrier identity.
        pub reference: Name,
    }
}
enum_type! {
    #[norito_schema(name = "iroha_data_model::isi::settlement::SettlementExecutionOrder")]
    pub enum SettlementExecutionOrder {
        DeliveryThenPayment,
        PaymentThenDelivery,
    }
}
enum_type! {
    /// Native settlement accepts only an all-or-nothing outcome.
    /// Discriminant zero is canonical; all other binary tags and JSON names are invalid.
    #[norito_schema(name = "iroha_data_model::isi::settlement::SettlementAtomicity")]
    pub enum SettlementAtomicity {
        AllOrNothing,
    }
}
#[allow(clippy::derivable_impls)]
impl Default for SettlementExecutionOrder {
    fn default() -> Self {
        Self::DeliveryThenPayment
    }
}
#[allow(clippy::derivable_impls)]
impl Default for SettlementAtomicity {
    fn default() -> Self {
        Self::AllOrNothing
    }
}
/// Execution plan covering leg ordering and failure handling.
#[derive(
    Copy,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    CopyGetters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get_copy = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::settlement::SettlementPlan")]
pub struct SettlementPlan {
    /// Ordering of the settlement legs.
    order: SettlementExecutionOrder,
    /// Atomicity policy to apply when executing the settlement.
    atomicity: SettlementAtomicity,
}
impl SettlementPlan {
    /// Construct a settlement plan from the desired order and atomicity policy.
    pub const fn new(order: SettlementExecutionOrder, atomicity: SettlementAtomicity) -> Self {
        Self { order, atomicity }
    }
}
impl Default for SettlementPlan {
    fn default() -> Self {
        Self::new(
            SettlementExecutionOrder::DeliveryThenPayment,
            SettlementAtomicity::AllOrNothing,
        )
    }
}
/// One leg of a bilateral settlement (asset or payment).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::settlement::SettlementLeg")]
pub struct SettlementLeg {
    /// Asset definition exchanged in this leg.
    pub asset_definition_id: AssetDefinitionId,
    /// Quantity of the asset exchanged.
    pub quantity: Quantity,
    /// Account sending the asset.
    pub from: AccountId,
    /// Account receiving the asset.
    pub to: AccountId,
    /// Optional metadata (e.g., ISIN, clearing reference).
    pub metadata: Metadata,
}
/// Immutable identity of one first-release FX corridor.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorId")]
pub struct FxCorridorId {
    /// Stable governed corridor name.
    pub policy_id: Name,
    /// Private dataspace holding the source currency.
    pub source_dataspace: DataSpaceId,
    /// Source-currency asset definition.
    pub source_asset_definition_id: AssetDefinitionId,
    /// Private dataspace holding the destination reserve.
    pub destination_dataspace: DataSpaceId,
    /// Destination-currency asset definition.
    pub destination_asset_definition_id: AssetDefinitionId,
}
/// Exact retained oracle event selected by a signed FX settlement.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorOracleEvidence")]
pub struct FxCorridorOracleEvidence {
    /// Governed feed that produced the rate.
    pub feed_id: FeedId,
    /// Exact current feed configuration version.
    pub feed_config_version: FeedConfigVersion,
    /// Exact aggregated feed slot.
    pub slot: FeedSlot,
    /// Exact upstream request commitment.
    pub request_hash: Hash,
    /// Typed hash of the complete retained feed event.
    pub event_hash: HashOf<FeedEvent>,
}
/// Deterministic fixed-window usage retained for one FX corridor.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorUsage")]
pub struct FxCorridorUsage {
    /// Consensus-time-aligned start of the current velocity window.
    pub window_start_ms: u64,
    /// Successful settlements committed in the current window.
    pub settlements: u64,
    /// Total source currency collected in the current window.
    pub source_amount: Quantity,
    /// Total destination currency released in the current window.
    pub destination_amount: Quantity,
}
/// Immutable routing and pricing policy for one native FX corridor.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorPolicy")]
pub struct FxCorridorPolicy {
    /// Stable policy identifier referenced by settlement instructions.
    pub policy_id: Name,
    /// Monotonic policy revision used to bind signed settlement intent.
    pub revision: u64,
    /// Immutable account that funds the isolated destination reserve and receives source funds.
    pub owner: AccountId,
    /// Dataspace holding the source currency balance.
    pub source_dataspace: DataSpaceId,
    /// Source-currency asset definition.
    pub source_asset_definition_id: AssetDefinitionId,
    /// Dataspace holding the destination reserve.
    pub destination_dataspace: DataSpaceId,
    /// Destination-currency asset definition.
    pub destination_asset_definition_id: AssetDefinitionId,
    /// Exact destination FI alias domains accepted for recipients.
    pub allowed_destination_alias_domains: BTreeSet<iroha_model_base::domain::DomainId>,
    /// Exact governed oracle feed whose latest event supplies the rate.
    pub oracle_feed_id: FeedId,
    /// Maximum consensus-time age accepted for the retained oracle event.
    pub max_oracle_age_ms: u64,
    /// Maximum source amount admitted by one settlement.
    pub max_source_amount_per_settlement: Quantity,
    /// Maximum destination exposure admitted by one settlement.
    pub max_destination_amount_per_settlement: Quantity,
    /// Deterministic consensus-time velocity window length.
    pub velocity_window_ms: u64,
    /// Maximum successful settlements admitted in one velocity window.
    pub max_settlements_per_window: u64,
    /// Maximum aggregate source amount admitted in one velocity window.
    pub max_source_amount_per_window: Quantity,
    /// Maximum aggregate destination amount admitted in one velocity window.
    pub max_destination_amount_per_window: Quantity,
    /// Whether new settlements may use this policy.
    pub enabled: bool,
}
impl FxCorridorPolicy {
    /// Return the first static policy invariant violation, if any.
    #[must_use]
    pub fn invariant_error(&self) -> Option<&'static str> {
        if self.revision == 0 {
            return Some("FX corridor policy revision must be non-zero");
        }
        if self.source_dataspace == DataSpaceId::UNIVERSAL
            || self.destination_dataspace == DataSpaceId::UNIVERSAL
        {
            return Some("FX corridor dataspaces must be private");
        }
        if self.source_dataspace == self.destination_dataspace {
            return Some("FX corridor dataspaces must be distinct");
        }
        if self.source_asset_definition_id == self.destination_asset_definition_id {
            return Some("FX corridor assets must be distinct");
        }
        if self.allowed_destination_alias_domains.is_empty() {
            return Some("FX corridor destination alias domains must not be empty");
        }
        if self.max_oracle_age_ms == 0 {
            return Some("FX corridor oracle maximum age must be non-zero");
        }
        if self.max_source_amount_per_settlement.is_zero()
            || self.max_destination_amount_per_settlement.is_zero()
            || self.max_source_amount_per_window.is_zero()
            || self.max_destination_amount_per_window.is_zero()
        {
            return Some("FX corridor exposure and velocity amount limits must be non-zero");
        }
        if self.max_source_amount_per_settlement > self.max_source_amount_per_window
            || self.max_destination_amount_per_settlement > self.max_destination_amount_per_window
        {
            return Some("FX corridor per-settlement exposure cannot exceed its window limit");
        }
        if self.velocity_window_ms == 0 || self.max_settlements_per_window == 0 {
            return Some("FX corridor velocity window and settlement limit must be non-zero");
        }
        None
    }
    /// Return the immutable corridor identity used for protocol escrow derivation.
    #[must_use]
    pub fn corridor_id(&self) -> FxCorridorId {
        FxCorridorId {
            policy_id: self.policy_id.clone(),
            source_dataspace: self.source_dataspace,
            source_asset_definition_id: self.source_asset_definition_id.clone(),
            destination_dataspace: self.destination_dataspace,
            destination_asset_definition_id: self.destination_asset_definition_id.clone(),
        }
    }
}
/// Derive the non-signable reserve account for one exact FX corridor and asset.
#[must_use]
pub fn fx_corridor_escrow_account_id_v1(
    network_id: &NetworkId,
    corridor_id: &FxCorridorId,
    asset_definition_id: &AssetDefinitionId,
) -> AccountId {
    let corridor_id = corridor_id.encode();
    let asset_definition_id = asset_definition_id.encode();
    AccountId::new(derive_non_signing_ed25519_public_key(
        FX_CORRIDOR_ESCROW_ACCOUNT_DOMAIN_V1,
        &[
            network_id.as_bytes(),
            corridor_id.as_slice(),
            asset_definition_id.as_slice(),
        ],
    ))
}
/// Complete governed set of native FX corridor policies.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorPolicyRegistry")]
pub struct FxCorridorPolicyRegistry {
    /// Policies keyed by their stable identifier.
    pub policies: BTreeMap<Name, FxCorridorPolicy>,
    /// Bounded O(1)-per-corridor exposure and velocity counters.
    pub usage: BTreeMap<Name, FxCorridorUsage>,
}
impl FxCorridorPolicyRegistry {
    /// Identifier of the custom parameter carrying all FX corridor policies.
    pub const PARAMETER_ID_STR: &'static str = "iroha:fx_corridor_policies";
    /// Construct the registry custom-parameter identifier.
    #[must_use]
    pub fn parameter_id() -> crate::parameter::CustomParameterId {
        Self::PARAMETER_ID_STR
            .parse()
            .expect("valid FX corridor policy-registry parameter identifier")
    }
    /// Return the policy registered under `policy_id`.
    #[must_use]
    pub fn get(&self, policy_id: &Name) -> Option<&FxCorridorPolicy> {
        self.policies.get(policy_id)
    }
    /// Insert or replace a policy under its embedded identifier.
    pub fn upsert(&mut self, policy: FxCorridorPolicy) {
        self.policies.insert(policy.policy_id.clone(), policy);
    }
    /// Return retained usage for `policy_id`.
    #[must_use]
    pub fn usage(&self, policy_id: &Name) -> Option<&FxCorridorUsage> {
        self.usage.get(policy_id)
    }
    /// Convert the registry into the custom parameter accepted by `SetParameter`.
    #[must_use]
    pub fn into_custom_parameter(self) -> crate::parameter::CustomParameter {
        crate::parameter::CustomParameter::new(
            Self::parameter_id(),
            iroha_primitives::json::Json::new(self),
        )
    }
    /// Decode a matching policy-registry custom parameter.
    ///
    /// # Errors
    ///
    /// Returns a Norito error when a parameter with the registry identifier
    /// does not contain a valid [`FxCorridorPolicyRegistry`].
    pub fn from_custom_parameter(
        custom: &crate::parameter::CustomParameter,
    ) -> Result<Option<Self>, norito::Error> {
        if custom.id() != &Self::parameter_id() {
            return Ok(None);
        }
        Ok(Some(custom.payload().try_into_any_norito::<Self>()?))
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Register or replace a native FX corridor policy.
    #[norito_schema(name = "iroha_data_model::isi::settlement::SetFxCorridorPolicy")]
    pub struct SetFxCorridorPolicy {
        /// Complete policy to persist under its stable identifier.
        pub policy: FxCorridorPolicy,
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Fund the isolated destination reserve of one exact FX corridor.
    #[norito_schema(name = "iroha_data_model::isi::settlement::FundFxCorridorEscrow")]
    pub struct FundFxCorridorEscrow {
        /// Stable corridor policy identifier.
        pub policy_id: Name,
        /// Exact active policy revision approved by the owner.
        pub expected_policy_revision: u64,
        /// Exact destination asset bound by the signed funding instruction.
        pub destination_asset_definition_id: AssetDefinitionId,
        /// Positive destination-currency quantity to deposit.
        pub amount: Quantity,
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Refund an inactive FX corridor reserve to its immutable owner.
    #[norito_schema(name = "iroha_data_model::isi::settlement::RefundFxCorridorEscrow")]
    pub struct RefundFxCorridorEscrow {
        /// Stable corridor policy identifier.
        pub policy_id: Name,
        /// Exact inactive policy revision approved by the owner.
        pub expected_policy_revision: u64,
        /// Exact destination asset bound by the signed refund instruction.
        pub destination_asset_definition_id: AssetDefinitionId,
        /// Positive destination-currency quantity to refund.
        pub amount: Quantity,
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Atomically settle one policy-backed cross-dataspace FX conversion.
    #[norito_schema(name = "iroha_data_model::isi::settlement::SettleFxCorridor")]
    pub struct SettleFxCorridor {
        /// Stable corridor policy identifier.
        pub policy_id: Name,
        /// Exact policy revision expected by the signer.
        pub expected_policy_revision: u64,
        /// Expected source asset, bound explicitly for admission and fee validation.
        pub source_asset_definition_id: AssetDefinitionId,
        /// Expected destination asset, bound explicitly for admission and fee validation.
        pub destination_asset_definition_id: AssetDefinitionId,
        /// Unique settlement/replay identifier.
        pub settlement_id: SettlementId,
        /// Recipient of the policy-derived destination currency.
        pub recipient: AccountId,
        /// Source-currency quantity collected from the signing account.
        pub source_amount: Quantity,
        /// Exact destination quantity approved by the signer.
        pub expected_destination_amount: Quantity,
        /// Exact retained oracle event approved by the signer.
        pub oracle_evidence: FxCorridorOracleEvidence,
    }
}
impl SetFxCorridorPolicy {
    /// Stable wire identifier used by tooling that reports the concrete operation.
    pub const WIRE_ID: &'static str = "iroha.settlement.fx_corridor.policy.set";
}
impl FundFxCorridorEscrow {
    /// Stable wire identifier used by tooling that reports the concrete operation.
    pub const WIRE_ID: &'static str = "iroha.settlement.fx_corridor.escrow.fund";
}
impl RefundFxCorridorEscrow {
    /// Stable wire identifier used by tooling that reports the concrete operation.
    pub const WIRE_ID: &'static str = "iroha.settlement.fx_corridor.escrow.refund";
}
impl SettleFxCorridor {
    /// Stable wire identifier used by tooling that reports the concrete operation.
    pub const WIRE_ID: &'static str = "iroha.settlement.fx_corridor.settle";
}
impl core::fmt::Display for SetFxCorridorPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SET FX CORRIDOR POLICY `{}`", self.policy.policy_id)
    }
}
impl core::fmt::Display for FundFxCorridorEscrow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FUND FX CORRIDOR ESCROW `{}` REVISION {}",
            self.policy_id, self.expected_policy_revision
        )
    }
}
impl core::fmt::Display for RefundFxCorridorEscrow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "REFUND FX CORRIDOR ESCROW `{}` REVISION {}",
            self.policy_id, self.expected_policy_revision
        )
    }
}
impl core::fmt::Display for SettleFxCorridor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SETTLE FX CORRIDOR `{}` REVISION {} AS `{}`",
            self.policy_id, self.expected_policy_revision, self.settlement_id
        )
    }
}
impl SettlementLeg {
    /// Construct a settlement leg without metadata.
    pub fn new(
        asset_definition_id: AssetDefinitionId,
        quantity: impl Into<Quantity>,
        from: AccountId,
        to: AccountId,
    ) -> Self {
        Self {
            asset_definition_id,
            quantity: quantity.into(),
            from,
            to,
            metadata: Metadata::default(),
        }
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Delivery-versus-payment settlement instruction requiring exact counterparty consent.
    ///
    /// Core accepts this instruction only with `AllOrNothing` atomicity and a
    /// counterparty-issued permission bound to [`DvpIsi::intent_hash`].
    #[norito_schema(name = "iroha_data_model::isi::settlement::DvpIsi")]
    pub struct DvpIsi {
        /// Stable identifier shared across the delivery lifecycle.
        pub settlement_id: SettlementId,
        /// Asset leg delivered in exchange for the payment leg.
        pub delivery_leg: SettlementLeg,
        /// Payment leg (cash or tokenised currency) completing the exchange.
        pub payment_leg: SettlementLeg,
        /// Execution plan describing leg order and failure handling.
        pub plan: SettlementPlan,
        /// Optional metadata propagated alongside the settlement for downstream reconciliation.
        pub metadata: Metadata,
    }
}
isi! {
    #[derive (JsonSerialize , JsonDeserialize)]
    /// Payment-versus-payment settlement instruction requiring exact counterparty consent.
    ///
    /// Core accepts this instruction only with `AllOrNothing` atomicity and a
    /// counterparty-issued permission bound to [`PvpIsi::intent_hash`].
    #[norito_schema(name = "iroha_data_model::isi::settlement::PvpIsi")]
    pub struct PvpIsi {
        /// Stable identifier associated with this FX settlement lifecycle.
        pub settlement_id: SettlementId,
        /// Primary currency leg.
        pub primary_leg: SettlementLeg,
        /// Counter currency leg.
        pub counter_leg: SettlementLeg,
        /// Execution plan describing leg order and failure handling.
        pub plan: SettlementPlan,
        /// Optional metadata propagated alongside the settlement for downstream reconciliation.
        pub metadata: Metadata,
    }
}
impl DvpIsi {
    /// Stable wire identifier used by the instruction registry.
    pub const WIRE_ID: &'static str = "iroha.settlement.dvp";
    /// Domain separator for the complete counterparty-authorized `DvP` intent.
    pub const INTENT_HASH_DOMAIN: &'static [u8] = b"iroha:settlement:dvp-intent:v1\0";
    /// Construct a `DvP` instruction enforcing basic invariants.
    pub fn new(
        settlement_id: SettlementId,
        delivery_leg: SettlementLeg,
        payment_leg: SettlementLeg,
        plan: SettlementPlan,
    ) -> Self {
        Self {
            settlement_id,
            delivery_leg,
            payment_leg,
            plan,
            metadata: Metadata::default(),
        }
    }
    /// Return the domain-separated commitment that a counterparty authorizes.
    ///
    /// The commitment covers the complete canonical instruction, including both
    /// legs, execution plan, settlement identifier, and metadata.
    #[must_use]
    pub fn intent_hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::new_from_chunks(&[Self::INTENT_HASH_DOMAIN, encoded.as_slice()])
    }
}
impl PvpIsi {
    /// Stable wire identifier used by the instruction registry.
    pub const WIRE_ID: &'static str = "iroha.settlement.pvp";
    /// Domain separator for the complete counterparty-authorized `PvP` intent.
    pub const INTENT_HASH_DOMAIN: &'static [u8] = b"iroha:settlement:pvp-intent:v1\0";
    /// Construct a `PvP` instruction enforcing basic invariants.
    pub fn new(
        settlement_id: SettlementId,
        primary_leg: SettlementLeg,
        counter_leg: SettlementLeg,
        plan: SettlementPlan,
    ) -> Self {
        Self {
            settlement_id,
            primary_leg,
            counter_leg,
            plan,
            metadata: Metadata::default(),
        }
    }
    /// Return the domain-separated commitment that a counterparty authorizes.
    ///
    /// The commitment covers the complete canonical instruction, including both
    /// legs, execution plan, settlement identifier, and metadata.
    #[must_use]
    pub fn intent_hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::new_from_chunks(&[Self::INTENT_HASH_DOMAIN, encoded.as_slice()])
    }
}
impl core::fmt::Display for DvpIsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DVP `{}` ORDER {:?} ATOMIC {:?}",
            self.settlement_id,
            self.plan.order(),
            self.plan.atomicity(),
        )
    }
}
impl core::fmt::Display for PvpIsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PVP `{}` ORDER {:?} ATOMIC {:?}",
            self.settlement_id,
            self.plan.order(),
            self.plan.atomicity(),
        )
    }
}
/// Immutable pricing context retained for a successful native FX settlement.
///
/// The named resolved movements in `SettlementDetails::FxCorridor` retain all parties,
/// amounts, asset definitions and scopes. This context retains the mandatory governed
/// policy revision and oracle observation without duplicating those movements.
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, JsonSerialize, JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct FxCorridorPricingContext {
    /// Stable corridor policy identifier.
    pub policy_id: Name,
    /// Exact policy revision used for execution.
    pub policy_revision: u64,
    /// Exact retained oracle event selected by the signed instruction.
    pub oracle_evidence: FxCorridorOracleEvidence,
    /// Consensus-time timestamp attached to the retained oracle event.
    pub oracle_recorded_at_ms: u64,
    /// Exact positive fixed-point destination/source rate from the oracle event.
    pub oracle_rate: ObservationValue,
}
/// A complete delivery-versus-payment exchange.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::DvpSettlementDetails")]
pub struct DvpSettlementDetails {
    /// Resolved delivery movement.
    pub delivery: ResolvedSettlementMovement,
    /// Resolved payment movement.
    pub payment: ResolvedSettlementMovement,
    /// Order in which the all-or-nothing exchange was prepared.
    pub order: SettlementExecutionOrder,
}

/// A complete payment-versus-payment exchange.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::PvpSettlementDetails")]
pub struct PvpSettlementDetails {
    /// Resolved primary movement.
    pub primary: ResolvedSettlementMovement,
    /// Resolved counter movement.
    pub counter: ResolvedSettlementMovement,
    /// Order in which the all-or-nothing exchange was prepared.
    pub order: SettlementExecutionOrder,
}

/// A complete governed FX exchange with mandatory pricing context.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::FxCorridorSettlementDetails")]
pub struct FxCorridorSettlementDetails {
    /// Actual source-currency collection.
    pub source: ResolvedSettlementMovement,
    /// Actual destination-currency payout.
    pub destination: ResolvedSettlementMovement,
    /// Exact authenticated governed pricing context.
    pub context: FxCorridorPricingContext,
}

/// A complete canonical N-payment atomic settlement.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::AtomicSettlementDetails")]
pub struct AtomicSettlementDetails {
    /// Every exact balance movement in the signed canonical order.
    pub movements: ResolvedSettlementMovements,
    /// Exact complete network-bound intent approved by the debit owners.
    pub intent_hash: Hash,
    /// Conditional escrows opened by this settlement, in signed canonical order.
    ///
    /// Empty when the intent has no escrow legs. The retained escrow records own
    /// custody, terms and lifecycle state.
    pub escrow_ids: Vec<crate::escrow::EscrowId>,
}

/// Exactly one successful settlement operation and its fully resolved movements.
///
/// There is no separate kind, optional FX context, arbitrary role list or partial
/// atomicity field that could contradict the selected operation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "value", deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::SettlementDetails")]
pub enum SettlementDetails {
    /// A complete delivery-versus-payment exchange.
    Dvp(DvpSettlementDetails),
    /// A complete payment-versus-payment exchange.
    Pvp(PvpSettlementDetails),
    /// A complete governed FX exchange with mandatory pricing context.
    FxCorridor(FxCorridorSettlementDetails),
    /// A complete canonical N-payment atomic settlement.
    Atomic(AtomicSettlementDetails),
}

impl SettlementDetails {
    /// Iterate every committed movement, including all N atomic movements.
    ///
    /// Reference-retention consumers must use both exact source and destination
    /// `AssetId` values; the fixed bilateral pair is not a bound on atomic receipts.
    pub fn movements(&self) -> impl Iterator<Item = &ResolvedSettlementMovement> {
        let (first, second, batch) = match self {
            Self::Dvp(DvpSettlementDetails {
                delivery, payment, ..
            }) => (Some(delivery), Some(payment), None),
            Self::Pvp(PvpSettlementDetails {
                primary, counter, ..
            }) => (Some(primary), Some(counter), None),
            Self::FxCorridor(FxCorridorSettlementDetails {
                source,
                destination,
                ..
            }) => (Some(source), Some(destination), None),
            Self::Atomic(AtomicSettlementDetails { movements, .. }) => {
                (None, None, Some(movements.as_slice()))
            }
        };
        first
            .into_iter()
            .chain(second)
            .chain(batch.into_iter().flatten())
    }
}

/// Immutable receipt persisted only after complete successful settlement.
///
/// The world-state map key is the unique `SettlementId`. Failed attempts create no
/// receipt. Resolved asset scopes come from the prepared transfer owner, never
/// from ambient routing or a subsequent state view.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::isi::settlement::SettlementReceipt")]
pub struct SettlementReceipt {
    /// Account that authorized the settlement carrier.
    pub authority: AccountId,
    /// Complete signed settlement metadata.
    pub metadata: Metadata,
    /// Block height in which all movements were committed.
    pub block_height: u64,
    /// Hash of the enclosing block.
    pub block_hash: HashOf<BlockHeader>,
    /// Block timestamp in milliseconds since Unix epoch.
    pub executed_at_ms: u64,
    /// One mandatory typed description of the complete successful operation.
    pub details: SettlementDetails,
}
impl crate::seal::Instruction for DvpIsi {}
impl crate::seal::Instruction for PvpIsi {}
impl crate::seal::Instruction for SetFxCorridorPolicy {}
impl crate::seal::Instruction for FundFxCorridorEscrow {}
impl crate::seal::Instruction for RefundFxCorridorEscrow {}
impl crate::seal::Instruction for SettleFxCorridor {}
isi_box! {
    /// Grouping enum for settlement instructions.
    #[norito_schema(name = "iroha_data_model::isi::settlement::SettlementInstructionBox")]
    pub enum SettlementInstructionBox {
        /// Delivery-versus-payment settlement.
        Dvp(DvpIsi),
        /// Payment-versus-payment settlement.
        Pvp(PvpIsi),
        /// Register or replace a native FX corridor policy.
        SetFxCorridorPolicy(SetFxCorridorPolicy),
        /// Fund one exact corridor's isolated destination reserve.
        FundFxCorridorEscrow(FundFxCorridorEscrow),
        /// Refund one inactive corridor reserve to its immutable owner.
        RefundFxCorridorEscrow(RefundFxCorridorEscrow),
        /// Execute one policy-backed native FX settlement.
        SettleFxCorridor(SettleFxCorridor),
        /// Execute one complete network-bound all-or-nothing N-payment settlement.
        Atomic(SettleAtomic),
    }
}
impl_into_box! {
    DvpIsi | PvpIsi | SetFxCorridorPolicy | FundFxCorridorEscrow | RefundFxCorridorEscrow | SettleFxCorridor | SettleAtomic => SettlementInstructionBox
}
impl crate::seal::Instruction for SettlementInstructionBox {}
impl SettlementInstructionBox {
    /// Stable Norito wire identifier for boxed settlement instructions.
    pub const WIRE_ID: &'static str = "iroha.settlement";
}
fn settlement_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_settlement_decode_from_slice {
    ($ty:ty { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = settlement_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_settlement_decode_from_slice!(DvpIsi {
    settlement_id: SettlementId,
    delivery_leg: SettlementLeg,
    payment_leg: SettlementLeg,
    plan: SettlementPlan,
    metadata: Metadata,
});
impl_settlement_decode_from_slice!(PvpIsi {
    settlement_id: SettlementId,
    primary_leg: SettlementLeg,
    counter_leg: SettlementLeg,
    plan: SettlementPlan,
    metadata: Metadata,
});
impl_settlement_decode_from_slice!(SetFxCorridorPolicy {
    policy: FxCorridorPolicy,
});
impl_settlement_decode_from_slice!(FundFxCorridorEscrow {
    policy_id: Name,
    expected_policy_revision: u64,
    destination_asset_definition_id: AssetDefinitionId,
    amount: Quantity,
});
impl_settlement_decode_from_slice!(RefundFxCorridorEscrow {
    policy_id: Name,
    expected_policy_revision: u64,
    destination_asset_definition_id: AssetDefinitionId,
    amount: Quantity,
});
impl_settlement_decode_from_slice!(SettleFxCorridor {
    policy_id: Name,
    expected_policy_revision: u64,
    source_asset_definition_id: AssetDefinitionId,
    destination_asset_definition_id: AssetDefinitionId,
    settlement_id: SettlementId,
    recipient: AccountId,
    source_amount: Quantity,
    expected_destination_amount: Quantity,
    oracle_evidence: FxCorridorOracleEvidence,
});
impl<'a> norito::core::DecodeFromSlice<'a> for SettlementInstructionBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = settlement_decode_flags();
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Dvp(super::decode_aos_slice_field::<DvpIsi>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            1 => Self::Pvp(super::decode_aos_slice_field::<PvpIsi>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::SetFxCorridorPolicy(super::decode_aos_slice_field::<SetFxCorridorPolicy>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            3 => Self::FundFxCorridorEscrow(super::decode_aos_slice_field::<FundFxCorridorEscrow>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            4 => Self::RefundFxCorridorEscrow(super::decode_aos_slice_field::<
                RefundFxCorridorEscrow,
            >(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            5 => Self::SettleFxCorridor(super::decode_aos_slice_field::<SettleFxCorridor>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            6 => Self::Atomic(super::decode_aos_slice_field::<SettleAtomic>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid SettlementInstructionBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Numeric;
    use norito::{
        codec::{Decode, Encode},
        core::DecodeFromSlice,
    };
    #[test]
    fn settlement_atomicity_rejects_retired_tags_and_names() {
        assert_eq!(SettlementAtomicity::AllOrNothing as u8, 0);
        let frame = norito::to_bytes(&SettlementAtomicity::AllOrNothing).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<SettlementAtomicity>(&frame).unwrap(),
            SettlementAtomicity::AllOrNothing
        );
        // Complete formerly accepted frames have valid schema, length and checksum;
        // rejection must come from the closed enum boundary, not corrupt framing.
        for (tag, name, frame) in [
            (
                1,
                "CommitFirstLeg",
                "4e525430000084f0cfcacef07ac0d3b044000262f53a000400000000000000973e373c6b0c4be90001000000",
            ),
            (
                2,
                "CommitSecondLeg",
                "4e525430000084f0cfcacef07ac0d3b044000262f53a000400000000000000f3dc425a899278cf0002000000",
            ),
        ] {
            assert!(SettlementAtomicity::try_from(tag).is_err());
            assert!(
                norito::decode_from_bytes::<SettlementAtomicity>(&hex::decode(frame).unwrap())
                    .is_err()
            );
            assert!(
                norito::json::from_value::<SettlementAtomicity>(norito::json::Value::String(
                    name.into()
                ))
                .is_err()
            );
            let plan = norito::json::to_json(&SettlementPlan::default()).unwrap();
            let invalid_plan = plan.replace("AllOrNothing", name);
            assert!(norito::json::from_str::<SettlementPlan>(&invalid_plan).is_err());
            let dvp = norito::json::to_json(&dvp_instruction())
                .unwrap()
                .replace("AllOrNothing", name);
            let pvp = norito::json::to_json(&pvp_instruction())
                .unwrap()
                .replace("AllOrNothing", name);
            assert!(norito::json::from_str::<DvpIsi>(&dvp).is_err());
            assert!(norito::json::from_str::<PvpIsi>(&pvp).is_err());
        }
    }
    #[derive(Encode)]
    struct ForgedSettleFxCorridor {
        policy_id: Name,
        expected_policy_revision: u64,
        source_asset_definition_id: AssetDefinitionId,
        destination_asset_definition_id: AssetDefinitionId,
        settlement_id: SettlementId,
        recipient: AccountId,
        source_amount: Numeric,
        expected_destination_amount: Quantity,
        oracle_evidence: FxCorridorOracleEvidence,
    }
    #[derive(Encode)]
    struct ForgedSettlementLeg {
        asset_definition_id: AssetDefinitionId,
        quantity: Numeric,
        from: AccountId,
        to: AccountId,
        metadata: Metadata,
    }
    #[derive(Encode)]
    struct ForgedResolvedSettlementMovement {
        source: crate::asset::AssetId,
        destination: crate::asset::AssetId,
        quantity: Numeric,
        metadata: Metadata,
    }
    const ALICE_SIGNATORY: &str =
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
    const BOB_SIGNATORY: &str =
        "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016";
    fn account(signatory: &str, _domain: &str) -> AccountId {
        AccountId::new(signatory.parse().expect("public key"))
    }
    fn asset(domain: &str, name: &str) -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new(domain, "universal").expect("domain"),
            name.parse().expect("name"),
        )
    }
    fn dvp_instruction() -> DvpIsi {
        let settlement_id: SettlementId = SettlementId::new(
            account(ALICE_SIGNATORY, "test"),
            "dvp_trade_1".parse().expect("reference"),
        );
        let delivery_leg = SettlementLeg::new(
            asset("wonderland", "bond"),
            1_000u32,
            account(ALICE_SIGNATORY, "test"),
            account(BOB_SIGNATORY, "test"),
        );
        let payment_leg = SettlementLeg::new(
            asset("wonderland", "usd"),
            1_005u32,
            account(BOB_SIGNATORY, "test"),
            account(ALICE_SIGNATORY, "test"),
        );
        DvpIsi {
            settlement_id,
            delivery_leg,
            payment_leg,
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        }
    }
    fn pvp_instruction() -> PvpIsi {
        let settlement_id: SettlementId = SettlementId::new(
            account(ALICE_SIGNATORY, "test"),
            "pvp_fx_1".parse().expect("reference"),
        );
        let primary_leg = SettlementLeg::new(
            asset("wonderland", "usd"),
            1_000u32,
            account(ALICE_SIGNATORY, "test"),
            account(BOB_SIGNATORY, "test"),
        );
        let counter_leg = SettlementLeg::new(
            asset("wonderland", "eur"),
            920u32,
            account(BOB_SIGNATORY, "test"),
            account(ALICE_SIGNATORY, "test"),
        );
        PvpIsi {
            settlement_id,
            primary_leg,
            counter_leg,
            plan: SettlementPlan::new(
                SettlementExecutionOrder::PaymentThenDelivery,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        }
    }
    fn fx_policy() -> FxCorridorPolicy {
        FxCorridorPolicy {
            policy_id: "cbuae_aed_sbp_pkr".parse().expect("policy id"),
            revision: 1,
            owner: account(ALICE_SIGNATORY, "cbuae"),
            source_dataspace: DataSpaceId::new(10),
            source_asset_definition_id: asset("cbuae", "aed"),
            destination_dataspace: DataSpaceId::new(12),
            destination_asset_definition_id: asset("sbp", "pkr"),
            allowed_destination_alias_domains: BTreeSet::from([
                DomainId::try_new("hbl", "sbp").expect("HBL domain"),
                DomainId::try_new("ubl", "sbp").expect("UBL domain"),
            ]),
            oracle_feed_id: "aed_pkr".parse().expect("feed id"),
            max_oracle_age_ms: 60_000,
            max_source_amount_per_settlement: Quantity::from(1_000_u32),
            max_destination_amount_per_settlement: Quantity::from(100_000_u32),
            velocity_window_ms: 60_000,
            max_settlements_per_window: 100,
            max_source_amount_per_window: Quantity::from(10_000_u32),
            max_destination_amount_per_window: Quantity::from(1_000_000_u32),
            enabled: true,
        }
    }
    fn fx_oracle_event() -> FeedEvent {
        FeedEvent {
            feed_id: "aed_pkr".parse().expect("feed id"),
            feed_config_version: FeedConfigVersion(1),
            slot: 42,
            request_hash: Hash::new(b"aed-pkr-request"),
            outcome: crate::oracle::FeedEventOutcome::Success(crate::oracle::FeedSuccess {
                value: ObservationValue::new(76, 0),
                entries: Vec::new(),
            }),
        }
    }
    fn fx_oracle_evidence() -> FxCorridorOracleEvidence {
        let event = fx_oracle_event();
        FxCorridorOracleEvidence {
            feed_id: event.feed_id.clone(),
            feed_config_version: event.feed_config_version,
            slot: event.slot,
            request_hash: event.request_hash,
            event_hash: HashOf::new(&event),
        }
    }
    fn fx_settlement_instruction() -> SettleFxCorridor {
        let policy = fx_policy();
        SettleFxCorridor {
            policy_id: policy.policy_id,
            expected_policy_revision: policy.revision,
            source_asset_definition_id: policy.source_asset_definition_id,
            destination_asset_definition_id: policy.destination_asset_definition_id,
            settlement_id: SettlementId::new(
                account(ALICE_SIGNATORY, "test"),
                "fx_settlement_1".parse().expect("reference"),
            ),
            recipient: account(BOB_SIGNATORY, "sbp"),
            source_amount: Quantity::from(10_u32),
            expected_destination_amount: Quantity::from(760_u32),
            oracle_evidence: fx_oracle_evidence(),
        }
    }
    fn fx_funding_instruction() -> FundFxCorridorEscrow {
        let policy = fx_policy();
        FundFxCorridorEscrow {
            policy_id: policy.policy_id,
            expected_policy_revision: policy.revision,
            destination_asset_definition_id: policy.destination_asset_definition_id,
            amount: Quantity::from(10_000_u32),
        }
    }
    fn fx_refund_instruction() -> RefundFxCorridorEscrow {
        let policy = fx_policy();
        RefundFxCorridorEscrow {
            policy_id: policy.policy_id,
            expected_policy_revision: policy.revision,
            destination_asset_definition_id: policy.destination_asset_definition_id,
            amount: Quantity::from(250_u32),
        }
    }

    #[test]
    #[ignore = "explicit current typed captures of owner-qualified settlement instructions"]
    fn print_scoped_settlement_bilateral_and_fx_fixture_rows() {
        use crate::isi::{
            generated_box_identity_tests::case, generated_record_identity_tests::capture,
        };
        let dvp = dvp_instruction();
        let pvp = pvp_instruction();
        let fx = fx_settlement_instruction();
        for row in [
            capture(dvp.clone()),
            capture(pvp.clone()),
            capture(fx.clone()),
        ] {
            println!(
                "SCOPED_SETTLEMENT_RECORD={}",
                norito::json::to_json(&row).unwrap()
            );
        }
        for row in [
            case("Dvp", SettlementInstructionBox::Dvp(dvp)),
            case("Pvp", SettlementInstructionBox::Pvp(pvp)),
            case(
                "SettleFxCorridor",
                SettlementInstructionBox::SettleFxCorridor(fx),
            ),
        ] {
            println!(
                "SCOPED_SETTLEMENT_BOX_CASE={}",
                norito::json::to_json(&row).unwrap()
            );
        }
    }
    #[test]
    fn dvp_roundtrip_encodes_plan() {
        let settlement_id: SettlementId = SettlementId::new(
            account(ALICE_SIGNATORY, "test"),
            "dvp_trade_1".parse().expect("reference"),
        );
        let delivery_leg = SettlementLeg::new(
            asset("wonderland", "bond"),
            1_000u32,
            account(ALICE_SIGNATORY, "test"),
            account(BOB_SIGNATORY, "test"),
        );
        let payment_leg = SettlementLeg::new(
            asset("wonderland", "usd"),
            1_005u32,
            account(BOB_SIGNATORY, "test"),
            account(ALICE_SIGNATORY, "test"),
        );
        let plan = SettlementPlan::new(
            SettlementExecutionOrder::DeliveryThenPayment,
            SettlementAtomicity::AllOrNothing,
        );
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg: delivery_leg.clone(),
            payment_leg: payment_leg.clone(),
            plan,
            metadata: Metadata::default(),
        };
        let bytes = instruction.encode();
        let decoded = DvpIsi::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(instruction, decoded);
        assert_eq!(decoded.plan().order(), plan.order());
        assert_eq!(decoded.plan().atomicity(), plan.atomicity());
        assert_eq!(
            decoded.delivery_leg().asset_definition_id(),
            delivery_leg.asset_definition_id()
        );
    }
    #[test]
    fn pvp_display_includes_identifier() {
        let settlement_id: SettlementId = SettlementId::new(
            account(ALICE_SIGNATORY, "test"),
            "pvp_fx_1".parse().expect("reference"),
        );
        let primary_leg = SettlementLeg::new(
            asset("wonderland", "usd"),
            1_000u32,
            account(ALICE_SIGNATORY, "test"),
            account(BOB_SIGNATORY, "test"),
        );
        let counter_leg = SettlementLeg::new(
            asset("wonderland", "eur"),
            920u32,
            account(BOB_SIGNATORY, "test"),
            account(ALICE_SIGNATORY, "test"),
        );
        let plan = SettlementPlan::new(
            SettlementExecutionOrder::PaymentThenDelivery,
            SettlementAtomicity::AllOrNothing,
        );
        let instruction = PvpIsi {
            settlement_id,
            primary_leg,
            counter_leg,
            plan,
            metadata: Metadata::default(),
        };
        let formatted = format!("{instruction}");
        assert!(formatted.contains("pvp_fx_1"));
        assert!(formatted.contains("PaymentThenDelivery"));
        assert!(formatted.contains("AllOrNothing"));
    }
    #[test]
    fn bilateral_intent_hash_binds_complete_instruction() {
        let dvp = dvp_instruction();
        let same = dvp.clone();
        let mut changed = dvp.clone();
        changed.payment_leg.quantity = Quantity::from(1_006_u32);
        assert_eq!(dvp.intent_hash(), same.intent_hash());
        assert_ne!(dvp.intent_hash(), changed.intent_hash());
        assert_ne!(dvp.intent_hash(), pvp_instruction().intent_hash());
    }
    #[test]
    fn settlement_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(dvp_instruction());
        assert_slice_roundtrip(pvp_instruction());
        assert_slice_roundtrip(SetFxCorridorPolicy {
            policy: fx_policy(),
        });
        assert_slice_roundtrip(fx_funding_instruction());
        assert_slice_roundtrip(fx_refund_instruction());
        assert_slice_roundtrip(fx_settlement_instruction());
        assert_slice_roundtrip(SettlementInstructionBox::Dvp(dvp_instruction()));
        assert_slice_roundtrip(SettlementInstructionBox::Pvp(pvp_instruction()));
        assert_slice_roundtrip(SettlementInstructionBox::SetFxCorridorPolicy(
            SetFxCorridorPolicy {
                policy: fx_policy(),
            },
        ));
        assert_slice_roundtrip(SettlementInstructionBox::FundFxCorridorEscrow(
            fx_funding_instruction(),
        ));
        assert_slice_roundtrip(SettlementInstructionBox::RefundFxCorridorEscrow(
            fx_refund_instruction(),
        ));
        assert_slice_roundtrip(SettlementInstructionBox::SettleFxCorridor(
            fx_settlement_instruction(),
        ));
    }
    #[test]
    fn fx_protocol_escrow_binds_exact_network_corridor_and_asset() {
        let policy = fx_policy();
        let first_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"fx-network-one")),
        );
        let second_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"fx-network-two")),
        );
        let first = fx_corridor_escrow_account_id_v1(
            &first_network,
            &policy.corridor_id(),
            &policy.destination_asset_definition_id,
        );
        let other_network = fx_corridor_escrow_account_id_v1(
            &second_network,
            &policy.corridor_id(),
            &policy.destination_asset_definition_id,
        );
        let other_asset = fx_corridor_escrow_account_id_v1(
            &first_network,
            &policy.corridor_id(),
            &policy.source_asset_definition_id,
        );
        let mut other_corridor = policy.corridor_id();
        other_corridor.policy_id = "other_corridor".parse().expect("corridor id");
        let other_corridor = fx_corridor_escrow_account_id_v1(
            &first_network,
            &other_corridor,
            &policy.destination_asset_definition_id,
        );
        assert_ne!(first, other_network);
        assert_ne!(first, other_asset);
        assert_ne!(first, other_corridor);
    }

    #[test]
    fn settlement_instructions_json_roundtrip() {
        let dvp = dvp_instruction();
        let encoded = norito::json::to_json(&dvp).expect("serialize DvP instruction");
        let decoded: DvpIsi =
            norito::json::from_str(&encoded).expect("deserialize DvP instruction");
        assert_eq!(decoded, dvp);
        let pvp = pvp_instruction();
        let encoded = norito::json::to_json(&pvp).expect("serialize PvP instruction");
        let decoded: PvpIsi =
            norito::json::from_str(&encoded).expect("deserialize PvP instruction");
        assert_eq!(decoded, pvp);
        let policy = SetFxCorridorPolicy {
            policy: fx_policy(),
        };
        let encoded = norito::json::to_json(&policy).expect("serialize FX policy instruction");
        assert!(encoded.contains("\"owner\":"));
        assert!(encoded.contains("\"oracle_feed_id\":[\"aed_pkr\"]"));
        assert!(
            encoded.contains("\"allowed_destination_alias_domains\":[\"hbl.sbp\",\"ubl.sbp\"]")
        );
        let decoded: SetFxCorridorPolicy =
            norito::json::from_str(&encoded).expect("deserialize FX policy instruction");
        assert_eq!(decoded, policy);
        assert!(!encoded.contains("source_sink"));
        assert!(!encoded.contains("destination_reserve"));
        assert!(!encoded.contains("rate_numerator"));
        let settlement = fx_settlement_instruction();
        let encoded =
            norito::json::to_json(&settlement).expect("serialize FX settlement instruction");
        let decoded: SettleFxCorridor =
            norito::json::from_str(&encoded).expect("deserialize FX settlement instruction");
        assert_eq!(decoded, settlement);
    }
    #[test]
    fn resolved_receipt_json_requires_canonical_quantity_strings() {
        let details = ResolvedSettlementMovement {
            source: crate::asset::AssetId::new(
                asset("bank", "cash"),
                account(ALICE_SIGNATORY, "bank"),
            ),
            destination: crate::asset::AssetId::new(
                asset("bank", "cash"),
                account(BOB_SIGNATORY, "bank"),
            ),
            quantity: Quantity::from(10_u32),
            metadata: Metadata::default(),
        };
        let canonical =
            norito::json::to_json(&details).expect("serialize resolved receipt movement");
        assert!(canonical.contains("\"quantity\":\"10\""));
        let decoded: ResolvedSettlementMovement =
            norito::json::from_str(&canonical).expect("canonical receipt JSON");
        assert_eq!(decoded, details);
        for replacement in ["\"quantity\":10", "\"quantity\":\"010\""] {
            let malformed = canonical.replace("\"quantity\":\"10\"", replacement);
            assert!(
                norito::json::from_str::<ResolvedSettlementMovement>(&malformed).is_err(),
                "receipts must reject non-string and non-canonical quantity encodings"
            );
        }
    }
    #[test]
    fn committed_settlement_receipt_roundtrips_one_fixed_leg_pair() {
        let DvpIsi {
            delivery_leg,
            payment_leg,
            plan,
            ..
        } = dvp_instruction();
        let receipt = SettlementReceipt {
            authority: delivery_leg.from().clone(),
            metadata: Metadata::default(),
            block_height: 7,
            block_hash: HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                [0xA7; Hash::LENGTH],
            )),
            executed_at_ms: 11,
            details: SettlementDetails::Dvp(crate::isi::DvpSettlementDetails {
                order: plan.order(),
                delivery: ResolvedSettlementMovement {
                    source: crate::asset::AssetId::new(
                        delivery_leg.asset_definition_id.clone(),
                        delivery_leg.from.clone(),
                    ),
                    destination: crate::asset::AssetId::new(
                        delivery_leg.asset_definition_id,
                        delivery_leg.to,
                    ),
                    quantity: delivery_leg.quantity,
                    metadata: delivery_leg.metadata,
                },
                payment: ResolvedSettlementMovement {
                    source: crate::asset::AssetId::new(
                        payment_leg.asset_definition_id.clone(),
                        payment_leg.from.clone(),
                    ),
                    destination: crate::asset::AssetId::new(
                        payment_leg.asset_definition_id,
                        payment_leg.to,
                    ),
                    quantity: payment_leg.quantity,
                    metadata: payment_leg.metadata,
                },
            }),
        };
        let bytes = receipt.encode();
        let decoded = SettlementReceipt::decode(&mut bytes.as_slice()).expect("decode receipt");
        assert_eq!(decoded, receipt);
        assert!(matches!(
            decoded.details,
            SettlementDetails::Dvp(crate::isi::DvpSettlementDetails { .. })
        ));

        {
            let json = norito::json::to_json(&receipt).expect("serialize receipt");
            assert!(
                !json.contains("\"settlement_id\"") && !json.contains("\"outcome\""),
                "the map key is the sole settlement identity and receipt presence means success"
            );
            let decoded: SettlementReceipt =
                norito::json::from_str(&json).expect("deserialize receipt");
            assert_eq!(decoded, receipt);
            assert!(matches!(
                decoded.details,
                SettlementDetails::Dvp(crate::isi::DvpSettlementDetails { .. })
            ));
        }
    }
    #[test]
    fn negative_numeric_payloads_cannot_decode_as_settlement_quantities() {
        let encoded = ForgedSettlementLeg {
            asset_definition_id: asset("wonderland", "bond"),
            quantity: Numeric::new(-1_i32, 0),
            from: account(ALICE_SIGNATORY, "test"),
            to: account(BOB_SIGNATORY, "test"),
            metadata: Metadata::default(),
        }
        .encode();
        assert!(
            SettlementLeg::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a settlement leg"
        );
        let policy = fx_policy();
        let recipient = account(BOB_SIGNATORY, "sbp");
        let forged_instruction = ForgedSettleFxCorridor {
            policy_id: policy.policy_id.clone(),
            expected_policy_revision: policy.revision,
            source_asset_definition_id: policy.source_asset_definition_id.clone(),
            destination_asset_definition_id: policy.destination_asset_definition_id.clone(),
            settlement_id: SettlementId::new(
                account(ALICE_SIGNATORY, "test"),
                "negative_fx_settlement".parse().expect("reference"),
            ),
            recipient: recipient.clone(),
            source_amount: Numeric::new(-1_i32, 0),
            expected_destination_amount: Quantity::from(760_u32),
            oracle_evidence: fx_oracle_evidence(),
        };
        assert!(
            SettleFxCorridor::decode_from_slice(&forged_instruction.encode()).is_err(),
            "a negative signed payload must not decode as an FX settlement instruction"
        );
        let forged_receipt = ForgedResolvedSettlementMovement {
            source: crate::asset::AssetId::with_scope(
                policy.source_asset_definition_id,
                policy.owner,
                crate::asset::AssetBalanceScope::Dataspace(policy.source_dataspace),
            ),
            destination: crate::asset::AssetId::with_scope(
                policy.destination_asset_definition_id,
                recipient,
                crate::asset::AssetBalanceScope::Dataspace(policy.destination_dataspace),
            ),
            quantity: Numeric::new(-1_i32, 0),
            metadata: Metadata::default(),
        };
        let encoded = forged_receipt.encode();
        assert!(
            ResolvedSettlementMovement::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a durable FX settlement receipt"
        );
    }
    #[test]
    fn settlement_registry_decodes_only_the_stable_box_id() {
        let registry = crate::isi::registry::default();
        for value in [
            SettlementInstructionBox::Dvp(dvp_instruction()),
            SettlementInstructionBox::Pvp(pvp_instruction()),
            SettlementInstructionBox::SetFxCorridorPolicy(SetFxCorridorPolicy {
                policy: fx_policy(),
            }),
            SettlementInstructionBox::FundFxCorridorEscrow(fx_funding_instruction()),
            SettlementInstructionBox::RefundFxCorridorEscrow(fx_refund_instruction()),
            SettlementInstructionBox::SettleFxCorridor(fx_settlement_instruction()),
        ] {
            assert_registry_decodes(&registry, SettlementInstructionBox::WIRE_ID, value);
        }
        for name in [
            std::any::type_name::<DvpIsi>(),
            std::any::type_name::<PvpIsi>(),
            std::any::type_name::<SetFxCorridorPolicy>(),
            std::any::type_name::<FundFxCorridorEscrow>(),
            std::any::type_name::<RefundFxCorridorEscrow>(),
            std::any::type_name::<SettleFxCorridor>(),
            DvpIsi::WIRE_ID,
            PvpIsi::WIRE_ID,
            SetFxCorridorPolicy::WIRE_ID,
            FundFxCorridorEscrow::WIRE_ID,
            RefundFxCorridorEscrow::WIRE_ID,
            SettleFxCorridor::WIRE_ID,
        ] {
            assert!(!registry.contains(name), "{name} must remain boxed-only");
        }
        assert!(!registry.contains(std::any::type_name::<SettlementInstructionBox>()));
    }
}

#[cfg(test)]
mod captured_settlement_ordinary_schema_tests;
