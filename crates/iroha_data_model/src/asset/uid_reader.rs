//! Private contract-scoped beneficial-holdings quotes and revocable reader grants.

use super::AssetDefinitionId;
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, smart_contract::ContractAddress,
};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Asset-owner grant to one exact contract instance for UID holding quotes.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidPolicyReaderV1")]
pub struct AssetUidPolicyReaderV1 {
    /// Exact globally scoped asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact active contract instance, never a caller-supplied signing identity.
    pub controller: ContractAddress,
    /// Starts at one and advances exactly once on each owner update.
    pub revision: u64,
    /// Explicit revocation immediately stops quotes.
    pub enabled: bool,
}

/// Current aggregate beneficial holding quote without identity or roster disclosure.
///
/// Callers must pin the policy revision and any current link revision when
/// executing a mutation. A quote never grants transfer authority or cap bypass.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::uid::AssetUidHoldingQuoteV1")]
pub struct AssetUidHoldingQuoteV1 {
    /// Exact requested asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact requested wallet.
    pub account_id: AccountId,
    /// Current policy revision, required by subsequent native mutations.
    pub policy_revision: u64,
    /// All wallets and unresolved native payer reserves for the bound identity.
    pub beneficial_holdings: Quantity,
    /// Current aggregate holding limit.
    pub holding_limit: Option<Quantity>,
    /// Maximum of aggregate holdings plus incoming value minus the cap and zero.
    pub required_overflow: Quantity,
}
