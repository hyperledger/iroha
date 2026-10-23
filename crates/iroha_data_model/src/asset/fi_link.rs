//! Native FI eligibility and owner-approved opaque checking-account links.

use super::AssetDefinitionId;
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, smart_contract::ContractAddress,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Asset-owner approval of one exact FI settlement account.
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
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiV1")]
pub struct AssetFiV1 {
    /// Exact globally scoped asset.
    pub asset_definition_id: AssetDefinitionId,
    /// FI signing identity and settlement destination.
    pub fi_account_id: AccountId,
    /// Starts at one and advances exactly once per update.
    pub revision: u64,
    /// Revocation invalidates every link referring to this FI revision.
    pub enabled: bool,
}

/// FI-authenticated reference to participant-held checking-account details.
///
/// The reference must be a cryptographically opaque participant reference, never
/// raw account details or a deterministic digest of a checking-account number.
/// This record alone does not authorize any wallet debit or capability.
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
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiLinkAttestationV1")]
pub struct AssetFiLinkAttestationV1 {
    /// Exact globally scoped asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Wallet whose checking-account relationship the FI verified.
    pub account_id: AccountId,
    /// Exact registered FI signing identity and settlement destination.
    pub fi_account_id: AccountId,
    /// Commitment to the opaque reference held at the participant boundary.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub reference_digest: [u8; 32],
    /// Starts at one and advances exactly once for this exact reference.
    pub revision: u64,
    /// Revocation invalidates owner links to this attestation revision.
    pub enabled: bool,
}

/// Current owner-approved checking-account link and capabilities for one wallet.
///
/// Both FI eligibility and the exact FI attestation remain revision-bound.
/// Changing either requires fresh owner approval before monetary use.
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
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiLinkV1")]
pub struct AssetFiLinkV1 {
    /// Exact globally scoped asset.
    pub asset_definition_id: AssetDefinitionId,
    /// Owner-controlled wallet.
    pub account_id: AccountId,
    /// Derived settlement destination, approved by the owner.
    pub fi_account_id: AccountId,
    /// Exact participant reference authenticated by the FI.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub reference_digest: [u8; 32],
    /// Exact FI eligibility revision approved by the owner.
    pub fi_revision: u64,
    /// Exact FI attestation revision approved by the owner.
    pub attestation_revision: u64,
    /// Starts at one and advances exactly once on each owner update.
    pub revision: u64,
    /// False disables all monetary uses of this link.
    pub enabled: bool,
    /// Exact contract instance approved to execute enabled automated capabilities.
    pub controller: Option<ContractAddress>,
    /// Owner consent to move beneficial holdings above the cap to this FI.
    pub waterfall: bool,
    /// Owner consent to the separate reverse-waterfall facility.
    ///
    /// This flag does not itself enable an execution path or grant FI debit rights.
    pub reverse_waterfall: bool,
}

/// Exact relationship lookup, accessible only to the asset owner or wallet owner.
///
/// Missing records remain `None`; revocation retains a present disabled record.
/// The current wallet link may differ from the requested FI reference.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiRelationshipViewV1")]
pub struct AssetFiRelationshipViewV1 {
    /// Current eligibility of the exact requested FI.
    pub fi: Option<AssetFiV1>,
    /// Current FI authentication of the exact requested opaque reference.
    pub attestation: Option<AssetFiLinkAttestationV1>,
    /// Current owner-approved wallet link, including disabled links.
    pub link: Option<AssetFiLinkV1>,
    /// Authenticated ledger time of the captured native view.
    pub ledger_time_ms: u64,
    /// Captured committed ledger height.
    pub as_of_height: u64,
}

/// Actual authenticated contract frame of a native linked-FI movement.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiTransferControllerV1")]
pub struct AssetFiTransferControllerV1 {
    /// Contract instance admitted by the owner link.
    pub address: ContractAddress,
    /// Executing runtime subject of that instance.
    pub subject: AccountId,
    /// Actual executing entrypoint.
    pub entrypoint: String,
}

/// Immutable native execution record for one linked-FI transfer occurrence.
///
/// Decoding a record grants no authority. Consumers must verify its certified
/// membership and join its original execution and exact transcript occurrence.
/// Later FI/link revisions do not replace the relationship captured here.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_link::AssetFiTransferReceiptV1")]
pub struct AssetFiTransferReceiptV1 {
    /// Exact asset-definition incarnation admitted for this native occurrence.
    pub asset_incarnation: crate::nexus::AxtAssetIncarnationV1,
    /// Network of the executing native state.
    pub network: crate::NetworkId,
    /// Identity selected by the native movement transcript resolver.
    pub execution_call_hash: iroha_crypto::Hash,
    /// Hash of the complete canonical native instruction box.
    pub instruction_hash: iroha_crypto::Hash,
    /// Exact five-field instruction executed by Native.
    pub instruction: crate::isi::asset_fi::TransferToLinkedFiV1,
    /// Actual debit authority.
    pub authority: AccountId,
    /// Actual contract frame, absent for direct owner execution.
    pub controller: Option<AssetFiTransferControllerV1>,
    /// Complete FI eligibility admitted for this occurrence.
    pub fi: AssetFiV1,
    /// Complete opaque-reference authentication admitted for this occurrence.
    pub attestation: AssetFiLinkAttestationV1,
    /// Complete owner approval admitted for this occurrence.
    pub link: AssetFiLinkV1,
    /// Native UID bound to the debited wallet.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uid: [u8; 32],
    /// Admitted UID policy revision.
    pub uid_policy_revision: u64,
    /// Hash of the complete canonical admitted UID policy.
    pub uid_policy_hash: iroha_crypto::Hash,
    /// Height of the actual execution.
    pub execution_height: u64,
    /// Certified block time used by the actual execution.
    pub execution_time_ms: u64,
    /// Zero-based occurrence within this call's native transfer transcript list.
    pub transcript_index: u64,
}
