//! Typed FI observations committed by native assertions at their execution cut.
use super::{
    AssetDefinitionId,
    fi_link::{AssetFiLinkAttestationV1, AssetFiLinkV1, AssetFiTransferReceiptV1, AssetFiV1},
    uid::{AssetUidBindingV1, AssetUidPolicyV1},
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    account::AccountId,
    isi::asset_fi::{SetAssetFiLinkV1, TransferToLinkedFiV1},
    nexus::AxtAssetIncarnationV1,
    smart_contract::ContractAddress,
};
use iroha_crypto::Hash;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Exact descriptive operation whose selected current FI context is observed.
/// This value grants no approval, debit authority or exemption.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "content", deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_context::AssetFiContextTargetV1")]
pub enum AssetFiContextTargetV1 {
    /// Complete prospective owner approval, including its policy revision.
    LinkApproval(SetAssetFiLinkV1),
    /// Transfer and exact FI selectors/revisions actually retained in consent.
    Transfer {
        /// Original five-field native transfer.
        instruction: TransferToLinkedFiV1,
        /// Exact FI settlement account resolved through admitted runtime mapping.
        fi_account_id: AccountId,
        /// Exact opaque participant reference retained in consent.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        reference_digest: [u8; 32],
        /// FI eligibility revision retained in consent.
        expected_fi_revision: u64,
        /// FI attestation revision retained in consent.
        expected_attestation_revision: u64,
    },
}

/// Exact currently active native address/subject relationship; no code-hash claim.
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
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_context::AssetFiControllerBindingV1")]
pub struct AssetFiControllerBindingV1 {
    /// Selected contract address.
    pub address: ContractAddress,
    /// Native subject currently bound to that address.
    pub subject: AccountId,
}

/// Current selected native rows at the assertion instruction's execution cut.
/// Absence and stale/disabled relationships remain explicit observations.
/// Height and time come from verified execution, never from this snapshot.
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
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::asset::fi_context::AssetFiContextSnapshotV1")]
pub struct AssetFiContextSnapshotV1 {
    /// Exact Global asset definition.
    pub asset_definition_id: AssetDefinitionId,
    /// Exact live native asset incarnation at this cut.
    pub asset_incarnation: AxtAssetIncarnationV1,
    /// Exact selected wallet.
    pub account_id: AccountId,
    /// Expected opaque UID context.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub uid: [u8; 32],
    /// Exact target FI account.
    pub fi_account_id: AccountId,
    /// Exact opaque participant reference selected by the target.
    #[norito(json = "crate::json_helpers::fixed_bytes")]
    pub reference_digest: [u8; 32],
    /// Current exact wallet membership, or explicit absence.
    #[norito(required)]
    pub binding: Option<AssetUidBindingV1>,
    /// Current exact UID policy, or explicit absence.
    #[norito(required)]
    pub policy: Option<AssetUidPolicyV1>,
    /// Current selected FI eligibility, including disabled state.
    #[norito(required)]
    pub fi: Option<AssetFiV1>,
    /// Current selected FI reference authentication.
    #[norito(required)]
    pub attestation: Option<AssetFiLinkAttestationV1>,
    /// Current owner link, which may differ from the descriptive target.
    #[norito(required)]
    pub link: Option<AssetFiLinkV1>,
    /// Selected controller's active native binding; inactive/absent means None.
    #[norito(required)]
    pub controller: Option<AssetFiControllerBindingV1>,
}

/// Hash the complete canonical typed target, including its schema frame.
/// # Errors
/// Returns the original canonical encoder failure.
pub fn asset_fi_context_target_hash_v1(
    value: &AssetFiContextTargetV1,
) -> Result<Hash, norito::core::Error> {
    Ok(Hash::new(norito::encode_canonical(value)?))
}
/// Hash the complete canonical snapshot, including explicit absence fields.
/// # Errors
/// Returns the original canonical encoder failure.
pub fn asset_fi_context_snapshot_hash_v1(
    value: &AssetFiContextSnapshotV1,
) -> Result<Hash, norito::core::Error> {
    Ok(Hash::new(norito::encode_canonical(value)?))
}
/// Hash the complete immutable native receipt, including captured incarnation.
/// # Errors
/// Returns the original canonical encoder failure.
pub fn asset_fi_transfer_receipt_hash_v1(
    value: &AssetFiTransferReceiptV1,
) -> Result<Hash, norito::core::Error> {
    Ok(Hash::new(norito::encode_canonical(value)?))
}
