//! Private exact-wallet FI relationship lookup.

use crate::{account::AccountId, asset::AssetDefinitionId};
use derive_more::Display;

queries! {
    /// Resolve FI eligibility, an exact opaque reference, and the current owner link.
    ///
    /// Only the exact asset owner or exact wallet owner may query this view. FI
    /// status or public asset read access never grants visibility into a wallet's
    /// link to another FI.
    #[derive(Display)]
    #[display("Find FI relationship for `{account_id}` and `{asset_definition_id}`")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_fi::FindAssetFiLinkV1")]
    pub struct FindAssetFiLinkV1 {
        /// Exact globally scoped asset.
        pub asset_definition_id: AssetDefinitionId,
        /// Exact owner-controlled wallet.
        pub account_id: AccountId,
        /// FI whose eligibility and reference authentication are requested.
        pub fi_account_id: AccountId,
        /// Opaque participant reference commitment.
        pub reference_digest: [u8; 32],
    }

    /// Read zero or one immutable native FI occurrence candidate by its exact key.
    ///
    /// Only the exact wallet or current Global asset owner may read this private
    /// original. This query supplies no certified membership or execution proof.
    #[derive(Display)]
    #[display("Find FI receipt for `{account_id}` at `{execution_call_hash}`/{transcript_index}")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_fi::FindAssetFiTransferReceiptV1")]
    pub struct FindAssetFiTransferReceiptV1 {
        /// Exact Global asset definition.
        pub asset_definition_id: AssetDefinitionId,
        /// Exact historical incarnation captured by the native occurrence.
        pub expected_incarnation: crate::nexus::AxtAssetIncarnationV1,
        /// Exact source wallet retained in the receipt.
        pub account_id: AccountId,
        /// Native call whose transfer transcript contains the occurrence.
        pub execution_call_hash: iroha_crypto::Hash,
        /// Zero-based actual transfer transcript ordinal within that call.
        pub transcript_index: u64,
    }
}
