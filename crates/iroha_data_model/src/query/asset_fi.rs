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
}
