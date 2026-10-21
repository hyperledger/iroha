//! Owner-scoped native UID policy queries with normal stored cursor pagination.
use crate::{account::AccountId, asset::AssetDefinitionId};
use derive_more::Display;

queries! {
    /// Enumerate every UID policy for one exact asset, or select one exact UID.
    ///
    /// Only the exact asset-definition owner may start or continue this query.
    /// A participant's ability to read its own wallet does not reveal sibling
    /// wallets associated with other participants.
    #[derive(Display)]
    #[display("Find UID policies for `{asset_definition_id}`")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_uid::FindAssetUidPoliciesV1")]
    pub struct FindAssetUidPoliciesV1 {
        /// Exact governed asset.
        pub asset_definition_id: AssetDefinitionId,
        /// Exact identity filter. Absent enumerates the asset's complete roster.
        pub uid: Option<[u8; 32]>,
        /// Optional exact wallet whose holdings are requested in the selected UID.
        /// Requires `uid: Some`; native reciprocal membership must match.
        /// This selector does not grant authority to read another owner's policy.
        pub wallet_account_id: Option<AccountId>,
    }
}
