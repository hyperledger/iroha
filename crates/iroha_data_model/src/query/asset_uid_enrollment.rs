//! Owner-only mandatory asset-enrollment activation observation.

use crate::asset::AssetDefinitionId;
use derive_more::Display;

queries! {
    /// Read whether this exact asset has activated complete holder enrollment.
    ///
    /// This always returns one watermarked row: absence of activation must not
    /// be confused with an empty UID roster, a missing page or a zero balance.
    #[derive(Display)]
    #[display("Find mandatory UID enrollment for `{asset_definition_id}`")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_uid_enrollment::FindAssetUidEnrollmentV1")]
    pub struct FindAssetUidEnrollmentV1 {
        /// Exact Global asset, readable only by its definition owner.
        pub asset_definition_id: AssetDefinitionId,
    }
}
