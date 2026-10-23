//! Complete bounded escrow originals for the exact current asset owner.
use crate::{asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};
use derive_more::Display;
queries! {
    /// Return one initialized, complete asset scope, including explicit zero.
    /// Only pass predicates, zero offset and ephemeral cursor mode are admitted.
    #[derive(Display)]
    #[display("Find complete native escrow scope for `{asset_definition_id}`")]
    #[norito(deny_unknown_fields)]
    #[norito_schema(name = "iroha_data_model::query::asset_escrow_scope::FindAssetEscrowsByAssetDefinitionV1")]
    pub struct FindAssetEscrowsByAssetDefinitionV1 {
        /// Exact asset definition, not a tenant label.
        pub asset_definition_id: AssetDefinitionId,
        /// Must match the current native incarnation at the selected World.
        pub expected_incarnation: AxtAssetIncarnationV1,
    }
}
