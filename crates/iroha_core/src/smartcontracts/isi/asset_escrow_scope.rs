//! Owner-only native initialization; no generic permission or caller count.
use super::*;
use iroha_data_model::{
    isi::asset_escrow_scope::InitializeAssetEscrowReadScopeV1,
    query::asset_escrow_scope::FindAssetEscrowsByAssetDefinitionV1,
    escrow::scoped::AssetEscrowScopeOriginalV1,
};
impl Execute for InitializeAssetEscrowReadScopeV1 {
    fn execute(self, authority: &AccountId, tx: &mut StateTransaction<'_, '_>) -> Result<(), Error> {
        crate::state::asset_escrow_scope::initialize(&mut tx.world, authority,
            &self.asset_definition_id, &self.expected_incarnation, self.expected_revision,
            |_, _| Ok(()))
    }
}
impl crate::smartcontracts::ValidQuery for FindAssetEscrowsByAssetDefinitionV1 {
    fn execute(self, _filter: iroha_data_model::query::dsl::CompoundPredicate<AssetEscrowScopeOriginalV1>,
        _state: &impl crate::state::StateReadOnly)
        -> Result<impl Iterator<Item = AssetEscrowScopeOriginalV1>, iroha_data_model::query::error::QueryExecutionFail>
    {
        Err::<core::iter::Empty<AssetEscrowScopeOriginalV1>, _>(
            iroha_data_model::query::error::QueryExecutionFail::Conversion(
                "escrow scope requires bounded ordinary native query admission".into()))
    }
}
