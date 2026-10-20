//! Four actual original frozen escrow owners and one exact both-image relation.
//! Scoped rows do not establish instruction validity, complete State or AXT authority.
//! TODO: join all remaining originals/cells/history to sole StatePublication and Kura.
use super::{CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits};
use crate::state::{
    StateBlock, authority_registry::grouped_ownership::validate_original_escrows,
    block_field::AggregatePublication,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    account::AccountId,
    escrow::{AssetEscrowRecord, AssetEscrowStatus, EscrowId},
};
use mv::storage::FrozenStorageImages;
struct Original<'frozen> {
    rows: FrozenStorageImages<'frozen, EscrowId, AssetEscrowRecord>,
    sellers: FrozenStorageImages<'frozen, (AccountId, EscrowId), ()>,
    buyers: FrozenStorageImages<'frozen, (AccountId, EscrowId), ()>,
    statuses: FrozenStorageImages<'frozen, (AssetEscrowStatus, EscrowId), ()>,
    budget: &'frozen AllocationBudget,
}
impl<'frozen> Original<'frozen> {
    fn retain(block: &'frozen StateBlock<'_>) -> Option<Self> {
        let fields = block.fields.as_ref()?;
        if fields.world.publication != AggregatePublication::Frozen {
            return None;
        }
        let rows = fields.world.asset_escrows.frozen_images()?;
        let sellers = fields.world.asset_escrows_by_seller.frozen_images()?;
        let buyers = fields.world.asset_escrows_by_buyer.frozen_images()?;
        let statuses = fields.world.asset_escrows_by_status.frozen_images()?;
        let rows_owned = rows.belongs_to(&fields.state_ref.world.asset_escrows);
        let sellers_owned = sellers.belongs_to(&fields.state_ref.world.asset_escrows_by_seller);
        let buyers_owned = buyers.belongs_to(&fields.state_ref.world.asset_escrows_by_buyer);
        let statuses_owned = statuses.belongs_to(&fields.state_ref.world.asset_escrows_by_status);
        if !rows_owned
            || !sellers_owned
            || !buyers_owned
            || !statuses_owned
            || rows.mode() != sellers.mode()
            || rows.mode() != buyers.mode()
            || rows.mode() != statuses.mode()
        {
            return None;
        }
        Some(Self {
            rows,
            sellers,
            buyers,
            statuses,
            budget: &fields.state_ref.ivm_execution_budget,
        })
    }
}
/// Validate both original escrow images and encode the actual original current rows.
/// The four targets/modes and original State pool remain borrowed through encoding.
pub(in crate::state) fn capture(
    block: &StateBlock<'_>,
    limits: LeafLimits,
    max_work: u64,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let Some(original) = Original::retain(block) else {
        return Ok(None);
    };
    validate_original_escrows(
        &original.rows,
        &original.sellers,
        &original.buyers,
        &original.statuses,
        max_work,
    )?;
    CanonicalTableLeafSet::paired_table_from_rows(
        "world.asset_escrows",
        limits,
        original.budget,
        original.rows.current_entries(),
    )
    .map(Some)
}
#[cfg(test)]
#[path = "frozen_escrows/tests.rs"]
mod tests;
