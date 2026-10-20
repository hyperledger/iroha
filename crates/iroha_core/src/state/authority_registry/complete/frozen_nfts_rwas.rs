//! Actual three-owner NFT and four-owner RWA frozen relations and canonical encoding.
//! Scoped tables grant no joint StatePublication, economic or finality authority.
//! TODO: join all remaining cells/history/owners to sole StatePublication and Kura.
use super::{CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits};
use crate::state::{
    StateBlock,
    authority_registry::grouped_ownership::{validate_original_nfts, validate_original_rwas},
    block_field::AggregatePublication,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{
    account::AccountId,
    nft::{NftId, NftValue},
    rwa::{RwaId, RwaValue},
};
use iroha_model_base::{domain::DomainId, name::Name};
use mv::storage::FrozenStorageImages;
struct OriginalNfts<'frozen> {
    rows: FrozenStorageImages<'frozen, NftId, NftValue>,
    owners: FrozenStorageImages<'frozen, (AccountId, NftId), ()>,
    domains: FrozenStorageImages<'frozen, (DomainId, NftId), ()>,
    budget: &'frozen AllocationBudget,
}
impl<'frozen> OriginalNfts<'frozen> {
    fn retain(block: &'frozen StateBlock<'_>) -> Option<Self> {
        let fields = block.fields.as_ref()?;
        if fields.world.publication != AggregatePublication::Frozen {
            return None;
        }
        let rows = fields.world.nfts.frozen_images()?;
        let owners = fields.world.nfts_by_owner.frozen_images()?;
        let domains = fields.world.nfts_by_domain.frozen_images()?;
        let rows_owned = rows.belongs_to(&fields.state_ref.world.nfts);
        let owners_owned = owners.belongs_to(&fields.state_ref.world.nfts_by_owner);
        let domains_owned = domains.belongs_to(&fields.state_ref.world.nfts_by_domain);
        let rows_mode = rows.mode();
        let owners_mode = owners.mode();
        let domains_mode = domains.mode();
        if !rows_owned
            || !owners_owned
            || !domains_owned
            || rows_mode != owners_mode
            || rows_mode != domains_mode
        {
            return None;
        }
        Some(Self {
            rows,
            owners,
            domains,
            budget: &fields.state_ref.ivm_execution_budget,
        })
    }
}
/// Check both exact original images and encode their original current rows with the State pool.
pub(in crate::state) fn capture_nfts(
    block: &StateBlock<'_>,
    limits: LeafLimits,
    max_work: u64,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let Some(original) = OriginalNfts::retain(block) else {
        return Ok(None);
    };
    validate_original_nfts(
        &original.rows,
        &original.owners,
        &original.domains,
        max_work,
    )?;
    CanonicalTableLeafSet::paired_table_from_rows(
        "world.nfts",
        limits,
        original.budget,
        original.rows.current_entries(),
    )
    .map(Some)
}
struct OriginalRwas<'frozen> {
    rows: FrozenStorageImages<'frozen, RwaId, RwaValue>,
    owners: FrozenStorageImages<'frozen, (AccountId, RwaId), ()>,
    statuses: FrozenStorageImages<'frozen, (Option<Name>, RwaId), ()>,
    frozen: FrozenStorageImages<'frozen, (bool, RwaId), ()>,
    budget: &'frozen AllocationBudget,
}
impl<'frozen> OriginalRwas<'frozen> {
    fn retain(block: &'frozen StateBlock<'_>) -> Option<Self> {
        let fields = block.fields.as_ref()?;
        if fields.world.publication != AggregatePublication::Frozen {
            return None;
        }
        let rows = fields.world.rwas.frozen_images()?;
        let owners = fields.world.rwas_by_owner.frozen_images()?;
        let statuses = fields.world.rwas_by_status.frozen_images()?;
        let frozen = fields.world.rwas_by_frozen.frozen_images()?;
        let rows_owned = rows.belongs_to(&fields.state_ref.world.rwas);
        let owners_owned = owners.belongs_to(&fields.state_ref.world.rwas_by_owner);
        let statuses_owned = statuses.belongs_to(&fields.state_ref.world.rwas_by_status);
        let frozen_owned = frozen.belongs_to(&fields.state_ref.world.rwas_by_frozen);
        let rows_mode = rows.mode();
        let owners_mode = owners.mode();
        let statuses_mode = statuses.mode();
        let frozen_mode = frozen.mode();
        if !rows_owned
            || !owners_owned
            || !statuses_owned
            || !frozen_owned
            || rows_mode != owners_mode
            || rows_mode != statuses_mode
            || rows_mode != frozen_mode
        {
            return None;
        }
        Some(Self {
            rows,
            owners,
            statuses,
            frozen,
            budget: &fields.state_ref.ivm_execution_budget,
        })
    }
}
/// Check both exact original images and encode their original current rows with the State pool.
pub(in crate::state) fn capture_rwas(
    block: &StateBlock<'_>,
    limits: LeafLimits,
    max_work: u64,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let Some(original) = OriginalRwas::retain(block) else {
        return Ok(None);
    };
    validate_original_rwas(
        &original.rows,
        &original.owners,
        &original.statuses,
        &original.frozen,
        max_work,
    )?;
    CanonicalTableLeafSet::paired_table_from_rows(
        "world.rwas",
        limits,
        original.budget,
        original.rows.current_entries(),
    )
    .map(Some)
}
#[cfg(test)]
#[path = "frozen_nfts_rwas/tests.rs"]
mod tests;
