//! Frozen balance/reference/index owners and exact direct-home authority.
//! Scoped rows do not supply complete State or private settlement authority.
//! TODO: join all remaining owners/cells/history to StatePublication and Kura.
use super::{CanonicalTableLeafSet, CanonicalTablePairedSnapshot, LeafError, LeafLimits};
use crate::state::{
    StateBlock, authority_registry::grouped_ownership::validate_original_assets,
    block_field::AggregatePublication,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::nexus::AxtAssetIncarnationV1;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinition, AssetDefinitionDirectHomeV1, AssetDefinitionId, AssetId, AssetValue},
    domain::Domain,
};
use iroha_model_base::domain::DomainId;
use mv::storage::FrozenStorageImages;
use std::collections::BTreeSet;
struct Original<'frozen> {
    homes: FrozenStorageImages<'frozen, AssetDefinitionId, AssetDefinitionDirectHomeV1>,
    incarnations: FrozenStorageImages<'frozen, AssetDefinitionId, AxtAssetIncarnationV1>,
    rows: FrozenStorageImages<'frozen, AssetId, AssetValue>,
    definitions: FrozenStorageImages<'frozen, AssetDefinitionId, AssetDefinition>,
    domains: FrozenStorageImages<'frozen, DomainId, Domain>,
    by_definition: FrozenStorageImages<'frozen, AssetDefinitionId, BTreeSet<AssetId>>,
    by_account: FrozenStorageImages<'frozen, AccountId, BTreeSet<AssetId>>,
    by_domain: FrozenStorageImages<'frozen, DomainId, BTreeSet<AssetId>>,
    holders: FrozenStorageImages<'frozen, AssetDefinitionId, BTreeSet<AccountId>>,
    nonzero: FrozenStorageImages<'frozen, AssetDefinitionId, BTreeSet<AccountId>>,
    budget: &'frozen AllocationBudget,
}
impl<'frozen> Original<'frozen> {
    fn retain(block: &'frozen StateBlock<'_>) -> Option<Self> {
        let fields = block.fields.as_ref()?;
        if fields.world.publication != AggregatePublication::Frozen {
            return None;
        }
        let homes = fields.world.asset_definition_direct_homes.frozen_images()?;
        let incarnations = fields.world.axt_asset_incarnations.frozen_images()?;
        let rows = fields.world.assets.frozen_images()?;
        let definitions = fields.world.asset_definitions.frozen_images()?;
        let domains = fields.world.domains.frozen_images()?;
        let by_definition = fields.world.asset_definition_assets.frozen_images()?;
        let by_account = fields.world.assets_by_account.frozen_images()?;
        let by_domain = fields.world.assets_by_domain.frozen_images()?;
        let holders = fields.world.asset_definition_holders.frozen_images()?;
        let nonzero = fields
            .world
            .asset_definition_nonzero_holders
            .frozen_images()?;
        let rows_owned = rows.belongs_to(&fields.state_ref.world.assets);
        let definitions_owned = definitions.belongs_to(&fields.state_ref.world.asset_definitions);
        let domains_owned = domains.belongs_to(&fields.state_ref.world.domains);
        let by_definition_owned =
            by_definition.belongs_to(&fields.state_ref.world.asset_definition_assets);
        let by_account_owned = by_account.belongs_to(&fields.state_ref.world.assets_by_account);
        let by_domain_owned = by_domain.belongs_to(&fields.state_ref.world.assets_by_domain);
        let holders_owned = holders.belongs_to(&fields.state_ref.world.asset_definition_holders);
        let nonzero_owned =
            nonzero.belongs_to(&fields.state_ref.world.asset_definition_nonzero_holders);
        if !homes.belongs_to(&fields.state_ref.world.asset_definition_direct_homes)
            || !incarnations.belongs_to(&fields.state_ref.world.axt_asset_incarnations)
            || rows.mode() != homes.mode()
            || rows.mode() != incarnations.mode()
            || !rows_owned
            || !definitions_owned
            || !domains_owned
            || !by_definition_owned
            || !by_account_owned
            || !by_domain_owned
            || !holders_owned
            || !nonzero_owned
            || rows.mode() != definitions.mode()
            || rows.mode() != domains.mode()
            || rows.mode() != by_definition.mode()
            || rows.mode() != by_account.mode()
            || rows.mode() != by_domain.mode()
            || rows.mode() != holders.mode()
            || rows.mode() != nonzero.mode()
        {
            return None;
        }
        Some(Self {
            homes,
            incarnations,
            rows,
            definitions,
            domains,
            by_definition,
            by_account,
            by_domain,
            holders,
            nonzero,
            budget: &fields.state_ref.ivm_execution_budget,
        })
    }
}
/// Validate both original balance images and encode the caller's actual assets.
/// Every original target/mode and the State pool stay borrowed through encoding.
pub(in crate::state) fn capture(
    block: &StateBlock<'_>,
    limits: LeafLimits,
    max_work: u64,
) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
    let Some(original) = Original::retain(block) else {
        return Ok(None);
    };
    validate_original_assets(
        &original.rows,
        &original.definitions,
        &original.domains,
        &original.by_definition,
        &original.by_account,
        &original.by_domain,
        &original.holders,
        &original.nonzero,
        &original.homes,
        &original.incarnations,
        max_work,
    )?;
    CanonicalTableLeafSet::paired_table_from_rows(
        "world.assets",
        limits,
        original.budget,
        original.rows.current_entries(),
    )
    .map(Some)
}
#[cfg(test)]
#[path = "frozen_assets/tests.rs"]
mod tests;

#[cfg(test)]
mod direct_home_admission_tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{
            State, authority_registry::grouped_ownership::asset_balance_test_support as fixture,
        },
    };
    use iroha_data_model::block::BlockHeader;
    use iroha_model_base::topology::DataSpaceId;
    use mv::storage::StorageReadOnly;
    use std::num::NonZeroU64;

    #[test]
    fn same_frozen_original_retries_after_original_pool_admission_refusal() {
        let _pin = crossbeam_epoch::pin();
        let mut world = *fixture::fixture(false);
        let id = fixture::definition("coin");
        world
            .set_asset_definition_dataspace_for_testing(id.clone(), DataSpaceId::new(7))
            .unwrap();
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let pool = state.ivm_execution_budget();
        let original_limit = pool.limit_bytes();
        let mut block = state.block(BlockHeader::new(NonZeroU64::MIN, None, None, 1, 0));
        let pointer = core::ptr::from_ref(block.world.asset_definitions.get(&id).unwrap());
        block.world.begin_freeze();
        block.world.finish_freeze();
        block.world.retire_frozen_cleanup();
        let baseline = pool.reserved_bytes();
        let limits = LeafLimits {
            max_tables: 1,
            max_rows: 64,
            max_payload_bytes: 65536,
            max_ordered_table_bytes: 131072,
            max_streamed_value_bytes: 131072,
        };
        pool.set_limit_bytes(0);
        // Direct-home rows need no extra backing; the leaf encoder refuses the empty pool.
        assert!(matches!(
            capture(&block, limits, 16_777_216),
            Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
        ));
        assert_eq!(pool.reserved_bytes(), baseline);
        pool.set_limit_bytes(original_limit);
        let snapshot = capture(&block, limits, 16_777_216).unwrap().unwrap();
        assert_eq!(
            core::ptr::from_ref(block.world.asset_definitions.get(&id).unwrap()),
            pointer
        );
        assert!(pool.reserved_bytes() > baseline);
        drop(snapshot);
        assert_eq!(pool.reserved_bytes(), baseline);
    }
}
