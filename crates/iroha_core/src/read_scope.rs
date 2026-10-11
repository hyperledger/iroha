//! Dataspace classes and immutable asset-definition homes shared by every consumer.
//!
//! A dataspace has exactly one class because the lane catalog keeps one visibility per
//! dataspace and keeps the universal dataspace public (`LaneCatalog::new`). Admission, balance
//! confinement and the router derive an asset definition's home through this one module, so
//! they cannot disagree about which dataspace owns a definition.

use crate::state::WorldReadOnly;
use iroha_data_model::{
    Identifiable,
    asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionHome},
    nexus::{DataSpaceCatalog, LaneCatalog, LaneVisibility},
};
use iroha_model_base::{error::ParseError, topology::DataSpaceId};

/// Whether `dataspace` is restricted in `catalog`.
///
/// The universal dataspace is always public. A non-universal dataspace is public only when the
/// catalog lists it with public lanes; an unknown dataspace counts as restricted.
#[must_use]
pub fn dataspace_is_restricted(catalog: &LaneCatalog, dataspace: DataSpaceId) -> bool {
    dataspace != DataSpaceId::UNIVERSAL
        && catalog.dataspace_visibility(dataspace) != Some(LaneVisibility::Public)
}

/// Immutable namespace home dataspace of `definition`.
///
/// The home is the direct-home row, else the owning domain's dataspace, else (for a global
/// definition with neither) the universal dataspace. Aliases and balance buckets never decide
/// it. `Ok(None)` means the owning domain names a dataspace the catalog does not know.
///
/// # Errors
/// Propagates an invalid direct-home row or an incoherent definition home.
pub fn home_dataspace(
    world: &(impl WorldReadOnly + ?Sized),
    definition: &AssetDefinition,
) -> Result<Option<DataSpaceId>, ParseError> {
    let direct = world.asset_definition_dataspace(definition.id())?;
    Ok(
        match AssetDefinitionHome::from_definition(definition, direct)? {
            AssetDefinitionHome::Global => Some(DataSpaceId::UNIVERSAL),
            AssetDefinitionHome::Dataspace(dataspace) => Some(dataspace),
            AssetDefinitionHome::Domain(domain) => {
                catalog_dataspace_id(world.dataspace_catalog(), domain.dataspace().as_ref())
            }
        },
    )
}

/// Home that confines every balance of `definition`, if any.
///
/// A dataspace-restricted definition homed in a non-universal dataspace H keeps its balances
/// only in the `Dataspace(H)` bucket and moves them only on route H. Global definitions and
/// universal-homed restricted definitions are not confined.
///
/// # Errors
/// Propagates an invalid direct-home row or an incoherent definition home.
pub fn confined_home(
    world: &(impl WorldReadOnly + ?Sized),
    definition: &AssetDefinition,
) -> Result<Option<DataSpaceId>, ParseError> {
    if definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted {
        return Ok(None);
    }
    Ok(home_dataspace(world, definition)?.filter(|home| *home != DataSpaceId::UNIVERSAL))
}

fn catalog_dataspace_id(catalog: &DataSpaceCatalog, alias: &str) -> Option<DataSpaceId> {
    if alias.eq_ignore_ascii_case("universal") {
        return Some(DataSpaceId::UNIVERSAL);
    }
    catalog.by_alias(alias).map(|entry| entry.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_data_model::{
        Registrable,
        asset::AssetDefinitionId,
        nexus::{DataSpaceMetadata, LaneConfig},
    };
    use iroha_model_base::{domain::DomainId, topology::LaneId};
    use iroha_test_samples::ALICE_ID;
    use std::num::NonZeroU32;

    fn catalog() -> LaneCatalog {
        let lane = |id: u32, alias: &str, dataspace: u64, visibility| LaneConfig {
            id: LaneId::new(id),
            alias: alias.to_owned(),
            dataspace_id: DataSpaceId::new(dataspace),
            visibility,
            ..LaneConfig::default()
        };
        LaneCatalog::new(
            NonZeroU32::new(3).unwrap(),
            vec![
                lane(0, "core", 0, LaneVisibility::Public),
                lane(1, "bpng", 5, LaneVisibility::Public),
                lane(2, "cbsi", 6, LaneVisibility::Restricted),
            ],
        )
        .unwrap()
    }

    #[test]
    fn universal_is_public_and_unknown_dataspaces_are_restricted() {
        let catalog = catalog();
        assert!(!dataspace_is_restricted(&catalog, DataSpaceId::UNIVERSAL));
        assert!(!dataspace_is_restricted(&catalog, DataSpaceId::new(5)));
        assert!(dataspace_is_restricted(&catalog, DataSpaceId::new(6)));
        assert!(dataspace_is_restricted(&catalog, DataSpaceId::new(99)));
        assert!(!dataspace_is_restricted(
            &LaneCatalog::default(),
            DataSpaceId::UNIVERSAL
        ));
    }

    #[test]
    fn home_follows_row_then_domain_then_universal_and_confines_restricted_definitions() {
        let mut world = World::default();
        let dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(5),
                alias: "bpng".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: DataSpaceId::new(6),
                alias: "cbsi".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .unwrap();
        let id = |name: &str| {
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("homes", "universal").unwrap(),
                name.parse().unwrap(),
            )
        };
        let build = |name: &str, policy, domain: Option<DomainId>| {
            AssetDefinition::numeric(id(name), name, policy, domain).build(&ALICE_ID)
        };
        let global = build("xor", AssetBalancePolicy::Global, None);
        let domain_kina = build(
            "kina",
            AssetBalancePolicy::DataspaceRestricted,
            Some(DomainId::try_new("cash", "bpng").unwrap()),
        );
        let universal_points = build(
            "points",
            AssetBalancePolicy::DataspaceRestricted,
            Some(DomainId::try_new("cash", "universal").unwrap()),
        );
        let unknown = build(
            "lost",
            AssetBalancePolicy::DataspaceRestricted,
            Some(DomainId::try_new("cash", "nowhere").unwrap()),
        );
        let direct = build("sbd", AssetBalancePolicy::DataspaceRestricted, None);
        world
            .insert_direct_asset_definition_with_assets_for_testing(
                direct.clone(),
                DataSpaceId::new(6),
                [],
            )
            .unwrap();
        let state = State::new_with_pre_genesis_nexus_for_testing(
            world,
            iroha_config::parameters::actual::Nexus {
                dataspace_catalog,
                lane_catalog: catalog(),
                ..Default::default()
            },
            LiveQueryStore::start_test(),
        );
        let view = state.world_view();
        assert_eq!(
            home_dataspace(&view, &global).unwrap(),
            Some(DataSpaceId::UNIVERSAL)
        );
        assert_eq!(confined_home(&view, &global).unwrap(), None);
        assert_eq!(
            home_dataspace(&view, &domain_kina).unwrap(),
            Some(DataSpaceId::new(5))
        );
        assert_eq!(
            confined_home(&view, &domain_kina).unwrap(),
            Some(DataSpaceId::new(5))
        );
        assert_eq!(
            home_dataspace(&view, &universal_points).unwrap(),
            Some(DataSpaceId::UNIVERSAL)
        );
        assert_eq!(confined_home(&view, &universal_points).unwrap(), None);
        assert_eq!(home_dataspace(&view, &unknown).unwrap(), None);
        assert_eq!(
            home_dataspace(&view, &direct).unwrap(),
            Some(DataSpaceId::new(6))
        );
        assert_eq!(
            confined_home(&view, &direct).unwrap(),
            Some(DataSpaceId::new(6))
        );
        // A restricted domainless definition without its row has no coherent home.
        let homeless = build("homeless", AssetBalancePolicy::DataspaceRestricted, None);
        assert!(home_dataspace(&view, &homeless).is_err());
    }
}
