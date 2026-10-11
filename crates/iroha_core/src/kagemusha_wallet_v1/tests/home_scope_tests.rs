//! A wallet registration's balance scope must be exactly its asset definition's balance home.

use crate::{
    kagemusha_wallet_v1::wsv::registration_scope_matches_home,
    query::store::LiveQueryStore,
    state::{State, World},
};
use iroha_data_model::{
    Registrable,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId},
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
};
use iroha_model_base::{
    domain::DomainId,
    topology::{DataSpaceId, LaneId},
};
use iroha_test_samples::ALICE_ID;

fn definition(name: &str, policy: AssetBalancePolicy, domain: Option<&str>) -> AssetDefinition {
    let id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wallet", "universal").unwrap(),
        name.parse().unwrap(),
    );
    AssetDefinition::numeric(
        id,
        name,
        policy,
        domain.map(|domain| {
            let (name, dataspace) = domain.split_once('.').unwrap();
            DomainId::try_new(name, dataspace).unwrap()
        }),
    )
    .build(&ALICE_ID)
}

#[test]
fn registration_scope_must_equal_the_definition_home() {
    let bpng = DataSpaceId::new(5);
    let cbsi = DataSpaceId::new(6);
    let sbd = definition("sbd", AssetBalancePolicy::DataspaceRestricted, None);
    let mut world = World::default();
    world
        .insert_direct_asset_definition_with_assets_for_testing(sbd.clone(), cbsi, [])
        .unwrap();
    let state = State::new_with_pre_genesis_nexus_for_testing(
        world,
        iroha_config::parameters::actual::Nexus {
            dataspace_catalog: DataSpaceCatalog::new(vec![
                DataSpaceMetadata::default(),
                DataSpaceMetadata {
                    id: bpng,
                    alias: "bpng".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
                DataSpaceMetadata {
                    id: cbsi,
                    alias: "cbsi".to_owned(),
                    description: None,
                    fault_tolerance: 1,
                },
            ])
            .unwrap(),
            lane_catalog: LaneCatalog::new(
                core::num::NonZeroU32::new(3).unwrap(),
                [
                    (0, "core", DataSpaceId::UNIVERSAL, LaneVisibility::Public),
                    (1, "bpng", bpng, LaneVisibility::Public),
                    (2, "cbsi", cbsi, LaneVisibility::Restricted),
                ]
                .into_iter()
                .map(|(id, alias, dataspace_id, visibility)| LaneConfig {
                    id: LaneId::new(id),
                    alias: alias.to_owned(),
                    dataspace_id,
                    visibility,
                    ..LaneConfig::default()
                })
                .collect(),
            )
            .unwrap(),
            ..Default::default()
        },
        LiveQueryStore::start_test(),
    );
    let view = state.world_view();
    let kina = definition(
        "kina",
        AssetBalancePolicy::DataspaceRestricted,
        Some("cash.bpng"),
    );
    let points = definition(
        "points",
        AssetBalancePolicy::DataspaceRestricted,
        Some("cash.universal"),
    );
    let xor = definition("xor", AssetBalancePolicy::Global, None);
    let dataspace = AssetBalanceScope::Dataspace;
    for (definition, scope, accepted) in [
        // Directly homed restricted definition: only its home bucket.
        (&sbd, dataspace(cbsi), true),
        (&sbd, dataspace(bpng), false),
        (&sbd, dataspace(DataSpaceId::UNIVERSAL), false),
        (&sbd, AssetBalanceScope::Global, false),
        // Domain-homed restricted definition (Kina in bpng) is unaffected.
        (&kina, dataspace(bpng), true),
        (&kina, dataspace(cbsi), false),
        // A universal-homed restricted definition has no single wallet home.
        (&points, dataspace(bpng), false),
        (&points, dataspace(DataSpaceId::UNIVERSAL), false),
        // Global definitions register the global scope only.
        (&xor, AssetBalanceScope::Global, true),
        (&xor, dataspace(bpng), false),
    ] {
        assert_eq!(
            registration_scope_matches_home(&view, definition, scope),
            accepted,
            "{} with {scope:?}",
            definition.name()
        );
    }
}
