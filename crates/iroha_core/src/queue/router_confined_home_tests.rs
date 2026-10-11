// Phase A home confinement: a restricted definition homed in a non-universal dataspace H
// routes balance operations only to H and refuses an explicit universal or foreign bucket.
#[test]
fn direct_homed_kina_mint_with_explicit_universal_scope_is_refused() {
    let (alice_id, alice_keypair) = gen_account_in("wonderland");
    let bpng = DataSpaceId::new(5);
    let dataspace_catalog = dataspace_catalog(&[(bpng, "bpng")]);
    let lane_catalog = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(5), bpng),
    ]);
    let router = default_router(dataspace_catalog.clone(), lane_catalog.clone());
    let kina = AssetDefinitionId::derive_from_components(
        DomainId::try_new("cash", "universal").expect("identity seed"),
        "kina".parse().expect("asset definition name"),
    );
    let mut world = crate::state::World::default();
    world
        .insert_direct_asset_definition_with_assets_for_testing(
            AssetDefinition::numeric(
                kina.clone(),
                "Kina".to_owned(),
                AssetBalancePolicy::DataspaceRestricted,
                None,
            )
            .build(&alice_id),
            bpng,
            [],
        )
        .expect("direct-home fixture");
    let state = crate::state::State::new_with_nexus_for_testing(
        world,
        iroha_config::parameters::actual::Nexus {
            dataspace_catalog,
            lane_catalog,
            ..Default::default()
        },
        crate::query::store::LiveQueryStore::start_test(),
    );
    let mint = |scope| {
        sample_transaction(
            &alice_id,
            alice_keypair.private_key(),
            vec![InstructionBox::from(Mint::asset_quantity(
                1_u32,
                AssetId::with_scope(kina.clone(), alice_id.clone(), scope),
            ))],
        )
    };
    let view = state.view();
    for scope in [
        AssetBalanceScope::Dataspace(DataSpaceId::UNIVERSAL),
        AssetBalanceScope::Dataspace(DataSpaceId::new(9)),
    ] {
        assert!(
            matches!(
                router.try_route_plan_with_view(&mint(scope), &view),
                Err(RoutingResolveError::OrdinaryRouteUnavailable { .. })
            ),
            "{scope:?}"
        );
    }
    for scope in [AssetBalanceScope::Dataspace(bpng), AssetBalanceScope::Global] {
        assert_eq!(
            router
                .try_route_plan_with_view(&mint(scope), &view)
                .expect("home bucket routes to the home lane"),
            RoutingPlan::single(RoutingDecision::new(LaneId::new(5), bpng)),
            "{scope:?}"
        );
    }
}
