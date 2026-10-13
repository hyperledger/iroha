// Exact pool batches must retain the same coordinator through ingress and State admission.
fn private_pool_route_fixture_instruction(dataspace: u64) -> InstructionBox {
    ActivatePrivateSettlementPoolV1 {
        version: AtomicPrivateSettlementV1::VERSION,
        route: PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(dataspace),
            lane_id: LaneId::new(u32::try_from(dataspace).expect("fixture value fits u32")),
            lane_incarnation: Hash::new(dataspace.to_le_bytes()),
        },
        pool_id: iroha_data_model::privacy::PrivacyPoolIdV1::new(
            [u8::try_from(dataspace).expect("fixture value fits u8"); 32],
        ),
        asset_binding_commitment: Hash::new(b"private-pool-route-asset"),
        audit_policy_digest: Hash::new(b"private-pool-route-policy"),
        audit_key_epoch: 1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: 10,
            retirement_height: None,
        },
        governance_digest: Hash::new(b"private-pool-route-governance"),
        initial_commitments: vec![iroha_data_model::privacy::PrivacyCommitmentV1::new(
            [0x91; 32],
        )],
    }
    .into()
}

fn private_pool_route_fixture_router() -> ConfigLaneRouter {
    default_router(
        dataspace_catalog(&[
            (DataSpaceId::new(1), "poolone"),
            (DataSpaceId::new(2), "pooltwo"),
            (DataSpaceId::new(3), "poolthree"),
            (DataSpaceId::new(4), "poolfour"),
        ]),
        catalog_with_lane_dataspaces(
            &(0..=4)
                .map(|i| (LaneId::new(i), DataSpaceId::new(u64::from(i))))
                .collect::<Vec<_>>(),
        ),
    )
}

#[test]
fn private_pool_batch_executable_has_the_same_global_coordinator() {
    let (sponsor, signer) = gen_account_in("pool-route-batch");
    let router = private_pool_route_fixture_router();
    let mut state = blank_state();
    install_router_nexus(&mut state, &router);
    let tx = sample_executable_transaction(
        &sponsor,
        signer.private_key(),
        Executable::Batch(
            (1..=3)
                .map(|id| {
                    ExecutableBatchItem::Instruction(private_pool_route_fixture_instruction(id))
                })
                .collect(),
        ),
    );
    let expected = router.try_route_plan_with_view(&tx, &state.view()).unwrap();
    assert_eq!(
        expected.coordinator_route(),
        RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)
    );
    assert_eq!(expected.legs().len(), 4);
    assert_eq!(
        router.try_route_plan_without_state(&tx).unwrap(),
        Some(expected)
    );
}

#[test]
fn private_pool_single_dataspace_stays_local_with_repeated_pool_instructions() {
    let (sponsor, signer) = gen_account_in("pool-route-local");
    let router = private_pool_route_fixture_router();
    let mut state = blank_state();
    install_router_nexus(&mut state, &router);
    for count in [1, 2] {
        let tx = sample_transaction(
            &sponsor,
            signer.private_key(),
            (0..count)
                .map(|_| private_pool_route_fixture_instruction(2))
                .collect(),
        );
        let expected =
            RoutingPlan::single(RoutingDecision::new(LaneId::new(2), DataSpaceId::new(2)));
        assert_eq!(
            router.try_route_plan_without_state(&tx).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            router.try_route_plan_with_view(&tx, &state.view()).unwrap(),
            expected
        );
    }
}
