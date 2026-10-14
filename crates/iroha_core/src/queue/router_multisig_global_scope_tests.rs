// Regression coverage for scoped multisig accounts proposing global balance writes.

#[test]
fn multisig_global_balance_route_does_not_inherit_account_scope() {
    let (authority, keypair) = gen_account_in("wonderland");
    let (multisig, _) = gen_account_in("wonderland");
    let (recipient, _) = gen_account_in("wonderland");
    let dataspace = DataSpaceId::new(10);
    let spaces = dataspace_catalog(&[(dataspace, "paynet")]);
    let lanes = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(2), dataspace),
    ]);
    let domain = DomainId::try_new("cash", "paynet").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "pkr".parse().unwrap());
    let mut state = state_with_asset_definitions(
        vec![
            AssetDefinition::numeric(
                definition.clone(),
                "pkr".to_owned(),
                AssetBalancePolicy::Global,
                Some(domain),
            )
            .build(&authority),
        ],
        spaces.clone(),
        lanes.clone(),
    );
    bind_asset_definition_alias(&mut state, &definition, "pkr#paynet");
    scope_account_to_dataspace(&mut state, &multisig, dataspace);
    scope_account_to_dataspace(&mut state, &recipient, dataspace);
    let instructions = vec![InstructionBox::from(
        iroha_data_model::isi::Transfer::asset_quantity(
            AssetId::of(definition, multisig.clone()),
            1_u32,
            recipient,
        ),
    )];
    let hash = HashOf::new(&instructions);
    let proposal_id = test_id(&multisig, &hash);
    let propose = InstructionBox::from(MultisigPropose::new(
        multisig.clone(),
        test_nonce(&hash),
        instructions.clone(),
        None,
    ));
    state.world.smart_contract_state_mut_for_testing().insert(
        multisig_proposal_state_key(&multisig, &proposal_id),
        encoded_multisig_proposal_state(&MultisigProposalState {
            network_id: super::super::queue_test_network_id(),
            multisig_account_id: multisig.clone(),
            proposal_nonce: test_nonce(&hash),
            proposal_id,
            instructions_hash: hash,
            transaction_ttl_ms: None,
            instructions: instructions.clone(),
            proposed_at_ms: 1,
            expires_at_ms: 10_000,
            approvals: BTreeSet::new(),
        }),
    );
    let approve = InstructionBox::from(MultisigApprove::new(multisig, proposal_id, hash));
    let router = ConfigLaneRouter::new(default_routing_policy(), spaces, lanes);
    for body in [
        instructions,
        vec![propose.clone()],
        vec![approve.clone()],
        vec![propose, approve],
    ] {
        let tx = sample_transaction(&authority, keypair.private_key(), body);
        assert_eq!(
            router
                .try_route_plan_with_state(&tx, &state)
                .expect("the global balance write must route successfully"),
            RoutingPlan::single(RoutingDecision::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL)),
            "a global balance write must retain its single universal route through multisig",
        );
    }
}

#[test]
fn multisig_unscoped_payload_retains_account_scope() {
    let (authority, keypair) = gen_account_in("wonderland");
    let (multisig, _) = gen_account_in("wonderland");
    let dataspace = DataSpaceId::new(10);
    let spaces = dataspace_catalog(&[(dataspace, "paynet")]);
    let lanes = catalog_with_lane_dataspaces(&[
        (LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        (LaneId::new(2), dataspace),
    ]);
    let mut state = state_with_asset_definitions(Vec::new(), spaces, lanes);
    scope_account_to_dataspace(&mut state, &multisig, dataspace);
    let instructions = vec![InstructionBox::from(iroha_data_model::isi::Log::new(
        iroha_data_model::Level::INFO,
        "scoped multisig".to_owned(),
    ))];
    let tx = sample_transaction(
        &authority,
        keypair.private_key(),
        vec![
            MultisigPropose::new(
                multisig,
                test_nonce(&HashOf::new(&instructions)),
                instructions,
                None,
            )
            .into(),
        ],
    );
    let view = state.view();
    assert_eq!(
        native_amx_participant_dataspaces_with_world_at(
            &tx,
            &view.nexus().dataspace_catalog,
            view.world(),
            None,
        )
        .expect("the unscoped multisig payload must resolve its participants"),
        vec![dataspace],
        "a payload without a concrete target still inherits the multisig account scope",
    );
}
