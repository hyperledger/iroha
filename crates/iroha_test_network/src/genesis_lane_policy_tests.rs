// Native private-lane authority and custom genesis policy binding.
// A physical catalog cannot activate a native lane for a genesis input. The signed
// policy creates the lane for subsequent blocks; genesis bootstrap stays universal.

fn custom_npos_genesis_builder(include_private_input: bool) -> NetworkBuilder {
    init_instruction_registry();
    let mut npos = SumeragiNposParameters::default();
    npos.epoch_seed = CryptoHash::new(chain_id().into_inner().as_bytes()).into();
    npos.max_validators = 4;
    NetworkBuilder::new()
        .with_peers(4)
        .with_npos_consensus()
        .without_npos_genesis_bootstrap()
        .with_genesis_block(move |topology, topology_entries| {
            let domain_id = DomainId::try_new("deferred_genesis", "universal")
                .expect("deferred-genesis domain id");
            let asset_definition_id = AssetDefinitionId::derive_from_components(
                domain_id.clone(),
                "private_credit".parse().expect("asset name"),
            );
            let scoped_asset_id = AssetId::with_scope(
                asset_definition_id.clone(),
                ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(DataSpaceId::new(1)),
            );
            let mut post_topology = vec![vec![
                Register::domain(Domain::new(domain_id.clone())).into(),
                Register::asset_definition(AssetDefinition::numeric(
                    asset_definition_id,
                    "deferred private credit".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain_id),
                ))
                .into(),
            ]];
            if include_private_input {
                post_topology.push(vec![Mint::asset_quantity(1_u32, scoped_asset_id).into()]);
            }
            use iroha_data_model::sumeragi_lanes::{
                SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy,
            };
            let policy = SumeragiLanePolicy {
                da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
                anchor_freshness: 64,
                max_merge_blocks: 16,
                stall_window: 10_000,
                lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
                fixed: vec![SumeragiFixedLane {
                    lane: LaneId::new(1),
                    dataspace: DataSpaceId::new(1),
                    committee: topology_entries
                        .iter()
                        .map(|entry| SumeragiLaneMember {
                            peer: entry.peer.clone(),
                            pop: entry
                                .pop_bytes()
                                .expect("well-formed lane PoP")
                                .expect("lane member PoP"),
                        })
                        .collect(),
                }],
                routes: Vec::new(),
                autoscale: None,
            };
            post_topology.push(vec![
                SetParameter::new(Parameter::Custom(policy.into_custom_parameter())).into(),
            ]);
            unexecuted_genesis_factory_with_post_topology(
                Vec::new(),
                post_topology,
                topology,
                topology_entries,
            )
        })
        .with_genesis_instruction(InstructionBox::from(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        ))))
        .with_config_layer(|layer| {
            let mut universal = Table::new();
            universal.insert("alias".into(), Value::String("universal".to_owned()));
            universal.insert("id".into(), Value::Integer(0));
            universal.insert("fault_tolerance".into(), Value::Integer(1));
            let mut private = Table::new();
            private.insert("alias".into(), Value::String("private-1".to_owned()));
            private.insert("id".into(), Value::Integer(1));
            private.insert(
                "manifest_hash".into(),
                Value::String(format!("01{}", "00".repeat(31))),
            );
            private.insert("fault_tolerance".into(), Value::Integer(1));
            let mut lane0 = Table::new();
            lane0.insert("index".into(), Value::Integer(0));
            lane0.insert("alias".into(), Value::String("global".to_owned()));
            lane0.insert("dataspace".into(), Value::String("universal".to_owned()));
            lane0.insert("visibility".into(), Value::String("public".to_owned()));
            lane0.insert("metadata".into(), Value::Table(Table::new()));
            let mut lane1 = Table::new();
            lane1.insert("index".into(), Value::Integer(1));
            lane1.insert("alias".into(), Value::String("private".to_owned()));
            lane1.insert("dataspace".into(), Value::String("private-1".to_owned()));
            lane1.insert("visibility".into(), Value::String("restricted".to_owned()));
            lane1.insert("metadata".into(), Value::Table(Table::new()));
            layer
                .write(["nexus", "lane_count"], 2_i64)
                .write(
                    ["nexus", "dataspace_catalog"],
                    Value::Array(vec![Value::Table(universal), Value::Table(private)]),
                )
                .write(
                    ["nexus", "lane_catalog"],
                    Value::Array(vec![Value::Table(lane0), Value::Table(lane1)]),
                )
                .write(["nexus", "staking", "max_validators"], 4_i64);
        })
}

#[test]
fn with_genesis_block_respects_npos_consensus_mode() {
    let network = build_with_isolated_permit(custom_npos_genesis_builder(false));
    let profile = network.consensus_bootstrap_profile();
    assert_eq!(
        profile.mode_tag, NPOS_TAG,
        "custom genesis should preserve requested NPoS consensus mode",
    );
    let produced = network.genesis();
    assert!(
        produced
            .0
            .output_results()
            .all(|result| result.as_ref().is_ok()),
        "custom registry and lane-policy bootstrap must pre-execute under the final catalog"
    );
    let config_layers: Vec<Table> = network.config_layers().map(Cow::into_owned).collect();
    let peer = network.peers().first().expect("network should have peers");
    let actual = resolve_actual_config(peer, &config_layers)
        .expect("deferred-genesis final config should resolve");
    let expected_policies = iroha_core::da::proof_policy_bundle(&actual.nexus.lane_config);
    assert_eq!(
        produced.0.da_proof_policies(),
        Some(&expected_policies),
        "custom genesis must bind the builder-resolved multi-lane DA policy"
    );
    assert_eq!(
        produced
            .0
            .header()
            .confidential_features()
            .and_then(|digest| digest.zk_policy_hash),
        Some(iroha_core::state::default_genesis_confidential_policy_hash()),
        "custom genesis must bind the builder-resolved confidential policy"
    );
    assert_exactly_one_consensus_handshake(&produced, &consensus_handshake_parameter(&profile));
    let metadata = consensus_handshake_metadata(&produced)
        .expect("custom genesis should include consensus handshake metadata");
    assert_eq!(
        metadata.mode,
        SumeragiConsensusMode::Npos,
        "custom genesis handshake metadata should advertise NPoS mode",
    );
    use iroha_data_model::sumeragi_lanes::SumeragiLanePolicy;
    let parameters = consensus_parameters_from_genesis(&produced);
    let signed_policy = parameters
        .custom()
        .get(&SumeragiLanePolicy::parameter_id())
        .and_then(SumeragiLanePolicy::from_custom_parameter)
        .expect("signed native lane policy")
        .expect("canonical native lane policy");
    assert_eq!(signed_policy.fixed.len(), 1);
    assert_eq!(signed_policy.fixed[0].lane, LaneId::new(1));
    assert_eq!(signed_policy.fixed[0].dataspace, DataSpaceId::new(1));
    assert_eq!(
        signed_policy.fixed[0]
            .committee
            .iter()
            .map(|member| member.peer.clone())
            .collect::<BTreeSet<_>>(),
        network.validators().iter().map(NetworkPeer::id).collect()
    );
}

#[test]
fn with_genesis_block_rejects_private_inputs_without_an_active_native_lane() {
    let panic = std::panic::catch_unwind(|| {
        let _ = build_with_isolated_permit(custom_npos_genesis_builder(true));
    })
    .expect_err("a signed policy cannot retroactively grant an active native genesis route");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("native route rejection diagnostic");
    assert!(
        message.contains("Network source has no exact active native lane"),
        "{message}"
    );
}
