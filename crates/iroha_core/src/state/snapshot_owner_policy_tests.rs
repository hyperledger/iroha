state_test! { sync startup_sumeragi_key_policy_matches_canonical_state_without_mutation
    let mut state = blank_test_state();
    let mut canonical = SumeragiPolicyConfig::from(
        &iroha_data_model::parameter::system::SumeragiParameters::default(),
    );
    let before = norito::json::to_value(&state).expect("canonical default State");
    state.validate_sumeragi_key_policy(canonical.clone()).expect("default policy matches");
    assert_eq!(norito::json::to_value(&state).expect("State after validation"), before);
    canonical.key_activation_lead_blocks = 5;
    canonical.key_overlap_grace_blocks = 13;
    canonical.key_expiry_grace_blocks = 2;
    let _ = canonical.key_allowed_algorithms.insert(Algorithm::Ed25519);
    state.set_sumeragi_parameters(canonical.clone());
    let before = norito::json::to_value(&state).expect("canonical nondefault fixture State");
    state.validate_sumeragi_key_policy(canonical.clone()).expect("retained nondefault policy matches");
    assert_eq!(norito::json::to_value(&state).expect("State after validation"), before);
    let hash = crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot");
    {
        let mut parameters = state.world.parameters.block();
        let mut consensus = parameters.sumeragi().clone();
        consensus.key_allowed_algorithms.reverse();
        parameters.set_sumeragi(consensus);
        parameters.commit();
    }
    let before = norito::json::to_value(&state).expect("equivalent algorithm order");
    state.validate_sumeragi_key_policy(canonical).expect("algorithm order is not policy");
    assert_eq!(norito::json::to_value(&state).expect("State after validation"), before);
    assert_eq!(crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"), hash);
}

state_test! { sync startup_sumeragi_key_policy_rejects_each_mismatch_without_mutation
    let state = blank_test_state();
    let canonical = SumeragiPolicyConfig::from(
        &iroha_data_model::parameter::system::SumeragiParameters::default(),
    );
    let before = norito::json::to_value(&state).expect("canonical State");
    for field in [
        "key_activation_lead_blocks", "key_overlap_grace_blocks",
        "key_expiry_grace_blocks", "key_allowed_algorithms",
    ] {
        let mut configured = canonical.clone();
        match field {
            "key_activation_lead_blocks" => configured.key_activation_lead_blocks += 1,
            "key_overlap_grace_blocks" => configured.key_overlap_grace_blocks += 1,
            "key_expiry_grace_blocks" => configured.key_expiry_grace_blocks += 1,
            "key_allowed_algorithms" => {
                let _ = configured.key_allowed_algorithms.insert(Algorithm::Ed25519);
            }
            _ => unreachable!("fixed policy field list"),
        }
        assert_eq!(state.validate_sumeragi_key_policy(configured), Err(field));
        assert_eq!(norito::json::to_value(&state).expect("State after rejection"), before);
    }
}

// This validates an unauthenticated typed component and never creates State
// history. Native ownership must come from original signed/certified replay.
fn snapshot_runtime_component(
    snapshot: &norito::json::Value,
    state: &State,
    configured: Option<&iroha_config::parameters::actual::Nexus>,
) -> Result<
    (
        Cell<SnapshotNexusRuntime>,
        iroha_config::parameters::actual::Nexus,
    ),
    super::deserialize::StateRestoreError,
> {
    let value = snapshot
        .as_object()
        .and_then(|value| value.get("nexus_runtime"))
        .ok_or_else(|| norito::json::Error::missing_field("nexus_runtime"))?
        .clone();
    let hashes = state
        .block_hashes
        .view()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    super::deserialize::decode_nexus_runtime_component_for_testing(
        value,
        &hashes,
        &state.world,
        &state.ivm_execution_budget(),
        Hash::prehashed(
            state
                .lane_manifests
                .read()
                .baseline_consensus_policy_digest(),
        ),
        configured,
    )
}

fn snapshot_owner_policy_fixture() -> (
    tempfile::TempDir,
    Box<State>,
    iroha_config::parameters::actual::Nexus,
) {
    snapshot_owner_policy_fixture_with_stored_history(false)
}

fn snapshot_owner_policy_fixture_with_stored_history(
    store_history: bool,
) -> (
    tempfile::TempDir,
    Box<State>,
    iroha_config::parameters::actual::Nexus,
) {
    let directory = tempfile::tempdir().expect("owner policy fixture directory");
    let dataspace = DataSpaceId::new(9);
    let catalog = LaneCatalog::new(
        nonzero!(5_u32),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(4),
                alias: "public-staking-sibling".to_owned(),
                dataspace_id: dataspace,
                ..LaneConfig::default()
            },
            LaneConfig {
                id: LaneId::new(3),
                alias: "public-staking-owner".to_owned(),
                dataspace_id: dataspace,
                ..LaneConfig::default()
            },
        ],
    )
    .expect("shared nondefault dataspace catalog");
    let mut configured = startup_nexus_for_catalog(catalog.clone());
    configured.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: dataspace,
            alias: "shared-staking".to_owned(),
            description: Some("snapshot ownership fixture".to_owned()),
            fault_tolerance: 2,
        },
    ])
    .expect("nondefault dataspace policy");
    configured.configured_dataspace_catalog = configured.dataspace_catalog.clone();
    configured.staking.max_validators = nonzero!(7_u32);
    configured.autoscale.enabled = false;
    // Reserve a valid range above the static lanes; disabled autoscaling still validates its bounds.
    configured.autoscale.min_lane_id = nonzero!(5_u32);
    configured.autoscale.max_lane_id_exclusive = nonzero!(8_u32);
    let (kura, mut state) =
        authenticated_startup_state_for_testing(directory.path().join("kura"), &catalog);
    state
        .set_nexus_from_config(configured.clone())
        .expect("install configured owner policy before genesis");
    let configured_predecessor = state.canonical_runtime.view().get().clone();
    let (validator, keypair) = bls_account_in("snapshot-owner");
    let npos = SumeragiNposParameters::default();
    assert_eq!(
        npos.xor_asset_definition_id.to_string(),
        configured.fees.fee_asset_id,
        "fixture staking and fee policies select the same canonical network XOR"
    );
    let custody_asset = AssetId::new(npos.xor_asset_definition_id.clone(), validator.clone());
    {
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut transaction = block.transaction();
        Register::account(Account::new(validator.clone()))
            .execute(&validator, &mut transaction)
            .expect("register staking validator account");
        // Custody identity comes from committed genesis policy. Install that
        // exact network XOR policy through the same ISI path as real genesis.
        SetParameter::new(iroha_data_model::parameter::Parameter::Custom(
            npos.into_custom_parameter(),
        ))
        .execute(&validator, &mut transaction)
        .expect("install the genesis network XOR and staking policy");
        Register::asset_definition(AssetDefinition::new(
            custody_asset.definition().clone(),
            "Snapshot staking reserve",
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&validator, &mut transaction)
        .expect("register staking custody definition");
        Mint::asset_quantity(Quantity::from(1_000_000_u64), custody_asset.clone())
            .execute(&validator, &mut transaction)
            .expect("fund staking custody");
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("publish staking custody backing");
    }
    insert_active_public_lane_validator_for_test(
        &state,
        LaneId::new(3),
        &validator,
        &keypair,
        1_000_000,
    );
    {
        let mut world = state.world.block();
        world
            .public_lane_validators
            .get_mut(&(LaneId::new(3), validator.clone()))
            .expect("fixture validator exists")
            .activation_height = 1;
        world.public_lane_stake_custody.insert(
            (LaneId::new(3), validator.clone()),
            (custody_asset.clone(), Quantity::from(1_000_000_u64)),
        );
        world
            .public_lane_stake_reserves
            .insert(custody_asset, Quantity::from(1_000_000_u64));
        world.commit();
    }
    // The fixture models a committed staking owner at both snapshot cuts.
    state.world.block().commit();
    if store_history {
        // Replacement rebuilds DA indexes from the exact canonical Kura prefix.
        // Store checked empty, result-bearing bodies for this structural history;
        // these signatures authenticate their bodies, not execution or finality.
        let keypair = crate::state::checked_keypair();
        let policy = crate::da::proof_policy_bundle(&state.nexus_snapshot().lane_config);
        let mut previous = None;
        for height in 1_u64..=5 {
            let mut header = BlockHeader::new(
                NonZeroU64::new(height).unwrap(),
                previous,
                None,
                height * 100,
                0,
            );
            header.set_confidential_features(Some(
                iroha_data_model::confidential::DEFAULT_CONFIDENTIAL_FEATURE_DIGEST,
            ));
            let mut builder = iroha_data_model::block::builder::BlockBuilder::new(header);
            builder.set_da_proof_policies(Some(policy.clone()));
            let mut carrier = builder
                .try_build_with_signature(0, keypair.private_key())
                .expect("structural predecessor signs its exact proposal body");
            carrier
                .set_execution_outputs(
                    Vec::new(),
                    0,
                    BTreeMap::new(),
                    Vec::new(),
                    AxtPolicySnapshot::default(),
                    Default::default(),
                    &crate::execution_output_test_support::structural_output_limits(),
                )
                .expect("checked empty typed output collection");
            carrier
                .validate_proposal_commitments()
                .expect("complete canonical proposal");
            carrier
                .validate_execution_result_structure()
                .expect("complete canonical output structure");
            carrier
                .validate_output_merkle_cache()
                .expect("complete canonical output caches");
            previous = Some(carrier.hash());
            kura.store_block(crate::block::reserve_block_for_tests().initialize(carrier))
                .expect("persist actual predecessor body");
        }
    }
    seed_committed_height_for_state_test(&state, 5);
    // The existing fixture prepopulates World and carrier-hash metadata; it does
    // not execute five carriers. Retain the exact pre-setup runtime policy and
    // lineage, then let the explicit metadata helper supply both sample cuts.
    let mut runtime = state.canonical_runtime.block();
    *runtime.get_mut() = configured_predecessor;
    runtime.commit();
    seed_autoscale_sample_history_for_snapshot_test(&state);
    state
        .world
        .validate_numeric_asset_invariants()
        .expect("snapshot fixture asset references and quantities are valid");
    state
        .world
        .validate_quantity_ledger_invariants()
        .expect("snapshot fixture staking tenure and quantity ledgers are valid");
    let value = norito::json::to_value(&state).expect("serialize live staking snapshot");
    let expected_runtime = value
        .as_object()
        .expect("State object")
        .get("nexus_runtime")
        .expect("snapshot runtime")
        .clone();
    assert!(matches!(
        deserialize_state_snapshot_value_with_kura(value.clone(), Arc::clone(&kura)),
        Err(super::deserialize::StateRestoreError::NativeExecutionReplayRequired)
    ));
    let (component, projected_nexus) =
        snapshot_runtime_component(&value, &state, Some(&configured))
            .expect("validate original structural owner and both runtime cuts");
    assert_eq!(
        norito::json::to_value(&component).expect("reserialize typed runtime component"),
        expected_runtime,
        "component decoding must not normalize the retained owner policy"
    );
    assert_eq!(
        SnapshotNexusOwnerPolicy::from_nexus(&projected_nexus),
        SnapshotNexusOwnerPolicy::from_nexus(&configured)
    );
    // Retain the original structural State; decoded component bytes do not
    // establish execution/finality or set the restored-native authority bit.
    (directory, Box::new(state), configured)
}

state_test! { sync snapshot_owner_policy_survives_startup_with_live_nondefault_staking
    let (_directory, mut restored, configured) = snapshot_owner_policy_fixture();
    let owner = LaneId::new(3);
    let before_policy = SnapshotNexusOwnerPolicy::from_nexus(&restored.nexus_snapshot());
    assert_eq!(before_policy, SnapshotNexusOwnerPolicy::from_nexus(&configured));
    assert_eq!(
        nexus_staking_authority_lane_at_height(owner, &restored.nexus_snapshot(), 5),
        Some(owner),
        "the loaded snapshot already identifies the nondefault dataspace owner"
    );
    let before = norito::json::to_json(&restored).expect("capture restored custody");
    assert!(!restored.nexus_runtime_restored_from_snapshot());
    assert!(matches!(
        restored.prepare_restored_configured_primary_geometry_anchor(&configured.configured_lane_catalog),
        Err(LaneLifecycleError::ConfiguredCatalogBaseline(message))
            if message.contains("requires a decoded Nexus runtime snapshot")
    ), "a structural component cannot manufacture trusted restored geometry");
    restored
        .restore_kura_lane_segments_from_nexus()
        .expect("restore snapshot-authenticated lane geometry");
    restored
        .set_nexus_from_config(configured.clone())
        .expect("same static policy must preserve live nondefault staking on restart");
    restored
        .set_nexus_from_config(configured)
        .expect("repeated same-policy installation is idempotent");
    assert_eq!(
        norito::json::to_json(&restored).expect("capture post-startup custody"),
        before,
        "startup must preserve the snapshot World, lineage and owner policy"
    );
}

state_test! { sync snapshot_runtime_catalog_restart_authenticates_full_configured_dataspace_baseline
    use iroha_data_model::nexus::{
        NexusRuntimeCatalogV1, RuntimeDataSpaceAdditionV1, dataspace_catalog_hash,
    };

    let (_directory, state, configured) = snapshot_owner_policy_fixture_with_stored_history(true);
    let baseline = configured.configured_dataspace_catalog.clone();
    assert!(baseline.entries().iter().any(|entry| entry.description.is_some()));
    let manifest_hash = [0x63; 32];
    let runtime = NexusRuntimeCatalogV1 {
        version: NexusRuntimeCatalogV1::VERSION,
        baseline_dataspaces_hash: dataspace_catalog_hash(&baseline),
        baseline_manifests_hash: Hash::prehashed(
            state.lane_manifests.read().baseline_consensus_policy_digest(),
        ),
        dataspaces: vec![RuntimeDataSpaceAdditionV1 {
            descriptor: DataSpaceMetadata {
                id: DataSpaceId::from_hash(&manifest_hash),
                alias: "paid-runtime-dataspace".to_owned(),
                description: Some("committed catalog description".to_owned()),
                fault_tolerance: 1,
            },
            manifest_hash,
        }],
        manifests: Vec::new(),
    };
    let effective = runtime_catalog_dataspaces(&baseline, Some(&runtime))
        .expect("valid baseline and committed addition");
    let mut current_nexus = configured.clone();
    current_nexus.dataspace_catalog = effective.clone();
    *state.nexus.write() = current_nexus.clone();
    let mut current_runtime = state.canonical_runtime.view().get().clone();
    current_runtime.owner_policy = SnapshotNexusOwnerPolicy::from_nexus(&current_nexus);
    state.canonical_runtime.replace_current_preserving_predecessor(current_runtime);
    {
        let mut world = state.world.block();
        world.parameters.get_mut().set_parameter(
            iroha_data_model::parameter::Parameter::Custom(
                runtime.into_custom_parameter().expect("valid protected catalog"),
            ),
        ).expect("valid fixture parameters");
        world.commit();
    }
    let snapshot = norito::json::to_json(&state).expect("serialize committed catalog snapshot");
    let value: norito::json::Value = norito::json::from_json(&snapshot).unwrap();
    assert!(matches!(
        deserialize_state_snapshot_value_with_kura(value.clone(), Arc::clone(&state.kura)),
        Err(super::deserialize::StateRestoreError::NativeExecutionReplayRequired)
    ));
    let (_, restored_nexus) = snapshot_runtime_component(&value, &state, Some(&configured))
        .expect("full configured baseline validates the retained runtime catalog component");
    assert_eq!(restored_nexus.configured_dataspace_catalog, baseline);
    assert_eq!(restored_nexus.dataspace_catalog, effective);

    let mut changed_config = configured;
    let mut entries = baseline.entries().to_vec();
    entries.last_mut().expect("configured dataspace").description =
        Some("different configured description".to_owned());
    changed_config.configured_dataspace_catalog =
        DataSpaceCatalog::new(entries).expect("same physical geometry, changed baseline bytes");
    let error = snapshot_runtime_component(&value, &state, Some(&changed_config))
        .err()
        .expect("changed full baseline must fail catalog authentication");
    assert!(error.to_string().contains("configured dataspace baseline differs"), "{error}");
    let error = snapshot_runtime_component(&value, &state, None)
        .err()
        .expect("catalog restore without full configured baseline must fail closed");
    assert!(error.to_string().contains("requires the complete configured dataspace baseline"), "{error}");
}

state_test! { sync snapshot_owner_policy_rejects_changed_owner_before_and_after_hydration
    let (_directory, mut restored, configured) = snapshot_owner_policy_fixture();
    for hydrated in [false, true] {
        if hydrated {
            restored
                .set_nexus_from_config(configured.clone())
                .expect("install unchanged policy between negative controls");
        }
        for change_owner in [false, true] {
            let before = norito::json::to_json(&restored).expect("capture prior State");
            let journal = restored.kura.lane_geometry_journal_state_for_test()
                .expect("capture prior durable geometry");
            let mut changed = configured.clone();
            if change_owner {
                // A new lower public sibling would replace the sole mutable
                // staking owner without moving its existing funded custody.
                let mut lanes = changed.lane_catalog.lanes().to_vec();
                lanes.push(LaneConfig {
                    id: LaneId::new(2),
                    alias: "replacement-staking-owner".to_owned(),
                    dataspace_id: DataSpaceId::new(9),
                    ..LaneConfig::default()
                });
                changed.lane_catalog = LaneCatalog::new(
                    changed.lane_catalog.lane_count(), lanes,
                ).expect("uniform public dataspace with a lower candidate owner");
                changed.lane_config = iroha_config::parameters::actual::LaneConfig::from_catalog(
                    &changed.lane_catalog,
                );
            } else {
                changed.staking.public_validator_mode =
                    iroha_config::parameters::actual::LaneValidatorMode::AdminManaged;
            }
            let result = if change_owner {
                // Prospective lifecycle additions use this same owner guard.
                // Configuration ingress cannot introduce a new catalog at a
                // non-genesis height, so exercise the custody rule directly.
                ensure_live_shared_dataspace_staking_owner_is_not_reset(
                    &restored.world.view(),
                    &restored.nexus_snapshot(),
                    &changed,
                    &BTreeSet::new(),
                    restored.block_hashes.view().len() as u64,
                )
            } else {
                restored.set_nexus_from_config(changed)
            };
            let error = result
                .expect_err("real owner change must fail both before and after initial hydration");
            assert!(matches!(error, LaneLifecycleError::UnsafeRetirement { lane, reason }
                if lane == LaneId::new(3)
                    && reason == LIVE_SHARED_DATASPACE_STAKING_OWNER_CHANGE_REASON));
            assert_eq!(norito::json::to_json(&restored).expect("unchanged State"), before);
            assert_eq!(restored.kura.lane_geometry_journal_state_for_test()
                .expect("unchanged durable geometry"), journal);
        }
    }
}

state_test! { sync snapshot_owner_policy_requires_complete_canonical_fields
    let (_directory, state, _) = snapshot_owner_policy_fixture();
    let snapshot = norito::json::to_value(&state).expect("canonical snapshot");
    let runtime = snapshot.as_object().expect("State object")
        .get("nexus_runtime").expect("runtime").as_object().expect("runtime object");
    let policy = runtime.get("blocks").expect("current runtime").as_object().expect("runtime record")
        .get("owner_policy").expect("required owner policy");
    let fields = policy.as_object().expect("owner policy object")
        .keys().cloned().collect::<Vec<_>>();
    assert_eq!(fields.len(), 9);
    for field in fields {
        let mut missing = snapshot.clone();
        let _ = missing.as_object_mut().expect("State object")
            .get_mut("nexus_runtime").expect("runtime").as_object_mut().expect("runtime object")
            .get_mut("blocks").expect("current runtime").as_object_mut().expect("runtime record")
            .get_mut("owner_policy").expect("policy").as_object_mut().expect("policy object")
            .remove(&field);
        assert!(snapshot_runtime_component(&missing, &state, None).is_err(),
            "missing owner policy field {field} must not select a default");
    }
    let mut absent = snapshot.clone();
    let _ = absent.as_object_mut().expect("State object")
        .get_mut("nexus_runtime").expect("runtime").as_object_mut().expect("runtime object")
            .get_mut("blocks").expect("current runtime").as_object_mut().expect("runtime record")
        .remove("owner_policy");
    assert!(snapshot_runtime_component(&absent, &state, None).is_err());
    for (field, invalid) in [
        ("max_validators", norito::json::Value::from(0_u64)),
        ("autoscale_min_lane_id", norito::json::Value::from(0_u64)),
        ("autoscale_max_lane_id_exclusive", norito::json::Value::from(4_u64)),
        ("autoscale_max_lane_id_exclusive", norito::json::Value::from(9_u64)),
        ("public_validator_mode", norito::json::from_json::<norito::json::Value>(
            r#"{"mode":"unknown-mode","value":null}"#,
        ).expect("well-formed envelope with an unknown staking mode")),
        ("routing_default_lane", norito::json::Value::from(1_u64)),
        ("routing_default_dataspace", norito::json::Value::from(9_u64)),
        ("dataspaces", norito::json::Value::Array(Vec::new())),
    ] {
        let mut changed = snapshot.clone();
        let _ = changed.as_object_mut().expect("State object")
            .get_mut("nexus_runtime").expect("runtime").as_object_mut().expect("runtime object")
            .get_mut("blocks").expect("current runtime").as_object_mut().expect("runtime record")
            .get_mut("owner_policy").expect("policy").as_object_mut().expect("policy object")
            .insert(field.to_owned(), invalid);
        assert!(snapshot_runtime_component(&changed, &state, None).is_err(),
            "malformed owner policy field {field} must fail");
    }
    let mut noncanonical = snapshot;
    let dataspaces = noncanonical.as_object_mut().expect("State object")
        .get_mut("nexus_runtime").expect("runtime").as_object_mut().expect("runtime object")
            .get_mut("blocks").expect("current runtime").as_object_mut().expect("runtime record")
        .get_mut("owner_policy").expect("policy").as_object_mut().expect("policy object")
        .get_mut("dataspaces").expect("dataspaces");
    let norito::json::Value::Array(entries) = dataspaces else { panic!("dataspace array"); };
    entries.reverse();
    assert!(snapshot_runtime_component(&noncanonical, &state, None).is_err());
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot");
    let mut descriptions = state.nexus_snapshot().dataspace_catalog.entries().to_vec();
    for entry in &mut descriptions {
        entry.description = Some("different local operator description".to_owned());
    }
    state.nexus.write().dataspace_catalog = DataSpaceCatalog::new(descriptions)
        .expect("description-only catalog update");
    assert_eq!(crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"), before,
        "operator-facing descriptions must not affect the canonical commitment");
    // Structural commitment sensitivity, not a live policy transition: mutate
    // the actual current record while retaining the exact predecessor.
    let mut changed_owner = state.canonical_runtime.view().get().clone();
    changed_owner.owner_policy.max_validators = 8;
    state.canonical_runtime.replace_current_preserving_predecessor(changed_owner);
    assert_ne!(crate::snapshot::canonical_state_snapshot_hash(&state).expect("stable valid fixture snapshot"), before,
        "the owner policy must be authenticated by the canonical snapshot commitment");
}

state_test! { sync snapshot_runtime_requires_exact_retained_predecessor_and_roundtrips_both_cuts
    let (_directory, state, _) = snapshot_owner_policy_fixture_with_stored_history(true);
    let current = state.canonical_runtime.view().get().clone();
    let predecessor = state.canonical_runtime.predecessor_view().get().clone()
        .expect("explicitly published runtime predecessor fixture");
    assert_eq!(current.autoscale_sample_history.last().unwrap().block_height, 5);
    assert_eq!(predecessor.autoscale_sample_history.last().unwrap().block_height, 4);
    let snapshot = norito::json::to_value(&state).expect("complete State snapshot");
    assert!(matches!(
        deserialize_state_snapshot_value_with_kura(snapshot.clone(), Arc::clone(&state.kura)),
        Err(super::deserialize::StateRestoreError::NativeExecutionReplayRequired)
    ));
    let (restored, _) = snapshot_runtime_component(&snapshot, &state, None)
        .expect("decode complete typed runtime component with both cuts");
    assert_eq!(restored.view().get(), &current);
    assert_eq!(restored.predecessor_view().get(), &Some(predecessor.clone()));
    assert_eq!(norito::json::to_json(&restored).unwrap(),
        norito::json::to_json(&state.canonical_runtime).unwrap(),
        "complete canonical Nexus runtime component survives decode without native authority");
    {
        let replacement = restored.block_and_revert();
        assert_eq!(replacement.get(), &predecessor);
        assert_eq!(replacement.get().autoscale_sample_history.last().unwrap().block_height, 4);
        assert_eq!(replacement.get().lineage_projection(), predecessor.lineage_projection());
    }
    assert_eq!(restored.view().get(), &current,
        "abandoned replacement cannot alter either retained cut");
    assert_eq!(restored.predecessor_view().get(), &Some(predecessor.clone()));

    let mut wrong_sample = predecessor.clone();
    wrong_sample.autoscale_sample_history.last_mut().unwrap().block_hash =
        HashOf::from_untyped_unchecked(Hash::new(b"wrong runtime predecessor sample"));
    let mut future_lineage = predecessor.clone();
    future_lineage.lane_incarnation_lineage.last_mut().unwrap().activation_height = 5;
    let mut wrong_physical_policy = predecessor.clone();
    wrong_physical_policy.owner_policy.dataspaces.last_mut().unwrap().fault_tolerance += 1;
    for (label, invalid) in [
        ("missing predecessor", norito::json::Value::Null),
        ("current record reused as predecessor", norito::json::to_value(&current).unwrap()),
        ("wrong predecessor sample hash", norito::json::to_value(&wrong_sample).unwrap()),
        ("future predecessor lineage", norito::json::to_value(&future_lineage).unwrap()),
        ("predecessor physical policy disagrees with World", norito::json::to_value(&wrong_physical_policy).unwrap()),
    ] {
        let invalid = match invalid {
            norito::json::Value::Null => norito::json::Value::Null,
            value => norito::json::to_value(&mv::json::SnapshotUndoValue { value }).unwrap(),
        };
        let mut corrupt = snapshot.clone();
        let _ = corrupt.as_object_mut().unwrap().get_mut("nexus_runtime").unwrap()
            .as_object_mut().unwrap().insert("revert".to_owned(), invalid);
        let error = snapshot_runtime_component(&corrupt, &state, None)
            .err().expect(label);
        assert!(error.to_string().contains("nexus_runtime"), "{label}: {error}");
    }
    let fields = norito::json::to_value(&predecessor.owner_policy).unwrap()
        .as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(fields.len(), 9);
    for field in fields {
        let mut corrupt = snapshot.clone();
        let _ = corrupt.as_object_mut().unwrap().get_mut("nexus_runtime").unwrap().as_object_mut().unwrap()
            .get_mut("revert").unwrap().as_object_mut().unwrap().get_mut("value").unwrap()
            .as_object_mut().unwrap().get_mut("owner_policy").unwrap()
            .as_object_mut().unwrap().remove(&field);
        assert!(snapshot_runtime_component(&corrupt, &state, None).is_err(),
            "predecessor owner policy field {field} is mandatory");
    }
}

state_test! { sync snapshot_runtime_height_zero_requires_absent_predecessor
    let state = blank_test_state();
    let snapshot = norito::json::to_value(&state).expect("height-zero State snapshot");
    let restored = deserialize_state_snapshot_value_with_kura(snapshot.clone(), Arc::clone(&state.kura))
        .expect("height-zero State with no runtime undo");
    assert!(restored.canonical_runtime.predecessor_view().get().is_none());
    assert_eq!(restored.canonical_runtime.view().get(), state.canonical_runtime.view().get());
    let mut corrupt = snapshot;
    let _ = corrupt.as_object_mut().unwrap().get_mut("nexus_runtime").unwrap().as_object_mut().unwrap()
        .insert("revert".to_owned(), norito::json::to_value(&mv::json::SnapshotUndoValue { value: state.canonical_runtime.view().get() }).unwrap());
    let error = deserialize_state_snapshot_value_with_kura(corrupt, Arc::clone(&state.kura))
        .err().expect("height zero cannot advertise an earlier runtime cut");
    assert!(error.to_string().contains("height-zero runtime cannot retain predecessor undo"));
}

state_test! { sync snapshot_owner_policy_native_replay_retains_original_configured_baseline
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    let (_directory, _component, configured) = snapshot_owner_policy_fixture();
    let config = || {
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.nexus = Some(configured.clone());
        config
    };
    let mut source = CertifiedTestChain::start(config()).expect("original configured signed genesis");
    source.commit(Vec::new());
    let mut replay = CertifiedTestChain::start(config()).expect("same configured signed genesis");
    replay.replay_from(&source).expect("replay exact original certified owner history");
    assert_eq!(replay.state().network_id_ref(), source.state().network_id_ref());
    assert_eq!(replay.state().view().latest_block_hash(), source.state().view().latest_block_hash());
    assert_eq!(SnapshotNexusOwnerPolicy::from_nexus(&replay.state().nexus_snapshot()),
        SnapshotNexusOwnerPolicy::from_nexus(&configured));
    assert_eq!(replay.state().nexus_snapshot().configured_lane_catalog, configured.configured_lane_catalog);
    assert_eq!(replay.state().nexus_snapshot().configured_dataspace_catalog, configured.configured_dataspace_catalog);
    assert_eq!(crate::snapshot::canonical_state_snapshot_hash(replay.state()).unwrap(),
        crate::snapshot::canonical_state_snapshot_hash(source.state()).unwrap());
    assert!(matches!(
        deserialize_state_snapshot_value_with_kura(norito::json::to_value(replay.state().as_ref()).unwrap(),
            Arc::clone(replay.kura())),
        Err(super::deserialize::StateRestoreError::NativeExecutionReplayRequired)
    ));
    assert!(!replay.state().nexus_runtime_restored_from_snapshot());
}
