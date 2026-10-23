// Original template monetary authorship, exact asset binding and caller-context controls.
fn staking_source_template(path: &str) -> GenesisSourceTemplate {
    GenesisSourceTemplate::from_path(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .expect("read the explicit first-release source")
}

fn staking_source_custom(template: &mut GenesisSourceTemplate) -> &mut norito::json::Map {
    template
        .value
        .get_mut("transactions")
        .and_then(norito::json::Value::as_array_mut)
        .unwrap()
        .iter_mut()
        .find_map(|transaction| {
            transaction
                .get_mut("parameters")
                .and_then(|parameters| parameters.get_mut("custom"))
                .and_then(norito::json::Value::as_object_mut)
        })
        .expect("one explicit parameter snapshot")
}

fn staking_source_asset(path: &str) -> AssetDefinitionId {
    if path
        .split('/')
        .any(|part| matches!(part, "nexus" | "iroha3-nexus"))
    {
        AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::parse_fully_qualified("mainnet-fixture.universal")
                .unwrap(),
            "xor".parse().unwrap(),
        )
    } else {
        SumeragiNposParameters::default().xor_asset_definition_id
    }
}

#[test]
fn source_materialization_binds_all_three_assets_and_preserves_authored_staking_terms() {
    use iroha_data_model::account::address::ChainDiscriminantGuard;
    for path in [
        "defaults/genesis.template.json",
        "defaults/kagami/iroha3-dev/genesis.template.json",
        "defaults/kagami/iroha3-nexus/genesis.template.json",
        "defaults/nexus/genesis.template.json",
        "configs/soranexus/nexus/genesis.template.json",
        "configs/soranexus/taira/genesis.template.json",
        "crates/iroha_kagami/tests/fixtures/taira_nevo_v2/unsigned-genesis.template.json",
    ] {
        let mut template = staking_source_template(path);
        let selected = staking_source_asset(path);
        let chain = u16::try_from(
            template
                .value
                .get("chain_discriminant")
                .unwrap()
                .as_u64()
                .unwrap(),
        )
        .unwrap();
        let _author = ChainDiscriminantGuard::enter(chain);
        let custom = staking_source_custom(&mut template);
        let alternate_sink = custom["root_fees_v1"]
            .get("payload")
            .unwrap()
            .get("sponsor_vault_custody_account_id")
            .unwrap()
            .clone();
        let payload = custom
            .get_mut(PublicLaneStakingPolicy::PARAMETER_ID_STR)
            .unwrap()
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap();
        // Distinct values detect accidental replacement with a producer default profile.
        payload.insert("min_validator_stake".into(), norito::json!("17.25"));
        payload.insert("max_stake_shares_per_validator".into(), norito::json!(19));
        payload.insert("max_pending_unbonds_per_share".into(), norito::json!(3));
        payload.insert("unbonding_delay_ms".into(), norito::json!(123456));
        payload.insert("max_slash_bps".into(), norito::json!(4321));
        payload.insert("slash_sink_account_id".into(), alternate_sink);
        let mut expected_payload = norito::json::Value::Object(payload.clone());
        expected_payload.as_object_mut().unwrap().insert(
            "stake_asset_id".into(),
            norito::json!(selected.canonical_address()),
        );
        let expected: PublicLaneStakingPolicy =
            norito::json::from_str(&norito::json::to_json(&expected_payload).unwrap()).unwrap();
        let before = RawGenesisTransaction::from_json_slice_at_path(
            &norito::json::to_vec(&template.value).unwrap(),
            &template.json_path,
        )
        .unwrap();
        let materialized = template.materialize(Some(selected.clone())).unwrap();
        let parameters = materialized.effective_parameters().unwrap();
        let staking = PublicLaneStakingPolicy::from_parameters(&parameters).unwrap();
        let fees = iroha_data_model::block::consensus::RootFeePolicy::from_parameters(&parameters)
            .unwrap()
            .unwrap();
        let npos = SumeragiNposParameters::from_custom_parameter(
            &parameters.custom()[&SumeragiNposParameters::parameter_id()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(staking, expected, "{path}");
        assert_eq!(staking.stake_asset_id, selected, "{path}");
        assert_eq!(fees.fee_asset_id, selected, "{path}");
        assert_eq!(npos.xor_asset_definition_id, selected, "{path}");
        assert_eq!(
            before.transactions().len(),
            materialized.transactions().len()
        );
        for (original, completed) in before
            .transactions()
            .iter()
            .zip(materialized.transactions())
        {
            assert_eq!(
                original.instructions().to_vec().encode(),
                completed.instructions().to_vec().encode()
            );
            assert_eq!(
                norito::json::to_json(&original.ivm_triggers).unwrap(),
                norito::json::to_json(&completed.ivm_triggers).unwrap()
            );
            assert_eq!(
                norito::json::to_json(&original.topology).unwrap(),
                norito::json::to_json(&completed.topology).unwrap()
            );
        }
        assert!(materialized.consensus_fingerprint().is_some());
    }
}

#[test]
fn source_materialization_refuses_missing_and_duplicate_staking_recipes() {
    let original = staking_source_template("defaults/genesis.template.json");
    let selected = staking_source_asset("defaults/genesis.template.json");
    let mut missing = original.clone();
    assert!(
        staking_source_custom(&mut missing)
            .remove(PublicLaneStakingPolicy::PARAMETER_ID_STR)
            .is_some()
    );
    let error = missing.materialize(Some(selected.clone())).unwrap_err();
    assert!(
        error.to_string().contains("election=1, fee=1, staking=0"),
        "{error}"
    );
    let mut duplicate = original;
    let policy =
        staking_source_custom(&mut duplicate)[PublicLaneStakingPolicy::PARAMETER_ID_STR].clone();
    let mut duplicate_custom = norito::json::Map::new();
    duplicate_custom.insert(PublicLaneStakingPolicy::PARAMETER_ID_STR.into(), policy);
    duplicate.value.get_mut("transactions").unwrap().as_array_mut().unwrap().push(
        norito::json!({"parameters": {"custom": (norito::json::Value::Object(duplicate_custom))}, "instructions": [], "ivm_triggers": []}),
    );
    let error = duplicate.materialize(Some(selected)).unwrap_err();
    assert!(
        error.to_string().contains("election=1, fee=1, staking=2"),
        "{error}"
    );
}

#[test]
fn permissioned_source_keeps_authored_staking_asset_and_rejects_npos_selection() {
    let mut authored = fixture_policy();
    authored.stake_asset_id = AssetDefinitionId::derive_from_components(
        iroha_model_base::domain::DomainId::parse_fully_qualified("permissioned-staking.universal")
            .unwrap(),
        "bond".parse().unwrap(),
    );
    authored.unbonding_delay_ms = 45678;
    let manifest = builder()
        .with_staking_policy(authored.clone())
        .unwrap()
        .build_raw()
        .unwrap();
    let mut value: norito::json::Value =
        norito::json::from_str(&norito::json::to_json(&manifest).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("consensus_fingerprint".into(), norito::json::Value::Null);
    let template = GenesisSourceTemplate {
        json_path: PathBuf::from("permissioned.template.json"),
        value,
    };
    assert!(
        template
            .clone()
            .materialize(Some(
                SumeragiNposParameters::default().xor_asset_definition_id
            ))
            .is_err()
    );
    let completed = template.materialize(None).unwrap();
    assert_eq!(
        PublicLaneStakingPolicy::from_parameters(&completed.effective_parameters().unwrap())
            .unwrap(),
        authored
    );
    assert_eq!(
        completed.consensus_mode(),
        iroha_data_model::parameter::system::SumeragiConsensusMode::Permissioned
    );
}

#[test]
fn staking_source_materialization_restores_caller_context_on_success_and_error() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
    for (path, caller, author) in [
        ("configs/soranexus/taira/genesis.template.json", 753, 369),
        ("configs/soranexus/nexus/genesis.template.json", 369, 753),
    ] {
        let _caller = ChainDiscriminantGuard::enter(caller);
        let template = staking_source_template(path);
        let selected = staking_source_asset(path);
        let completed = template
            .clone()
            .materialize(Some(selected.clone()))
            .unwrap();
        assert_eq!(completed.chain_discriminant(), author);
        assert_eq!(chain_discriminant(), caller);
        let mut malformed = template;
        staking_source_custom(&mut malformed)
            .get_mut(PublicLaneStakingPolicy::PARAMETER_ID_STR)
            .unwrap()
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "stake_escrow_account_id".into(),
                norito::json!("not-an-account"),
            );
        assert!(malformed.materialize(Some(selected)).is_err());
        assert_eq!(chain_discriminant(), caller);
    }
}
