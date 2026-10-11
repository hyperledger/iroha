#[test]
fn profile_account_defaults_materialize_selected_chain_before_root_parse() {
    use iroha_data_model::account::address::ChainDiscriminantGuard;

    // The explicit effective configuration, not ambient test-thread state, selects the prefix.
    let _ambient = ChainDiscriminantGuard::enter(777);
    let mut layers = vec![
        Table::new().write("chain_discriminant", 753_i64),
        Table::new().write("chain_discriminant", 369_i64),
    ];
    let originals = layers.clone();
    assert_eq!(
        materialize_profile_account_defaults(&mut layers).unwrap(),
        369
    );
    assert_eq!(&layers[..originals.len()], originals.as_slice());
    let (_peer_directory, _peer, merged) = sora_profile_runtime_config_fixture(&layers);
    let expected_bond = defaults::governance::bond_escrow_account_id()
        .to_i105_for_discriminant(369)
        .unwrap();
    for path in [
        &["gov", "citizenship_escrow_account"][..],
        &["gov", "bond_escrow_account"][..],
        &["gov", "slash_receiver_account"][..],
        &["gov", "viral_incentive_pool_account"][..],
        &["gov", "viral_escrow_account"][..],
        &["network", "soranet_vpn", "operator_account_id"][..],
    ] {
        assert_eq!(
            get_nested_value(&merged, path).and_then(Value::as_str),
            Some(expected_bond.as_str())
        );
    }
    let user = ConfigReader::new()
        .with_env(MockEnv::default())
        .with_toml_source(TomlSource::inline(merged))
        .read_and_complete::<iroha_config::parameters::user::Root>()
        .expect("complete selected-profile user config");
    let actual = user
        .parse()
        .expect("full native Root parse accepts generated chain369 defaults");
    assert_eq!(
        actual.gov.bond_escrow_account,
        defaults::governance::bond_escrow_account_id()
    );
    assert_eq!(
        actual.gov.sorafs_pin_fee_treasury_account,
        defaults::governance::sorafs_pin_fee::treasury_account_id()
    );
    assert_eq!(
        actual.network.soranet_vpn.operator_account_id,
        defaults::governance::bond_escrow_account_id()
    );
    assert!(!actual.network.soranet_vpn.enabled);
    assert_eq!(
        actual.nexus.fees.sponsor_vault_custody_account_id,
        defaults::nexus::fees::sponsor_vault_custody_account_id()
    );
    assert!(actual.gov.sorafs_telemetry.submitters.is_empty());
    // The actual profile-detection path must also parse these same materialized layers.
    let _profile = config_requires_sora_profile(&layers);
    let once = layers.clone();
    assert_eq!(
        materialize_profile_account_defaults(&mut layers).unwrap(),
        369
    );
    assert_eq!(layers, once, "materialization is idempotent");
}

#[test]
fn profile_account_defaults_preserve_explicit_foreign_and_invalid_overrides() {
    let foreign = defaults::governance::bond_escrow_account_id()
        .to_i105_for_discriminant(753)
        .unwrap();
    for vpn in [false, true] {
        let mut explicit = Table::new().write("chain_discriminant", 369_i64);
        let path: &[&str] = if vpn {
            TomlWriter::new(&mut explicit).write(
                ["network", "soranet_vpn", "operator_account_id"],
                foreign.clone(),
            );
            &["network", "soranet_vpn", "operator_account_id"]
        } else {
            TomlWriter::new(&mut explicit).write(["gov", "bond_escrow_account"], foreign.clone());
            &["gov", "bond_escrow_account"]
        };
        let mut layers = vec![explicit.clone()];
        assert_eq!(
            materialize_profile_account_defaults(&mut layers).unwrap(),
            369
        );
        assert_eq!(
            layers[0], explicit,
            "explicit source bytes remain logically unchanged"
        );
        let merged = merged_sora_profile_detection_config(&layers);
        assert_eq!(
            get_nested_value(&merged, path).and_then(Value::as_str),
            Some(foreign.as_str())
        );
        let user = ConfigReader::new()
            .with_env(MockEnv::default())
            .with_toml_source(TomlSource::inline(merged))
            .read_and_complete::<iroha_config::parameters::user::Root>()
            .expect("read explicit foreign literal");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| user.parse()))
            .expect_err("native strict parser still rejects the explicit foreign account");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("native parse diagnostic");
        let expected = if vpn {
            "network.soranet_vpn.operator_account_id"
        } else {
            "governance bond escrow account"
        };
        assert!(
            message.contains(expected),
            "foreign-address rejection must identify its field: {message}"
        );
    }
    let malformed = Table::new()
        .write("chain_discriminant", 369_i64)
        .write("gov", 17_i64);
    let mut layers = vec![malformed.clone()];
    materialize_profile_account_defaults(&mut layers).unwrap();
    assert_eq!(layers[0], malformed);
    assert_eq!(
        merged_sora_profile_detection_config(&layers).get("gov"),
        Some(&Value::Integer(17)),
        "a generated nested default must not replace an explicit malformed ancestor"
    );
    for invalid in [
        Value::Integer(-1),
        Value::Integer(65_536),
        Value::String("369".to_owned()),
    ] {
        let mut layers = vec![Table::new().write("chain_discriminant", invalid)];
        let before = layers.clone();
        assert!(materialize_profile_account_defaults(&mut layers).is_err());
        assert_eq!(
            layers, before,
            "invalid profile cannot partially materialize defaults"
        );
    }
}
