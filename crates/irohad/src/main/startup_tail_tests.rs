#[test]
#[allow(clippy::bool_assert_comparison)] // for expressiveness
fn default_args() {
    let args = Args::try_parse_from(["test"]).unwrap();
    assert_eq!(args.terminal_colors, is_coloring_supported());
    assert!(!args.startup.check_config);
    #[cfg(feature = "test-network-parliament-signers")]
    assert_eq!(
        args.test_network_parliament_beacon_signer_mode,
        TestNetworkParliamentBeaconSignerMode::Valid,
    );
}

#[cfg(feature = "test-network-parliament-signers")]
#[test]
fn feature_only_parliament_beacon_signer_mode_is_exact_and_hidden() {
    for (value, expected) in [
        ("valid", TestNetworkParliamentBeaconSignerMode::Valid),
        ("absent", TestNetworkParliamentBeaconSignerMode::Absent),
        ("invalid", TestNetworkParliamentBeaconSignerMode::Invalid),
    ] {
        let args = Args::try_parse_from([
            "test",
            "--test-network-parliament-beacon-signer-mode",
            value,
        ])
        .expect("parse exact feature-only beacon signer mode");
        assert_eq!(args.test_network_parliament_beacon_signer_mode, expected);
    }
    assert!(
        Args::try_parse_from([
            "test",
            "--test-network-parliament-beacon-signer-mode",
            "faulty",
        ])
        .is_err(),
        "unknown feature-only modes must fail closed",
    );
    let help = Args::try_parse_from(["test", "--help"])
        .expect_err("help exits through clap")
        .to_string();
    assert!(
        !help.contains("test-network-parliament-beacon-signer-mode"),
        "the feature-only child-process argument must remain hidden",
    );
}
#[test]
fn check_config_flag_is_opt_in() {
    let args = Args::try_parse_from(["test", "--check-config"]).unwrap();
    assert!(args.startup.check_config);
}
#[test]
#[allow(clippy::bool_assert_comparison)] // for expressiveness
fn terminal_colors_works_as_expected() -> eyre::Result<()> {
    fn try_with(arg: &str) -> eyre::Result<bool> {
        Ok(Args::try_parse_from(["test", arg])?.terminal_colors)
    }
    assert_eq!(
        Args::try_parse_from(["test"])?.terminal_colors,
        is_coloring_supported()
    );
    assert_eq!(try_with("--terminal-colors")?, true);
    assert_eq!(try_with("--terminal-colors=false")?, false);
    assert_eq!(try_with("--terminal-colors=true")?, true);
    assert!(try_with("--terminal-colors=random").is_err());
    Ok(())
}
#[test]
fn user_provided_config_path_works() {
    let args = Args::try_parse_from(["test", "--config", "/home/custom/file.json"]).unwrap();
    assert_eq!(args.config, Some(PathBuf::from("/home/custom/file.json")));
}
#[test]
fn user_can_provide_any_extension() {
    let _args = Args::try_parse_from(["test", "--config", "file.toml.but.not"])
        .expect("should allow doing this as well");
}
#[test]
fn canonical_single_lane_topology_is_not_custom() {
    let nexus = iroha_config::parameters::actual::Nexus::default();
    assert!(!nexus_topology_is_custom(&nexus));
}
#[test]
fn expanded_lane_catalog_is_custom_topology() {
    use iroha_data_model::nexus::{LaneCatalog, LaneConfig};
    use std::num::NonZeroU32;
    let lane_catalog = LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(1),
                alias: "lane-1".to_owned(),
                description: None,
                ..LaneConfig::default()
            },
        ],
    )
    .expect("lane catalog");
    let nexus = iroha_config::parameters::actual::Nexus {
        lane_config: iroha_config::parameters::actual::LaneConfig::from_catalog(&lane_catalog),
        lane_catalog,
        ..Default::default()
    };
    assert!(nexus_topology_is_custom(&nexus));
}
#[test]
fn multilane_config_parses() {
    let config = Config::from_toml_source(TomlSource::inline(multilane_config_table()))
        .expect("multi-lane config should parse");
    assert_eq!(config.nexus.lane_catalog.lane_count().get(), 2);
    assert_eq!(config.nexus.lane_config.entries().len(), 2);
}
#[test]
fn read_genesis_handles_decode_failure() {
    // Create a bogus genesis file and ensure we return an error instead of panicking.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.genesis.signed.nrt");
    std::fs::write(&path, [0u8, 1u8, 2u8, 3u8]).unwrap();
    let res = read_genesis(&path);
    assert!(res.is_err());
}
#[test]
fn read_genesis_initializes_instruction_registry() {
    use iroha_data_model::isi::{InstructionRegistry, set_instruction_registry};
    let _registry_guard = instruction_registry_test_guard();
    // Start with an empty registry to simulate uninitialized state.
    set_instruction_registry(InstructionRegistry::new());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.genesis.signed.nrt");
    std::fs::write(&path, [0u8, 1u8, 2u8, 3u8]).unwrap();
    // `read_genesis` should initialize the registry internally and simply
    // return a decode error for the bogus file instead of panicking.
    let res = read_genesis_unlocked(&path);
    assert!(res.is_err());
}
#[cfg(feature = "beep")]
#[test]
fn startup_beep_respects_config_flag() {
    assert!(
        !startup_beep(false),
        "beep disabled by config flag should no-op"
    );
    assert!(
        startup_beep(true),
        "beep enabled by config flag should play once"
    );
}
