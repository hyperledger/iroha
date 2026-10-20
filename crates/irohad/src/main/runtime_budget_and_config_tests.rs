// Runtime storage-budget and fail-closed daemon configuration regressions.
#[test]
fn runtime_budget_rejects_zero_underflow_and_overflow() {
    for probe in [
        storage_budget_probe(1_000, 200, 0),
        storage_budget_probe(1_000, 199, 0),
        storage_budget_probe(1_000, 1, u64::MAX),
    ] {
        assert!(
            derive_runtime_nexus_storage_budget(&[probe]).is_err(),
            "invalid capacity arithmetic must fail closed"
        );
    }
}

#[cfg(unix)]
#[test]
fn runtime_reconciliation_keeps_read_only_key_config_bytes_mode_and_inode() -> eyre::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (_parsed, _dir, config_path) = parse_config_with_overrides(|_, _| {})?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o400))?;
    let original_bytes = std::fs::read(&config_path)?;
    let original_metadata = std::fs::metadata(&config_path)?;
    assert_eq!(original_metadata.mode() & 0o777, 0o400);
    let (config, _genesis) = read_config_with_fixture_space(&Args {
        config: Some(config_path.clone()),
        genesis_manifest_json: None,
        startup: StartupArgs {
            check_config: false,
            json: false,
            check_storage: false,
            require_genesis_inrou_deployment_authority: None,
            trace_config: false,
            config_blake3: None,
            sumeragi_assert_fresh_key: false,
        },
        terminal_colors: false,
        language: None,
        sora: true,
        #[cfg(feature = "test-network-parliament-signers")]
        test_network_parliament_beacon_signer_mode: TestNetworkParliamentBeaconSignerMode::Valid,
        fastpq_execution_mode: None,
        fastpq_poseidon_mode: None,
        fastpq_device_class: None,
        fastpq_chip_family: None,
        fastpq_gpu_kind: None,
    })
    .map_err(|report| eyre::eyre!("{report:?}"))?;
    assert!(
        config.nexus.storage.effective_local_budget_bytes.is_some(),
        "startup must complete runtime reconciliation"
    );
    let final_metadata = std::fs::metadata(&config_path)?;
    assert_eq!(std::fs::read(&config_path)?, original_bytes);
    assert_eq!(final_metadata.mode(), original_metadata.mode());
    assert_eq!(final_metadata.ino(), original_metadata.ino());
    Ok(())
}

#[test]
fn statvfs_capacity_uses_the_fundamental_fragment_size() {
    assert_eq!(statvfs_fragment_size(4_096, 1_048_576), Some(4_096));
    assert_eq!(statvfs_fragment_size(0, 4_096), Some(4_096));
    assert_eq!(statvfs_fragment_size(0, 0), None);
}

#[test]
fn budget_root_allows_ancestor_symlink_but_rejects_exact_and_dangling_links() -> eyre::Result<()> {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let real_parent = temp.path().join("real-parent");
    let real_root = real_parent.join("managed");
    std::fs::create_dir_all(&real_root)?;
    let alias_parent = temp.path().join("alias-parent");
    symlink(&real_parent, &alias_parent)?;
    let lexical_root =
        normalize_budget_probe_path(alias_parent.join("managed")).expect("absolute path");
    let resolved = resolve_budget_probe_root(&lexical_root, NexusStorageBudgetComponent::Kura)
        .expect("a symlink strictly above the managed root is allowed");
    let canonical_root = std::fs::canonicalize(&real_root)?;
    assert_eq!(
        resolved.managed_root.as_deref(),
        Some(canonical_root.as_path())
    );
    let direct = resolve_budget_probe_root(
        &normalize_budget_probe_path(real_root.clone()).expect("absolute direct root"),
        NexusStorageBudgetComponent::Sorafs,
    )
    .expect("the direct spelling resolves");
    let mut managed_roots = vec![
        direct.managed_root.expect("direct managed root"),
        resolved.managed_root.expect("alias managed root"),
    ];
    deduplicate_managed_roots(&mut managed_roots);
    assert_eq!(managed_roots, vec![canonical_root.clone()]);
    let exact_link = temp.path().join("exact-root-link");
    symlink(&real_root, &exact_link)?;
    let exact_error = resolve_budget_probe_root(&exact_link, NexusStorageBudgetComponent::Kura)
        .expect_err("the exact managed root must not be a symlink");
    assert!(format!("{exact_error:?}").contains("must not be a symbolic link or reparse point"));
    let dangling_link = temp.path().join("dangling-root-link");
    symlink(temp.path().join("missing-target"), &dangling_link)?;
    assert!(
        resolve_budget_probe_root(&dangling_link, NexusStorageBudgetComponent::Kura).is_err(),
        "a dangling exact-root link must fail closed"
    );
    Ok(())
}
#[cfg(unix)]
#[test]
fn explicit_budget_does_not_downgrade_structural_path_failures() -> eyre::Result<()> {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let real_root = temp.path().join("real-root");
    std::fs::create_dir(&real_root)?;
    let linked_root = temp.path().join("linked-root");
    symlink(&real_root, &linked_root)?;
    let (mut config, _dir, _config_path) = parse_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table)
            .write(["nexus", "storage", "local_budget_bytes"], 2_000_i64);
    })?;
    config.kura.store_dir = WithOrigin::inline(linked_root);
    let error = reconcile_nexus_storage_budget(&mut config, filesystem_space)
        .expect_err("an explicit budget must not suppress a structural path failure");
    assert!(format!("{error:?}").contains("must not be a symbolic link or reparse point"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn managed_root_measurement_rejects_descendant_links_and_identity_drift() -> eyre::Result<()> {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("managed");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&outside)?;
    let descendant_link = root.join("linked-child");
    symlink(&outside, &descendant_link)?;
    let canonical_root = std::fs::canonicalize(&root)?;
    let filesystem_id = filesystem_identity(&canonical_root).expect("filesystem identity");
    let link_error = managed_root_size(&canonical_root, &filesystem_id)
        .expect_err("descendant links must fail closed");
    assert!(
        link_error
            .to_string()
            .contains("symbolic link or reparse point")
    );
    std::fs::remove_file(descendant_link)?;
    let mount_child = canonical_root.join("mounted-child");
    std::fs::create_dir(&mount_child)?;
    let cross_mount_error =
        managed_root_size_with_identity(&canonical_root, &filesystem_id, |path| {
            if path == mount_child.as_path() {
                Some("dev:other".to_owned())
            } else {
                Some(filesystem_id.clone())
            }
        })
        .expect_err("a descendant mount boundary must fail closed");
    assert!(
        cross_mount_error
            .to_string()
            .contains("crosses from filesystem")
    );
    assert!(
        managed_root_size(&canonical_root, "dev:stale").is_err(),
        "the filesystem identity is rechecked during measurement"
    );
    Ok(())
}
#[test]
fn operator_explicit_budget_shortfall_accounts_for_managed_bytes() -> eyre::Result<()> {
    let (mut config, _dir, _config_path) = parse_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table)
            .write(["nexus", "storage", "local_budget_bytes"], 2_000_i64);
    })?;
    config.apply_storage_budget();
    let mut filesystem = StorageBudgetFilesystemProbe {
        filesystem_id: "dev:1".to_owned(),
        path: PathBuf::from("/tmp/storage"),
        total_bytes: 10_000,
        available_bytes: 1_000,
        managed_bytes: 100,
        components: NexusStorageBudgetComponent::ORDER.to_vec(),
        managed_roots: Vec::new(),
        derived_budget_bytes: None,
    };
    assert_eq!(
        operator_explicit_budget_shortfall(&config, &filesystem),
        Some(2_000)
    );
    filesystem.available_bytes = 1_900;
    assert_eq!(
        operator_explicit_budget_shortfall(&config, &filesystem),
        None
    );
    Ok(())
}
#[test]
fn normalize_windows_volume_mount_point_adds_trailing_separator() {
    assert_eq!(
        normalize_windows_volume_mount_point(r"C:\nexus\storage"),
        r"C:\nexus\storage\"
    );
    assert_eq!(
        normalize_windows_volume_mount_point(r"\\?\Volume{ABCDEF12-3456-7890-ABCD-EF1234567890}\"),
        r"\\?\Volume{ABCDEF12-3456-7890-ABCD-EF1234567890}\"
    );
}
#[test]
fn normalize_windows_volume_identity_uses_lowercased_guid_path() {
    assert_eq!(
        normalize_windows_volume_identity(r"\\?\Volume{ABCDEF12-3456-7890-ABCD-EF1234567890}\"),
        r"volume:\\?\volume{abcdef12-3456-7890-abcd-ef1234567890}\"
    );
}
#[test]
fn windows_string_from_wide_buffer_stops_at_first_nul() {
    let buffer: Vec<u16> = "Volume\0ignored".encode_utf16().collect();
    assert_eq!(
        windows_string_from_wide_buffer(&buffer).as_deref(),
        Some("Volume")
    );
    assert_eq!(windows_string_from_wide_buffer(&[]), None);
}
#[test]
fn validate_config_io_flags_address_conflict() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|table, _genesis_key| {
        if let Some(genesis_table) = table.get_mut("genesis").and_then(toml::Value::as_table_mut) {
            genesis_table.remove("file");
        }
        iroha_config::base::toml::Writer::new(table).write(
            ["torii", "address"],
            socket_addr!(127.0.0.1:1337).to_literal(),
        );
    })?;
    let mut emitter = Emitter::new();
    validate_config_io(&mut emitter, &config);
    let report = emitter
        .into_result()
        .expect_err("expected validation errors");
    let report_text = format!("{report:#}");
    assert_contains!(
        report_text,
        "Torii and Network addresses are the same, but should be different"
    );
    Ok(())
}
#[test]
fn block_sync_topic_must_carry_the_local_sync_budget() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|_, _| {})?;
    let origin = config.common.trusted_peers.value().myself.id().clone();
    let required =
        iroha_core::sumeragi::net::minimum_block_sync_frame_bytes(&origin, &config.sumeragi.local);
    assert!(
        required <= iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get(),
        "the shipped block-sync cap carries the default sync budget"
    );
    validate_network_frame_runtime_limit(&config).expect("shipped defaults are accepted");
    for (cap, accepted) in [(required, true), (required - 1, false)] {
        let (topic_config, _topic_dir, _topic_config_path) =
            load_config_with_overrides(|table, _genesis_key| {
                iroha_config::base::toml::Writer::new(table).write(
                    ["network", "max_frame_bytes_block_sync"],
                    i64::try_from(cap).expect("topic cap fits i64"),
                );
            })?;
        let result = validate_network_frame_runtime_limit(&topic_config);
        assert_eq!(result.is_ok(), accepted, "max_frame_bytes_block_sync={cap}");
        if !accepted {
            assert_contains!(
                format!("{:#}", result.unwrap_err()),
                "cannot carry the largest sync response of sumeragi.sync_max_bytes"
            );
        }
    }
    Ok(())
}
#[test]
fn control_topic_must_carry_the_largest_control_frame() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|_, _| {})?;
    let origin = config.common.trusted_peers.value().myself.id().clone();
    let required = iroha_core::sumeragi::net::minimum_control_frame_bytes(&origin);
    assert!(
        required <= iroha_config::parameters::defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
        "the shipped control cap carries the largest control frame"
    );
    validate_network_frame_runtime_limit(&config).expect("shipped defaults are accepted");
    for (cap, accepted) in [(required, true), (required - 1, false)] {
        let (topic_config, _topic_dir, _topic_config_path) =
            load_config_with_overrides(|table, _genesis_key| {
                iroha_config::base::toml::Writer::new(table).write(
                    ["network", "max_frame_bytes_control"],
                    i64::try_from(cap).expect("topic cap fits i64"),
                );
            })?;
        let result = validate_network_frame_runtime_limit(&topic_config);
        assert_eq!(result.is_ok(), accepted, "max_frame_bytes_control={cap}");
        if !accepted {
            assert_contains!(
                format!("{:#}", result.unwrap_err()),
                "cannot carry the largest consensus control frame"
            );
        }
    }
    Ok(())
}
#[test]
fn check_config_and_runtime_enforce_frame_cap_boundary() -> eyre::Result<()> {
    let (exact_config, _exact_dir, _exact_config_path) =
        load_config_with_overrides(|table, _genesis_key| {
            iroha_config::base::toml::Writer::new(table).write(
                ["network", "max_frame_bytes"],
                i64::try_from(iroha_p2p::MAX_ENCRYPTED_FRAME_BYTES)
                    .expect("runtime frame limit fits i64"),
            );
        })?;
    validate_network_frame_runtime_limit(&exact_config)
        .expect("the exact deterministic runtime frame limit must be accepted");
    let (config, _dir, _config_path) = load_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table).write(
            ["network", "max_frame_bytes"],
            i64::try_from(iroha_p2p::MAX_ENCRYPTED_FRAME_BYTES + 1)
                .expect("first rejected frame cap fits i64"),
        );
    })?;
    assert_eq!(
        config.network.max_frame_bytes,
        iroha_p2p::MAX_ENCRYPTED_FRAME_BYTES + 1
    );
    let check_report = validate_config_and_genesis_for_check(&config, None, None)
        .map(drop)
        .expect_err("--check-config must reject an unrepresentable frame cap");
    assert_contains!(
        format!("{check_report:#}"),
        "exceeds the deterministic encrypted P2P runtime limit of 2147483643 bytes"
    );
    let runtime_report =
        validate_config(&config).expect_err("runtime preflight must reject before binding sockets");
    assert_contains!(
        format!("{runtime_report:#}"),
        "exceeds the deterministic encrypted P2P runtime limit of 2147483643 bytes"
    );
    let encrypted_cap = iroha_config::parameters::defaults::network::MAX_FRAME_BYTES.get();
    let plaintext_ceiling = iroha_p2p::frame_plaintext_cap(encrypted_cap);
    for topic in ["max_frame_bytes_consensus", "max_frame_bytes_connect"] {
        let (topic_config, _topic_dir, _topic_config_path) =
            load_config_with_overrides(|table, _genesis_key| {
                iroha_config::base::toml::Writer::new(table).write(
                    ["network", topic],
                    i64::try_from(plaintext_ceiling + 1)
                        .expect("first rejected topic cap fits i64"),
                );
            })?;
        let check_report = validate_config_and_genesis_for_check(&topic_config, None, None)
            .map(drop)
            .expect_err("--check-config must reject a topic cap above plaintext capacity");
        let expected = format!(
            "network.{topic} ({}) exceeds the AEAD-specific plaintext ceiling of {plaintext_ceiling} bytes derived from network.max_frame_bytes ({encrypted_cap})",
            plaintext_ceiling + 1
        );
        assert_contains!(format!("{check_report:#}"), &expected);
        let runtime_report = validate_config(&topic_config)
            .expect_err("runtime preflight must reject the same invalid topic cap");
        assert_contains!(format!("{runtime_report:#}"), &format!("network.{topic}"));
    }
    Ok(())
}
#[test]
fn validator_requires_confidential_enabled() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table)
            .write(["sumeragi", "role"], "validator")
            .write(["confidential", "enabled"], false)
            .write(["confidential", "assume_valid"], false);
    })?;
    let report = validate_config(&config).unwrap_err();
    assert_contains!(
        format!("{report:#}"),
        "validator nodes must enable confidential verification"
    );
    Ok(())
}
#[test]
fn validate_config_runtime_rejects_validator_confidential_disabled() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table)
            .write(["sumeragi", "role"], "validator")
            .write(["confidential", "enabled"], false)
            .write(["confidential", "assume_valid"], false);
    })?;
    let mut emitter = Emitter::new();
    validate_config_runtime(&mut emitter, &config);
    let report = emitter
        .into_result()
        .expect_err("expected validation errors");
    assert_contains!(
        format!("{report:#}"),
        "validator nodes must enable confidential verification"
    );
    Ok(())
}
#[test]
fn validate_config_runtime_rejects_sorafs_storage_without_compliance() -> eyre::Result<()> {
    let (mut config, _dir, _config_path) = load_config_with_overrides(|_, _| {})?;
    config.torii.sorafs_storage.enabled = true;
    config.torii.sorafs_gateway.compliance = None;
    let mut emitter = Emitter::new();
    validate_config_runtime(&mut emitter, &config);
    let report = emitter
        .into_result()
        .expect_err("ungoverned embedded storage must fail before startup");
    assert_contains!(
        format!("{report:#}"),
        "sorafs.storage.enabled requires the governed sorafs.gateway.compliance controller"
    );
    Ok(())
}
#[test]
fn validate_config_runtime_rejects_gateway_automation_without_storage() -> eyre::Result<()> {
    let (mut config, _dir, _config_path) = load_config_with_overrides(|_, _| {})?;
    config.torii.sorafs_storage.enabled = false;
    config.torii.sorafs_gateway.acme.enabled = true;
    let mut emitter = Emitter::new();
    validate_config_runtime(&mut emitter, &config);
    let report = emitter
        .into_result()
        .expect_err("gateway automation without storage must fail before startup");
    assert_contains!(
        format!("{report:#}"),
        "SoraFS gateway ACME/compliance configuration requires sorafs.storage.enabled"
    );
    Ok(())
}
#[test]
fn validator_cannot_assume_valid_confidential() -> eyre::Result<()> {
    let (config, _dir, _config_path) = load_config_with_overrides(|table, _genesis_key| {
        iroha_config::base::toml::Writer::new(table)
            .write(["sumeragi", "role"], "validator")
            .write(["confidential", "enabled"], true)
            .write(["confidential", "assume_valid"], true);
    })?;
    let report = validate_config(&config).unwrap_err();
    assert_contains!(
        format!("{report:#}"),
        "validator nodes cannot enable confidential observer mode"
    );
    Ok(())
}

#[test]
fn injected_filesystem_capacity_still_rejects_zero_budget_and_real_links() -> eyre::Result<()> {
    let (mut config, temp, _path) = parse_config_with_overrides(|_, _| {})?;
    config.kura.store_dir = WithOrigin::inline(temp.path().join("empty-kura"));
    config.torii.sorafs_storage.data_dir = temp.path().join("empty-sorafs");
    config.tiered_state.da_store_root = Some(temp.path().join("empty-cold"));
    assert!(config.nexus.storage.local_budget_bytes.is_none());
    assert!(config.nexus.storage.effective_local_budget_bytes.is_none());
    let error = reconcile_nexus_storage_budget(&mut config, |_| Some((0, 1_000)))
        .expect_err("zero available capacity with no managed bytes cannot fund a budget");
    let diagnostic = format!("{error:?}");
    assert!(
        diagnostic.contains("no safe non-zero Nexus storage budget"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains("200 bytes of headroom"), "{diagnostic}");
    assert!(config.nexus.storage.effective_local_budget_bytes.is_none());
    let real = temp.path().join("real-managed");
    std::fs::create_dir(&real)?;
    let alias = temp.path().join("linked-managed");
    std::os::unix::fs::symlink(&real, &alias)?;
    config.kura.store_dir = WithOrigin::inline(alias);
    let error = reconcile_nexus_storage_budget(&mut config, |_| Some((800, 1_000)))
        .expect_err("injected capacity must not bypass real path ownership");
    assert!(format!("{error:?}").contains("must not be a symbolic link or reparse point"));
    assert!(config.nexus.storage.effective_local_budget_bytes.is_none());
    Ok(())
}
