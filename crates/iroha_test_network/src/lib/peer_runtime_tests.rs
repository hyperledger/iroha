#[cfg(test)]
mod post_genesis_liveness_tests {
    use super::*;
    use tokio::sync::broadcast;
    #[tokio::test]
    async fn detects_none_when_timer_expires() {
        let (_tx, rx) = broadcast::channel(4);
        assert!(
            detect_peer_termination(rx, Duration::from_millis(25))
                .await
                .is_none()
        );
    }
    #[tokio::test]
    async fn detects_killed_event() {
        let (tx, rx) = broadcast::channel(4);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(PeerLifecycleEvent::Killed);
        });
        assert_eq!(
            detect_peer_termination(rx, Duration::from_secs(1)).await,
            Some(TerminationKind::Killed)
        );
    }
    #[test]
    fn advances_next_height_for_each_block() {
        let mut block_height = BlockHeight {
            total: 1,
            non_empty: 1,
        };
        let mut next_height = block_height.total.checked_add(1).expect("setup overflow");
        advance_block_height(&mut block_height, &mut next_height, 2, false);
        advance_block_height(&mut block_height, &mut next_height, 3, true);
        assert_eq!(block_height.total, 3);
        assert_eq!(block_height.non_empty, 2);
        assert_eq!(next_height, 4);
    }
}
#[cfg(test)]
mod start_event_tests {
    use super::*;
    use tokio::sync::broadcast;
    #[tokio::test]
    async fn waits_until_server_started_event() {
        let (tx, rx) = broadcast::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(PeerLifecycleEvent::Spawned);
            let _ = tx.send(PeerLifecycleEvent::BlockApplied { height: 1 });
            let _ = tx.send(PeerLifecycleEvent::ServerStarted);
        });
        let event = wait_for_start_event(rx).await;
        assert!(matches!(event, Some(PeerLifecycleEvent::ServerStarted)));
    }
    #[test]
    fn storage_fallback_requires_bootstrap_grace_running_and_block_1() {
        let grace = START_CHECKED_STORAGE_FALLBACK_GRACE;
        assert!(!start_checked_storage_fallback_ready(
            false, grace, true, true
        ));
        assert!(!start_checked_storage_fallback_ready(
            true,
            grace.saturating_sub(Duration::from_millis(1)),
            true,
            true
        ));
        assert!(!start_checked_storage_fallback_ready(
            true, grace, false, true
        ));
        assert!(!start_checked_storage_fallback_ready(
            true, grace, true, false
        ));
    }
    #[test]
    fn storage_fallback_allows_ready_bootstrap_peer() {
        assert!(start_checked_storage_fallback_ready(
            true,
            START_CHECKED_STORAGE_FALLBACK_GRACE,
            true,
            true
        ));
    }
}
#[cfg(test)]
mod diagnostics_tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn snapshot_dir_entries_are_sorted_and_truncated() {
        let dir = tempdir().expect("tempdir");
        for name in ["z", "a", "c", "b", "y", "x"] {
            let path = dir.path().join(name);
            std::fs::write(path, name).expect("create file");
        }
        let entries = snapshot_dir_entries(dir.path(), 3);
        assert_eq!(entries[0], "a");
        assert_eq!(entries[1], "b");
        assert_eq!(entries[2], "c");
        assert!(
            entries.last().unwrap().starts_with("(+"),
            "should include truncation marker"
        );
    }
    #[test]
    fn snapshot_snippet_keeps_short_strings_intact() {
        let message = "ok";
        assert_eq!(snapshot_snippet(message), message);
    }
    #[test]
    fn snapshot_snippet_truncates_and_marks_long_messages() {
        let message = "a".repeat(SNAPSHOT_MESSAGE_SNIPPET_MAX_CHARS + 5);
        let snippet = snapshot_snippet(&message);
        assert_eq!(
            snippet.len(),
            SNAPSHOT_MESSAGE_SNIPPET_MAX_CHARS + '…'.len_utf8()
        );
        assert!(
            snippet.ends_with('…'),
            "snippet should mark truncation with an ellipsis"
        );
    }
    #[test]
    fn storage_snapshot_detects_existing_pipeline_entries() {
        let dir = tempdir().expect("tempdir");
        let storage = dir.path().join("storage");
        let blocks = storage.join("blocks").join("lane_000_default");
        let pipeline = blocks.join("pipeline");
        std::fs::create_dir_all(&pipeline).expect("pipeline dir");
        std::fs::create_dir_all(&blocks).expect("block dir");
        std::fs::write(pipeline.join(PIPELINE_SIDECARS_DATA_FILE), b"genesis")
            .expect("pipeline data file");
        std::fs::write(
            pipeline.join(PIPELINE_SIDECARS_INDEX_FILE),
            vec![0u8; PIPELINE_INDEX_ENTRY_SIZE_U64 as usize],
        )
        .expect("pipeline index file");
        let snapshot = PeerStorageSnapshot::capture(storage.clone(), true);
        assert!(snapshot.store_exists);
        assert!(snapshot.has_block_1_artifact);
        assert!(
            snapshot
                .pipeline_entries
                .iter()
                .any(|entry| entry == PIPELINE_SIDECARS_DATA_FILE),
            "expected pipeline snapshot to include sidecar data file"
        );
    }
}
#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::process::Stdio;
    use tempfile::tempdir;
    use tokio::fs::File;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::process::Command;
    #[cfg(target_family = "unix")]
    #[tokio::test]
    async fn shutdown_prefers_sigterm_before_sigquit() {
        let dir = tempdir().expect("tempdir");
        let signal_log = dir.path().join("signals.log");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(
            r#": > "$SIGNAL_LOG"; trap 'echo SIGTERM >> "$SIGNAL_LOG"; exit 0' TERM; trap 'echo SIGQUIT >> "$SIGNAL_LOG"; exit 0' QUIT; while true; do sleep 1; done"#,
        );
        cmd.env("SIGNAL_LOG", &signal_log);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn signal trapper");
        let (events, _rx) = broadcast::channel(4);
        let (block_height, _rx) = watch::channel(None);
        let (_fatal_tx, fatal_rx) = watch::channel(false);
        let mut peer_exit = PeerExit {
            child,
            span: tracing::Span::none(),
            is_running: Arc::new(AtomicBool::new(true)),
            is_normal_shutdown_started: Arc::new(AtomicBool::new(false)),
            events,
            block_height,
            fatal_rx,
            stderr_log_ready: Arc::new(Notify::new()),
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _status = peer_exit
            .shutdown_or_kill()
            .await
            .expect("shutdown should complete");
        let log = std::fs::read_to_string(&signal_log).expect("read signal log");
        assert!(
            log.contains("SIGTERM"),
            "expected SIGTERM handler to run, log: {log:?}"
        );
        assert!(
            !log.contains("SIGQUIT"),
            "SIGQUIT should not be used for a responsive shutdown, log: {log:?}"
        );
    }
    #[tokio::test]
    async fn shutdown_treats_already_exited_child_as_graceful_completion() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("exit 0");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn short-lived child");
        let (events, _rx) = broadcast::channel(4);
        let (block_height, _rx) = watch::channel(None);
        let (_fatal_tx, fatal_rx) = watch::channel(false);
        let mut peer_exit = PeerExit {
            child,
            span: tracing::Span::none(),
            is_running: Arc::new(AtomicBool::new(true)),
            is_normal_shutdown_started: Arc::new(AtomicBool::new(false)),
            events,
            block_height,
            fatal_rx,
            stderr_log_ready: Arc::new(Notify::new()),
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let status = peer_exit
            .shutdown_or_kill()
            .await
            .expect("already-exited child should be handled cleanly");
        assert!(
            status.success(),
            "expected successful exit status, got {status:?}"
        );
    }
    #[tokio::test]
    async fn monitor_handles_shutdown_race_after_child_already_exited() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("exit 0");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn short-lived child");
        let (events, _rx) = broadcast::channel(4);
        let (block_height, _rx) = watch::channel(None);
        let (_fatal_tx, fatal_rx) = watch::channel(false);
        let stderr_log_ready = Arc::new(Notify::new());
        let peer_exit = PeerExit {
            child,
            span: tracing::Span::none(),
            is_running: Arc::new(AtomicBool::new(true)),
            is_normal_shutdown_started: Arc::new(AtomicBool::new(false)),
            events,
            block_height,
            fatal_rx,
            stderr_log_ready: Arc::clone(&stderr_log_ready),
            stderr_live: Arc::new(StdMutex::new(LiveStderrState::default())),
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            stderr_log_ready.notify_waiters();
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        shutdown_tx
            .send(())
            .expect("shutdown signal should be delivered");
        tokio::time::timeout(Duration::from_secs(1), peer_exit.monitor(shutdown_rx))
            .await
            .expect("peer monitor should complete")
            .expect("already-exited child should be treated as graceful during shutdown race");
    }
    #[tokio::test]
    async fn log_drain_exits_on_shutdown_notify() {
        let dir = tempdir().expect("tempdir");
        let log_path = dir.path().join("stdout.log");
        let file = File::create(&log_path).await.expect("create log file");
        let (mut writer, reader) = duplex(64);
        let (fatal_tx, fatal_rx) = watch::channel(false);
        let is_running = Arc::new(AtomicBool::new(true));
        let handle = tokio::spawn(drain_log_lines(
            reader,
            file,
            fatal_rx,
            is_running.clone(),
            |_| {},
            None,
            "stdout",
        ));
        writer.write_all(b"hello\n").await.expect("write line");
        writer.flush().await.expect("flush");
        is_running.store(false, Ordering::Relaxed);
        let _ = fatal_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("log task should exit")
            .expect("log task should not panic");
    }
}
#[cfg(test)]
mod sora_profile_tests {
    use super::*;
    #[test]
    fn sora_profile_detection_defaults_parse_with_bls_keys() {
        let (_peer_directory, _peer, defaults) = sora_profile_runtime_config_fixture(&[]);
        let config =
            iroha_config::parameters::actual::Root::from_toml_source(TomlSource::inline(defaults))
                .expect("sora profile detection defaults should parse");
        assert_eq!(
            config.genesis.expected_hash.to_string(),
            NON_RUNTIME_GENESIS_EXPECTED_HASH_BODY_FOR_CONFIG_PROJECTION,
            "profile detection must use only the marked non-runtime projection sentinel"
        );
        assert_eq!(
            config.streaming.key_material.identity().algorithm(),
            iroha_crypto::Algorithm::Ed25519
        );
        let trusted = config.common.trusted_peers.value();
        let myself_pk = trusted.myself.id().public_key().clone();
        let pop = trusted
            .pops
            .get(&myself_pk)
            .expect("sora profile default must provide PoP for self");
        iroha_crypto::bls_normal_pop_verify(&myself_pk, pop)
            .expect("sora profile default PoP should verify");
    }
    #[test]
    fn sora_profile_detection_overrides_streaming_identity_keys() {
        let mut streaming = Table::new();
        streaming.insert(
            "identity_public_key".into(),
            Value::String(SORA_PROFILE_BLS_PUBLIC_KEY.to_string()),
        );
        streaming.insert(
            "identity_private_key".into(),
            Value::String(SORA_PROFILE_BLS_PRIVATE_KEY.to_string()),
        );
        let mut layer = Table::new();
        layer.insert("streaming".into(), Value::Table(streaming));
        let (_peer_directory, _peer, merged) = sora_profile_runtime_config_fixture(&[layer]);
        let config =
            iroha_config::parameters::actual::Root::from_toml_source(TomlSource::inline(merged))
                .expect("merged sora profile detection config should parse");
        assert_eq!(
            config.streaming.key_material.identity().algorithm(),
            iroha_crypto::Algorithm::Ed25519
        );
    }
    #[test]
    fn sora_profile_detection_preserves_exact_supplied_pop_roster() {
        let other =
            checked_key_pair_from_seed(b"sora-profile-pop-merge".to_vec(), Algorithm::BlsNormal);
        let other_pop =
            iroha_crypto::bls_normal_pop_prove(other.private_key()).expect("BLS PoP generation");
        let other_pk = other.public_key().to_string();
        let mut pop_entry = Table::new();
        pop_entry.insert("public_key".into(), Value::String(other_pk.clone()));
        pop_entry.insert(
            "pop_hex".into(),
            Value::String(format!("0x{}", hex_lower(&other_pop))),
        );
        let supplied = vec![Value::Table(pop_entry)];
        let mut layer = Table::new();
        layer.insert("trusted_peers_pop".into(), Value::Array(supplied.clone()));
        let merged = merged_sora_profile_detection_config(&[layer]);
        let entries = merged
            .get("trusted_peers_pop")
            .and_then(Value::as_array)
            .expect("trusted_peers_pop array");
        assert_eq!(
            entries, &supplied,
            "profile detection must preserve the exact caller-owned roster without adding a voter"
        );
        iroha_crypto::bls_normal_pop_verify(other.public_key(), &other_pop)
            .expect("the preserved caller PoP remains valid");
    }
    #[test]
    fn sora_profile_detection_is_false_for_defaults() {
        assert!(!config_requires_sora_profile(&[Table::new()]));
    }
    #[test]
    fn sora_profile_detection_allows_empty_nexus_table_without_overrides() {
        let nexus = toml::map::Map::new();
        let mut table = Table::new();
        table.insert("nexus".into(), toml::Value::Table(nexus));
        assert!(!config_requires_sora_profile(&[table]));
    }
    #[test]
    fn sora_profile_detection_flags_nexus_lane_overrides() {
        let mut lane = toml::map::Map::new();
        lane.insert("alias".into(), toml::Value::String("lane0".into()));
        lane.insert("index".into(), toml::Value::Integer(0));
        let mut scheduler = toml::map::Map::new();
        scheduler.insert("teu_capacity".into(), toml::Value::Integer(262_144));
        lane.insert("scheduler".into(), toml::Value::Table(scheduler));
        let mut fusion = toml::map::Map::new();
        fusion.insert("floor_teu".into(), toml::Value::Integer(131_072));
        fusion.insert("exit_teu".into(), toml::Value::Integer(262_144));
        let mut audit = toml::map::Map::new();
        audit.insert("sample_size".into(), toml::Value::Integer(1));
        audit.insert("window_count".into(), toml::Value::Integer(1));
        audit.insert("interval_ms".into(), toml::Value::Integer(60_000));
        let mut da = toml::map::Map::new();
        da.insert("q_in_slot_total".into(), toml::Value::Integer(1));
        da.insert("q_in_slot_per_ds_min".into(), toml::Value::Integer(1));
        da.insert("sample_size_base".into(), toml::Value::Integer(1));
        da.insert("sample_size_max".into(), toml::Value::Integer(1));
        da.insert("threshold_base".into(), toml::Value::Integer(1));
        da.insert("per_attester_shards".into(), toml::Value::Integer(1));
        da.insert("audit".into(), toml::Value::Table(audit));
        let mut nexus = toml::map::Map::new();
        nexus.insert("lane_count".into(), toml::Value::Integer(1));
        nexus.insert(
            "lane_catalog".into(),
            toml::Value::Array(vec![toml::Value::Table(lane)]),
        );
        nexus.insert("fusion".into(), toml::Value::Table(fusion));
        nexus.insert("da".into(), toml::Value::Table(da));
        let mut table = Table::new();
        table.insert("nexus".into(), toml::Value::Table(nexus));
        assert!(config_requires_sora_profile(&[table]));
    }
    #[test]
    fn sora_profile_detection_ignores_default_routing_policy() {
        let mut policy = toml::map::Map::new();
        policy.insert("default_lane".into(), toml::Value::Integer(0));
        policy.insert(
            "default_dataspace".into(),
            toml::Value::String("universal".into()),
        );
        let mut nexus = toml::map::Map::new();
        nexus.insert("routing_policy".into(), toml::Value::Table(policy));
        let mut table = Table::new();
        table.insert("nexus".into(), toml::Value::Table(nexus));
        assert!(!config_requires_sora_profile(&[table]));
    }
    #[test]
    fn raw_nexus_overrides_ignores_default_routing_policy() {
        let mut policy = toml::map::Map::new();
        policy.insert(
            "default_lane".into(),
            toml::Value::Integer(i64::from(
                iroha_config::parameters::defaults::nexus::DEFAULT_ROUTING_LANE_INDEX,
            )),
        );
        policy.insert(
            "default_dataspace".into(),
            toml::Value::String(
                iroha_config::parameters::defaults::nexus::DEFAULT_DATASPACE_ALIAS.to_string(),
            ),
        );
        let mut nexus = toml::map::Map::new();
        nexus.insert("routing_policy".into(), toml::Value::Table(policy));
        let mut table = Table::new();
        table.insert("nexus".into(), toml::Value::Table(nexus));
        assert!(!typed_sora_profile_requirements(&table).expect("canonical default routing policy"));
    }
}
#[cfg(test)]
mod retry_backoff_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn retry_with_backoff_for_succeeds_before_timeout() {
        let attempts = AtomicUsize::new(0);
        let result = retry_with_backoff_for(Duration::from_millis(500), || {
            let count = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                if count < 2 {
                    Err::<usize, ()>(())
                } else {
                    Ok(count)
                }
            }
        })
        .await
        .expect("should not time out");
        assert!(result >= 2);
    }
    #[tokio::test]
    async fn retry_with_backoff_for_times_out() {
        let attempts = AtomicUsize::new(0);
        let result = retry_with_backoff_for(Duration::from_millis(75), || {
            let _ = attempts.fetch_add(1, Ordering::Relaxed);
            async move { Err::<(), ()>(()) }
        })
        .await;
        assert!(result.is_err());
        assert!(attempts.load(Ordering::Relaxed) > 0);
    }
}
