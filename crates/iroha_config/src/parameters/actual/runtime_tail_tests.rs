#[test]
fn sorafs_site_binding_defaults_are_disabled_and_bounded() {
    let config = SorafsGatewaySiteBindings::default();
    assert_eq!(config.path, None);
    assert_eq!(config.max_bytes.get(), 1024 * 1024);
    assert_eq!(config.max_sites.get(), 1024);
}
#[test]
fn streaming_codec_default_entropy_mode_matches_build_flag() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let codec = StreamingCodec::from_defaults();
    assert_eq!(codec.entropy_mode, EntropyMode::RansBundled);
}
#[test]
fn streaming_default_entropy_string_tracks_build_flag() {
    assert!(
        norito::streaming::BUNDLED_RANS_BUILD_AVAILABLE,
        "Bundled rANS must be compiled in for the first release; rebuild with ENABLE_RANS_BUNDLES=1"
    );
    let default = defaults::streaming::codec::entropy_mode();
    assert_eq!(
        default,
        defaults::streaming::codec::BUNDLED_ENTROPY_MODE,
        "string helper should mirror bundled availability"
    );
}
#[test]
fn soranet_pow_defaults_are_const_initializable() {
    const CONST_POW: SoranetPow = SoranetPow::default_const();
    const CONST_PUZZLE: SoranetPuzzle = SoranetPuzzle::default_const();
    let runtime = SoranetPow::default();
    assert_eq!(
        runtime.difficulty,
        iroha_crypto::soranet::puzzle::DEFAULT_DIFFICULTY
    );
    assert_ne!(runtime.difficulty, 0);
    assert_eq!(CONST_POW.difficulty, runtime.difficulty);
    assert_eq!(CONST_POW.max_future_skew, runtime.max_future_skew);
    assert_eq!(CONST_POW.min_ticket_ttl, runtime.min_ticket_ttl);
    assert_eq!(CONST_POW.ticket_ttl, runtime.ticket_ttl);
    assert_eq!(
        CONST_POW.revocation_store_capacity,
        runtime.revocation_store_capacity
    );
    assert_eq!(CONST_POW.revocation_max_ttl, runtime.revocation_max_ttl);
    assert_eq!(
        CONST_POW.revocation_store_path,
        runtime.revocation_store_path
    );
    assert_eq!(CONST_POW.puzzle, runtime.puzzle);
    let runtime_puzzle = runtime.puzzle;
    assert_eq!(CONST_PUZZLE.memory_kib, runtime_puzzle.memory_kib);
    assert_eq!(CONST_PUZZLE.time_cost, runtime_puzzle.time_cost);
    assert_eq!(CONST_PUZZLE.lanes, runtime_puzzle.lanes);
}
#[test]
fn no_trusted_peers() {
    let value = TrustedPeers {
        myself: dummy_peer(80),
        others: unique_vec![],
        pops: std::collections::BTreeMap::default(),
    };
    assert!(!value.contains_other_trusted_peers());
}
#[test]
fn one_trusted_peer() {
    let value = TrustedPeers {
        myself: dummy_peer(80),
        others: unique_vec![dummy_peer(81)],
        pops: std::collections::BTreeMap::default(),
    };
    assert!(value.contains_other_trusted_peers());
}
#[test]
fn many_trusted_peers() {
    let value = TrustedPeers {
        myself: dummy_peer(80),
        others: unique_vec![dummy_peer(1), dummy_peer(2), dummy_peer(3), dummy_peer(4),],
        pops: std::collections::BTreeMap::default(),
    };
    assert!(value.contains_other_trusted_peers());
}
#[test]
fn telemetry_profile_predicates_match_expectations() {
    assert!(!TelemetryProfile::Disabled.metrics_enabled());
    assert!(!TelemetryProfile::Disabled.expensive_metrics_enabled());
    assert!(!TelemetryProfile::Disabled.developer_outputs_enabled());
    assert!(TelemetryProfile::Operator.metrics_enabled());
    assert!(!TelemetryProfile::Operator.expensive_metrics_enabled());
    assert!(!TelemetryProfile::Operator.developer_outputs_enabled());
    assert!(TelemetryProfile::Extended.metrics_enabled());
    assert!(TelemetryProfile::Extended.expensive_metrics_enabled());
    assert!(!TelemetryProfile::Extended.developer_outputs_enabled());
    assert!(TelemetryProfile::Developer.metrics_enabled());
    assert!(!TelemetryProfile::Developer.expensive_metrics_enabled());
    assert!(TelemetryProfile::Developer.developer_outputs_enabled());
    assert!(TelemetryProfile::Full.metrics_enabled());
    assert!(TelemetryProfile::Full.expensive_metrics_enabled());
    assert!(TelemetryProfile::Full.developer_outputs_enabled());
}
#[test]
fn telemetry_profile_from_user_enum_round_trips() {
    use super::user;
    assert_eq!(
        TelemetryProfile::from(user::TelemetryProfile::Disabled),
        TelemetryProfile::Disabled
    );
    assert_eq!(
        TelemetryProfile::from(user::TelemetryProfile::Operator),
        TelemetryProfile::Operator
    );
    assert_eq!(
        TelemetryProfile::from(user::TelemetryProfile::Extended),
        TelemetryProfile::Extended
    );
    assert_eq!(
        TelemetryProfile::from(user::TelemetryProfile::Developer),
        TelemetryProfile::Developer
    );
    assert_eq!(
        TelemetryProfile::from(user::TelemetryProfile::Full),
        TelemetryProfile::Full
    );
}
#[test]
fn fraud_monitoring_new_dedup_and_defaults() {
    use url::Url;
    let url = Url::parse("https://risk.example/api").expect("url");
    let cfg = FraudMonitoring::new(
        vec![url.clone(), url.clone()],
        Duration::from_millis(0),
        Duration::from_millis(0),
    );
    assert_eq!(cfg.service_endpoints.len(), 1);
    assert_eq!(cfg.service_endpoints[0], url);
    assert_eq!(
        cfg.connect_timeout,
        defaults::fraud_monitoring::CONNECT_TIMEOUT
    );
    assert_eq!(
        cfg.request_timeout,
        defaults::fraud_monitoring::REQUEST_TIMEOUT
    );
    assert!(!cfg.policy.missing_assessment_permitted);
    assert!(cfg.policy.required_minimum_band.is_none());
    assert!(!cfg.policy.enabled);
    assert!(cfg.policy.attesters.is_empty());
}
#[test]
fn fraud_monitoring_default_matches_defaults() {
    let cfg = FraudMonitoring::default();
    assert!(!cfg.policy.enabled);
    assert!(cfg.service_endpoints.is_empty());
    assert_eq!(
        cfg.connect_timeout,
        defaults::fraud_monitoring::CONNECT_TIMEOUT
    );
    assert_eq!(
        cfg.request_timeout,
        defaults::fraud_monitoring::REQUEST_TIMEOUT
    );
    assert!(!cfg.policy.missing_assessment_permitted);
    assert!(cfg.policy.required_minimum_band.is_none());
    assert!(cfg.policy.attesters.is_empty());
}
#[test]
fn lane_config_derives_display_and_cache_labels() {
    let catalog = LaneCatalog::new(
        NonZeroU32::new(2).expect("nonzero lane count"),
        vec![
            LaneConfigMetadata::default(),
            LaneConfigMetadata {
                id: LaneId::new(1),
                alias: "Public Lane ①".to_string(),
                lane_type: Some("default_public".to_string()),
                governance: Some("parliament".to_string()),
                ..LaneConfigMetadata::default()
            },
        ],
    )
    .expect("catalog");
    let config = LaneConfig::from_catalog(&catalog);
    let entries = config.entries();
    assert_eq!(entries.len(), 2);
    let default_entry = config.entry(LaneId::SINGLE).expect("default lane exists");
    assert_eq!(default_entry.alias, "default");
    assert_eq!(default_entry.slug, "default");
    assert_eq!(default_entry.kura_segment, "lane_000_default");
    assert_eq!(default_entry.merge_segment, "lane_000_default_merge");
    assert_eq!(
        default_entry.lane_id,
        LaneId::SINGLE,
        "display/cache labels retain the configured route identity"
    );
    assert_eq!(
        default_entry.key_prefix,
        LaneId::SINGLE.as_u32().to_be_bytes()
    );
    assert_eq!(default_entry.dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(default_entry.visibility, LaneVisibility::Public);
    assert_eq!(
        default_entry.storage_profile,
        LaneStorageProfile::FullReplica
    );
    let public_entry = config.entry(LaneId::new(1)).expect("lane 1 exists");
    assert_eq!(public_entry.alias, "Public Lane ①");
    assert_eq!(public_entry.slug, "public_lane");
    assert_eq!(public_entry.kura_segment, "lane_001_public_lane");
    assert_eq!(public_entry.merge_segment, "lane_001_public_lane_merge");
    assert_eq!(
        public_entry.lane_id,
        LaneId::new(1),
        "alias normalization cannot change the configured route identity"
    );
    assert_eq!(
        public_entry.key_prefix,
        LaneId::new(1).as_u32().to_be_bytes()
    );
    assert_eq!(public_entry.dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(public_entry.visibility, LaneVisibility::Public);
    assert_eq!(
        public_entry.storage_profile,
        LaneStorageProfile::FullReplica
    );
}
