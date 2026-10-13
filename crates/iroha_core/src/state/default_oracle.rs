fn default_oracle() -> iroha_config::parameters::actual::Oracle {
    iroha_config::parameters::actual::Oracle {
        history_depth: iroha_config::parameters::defaults::oracle::history_depth(),
        economics: iroha_config::parameters::actual::OracleEconomics {
            reward_asset: iroha_config::parameters::defaults::oracle::reward_asset(),
            reward_pool: iroha_config::parameters::defaults::oracle::reward_pool(),
            reward_amount: iroha_config::parameters::defaults::oracle::reward_amount(),
            slash_asset: iroha_config::parameters::defaults::oracle::slash_asset(),
            slash_receiver: iroha_config::parameters::defaults::oracle::slash_receiver(),
            slash_outlier_amount: iroha_config::parameters::defaults::oracle::slash_outlier_amount(
            ),
            slash_error_amount: iroha_config::parameters::defaults::oracle::slash_error_amount(),
            slash_no_show_amount: iroha_config::parameters::defaults::oracle::slash_no_show_amount(
            ),
            dispute_bond_asset: iroha_config::parameters::defaults::oracle::dispute_bond_asset(),
            dispute_bond_amount: iroha_config::parameters::defaults::oracle::dispute_bond_amount(),
            dispute_reward_amount:
                iroha_config::parameters::defaults::oracle::dispute_reward_amount(),
            frivolous_slash_amount:
                iroha_config::parameters::defaults::oracle::frivolous_slash_amount(),
        },
        governance: iroha_config::parameters::actual::OracleGovernance {
            intake_sla_blocks: iroha_config::parameters::defaults::oracle::intake_sla_blocks(),
            rules_sla_blocks: iroha_config::parameters::defaults::oracle::rules_sla_blocks(),
            cop_sla_blocks: iroha_config::parameters::defaults::oracle::cop_sla_blocks(),
            technical_sla_blocks: iroha_config::parameters::defaults::oracle::technical_sla_blocks(
            ),
            policy_jury_sla_blocks:
                iroha_config::parameters::defaults::oracle::policy_jury_sla_blocks(),
            enact_sla_blocks: iroha_config::parameters::defaults::oracle::enact_sla_blocks(),
            intake_min_votes: iroha_config::parameters::defaults::oracle::intake_min_votes(),
            rules_min_votes: iroha_config::parameters::defaults::oracle::rules_min_votes(),
            cop_min_votes: iroha_config::parameters::actual::OracleChangeThresholds {
                low: iroha_config::parameters::defaults::oracle::cop_low_votes(),
                medium: iroha_config::parameters::defaults::oracle::cop_medium_votes(),
                high: iroha_config::parameters::defaults::oracle::cop_high_votes(),
            },
            technical_min_votes: iroha_config::parameters::defaults::oracle::technical_min_votes(),
            policy_jury_min_votes: iroha_config::parameters::actual::OracleChangeThresholds {
                low: iroha_config::parameters::defaults::oracle::policy_jury_low_votes(),
                medium: iroha_config::parameters::defaults::oracle::policy_jury_medium_votes(),
                high: iroha_config::parameters::defaults::oracle::policy_jury_high_votes(),
            },
        },
        twitter_binding: iroha_config::parameters::actual::OracleTwitterBinding {
            feed_id: iroha_config::parameters::defaults::oracle::twitter_binding_feed_id(),
            pepper_id: iroha_config::parameters::defaults::oracle::twitter_binding_pepper_id(),
            max_ttl_ms: iroha_config::parameters::defaults::oracle::twitter_binding_max_ttl_ms(),
            min_ttl_ms: iroha_config::parameters::defaults::oracle::twitter_binding_min_ttl_ms(),
            min_update_spacing_ms:
                iroha_config::parameters::defaults::oracle::twitter_binding_min_update_spacing_ms(),
        },
    }
}
fn default_content_cfg() -> iroha_config::parameters::actual::Content {
    iroha_config::parameters::actual::Content {
        max_bundle_bytes: iroha_config::parameters::defaults::content::MAX_BUNDLE_BYTES,
        max_files: iroha_config::parameters::defaults::content::MAX_FILES,
        max_path_len: iroha_config::parameters::defaults::content::MAX_PATH_LEN,
        max_retention_blocks: iroha_config::parameters::defaults::content::MAX_RETENTION_BLOCKS,
        chunk_size_bytes: iroha_config::parameters::defaults::content::CHUNK_SIZE_BYTES,
        publish_allow_accounts: Vec::new(),
        limits: iroha_config::parameters::actual::ContentLimits {
            max_requests_per_second: nonzero!(
                iroha_config::parameters::defaults::content::MAX_REQUESTS_PER_SECOND
            ),
            request_burst: nonzero!(iroha_config::parameters::defaults::content::REQUEST_BURST),
            max_egress_bytes_per_second: NonZeroU64::new(u64::from(
                iroha_config::parameters::defaults::content::MAX_EGRESS_BYTES_PER_SECOND,
            ))
            .expect("default egress limit nonzero"),
            egress_burst_bytes: NonZeroU64::new(
                iroha_config::parameters::defaults::content::EGRESS_BURST_BYTES,
            )
            .expect("default egress burst nonzero"),
        },
        default_cache_max_age_secs:
            iroha_config::parameters::defaults::content::DEFAULT_CACHE_MAX_AGE_SECS,
        max_cache_max_age_secs: iroha_config::parameters::defaults::content::MAX_CACHE_MAX_AGE_SECS,
        immutable_bundles: iroha_config::parameters::defaults::content::IMMUTABLE_BUNDLES,
        default_auth_mode: iroha_data_model::content::ContentAuthMode::Public,
        slo: iroha_config::parameters::actual::ContentSlo {
            target_p50_latency_ms: nonzero!(
                iroha_config::parameters::defaults::content::TARGET_P50_LATENCY_MS
            ),
            target_p99_latency_ms: nonzero!(
                iroha_config::parameters::defaults::content::TARGET_P99_LATENCY_MS
            ),
            target_availability_bps: nonzero!(
                iroha_config::parameters::defaults::content::TARGET_AVAILABILITY_BPS
            ),
        },
        pow: iroha_config::parameters::actual::ContentPow {
            difficulty_bits: iroha_config::parameters::defaults::content::POW_DIFFICULTY_BITS,
            header_name: iroha_config::parameters::defaults::content::default_pow_header(),
        },
        stripe_layout: iroha_config::parameters::defaults::content::default_stripe_layout(),
    }
}
fn default_fraud_monitoring_cfg() -> iroha_config::parameters::actual::FraudMonitoring {
    iroha_config::parameters::actual::FraudMonitoring::new(
        Vec::new(),
        iroha_config::parameters::defaults::fraud_monitoring::CONNECT_TIMEOUT,
        iroha_config::parameters::defaults::fraud_monitoring::REQUEST_TIMEOUT,
    )
}
