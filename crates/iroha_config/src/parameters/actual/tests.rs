#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus};
    use iroha_model_base::metadata::Metadata;

    #[test]
    fn mcp_inflight_dispatch_limit_default_is_nonzero() {
        assert_eq!(ToriiMcp::default().max_inflight_dispatches.get(), 32);
    }

    #[test]
    fn first_release_labels_are_exact_and_alias_free() {
        assert_eq!(LaneProfile::parse_label("core"), Some(LaneProfile::Core));
        assert_eq!(LaneProfile::parse_label("home"), Some(LaneProfile::Home));
        for label in ["CORE", " home", "unknown"] {
            assert_eq!(LaneProfile::parse_label(label), None, "{label:?}");
        }

        assert_eq!(GasLiquidity::from_str("tier1"), Ok(GasLiquidity::Tier1));
        for label in ["deep", "tier1-deep", "TIER1", " tier1"] {
            assert!(GasLiquidity::from_str(label).is_err(), "{label:?}");
        }
        assert_eq!(GasVolatility::from_str("stable"), Ok(GasVolatility::Stable));
        for label in ["calm", "STABLE", "stable "] {
            assert!(GasVolatility::from_str(label).is_err(), "{label:?}");
        }

        assert_eq!(NoritoRpcStage::parse("ga"), Some(NoritoRpcStage::Ga));
        for label in ["general", "general_availability", "GA", " ga"] {
            assert_eq!(NoritoRpcStage::parse(label), None, "{label:?}");
        }

        assert_eq!(
            ToriiMcpProfile::parse("read_only"),
            Some(ToriiMcpProfile::ReadOnly)
        );
        for label in ["readonly", "read-only", "write", "ops", "OPERATOR"] {
            assert_eq!(ToriiMcpProfile::parse(label), None, "{label:?}");
        }
    }

    #[test]
    #[should_panic(expected = "inrou.enabled requires soracloud_runtime.production_mode = true")]
    fn soracloud_actual_posture_rejects_nonproduction_inrou() {
        let mut runtime = SoracloudRuntime {
            production_mode: false,
            ..SoracloudRuntime::default()
        };
        runtime.inrou.enabled = true;
        runtime.inrou.portable_vm_uid = NonZeroU32::new(70_000);
        runtime.inrou.portable_vm_gid = NonZeroU32::new(70_000);
        runtime.inrou.trusted_guest_artifact = Some(SoraPublishedInrouGuestImageArtifactV1 {
            manifest_digest_hex: "31".repeat(32),
            content_cid: "bafyr6ibrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrgeytcmjrge".to_owned(),
        });

        runtime.assert_runtime_posture();
    }

    #[test]
    fn sora_profile_keeps_logical_lanes_in_the_universal_dataspace() {
        let lanes = sora_lane_catalog();
        let lane_bindings: Vec<_> = lanes
            .lanes()
            .iter()
            .map(|lane| (lane.alias.as_str(), lane.dataspace_id))
            .collect();
        assert_eq!(
            lane_bindings,
            [
                ("core", DataSpaceId::UNIVERSAL),
                ("governance", DataSpaceId::UNIVERSAL),
                ("zk", DataSpaceId::UNIVERSAL),
            ],
            "logical governance and zk lanes must not manufacture physical dataspaces"
        );

        let dataspaces = sora_dataspace_catalog();
        assert!(
            matches!(dataspaces.entries(), [entry]
                if entry.id == DataSpaceId::UNIVERSAL && entry.alias == "universal"),
            "the shared Sora profile should expose exactly the universal physical dataspace"
        );

        let routing = sora_routing_policy();
        assert!(
            routing.rules.iter().all(|rule| {
                matches!(rule.lane.as_u32(), 1 | 2)
                    && rule.dataspace == Some(DataSpaceId::UNIVERSAL)
            }),
            "governance and zk routing rules must select lanes within universal"
        );
    }

    #[test]
    fn nexus_consensus_policy_digest_is_stable_across_replayed_topology_progress() {
        let baseline = Nexus::default();
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid default policy");
        let mut progressed = baseline.clone();
        progressed.autoscale.last_transition_height = 42;
        progressed.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane bound"),
            vec![
                LaneConfigMetadata::default(),
                LaneConfigMetadata {
                    id: LaneId::new(1),
                    alias: "elastic-lane-1".to_owned(),
                    ..LaneConfigMetadata::default()
                },
            ],
        )
        .expect("valid progressed lane catalog");
        progressed.lane_config = LaneConfig::from_catalog(&progressed.lane_catalog);
        assert_eq!(
            nexus_consensus_policy_digest(&progressed).expect("valid progressed policy"),
            expected,
            "height-local topology progress must not lock a lagging peer out of block sync"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_keeps_configured_dataspaces_during_runtime_addition() {
        let baseline = Nexus::default();
        assert_eq!(
            baseline.configured_dataspace_catalog,
            baseline.dataspace_catalog
        );
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid baseline policy");
        let mut expanded = baseline.clone();
        expanded.dataspace_catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(8_648_377_547_929_788_715),
                alias: "bpng".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("valid committed dataspace addition");
        assert_eq!(
            expanded.configured_dataspace_catalog,
            baseline.dataspace_catalog
        );
        assert_eq!(
            nexus_consensus_policy_digest(&expanded).expect("valid expanded runtime policy"),
            expected,
            "committed runtime geometry does not rewrite the immutable execution policy"
        );
        expanded.configured_dataspace_catalog = expanded.dataspace_catalog.clone();
        assert_ne!(
            nexus_consensus_policy_digest(&expanded).expect("valid different configured policy"),
            expected,
            "a local baseline addition must remain execution-policy drift"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_binds_configured_lane_catalog() {
        let baseline = Nexus::default();
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid default policy");
        let mut different_genesis = baseline;
        different_genesis.configured_lane_catalog = LaneCatalog::new(
            NonZeroU32::new(2).expect("nonzero lane bound"),
            vec![
                LaneConfigMetadata::default(),
                LaneConfigMetadata {
                    id: LaneId::new(1),
                    alias: "configured-lane-1".to_owned(),
                    ..LaneConfigMetadata::default()
                },
            ],
        )
        .expect("valid configured lane catalog");
        assert_ne!(
            nexus_consensus_policy_digest(&different_genesis)
                .expect("valid different configured policy"),
            expected,
            "validators configured with different genesis lane catalogs must not share a policy digest"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_excludes_operational_paths_and_worker_timing() {
        let baseline = Nexus::default();
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid default policy");
        let mut operational_drift = baseline;
        operational_drift.registry.manifest_directory = Some(PathBuf::from("/srv/lane-manifests"));
        operational_drift.registry.cache_directory = Some(PathBuf::from("/var/cache/lanes"));
        operational_drift.registry.poll_interval = Duration::from_secs(17);
        operational_drift.relay_worker.retry_backoff = Duration::from_secs(9);
        operational_drift.compliance.policy_dir = Some(PathBuf::from("/srv/lane-policies"));
        assert_eq!(
            nexus_consensus_policy_digest(&operational_drift).expect("valid operational drift"),
            expected,
            "filesystem placement and local worker cadence must not partition validators"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_excludes_lane_operator_metadata() {
        let mut left = Nexus::default();
        let mut left_lane = LaneConfigMetadata {
            description: Some("left operator note".to_owned()),
            ..LaneConfigMetadata::default()
        };
        left_lane
            .metadata
            .insert("operator.owner".to_owned(), "left".to_owned());
        left.configured_lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane bound"),
            vec![left_lane],
        )
        .expect("valid configured catalog");

        let mut right = left.clone();
        let mut right_lane = right.configured_lane_catalog.lanes()[0].clone();
        right_lane.description = Some("right operator note".to_owned());
        right_lane
            .metadata
            .insert("operator.owner".to_owned(), "right".to_owned());
        right.configured_lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane bound"),
            vec![right_lane],
        )
        .expect("valid configured catalog");

        assert_eq!(
            nexus_consensus_policy_digest(&left).expect("valid left policy"),
            nexus_consensus_policy_digest(&right).expect("valid right policy"),
            "lane descriptions and operator metadata must not partition validators"
        );

        let mut functional = right;
        let mut functional_lane = functional.configured_lane_catalog.lanes()[0].clone();
        functional_lane.scheduler = Some(iroha_data_model::nexus::LaneSchedulerPolicy::new(
            Some(std::num::NonZeroU64::new(2048).expect("positive capacity")),
            None,
        ));
        functional.configured_lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane bound"),
            vec![functional_lane],
        )
        .expect("valid configured catalog");
        assert_ne!(
            nexus_consensus_policy_digest(&left).expect("valid left policy"),
            nexus_consensus_policy_digest(&functional).expect("valid functional policy"),
            "typed scheduler policy must partition validators"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_changes_for_each_decision_policy_family() {
        let baseline = Nexus::default();
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid default policy");
        let mut threshold_drift = baseline.clone();
        threshold_drift.autoscale.scale_out_latency_ratio = f64::from_bits(
            threshold_drift
                .autoscale
                .scale_out_latency_ratio
                .to_bits()
                .saturating_add(1),
        );
        assert_ne!(
            nexus_consensus_policy_digest(&threshold_drift).expect("valid threshold drift"),
            expected,
            "exact f64 policy bits must be committed"
        );
        let mut routing_drift = baseline.clone();
        routing_drift.routing_policy.rules.push(LaneRoutingRule {
            lane: LaneId::SINGLE,
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                instruction: Some("transfer".to_owned()),
                ..LaneRoutingMatcher::default()
            },
        });
        assert_ne!(
            nexus_consensus_policy_digest(&routing_drift).expect("valid routing drift"),
            expected
        );
        let mut staking_drift = baseline.clone();
        staking_drift.staking.min_validator_stake = staking_drift
            .staking
            .min_validator_stake
            .try_add(&Quantity::one())
            .expect("test stake remains representable");
        assert_ne!(
            nexus_consensus_policy_digest(&staking_drift).expect("valid staking drift"),
            expected
        );
        let mut committee_drift = baseline;
        committee_drift.endorsement.quorum = committee_drift.endorsement.quorum.saturating_add(1);
        assert_ne!(
            nexus_consensus_policy_digest(&committee_drift).expect("valid committee drift"),
            expected
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_changes_for_execution_and_da_policy_drift() {
        let baseline = Nexus::default();
        let expected = nexus_consensus_policy_digest(&baseline).expect("valid default policy");
        let mut dataspace_drift = baseline.clone();
        dataspace_drift.configured_dataspace_catalog =
            DataSpaceCatalog::new(vec![DataSpaceMetadata {
                fault_tolerance: 2,
                ..DataSpaceMetadata::default()
            }])
            .expect("valid dataspace committee drift");
        assert_ne!(
            nexus_consensus_policy_digest(&dataspace_drift).expect("valid dataspace drift"),
            expected,
            "dataspace fault tolerance changes the 3f+1 lane committee"
        );
        let mut dataspace_id_drift = baseline.clone();
        dataspace_id_drift.configured_dataspace_catalog =
            DataSpaceCatalog::new(vec![DataSpaceMetadata {
                id: DataSpaceId::new(7),
                ..DataSpaceMetadata::default()
            }])
            .expect("valid dataspace identifier catalog");
        assert_ne!(
            nexus_consensus_policy_digest(&dataspace_id_drift)
                .expect("digest does not perform cross-catalog validation"),
            expected,
            "dataspace identities used for committee lookup must be committed"
        );
        let mut fee_drift = baseline.clone();
        fee_drift.fees.per_byte_fee = Quantity::from(123_456_u32);
        assert_ne!(
            nexus_consensus_policy_digest(&fee_drift).expect("valid fee drift"),
            expected
        );
        let mut axt_drift = baseline.clone();
        axt_drift.axt.max_clock_skew_ms = axt_drift.axt.max_clock_skew_ms.saturating_add(1);
        assert_ne!(
            nexus_consensus_policy_digest(&axt_drift).expect("valid AXT drift"),
            expected
        );
        let mut commit_drift = baseline.clone();
        commit_drift.commit.window_slots =
            NonZeroU16::new(commit_drift.commit.window_slots.get().saturating_add(1))
                .expect("nonzero commit window");
        assert_ne!(
            nexus_consensus_policy_digest(&commit_drift).expect("valid commit drift"),
            expected
        );
        let mut da_drift = baseline;
        da_drift.da.sample_size_max =
            NonZeroU16::new(da_drift.da.sample_size_max.get().saturating_add(1))
                .expect("nonzero DA sample size");
        assert_ne!(
            nexus_consensus_policy_digest(&da_drift).expect("valid DA drift"),
            expected
        );
    }
    #[test]
    fn nexus_staking_work_bounds_are_signed_by_both_consensus_projections() {
        let baseline = Nexus::default();
        let baseline_policy =
            nexus_consensus_policy_digest(&baseline).expect("valid default Nexus policy");

        let mut share_bound_drift = baseline.clone();
        share_bound_drift.staking.max_stake_shares_per_validator = NonZeroU32::new(
            share_bound_drift
                .staking
                .max_stake_shares_per_validator
                .get()
                + 1,
        )
        .expect("incremented share bound stays non-zero");
        let mut pending_bound_drift = baseline;
        pending_bound_drift.staking.max_pending_unbonds_per_share = NonZeroU32::new(
            pending_bound_drift
                .staking
                .max_pending_unbonds_per_share
                .get()
                + 1,
        )
        .expect("incremented pending-unbond bound stays non-zero");

        for (label, changed) in [
            ("stake-share bound", share_bound_drift),
            ("pending-unbond bound", pending_bound_drift),
        ] {
            assert_ne!(
                nexus_consensus_policy_digest(&changed).expect("valid changed Nexus policy"),
                baseline_policy,
                "{label} must change the canonical Nexus policy digest"
            );
        }
    }
    #[test]
    fn nexus_consensus_policy_digest_canonicalizes_dataspace_catalog_order() {
        let universal = DataSpaceMetadata::default();
        let settlement = DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "settlement".to_owned(),
            description: None,
            fault_tolerance: 2,
        };
        let left = Nexus {
            configured_dataspace_catalog: DataSpaceCatalog::new(vec![
                universal.clone(),
                settlement.clone(),
            ])
            .expect("valid dataspace catalog"),
            ..Nexus::default()
        };
        let mut right = left.clone();
        right.configured_dataspace_catalog = DataSpaceCatalog::new(vec![settlement, universal])
            .expect("valid reordered dataspace catalog");
        assert_eq!(
            nexus_consensus_policy_digest(&left).expect("valid left policy"),
            nexus_consensus_policy_digest(&right).expect("valid right policy"),
            "catalog iteration order is not a committee policy input"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_uses_typed_endorsement_committee_set() {
        let first = KeyPair::try_from_seed(vec![0x41; 32], Algorithm::Ed25519)
            .expect("derive first committee key")
            .public_key()
            .clone();
        let second = KeyPair::try_from_seed(vec![0x42; 32], Algorithm::Ed25519)
            .expect("derive second committee key")
            .public_key()
            .clone();
        let mut left = Nexus::default();
        left.endorsement.committee_keys =
            BTreeSet::from([second.clone(), first.clone(), first.clone()]);
        left.endorsement.quorum = 2;
        let mut right = left.clone();
        right.endorsement.committee_keys = BTreeSet::from([first.clone(), second]);

        assert_eq!(
            nexus_consensus_policy_digest(&left).expect("valid left policy"),
            nexus_consensus_policy_digest(&right).expect("valid right policy"),
            "the typed endorsement committee set has one canonical policy projection"
        );

        let replacement = KeyPair::try_from_seed(vec![0x43; 32], Algorithm::Ed25519)
            .expect("derive replacement committee key")
            .public_key()
            .clone();
        right.endorsement.committee_keys = BTreeSet::from([first, replacement]);
        assert_ne!(
            nexus_consensus_policy_digest(&left).expect("valid left policy"),
            nexus_consensus_policy_digest(&right).expect("valid changed policy"),
            "changing the canonical endorsement committee set must change the policy digest"
        );
    }
    #[test]
    fn nexus_consensus_policy_digest_rejects_non_finite_autoscale_ratio() {
        let mut nexus = Nexus::default();
        nexus.autoscale.scale_in_utilization_ratio = f64::NAN;
        assert!(matches!(
            nexus_consensus_policy_digest(&nexus),
            Err(NexusConsensusPolicyDigestError::InvalidRatio {
                field: "nexus.autoscale.scale_in_utilization_ratio",
                ..
            })
        ));
    }
    #[test]
    fn nexus_consensus_policy_digest_requires_and_binds_loaded_compliance_policy_set() {
        let mut nexus = Nexus::default();
        nexus.compliance.enabled = true;
        assert_eq!(
            nexus_consensus_policy_digest(&nexus),
            Err(NexusConsensusPolicyDigestError::MissingCompliancePolicyDigest)
        );
        let left = nexus_consensus_policy_digest_with_compliance(&nexus, Some([0x11; 32]))
            .expect("bound compliance policy set");
        let right = nexus_consensus_policy_digest_with_compliance(&nexus, Some([0x12; 32]))
            .expect("bound compliance policy set");
        assert_ne!(left, right);
    }
    #[test]
    fn nexus_consensus_policy_digest_binds_loaded_lane_manifest_policy_set() {
        let nexus = Nexus::default();
        let left =
            nexus_consensus_policy_digest_with_runtime_policies(&nexus, None, Some([0x21; 32]))
                .expect("bound lane manifest policy set");
        let right =
            nexus_consensus_policy_digest_with_runtime_policies(&nexus, None, Some([0x22; 32]))
                .expect("bound lane manifest policy set");
        assert_ne!(left, right);
    }
    #[test]
    fn nexus_policy_preimage_is_exact_digest_source_under_ambient_layout_changes() {
        const DOMAIN: &[u8] = b"iroha:nexus:consensus-policy:v1\0";
        let nexus = Nexus::default();
        let compliance = None;
        let manifests = Some([0x31; 32]);
        let preimage =
            nexus_consensus_policy_preimage_with_runtime_policies(&nexus, compliance, manifests)
                .expect("canonical Nexus preimage");
        let digest =
            nexus_consensus_policy_digest_with_runtime_policies(&nexus, compliance, manifests)
                .expect("Nexus digest");
        assert_eq!(
            digest,
            <[u8; 32]>::from(Hash::new_from_chunks(&[DOMAIN, preimage.as_slice()]))
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(
            nexus_consensus_policy_preimage_with_runtime_policies(&nexus, compliance, manifests)
                .expect("ambient-independent preimage"),
            preimage
        );
        assert_eq!(
            nexus_consensus_policy_digest_with_runtime_policies(&nexus, compliance, manifests)
                .expect("ambient-independent digest"),
            digest
        );
    }
    fn execution_policy_hash(config: &Root) -> [u8; 32] {
        execution_policy_digest_v1(
            &config.pipeline,
            &config.oracle,
            &config.crypto,
            &config.fraud_monitoring,
            &config.gov,
            &config.content,
            &config.settlement,
            [0x11; 32],
            [0x22; 32],
        )
    }
    #[test]
    fn execution_policy_digest_binds_every_process_local_decision_family() {
        let baseline = super::sora_profile_tests::minimal_root();
        let expected = execution_policy_hash(&baseline);
        let assert_changed = |label: &str, changed: Root| {
            assert_ne!(
                execution_policy_hash(&changed),
                expected,
                "{label} must change the execution-policy identity"
            );
        };
        let mut changed = baseline.clone();
        changed.pipeline.overlay_max_bytes = changed.pipeline.overlay_max_bytes.saturating_add(1);
        assert_changed("pipeline validity policy", changed);
        let mut changed = baseline.clone();
        changed.crypto.default_hash.push_str("-different");
        assert_changed("cryptographic admission policy", changed);
        let mut changed = baseline.clone();
        changed.oracle.history_depth =
            NonZeroUsize::new(changed.oracle.history_depth.get().saturating_add(1))
                .expect("nonzero history depth");
        assert_changed("oracle execution policy", changed);
        let mut changed = baseline.clone();
        changed.fraud_monitoring.enabled = !changed.fraud_monitoring.enabled;
        assert_changed("fraud admission policy", changed);
        let mut changed = baseline.clone();
        changed.gov.plain_voting_enabled = !changed.gov.plain_voting_enabled;
        assert_changed("governance execution policy", changed);
        let mut changed = baseline.clone();
        changed.gov.max_active_referenda =
            NonZeroU32::new(changed.gov.max_active_referenda.get().saturating_add(1))
                .expect("incremented referendum cap remains nonzero");
        assert_changed("active-referendum cardinality policy", changed);
        let mut changed = baseline.clone();
        changed.gov.max_lock_owners_per_referendum = NonZeroU32::new(
            changed
                .gov
                .max_lock_owners_per_referendum
                .get()
                .saturating_add(1),
        )
        .expect("incremented lock-owner cap remains nonzero");
        assert_changed("per-referendum lock-owner cardinality policy", changed);
        let mut changed = baseline.clone();
        changed.gov.parliament_sortition_pulse_delay_blocks = changed
            .gov
            .parliament_sortition_pulse_delay_blocks
            .saturating_add(1);
        assert_changed("Parliament sortition pulse-delay policy", changed);
        let mut changed = baseline.clone();
        changed.gov.parliament_timed_ovn.release_delay_blocks = changed
            .gov
            .parliament_timed_ovn
            .release_delay_blocks
            .saturating_add(1);
        assert_changed("Parliament timed-OVN height policy", changed);
        let mut changed = baseline.clone();
        changed.gov.parliament_timed_ovn.opening_phase_blocks = changed
            .gov
            .parliament_timed_ovn
            .opening_phase_blocks
            .saturating_add(1);
        assert_changed("Parliament timed-OVN opening policy", changed);
        let mut changed = baseline.clone();
        changed.gov.parliament_public_finding_phase_blocks = changed
            .gov
            .parliament_public_finding_phase_blocks
            .saturating_add(1);
        assert_changed("Parliament public-finding deadline policy", changed);
        let mut changed = baseline.clone();
        changed.gov.sorafs_pin_policy.max_global_manifests = changed
            .gov
            .sorafs_pin_policy
            .max_global_manifests
            .saturating_add(1);
        assert_changed("SoraFS pin resource policy", changed);
        let mut changed = baseline.clone();
        changed.content.max_files = changed.content.max_files.saturating_add(1);
        assert_changed("content admission policy", changed);
        let mut changed = baseline;
        changed.settlement.router.epsilon_bps =
            changed.settlement.router.epsilon_bps.saturating_add(1);
        assert_changed("settlement execution policy", changed);
        let fixed = super::sora_profile_tests::minimal_root();
        for (label, nexus, zk) in [
            ("Nexus runtime policy", [0x12; 32], [0x22; 32]),
            ("ZK runtime policy", [0x11; 32], [0x23; 32]),
        ] {
            assert_ne!(
                execution_policy_digest_v1(
                    &fixed.pipeline,
                    &fixed.oracle,
                    &fixed.crypto,
                    &fixed.fraud_monitoring,
                    &fixed.gov,
                    &fixed.content,
                    &fixed.settlement,
                    nexus,
                    zk,
                ),
                execution_policy_hash(&fixed),
                "{label} must change the execution-policy identity"
            );
        }
    }

    #[test]
    fn execution_policy_digest_binds_every_oracle_economics_field() {
        let baseline = super::sora_profile_tests::minimal_root();
        let expected = execution_policy_hash(&baseline);
        let alternate_asset = AssetDefinitionId::derive_from_components(
            DomainId::parse_fully_qualified("security.audit")
                .expect("valid alternate asset domain"),
            Name::from_str("alternate").expect("valid alternate asset name"),
        );
        let alternate_account = baseline.oracle.economics.slash_receiver.clone();
        assert_ne!(
            alternate_account, baseline.oracle.economics.reward_pool,
            "the default protocol custody accounts must remain distinct"
        );

        let assert_changed = |label: &str, changed: Root| {
            assert_ne!(
                execution_policy_hash(&changed),
                expected,
                "oracle economics field `{label}` must change the execution-policy identity"
            );
        };
        let add_one = |value: &Quantity| {
            value
                .try_add(&Quantity::one())
                .expect("test quantity remains representable")
        };

        let mut changed = baseline.clone();
        changed.oracle.economics.reward_asset = alternate_asset.clone();
        assert_changed("reward_asset", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.reward_pool = alternate_account.clone();
        assert_changed("reward_pool", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.reward_amount = add_one(&changed.oracle.economics.reward_amount);
        assert_changed("reward_amount", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.slash_asset = alternate_asset.clone();
        assert_changed("slash_asset", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.slash_receiver = baseline.oracle.economics.reward_pool.clone();
        assert_changed("slash_receiver", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.slash_outlier_amount =
            add_one(&changed.oracle.economics.slash_outlier_amount);
        assert_changed("slash_outlier_amount", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.slash_error_amount =
            add_one(&changed.oracle.economics.slash_error_amount);
        assert_changed("slash_error_amount", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.slash_no_show_amount =
            add_one(&changed.oracle.economics.slash_no_show_amount);
        assert_changed("slash_no_show_amount", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.dispute_bond_asset = alternate_asset;
        assert_changed("dispute_bond_asset", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.dispute_bond_amount =
            add_one(&changed.oracle.economics.dispute_bond_amount);
        assert_changed("dispute_bond_amount", changed);
        let mut changed = baseline.clone();
        changed.oracle.economics.dispute_reward_amount =
            add_one(&changed.oracle.economics.dispute_reward_amount);
        assert_changed("dispute_reward_amount", changed);
        let mut changed = baseline;
        changed.oracle.economics.frivolous_slash_amount =
            add_one(&changed.oracle.economics.frivolous_slash_amount);
        assert_changed("frivolous_slash_amount", changed);
    }
    #[test]
    fn execution_policy_digest_excludes_only_result_preserving_operational_drift() {
        let mut baseline = super::sora_profile_tests::minimal_root();
        baseline.fraud_monitoring.missing_assessment_grace = Duration::from_secs(1);
        let expected = execution_policy_hash(&baseline);
        let mut operational = baseline;
        operational.pipeline.workers = operational.pipeline.workers.saturating_add(1);
        operational.pipeline.parallel_overlay = !operational.pipeline.parallel_overlay;
        operational.pipeline.parallel_apply = !operational.pipeline.parallel_apply;
        operational.pipeline.gpu_key_bucket = !operational.pipeline.gpu_key_bucket;
        operational.pipeline.cache_size = operational.pipeline.cache_size.saturating_add(1);
        operational.pipeline.ivm_prover_threads =
            operational.pipeline.ivm_prover_threads.saturating_add(1);
        operational.pipeline.signature_batch_max_ed25519 = operational
            .pipeline
            .signature_batch_max_ed25519
            .saturating_add(1);
        operational.pipeline.debug_trace_tx_eval = !operational.pipeline.debug_trace_tx_eval;
        operational.crypto.enable_sm_openssl_preview =
            !operational.crypto.enable_sm_openssl_preview;
        operational.fraud_monitoring.request_timeout += Duration::from_millis(1);
        operational.fraud_monitoring.missing_assessment_grace += Duration::from_secs(1);
        operational.gov.alias_frontier_telemetry = !operational.gov.alias_frontier_telemetry;
        operational.gov.debug_trace_pipeline = !operational.gov.debug_trace_pipeline;
        operational.content.limits.max_requests_per_second = NonZeroU32::new(
            operational
                .content
                .limits
                .max_requests_per_second
                .get()
                .saturating_add(1),
        )
        .expect("nonzero gateway limit");
        operational.content.pow.difficulty_bits =
            operational.content.pow.difficulty_bits.saturating_add(1);
        assert_eq!(
            execution_policy_hash(&operational),
            expected,
            "worker, cache, accelerator, tracing, transport, and gateway drift must not partition validators"
        );
    }
    #[test]
    fn viral_incentives_default_survives_chain_override() {
        let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(777);
        let defaults = ViralIncentives::default();
        assert_eq!(
            defaults.incentive_pool_account,
            crate::parameters::defaults::governance::slash_receiver_account_id()
        );
        assert_eq!(
            defaults.escrow_account,
            crate::parameters::defaults::governance::slash_receiver_account_id()
        );
    }
    #[test]
    fn sorafs_telemetry_policy_default_has_no_implicit_submitters() {
        let _chain = iroha_data_model::account::address::ChainDiscriminantGuard::enter(777);
        let defaults = SorafsTelemetryPolicy::default();
        assert!(defaults.submitters.is_empty());
    }
    #[test]
    fn sumeragi_default_nexus_amx_hash_is_stable() {
        assert_eq!(
            Nexus::default().staking.stake_asset_id,
            Nexus::default().fees.fee_asset_id,
            "recommended staking custody and fees must use the canonical XOR asset",
        );
        let hash =
            sumeragi_nexus_amx_context_hash(&Nexus::default(), &Pipeline::default(), &[], &[]);
        assert_eq!(
            hex::encode(hash.as_ref()),
            "b8c9897f84a0fd3162c821e06afdd659466c3ca3193d7853b76e819e840d2a4b",
        );
        assert_eq!(
            <[u8; 32]>::from(hash),
            iroha_data_model::block::consensus::RECOMMENDED_NEXUS_AMX_CONTEXT_HASH,
            "data-model genesis defaults must track the canonical config projection",
        );
        assert_eq!(
            sumeragi_nexus_amx_context_hash_with_catalog_policy(
                &Nexus::default(),
                &Pipeline::default(),
                &[],
                &[],
                None,
            ),
            hash,
            "absence of a committed catalog policy preserves the original context projection"
        );
    }
    #[test]
    fn sumeragi_nexus_amx_hash_binds_committed_catalog_policy() {
        let nexus = Nexus::default();
        let pipeline = Pipeline::default();
        let baseline = sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &[]);
        let root = Hash::new(b"first committed catalog with exact four-validator manifest");
        let changed_root = Hash::new(b"changed committed manifest authority");
        let committed = sumeragi_nexus_amx_context_hash_with_catalog_policy(
            &nexus,
            &pipeline,
            &[],
            &[],
            Some(root),
        );
        assert_ne!(
            committed, baseline,
            "the authorization root is consensus-relevant"
        );
        assert_ne!(
            committed,
            sumeragi_nexus_amx_context_hash_with_catalog_policy(
                &nexus,
                &pipeline,
                &[],
                &[],
                Some(changed_root),
            ),
            "same geometry with different manifest policy cannot share a height context"
        );
        let mut changed_geometry = nexus.clone();
        changed_geometry.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
            fault_tolerance: 2,
            ..DataSpaceMetadata::default()
        }])
        .expect("valid changed geometry");
        assert_ne!(
            committed,
            sumeragi_nexus_amx_context_hash_with_catalog_policy(
                &changed_geometry,
                &pipeline,
                &[],
                &[],
                Some(root),
            ),
            "the committed root supplements the complete effective geometry projection"
        );
    }
    #[test]
    fn sumeragi_nexus_amx_hash_canonicalizes_dataspace_catalog_order() {
        let universal = DataSpaceMetadata::default();
        let settlement = DataSpaceMetadata {
            id: DataSpaceId::new(7),
            alias: "settlement".to_owned(),
            description: Some("settlement dataspace".to_owned()),
            fault_tolerance: 2,
        };
        let left = Nexus {
            dataspace_catalog: DataSpaceCatalog::new(vec![universal.clone(), settlement.clone()])
                .expect("valid dataspace catalog"),
            ..Nexus::default()
        };
        let mut right = left.clone();
        right.dataspace_catalog = DataSpaceCatalog::new(vec![settlement, universal])
            .expect("valid reordered dataspace catalog");

        assert_eq!(
            sumeragi_nexus_amx_context_hash(&left, &Pipeline::default(), &[], &[]),
            sumeragi_nexus_amx_context_hash(&right, &Pipeline::default(), &[], &[]),
            "dataspace catalog iteration order must not affect the signed Nexus/AMX commitment"
        );
    }
    #[test]
    fn sumeragi_nexus_amx_hash_excludes_operator_descriptions() {
        let mut left = Nexus::default();
        let mut left_lane = LaneConfigMetadata {
            description: Some("left lane note".to_owned()),
            ..LaneConfigMetadata::default()
        };
        left_lane
            .metadata
            .insert("operator.owner".to_owned(), "left".to_owned());
        left.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane bound"),
            vec![left_lane],
        )
        .expect("valid lane catalog");
        let mut left_dataspace = left
            .dataspace_catalog
            .entries()
            .first()
            .expect("default dataspace")
            .clone();
        left_dataspace.description = Some("left operator note".to_owned());
        left.dataspace_catalog =
            DataSpaceCatalog::new(vec![left_dataspace]).expect("valid dataspace catalog");
        left.routing_policy.rules = vec![LaneRoutingRule {
            lane: LaneId::SINGLE,
            dataspace: Some(DataSpaceId::UNIVERSAL),
            matcher: LaneRoutingMatcher {
                description: Some("left routing note".to_owned()),
                ..LaneRoutingMatcher::default()
            },
        }];

        let mut right = left.clone();
        let mut right_lane = right.lane_catalog.lanes()[0].clone();
        right_lane.description = Some("right lane note".to_owned());
        right_lane
            .metadata
            .insert("operator.owner".to_owned(), "right".to_owned());
        right.lane_catalog = LaneCatalog::new(
            NonZeroU32::new(1).expect("non-zero lane bound"),
            vec![right_lane],
        )
        .expect("valid lane catalog");
        let mut right_dataspace = right
            .dataspace_catalog
            .entries()
            .first()
            .expect("configured dataspace")
            .clone();
        right_dataspace.description = Some("right operator note".to_owned());
        right.dataspace_catalog =
            DataSpaceCatalog::new(vec![right_dataspace]).expect("valid dataspace catalog");
        right.routing_policy.rules[0].matcher.description = Some("right routing note".to_owned());

        assert_eq!(
            sumeragi_nexus_amx_context_hash(&left, &Pipeline::default(), &[], &[]),
            sumeragi_nexus_amx_context_hash(&right, &Pipeline::default(), &[], &[]),
            "operator-only lane/dataspace descriptions, lane metadata, and routing descriptions must not affect consensus"
        );
    }
    #[test]
    fn sumeragi_nexus_amx_hash_canonicalizes_fee_exempt_authorities() {
        let authority = |seed| {
            AccountId::new(
                KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                    .expect("deterministic fee-exempt authority key")
                    .public_key()
                    .clone(),
            )
        };
        let authority_a = authority(1);
        let authority_b = authority(2);
        let authority_c = authority(3);
        let mut left = Nexus::default();
        left.fees.successful_claim_fee_exempt_authorities = BTreeSet::from([
            authority_b.clone(),
            authority_a.clone(),
            authority_a.clone(),
        ]);
        let mut right = left.clone();
        right.fees.successful_claim_fee_exempt_authorities =
            BTreeSet::from([authority_a, authority_b]);

        assert_eq!(
            sumeragi_nexus_amx_context_hash(&left, &Pipeline::default(), &[], &[]),
            sumeragi_nexus_amx_context_hash(&right, &Pipeline::default(), &[], &[]),
            "set order and duplicate entries must not affect the signed Nexus/AMX commitment"
        );

        right.fees.successful_claim_fee_exempt_authorities = BTreeSet::from([authority_c]);
        assert_ne!(
            sumeragi_nexus_amx_context_hash(&left, &Pipeline::default(), &[], &[]),
            sumeragi_nexus_amx_context_hash(&right, &Pipeline::default(), &[], &[]),
            "changing the canonical authority set must change the signed commitment"
        );
    }
    fn test_active_validator(seed: u8, lane: LaneId) -> GenesisActiveNexusLaneRecord {
        let peer = PeerId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic BLS test key")
                .public_key()
                .clone(),
        );
        let validator = AccountId::new(peer.public_key().clone());
        let record = PublicLaneValidatorRecord {
            lane_id: lane,
            validator: validator.clone(),
            peer_id: peer,
            stake_account: validator.clone(),
            total_stake: iroha_primitives::numeric::Quantity::from(10_u64),
            self_stake: iroha_primitives::numeric::Quantity::from(10_u64),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
            last_reward_epoch: None,
        };
        ((lane, validator), record)
    }
    #[test]
    fn sumeragi_nexus_amx_hash_binds_every_projection_category() {
        let nexus = Nexus::default();
        let pipeline = Pipeline::default();
        let baseline = sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &[]);
        let assert_nexus_change = |label: &str, changed: Nexus| {
            assert_ne!(
                baseline,
                sumeragi_nexus_amx_context_hash(&changed, &pipeline, &[], &[]),
                "{label} must change the signed Nexus/AMX commitment"
            );
        };
        let mut changed = nexus.clone();
        changed.lane_catalog = sora_lane_catalog();
        assert_nexus_change("lane catalog", changed);
        let mut changed = nexus.clone();
        let mut dataspace = changed.dataspace_catalog.entries()[0].clone();
        dataspace.fault_tolerance = dataspace.fault_tolerance.saturating_add(1);
        changed.dataspace_catalog =
            DataSpaceCatalog::new(vec![dataspace]).expect("valid changed dataspace catalog");
        assert_nexus_change("dataspace catalog", changed);
        let mut changed = nexus.clone();
        changed.routing_policy.default_lane = LaneId::new(1);
        assert_nexus_change("routing policy", changed);
        let mut changed = nexus.clone();
        changed.staking.min_validator_stake = changed
            .staking
            .min_validator_stake
            .try_add(&Quantity::one())
            .expect("test stake remains representable");
        assert_nexus_change("staking policy", changed);
        let mut changed = nexus.clone();
        changed.fees.sponsor_vault_custody_account_id = AccountId::new(
            KeyPair::try_from_seed(vec![0xF5; 32], Algorithm::Ed25519)
                .expect("deterministic sponsor vault test key")
                .public_key()
                .clone(),
        );
        assert_nexus_change("fee sponsor vault custody", changed);
        let mut changed = nexus.clone();
        changed.dataspace_fee_sponsor_program_ids.insert(
            DataSpaceId::UNIVERSAL,
            FeeSponsorProgramId::new(
                changed.fees.sponsor_vault_custody_account_id.clone(),
                "default".parse().expect("valid sponsor program name"),
            ),
        );
        assert_nexus_change("dataspace sponsor program", changed);
        let mut changed = nexus.clone();
        changed.axt.max_clock_skew_ms += 1;
        assert_nexus_change("AXT policy", changed);
        let mut changed = nexus.clone();
        changed.fusion.floor_teu += 1;
        assert_nexus_change("lane fusion policy", changed);
        let mut changed = nexus.clone();
        changed.autoscale.enabled = !changed.autoscale.enabled;
        assert_nexus_change("lane autoscale policy", changed);
        let mut changed = nexus.clone();
        changed.commit.window_slots = NonZeroU16::new(changed.commit.window_slots.get() + 1)
            .expect("incremented window stays non-zero");
        assert_nexus_change("commit policy", changed);
        let mut changed = nexus.clone();
        changed.da.q_in_slot_total = NonZeroU32::new(changed.da.q_in_slot_total.get() + 1)
            .expect("incremented DA budget stays non-zero");
        assert_nexus_change("DA sampling policy", changed);
        let mut changed = nexus.clone();
        changed.da.ingest_quota_window_blocks =
            NonZeroU64::new(changed.da.ingest_quota_window_blocks.get() + 1)
                .expect("incremented DA quota window stays non-zero");
        assert_nexus_change("DA ingest quota policy", changed);
        let mut changed = nexus.clone();
        changed.da.audit.interval += Duration::from_nanos(1);
        assert_nexus_change("DA audit policy", changed);
        let mut changed = nexus.clone();
        changed.da.recovery.request_timeout += Duration::from_nanos(1);
        assert_nexus_change("DA recovery policy", changed);
        let mut changed = nexus.clone();
        changed.da.rotation.seed_tag.push('x');
        assert_nexus_change("DA rotation policy", changed);
        let mut changed_pipeline = pipeline.clone();
        changed_pipeline.amx_per_instruction_ns += 1;
        assert_ne!(
            baseline,
            sumeragi_nexus_amx_context_hash(&nexus, &changed_pipeline, &[], &[]),
            "deterministic AMX budgets must change the signed commitment"
        );
        let active = [test_active_validator(0xA1, LaneId::SINGLE)];
        assert_ne!(
            baseline,
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &active, &[]),
            "staged active validators must change the signed commitment"
        );
        let lifecycle = [SumeragiLaneLifecycleEntry {
            lane_id: LaneId::SINGLE,
            generation: 0,
            incarnation: Hash::new(b"sumeragi-test-incarnation"),
            activation_height: 7,
        }];
        assert_ne!(
            baseline,
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &lifecycle),
            "lane lifecycle history must change the signed commitment"
        );
        let mut changed_generation = lifecycle;
        changed_generation[0].generation += 1;
        assert_ne!(
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &lifecycle),
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &changed_generation),
            "retained lane generation must be committed independently of the current catalog"
        );
        let mut changed_lifecycle = lifecycle;
        changed_lifecycle[0].activation_height += 1;
        assert_ne!(
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &lifecycle),
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &changed_lifecycle),
            "activation height must be committed independently of the current catalog"
        );
        let retained_with_retired_lane = [
            lifecycle[0],
            SumeragiLaneLifecycleEntry {
                lane_id: LaneId::new(7),
                generation: 3,
                incarnation: Hash::new(b"retired-lane-incarnation"),
                activation_height: 11,
            },
        ];
        assert_ne!(
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &lifecycle),
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &[], &retained_with_retired_lane,),
            "retired lane lineage must remain committed after catalog removal"
        );
    }
    #[test]
    fn sumeragi_nexus_amx_hash_canonicalizes_validator_and_lineage_order() {
        let nexus = Nexus::default();
        let pipeline = Pipeline::default();
        let first = test_active_validator(0xA2, LaneId::new(1));
        let second = test_active_validator(0xA3, LaneId::SINGLE);
        let forward = [first.clone(), second.clone()];
        let reverse = [second, first];
        assert_eq!(
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &forward, &[]),
            sumeragi_nexus_amx_context_hash(&nexus, &pipeline, &reverse, &[]),
        );
        let first_lifecycle = SumeragiLaneLifecycleEntry {
            lane_id: LaneId::new(1),
            generation: 2,
            incarnation: Hash::new(b"first-lifecycle"),
            activation_height: 3,
        };
        let second_lifecycle = SumeragiLaneLifecycleEntry {
            lane_id: LaneId::SINGLE,
            generation: 0,
            incarnation: Hash::new(b"second-lifecycle"),
            activation_height: 0,
        };
        assert_eq!(
            sumeragi_nexus_amx_context_hash(
                &nexus,
                &pipeline,
                &[],
                &[first_lifecycle, second_lifecycle],
            ),
            sumeragi_nexus_amx_context_hash(
                &nexus,
                &pipeline,
                &[],
                &[second_lifecycle, first_lifecycle],
            ),
            "retained lane-lineage input order must not affect the context commitment"
        );
    }
}
#[cfg(test)]
mod sora_profile_tests {
    use super::*;
    use iroha_config_base::toml::TomlSource;
    use iroha_data_model::nexus::{LaneCatalog, LaneConfig as LaneConfigMetadata};
    use std::num::NonZeroU32;
    use toml::Table;
    const MINIMAL_CONFIG: &str = r#"
chain = "00000000-0000-0000-0000-000000000000"
public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2"
private_key = "8926201CA347641228C3B79AA43839DEDC85FA51C0E8B9B6A00F6B0D6B0423E902973F"
soranet_transport_public_key = "ed0120D9F6AEF1813164294D1D9C0662FEB9C7F7861B4DFFE385680331093DA4ABD10B"
soranet_transport_private_key = "802620134C4527B3852AE2218A8F079B301C651EAD8C7567B96BD7A9BE8DB366E46B89"
trusted_peers_pop = [
  { public_key = "ea01309060D021340617E9554CCBC2CF3CC3DB922A9BA323ABDF7C271FCC6EF69BE7A8DEBCA7D9E96C0F0089ABA22CDAADE4A2", pop_hex = "8515da750f81182aaba5c22fc9f03a01e81ed85e4495a2ca6b29a71c0c8549537e31e79cddf6ff285b9e22d0d9dc17ce0f46e7d0cf78b2ef9feab50c849a1ea8e1e4f07e966f6113faa8a999317545d9f111b8e08a7273913710b43a20b19c08" }
]

[network]
address = "addr:127.0.0.1:1337#8F78"
public_address = "addr:127.0.0.1:1337#8F78"

[torii]
address = "addr:127.0.0.1:8080#8942"

[genesis]
public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
expected_hash = "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"

[streaming]
identity_public_key = "ed01208BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB"
identity_private_key = "8026208F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F"
"#;
    pub(super) fn minimal_root() -> Root {
        let table: Table = toml::from_str(MINIMAL_CONFIG).expect("parse minimal config table");
        Root::from_toml_source(TomlSource::inline(table)).expect("load minimal config")
    }
    fn minimal_root_with_sorafs_admission() -> Root {
        let config = format!(
            r"{MINIMAL_CONFIG}

[sorafs.discovery.admission]
enabled = true
"
        );
        let table: Table = toml::from_str(&config).expect("parse config with SoraFS admission");
        Root::from_toml_source(TomlSource::inline(table))
            .expect("load config with valid SoraFS admission")
    }
    include!("sora_profile_discovery_disabled_test.rs");
    include!("sora_profile_runtime_tests.rs");
}
