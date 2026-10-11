#[cfg(all(test, feature = "telemetry"))]
mod tests {
    use super::{sorafs_capacity_tests::build_por_challenge, *};
    use http::StatusCode;
    use http_body_util::BodyExt;
    use iroha_core::{kura::Kura, query::store::LiveQueryStore, state::World};
    use iroha_crypto::Algorithm;
    use iroha_data_model::{
        block::BlockHeader,
        events::{
            EventBox,
            pipeline::{BlockEvent, BlockStatus},
        },
    };
    use iroha_telemetry::metrics::Metrics;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    #[test]
    fn openapi_handler_emits_alias_spec() {
        Runtime::new().expect("runtime").block_on(async {
            let app = crate::mk_app_state_for_tests();
            let response = super::handler_openapi_spec(State(app)).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect body")
                .to_bytes();
            let doc: norito::json::Value =
                norito::json::from_slice(body.as_ref()).expect("decode openapi spec");
            let paths = doc
                .get("paths")
                .and_then(norito::json::Value::as_object)
                .expect("paths section");
            assert!(!paths.contains_key("/v1/aliases/voprf/evaluate"));
            assert!(paths.contains_key("/v1/aliases/resolve"));
            assert!(paths.contains_key("/v1/aliases/resolve-index"));
        });
    }
    #[tokio::test]
    async fn status_response_bounds_unavailable_fresh_block_counter_sync() {
        let metrics = Arc::new(Metrics::default());
        metrics.block_height.inc_by(4_193);
        let telemetry = MaybeTelemetry::from_profile(
            Some(Telemetry::new(metrics, true)),
            TelemetryProfile::Full,
        );
        let error = super::handle_status(
            &crate::build_identity_test_fixture::build_identity().status(),
            &telemetry,
            Some(axum::http::HeaderValue::from_static("application/json")),
        )
        .await
        .expect_err("an unavailable telemetry actor must fail status retriably");
        assert!(matches!(
            error,
            Error::AppServiceUnavailable {
                code: "status_metrics_unavailable",
                ..
            }
        ));
    }
    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn status_root_includes_effective_nexus_routing_policy() {
        use http_body_util::BodyExt;
        let policy = ActualLaneRoutingPolicy {
            default_lane: LaneId::new(0),
            default_dataspace: DataSpaceId::UNIVERSAL,
            rules: vec![iroha_config::parameters::actual::LaneRoutingRule {
                lane: LaneId::new(3),
                dataspace: Some(DataSpaceId::new(6647857470246403404)),
                matcher: iroha_config::parameters::actual::LaneRoutingMatcher {
                    account: None,
                    instruction: Some("smartcontract::deploy".into()),
                    description: Some("Route contract deployments to private is".into()),
                },
            }],
        };
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        let private_id = DataSpaceId::new(6647857470246403404);
        nexus.dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
            iroha_data_model::nexus::DataSpaceMetadata::default(),
            iroha_data_model::nexus::DataSpaceMetadata {
                id: private_id,
                alias: "private-status".into(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("status dataspace catalog");
        let lanes = (0..4)
            .map(|id| iroha_data_model::nexus::LaneConfig {
                id: LaneId::new(id),
                alias: format!("status-lane-{id}"),
                dataspace_id: if id == 3 {
                    private_id
                } else {
                    DataSpaceId::UNIVERSAL
                },
                ..Default::default()
            })
            .collect();
        nexus.lane_catalog =
            iroha_data_model::nexus::LaneCatalog::new(nonzero_ext::nonzero!(4u32), lanes)
                .expect("status lane catalog");
        nexus.configured_lane_catalog = nexus.lane_catalog.clone();
        nexus.routing_policy = policy;
        let telemetry = MaybeTelemetry::for_tests_with_nexus(Some(nexus));
        let response = super::handle_status(
            &crate::build_identity_test_fixture::build_identity().status(),
            &telemetry,
            Some(axum::http::HeaderValue::from_static("application/json")),
        )
        .await
        .expect("status succeeds");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let payload: norito::json::Value =
            norito::json::from_slice(&body).expect("decode status payload");
        assert_eq!(
            payload.get("build"),
            Some(
                &norito::json::to_value(
                    &crate::build_identity_test_fixture::build_identity().status()
                )
                .expect("encode owning executable status")
            )
        );
        let rules = payload
            .get("nexus")
            .and_then(|nexus| nexus.get("routing_policy"))
            .and_then(|routing| routing.get("rules"))
            .and_then(norito::json::Value::as_array)
            .expect("routing rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("lane").and_then(norito::json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            rules[0]
                .get("dataspace_id")
                .and_then(norito::json::Value::as_u64),
            Some(6647857470246403404)
        );
        assert_eq!(
            rules[0]
                .get("matcher")
                .and_then(|matcher| matcher.get("instruction"))
                .and_then(norito::json::Value::as_str),
            Some("smartcontract::deploy")
        );
    }
    #[tokio::test]
    async fn status_exact_probes_return_independent_json_scalars() {
        let metrics = Arc::new(Metrics::default());
        metrics.block_height.inc_by(4_193);
        let telemetry = MaybeTelemetry::from_profile(
            Some(Telemetry::new(metrics, true)),
            TelemetryProfile::Full,
        );
        for (response, expected) in [
            (
                super::handle_status_blocks(&telemetry, 4_274)
                    .expect("block-height probe succeeds without a telemetry sync"),
                4_274,
            ),
            (
                super::handle_status_peers(&telemetry, 7)
                    .expect("peer-count probe succeeds without a telemetry sync"),
                7,
            ),
        ] {
            assert_eq!(
                response.headers().get(axum::http::header::CONTENT_TYPE),
                Some(&axum::http::HeaderValue::from_static("application/json"))
            );
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect exact status response")
                .to_bytes();
            let value: u64 = norito::json::from_slice(&body).expect("decode status scalar");
            assert_eq!(value, expected);
        }
    }
    #[cfg(feature = "telemetry")]
    #[tokio::test]
    async fn metrics_handler_exports_lane_labels() {
        let telemetry = MaybeTelemetry::for_tests();
        telemetry
            .metrics()
            .await
            .set_lane_block_height("lane-0", "global", 3);
        let rendered = super::handle_metrics(&telemetry)
            .await
            .expect("metrics should render");
        assert!(
            rendered.contains("nexus_lane_block_height"),
            "lane metrics are part of every first-release Nexus exposition"
        );
    }
    #[tokio::test]
    async fn sumeragi_status_is_unavailable_before_the_instance_starts() {
        let response = super::handle_v1_sumeragi_status(None, None)
            .await
            .expect("status handler");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    #[tokio::test]
    async fn sumeragi_status_serves_the_instance_status_as_json() {
        let key = iroha_crypto::KeyPair::from_seed(vec![9; 32], iroha_crypto::Algorithm::BlsNormal)
            .public_key()
            .clone();
        let expected = iroha_data_model::sumeragi::SumeragiStatus {
            protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: iroha_crypto::Hash::new(b"native Torii diagnostic configuration"),
            beacon_horizon: None,
            instance: [1; 32],
            height: 42,
            view: 3,
            stage: 1,
            leader: Some(key.clone()),
            proxy_tail: Some(key.clone()),
            high_qc_view: Some(2),
            level: 1,
            start_level: 0,
            t_retx_ms: 250,
            committed_height: 41,
            applied_height: 41,
            awaiting: false,
            signer: Some(key),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: iroha_data_model::sumeragi::SumeragiFootprint {
                votes: 0,
                timeouts: 0,
                blocks: 1,
                exec_entries: 1,
                wants: 0,
                pending_apply: 0,
                sync_entries: 0,
                sync_bytes: 0,
                peers: 4,
                recent_headers: 8,
                configs: 3,
                cert_cache: 0,
                evidence_keys: 0,
                probe: 0,
            },
        };
        let response = super::handle_v1_sumeragi_status(
            Some(axum::http::HeaderValue::from_static("application/json")),
            Some(expected.clone()),
        )
        .await
        .expect("status handler");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect status body")
            .to_bytes();
        let decoded: iroha_data_model::sumeragi::SumeragiStatus =
            norito::json::from_slice(&body).expect("decode status");
        assert_eq!(decoded, expected);
    }
    #[tokio::test]
    async fn permissioned_sumeragi_diagnostics_omit_npos_and_canonical_state() {
        let kura = Kura::blank_kura_for_testing();
        let state = std::sync::Arc::new(CoreState::new_for_testing(
            World::default(),
            Arc::clone(&kura),
            LiveQueryStore::start_test(),
        ));
        let queue = Arc::new(Queue::from_config(
            iroha_config::parameters::actual::Queue::default(),
            tokio::sync::broadcast::channel(1).0,
        ));
        let response = super::handle_v1_sumeragi_diagnostics(
            axum::extract::State(Arc::clone(&state)),
            Some(queue),
            Some(axum::http::HeaderValue::from_static("application/json")),
        )
        .await
        .expect("diagnostics handler");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect diagnostics body")
            .to_bytes();
        let decoded: SumeragiDiagnosticsStatus =
            norito::json::from_slice(&body).expect("decode diagnostics");
        assert!(decoded.npos.is_none());
        assert_eq!(decoded.tx_queue_depth, 0);
        assert!(!decoded.tx_queue_saturated);
        let json: norito::json::Value =
            norito::json::from_slice(&body).expect("decode diagnostics JSON object");
        assert!(json.get("npos").is_none());
        for retired in [
            "lane_commitments",
            "dataspace_commitments",
            "pipeline_execution",
            "lane_relay_envelopes",
            "native_amx_participant_applications",
            "autonomous_lane_executions",
        ] {
            assert!(
                json.get(retired).is_none(),
                "retired diagnostic owner must not reappear"
            );
        }
        for canonical in ["height", "view", "phase", "leader", "locked_prepare_qc"] {
            assert!(
                json.get(canonical).is_none(),
                "leaked canonical field {canonical}"
            );
        }
    }
    #[tokio::test]
    async fn sumeragi_diagnostics_require_the_live_queue_owner() {
        let state = Arc::new(CoreState::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ));
        let error = super::handle_v1_sumeragi_diagnostics(
            axum::extract::State(state),
            None,
            Some(axum::http::HeaderValue::from_static("application/json")),
        )
        .await
        .expect_err("missing queue cannot be represented as an empty queue");
        assert!(matches!(
            error,
            Error::AppServiceUnavailable {
                code: "transaction_queue_unavailable",
                ..
            }
        ));
        assert_eq!(
            error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn sumeragi_diagnostics_report_live_queue_pressure_and_committed_age_budget() {
        use iroha_core::{
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
            tx::AcceptedTransaction,
        };
        use iroha_data_model::prelude::{Account, AccountId, Level, Log, TransactionBuilder};

        let key = iroha_crypto::KeyPair::from_seed(vec![0x7D; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let chain = CertifiedTestChain::start(TestChainConfig::new(world, 1))
            .expect("original signed genesis");
        let state = Arc::clone(chain.state());
        let config = iroha_config::parameters::actual::Queue {
            capacity: std::num::NonZeroUsize::new(1).unwrap(),
            ..Default::default()
        };
        let queue = Arc::new(Queue::from_config(
            config,
            tokio::sync::broadcast::channel(1).0,
        ));
        let transaction = TransactionBuilder::new(
            *state.network_id_ref(),
            authority,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(Level::INFO, "live diagnostics".to_owned())])
        .sign(key.private_key());
        let accepted = AcceptedTransaction::accept(
            transaction,
            state.network_id_ref(),
            Duration::from_secs(5),
            iroha_data_model::parameter::TransactionParameters::default(),
            state.crypto().as_ref(),
        )
        .expect("original signed transaction passes envelope admission");
        queue
            .push(accepted, state.view())
            .expect("queue real admitted work");
        let _ = queue.backdate_queued_transactions_for_tests(Duration::from_secs(3_600));
        let before = queue.set_pressure_age_budget_for_tests(Duration::from_secs(7_200));
        assert!(!before.saturated_by_age, "deliberately stale local budget");
        let response = super::handle_v1_sumeragi_diagnostics(
            axum::extract::State(Arc::clone(&state)),
            Some(Arc::clone(&queue)),
            Some(axum::http::HeaderValue::from_static("application/json")),
        )
        .await
        .expect("diagnostics handler");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let decoded: SumeragiDiagnosticsStatus = norito::json::from_slice(&body).unwrap();
        assert_eq!(decoded.tx_queue_depth, 1);
        assert_eq!(decoded.tx_queue_capacity, 1);
        assert_eq!(decoded.tx_queue_retained_bytes, before.retained_bytes);
        assert!(decoded.tx_queue_retained_bytes > 0);
        assert_eq!(
            decoded.tx_queue_max_retained_bytes,
            before.max_retained_bytes.get()
        );
        assert!(decoded.tx_queue_saturated);
        assert!(decoded.tx_queue_saturated_by_count);
        assert!(!decoded.tx_queue_saturated_by_bytes);
        assert!(
            decoded.tx_queue_saturated_by_age,
            "handler refreshes the committed cadence budget"
        );
        assert!(decoded.tx_queue_oldest_queued_age_ms >= 3_600_000);
    }
    #[test]
    fn npos_diagnostics_refusal_retries_the_original_policy() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiNposParameters},
        };
        let mut config = TestChainConfig::new(World::new(), 1_000);
        config.consensus_mode = SumeragiConsensusMode::Npos;
        config.genesis_parameters.push(Parameter::Custom(
            SumeragiNposParameters::default().into_custom_parameter(),
        ));
        let chain = CertifiedTestChain::start(config).expect("original signed NPoS genesis");
        let view = chain.state().view();
        let original = view
            .world()
            .parameters()
            .custom()
            .get(&SumeragiNposParameters::parameter_id())
            .unwrap();
        let bytes = original.payload().get().to_owned();
        let expected = super::sumeragi_npos_diagnostics(view.world())
            .unwrap()
            .unwrap();
        let refused = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
            || super::sumeragi_npos_diagnostics(view.world()),
        );
        assert!(matches!(
            refused,
            Err(Error::Query(iroha_data_model::ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::GasBudgetExceeded
            )))
        ));
        assert_eq!(original.payload().get(), &bytes);
        let retry = super::sumeragi_npos_diagnostics(view.world())
            .unwrap()
            .unwrap();
        assert_eq!(retry.epoch_seed, expected.epoch_seed);
        assert_eq!(retry.epoch_length_blocks, expected.epoch_length_blocks);
        assert_eq!(original.payload().get(), &bytes);
    }
    #[test]
    fn malformed_npos_diagnostics_are_rejected() {
        use iroha_core::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
        use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};

        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("original signed genesis");
        let proposal = chain.proposal(Some(2_000), vec![]);
        let mut block = chain.state().block(proposal.header());
        let zero_seed = SumeragiNposParameters {
            epoch_seed: [0; 32],
            ..Default::default()
        };
        let invalid_windows = SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(10).expect("non-zero epoch length"),
            ..Default::default()
        };
        for invalid in [zero_seed, invalid_windows] {
            let mut tx = block.transaction();
            tx.world
                .parameters_mut_for_testing()
                .get_mut()
                .set_parameter(Parameter::Custom(invalid.into_custom_parameter()));
            let error = super::sumeragi_npos_diagnostics(&tx.world)
                .expect_err("malformed original NPoS policy must remain terminal");
            assert!(
                matches!(
                    error,
                    Error::Query(iroha_data_model::ValidationFail::InternalError(_))
                ),
                "{error:?}"
            );
        }
    }
    #[tokio::test]
    async fn status_accept_header_returns_codec_norito() {
        let telemetry = MaybeTelemetry::for_tests();
        let expected = telemetry
            .metrics()
            .await
            .status_snapshot(&crate::build_identity_test_fixture::build_identity().status());
        let response = super::handle_status(
            &crate::build_identity_test_fixture::build_identity().status(),
            &telemetry,
            Some(axum::http::HeaderValue::from_static(
                crate::utils::NORITO_MIME_TYPE,
            )),
        )
        .await
        .expect("status handler");
        assert_eq!(
            response.headers().get(axum::http::header::CONTENT_TYPE),
            Some(&axum::http::HeaderValue::from_static(
                crate::utils::NORITO_MIME_TYPE
            ))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let decoded: Status = norito::decode_from_bytes(&body).expect("decode Norito status");
        assert_eq!(
            norito::json::to_value(&decoded.build).expect("encode decoded executable status"),
            norito::json::to_value(&expected.build).expect("encode expected executable status"),
        );
        assert_eq!(decoded.blocks, expected.blocks);
        assert_eq!(decoded.blocks_non_empty, expected.blocks_non_empty);
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn committed_block_height_detects_commits() {
        use std::num::NonZeroU64;
        let header = BlockHeader {
            height: NonZeroU64::new(7).unwrap(),
            prev_block_hash: None,
            merkle_root: None,
            da_proof_policies_hash: None,
            da_commitments_hash: None,
            da_pin_intents_hash: None,
            npos_effects_hash: None,
            global_beacon_pulse_hash: None,
            execution_context_hash: None,
            creation_time_ms: 0,
            view_change_index: 0,
            confidential_features: None,
        };
        let committed: EventBox = BlockEvent {
            header,
            status: BlockStatus::Committed,
        }
        .into();
        assert_eq!(super::committed_block_height(&committed), Some(7));
        let committed_batch = EventBox::PipelineBatch(vec![PipelineEventBox::from(BlockEvent {
            header: BlockHeader {
                height: NonZeroU64::new(7).unwrap(),
                prev_block_hash: None,
                merkle_root: None,
                da_proof_policies_hash: None,
                da_commitments_hash: None,
                da_pin_intents_hash: None,
                npos_effects_hash: None,
                global_beacon_pulse_hash: None,
                execution_context_hash: None,
                creation_time_ms: 0,
                view_change_index: 0,
                confidential_features: None,
            },
            status: BlockStatus::Committed,
        })]);
        assert_eq!(super::committed_block_height(&committed_batch), Some(7));
        let created_header = BlockHeader {
            height: NonZeroU64::new(3).unwrap(),
            prev_block_hash: None,
            merkle_root: None,
            da_proof_policies_hash: None,
            da_commitments_hash: None,
            da_pin_intents_hash: None,
            npos_effects_hash: None,
            global_beacon_pulse_hash: None,
            execution_context_hash: None,
            creation_time_ms: 0,
            view_change_index: 0,
            confidential_features: None,
        };
        let created: EventBox = BlockEvent {
            header: created_header,
            status: BlockStatus::Created,
        }
        .into();
        assert!(super::committed_block_height(&created).is_none());
        let created_batch = EventBox::PipelineBatch(vec![PipelineEventBox::from(BlockEvent {
            header: BlockHeader {
                height: NonZeroU64::new(3).unwrap(),
                prev_block_hash: None,
                merkle_root: None,
                da_proof_policies_hash: None,
                da_commitments_hash: None,
                da_pin_intents_hash: None,
                npos_effects_hash: None,
                global_beacon_pulse_hash: None,
                execution_context_hash: None,
                creation_time_ms: 0,
                view_change_index: 0,
                confidential_features: None,
            },
            status: BlockStatus::Created,
        })]);
        assert!(super::committed_block_height(&created_batch).is_none());
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn average_block_time_handles_empty_chain() {
        let state = CoreState::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let owner = crate::history_producer::HistoryProducerOwner::for_test();
        let budget = owner.canonical_history_budget();
        assert!(
            super::average_block_time_ms(&state, 0, 10, &budget)
                .expect("empty history needs no body admission")
                .is_none()
        );
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn latest_block_created_at_missing_when_height_zero() {
        let state = CoreState::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        assert!(
            super::latest_block_created_at(
                &state,
                0,
                &crate::history_producer::HistoryProducerOwner::for_test()
                    .canonical_history_budget()
            )
            .expect("height zero needs no body admission")
            .is_none()
        );
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn por_status_export_and_report_handlers() {
        let coordinator = std::sync::Arc::new(crate::sorafs::PorCoordinator::new());
        let provider_a = [0xAB; 32];
        let provider_b = [0xBC; 32];
        let challenge_a = build_por_challenge(0x10, provider_a, 540, 1_672_620_000);
        let challenge_b = build_por_challenge(0x20, provider_b, 880, 1_700_000_000);
        coordinator
            .record_challenge(&challenge_a)
            .expect("first challenge recorded");
        coordinator
            .record_challenge(&challenge_b)
            .expect("second challenge recorded");
        let status_query = PorStatusQueryDto {
            manifest: Some(hex::encode(challenge_a.manifest_digest)),
            provider: Some(hex::encode(challenge_a.provider_id)),
            epoch: Some(challenge_a.epoch_id),
            status: Some("pending".to_string()),
            limit: 5,
            max_bytes: POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1,
            cursor: None,
        };
        let status_page = super::handle_get_sorafs_por_status(coordinator.clone(), status_query)
            .expect("status handler responds");
        assert_eq!(status_page.statuses.len(), 1);
        assert_eq!(
            status_page.statuses[0].challenge_id,
            challenge_a.challenge_id
        );
        let oversized_status_query = PorStatusQueryDto {
            manifest: None,
            provider: None,
            epoch: None,
            status: None,
            limit: POR_CHALLENGE_STATUS_PAGE_MAX_RECORDS_V1 + 1,
            max_bytes: POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1,
            cursor: None,
        };
        assert!(
            super::handle_get_sorafs_por_status(coordinator.clone(), oversized_status_query)
                .is_err()
        );
        let export = super::handle_get_sorafs_por_export(
            coordinator.clone(),
            PorExportQueryDto {
                start_epoch: Some(challenge_a.epoch_id),
                end_epoch: Some(challenge_a.epoch_id),
                limit: 5,
                max_bytes: POR_STATUS_PAGE_MAX_CANONICAL_BYTES_V1,
                cursor: None,
            },
        )
        .expect("export handler responds");
        assert_eq!(export.page.statuses.len(), 1);
        assert_eq!(
            export.page.statuses[0].challenge_id,
            challenge_a.challenge_id
        );
        let invalid_report_response = super::handle_get_sorafs_por_report(
            coordinator.clone(),
            PorReportIsoWeek {
                year: 9999,
                week: 52,
            },
        )
        .expect_err("an ISO week whose end is not representable must be rejected")
        .into_response();
        assert_eq!(
            invalid_report_response.status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        let report = super::handle_get_sorafs_por_report(
            coordinator.clone(),
            PorReportIsoWeek {
                year: 2023,
                week: 1,
            },
        )
        .expect("report handler responds");
        assert!(
            report.challenges_total >= 1,
            "weekly report must include the recorded challenge"
        );
    }
    #[cfg(feature = "app_api")]
    mod finality_attestation_handler_tests {
        use crate::{SharedAppState, tests_runtime_handlers::ReadinessNode};
        use axum::{
            Router,
            body::Body,
            http::{Request, StatusCode},
        };
        use iroha_crypto::{Algorithm, Hash, KeyPair};
        use iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation;
        use iroha_model_base::peer::PeerId;
        use iroha_torii_shared::{
            ErrorEnvelope,
            bridge_attestation::{
                FINALITY_ATTESTATION_FAILURE_CODE, FINALITY_ATTESTATION_FAILURE_MAX_BYTES,
                FinalityAttestationFailure, FinalityAttestationFailureReason as Reason,
            },
        };
        use norito::codec::Encode as _;
        use std::sync::Arc;
        use tower::ServiceExt as _;

        fn router(app: &SharedAppState) -> Router {
            Router::new()
                .route(
                    "/v1/bridge/finality/{height}",
                    axum::routing::get(crate::handler_bridge_finality_proof),
                )
                .route(
                    "/v1/bridge/finality/bundle/{height}",
                    axum::routing::get(crate::handler_bridge_finality_bundle),
                )
                .route(
                    iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION.path(),
                    axum::routing::get(crate::handler_bridge_finality_attestation),
                )
                .route(
                    iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION_LATEST
                        .path(),
                    axum::routing::get(crate::handler_bridge_finality_attestation_latest),
                )
                .layer(axum::middleware::from_fn(crate::enforce_route_timeout))
                .layer(axum::middleware::from_fn(crate::capture_response_format))
                .layer(axum::middleware::from_fn(crate::coalesce_accept_headers))
                .layer(axum::middleware::from_fn(
                    crate::enforce_typed_error_contract,
                ))
                .layer(axum::middleware::from_fn(crate::enforce_json_utf8_charset))
                .with_state(Arc::clone(app))
        }

        fn request(height: u64, challenge: [u8; 32]) -> Request<Body> {
            selector_request(&height.to_string(), challenge)
        }

        fn selector_request(selector: &str, challenge: [u8; 32]) -> Request<Body> {
            let mut request = Request::builder()
                .uri(format!("/v1/bridge/finality/attestation/{selector}"))
                .header(axum::http::header::ACCEPT, "application/x-norito")
                .header(
                    crate::BRIDGE_FINALITY_CHALLENGE_HEADER,
                    hex::encode(challenge),
                )
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(crate::loopback_connect_info());
            request
        }

        async fn assert_failure(
            app: &SharedAppState,
            height: u64,
            challenge: [u8; 32],
            reason: Reason,
        ) -> FinalityAttestationFailure {
            assert_selector_failure(app, &height.to_string(), height, challenge, reason).await
        }

        async fn assert_selector_failure(
            app: &SharedAppState,
            selector: &str,
            height: u64,
            challenge: [u8; 32],
            reason: Reason,
        ) -> FinalityAttestationFailure {
            let response = router(app)
                .oneshot(selector_request(selector, challenge))
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), reason.http_status_code());
            assert_eq!(
                response.headers()[axum::http::header::CONTENT_TYPE],
                "application/x-norito"
            );
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(
                !response
                    .headers()
                    .contains_key(axum::http::header::RETRY_AFTER)
            );
            let bytes =
                axum::body::to_bytes(response.into_body(), FINALITY_ATTESTATION_FAILURE_MAX_BYTES)
                    .await
                    .unwrap();
            let envelope: ErrorEnvelope = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .expect("canonical real-handler failure envelope");
            assert_eq!(envelope.code(), FINALITY_ATTESTATION_FAILURE_CODE);
            let mut details = envelope.details.unwrap();
            let failure = details.finality_attestation_failure.take().unwrap();
            assert!(details.is_empty());
            assert_eq!(failure.reason, reason);
            assert!(failure.matches(
                height,
                challenge,
                &PeerId::new(app.torii_proxy_bridge_signer.public_key().clone()),
                *app.state.network_id_ref(),
            ));
            if reason != Reason::TipChanged {
                assert!(failure.tip_mismatch.is_none());
            }
            failure
        }

        #[tokio::test]
        async fn finality_attestation_direct_http_admission_reaches_inactive_native_worker() {
            let fixture = ReadinessNode::start_at_tip(true);
            let app = &fixture.app;
            for route in [
                iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY,
                iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION,
                iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION_LATEST,
            ] {
                assert!(crate::app_routed_read_http_endpoint(route.stable_route_id()).is_none());
            }
            // Exercise the same real public handler's admission and physical worker boundary.
            // An inactive-only native producer must not silently become unreachable here.
            let admission = crate::acquire_query_admission(app.as_ref(), true)
                .await
                .unwrap();
            let active =
                crate::routing::run_admitted_blocking(admission, "attestation scope check", || {
                    Ok(norito::core::decode_limits_active())
                })
                .await
                .unwrap();
            assert!(!active);
            let response = router(app).oneshot(request(2, [0x63; 32])).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
                .await
                .unwrap();
            let attestation: SumeragiFinalityAttestation = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap();
            attestation.verify().unwrap();
        }

        #[tokio::test]
        async fn finality_attestation_handler_binds_current_node_success_and_actual_tip_race() {
            let fixture = ReadinessNode::start_at_tip(true);
            let app = &fixture.app;
            let challenge = [0x37; 32];
            let response = router(app).oneshot(request(2, challenge)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[axum::http::header::CONTENT_TYPE],
                "application/x-norito"
            );
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
                .await
                .unwrap();
            let attestation: SumeragiFinalityAttestation = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .expect("canonical current-node HTTP attestation");
            attestation
                .verify()
                .expect("real node signature and current embedded certificate");
            let body = &attestation.body;
            assert_eq!(body.challenge, challenge);
            assert_eq!(body.network_id, *app.state.network_id_ref());
            let node = app.sumeragi.as_ref().unwrap();
            assert_eq!(body.node_id, node.identity().node_id);
            assert_eq!(
                body.node_fingerprint,
                Hash::new(node.identity().node_id.encode())
            );
            assert_eq!(body.config_fingerprint, node.identity().config_fingerprint);
            assert_eq!(
                body.build_fingerprint,
                Hash::new_from_chunks(&[
                    app.build_status.version.as_bytes(),
                    app.build_status.git_commit_sha.as_bytes(),
                ])
            );
            assert_eq!(body.status.committed_height, 2);
            assert_eq!(body.status.applied_height, 2);
            assert_eq!(body.genesis_finality_proof.height(), 1);
            assert_eq!(body.finality_proof.height(), 2);
            body.finality_proof
                .decode_checked()
                .expect("actual non-genesis BLS quorum proof");
            for endpoint in ["/v1/bridge/finality/2", "/v1/bridge/finality/bundle/2"] {
                let mut request = Request::builder()
                    .uri(endpoint)
                    .header(axum::http::header::ACCEPT, "application/x-norito")
                    .body(Body::empty())
                    .unwrap();
                request
                    .extensions_mut()
                    .insert(crate::loopback_connect_info());
                let response = router(app).oneshot(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{endpoint}");
                let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
                    .await
                    .unwrap();
                let proof = if endpoint.contains("bundle") {
                    let bundle: iroha_data_model::sumeragi_finality::SumeragiFinalityBundle =
                        norito::decode_canonical_with_limits(
                            &bytes,
                            norito::canonical_decode_limits(bytes.len()),
                        )
                        .unwrap();
                    assert_eq!(bundle.network_id, body.network_id);
                    bundle.finality_proof
                } else {
                    norito::decode_canonical_with_limits::<
                        iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
                    >(&bytes, norito::canonical_decode_limits(bytes.len()))
                    .unwrap()
                };
                assert_eq!(
                    proof, body.finality_proof,
                    "all current proof routes bind the same durable block"
                );
            }
            let failure = assert_failure(app, 3, [0x38; 32], Reason::TipChanged).await;
            let progress = failure.tip_mismatch.unwrap();
            assert_eq!(
                (
                    progress.requested_height,
                    progress.applied_height,
                    progress.status_height
                ),
                (3, 2, 2)
            );
        }

        #[tokio::test]
        async fn finality_attestation_latest_signs_current_status_and_rejects_stopped_driver() {
            let mut fixture = ReadinessNode::start();
            let node = fixture.app.sumeragi.as_ref().unwrap();
            assert!(node.ready());
            assert!(!node.restart_required());
            let challenge = [0x39; 32];
            let response = router(&fixture.app)
                .oneshot(selector_request("latest", challenge))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
                .await
                .unwrap();
            let attestation: SumeragiFinalityAttestation = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap();
            attestation.verify().unwrap();
            assert_eq!(attestation.body.challenge, challenge);
            assert_eq!(attestation.body.finality_proof.height(), 1);
            let mut tampered = attestation;
            tampered.body.status.view += 1;
            assert!(
                tampered.verify().is_err(),
                "node signature covers actual status"
            );
            fixture.stop();
            let node = fixture.app.sumeragi.as_ref().unwrap();
            assert!(node.status_dto().is_some(), "shutdown retains diagnostics");
            assert!(!node.ready());
            assert!(node.restart_required());
            assert_failure(&fixture.app, 1, [0x3A; 32], Reason::RestartRequired).await;
            assert_selector_failure(
                &fixture.app,
                "latest",
                1,
                [0x3B; 32],
                Reason::RestartRequired,
            )
            .await;
        }

        #[tokio::test]
        async fn finality_attestation_handler_distinguishes_absent_driver_and_foreign_signer() {
            let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
            assert_failure(&app, 1, [0x41; 32], Reason::ConsensusUninitialized).await;
            let mut fixture = ReadinessNode::start();
            Arc::get_mut(&mut fixture.app)
                .unwrap()
                .torii_proxy_bridge_signer =
                KeyPair::from_seed(vec![0xA2; 32], Algorithm::BlsNormal);
            assert_failure(&fixture.app, 1, [0x42; 32], Reason::InternalFailure).await;
        }

        #[tokio::test]
        async fn finality_attestation_handler_rejects_missing_and_corrupt_embedded_certificate() {
            use iroha_core::{
                kura::Kura,
                query::store::LiveQueryStore,
                state::{State, StateReadOnly, World},
            };
            use iroha_data_model::block::CommitCertificate;
            for corrupt in [false, true] {
                let mut fixture = ReadinessNode::start();
                let view = fixture.app.state.view();
                let block = view
                    .latest_block()
                    .expect("funded canonical history read")
                    .unwrap()
                    .as_ref()
                    .clone()
                    .with_commit_certificate(corrupt.then(|| {
                        CommitCertificate::from_untrusted_parts(
                            Vec::new(),
                            Vec::new(),
                            b"invalid result".to_vec(),
                            Vec::new(),
                        )
                    }));
                let header = block.header();
                let hash = block.hash();
                drop(view);
                let kura = Kura::blank_kura_for_testing();
                let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
                    World::default(),
                    Arc::clone(&kura),
                    LiveQueryStore::start_test(),
                    fixture.app.state.chain_id_ref().clone(),
                    *fixture.app.state.network_id_ref(),
                ));
                // Provision authenticated primary storage while it is empty,
                // then inject only the deliberate certificate defect.
                kura.store_block(
                    iroha_data_model::block::SharedSignedBlock::try_new(
                        block,
                        &state.ivm_execution_budget(),
                    )
                    .expect("fund deliberate certificate defect fixture"),
                )
                .expect("persist canonical deliberately damaged certificate fixture");
                let mut hashes = state.block_hashes.block();
                hashes.push_for_tests(hash);
                hashes.commit_for_tests();
                state.update_latest_block_header_cache_for_tests(header);
                let app = Arc::get_mut(&mut fixture.app).unwrap();
                app.state = state;
                app.kura = kura;
                assert_failure(
                    &fixture.app,
                    1,
                    [0x51; 32],
                    if corrupt {
                        Reason::ConflictingState
                    } else {
                        Reason::FinalityUnavailable
                    },
                )
                .await;
            }
        }

        #[tokio::test]
        async fn finality_attestation_handler_rejects_auth_challenge_and_admission_before_startup()
        {
            for case in 0..3 {
                let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
                let app_mut = Arc::get_mut(&mut app).unwrap();
                if case == 0 {
                    app_mut.require_api_token = true;
                    app_mut.api_token_digests =
                        Arc::new(crate::limits::ApiTokenDigestSet::default());
                }
                if case != 1 {
                    app_mut.query_heavy_inflight = Arc::new(tokio::sync::Semaphore::new(0));
                    app_mut.query_queue_timeout = std::time::Duration::from_millis(1);
                }
                let mut request = request(1, [0x61; 32]);
                if case == 1 {
                    request
                        .headers_mut()
                        .remove(crate::BRIDGE_FINALITY_CHALLENGE_HEADER);
                }
                let response = router(&app).oneshot(request).await.unwrap();
                let expected = match case {
                    0 => StatusCode::FORBIDDEN,
                    1 => StatusCode::BAD_REQUEST,
                    _ => StatusCode::TOO_MANY_REQUESTS,
                };
                assert_eq!(response.status(), expected);
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let envelope: ErrorEnvelope = norito::decode_canonical_with_limits(
                    &bytes,
                    norito::canonical_decode_limits(bytes.len()),
                )
                .unwrap();
                assert_ne!(envelope.code(), FINALITY_ATTESTATION_FAILURE_CODE);
                assert!(
                    envelope
                        .details
                        .is_none_or(|details| details.finality_attestation_failure.is_none())
                );
            }
        }
    }
}
#[cfg(feature = "profiling")]
pub mod profiling {
    use super::*;
    use nonzero_ext::nonzero;
    use pprof::protos::Message;
    use std::num::{NonZeroU16, NonZeroU64};
    /// Query params used to configure profile gathering
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_torii::routing::profiling::ProfileParams")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(
        crate::json_macros::JsonSerialize,
        norito::derive::NoritoSerialize,
        crate::json_macros::JsonDeserialize,
        norito::derive::NoritoDeserialize,
        Clone,
        Copy,
    )]
    pub struct ProfileParams {
        /// How often to sample Iroha
        #[norito(default = "ProfileParams::default_frequency")]
        frequency: NonZeroU16,
        /// How long to sample Iroha
        #[norito(default = "ProfileParams::default_seconds")]
        seconds: NonZeroU64,
    }
    impl ProfileParams {
        fn default_frequency() -> NonZeroU16 {
            nonzero!(99_u16)
        }
        fn default_seconds() -> NonZeroU64 {
            nonzero!(10_u64)
        }
    }
    /// Serve pprof profile data
    pub async fn handle_profile(
        ProfileParams { frequency, seconds }: ProfileParams,
        profiling_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Vec<u8>> {
        match profiling_lock.try_lock() {
            Ok(_guard) => {
                let mut body = Vec::new();
                {
                    // Create profiler guard
                    let guard = pprof::ProfilerGuardBuilder::default()
                        .frequency(i32::from(frequency.get()))
                        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                        .build()
                        .map_err(|e| {
                            Error::Pprof(eyre::eyre!(
                                "pprof::ProfilerGuardBuilder::build fail: {}",
                                e
                            ))
                        })?;
                    // Collect profiles for seconds
                    tokio::time::sleep(tokio::time::Duration::from_secs(seconds.get())).await;
                    let report = guard
                        .report()
                        .build()
                        .map_err(|e| Error::Pprof(eyre::eyre!("generate report fail: {}", e)))?;
                    let profile = report.pprof().map_err(|e| {
                        Error::Pprof(eyre::eyre!("generate pprof from report fail: {}", e))
                    })?;
                    profile.encode(&mut body).map_err(|e| {
                        Error::Pprof(eyre::eyre!("encode pprof into bytes fail: {}", e))
                    })?;
                }
                Ok(body)
            }
            Err(_) => {
                // profile already running return error
                Err(Error::Pprof(eyre::eyre!("profiling already running")))
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[tokio::test]
        async fn profiling_encodes_pprof_payload() {
            let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
            let params = ProfileParams {
                frequency: nonzero!(99_u16),
                seconds: nonzero!(1_u64),
            };
            let payload = handle_profile(params, lock).await.expect("profile payload");
            assert!(!payload.is_empty(), "pprof payload should not be empty");
        }
    }
}
#[cfg(all(test, feature = "ws_integration_tests"))]
mod event_stream_tests {
    use super::event::handle_events_stream_with_receiver;
    use axum::{Router, extract::ws::WebSocketUpgrade, routing::get};
    use futures_util::{SinkExt as _, StreamExt as _};
    use iroha_core::EventsSender;
    use iroha_crypto::{Hash, HashOf};
    use iroha_data_model::{
        events::{
            EventBox, EventFilterBox,
            pipeline::{
                PipelineEventBox, TransactionEvent, TransactionEventFilter, TransactionStatus,
            },
            stream::{EventMessage, EventSubscriptionRequest},
        },
        transaction::SignedTransaction,
    };
    use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
    use norito::{decode_from_bytes, to_bytes};
    use std::{io::ErrorKind, sync::Arc};
    use tokio::{net::TcpListener, sync::Mutex};
    async fn spawn_event_stream_server(
        receiver: tokio::sync::broadcast::Receiver<EventBox>,
    ) -> Option<std::net::SocketAddr> {
        let rx_holder = Arc::new(Mutex::new(Some(receiver)));
        let app = Router::new().route(
            "/ws",
            get({
                let rx_holder = Arc::clone(&rx_holder);
                move |ws: WebSocketUpgrade| {
                    let rx_holder = Arc::clone(&rx_holder);
                    async move {
                        ws.on_upgrade(move |ws| async move {
                            let mut guard = rx_holder.lock().await;
                            let rx = guard.take().expect("event receiver already used");
                            let _ = handle_events_stream_with_receiver(
                                rx,
                                ws,
                                std::time::Duration::from_millis(
                                    iroha_config::parameters::defaults::torii::WS_MESSAGE_TIMEOUT_MS,
                                ),
                            )
                            .await;
                        })
                    }
                }
            }),
        );
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("tcp bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum server");
        });
        Some(addr)
    }
    async fn connect_event_stream(
        addr: std::net::SocketAddr,
    ) -> Option<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    > {
        match tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await {
            Ok((stream, _response)) => Some(stream),
            Err(tokio_tungstenite::tungstenite::Error::Io(io_err))
                if io_err.kind() == ErrorKind::PermissionDenied =>
            {
                None
            }
            Err(err) => panic!("ws connect failed: {err}"),
        }
    }
    async fn next_close_frame(
        stream: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> tokio_tungstenite::tungstenite::protocol::CloseFrame {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match stream.next().await {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(Some(frame)))) => {
                        break frame;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => panic!("ws message error: {err}"),
                    None => panic!("ws stream closed without a close frame"),
                }
            }
        })
        .await
        .expect("timed out waiting for close frame")
    }
    #[tokio::test]
    async fn ws_stream_receives_buffered_events() {
        let events: EventsSender = tokio::sync::broadcast::channel(16).0;
        let hash = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
            [0x11; Hash::LENGTH],
        ));
        let other_hash = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
            [0x22; Hash::LENGTH],
        ));
        let queued_event = EventBox::PipelineBatch(vec![
            PipelineEventBox::Transaction(TransactionEvent {
                hash,
                block_height: None,
                lane_id: LaneId::new(0),
                dataspace_id: DataSpaceId::new(0),
                status: TransactionStatus::Queued,
            }),
            PipelineEventBox::Transaction(TransactionEvent {
                hash: other_hash,
                block_height: None,
                lane_id: LaneId::new(0),
                dataspace_id: DataSpaceId::new(0),
                status: TransactionStatus::Queued,
            }),
        ]);
        let rx_holder = Arc::new(Mutex::new(Some(events.subscribe())));
        events
            .send(queued_event)
            .expect("receiver should be subscribed");
        let app = Router::new().route(
            "/ws",
            get({
                let rx_holder = Arc::clone(&rx_holder);
                move |ws: WebSocketUpgrade| {
                    let rx_holder = Arc::clone(&rx_holder);
                    async move {
                        ws.on_upgrade(move |ws| async move {
                            let mut guard = rx_holder.lock().await;
                            let rx = guard.take().expect("event receiver already used");
                            let _ = handle_events_stream_with_receiver(
                                rx,
                                ws,
                                std::time::Duration::from_millis(
                                    iroha_config::parameters::defaults::torii::WS_MESSAGE_TIMEOUT_MS,
                                ),
                            )
                            .await;
                        })
                    }
                }
            }),
        );
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("tcp bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum server");
        });
        let (mut ws_stream, _resp) =
            match tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await {
                Ok(pair) => pair,
                Err(tokio_tungstenite::tungstenite::Error::Io(io_err))
                    if io_err.kind() == ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(err) => panic!("ws connect failed: {err}"),
            };
        let sub = EventSubscriptionRequest::new(vec![EventFilterBox::Pipeline(
            TransactionEventFilter::default().for_hash(hash).into(),
        )]);
        let sub_bytes = to_bytes(&sub).expect("encode subscription");
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                sub_bytes.into(),
            ))
            .await
            .expect("send subscription");
        let mut got_event = None;
        while let Some(msg) = ws_stream.next().await {
            let msg = msg.expect("ws message");
            if let tokio_tungstenite::tungstenite::Message::Binary(bytes) = msg {
                let event_msg: EventMessage =
                    decode_from_bytes(bytes.as_ref()).expect("decode event message");
                let event_box: EventBox = event_msg.into();
                if let EventBox::Pipeline(PipelineEventBox::Transaction(event)) = event_box {
                    got_event = Some(event);
                    break;
                }
            }
        }
        let event = got_event.expect("transaction event");
        assert_eq!(event.hash(), &hash);
        assert_eq!(event.status(), &TransactionStatus::Queued);
    }
    #[tokio::test]
    async fn ws_stream_reports_lag_and_closes() {
        let events: EventsSender = tokio::sync::broadcast::channel(1).0;
        let lagged_hash = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
            [0x11; Hash::LENGTH],
        ));
        let wanted_hash = HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
            [0x22; Hash::LENGTH],
        ));
        let lagged_event = EventBox::Pipeline(PipelineEventBox::Transaction(TransactionEvent {
            hash: lagged_hash,
            block_height: None,
            lane_id: LaneId::new(0),
            dataspace_id: DataSpaceId::new(0),
            status: TransactionStatus::Queued,
        }));
        let wanted_event = EventBox::Pipeline(PipelineEventBox::Transaction(TransactionEvent {
            hash: wanted_hash.clone(),
            block_height: None,
            lane_id: LaneId::new(0),
            dataspace_id: DataSpaceId::new(0),
            status: TransactionStatus::Queued,
        }));
        let rx_holder = Arc::new(Mutex::new(Some(events.subscribe())));
        events
            .send(lagged_event)
            .expect("receiver should be subscribed");
        events
            .send(wanted_event)
            .expect("receiver should be subscribed");
        let app = Router::new().route(
            "/ws",
            get({
                let rx_holder = Arc::clone(&rx_holder);
                move |ws: WebSocketUpgrade| {
                    let rx_holder = Arc::clone(&rx_holder);
                    async move {
                        ws.on_upgrade(move |ws| async move {
                            let mut guard = rx_holder.lock().await;
                            let rx = guard.take().expect("event receiver already used");
                            let _ = handle_events_stream_with_receiver(
                                rx,
                                ws,
                                std::time::Duration::from_millis(
                                    iroha_config::parameters::defaults::torii::WS_MESSAGE_TIMEOUT_MS,
                                ),
                            )
                            .await;
                        })
                    }
                }
            }),
        );
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("tcp bind failed: {err}"),
        };
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("axum server");
        });
        let (mut ws_stream, _resp) =
            match tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await {
                Ok(pair) => pair,
                Err(tokio_tungstenite::tungstenite::Error::Io(io_err))
                    if io_err.kind() == ErrorKind::PermissionDenied =>
                {
                    return;
                }
                Err(err) => panic!("ws connect failed: {err}"),
            };
        let sub = EventSubscriptionRequest::new(vec![EventFilterBox::Pipeline(
            TransactionEventFilter::default()
                .for_hash(wanted_hash.clone())
                .into(),
        )]);
        let sub_bytes = to_bytes(&sub).expect("encode subscription");
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                sub_bytes.into(),
            ))
            .await
            .expect("send subscription");
        let close = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match ws_stream.next().await {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(Some(frame)))) => {
                        break frame;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => panic!("ws message error: {err}"),
                    None => panic!("ws stream closed without a close frame"),
                }
            }
        })
        .await
        .expect("timed out waiting for close frame");
        assert_eq!(u16::from(close.code), crate::stream::CLOSE_TRY_AGAIN_LATER);
        assert_eq!(close.reason, "event_stream_lagged:1");
    }
    #[tokio::test]
    async fn ws_stream_rejects_text_subscription_payload() {
        let events: EventsSender = tokio::sync::broadcast::channel(4).0;
        let Some(addr) = spawn_event_stream_server(events.subscribe()).await else {
            return;
        };
        let Some(mut ws_stream) = connect_event_stream(addr).await else {
            return;
        };
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "not-norito".into(),
            ))
            .await
            .expect("send text subscription");
        let close = next_close_frame(&mut ws_stream).await;
        assert_eq!(u16::from(close.code), crate::stream::CLOSE_INVALID_PAYLOAD);
        assert_eq!(close.reason, "invalid_subscription_payload");
    }
    #[tokio::test]
    async fn ws_stream_rejects_empty_event_filter_set() {
        let events: EventsSender = tokio::sync::broadcast::channel(4).0;
        let Some(addr) = spawn_event_stream_server(events.subscribe()).await else {
            return;
        };
        let Some(mut ws_stream) = connect_event_stream(addr).await else {
            return;
        };
        let subscription = EventSubscriptionRequest::new(Vec::new());
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                to_bytes(&subscription)
                    .expect("encode empty subscription")
                    .into(),
            ))
            .await
            .expect("send empty subscription");
        let close = next_close_frame(&mut ws_stream).await;
        assert_eq!(u16::from(close.code), crate::stream::CLOSE_POLICY_VIOLATION);
        assert_eq!(close.reason, "invalid_event_subscription");
    }
    #[tokio::test]
    async fn ws_stream_rejects_data_after_subscription() {
        let events: EventsSender = tokio::sync::broadcast::channel(4).0;
        let Some(addr) = spawn_event_stream_server(events.subscribe()).await else {
            return;
        };
        let Some(mut ws_stream) = connect_event_stream(addr).await else {
            return;
        };
        let subscription = EventSubscriptionRequest::new(vec![EventFilterBox::Pipeline(
            TransactionEventFilter::default().into(),
        )]);
        let bytes = to_bytes(&subscription).expect("encode subscription");
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes.clone().into(),
            ))
            .await
            .expect("send subscription");
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes.into(),
            ))
            .await
            .expect("send unexpected second request");
        let close = next_close_frame(&mut ws_stream).await;
        assert_eq!(u16::from(close.code), crate::stream::CLOSE_INVALID_PAYLOAD);
        assert_eq!(close.reason, "invalid_subscription_payload");
    }
    #[tokio::test]
    async fn ws_stream_emits_transport_heartbeat() {
        let events: EventsSender = tokio::sync::broadcast::channel(4).0;
        let Some(addr) = spawn_event_stream_server(events.subscribe()).await else {
            return;
        };
        let Some(mut ws_stream) = connect_event_stream(addr).await else {
            return;
        };
        let subscription = EventSubscriptionRequest::new(vec![EventFilterBox::Pipeline(
            TransactionEventFilter::default().into(),
        )]);
        ws_stream
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                to_bytes(&subscription).expect("encode subscription").into(),
            ))
            .await
            .expect("send subscription");
        let heartbeat = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                match ws_stream.next().await {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(payload))) => {
                        break payload;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => panic!("ws heartbeat error: {err}"),
                    None => panic!("ws stream closed before heartbeat"),
                }
            }
        })
        .await
        .expect("timed out waiting for heartbeat");
        assert!(heartbeat.is_empty());
    }
}
