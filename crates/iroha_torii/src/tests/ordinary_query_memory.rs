// Focused tests for Torii's app-local ordinary-query memory corridor.
#[cfg(test)]
mod ordinary_query_memory_tests {
    use super::*;
    use iroha_core::smartcontracts::isi::query::{
        OrdinaryQueryExecutionLimits, OrdinaryQueryMemoryReservation as _,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    fn default_geometry() -> (QueryMemoryGeometry, ByteWeightedMemoryPool) {
        let geometry = query_memory_geometry(
            usize::try_from(defaults::torii::QUERY_FANOUT_MAX_RETAINED_BYTES.get())
                .expect("default pool fits usize"),
            usize::try_from(defaults::torii::QUERY_FANOUT_MAX_WORKING_SET_BYTES.get())
                .expect("default per-query ceiling fits usize"),
            usize::try_from(defaults::torii::MAX_CONTENT_LEN.get())
                .expect("default content limit fits usize"),
            defaults::torii::QUERY_HEAVY_MAX_INFLIGHT.get(),
        )
        .expect("default query geometry");
        let pool =
            ByteWeightedMemoryPool::new(geometry.fanout_pool_bytes).expect("default weighted pool");
        (geometry, pool)
    }
    fn default_policy(
        geometry: QueryMemoryGeometry,
        pool: &ByteWeightedMemoryPool,
    ) -> OrdinaryQueryServerPolicy {
        let working_set = geometry
            .fanout_working_set_bytes
            .min(usize::try_from(pool.capacity_bytes()).expect("capacity fits usize"));
        OrdinaryQueryServerPolicy::new(
            routing::AppQueryLimits::default(),
            geometry.ingress,
            QueryFanoutMemoryEnvelope::for_body_admission(working_set)
                .expect("default fanout envelope"),
        )
        .expect("default ordinary policy")
    }
    #[cfg(feature = "app_api")]
    fn proof_query_fixture(
        seed: u8,
        proof_bytes: usize,
    ) -> (
        SharedAppState,
        AccountId,
        iroha_data_model::proof::ProofRecord,
        String,
    ) {
        use base64::Engine as _;
        use iroha_data_model::{
            bridge::{
                BridgeProof, BridgeProofPayload, BridgeProofRange, BridgeProofRecord,
                BridgeTransparentProof,
            },
            proof::{ProofBox, ProofId, ProofRecord, ProofStatus},
            query::{QueryRequest, SingularQueryBox, proof::prelude::FindProofRecordById},
        };
        use iroha_version::codec::EncodeVersioned as _;
        let key_pair = tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            seed,
            "derive bounded proof query key",
        );
        let authority = AccountId::new(key_pair.public_key().clone());
        let id = ProofId {
            backend: "debug-proof".into(),
            proof_hash: [seed; 32],
        };
        let bridge = (proof_bytes != 0).then(|| BridgeProofRecord {
            proof: BridgeProof {
                range: BridgeProofRange {
                    start_height: 1,
                    end_height: 1,
                },
                payload: BridgeProofPayload::TransparentZk(BridgeTransparentProof {
                    verifier_manifest_hash: [0xA5; 32],
                    proof: ProofBox::new("debug-proof".into(), vec![0x5A; proof_bytes]),
                    recursion_depth: Some(1),
                }),
            },
            commitment: [0xC3; 32],
            size_bytes: u32::try_from(proof_bytes).expect("proof fixture fits u32"),
        });
        let record = ProofRecord {
            id: id.clone(),
            vk_ref: None,
            vk_commitment: None,
            status: ProofStatus::Verified,
            verified_at_height: Some(1),
            bridge,
        };
        let world = tests_runtime_handlers::world_with_account(&authority);
        let app = tests_runtime_handlers::mk_app_state_for_tests_with_world(world);
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("nonzero proof fixture height"),
            None,
            None,
            0,
            0,
        );
        let mut block = app.state.block(header);
        let mut transaction = block.transaction();
        let transaction_world = transaction.world_mut_for_testing();
        transaction_world.add_account_permission(&authority, CanReadAllLedgerData.into());
        transaction_world
            .proofs_mut_for_testing()
            .insert(id.clone(), record.clone());
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit bounded proof fixture");
        let signed = authorize_query_for_test(
            QueryRequest::Singular(SingularQueryBox::FindProofRecordById(FindProofRecordById {
                id,
            })),
            authority.clone(),
        )
        .sign(&key_pair);
        let signed_query_b64 =
            base64::engine::general_purpose::STANDARD.encode(signed.encode_versioned());
        (app, authority, record, signed_query_b64)
    }
    #[cfg(feature = "app_api")]
    fn proof_query_dto(signed_query_b64: &str) -> crate::routing::ProofFindByIdQueryDto {
        crate::routing::ProofFindByIdQueryDto {
            signed_query_b64: signed_query_b64.to_owned(),
        }
    }
    #[test]
    fn weighted_pool_rounding_is_conservative_and_never_overcommits() {
        let pool = ByteWeightedMemoryPool::with_max_permits(10, 3).expect("small test pool");
        assert_eq!(pool.bytes_per_permit.get(), 4);
        assert_eq!(pool.total_permits.get(), 2);
        assert_eq!(pool.capacity_bytes(), 8);
        let permit = pool
            .try_acquire_parts([5])
            .expect("five bytes round to both permits");
        assert_eq!(permit.num_permits(), 2);
        assert_eq!(pool.available_bytes(), 0);
        assert!(pool.try_acquire_parts([1]).is_none());
        drop(permit);
        assert_eq!(pool.available_bytes(), 8);
    }
    #[test]
    fn weighted_pool_handles_u32_boundary_without_ceil_overflow() {
        let Ok(larger_than_u32) = usize::try_from(u64::from(u32::MAX) + 17) else {
            return;
        };
        let pool = ByteWeightedMemoryPool::new(larger_than_u32).expect("large weighted pool");
        assert!(pool.bytes_per_permit.get() > 1);
        assert!(pool.capacity_bytes() <= u64::try_from(larger_than_u32).unwrap());
        assert!(pool.capacity_bytes() > 0);
        assert!(pool.try_acquire_parts([u64::MAX]).is_none());
    }
    #[test]
    fn independently_rounded_start_parts_split_without_losing_p() {
        let pool = ByteWeightedMemoryPool::with_max_permits(32, 8).expect("split test pool");
        let permit = pool
            .try_acquire_parts([5, 3])
            .expect("P and R round independently");
        let mut reservation = ToriiOrdinaryQueryMemoryReservation {
            permit,
            bytes_per_permit: pool.bytes_per_permit,
            pool_generation: pool.generation(),
        };
        assert_eq!(reservation.reserved_bytes(), 12);
        let child = reservation.split_off(3).expect("split rounded R");
        assert_eq!(child.reserved_bytes(), 4);
        assert_eq!(child.pool_generation(), pool.generation());
        assert_eq!(reservation.reserved_bytes(), 8);
        assert_eq!(pool.available_bytes(), 20);
        drop(child);
        assert_eq!(pool.available_bytes(), 24);
        drop(reservation);
        assert_eq!(pool.available_bytes(), 32);
    }
    #[test]
    fn failed_split_leaves_parent_weight_unchanged() {
        let pool = ByteWeightedMemoryPool::with_max_permits(16, 4).expect("split test pool");
        let permit = pool.try_acquire_parts([8]).expect("two permits");
        let mut reservation = ToriiOrdinaryQueryMemoryReservation {
            permit,
            bytes_per_permit: pool.bytes_per_permit,
            pool_generation: pool.generation(),
        };
        assert!(reservation.split_off(9).is_none());
        assert_eq!(reservation.reserved_bytes(), 8);
    }
    #[test]
    fn app_local_pool_and_policy_generations_are_unique_and_wrap_closed() {
        let (geometry, first_pool) = default_geometry();
        let first_policy = default_policy(geometry, &first_pool);
        let second_pool =
            ByteWeightedMemoryPool::new(geometry.fanout_pool_bytes).expect("second weighted pool");
        let second_policy = default_policy(geometry, &second_pool);
        assert_ne!(first_pool.generation(), second_pool.generation());
        assert_ne!(
            first_policy.limits.policy_generation(),
            second_policy.limits.policy_generation()
        );
        let wrapped = AtomicU64::new(u64::MAX);
        assert_eq!(take_nonzero_generation(&wrapped), None);
        assert_eq!(wrapped.load(Ordering::Relaxed), u64::MAX);
        let invalid = AtomicU64::new(0);
        assert_eq!(take_nonzero_generation(&invalid), None);
    }
    #[test]
    fn torii_policy_charges_the_transport_copy_above_core_minimum() {
        let (geometry, pool) = default_geometry();
        let policy = default_policy(geometry, &pool);
        let limits = policy.limits;
        let core_minimum = OrdinaryQueryExecutionLimits::required_execution_headroom_bytes(
            limits.max_page_items(),
            limits.max_source_item_bytes(),
            limits.max_response_bytes(),
            limits.max_request_graph_bytes(),
            limits.max_revalidation_archive_bytes(),
            limits.revalidation_decode_limits(),
        )
        .expect("Core execution geometry");
        let transport_copy = limits
            .max_response_bytes()
            .checked_add(
                u64::try_from(TORII_PROXY_REQUEST_FRAME_OVERHEAD_BYTES_V1)
                    .expect("transport overhead fits u64"),
            )
            .expect("transport copy geometry");
        assert_eq!(
            limits.execution_headroom_bytes(),
            core_minimum + transport_copy
        );
        assert!(pool.can_reserve_parts(policy.start_reservation_parts()));
        assert_eq!(
            policy.singular_execution_reservation_bytes,
            u64::try_from(geometry.fanout_working_set_bytes)
                .expect("singular working set fits u64")
        );
        assert!(pool.can_reserve_parts(policy.singular_execution_reservation_parts()));
    }
    #[test]
    fn exhausted_weighted_pool_rejects_start_without_pinning_ingress() {
        let app = mk_app_state_for_tests();
        let _fanout = app
            .query_fanout_inflight
            .try_acquire_parts([app.query_fanout_inflight.capacity_bytes()])
            .expect("fixture occupies the entire weighted pool");
        let ingress_slots = app.query_ingress_inflight.available_permits();
        let ingress = (0..ingress_slots)
            .map(|_| {
                app.query_ingress_inflight
                    .clone()
                    .try_acquire_owned()
                    .expect("test occupies an ingress slot")
            })
            .collect::<Vec<_>>();
        assert_eq!(app.query_ingress_inflight.available_permits(), 0);
        assert!(try_acquire_ordinary_query_memory(&app, true, false).is_err());
        drop(ingress);
        assert_eq!(
            app.query_ingress_inflight.available_permits(),
            ingress_slots,
            "fail-fast promotion must not retain any ingress slot"
        );
    }
    #[test]
    fn proxy_memory_promotion_ignores_the_ordinary_query_wait_timeout() {
        let mut app = mk_app_state_for_tests();
        Arc::get_mut(&mut app)
            .expect("unique test app")
            .query_queue_timeout = Duration::from_secs(60);
        let held = try_acquire_torii_proxy_memory(&app).expect("occupy proxy memory lane");
        let result = acquire_torii_proxy_memory(&app);
        assert!(result.is_err());
        drop(held);
    }
    #[test]
    fn response_body_owns_ordinary_lease_after_extension_is_removed() {
        let pool = ByteWeightedMemoryPool::with_max_permits(16, 16).expect("body test pool");
        let permit = pool.try_acquire_parts([8]).expect("body lease");
        let lease = iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease::new(
            ToriiOrdinaryQueryMemoryReservation {
                permit,
                bytes_per_permit: pool.bytes_per_permit,
                pool_generation: pool.generation(),
            },
        );
        let mut response = hold_ordinary_query_memory_in_response_body(
            Response::new(Body::from("ok")),
            OrdinaryQueryResponseMemory::new(lease),
        );
        assert_eq!(pool.available_bytes(), 8);
        let extension = response
            .extensions_mut()
            .remove::<OrdinaryQueryResponseMemory>()
            .expect("response extension");
        drop(extension);
        let (_, slow_body) = response.into_parts();
        assert_eq!(pool.available_bytes(), 8);
        drop(slow_body);
        assert_eq!(pool.available_bytes(), 16);
    }
    #[test]
    fn admitted_ordinary_output_closure_has_bounded_json_writers() {
        use iroha_data_model::query::{
            QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryResponse,
            SingularQueryOutputBox,
        };
        let iterable = |batch| {
            QueryResponse::Iterable(QueryOutput {
                batch: QueryOutputBatchBoxTuple::from_batch(batch),
                remaining_items: Some(0),
                has_more: false,
                continue_cursor: None,
            })
        };
        let responses = [
            iterable(QueryOutputBatchBox::RoleId(vec![
                "ordinary_role".parse().expect("role ID"),
            ])),
            iterable(QueryOutputBatchBox::TriggerId(vec![
                "ordinary_trigger".parse().expect("trigger ID"),
            ])),
            QueryResponse::Singular(SingularQueryOutputBox::AbiVersion(
                iroha_data_model::query::runtime::AbiVersion { abi_version: 1 },
            )),
        ];
        for response in responses {
            let exact = norito::json::to_string(&response)
                .expect("ordinary response JSON")
                .len();
            assert!(
                crate::utils::respond_with_format_bounded(
                    response.clone(),
                    ResponseFormat::Json,
                    exact,
                )
                .is_ok()
            );
            assert!(matches!(
                crate::utils::respond_with_format_bounded(
                    response,
                    ResponseFormat::Json,
                    exact - 1,
                ),
                Err(crate::utils::BoundedResponseEncodeError::JsonBodyTooLarge { .. })
            ));
        }
    }
    #[test]
    fn iterable_response_exposes_its_server_cursor_for_failure_cleanup() {
        use iroha_data_model::query::{
            QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryResponse,
            parameters::ForwardCursor,
        };
        let query_id = "ab".repeat(32);
        let response = QueryResponse::Iterable(QueryOutput {
            batch: QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::RoleId(Vec::new())),
            remaining_items: Some(1),
            has_more: true,
            continue_cursor: Some(ForwardCursor {
                query: query_id.clone(),
                cursor: std::num::NonZeroU64::new(1).expect("non-zero cursor"),
                gas_budget: None,
            }),
        });
        assert_eq!(
            query_response_cursor_query_id(&response),
            Some(query_id.as_str())
        );
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn failed_response_encoding_discards_the_stored_cursor() {
        use iroha_data_model::{
            account::Account,
            domain::Domain,
            query::{QueryRequest, parameters::ForwardCursor},
        };
        let key_pair = tests_runtime_handlers::checked_torii_test_ed25519_keypair(
            0xd7,
            "derive cursor-cleanup authority key",
        );
        let authority = AccountId::new(key_pair.public_key().clone());
        let other = tests_runtime_handlers::checked_torii_test_account_id(
            0xd8,
            "derive cursor-cleanup second account",
        );
        let domain_id: DomainId =
            DomainId::try_new("cursor_cleanup", "universal").expect("domain ID");
        let world = iroha_core::state::World::with(
            [Domain::new(domain_id).build(&authority)],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(other).build(&authority),
            ],
            [],
        );
        let app = tests_runtime_handlers::mk_app_state_for_tests_with_world(world);
        let header = BlockHeader::new(
            NonZeroU64::new(1).expect("nonzero cursor-cleanup height"),
            None,
            None,
            0,
            0,
        );
        let mut block = app.state.block(header);
        let mut transaction = block.transaction();
        transaction
            .world_mut_for_testing()
            .add_account_permission(&authority, CanReadAllLedgerData.into());
        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit cursor-cleanup permission");

        let mut query = tests_runtime_handlers::build_find_account_ids_query_for_test();
        query.params.fetch_size.fetch_size =
            Some(NonZeroU64::new(1).expect("nonzero cursor-cleanup fetch size"));
        let request = authorize_query_for_test(QueryRequest::Start(query), authority.clone());
        let response = execute_admitted_signed_query_with_opts(
            &app,
            request,
            QueryOptions {
                cursor_mode: Some("stored".to_owned()),
                ..QueryOptions::default()
            },
        )
        .await
        .expect("stored query produces a cursor-bearing response");
        let (response, memory_lease) = response.into_parts();
        let cursor: ForwardCursor = match &response {
            iroha_data_model::query::QueryResponse::Iterable(output) => output
                .continue_cursor
                .clone()
                .expect("two accounts with fetch size one produce a cursor"),
            iroha_data_model::query::QueryResponse::Singular(_) => {
                panic!("account ID query must be iterable")
            }
        };
        assert!(
            app.query_service
                .ordinary_cursor_retained_bytes(&cursor, &authority)
                .is_ok(),
            "cursor must exist before response encoding"
        );

        let encoded = encode_query_response_with_memory_lease_bounded(
            app.as_ref(),
            response,
            memory_lease,
            ResponseFormat::Json,
            1,
        );
        assert_eq!(encoded.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            app.query_service
                .ordinary_cursor_retained_bytes(&cursor, &authority)
                .is_err(),
            "an undisclosed cursor must be removed when encoding fails"
        );
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn proof_query_uses_bounded_singular_lane_and_preserves_json() {
        let (app, _, expected, signed_query_b64) = proof_query_fixture(0xD1, 0);
        let response = handler_proofs_query(
            State(app),
            HeaderMap::new(),
            crate::loopback_connect_info(),
            Some(crate::utils::extractors::ExtractAccept(
                HeaderValue::from_static("application/json"),
            )),
            NoritoJson(proof_query_dto(&signed_query_b64)),
        )
        .await
        .expect("bounded proof query executes");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("proof response body");
        let decoded: iroha_data_model::query::QueryResponse =
            norito::json::from_slice(&body).expect("decode proof JSON response");
        assert!(matches!(
            decoded,
            iroha_data_model::query::QueryResponse::Singular(
                iroha_data_model::query::SingularQueryOutputBox::ProofRecord(actual)
            ) if actual == expected
        ));
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn proof_query_fails_fast_before_consuming_the_signed_nonce() {
        let (app, _, _, signed_query_b64) = proof_query_fixture(0xD2, 0);
        let held = app
            .query_fanout_inflight
            .try_acquire_parts([app.query_fanout_inflight.capacity_bytes()])
            .expect("occupy the entire proof memory lane");
        let rejected = execute_bounded_proof_query(
            &app,
            proof_query_dto(&signed_query_b64),
            ResponseFormat::Norito,
        )
        .await
        .expect("capacity rejection is an HTTP response");
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(rejected);
        drop(held);
        let accepted = execute_bounded_proof_query(
            &app,
            proof_query_dto(&signed_query_b64),
            ResponseFormat::Norito,
        )
        .await
        .expect("the same nonce remains unused after fail-fast rejection");
        assert_eq!(accepted.status(), StatusCode::OK);
    }
    #[cfg(feature = "app_api")]
    #[test]
    fn proof_query_rejects_oversized_base64_before_versioned_decode() {
        let phase_bytes = 2;
        let envelope = QueryFanoutMemoryEnvelope::with_phase_bytes(64_000_000, 0, phase_bytes)
            .expect("small proof request envelope");
        let dto = crate::routing::ProofFindByIdQueryDto {
            signed_query_b64: "A"
                .repeat(canonical_base64_max_len(envelope.route_body_bytes).saturating_add(1)),
        };
        let response = decode_bounded_proof_query(dto, envelope)
            .err()
            .expect("oversized proof input must fail before versioned decode");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn proof_query_rejects_output_above_singular_frame_limit() {
        let (app, authority, record, _) = proof_query_fixture(0xD3, 4 * 1_024);
        let reservation = try_acquire_query_fanout_memory(&app).expect("proof memory lane");
        let phase_bytes = 2;
        let envelope = QueryFanoutMemoryEnvelope::with_phase_bytes(
            app.query_fanout_working_set_bytes,
            0,
            phase_bytes,
        )
        .expect("small singular output phase fits the full reservation");
        assert!(
            norito::core::encoded_frame_len(&record).expect("measure proof fixture")
                > envelope.candidate_encoded_bytes
        );
        let request = authorize_query_for_test(
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindProofRecordById(
                    iroha_data_model::query::proof::prelude::FindProofRecordById {
                        id: record.id.clone(),
                    },
                ),
            ),
            authority,
        );
        let response =
            execute_torii_verified_query_route_scan_locally(&app, request, envelope, reservation)
                .await
                .expect_err("oversized proof output must fail closed");
        assert!(!response.status().is_success());
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            app.query_fanout_inflight.capacity_bytes(),
            "failed proof execution releases its complete reservation"
        );
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn proof_response_slow_body_owns_the_fanout_reservation() {
        let (app, _, _, signed_query_b64) = proof_query_fixture(0xD4, 0);
        let available_before = app.query_fanout_inflight.available_bytes();
        let mut response = execute_bounded_proof_query(
            &app,
            proof_query_dto(&signed_query_b64),
            ResponseFormat::Norito,
        )
        .await
        .expect("bounded proof response");
        let available_while_live = app.query_fanout_inflight.available_bytes();
        assert!(available_while_live < available_before);
        let extension = response
            .extensions_mut()
            .remove::<QueryFanoutMemoryReservation>()
            .expect("proof response reservation extension");
        drop(extension);
        let (_, slow_body) = response.into_parts();
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            available_while_live
        );
        drop(slow_body);
        assert_eq!(
            app.query_fanout_inflight.available_bytes(),
            available_before
        );
    }
    #[cfg(feature = "app_api")]
    #[tokio::test]
    async fn proof_query_uses_the_source_bounded_ordinary_singular_lane() {
        let (app, authority, record, _) = proof_query_fixture(0xD5, 0);
        let request = authorize_query_for_test(
            iroha_data_model::query::QueryRequest::Singular(
                iroha_data_model::query::SingularQueryBox::FindProofRecordById(
                    iroha_data_model::query::proof::prelude::FindProofRecordById {
                        id: record.id.clone(),
                    },
                ),
            ),
            authority,
        );
        let response =
            execute_admitted_signed_query_with_opts(&app, request, QueryOptions::default())
                .await
                .expect("bounded proof query enters the ordinary singular lane");
        let (response, memory_lease) = response.into_parts();
        assert!(matches!(
            response,
            iroha_data_model::query::QueryResponse::Singular(
                iroha_data_model::query::SingularQueryOutputBox::ProofRecord(actual)
            ) if actual == record
        ));
        assert!(
            memory_lease.reserved_bytes()
                >= app
                    .ordinary_query_policy
                    .singular_execution_reservation_bytes
        );
    }
    #[test]
    fn bounded_norito_response_accepts_exact_f_and_rejects_f_minus_one() {
        let value = vec![1_u64, 2, 3, 5, 8];
        let exact = norito::core::to_bytes(&value)
            .expect("encode fixture")
            .len();
        assert!(crate::utils::respond_with_format_bounded(
            value.clone(),
            ResponseFormat::Norito,
            exact,
        )
        .is_ok());
        assert!(matches!(
            crate::utils::respond_with_format_bounded(value, ResponseFormat::Norito, exact - 1,),
            Err(crate::utils::BoundedResponseEncodeError::BodyTooLarge { .. })
        ));
    }
    #[tokio::test]
    async fn aborted_blocking_join_keeps_weight_until_worker_exits() {
        let pool = ByteWeightedMemoryPool::with_max_permits(16, 16).expect("cancel test pool");
        let permit = pool.try_acquire_parts([8]).expect("worker lease");
        let reservation = ToriiOrdinaryQueryMemoryReservation {
            permit,
            bytes_per_permit: pool.bytes_per_permit,
            pool_generation: pool.generation(),
        };
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).expect("signal worker entry");
            release_rx.recv().expect("release worker");
            drop(reservation);
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker entered");
        worker.abort();
        assert_eq!(pool.available_bytes(), 8);
        release_tx.send(()).expect("release detached worker");
        for _ in 0..100 {
            if pool.available_bytes() == 16 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("detached blocking worker did not release its reservation");
    }
    #[cfg(feature = "connect")]
    #[tokio::test]
    async fn proxy_snapshot_and_rebuilt_body_keep_ordinary_weight() {
        let pool = ByteWeightedMemoryPool::with_max_permits(16, 16).expect("proxy test pool");
        let permit = pool.try_acquire_parts([8]).expect("proxy lease");
        let lease = iroha_core::smartcontracts::isi::query::OrdinaryQueryMemoryLease::new(
            ToriiOrdinaryQueryMemoryReservation {
                permit,
                bytes_per_permit: pool.bytes_per_permit,
                pool_generation: pool.generation(),
            },
        );
        let response = hold_ordinary_query_memory_in_response_body(
            Response::new(Body::from("ok")),
            OrdinaryQueryResponseMemory::new(lease),
        );
        let admitted = response_to_admitted_torii_proxy_snapshot(response, 8).await;
        assert!(admitted.ordinary_query_memory.is_some());
        assert_eq!(pool.available_bytes(), 8);
        let mut rebuilt = admitted_torii_proxy_snapshot_to_response(admitted);
        let extracted = take_ordinary_query_memory_reservation(&mut rebuilt)
            .expect("rebuilt response extension");
        drop(extracted);
        let (_, slow_body) = rebuilt.into_parts();
        assert_eq!(pool.available_bytes(), 8);
        drop(slow_body);
        assert_eq!(pool.available_bytes(), 16);
    }
}
