// Focused cross-dataspace fanout allocation and pagination bounds.
fn fanout_memory_test_request(
    limit: Option<u64>,
) -> iroha_data_model::query::QueryRequestWithAuthority {
    authorize_query_for_test(
        iroha_data_model::query::json::IterableQueryJson {
            kind: iroha_data_model::query::json::IterableQueryKind::FindDomains,
            params: iroha_data_model::query::json::IterableQueryParamsJson {
                limit,
                offset: None,
                fetch_size: Some(1),
                sort_by_metadata_key: None,
                order: None,
            },
            predicate: None,
        }
        .into_request()
        .expect("iterable request should build"),
        iroha_test_samples::ALICE_ID.clone(),
    )
}
#[test]
fn unbounded_iterable_fanout_is_rejected_by_explicit_capability_map() {
    let response = ensure_bounded_fanout_query(&fanout_memory_test_request(Some(1)))
        .expect_err("FindDomains must fail before any route executes");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("query_unsupported")
    );
}
#[test]
fn opaque_fast_dsl_identity_query_fails_closed() {
    let request = authorize_query_for_test(
        iroha_data_model::query::json::IterableQueryJson {
            kind: iroha_data_model::query::json::IterableQueryKind::FindRoleIds,
            params: iroha_data_model::query::json::IterableQueryParamsJson {
                limit: Some(1),
                ..Default::default()
            },
            predicate: None,
        }
        .into_request()
        .expect("role-id request should build"),
        iroha_test_samples::ALICE_ID.clone(),
    );
    let response = ensure_bounded_fanout_query(&request)
        .expect_err("opaque fast-DSL components must fail closed");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[test]
fn singular_fanout_is_admitted_without_a_variant_allowlist() {
    let request = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAbiVersion(
                iroha_data_model::query::runtime::prelude::FindAbiVersion,
            ),
        ),
        iroha_test_samples::ALICE_ID.clone(),
    );
    ensure_bounded_fanout_query(&request).expect("every singular arm uses the bounded corridor");
}
#[test]
fn singular_fanout_retains_only_the_first_matching_result() {
    let output = |abi_version| {
        iroha_data_model::query::SingularQueryOutputBox::AbiVersion(
            iroha_data_model::query::runtime::AbiVersion { abi_version },
        )
    };
    let mut retained = None;
    retain_matching_singular_fanout_output(&mut retained, output(1))
        .expect("first route result is retained");
    retain_matching_singular_fanout_output(&mut retained, output(1))
        .expect("an equal current result is compared and dropped");
    assert_eq!(retained, Some(output(1)));
    let response = retain_matching_singular_fanout_output(&mut retained, output(2))
        .expect_err("different route results must conflict");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(retained, Some(output(1)));
}
#[test]
fn singular_fanout_drops_decoded_template_before_route_loop() {
    let source = include_str!("../../lib.rs");
    let singular = source
        .split_once("async fn execute_torii_singular_query_via_fanout_for_routes_admitted")
        .expect("singular fanout function remains present")
        .1
        .split_once("async fn execute_torii_query_via_fanout_for_routes_admitted")
        .expect("generic fanout function follows the singular implementation")
        .0;
    let template_drop = singular
        .find("drop(verified_query);")
        .expect("decoded singular template is explicitly dropped");
    let route_loop = singular
        .find("for route in routes")
        .expect("singular fanout remains sequential");
    assert!(template_drop < route_loop);
    assert!(singular.contains("decode_verified_singular_fanout_request_bounded"));
    assert!(!singular.contains("clone_verified_query_request_bounded"));
}
#[test]
fn canonical_unit_payload_rejects_nonempty_bytes_without_decoding() {
    let mut hostile = [0_u8; 32];
    hostile[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(bounded_unit_query_payload_matches(&[]));
    assert!(
        !bounded_unit_query_payload_matches(&hostile),
        "a non-unit query sharing RoleId/TriggerId output must fail on raw payload shape"
    );
}
#[test]
fn query_fanout_slot_count_enforces_aggregate_byte_budget() {
    assert_eq!(
        query_fanout_slot_count(128_000_000, 64_000_000, 32).map(NonZeroUsize::get),
        Some(2)
    );
    assert_eq!(
        query_fanout_slot_count(512_000_000, 64_000_000, 3).map(NonZeroUsize::get),
        Some(3),
        "the general heavy-query ceiling must still bound fanout concurrency"
    );
    assert_eq!(query_fanout_slot_count(63_999_999, 64_000_000, 32), None);
    assert_eq!(query_fanout_slot_count(128_000_000, 0, 32), None);
}
#[test]
fn fanout_envelope_charges_exact_signed_and_verified_request_frames() {
    let unit = 2_048_usize;
    let working_set = query_fanout_fixed_overhead_bytes()
        .and_then(|fixed| {
            unit.checked_mul(QUERY_FANOUT_PREBODY_UNITS)
                .and_then(|variable| fixed.checked_add(variable))
        })
        .expect("fanout exact boundary fits usize");
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(working_set, unit, unit)
        .expect("seven signed frames, one verified frame, and seven phases fit exactly");
    assert_eq!(envelope.request_bytes, unit * 8);
    assert_eq!(envelope.accumulator_retained_bytes, unit);
    assert_eq!(envelope.final_body_bytes, unit * 2);
    assert!(envelope.phases_fit());
    assert!(
        QueryFanoutMemoryEnvelope::for_request_lengths(working_set, unit, unit + 1).is_err(),
        "the verified frame is measured independently and cannot exceed its admission unit"
    );
}
#[test]
fn fanout_envelope_covers_outer_and_local_core_accumulators() {
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 4_096, 8_192)
        .expect("test envelope should fit");
    let local_scan = checked_sum([
        envelope.request_decode_allocated_bytes,
        envelope.accumulator_retained_bytes,
        envelope.accumulator_retained_bytes,
        envelope.candidate_allocation_bytes,
        envelope.candidate_encoded_bytes,
    ])
    .expect("test phase accounting fits usize");
    let admitted = envelope
        .working_set_bytes
        .checked_sub(envelope.request_bytes)
        .and_then(|remaining| {
            remaining.checked_sub(
                query_fanout_fixed_overhead_bytes().expect("fanout fixed overhead fits usize"),
            )
        })
        .expect("admitted phase bytes fit checked subtraction");
    assert!(local_scan <= admitted);
    let final_encode = checked_sum([
        envelope.decode_allocated_bytes,
        envelope.final_body_bytes,
        envelope.final_body_bytes,
    ])
    .expect("test final phase accounting fits usize");
    assert!(final_encode <= admitted);
    assert_eq!(
        envelope.final_body_bytes,
        envelope
            .decode_allocated_bytes
            .checked_mul(2)
            .expect("two decode units fit usize"),
        "the final phase must reserve two units for cache-free identifier encoding scratch"
    );
    assert_eq!(
        iroha_core::smartcontracts::isi::query::canonical_query_candidate_allocation_bytes(
            u64::try_from(envelope.candidate_encoded_bytes).expect("candidate cap fits u64"),
        ),
        Some(
            u64::try_from(envelope.candidate_allocation_bytes)
                .expect("candidate allocation cap fits u64")
        ),
        "Torii must charge Core's complete frame-capacity and retained-node envelope"
    );
    let next_encoded = envelope
        .candidate_encoded_bytes
        .checked_add(1)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .expect("next candidate cap fits u64");
    let next_allocation =
        iroha_core::smartcontracts::isi::query::canonical_query_candidate_allocation_bytes(
            next_encoded,
        )
        .and_then(|bytes| usize::try_from(bytes).ok())
        .expect("next candidate allocation fits usize");
    assert!(
        next_allocation > envelope.candidate_allocation_bytes,
        "one frame byte above the admitted candidate cap must exceed its phase"
    );
    assert!(envelope.phases_fit());
}
#[test]
fn fanout_envelope_covers_retain_first_singular_comparison() {
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 4_096, 8_192)
        .expect("test envelope should fit");
    let retained_first_route = envelope.decode_allocated_bytes;
    let retained_core_builder = envelope.decode_allocated_bytes;
    let current_source_or_decode = envelope.decode_allocated_bytes;
    let singular_compare = checked_sum([
        envelope.request_decode_allocated_bytes,
        retained_first_route,
        retained_core_builder,
        current_source_or_decode,
        envelope.candidate_encoded_bytes,
        envelope.candidate_encoded_bytes,
        envelope.candidate_encoded_bytes,
    ])
    .expect("singular comparison phase fits usize");
    let admitted = envelope
        .working_set_bytes
        .checked_sub(envelope.request_bytes)
        .and_then(|remaining| {
            remaining.checked_sub(
                query_fanout_fixed_overhead_bytes().expect("fanout fixed overhead fits usize"),
            )
        })
        .expect("admitted phase bytes fit checked subtraction");
    assert!(singular_compare <= admitted);
    assert_eq!(
        retained_core_builder, current_source_or_decode,
        "one retained builder and exactly one maximum current share distinct resident phases"
    );
    let limits = envelope.singular_output_limits();
    assert_eq!(
        limits.max_frame_bytes(),
        u64::try_from(envelope.candidate_encoded_bytes).expect("frame limit fits u64")
    );
    assert_eq!(
        limits.max_allocated_bytes(),
        u64::try_from(envelope.decode_allocated_bytes).expect("decode limit fits u64")
    );
}
#[test]
fn fanout_fixed_overhead_matches_config_default() {
    let runtime = query_fanout_fixed_overhead_bytes()
        .expect("runtime fanout fixed overhead must fit the platform address space");
    let runtime =
        u64::try_from(runtime).expect("runtime fanout fixed overhead must fit the config type");
    assert_eq!(
        runtime,
        iroha_config::parameters::defaults::torii::QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1,
        "the config default must track the runtime protocol-derived fixed envelope"
    );
}
#[test]
fn fanout_fixed_overhead_covers_the_protocol_route_catalogue() {
    let ingress_fixed = query_ingress_fixed_overhead_bytes()
        .expect("ingress fixed overhead must fit the platform address space");
    assert_eq!(
        ingress_fixed,
        QUERY_FANOUT_BASE_OVERHEAD_BYTES
            + QUERY_FANOUT_ROUTE_OVERHEAD_BYTES
                * iroha_data_model::nexus::MAX_ACTIVE_EXECUTION_LANES
            + QUERY_FANOUT_PUBLIC_KEY_VALIDATION_SCRATCH_BYTES
    );
    let candidate_snapshot = query_fanout_candidate_snapshot_overhead_bytes()
        .expect("candidate snapshot overhead must fit the platform address space");
    let per_candidate = iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES
        .checked_mul(QUERY_FANOUT_CANDIDATE_IDENTITY_REPRESENTATIONS)
        .and_then(|bytes| {
            bytes.checked_add(iroha_core::governance::manifest::MANIFEST_SOURCE_MAX_VALUE_BYTES_V1)
        })
        .and_then(|bytes| bytes.checked_add(QUERY_FANOUT_CANDIDATE_CONTAINER_OVERHEAD_BYTES))
        .expect("per-candidate accounting fits usize");
    assert_eq!(
        candidate_snapshot,
        per_candidate * iroha_core::governance::manifest::LANE_MANIFEST_MAX_VALIDATORS_V1,
        "one sequential candidate snapshot must charge all 256 bounded manifest statuses"
    );
    assert_eq!(
        query_fanout_fixed_overhead_bytes(),
        ingress_fixed
            .checked_add(QUERY_FANOUT_SOURCE_OVERHEAD_BYTES)
            .and_then(|bytes| bytes.checked_add(candidate_snapshot))
    );
    assert!(
        QUERY_FANOUT_ROUTE_OVERHEAD_BYTES
            >= core::mem::size_of::<(
                iroha_model_base::topology::DataSpaceId,
                iroha_model_base::topology::LaneId,
            )>() + core::mem::size_of::<RoutingDecision>(),
        "the per-route charge must cover map payload plus the collected route"
    );
    assert_eq!(
        QUERY_FANOUT_SOURCE_OVERHEAD_BYTES,
        usize::try_from(
            iroha_core::smartcontracts::isi::query::CANONICAL_QUERY_PREBOUNDED_SOURCE_BYTES
        )
        .expect("Core source bound fits usize")
    );
    assert_eq!(
        QUERY_FANOUT_PUBLIC_KEY_VALIDATION_SCRATCH_BYTES,
        iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES
    );
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 4_096, 8_192)
        .expect("the protocol-fixed validation scratch fits the working set");
    let local_scan = checked_sum([
        envelope.request_decode_allocated_bytes,
        envelope.accumulator_retained_bytes,
        envelope.accumulator_retained_bytes,
        envelope.candidate_allocation_bytes,
        envelope.candidate_encoded_bytes,
    ])
    .expect("test local phase accounting fits usize");
    let route_catalogue = QUERY_FANOUT_ROUTE_OVERHEAD_BYTES
        .checked_mul(iroha_data_model::nexus::MAX_ACTIVE_EXECUTION_LANES)
        .expect("route catalogue accounting fits usize");
    let accounted_peak = checked_sum([
        envelope.request_bytes,
        QUERY_FANOUT_BASE_OVERHEAD_BYTES,
        route_catalogue,
        QUERY_FANOUT_SOURCE_OVERHEAD_BYTES,
        QUERY_FANOUT_PUBLIC_KEY_VALIDATION_SCRATCH_BYTES,
        candidate_snapshot,
        local_scan,
    ])
    .expect("complete test accounting fits usize");
    assert!(accounted_peak <= envelope.working_set_bytes);
}
#[cfg(feature = "connect")]
#[test]
fn huge_online_population_does_not_expand_authoritative_candidate_partition() {
    const ONLINE_PEERS: u32 = 4_096;
    const AUTHORITATIVE_PEERS: usize =
        iroha_core::governance::manifest::LANE_MANIFEST_MAX_VALIDATORS_V1;
    let peers = (0..ONLINE_PEERS)
        .map(|index| {
            let mut seed = vec![0x5a_u8; 32];
            seed[..4].copy_from_slice(&(index + 1).to_le_bytes());
            let keypair = KeyPair::try_from_seed(seed, iroha_crypto::Algorithm::Ed25519)
                .expect("derive hostile online-population fixture key");
            Peer::new(
                format!("127.0.0.1:{}", 10_000 + index)
                    .parse()
                    .expect("valid hostile online-population address"),
                keypair.public_key().clone(),
            )
        })
        .collect::<Vec<_>>();
    let statuses = peers
        .iter()
        .take(AUTHORITATIVE_PEERS)
        .map(|peer| AuthoritativeLanePeerStatus {
            peer_id: peer.id().clone(),
            torii_url: None,
        })
        .collect::<Vec<_>>();
    let expected = statuses
        .iter()
        .map(|status| status.peer_id.clone())
        .collect::<Vec<_>>();
    let (_online_tx, online_rx) =
        tokio::sync::watch::channel(peers.into_iter().collect::<std::collections::HashSet<_>>());
    let provider = OnlinePeersProvider::new_with_response_limit(online_rx, 1);
    let first = partition_authoritative_lane_peer_statuses(&provider, statuses.clone());
    let second = partition_authoritative_lane_peer_statuses(&provider, statuses);
    assert_eq!(first.authoritative_total_count, AUTHORITATIVE_PEERS);
    assert_eq!(first.authoritative, expected);
    assert_eq!(first.online, expected);
    assert!(first.offline.is_empty());
    assert_eq!(
        second.authoritative_total_count,
        first.authoritative_total_count
    );
    assert_eq!(second.authoritative, first.authoritative);
    assert_eq!(second.online, first.online);
    assert_eq!(second.offline, first.offline);
    assert!(usize::try_from(ONLINE_PEERS).unwrap() > first.online.len());
}
#[test]
fn fanout_request_charge_does_not_multiply_by_route_count() {
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 1_024, 2_048)
        .expect("test envelope should fit");
    for _route in 0..10_000 {
        assert_eq!(envelope.request_bytes, 9_216);
        assert!(envelope.phases_fit());
    }
}
#[test]
fn fanout_request_representation_depth_is_named_and_checked() {
    assert_eq!(QUERY_FANOUT_HTTP_SIGNED_REQUEST_REPRESENTATIONS, 6);
    assert_eq!(QUERY_FANOUT_P2P_SIGNED_REQUEST_REPRESENTATIONS, 7);
    assert_eq!(QUERY_FANOUT_SIGNED_REQUEST_REPRESENTATIONS, 7);
    assert_eq!(QUERY_FANOUT_VERIFIED_REQUEST_REPRESENTATIONS, 1);
    assert_eq!(QUERY_FANOUT_PHASE_COUNT, 7);
    assert_eq!(QUERY_FANOUT_PREBODY_UNITS, 15);
    let signed = 3_usize;
    let verified = 5_usize;
    assert_eq!(
        signed * QUERY_FANOUT_HTTP_SIGNED_REQUEST_REPRESENTATIONS + verified,
        23,
        "HTTP owns six signed-query-sized representations before transport handoff"
    );
    assert_eq!(
        QueryFanoutMemoryEnvelope::retained_request_bytes(signed, verified),
        Some(26),
        "P2P adds exactly one outer NetworkMessage representation"
    );
    assert_eq!(
        QueryFanoutMemoryEnvelope::retained_request_bytes(usize::MAX / 7 + 1, 0),
        None,
        "representation accounting must reject multiplication overflow"
    );
}
#[test]
fn fanout_prebody_exact_boundary_and_checked_phase_overflow() {
    let working_set = 64_000_000;
    let provisional = QueryFanoutMemoryEnvelope::for_body_admission(working_set)
        .expect("pre-body envelope should fit");
    let unit = provisional.route_body_bytes;
    QueryFanoutMemoryEnvelope::for_request_lengths(working_set, unit, unit)
        .expect("the exact 7Q + E + 7P boundary must make progress");
    assert!(
        QueryFanoutMemoryEnvelope::for_request_lengths(working_set, unit + 1, unit).is_err(),
        "one signed-query byte above the pre-body unit must fail before decode"
    );
    let near_overflow = QueryFanoutMemoryEnvelope {
        working_set_bytes: usize::MAX,
        request_bytes: usize::MAX,
        request_decode_allocated_bytes: usize::MAX,
        accumulator_retained_bytes: usize::MAX,
        route_body_bytes: usize::MAX,
        decode_allocated_bytes: usize::MAX,
        candidate_allocation_bytes: usize::MAX,
        candidate_encoded_bytes: usize::MAX,
        final_body_bytes: usize::MAX,
    };
    assert!(
        !near_overflow.phases_fit(),
        "checked admission arithmetic must never turn saturation into success"
    );
}
#[test]
fn query_memory_geometry_splits_one_aggregate_pool_without_overcommit() {
    let aggregate = 64_000_000;
    let geometry = query_memory_geometry(aggregate, 48_000_000, 64_000_000, 32)
        .expect("default-sized aggregate pool should admit both lanes");
    assert_eq!(geometry.ingress_slots.get(), QUERY_INGRESS_SLOT_COUNT);
    assert!(geometry.ingress.phases_fit());
    assert!(
        QueryFanoutMemoryEnvelope::for_body_admission(geometry.fanout_working_set_bytes).is_ok()
    );
    let ingress_reserved = geometry.ingress.slot_bytes * geometry.ingress_slots.get();
    let fanout_reserved = geometry.fanout_working_set_bytes * geometry.fanout_slots.get();
    assert!(ingress_reserved + fanout_reserved <= aggregate);
    assert!(geometry.fanout_working_set_bytes < aggregate);
    assert!(
        query_memory_geometry(
            usize::try_from(
                iroha_config::parameters::defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1
            )
            .expect("V1 pool minimum fits usize"),
            48_000_000,
            1,
            32,
        )
        .is_some(),
        "the minimum pool must admit fixed overhead even with a one-byte general body cap"
    );
    assert!(
        query_memory_geometry(64_000_000, 48_000_000, 1, 32).is_some(),
        "small valid body limits must derive a complete slot instead of being disabled"
    );
}

#[test]
fn query_memory_geometry_separates_complete_request_ceiling_from_concurrency() {
    let cap = 48_000_000;
    let small = query_memory_geometry(64_000_000, cap, 64_000_000, 32).unwrap();
    let default = query_memory_geometry(512_000_000, cap, 64_000_000, 32).unwrap();
    assert_eq!(small.fanout_working_set_bytes, cap);
    assert_eq!(default.fanout_working_set_bytes, cap);
    assert_eq!(small.fanout_slots.get(), 1);
    assert_eq!(default.fanout_slots.get(), 8);
    assert_eq!(default.fanout_pool_bytes, 384_000_000);
    assert_eq!(
        default.ingress.slot_bytes * default.ingress_slots.get(),
        128_000_000
    );
    assert!(default.ingress.phases_fit());
    let envelope = QueryFanoutMemoryEnvelope::for_body_admission(cap).unwrap();
    assert!(envelope.phases_fit());
    assert!(default.ingress.body_bytes <= envelope.route_body_bytes);
    let bounded = query_memory_geometry(512_000_000, cap, 64_000_000, 2).unwrap();
    assert_eq!(bounded.fanout_slots.get(), 2);
    let smaller = query_memory_geometry(48_000_000, cap, 64_000_000, 32).unwrap();
    assert_eq!(smaller.fanout_working_set_bytes, 36_000_000);
    assert!(
        QueryFanoutMemoryEnvelope::for_body_admission(smaller.fanout_working_set_bytes)
            .unwrap()
            .phases_fit()
    );
    assert!(query_memory_geometry(512_000_000, 0, 64_000_000, 32).is_none());
    assert!(query_memory_geometry(512_000_000, 1, 64_000_000, 32).is_none());
}

#[test]
fn query_memory_pool_admits_eight_portal_reads_without_raising_request_limits() {
    let per_request_bytes = 192_000_000;
    let previous = query_memory_geometry(512_000_000, per_request_bytes, 64_000_000, 64)
        .expect("previous query pool is valid");
    let expanded = query_memory_geometry(2_048_000_000, per_request_bytes, 64_000_000, 64)
        .expect("expanded query pool is valid");
    assert_eq!(previous.fanout_slots.get(), 2);
    assert_eq!(expanded.fanout_slots.get(), 8);
    for geometry in [&previous, &expanded] {
        assert_eq!(geometry.fanout_working_set_bytes, per_request_bytes);
        let pool = ByteWeightedMemoryPool::new(geometry.fanout_pool_bytes)
            .expect("query pool fits the weighted semaphore");
        assert!(
            pool.try_acquire_parts([pool.capacity_bytes() + 1])
                .is_none()
        );
        let mut retained_responses = Vec::new();
        for _ in 0..geometry.fanout_slots.get() {
            retained_responses.push(
                pool.try_acquire_parts([per_request_bytes as u64])
                    .expect("each normal portal read owns its complete working set"),
            );
        }
        assert_eq!(pool.available_bytes(), 0);
        assert!(pool.try_acquire_parts([per_request_bytes as u64]).is_none());
        drop(retained_responses.pop());
        let next = pool
            .try_acquire_parts([per_request_bytes as u64])
            .expect("draining one response admits the next read");
        assert!(pool.try_acquire_parts([per_request_bytes as u64]).is_none());
        drop(next);
        drop(retained_responses);
        assert_eq!(pool.available_bytes(), pool.capacity_bytes());
    }
    let previous_envelope =
        QueryFanoutMemoryEnvelope::for_body_admission(previous.fanout_working_set_bytes).unwrap();
    let expanded_envelope =
        QueryFanoutMemoryEnvelope::for_body_admission(expanded.fanout_working_set_bytes).unwrap();
    assert_eq!(
        previous_envelope.route_body_bytes,
        expanded_envelope.route_body_bytes
    );
}

#[test]
fn query_memory_parser_geometry_matches_runtime_complete_phases() {
    use iroha_config::parameters::defaults::torii as config;
    assert_eq!(
        query_fanout_fixed_overhead_bytes().unwrap() as u64,
        config::QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1
    );
    assert_eq!(
        query_ingress_fixed_overhead_bytes().unwrap() as u64,
        config::QUERY_INGRESS_FIXED_OVERHEAD_BYTES_V1
    );
    assert_eq!(
        QUERY_FANOUT_PREBODY_UNITS as u64,
        config::QUERY_FANOUT_PREBODY_UNITS_V1
    );
    assert_eq!(
        QUERY_INGRESS_POOL_DIVISOR as u64,
        config::QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1
    );
    assert_eq!(
        QUERY_INGRESS_SLOT_COUNT as u64,
        config::QUERY_MEMORY_INGRESS_SLOTS_V1
    );
    assert_eq!(
        QUERY_INGRESS_PHASE_UNITS as u64,
        config::QUERY_INGRESS_PHASE_UNITS_V1
    );
    for (aggregate, ceiling, content) in [
        (20_000_000, 48_000_000, 64_000_000),
        (64_000_000, 48_000_000, 64_000_000),
        (512_000_000, 48_000_000, 64_000_000),
        (512_000_000, 36_000_000, 64_000_000),
        (512_000_000, 48_000_000, 8 * 1024),
    ] {
        let geometry = query_memory_geometry(aggregate, ceiling, content, 32).unwrap();
        let envelope =
            QueryFanoutMemoryEnvelope::for_body_admission(geometry.fanout_working_set_bytes)
                .unwrap();
        assert_eq!(
            geometry.fanout_working_set_bytes as u64,
            config::query_fanout_working_set_bytes(
                aggregate as u64,
                ceiling as u64,
                content as u64
            )
            .unwrap()
        );
        assert_eq!(
            envelope.route_body_bytes as u64,
            config::app_api_routed_read_route_body_phase_bytes(
                aggregate as u64,
                ceiling as u64,
                content as u64
            )
            .unwrap()
        );
        assert_eq!(
            geometry.ingress.body_bytes as u64,
            config::query_ingress_body_phase_bytes(
                aggregate as u64,
                ceiling as u64,
                content as u64
            )
            .unwrap()
        );
        assert!(geometry.ingress.body_bytes >= 8 * 1024);
        assert!(envelope.route_body_bytes >= 8 * 1024);
        assert!(geometry.ingress.phases_fit());
        assert!(envelope.phases_fit());
    }
}
#[test]
fn ingress_envelope_accounts_raw_decode_canonical_and_scope_phases() {
    let fixed = query_ingress_fixed_overhead_bytes().expect("ingress fixed overhead fits usize");
    assert_eq!(QUERY_INGRESS_PHASE_UNITS, 5);
    let slot = fixed + QUERY_INGRESS_PHASE_UNITS * 17;
    let envelope = QueryIngressMemoryEnvelope::from_slot_bytes(slot, usize::MAX)
        .expect("exact ingress phase boundary should fit");
    assert_eq!(envelope.body_bytes, 17);
    assert_eq!(envelope.decode_allocated_bytes, 17);
    assert_eq!(envelope.canonical_encoded_bytes, 17);
    assert_eq!(envelope.scope_decode_allocated_bytes, 17);
    assert_eq!(envelope.scope_canonical_encoded_bytes, 17);
    assert!(envelope.phases_fit());
    assert!(QueryIngressMemoryEnvelope::from_slot_bytes(fixed, usize::MAX).is_none());
}
#[test]
fn internal_proxy_http_envelope_accounts_decode_shared_frame_local_clone_and_scratch() {
    let fixed = query_fanout_fixed_overhead_bytes().expect("proxy fixed overhead fits usize");
    let envelope = ToriiProxyHttpIngressEnvelope::from_max_content_bytes(17)
        .expect("exact proxy HTTP phase boundary should fit");
    assert_eq!(
        envelope.working_set_bytes,
        fixed + TORII_PROXY_RETRYABLE_RETAINED_BODY_BYTES_V1 + 5 * 17
    );
    let omitted = ToriiProxyHttpIngressEnvelope {
        working_set_bytes: envelope.working_set_bytes
            - TORII_PROXY_RETRYABLE_RETAINED_BODY_BYTES_V1,
        ..envelope
    };
    assert!(
        !omitted.phases_fit(),
        "omitting the retained retry diagnostic reservation must fail admission"
    );
    assert_eq!(envelope.body_bytes, 17);
    assert_eq!(envelope.decode_allocated_bytes, 17);
    assert_eq!(envelope.forwarded_request_bytes, 17);
    assert_eq!(envelope.forwarding_transient_bytes, 17);
    assert!(envelope.phases_fit());
    let undersized = ToriiProxyHttpIngressEnvelope {
        working_set_bytes: envelope.working_set_bytes - 1,
        ..envelope
    };
    assert!(
        !undersized.phases_fit(),
        "the local clone, fixed response window and reduction scratch must all be charged"
    );
}
#[test]
fn public_ingress_and_local_clone_share_one_fanout_decode_phase() {
    let geometry = query_memory_geometry(64_000_000, 48_000_000, 64_000_000, 32)
        .expect("default query-memory geometry should fit");
    let provisional =
        QueryFanoutMemoryEnvelope::for_body_admission(geometry.fanout_working_set_bytes)
            .expect("provisional fanout geometry should fit");
    let ingress_decode = geometry
        .ingress
        .request_decode_limits(provisional)
        .expect("bounded ingress decode limits should fit")
        .max_total_allocated_bytes();
    let local_clone_decode = provisional
        .request_decode_limits(geometry.ingress.body_bytes)
        .expect("bounded local-clone decode limits should fit")
        .max_total_allocated_bytes();
    assert!(
        ingress_decode + local_clone_decode <= provisional.request_decode_allocated_bytes,
        "the retained ingress request and one local clone must fit fanout's single D phase"
    );
}
#[test]
fn skewed_query_memory_pool_cannot_raise_ingress_above_fanout_or_content_cap() {
    let max_content = 1;
    let geometry = query_memory_geometry(1024 * 1024 * 1024, 48_000_000, max_content, 32)
        .expect("large aggregate and minimum content geometry should fit");
    let fanout = QueryFanoutMemoryEnvelope::for_body_admission(geometry.fanout_working_set_bytes)
        .expect("derived fanout geometry should fit");
    assert_eq!(geometry.ingress.body_bytes, max_content);
    assert!(geometry.ingress.body_bytes <= fanout.route_body_bytes);
    let minimum_candidate_bytes = usize::try_from(
        iroha_core::smartcontracts::isi::query::canonical_query_candidate_allocation_bytes(1)
            .expect("minimum canonical candidate allocation"),
    )
    .expect("minimum candidate allocation fits usize");
    assert!(fanout.route_body_bytes >= minimum_candidate_bytes);
    assert!(fanout.candidate_allocation_bytes <= fanout.route_body_bytes);
    assert!(fanout.phases_fit());
    assert!(
        QueryFanoutMemoryEnvelope::with_phase_bytes(
            geometry.fanout_working_set_bytes,
            0,
            minimum_candidate_bytes - 1,
        )
        .is_err(),
        "one byte below the real canonical allocation floor must still fail"
    );
}
#[test]
fn fanout_decode_limits_use_the_reserved_allocation_phase() {
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 1_024, 2_048)
        .expect("test envelope should fit");
    let limits = envelope
        .response_decode_limits(4_096)
        .expect("bounded response decode limits should fit");
    assert_eq!(limits.max_field_bytes(), 4_096);
    assert_eq!(
        limits.max_total_allocated_bytes(),
        envelope.decode_allocated_bytes
    );
    assert_eq!(
        limits.max_nesting_depth(),
        norito::core::MAX_VALUE_NESTING_DEPTH
    );
    assert_eq!(
        envelope
            .request_decode_limits(4_096)
            .expect("bounded request decode limits should fit")
            .max_total_allocated_bytes(),
        envelope.request_decode_allocated_bytes / 2,
        "the retained coordinator request and one local clone split D exactly"
    );
    assert_eq!(
        envelope
            .query_scope_limits()
            .decode_limits(4_096)
            .expect("bounded scope decode limits should fit")
            .max_total_allocated_bytes(),
        envelope.request_decode_allocated_bytes / 4,
        "a nested scope query and its extracted route identifier split the other half of D"
    );
}
#[test]
fn ingress_scope_cannot_borrow_the_larger_unowned_fanout_limit() {
    let geometry = query_memory_geometry(64_000_000, 48_000_000, 64_000_000, 32)
        .expect("default query-memory geometry should fit");
    let fanout = QueryFanoutMemoryEnvelope::for_body_admission(geometry.fanout_working_set_bytes)
        .expect("default fanout envelope should fit");
    let ingress_limits = geometry.ingress.query_scope_limits();
    let fanout_limits = fanout.query_scope_limits();
    let hostile_len = ingress_limits.decode_allocated_bytes + 1;
    assert!(
        hostile_len <= fanout_limits.decode_allocated_bytes,
        "fixture must fit provisional fanout while exceeding held ingress"
    );
    let hostile_payload = vec![0_u8; hostile_len];
    let response =
        decode_query_payload_bounded::<iroha_data_model::prelude::FindDomainsByAccountId>(
            &hostile_payload,
            ingress_limits,
        )
        .expect_err("unowned fanout capacity must not authorize nested decode");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .and_then(|value| value.to_str().ok()),
        Some("query_capacity_exceeded")
    );
}
#[test]
fn prebody_geometry_cannot_shrink_after_exact_request_measurement() {
    let working_set = 64_000_000;
    let provisional = QueryFanoutMemoryEnvelope::for_body_admission(working_set)
        .expect("pre-body admission geometry should fit");
    let exact = QueryFanoutMemoryEnvelope::for_request_lengths(
        working_set,
        provisional.route_body_bytes,
        provisional.candidate_encoded_bytes,
    )
    .expect("the two admitted frame limits must fit their exact envelope");
    assert!(exact.route_body_bytes >= provisional.route_body_bytes);
    assert!(
        exact.request_decode_allocated_bytes >= provisional.request_decode_allocated_bytes,
        "bounded initial decode remains within the exact post-verification envelope"
    );
}
#[test]
fn fanout_decode_budget_accepts_exact_bound_and_rejects_next_byte() {
    let mut budget = ToriiFanoutDecodeBudget::new(8);
    budget.charge(8).expect("the exact budget must fit");
    assert!(budget.remaining().is_err());
    assert!(budget.charge(1).is_err());
}
#[test]
fn versioned_ingress_counts_bad_exact_serializer_before_destination_allocation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_torii::torii_routed_read_tests::versioned_ingress_counts_bad_exact_serializer_before_destination_allocation::BadExact"
    )]
    struct BadExact<'a> {
        calls: &'a AtomicUsize,
        payload: [u8; 32],
    }
    impl norito::core::SerializePayload for BadExact<'_> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::io::Write::write_all(writer, &self.payload)?;
            Ok(())
        }
        fn encoded_len_exact(&self) -> Option<usize> {
            Some(0)
        }
    }
    impl iroha_version::Version for BadExact<'_> {
        fn version(&self) -> u8 {
            1
        }
        fn supported_versions() -> core::ops::Range<u8> {
            1..2
        }
    }
    let calls = AtomicUsize::new(0);
    let hostile = BadExact {
        calls: &calls,
        payload: [0x5a; 32],
    };
    let rejection = encode_versioned_norito_bounded(&hostile, 32)
        .expect_err("the real 33-byte versioned frame must exceed the 32-byte cap");
    assert_eq!(rejection.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the rejected value must only run the sink preflight, never destination encoding"
    );
    let encoded = encode_versioned_norito_bounded(&hostile, 33)
        .expect("the exact real frame boundary should fit");
    assert_eq!(encoded.len(), 33);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
#[test]
fn versioned_ingress_accepts_payload_only_roots_without_frame_identity() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // No NoritoSchema: this helper emits a version byte and adaptive payload.
    struct PayloadOnly<'a>(&'a AtomicUsize);
    impl norito::core::SerializePayload for PayloadOnly<'_> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::io::Write::write_all(writer, &[0xA5; 4])?;
            Ok(())
        }
    }
    impl iroha_version::Version for PayloadOnly<'_> {
        fn version(&self) -> u8 {
            1
        }
        fn supported_versions() -> core::ops::Range<u8> {
            1..2
        }
    }
    let calls = AtomicUsize::new(0);
    let payload = PayloadOnly(&calls);
    let rejected = encode_versioned_norito_bounded(&payload, 4)
        .expect_err("the version byte is part of the exact admission bound");
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let bytes = encode_versioned_norito_bounded(&payload, 5)
        .expect("a payload-only root fits its exact versioned boundary");
    assert_eq!(bytes, [1, 0xA5, 0xA5, 0xA5, 0xA5]);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
#[test]
fn fixed_capacity_norito_writer_refuses_growth_past_preflight() {
    use std::io::Write as _;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(3)
        .expect("three-byte test destination should reserve");
    let mut writer = FixedCapacityNoritoWriter {
        bytes: &mut bytes,
        max_bytes: 3,
    };
    writer
        .write_all(&[1, 2, 3])
        .expect("exact counted payload should fit");
    assert!(writer.write_all(&[4]).is_err());
    assert_eq!(bytes, [1, 2, 3]);
}
#[tokio::test]
async fn non_norito_signed_query_is_rejected_before_body_memory_admission() {
    let authority = routed_read_test_account(0xd7);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let ingress_before = app.query_ingress_inflight.available_permits();
    let fanout_before = app.query_fanout_inflight.available_permits();
    for content_type in [Some("text/plain"), None] {
        let mut builder = axum::extract::Request::builder();
        if let Some(content_type) = content_type {
            builder = builder.header(axum::http::header::CONTENT_TYPE, content_type);
        }
        let mut request = builder
            .body(Body::from("{\"content\":[]}"))
            .expect("hostile signed-query request");
        request
            .extensions_mut()
            .insert(crate::loopback_connect_info());
        let response =
            match <AdmittedSignedQuery as axum::extract::FromRequest<SharedAppState>>::from_request(
                request, &app,
            )
            .await
            {
                Ok(_) => panic!(
                    "bounded signed-query ingress must reject non-Norito input before reading it"
                ),
                Err(response) => response,
            };
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            app.query_ingress_inflight.available_permits(),
            ingress_before,
            "media-type rejection must happen before an ingress reservation"
        );
        assert_eq!(
            app.query_fanout_inflight.available_permits(),
            fanout_before,
            "media-type rejection must not consume fanout execution memory"
        );
    }
}
#[tokio::test]
async fn bounded_json_signed_query_remains_supported() {
    let key_pair = crate::tests_runtime_handlers::checked_torii_test_ed25519_keypair(
        0xe7,
        "derive JSON signed-query fixture key",
    );
    let authority = AccountId::new(key_pair.public_key().clone());
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let signed_query =
        crate::tests_runtime_handlers::signed_find_triggers_query_for_test(authority, &key_pair);
    let body = norito::json::to_json(
        &iroha_data_model::query::json_wrappers::SignedQueryJson::from(&signed_query),
    )
    .expect("encode signed query as JSON");
    let mut request = axum::extract::Request::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("JSON signed-query request");
    request
        .extensions_mut()
        .insert(crate::loopback_connect_info());
    let admitted =
        <AdmittedSignedQuery as axum::extract::FromRequest<SharedAppState>>::from_request(
            request, &app,
        )
        .await
        .expect("bounded JSON signed-query ingress remains supported");
    assert_eq!(
        norito::codec::Encode::encode(&admitted.query),
        norito::codec::Encode::encode(&signed_query)
    );
}
#[tokio::test]
async fn duplicate_signed_query_content_type_is_rejected_before_body_poll() {
    let authority = routed_read_test_account(0xd8);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let ingress_before = app.query_ingress_inflight.available_permits();
    let fanout_before = app.query_fanout_inflight.available_permits();
    let mut request = axum::extract::Request::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/x-norito")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, std::convert::Infallible>,
        >()))
        .expect("duplicate-media signed-query request");
    request.headers_mut().append(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    request
        .extensions_mut()
        .insert(crate::loopback_connect_info());
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        <AdmittedSignedQuery as axum::extract::FromRequest<SharedAppState>>::from_request(
            request, &app,
        ),
    )
    .await
    .expect("duplicate Content-Type rejection must not poll the pending body");
    let rejection = match result {
        Ok(_) => panic!("duplicate Norito/JSON Content-Type must fail closed"),
        Err(response) => response,
    };
    assert_eq!(rejection.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before,
        "duplicate media rejection must precede ingress admission"
    );
    assert_eq!(
        app.query_fanout_inflight.available_permits(),
        fanout_before,
        "duplicate media rejection must not consume fanout execution memory"
    );
}
#[tokio::test]
async fn slow_signed_query_body_does_not_occupy_fanout_execution_memory() {
    let authority = routed_read_test_account(0xd9);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let ingress_before = app.query_ingress_inflight.available_permits();
    let fanout_before = app.query_fanout_inflight.available_permits();
    let mut request = axum::extract::Request::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/x-norito")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, std::convert::Infallible>,
        >()))
        .expect("pending signed-query request");
    request
        .extensions_mut()
        .insert(crate::loopback_connect_info());
    let mut extraction = Box::pin(<AdmittedSignedQuery as axum::extract::FromRequest<
        SharedAppState,
    >>::from_request(request, &app));
    tokio::select! {
        result = &mut extraction => panic!("pending body unexpectedly completed: {}", result.is_ok()),
        () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
    }
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before - 1,
        "the stalled body owns exactly one bounded ingress slot"
    );
    assert_eq!(
        app.query_fanout_inflight.available_permits(),
        fanout_before,
        "a stalled body must leave the fanout execution lane available"
    );
    drop(extraction);
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before
    );
}
#[tokio::test]
async fn stalled_signed_query_body_releases_ingress_at_signature_window() {
    let authority = routed_read_test_account(0xea);
    let mut app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    Arc::get_mut(&mut app)
        .expect("test app state has one owner")
        .signed_query_admission = Arc::new(
        routing::SignedQueryAdmission::new(
            signed_query_test_network_id(),
            Duration::ZERO,
            Duration::from_millis(5),
            NonZeroUsize::new(1).expect("nonzero replay capacity"),
        )
        .expect("five-millisecond signed-query body window"),
    );
    let ingress_before = app.query_ingress_inflight.available_permits();
    let mut request = axum::extract::Request::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/x-norito")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, std::convert::Infallible>,
        >()))
        .expect("pending signed-query request");
    request
        .extensions_mut()
        .insert(crate::loopback_connect_info());
    let admission = tokio::time::timeout(
        Duration::from_millis(100),
        <AdmittedSignedQuery as axum::extract::FromRequest<SharedAppState>>::from_request(
            request, &app,
        ),
    )
    .await
    .expect("signature-derived body timeout must complete");
    let response = match admission {
        Ok(_) => panic!("a stalled signed-query body must time out"),
        Err(response) => response,
    };
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before,
        "timing out a stalled body must release its complete ingress slot"
    );
}
#[tokio::test]
async fn ingress_to_fanout_promotion_fails_fast_without_starving_other_bodies() {
    let authority = routed_read_test_account(0xda);
    let app = mk_app_state_for_tests_with_world(world_with_account(&authority));
    let fanout = app
        .query_fanout_inflight
        .try_acquire_parts([app.query_fanout_inflight.capacity_bytes()])
        .expect("fixture occupies the entire fanout pool");
    let ingress_before = app.query_ingress_inflight.available_permits();
    let ingress = acquire_query_ingress_memory(&app)
        .await
        .expect("one body owns an ingress slot");
    let rejection = match try_acquire_query_fanout_memory(&app) {
        Ok(_) => panic!("promotion must not wait while it owns ingress memory"),
        Err(response) => response,
    };
    assert_eq!(rejection.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before - 1,
        "failed promotion must leave all other ingress slots available"
    );
    drop(ingress);
    drop(fanout);
    assert_eq!(
        app.query_ingress_inflight.available_permits(),
        ingress_before
    );
}
#[tokio::test]
async fn incompatible_response_diagnostic_does_not_format_hostile_payload() {
    let marker = "hostile-query-payload-canary";
    let hostile = iroha_data_model::query::QueryResponse::Iterable(
        iroha_data_model::query::QueryOutput::new(
            iroha_data_model::query::QueryOutputBatchBoxTuple::from_batch(
                iroha_data_model::query::QueryOutputBatchBox::String(vec![marker.repeat(2048)]),
            ),
            0,
            None,
        ),
    );
    let response = match hostile {
        iroha_data_model::query::QueryResponse::Iterable(_) => {
            incompatible_routed_query_response("a singular query output")
        }
        _ => unreachable!("hostile fixture is iterable"),
    };
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("fixed mismatch diagnostic must stay small");
    assert!(bytes.len() < 512);
    assert!(
        !bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );
    let error: ErrorEnvelope = norito::decode_from_bytes(&bytes).expect("fixed error envelope");
    assert_eq!(error.code(), "query_conflict");
    assert_eq!(
        error.message(),
        "routed query returned an incompatible response variant; expected a singular query output"
    );
}
#[tokio::test]
async fn skipped_route_response_drops_body_and_its_permit_before_next_route() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let body_permit = semaphore
        .clone()
        .try_acquire_owned()
        .expect("hostile route body owns the only test permit");
    let probe = DropProbe(Arc::clone(&dropped));
    let body = Body::from_stream(futures::stream::once(async move {
        let _probe = probe;
        let _body_permit = body_permit;
        std::future::pending::<Result<Bytes, std::convert::Infallible>>().await
    }));
    let response = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body)
        .expect("hostile route response");
    let mut skipped = SkippedRoutedQueryErrors::default();
    skipped.record_and_drop(response);
    assert!(
        dropped.load(Ordering::SeqCst),
        "the pending response stream must be cancelled before the next route"
    );
    let _next_route_permit = semaphore
        .clone()
        .try_acquire_owned()
        .expect("dropping the skipped body must release ownership before the next route");
    assert_eq!(
        skipped,
        SkippedRoutedQueryErrors {
            saw_not_found: true,
            saw_route_unavailable: false,
        }
    );
}
#[test]
fn hostile_remote_batch_decode_stops_at_explicit_allocation_limit() {
    let batch = iroha_data_model::query::QueryOutputBatchBox::String(vec!["x".repeat(32 * 1024)]);
    let response = iroha_data_model::query::QueryResponse::Iterable(
        iroha_data_model::query::QueryOutput::new(
            iroha_data_model::query::QueryOutputBatchBoxTuple::from_batch(batch),
            0,
            None,
        ),
    );
    let bytes = norito::to_bytes(&response).expect("hostile route response should encode");
    let limits = QueryFanoutMemoryEnvelope::decode_limits_for(bytes.len(), 64)
        .expect("hostile fixture length should fit decoder-limit arithmetic");
    assert!(
        norito::decode_from_bytes_with_limits::<iroha_data_model::query::QueryResponse>(
            &bytes, limits,
        )
        .is_err(),
        "remote route output must fail before allocating its hostile string"
    );
}
#[test]
fn fanout_decode_limits_reject_element_count_overflow() {
    let overflowing_encoded_len = usize::MAX / 8 + 1;
    assert!(
        QueryFanoutMemoryEnvelope::decode_limits_for(overflowing_encoded_len, 1).is_err(),
        "decoder element-limit arithmetic must fail closed instead of saturating"
    );
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn stalled_admitted_body_cannot_start_a_second_body_decode() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let stalled_body_reservation = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("first request owns the only byte-envelope slot");
    let second_decode_started = Arc::new(AtomicBool::new(false));
    let waiting = {
        let semaphore = Arc::clone(&semaphore);
        let second_decode_started = Arc::clone(&second_decode_started);
        async move {
            let _reservation = semaphore
                .acquire_owned()
                .await
                .expect("test semaphore remains open");
            second_decode_started.store(true, Ordering::SeqCst);
        }
    };
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), waiting)
            .await
            .is_err(),
        "a second request must wait before polling or decoding its body"
    );
    assert!(!second_decode_started.load(Ordering::SeqCst));
    drop(stalled_body_reservation);
    let _reservation = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("the released byte-envelope slot becomes available");
    assert_eq!(semaphore.available_permits(), 0);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn query_fanout_memory_permit_lives_until_response_body_is_dropped() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("test semaphore should be open");
    let response = hold_query_fanout_memory_in_response_body(
        Response::new(Body::from(Bytes::from_static(b"bounded"))),
        QueryFanoutMemoryReservation::new(permit),
    );
    assert_eq!(semaphore.available_permits(), 0);
    drop(response);
    assert_eq!(semaphore.available_permits(), 1);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn torii_proxy_memory_permit_lives_until_response_body_is_dropped() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("test semaphore should be open");
    let response = hold_torii_proxy_memory_in_response_body(
        Response::new(Body::from(Bytes::from_static(b"bounded"))),
        ToriiProxyMemoryReservation::new(permit),
    );
    assert_eq!(
        semaphore.available_permits(),
        0,
        "the proxy response body must retain the complete request reservation"
    );
    drop(response);
    assert_eq!(semaphore.available_permits(), 1);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn query_fanout_memory_permit_transfers_through_proxy_snapshot_and_slow_body() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("test semaphore should be open");
    let response = hold_query_fanout_memory_in_response_body(
        Response::new(Body::from(Bytes::from_static(b"bounded"))),
        QueryFanoutMemoryReservation::new(permit),
    );
    let admitted = response_to_admitted_torii_proxy_snapshot(response, 8).await;
    assert_eq!(admitted.snapshot.body, b"bounded");
    assert_eq!(semaphore.available_permits(), 0);
    let response = torii_proxy_snapshot_to_response(admitted.snapshot);
    let response = hold_query_fanout_memory_reservation_in_response_body(
        response,
        admitted
            .fanout_reservation
            .expect("fanout response must transfer its reservation"),
    );
    assert_eq!(semaphore.available_permits(), 0);
    let (parts, body) = response.into_parts();
    drop(parts);
    assert_eq!(semaphore.available_permits(), 0);
    let body = http_body_util::BodyExt::collect(body)
        .await
        .expect("bounded response body should collect");
    assert_eq!(body.to_bytes(), Bytes::from_static(b"bounded"));
    assert_eq!(semaphore.available_permits(), 1);
}
#[cfg(feature = "connect")]
#[tokio::test]
async fn query_fanout_worker_clone_survives_cancelled_response() {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("test semaphore should be open");
    let reservation = QueryFanoutMemoryReservation::new(permit);
    let worker_reservation = reservation.clone();
    let response = hold_query_fanout_memory_in_response_body(
        Response::new(Body::from(Bytes::from_static(b"bounded"))),
        reservation,
    );
    drop(response);
    assert_eq!(
        semaphore.available_permits(),
        0,
        "HTTP cancellation must not readmit work while the physical worker is live"
    );
    drop(worker_reservation);
    assert_eq!(semaphore.available_permits(), 1);
}

fn singular_asset_absence_fixture() -> (
    iroha_data_model::asset::AssetId,
    Vec<u8>,
    QueryFanoutMemoryEnvelope,
) {
    let asset = iroha_data_model::asset::AssetId::new(
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
                .expect("fixture domain"),
            "xor".parse().expect("fixture asset name"),
        ),
        iroha_test_samples::ALICE_ID.clone(),
    );
    let request = authorize_query_for_test(
        iroha_data_model::query::QueryRequest::Singular(
            iroha_data_model::query::SingularQueryBox::FindAssetById(
                iroha_data_model::query::asset::prelude::FindAssetById::new(asset.clone()),
            ),
        ),
        iroha_test_samples::ALICE_ID.clone(),
    );
    let envelope = QueryFanoutMemoryEnvelope::for_request_lengths(64_000_000, 4_096, 8_192)
        .expect("fixture envelope");
    let frame = encode_verified_singular_fanout_request_bounded(&request, envelope)
        .expect("fixture verified request");
    (asset, frame, envelope)
}
fn singular_asset_absence_response(asset: iroha_data_model::asset::AssetId) -> Response {
    (
        StatusCode::NOT_FOUND,
        NoritoBody(
            ErrorEnvelope::new("query_asset_not_found", "asset missing").with_details(
                ErrorDetails {
                    query_asset_not_found: Some(asset),
                    ..Default::default()
                },
            ),
        ),
    )
        .into_response()
}
#[tokio::test]
async fn singular_asset_absence_requires_every_route_to_match_the_original_selector() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    for format in [ResponseFormat::Norito, ResponseFormat::Json] {
        let mut skipped = SingularRoutedQueryErrors::default();
        for _ in 0..4 {
            skipped
                .record_and_drop(
                    singular_asset_absence_response(asset.clone()),
                    &frame,
                    envelope,
                    Duration::from_secs(1),
                )
                .await
                .expect("canonical matching route absence");
        }
        let response = skipped.into_response(&frame, envelope, format);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(response.into_body(), envelope.final_body_bytes)
            .await
            .expect("bounded aggregate absence");
        let error: ErrorEnvelope = match format {
            ResponseFormat::Norito => {
                norito::decode_from_bytes(&bytes).expect("Norito error envelope")
            }
            ResponseFormat::Json => norito::json::from_slice(&bytes).expect("JSON error envelope"),
        };
        assert_eq!(error.code(), "query_asset_not_found");
        assert_eq!(
            error.details.expect("typed details").query_asset_not_found,
            Some(asset.clone())
        );
    }
}
#[tokio::test]
async fn singular_asset_absence_rejects_a_different_selector() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    let other = iroha_data_model::asset::AssetId::new(
        asset.definition().clone(),
        iroha_test_samples::BOB_ID.clone(),
    );
    let response = SingularRoutedQueryErrors::default()
        .record_and_drop(
            singular_asset_absence_response(other),
            &frame,
            envelope,
            Duration::from_secs(1),
        )
        .await
        .expect_err("another account's asset absence cannot prove the requested asset missing");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(torii_response_has_reject_code(
        &response,
        "route_unavailable"
    ));
}
#[tokio::test]
async fn singular_asset_absence_rejects_malformed_noncanonical_and_unbound_errors() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    let original = singular_asset_absence_response(asset);
    let bytes = axum::body::to_bytes(original.into_body(), envelope.route_body_bytes)
        .await
        .expect("fixture envelope bytes");
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    let unbound = norito::to_bytes(&ErrorEnvelope::new(
        "query_asset_not_found",
        "missing details",
    ))
    .expect("unbound fixture envelope");
    for body in [b"invalid Norito".to_vec(), trailing, unbound] {
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(axum::http::header::CONTENT_TYPE, utils::NORITO_MIME_TYPE)
            .header("x-iroha-reject-code", "query_asset_not_found")
            .body(Body::from(body))
            .expect("malformed response");
        let rejected = SingularRoutedQueryErrors::default()
            .record_and_drop(response, &frame, envelope, Duration::from_secs(1))
            .await
            .expect_err("invalid body cannot be authenticated from its header");
        assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
        assert!(torii_response_has_reject_code(
            &rejected,
            "route_unavailable"
        ));
    }
}
#[tokio::test]
async fn singular_asset_absence_keeps_generic_not_found_unproven() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    let mut skipped = SingularRoutedQueryErrors::default();
    for response in [
        singular_asset_absence_response(asset),
        torii_proxy_error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "unspecified route absence",
        ),
    ] {
        skipped
            .record_and_drop(response, &frame, envelope, Duration::from_secs(1))
            .await
            .expect("skippable route response");
    }
    let response = skipped.into_response(&frame, envelope, ResponseFormat::Norito);
    let error = response_error(response).await;
    assert_eq!(error.code(), "not_found");
    assert!(error.details.is_none());
}
#[tokio::test]
async fn singular_asset_absence_unavailable_routes_outrank_missing_in_both_orders() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    for unavailable_first in [false, true] {
        let mut skipped = SingularRoutedQueryErrors::default();
        for unavailable in [unavailable_first, !unavailable_first] {
            let response = if unavailable {
                torii_proxy_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "route_unavailable",
                    "route unavailable",
                )
            } else {
                singular_asset_absence_response(asset.clone())
            };
            skipped
                .record_and_drop(response, &frame, envelope, Duration::from_secs(1))
                .await
                .expect("skippable route response");
        }
        let response = skipped.into_response(&frame, envelope, ResponseFormat::Norito);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error = response_error(response).await;
        assert_eq!(error.code(), "route_unavailable");
        assert!(error.details.is_none());
    }
}
#[tokio::test]
async fn singular_asset_absence_releases_body_and_extension_leases_on_every_exit() {
    let (asset, frame, envelope) = singular_asset_absence_fixture();
    for outcome in 0..4 {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().expect("route lease");
        let mut response = singular_asset_absence_response(asset.clone());
        let mut limits = envelope;
        match outcome {
            0 => {}
            1 => limits.route_body_bytes = 1,
            2 => {
                *response.body_mut() = Body::from_stream(futures::stream::pending::<
                    Result<Bytes, std::convert::Infallible>,
                >());
            }
            _ => {
                response
                    .headers_mut()
                    .remove(axum::http::header::CONTENT_TYPE);
                *response.body_mut() = Body::from_stream(futures::stream::pending::<
                    Result<Bytes, std::convert::Infallible>,
                >());
            }
        }
        let response = hold_query_fanout_memory_in_response_body(
            response,
            QueryFanoutMemoryReservation::new(permit),
        );
        let result = SingularRoutedQueryErrors::default()
            .record_and_drop(response, &frame, limits, Duration::from_millis(1))
            .await;
        assert_eq!(result.is_err(), matches!(outcome, 1 | 2));
        assert_eq!(
            semaphore.available_permits(),
            1,
            "route body and extension lease must be released before advancing"
        );
    }
}
#[tokio::test]
async fn singular_asset_absence_obeys_decode_allocation_ceiling() {
    let (asset, frame, mut envelope) = singular_asset_absence_fixture();
    envelope.decode_allocated_bytes = 1;
    let response = SingularRoutedQueryErrors::default()
        .record_and_drop(
            singular_asset_absence_response(asset),
            &frame,
            envelope,
            Duration::from_secs(1),
        )
        .await
        .expect_err("typed errors remain inside the allocated decode phase");
    assert!(torii_response_has_reject_code(
        &response,
        "route_unavailable"
    ));
}
