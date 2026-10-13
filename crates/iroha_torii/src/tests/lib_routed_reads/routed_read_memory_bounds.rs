// Focused phase-ledger tests for application routed reads.
fn routed_read_working_set_for_phase(phase_bytes: usize) -> usize {
    query_fanout_fixed_overhead_bytes()
        .expect("fixed fanout overhead fits")
        .checked_add(
            phase_bytes
                .checked_mul(QUERY_FANOUT_PREBODY_UNITS)
                .expect("phase geometry fits"),
        )
        .expect("test working set fits")
}
#[test]
fn routed_read_body_limits_preserve_configured_and_envelope_caps() {
    let phase = 256 * 1024;
    let working_set = routed_read_working_set_for_phase(phase);
    let memory_limited = ToriiRoutedReadMemoryBudget::new(working_set, phase * 4)
        .expect("working set admits app routed reads");
    assert_eq!(memory_limited.route_body_limit(), phase);
    assert_eq!(memory_limited.final_body_limit(), phase * 2);
    let configured = ToriiRoutedReadMemoryBudget::new(working_set, phase / 2)
        .expect("working set admits app routed reads");
    assert_eq!(configured.route_body_limit(), phase / 2);
    assert_eq!(configured.final_body_limit(), phase / 2);
}
#[test]
fn routed_read_json_retains_measured_graph_and_canonical_capacity() {
    let phase = 256 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let body = br#"{"items":[0,1,2],"nested":{"name":"alice"}}"#;
    let plan = budget.decode_plan(body.len()).expect("small body fits");
    let profile = budget
        .json_profile(body, plan)
        .expect("valid JSON preflights");
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::json::from_slice::<Value>(body)
    });
    let value = value.expect("valid JSON decodes");
    budget
        .verify_json_value_usage(profile, usage)
        .expect("parser charge covers the graph");
    let canonical = norito::json::to_json_bounded_boxed(&value, plan.canonical_limit_bytes)
        .expect("small canonical JSON fits")
        .into_vec();
    budget
        .retain_decode_usage(usage)
        .expect("measured graph fits retained phase");
    budget
        .retain_canonical_capacity(canonical.capacity())
        .expect("exact canonical bytes fit candidate phase");
    assert_eq!(budget.retained_decoded_bytes, usage.total_allocated_bytes());
    assert_eq!(budget.retained_canonical_bytes, canonical.capacity());
}
#[test]
fn routed_read_json_graph_uses_each_objects_exact_conservative_node_count() {
    let phase = 256 * 1024;
    let budget = ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
        .expect("working set admits app routed reads");
    let body = br#"{"full":{"a":0,"b":1,"c":2,"d":3,"e":4},"empty":{}}"#;
    let plan = budget.decode_plan(body.len()).expect("small body fits");
    let profile = budget
        .json_profile(body, plan)
        .expect("valid JSON preflights");
    assert_eq!(profile.object_btree_node_upper_bound(), 2);
    let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::json::from_slice::<Value>(body)
    });
    value.expect("valid JSON decodes");
    budget
        .verify_json_value_usage(profile, usage)
        .expect("exact per-object topology does not falsely reject the graph");
}
#[test]
fn routed_read_request_and_preflight_use_derived_phase_boundaries() {
    let phase = 64 * 1024;
    let budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase * 2)
            .expect("working set admits app routed reads");
    budget
        .admit_request_bytes(phase)
        .expect("exact request phase fits");
    assert!(budget.app_request_phases_fit(phase));
    assert!(budget.admit_request_bytes(phase + 1).is_err());
    assert!(budget.decode_plan(phase + 1).is_err());
    let malformed = br#"{"unterminated": ["#;
    let plan = budget
        .decode_plan(malformed.len())
        .expect("small malformed body reaches lexical validation");
    assert!(budget.json_profile(malformed, plan).is_err());
}
#[test]
fn app_request_high_water_charges_five_phases_and_transport_exactly() {
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let exact = budget
        .app_request_high_water_bytes(phase)
        .expect("five request representations and fixed terms fit usize");
    assert!(exact <= budget.envelope.working_set_bytes);
    assert_eq!(
        usize::try_from(iroha_config::parameters::defaults::torii::HTTP_READ_CHUNK_BYTES_V1)
            .expect("HTTP read chunk fits usize"),
        8 * 1024
    );
    assert!(
        budget
            .envelope
            .working_set_bytes
            .checked_sub(exact)
            .is_some(),
        "the exact high-water fits the admitted reservation"
    );
    budget.envelope.working_set_bytes = exact;
    assert!(budget.app_request_phases_fit(phase));
    budget.envelope.working_set_bytes = exact.checked_sub(1).expect("high-water is nonzero");
    assert!(!budget.app_request_phases_fit(phase));
    assert!(budget.request_decode_plan().is_err());
    assert_eq!(APP_ROUTED_READ_MAX_URL_PARAMETERS_V1, 2);
    assert!(app_routed_read_url_parameter_fixed_bytes().is_some());
}
#[test]
fn routed_read_decode_plan_uses_full_phase_and_retains_measured_usage() {
    let phase = 256 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let plan = budget.decode_plan(1024).expect("route body fits");
    assert_eq!(plan.limits.max_total_allocated_bytes(), phase);
    assert_eq!(plan.limits.max_total_elements(), phase);
    let (charged, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::core::reserve_decode_allocation(phase / 4)
    });
    charged.expect("test allocation fits decode phase");
    budget
        .retain_decode_usage(usage)
        .expect("measured allocation fits accumulator");
    budget
        .retain_canonical_bytes(plan.canonical_limit_bytes / 4)
        .expect("candidate bytes fit");
    let next = budget.decode_plan(1024).expect("next route still decodes");
    assert_eq!(
        next.limits.max_total_allocated_bytes(),
        phase,
        "a later route receives the full transient phase, not an arbitrary fair split"
    );
    assert!(next.canonical_limit_bytes < plan.canonical_limit_bytes);
}
#[test]
fn routed_read_merge_tracks_only_canonical_keys_it_keeps() {
    let phase = 256 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let value = norito::json!({"id": "alice"});
    let candidate = budget
        .canonical_json_candidate(&value)
        .expect("small canonical candidate fits");
    assert_eq!(budget.retained_canonical_bytes, 0);
    budget
        .retain_canonical_capacity(candidate.capacity())
        .expect("retained key fits");
    assert_eq!(budget.retained_canonical_bytes, candidate.capacity());
    budget.begin_typed_merge();
    assert_eq!(budget.retained_canonical_bytes, candidate.capacity());
    budget.begin_json_merge();
    assert_eq!(budget.retained_canonical_bytes, 0);
}
#[test]
fn routed_read_typed_json_candidate_uses_only_transient_merge_phases() {
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    budget.begin_json_merge();
    let candidate = Value::String("typed candidate".to_owned());
    let retained_before = budget.retained_decoded_bytes;
    let canonical_before = budget.retained_canonical_bytes;
    let merge_before = budget.merge_allocated_bytes;
    budget
        .inspect_typed_json_candidate::<String, _, _>(
            &candidate,
            "valid test string expected",
            <String as norito::json::JsonDeserialize>::json_from_value,
            |decoded| {
                assert_eq!(decoded, "typed candidate");
                Ok(())
            },
        )
        .expect("small typed candidate fits its transient phases");
    assert_eq!(budget.retained_decoded_bytes, retained_before);
    assert_eq!(budget.retained_canonical_bytes, canonical_before);
    assert_eq!(budget.merge_allocated_bytes, merge_before);

    budget.envelope.decode_allocated_bytes = 0;
    assert!(
        budget
            .inspect_typed_json_candidate::<String, _, _>(
                &candidate,
                "valid test string expected",
                <String as norito::json::JsonDeserialize>::json_from_value,
                |_| Ok(()),
            )
            .is_err(),
        "candidate decoding must fail before allocating without a decode phase"
    );

    budget.envelope.decode_allocated_bytes = 1;
    let response = budget
        .inspect_typed_json_candidate::<String, _, _>(
            &candidate,
            "valid test string expected",
            <String as norito::json::JsonDeserialize>::json_from_value,
            |_| Ok(()),
        )
        .expect_err("candidate allocation must honor the transient decode phase");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(torii_response_has_reject_code(
        &response,
        "route_unavailable"
    ));
}
#[test]
fn routed_read_canonical_ledger_charges_spare_vector_capacity() {
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let mut canonical = Vec::with_capacity(257);
    canonical.push(7);
    budget
        .retain_canonical_capacity(canonical.capacity())
        .expect("spare canonical capacity fits");
    assert_eq!(budget.retained_canonical_bytes, canonical.capacity());
    assert!(budget.retained_canonical_bytes > canonical.len());
}
#[test]
fn routed_read_request_accounting_uses_owned_capacities() {
    let mut path_args = Vec::with_capacity(4);
    let mut path = String::with_capacity(31);
    path.push_str("alice");
    path_args.push(path);
    let mut query = String::with_capacity(37);
    query.push_str("limit=1");
    let mut body = Vec::with_capacity(43);
    body.push(0);
    let expected = path_args.capacity() * core::mem::size_of::<String>()
        + path_args[0].capacity()
        + query.capacity()
        + body.capacity();
    assert_eq!(
        torii_routed_read_request_bytes(
            &path_args,
            path_args.capacity(),
            Some(&query),
            body.capacity(),
        )
        .expect("request capacities fit"),
        expected
    );
}
#[test]
fn routed_read_retained_vector_uses_exact_precharged_capacity_growth() {
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let mut values = budget
        .try_retained_vec::<u64>(1)
        .expect("small retained vector fits");
    budget
        .push_retained(&mut values, 1)
        .expect("reserved slot accepts first value");
    budget
        .push_retained(&mut values, 2)
        .expect("growth remains inside retained phase");
    assert_eq!(values, [1, 2]);
    assert_eq!(values.capacity(), 2);
    assert_eq!(
        budget.retained_decoded_bytes,
        values.capacity() * core::mem::size_of::<u64>()
    );
    assert!(budget.try_retained_vec::<u8>(usize::MAX).is_err());
    budget.envelope.accumulator_retained_bytes = 2 * core::mem::size_of::<u64>();
    assert!(budget.push_retained(&mut values, 3).is_err());
    assert_eq!(values, [1, 2]);
    assert_eq!(
        values.capacity(),
        2,
        "rejection precedes replacement allocation"
    );
}
#[test]
fn routed_read_exact_growth_transfers_each_owned_value_once() {
    struct DropProbe(std::rc::Rc<std::cell::Cell<usize>>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let drops = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut values = budget
        .try_retained_vec::<DropProbe>(1)
        .expect("initial exact allocation");
    budget
        .push_retained(&mut values, DropProbe(std::rc::Rc::clone(&drops)))
        .expect("first value");
    budget
        .push_retained(&mut values, DropProbe(std::rc::Rc::clone(&drops)))
        .expect("growth transfers the first value");
    assert_eq!(drops.get(), 0, "growth must not drop transferred values");
    drop(values);
    assert_eq!(drops.get(), 2, "each retained value drops exactly once");
}
#[test]
fn routed_read_merge_vector_uses_exact_precharged_capacity() {
    let phase = 64 * 1024;
    let mut budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
            .expect("working set admits app routed reads");
    let values = budget
        .try_merge_vec::<u64>(17)
        .expect("small merge vector fits");
    let allocated_bytes = values
        .capacity()
        .checked_mul(core::mem::size_of::<u64>())
        .expect("test capacity fits");
    assert_eq!(values.capacity(), 17);
    assert_eq!(budget.merge_allocated_bytes, allocated_bytes);
    assert!(budget.try_merge_vec::<u8>(usize::MAX).is_err());
    budget.envelope.candidate_allocation_bytes = allocated_bytes;
    assert!(budget.try_merge_vec::<u8>(1).is_err());
    assert_eq!(budget.merge_allocated_bytes, allocated_bytes);
}
#[test]
fn routed_read_final_json_is_counted_before_allocation() {
    let phase = 64 * 1024;
    let budget = ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), 32)
        .expect("working set admits app routed reads");
    let oversized = Value::String("x".repeat(64));
    assert!(budget.json_response(&oversized).is_err());
}
#[test]
fn routed_read_exact_json_destination_transfers_to_bytes_without_copying() {
    let value = Value::String("bounded response".to_owned());
    let boxed = norito::json::to_json_bounded_boxed(&value, 64).expect("small JSON fits");
    let pointer = boxed.as_ptr();
    let bytes = Bytes::from(boxed);
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(bytes.as_ref(), br#""bounded response""#);
}
#[test]
fn routed_read_source_keeps_multiroute_fanout_enabled() {
    // The routed-read helpers are `include!`d into lib.rs, so the wiring spans
    // lib.rs and the included collect/execute sources.
    let source = [
        include_str!("../../lib.rs"),
        include_str!("../../torii_app_routed_read_route_collect.rs"),
        include_str!("../../torii_app_routed_read_execute.rs"),
    ]
    .concat();
    for required in [
        "include!(\"torii_app_routed_read_source.rs\")",
        "include!(\"torii_app_routed_read_route_collect.rs\")",
        "include!(\"torii_app_routed_read_execute.rs\")",
        "collect_torii_routed_list_json_payloads",
        "execute_torii_read_fanout_for_resolved_routes_admitted",
        "resolve_torii_proof_record_for_supported_routes(",
        "collect_torii_alias_json_payloads",
        "collect_torii_alias_lookup_json_payloads",
    ] {
        assert!(
            source.contains(required),
            "bounded multi-route source `{required}` must remain wired"
        );
    }
}

#[test]
fn routed_read_json_graph_preserves_leaf_split_nested_and_exact_decode_refusals() {
    let phase = 256 * 1024;
    for entries in [0, 1, 5, 6, 11, 12, 31] {
        let fields = (0..entries)
            .map(|index| format!("\"k{index}\":0"))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!("{{\"full\":{{{fields}}},\"empty\":{{}},\"items\":[\"a\\nb\",0]}}");
        let mut budget =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .unwrap();
        let plan = budget.decode_plan(body.len()).unwrap();
        let profile = budget.json_profile(body.as_bytes(), plan).unwrap();
        let graph = torii_routed_read_json_value_graph_bytes(profile).unwrap();
        assert_eq!(
            graph,
            profile.string_capacity_bytes()
                + profile.array_entries() * core::mem::size_of::<Value>()
                + profile.object_btree_allocation_bytes()
        );
        let (value, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
            norito::json::from_slice::<Value>(body.as_bytes())
        });
        let value = value.unwrap();
        budget.verify_json_value_usage(profile, usage).unwrap();
        let exact = usage.total_allocated_bytes();
        let exact_limits = norito::DecodeLimits::new(
            phase,
            phase,
            phase,
            exact,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        let (decoded, exact_usage) =
            norito::core::with_decode_limits_measured(exact_limits, || {
                norito::json::from_slice::<Value>(body.as_bytes())
            });
        assert_eq!(decoded.unwrap(), value);
        assert_eq!(exact_usage.total_allocated_bytes(), exact);
        let short_limits = norito::DecodeLimits::new(
            phase,
            phase,
            phase,
            exact - 1,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        let (decoded, _) = norito::core::with_decode_limits_measured(short_limits, || {
            norito::json::from_slice::<Value>(body.as_bytes())
        });
        assert!(
            decoded.unwrap_err().is_decode_resource_limit(),
            "original one-byte decode ceiling"
        );
        budget.envelope.accumulator_retained_bytes = exact - 1;
        assert!(budget.retain_decode_usage(usage).is_err());
        assert_eq!(
            budget.retained_decoded_bytes, 0,
            "refusal does not debit the original retained pool"
        );
        budget.envelope.accumulator_retained_bytes = exact;
        budget.retain_decode_usage(usage).unwrap();
        assert_eq!(budget.retained_decoded_bytes, exact);
    }
}
#[test]
fn routed_read_json_graph_refuses_missing_original_object_charge() {
    let phase = 256 * 1024;
    let budget =
        ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase).unwrap();
    let body = br#"{"a":0,"b":1,"c":2,"d":3,"e":4,"f":5}"#;
    let plan = budget.decode_plan(body.len()).unwrap();
    let profile = budget.json_profile(body, plan).unwrap();
    let graph = torii_routed_read_json_value_graph_bytes(profile).unwrap();
    let (charged, usage) = norito::core::with_decode_limits_measured(plan.limits, || {
        norito::core::reserve_decode_allocation(graph - 1)
    });
    charged.unwrap();
    let refusal = budget.verify_json_value_usage(profile, usage).unwrap_err();
    assert_eq!(refusal.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(budget.retained_decoded_bytes, 0);
}
#[tokio::test]
async fn routed_read_single_route_pipeline_status_keeps_original_json_graph_and_response() {
    let phase = 256 * 1024;
    for kind in [
        "Queued",
        "Approved",
        "Committed",
        "Applied",
        "Rejected",
        "Expired",
    ] {
        let mut budget =
            ToriiRoutedReadMemoryBudget::new(routed_read_working_set_for_phase(phase), phase)
                .unwrap();
        let response = crate::utils::respond_with_format(
            PipelineTransactionStatusResponse::new(
                HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                    [0x51; Hash::LENGTH],
                ))
                .to_string(),
                PipelineTransactionStatus {
                    kind: kind.to_owned(),
                    block_height: Some(7),
                },
                "global".to_owned(),
                "state".to_owned(),
            ),
            ResponseFormat::Json,
        );
        let response = bound_torii_single_route_response(
            response,
            ToriiProxyResponseFormatV1::Json,
            &mut budget,
        )
        .await
        .expect("real pipeline status survives the original proxied JSON accounting");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            budget.retained_decoded_bytes > 0,
            "complete decoded owner remains debited"
        );
        let body = axum::body::to_bytes(response.into_body(), budget.final_body_limit())
            .await
            .unwrap();
        let decoded: PipelineTransactionStatusResponse = norito::json::from_slice(&body).unwrap();
        assert_eq!(decoded.status.kind, kind);
        assert_eq!(decoded.status.block_height, Some(7));
        assert_eq!(decoded.scope, "global");
        assert_eq!(decoded.resolved_from, "state");
        assert_eq!(
            decoded.hash,
            HashOf::<SignedTransaction>::from_untyped_unchecked(Hash::prehashed(
                [0x51; Hash::LENGTH]
            ))
            .to_string()
        );
    }
}
