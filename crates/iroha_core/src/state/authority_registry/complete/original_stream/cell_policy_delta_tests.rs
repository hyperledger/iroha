// Cell deltas retain source/schema visitation without materializing untouched values.

fn append_clock(block: &StateBlock<'_>, output: &mut Collector) -> Result<(), CaptureError> {
    output.cell(
        "world.soradns_last_publish_ms",
        &block.world.soradns_last_publish_ms,
        &block.state_ref.world.soradns_last_publish_ms,
        block.world.parameters.mode(),
        bare,
    )
}

#[test]
fn untouched_cell_delta_keeps_original_identity_without_value_work_or_credit() {
    // Keep retired fixture generations from refunding the exact State pool
    // while this test measures admission, refusal and capture-only refunds.
    let _retirement_pin = crossbeam_epoch::pin();
    let state = state();
    let mut block = state.block(header(1));
    freeze(&mut block);
    let mut bound = limits();
    bound.max_rows = 0;
    bound.max_source_visits = 0;
    bound.max_total_payload_bytes = 0;
    let budget = state.ivm_execution_budget();
    let initial = budget.reserved_bytes();
    let mut delta = Collector::new(budget.clone(), bound, CaptureIntent::Changes).unwrap();
    let original_limit = budget.limit_bytes();
    let capture_backing = budget.reserved_bytes() - initial;
    let blocker = budget
        .try_reserve_bytes(original_limit - budget.reserved_bytes())
        .unwrap();
    assert!(
        append_clock(&block, &mut delta).is_ok(),
        "untouched cell change capture must admit no value work or credit"
    );
    let field = find(&delta, "world.soradns_last_publish_ms");
    assert!(field.current.as_slice().is_empty() && field.undo.as_slice().is_empty());
    assert_eq!(
        field.source,
        SourceIdentity::Journal(block.world.soradns_last_publish_ms.publication_identity())
    );
    assert_eq!(
        (delta.rows, delta.source_visits, delta.payload_bytes),
        (0, 0, 0)
    );
    assert_eq!(budget.reserved_bytes(), original_limit);
    assert!(matches!(
        append_clock(&block, &mut delta),
        Err(CaptureError::Duplicate("world.soradns_last_publish_ms"))
    ));
    delta.start_traversal();
    append_clock(&block, &mut delta).unwrap();
    assert!(matches!(
        delta.require_complete(),
        Err(CaptureError::Missing(_))
    ));
    assert!(matches!(
        delta.projected_cell(
            "state.transactions.current",
            SourceIdentity::Policy(0),
            false,
            |_| panic!("table cannot become an empty cell"),
            |_| panic!("table cannot become an empty cell"),
        ),
        Err(CaptureError::Schema("state.transactions.current"))
    ));
    drop(blocker);
    let mut complete = Collector::new(budget.clone(), bound, CaptureIntent::Complete).unwrap();
    assert!(matches!(
        append_clock(&block, &mut complete),
        Err(CaptureError::CountLimit)
    ));
    drop(complete);
    // An equal payload in a new target generation still invalidates the source.
    {
        let mut next = state.world.soradns_last_publish_ms.block();
        let same = *next.get();
        *next.get_mut() = same;
        next.commit();
    }
    delta.start_traversal();
    assert!(matches!(
        append_clock(&block, &mut delta),
        Err(CaptureError::Changed("world.soradns_last_publish_ms"))
    ));
    assert!(
        find(&delta, "world.soradns_last_publish_ms")
            .current
            .as_slice()
            .is_empty()
    );
    let before_drop = budget.reserved_bytes();
    drop(delta);
    // The equal target publication above owns independent State credit. The
    // exact capture backing still refunds without changing that target owner.
    assert_eq!(budget.reserved_bytes(), before_drop - capture_backing);
    assert_eq!(budget.limit_bytes(), original_limit);
}

#[test]
fn touched_equal_and_changed_cell_deltas_recreate_cold_bytes_and_keep_refusal() {
    // Keep retired fixture generations from refunding the exact State pool
    // while this test measures admission, refusal and capture-only refunds.
    let _retirement_pin = crossbeam_epoch::pin();
    for successor in [None, Some(17)] {
        let state = state();
        let mut block = state.block(header(1));
        let before = *block.world.soradns_last_publish_ms.get();
        *block.world.soradns_last_publish_ms.get_mut() = Some(99);
        *block.world.soradns_last_publish_ms.get_mut() = successor;
        freeze(&mut block);
        let before_bytes = norito::codec::encode_adaptive(&before);
        let after_bytes = norito::codec::encode_adaptive(&successor);
        let budget = state.ivm_execution_budget();
        let initial = budget.reserved_bytes();
        let original_limit = budget.limit_bytes();
        let mut bound = limits();
        bound.max_rows = 2;
        bound.max_source_visits = 2;
        let mut delta = Collector::new(budget.clone(), bound, CaptureIntent::Changes).unwrap();
        let backing_and_current = 2 * std::mem::size_of::<Row>() + after_bytes.len();
        let blocker = budget
            .try_reserve_bytes(original_limit - budget.reserved_bytes() - backing_and_current)
            .unwrap();
        let error = append_clock(&block, &mut delta).unwrap_err();
        let CaptureError::Allocation(ChargedBufferError::Admission(refusal)) = error else {
            panic!("touched cell undo must preserve its exact allocator cause")
        };
        let AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            ..
        } = &refusal
        else {
            panic!("retained cell credit must cause genuine Capacity")
        };
        assert_eq!(
            (*requested_bytes, *reserved_bytes, *limit_bytes),
            (before_bytes.len(), original_limit, original_limit)
        );
        assert_eq!(
            budget.try_reserve_bytes(before_bytes.len()).err().unwrap(),
            refusal
        );
        let pending = delta.pending.as_ref().unwrap();
        assert_eq!(pending.current.as_ref().unwrap().as_slice().len(), 1);
        assert!(pending.undo.as_ref().unwrap().as_slice().is_empty());
        let retained = pending.current.as_ref().unwrap().as_slice()[0]
            .value
            .as_ref()
            .unwrap()
            .bytes()
            .as_ptr();
        assert_eq!(delta.payload_bytes, after_bytes.len());
        drop(blocker);
        delta.start_traversal();
        append_clock(&block, &mut delta).unwrap();
        assert_eq!(
            delta.source_visits, 1,
            "retry encodes only the missing cell preimage"
        );
        let field = find(&delta, "world.soradns_last_publish_ms");
        assert_eq!(field.current.as_slice().len(), 1);
        assert_eq!(field.undo.as_slice().len(), 1);
        assert_eq!(
            field.current.as_slice()[0]
                .value
                .as_ref()
                .unwrap()
                .bytes()
                .as_ptr(),
            retained
        );
        assert_eq!(
            field.undo.as_slice()[0].value.as_ref().unwrap().bytes(),
            before_bytes
        );
        assert_eq!(
            field.current.as_slice()[0].value.as_ref().unwrap().bytes(),
            after_bytes
        );
        let mut cold = Collector::new(budget.clone(), limits(), CaptureIntent::Complete).unwrap();
        append_clock(&block, &mut cold).unwrap();
        let mut replay = BTreeMap::from([(Vec::new(), before_bytes)]);
        for undo in field.undo.as_slice() {
            assert_eq!(
                replay.get(undo.key.bytes()).map(Vec::as_slice),
                undo.value.as_ref().map(Frame::bytes)
            );
            replay.insert(
                undo.key.bytes().to_vec(),
                field.current.as_slice()[0]
                    .value
                    .as_ref()
                    .unwrap()
                    .bytes()
                    .to_vec(),
            );
        }
        assert_eq!(replay, values(find(&cold, "world.soradns_last_publish_ms")));
        if successor == before {
            assert_eq!(
                field.undo.as_slice()[0].value.as_ref().map(Frame::bytes),
                field.current.as_slice()[0].value.as_ref().map(Frame::bytes)
            );
        }
        drop(cold);
        drop(delta);
        assert_eq!(budget.reserved_bytes(), initial);
        assert_eq!(budget.limit_bytes(), original_limit);
    }
}

fn frozen_policy_block(
    state: &State,
    touch_parameters: bool,
    touch_runtime: bool,
    change_catalog: bool,
) -> StateBlock<'_> {
    {
        let mut parameters = state.world.parameters.block();
        let fees = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
        parameters
            .get_mut()
            .set_parameter(iroha_data_model::parameter::Parameter::Custom(
                fees.into_custom_parameter().unwrap(),
            ))
            .unwrap();
        // These projection controls start with a complete original policy cut;
        // the separate genesis-undo controls retain their genuinely absent policy.
        parameters
            .get_mut()
            .set_parameter(
                crate::sumeragi::test_chain::crypto_fixture_policy()
                    .into_parameter()
                    .expect("canonical original projection crypto policy"),
            )
            .expect("install the projection fixture's original crypto policy");
        parameters.commit();
    }
    let mut block = state.block(header(1));
    if touch_parameters {
        let same = block.world.parameters.get().clone();
        *block.world.parameters.get_mut() = same;
    }
    let fields = block.fields.as_mut().unwrap();
    if touch_runtime {
        let current = fields.canonical_runtime.get_mut();
        if change_catalog {
            current.lanes[0].alias.push_str("-changed");
        }
    }
    fields.world.begin_freeze();
    fields.canonical_runtime.begin_freeze();
    fields.world.finish_freeze();
    fields.canonical_runtime.finish_freeze();
    fields.world.retire_frozen_cleanup();
    fields.canonical_runtime.retire_frozen_cleanup();
    block
}

#[test]
fn unchanged_policy_delta_skips_projection_scratch_with_exhausted_original_pool() {
    // Keep retired fixture generations from refunding the exact State pool
    // while this test measures admission, refusal and capture-only refunds.
    let _retirement_pin = crossbeam_epoch::pin();
    let (state, _) = crate::state::publication::musubi_materializer_test_support::fixture();
    let block = frozen_policy_block(&state, false, false, false);
    let fields = block.fields.as_ref().unwrap();
    assert!(
        !fields
            .world
            .parameters
            .frozen_values()
            .unwrap()
            .0
            .crypto_policy()
            .expect("original committed admission policy")
            .allowed_algorithms()
            .is_empty()
    );
    let budget = state.ivm_execution_budget();
    let initial = budget.reserved_bytes();
    let mut bound = limits();
    bound.max_rows = 0;
    bound.max_source_visits = 0;
    bound.max_total_payload_bytes = 0;
    let mut delta = Collector::new(budget.clone(), bound, CaptureIntent::Changes).unwrap();
    let original_limit = budget.limit_bytes();
    let blocker = budget
        .try_reserve_bytes(original_limit - budget.reserved_bytes())
        .unwrap();
    assert!(
        policies::append(fields, &mut delta).is_ok(),
        "unchanged policies must skip borrowed projection scratch before allocation"
    );
    assert_eq!(
        (delta.rows, delta.source_visits, delta.payload_bytes),
        (0, 0, 0)
    );
    assert_eq!(budget.reserved_bytes(), original_limit);
    // The committed crypto policy belongs to world.parameters; the local
    // execution snapshot must not create a second canonical state.crypto cell.
    let expected_fields = [
        "state.oracle",
        "state.gov",
        "state.settlement",
        "state.content",
        "state.pipeline",
        "state.zk",
        "runtime.lanes",
        "state.lane_compliance",
        "state.lane_manifests",
        "state.nexus",
    ];
    assert_eq!(delta.fields.as_slice().len(), expected_fields.len());
    for (field, expected_id) in delta.fields.as_slice().iter().zip(expected_fields) {
        assert_eq!(field.id, expected_id);
        assert!(
            field.seen && field.current.as_slice().is_empty() && field.undo.as_slice().is_empty()
        );
    }
    delta.start_traversal();
    policies::append(fields, &mut delta).unwrap();
    assert_eq!(budget.reserved_bytes(), original_limit);
    drop(blocker);
    let mut cold = Collector::new(budget.clone(), limits(), CaptureIntent::Complete).unwrap();
    policies::append(fields, &mut cold).unwrap();
    assert_eq!(cold.fields.as_slice().len(), delta.fields.as_slice().len());
    for field in cold.fields.as_slice() {
        assert_eq!(field.current.as_slice().len(), 1);
        assert!(field.undo.as_slice().is_empty());
        assert_eq!(find(&delta, field.id).source, field.source);
    }
    drop(cold);
    delta.start_traversal();
    assert!(matches!(
        delta.skip_cell_projection("state.oracle", SourceIdentity::Policy(0), false),
        Err(CaptureError::Changed("state.oracle"))
    ));
    drop(delta);
    assert_eq!(budget.reserved_bytes(), initial);
}
#[test]
fn runtime_catalog_touch_keeps_manifest_preimage_and_refuses_foreign_binding() {
    for change_catalog in [false, true] {
        let (state, _) = crate::state::publication::musubi_materializer_test_support::fixture();
        let block = frozen_policy_block(&state, true, true, change_catalog);
        let fields = block.fields.as_ref().unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &fields.lane_manifests,
            &fields.runtime_policy.manifests
        ));
        let mut delta = Collector::new(
            state.ivm_execution_budget(),
            limits(),
            CaptureIntent::Changes,
        )
        .unwrap();
        let result = policies::append(fields, &mut delta);
        if change_catalog {
            assert!(
                matches!(&result, Err(CaptureError::Codec(error)) if error.to_string().contains("different frozen catalog")),
                "runtime catalog touches must retain original manifest binding checks"
            );
            continue;
        }
        result.unwrap();
        let manifest = find(&delta, "state.lane_manifests");
        assert_eq!(
            manifest.undo.as_slice().len(),
            1,
            "runtime catalog touches must retain original manifest preimage"
        );
        let mut cold = Collector::new(
            state.ivm_execution_budget(),
            limits(),
            CaptureIntent::Complete,
        )
        .unwrap();
        policies::append(fields, &mut cold).unwrap();
        let mut replay = BTreeMap::new();
        for field in cold.fields.as_slice() {
            let before = field
                .undo
                .as_slice()
                .first()
                .or_else(|| field.current.as_slice().first())
                .unwrap();
            replay.insert(field.id, before.value.as_ref().unwrap().bytes().to_vec());
        }
        for field in delta.fields.as_slice() {
            for before in field.undo.as_slice() {
                assert_eq!(
                    replay.get(field.id).map(Vec::as_slice),
                    before.value.as_ref().map(Frame::bytes)
                );
                replay.insert(
                    field.id,
                    field.current.as_slice()[0]
                        .value
                        .as_ref()
                        .unwrap()
                        .bytes()
                        .to_vec(),
                );
            }
        }
        for field in cold.fields.as_slice() {
            assert_eq!(
                replay.get(field.id).map(Vec::as_slice),
                field.current.as_slice()[0].value.as_ref().map(Frame::bytes)
            );
        }
        for id in [
            "state.pipeline",
            "state.zk",
            "runtime.lanes",
            "state.lane_manifests",
            "state.nexus",
        ] {
            let field = find(&delta, id);
            assert_eq!(field.undo.as_slice().len(), 1);
            assert_eq!(
                field.current.as_slice()[0].value.as_ref().map(Frame::bytes),
                field.undo.as_slice()[0].value.as_ref().map(Frame::bytes)
            );
        }
    }
}
