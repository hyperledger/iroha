// Focused tests for Torii cross-dataspace fanout memory configuration.
#[test]
fn query_fanout_pool_may_be_smaller_than_the_general_body_cap() {
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert(
        "query_fanout_max_retained_bytes".into(),
        Value::Integer(
            i64::try_from(defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1)
                .expect("protocol minimum fits TOML integer"),
        ),
    );
    let root = load_root(table);
    assert_eq!(
        root.torii.query_fanout_max_retained_bytes.get(),
        defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1
    );
    assert!(
        root.torii.query_fanout_max_retained_bytes.get() < root.torii.max_content_len.get(),
        "the query pool derives a smaller phase-bounded body limit instead of rejecting the general listener cap"
    );
    let aggregate = root.torii.query_fanout_max_retained_bytes.get();
    let ceiling = root.torii.query_fanout_max_working_set_bytes.get();
    assert_eq!(ceiling, 48_000_000);
    let working_set = defaults::torii::query_fanout_working_set_bytes(
        aggregate,
        ceiling,
        root.torii.max_content_len.get(),
    )
    .expect("the smaller aggregate still admits a complete working set");
    assert_eq!(working_set, 15_000_000);
    assert!(working_set < ceiling);
    assert_eq!(
        defaults::torii::query_ingress_body_phase_bytes(
            aggregate,
            ceiling,
            root.torii.max_content_len.get(),
        ),
        Some(25_526),
        "all four independent ingress slots remain larger than the native read chunk"
    );
    assert_eq!(
        aggregate / defaults::torii::QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1 + working_set,
        aggregate,
        "one complete fanout and all ingress slots fit the smaller configured aggregate"
    );
}
#[test]
fn query_fanout_aggregate_capacity_does_not_expand_per_query_phase() {
    let expected_working_set = 48_000_000;
    // Derive the phase from the fixed per-query ceiling and current protocol
    // geometry, independently of the aggregate capacity varied below.
    let expected_phase = (expected_working_set
        - defaults::torii::QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1)
        / defaults::torii::QUERY_FANOUT_PREBODY_UNITS_V1;
    for (aggregate, expected_slots) in [(64_000_000, 1), (512_000_000, 8), (1_024_000_000, 16)] {
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert(
                "query_fanout_max_retained_bytes".into(),
                Value::Integer(aggregate),
            );
        let torii = load_root(table).torii;
        let aggregate = torii.query_fanout_max_retained_bytes.get();
        let ceiling = torii.query_fanout_max_working_set_bytes.get();
        let working_set = defaults::torii::query_fanout_working_set_bytes(
            aggregate,
            ceiling,
            torii.max_content_len.get(),
        )
        .expect("parsed configuration admits a complete working set");
        assert_eq!(working_set, expected_working_set);
        assert_eq!(
            defaults::torii::app_api_routed_read_route_body_phase_bytes(
                aggregate,
                ceiling,
                torii.max_content_len.get(),
            ),
            Some(expected_phase),
            "aggregate capacity changes concurrency, not one query's phase limit"
        );
        let ingress_pool = aggregate / defaults::torii::QUERY_MEMORY_INGRESS_POOL_DIVISOR_V1;
        let fanout_pool = aggregate - ingress_pool;
        assert_eq!(fanout_pool / working_set, expected_slots);
        assert!(ingress_pool + expected_slots * working_set <= aggregate);
    }
}
#[test]
fn query_fanout_working_set_ceiling_accepts_exact_transport_geometry() {
    let minimum = defaults::torii::QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1
        + defaults::torii::QUERY_FANOUT_PREBODY_UNITS_V1
            * defaults::torii::HTTP_READ_CHUNK_BYTES_V1;
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert(
        "query_fanout_max_working_set_bytes".into(),
        Value::Integer(i64::try_from(minimum).expect("working-set bound fits TOML integer")),
    );
    let root = load_root(table.clone());
    assert_eq!(root.torii.query_fanout_max_working_set_bytes.get(), minimum);
    for phase in [
        defaults::torii::app_api_routed_read_route_body_phase_bytes(
            root.torii.query_fanout_max_retained_bytes.get(),
            minimum,
            root.torii.max_content_len.get(),
        ),
        defaults::torii::query_ingress_body_phase_bytes(
            root.torii.query_fanout_max_retained_bytes.get(),
            minimum,
            root.torii.max_content_len.get(),
        ),
    ] {
        assert_eq!(phase, Some(defaults::torii::HTTP_READ_CHUNK_BYTES_V1));
    }
    table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table")
        .insert(
            "query_fanout_max_working_set_bytes".into(),
            Value::Integer(
                i64::try_from(minimum - 1).expect("working-set bound fits TOML integer"),
            ),
        );
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("a ceiling one byte below complete transport geometry must fail closed");
    assert!(format!("{error:?}").contains(
        "Torii's fixed HTTP read chunk exceeds the App API routed-read transport-frame phase"
    ));
}
#[test]
fn query_fanout_working_set_ceiling_rejects_zero_or_non_byte_values() {
    for invalid in [
        Value::Integer(0),
        Value::Integer(-1),
        Value::Float(f64::INFINITY),
    ] {
        let mut table = base_table();
        table
            .get_mut("torii")
            .and_then(Value::as_table_mut)
            .expect("torii table")
            .insert("query_fanout_max_working_set_bytes".into(), invalid);
        let error = actual::Root::from_toml_source(TomlSource::inline(table))
            .expect_err("working-set ceiling must be a finite positive byte count");
        assert!(format!("{error:?}").contains("query_fanout_max_working_set_bytes"));
    }
}
#[test]
fn query_fanout_retention_budget_rejects_below_protocol_pool() {
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert(
        "query_fanout_max_retained_bytes".into(),
        Value::Integer(
            i64::try_from(defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1 - 1)
                .expect("protocol minimum fits TOML integer"),
        ),
    );
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("a pool below the source-coupled geometry must fail closed");
    assert!(format!("{error:?}").contains(&format!(
        "query_fanout_max_retained_bytes must be at least {} bytes",
        defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1
    )));
}
#[test]
fn zero_torii_content_bound_is_rejected() {
    let mut table = base_table();
    table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table")
        .insert("max_content_len".into(), Value::Integer(0));
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("zero maximum response size must fail closed");
    assert!(format!("{error:?}").contains("torii.max_content_len must be greater than zero"));
}
#[test]
fn minimum_transport_content_limit_keeps_a_complete_query_envelope() {
    let exact = i64::try_from(defaults::torii::HTTP_READ_CHUNK_BYTES_V1)
        .expect("HTTP read chunk fits TOML integer");
    let mut table = base_table();
    table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table")
        .insert("max_content_len".into(), Value::Integer(exact));
    let root = load_root(table);
    assert_eq!(root.torii.max_content_len.get(), exact.cast_unsigned());
    assert!(
        root.torii.max_content_len.get() < root.torii.query_fanout_max_retained_bytes.get(),
        "the exact transport minimum remains far below the aggregate query-memory pool"
    );
}
#[test]
fn undersized_aggregate_query_memory_pool_is_rejected() {
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert(
        "query_fanout_max_retained_bytes".into(),
        Value::Integer(
            i64::try_from(defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1 - 1)
                .expect("protocol minimum fits TOML integer"),
        ),
    );
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("an aggregate pool below the V1 split must fail closed");
    assert!(format!("{error:?}").contains(&format!(
        "query_fanout_max_retained_bytes must be at least {} bytes for four bounded ingress slots",
        defaults::torii::QUERY_FANOUT_MIN_POOL_BYTES_V1
    )));
}
#[test]
fn internal_proxy_memory_geometry_overflow_is_rejected_at_config_load() {
    let headroom = usize::try_from(defaults::torii::TORII_PROXY_HTTP_FIXED_MEMORY_HEADROOM_V1)
        .expect("proxy headroom fits usize");
    let phases = usize::try_from(defaults::torii::TORII_PROXY_HTTP_MEMORY_PHASE_UNITS_V1)
        .expect("proxy phase count fits usize");
    let first_overflow = (usize::MAX - headroom) / phases + 1;
    let Ok(first_overflow) = i64::try_from(first_overflow) else {
        return;
    };
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert("max_content_len".into(), Value::Integer(first_overflow));
    torii.insert(
        "query_fanout_max_retained_bytes".into(),
        Value::Integer(first_overflow),
    );
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("overflowing proxy memory geometry must fail before router construction");
    assert!(
        format!("{error:?}")
            .contains("max_content_len is too large for the first-release internal proxy")
    );
}
#[test]
fn content_limit_above_proxy_protocol_body_cap_is_rejected() {
    let first_invalid = defaults::torii::TORII_PROXY_MAX_INNER_BODY_BYTES_V1 + 1;
    let mut table = base_table();
    let torii = table
        .get_mut("torii")
        .and_then(Value::as_table_mut)
        .expect("torii table");
    torii.insert(
        "max_content_len".into(),
        Value::Integer(i64::try_from(first_invalid).expect("protocol bound fits TOML integer")),
    );
    torii.insert(
        "query_fanout_max_retained_bytes".into(),
        Value::Integer(i64::try_from(first_invalid).expect("protocol bound fits TOML integer")),
    );
    let error = actual::Root::from_toml_source(TomlSource::inline(table))
        .expect_err("content above the proxy protocol bound must fail at config load");
    assert!(format!("{error:?}").contains("proxy inner-body maximum"));
}
