//! Shared native benchmark report consistency checks for repository developer tools.
//!
//! Report arithmetic is not device provenance, a proof audit, or production qualification.
use fastpq_isi::{FASTPQ_CATALOG_V1, FASTPQ_FINAL_V1_ID};
use norito::json::{Map, Number, Value};
use std::collections::BTreeSet;

pub(super) const OPERATIONS: [&str; 6] = [
    "fft",
    "ifft",
    "lde",
    "digest384_trace_columns",
    "digest384_merkle_pairs",
    "bn254_poseidon_words",
];
const FIELDS: [&str; 15] = [
    "schema",
    "catalog",
    "protocol",
    "profile",
    "role",
    "phase",
    "level",
    "digest_lanes",
    "output_encoding",
    "frame_count",
    "input_field_bytes",
    "canonical_words",
    "sponge_permutations",
    "output_bytes",
    "cpu_reference_verified",
];
const GPU_FIELDS: [&str; 13] = [
    "backend",
    "warmup_invocations",
    "timed_invocations",
    "invocations",
    "dispatches",
    "frames",
    "canonical_words",
    "descriptor_words",
    "output_words",
    "max_batch_frames",
    "max_batch_words",
    "parity_checked_digests",
    "parity_checked_lanes",
];
type Check<T = ()> = Result<T, String>;
fn add(a: u64, b: u64) -> Check<u64> {
    a.checked_add(b)
        .ok_or_else(|| "benchmark count overflow".into())
}
fn mul(a: u64, b: u64) -> Check<u64> {
    a.checked_mul(b)
        .ok_or_else(|| "benchmark count overflow".into())
}
fn object<'a>(value: &'a Value, label: &str) -> Check<&'a Map> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}
fn number(value: &Value, key: &str, minimum: u64) -> Check<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n >= minimum)
        .ok_or_else(|| format!("{key} must be an integer >= {minimum}"))
}
// Norito's general numeric equality intentionally equates integral floats and
// integers. Report claims preserve JSON number kind across duplicate copies.
fn same_value(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(Number::F64(a)), Value::Number(Number::F64(b))) => a == b,
        (Value::Number(Number::F64(_)), Value::Number(_))
        | (Value::Number(_), Value::Number(Number::F64(_))) => false,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_value(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| same_value(value, other)))
        }
        _ => left == right,
    }
}
fn same_optional(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(a), Some(b)) => same_value(a, b),
        _ => false,
    }
}
fn equal(value: &Value, key: &str, expected: Value) -> Check {
    if value
        .get(key)
        .is_some_and(|actual| same_value(actual, &expected))
    {
        Ok(())
    } else {
        Err(format!("{key} differs from the canonical benchmark value"))
    }
}
fn eqn(value: &Value, key: &str, expected: u64) -> Check {
    equal(value, key, Value::from(expected))
}
fn closed<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Check<&'a Map> {
    let map = object(value, label)?;
    if required.iter().all(|key| map.contains_key(*key))
        && map
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    {
        Ok(map)
    } else {
        Err(format!("{label} must contain exactly its canonical fields"))
    }
}
pub(super) fn require_operation(name: &str) -> Check {
    if OPERATIONS.contains(&name) {
        Ok(())
    } else {
        Err(format!("unknown benchmark operation `{name}`"))
    }
}
pub(super) fn require_filter(name: &str) -> Check {
    if name == "all" {
        Ok(())
    } else {
        require_operation(name)
    }
}
pub(super) fn is_digest384(name: &str) -> bool {
    matches!(name, "digest384_trace_columns" | "digest384_merkle_pairs")
}
fn framed_words(bytes: u64) -> Check<u64> {
    if bytes > u64::from(u32::MAX) {
        return Err("framed input exceeds the primitive field-byte bound".into());
    }
    add(bytes / 7, 3)
}
fn base_words(phase: &str) -> Check<u64> {
    [
        "iroha:goldilocks-digest384:message-frame:v1",
        FASTPQ_CATALOG_V1,
        FASTPQ_FINAL_V1_ID,
        FASTPQ_FINAL_V1_ID,
        "fastpq:v1:preprocessing-trace",
        phase,
    ]
    .iter()
    .try_fold(19, |sum, field| add(sum, framed_words(field.len() as u64)?))
}
fn geometry(name: &str, frames: u64, length: u64) -> Check<(u64, u64)> {
    if name == "digest384_merkle_pairs" {
        let words = add(base_words("binary-node")?, mul(2, framed_words(48)?)?)?;
        return Ok((mul(frames, 96)?, mul(frames, add(words, words % 2)?)?));
    }
    let base = add(base_words("column-leaf")?, framed_words(mul(length, 8)?)?)?;
    let (mut first, mut end, mut digits, mut names, mut total) = (0, 100, 2, 0, 0);
    while first < frames {
        let count = frames.min(end) - first;
        let name_len = 6 + digits;
        names = add(names, mul(count, name_len)?)?;
        let words = add(base, framed_words(name_len)?)?;
        total = add(total, mul(count, add(words, words % 2)?)?)?;
        first = end;
        end = end.saturating_mul(10);
        digits += 1;
    }
    Ok((add(mul(mul(frames, length)?, 8)?, names)?, total))
}
fn staging_metrics(value: &Value, count: &str) -> Check {
    number(value, count, 0)?;
    for key in ["flatten_ms", "wait_ms", "wait_ratio"] {
        let n = value
            .get(key)
            .and_then(Value::as_f64)
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or_else(|| format!("staging {key} must be finite and nonnegative"))?;
        if key == "wait_ratio" && n > 1.0 {
            return Err("staging wait_ratio exceeds one".into());
        }
    }
    Ok(())
}
fn validate_staging(value: &Value) -> Check {
    let fields = ["batches", "flatten_ms", "wait_ms", "wait_ratio"];
    closed(value, &fields, &["phases", "samples"], "column_staging")?;
    staging_metrics(value, "batches")?;
    let phases = value.get("phases").ok_or("staging phases missing")?;
    let samples = value.get("samples").ok_or("staging samples missing")?;
    closed(phases, &["fft", "lde"], &[], "staging phases")?;
    closed(samples, &["fft", "lde"], &[], "staging samples")?;
    for name in ["fft", "lde"] {
        let phase = phases.get(name).ok_or("staging phase missing")?;
        closed(phase, &fields, &[], "staging phase")?;
        staging_metrics(phase, "batches")?;
        for sample in samples
            .get(name)
            .and_then(Value::as_array)
            .ok_or("staging samples must be arrays")?
        {
            closed(
                sample,
                &["batch", "flatten_ms", "wait_ms", "wait_ratio"],
                &[],
                "staging sample",
            )?;
            staging_metrics(sample, "batch")?;
        }
    }
    Ok(())
}
pub(super) fn retired_fields(report: &Value) -> Check {
    for key in [
        "poseidon_microbench",
        "poseidon_profiles",
        "scalar_lane",
        "speedup_vs_scalar",
        "default_mean_ms",
        "scalar_mean_ms",
    ] {
        if report.get(key).is_some() {
            return Err(format!("retired benchmark field `{key}`"));
        }
    }
    if let Some(queue) = report.get("metal_dispatch_queue") {
        for key in ["poseidon", "poseidon_pipeline"] {
            if queue.get(key).is_some() {
                return Err(format!("retired queue field `{key}`"));
            }
        }
    }
    if let Some(staging) = report.get("column_staging") {
        validate_staging(staging)?;
    }
    if let Some(heuristics) = report.get("metal_heuristics")
        && (heuristics.get("poseidon_batch_multiplier").is_some()
            || heuristics
                .get("batch_columns")
                .and_then(|v| v.get("poseidon"))
                .is_some())
    {
        return Err("unused scalar scheduling geometry is not benchmark evidence".into());
    }
    match report {
        Value::Object(map) => {
            for child in map.values() {
                retired_fields(child)?;
            }
        }
        Value::Array(rows) => {
            for child in rows {
                retired_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn validate_report(report: &Value, flattened: bool) -> Check {
    object(report, "report")?;
    retired_fields(report)?;
    let schema = report
        .get("producer_schema")
        .and_then(Value::as_str)
        .ok_or("producer_schema missing")?;
    let enabled = match (
        schema,
        report.get("execution_mode").and_then(Value::as_str),
        report.get("gpu_backend").and_then(Value::as_str),
    ) {
        ("metal_flat" | "cuda_nested", Some("cpu"), Some("none")) => false,
        ("metal_flat", Some("gpu"), Some("metal")) | ("cuda_nested", Some("gpu"), Some("cuda")) => {
            true
        }
        _ => return Err("producer_schema and explicit execution/backend identity disagree".into()),
    };
    equal(report, "gpu_available", Value::Bool(enabled))?;
    let rows = number(report, "rows", 1)?;
    let padded = number(report, "padded_rows", 1)?;
    let max_rows = 1_u64
        << fastpq_isi::find_by_name(FASTPQ_FINAL_V1_ID)
            .ok_or("canonical parameters missing")?
            .trace_log_size;
    if rows > max_rows || padded > max_rows || rows.checked_next_power_of_two() != Some(padded) {
        return Err("invalid bounded report row geometry".into());
    }
    number(report, "column_count", 1)?;
    add(
        number(report, "warmups", 0)?,
        number(report, "iterations", 1)?,
    )?;
    let entries = report
        .get("operations")
        .and_then(Value::as_array)
        .ok_or("report.operations missing")?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let name = entry
            .get("operation")
            .and_then(Value::as_str)
            .ok_or("operation name missing")?;
        require_operation(name)?;
        if !names.insert(name) {
            return Err(format!("duplicate operation `{name}`"));
        }
        validate_operation(entry, report, flattened)?;
    }
    {
        let filter = report
            .get("operation_filter")
            .and_then(Value::as_str)
            .ok_or("operation_filter must be present as a canonical string")?;
        require_filter(filter)?;
        if filter == "all" {
            if names.len() != OPERATIONS.len()
                || !entries.iter().zip(OPERATIONS).all(|(entry, name)| {
                    entry.get("operation").and_then(Value::as_str) == Some(name)
                })
            {
                return Err("all operation rows do not match canonical catalog".into());
            }
        } else {
            require_operation(filter)?;
            if names.len() != 1 || !names.contains(filter) {
                return Err("operation rows do not match declared filter".into());
            }
        }
    }
    Ok(())
}
fn finite(value: &Value, label: &str, nonnegative: bool) -> Check<f64> {
    value
        .as_f64()
        .filter(|n| n.is_finite() && (!nonnegative || *n >= 0.0))
        .ok_or_else(|| {
            format!(
                "{label} must be a finite{} number",
                if nonnegative { " nonnegative" } else { "" }
            )
        })
}
fn summary_mean(value: &Value, metal: bool, label: &str) -> Check {
    object(value, label)?;
    let mean = finite(
        value.get("mean_ms").ok_or("timing mean missing")?,
        label,
        true,
    )?;
    if metal {
        let min = finite(
            value.get("min_ms").ok_or("timing minimum missing")?,
            label,
            true,
        )?;
        let max = finite(
            value.get("max_ms").ok_or("timing maximum missing")?,
            label,
            true,
        )?;
        if min > mean || mean > max {
            return Err("timing range does not contain mean".into());
        }
    }
    Ok(())
}
fn validate_common_operation(entry: &Value, report: &Value, flattened: bool) -> Check {
    object(entry, "operation")?;
    number(entry, "columns", 1)?;
    number(entry, "input_len", 0)?;
    let metal = report.get("producer_schema").and_then(Value::as_str) == Some("metal_flat");
    let digest = entry
        .get("operation")
        .and_then(Value::as_str)
        .is_some_and(is_digest384);
    if !metal || digest {
        for key in ["output_len", "input_bytes", "output_bytes"] {
            number(entry, key, 0)?;
        }
    }
    if !metal && !digest {
        number(entry, "estimated_gpu_transfer_bytes", 0)?;
    }
    let enabled = report
        .get("gpu_available")
        .and_then(Value::as_bool)
        .ok_or("gpu_available missing")?;
    if flattened {
        if ["cpu", "gpu", "speedup", "gpu_recorded"]
            .iter()
            .any(|key| entry.get(*key).is_some())
        {
            return Err("flat timing must not contain raw timing objects".into());
        }
        finite(
            entry.get("cpu_mean_ms").ok_or("flat CPU mean missing")?,
            "CPU mean",
            true,
        )?;
        for key in ["gpu_mean_ms", "speedup_ratio", "speedup_delta_ms"] {
            let value = entry.get(key).ok_or_else(|| {
                format!("flat {key} must be present, with null for absent raw metrics")
            })?;
            if enabled {
                finite(value, key, key != "speedup_delta_ms")?;
            } else if !value.is_null() {
                return Err("CPU report must have null flat GPU metrics".into());
            }
        }
    } else {
        if [
            "cpu_mean_ms",
            "gpu_mean_ms",
            "speedup_ratio",
            "speedup_delta_ms",
        ]
        .iter()
        .any(|key| entry.get(*key).is_some())
        {
            return Err("raw timing must not contain flat timing fields".into());
        }
        summary_mean(
            entry.get("cpu").ok_or("CPU timing missing")?,
            metal,
            "CPU timing",
        )?;
        if metal {
            equal(entry, "gpu_recorded", Value::Bool(enabled))?;
        }
        if enabled {
            summary_mean(
                entry.get("gpu").ok_or("GPU timing missing")?,
                metal,
                "GPU timing",
            )?;
            let speedup = entry.get("speedup").ok_or("speedup missing")?;
            object(speedup, "speedup")?;
            finite(
                speedup.get("ratio").ok_or("speedup ratio missing")?,
                "speedup ratio",
                true,
            )?;
            finite(
                speedup.get("delta_ms").ok_or("speedup delta missing")?,
                "speedup delta",
                false,
            )?;
        } else if entry.get("gpu").is_some() || entry.get("speedup").is_some() {
            return Err("CPU raw report must omit GPU metrics".into());
        }
    }
    Ok(())
}
fn validate_operation(entry: &Value, report: &Value, flattened: bool) -> Check {
    validate_common_operation(entry, report, flattened)?;
    let name = entry
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("operation missing")?;
    if !is_digest384(name) {
        if entry.get("digest384").is_some() || entry.get("gpu_payload_buffer_bytes").is_some() {
            return Err("six-lane evidence cannot label another operation".into());
        }
        return Ok(());
    }
    if entry.get("estimated_gpu_transfer_bytes").is_some() {
        return Err("six-lane logical buffer bytes are not transfer bytes".into());
    }
    let evidence = entry.get("digest384").ok_or("missing digest384 evidence")?;
    let fields = closed(evidence, &FIELDS, &["gpu"], "digest384")?;
    let frames = number(entry, "columns", 1)?;
    let length = number(entry, "input_len", 1)?;
    let rows = number(report, "rows", 1)?;
    let padded = number(report, "padded_rows", 1)?;
    let columns = number(report, "column_count", 1)?;
    let max_rows = 1_u64
        << fastpq_isi::find_by_name(FASTPQ_FINAL_V1_ID)
            .ok_or("canonical parameters missing")?
            .trace_log_size;
    if rows > max_rows || padded > max_rows || rows.checked_next_power_of_two() != Some(padded) {
        return Err("invalid bounded report row geometry".into());
    }
    let (phase, level) = if name == "digest384_trace_columns" {
        if frames != columns || length != padded {
            return Err("trace operation does not match report geometry".into());
        }
        ("column-leaf", 0)
    } else {
        if frames != rows || length != 12 {
            return Err("Merkle operation does not match report geometry".into());
        }
        ("binary-node", 1)
    };
    let (input_bytes, words) = geometry(name, frames, length)?;
    for (key, value) in [
        ("schema", "fastpq-digest384-primitive-benchmark-v1"),
        ("catalog", FASTPQ_CATALOG_V1),
        ("protocol", FASTPQ_FINAL_V1_ID),
        ("profile", FASTPQ_FINAL_V1_ID),
        ("role", "fastpq:v1:preprocessing-trace"),
        ("phase", phase),
        ("output_encoding", "six-canonical-u64-le-words"),
    ] {
        equal(evidence, key, Value::from(value))?;
    }
    for (key, value) in [
        ("level", level),
        ("digest_lanes", 6),
        ("frame_count", frames),
        ("input_field_bytes", input_bytes),
        ("canonical_words", words),
        ("sponge_permutations", mul(3, words)?),
        ("output_bytes", mul(48, frames)?),
    ] {
        eqn(evidence, key, value)?;
    }
    equal(evidence, "cpu_reference_verified", Value::Bool(true))?;
    for (key, value) in [
        ("input_bytes", input_bytes),
        ("output_len", 6),
        ("output_bytes", mul(48, frames)?),
        (
            "gpu_payload_buffer_bytes",
            add(mul(8, words)?, mul(72, frames)?)?,
        ),
    ] {
        eqn(entry, key, value)?;
    }
    let mode = report
        .get("execution_mode")
        .and_then(Value::as_str)
        .ok_or("execution_mode missing")?;
    let backend = report
        .get("gpu_backend")
        .and_then(Value::as_str)
        .ok_or("gpu_backend missing")?;
    let has_gpu = if flattened {
        entry
            .get("gpu_mean_ms")
            .is_some_and(|value| !value.is_null())
    } else {
        entry.get("gpu").is_some()
    };
    let enabled = match (mode, backend) {
        ("cpu", "none") => false,
        ("gpu", "metal" | "cuda") => true,
        _ => return Err("explicit CPU/device execution required".into()),
    };
    equal(report, "gpu_available", Value::Bool(enabled))?;
    if has_gpu != enabled {
        return Err("GPU timing presence disagrees with execution mode".into());
    }
    if entry.get("gpu_recorded").is_some() {
        equal(entry, "gpu_recorded", Value::Bool(has_gpu))?;
    }
    let warmups = number(report, "warmups", 0)?;
    let iterations = number(report, "iterations", 1)?;
    if !enabled {
        if fields.contains_key("gpu") {
            return Err("CPU report must omit device evidence".into());
        }
        return Ok(());
    }
    let gpu = evidence.get("gpu").ok_or("device evidence missing")?;
    closed(gpu, &GPU_FIELDS, &[], "digest384.gpu")?;
    equal(gpu, "backend", Value::from(backend))?;
    let invocations = add(warmups, iterations)?;
    let total_frames = mul(frames, invocations)?;
    let total_words = mul(words, invocations)?;
    for (key, value) in [
        ("warmup_invocations", warmups),
        ("timed_invocations", iterations),
        ("invocations", invocations),
        ("frames", total_frames),
        ("canonical_words", total_words),
        ("descriptor_words", mul(3, total_frames)?),
        ("output_words", mul(6, total_frames)?),
        ("parity_checked_digests", total_frames),
        ("parity_checked_lanes", mul(6, total_frames)?),
    ] {
        eqn(gpu, key, value)?;
    }
    let dispatches = number(gpu, "dispatches", invocations)?;
    let max_frames = number(gpu, "max_batch_frames", 1)?;
    let max_words = number(gpu, "max_batch_words", 1)?;
    if dispatches > total_frames
        || max_frames > frames.min(65_536)
        || max_words > words.min(4_194_304)
        || max_words % 2 != 0
        || max_words < mul(max_frames, 2)?
        || mul(max_frames, dispatches)? < total_frames
        || mul(max_words, dispatches)? < total_words
    {
        return Err("device dispatches cannot cover claimed complete frames".into());
    }
    Ok(())
}

/// Select and validate the explicitly declared producer and all present projections.
pub(super) fn report_from_root(root: &Value) -> Check<&Value> {
    retired_fields(root)?;
    let schema = root
        .get("producer_schema")
        .and_then(Value::as_str)
        .ok_or("producer_schema missing")?;
    match schema {
        "metal_flat" if root.get("report").is_none() && root.get("benchmarks").is_none() => {
            validate_report(root, false)?;
            Ok(root)
        }
        "metal_flat" | "cuda_nested" => {
            let report = root
                .get("report")
                .ok_or("declared envelope requires report")?;
            let flat = root
                .get("benchmarks")
                .ok_or("declared envelope requires benchmarks")?;
            equal(report, "producer_schema", Value::from(schema))?;
            if flat.get("producer_schema").is_some() {
                equal(flat, "producer_schema", Value::from(schema))?;
            }
            validate_report(report, false)?;
            // The explicit envelope supplies the schema for its flat projection.
            // This optional duplicate tag does not select a producer.
            let mut flat_context = flat.clone();
            object(flat, "benchmarks")?;
            flat_context
                .as_object_mut()
                .expect("validated flat map")
                .insert("producer_schema".into(), Value::from(schema));
            validate_report(&flat_context, true)?;
            for key in [
                "rows",
                "padded_rows",
                "column_count",
                "iterations",
                "warmups",
                "execution_mode",
                "gpu_backend",
                "gpu_available",
                "operation_filter",
                "column_staging",
                "bn254_metrics",
                "bn254_warnings",
            ] {
                if !same_optional(report.get(key), flat.get(key)) {
                    return Err(format!("report copies disagree on {key}"));
                }
            }
            let nested = report
                .get("operations")
                .and_then(Value::as_array)
                .ok_or("report operations missing")?;
            let flattened = flat
                .get("operations")
                .and_then(Value::as_array)
                .ok_or("benchmark operations missing")?;
            if nested.len() != flattened.len() {
                return Err("operation projections differ in length".into());
            }
            for (entry, projected) in nested.iter().zip(flattened) {
                if !same_optional(entry.get("operation"), projected.get("operation")) {
                    return Err("operation copies disagree on ordered operation names".into());
                }
                for key in [
                    "columns",
                    "input_len",
                    "output_len",
                    "input_bytes",
                    "output_bytes",
                    "estimated_gpu_transfer_bytes",
                    "gpu_payload_buffer_bytes",
                    "digest384",
                ] {
                    if !same_optional(entry.get(key), projected.get(key)) {
                        return Err(format!("operation copies disagree on {key}"));
                    }
                }
                for (object, key, target) in [
                    ("cpu", "mean_ms", "cpu_mean_ms"),
                    ("gpu", "mean_ms", "gpu_mean_ms"),
                    ("speedup", "ratio", "speedup_ratio"),
                    ("speedup", "delta_ms", "speedup_delta_ms"),
                ] {
                    let absent = Value::Null;
                    let value = entry
                        .get(object)
                        .and_then(|map| map.get(key))
                        .unwrap_or(&absent);
                    if !projected
                        .get(target)
                        .is_some_and(|other| same_value(value, other))
                    {
                        return Err(format!("operation copies disagree on {target}"));
                    }
                }
            }
            Ok(report)
        }
        _ => Err("unknown producer_schema".into()),
    }
}

#[cfg(test)]
pub(super) fn test_report(rows: u64, flattened: bool) -> Value {
    // Synthetic schema controls only: these values never attest to a device run.
    let mut map = Map::new();
    for (key, value) in [
        ("rows", rows),
        ("padded_rows", rows.next_power_of_two()),
        ("column_count", 2),
        ("warmups", 1),
        ("iterations", 3),
    ] {
        map.insert(key.into(), Value::from(value));
    }
    for (key, value) in [
        ("producer_schema", "cuda_nested"),
        ("execution_mode", "gpu"),
        ("gpu_backend", "cuda"),
        ("operation_filter", "all"),
    ] {
        map.insert(key.into(), Value::from(value));
    }
    map.insert("gpu_available".into(), Value::Bool(true));
    let entries = OPERATIONS
        .iter()
        .map(|name| {
            let mut entry = Map::new();
            entry.insert("operation".into(), Value::from(*name));
            if !is_digest384(name) {
                let length = if *name == "lde" {
                    rows.next_power_of_two() * 8
                } else {
                    rows.next_power_of_two()
                };
                for (key, value) in [
                    ("columns", 2),
                    ("input_len", length),
                    ("output_len", length),
                    ("input_bytes", 16 * length),
                    ("output_bytes", 16 * length),
                    ("estimated_gpu_transfer_bytes", 32 * length),
                ] {
                    entry.insert(key.into(), Value::from(value));
                }
            }
            let cpu_ms = if *name == "fft" { 504.0 } else { 840.0 };
            let gpu_ms = match *name {
                "fft" => 420.0,
                "lde" => 800.0,
                _ => 700.0,
            };
            if flattened {
                for (key, value) in [
                    ("cpu_mean_ms", cpu_ms),
                    ("gpu_mean_ms", gpu_ms),
                    ("speedup_ratio", cpu_ms / gpu_ms),
                    ("speedup_delta_ms", cpu_ms - gpu_ms),
                ] {
                    entry.insert(key.into(), Value::from(value));
                }
            } else {
                for (key, value) in [("cpu", cpu_ms), ("gpu", gpu_ms)] {
                    let fields = [
                        ("mean_ms".to_owned(), Value::from(value)),
                        ("min_ms".to_owned(), Value::from(value)),
                        ("max_ms".to_owned(), Value::from(value)),
                    ]
                    .into_iter()
                    .collect();
                    entry.insert(key.into(), Value::Object(fields));
                }
                entry.insert(
                    "speedup".into(),
                    Value::Object(
                        [
                            ("ratio".into(), Value::from(cpu_ms / gpu_ms)),
                            ("delta_ms".into(), Value::from(cpu_ms - gpu_ms)),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                );
            }
            if is_digest384(name) {
                let frames = if *name == "digest384_trace_columns" {
                    2
                } else {
                    rows
                };
                let length = if *name == "digest384_trace_columns" {
                    rows.next_power_of_two()
                } else {
                    12
                };
                let (bytes, words) = geometry(name, frames, length).unwrap();
                for (key, value) in [
                    ("columns", frames),
                    ("input_len", length),
                    ("input_bytes", bytes),
                    ("output_len", 6),
                    ("output_bytes", 48 * frames),
                    ("gpu_payload_buffer_bytes", 8 * words + 72 * frames),
                ] {
                    entry.insert(key.into(), Value::from(value));
                }
                let mut evidence = Map::new();
                let phase = if *name == "digest384_trace_columns" {
                    "column-leaf"
                } else {
                    "binary-node"
                };
                for (key, value) in [
                    ("schema", "fastpq-digest384-primitive-benchmark-v1"),
                    ("catalog", FASTPQ_CATALOG_V1),
                    ("protocol", FASTPQ_FINAL_V1_ID),
                    ("profile", FASTPQ_FINAL_V1_ID),
                    ("role", "fastpq:v1:preprocessing-trace"),
                    ("phase", phase),
                    ("output_encoding", "six-canonical-u64-le-words"),
                ] {
                    evidence.insert(key.into(), Value::from(value));
                }
                for (key, value) in [
                    ("level", u64::from(phase == "binary-node")),
                    ("digest_lanes", 6),
                    ("frame_count", frames),
                    ("input_field_bytes", bytes),
                    ("canonical_words", words),
                    ("sponge_permutations", 3 * words),
                    ("output_bytes", 48 * frames),
                ] {
                    evidence.insert(key.into(), Value::from(value));
                }
                evidence.insert("cpu_reference_verified".into(), Value::Bool(true));
                let mut gpu = Map::new();
                gpu.insert("backend".into(), Value::from("cuda"));
                // One complete frame per synthetic callback keeps these controls bounded at every tested geometry.
                let maximum_words = words / frames + (words / frames) % 2;
                for (key, value) in [
                    ("warmup_invocations", 1),
                    ("timed_invocations", 3),
                    ("invocations", 4),
                    ("dispatches", 4 * frames),
                    ("frames", 4 * frames),
                    ("canonical_words", 4 * words),
                    ("descriptor_words", 12 * frames),
                    ("output_words", 24 * frames),
                    ("max_batch_frames", 1),
                    ("max_batch_words", maximum_words),
                    ("parity_checked_digests", 4 * frames),
                    ("parity_checked_lanes", 24 * frames),
                ] {
                    gpu.insert(key.into(), Value::from(value));
                }
                evidence.insert("gpu".into(), Value::Object(gpu));
                entry.insert("digest384".into(), Value::Object(evidence));
            }
            Value::Object(entry)
        })
        .collect();
    map.insert("operations".into(), Value::Array(entries));
    let result = Value::Object(map);
    validate_report(&result, flattened).unwrap();
    result
}

#[cfg(test)]
pub(super) fn test_metal_report(rows: u64) -> Value {
    let mut report = test_report(rows, false);
    let map = report.as_object_mut().unwrap();
    map.insert("producer_schema".into(), Value::from("metal_flat"));
    map.insert("gpu_backend".into(), Value::from("metal"));
    for operation in map.get_mut("operations").unwrap().as_array_mut().unwrap() {
        operation
            .as_object_mut()
            .unwrap()
            .insert("gpu_recorded".into(), Value::Bool(true));
        if let Some(gpu) = operation
            .get_mut("digest384")
            .and_then(|e| e.get_mut("gpu"))
        {
            gpu.as_object_mut()
                .unwrap()
                .insert("backend".into(), Value::from("metal"));
        }
    }
    validate_report(&report, false).unwrap();
    report
}
#[cfg(test)]
pub(super) fn test_staging() -> Value {
    norito::json!({
        "batches": 32, "flatten_ms": 420.0, "wait_ms": 180.0, "wait_ratio": 0.3,
        "phases": {
            "fft": {"batches": 16, "flatten_ms": 210.0, "wait_ms": 90.0, "wait_ratio": 0.3},
            "lde": {"batches": 16, "flatten_ms": 210.0, "wait_ms": 90.0, "wait_ratio": 0.3}
        },
        "samples": {
            "fft": [{"batch": 1, "flatten_ms": 21.0, "wait_ms": 9.0, "wait_ratio": 0.3}],
            "lde": []
        }
    })
}

#[cfg(test)]
fn test_bundle(metal: bool, cpu: bool, flat_tag: bool) -> Value {
    let mut report = if metal {
        test_metal_report(3)
    } else {
        test_report(3, false)
    };
    if cpu {
        let map = report.as_object_mut().unwrap();
        map.insert("execution_mode".into(), Value::from("cpu"));
        map.insert("gpu_backend".into(), Value::from("none"));
        map.insert("gpu_available".into(), Value::Bool(false));
        for entry in map.get_mut("operations").unwrap().as_array_mut().unwrap() {
            let entry = entry.as_object_mut().unwrap();
            entry.remove("gpu");
            entry.remove("speedup");
            if metal {
                entry.insert("gpu_recorded".into(), Value::Bool(false));
            }
            if let Some(evidence) = entry.get_mut("digest384") {
                evidence.as_object_mut().unwrap().remove("gpu");
            }
        }
    }
    let mut flat = report.clone();
    for entry in flat.get_mut("operations").unwrap().as_array_mut().unwrap() {
        let map = entry.as_object_mut().unwrap();
        map.remove("gpu_recorded");
        let cpu = map.remove("cpu").unwrap();
        let gpu = map.remove("gpu");
        let speedup = map.remove("speedup");
        map.insert("cpu_mean_ms".into(), cpu.get("mean_ms").unwrap().clone());
        map.insert(
            "gpu_mean_ms".into(),
            gpu.as_ref()
                .and_then(|v| v.get("mean_ms"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        for (field, target) in [("ratio", "speedup_ratio"), ("delta_ms", "speedup_delta_ms")] {
            map.insert(
                target.into(),
                speedup
                    .as_ref()
                    .and_then(|v| v.get(field))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }
    if !flat_tag {
        flat.as_object_mut().unwrap().remove("producer_schema");
    }
    Value::Object(
        [
            (
                "producer_schema".into(),
                Value::from(if metal { "metal_flat" } else { "cuda_nested" }),
            ),
            ("report".into(), report),
            ("benchmarks".into(), flat),
        ]
        .into_iter()
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_count_math_matches_actual_primitive_at_generated_name_boundaries() {
        use fastpq_isi::{GoldilocksDigest384FrameV1, GoldilocksDigestDomainV1};
        for frames in [1_u64, 2, 99, 100, 101] {
            let mut words = 0;
            let mut bytes = 0;
            for index in 0..frames {
                let name = format!("bench_{index:02}");
                let values = [0_u8; 32];
                let fields = [name.as_bytes(), values.as_slice()];
                let frame = GoldilocksDigest384FrameV1::new(
                    GoldilocksDigestDomainV1 {
                        catalog: FASTPQ_CATALOG_V1.as_bytes(),
                        protocol: FASTPQ_FINAL_V1_ID.as_bytes(),
                        profile: FASTPQ_FINAL_V1_ID.as_bytes(),
                        role: b"fastpq:v1:preprocessing-trace",
                        phase: b"column-leaf",
                        level: 0,
                        index,
                        counter: 0,
                    },
                    &fields,
                )
                .unwrap();
                words += frame.word_count() as u64;
                bytes += (name.len() + values.len()) as u64;
            }
            assert_eq!(
                geometry("digest384_trace_columns", frames, 4).unwrap(),
                (bytes, words)
            );
        }
        assert!(geometry("digest384_trace_columns", u64::MAX, u64::MAX).is_err());
    }
    #[test]
    fn closed_evidence_rejects_every_field_deletion_or_mutation() {
        let report = test_report(3, false);
        for index in [3, 4] {
            let entry = report.get("operations").unwrap().as_array().unwrap()[index].clone();
            validate_operation(&entry, &report, false).unwrap();
            for key in FIELDS {
                let mut changed = entry.clone();
                changed
                    .get_mut("digest384")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                assert!(
                    validate_operation(&changed, &report, false).is_err(),
                    "missing {key}"
                );
                let mut changed = entry.clone();
                changed
                    .get_mut("digest384")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Null);
                assert!(
                    validate_operation(&changed, &report, false).is_err(),
                    "null {key}"
                );
            }
            for key in GPU_FIELDS {
                let mut changed = entry.clone();
                changed
                    .get_mut("digest384")
                    .unwrap()
                    .get_mut("gpu")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Null);
                assert!(
                    validate_operation(&changed, &report, false).is_err(),
                    "device {key}"
                );
            }
            let mut changed = entry.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert("estimated_gpu_transfer_bytes".into(), Value::Null);
            assert!(validate_operation(&changed, &report, false).is_err());
            let mut changed = entry.clone();
            changed
                .get_mut("digest384")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), Value::Null);
            assert!(validate_operation(&changed, &report, false).is_err());
        }
    }
    #[test]
    fn preserves_fft_lde_staging_and_rejects_retired_or_malformed_phases() {
        let staging = test_staging();
        validate_staging(&staging).unwrap();
        let mut report = test_metal_report(3);
        report
            .as_object_mut()
            .unwrap()
            .insert("column_staging".into(), staging.clone());
        report_from_root(&report).unwrap();
        for group in ["phases", "samples"] {
            for key in ["poseidon", "unknown"] {
                let mut changed = staging.clone();
                changed
                    .get_mut(group)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Null);
                assert!(validate_staging(&changed).is_err(), "{group}.{key}");
            }
            let mut changed = staging.clone();
            changed
                .get_mut(group)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("lde");
            assert!(validate_staging(&changed).is_err());
        }
        for key in [
            "batches",
            "flatten_ms",
            "wait_ms",
            "wait_ratio",
            "phases",
            "samples",
        ] {
            let mut changed = staging.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(validate_staging(&changed).is_err(), "missing {key}");
        }
        for field in ["flatten_ms", "wait_ms", "wait_ratio"] {
            let mut changed = staging.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert(field.into(), Value::from(-1.0));
            assert!(validate_staging(&changed).is_err(), "negative {field}");
        }
        let mut changed = staging;
        changed
            .as_object_mut()
            .unwrap()
            .insert("wait_ratio".into(), Value::from(1.001));
        assert!(validate_staging(&changed).is_err());
        for retired in [
            norito::json!({"poseidon_batch_multiplier": null}),
            norito::json!({"batch_columns": {"poseidon": null}}),
        ] {
            let mut changed = report.clone();
            changed
                .as_object_mut()
                .unwrap()
                .insert("metal_heuristics".into(), retired);
            assert!(report_from_root(&changed).is_err());
        }
    }
    #[test]
    fn producer_backend_and_filter_are_explicit_even_without_digest_operations() {
        let report = test_metal_report(3);
        report_from_root(&report).unwrap();
        for (key, value) in [
            ("gpu_backend", Value::from("cuda")),
            ("producer_schema", Value::from("cuda_nested")),
            ("operation_filter", Value::from("ALL")),
            ("operation_filter", Value::from(" all")),
            ("operation_filter", Value::Null),
        ] {
            let mut changed = report.clone();
            changed.as_object_mut().unwrap().insert(key.into(), value);
            assert!(validate_report(&changed, false).is_err(), "{key}");
        }
        let mut changed = report;
        changed.as_object_mut().unwrap().remove("operation_filter");
        assert!(validate_report(&changed, false).is_err());
    }
    #[test]
    fn cross_language_final_v1_fixtures_have_identical_acceptance() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository = match env!("CARGO_PKG_NAME") {
            "xtask" => manifest_dir.parent().unwrap(),
            "fastpq_poseidon_tools" => manifest_dir.parent().unwrap().parent().unwrap(),
            other => panic!("fixture root must be explicitly owned for consumer {other}"),
        };
        let directory = repository.join("fixtures/fastpq/benchmark_v1");
        let manifest: Value = norito::json::from_slice(
            &std::fs::read(directory.join("manifest.json"))
                .expect("maintained cross-language fixture manifest"),
        )
        .unwrap();
        assert_eq!(manifest.get("hardware_evidence"), Some(&Value::Bool(false)));
        assert_eq!(
            manifest.get("schema").and_then(Value::as_str),
            Some("fastpq-benchmark-v1-synthetic-contract-fixtures")
        );
        let rows = manifest.get("files").unwrap().as_array().unwrap();
        assert_eq!(rows.len(), 16);
        let (mut accepted, mut rejected) = (0, 0);
        for row in rows {
            let name = row.get("path").unwrap().as_str().unwrap();
            assert!(!name.contains('/') && !name.contains(".."));
            let bytes =
                std::fs::read(directory.join(name)).expect("all maintained fixtures are required");
            let value: Value = norito::json::from_slice(&bytes).unwrap();
            let result = report_from_root(&value);
            match row.get("expected").unwrap().as_str().unwrap() {
                "accept" => {
                    accepted += 1;
                    assert!(result.is_ok(), "{name}: {result:?}");
                }
                "reject" => {
                    rejected += 1;
                    assert!(result.is_err(), "{name} must reject");
                }
                other => panic!("unknown fixture expectation {other}"),
            }
        }
        assert_eq!((accepted, rejected), (8, 8));
    }
    #[test]
    fn current_wrapped_cpu_gpu_reports_require_nullable_flat_metrics_and_typed_ordered_copies() {
        for metal in [false, true] {
            for cpu in [false, true] {
                for flat_tag in [false, true] {
                    let root = test_bundle(metal, cpu, flat_tag);
                    report_from_root(&root).unwrap();
                    for key in ["gpu_mean_ms", "speedup_ratio", "speedup_delta_ms"] {
                        let mut changed = root.clone();
                        changed
                            .get_mut("benchmarks")
                            .unwrap()
                            .get_mut("operations")
                            .unwrap()
                            .as_array_mut()
                            .unwrap()[0]
                            .as_object_mut()
                            .unwrap()
                            .remove(key);
                        assert!(
                            report_from_root(&changed).is_err(),
                            "missing {key} metal={metal} cpu={cpu}"
                        );
                    }
                    let mut changed = root.clone();
                    changed.as_object_mut().unwrap().remove("producer_schema");
                    assert!(report_from_root(&changed).is_err());
                    let mut changed = root.clone();
                    changed
                        .get_mut("report")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("producer_schema");
                    assert!(report_from_root(&changed).is_err());
                    let mut changed = root.clone();
                    changed
                        .get_mut("benchmarks")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert("producer_schema".into(), Value::from("other"));
                    assert!(report_from_root(&changed).is_err());
                    let mut changed = root.clone();
                    changed
                        .get_mut("benchmarks")
                        .unwrap()
                        .get_mut("operations")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                        .swap(0, 1);
                    assert!(report_from_root(&changed).is_err());
                    let mut changed = root.clone();
                    changed
                        .get_mut("benchmarks")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert("column_count".into(), Value::from(2.0));
                    assert!(report_from_root(&changed).is_err());
                    let mut changed = root.clone();
                    changed
                        .get_mut("benchmarks")
                        .unwrap()
                        .get_mut("operations")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()[0]
                        .as_object_mut()
                        .unwrap()
                        .insert("cpu_mean_ms".into(), Value::from(504_u64));
                    assert!(
                        report_from_root(&changed).is_err(),
                        "integral float and integer timing copies differ"
                    );
                    let mut changed = root.clone();
                    changed
                        .get_mut("report")
                        .unwrap()
                        .get_mut("operations")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()[0]
                        .as_object_mut()
                        .unwrap()
                        .insert("gpu".into(), Value::Null);
                    assert!(
                        report_from_root(&changed).is_err(),
                        "raw null is not omitted GPU timing"
                    );
                    let mut changed = root;
                    changed
                        .get_mut("benchmarks")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert("column_staging".into(), test_staging());
                    assert!(
                        report_from_root(&changed).is_err(),
                        "staging copies must agree"
                    );
                }
            }
        }
    }
    #[test]
    fn flattened_reports_reject_raw_gpu_recording_markers() {
        for metal in [false, true] {
            for cpu in [false, true] {
                let mut root = test_bundle(metal, cpu, false);
                assert!(report_from_root(&root).is_ok());
                root.get_mut("benchmarks")
                    .unwrap()
                    .get_mut("operations")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()[0]
                    .as_object_mut()
                    .unwrap()
                    .insert("gpu_recorded".into(), Value::Bool(!cpu));
                assert!(report_from_root(&root).is_err());
            }
        }
    }

    #[test]
    fn duplicated_bn254_diagnostics_retain_exact_presence_and_json_types() {
        for key in ["bn254_metrics", "bn254_warnings"] {
            for metal in [false, true] {
                let mut root = test_bundle(metal, false, false);
                let value = Value::Array(vec![Value::from(1_u64)]);
                for copy in ["report", "benchmarks"] {
                    root.get_mut(copy)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert(key.into(), value.clone());
                }
                assert!(report_from_root(&root).is_ok());
                let mut changed = root.clone();
                changed
                    .get_mut("benchmarks")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
                assert!(report_from_root(&changed).is_err());
                root.get_mut("benchmarks")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), Value::Array(vec![Value::from(1.0)]));
                assert!(report_from_root(&root).is_err());
            }
        }
    }

    #[test]
    fn all_filter_and_integer_work_claims_use_exact_canonical_inventory_and_json_kinds() {
        let report = test_metal_report(3);
        for partial in [true, false] {
            let mut changed = report.clone();
            let rows = changed
                .get_mut("operations")
                .unwrap()
                .as_array_mut()
                .unwrap();
            if partial {
                rows.pop();
            } else {
                rows.swap(0, 1);
            }
            assert!(report_from_root(&changed).is_err());
        }
        for key in [
            "level",
            "digest_lanes",
            "frame_count",
            "canonical_words",
            "sponge_permutations",
            "output_bytes",
        ] {
            let mut changed = report.clone();
            let evidence = changed
                .get_mut("operations")
                .unwrap()
                .as_array_mut()
                .unwrap()[3]
                .get_mut("digest384")
                .unwrap()
                .as_object_mut()
                .unwrap();
            let value = evidence.get(key).unwrap().as_f64().unwrap();
            evidence.insert(key.into(), Value::from(value));
            assert!(report_from_root(&changed).is_err(), "integral float {key}");
        }
    }
    #[test]
    fn generic_focused_reports_reject_missing_geometry_timing_and_nested_retired_claims() {
        let mut report = test_metal_report(3);
        report
            .as_object_mut()
            .unwrap()
            .insert("operation_filter".into(), Value::from("fft"));
        report
            .get_mut("operations")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .truncate(1);
        report_from_root(&report).unwrap();
        for field in [
            "rows",
            "padded_rows",
            "iterations",
            "warmups",
            "column_count",
        ] {
            let mut changed = report.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(report_from_root(&changed).is_err(), "missing {field}");
        }
        for field in [
            "columns",
            "input_len",
            "cpu",
            "gpu",
            "speedup",
            "gpu_recorded",
        ] {
            let mut changed = report.clone();
            changed
                .get_mut("operations")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(report_from_root(&changed).is_err(), "missing {field}");
        }
        for key in [
            "poseidon_microbench",
            "poseidon_profiles",
            "scalar_lane",
            "speedup_vs_scalar",
            "default_mean_ms",
            "scalar_mean_ms",
        ] {
            let mut changed = report.clone();
            changed
                .get_mut("operations")
                .unwrap()
                .as_array_mut()
                .unwrap()[0]
                .as_object_mut()
                .unwrap()
                .insert(key.into(), Value::Null);
            assert!(report_from_root(&changed).is_err(), "nested retired {key}");
        }
        let mut changed = report;
        changed
            .get_mut("operations")
            .unwrap()
            .as_array_mut()
            .unwrap()[0]
            .get_mut("gpu")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("mean_ms".into(), Value::from("fake"));
        assert!(report_from_root(&changed).is_err());
        assert!(!same_value(&Value::from(1_u64), &Value::from(1.0)));
    }
    #[test]
    fn producer_tag_and_copy_disagreement_are_rejected() {
        let report = test_report(3, false);
        let flat = test_report(3, true);
        let root = Value::Object(
            [
                ("producer_schema".into(), Value::from("cuda_nested")),
                ("report".into(), report),
                ("benchmarks".into(), flat),
            ]
            .into_iter()
            .collect(),
        );
        report_from_root(&root).unwrap();
        for (key, value) in [
            ("producer_schema", Value::from("legacy")),
            ("producer_schema", Value::Null),
            ("poseidon_microbench", Value::Null),
        ] {
            let mut changed = root.clone();
            changed.as_object_mut().unwrap().insert(key.into(), value);
            assert!(report_from_root(&changed).is_err());
        }
        let mut changed = root.clone();
        changed
            .get_mut("benchmarks")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("rows".into(), Value::from(4_u8));
        assert!(report_from_root(&changed).is_err());
        let mut changed = root;
        changed
            .get_mut("benchmarks")
            .unwrap()
            .get_mut("operations")
            .unwrap()
            .as_array_mut()
            .unwrap()[3]
            .as_object_mut()
            .unwrap()
            .insert("gpu_mean_ms".into(), Value::from(1.0));
        assert!(report_from_root(&changed).is_err());
    }
}
