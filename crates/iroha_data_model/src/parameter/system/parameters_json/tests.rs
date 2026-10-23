//! Canonical record equality, original ownership and native refusal controls.

use super::*;
use crate::amx_prepare_streaming_allocations::{
    PhysicalObservation, measured, with_nth_exact_allocation_denial,
};
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, classify_decode_attempt,
};

fn decode(
    source: &str,
    pool: &AllocationBudget,
) -> Result<AdmittedParameters, ParametersJsonAdmissionError> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let owner = AdmittedParameters::try_decode_json(&mut parser, pool)?;
    parser.finish_document()?;
    Ok(owner)
}
fn failure(
    result: Result<AdmittedParameters, ParametersJsonAdmissionError>,
) -> ParametersJsonAdmissionError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected refusal"),
    }
}
fn reject(source: &str) {
    let pool = AllocationBudget::new(1 << 20);
    assert!(
        json::from_str::<Parameters>(source).is_err(),
        "ordinary: {source}"
    );
    assert!(decode(source, &pool).is_err(), "admitted: {source}");
    assert_eq!(pool.reserved_bytes(), 0, "{source}");
}
fn limits(bytes: usize) -> DecodeLimits {
    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
const CUSTOM: &str = r#"{"custom":{"long_custom_parameter_identity_beyond_inline":{"id":"long_custom_parameter_identity_beyond_inline","payload":{"a":[1,true],"b":"text"}}},"sumeragi":{"due_work_max_lag_ms":60000,"key_allowed_algorithms":["ed25519","bls_normal"]}}"#;

#[test]
fn complete_record_matches_ordinary_and_canonical_binary_roundtrip() {
    use norito::codec::{Decode, Encode};
    let expected = Parameters::default();
    let source = json::to_json(&expected).unwrap();
    let pool = AllocationBudget::new(1 << 20);
    let owner = decode(&source, &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    assert_eq!(json::from_str::<Parameters>(&source).unwrap(), expected);
    assert_eq!(json::to_json(owner.get()).unwrap(), source);
    let bytes = owner.get().encode();
    assert_eq!(Parameters::decode(&mut bytes.as_slice()).unwrap(), expected);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_pool_defaults_have_no_temporary_graph_and_exact_one_array() {
    let expected = Parameters::default();
    let layout =
        Layout::array::<Algorithm>(defaults::sumeragi::KEY_ALLOWED_ALGORITHMS.len()).unwrap();
    let pool = AllocationBudget::new(layout.size());
    let foreign = AllocationBudget::new(layout.size());
    let (owner, requests) = measured(|| AdmittedParameters::try_protocol_default(&pool));
    assert_eq!(requests, [1, 0, 0]);
    let owner = owner.unwrap();
    assert_eq!(owner.get(), &expected);
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&foreign));
    assert_eq!(pool.reserved_bytes(), layout.size());
    assert_eq!(owner.custody.bytes(), layout.size());
    assert!(owner.get().custom.belongs_to(&pool));
    drop(owner);
    let owner = decode("{}", &pool).unwrap();
    assert_eq!(owner.get(), &expected);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn zero_budget_denies_before_native_allocation_and_empty_array_retains_pool_identity() {
    let pool = AllocationBudget::new(0);
    for factory in [false, true] {
        let (result, requests) = measured(|| {
            if factory {
                AdmittedParameters::try_protocol_default(&pool)
            } else {
                decode("{}", &pool)
            }
        });
        assert!(matches!(
            result,
            Err(ParametersJsonAdmissionError::Allocation(
                ChargedBufferError::Admission(_)
            ))
        ));
        assert_eq!(requests, [0, 0, 0]);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    let empty = r#"{"sumeragi":{"due_work_max_lag_ms":60000,"key_allowed_algorithms":[]}}"#;
    let owner = decode(empty, &pool).unwrap();
    assert!(owner.belongs_to(&pool));
    assert!(!owner.belongs_to(&AllocationBudget::new(0)));
    assert!(owner.get().sumeragi.key_allowed_algorithms.is_empty());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn escaped_keys_and_algorithm_text_use_the_same_original_scratch_pool() {
    let source = r#"{"sumer\u0061gi":{"due_work_max_lag_ms":60000,"key_allowed_algorithms":["ed\u00325519","bls_normal"]},"transact\u0069on":{"max_metadata_depth":7,"require_sequence":true},"executor":{"execution_depth":255}}"#;
    let pool = AllocationBudget::new(1 << 20);
    let owner = decode(source, &pool).unwrap();
    assert_eq!(owner.get(), &json::from_str::<Parameters>(source).unwrap());
    assert_eq!(
        owner.get().sumeragi.key_allowed_algorithms,
        [Algorithm::Ed25519, Algorithm::BlsNormal]
    );
    assert_eq!(owner.get().transaction.max_metadata_depth.get(), 7);
    assert!(owner.get().transaction.require_sequence);
    assert_eq!(owner.get().executor.execution_depth, 255);
    drop(owner);
    assert_eq!(pool.reserved_bytes(), 0);
    let zero = AllocationBudget::new(0);
    assert!(matches!(
        decode(source, &zero),
        Err(ParametersJsonAdmissionError::Allocation(
            ChargedBufferError::Admission(_)
        ))
    ));
    assert_eq!(zero.reserved_bytes(), 0);
}

#[test]
fn malformed_records_scalar_bounds_duplicates_and_unknowns_are_rejected() {
    for source in [
        "[]",
        "null",
        r#"{"sumeragi":{}}"#,
        r#"{"block":{}}"#,
        r#"{"sumeragi":{"due_work_max_lag_ms":0}}"#,
        r#"{"sumeragi":{"due_work_max_lag_ms":1,"max_block_bytes":4294967296}}"#,
        r#"{"sumeragi":{"due_work_max_lag_ms":1,"key_allowed_algorithms":["unknown"]}}"#,
        r#"{"sumeragi":{"due_work_max_lag_ms":1,"key_allowed_algorithms":[1]}}"#,
        r#"{"transaction":{"max_metadata_depth":65536}}"#,
        r#"{"transaction":{"max_metadata_depth":0}}"#,
        r#"{"transaction":{"max_tx_bytes":18446744073709551616}}"#,
        r#"{"transaction":{"require_sequence":1}}"#,
        r#"{"smart_contract":{"fuel":-1}}"#,
        r#"{"smart_contract":{"memory":1.0}}"#,
        r#"{"smart_contract":{"max_output_items":1e0}}"#,
        r#"{"executor":{"execution_depth":256}}"#,
        r#"{"executor":{"fuel":1,"fuel":2}}"#,
        r#"{"executor":{"fuel":1,"fu\u0065l":2}}"#,
        r#"{"transaction":{},"transaction":{}}"#,
        r#"{"custom":{},"cust\u006fm":{}}"#,
        r#"{"sumeragi":{"due_work_max_lag_ms":1,"unexpected":0}}"#,
        r#"{"smart_contract":{"unexpected":0}}"#,
        r#"{"unexpected":0}"#,
        r#"{"custom":{"a":{"id":"b","payload":null}}}"#,
        "{} false",
        r#"{"executor":{"execution_depth":00}}"#,
    ] {
        reject(source);
    }
    // Preserve the existing Value-based unsigned scalar domain without a Value tree.
    let zero = r#"{"sumeragi":{"due_work_max_lag_ms":1,"max_clock_drift_ms":-0},"executor":{"execution_depth":-0}}"#;
    let pool = AllocationBudget::new(1 << 20);
    let owner = decode(zero, &pool).unwrap();
    assert_eq!(owner.get().sumeragi.max_clock_drift_ms, 0);
    assert_eq!(owner.get().executor.execution_depth, 0);
    assert_eq!(owner.get(), &json::from_str::<Parameters>(zero).unwrap());
}

#[test]
fn every_required_capacity_field_and_nested_record_retains_its_contract() {
    // Mutating a test Value is only fixture authoring; production decode never uses it.
    let original = json::to_value(&Parameters::default()).unwrap();
    let paths: &[&[&str]] = &[
        &["block", "max_time_trigger_invocations"],
        &["block", "execution_output"],
        &["block", "fastpq_source"],
        &["block", "execution_output", "max_outputs"],
        &["block", "execution_output", "max_output_bytes"],
        &["block", "execution_output", "max_total_output_bytes"],
        &["block", "execution_output", "max_executed_wire_bytes"],
        &["block", "execution_output", "max_pipeline_triggers"],
        &["block", "execution_output", "max_time_triggers"],
        &["block", "execution_output", "max_time_invocations"],
        &["block", "fastpq_source", "intrinsic"],
        &["block", "fastpq_source", "block"],
        &[
            "block",
            "fastpq_source",
            "max_native_maintenance_invocations",
        ],
        &["block", "fastpq_source", "mandatory"],
        &[
            "block",
            "fastpq_source",
            "mandatory",
            "max_retained_obligations",
        ],
        &["block", "fastpq_source", "mandatory", "per_obligation"],
    ];
    fn remove(value: &mut json::Value, path: &[&str]) {
        let json::Value::Object(map) = value else {
            panic!("test object")
        };
        if path.len() == 1 {
            assert!(map.remove(path[0]).is_some());
        } else {
            remove(map.get_mut(path[0]).unwrap(), &path[1..]);
        }
    }
    for path in paths {
        let mut altered = original.clone();
        remove(&mut altered, path);
        reject(&json::to_json(&altered).unwrap());
    }
    for parent in [
        vec!["block", "fastpq_source", "intrinsic"],
        vec!["block", "fastpq_source", "block"],
        vec!["block", "fastpq_source", "mandatory", "per_obligation"],
    ] {
        for field in [
            "max_executed_entries",
            "max_transcripts",
            "max_deltas",
            "max_input_transcript_bytes",
            "max_statement_bytes",
            "max_total_statement_bytes",
        ] {
            let mut path = parent.clone();
            path.push(field);
            let mut altered = original.clone();
            remove(&mut altered, &path);
            reject(&json::to_json(&altered).unwrap());
        }
    }
}

#[test]
fn nested_capacity_unknown_duplicate_and_unsigned_constraints_are_not_defaulted() {
    let source = json::to_json(&Parameters::default()).unwrap();
    for name in [
        "max_outputs",
        "max_executed_entries",
        "max_retained_obligations",
        "max_native_maintenance_invocations",
    ] {
        let needle = format!("\"{name}\":");
        let duplicate = source.replacen(&needle, &format!("\"{name}\":1,{needle}"), 1);
        reject(&duplicate);
        let unknown = source.replacen(&needle, &format!("\"unexpected_{name}\":"), 1);
        reject(&unknown);
        let start = source.find(&needle).unwrap() + needle.len();
        let len = source[start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        for bad in ["-0", "-1", "4294967296", "1.0"] {
            let mut altered = source.clone();
            altered.replace_range(start..start + len, bad);
            reject(&altered);
        }
    }
}

#[test]
fn custom_escaping_json_clone_keeps_its_original_charge_after_parameter_drop() {
    let pool = AllocationBudget::new(1 << 20);
    let owner = decode(CUSTOM, &pool).unwrap();
    assert!(owner.belongs_to(&pool));
    assert_eq!(owner.get(), &json::from_str::<Parameters>(CUSTOM).unwrap());
    let raw = owner
        .get()
        .custom
        .values()
        .next()
        .unwrap()
        .payload()
        .clone();
    assert!(raw.belongs_to(&pool));
    drop(owner);
    assert!(pool.reserved_bytes() > 0);
    assert_eq!(raw.get(), r#"{"a":[1,true],"b":"text"}"#);
    drop(raw);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn partial_budget_failures_refund_and_retry_preserves_source_and_sibling() {
    let pool = AllocationBudget::new(1 << 20);
    let sibling = decode("{}", &pool).unwrap();
    let held = pool.reserved_bytes();
    let source = CUSTOM.to_owned();
    let original = source.clone();
    let mut refusals = 0;
    let mut success = false;
    for capacity in (held..8192).step_by(23) {
        pool.set_limit_bytes(capacity);
        match decode(&source, &pool) {
            Err(_) => refusals += 1,
            Ok(owner) => {
                assert_eq!(owner.get(), &json::from_str::<Parameters>(&source).unwrap());
                drop(owner);
                success = true;
                break;
            }
        }
        assert_eq!(pool.reserved_bytes(), held);
        assert!(sibling.belongs_to(&pool));
        assert_eq!(source, original);
    }
    assert!(refusals > 2 && success);
    assert_eq!(pool.reserved_bytes(), held);
    drop(sibling);
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(1 << 20);
    drop(decode(&source, &pool).unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn actual_array_and_algorithm_scratch_allocations_refuse_fallibly() {
    let source =
        r#"{"sumeragi":{"due_work_max_lag_ms":60000,"key_allowed_algorithms":["ed25519"]}}"#;
    let pool = AllocationBudget::new(1 << 20);
    let (owner, requests) = measured(|| decode(source, &pool));
    assert_eq!(requests, [2, 0, 0]);
    drop(owner.unwrap());
    assert_eq!(pool.reserved_bytes(), 0);
    for layout in [
        Layout::array::<Algorithm>(1).unwrap(),
        Layout::array::<u8>(7).unwrap(),
    ] {
        let (result, denied) =
            with_nth_exact_allocation_denial(layout, 0, || decode(source, &pool));
        assert!(denied);
        assert!(
            matches!(result,Err(ParametersJsonAdmissionError::Allocation(ChargedBufferError::Allocator{requested_bytes}))if requested_bytes==layout.size())
        );
        assert_eq!(pool.reserved_bytes(), 0);
        drop(decode(source, &pool).unwrap());
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
#[allow(unsafe_code)]
fn transferred_custody_follows_actual_array_retirement_and_unwind() {
    struct Enclosing {
        value: Parameters,
        _custody: ParametersCustody,
    }
    let pool = AllocationBudget::new(1 << 20);
    let observation = PhysicalObservation::start();
    let owner = decode("{}", &pool).unwrap();
    let pointer = owner.get().sumeragi.key_allowed_algorithms.as_ptr() as usize;
    let expected = owner.custody.bytes();
    // SAFETY: Enclosing exposes no mutation and destroys the value before custody.
    let (value, custody) = unsafe { owner.into_allocation_parts() };
    let enclosing = Enclosing {
        value,
        _custody: custody,
    };
    assert_eq!(
        enclosing.value.sumeragi.key_allowed_algorithms,
        defaults::sumeragi::KEY_ALLOWED_ALGORITHMS
    );
    assert_eq!(pool.reserved_bytes(), expected);
    assert_eq!(observation.snapshot().retirements(pointer), 0);
    drop(enclosing);
    assert_eq!(observation.snapshot().retirements(pointer), 1);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(observation);
    let owner = decode(CUSTOM, &pool).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _owner = owner;
        panic!("abandon full parameter destination");
    }));
    assert!(result.is_err());
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn original_observer_is_preserved_saved_replay_invalid_and_work_cumulative() {
    let pool = AllocationBudget::new(1 << 20);
    let (result, usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || decode(CUSTOM, &pool));
    drop(result.unwrap());
    let demand = usage.total_allocated_bytes();
    assert!(demand > 0);
    let context = DecodeBudgetContext::new(limits(usize::MAX));
    let mut seen = None;
    let attempt = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let error = failure(decode(CUSTOM, &pool));
                    let ParametersJsonAdmissionError::Json(json::Error::ScopedDecodeResource(
                        origin,
                    )) = error
                    else {
                        panic!("original observer lost: {error:?}")
                    };
                    seen = Some(origin.clone());
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original identity lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = context
        .with(|| {
            norito::with_decode_limits_scope(limits(demand - 1), || {
                classify_decode_attempt(|| {
                    let _ = failure(decode(CUSTOM, &pool));
                    Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
                })
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    let before = context.consumed_allocated_bytes();
    drop(context.with(|| decode(CUSTOM, &pool)).unwrap());
    assert_eq!(
        context.consumed_allocated_bytes() - before,
        u64::try_from(demand).unwrap()
    );
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn admitted_update_and_removal_preserve_source_and_own_exact_custom_successor() {
    use crate::parameter::{CustomParameter, Parameter};
    let source_pool = AllocationBudget::new(1 << 20);
    let source = decode(CUSTOM, &source_pool).unwrap();
    let source_bytes = json::to_json(source.get()).unwrap();
    let id = source.get().custom.keys().next().unwrap();
    let replacement = Parameter::Custom(CustomParameter::new(
        id.clone(),
        iroha_primitives::json::Json::new(42_u64),
    ));
    let pool = AllocationBudget::new(1 << 20);
    let next = AdmittedParameters::try_with_parameter(source.get(), &replacement, &pool).unwrap();
    let mut expected = source.get().clone();
    expected.set_parameter(replacement.clone());
    assert_eq!(next.get(), &expected);
    assert!(next.belongs_to(&pool));
    assert_ne!(
        next.get().sumeragi.key_allowed_algorithms.as_ptr(),
        source.get().sumeragi.key_allowed_algorithms.as_ptr()
    );
    assert_eq!(json::to_json(source.get()).unwrap(), source_bytes);
    let removed = AdmittedParameters::try_without_custom(next.get(), id, &pool).unwrap();
    assert!(removed.get().custom.is_empty());
    assert_eq!(next.get().custom.len(), 1);
    assert!(removed.belongs_to(&pool));
    drop(removed);
    drop(next);
    assert_eq!(pool.reserved_bytes(), 0);
    drop(source);
    assert_eq!(source_pool.reserved_bytes(), 0);
}

#[test]
fn every_scalar_family_uses_same_setter_without_mutating_retained_custom() {
    use crate::parameter::{
        BlockParameter, Parameter, SmartContractParameter, SumeragiParameter, TransactionParameter,
    };
    let source_pool = AllocationBudget::new(1 << 20);
    let source = decode(CUSTOM, &source_pool).unwrap();
    let updates = [
        Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(17)),
        Parameter::Block(BlockParameter::MaxTransactions(
            NonZeroU64::new(31).unwrap(),
        )),
        Parameter::Transaction(TransactionParameter::RequireSequence(true)),
        Parameter::SmartContract(SmartContractParameter::Fuel(NonZeroU64::new(53).unwrap())),
        Parameter::Executor(SmartContractParameter::Memory(NonZeroU64::new(67).unwrap())),
    ];
    for update in updates {
        let pool = AllocationBudget::new(1 << 20);
        let next = AdmittedParameters::try_with_parameter(source.get(), &update, &pool).unwrap();
        let mut expected = source.get().clone();
        expected.set_parameter(update);
        assert_eq!(next.get(), &expected);
        assert!(next.belongs_to(&pool));
        assert!(source.get().custom.belongs_to(&source_pool));
        drop(next);
        assert_eq!(pool.reserved_bytes(), 0);
    }
    drop(source);
    assert_eq!(source_pool.reserved_bytes(), 0);
}

#[test]
fn complete_sumeragi_successor_funds_original_array_before_copy_and_refunds_late_refusal() {
    let source_pool = AllocationBudget::new(1 << 20);
    let source = decode(CUSTOM, &source_pool).unwrap();
    let mut family = source.get().sumeragi.clone();
    family.key_allowed_algorithms = vec![Algorithm::Ed25519];
    family.max_clock_drift_ms = 123;
    let measured = AllocationBudget::new(1 << 20);
    let next = AdmittedParameters::try_with_sumeragi(source.get(), &family, &measured).unwrap();
    assert_eq!(&next.get().sumeragi, &family);
    assert_eq!(next.get().custom, source.get().custom);
    assert_ne!(
        next.get().sumeragi.key_allowed_algorithms.as_ptr(),
        family.key_allowed_algorithms.as_ptr()
    );
    drop(next);
    let peak = measured.peak_reserved_bytes();
    assert_eq!(measured.reserved_bytes(), 0);
    let constrained = AllocationBudget::new(peak - 1);
    assert!(AdmittedParameters::try_with_sumeragi(source.get(), &family, &constrained).is_err());
    assert_eq!(constrained.reserved_bytes(), 0);
    constrained.set_limit_bytes(peak);
    drop(AdmittedParameters::try_with_sumeragi(source.get(), &family, &constrained).unwrap());
    assert_eq!(constrained.reserved_bytes(), 0);
    let layout = Layout::array::<Algorithm>(family.key_allowed_algorithms.len()).unwrap();
    let (result, refused) = with_nth_exact_allocation_denial(layout, 0, || {
        AdmittedParameters::try_with_sumeragi(source.get(), &family, &constrained)
    });
    assert!(refused);
    assert!(result.is_err());
    assert_eq!(constrained.reserved_bytes(), 0);
    assert_eq!(
        source.get().sumeragi.max_clock_drift_ms,
        json::from_str::<Parameters>(CUSTOM)
            .unwrap()
            .sumeragi
            .max_clock_drift_ms
    );
}

#[test]
fn borrowed_custom_update_funds_before_copy_and_matches_parameter_destination() {
    let pool = AllocationBudget::new(1 << 20);
    let source = AdmittedParameters::try_protocol_default(&pool).unwrap();
    let custom = crate::parameter::CustomParameter::new(
        "borrowed_custom".parse().unwrap(),
        iroha_primitives::json::Json::new(17_u32),
    );
    let zero = AllocationBudget::new(0);
    let (refused, allocations) =
        measured(|| AdmittedParameters::try_with_custom(source.get(), &custom, &zero));
    assert!(refused.is_err());
    assert_eq!(allocations, [0, 0, 0]);
    assert_eq!(zero.reserved_bytes(), 0);
    let borrowed = AdmittedParameters::try_with_custom(source.get(), &custom, &pool).unwrap();
    let wrapped = AdmittedParameters::try_with_parameter(
        source.get(),
        &crate::parameter::Parameter::Custom(custom.clone()),
        &pool,
    )
    .unwrap();
    assert_eq!(borrowed.get(), wrapped.get());
    assert_eq!(borrowed.get().custom.get(custom.id()), Some(&custom));
    assert!(borrowed.belongs_to(&pool));
    assert!(source.get().custom.is_empty());
}
