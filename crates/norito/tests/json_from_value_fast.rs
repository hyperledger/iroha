use norito::json::{self, Error, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[test]
fn from_value_vec_avoids_string_roundtrip() {
    let input = Value::Array(vec![
        Value::from(1u64),
        Value::from(2u64),
        Value::from(3u64),
    ]);
    let output: Vec<u64> = json::from_value(input).expect("vec from value");
    assert_eq!(output, vec![1, 2, 3]);
}
#[test]
fn from_value_option_handles_null() {
    let none: Option<String> = json::from_value(Value::Null).expect("option none");
    assert!(none.is_none());
    let some: Option<String> =
        json::from_value(Value::String("hello".to_owned())).expect("option some");
    assert_eq!(some.as_deref(), Some("hello"));
}
#[test]
fn from_value_hashset_reports_duplicates() {
    let dup = Value::Array(vec![Value::from(1u64), Value::from(1u64)]);
    let err = json::from_value::<HashSet<u64>>(dup).expect_err("duplicate should fail");
    match err {
        Error::Message(msg) => assert_eq!(msg, "duplicate element in set"),
        other => panic!("expected duplicate error, got {other:?}"),
    }
}
#[test]
fn from_value_hashmap_object() {
    let mut obj = Value::Object(BTreeMap::new());
    if let Value::Object(map) = &mut obj {
        map.insert("a".into(), Value::from(1u64));
        map.insert("b".into(), Value::from(2u64));
    }
    let out: HashMap<String, u64> = json::from_value(obj).expect("hashmap");
    assert_eq!(out.get("a"), Some(&1));
    assert_eq!(out.get("b"), Some(&2));
}
#[test]
fn from_value_btreemap_object() {
    let mut map = Value::Object(BTreeMap::new());
    if let Value::Object(obj) = &mut map {
        obj.insert("foo".into(), Value::from(5u64));
        obj.insert("bar".into(), Value::from(6u64));
    }
    let out: BTreeMap<String, u64> = json::from_value(map).expect("btreemap");
    assert_eq!(out.get("bar"), Some(&6));
    assert_eq!(out.get("foo"), Some(&5));
}
#[test]
fn from_value_hashmap_numeric_keys() {
    let mut obj = Value::Object(BTreeMap::new());
    if let Value::Object(map) = &mut obj {
        map.insert("1".into(), Value::from("one"));
        map.insert("2".into(), Value::from("two"));
    }
    let out: HashMap<u32, String> = json::from_value(obj).expect("numeric keys");
    assert_eq!(out.get(&1), Some(&"one".to_string()));
    assert_eq!(out.get(&2), Some(&"two".to_string()));
}
#[test]
fn from_value_hashmap_bool_keys() {
    let mut obj = Value::Object(BTreeMap::new());
    if let Value::Object(map) = &mut obj {
        map.insert("true".into(), Value::from(1u64));
        map.insert("false".into(), Value::from(0u64));
    }
    let out: HashMap<bool, u64> = json::from_value(obj).expect("bool keys");
    assert_eq!(out.get(&true), Some(&1));
    assert_eq!(out.get(&false), Some(&0));
}
#[test]
fn from_value_hex_array() {
    let raw = Value::String("0a0b0c0d".to_owned());
    let bytes: [u8; 4] = json::from_value(raw).expect("decode hex");
    assert_eq!(bytes, [0x0A, 0x0B, 0x0C, 0x0D]);
}
#[test]
fn from_value_value_clones() {
    let original = Value::Bool(true);
    let cloned: Value = json::from_value(original.clone()).expect("clone value");
    assert_eq!(cloned, original);
}
#[test]
fn from_value_btreeset_roundtrip() {
    let input = Value::Array(vec![
        Value::from(3u64),
        Value::from(1u64),
        Value::from(2u64),
    ]);
    let out: BTreeSet<u64> = json::from_value(input).expect("btreeset");
    let expected: BTreeSet<u64> = [1u64, 2u64, 3u64].into_iter().collect();
    assert_eq!(out, expected);
}

mod resource_budget {
    //! Native Value conversion retains each active element and allocation owner.

    use norito::{
        core::{
            DecodeAllocationUsage, DecodeAttemptErrorKind, DecodeLimits, DecodeResourceError,
            classify_decode_attempt, owned_btree_allocation_bytes,
            owned_hash_table_allocation_bytes, with_decode_limits_measured,
            with_decode_limits_scope,
        },
        json::{self, Error, JsonDeserialize, Value},
    };
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        fmt::Debug,
        mem::size_of,
    };

    fn limits(sequence: usize, elements: usize, bytes: usize) -> DecodeLimits {
        DecodeLimits::new(sequence, usize::MAX, elements, bytes, 32)
    }

    fn convert<T: JsonDeserialize>(
        input: &Value,
        budget: DecodeLimits,
        consuming: bool,
    ) -> (Result<T, Error>, DecodeAllocationUsage) {
        if consuming {
            let owned = input.clone();
            with_decode_limits_measured(budget, || json::from_value(owned))
        } else {
            with_decode_limits_measured(budget, || T::json_from_value(input))
        }
    }

    fn assert_resource<T: Debug>(result: Result<T, Error>, expected: DecodeResourceError) {
        let error = result.expect_err("native conversion must enforce its original budget");
        assert_eq!(
            error.into_core_error().decode_resource_error(),
            Some(expected)
        );
    }

    fn assert_exact<T: JsonDeserialize + Debug + PartialEq>(
        input: &Value,
        expected: &T,
        elements: usize,
        bytes: usize,
    ) {
        for consuming in [false, true] {
            let (result, usage) = convert::<T>(input, limits(elements, elements, bytes), consuming);
            assert_eq!(&result.expect("exact native budget"), expected);
            assert_eq!(usage.total_elements(), elements);
            assert_eq!(usage.total_allocated_bytes(), bytes);
        }
    }

    fn assert_collection<T: JsonDeserialize + Debug + PartialEq>(
        input: &Value,
        expected: &T,
        storage: usize,
    ) {
        // All five callers independently supply exactly two source entries.
        let bytes = 2 + storage;
        for consuming in [false, true] {
            let (result, usage) = convert::<T>(input, limits(1, 2, bytes), consuming);
            assert_resource(
                result,
                DecodeResourceError::SequenceLengthExceeded {
                    length: 2,
                    limit: 1,
                },
            );
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            let (result, usage) = convert::<T>(input, limits(2, 1, bytes), consuming);
            assert_resource(
                result,
                DecodeResourceError::TotalElementsExceeded {
                    attempted: 2,
                    limit: 1,
                },
            );
            assert_eq!(usage.total_elements(), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
            let (result, _) = convert::<T>(input, limits(2, 2, bytes - 1), consuming);
            assert_resource(
                result,
                DecodeResourceError::TotalAllocationExceeded {
                    attempted: u64::try_from(bytes).expect("small fixture charge"),
                    limit: u64::try_from(bytes - 1).expect("small fixture charge"),
                },
            );
        }
        assert_exact(input, expected, 2, bytes);
    }

    fn two_values() -> Value {
        Value::Array(vec![Value::from(1_u64), Value::from(2_u64)])
    }

    fn two_entries() -> Value {
        Value::Object(BTreeMap::from([
            (String::from("1"), Value::from(2_u64)),
            (String::from("3"), Value::from(4_u64)),
        ]))
    }

    #[test]
    fn vec_conversion_enforces_sequence_total_and_storage_budgets() {
        assert_collection(&two_values(), &vec![1_u64, 2], 2 * size_of::<u64>());
    }

    #[test]
    fn btree_set_conversion_enforces_sequence_total_and_storage_budgets() {
        assert_collection(
            &two_values(),
            &BTreeSet::from([1_u64, 2]),
            owned_btree_allocation_bytes::<u64, ()>(2).expect("two-entry tree"),
        );
    }

    #[test]
    fn hash_set_conversion_enforces_sequence_total_and_storage_budgets() {
        assert_collection(
            &two_values(),
            &HashSet::from([1_u64, 2]),
            owned_hash_table_allocation_bytes::<u64>(2).expect("two-entry table"),
        );
    }

    #[test]
    fn btree_map_conversion_enforces_sequence_total_and_storage_budgets() {
        assert_collection(
            &two_entries(),
            &BTreeMap::from([(1_u64, 2_u64), (3, 4)]),
            owned_btree_allocation_bytes::<u64, u64>(2).expect("two-entry tree"),
        );
    }

    #[test]
    fn hash_map_conversion_enforces_sequence_total_and_storage_budgets() {
        assert_collection(
            &two_entries(),
            &HashMap::from([(1_u64, 2_u64), (3, 4)]),
            owned_hash_table_allocation_bytes::<(u64, u64)>(2).expect("two-entry table"),
        );
    }

    #[test]
    fn native_value_clone_charges_strings_arrays_and_object_owners() {
        let cases = [
            (Value::String(String::from("leaf")), 0, 4),
            (two_values(), 2, 2 + 2 * size_of::<Value>()),
            (
                Value::Object(BTreeMap::from([(
                    String::from("key"),
                    Value::String(String::from("value")),
                )])),
                1,
                1 + owned_btree_allocation_bytes::<String, Value>(1).expect("one-entry tree")
                    + 3
                    + 5,
            ),
        ];
        for (input, elements, bytes) in cases {
            for consuming in [false, true] {
                let (result, _) =
                    convert::<Value>(&input, limits(elements, elements, 0), consuming);
                let first_charge = if elements == 0 { bytes } else { elements };
                assert_resource(
                    result,
                    DecodeResourceError::TotalAllocationExceeded {
                        attempted: u64::try_from(first_charge).expect("small first charge"),
                        limit: 0,
                    },
                );
                let (result, _) =
                    convert::<Value>(&input, limits(elements, elements, bytes - 1), consuming);
                assert_resource(
                    result,
                    DecodeResourceError::TotalAllocationExceeded {
                        attempted: u64::try_from(bytes).expect("small fixture charge"),
                        limit: u64::try_from(bytes - 1).expect("small fixture charge"),
                    },
                );
            }
            assert_exact(&input, &input, elements, bytes);
        }
        let input = Value::Object(BTreeMap::from([(
            String::from("key"),
            Value::String(String::from("value")),
        )]));
        let (clone, _) = convert::<Value>(&input, limits(1, 1, usize::MAX), false);
        let Value::Object(mut clone) = clone.expect("charged independent clone") else {
            panic!("object fixture");
        };
        let Value::String(leaf) = clone.get_mut("key").expect("original key") else {
            panic!("string fixture");
        };
        leaf.push('!');
        assert_eq!(input["key"].as_str(), Some("value"));
        assert_eq!(clone["key"].as_str(), Some("value!"));
    }

    fn assert_nested<T: JsonDeserialize + Debug + PartialEq>(
        input: &Value,
        expected: &T,
        bytes: usize,
    ) {
        for consuming in [false, true] {
            let (result, usage) = convert::<T>(input, limits(2, 3, bytes), consuming);
            assert_resource(
                result,
                DecodeResourceError::TotalElementsExceeded {
                    attempted: 4,
                    limit: 3,
                },
            );
            assert_eq!(usage.total_elements(), 3);
        }
        assert_exact(input, expected, 4, bytes);
    }

    #[test]
    fn nested_native_conversions_charge_each_container_once() {
        let input = Value::Array(vec![
            Value::Array(vec![Value::from(1_u64)]),
            Value::Array(vec![Value::from(2_u64)]),
        ]);
        let expected = vec![vec![1_u64], vec![2_u64]];
        let storage = 4 + 2 * size_of::<Vec<u64>>() + 2 * size_of::<u64>();
        assert_nested(&input, &expected, storage);
        assert_nested(&input, &input, 4 + 4 * size_of::<Value>());
        assert_nested(
            &input,
            &Some(Box::new(expected)),
            storage + size_of::<Vec<Vec<u64>>>(),
        );
    }

    #[test]
    fn collection_refusals_keep_scope_provenance_and_shared_cumulative_counts() {
        let input = two_values();
        for (outer, protocol, expected) in [
            (1, 4, DecodeAttemptErrorKind::EnclosingLimit),
            (4, 1, DecodeAttemptErrorKind::Invalid),
            (1, 1, DecodeAttemptErrorKind::Invalid),
        ] {
            let error = with_decode_limits_scope(limits(outer, 4, 1024), || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(limits(protocol, 4, 1024), || {
                        Vec::<u64>::json_from_value(&input).map_err(Error::into_core_error)
                    })
                })
            })
            .expect_err("original refusing layer must survive native conversion");
            assert_eq!(error.kind(), expected);
            assert_eq!(
                error.into_error().decode_resource_error(),
                Some(DecodeResourceError::SequenceLengthExceeded {
                    length: 2,
                    limit: 1
                })
            );
        }
        let first = Value::Array(vec![Value::from(7_u64)]);
        let (result, usage) = with_decode_limits_measured(limits(2, 2, 1024), || {
            assert_eq!(Vec::<u64>::json_from_value(&first)?, vec![7_u64]);
            Vec::<u64>::json_from_value(&input)
        });
        assert_resource(
            result,
            DecodeResourceError::TotalElementsExceeded {
                attempted: 3,
                limit: 2,
            },
        );
        assert_eq!(usage.total_elements(), 1);
        assert_exact(&input, &vec![1_u64, 2], 2, 2 + 2 * size_of::<u64>());
    }

    #[derive(Debug)]
    struct ChildProbe;

    thread_local! { static CHILD_CALLS: Cell<usize> = const { Cell::new(0) }; }

    impl JsonDeserialize for ChildProbe {
        fn json_deserialize(_parser: &mut json::Parser<'_>) -> Result<Self, Error> {
            panic!("native collection must not serialize a child");
        }
        fn json_from_value(_value: &Value) -> Result<Self, Error> {
            CHILD_CALLS.with(|count| count.set(count.get() + 1));
            Ok(Self)
        }
    }

    #[test]
    fn collection_sequence_admission_precedes_child_work() {
        let input = two_values();
        for consuming in [false, true] {
            CHILD_CALLS.with(|count| count.set(0));
            let (result, usage) = convert::<Vec<ChildProbe>>(&input, limits(1, 2, 1024), consuming);
            assert_resource(
                result,
                DecodeResourceError::SequenceLengthExceeded {
                    length: 2,
                    limit: 1,
                },
            );
            assert_eq!(CHILD_CALLS.with(Cell::get), 0);
            assert_eq!(usage.total_allocated_bytes(), 0);
        }
    }

    #[test]
    fn admitted_duplicate_sets_and_parsed_map_keys_keep_original_errors() {
        let set = Value::Array(vec![Value::from(1_u64), Value::from(1_u64)]);
        let map = Value::Object(BTreeMap::from([
            (String::from("01"), Value::from(1_u64)),
            (String::from("1"), Value::from(2_u64)),
        ]));
        for consuming in [false, true] {
            for result in [
                convert::<BTreeSet<u64>>(&set, limits(2, 2, 4096), consuming)
                    .0
                    .map(|_| ()),
                convert::<HashSet<u64>>(&set, limits(2, 2, 4096), consuming)
                    .0
                    .map(|_| ()),
            ] {
                assert!(
                    matches!(result, Err(Error::Message(message)) if message == "duplicate element in set")
                );
            }
            for result in [
                convert::<BTreeMap<u64, u64>>(&map, limits(2, 2, 4096), consuming)
                    .0
                    .map(|_| ()),
                convert::<HashMap<u64, u64>>(&map, limits(2, 2, 4096), consuming)
                    .0
                    .map(|_| ()),
            ] {
                assert!(matches!(result, Err(Error::DuplicateField { field }) if field == "1"));
            }
        }
    }

    #[test]
    fn scalar_and_empty_native_values_need_no_elements_or_heap_charge() {
        for input in [
            Value::Null,
            Value::Bool(true),
            Value::from(7_u64),
            Value::String(String::new()),
            Value::Array(Vec::new()),
            Value::Object(BTreeMap::new()),
        ] {
            for consuming in [false, true] {
                let (result, usage) =
                    convert::<Value>(&input, DecodeLimits::new(0, usize::MAX, 0, 0, 0), consuming);
                assert_eq!(result.expect("empty or scalar root fits depth zero"), input);
                assert_eq!(usage.total_elements(), 0);
                assert_eq!(usage.total_allocated_bytes(), 0);
            }
        }
    }
}
