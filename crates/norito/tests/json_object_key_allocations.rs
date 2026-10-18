//! Allocation limits for JSON object-key text and complete owned-value cleanup.

use norito::json::{self, BoundedJsonError};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    collections::BTreeMap,
};

struct TrackingAllocator;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static DEALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(bytes: usize) {
    if TRACKING.with(Cell::get) {
        ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
        ALLOCATED_BYTES.with(|count| count.set(count.get().saturating_add(bytes)));
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: forward the allocation request unchanged to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        // SAFETY: forward the zeroed allocation request unchanged to System.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer and layout belong to the matching System allocation.
        unsafe { System.dealloc(pointer, layout) }
        if TRACKING.with(Cell::get) {
            DEALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
            DEALLOCATED_BYTES.with(|count| count.set(count.get().saturating_add(layout.size())));
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if TRACKING.with(Cell::get) {
            REALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
        }
        record_allocation(size);
        // SAFETY: forward the existing allocation and new size unchanged to System.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    struct StopTracking;
    impl Drop for StopTracking {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    ALLOCATED_BYTES.with(|count| count.set(0));
    DEALLOCATIONS.with(|count| count.set(0));
    DEALLOCATED_BYTES.with(|count| count.set(0));
    REALLOCATIONS.with(|count| count.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    let tracking = StopTracking;
    let result = operation();
    drop(tracking);
    (
        result,
        ALLOCATIONS.with(Cell::get),
        ALLOCATED_BYTES.with(Cell::get),
    )
}

#[test]
fn oversized_string_and_hex_keys_fail_before_allocating_output_or_scratch() {
    let text = "x".repeat(32 * 1024);
    let bytes = [0xab_u8; 32 * 1024];
    let text_map = BTreeMap::from([(text.as_str(), 1_u8)]);
    let byte_map = BTreeMap::from([(&bytes, 1_u8)]);
    // Warm the writer and thread-local state outside allocation accounting.
    assert_eq!(
        json::to_json_bounded(&text_map, 8),
        Err(BoundedJsonError::BodyTooLarge)
    );
    assert_eq!(
        json::to_json_bounded(&byte_map, 8),
        Err(BoundedJsonError::BodyTooLarge)
    );

    for (result, count, allocated) in [
        measured(|| json::to_json_bounded(&text_map, 8)),
        measured(|| json::to_json_bounded(&byte_map, 8)),
    ] {
        assert_eq!(result, Err(BoundedJsonError::BodyTooLarge));
        assert_eq!((count, allocated), (0, 0));
    }
}

#[test]
fn successful_hex_key_serialization_allocates_only_the_exact_output() {
    let bytes = [0xab_u8; 4096];
    let map = BTreeMap::from([(&bytes, 1_u8)]);
    let exact = bytes.len() * 2 + "{\"\":1}".len();
    let warm = json::to_json_bounded(&map, exact).unwrap();
    assert_eq!(warm.len(), exact);
    let (result, count, allocated) = measured(|| json::to_json_bounded(&map, exact));
    assert_eq!(result.unwrap(), warm);
    assert_eq!((count, allocated), (1, exact));
}

#[derive(Debug)]
struct OwnershipMeasurement {
    allocations: usize,
    allocated_bytes: usize,
    deallocations: usize,
    deallocated_bytes: usize,
    reallocations: usize,
}

fn measured_ownership<T>(operation: impl FnOnce() -> T) -> (T, OwnershipMeasurement) {
    let (value, allocations, allocated_bytes) = measured(operation);
    (
        value,
        OwnershipMeasurement {
            allocations,
            allocated_bytes,
            deallocations: DEALLOCATIONS.with(Cell::get),
            deallocated_bytes: DEALLOCATED_BYTES.with(Cell::get),
            reallocations: REALLOCATIONS.with(Cell::get),
        },
    )
}

fn assert_fully_released(built: &OwnershipMeasurement, dropped: &OwnershipMeasurement) {
    assert!(built.allocations > built.deallocations);
    assert!(built.allocated_bytes > built.deallocated_bytes);
    // These fixtures use exact-size vectors and BTreeMap insertions. Refuse an
    // unnoticed realloc rather than treating it as a measured free event.
    assert_eq!(built.reallocations, 0);
    assert_eq!(dropped.reallocations, 0);
    assert_eq!(dropped.allocations, 0);
    assert_eq!(dropped.allocated_bytes, 0);
    assert_eq!(
        dropped.deallocations,
        built.allocations.checked_sub(built.deallocations).unwrap()
    );
    assert_eq!(
        dropped.deallocated_bytes,
        built
            .allocated_bytes
            .checked_sub(built.deallocated_bytes)
            .unwrap()
    );
}

#[path = "support/json_cleanup_comb.rs"]
mod json_cleanup_comb;
use json_cleanup_comb::{CombContainer, deep_comb, pair};

#[test]
fn deep_array_comb_cleanup_uses_default_stack_and_releases_every_owner() {
    let (value, built) = measured_ownership(|| deep_comb(CombContainer::Array, 4_096));
    let ((), dropped) = measured_ownership(|| json::drop_json_value_iteratively(value));
    assert_fully_released(&built, &dropped);
}

#[test]
fn deep_object_comb_cleanup_uses_default_stack_and_releases_every_owner() {
    let (value, built) = measured_ownership(|| deep_comb(CombContainer::Object, 4_096));
    let ((), dropped) = measured_ownership(|| json::drop_json_value_iteratively(value));
    assert_fully_released(&built, &dropped);
}

fn mixed_value() -> json::Value {
    let mut value = json::Value::Array(vec![
        json::Value::Null,
        json::Value::Bool(true),
        json::Value::from(17_u64),
        json::Value::String(String::from("original string owner")),
        json::Value::Array(Vec::new()),
        json::Value::Object(BTreeMap::new()),
    ]);
    for _ in 0..128 {
        value = pair(CombContainer::Array, json::Value::Array(Vec::new()), value);
        value = pair(
            CombContainer::Object,
            value,
            json::Value::Object(BTreeMap::new()),
        );
    }
    value
}

#[test]
fn mixed_container_cleanup_releases_keys_strings_and_original_container_capacity() {
    let (value, built) = measured_ownership(mixed_value);
    let ((), dropped) = measured_ownership(|| json::drop_json_value_iteratively(value));
    assert_fully_released(&built, &dropped);
}

#[derive(Debug)]
struct IgnoreValue;

impl json::JsonDeserialize for IgnoreValue {
    fn json_deserialize(_parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        Ok(Self)
    }

    fn json_from_value(_value: &json::Value) -> Result<Self, json::Error> {
        Ok(Self)
    }
}

#[test]
fn refused_public_value_conversion_releases_the_original_deep_comb() {
    let (value, built) = measured_ownership(|| deep_comb(CombContainer::Array, 4_096));
    let (result, dropped) = measured_ownership(|| json::from_value::<IgnoreValue>(value));
    assert!(matches!(
        result,
        Err(json::Error::NestingDepthExceeded {
            depth,
            limit: json::MAX_JSON_VALUE_NESTING_DEPTH,
            context: "JSON value",
        }) if depth == json::MAX_JSON_VALUE_NESTING_DEPTH + 1
    ));
    assert_fully_released(&built, &dropped);
}

#[derive(Debug, PartialEq, Eq, norito_derive::FastJson, norito_derive::JsonDeserialize)]
#[norito(no_fast_from_json)]
struct FastDepthLeaf {
    value: u64,
}

#[derive(Debug, PartialEq, Eq, norito_derive::FastJson, norito_derive::JsonDeserialize)]
#[norito(no_fast_from_json)]
struct FastDepthProbe {
    nested: Vec<FastDepthLeaf>,
}

fn decode_fast_depth(input: &str) -> Result<FastDepthProbe, json::Error> {
    json::from_json_fast(input)
}

fn decode_smart_depth(input: &str) -> Result<FastDepthProbe, json::Error> {
    json::from_json_fast_smart(input)
}

fn decode_auto_depth(input: &str) -> Result<FastDepthProbe, json::Error> {
    json::from_json_auto(input)
}

fn fast_depth_limits(depth: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth)
}

fn pad_document(document: &str, length: usize) -> String {
    assert!(document.len() <= length);
    let mut padded = String::with_capacity(length);
    padded.push_str(document);
    for _ in document.len()..length {
        padded.push(' ');
    }
    padded
}

#[test]
fn fast_entry_active_depth_refuses_before_any_tape_allocation() {
    for length in [256, 257] {
        let input = pad_document(r#"{"nested":[{"value":7}]}"#, length);
        for decode in [decode_fast_depth, decode_smart_depth, decode_auto_depth] {
            // Warm unrelated one-time state and validate the same successful input
            // outside measurement. The inherited scope is also established first.
            let expected = FastDepthProbe {
                nested: vec![FastDepthLeaf { value: 7 }],
            };
            assert_eq!(
                norito::with_decode_limits_scope(fast_depth_limits(3), || decode(&input)).unwrap(),
                expected
            );
            let (result, count, bytes) =
                norito::with_decode_limits_scope(fast_depth_limits(2), || {
                    measured(|| decode(&input))
                });
            let error = result.expect_err("active depth must refuse before tape allocation");
            assert_eq!(
                error.into_core_error().decode_resource_error(),
                Some(norito::core::DecodeResourceError::NestingDepthExceeded {
                    depth: 3,
                    limit: 2,
                    context: "decode budget",
                })
            );
            assert_eq!((count, bytes), (0, 0));
        }
    }
}

#[test]
fn fast_entry_fixed_depth_precedes_active_depth_without_tape_allocation() {
    let document = format!(
        "{}0{}",
        "[".repeat(json::MAX_JSON_VALUE_NESTING_DEPTH),
        "]".repeat(json::MAX_JSON_VALUE_NESTING_DEPTH)
    );
    for length in [256, 257] {
        let input = pad_document(&document, length);
        for decode in [decode_fast_depth, decode_smart_depth, decode_auto_depth] {
            let (result, count, bytes) =
                norito::with_decode_limits_scope(fast_depth_limits(0), || {
                    measured(|| decode(&input))
                });
            assert!(matches!(
                result,
                Err(json::Error::NestingDepthExceeded {
                    depth,
                    limit: json::MAX_JSON_VALUE_NESTING_DEPTH,
                    context: "JSON value",
                }) if depth == json::MAX_JSON_VALUE_NESTING_DEPTH + 1
            ));
            assert_eq!((count, bytes), (0, 0));
        }
    }
}

#[test]
fn fast_dispatch_exact_depth_and_trailing_refusal_preserve_both_threshold_sides() {
    let expected = FastDepthProbe {
        nested: vec![FastDepthLeaf { value: 7 }],
    };
    for length in [256, 257] {
        let input = pad_document(r#"{"nested":[{"value":7}]}"#, length);
        let mut trailing = pad_document(r#"{"nested":[{"value":7}]}"#, length - 1);
        trailing.push('0');
        for decode in [decode_fast_depth, decode_smart_depth, decode_auto_depth] {
            assert_eq!(
                norito::with_decode_limits_scope(fast_depth_limits(3), || decode(&input)).unwrap(),
                expected
            );
            let error =
                norito::with_decode_limits_scope(fast_depth_limits(3), || decode(&trailing))
                    .expect_err("the original trailing byte must remain rejected");
            assert!(matches!(
                error,
                json::Error::TrailingCharacters { byte, line: 1, col }
                    if byte == length - 1 && col == length
            ));
        }
    }
}
