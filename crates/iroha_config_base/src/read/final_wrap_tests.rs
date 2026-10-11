//! Final wrapper layout, ownership and ordinary reader construction-order controls.

use super::*;
use std::{cell::Cell, mem::size_of};

std::thread_local! {
    static VALUE_DROPS: Cell<usize> = const { Cell::new(0) };
    static ROOT_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
    static NESTED_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

struct LargeValue {
    bytes: [u8; 64 * 1024],
}
impl LargeValue {
    fn new() -> Self {
        Self {
            bytes: [0x5a; 64 * 1024],
        }
    }
}
impl Drop for LargeValue {
    fn drop(&mut self) {
        VALUE_DROPS.with(|count| count.set(count.get() + 1));
    }
}
fn reset_counts() {
    VALUE_DROPS.with(|count| count.set(0));
    ROOT_CONSTRUCTIONS.with(|count| count.set(0));
    NESTED_CONSTRUCTIONS.with(|count| count.set(0));
}

#[test]
fn final_wrapper_layout_does_not_scale_with_value_and_immediate_move_drops_once() {
    reset_counts();
    assert!(size_of::<LargeValue>() >= 64 * 1024);
    assert!(size_of::<FinalWrap<LargeValue>>() <= 4 * size_of::<usize>());
    assert_eq!(
        size_of::<FinalWrap<LargeValue>>(),
        size_of::<FinalWrap<u8>>()
    );
    let wrapped = ReadingDoneValue::Fine(LargeValue::new()).into_final();
    assert_eq!(VALUE_DROPS.with(Cell::get), 0);
    let value = wrapped.unwrap();
    assert!(value.bytes.iter().all(|byte| *byte == 0x5a));
    assert_eq!(VALUE_DROPS.with(Cell::get), 0);
    drop(value);
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
    let wrapped = ReadingDoneValue::Fine(LargeValue::new()).into_final();
    drop(wrapped);
    assert_eq!(VALUE_DROPS.with(Cell::get), 2);
}

#[test]
fn deferred_wrapper_moves_or_drops_its_capture_once_without_early_execution() {
    reset_counts();
    let value = LargeValue::new();
    let pending = FinalWrap::value_fn(move || {
        ROOT_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        value
    });
    assert_eq!(ROOT_CONSTRUCTIONS.with(Cell::get), 0);
    drop(pending);
    assert_eq!(ROOT_CONSTRUCTIONS.with(Cell::get), 0);
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
    let value = LargeValue::new();
    let pending = FinalWrap::value_fn(move || {
        ROOT_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
        value
    });
    let value = pending.unwrap();
    assert_eq!(ROOT_CONSTRUCTIONS.with(Cell::get), 1);
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
    assert_eq!(value.bytes[0], 0x5a);
    drop(value);
    assert_eq!(VALUE_DROPS.with(Cell::get), 2);
}

struct Nested {
    flag: WithOrigin<bool>,
}
impl ReadConfig for Nested {
    fn read(reader: &mut ConfigReader) -> FinalWrap<Self> {
        let flag = reader
            .read_parameter::<bool>(["flag"])
            .value_required()
            .finish_with_origin();
        FinalWrap::value_fn(move || {
            NESTED_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
            Self {
                flag: flag.unwrap(),
            }
        })
    }
}
struct Root {
    number: WithOrigin<u64>,
    fallback: WithOrigin<u64>,
    nested: Nested,
    value: LargeValue,
}
impl ReadConfig for Root {
    fn read(reader: &mut ConfigReader) -> FinalWrap<Self> {
        let number = reader
            .read_parameter::<u64>(["number"])
            .value_required()
            .finish_with_origin();
        let fallback = reader
            .read_parameter::<u64>(["fallback"])
            .value_or_else(|| 42)
            .finish_with_origin();
        let nested = reader.read_nested::<Nested>("nested");
        // Exercise the same immediate-value finalizer held by the deferred root closure.
        let value = ReadingDoneValue::Fine(LargeValue::new()).into_final();
        FinalWrap::value_fn(move || {
            ROOT_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
            Self {
                number: number.unwrap(),
                fallback: fallback.unwrap(),
                nested: nested.unwrap(),
                value: value.unwrap(),
            }
        })
    }
}

#[test]
fn reader_completes_once_then_constructs_nested_values_with_original_origins() {
    reset_counts();
    let source = TomlSource::inline(::toml::toml! {
        number = 7
        [nested]
        flag = true
    });
    let original_path = source.path().clone();
    let root = ConfigReader::new()
        .without_env()
        .with_toml_source(source)
        .read_and_complete::<Root>()
        .expect("complete original configuration");
    assert_eq!(ROOT_CONSTRUCTIONS.with(Cell::get), 1);
    assert_eq!(NESTED_CONSTRUCTIONS.with(Cell::get), 1);
    assert_eq!(VALUE_DROPS.with(Cell::get), 0);
    assert_eq!(*root.number.value(), 7);
    assert_eq!(*root.fallback.value(), 42);
    assert!(*root.nested.flag.value());
    assert_eq!(root.value.bytes[65_535], 0x5a);
    assert!(
        matches!(root.number.origin(), ParameterOrigin::File { id, path } if id.to_string() == "number" && path == &original_path)
    );
    assert!(
        matches!(root.nested.flag.origin(), ParameterOrigin::File { id, path } if id.to_string() == "nested.flag" && path == &original_path)
    );
    assert!(
        matches!(root.fallback.origin(), ParameterOrigin::Default { id } if id.to_string() == "fallback")
    );
    drop(root);
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
}

#[test]
fn reader_aggregates_errors_before_construction_and_drops_retained_values_once() {
    reset_counts();
    let result = ConfigReader::new()
        .without_env()
        .with_toml_source(TomlSource::inline(::toml::toml! {
            number = "invalid integer"
            unknown = true
        }))
        .read_and_complete::<Root>();
    let Err(report) = result else {
        panic!("invalid configuration unexpectedly constructed")
    };
    let rendered = format!("{report:#?}");
    assert!(rendered.contains("number"));
    assert!(rendered.contains("nested.flag"));
    assert!(rendered.contains("unknown"));
    assert_eq!(ROOT_CONSTRUCTIONS.with(Cell::get), 0);
    assert_eq!(NESTED_CONSTRUCTIONS.with(Cell::get), 0);
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
    let mapper_called = Cell::new(false);
    let errored = ReadingDoneValue::<u8>::Errored.into_final_with(|_| {
        mapper_called.set(true);
        LargeValue::new()
    });
    drop(errored);
    assert!(!mapper_called.get());
    assert_eq!(VALUE_DROPS.with(Cell::get), 1);
}
