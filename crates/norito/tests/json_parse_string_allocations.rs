//! Allocation and escape-parity checks for owned JSON string parsing.
#![cfg(feature = "json")]
use norito::json::Parser;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
struct CountingAllocator;
thread_local! {
    static OBSERVED_ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}
fn record_allocation_request() {
    OBSERVED_ALLOCATIONS.with(|counter| {
        if let Some(count) = counter.get() {
            counter.set(Some(count.saturating_add(1)));
        }
    });
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation_request();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation_request();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation_request();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;
struct AllocationObservation {
    previous: Option<usize>,
}
impl Drop for AllocationObservation {
    fn drop(&mut self) {
        OBSERVED_ALLOCATIONS.with(|counter| counter.set(self.previous));
    }
}
fn measured_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let observation = AllocationObservation {
        previous: OBSERVED_ALLOCATIONS.with(|counter| counter.replace(Some(0))),
    };
    let result = operation();
    let count = OBSERVED_ALLOCATIONS.with(|counter| counter.get().unwrap());
    drop(observation);
    (result, count)
}
#[test]
fn escaped_string_reuses_its_unescape_buffer() {
    const SOURCE: &str = r#""a\nb\tc\"d""#;
    let (parsed, allocations) = measured_allocations(|| {
        Parser::new(SOURCE)
            .parse_string()
            .expect("parse escaped string")
    });
    assert_eq!(parsed, "a\nb\tc\"d");
    assert_eq!(
        allocations, 1,
        "the returned String must take ownership of the single unescape buffer"
    );
}
#[test]
fn escaped_string_conversion_preserves_all_escape_forms() {
    let cases = [
        (r#""quote: \"""#, "quote: \""),
        (r#""slash: \\""#, "slash: \\"),
        (r#""solidus: \/""#, "solidus: /"),
        (r#""controls: \b\f\n\r\t""#, "controls: \u{8}\u{c}\n\r\t"),
        (r#""bmp: \u263a""#, "bmp: ☺"),
        (r#""pair: \ud83d\ude00""#, "pair: 😀"),
    ];
    for (source, expected) in cases {
        let actual = Parser::new(source)
            .parse_string()
            .expect("parse JSON escape form");
        assert_eq!(actual, expected, "escape mismatch for {source:?}");
    }
}

mod field_budget {
    //! Decoded UTF-8 fields keep their original scoped limits and parser ownership.

    use super::measured_allocations;
    use norito::{
        core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, DecodeResourceError,
            classify_decode_attempt, with_decode_limits_scope,
        },
        json::{self, Arena, Error, JsonDeserialize, KeyRef, Parser, StrRef, TapeWalker, Value},
    };
    use std::{
        cell::Cell,
        collections::{BTreeMap, HashMap},
    };

    fn limits(field: usize, allocation: usize) -> DecodeLimits {
        DecodeLimits::new(16, field, 64, allocation, 32)
    }

    fn assert_field<T>(result: Result<T, Error>, length: u64, limit: u64) {
        let error = result.err().expect("decoded UTF-8 field must refuse");
        assert_eq!(
            error.into_core_error().decode_resource_error(),
            Some(DecodeResourceError::FieldLengthExceeded { length, limit })
        );
    }

    const STRINGS: [(&str, &str); 4] = [
        (r#""abc""#, "abc"),
        (r#""é""#, "é"),
        (r#""\u00e9""#, "é"),
        (r#""\ud83d\ude00""#, "😀"),
    ];

    #[test]
    fn owned_strings_check_decoded_field_before_allocation() {
        for (source, expected) in STRINGS {
            let exact = DecodeBudgetContext::new(limits(expected.len(), expected.len()));
            let mut parser = Parser::new(source);
            let (result, allocations) =
                exact.with(|| measured_allocations(|| parser.parse_string()));
            assert_eq!(result.expect("exact decoded field"), expected);
            assert_eq!(allocations, 1);
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(expected.len()).unwrap()
            );
            assert_eq!(parser.position(), source.len());

            let short = DecodeBudgetContext::new(limits(expected.len() - 1, 0));
            let mut parser = Parser::new(source);
            let (result, allocations) =
                short.with(|| measured_allocations(|| parser.parse_string()));
            assert_field(
                result,
                u64::try_from(expected.len()).unwrap(),
                u64::try_from(expected.len() - 1).unwrap(),
            );
            assert_eq!(allocations, 0, "field refusal precedes owned allocation");
            assert_eq!(short.consumed_allocated_bytes(), 0);
            assert_eq!(
                parser.position(),
                if source.contains('\\') {
                    1
                } else {
                    source.len()
                }
            );
        }
    }

    #[test]
    fn caller_string_buffers_keep_field_priority_and_one_charge() {
        for (source, expected) in STRINGS {
            let calls = Cell::new(0);
            let short = DecodeBudgetContext::new(limits(expected.len() - 1, 0));
            let mut parser = Parser::new(source);
            let (result, allocations) = short.with(|| {
                measured_allocations(|| {
                    parser.parse_string_with_buffer::<Vec<u8>, Error>(|length| {
                        calls.set(calls.get() + 1);
                        Ok(vec![0; length])
                    })
                })
            });
            assert_field(
                result,
                u64::try_from(expected.len()).unwrap(),
                u64::try_from(expected.len() - 1).unwrap(),
            );
            assert_eq!(calls.get(), 0);
            assert_eq!(allocations, 0);
            assert_eq!(short.consumed_allocated_bytes(), 0);
            let exact = DecodeBudgetContext::new(limits(expected.len(), expected.len()));
            let result = exact.with(|| {
                Parser::new(source).parse_string_with_buffer::<Vec<u8>, Error>(|length| {
                    calls.set(calls.get() + 1);
                    Ok(vec![0; length])
                })
            });
            assert_eq!(result.unwrap(), expected.as_bytes());
            assert_eq!(calls.get(), 1);
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(expected.len()).unwrap()
            );
        }
    }

    #[derive(Clone, Copy)]
    enum Reader {
        Parser,
        Tape,
    }

    struct ReadResult {
        value: Result<String, Error>,
        cursor: usize,
        allocations: usize,
        tape_index: Option<usize>,
    }

    fn read_reference(source: &str, field: usize, reader: Reader) -> ReadResult {
        let context = DecodeBudgetContext::new(limits(field, usize::MAX));
        let mut arena = Arena::new();
        match reader {
            Reader::Parser => {
                let mut parser = Parser::new(source);
                let (value, allocations) =
                    context.with(|| measured_allocations(|| parser.parse_string_ref(&mut arena)));
                let value = value.map(|value| value.to_string());
                ReadResult {
                    value,
                    cursor: parser.position(),
                    allocations,
                    tape_index: None,
                }
            }
            Reader::Tape => {
                // Stage-1 construction is deliberately outside this string-owner observation.
                let mut walker = TapeWalker::new(source);
                let (value, allocations) = context
                    .with(|| measured_allocations(|| walker.parse_string_ref_inline(&mut arena)));
                let value = value.map(|value| value.to_string());
                ReadResult {
                    value,
                    cursor: walker.raw_pos(),
                    allocations,
                    tape_index: Some(walker.idx),
                }
            }
        }
    }

    fn assert_reference_fields(reader: Reader) {
        for (source, expected) in STRINGS {
            let exact = read_reference(source, expected.len(), reader);
            assert_eq!(exact.value.unwrap(), expected);
            assert_eq!(exact.cursor, source.len());
            if !source.contains('\\') {
                assert_eq!(exact.allocations, 0);
            }
            let short = read_reference(source, expected.len() - 1, reader);
            assert_field(
                short.value,
                u64::try_from(expected.len()).unwrap(),
                u64::try_from(expected.len() - 1).unwrap(),
            );
            assert_eq!(
                short.allocations, 0,
                "no escape scratch or arena growth before field admission"
            );
            let expected_cursor = if source.contains('\\') {
                match reader {
                    Reader::Parser => 1,
                    Reader::Tape => 0,
                }
            } else {
                source.len()
            };
            assert_eq!(short.cursor, expected_cursor);
            if let Some(index) = short.tape_index {
                assert_eq!(index, if source.contains('\\') { 0 } else { 2 });
            }
        }
    }

    #[test]
    fn parser_reference_fields_refuse_before_escape_scratch() {
        assert_reference_fields(Reader::Parser);
    }

    #[test]
    fn tape_reference_fields_refuse_before_escape_scratch() {
        assert_reference_fields(Reader::Tape);
    }

    #[test]
    fn reference_success_keeps_input_borrow_and_cursor_parity() {
        let source = "  \"é\"  :";
        let context = DecodeBudgetContext::new(limits(2, 0));
        let mut arena = Arena::new();
        let mut parser = Parser::new(source);
        let result = context
            .with(|| parser.parse_string_ref(&mut arena))
            .unwrap();
        match result {
            StrRef::Borrowed(text) => assert_eq!(text.as_ptr(), source[3..].as_ptr()),
            StrRef::Owned(_) => panic!("unescaped input must remain borrowed"),
        }
        assert_eq!(parser.position(), 6);
        let mut walker = TapeWalker::new(source);
        let result = context
            .with(|| walker.parse_string_ref_inline(&mut arena))
            .unwrap();
        match result {
            StrRef::Borrowed(text) => assert_eq!(text.as_ptr(), source[3..].as_ptr()),
            StrRef::Owned(_) => panic!("unescaped input must remain borrowed"),
        }
        assert_eq!(walker.raw_pos(), 8);
        assert_eq!(walker.idx, 2);
        assert_eq!(context.consumed_allocated_bytes(), 0);
    }

    #[test]
    fn malformed_reference_escapes_keep_original_errors_before_short_fields() {
        let cases = [
            (r#""\q""#, "bad escape", 2),
            (r#""\uDC00""#, "unexpected low surrogate", 6),
            (r#""\uD800\u0041""#, "invalid low surrogate", 12),
            (r#""\uD800""#, "expected low surrogate", 7),
        ];
        for reader in [Reader::Parser, Reader::Tape] {
            for (source, expected, offset) in cases {
                let observed = read_reference(source, 0, reader);
                match observed.value.unwrap_err() {
                    Error::WithPos {
                        msg,
                        byte,
                        line,
                        col,
                    } => {
                        assert_eq!((msg, byte, line, col), (expected, offset, 1, offset + 1));
                    }
                    error => panic!("original syntax diagnostic changed: {error:?}"),
                }
                assert_eq!(
                    observed.allocations, 0,
                    "malformed escape cannot allocate scratch"
                );
                assert_eq!(
                    observed.cursor,
                    match reader {
                        Reader::Parser => 1,
                        Reader::Tape => 0,
                    }
                );
            }
        }
        let parser = read_reference(r#""\u12""#, 0, Reader::Parser);
        assert!(matches!(
            parser.value,
            Err(Error::InvalidHex {
                byte: 5,
                line: 1,
                col: 6
            })
        ));
        let tape = read_reference(r#""\u12""#, 0, Reader::Tape);
        assert!(matches!(
            tape.value,
            Err(Error::EofHex {
                byte: 3,
                line: 1,
                col: 4
            })
        ));
        assert_eq!((parser.allocations, tape.allocations), (0, 0));
    }

    #[test]
    fn native_string_copies_and_hex_fields_use_decoded_utf8_length() {
        for text in ["abc", "é", "😀"] {
            let input = Value::String(text.to_owned());
            let short = DecodeBudgetContext::new(limits(text.len() - 1, 0));
            let (result, allocations) =
                short.with(|| measured_allocations(|| String::json_from_value(&input)));
            assert_field(
                result,
                u64::try_from(text.len()).unwrap(),
                u64::try_from(text.len() - 1).unwrap(),
            );
            assert_eq!(allocations, 0);
            let (result, allocations) =
                short.with(|| measured_allocations(|| Box::<str>::json_from_value(&input)));
            assert_field(
                result,
                u64::try_from(text.len()).unwrap(),
                u64::try_from(text.len() - 1).unwrap(),
            );
            assert_eq!(allocations, 0);
            let (result, allocations) =
                short.with(|| measured_allocations(|| Value::json_from_value(&input)));
            assert_field(
                result,
                u64::try_from(text.len()).unwrap(),
                u64::try_from(text.len() - 1).unwrap(),
            );
            assert_eq!(allocations, 0);
            let exact = DecodeBudgetContext::new(limits(text.len(), text.len()));
            assert_eq!(
                exact.with(|| String::json_from_value(&input)).unwrap(),
                text
            );
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(text.len()).unwrap()
            );
            let exact = DecodeBudgetContext::new(limits(text.len(), text.len()));
            assert_eq!(
                exact
                    .with(|| Box::<str>::json_from_value(&input))
                    .unwrap()
                    .as_ref(),
                text
            );
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(text.len()).unwrap()
            );
            let exact = DecodeBudgetContext::new(limits(text.len(), text.len()));
            assert_eq!(
                exact.with(|| Value::json_from_value(&input)).unwrap(),
                input
            );
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(text.len()).unwrap()
            );
        }
        let input = Value::String("00".to_owned());
        assert_field(
            with_decode_limits_scope(limits(1, 0), || <[u8; 1]>::json_from_value(&input)),
            2,
            1,
        );
        assert_eq!(
            with_decode_limits_scope(limits(2, 0), || <[u8; 1]>::json_from_value(&input)).unwrap(),
            [0]
        );
    }

    #[test]
    fn borrowed_and_buffered_keys_preserve_field_admission_and_colon_progress() {
        for (source, expected) in [("\"é\":7", "é"), (r#""\u00e9":7"#, "é")] {
            let calls = Cell::new(0);
            let context = DecodeBudgetContext::new(limits(1, 0));
            let mut parser = Parser::new(source);
            let (result, allocations) = context.with(|| {
                measured_allocations(|| {
                    parser.parse_key_with_buffer::<Vec<u8>, Error>(|length| {
                        calls.set(calls.get() + 1);
                        Ok(vec![0; length])
                    })
                })
            });
            assert_field(result, 2, 1);
            assert_eq!(calls.get(), 0);
            assert_eq!(allocations, 0);
            assert_eq!(
                parser.position(),
                if source.contains('\\') {
                    1
                } else {
                    source.len() - 1
                }
            );
            let context = DecodeBudgetContext::new(limits(2, 2));
            let mut parser = Parser::new(source);
            let key = context.with(|| parser.parse_key()).unwrap();
            match key {
                KeyRef::Borrowed(text) => {
                    assert_eq!(text, expected);
                    assert_eq!(text.as_ptr(), source[1..].as_ptr());
                }
                KeyRef::Owned(text) => assert_eq!(text, expected),
            }
            assert_eq!(parser.position(), source.len() - 1);
            assert_eq!(
                context.consumed_allocated_bytes(),
                if source.contains('\\') { 2 } else { 0 }
            );
        }
    }

    #[test]
    fn key_syntax_keeps_branch_specific_refusal_priority() {
        let mut parser = Parser::new("\"abc\"  !");
        let error = with_decode_limits_scope(limits(0, 0), || parser.parse_key())
            .err()
            .unwrap();
        assert!(matches!(
            error,
            Error::WithPos {
                msg: "expected :",
                byte: 8,
                line: 1,
                col: 9
            }
        ));
        assert_eq!(parser.position(), 8);
        let mut parser = Parser::new(r#""\u0061" !"#);
        assert_field(
            with_decode_limits_scope(limits(0, 0), || parser.parse_key()),
            1,
            0,
        );
        assert_eq!(parser.position(), 1);
        let mut walker = TapeWalker::new(r#""\u0061" !"#);
        let error = with_decode_limits_scope(limits(0, 0), || walker.read_key_hash()).unwrap_err();
        assert!(matches!(
            error,
            Error::ExpectedColon {
                byte: 7,
                line: 1,
                col: 8
            }
        ));
        assert_eq!(walker.raw_pos(), 8);
        assert_eq!(walker.idx, 2);
        assert_eq!(walker.last_key(), r#"\u0061"#);
    }

    #[test]
    fn key_hash_fields_preserve_hash_last_key_and_tape_cursor() {
        for (source, decoded) in [
            (r#""é":0"#, "é"),
            (r#""\u00e9":0"#, "é"),
            (r#""\ud83d\ude00":0"#, "😀"),
        ] {
            let close = source.rfind('"').unwrap();
            let mut parser = Parser::new(source);
            let context = DecodeBudgetContext::new(limits(decoded.len(), usize::MAX));
            let expected_hash = context.with(|| parser.read_key_hash()).unwrap();
            assert_eq!(expected_hash, json::key_hash_const(decoded));
            assert_eq!(parser.position(), close + 1);
            let mut walker = TapeWalker::new(source);
            let (hash, allocations) =
                context.with(|| measured_allocations(|| walker.read_key_hash()));
            assert_eq!(hash.unwrap(), expected_hash);
            assert_eq!(allocations, 0);
            assert_eq!(
                (walker.raw_pos(), walker.idx, walker.last_key()),
                (close + 1, 2, &source[1..close])
            );
            let short = DecodeBudgetContext::new(limits(decoded.len() - 1, 0));
            let mut walker = TapeWalker::new(source);
            let (result, allocations) =
                short.with(|| measured_allocations(|| walker.read_key_hash()));
            assert_field(
                result,
                u64::try_from(decoded.len()).unwrap(),
                u64::try_from(decoded.len() - 1).unwrap(),
            );
            assert_eq!(allocations, 0);
            assert_eq!(
                (walker.raw_pos(), walker.idx, walker.last_key()),
                (close + 1, 2, &source[1..close])
            );
            let mut parser = Parser::new(source);
            assert_field(
                short.with(|| parser.read_key_hash()),
                u64::try_from(decoded.len()).unwrap(),
                u64::try_from(decoded.len() - 1).unwrap(),
            );
        }
    }

    #[test]
    fn direct_numeric_map_keys_cannot_bypass_field_limit() {
        let input = Value::Object(BTreeMap::from([("123".to_owned(), Value::from(7_u64))]));
        assert_field(
            with_decode_limits_scope(limits(2, usize::MAX), || {
                BTreeMap::<u64, u64>::json_from_value(&input)
            }),
            3,
            2,
        );
        assert_field(
            with_decode_limits_scope(limits(2, usize::MAX), || {
                HashMap::<u64, u64>::json_from_value(&input)
            }),
            3,
            2,
        );
        assert_eq!(
            with_decode_limits_scope(limits(3, usize::MAX), || {
                BTreeMap::<u64, u64>::json_from_value(&input)
            })
            .unwrap(),
            BTreeMap::from([(123, 7)])
        );
        assert_eq!(
            with_decode_limits_scope(limits(3, usize::MAX), || {
                HashMap::<u64, u64>::json_from_value(&input)
            })
            .unwrap(),
            HashMap::from([(123, 7)])
        );
        let duplicate = Value::Object(BTreeMap::from([
            ("01".to_owned(), Value::from(1_u64)),
            ("1".to_owned(), Value::from(2_u64)),
        ]));
        for result in [
            with_decode_limits_scope(limits(2, usize::MAX), || {
                BTreeMap::<u64, u64>::json_from_value(&duplicate).map(|_| ())
            }),
            with_decode_limits_scope(limits(2, usize::MAX), || {
                HashMap::<u64, u64>::json_from_value(&duplicate).map(|_| ())
            }),
        ] {
            assert!(matches!(result, Err(Error::DuplicateField { field }) if field == "1"));
        }
    }

    #[test]
    fn field_refusal_preserves_scope_identity_retry_and_cumulative_charge() {
        let input = Value::String("abc".to_owned());
        for (outer, protocol, expected) in [
            (2, 3, DecodeAttemptErrorKind::EnclosingLimit),
            (3, 2, DecodeAttemptErrorKind::Invalid),
            (2, 2, DecodeAttemptErrorKind::Invalid),
        ] {
            let error = with_decode_limits_scope(limits(outer, 64), || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(limits(protocol, 64), || {
                        String::json_from_value(&input).map_err(Error::into_core_error)
                    })
                })
            })
            .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert_eq!(
                error.into_error().decode_resource_error(),
                Some(DecodeResourceError::FieldLengthExceeded {
                    length: 3,
                    limit: 2
                })
            );
        }
        let exact = DecodeBudgetContext::new(limits(3, 6));
        assert_eq!(
            exact.with(|| String::json_from_value(&input)).unwrap(),
            "abc"
        );
        assert_eq!(
            exact.with(|| String::json_from_value(&input)).unwrap(),
            "abc"
        );
        assert_eq!(exact.consumed_allocated_bytes(), 6);
        let error = exact.with(|| String::json_from_value(&input)).unwrap_err();
        assert_eq!(
            error.into_core_error().decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded {
                attempted: 9,
                limit: 6
            })
        );
        assert_eq!(exact.consumed_allocated_bytes(), 6);
        assert_eq!(String::json_from_value(&input).unwrap(), "abc");
    }
}

#[test]
fn allocation_observation_is_thread_local_under_overlapping_scopes() {
    use std::sync::atomic::{AtomicU8, Ordering};
    fn allocate_once() {
        let layout = Layout::new::<u64>();
        // SAFETY: a nonzero valid layout is paired with the exact allocation on release.
        unsafe {
            let pointer = CountingAllocator.alloc(layout);
            assert!(!pointer.is_null());
            std::hint::black_box(pointer);
            CountingAllocator.dealloc(pointer, layout);
        }
    }
    // A parking barrier may allocate thread metadata during its first wait.
    // Atomic rendezvous keeps that unrelated allocation out of this census.
    let phase = AtomicU8::new(0);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            measured_allocations(|| {
                allocate_once();
                phase.store(1, Ordering::Release);
                while phase.load(Ordering::Acquire) != 2 {
                    std::hint::spin_loop();
                }
            })
            .1
        });
        let second = scope.spawn(|| {
            while phase.load(Ordering::Acquire) != 1 {
                std::hint::spin_loop();
            }
            measured_allocations(|| {
                for _ in 0..3 {
                    allocate_once();
                }
                phase.store(2, Ordering::Release);
            })
            .1
        });
        assert_eq!(first.join().unwrap(), 1);
        assert_eq!(second.join().unwrap(), 3);
    });
}

#[test]
fn allocation_observation_restores_tracking_after_unwind() {
    let result =
        std::panic::catch_unwind(|| measured_allocations(|| panic!("observation unwind control")));
    assert!(result.is_err());
    assert_eq!(OBSERVED_ALLOCATIONS.with(Cell::get), None);
    let (_, count) = measured_allocations(|| {});
    assert_eq!(count, 0);
    assert_eq!(OBSERVED_ALLOCATIONS.with(Cell::get), None);
}

#[test]
fn allocation_observation_forwards_zeroed_and_reallocated_storage() {
    let initial = Layout::new::<[u8; 8]>();
    let expanded = Layout::new::<[u8; 16]>();
    let ((zeroed, preserved), count) = measured_allocations(|| {
        // SAFETY: both layouts are nonzero with the same alignment. The successful
        // reallocation transfers the original pointer; the resulting allocation is
        // released exactly once using its new layout. Refused allocation panics.
        unsafe {
            let pointer = CountingAllocator.alloc_zeroed(initial);
            assert!(!pointer.is_null());
            let mut zeroed = [0_u8; 8];
            zeroed.copy_from_slice(std::slice::from_raw_parts(pointer, 8));
            pointer.write_bytes(0x5a, 8);
            let resized = CountingAllocator.realloc(pointer, initial, expanded.size());
            if resized.is_null() {
                CountingAllocator.dealloc(pointer, initial);
                panic!("fixture reallocation refused");
            }
            let mut preserved = [0_u8; 8];
            preserved.copy_from_slice(std::slice::from_raw_parts(resized, 8));
            CountingAllocator.dealloc(resized, expanded);
            (zeroed, preserved)
        }
    });
    assert_eq!(zeroed, [0; 8]);
    assert_eq!(preserved, [0x5a; 8]);
    assert_eq!(count, 2);
    assert_eq!(OBSERVED_ALLOCATIONS.with(Cell::get), None);
}

mod fast_depth_order {
    //! Physical tape admission is checked by the same thread-local allocation owner.

    use super::measured_allocations;
    use norito::{
        core::{DecodeBudgetContext, DecodeLimits, DecodeResourceError},
        json::{self, Error},
    };

    #[derive(Debug, PartialEq, Eq, norito_derive::FastJson, norito_derive::JsonDeserialize)]
    #[norito(no_fast_from_json)]
    struct Probe {
        value: u64,
    }

    fn decode_fast(input: &str) -> Result<Probe, Error> {
        json::from_json_fast(input)
    }
    fn decode_smart(input: &str) -> Result<Probe, Error> {
        json::from_json_fast_smart(input)
    }
    fn decode_auto(input: &str) -> Result<Probe, Error> {
        json::from_json_auto(input)
    }
    fn limits(depth: usize) -> DecodeLimits {
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, depth)
    }
    fn padded(value: &str, length: usize) -> String {
        assert!(value.len() <= length);
        let mut input = String::with_capacity(length);
        input.push_str(value);
        for _ in value.len()..length {
            input.push(' ');
        }
        input
    }

    #[test]
    fn active_depth_refuses_before_structural_tape_allocation() {
        for length in [256, 257] {
            let input = padded(r#"{"value":7}"#, length);
            for decode in [decode_fast, decode_smart, decode_auto] {
                let context = DecodeBudgetContext::new(limits(0));
                let (result, allocations) =
                    context.with(|| measured_allocations(|| decode(&input)));
                let error = result.expect_err("the original active depth must refuse");
                assert_eq!(
                    error.into_core_error().decode_resource_error(),
                    Some(DecodeResourceError::NestingDepthExceeded {
                        depth: 1,
                        limit: 0,
                        context: "decode budget"
                    })
                );
                assert_eq!(
                    allocations, 0,
                    "active depth refusal must precede structural tape allocation"
                );
                assert_eq!(context.consumed_allocated_bytes(), 0);
            }
        }
    }

    #[test]
    fn fixed_depth_refuses_before_structural_tape_allocation() {
        let body = format!(
            "{}7{}",
            "[".repeat(json::MAX_JSON_VALUE_NESTING_DEPTH),
            "]".repeat(json::MAX_JSON_VALUE_NESTING_DEPTH)
        );
        for length in [256, 257] {
            let input = padded(&body, length);
            for decode in [decode_fast, decode_smart, decode_auto] {
                let context = DecodeBudgetContext::new(limits(0));
                let (result, allocations) =
                    context.with(|| measured_allocations(|| decode(&input)));
                assert!(
                    matches!(result, Err(Error::NestingDepthExceeded { depth, limit: json::MAX_JSON_VALUE_NESTING_DEPTH, context: "JSON value" }) if depth == json::MAX_JSON_VALUE_NESTING_DEPTH + 1)
                );
                assert_eq!(
                    allocations, 0,
                    "fixed depth refusal must precede structural tape allocation"
                );
                assert_eq!(context.consumed_allocated_bytes(), 0);
            }
        }
    }

    #[test]
    fn exact_depth_and_trailing_position_survive_both_dispatch_thresholds() {
        for length in [256, 257] {
            let input = padded(r#"{"value":7}"#, length);
            let mut trailing = padded(r#"{"value":7}"#, length - 1);
            trailing.push('0');
            for decode in [decode_fast, decode_smart, decode_auto] {
                let context = DecodeBudgetContext::new(limits(1));
                assert_eq!(context.with(|| decode(&input)).unwrap(), Probe { value: 7 });
                let result = context.with(|| decode(&trailing));
                assert!(
                    matches!(result, Err(Error::TrailingCharacters { byte, line: 1, col }) if byte == length - 1 && col == length)
                );
            }
        }
    }
}

mod fallback_scratch {
    //! The default Value adapter admits its original serialization scratch before allocation.

    use super::measured_allocations;
    use norito::{
        core::{
            DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, DecodeResourceError,
            classify_decode_attempt, with_decode_limits_scope,
        },
        json::{self, Error, JsonDeserialize, Parser, Value},
    };
    use std::cell::Cell;

    thread_local! {
        static PARSER_CALLS: Cell<usize> = const { Cell::new(0) };
        static TRAILING_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    fn limits(bytes: usize, depth: usize) -> DecodeLimits {
        DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, depth)
    }

    fn assert_allocation<T>(result: Result<T, Error>, attempted: u64, limit: u64) {
        assert_eq!(
            result
                .err()
                .expect("original scratch allocation must refuse")
                .into_core_error()
                .decode_resource_error(),
            Some(DecodeResourceError::TotalAllocationExceeded { attempted, limit })
        );
    }

    #[derive(Debug, PartialEq)]
    struct Scalar(u64);
    impl JsonDeserialize for Scalar {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            PARSER_CALLS.with(|calls| calls.set(calls.get() + 1));
            u64::json_deserialize(parser).map(Self)
        }
    }

    #[derive(Debug, PartialEq)]
    struct Text(String);
    impl JsonDeserialize for Text {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            String::json_deserialize(parser).map(Self)
        }
    }

    #[test]
    fn scalar_fallback_refuses_before_scratch_and_preserves_cumulative_owner() {
        for consuming in [false, true] {
            let value = Value::from(7_u64);
            let refused = DecodeBudgetContext::new(limits(0, 0));
            PARSER_CALLS.with(|calls| calls.set(0));
            let (result, allocations) = refused.with(|| {
                measured_allocations(|| {
                    if consuming {
                        json::from_value::<Scalar>(value)
                    } else {
                        Scalar::json_from_value(&value)
                    }
                })
            });
            assert_allocation(result, 1, 0);
            assert_eq!(allocations, 0);
            assert_eq!(refused.consumed_allocated_bytes(), 0);
            PARSER_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        }
        let value = Value::from(7_u64);
        let owner = DecodeBudgetContext::new(limits(1, 0));
        PARSER_CALLS.with(|calls| calls.set(0));
        let (result, allocations) =
            owner.with(|| measured_allocations(|| Scalar::json_from_value(&value)));
        assert_eq!(result.unwrap(), Scalar(7));
        assert_eq!(allocations, 1);
        assert_eq!(owner.consumed_allocated_bytes(), 1);
        let (result, allocations) =
            owner.with(|| measured_allocations(|| Scalar::json_from_value(&value)));
        assert_allocation(result, 2, 1);
        assert_eq!(allocations, 0);
        assert_eq!(owner.consumed_allocated_bytes(), 1);
        PARSER_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    }

    #[test]
    fn string_fallback_charges_five_scratch_bytes_then_three_destination_bytes() {
        for (cap, charged, allocations, attempted) in
            [(4, 0, 0, 5), (5, 5, 1, 8), (7, 5, 1, 8), (8, 8, 2, 0)]
        {
            let value = Value::String(String::from("abc"));
            let owner =
                DecodeBudgetContext::new(DecodeLimits::new(usize::MAX, 3, usize::MAX, cap, 0));
            let (result, observed) =
                owner.with(|| measured_allocations(|| Text::json_from_value(&value)));
            if cap == 8 {
                let decoded = result.unwrap();
                assert_eq!(decoded.0, "abc");
                assert_eq!(decoded.0.capacity(), 3);
            } else {
                assert_allocation(result, attempted, u64::try_from(cap).unwrap());
            }
            assert_eq!(owner.consumed_allocated_bytes(), charged);
            assert_eq!(observed, allocations);
        }
    }

    #[test]
    fn scratch_refusal_preserves_original_scoped_provenance_and_same_input_retry() {
        let value = Value::from(7_u64);
        for (outer, protocol, expected) in [
            (0, 1, DecodeAttemptErrorKind::EnclosingLimit),
            (1, 0, DecodeAttemptErrorKind::Invalid),
            (0, 0, DecodeAttemptErrorKind::Invalid),
        ] {
            let refusal = with_decode_limits_scope(limits(outer, 0), || {
                classify_decode_attempt(|| {
                    with_decode_limits_scope(limits(protocol, 0), || {
                        Scalar::json_from_value(&value).map_err(Error::into_core_error)
                    })
                })
            })
            .expect_err("the original scratch scope must refuse");
            assert_eq!(refusal.kind(), expected);
            assert_eq!(
                refusal.into_error().decode_resource_error(),
                Some(DecodeResourceError::TotalAllocationExceeded {
                    attempted: 1,
                    limit: 0
                })
            );
        }
        assert_eq!(
            with_decode_limits_scope(limits(1, 0), || Scalar::json_from_value(&value)).unwrap(),
            Scalar(7)
        );
    }

    #[derive(Debug)]
    struct NoConsume;
    impl JsonDeserialize for NoConsume {
        fn json_deserialize(_parser: &mut Parser<'_>) -> Result<Self, Error> {
            Ok(Self)
        }
        fn json_drop_after_error(self) {
            TRAILING_DROPS.with(|drops| drops.set(drops.get() + 1));
        }
    }

    #[test]
    fn sufficient_scratch_keeps_typed_errors_and_original_trailing_drop() {
        let value = Value::Bool(true);
        let original = json::from_json::<Scalar>("true").unwrap_err();
        let result =
            with_decode_limits_scope(limits(4, 0), || Scalar::json_from_value(&value)).unwrap_err();
        assert_eq!(format!("{result:?}"), format!("{original:?}"));
        TRAILING_DROPS.with(|drops| drops.set(0));
        let value = Value::from(7_u64);
        let result = with_decode_limits_scope(limits(1, 0), || NoConsume::json_from_value(&value));
        assert!(matches!(
            result,
            Err(Error::TrailingCharacters {
                byte: 0,
                line: 1,
                col: 1
            })
        ));
        TRAILING_DROPS.with(|drops| assert_eq!(drops.get(), 1));
    }

    #[derive(Debug)]
    struct Skip;
    impl JsonDeserialize for Skip {
        fn json_deserialize(parser: &mut Parser<'_>) -> Result<Self, Error> {
            parser.skip_value_lexical()?;
            Ok(Self)
        }
    }

    #[test]
    fn fallback_preserves_empty_terminal_depth_and_refuses_depth_before_scratch() {
        for object in [false, true] {
            let mut text = if object {
                String::from("{}")
            } else {
                String::from("[]")
            };
            for _ in 1..33 {
                text = format!("[{text}]");
            }
            let value = json::parse_value(&text).unwrap();
            let exact = DecodeBudgetContext::new(limits(text.len(), 32));
            let (result, allocations) =
                exact.with(|| measured_allocations(|| Skip::json_from_value(&value)));
            result.unwrap();
            assert_eq!(
                exact.consumed_allocated_bytes(),
                u64::try_from(text.len()).unwrap()
            );
            assert_eq!(allocations, 1);
            let short = DecodeBudgetContext::new(limits(0, 31));
            let (result, allocations) =
                short.with(|| measured_allocations(|| Skip::json_from_value(&value)));
            assert_eq!(
                result
                    .unwrap_err()
                    .into_core_error()
                    .decode_resource_error(),
                Some(DecodeResourceError::NestingDepthExceeded {
                    depth: 32,
                    limit: 31,
                    context: "decode budget"
                })
            );
            assert_eq!(allocations, 0);
            assert_eq!(short.consumed_allocated_bytes(), 0);
            let forbidden = Value::Array(vec![value]);
            let zero = DecodeBudgetContext::new(limits(0, 0));
            let (result, allocations) =
                zero.with(|| measured_allocations(|| Skip::json_from_value(&forbidden)));
            assert!(matches!(
                result,
                Err(Error::NestingDepthExceeded {
                    depth: 34,
                    limit: 33,
                    context: "JSON value"
                })
            ));
            assert_eq!(allocations, 0);
            assert_eq!(zero.consumed_allocated_bytes(), 0);
        }
    }
}
