//! Caller-owned JSON destinations preserve canonical kernels and typed refusal.
use super::*;
use crate::json::Value;

#[derive(Debug)]
enum Failure {
    Json(Error),
    Original(u64),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Json(error)
    }
}

#[test]
fn exact_string_destination_matches_owned_utf8_escapes_and_cursor() {
    for source in [r#""plain""#, r#""\n\u0041\uD83D\uDE80é""#, r#""""#] {
        let mut owned = Parser::new(source);
        let expected = owned.parse_string().unwrap();
        let mut destination = Parser::new(source);
        let actual = destination
            .parse_string_with_buffer(|length| Ok::<_, Failure>(vec![0_u8; length]))
            .unwrap();
        assert_eq!(actual, expected.as_bytes());
        assert_eq!(destination.position(), owned.position());
        assert!(destination.eof());
    }
    for source in [r#""\uD800""#, r#""\q""#, "\"unterminated"] {
        let owned = Parser::new(source).parse_string().unwrap_err();
        let result = Parser::new(source)
            .parse_string_with_buffer(|length| Ok::<_, Failure>(vec![0_u8; length]))
            .unwrap_err();
        assert!(matches!(result, Failure::Json(actual) if actual.to_string()==owned.to_string()));
    }
}

#[test]
fn string_destination_refusal_preserves_original_cause_and_logical_priority() {
    let mut parser = Parser::new(r#""abcdef""#);
    let mut allocated = 0;
    let result = parser.parse_string_with_buffer(|length| {
        allocated += 1;
        assert_eq!(length, 6);
        Err::<Vec<u8>, _>(Failure::Original(73))
    });
    assert!(matches!(result, Err(Failure::Original(73))));
    assert_eq!(allocated, 1);
    let limits = crate::core::DecodeLimits::new(1024, 1024, 1024, 0, 32);
    crate::core::with_decode_limits_scope(limits, || {
        let mut parser = Parser::new(r#""abcdef""#);
        let result = parser.parse_string_with_buffer(|_| {
            allocated += 1;
            Err::<Vec<u8>, _>(Failure::Original(74))
        });
        assert!(matches!(result, Err(Failure::Json(_))));
    });
    assert_eq!(
        allocated, 1,
        "logical string refusal precedes physical owner callback"
    );
    let result =
        Parser::new(r#""abc""#).parse_string_with_buffer(|_| Ok::<_, Failure>(vec![0x55; 2]));
    assert!(matches!(result, Err(Failure::Json(_))));
}

#[test]
fn typed_object_and_sequence_callbacks_preserve_refusal_count_and_delimiters() {
    let mut parser = Parser::new(r#"{"value":[1,2]}"#);
    let mut map = MapVisitor::new(&mut parser).unwrap();
    assert_eq!(map.next_key().unwrap().unwrap().as_str(), "value");
    let result = map.parse_value_with_parser_typed(|parser| {
        let mut values = SeqVisitor::new(parser)?;
        assert_eq!(values.total_entries(), 2);
        assert_eq!(
            values.next_element_with_parser_typed(|parser| {
                Ok::<_, Failure>(parser.parse_u64()?)
            })?,
            Some(1)
        );
        values.next_element_with_parser_typed(|_| Err::<u64, _>(Failure::Original(91)))
    });
    assert!(matches!(result, Err(Failure::Original(91))));
    let mut parser = Parser::new(r#"{"value":[1,2]}"#);
    let mut map = MapVisitor::new(&mut parser).unwrap();
    map.next_key().unwrap();
    let result = map
        .parse_value_with_parser_typed(|parser| {
            let mut values = SeqVisitor::new(parser)?;
            let first = values
                .next_element_with_parser_typed(|parser| Ok::<_, Failure>(parser.parse_u64()?))?;
            let second = values
                .next_element_with_parser_typed(|parser| Ok::<_, Failure>(parser.parse_u64()?))?;
            assert!(values.next_element::<u64>()?.is_none());
            values.finish()?;
            Ok::<_, Failure>((first, second))
        })
        .unwrap();
    assert_eq!(result, (Some(1), Some(2)));
    map.finish().unwrap();
    assert!(parser.eof());
}

#[test]
fn string_destination_exact_preflight_never_indexes_outside_malformed_or_unicode_input() {
    for scalar in [
        0, 1, 0x1f, 0x20, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ] {
        let ch = char::from_u32(scalar).unwrap();
        let source = crate::json::to_json(&ch.to_string()).unwrap();
        let actual = Parser::new(&source)
            .parse_string_with_buffer(|length| Ok::<_, Failure>(vec![0; length]))
            .unwrap();
        assert_eq!(actual, ch.to_string().as_bytes());
        for end in 0..source.len() {
            if !source.is_char_boundary(end) {
                continue;
            }
            let prefix = &source[..end];
            let result = std::panic::catch_unwind(|| {
                Parser::new(prefix)
                    .parse_string_with_buffer(|length| Ok::<_, Failure>(vec![0; length]))
            });
            assert!(
                result.is_ok(),
                "malformed prefix must return syntax failure"
            );
            assert!(result.unwrap().is_err());
        }
    }
    for source in [
        r#""\u""#,
        r#""\u000G""#,
        r#""\uD800\u0000""#,
        r#""\uDFFF""#,
        r#""\uD800x""#,
        "\"\n\"",
        r#""\uD800\q""#,
    ] {
        let mut calls = 0;
        let result = Parser::new(source).parse_string_with_buffer(|length| {
            calls += 1;
            Ok::<_, Failure>(vec![0; length])
        });
        assert!(matches!(result, Err(Failure::Json(_))));
        assert_eq!(
            calls, 0,
            "preflight syntax failure precedes the destination allocation"
        );
    }
}

#[test]
fn string_destination_active_successful_prefix_is_not_refunded_on_refusal() {
    let limits = crate::core::DecodeLimits::new(1024, 1024, 1024, 3, 32);
    crate::core::with_decode_limits_scope(limits, || {
        let first = Parser::new(r#""abc""#)
            .parse_string_with_buffer(|_| Err::<Vec<u8>, _>(Failure::Original(104)));
        assert!(matches!(first, Err(Failure::Original(104))));
        let mut calls = 0;
        let retry = Parser::new(r#""x""#).parse_string_with_buffer(|length| {
            calls += 1;
            Ok::<_, Failure>(vec![0; length])
        });
        assert!(matches!(retry, Err(Failure::Json(ref error)) if error.is_decode_resource_limit()));
        assert_eq!(calls, 0);
    });
    crate::core::with_decode_limits_scope(limits, || {
        assert_eq!(Parser::new(r#""abc""#).parse_string().unwrap(), "abc");
        assert!(
            Parser::new(r#""x""#)
                .parse_string()
                .unwrap_err()
                .is_decode_resource_limit()
        );
    });
}

#[derive(Debug)]
enum KeyFailure {
    Json(Error),
    Allocation(iroha_allocation::ChargedBufferError),
}
impl From<Error> for KeyFailure {
    fn from(error: Error) -> Self {
        Self::Json(error)
    }
}
impl From<iroha_allocation::ChargedBufferError> for KeyFailure {
    fn from(error: iroha_allocation::ChargedBufferError) -> Self {
        Self::Allocation(error)
    }
}
struct KeyBytes(iroha_allocation::ChargedBuffer<u8>);
impl AsMut<[u8]> for KeyBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
fn admit_key(
    length: usize,
    pool: &iroha_allocation::AllocationBudget,
) -> Result<KeyBytes, KeyFailure> {
    let mut bytes = iroha_allocation::ChargedBuffer::new(length, pool)?;
    for _ in 0..length {
        bytes.push_reserved(0);
    }
    Ok(KeyBytes(bytes))
}
fn key_text<'s>(key: &'s KeyRef<'_, KeyBytes>) -> &'s str {
    match key {
        KeyRef::Borrowed(text) => text,
        KeyRef::Owned(bytes) => {
            std::str::from_utf8(bytes.0.as_slice()).expect("canonical UTF-8 key")
        }
    }
}
fn key_limits(bytes: usize) -> crate::core::DecodeLimits {
    crate::core::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, bytes, usize::MAX)
}
fn key_bytes_u64(bytes: usize) -> u64 {
    u64::try_from(bytes).expect("fixture fits u64")
}

#[test]
fn admitted_keys_preserve_original_borrow_and_exact_escaped_pool_charge() {
    let source = r#"  "plainé" : 7"#;
    let pool = iroha_allocation::AllocationBudget::new(0);
    let mut ordinary = Parser::new(source);
    let expected = ordinary.parse_key().unwrap();
    let mut parser = Parser::new(source);
    let key = parser
        .parse_key_with_buffer(|_| -> Result<KeyBytes, KeyFailure> {
            panic!("unescaped original key must never invoke its destination")
        })
        .unwrap();
    let KeyRef::Borrowed(text) = key else {
        panic!("unescaped key must remain borrowed")
    };
    assert_eq!(text, expected.as_str());
    assert!(std::ptr::eq(text.as_ptr(), source[3..].as_ptr()));
    assert_eq!(parser.position(), ordinary.position());
    assert_eq!(pool.reserved_bytes(), 0);

    for source in [r#""\u0062ond":3"#, r#""\u00e9":4"#, r#""\uD83D\uDE80":5"#] {
        let mut ordinary = Parser::new(source);
        let expected = ordinary.parse_key().unwrap();
        let length = expected.as_str().len();
        let control = crate::core::DecodeBudgetContext::allocation_layout().size();
        let pool = iroha_allocation::AllocationBudget::new(control + length);
        let foreign = iroha_allocation::AllocationBudget::new(control + length);
        let context =
            crate::core::DecodeBudgetContext::try_new_owned(key_limits(length), &pool).unwrap();
        let mut parser = Parser::new(source);
        let key = context
            .with(|| parser.parse_key_with_buffer(|length| admit_key(length, &pool)))
            .unwrap();
        assert_eq!(key_text(&key), expected.as_str());
        assert_eq!(parser.position(), ordinary.position());
        let KeyRef::Owned(ref bytes) = key else {
            panic!("escaped key must retain its admitted destination")
        };
        assert!(bytes.0.belongs_to(&pool));
        assert!(!bytes.0.belongs_to(&foreign));
        assert_eq!(pool.reserved_bytes(), control + length);
        assert_eq!(pool.peak_reserved_bytes(), control + length);
        assert_eq!(context.consumed_allocated_bytes(), key_bytes_u64(length));
        drop(key);
        assert_eq!(pool.reserved_bytes(), control);
        drop(context);
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}

#[test]
fn admitted_key_refusal_preserves_original_release_and_cumulative_colon_order() {
    use iroha_allocation::{
        AllocationBudget, AllocationRefusal, ChargedBufferError, release::ReleaseRegistration,
    };
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    // The genuine string debit precedes the missing colon even on the original slow path.
    let source = r#""\u0062ond" 3"#;
    let text = crate::json::from_str::<String>(r#""\u0062ond""#).unwrap();
    let length = text.len();
    let ordinary = Parser::new(source).parse_key().err().unwrap();
    let control = crate::core::DecodeBudgetContext::allocation_layout().size();
    let registration_layout = ReleaseRegistration::allocation_layout();
    let baseline = control + registration_layout.size();
    let pool = AllocationBudget::new(baseline + length);
    let context =
        crate::core::DecodeBudgetContext::try_new_owned(key_limits(length * 2), &pool).unwrap();
    let mut reservation = pool.try_reserve(registration_layout).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    assert!(registration.belongs_to(&pool));
    let blocker = pool.try_reserve_bytes(length).unwrap();
    let error = context
        .with(|| Parser::new(source).parse_key_with_buffer(|length| admit_key(length, &pool)))
        .err()
        .unwrap();
    let KeyFailure::Allocation(ChargedBufferError::Admission(AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    })) = error
    else {
        panic!("escaped key must preserve the original typed capacity refusal before colon syntax")
    };
    assert_eq!(requested_bytes, length);
    assert_eq!(reserved_bytes, baseline + length);
    assert_eq!(limit_bytes, baseline + length);
    assert_eq!(context.consumed_allocated_bytes(), key_bytes_u64(length));
    assert_eq!(pool.reserved_bytes(), baseline + length);
    let mut waiting = release.wait_for_release(&mut registration);
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Pending
    ));
    drop(blocker);
    assert!(matches!(
        Pin::new(&mut waiting).poll(&mut task),
        Poll::Ready(())
    ));
    drop(waiting);
    let retry = context
        .with(|| Parser::new(source).parse_key_with_buffer(|length| admit_key(length, &pool)))
        .err()
        .unwrap();
    assert!(
        matches!(retry, KeyFailure::Json(ref actual) if actual.to_string() == ordinary.to_string())
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        key_bytes_u64(length * 2)
    );
    assert_eq!(pool.reserved_bytes(), baseline);
    let mut calls = 0;
    let exhausted = context
        .with(|| {
            Parser::new(source).parse_key_with_buffer(|length| {
                calls += 1;
                admit_key(length, &pool)
            })
        })
        .err()
        .unwrap();
    assert!(matches!(exhausted, KeyFailure::Json(ref error) if error.is_decode_resource_limit()));
    assert_eq!(
        calls, 0,
        "original logical refusal still precedes physical key admission"
    );
    assert_eq!(
        context.consumed_allocated_bytes(),
        key_bytes_u64(length * 2)
    );
    drop(registration);
    drop(context);
    assert_eq!(pool.reserved_bytes(), 0);
}

#[test]
fn admitted_keys_preserve_malformed_unicode_colon_and_destination_errors() {
    for source in [
        r#""\uD800":3"#,
        r#""\q":3"#,
        "\"unterminated",
        "\"\n\":1",
        r#""plain" 3"#,
        r#""\u0062ond" 3"#,
    ] {
        let ordinary = Parser::new(source).parse_key().err().unwrap();
        let actual = Parser::new(source)
            .parse_key_with_buffer(|length| Ok::<_, KeyFailure>(vec![0; length]))
            .err()
            .unwrap();
        assert!(
            matches!(actual, KeyFailure::Json(ref error) if error.to_string() == ordinary.to_string()),
            "original key error order must match: {source}"
        );
    }
    let mut calls = 0;
    let result = Parser::new(r#""\uD800":3"#).parse_key_with_buffer(|length| {
        calls += 1;
        Ok::<_, KeyFailure>(vec![0; length])
    });
    assert!(matches!(result, Err(KeyFailure::Json(_))));
    assert_eq!(
        calls, 0,
        "malformed original escape precedes destination admission"
    );
    let result = Parser::new(r#""\u0062ond":3"#)
        .parse_key_with_buffer(|length| Ok::<_, KeyFailure>(vec![0; length - 1]));
    assert!(
        matches!(result, Err(KeyFailure::Json(ref error)) if error.to_string() == "JSON string destination length differs")
    );
}

#[test]
fn admitted_map_keys_preserve_shared_lifecycle_and_original_typed_refusal() {
    let pool = iroha_allocation::AllocationBudget::new(32);
    let source = r#"{"first":1,"\u006eext":2}"#;
    let mut ordinary = Parser::new(source);
    let mut expected = MapVisitor::new(&mut ordinary).unwrap();
    assert_eq!(expected.next_key().unwrap().unwrap().as_str(), "first");
    let pending = expected.next_key().err().unwrap();
    assert_eq!(expected.parse_value::<u64>().unwrap(), 1);
    assert_eq!(expected.next_key().unwrap().unwrap().as_str(), "next");
    assert_eq!(expected.parse_value::<u64>().unwrap(), 2);
    assert!(expected.next_key().unwrap().is_none());
    expected.finish().unwrap();
    let mut parser = Parser::new(source);
    let mut map = MapVisitor::new(&mut parser).unwrap();
    let first = map
        .next_key_with_buffer(|length| admit_key(length, &pool))
        .unwrap()
        .unwrap();
    assert_eq!(key_text(&first), "first");
    let mut calls = 0;
    let error = map
        .next_key_with_buffer(|length| {
            calls += 1;
            admit_key(length, &pool)
        })
        .err()
        .unwrap();
    assert!(
        matches!(error, KeyFailure::Json(ref error) if error.to_string() == pending.to_string())
    );
    assert_eq!(calls, 0);
    assert_eq!(map.parse_value::<u64>().unwrap(), 1);
    let next = map
        .next_key_with_buffer(|length| admit_key(length, &pool))
        .unwrap()
        .unwrap();
    assert_eq!(key_text(&next), "next");
    assert_eq!(map.parse_value::<u64>().unwrap(), 2);
    assert!(
        map.next_key_with_buffer(|length| admit_key(length, &pool))
            .unwrap()
            .is_none()
    );
    map.finish().unwrap();
    assert_eq!(parser.position(), ordinary.position());
    drop(next);
    drop(first);
    assert_eq!(pool.reserved_bytes(), 0);
    for source in ["{}", r#"{"first":1,}"#] {
        let mut ordinary = Parser::new(source);
        let mut parser = Parser::new(source);
        let mut expected = MapVisitor::new(&mut ordinary).unwrap();
        let mut actual = MapVisitor::new(&mut parser).unwrap();
        if source != "{}" {
            expected.next_key().unwrap();
            expected.parse_value::<u64>().unwrap();
            actual
                .next_key_with_buffer(|length| admit_key(length, &pool))
                .unwrap();
            actual.parse_value::<u64>().unwrap();
            let error = expected.next_key().err().unwrap();
            let refused = actual
                .next_key_with_buffer(|length| admit_key(length, &pool))
                .err()
                .unwrap();
            assert!(
                matches!(refused, KeyFailure::Json(ref actual) if actual.to_string() == error.to_string())
            );
        } else {
            assert!(
                actual
                    .next_key_with_buffer(|_| -> Result<KeyBytes, KeyFailure> {
                        panic!("empty object needs no key")
                    })
                    .unwrap()
                    .is_none()
            );
        }
    }
    let empty_pool = iroha_allocation::AllocationBudget::new(0);
    let mut parser = Parser::new(r#"{"\u006eext":2}"#);
    let mut map = MapVisitor::new(&mut parser).unwrap();
    let refusal = map
        .next_key_with_buffer(|length| admit_key(length, &empty_pool))
        .err()
        .unwrap();
    assert!(matches!(
        refusal,
        KeyFailure::Allocation(iroha_allocation::ChargedBufferError::Admission(
            iroha_allocation::AllocationRefusal::ExceedsLimit {
                requested_bytes: 4,
                limit_bytes: 0,
            }
        ))
    ));
}

#[test]
fn seeded_document_finish_preserves_ordinary_whitespace_and_exact_trailing_positions() {
    for source in ["1", "  1 \n\t", "1 2", "\n 1 \n false", "true\n null"] {
        let mut seeded = Parser::new(source);
        seeded.preflight_document().unwrap();
        seeded.skip_ws();
        let value = Value::json_deserialize(&mut seeded).unwrap();
        let completed = seeded.finish_document();
        let ordinary = crate::json::from_json::<Value>(source);
        match (ordinary, completed) {
            (Ok(expected), Ok(())) => assert_eq!(value, expected),
            (
                Err(Error::TrailingCharacters {
                    byte: b1,
                    line: l1,
                    col: c1,
                }),
                Err(Error::TrailingCharacters {
                    byte: b2,
                    line: l2,
                    col: c2,
                }),
            ) => {
                assert_eq!((b1, l1, c1), (b2, l2, c2));
            }
            pair => panic!("same complete-document relation must be used: {pair:?}"),
        }
    }
}

#[test]
fn seeded_document_depth_refusal_precedes_any_field_decode_and_keeps_cursor() {
    struct Reached;
    impl JsonDeserialize for Reached {
        fn json_deserialize(_: &mut Parser<'_>) -> Result<Self, Error> {
            panic!("document depth must refuse before entering the field decoder")
        }
    }
    let depth = crate::json::MAX_JSON_VALUE_NESTING_DEPTH + 1;
    let source = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    let ordinary = crate::json::from_json::<Reached>(&source).err().unwrap();
    let parser = Parser::new(&source);
    let before = parser.position();
    let seeded = parser.preflight_document().unwrap_err();
    assert_eq!(format!("{seeded:?}"), format!("{ordinary:?}"));
    assert!(matches!(seeded, Error::NestingDepthExceeded { .. }));
    assert_eq!(parser.position(), before);
}
