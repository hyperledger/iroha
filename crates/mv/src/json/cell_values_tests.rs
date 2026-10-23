//! Shared typed Cell grammar, original key custody and pre-initialization comparison.
use super::*;
use iroha_allocation::{AllocationBudget, ChargedBuffer, ChargedBufferError};
use norito::core::{
    DecodeAttemptErrorKind, DecodeBudgetContext, DecodeLimits, classify_decode_attempt,
};
use std::cell::Cell as Counter;
#[derive(Debug)]
enum Failure {
    Json(json::Error),
    Allocation(ChargedBufferError),
    Value(u64),
}
impl From<json::Error> for Failure {
    fn from(e: json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<ChargedBufferError> for Failure {
    fn from(e: ChargedBufferError) -> Self {
        Self::Allocation(e)
    }
}
struct KeyBytes(ChargedBuffer<u8>);
impl AsMut<[u8]> for KeyBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<[u8]> for KeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
fn key_bytes(length: usize, pool: &AllocationBudget) -> Result<KeyBytes, Failure> {
    let mut bytes = ChargedBuffer::new(length, pool)?;
    for _ in 0..length {
        bytes.push_reserved(0);
    }
    Ok(KeyBytes(bytes))
}
fn decode_optional(
    source: &str,
    pool: &AllocationBudget,
) -> Result<(Option<u64>, Option<Option<u64>>), Failure> {
    let mut parser = json::Parser::new(source);
    parser.preflight_document()?;
    let values = parse_cell_values_with(
        &mut parser,
        |p| Ok(Option::<u64>::json_deserialize(p)?),
        |n| key_bytes(n, pool),
    )?;
    parser.finish_document()?;
    Ok(values)
}
#[test]
fn typed_values_share_ordinary_presence_and_field_order_without_key_allocation() {
    for (source, expected) in [
        (r#"{"revert":null,"blocks":17}"#, (Some(17), None)),
        (
            r#"{"revert":{"value":null},"blocks":17}"#,
            (Some(17), Some(None)),
        ),
        (
            r#"{"blocks":null,"revert":{"value":7}}"#,
            (None, Some(Some(7))),
        ),
    ] {
        let pool = AllocationBudget::new(0);
        assert_eq!(decode_optional(source, &pool).unwrap(), expected);
        let ordinary: Cell<Option<u64>> = json::from_str(source).unwrap();
        assert_eq!(*ordinary.view().get(), expected.0);
        assert_eq!(*ordinary.predecessor_view().get(), expected.1);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
#[test]
fn typed_values_require_no_clone_or_mv_value_bound() {
    struct MoveOnly(u64);
    let mut parser = json::Parser::new(r#"{"revert":{"value":3},"blocks":5}"#);
    let (current, undo) = parse_cell_values_with::<MoveOnly, Failure, Vec<u8>>(
        &mut parser,
        |p| Ok(MoveOnly(u64::json_deserialize(p)?)),
        |_| panic!("unescaped keys borrow source"),
    )
    .unwrap();
    parser.finish_document().unwrap();
    assert_eq!(current.0, 5);
    assert_eq!(undo.unwrap().0, 3);
}
#[test]
fn typed_and_ordinary_refuse_the_same_strict_cell_and_undo_shapes() {
    for source in [
        "[]",
        "{}",
        r#"{"blocks":1}"#,
        r#"{"revert":null}"#,
        r#"{"revert":null,"revert":null,"blocks":1}"#,
        r#"{"revert":null,"blocks":1,"blocks":2}"#,
        r#"{"revert":null,"blocks":1,"extra":0}"#,
        r#"{"revert":7,"blocks":1}"#,
        r#"{"revert":{},"blocks":1}"#,
        r#"{"revert":{"extra":null},"blocks":1}"#,
        r#"{"revert":{"value":null,"value":null},"blocks":1}"#,
        r#"{"revert":{"value":null,"extra":0},"blocks":1}"#,
        r#"{"revert":{"value":null,},"blocks":1}"#,
        r#"{"revert":null,"blocks":1,}"#,
        r#"{"revert":null,"blocks":1} true"#,
        r#"{"revert":null,"blocks":-1}"#,
        r#"{"revert":null,"blo\u0063ks":1,"blocks":2}"#,
        r#"{"revert":{"val\u0075e":null,"value":null},"blocks":1}"#,
    ] {
        let pool = AllocationBudget::new(64);
        assert!(
            decode_optional(source, &pool).is_err(),
            "typed accepted {source}"
        );
        assert!(
            json::from_str::<Cell<Option<u64>>>(source).is_err(),
            "ordinary accepted {source}"
        );
        assert_eq!(pool.reserved_bytes(), 0, "{source}");
    }
}
#[test]
fn escaped_outer_and_undo_keys_keep_original_pool_overlap_and_retry() {
    let source = r#"{"re\u0076ert":{"val\u0075e":7},"blo\u0063ks":11}"#;
    let pool = AllocationBudget::new(5);
    assert!(matches!(
        decode_optional(source, &pool),
        Err(Failure::Allocation(ChargedBufferError::Admission(_)))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(10);
    assert!(matches!(
        decode_optional(source, &pool),
        Err(Failure::Allocation(ChargedBufferError::Admission(_)))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(11);
    let mut requests = Vec::new();
    let mut parser = json::Parser::new(source);
    let actual = parse_cell_values_with(
        &mut parser,
        |p| Ok::<_, Failure>(u64::json_deserialize(p)?),
        |n| {
            requests.push((n, pool.reserved_bytes()));
            key_bytes(n, &pool)
        },
    )
    .unwrap();
    parser.finish_document().unwrap();
    assert_eq!(actual, (11, Some(7)));
    assert_eq!(requests, [(6, 0), (5, 6), (6, 0)]);
    assert_eq!(pool.reserved_bytes(), 0);
    assert_eq!(
        decode_optional(source, &pool).unwrap(),
        (Some(11), Some(Some(7)))
    );
}
#[test]
fn later_key_refusal_drops_exact_decoded_value_before_retry() {
    struct Observed<'a>(&'a Counter<usize>, u64);
    impl Drop for Observed<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Counter::new(0);
    let calls = Counter::new(0);
    let pool = AllocationBudget::new(0);
    let source = r#"{"blocks":11,"re\u0076ert":null}"#;
    let parse = |pool: &AllocationBudget| {
        parse_cell_values_with(
            &mut json::Parser::new(source),
            |p| {
                calls.set(calls.get() + 1);
                Ok::<_, Failure>(Observed(&drops, u64::json_deserialize(p)?))
            },
            |n| key_bytes(n, pool),
        )
    };
    assert!(matches!(
        parse(&pool),
        Err(Failure::Allocation(ChargedBufferError::Admission(_)))
    ));
    assert_eq!((calls.get(), drops.get()), (1, 1));
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(6);
    let (current, undo) = parse(&pool).unwrap();
    assert_eq!(current.1, 11);
    assert!(undo.is_none());
    assert_eq!((calls.get(), drops.get()), (2, 1));
    drop(current);
    assert_eq!(drops.get(), 2);
    assert_eq!(pool.reserved_bytes(), 0);
}
#[test]
fn original_typed_value_error_is_forwarded_without_parsing_later_value() {
    let calls = Counter::new(0);
    let error = parse_cell_values_with::<u64, Failure, Vec<u8>>(
        &mut json::Parser::new(r#"{"revert":{"value":7},"blocks":11}"#),
        |_| {
            calls.set(calls.get() + 1);
            Err(Failure::Value(73))
        },
        |_| panic!("unescaped keys borrow source"),
    )
    .unwrap_err();
    assert!(matches!(error, Failure::Value(73)));
    assert_eq!(calls.get(), 1);
}
#[test]
fn escaped_key_keeps_original_native_observer_and_saved_replay_invalid() {
    let source = r#"{"re\u0076ert":null,"blocks":11}"#;
    let pool = AllocationBudget::new(64);
    let context = DecodeBudgetContext::new(DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let mut seen = None;
    let attempt = context
        .with(|| {
            classify_decode_attempt(|| {
                decode_optional(source, &pool).map_err(|error| {
                    let Failure::Json(json::Error::ScopedDecodeResource(origin)) = error else {
                        panic!("original observer lost: {error:?}")
                    };
                    seen = Some(origin.clone());
                    norito::Error::ScopedDecodeResource(origin)
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let norito::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original refusal lost")
    };
    assert_eq!(seen.as_ref(), Some(&origin));
    assert_eq!(pool.reserved_bytes(), 0);
    let replay = context
        .with(|| {
            classify_decode_attempt(|| {
                let _ = decode_optional(source, &pool).unwrap_err();
                Err::<(), _>(norito::Error::ScopedDecodeResource(origin))
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert_eq!(decode_optional(source, &pool).unwrap(), (Some(11), None));
    assert_eq!(pool.reserved_bytes(), 0);
}
struct Compare<'a> {
    expected: &'a [u8],
    offset: usize,
    depth: usize,
}
impl JsonWriteSink for Compare<'_> {
    fn push(&mut self, v: char) -> Result<(), BoundedJsonError> {
        self.push_str(v.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, v: &str) -> Result<(), BoundedJsonError> {
        let end = self
            .offset
            .checked_add(v.len())
            .ok_or(BoundedJsonError::BodyTooLarge)?;
        if self.expected.get(self.offset..end) != Some(v.as_bytes()) {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.offset = end;
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        self.depth += 1;
        Ok(())
    }
    fn end_container(&mut self) {
        self.depth -= 1;
    }
}
#[test]
fn shared_writer_compares_explicit_original_values_without_a_cell_or_clone() {
    for (current, undo, expected) in [
        (Some(17_u64), None, r#"{"revert":null,"blocks":17}"#),
        (
            Some(17),
            Some(None),
            r#"{"revert":{"value":null},"blocks":17}"#,
        ),
        (
            None,
            Some(Some(7)),
            r#"{"revert":{"value":7},"blocks":null}"#,
        ),
    ] {
        let mut sink = Compare {
            expected: expected.as_bytes(),
            offset: 0,
            depth: 0,
        };
        write_cell_values_to(&undo, &current, &mut sink).unwrap();
        assert_eq!(sink.offset, expected.len());
        assert_eq!(sink.depth, 0);
        let mut short = Compare {
            expected: &expected.as_bytes()[..expected.len() - 1],
            offset: 0,
            depth: 0,
        };
        assert_eq!(
            write_cell_values_to(&undo, &current, &mut short),
            Err(BoundedJsonError::BodyTooLarge)
        );
        assert_eq!(short.depth, 0);
    }
}
#[test]
fn noncanonical_refusal_releases_full_prepaid_initialization_without_ebr_publication() {
    use crate::cell::CellInitialization;
    let pool = AllocationBudget::new(usize::MAX);
    let initialization = CellInitialization::<Option<u64>>::try_reserve(&pool).unwrap();
    assert!(pool.reserved_bytes() > 0);
    let source = r#"{"blocks":17,"revert":{"value":null}}"#;
    let (current, undo) = decode_optional(source, &pool).unwrap();
    let mut sink = Compare {
        expected: source.as_bytes(),
        offset: 0,
        depth: 0,
    };
    assert_eq!(
        write_cell_values_to(&undo, &current, &mut sink),
        Err(BoundedJsonError::BodyTooLarge)
    );
    assert_eq!(sink.depth, 0);
    // Reject before initialize: no temporary Cell or retired EBR generation.
    drop(initialization);
    assert_eq!(pool.reserved_bytes(), 0);
}
