//! Streaming canonical validation against the maintained semantic writer oracle.

use super::*;
use crate::json::JsonDeserialize as _;

fn check(source: &str) -> Result<(), Error> {
    validate_canonical_json_with_buffer(source, |length| Ok(vec![0_u8; length]))
}

#[test]
fn canonical_streaming_matches_the_original_parser_and_writer() {
    for source in [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "-0.0",
        "1.0",
        "1e0",
        "1E+0",
        "1e-8",
        "18446744073709551616",
        "340282366920938463463374607431768211455",
        "-9223372036854775808",
        "-9223372036854775809",
        "1e999",
        "01",
        "1.",
        r#""plain""#,
        r#""é😀""#,
        r#""\u00e9""#,
        r#""\/""#,
        r#""\n\t\r\b\f\\\"""#,
        r#""\u0000""#,
        r#""\u001f""#,
        r#""\u001F""#,
        r#""\ud83d\ude00""#,
        r#"[]"#,
        r#"{}"#,
        r#"[1,true,{"a":"x","b":[null]}]"#,
        r#"{"a":1,"b":2}"#,
        r#"{"b":2,"a":1}"#,
        r#"{"a":1,"a":2}"#,
        r#"{"\u0061":1}"#,
        r#"{"a":1, "b":2}"#,
        " null",
        "null ",
        "null true",
        "[1,]",
        "{",
        r#"{"a" 1}"#,
        r#""\ud800""#,
    ] {
        let expected = super::super::parse_value(source)
            .and_then(|value| {
                let written = super::super::to_json_bounded(&value, 1 << 20)
                    .map_err(|error| Error::from_decode_resource(error.into_core_error()));
                super::super::drop_json_value_iteratively(value);
                written
            })
            .is_ok_and(|canonical| canonical == source);
        assert_eq!(check(source).is_ok(), expected, "{source}");
    }
}

#[test]
fn original_structural_depth_boundary_is_preserved_without_a_value_tree() {
    let maximum = super::super::MAX_JSON_VALUE_NESTING_DEPTH;
    let valid = format!("{}null{}", "[".repeat(maximum - 1), "]".repeat(maximum - 1));
    let invalid = format!("[{valid}]");
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            assert!(check(&valid).is_ok());
            assert!(matches!(
                check(&invalid),
                Err(Error::NestingDepthExceeded { .. })
            ));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[derive(Debug)]
enum Failure {
    Json(Error),
    Allocation(iroha_allocation::ChargedBufferError),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Json(error)
    }
}
struct Text(iroha_allocation::ChargedBuffer<u8>);
impl AsRef<[u8]> for Text {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl AsMut<[u8]> for Text {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

fn funded(source: &str, pool: &iroha_allocation::AllocationBudget) -> Result<(), Failure> {
    validate_canonical_json_with_buffer(source, |length| {
        let mut text =
            iroha_allocation::ChargedBuffer::new(length, pool).map_err(Failure::Allocation)?;
        for _ in 0..length {
            text.push_reserved(0);
        }
        Ok(Text(text))
    })
}

#[test]
fn scratch_is_original_pool_owned_and_refunds_on_valid_and_invalid_documents() {
    let pool = iroha_allocation::AllocationBudget::new(0);
    assert!(matches!(
        funded(r#""text""#, &pool),
        Err(Failure::Allocation(
            iroha_allocation::ChargedBufferError::Admission(_)
        ))
    ));
    assert_eq!(pool.reserved_bytes(), 0);
    pool.set_limit_bytes(1024);
    for source in [
        r#"{"a":"text","b":"next"}"#,
        r#"{"\u0061":"text"}"#,
        r#"{"b":"text","a":"next"}"#,
    ] {
        match funded(source, &pool) {
            Ok(()) => assert!(check(source).is_ok()),
            Err(Failure::Json(error)) => assert!(error.to_string().contains("canonical")),
            Err(error) => panic!("unexpected funded failure: {error:?}"),
        }
        assert_eq!(pool.reserved_bytes(), 0);
    }
}

#[test]
fn logical_refusal_keeps_original_attempt_identity_and_saved_replay_is_invalid() {
    use crate::core::{DecodeAttemptErrorKind, classify_decode_attempt};
    let zero = crate::core::DecodeBudgetContext::new(crate::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        usize::MAX,
    ));
    let mut seen = None;
    let attempt = zero
        .with(|| {
            classify_decode_attempt(|| {
                check(r#""text""#).map_err(|error| {
                    let Error::ScopedDecodeResource(origin) = &error else {
                        panic!("original scope: {error:?}")
                    };
                    seen = Some(origin.clone());
                    error.into_core_error()
                })
            })
        })
        .unwrap_err();
    assert_eq!(attempt.kind(), DecodeAttemptErrorKind::EnclosingLimit);
    let crate::Error::ScopedDecodeResource(origin) =
        attempt.into_local_refusal().unwrap().into_error()
    else {
        panic!("original identity lost")
    };
    assert_eq!(Some(&origin), seen.as_ref());
    let replay = zero
        .with(|| {
            classify_decode_attempt(|| {
                let _ = check(r#""fresh""#).unwrap_err();
                Err::<(), _>(crate::Error::ScopedDecodeResource(origin))
            })
        })
        .unwrap_err();
    assert_eq!(replay.kind(), DecodeAttemptErrorKind::Invalid);
    assert!(check(r#""text""#).is_ok());
}

#[test]
fn array_destination_uses_exact_ordinary_cursor_and_refusal_before_elements() {
    for source in ["[]", "[1,2]", " [1, 2] ", "[1,]", "[1 2]", "[", "{}"] {
        let mut ordinary = Parser::new(source);
        let expected = ordinary.parse_array::<u64>();
        let mut admitted = Parser::new(source);
        let actual: Result<Vec<u64>, Error> = admitted.parse_array_with(
            |count| Ok(Vec::with_capacity(count)),
            u64::json_deserialize,
            Vec::push,
        );
        assert_eq!(
            actual.as_ref().map_err(ToString::to_string),
            expected.as_ref().map_err(ToString::to_string),
            "{source}"
        );
        assert_eq!(admitted.position(), ordinary.position(), "{source}");
    }
    let mut parser = Parser::new("[1,2]");
    let error: Result<Vec<u64>, Error> = parser.parse_array_with(
        |count| {
            assert_eq!(count, 2);
            Err(Error::UnsupportedFeature("original destination refusal"))
        },
        |_| panic!("no element may be parsed before destination admission"),
        Vec::push,
    );
    assert!(matches!(
        error,
        Err(Error::UnsupportedFeature("original destination refusal"))
    ));
}
