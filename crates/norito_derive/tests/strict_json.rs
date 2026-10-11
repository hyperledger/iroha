//! Runtime coverage for strict Norito JSON derives.
use norito::json::JsonDeserialize as _;
use norito::json::{self, Arena, Error, FastFromJson, TapeWalker};
use norito_derive::{JsonDeserialize, JsonSerialize};
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictInner {
    value: u32,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictGeneric<'a, 'arena, '__norito_json, '__norito_arena, T, const N: usize> {
    value: T,
    #[norito(skip)]
    marker: core::marker::PhantomData<(
        &'a (),
        &'arena (),
        &'__norito_json (),
        &'__norito_arena (),
        [u8; N],
    )>,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictEmpty {}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictOuter {
    child: StrictInner,
    children: Vec<StrictInner>,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
struct Permissive {
    value: u32,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictOptional {
    optional: Option<u32>,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
struct RequiredOptional {
    #[norito(required)]
    optional: Option<u32>,
}
macro_rules! required_record {
    ($name:ident, $derive:path, $ty:ty) => {
        #[derive(Debug, PartialEq, Eq, $derive)]
        struct $name {
            #[norito(required)]
            required: $ty,
            optional: $ty,
        }
    };
}
required_record!(MacroRequiredOptional, JsonDeserialize, Option<u32>);
required_record!(
    FastMacroRequiredOptional,
    norito_derive::FastJson,
    ::core::option::Option<u32>
);
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
struct FlattenedFields {
    label: String,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(deny_unknown_fields)]
struct StrictFlattened {
    id: u32,
    #[norito(flatten)]
    fields: FlattenedFields,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
struct RequiredWithFlatten {
    #[norito(required)]
    optional: Option<u32>,
    #[norito(flatten)]
    fields: FlattenedFields,
}
#[derive(Debug, PartialEq, Eq, norito_derive::FastJson)]
struct FastRequiredOptional {
    #[norito(required)]
    optional: Option<u32>,
}
#[derive(Debug, PartialEq, Eq, norito_derive::FastJson)]
struct FastRenamedRequired {
    #[norito(rename = "wire_value")]
    value: u32,
}
#[derive(Debug, PartialEq, Eq, norito_derive::FastJson)]
struct FastRequiredWithFlatten {
    #[norito(required)]
    optional: Option<u32>,
    #[norito(flatten)]
    fields: FlattenedFields,
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(tag = "kind", content = "payload", deny_unknown_fields)]
enum StrictEvent {
    Unit,
    Record { id: u32 },
}
#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize)]
#[norito(tag = "kind", content = "payload")]
enum RequiredEvent {
    Record {
        #[norito(required)]
        optional: Option<u32>,
    },
}
#[derive(Debug, PartialEq, Eq, norito_derive::FastJson)]
#[norito(tag = "kind", content = "payload")]
enum FastRequiredEvent {
    Record {
        #[norito(required)]
        optional: Option<u32>,
    },
}
fn decode_fast<'a, T: FastFromJson<'a>>(input: &'a str) -> Result<T, norito::Error> {
    let mut walker = TapeWalker::new(input);
    let mut arena = Arena::new();
    T::parse(&mut walker, &mut arena)
}
fn assert_missing_field(error: impl core::fmt::Display, field: &str) {
    let message = error.to_string();
    assert!(
        message.contains(&format!("missing field `{field}`")),
        "unexpected error: {message}"
    );
}
fn assert_structured_missing_field(error: Error, expected: &str) {
    match error {
        Error::MissingField { field } => assert_eq!(field, expected),
        other => panic!("expected missing field `{expected}`, got {other:?}"),
    }
}
fn assert_fast_structured_missing_field(error: norito::Error, expected: &str) {
    match error {
        norito::Error::Json(Error::MissingField { field }) => assert_eq!(field, expected),
        other => panic!("expected missing field `{expected}`, got {other:?}"),
    }
}
fn assert_unknown_field(error: Error, expected: &str) {
    match error {
        Error::UnknownField { field } => assert_eq!(field, expected),
        other => panic!("expected unknown field `{expected}`, got {other:?}"),
    }
}
fn assert_duplicate_field(error: Error, expected: &str) {
    match error {
        Error::DuplicateField { field } => assert_eq!(field, expected),
        other => panic!("expected duplicate field `{expected}`, got {other:?}"),
    }
}
#[test]
fn generic_json_fallback_preserves_roundtrip_and_closed_schema() {
    type Envelope = StrictGeneric<'static, 'static, 'static, 'static, StrictInner, 4>;
    let value = Envelope {
        value: StrictInner { value: 7 },
        marker: core::marker::PhantomData,
    };
    let text = json::to_json(&value).expect("serialize generic strict envelope");
    assert_eq!(
        json::from_slice::<Envelope>(text.as_bytes()).unwrap(),
        value
    );
    assert_eq!(decode_fast::<Envelope>(&text).unwrap(), value);
    for (input, expected) in [
        (r#"{}"#, "missing field `value`"),
        (
            r#"{"value":{"value":7},"future":1}"#,
            "unknown field `future`",
        ),
        (
            r#"{"value":{"value":7},"value":{"value":8}}"#,
            "duplicate field `value`",
        ),
        (
            r#"{"value":{"value":7,"future":1}}"#,
            "unknown field `future`",
        ),
    ] {
        let ordinary = json::from_slice::<Envelope>(input.as_bytes()).unwrap_err();
        let fast = decode_fast::<Envelope>(input).unwrap_err();
        assert!(ordinary.to_string().contains(expected), "{ordinary}");
        assert!(fast.to_string().contains(expected), "{fast}");
    }
}
#[test]
fn named_struct_rejects_unknown_fields_without_changing_permissive_default() {
    let error = json::from_slice::<StrictInner>(br#"{"value":1,"future":2}"#)
        .expect_err("strict struct must reject unknown field");
    assert_unknown_field(error, "future");
    let permissive = json::from_slice::<Permissive>(br#"{"value":1,"future":2}"#)
        .expect("unannotated struct remains permissive");
    assert_eq!(permissive, Permissive { value: 1 });
}
#[test]
fn empty_named_struct_accepts_only_an_empty_object() {
    assert_eq!(
        json::from_slice::<StrictEmpty>(br#"{}"#).expect("empty strict object"),
        StrictEmpty {}
    );
    assert_eq!(
        json::to_json(&StrictEmpty {}).expect("serialize empty strict object"),
        "{}"
    );
    let error = json::from_slice::<StrictEmpty>(br#"{"retired":true}"#)
        .expect_err("empty strict object must reject every field");
    assert_unknown_field(error, "retired");
}
#[test]
fn tagged_unit_enum_requires_explicit_content_member() {
    let canonical = json::from_slice::<StrictEvent>(br#"{"kind":"Unit","payload":null}"#)
        .expect("explicit unit payload");
    assert_eq!(canonical, StrictEvent::Unit);
    let error = json::from_slice::<StrictEvent>(br#"{"kind":"Unit"}"#)
        .expect_err("unit enum content must not be inferred");
    assert_structured_missing_field(error, "payload");
}
#[test]
fn strictness_applies_to_nested_objects_and_array_elements() {
    for input in [
        br#"{"child":{"value":1,"future":2},"children":[]}"#.as_slice(),
        br#"{"child":{"value":1},"children":[{"value":2,"future":3}]}"#.as_slice(),
    ] {
        let error = json::from_slice::<StrictOuter>(input)
            .expect_err("nested strict struct must reject unknown field");
        assert_unknown_field(error, "future");
    }
}
#[test]
fn strict_struct_keeps_optional_absence_and_explicit_null_semantics() {
    assert_eq!(
        json::from_slice::<StrictOptional>(br#"{}"#).expect("omitted option"),
        StrictOptional { optional: None }
    );
    assert_eq!(
        json::from_slice::<StrictOptional>(br#"{"optional":null}"#).expect("explicit null option"),
        StrictOptional { optional: None }
    );
}
#[test]
fn derived_missing_fields_remain_structured_on_every_object_decode_path() {
    assert_structured_missing_field(
        json::from_slice::<StrictInner>(br#"{}"#).expect_err("direct omission must reject"),
        "value",
    );
    let empty: json::Value = json::from_slice(br#"{}"#).expect("empty JSON object");
    assert_structured_missing_field(
        json::from_value::<StrictInner>(empty).expect_err("value omission must reject"),
        "value",
    );
    assert_structured_missing_field(
        json::from_str::<RequiredWithFlatten>(r#"{"label":"known"}"#)
            .expect_err("flatten omission must reject"),
        "optional",
    );
    assert_fast_structured_missing_field(
        decode_fast::<FastRequiredOptional>(r#"{}"#).expect_err("fast omission must reject"),
        "optional",
    );
    assert_fast_structured_missing_field(
        decode_fast::<FastRenamedRequired>(r#"{}"#).expect_err("renamed fast omission must reject"),
        "wire_value",
    );
    assert_fast_structured_missing_field(
        decode_fast::<FastRequiredWithFlatten>(r#"{"label":"known"}"#)
            .expect_err("fast flatten omission must reject"),
        "optional",
    );
    assert_structured_missing_field(
        json::from_str::<RequiredEvent>(r#"{"kind":"Record","payload":{}}"#)
            .expect_err("enum omission must reject"),
        "optional",
    );
    assert_fast_structured_missing_field(
        decode_fast::<FastRequiredEvent>(r#"{"kind":"Record","payload":{}}"#)
            .expect_err("fast enum omission must reject"),
        "optional",
    );
}
#[test]
fn macro_forwarded_option_types_preserve_required_keys_and_explicit_null() {
    for (input, required) in [
        (r#"{"required":null}"#, None),
        (r#"{"required":7}"#, Some(7)),
    ] {
        let expected = MacroRequiredOptional {
            required,
            optional: None,
        };
        assert_eq!(
            json::from_str::<MacroRequiredOptional>(input).unwrap(),
            expected
        );
        assert_eq!(
            json::from_json_fast::<MacroRequiredOptional>(input).unwrap(),
            expected
        );
        assert_eq!(
            decode_fast::<FastMacroRequiredOptional>(input).unwrap(),
            FastMacroRequiredOptional {
                required,
                optional: None,
            }
        );
    }
    assert_structured_missing_field(
        json::from_str::<MacroRequiredOptional>(r#"{}"#)
            .expect_err("macro-forwarded required key cannot be omitted"),
        "required",
    );
    assert_missing_field(
        json::from_json_fast::<MacroRequiredOptional>(r#"{}"#)
            .expect_err("fallback macro-forwarded required key cannot be omitted"),
        "required",
    );
    assert_fast_structured_missing_field(
        decode_fast::<FastMacroRequiredOptional>(r#"{}"#)
            .expect_err("fast macro-forwarded required key cannot be omitted"),
        "required",
    );
}
#[test]
fn required_option_distinguishes_omission_from_explicit_null_on_normal_and_fallback_paths() {
    let expected = RequiredOptional { optional: None };
    assert_eq!(
        json::from_slice::<RequiredOptional>(br#"{"optional":null}"#)
            .expect("explicit null on normal path"),
        expected
    );
    assert_missing_field(
        json::from_slice::<RequiredOptional>(br#"{}"#).expect_err("omission must reject"),
        "optional",
    );
    assert_eq!(
        json::from_json_fast::<RequiredOptional>(r#"{"optional":null}"#)
            .expect("explicit null on fallback fast path"),
        expected
    );
    assert_missing_field(
        json::from_json_fast::<RequiredOptional>(r#"{}"#)
            .expect_err("fallback omission must reject"),
        "optional",
    );
}
#[test]
fn required_option_is_enforced_by_direct_fast_and_flatten_paths() {
    assert_eq!(
        decode_fast::<FastRequiredOptional>(r#"{"optional":null}"#)
            .expect("explicit null on direct fast path"),
        FastRequiredOptional { optional: None }
    );
    assert_missing_field(
        decode_fast::<FastRequiredOptional>(r#"{}"#).expect_err("fast omission must reject"),
        "optional",
    );
    let normal = r#"{"optional":null,"label":"known"}"#;
    assert_eq!(
        json::from_str::<RequiredWithFlatten>(normal).expect("normal flatten path"),
        RequiredWithFlatten {
            optional: None,
            fields: FlattenedFields {
                label: "known".to_owned(),
            },
        }
    );
    assert_missing_field(
        json::from_str::<RequiredWithFlatten>(r#"{"label":"known"}"#)
            .expect_err("normal flatten omission must reject"),
        "optional",
    );
    assert_eq!(
        decode_fast::<FastRequiredWithFlatten>(normal).expect("fast flatten path"),
        FastRequiredWithFlatten {
            optional: None,
            fields: FlattenedFields {
                label: "known".to_owned(),
            },
        }
    );
    assert_missing_field(
        decode_fast::<FastRequiredWithFlatten>(r#"{"label":"known"}"#)
            .expect_err("fast flatten omission must reject"),
        "optional",
    );
}
#[test]
fn required_option_is_enforced_in_tagged_enum_named_fields() {
    let explicit = r#"{"kind":"Record","payload":{"optional":null}}"#;
    assert_eq!(
        json::from_str::<RequiredEvent>(explicit).expect("normal enum explicit null"),
        RequiredEvent::Record { optional: None }
    );
    assert_missing_field(
        json::from_str::<RequiredEvent>(r#"{"kind":"Record","payload":{}}"#)
            .expect_err("normal enum omission must reject"),
        "optional",
    );
    assert_eq!(
        decode_fast::<FastRequiredEvent>(explicit).expect("fast enum explicit null"),
        FastRequiredEvent::Record { optional: None }
    );
    assert_missing_field(
        decode_fast::<FastRequiredEvent>(r#"{"kind":"Record","payload":{}}"#)
            .expect_err("fast enum omission must reject"),
        "optional",
    );
}
#[test]
fn strict_flatten_rejects_fields_not_consumed_by_flattened_value() {
    let decoded = json::from_slice::<StrictFlattened>(br#"{"id":7,"label":"known"}"#)
        .expect("known flattened fields");
    assert_eq!(
        decoded,
        StrictFlattened {
            id: 7,
            fields: FlattenedFields {
                label: "known".to_owned(),
            },
        }
    );
    let error =
        json::from_slice::<StrictFlattened>(br#"{"id":7,"label":"known","unclaimed":true}"#)
            .expect_err("unclaimed flattened field must reject");
    assert_unknown_field(error, "unclaimed");
}
#[test]
fn tagged_enum_rejects_unknown_envelope_and_variant_fields() {
    let direct_envelope =
        json::from_json::<StrictEvent>(r#"{"kind":"Unit","payload":null,"future":false}"#)
            .expect_err("strict enum envelope must reject unknown field on direct parser path");
    assert_unknown_field(direct_envelope, "future");
    let envelope =
        json::from_slice::<StrictEvent>(br#"{"kind":"Unit","payload":null,"future":false}"#)
            .expect_err("strict enum envelope must reject unknown field");
    assert_unknown_field(envelope, "future");
    let payload =
        json::from_slice::<StrictEvent>(br#"{"kind":"Record","payload":{"id":1,"future":false}}"#)
            .expect_err("strict enum payload must reject unknown field");
    assert_unknown_field(payload, "future");
}
#[test]
fn tagged_enum_rejects_duplicate_tag_and_content_on_direct_parser_path() {
    let duplicate_tag =
        json::from_json::<StrictEvent>(r#"{"kind":"Unit","kind":"Unit","payload":null}"#)
            .expect_err("duplicate tag must reject");
    assert_duplicate_field(duplicate_tag, "kind");
    let duplicate_content =
        json::from_json::<StrictEvent>(r#"{"kind":"Unit","payload":null,"payload":null}"#)
            .expect_err("duplicate content must reject");
    assert_duplicate_field(duplicate_content, "payload");
}
#[test]
fn value_conversion_path_enforces_unknown_fields() {
    let value: json::Value =
        json::from_slice(br#"{"value":1,"future":2}"#).expect("generic JSON value");
    let error = json::from_value::<StrictInner>(value)
        .expect_err("strict json_from_value must reject unknown field");
    assert_unknown_field(error, "future");
}
#[test]
fn preparse_rejects_escaped_duplicate_keys_recursively() {
    let error =
        json::from_slice::<StrictOuter>(br#"{"child":{"value":1,"\u0076alue":2},"children":[]}"#)
            .expect_err("escaped duplicate key must reject before typed decode");
    assert_duplicate_field(error, "value");
}

// This type deliberately has no JSON traits: the helper must own both directions and the
// derive must not add a default JsonDeserialize bound for the named enum field.
#[derive(Debug, PartialEq, Eq)]
struct HelperBytes([u8; 4]);

mod helper_bytes {
    use super::HelperBytes;
    use norito::json::{self, JsonDeserialize as _, JsonSerialize as _};

    pub(super) fn serialize(value: &HelperBytes, out: &mut String) {
        value.0.to_vec().json_serialize(out);
    }

    pub(super) fn serialize_bounded(
        value: &HelperBytes,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        value.0.to_vec().json_serialize_to(out)
    }

    pub(super) fn deserialize(parser: &mut json::Parser<'_>) -> Result<HelperBytes, json::Error> {
        let bytes = Vec::<u8>::json_deserialize(parser)?;
        let bytes = bytes.try_into().map_err(|_: Vec<u8>| {
            json::Error::Message("expected exactly four helper bytes".into())
        })?;
        Ok(HelperBytes(bytes))
    }
}

#[derive(Debug, PartialEq, Eq, JsonDeserialize, JsonSerialize, norito_derive::FastJson)]
#[norito(
    tag = "kind",
    content = "payload",
    deny_unknown_fields,
    no_fast_from_json
)]
enum StrictHelperEvent {
    Combined {
        #[norito(json = "helper_bytes")]
        bytes: HelperBytes,
    },
    Separate {
        #[norito(
            with = "helper_bytes",
            bounded_with = "helper_bytes::serialize_bounded"
        )]
        bytes: HelperBytes,
    },
}

#[test]
fn named_enum_helpers_roundtrip_without_default_field_traits_and_remain_strict() {
    for (kind, value) in [
        (
            "Combined",
            StrictHelperEvent::Combined {
                bytes: HelperBytes([1, 2, 3, 4]),
            },
        ),
        (
            "Separate",
            StrictHelperEvent::Separate {
                bytes: HelperBytes([1, 2, 3, 4]),
            },
        ),
    ] {
        let expected = format!(r#"{{"kind":"{kind}","payload":{{"bytes":[1,2,3,4]}}}}"#);
        assert_eq!(json::to_json(&value).unwrap(), expected);
        assert_eq!(
            json::to_json_bounded(&value, expected.len()).unwrap(),
            expected
        );
        assert!(json::to_json_bounded(&value, expected.len() - 1).is_err());
        assert_eq!(
            json::from_str::<StrictHelperEvent>(&expected).unwrap(),
            value
        );
        assert_eq!(decode_fast::<StrictHelperEvent>(&expected).unwrap(), value);
        assert_eq!(
            json::from_slice::<StrictHelperEvent>(expected.as_bytes()).unwrap(),
            value
        );
        let parsed = json::from_str::<json::Value>(&expected).unwrap();
        assert_eq!(
            json::from_value::<StrictHelperEvent>(parsed).unwrap(),
            value
        );
        for payload in [
            r#"{}"#,
            r#"{"bytes":[1,2,3]}"#,
            r#"{"bytes":[1,2,3,4,5]}"#,
            r#"{"bytes":[1,2,3,256]}"#,
            r#"{"bytes":"01020304"}"#,
            r#"{"bytes":[1,2,3,4],"bytes":[1,2,3,4]}"#,
            r#"{"bytes":[1,2,3,4],"unexpected":true}"#,
        ] {
            let wrong = format!(r#"{{"kind":"{kind}","payload":{payload}}}"#);
            assert!(
                json::from_str::<StrictHelperEvent>(&wrong).is_err(),
                "{wrong}"
            );
            assert!(decode_fast::<StrictHelperEvent>(&wrong).is_err(), "{wrong}");
        }
        let unknown = expected.replacen('{', r#"{"unexpected":true,"#, 1);
        assert!(json::from_str::<StrictHelperEvent>(&unknown).is_err());
        assert!(decode_fast::<StrictHelperEvent>(&unknown).is_err());
    }
}

// A macro's ty fragment reaches derives as an invisible Type::Group. Both fields must retain
// Option semantics, while only the explicitly required key must be present in JSON.
macro_rules! forwarded_normal_options {
    ($name:ident, $ty:ty) => {
        #[derive(
            Debug,
            PartialEq,
            Eq,
            JsonDeserialize,
            JsonSerialize,
            norito::Encode,
            norito::Decode,
            norito::NoritoSchema,
        )]
        #[norito_schema(name = "norito_derive::strict_json::ForwardedNormalOptions")]
        #[norito(deny_unknown_fields)]
        struct $name {
            #[norito(required)]
            required: $ty,
            optional: $ty,
        }
    };
}
macro_rules! forwarded_fast_options {
    ($name:ident, $ty:ty) => {
        #[derive(Debug, PartialEq, Eq, norito_derive::FastJson)]
        #[norito(deny_unknown_fields)]
        struct $name {
            #[norito(required)]
            required: $ty,
            optional: $ty,
        }
    };
}
forwarded_normal_options!(ForwardedNormalOptions, Option<u32>);
forwarded_fast_options!(ForwardedFastOptions, Option<u32>);

#[test]
fn macro_forwarded_required_option_retains_explicit_key_on_normal_and_direct_fast_paths() {
    let expected = ForwardedNormalOptions {
        required: None,
        optional: None,
    };
    let original = r#"{"required":null}"#;
    assert_eq!(
        json::from_json::<ForwardedNormalOptions>(original).unwrap(),
        expected
    );
    assert_eq!(
        json::from_json_fast::<ForwardedNormalOptions>(original).unwrap(),
        expected
    );
    assert_eq!(
        decode_fast::<ForwardedFastOptions>(original).unwrap(),
        ForwardedFastOptions {
            required: None,
            optional: None
        }
    );
    assert_structured_missing_field(
        json::from_json::<ForwardedNormalOptions>(r#"{}"#).unwrap_err(),
        "required",
    );
    assert_missing_field(
        json::from_json_fast::<ForwardedNormalOptions>(r#"{}"#).unwrap_err(),
        "required",
    );
    assert_fast_structured_missing_field(
        decode_fast::<ForwardedFastOptions>(r#"{}"#).unwrap_err(),
        "required",
    );
    let canonical = r#"{"required":null,"optional":null}"#;
    assert_eq!(json::to_json(&expected).unwrap(), canonical);
    let bytes = norito::to_bytes(&expected).unwrap();
    assert_eq!(
        norito::decode_from_bytes::<ForwardedNormalOptions>(&bytes).unwrap(),
        expected
    );
}

#[test]
fn macro_forwarded_optional_option_keeps_absence_null_and_values_on_both_json_paths() {
    for (original, required, optional) in [
        (r#"{"required":null}"#, None, None),
        (r#"{"required":null,"optional":null}"#, None, None),
        (r#"{"required":7}"#, Some(7), None),
        (r#"{"required":7,"optional":8}"#, Some(7), Some(8)),
    ] {
        let expected = ForwardedNormalOptions { required, optional };
        assert_eq!(
            json::from_json::<ForwardedNormalOptions>(original).unwrap(),
            expected
        );
        assert_eq!(
            json::from_json_fast::<ForwardedNormalOptions>(original).unwrap(),
            expected
        );
        assert_eq!(
            decode_fast::<ForwardedFastOptions>(original).unwrap(),
            ForwardedFastOptions { required, optional }
        );
        let bytes = norito::to_bytes(&expected).unwrap();
        assert_eq!(
            norito::decode_from_bytes::<ForwardedNormalOptions>(&bytes).unwrap(),
            expected
        );
    }
}

macro_rules! forwarded_option_record {
    ($required:ty, $optional:ty) => {
        #[derive(
            Debug,
            PartialEq,
            Eq,
            JsonDeserialize,
            JsonSerialize,
            norito_derive::FastJson,
            norito::Encode,
            norito::Decode,
            norito::NoritoSchema,
        )]
        #[norito(no_fast_from_json, deny_unknown_fields)]
        #[norito_schema(name = "norito.test.ForwardedOptionRecord")]
        struct ForwardedOptionRecord {
            #[norito(required)]
            required: $required,
            optional: $optional,
        }
    };
}
forwarded_option_record!(Option<u32>, ::core::option::Option<u32>);

#[test]
fn forwarded_macro_option_preserves_required_null_and_optional_omission_on_every_json_path() {
    for (input, expected) in [
        (
            r#"{"required":null}"#,
            ForwardedOptionRecord {
                required: None,
                optional: None,
            },
        ),
        (
            r#"{"required":7,"optional":9}"#,
            ForwardedOptionRecord {
                required: Some(7),
                optional: Some(9),
            },
        ),
    ] {
        assert_eq!(
            json::from_slice::<ForwardedOptionRecord>(input.as_bytes()).unwrap(),
            expected
        );
        assert_eq!(
            json::from_value::<ForwardedOptionRecord>(json::from_str(input).unwrap()).unwrap(),
            expected
        );
        assert_eq!(
            decode_fast::<ForwardedOptionRecord>(input).unwrap(),
            expected
        );
        let binary = norito::encode_canonical(&expected).unwrap();
        assert_eq!(
            norito::decode_canonical::<ForwardedOptionRecord>(&binary).unwrap(),
            expected
        );
        let encoded = json::to_json(&expected).unwrap();
        assert!(encoded.contains("\"required\":"));
        assert_eq!(
            json::from_str::<ForwardedOptionRecord>(&encoded).unwrap(),
            expected
        );
    }
    for input in [r#"{}"#, r#"{"optional":9}"#] {
        assert_missing_field(
            json::from_slice::<ForwardedOptionRecord>(input.as_bytes()).unwrap_err(),
            "required",
        );
        assert_missing_field(
            json::from_value::<ForwardedOptionRecord>(json::from_str(input).unwrap()).unwrap_err(),
            "required",
        );
        assert_missing_field(
            decode_fast::<ForwardedOptionRecord>(input).unwrap_err(),
            "required",
        );
    }
    for input in [
        r#"{"required":null,"required":7}"#,
        r#"{"required":null,"extra":7}"#,
    ] {
        assert!(json::from_slice::<ForwardedOptionRecord>(input.as_bytes()).is_err());
        assert!(decode_fast::<ForwardedOptionRecord>(input).is_err());
    }
}
