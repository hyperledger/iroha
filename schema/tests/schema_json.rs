//! This test checks how the json-serialized schema looks like.

#![allow(dead_code)]
#![allow(unused_tuple_struct_fields)]

use iroha_schema::IntoSchema;
use serde_json::json;

/// It expects to have three parameters: a type definition item, an expected schema type name and a JSON schema.
///
/// The json is passed to the `serde_json::json!` macro, so it can be a string, an array or an object.
///
/// Only the schema of the type itself is checked, not the schema of its fields.
///
/// NOTE: this macro doesn't support generics.
macro_rules! check_schema {
    ($(#[$($meta:tt)*])* struct $ty:ident, $type_name:ident, $json:tt) => {{
        #[derive(IntoSchema)]
        $(#[$($meta)*])*
        struct $ty;
        check_schema!(@impl $ty, $type_name, $json);
    }};
    ($(#[$($meta:tt)*])* struct $ty:ident ($($body:tt)*), $type_name:ident, $json:tt) => {{
        #[derive(IntoSchema)]
        $(#[$($meta)*])*
        struct $ty($($body)*);
        check_schema!(@impl $ty, $type_name, $json);
    }};
    ($(#[$($meta:tt)*])* struct $ty:ident {$($body:tt)*}, $type_name:ident, $json:tt) => {{
        #[derive(IntoSchema)]
        $(#[$($meta)*])*
        struct $ty {$($body)*}
        check_schema!(@impl $ty, $type_name, $json);
    }};
    ($(#[$($meta:tt)*])* enum $ty:ident {$($body:tt)*}, $type_name:ident, $json:tt) => {{
        #[derive(IntoSchema)]
        $(#[$($meta)*])*
        enum $ty {$($body)*}
        check_schema!(@impl $ty, $type_name, $json);
    }};
    (@impl $ty:ident, $type_name:ident, $json:tt) => {{
        assert_eq!(
            $ty::type_name(),
            stringify!($type_name),
            "Type name of {} is not equal to the expected one",
            stringify!($ty)
        );
        let __schema = serde_json::value::to_value(&$ty::schema())
            .expect("Failed to serialize schema to JSON");
        assert_eq!(
            __schema.get(&$ty::type_name()).unwrap().clone(),
            json!($json),
            "Schema of {} is not equal to the expected one",
            stringify!($ty)
        );
    }};
}

#[test]
fn test_struct() {
    check_schema!(
        struct EmptyNamedStruct {},
        EmptyNamedStruct,
        {"Struct": []}
    );

    // this behaviour is weird...
    check_schema!(
        struct EmptyTupleStruct(),
        EmptyTupleStruct,
        null
    );
    check_schema!(
        struct UnitStruct,
        UnitStruct,
        null
    );

    check_schema!(
        struct NormalStruct {
            normal_field_1: u32,
            normal_field_2: u32,
        },
        NormalStruct,
        {"Struct": [
            {"name": "normal_field_1", "type": "u32"},
            {"name": "normal_field_2", "type": "u32"}
        ]}
    );
    check_schema!(
        struct NewtypeStruct(u32),
        NewtypeStruct,
        "u32"
    );
    check_schema!(
        struct TupleStruct(u32, u32),
        TupleStruct,
        {"Tuple": [
            "u32", "u32"
        ]}
    );
}

#[test]
fn test_struct_codec_attr() {
    check_schema!(
        struct SkipField {
            #[codec(skip)]
            skipped_field: u32,
            normal_field: u32,
        },
        SkipField,
        {"Struct": [
            {"name": "normal_field", "type": "u32"}
        ]}
    );
    check_schema!(
        struct CompactField {
            #[codec(compact)]
            compact_field: u32,
        },
        CompactField,
        {"Struct": [
            {"name": "compact_field", "type": "Compact<u32>"}
        ]}
    );
}

#[test]
fn test_transparent() {
    check_schema!(
        #[schema(transparent)]
        struct TransparentStruct(u32),
        u32,
        {"Int": "FixedWidth"}
    );
    check_schema!(
        #[schema(transparent = "u32")]
        struct TransparentStructExplicitInt {
            a: u32,
            b: i32,
        },
        u32,
        {"Int": "FixedWidth"}
    );
    check_schema!(
        #[schema(transparent = "String")]
        struct TransparentStructExplicitString {
            a: u32,
            b: i32,
        },
        String,
        "String"
    );
    check_schema!(
        #[schema(transparent = "String")]
        enum TransparentEnum {
            Variant1,
            Variant2,
        },
        String,
        "String"
    );
}

#[test]
fn test_enum() {
    check_schema!(
        enum EmptyEnum {},
        EmptyEnum,
        {"Enum": []}
    );
    check_schema!(
        enum DatalessEnum {
            Variant1,
            Variant2,
        },
        DatalessEnum,
        {"Enum": [
            {"discriminant": 0, "tag": "Variant1"},
            {"discriminant": 1, "tag": "Variant2"}
        ]}
    );
    check_schema!(
        enum DataEnum {
            Variant1(u32),
            // these variants are not supported by the schema
            //Variant2(u32, u32),
            //Variant2 { a: u32, b: u32 },
            Variant3(String)
        },
        DataEnum,
        {"Enum": [
            {"discriminant": 0, "tag": "Variant1", "type": "u32"},
            {"discriminant": 1, "tag": "Variant3", "type": "String"}
        ]}
    );
}

#[test]
fn test_enum_codec_attr() {
    check_schema!(
        enum SkipEnum {
            #[codec(skip)]
            Variant1,
            Variant2,
        },
        SkipEnum,
        {"Enum": [
            {"discriminant": 1, "tag": "Variant2"}
        ]}
    );
    check_schema!(
        enum IndexEnum {
            // ERROR: Fieldless enums with explicit discriminants are not allowed
            // Variant1 = 12,
            #[codec(index = 42)]
            Variant2,
        },
        IndexEnum,
        {"Enum": [
            {"discriminant": 42, "tag": "Variant2"}
        ]}
    );
    check_schema!(
        enum IndexDataEnum {
            #[codec(index = 42)]
            Variant2(u32),
        },
        IndexDataEnum,
        {"Enum": [
            {"discriminant": 42, "tag": "Variant2", "type": "u32"}
        ]}
    );
}
