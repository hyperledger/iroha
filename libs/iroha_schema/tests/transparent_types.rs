extern crate alloc;

use core::any::TypeId;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

/// This type tests transparent type inference
#[derive(Decode, Encode, IntoSchema)]
#[schema(transparent)]
struct TransparentStruct(u32);

/// This type tests explicit transparent type (u32)
#[derive(Decode, Encode, IntoSchema)]
#[schema(transparent = "u32")]
struct TransparentStructExplicitInt {
    a: u32,
    b: i32,
}

/// This type tests explicit transparent type (String)
#[derive(Decode, Encode, IntoSchema)]
#[schema(transparent = "String")]
struct TransparentStructExplicitString {
    a: u32,
    b: i32,
}

/// This type tests transparent type being an enum
#[derive(Decode, Encode, IntoSchema)]
#[schema(transparent = "String")]
enum TransparentEnum {
    Variant1,
    Variant2,
}

#[test]
fn transparent_types() {
    use alloc::collections::BTreeMap;

    use IntMode::*;
    use Metadata::*;

    let expected = [
        (
            TypeId::of::<std::string::String>(),
            ("String".to_string(), String),
        ),
        (TypeId::of::<u32>(), ("u32".to_string(), Int(FixedWidth))),
        (
            TypeId::of::<TransparentStruct>(),
            ("u32".to_string(), Int(FixedWidth)),
        ),
        (
            TypeId::of::<TransparentStructExplicitInt>(),
            ("u32".to_string(), Int(FixedWidth)),
        ),
        (
            TypeId::of::<TransparentStructExplicitString>(),
            ("String".to_string(), String),
        ),
        (
            TypeId::of::<TransparentEnum>(),
            ("String".to_string(), String),
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    let mut schema = MetaMap::new();
    TransparentStruct::update_schema_map(&mut schema);
    TransparentStructExplicitInt::update_schema_map(&mut schema);
    TransparentStructExplicitString::update_schema_map(&mut schema);
    TransparentEnum::update_schema_map(&mut schema);

    assert_eq!(schema, expected);
}
