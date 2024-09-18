extern crate alloc;

use core::any::TypeId;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(Decode, Encode, IntoSchema)]
enum Foo {
    Variant1(bool),
    Variant2(String),
    Variant3(Result<bool, String>),
    #[codec(skip)]
    _Variant4,
    Variant5(i32),
}

#[test]
fn default_discriminants() {
    use alloc::collections::BTreeMap;

    use IntMode::*;
    use Metadata::*;

    let expected = vec![
        (
            TypeId::of::<core::result::Result<bool, alloc::string::String>>(),
            MetaMapEntry {
                type_id: "Result<bool, String>".to_owned(),
                type_name: "Result<bool, String>".to_owned(),
                metadata: Result(ResultMeta {
                    ok: TypeId::of::<bool>(),
                    err: TypeId::of::<alloc::string::String>(),
                }),
            },
        ),
        (
            TypeId::of::<alloc::string::String>(),
            MetaMapEntry {
                type_id: "String".to_owned(),
                type_name: "String".to_owned(),
                metadata: String,
            },
        ),
        (
            TypeId::of::<bool>(),
            MetaMapEntry {
                type_id: "bool".to_owned(),
                type_name: "bool".to_owned(),
                metadata: Bool,
            },
        ),
        (
            TypeId::of::<Foo>(),
            MetaMapEntry {
                type_id: "Foo".to_owned(),
                type_name: "Foo".to_owned(),
                metadata: Enum(EnumMeta {
                    variants: vec![
                        EnumVariant {
                            tag: "Variant1".to_owned(),
                            discriminant: 0,
                            ty: Some(TypeId::of::<bool>()),
                        },
                        EnumVariant {
                            tag: "Variant2".to_owned(),
                            discriminant: 1,
                            ty: Some(TypeId::of::<alloc::string::String>()),
                        },
                        EnumVariant {
                            tag: "Variant3".to_owned(),
                            discriminant: 2,
                            ty: Some(TypeId::of::<
                                core::result::Result<bool, alloc::string::String>,
                            >()),
                        },
                        EnumVariant {
                            tag: "Variant5".to_owned(),
                            discriminant: 4,
                            ty: Some(TypeId::of::<i32>()),
                        },
                    ],
                }),
            },
        ),
        (
            TypeId::of::<i32>(),
            MetaMapEntry {
                type_id: "i32".to_owned(),
                type_name: "i32".to_owned(),
                metadata: Int(FixedWidth),
            },
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Foo::schema(), expected);
}
