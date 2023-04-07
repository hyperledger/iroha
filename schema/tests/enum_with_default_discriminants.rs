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
            (
                "Result<Bool, String>".to_owned(),
                Result(ResultMeta {
                    ok: TypeId::of::<bool>(),
                    err: TypeId::of::<alloc::string::String>(),
                }),
            ),
        ),
        (
            TypeId::of::<alloc::string::String>(),
            ("String".to_owned(), String),
        ),
        (TypeId::of::<bool>(), ("Bool".to_owned(), Bool)),
        (
            TypeId::of::<Foo>(),
            (
                "Foo".to_owned(),
                Enum(EnumMeta {
                    variants: vec![
                        EnumVariant {
                            tag: "Variant1".to_owned(),
                            ty: Some(TypeId::of::<bool>()),
                        },
                        EnumVariant {
                            tag: "Variant2".to_owned(),
                            ty: Some(TypeId::of::<alloc::string::String>()),
                        },
                        EnumVariant {
                            tag: "Variant3".to_owned(),
                            ty: Some(TypeId::of::<
                                core::result::Result<bool, alloc::string::String>,
                            >()),
                        },
                        EnumVariant {
                            tag: "Variant5".to_owned(),
                            ty: Some(TypeId::of::<i32>()),
                        },
                    ],
                }),
            ),
        ),
        (TypeId::of::<i32>(), ("i32".to_owned(), Int(FixedWidth))),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Foo::schema(), expected);
}
