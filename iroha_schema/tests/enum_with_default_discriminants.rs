use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(IntoSchema, Encode, Decode)]
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
    use std::collections::BTreeMap;

    use IntMode::*;
    use Metadata::*;

    let expected = vec![
        (
            "Result<bool, String>".to_owned(),
            Result(ResultMeta {
                ok: "bool".to_owned(),
                err: "String".to_owned(),
            }),
        ),
        ("String".to_owned(), String),
        ("bool".to_owned(), Bool),
        (
            "enum_with_default_discriminants::Foo".to_owned(),
            Enum(EnumMeta {
                variants: vec![
                    EnumVariant {
                        name: "Variant1".to_owned(),
                        discriminant: 0,
                        ty: Some("bool".to_owned()),
                    },
                    EnumVariant {
                        name: "Variant2".to_owned(),
                        discriminant: 1,
                        ty: Some("String".to_owned()),
                    },
                    EnumVariant {
                        name: "Variant3".to_owned(),
                        discriminant: 2,
                        ty: Some("Result<bool, String>".to_owned()),
                    },
                    EnumVariant {
                        name: "Variant5".to_owned(),
                        discriminant: 4,
                        ty: Some("i32".to_owned()),
                    },
                ],
            }),
        ),
        ("i32".to_owned(), Int(FixedWidth)),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Foo::get_schema(), expected);
}
