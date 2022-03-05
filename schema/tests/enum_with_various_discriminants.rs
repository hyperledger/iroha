// Lint triggers somewhere in Encode/Decode
#![allow(trivial_numeric_casts, clippy::unnecessary_cast)]

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(IntoSchema, Encode, Decode)]
enum Foo {
    #[codec(index = 1)]
    A,
    B = 77,
    C,
    #[codec(index = 99)]
    D = 88,
}

#[test]
fn discriminant() {
    use std::collections::BTreeMap;

    let expected_meta = vec![(
        "enum_with_various_discriminants::Foo".to_owned(),
        Metadata::Enum(EnumMeta {
            variants: vec![
                EnumVariant {
                    name: "A".to_owned(),
                    discriminant: 1,
                    ty: None,
                },
                EnumVariant {
                    name: "B".to_owned(),
                    discriminant: 77,
                    ty: None,
                },
                EnumVariant {
                    name: "C".to_owned(),
                    discriminant: 2,
                    ty: None,
                },
                EnumVariant {
                    name: "D".to_owned(),
                    discriminant: 99,
                    ty: None,
                },
            ],
        }),
    )]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(expected_meta, Foo::get_schema());
}
