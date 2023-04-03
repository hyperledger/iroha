// Lint triggers somewhere in Encode/Decode
#![allow(
    trivial_numeric_casts,
    clippy::unnecessary_cast,
    clippy::std_instead_of_alloc
)]

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
        core::any::TypeId::of::<Foo>(),
        (
            "Foo".to_owned(),
            Metadata::Enum(EnumMeta {
                variants: vec![
                    EnumVariant {
                        tag: "A".to_owned(),
                        discriminant: 1,
                        ty: None,
                    },
                    EnumVariant {
                        tag: "B".to_owned(),
                        discriminant: 77,
                        ty: None,
                    },
                    EnumVariant {
                        tag: "C".to_owned(),
                        discriminant: 2,
                        ty: None,
                    },
                    EnumVariant {
                        tag: "D".to_owned(),
                        discriminant: 99,
                        ty: None,
                    },
                ],
            }),
        ),
    )]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Foo::schema(), expected_meta);
}
