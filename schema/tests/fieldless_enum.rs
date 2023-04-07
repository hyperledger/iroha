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
    A,
    B,
    C,
    D,
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
                        ty: None,
                    },
                    EnumVariant {
                        tag: "B".to_owned(),
                        ty: None,
                    },
                    EnumVariant {
                        tag: "C".to_owned(),
                        ty: None,
                    },
                    EnumVariant {
                        tag: "D".to_owned(),
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
