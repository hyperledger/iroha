use iroha_schema::prelude::*;
use parity_scale_codec::Encode;

#[derive(IntoSchema, Encode)]
struct Foo {
    #[codec(compact)]
    u8_compact: u8,
    u8_fixed: u8,
    #[codec(compact)]
    u16_compact: u16,
    u16_fixed: u16,
    #[codec(compact)]
    u32_compact: u32,
    u32_fixed: u32,
    #[codec(compact)]
    u64_compact: u64,
    u64_fixed: u64,
    #[codec(compact)]
    u128_compact: u128,
    u128_fixed: u128,
}

#[test]
fn compact() {
    use std::collections::BTreeMap;

    use IntMode::*;
    use Metadata::*;

    let expected = vec![
        ("Compact<u128>".to_owned(), Int(IntMode::Compact)),
        ("Compact<u16>".to_owned(), Int(IntMode::Compact)),
        ("Compact<u32>".to_owned(), Int(IntMode::Compact)),
        ("Compact<u64>".to_owned(), Int(IntMode::Compact)),
        ("Compact<u8>".to_owned(), Int(IntMode::Compact)),
        (
            "numbers_compact_and_fixed::Foo".to_owned(),
            Struct(NamedFieldsMeta {
                declarations: vec![
                    Declaration {
                        name: "u8_compact".to_owned(),
                        ty: "Compact<u8>".to_owned(),
                    },
                    Declaration {
                        name: "u8_fixed".to_owned(),
                        ty: "u8".to_owned(),
                    },
                    Declaration {
                        name: "u16_compact".to_owned(),
                        ty: "Compact<u16>".to_owned(),
                    },
                    Declaration {
                        name: "u16_fixed".to_owned(),
                        ty: "u16".to_owned(),
                    },
                    Declaration {
                        name: "u32_compact".to_owned(),
                        ty: "Compact<u32>".to_owned(),
                    },
                    Declaration {
                        name: "u32_fixed".to_owned(),
                        ty: "u32".to_owned(),
                    },
                    Declaration {
                        name: "u64_compact".to_owned(),
                        ty: "Compact<u64>".to_owned(),
                    },
                    Declaration {
                        name: "u64_fixed".to_owned(),
                        ty: "u64".to_owned(),
                    },
                    Declaration {
                        name: "u128_compact".to_owned(),
                        ty: "Compact<u128>".to_owned(),
                    },
                    Declaration {
                        name: "u128_fixed".to_owned(),
                        ty: "u128".to_owned(),
                    },
                ],
            }),
        ),
        ("u128".to_owned(), Int(FixedWidth)),
        ("u16".to_owned(), Int(FixedWidth)),
        ("u32".to_owned(), Int(FixedWidth)),
        ("u64".to_owned(), Int(FixedWidth)),
        ("u8".to_owned(), Int(FixedWidth)),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Foo::get_schema(), expected);
}
