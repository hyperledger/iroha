extern crate alloc;

use core::any::TypeId;

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
    use alloc::collections::BTreeMap;

    use IntMode::*;
    use Metadata::*;

    let expected = vec![
        (
            TypeId::of::<iroha_schema::Compact<u128>>(),
            ("Compact<u128>".to_owned(), Int(IntMode::Compact)),
        ),
        (
            TypeId::of::<iroha_schema::Compact<u16>>(),
            ("Compact<u16>".to_owned(), Int(IntMode::Compact)),
        ),
        (
            TypeId::of::<iroha_schema::Compact<u32>>(),
            ("Compact<u32>".to_owned(), Int(IntMode::Compact)),
        ),
        (
            TypeId::of::<iroha_schema::Compact<u64>>(),
            ("Compact<u64>".to_owned(), Int(IntMode::Compact)),
        ),
        (
            TypeId::of::<iroha_schema::Compact<u8>>(),
            ("Compact<u8>".to_owned(), Int(IntMode::Compact)),
        ),
        (
            TypeId::of::<Foo>(),
            (
                "Foo".to_owned(),
                Struct(NamedFieldsMeta {
                    declarations: vec![
                        Declaration {
                            name: "u8_compact".to_owned(),
                            ty: TypeId::of::<iroha_schema::Compact<u8>>(),
                        },
                        Declaration {
                            name: "u8_fixed".to_owned(),
                            ty: TypeId::of::<u8>(),
                        },
                        Declaration {
                            name: "u16_compact".to_owned(),
                            ty: TypeId::of::<iroha_schema::Compact<u16>>(),
                        },
                        Declaration {
                            name: "u16_fixed".to_owned(),
                            ty: TypeId::of::<u16>(),
                        },
                        Declaration {
                            name: "u32_compact".to_owned(),
                            ty: TypeId::of::<iroha_schema::Compact<u32>>(),
                        },
                        Declaration {
                            name: "u32_fixed".to_owned(),
                            ty: TypeId::of::<u32>(),
                        },
                        Declaration {
                            name: "u64_compact".to_owned(),
                            ty: TypeId::of::<iroha_schema::Compact<u64>>(),
                        },
                        Declaration {
                            name: "u64_fixed".to_owned(),
                            ty: TypeId::of::<u64>(),
                        },
                        Declaration {
                            name: "u128_compact".to_owned(),
                            ty: TypeId::of::<iroha_schema::Compact<u128>>(),
                        },
                        Declaration {
                            name: "u128_fixed".to_owned(),
                            ty: TypeId::of::<u128>(),
                        },
                    ],
                }),
            ),
        ),
        (TypeId::of::<u128>(), ("u128".to_owned(), Int(FixedWidth))),
        (TypeId::of::<u16>(), ("u16".to_owned(), Int(FixedWidth))),
        (TypeId::of::<u32>(), ("u32".to_owned(), Int(FixedWidth))),
        (TypeId::of::<u64>(), ("u64".to_owned(), Int(FixedWidth))),
        (TypeId::of::<u8>(), ("u8".to_owned(), Int(FixedWidth))),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Foo::schema(), expected);
}
