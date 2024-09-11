extern crate alloc;

use alloc::collections::BTreeMap;
use core::any::TypeId;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(Decode, Encode, IntoSchema)]
struct Command(String, Vec<String>, #[codec(skip)] bool);

#[test]
fn unnamed() {
    use Metadata::*;

    let expected = vec![
        (
            TypeId::of::<alloc::string::String>(),
            ("String".to_owned(), String),
        ),
        (
            TypeId::of::<alloc::vec::Vec<alloc::string::String>>(),
            (
                "Vec<String>".to_owned(),
                Vec(VecMeta {
                    ty: TypeId::of::<alloc::string::String>(),
                }),
            ),
        ),
        (
            TypeId::of::<Command>(),
            (
                "Command".to_owned(),
                Tuple(UnnamedFieldsMeta {
                    types: vec![
                        TypeId::of::<alloc::string::String>(),
                        TypeId::of::<alloc::vec::Vec<alloc::string::String>>(),
                    ],
                }),
            ),
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Command::schema(), expected);
}
