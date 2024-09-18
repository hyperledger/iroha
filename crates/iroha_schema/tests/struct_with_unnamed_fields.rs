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
            MetaMapEntry {
                type_id: "String".to_owned(),
                type_name: "String".to_owned(),
                metadata: String,
            },
        ),
        (
            TypeId::of::<alloc::vec::Vec<alloc::string::String>>(),
            MetaMapEntry {
                type_id: "Vec<String>".to_owned(),
                type_name: "Vec<String>".to_owned(),
                metadata: Vec(VecMeta {
                    ty: TypeId::of::<alloc::string::String>(),
                }),
            },
        ),
        (
            TypeId::of::<Command>(),
            MetaMapEntry {
                type_id: "Command".to_owned(),
                type_name: "Command".to_owned(),
                metadata: Tuple(UnnamedFieldsMeta {
                    types: vec![
                        TypeId::of::<alloc::string::String>(),
                        TypeId::of::<alloc::vec::Vec<alloc::string::String>>(),
                    ],
                }),
            },
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Command::schema(), expected);
}
