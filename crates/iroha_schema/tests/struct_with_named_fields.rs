extern crate alloc;

use alloc::collections::BTreeMap;
use core::any::TypeId;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(Decode, Encode, IntoSchema)]
struct Command {
    executable: String,
    args: Vec<String>,
    #[codec(skip)]
    mock: bool,
    num: i32,
}

#[test]
fn named_fields() {
    use IntMode::*;
    use Metadata::*;

    let expected_struct = Struct(NamedFieldsMeta {
        declarations: vec![
            Declaration {
                name: "executable".to_owned(),
                ty: TypeId::of::<alloc::string::String>(),
            },
            Declaration {
                name: "args".to_owned(),
                ty: TypeId::of::<alloc::vec::Vec<alloc::string::String>>(),
            },
            Declaration {
                name: "num".to_owned(),
                ty: TypeId::of::<i32>(),
            },
        ],
    });

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
            TypeId::of::<i32>(),
            MetaMapEntry {
                type_id: "i32".to_owned(),
                type_name: "i32".to_owned(),
                metadata: Int(FixedWidth),
            },
        ),
        (
            TypeId::of::<Command>(),
            MetaMapEntry {
                type_id: "Command".to_owned(),
                type_name: "Command".to_owned(),
                metadata: expected_struct,
            },
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Command::schema(), expected);
}
