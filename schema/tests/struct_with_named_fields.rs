use std::collections::BTreeMap;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(IntoSchema, Encode, Decode)]
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
                ty: "String".to_owned(),
            },
            Declaration {
                name: "args".to_owned(),
                ty: "Vec<String>".to_owned(),
            },
            Declaration {
                name: "num".to_owned(),
                ty: "i32".to_owned(),
            },
        ],
    });

    let expected = vec![
        ("String".to_owned(), String),
        (
            "Vec<String>".to_owned(),
            Vec(VecMeta {
                ty: "String".to_owned(),
                sorted: false,
            }),
        ),
        ("i32".to_owned(), Int(FixedWidth)),
        (
            "struct_with_named_fields::Command".to_owned(),
            expected_struct,
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();

    assert_eq!(Command::get_schema(), expected);
}
