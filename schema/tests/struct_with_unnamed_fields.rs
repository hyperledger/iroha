use std::collections::BTreeMap;

use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

#[derive(IntoSchema, Encode, Decode)]
struct Command(String, Vec<String>, #[codec(skip)] bool);

#[test]
fn unnamed() {
    use Metadata::*;

    let expected = vec![
        ("String".to_owned(), String),
        (
            "Vec<String>".to_owned(),
            Vec(VecMeta {
                ty: "String".to_owned(),
                sorted: false,
            }),
        ),
        (
            "struct_with_unnamed_fields::Command".to_owned(),
            Tuple(UnnamedFieldsMeta {
                types: vec!["String".to_owned(), "Vec<String>".to_owned()],
            }),
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Command::get_schema(), expected);
}
