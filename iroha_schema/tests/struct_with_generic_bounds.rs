#[derive(iroha_schema::IntoSchema)]
struct Foo<V: iroha_schema::IntoSchema + Sized> {
    _value: Option<V>,
}

#[test]
fn check_generic() {
    use std::collections::BTreeMap;

    use iroha_schema::prelude::*;
    use Metadata::*;

    let expected_struct = Struct(NamedFieldsMeta {
        declarations: vec![Declaration {
            name: "_value".to_owned(),
            ty: "Option<bool>".to_owned(),
        }],
    });
    let expected = vec![
        ("bool".to_owned(), Bool),
        ("Option<bool>".to_owned(), Option("bool".to_owned())),
        (
            "struct_with_generic_bounds::Foo<bool>".to_owned(),
            expected_struct,
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Foo::<bool>::get_schema(), expected);
}
