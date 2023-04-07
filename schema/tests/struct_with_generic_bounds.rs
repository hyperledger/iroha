extern crate alloc;

#[derive(iroha_schema::IntoSchema)]
struct Foo<V> {
    _value: Option<V>,
}

#[test]
fn check_generic() {
    use alloc::collections::BTreeMap;
    use core::any::TypeId;

    use iroha_schema::prelude::*;
    use Metadata::*;

    let option_id = TypeId::of::<core::option::Option<bool>>();
    let expected_struct = Struct(NamedFieldsMeta {
        declarations: vec![Declaration {
            name: "_value".to_owned(),
            ty: option_id,
        }],
    });
    let expected = vec![
        (TypeId::of::<bool>(), ("Bool".to_owned(), Bool)),
        (
            TypeId::of::<core::option::Option<bool>>(),
            ("Option<Bool>".to_owned(), Option(TypeId::of::<bool>())),
        ),
        (
            TypeId::of::<Foo<bool>>(),
            ("Foo<Bool>".to_owned(), expected_struct),
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Foo::<bool>::schema(), expected);
}
