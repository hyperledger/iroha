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
        (
            TypeId::of::<bool>(),
            MetaMapEntry {
                type_id: "bool".to_owned(),
                type_name: "bool".to_owned(),
                metadata: Bool,
            },
        ),
        (
            TypeId::of::<core::option::Option<bool>>(),
            MetaMapEntry {
                type_id: "Option<bool>".to_owned(),
                type_name: "Option<bool>".to_owned(),
                metadata: Option(TypeId::of::<bool>()),
            },
        ),
        (
            TypeId::of::<Foo<bool>>(),
            MetaMapEntry {
                type_id: "Foo<bool>".to_owned(),
                type_name: "Foo<bool>".to_owned(),
                metadata: expected_struct,
            },
        ),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    assert_eq!(Foo::<bool>::schema(), expected);
}
