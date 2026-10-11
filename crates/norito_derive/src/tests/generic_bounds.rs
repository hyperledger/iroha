use super::*;
#[test]
fn concrete_recursive_field_does_not_create_a_cyclic_bound() {
    let mut generics = Generics::default();
    let field: syn::Type = syn::parse_quote!(Box<Expr>);
    add_bound(&mut generics, &field, quote!(DemoTrait));
    assert!(generics.where_clause.is_none());
}
#[test]
fn nested_generic_field_keeps_its_required_bound() {
    let mut generics: Generics = syn::parse_quote!(<'a, T, const N: usize>);
    let field: syn::Type = syn::parse_quote!(Cow<'a, [T; N]>);
    add_bound(&mut generics, &field, quote!(DemoTrait));
    let predicates = generics
        .where_clause
        .as_ref()
        .expect("generic field must add a where clause")
        .predicates
        .to_token_stream()
        .to_string();
    assert!(predicates.contains("Cow < 'a , [T ; N] > : DemoTrait"));
}

#[test]
fn generic_json_fallback_merges_generics_and_reuses_deserialize_obligation() {
    let input: DeriveInput = parse_quote! {
        struct Envelope<T, const N: usize> where T: Clone { value: [T; N] }
    };
    let generated = derive_fast_from_json_fallback(&input);
    let implementation: syn::ItemImpl =
        syn::parse2(generated).expect("one valid implementation generic parameter list");
    assert_eq!(implementation.generics.params.len(), 3);
    assert_eq!(
        implementation.self_ty.to_token_stream().to_string(),
        "Envelope < T , N >"
    );
    let bounds = implementation
        .generics
        .where_clause
        .unwrap()
        .to_token_stream()
        .to_string();
    assert!(bounds.contains("T : Clone"));
    assert!(bounds.contains("Self : norito :: json :: JsonDeserialize"));
}

#[test]
fn json_implementation_lifetimes_avoid_outer_and_nested_user_binders() {
    let generics: Generics = parse_quote! {
        <'__norito_json, '__norito_arena, T: for<'___norito_json> Fn(&'___norito_json str)>
    };
    assert_eq!(
        json_implementation_lifetime(&generics, "__norito_json").to_string(),
        "'____norito_json"
    );
    assert_eq!(
        json_implementation_lifetime(&generics, "__norito_arena").to_string(),
        "'___norito_arena"
    );
    let input: DeriveInput = parse_quote! {
        struct Borrowed<'a, 'arena, '__norito_json, '__norito_arena, T> {
            value: T,
            marker: ::core::marker::PhantomData<(&'a (), &'arena (), &'__norito_json (), &'__norito_arena ())>,
        }
    };
    syn::parse2::<syn::ItemImpl>(derive_fast_from_json_fallback(&input))
        .expect("user and generated lifetimes stay distinct");
}
