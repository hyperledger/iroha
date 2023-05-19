//! Crate with derive `IntoSchema` macro

#![allow(clippy::arithmetic_side_effects)]

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, parse_quote, spanned::Spanned, Attribute, Data, DataEnum,
    DataStruct, DeriveInput, Expr, Field, Fields, FieldsNamed, FieldsUnnamed, GenericParam,
    Generics, LitStr, Meta, NestedMeta, Type,
};

/// Derive [`iroha_schema::TypeId`]
///
/// Check out [`iroha_schema`] documentation
#[proc_macro_derive(TypeId, attributes(type_id))]
pub fn type_id_derive(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);
    impl_type_id(&mut input).into()
}

fn impl_type_id(input: &mut DeriveInput) -> TokenStream2 {
    let name = &input.ident;

    if let Some(bound) = input.attrs.iter().find_map(|attr| {
        if let Ok(Meta::List(list)) = attr.parse_meta() {
            if list.path.is_ident("type_id") {
                let type_id = list.nested.first().expect("Missing type_id");

                if let NestedMeta::Meta(Meta::NameValue(name_value)) = type_id {
                    if name_value.path.is_ident("bound") {
                        if let syn::Lit::Str(bound) = &name_value.lit {
                            return Some(bound.parse().expect("Invalid bound"));
                        }
                    }
                }
            }
        }

        None
    }) {
        input.generics.make_where_clause().predicates.push(bound);
    } else {
        input
            .generics
            .type_params_mut()
            .for_each(|ty_param| ty_param.bounds.push(parse_quote! {iroha_schema::TypeId}));
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let type_id_body = trait_body(name, &input.generics, true);

    quote! {
        impl #impl_generics iroha_schema::TypeId for #name #ty_generics #where_clause {
            fn id() -> String {
                #type_id_body
            }
        }
    }
}

/// Derive [`iroha_schema::IntoSchema`] and [`iroha_schema::TypeId`]
///
/// Check out [`iroha_schema`] documentation
#[proc_macro_derive(IntoSchema, attributes(schema))]
pub fn schema_derive(input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as DeriveInput);

    input.generics.type_params_mut().for_each(|ty_param| {
        ty_param
            .bounds
            .push(parse_quote! {iroha_schema::IntoSchema})
    });

    let impl_type_id = impl_type_id(&mut input.clone());

    let impl_schema = input
        .attrs
        .iter()
        .find_map(|attr| {
            if let Ok(Meta::List(list)) = attr.parse_meta() {
                if list.path.is_ident("schema") {
                    let type_id = list.nested.first().expect("Missing type_id");

                    if let NestedMeta::Meta(Meta::NameValue(name_value)) = type_id {
                        if name_value.path.is_ident("transparent") {
                            if let syn::Lit::Str(transparent_type) = &name_value.lit {
                                return Some(transparent_type.parse().expect("Invalid bound"));
                            }
                        }
                    }
                }
            }

            None
        })
        .map_or_else(
            || impl_into_schema(&input),
            |transparent_type| impl_transparent_into_schema(&input, &transparent_type),
        );

    quote! {
        #impl_type_id
        #impl_schema
    }
    .into()
}

fn impl_transparent_into_schema(input: &DeriveInput, transparent_type: &syn::Type) -> TokenStream2 {
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let name = &input.ident;

    quote! {
        impl #impl_generics iroha_schema::IntoSchema for #name #ty_generics #where_clause {
            fn update_schema_map(map: &mut iroha_schema::MetaMap) {
                if !map.contains_key::<Self>() {
                    if !map.contains_key::<#transparent_type>() {
                        <#transparent_type as iroha_schema::IntoSchema>::update_schema_map(map);
                    }

                    if let Some(schema) = map.get::<#transparent_type>() {
                        map.insert::<Self>(schema.clone());
                    }
                }
            }

            fn type_name() -> String {
               <#transparent_type as iroha_schema::IntoSchema>::type_name()
            }
        }
    }
}
fn impl_into_schema(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let type_name_body = trait_body(name, &input.generics, false);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let metadata = metadata(&input.data);

    quote! {
        impl #impl_generics iroha_schema::IntoSchema for #name #ty_generics #where_clause {
            fn type_name() -> String {
                #type_name_body
            }

            fn update_schema_map(map: &mut iroha_schema::MetaMap) {
               #metadata
            }
        }
    }
}

/// Body of [`IntoSchema::type_name`] method
fn trait_body(name: &Ident, generics: &Generics, is_type_id_trait: bool) -> TokenStream2 {
    let generics = &generics
        .params
        .iter()
        .filter_map(|param| match param {
            GenericParam::Type(ty) => Some(&ty.ident),
            _ => None,
        })
        .collect::<Vec<_>>();
    let name = LitStr::new(&name.to_string(), Span::call_site());

    if generics.is_empty() {
        return quote! { format!("{}", #name) };
    }

    let mut format_str = "{}<".to_owned();
    format_str.push_str(
        &generics
            .iter()
            .map(|_| "{}".to_owned())
            .collect::<Vec<_>>()
            .join(", "),
    );
    format_str.push('>');
    let format_str = LitStr::new(&format_str, Span::mixed_site());

    let generics = if is_type_id_trait {
        quote!(#(<#generics as iroha_schema::TypeId>::id()),*)
    } else {
        quote!(#(<#generics as iroha_schema::IntoSchema>::type_name()),*)
    };

    quote! {
        format!(
            #format_str,
            #name,
            #generics
        )
    }
}

/// Returns schema method body
fn metadata(data: &Data) -> TokenStream2 {
    let (types, expr) = match &data {
        Data::Enum(data_enum) => metadata_for_enums(data_enum),
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => metadata_for_structs(fields),
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(unnamed),
            ..
        }) => metadata_for_tuplestructs(unnamed),
        Data::Struct(DataStruct {
            fields: Fields::Unit,
            ..
        }) => {
            let expr = syn::parse2(quote! {
                iroha_schema::Metadata::Tuple(
                    iroha_schema::UnnamedFieldsMeta {
                        types: Vec::new()
                    }
                )
            })
            .expect("Failed to parse metadata tuple");
            (vec![], expr)
        }
        #[allow(clippy::unimplemented)]
        Data::Union(_) => unimplemented!(),
    };

    quote! {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(#expr); #(

            <#types as iroha_schema::IntoSchema>::update_schema_map(map); )*
        }
    }
}

/// Returns types for which schema should be called and metadata for tuplestruct
fn metadata_for_tuplestructs(fields: &FieldsUnnamed) -> (Vec<Type>, Expr) {
    let fields = fields.unnamed.iter().filter_map(filter_map_fields_types);
    let fields_ty = fields.clone().map(|field| field.ty).collect();
    let types = fields
        .map(|field| field.ty)
        .map(|ty| quote! { core::any::TypeId::of::<#ty>()});
    let expr = syn::parse2(quote! {
        iroha_schema::Metadata::Tuple(
            iroha_schema::UnnamedFieldsMeta {
                types: {
                    let mut types = Vec::new();
                    #( types.push(#types); )*
                    types
                }
            }
        )
    })
    .expect("Failed to parse metadata for tuplestructs");
    (fields_ty, expr)
}

/// Returns types for which schema should be called and metadata for struct
fn metadata_for_structs(fields: &FieldsNamed) -> (Vec<Type>, Expr) {
    let fields = fields.named.iter().filter_map(filter_map_fields_types);
    let declarations = fields.clone().map(|field| field_to_declaration(&field));
    let fields_ty = fields.map(|field| field.ty).collect();
    let expr = syn::parse2(quote! {
        iroha_schema::Metadata::Struct(
            iroha_schema::NamedFieldsMeta {
                declarations: {
                    let mut declarations = Vec::new();
                    #( declarations.push(#declarations); )*
                    declarations
                }
            }
        )
    })
    .expect("Failed to parse metadata for structs");
    (fields_ty, expr)
}

/// Takes variant fields and gets its type
#[allow(clippy::panic)]
fn variant_field(fields: &Fields) -> Option<Type> {
    let field = match fields {
        Fields::Unit => return None,
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => &fields.unnamed[0],
        Fields::Unnamed(_) => {
            panic!("Use at most 1 field in unnamed enum variants. Check out styleguide")
        }
        Fields::Named(_) => {
            panic!("Please don't use named fields on enums. It is against iroha styleguide")
        }
    };
    filter_map_fields_types(field).map(|this_field| this_field.ty)
}

/// Returns types for which schema should be called and metadata for struct
fn metadata_for_enums(data_enum: &DataEnum) -> (Vec<Type>, Expr) {
    let variants = data_enum
        .variants
        .iter()
        .enumerate()
        .filter(|(_, variant)| !should_skip(&variant.attrs))
        .map(|(discriminant, variant)| {
            let discriminant = variant_index(variant, discriminant);
            assert!(
                variant.discriminant.is_none(),
                "Fieldless enums with explicit discriminants are not allowed"
            );

            let name = &variant.ident;
            let ty = variant_field(&variant.fields).map_or_else(
                || quote! { None },
                |ty| quote! { Some(core::any::TypeId::of::<#ty>()) },
            );
            quote! {
                iroha_schema::EnumVariant {
                    tag: String::from(stringify!(#name)),
                    discriminant: #discriminant,
                    ty: #ty,
                }
            }
        });
    let fields_ty = data_enum
        .variants
        .iter()
        .filter(|variant| !should_skip(&variant.attrs))
        .filter_map(|variant| variant_field(&variant.fields))
        .collect();
    let expr = syn::parse2(quote! {
        iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants: {
                let mut variants = Vec::new();
                #( variants.push(#variants); )*
                variants
            }
        })
    })
    .expect("Failed to parse metadata for enums");

    (fields_ty, expr)
}

/// Generates declaration for field
fn field_to_declaration(field: &Field) -> TokenStream2 {
    let ident = field.ident.as_ref().expect("Field to declaration");
    let ty = &field.ty;

    quote! {
        iroha_schema::Declaration {
            name: String::from(stringify!(#ident)),
            ty: core::any::TypeId::of::<#ty>(),
        }
    }
}

/// Look for a `#[codec(compact)]` outer attribute on the given `Field`.
fn is_compact(field: &Field) -> bool {
    find_meta_item(field.attrs.iter(), |meta| {
        if let NestedMeta::Meta(Meta::Path(ref path)) = meta {
            if path.is_ident("compact") {
                return Some(());
            }
        }

        None
    })
    .is_some()
}

/// Look for a `#[codec(skip)]` in the given attributes.
fn should_skip(attrs: &[Attribute]) -> bool {
    find_meta_item(attrs.iter(), |meta| {
        if let NestedMeta::Meta(Meta::Path(ref path)) = meta {
            if path.is_ident("skip") {
                return Some(path.span());
            }
        }

        None
    })
    .is_some()
}

/// Look for a `#[scale(index = $int)]` attribute on a variant. If no attribute
/// is found, fall back to the discriminant or just the variant index.
fn variant_index(v: &syn::Variant, i: usize) -> TokenStream2 {
    // first look for an attribute
    let index = find_meta_item(v.attrs.iter(), |meta| {
        if let NestedMeta::Meta(Meta::NameValue(ref nv)) = meta {
            if nv.path.is_ident("index") {
                if let syn::Lit::Int(ref val) = nv.lit {
                    let byte = val
                        .base10_parse::<u8>()
                        .expect("Internal error, index attribute must have been checked");
                    return Some(byte);
                }
            }
        }

        None
    });

    // then fallback to discriminant or just index
    index
        .map(|int| quote! { #int })
        .or_else(|| {
            v.discriminant.as_ref().map(|(_, expr)| {
                let n: syn::Lit = syn::parse2(quote! { #expr })
                    .expect("Fallback in variant_index failed to parse");
                quote! { #n }
            })
        })
        .unwrap_or_else(|| quote! { #i as u8 })
}

/// Finds specific attribute with codec ident satisfying predicate
fn find_meta_item<'attr, F, R, I, M>(mut itr: I, mut pred: F) -> Option<R>
where
    F: FnMut(M) -> Option<R> + Clone,
    I: Iterator<Item = &'attr Attribute>,
    M: Parse,
{
    itr.find_map(|attr| {
        attr.path
            .is_ident("codec")
            .then(|| pred(attr.parse_args().ok()?))
            .flatten()
    })
}

/// Filter map function for types
fn filter_map_fields_types(field: &Field) -> Option<Field> {
    //skip if #[codec(skip)] used
    if should_skip(&field.attrs) {
        return None;
    }
    if is_compact(field) {
        let ty = &field.ty;
        let mut field = field.clone();
        field.ty = syn::parse2(quote! { iroha_schema::Compact<#ty> })
            .expect("Failed to parse compact schema variant");
        Some(field)
    } else {
        Some(field.clone())
    }
}
