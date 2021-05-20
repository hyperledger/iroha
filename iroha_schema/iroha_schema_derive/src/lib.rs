//! Crate with derive `IntoSchema` macro

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::clippy::unimplemented
)]

use proc_macro::TokenStream;
use proc_macro2::Ident;
use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct,
    DeriveInput, Expr, Field, Fields, FieldsNamed, FieldsUnnamed, GenericParam, Generics, Lit,
    LitStr, Meta, NestedMeta, Type, TypePath, Variant,
};

/// Check out docs in `iroha_schema` crate
#[proc_macro_derive(IntoSchema)]
pub fn schema_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    impl_schema(&input).into()
}

fn impl_schema(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (params, ident_params, where_clause) = generics(&input.generics);
    let type_name: TypePath = syn::parse2(quote! { #name <#(#ident_params),*> }).unwrap();
    let metadata = metadata(&input.data);

    let type_name_body = type_name_body(name, &input.generics);

    quote! {
        impl #params iroha_schema::IntoSchema for #type_name
        #where_clause
        {
            fn type_name() -> String {
                #type_name_body
            }

            fn schema(map: &mut iroha_schema::MetaMap) {
               #metadata
            }
        }
    }
}

/// Body of method `type_name`
fn type_name_body(name: &Ident, generics: &Generics) -> TokenStream2 {
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
        return quote! { format!("{}::{}", module_path!(), #name) };
    }

    let mut format_str = "{}::{}<".to_owned();
    format_str.push_str(
        &generics
            .iter()
            .map(|_| "{}".to_owned())
            .collect::<Vec<_>>()
            .join(", "),
    );
    format_str.push('>');
    let format_str = LitStr::new(&format_str, Span::mixed_site());

    quote! {
        format!(
            #format_str,
            module_path!(),
            #name,
            #(<#generics as iroha_schema::IntoSchema>::type_name()),*
        )
    }
}

/// Utility function which returns (generic parameters, their idents, and where clause from generic struct
fn generics(generics: &Generics) -> (TokenStream2, Vec<TokenStream2>, TokenStream2) {
    let Generics {
        params,
        where_clause,
        ..
    } = generics;
    let ident_params = params.iter().map(generic_ident).collect::<Vec<_>>();
    if params.is_empty() {
        (quote! {}, vec![], quote! {})
    } else {
        (quote! { <#params> }, ident_params, quote! { #where_clause })
    }
}

/// Returns ident from generic parameter (including lifetimes)
fn generic_ident(param: &GenericParam) -> TokenStream2 {
    match param {
        GenericParam::Type(ty) => {
            let ident = &ty.ident;
            quote! { #ident }
        }
        GenericParam::Const(constgeneric) => {
            let ident = &constgeneric.ident;
            quote! { #ident }
        }
        GenericParam::Lifetime(lifetime) => {
            let lifetime = &lifetime.lifetime;
            quote! { #lifetime }
        }
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
            let expr = syn::parse2(quote! {iroha_schema::Metadata::TupleStruct(
                iroha_schema::UnnamedFieldsMeta {
                    types: vec![],
                }
            )})
            .unwrap();
            (vec![], expr)
        }
        Data::Union(_) => unimplemented!(),
    };

    quote! {
        let _ = map
            .entry(<Self as iroha_schema::IntoSchema>::type_name())
            .or_insert_with(|| #expr);
        #(
            if !map.contains_key(&<#types as iroha_schema::IntoSchema>::type_name()) {
                <#types as iroha_schema::IntoSchema>::schema(map);
            }
        )*
    }
}

/// Returns types for which schema should be called and metadata for tuplestruct
fn metadata_for_tuplestructs(fields: &FieldsUnnamed) -> (Vec<Type>, Expr) {
    let fields = fields.unnamed.iter().filter_map(filter_map_fields_types);
    let fields_ty = fields.clone().map(|field| field.ty).collect();
    let declarations = fields
        .map(|field| field.ty)
        .map(|ty| quote! { <#ty as iroha_schema::IntoSchema>::type_name()});
    let expr = syn::parse2(quote! {
        iroha_schema::Metadata::TupleStruct(
            iroha_schema::UnnamedFieldsMeta {
                types: vec![#(#declarations),*],
            }
        )
    })
    .unwrap();
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
                declarations: vec![#(#declarations),*],
            }
        )
    })
    .unwrap();
    (fields_ty, expr)
}

/// Takes variant fields and gets its type
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
    filter_map_fields_types(field).map(|field| field.ty)
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
            let name = &variant.ident;
            let ty = if let Some(ty) = variant_field(&variant.fields) {
                quote! { Some(<#ty as iroha_schema::IntoSchema>::type_name()) }
            } else {
                quote! { None }
            };
            quote! {
                iroha_schema::EnumVariant {
                    name: stringify!(#name).to_owned(),
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
            variants: vec![#(#variants),*],
        })
    })
    .unwrap();

    (fields_ty, expr)
}

/// Generates declaration for field
fn field_to_declaration(field: &Field) -> TokenStream2 {
    let ident = field.ident.as_ref().unwrap();
    let ty = &field.ty;

    quote! {
        iroha_schema::Declaration {
            name: stringify!(#ident).to_owned(),
            ty: <#ty as iroha_schema::IntoSchema>::type_name(),
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
fn variant_index(v: &Variant, i: usize) -> TokenStream2 {
    // first look for an attribute
    let index = find_meta_item(v.attrs.iter(), |meta| {
        if let NestedMeta::Meta(Meta::NameValue(ref nv)) = meta {
            if nv.path.is_ident("index") {
                if let Lit::Int(ref v) = nv.lit {
                    let byte = v
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
        .map(|i| quote! { #i })
        .or_else(|| {
            v.discriminant.as_ref().map(|&(_, ref expr)| {
                let n: Lit = syn::parse2(quote! { #expr }).unwrap();
                quote! { #n }
            })
        })
        .unwrap_or_else(|| quote! { #i as u8 })
}

/// Finds specific attribute with codec ident satisfying predicate
fn find_meta_item<'a, F, R, I, M>(mut itr: I, mut pred: F) -> Option<R>
where
    F: FnMut(M) -> Option<R> + Clone,
    I: Iterator<Item = &'a Attribute>,
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
        field.ty = syn::parse2(quote! { iroha_schema::Compact<#ty> }).unwrap();
        Some(field)
    } else {
        Some(field.clone())
    }
}
