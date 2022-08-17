//! Crate with various derive macros

#![allow(clippy::restriction)]

use proc_macro::TokenStream;
use quote::quote;

/// Attribute for skipping from attribute
const SKIP_FROM_ATTR: &str = "skip_from";
const SKIP_TRY_FROM_ATTR: &str = "skip_try_from";
/// Attribute to skip inner container optimization. Useful for trait objects
const SKIP_CONTAINER: &str = "skip_container";

/// [`FromVariant`] is used for implementing `From<Variant> for Enum`
/// and `TryFrom<Enum> for Variant`.
///
/// ```rust
/// use iroha_derive::FromVariant;
///
/// trait MyTrait {}
///
/// #[derive(FromVariant)]
/// enum Obj {
///     Uint(u32),
///     Int(i32),
///     String(String),
///     // You can skip implementing `From`
///     Vec(#[skip_from] Vec<Obj>),
///     // You can also skip implementing `From` for item inside containers such as `Box`
///     Box(#[skip_container] Box<dyn MyTrait>)
/// }
///
/// // For example, to avoid:
/// impl<T: Into<Obj>> From<Vec<T>> for Obj {
///     fn from(vec: Vec<T>) -> Self {
///         # stringify!(
///         ...
///         # );
///         # todo!()
///     }
/// }
/// ```
#[proc_macro_derive(FromVariant, attributes(skip_from, skip_try_from, skip_container))]
pub fn from_variant_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_from_variant(&ast)
}

fn attrs_have_ident(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs.iter().any(|attr| attr.path.is_ident(ident))
}

const CONTAINERS: &[&str] = &["Box", "RefCell", "Cell", "Rc", "Arc", "Mutex", "RwLock"];

fn get_type_argument<'a, 'b>(
    s: &'a str,
    ty: &'b syn::TypePath,
) -> Option<&'b syn::GenericArgument> {
    let segments = &ty.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let syn::PathArguments::AngleBracketed(ref bracketed_arguments) = segments[0].arguments {
        assert_eq!(bracketed_arguments.args.len(), 1);
        Some(&bracketed_arguments.args[0])
    } else {
        unreachable!("No other arguments for types in enum variants possible")
    }
}

fn from_container_variant_internal(
    into_ty: &syn::Ident,
    into_variant: &syn::Ident,
    from_ty: &syn::GenericArgument,
    container_ty: &syn::TypePath,
) -> proc_macro2::TokenStream {
    quote! {
        impl From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (#container_ty :: new(origin))
            }
        }
    }
}

fn from_variant_internal(
    into_ty: &syn::Ident,
    into_variant: &syn::Ident,
    from_ty: &syn::Type,
) -> proc_macro2::TokenStream {
    quote! {
        impl From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (origin)
            }
        }
    }
}

fn from_variant(
    into_ty: &syn::Ident,
    into_variant: &syn::Ident,
    from_ty: &syn::Type,
    skip_container: bool,
) -> proc_macro2::TokenStream {
    let from_orig = from_variant_internal(into_ty, into_variant, from_ty);

    if let syn::Type::Path(path) = from_ty {
        let mut code = from_orig;

        if skip_container {
            return code;
        }

        for container in CONTAINERS {
            if let Some(inner) = get_type_argument(container, path) {
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| {
                        let mut segment = segment.clone();
                        segment.arguments = syn::PathArguments::default();
                        segment
                    })
                    .collect::<syn::punctuated::Punctuated<_, syn::token::Colon2>>();
                let path = syn::Path {
                    segments,
                    leading_colon: None,
                };
                let path = &syn::TypePath { path, qself: None };

                let from_inner =
                    from_container_variant_internal(into_ty, into_variant, inner, path);
                code = quote! {
                    #code
                    #from_inner
                };
            }
        }

        return code;
    }

    from_orig
}

fn try_into_variant(
    enum_ty: &syn::Ident,
    variant: &syn::Ident,
    variant_ty: &syn::Type,
) -> proc_macro2::TokenStream {
    quote! {
        impl TryFrom<#enum_ty> for #variant_ty {
            type Error = iroha_macro::error::ErrorTryFromEnum<#enum_ty, Self>;

            fn try_from(origin: #enum_ty) -> core::result::Result<Self, iroha_macro::error::ErrorTryFromEnum<#enum_ty, Self>> {
                if let #enum_ty :: #variant(variant) = origin {
                    Ok(variant)
                } else {
                    Err(iroha_macro::error::ErrorTryFromEnum::default())
                }
            }
        }
    }
}

fn impl_from_variant(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let froms = if let syn::Data::Enum(data_enum) = &ast.data {
        &data_enum.variants
    } else {
        panic!("Only enums are supported")
    }
    .iter()
    .filter_map(|variant| {
        if let syn::Fields::Unnamed(ref unnamed) = variant.fields {
            if unnamed.unnamed.len() == 1 {
                let variant_type = &unnamed
                    .unnamed
                    .first()
                    .expect("Won't fail as we have more than one argument for variant")
                    .ty;

                let try_into = if attrs_have_ident(&unnamed.unnamed[0].attrs, SKIP_TRY_FROM_ATTR) {
                    quote!()
                } else {
                    try_into_variant(name, &variant.ident, variant_type)
                };
                let from = if attrs_have_ident(&unnamed.unnamed[0].attrs, SKIP_FROM_ATTR) {
                    quote!()
                } else if attrs_have_ident(&unnamed.unnamed[0].attrs, SKIP_CONTAINER) {
                    from_variant(name, &variant.ident, variant_type, true)
                } else {
                    from_variant(name, &variant.ident, variant_type, false)
                };

                return Some(quote!(
                    #try_into
                    #from
                ));
            }
        }
        None
    });

    let gen = quote! {
        #(#froms)*
    };
    gen.into()
}

/// [`VariantCount`] derives an associated constant `VARIANT_COUNT: usize` for enums
/// that is equal to the count of variants in enum.
///
/// # Examples
///
/// ```
/// use iroha_derive::VariantCount;
///
/// #[derive(VariantCount)]
/// enum MyEnum {
///   First,
///   Second(i32),
///   Third {
///     a: usize,
///     b: usize
///   }
/// }
///
/// assert_eq!(MyEnum::VARIANT_COUNT, 3)
/// ```
///
/// # Panics
/// When derive attribute target is not an enum
//
// TODO: remove when https://github.com/rust-lang/rust/issues/73662
// or alternative stabilizes
#[proc_macro_derive(VariantCount)]
pub fn variant_count_derive(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = syn::parse(input).expect("Failed to parse input Token Stream.");

    let name = ast.ident;
    let (impl_generics, type_generics, where_clause) = ast.generics.split_for_impl();
    let variant_count = match ast.data {
        syn::Data::Enum(data_enum) => data_enum.variants.len(),
        _ => panic!("Only enums are supported"),
    };

    quote! {
        impl #impl_generics #name #type_generics
            #where_clause
        {
            /// Count of enum variants.
            const VARIANT_COUNT: usize = #variant_count;
        }
    }
    .into()
}
