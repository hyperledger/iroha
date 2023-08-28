//! Crate with various derive macros

#![allow(clippy::restriction)]

use darling::{util::SpannedValue, FromDeriveInput};
use manyhow::{manyhow, Result};
use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned, ToTokens};
use syn2::{spanned::Spanned, Token};

/// Attribute for skipping from attribute
const SKIP_FROM_ATTR: &str = "skip_from";
const SKIP_TRY_FROM_ATTR: &str = "skip_try_from";
/// Attribute to skip inner container optimization. Useful for trait objects
const SKIP_CONTAINER: &str = "skip_container";

/// Helper macro to expand FFI functions
#[manyhow]
#[proc_macro_attribute]
pub fn ffi_impl_opaque(_: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let item: syn2::ItemImpl = syn2::parse2(item)?;

    Ok(quote! {
        #[cfg_attr(
            all(feature = "ffi_export", not(feature = "ffi_import")),
            iroha_ffi::ffi_export
        )]
        #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
        #item
    })
}

#[derive(darling::FromDeriveInput, Debug)]
#[darling(supports(enum_any))]
struct FromVariantInput {
    ident: syn2::Ident,
    generics: syn2::Generics,
    data: darling::ast::Data<SpannedValue<FromVariantVariant>, darling::util::Ignored>,
}

// FromVariant manually implemented for additional validation
#[derive(Debug)]
struct FromVariantVariant {
    ident: syn2::Ident,
    fields: darling::ast::Fields<SpannedValue<FromVariantField>>,
}

impl FromVariantVariant {
    fn can_from_be_implemented(
        fields: &darling::ast::Fields<SpannedValue<FromVariantField>>,
    ) -> bool {
        fields.style == darling::ast::Style::Tuple && fields.fields.len() == 1
    }
}

impl darling::FromVariant for FromVariantVariant {
    fn from_variant(variant: &syn2::Variant) -> darling::Result<Self> {
        let ident = variant.ident.clone();
        let fields = darling::ast::Fields::try_from(&variant.fields)?;
        let mut accumulator = darling::error::Accumulator::default();

        let can_from_be_implemented = Self::can_from_be_implemented(&fields);

        for field in &fields.fields {
            if (field.skip_from || field.skip_container) && !can_from_be_implemented {
                accumulator.push(darling::Error::custom("#[skip_from], #[skip_try_from] and #[skip_container] attributes are only allowed for new-type enum variants (single unnamed field). The `From` traits will not be implemented for other kinds of variants").with_span(&field.span()));
            }
        }

        for attr in &variant.attrs {
            let span = attr.span();
            let attr = attr.path().to_token_stream().to_string();
            match attr.as_str() {
                SKIP_FROM_ATTR | SKIP_TRY_FROM_ATTR | SKIP_CONTAINER => {
                    accumulator.push(
                        darling::Error::custom(format!(
                            "#[{}] attribute should be applied to the field, not variant",
                            &attr
                        ))
                        .with_span(&span),
                    );
                }
                _ => {}
            }
        }

        accumulator.finish()?;

        Ok(Self { ident, fields })
    }
}

// FromField manually implemented for non-standard attributes
#[derive(Debug)]
struct FromVariantField {
    ty: syn2::Type,
    skip_from: bool,
    skip_try_from: bool,
    skip_container: bool,
}

// implementing manually, because darling can't parse attributes that are not under some unified attr
// It expects us to have a common attribute that will contain all the fields, like:
// #[hello(skip_from, skip_container)]
// The already defined macro API uses `skip_from` and `skip_container` attributes without any qualification
// Arguably, this is also more convenient for the user (?)
// Hence, we fall back to manual parsing
impl darling::FromField for FromVariantField {
    fn from_field(field: &syn2::Field) -> darling::Result<Self> {
        let mut skip_from = false;
        let mut skip_try_from = false;
        let mut skip_container = false;
        for attr in &field.attrs {
            match attr.path().clone().to_token_stream().to_string().as_str() {
                SKIP_FROM_ATTR => skip_from = true,
                SKIP_TRY_FROM_ATTR => skip_try_from = true,
                SKIP_CONTAINER => skip_container = true,
                // ignore unknown attributes, rustc handles them
                _ => continue,
            }
        }
        Ok(Self {
            ty: field.ty.clone(),
            skip_from,
            skip_try_from,
            skip_container,
        })
    }
}

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
#[manyhow]
#[proc_macro_derive(FromVariant, attributes(skip_from, skip_try_from, skip_container))]
pub fn from_variant_derive(input: TokenStream) -> Result<TokenStream> {
    let ast = syn2::parse2(input)?;
    let ast = FromVariantInput::from_derive_input(&ast)?;
    Ok(impl_from_variant(&ast))
}

const CONTAINERS: &[&str] = &["Box", "RefCell", "Cell", "Rc", "Arc", "Mutex", "RwLock"];

fn get_type_argument<'b>(s: &str, ty: &'b syn2::TypePath) -> Option<&'b syn2::GenericArgument> {
    // NOTE: this is NOT syn2::Path::is_ident because it allows for generic parameters
    let segments = &ty.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let syn2::PathArguments::AngleBracketed(ref bracketed_arguments) = segments[0].arguments {
        assert_eq!(bracketed_arguments.args.len(), 1);
        Some(&bracketed_arguments.args[0])
    } else {
        unreachable!("No other arguments for types in enum variants possible")
    }
}

fn from_container_variant_internal(
    into_ty: &syn2::Ident,
    into_variant: &syn2::Ident,
    from_ty: &syn2::GenericArgument,
    container_ty: &syn2::TypePath,
    generics: &syn2::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics core::convert::From<#from_ty> for #into_ty #ty_generics #where_clause {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (#container_ty :: new(origin))
            }
        }
    }
}

fn from_variant_internal(
    span: Span,
    into_ty: &syn2::Ident,
    into_variant: &syn2::Ident,
    from_ty: &syn2::Type,
    generics: &syn2::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote_spanned! { span =>
        impl #impl_generics core::convert::From<#from_ty> for #into_ty #ty_generics #where_clause {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #into_variant (origin)
            }
        }
    }
}

fn from_variant(
    span: Span,
    into_ty: &syn2::Ident,
    into_variant: &syn2::Ident,
    from_ty: &syn2::Type,
    generics: &syn2::Generics,
    skip_container: bool,
) -> TokenStream {
    let from_orig = from_variant_internal(span, into_ty, into_variant, from_ty, generics);

    if let syn2::Type::Path(path) = from_ty {
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
                        segment.arguments = syn2::PathArguments::default();
                        segment
                    })
                    .collect::<syn2::punctuated::Punctuated<_, Token![::]>>();
                let path = syn2::Path {
                    segments,
                    leading_colon: None,
                };
                let path = &syn2::TypePath { path, qself: None };

                let from_inner =
                    from_container_variant_internal(into_ty, into_variant, inner, path, generics);
                code = quote_spanned! { span =>
                    #code
                    #from_inner
                };
            }
        }

        return code;
    }

    from_orig
}

fn try_into_variant_single(
    span: Span,
    enum_ty: &syn2::Ident,
    variant: &syn2::Ident,
    variant_ty: &syn2::Type,
    generics: &syn2::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote_spanned! { span =>
        impl #impl_generics core::convert::TryFrom<#enum_ty #ty_generics> for #variant_ty #where_clause {
            type Error = ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>;

            fn try_from(origin: #enum_ty #ty_generics) -> core::result::Result<Self, Self::Error> {
                let #enum_ty :: #variant(variant) = origin;
                Ok(variant)
            }
        }
    }
}

fn try_into_variant(
    span: Span,
    enum_ty: &syn2::Ident,
    variant: &syn2::Ident,
    variant_ty: &syn2::Type,
    generics: &syn2::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote_spanned! { span =>
        impl #impl_generics core::convert::TryFrom<#enum_ty #ty_generics> for #variant_ty #where_clause {
            type Error = ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>;

            fn try_from(origin: #enum_ty #ty_generics) -> core::result::Result<Self, Self::Error> {
                if let #enum_ty :: #variant(variant) = origin {
                    Ok(variant)
                } else {
                    Err(iroha_macro::error::ErrorTryFromEnum::default())
                }
            }
        }
    }
}

fn impl_from_variant(ast: &FromVariantInput) -> TokenStream {
    let name = &ast.ident;

    let generics = &ast.generics;

    let enum_data = ast
        .data
        .as_ref()
        .take_enum()
        .expect("BUG: FromVariantInput is allowed to contain enum data only");
    let variant_count = enum_data.len();
    let froms = enum_data.into_iter().filter_map(|variant| {
        if !variant.fields.is_newtype() {
            return None;
        }
        let span = variant.span();
        let field =
            variant.fields.iter().next().expect(
                "BUG: FromVariantVariant should be newtype and thus contain exactly one field",
            );
        let variant_type = &field.ty;

        let try_into = if field.skip_try_from {
            quote!()
        } else if variant_count == 1 {
            try_into_variant_single(span, name, &variant.ident, variant_type, generics)
        } else {
            try_into_variant(span, name, &variant.ident, variant_type, generics)
        };
        let from = if field.skip_from {
            quote!()
        } else if field.skip_container {
            from_variant(span, name, &variant.ident, variant_type, generics, true)
        } else {
            from_variant(span, name, &variant.ident, variant_type, generics, false)
        };

        Some(quote!(
            #try_into
            #from
        ))
    });

    quote! { #(#froms)* }
}
