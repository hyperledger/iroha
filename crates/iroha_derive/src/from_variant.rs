use darling::{util::SpannedValue, FromDeriveInput};
use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned, ToTokens as _};
use syn::{spanned::Spanned as _, Token};

/// Attribute for skipping from attribute
const SKIP_FROM_ATTR: &str = "skip_from";
const SKIP_TRY_FROM_ATTR: &str = "skip_try_from";
/// Attribute to skip inner container optimization. Useful for trait objects
const SKIP_CONTAINER: &str = "skip_container";

#[derive(FromDeriveInput, Debug)]
#[darling(supports(enum_any))]
pub struct FromVariantInput {
    ident: syn::Ident,
    generics: syn::Generics,
    data: darling::ast::Data<SpannedValue<FromVariantVariant>, darling::util::Ignored>,
}

// FromVariant manually implemented for additional validation
#[derive(Debug)]
struct FromVariantVariant {
    ident: syn::Ident,
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
    fn from_variant(variant: &syn::Variant) -> darling::Result<Self> {
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
    ty: syn::Type,
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
    fn from_field(field: &syn::Field) -> darling::Result<Self> {
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

const CONTAINERS: &[&str] = &["Box", "RefCell", "Cell", "Rc", "Arc", "Mutex", "RwLock"];

fn get_type_argument<'b>(s: &str, ty: &'b syn::TypePath) -> Option<&'b syn::GenericArgument> {
    // NOTE: this is NOT syn::Path::is_ident because it allows for generic parameters
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
    generics: &syn::Generics,
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
    into_ty: &syn::Ident,
    into_variant: &syn::Ident,
    from_ty: &syn::Type,
    generics: &syn::Generics,
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
    into_ty: &syn::Ident,
    into_variant: &syn::Ident,
    from_ty: &syn::Type,
    generics: &syn::Generics,
    skip_container: bool,
) -> TokenStream {
    let from_orig = from_variant_internal(span, into_ty, into_variant, from_ty, generics);

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
                    .collect::<syn::punctuated::Punctuated<_, Token![::]>>();
                let path = syn::Path {
                    segments,
                    leading_colon: None,
                };
                let path = &syn::TypePath { path, qself: None };

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
    enum_ty: &syn::Ident,
    variant: &syn::Ident,
    variant_ty: &syn::Type,
    generics: &syn::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote_spanned! { span =>
        impl #impl_generics core::convert::TryFrom<#enum_ty #ty_generics> for #variant_ty #where_clause {
            type Error = ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>;

            fn try_from(origin: #enum_ty #ty_generics) -> core::result::Result<Self, ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>> {
                let #enum_ty :: #variant(variant) = origin;
                Ok(variant)
            }
        }
    }
}

fn try_into_variant(
    span: Span,
    enum_ty: &syn::Ident,
    variant: &syn::Ident,
    variant_ty: &syn::Type,
    generics: &syn::Generics,
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote_spanned! { span =>
        impl #impl_generics core::convert::TryFrom<#enum_ty #ty_generics> for #variant_ty #where_clause {
            type Error = ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>;

            fn try_from(origin: #enum_ty #ty_generics) -> core::result::Result<Self, ::iroha_macro::error::ErrorTryFromEnum<#enum_ty #ty_generics, Self>> {
                if let #enum_ty :: #variant(variant) = origin {
                    Ok(variant)
                } else {
                    Err(iroha_macro::error::ErrorTryFromEnum::default())
                }
            }
        }
    }
}

pub fn impl_from_variant(ast: &FromVariantInput) -> TokenStream {
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
