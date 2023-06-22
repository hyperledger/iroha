#![allow(
    clippy::str_to_string,
    clippy::mixed_read_write_in_expression,
    clippy::unwrap_in_result
)]

use iroha_macro_utils::{attr_struct, AttrParser};
use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    Attribute, Generics, Ident, Token, Type, Variant, Visibility,
};

mod kw {
    syn::custom_keyword!(origin);
    syn::custom_keyword!(variant);
}

pub struct HasOriginEnum {
    ident: Ident,
    variants: Punctuated<HasOriginVariant, Token![,]>,
    origin: Type,
}

pub struct HasOriginVariant {
    ident: Ident,
    extractor: Option<OriginExtractor>,
}

struct HasOriginAttr<T>(core::marker::PhantomData<T>);

impl<T: Parse> AttrParser<T> for HasOriginAttr<T> {
    const IDENT: &'static str = "has_origin";
}

attr_struct! {
    pub struct Origin {
        _kw: kw::origin,
        _eq: Token![=],
        ty: Type,
    }
}

attr_struct! {
    pub struct OriginExtractor {
        ident: Ident,
        _eq: Token![=>],
        extractor: syn::Expr,
    }
}

impl Parse for HasOriginEnum {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let _vis = input.parse::<Visibility>()?;
        let _enum_token = input.parse::<Token![enum]>()?;
        let ident = input.parse::<Ident>()?;
        let generics = input.parse::<Generics>()?;
        if !generics.params.is_empty() {
            abort!(generics, "Generics are not supported");
        }
        let content;
        let _brace_token = syn::braced!(content in input);
        let variants = content.parse_terminated(HasOriginVariant::parse)?;
        let origin = attrs
            .iter()
            .find_map(|attr| HasOriginAttr::<Origin>::parse(attr).ok())
            .map(|origin| origin.ty)
            .expect("Attribute `#[has_origin(origin = Type)]` is required");
        Ok(HasOriginEnum {
            ident,
            variants,
            origin,
        })
    }
}

impl Parse for HasOriginVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variant = input.parse::<Variant>()?;
        let Variant {
            ident,
            fields,
            attrs,
            ..
        } = variant;
        match fields {
            syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
            fields => abort!(fields, "Only supports tuple variants with single field"),
        };
        let extractor = attrs
            .iter()
            .find_map(|attr| HasOriginAttr::<OriginExtractor>::parse(attr).ok());
        Ok(HasOriginVariant { ident, extractor })
    }
}

pub fn impl_has_origin(enum_: &HasOriginEnum) -> TokenStream {
    let enum_ident = &enum_.ident;
    let enum_origin = &enum_.origin;
    let variants_match_arms = &enum_
        .variants
        .iter()
        .map(|variant| {
            let variant_ident = &variant.ident;
            variant.extractor.as_ref().map_or_else(
                || parse_quote!(#variant_ident(inner) => inner,),
                |extractor| {
                    let extractor_ident = &extractor.ident;
                    let extractor_expr = &extractor.extractor;
                    parse_quote!(#variant_ident(#extractor_ident) => #extractor_expr,)
                },
            )
        })
        .collect::<Vec<syn::Arm>>();

    quote! {
        impl HasOrigin for #enum_ident {
            type Origin = #enum_origin;

            fn origin_id(&self) -> &<Self::Origin as Identifiable>::Id {
                use #enum_ident::*;
                match self {
                    #(
                        #variants_match_arms
                    )*
                }
            }
        }
    }
    .into()
}
