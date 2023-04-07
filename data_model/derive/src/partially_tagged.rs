#![allow(
    clippy::str_to_string,
    clippy::mixed_read_write_in_expression,
    clippy::unwrap_in_result
)]

use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    Attribute, Generics, Ident, Token, Type, Variant, Visibility,
};

pub struct PartiallyTaggedEnum {
    attrs: Vec<Attribute>,
    ident: Ident,
    variants: Punctuated<PartiallyTaggedVariant, Token![,]>,
}

pub struct PartiallyTaggedVariant {
    attrs: Vec<Attribute>,
    ident: Ident,
    ty: Type,
    is_untagged: bool,
}

impl Parse for PartiallyTaggedEnum {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attrs = input.call(Attribute::parse_outer)?;
        let _vis = input.parse::<Visibility>()?;
        let _enum_token = input.parse::<Token![enum]>()?;
        let ident = input.parse::<Ident>()?;
        let generics = input.parse::<Generics>()?;
        if !generics.params.is_empty() {
            abort!(generics, "Generics is not supported");
        }
        let content;
        let _brace_token = syn::braced!(content in input);
        let variants = content.parse_terminated(PartiallyTaggedVariant::parse)?;
        attrs.retain(is_serde_attr);
        Ok(PartiallyTaggedEnum {
            attrs,
            ident,
            variants,
        })
    }
}

impl Parse for PartiallyTaggedVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variant = input.parse::<Variant>()?;
        let Variant {
            ident,
            fields,
            mut attrs,
            ..
        } = variant;
        let field = match fields {
            syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => fields
                .unnamed
                .into_iter()
                .next()
                .expect("Guaranteed to have exactly one field"),
            fields => abort!(fields, "Only supports tuple variants with single field"),
        };
        let ty = field.ty;
        let is_untagged = attrs.iter().any(is_untagged_attr);
        attrs.retain(is_serde_attr);
        Ok(PartiallyTaggedVariant {
            attrs,
            ident,
            ty,
            is_untagged,
        })
    }
}

impl PartiallyTaggedEnum {
    fn variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        self.variants.iter()
    }

    fn untagged_variants(&self) -> impl Iterator<Item = &PartiallyTaggedVariant> {
        self.variants.iter().filter(|variant| variant.is_untagged)
    }
}

/// Convert from vector of variants to tuple of vectors consisting of variant's fields
fn variants_to_tuple<'lt, I: Iterator<Item = &'lt PartiallyTaggedVariant>>(
    variants: I,
) -> (Vec<&'lt Ident>, Vec<&'lt Type>, Vec<&'lt [Attribute]>) {
    variants.fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut idents, mut types, mut attrs), variant| {
            idents.push(&variant.ident);
            types.push(&variant.ty);
            attrs.push(&variant.attrs);
            (idents, types, attrs)
        },
    )
}

/// Check if enum variant should be treated as untagged
fn is_untagged_attr(attr: &Attribute) -> bool {
    attr == &parse_quote!(#[serde_partially_tagged(untagged)])
}

/// Check if `#[serde...]` attribute
fn is_serde_attr(attr: &Attribute) -> bool {
    attr.path
        .get_ident()
        .map_or_else(|| false, |ident| ident.to_string().eq("serde"))
}

pub fn impl_partially_tagged_serialize(enum_: &PartiallyTaggedEnum) -> TokenStream {
    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let ref_internal_repr_ident = format_ident!("{}RefInternalRepr", enum_ident);
    let (variants_ident, variants_ty, variants_attrs) = variants_to_tuple(enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(enum_.untagged_variants());

    quote! {
        impl ::serde::Serialize for #enum_ident {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                #[derive(::serde::Serialize)]
                #(#enum_attrs)*
                enum #ref_internal_repr_ident<'re> {
                    #(
                        #(
                            #variants_attrs
                        )*
                        #variants_ident(&'re #variants_ty),
                    )*
                }

                #[inline]
                fn convert(value: &#enum_ident) -> #ref_internal_repr_ident<'_> {
                    match value {
                        #(
                            #enum_ident::#variants_ident(value) => #ref_internal_repr_ident::#variants_ident(&value),
                        )*
                    }
                }

                #[derive(::serde::Serialize)]
                #[serde(untagged)]
                enum SerializeHelper<'re> {
                    #(
                        #(
                            #untagged_variants_attrs
                        )*
                        #untagged_variants_ident(&'re #untagged_variants_ty),
                    )*
                    Other(#ref_internal_repr_ident<'re>),
                }

                let wrapper = match self {
                    #(
                        #enum_ident::#untagged_variants_ident(value) => SerializeHelper::#untagged_variants_ident(value),
                    )*
                    value => SerializeHelper::Other(convert(value)),
                };

                wrapper.serialize(serializer)
            }
        }
    }
    .into()
}

pub fn impl_partially_tagged_deserialize(enum_: &PartiallyTaggedEnum) -> TokenStream {
    let enum_ident = &enum_.ident;
    let enum_attrs = &enum_.attrs;
    let internal_repr_ident = format_ident!("{}InternalRepr", enum_ident);
    let (variants_ident, variants_ty, variants_attrs) = variants_to_tuple(enum_.variants());
    let (untagged_variants_ident, untagged_variants_ty, untagged_variants_attrs) =
        variants_to_tuple(enum_.untagged_variants());

    quote! {
        impl<'de> ::serde::Deserialize<'de> for #enum_ident {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                #[derive(::serde::Deserialize)]
                #(
                    #enum_attrs
                )*
                enum #internal_repr_ident {
                    #(
                        #(
                            #variants_attrs
                        )*
                        #variants_ident(#variants_ty),
                    )*
                }

                #[inline]
                fn convert(internal: #internal_repr_ident) -> #enum_ident {
                    match internal {
                        #(
                            #internal_repr_ident::#variants_ident(value) => #enum_ident::#variants_ident(value),
                        )*
                    }
                }

                #[derive(::serde::Deserialize)]
                #[serde(untagged)]
                enum DeserializeHelper {
                    #(
                        #(
                            #untagged_variants_attrs
                        )*
                        #untagged_variants_ident(#untagged_variants_ty),
                    )*
                    Other(#internal_repr_ident),
                }

                let wrapper = DeserializeHelper::deserialize(deserializer)?;
                match wrapper {
                    #(
                        DeserializeHelper::#untagged_variants_ident(value) => Ok(#enum_ident::#untagged_variants_ident(value)),
                    )*
                    DeserializeHelper::Other(value) => Ok(convert(value)),
                }
            }
        }
    }
    .into()
}
