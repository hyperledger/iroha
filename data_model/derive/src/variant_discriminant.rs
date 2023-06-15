use iroha_macro_utils::AttrParser;
use proc_macro::TokenStream;
use proc_macro_error::{abort, OptionExt as _};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Attribute, Generics, Ident, Token, Type, Visibility,
};

mod kw {
    syn::custom_keyword!(name);
}

pub struct VariantDiscriminantEnum {
    variants: Punctuated<Variant, Token![,]>,
    discriminant_type: Type,
}

impl Parse for VariantDiscriminantEnum {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let _vis = input.parse::<Visibility>()?;
        let _enum_token = input.parse::<Token![enum]>()?;
        let _ident = input.parse::<Ident>()?;
        let generics = input.parse::<Generics>()?;
        if !generics.params.is_empty() {
            abort!(generics, "Generics are not supported");
        }
        let content;
        let _brace_token = syn::braced!(content in input);
        let variants = content.parse_terminated(Variant::parse)?;
        let discriminant_type = attrs
            .iter()
            .find_map(|attr| VariantDiscriminantAttr::<Name>::parse(attr).ok())
            .map(|name_attr| name_attr.ty)
            .expect_or_abort("Attribute `#[strum_discriminants(name(...))]` is required");
        Ok(Self {
            variants,
            discriminant_type,
        })
    }
}

pub struct Variant {
    ty: Type,
    discriminant_name: Ident,
}

impl Parse for Variant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let syn::Variant { ident, fields, .. } = input.parse::<syn::Variant>()?;
        let unnamed = match fields {
            syn::Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => unnamed,
            fields => abort!(fields, "Only supports tuple variants with single field"),
        };

        let ty = unnamed.unnamed.first().expect("Checked above").ty.clone();
        Ok(Self {
            ty,
            discriminant_name: ident,
        })
    }
}

pub struct Name {
    _kw: kw::name,
    _paren: syn::token::Paren,
    ty: Type,
}

impl Parse for Name {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let kw = input.parse::<kw::name>()?;
        let content;
        let paren = syn::parenthesized!(content in input);
        let ty = content.parse::<Type>()?;
        Ok(Self {
            _kw: kw,
            _paren: paren,
            ty,
        })
    }
}

struct VariantDiscriminantAttr<T>(core::marker::PhantomData<T>);

impl<T: Parse> AttrParser<T> for VariantDiscriminantAttr<T> {
    const IDENT: &'static str = "variant_discriminant";
}

pub fn impl_variant_discriminant(enum_: &VariantDiscriminantEnum) -> TokenStream {
    let discriminant_type = &enum_.discriminant_type;
    let impls = enum_.variants.iter().map(|variant| {
        let Variant {
            ty,
            discriminant_name,
        } = variant;
        // In order to make doc-tests work, we need to not to use full path to `AssociatedConstant`
        quote! {
            impl AssociatedConstant<#discriminant_type> for #ty {
                const VALUE: #discriminant_type = #discriminant_type::#discriminant_name;
            }
        }
    });
    quote! {#(#impls)*}.into()
}
