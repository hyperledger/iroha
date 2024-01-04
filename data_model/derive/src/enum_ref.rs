use darling::{FromAttributes, FromDeriveInput, FromMeta, FromVariant};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

pub fn impl_enum_ref(input: &syn2::DeriveInput) -> manyhow::Result<TokenStream> {
    let input = EnumRef::from_derive_input(input)?;
    Ok(quote! { #input })
}

#[derive(Clone, Copy)]
enum Transparent {
    Transparent,
    NotTransparent,
}

#[derive(Clone)]
enum EnumRefDeriveAttrs {
    Derive(Vec<darling::ast::NestedMeta>),
}

#[derive(Clone, FromAttributes)]
#[darling(attributes(enum_ref))]
struct EnumRefAttrs {
    derive: EnumRefDeriveAttrs,
}

#[derive(Clone, Copy, FromAttributes)]
#[darling(attributes(enum_ref))]
struct EnumRefVariantAttrs {
    transparent: Transparent,
}

#[derive(Clone)]
struct EnumRefField {
    ty: syn2::Type,
}

#[derive(Clone)]
struct EnumRefVariant {
    ident: syn2::Ident,
    field: EnumRefField,
}

#[derive(Clone)]
struct EnumRef {
    attrs: EnumRefAttrs,
    ident: syn2::Ident,
    generics: syn2::Generics,
    data: darling::ast::Data<EnumRefVariant, darling::util::Ignored>,
}

impl FromMeta for Transparent {
    fn from_none() -> Option<Self> {
        Some(Self::NotTransparent)
    }

    fn from_word() -> darling::Result<Self> {
        Ok(Self::Transparent)
    }
}

impl FromMeta for EnumRefDeriveAttrs {
    fn from_list(items: &[darling::ast::NestedMeta]) -> darling::Result<Self> {
        Ok(Self::Derive(items.to_vec()))
    }
}

impl FromVariant for EnumRefVariant {
    fn from_variant(variant: &syn2::Variant) -> darling::Result<Self> {
        let transparent = EnumRefVariantAttrs::from_attributes(&variant.attrs)?;

        let mut fields: Vec<_> = variant
            .fields
            .iter()
            .map(|field| {
                assert_eq!(field.ident, None);

                EnumRefField {
                    ty: gen_field_ty(transparent.transparent, &field.ty),
                }
            })
            .collect();

        if fields.len() > 1 {
            return Err(darling::Error::custom(
                "Enums with more than 1 unnamed field are not supported",
            )
            .with_span(&variant.fields));
        }

        Ok(Self {
            ident: variant.ident.clone(),
            field: fields.swap_remove(0),
        })
    }
}

impl FromDeriveInput for EnumRef {
    fn from_derive_input(input: &syn2::DeriveInput) -> darling::Result<Self> {
        Ok(Self {
            attrs: EnumRefAttrs::from_attributes(&input.attrs)?,
            ident: gen_enum_ref_ident(&input.ident),
            generics: input.generics.clone(),
            data: darling::ast::Data::try_from(&input.data)?,
        })
    }
}

impl ToTokens for EnumRefAttrs {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let EnumRefDeriveAttrs::Derive(derive) = &self.derive;
        quote! {
            #[derive(#(#derive),*)]
        }
        .to_tokens(tokens);
    }
}

impl ToTokens for EnumRefField {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.ty.to_tokens(tokens);
    }
}

impl ToTokens for EnumRefVariant {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let EnumRefVariant { ident, field } = self;

        quote! {
            #ident(#field)
        }
        .to_tokens(tokens);
    }
}

impl ToTokens for EnumRef {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let EnumRef {
            attrs,
            ident,
            generics,
            data,
        } = self;

        let (impl_generics, _, where_clause) = generics.split_for_impl();
        let variants = if let darling::ast::Data::Enum(variants) = data {
            variants
        } else {
            unreachable!()
        };

        quote! {
            #attrs
            pub(super) enum #ident<'a> #impl_generics #where_clause {
                #(#variants),*
            }
        }
        .to_tokens(tokens);
    }
}

fn gen_enum_ref_ident(ident: &syn2::Ident) -> syn2::Ident {
    syn2::Ident::new(&format!("{ident}Ref"), proc_macro2::Span::call_site())
}

fn gen_field_ty(transparent: Transparent, field_ty: &syn2::Type) -> syn2::Type {
    if matches!(transparent, Transparent::Transparent) {
        if let syn2::Type::Path(ty) = field_ty {
            if let Some(ident) = ty.path.get_ident() {
                let ident = gen_enum_ref_ident(ident);
                return syn2::parse_quote! { #ident<'a> };
            }
        }
    }

    syn2::parse_quote!(&'a #field_ty)
}
