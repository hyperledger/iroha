#![allow(clippy::expect_used, clippy::mixed_read_write_in_expression)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Attribute, Field, Generics, Ident, Token, TypePath, Visibility,
};

pub struct IdInput {
    ident: Ident,
    id_type: TypePath,
}

impl Parse for IdInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let id_type = parse_id_attribute(&attrs);

        let _vis = input.parse::<Visibility>()?;
        let _struct_token = input.parse::<Token![struct]>()?;
        let ident = input.parse()?;
        let _generics = input.parse::<Generics>()?;
        let content;
        let _brace_token = syn::braced!(content in input);
        let _struct_fields = content.parse_terminated::<Field, Token![,]>(Field::parse_named)?;

        Ok(IdInput { ident, id_type })
    }
}

fn impl_ordeqhash(ast: &IdInput) -> proc_macro2::TokenStream {
    let name = &ast.ident;

    quote! {
        impl core::cmp::PartialOrd for #name {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl core::cmp::Ord for #name {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.id().cmp(other.id())
            }
        }

        impl core::cmp::PartialEq for #name {
            fn eq(&self, other: &Self) -> bool {
                self.id() == other.id()
            }
        }

        impl core::cmp::Eq for #name {}

        impl core::hash::Hash for #name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.id().hash(state);
            }
        }
    }
}

pub fn impl_id(ast: &IdInput) -> TokenStream {
    let id = &ast.id_type;
    let name = &ast.ident;

    let ordeqhash = impl_ordeqhash(ast);

    let body = if ast.ident.to_string().starts_with("NewRole") {
        // `NewRole` struct only has unconventional body
        quote! { &self.inner.id }
    } else {
        // Most usual case for many `data_model` structs
        quote! { &self.id }
    };
    quote! {
        impl Identifiable for #name {
            type Id = #id;

            #[inline]
            fn id(&self) -> &Self::Id {
                #body
            }
        }
        #ordeqhash
    }
    .into()
}

/// Find an attribute that is called `id`, parse only the provided
/// literal inside it. E.g. if it is #[id(type = "Id")], only `Id`
/// is extracted. Technically, the first component inside parentheses
/// could be anything with the current implementation.
fn parse_id_attribute(attrs: &[Attribute]) -> TypePath {
    attrs
        .iter()
        .find_map(|attr| {
            attr.path.is_ident("id").then(|| match attr.parse_meta() {
                Ok(syn::Meta::List(syn::MetaList { nested, .. })) => {
                    nested.iter().find_map(|m| match m {
                        syn::NestedMeta::Meta(syn::Meta::NameValue(syn::MetaNameValue {
                            lit: syn::Lit::Str(inner),
                            ..
                        })) => {
                            let path = inner
                                .parse::<syn::TypePath>()
                                .expect("Failed to parse the provided literal");
                            Some(path)
                        }
                        _ => None,
                    })
                }
                _ => None,
            })
        })
        .flatten()
        .expect("Should provide a valid type as an attribute to derive `Identifiable`")
}
