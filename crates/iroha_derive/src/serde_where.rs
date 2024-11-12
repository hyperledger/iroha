use iroha_macro_utils::Emitter;
use proc_macro2::TokenStream;
use quote::{ToTokens as _, TokenStreamExt as _};
use syn::{parse_quote, Token};

#[derive(Debug)]
pub struct SerdeWhereArguments {
    generics: Vec<syn::Type>,
}

impl syn::parse::Parse for SerdeWhereArguments {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let generics = syn::punctuated::Punctuated::<_, Token![,]>::parse_terminated(input)?;

        Ok(SerdeWhereArguments {
            generics: generics.into_iter().collect(),
        })
    }
}

pub fn impl_serde_where(
    _emitter: &mut Emitter,
    arguments: SerdeWhereArguments,
    mut input: syn::DeriveInput,
) -> TokenStream {
    fn make_bound<F>(arguments: &SerdeWhereArguments, f: F) -> String
    where
        F: Fn(&syn::Type) -> syn::WherePredicate,
    {
        let mut bound = TokenStream::new();

        bound.append_separated(
            arguments.generics.iter().map(f),
            syn::token::Comma::default(),
        );

        bound.to_string()
    }

    let serialize_bound = make_bound(&arguments, |ty| {
        parse_quote! {
            #ty: serde::Serialize
        }
    });
    let deserialize_bound = make_bound(&arguments, |ty| {
        parse_quote! {
            #ty: serde::Deserialize<'de>
        }
    });

    input.attrs.push(syn::parse_quote! {
        #[serde(bound(
            serialize = #serialize_bound,
            deserialize = #deserialize_bound,
        ))]
    });

    input.to_token_stream()
}
