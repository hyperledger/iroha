//! Crate with a proc macro for torii endpoint generation
#![allow(clippy::arithmetic)] // We should remove `clippy::restriction`.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, LitInt, Result as SynResult, Token,
};

/// Generate warp filters for endpoints, accepting functions
/// with any positive number of arguments within the range of `u8`.
///
/// Only the endpoint functions stated explicitly in the macro invocation
/// are created.
///
/// There are two kinds of accepted arguments. One is supplying
/// an integer literal denoting the number of arguments in a function
/// that the endpoint accepts. The endpoint name is generated automatically
/// in this case and will be in the shape of `endpoint{arg_count}`.
///
/// Another kind is a colon-separated string literal
/// followed by an integer literal, denoting custom name of the endpoint being
/// created and the number of arguments in a function that it accepts.
///
/// Also relies on `WarpResult` custom wrapper,
/// and thus any module using this macro should also reexport
/// the former, as well as some types from `warp` (see example).
///
/// # Panics:
/// 1) When provided with neither a string nor integer literal.
/// 2) When any of the argument count literals are not unique.
/// 3) When the colon-separated form has spaces in the provided name.
///
/// # Examples
///
/// ```rust
/// use warp::{Rejection, Filter};
/// use std::{convert::Infallible, marker::PhantomData};
/// // use iroha_cli::torii::utils::WarpResult;
/// pub struct WarpResult<O, E>(Result<O, E>);
/// use iroha_cli_derive::generate_endpoints;
///
/// // An example with arguments of both acceptable kinds.
/// // This would generate endpoints accepting functions with
/// // 2, 3, 4 and 5 arguments. The first and the last of them
/// // have the custom names provided, whereas the other two have
/// // defaults, such as `endpoint3`.
/// generate_endpoints!(3, my_endpoint: 2, 4, anotherOne: 5, );
/// ```
#[proc_macro]
pub fn generate_endpoints(input: TokenStream) -> TokenStream {
    let EndpointList(list) = parse_macro_input!(input as EndpointList);
    let arg_names = (1_u8..).map(|count| {
        Ident::new(
            format!("__endpoint_arg_{count}").as_str(),
            Span::call_site(),
        )
    });
    let arg_types = (1_u8..).map(|count| {
        Ident::new(
            format!("__Endpoint_Arg_{count}").as_str(),
            Span::call_site(),
        )
    });
    let mut endpoints = Vec::new();

    for item in list {
        let (fun_name, arg_names, arg_types) = match item {
            EndpointItem::ArgCount(arg_count) => {
                let fun_name = Ident::new(&format!("endpoint{arg_count}"), Span::call_site());
                #[allow(clippy::expect_used)]
                let count = arg_count
                    .base10_parse::<usize>()
                    .expect("Already checked at parse stage");
                let arg_names = arg_names.clone().take(count).collect::<Vec<_>>();
                let arg_types = arg_types.clone().take(count).collect::<Vec<_>>();
                (fun_name, arg_names, arg_types)
            }
            EndpointItem::NameAndArgCount {
                name: fun_name,
                arg_count,
            } => {
                #[allow(clippy::expect_used)]
                let count = arg_count
                    .base10_parse::<usize>()
                    .expect("Already checked at parse stage");
                let arg_names = arg_names.clone().take(count).collect::<Vec<_>>();
                let arg_types = arg_types.clone().take(count).collect::<Vec<_>>();
                (*fun_name, arg_names, arg_types)
            }
        };

        let expanded = quote! {
            #[inline]
            #[allow(clippy::redundant_pub_crate)]
            pub(crate) fn #fun_name < O, E, F, Fut, Fil, #( #arg_types ),* > (
                f: F,
                router: Fil,
            ) -> impl Filter<Extract = (WarpResult<O, E>,), Error = Rejection> + Clone
            where
                Fil: Filter<Extract = ( #( #arg_types ),* ), Error = Rejection> + Clone,
                F: Fn( #( #arg_types ),* ) -> Fut + Copy + Send + Sync + 'static,
                Fut: std::future::Future<Output = Result<O, E>> + Send,
                #( #arg_types: Send ),*
                {
                    router.and_then(move | #( #arg_names ),* | async move {
                        Ok::<_, Infallible>(WarpResult(f( #( #arg_names ),* ).await))
                    })
                }
        };

        endpoints.push(expanded);
    }

    quote! {
        #( #endpoints )*
    }
    .into()
}

#[derive(Debug)]
struct EndpointList(Vec<EndpointItem>);

#[derive(Debug)]
enum EndpointItem {
    NameAndArgCount { arg_count: LitInt, name: Box<Ident> },
    ArgCount(LitInt),
}

impl Parse for EndpointList {
    fn parse(input: ParseStream) -> SynResult<Self> {
        let items = Punctuated::<EndpointItem, Token![,]>::parse_terminated(input)?;
        let mut seen_arg_counts = Vec::new();
        for item in items.iter() {
            match item {
                EndpointItem::NameAndArgCount { arg_count, .. }
                | EndpointItem::ArgCount(arg_count) => {
                    let curr_count = arg_count.base10_parse::<u8>()?;
                    if seen_arg_counts.contains(&curr_count) {
                        return Err(syn::Error::new_spanned(
                            arg_count.token(),
                            "argument counts for all endpoints should be distinct",
                        ));
                    }
                    seen_arg_counts.push(curr_count);
                }
            }
        }

        Ok(Self(items.into_iter().collect()))
    }
}

impl Parse for EndpointItem {
    fn parse(input: ParseStream) -> SynResult<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(LitInt) {
            input.parse().map(EndpointItem::ArgCount)
        } else if lookahead.peek(Ident) {
            let name = input.parse()?;
            let _semicolon: Token![:] = input.parse()?;
            let arg_count = input.parse()?;
            Ok(Self::NameAndArgCount { name, arg_count })
        } else {
            Err(lookahead.error())
        }
    }
}
