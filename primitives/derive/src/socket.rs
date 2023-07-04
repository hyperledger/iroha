use std::net::SocketAddr;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::quote;

/// Stringify [TokenStream], without inserting any spaces in between
fn stringify_tokens(tokens: TokenStream) -> String {
    let mut result = String::new();

    for token_tree in tokens {
        match token_tree {
            TokenTree::Group(g) => {
                let inner = stringify_tokens(g.stream());

                let bracketed = match g.delimiter() {
                    Delimiter::Parenthesis => format!("({})", inner),
                    Delimiter::Brace => format!("{{{}}}", inner),
                    Delimiter::Bracket => format!("[{}]", inner),
                    Delimiter::None => inner,
                };

                result.push_str(&bracketed);
            }
            o => result.push_str(&o.to_string()),
        }
    }

    result
}

pub fn socket_impl(input: TokenStream) -> TokenStream {
    let input = stringify_tokens(input);

    let addr = match input.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            let message = format!("Failed to parse {:?}: {}", input, e);
            return quote! {
                compile_error!(#message)
            };
        }
    };

    match addr {
        SocketAddr::V4(v4) => {
            let [a, b, c, d] = v4.ip().octets();
            let port = v4.port();
            quote! {
                ::iroha_primitives::addr::SocketAddr::V4(
                    ::iroha_primitives::addr::SocketAddrV4 {
                        ip: ::iroha_primitives::addr::Ipv4Addr::new([#a, #b, #c, #d]),
                        port: #port
                    }
                )
            }
        }
        SocketAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.ip().segments();
            let port = v6.port();
            quote! {
                ::iroha_primitives::addr::SocketAddr::V6(
                    ::iroha_primitives::addr::SocketAddrV6 {
                        ip: ::iroha_primitives::addr::Ipv6Addr::new([#a, #b, #c, #d, #e, #f, #g, #h]),
                        port: #port
                    }
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        assert_eq!(
            socket_impl(quote!(127.0.0.1:8080)).to_string(),
            quote! {
                ::iroha_primitives::addr::SocketAddr::V4(
                    ::iroha_primitives::addr::SocketAddrV4 {
                        ip: ::iroha_primitives::addr::Ipv4Addr::new([127u8, 0u8, 0u8, 1u8]),
                        port: 8080u16
                    }
                )
            }
            .to_string()
        );
    }

    #[test]
    fn smoke_v6() {
        assert_eq!(
            socket_impl(quote!([2001:db8::1]:8080)).to_string(),
            quote! {
                ::iroha_primitives::addr::SocketAddr::V6(
                    ::iroha_primitives::addr::SocketAddrV6 {
                        ip: ::iroha_primitives::addr::Ipv6Addr::new([8193u16 , 3512u16 , 0u16 , 0u16 , 0u16 , 0u16 , 0u16 , 1u16]),
                        port: 8080u16
                    }
                )
            }
            .to_string()
        );
    }

    #[test]
    fn error_parens() {
        assert_eq!(
            socket_impl(quote!(127.(0.0.1):8080)).to_string(),
            quote! {
            compile_error!("Failed to parse \"127.(0.0.1):8080\": invalid socket address syntax")
        }
                .to_string()
        );
    }
}
