use std::net;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::quote;
use syn::{bracketed, parse::ParseStream, Token};

/// Stringify [`TokenStream`], without inserting any spaces in between
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

enum IpAddress {
    IPv4 {
        ip_tokens: TokenStream,
    },
    // In socket addresses, the IPv6 is wrapped in brackets
    // But to parse the IPv6 we need to remove those brackets
    // so we parse them separately on the `syn` level
    IPv6 {
        #[allow(unused)]
        bracket_token: syn::token::Bracket,
        ip_tokens: TokenStream,
    },
}

impl IpAddress {
    fn parse_v4(input: ParseStream) -> syn::Result<Self> {
        input.step(|cursor| {
            let mut rest = *cursor;

            let mut ip_tokens = TokenStream::new();

            while let Some((tt, next)) = rest.token_tree() {
                match tt {
                    TokenTree::Punct(punct) if punct.as_char() == ':' => {
                        return Ok((IpAddress::IPv4 { ip_tokens }, rest))
                    }
                    other => {
                        ip_tokens.extend([other]);
                        rest = next;
                    }
                }
            }

            Err(cursor.error("Socket address must have a colon in it"))
        })
    }

    fn parse_v6(input: ParseStream) -> syn::Result<Self> {
        let ip_tokens;
        Ok(IpAddress::IPv6 {
            bracket_token: bracketed!(ip_tokens in input),
            ip_tokens: ip_tokens.parse()?,
        })
    }

    fn parse_tokens(&self) -> syn::Result<net::IpAddr> {
        match self {
            IpAddress::IPv4 { ip_tokens } => {
                let ip_string = stringify_tokens(ip_tokens.clone());
                ip_string
                    .parse::<net::Ipv4Addr>()
                    .map(net::IpAddr::V4)
                    .map_err(|e| {
                        syn::Error::new_spanned(
                            ip_tokens,
                            format!("Failed to parse `{}` as an IPv4 address: {}", ip_string, e),
                        )
                    })
            }
            IpAddress::IPv6 { ip_tokens, .. } => {
                let ip_string = stringify_tokens(ip_tokens.clone());
                ip_string
                    .parse::<net::Ipv6Addr>()
                    .map(net::IpAddr::V6)
                    .map_err(|e| {
                        syn::Error::new_spanned(
                            ip_tokens,
                            format!("Failed to parse `{}` as an IPv6 address: {}", ip_string, e),
                        )
                    })
            }
        }
    }
}

impl syn::parse::Parse for IpAddress {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();

        if lookahead.peek(syn::token::Bracket) {
            Self::parse_v6(input)
        } else {
            Self::parse_v4(input)
        }
    }
}

struct SocketAddress {
    ip: IpAddress,
    #[allow(unused)]
    colon: Token![:],
    port: syn::Expr,
}

impl syn::parse::Parse for SocketAddress {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ip = input.parse::<IpAddress>()?;
        let colon = input.parse::<Token![:]>()?;
        let port = input.parse::<syn::Expr>()?;

        Ok(SocketAddress { ip, colon, port })
    }
}

pub fn socket_addr_impl(input: TokenStream) -> TokenStream {
    let socket_address = match syn::parse2::<SocketAddress>(input.clone()) {
        Ok(addr) => addr,
        Err(e) => return e.into_compile_error(),
    };

    let ip_address = match socket_address.ip.parse_tokens() {
        Ok(addr) => addr,
        Err(e) => return e.into_compile_error(),
    };
    let port = socket_address.port;

    match ip_address {
        net::IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            quote! {
                ::iroha_primitives::addr::SocketAddr::Ipv4(
                    ::iroha_primitives::addr::SocketAddrV4 {
                        ip: ::iroha_primitives::addr::Ipv4Addr::new([#a, #b, #c, #d]),
                        port: #port
                    }
                )
            }
        }
        net::IpAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h] = v6.segments();
            quote! {
                ::iroha_primitives::addr::SocketAddr::Ipv6(
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
    fn parse_ipv4() {
        assert_eq!(
            socket_addr_impl(quote!(127.0.0.1:8080)).to_string(),
            quote! {
                ::iroha_primitives::addr::SocketAddr::Ipv4(
                    ::iroha_primitives::addr::SocketAddrV4 {
                        ip: ::iroha_primitives::addr::Ipv4Addr::new([127u8, 0u8, 0u8, 1u8]),
                        port: 8080
                    }
                )
            }
            .to_string()
        );
    }

    #[test]
    fn parse_ipv6() {
        assert_eq!(
            socket_addr_impl(quote!([2001:db8::1]:8080)).to_string(),
            quote! {
                ::iroha_primitives::addr::SocketAddr::Ipv6(
                    ::iroha_primitives::addr::SocketAddrV6 {
                        ip: ::iroha_primitives::addr::Ipv6Addr::new([8193u16 , 3512u16 , 0u16 , 0u16 , 0u16 , 0u16 , 0u16 , 1u16]),
                        port: 8080
                    }
                )
            }
                .to_string()
        );
    }

    #[test]
    fn parse_port_expression() {
        assert_eq!(
            socket_addr_impl(
                quote!(127.0.0.1:unique_port::get_unique_free_port().map_err(Error::msg)?)
            )
            .to_string(),
            quote! {
                ::iroha_primitives::addr::SocketAddr::Ipv4(
                    ::iroha_primitives::addr::SocketAddrV4 {
                        ip: ::iroha_primitives::addr::Ipv4Addr::new([127u8, 0u8, 0u8, 1u8]),
                        port: unique_port::get_unique_free_port().map_err(Error::msg)?
                    }
                )
            }
            .to_string()
        );
    }

    #[test]
    fn error_parens() {
        assert_eq!(
            socket_addr_impl(quote!(127.(0.0.1):8080)).to_string(),
            quote! {
                compile_error! { "Failed to parse `127.(0.0.1)` as an IPv4 address: invalid IPv4 address syntax" }
            }
                .to_string()
        );
    }

    #[test]
    fn error_extra_tokens() {
        assert_eq!(
            socket_addr_impl(quote!(127.0.0.1:8080 1 2 3)).to_string(),
            quote! {
                compile_error! { "unexpected token" }
            }
            .to_string()
        );
    }
}
