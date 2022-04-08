//! Module with `DumpDecoded` macro implementation

use super::*;

#[cfg(feature = "dump_decoded")]
static mut TYPES: Option<Vec<String>> = None;
const HELPER_ATTR: &str = "dump_decoded";
const NAME_ATTR: &str = "name";

/// Macro to easily check if token matches concrete variant and panic if not
macro_rules! match_token {
    ($e:expr, $p:pat $(if $guard:expr)? => $r:expr) => {
        match $e {
            $p $(if $guard)? => $r,
            _ => panic!(
                "Invalid attribute syntax. Supported: #[{}(<attr> = \"<value>\")]",
                HELPER_ATTR
            ),
        }
    };
}

/// Parse [`HELPER_ATTR`] which is used to configure some parameters
fn parse_helper_attr(ast: &syn::DeriveInput) -> Option<&syn::Attribute> {
    ast.attrs.iter().find(|attr| {
        attr.path
            .segments
            .iter()
            .any(|segment| segment.ident == HELPER_ATTR)
    })
}

/// Parse [`NAME_ATTR`] attribute and returns alternative name for type being processed
///
/// # Panics
/// Panics if invalid syntax was provided. For valid syntax see [`parse_token!`]
fn parse_name_attr(attr: &syn::Attribute) -> String {
    use proc_macro2::TokenTree::*;

    let mut tokens = match_token!(
        attr.tokens.clone().into_iter().next(),
        Some(Group(group)) => group
    )
    .stream()
    .into_iter();

    let attr_name = match_token!(tokens.next(), Some(Ident(ident)) => ident);
    match_token!(tokens.next(), Some(Punct(punct)) if punct.as_char() == '=' => ());
    let attr_value = match_token!(tokens.next(), Some(Literal(literal)) => literal);

    if attr_name != NAME_ATTR {
        panic!("Only `{}` attribute is supported", NAME_ATTR)
    }

    let name = attr_value.to_string();
    name.strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
        .expect("Attribute value should be enclosed by double quotes")
        .to_owned()
}

/// Implementation of `DumpDecoded` derive
///
/// It implements `impl iroha_macro::DumpDecoded for #type_name {}`
/// and fills global vector of type names for future use by `generate_dump_decoded_map!()`
pub fn impl_dump_decoded(ast: &syn::DeriveInput) -> TokenStream {
    #[cfg(not(feature = "dump_decoded"))]
    {
        let _ast = ast;
        return TokenStream::default();
    }

    #[cfg(feature = "dump_decoded")]
    {
        #[allow(unsafe_code)]
        let types = unsafe {
            if TYPES.is_none() {
                TYPES = Some(Vec::new());
            }
            TYPES.as_mut().unwrap()
        };

        let type_name = &ast.ident;
        let type_name_string =
            parse_helper_attr(ast).map_or_else(|| type_name.to_string(), parse_name_attr);

        if types.contains(&type_name_string) {
            panic!(
                "Type with the same name already implements DumpDecoded. \
                 Consider using `#[{}({} = \"AnotherName\")`",
                HELPER_ATTR, NAME_ATTR
            )
        }
        types.push(type_name_string);

        let gen = quote! {
            #[cfg(feature = "dump_decoded")]
            impl iroha_macro::DumpDecoded for #type_name {}
        };
        gen.into()
    }
}

/// Implementation of `generate_dump_decoded_map!()` macro
///
/// It iterates over global vector filled by `#[derive(DumpDecoded)]`
/// and generates global map (Type Name -> `dump_decoded()` ptr)
pub fn impl_generate_dump_decoded_map() -> TokenStream {
    #[cfg(not(feature = "dump_decoded"))]
    return TokenStream::default();

    #[cfg(feature = "dump_decoded")]
    {
        #[allow(unsafe_code)]
        let types = unsafe {
            TYPES.as_mut().expect(
                "There isn't any type using `DumpDecoded` derive macro \
                    or macro expansion order is broken. Try rebuild.",
            )
        };

        let mut pairs = proc_macro2::TokenStream::default();
        for t in types {
            let type_path: syn::Path =
                syn::parse_str(t).unwrap_or_else(|_| panic!("{} is not an identifier", t));
            let pair = quote! {
                (
                    #t.to_owned(),
                    <#type_path as iroha_macro::DumpDecoded>::dump_decoded
                        as fn(&[u8], &mut dyn std::io::Write) -> Result<(), iroha_macro::eyre::Error>
                ),
            };
            pairs.extend(pair);
        }

        quote! {
            #[cfg(feature = "dump_decoded")]
            #[allow(missing_docs)]
            pub mod _dump_decoded_private {
                use super::*;

                use std::io::Write;
                use std::collections::HashMap;

                use iroha_macro::{once_cell::sync::Lazy, DumpDecodedMap};

                pub static MAP: Lazy<DumpDecodedMap> = Lazy::new(|| HashMap::from([#pairs]));
            }
        }
        .into()
    }
}

/// Implementation of `get_dump_decoded_map!()` macro
pub fn impl_get_dump_decoded_map() -> TokenStream {
    quote! {
        & *_dump_decoded_private::MAP
    }
    .into()
}
