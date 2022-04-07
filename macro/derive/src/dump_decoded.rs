//! Module with `DumpDecoded` macro implementation

use super::*;

#[cfg(feature = "dump_decoded")]
static mut TYPES: Option<Vec<String>> = None;

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

        let name = &ast.ident;
        types.push(name.to_string());

        let gen = quote! {
            #[cfg(feature = "dump_decoded")]
            impl iroha_macro::DumpDecoded for #name {}
        };
        gen.into()
    }
}

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
            let type_ident: syn::Ident = syn::parse_str(t).unwrap();
            let pair = quote! {
                (
                    stringify!(#type_ident).to_owned(),
                    <#type_ident as iroha_macro::DumpDecoded>::dump_decoded
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

pub fn impl_get_dump_decoded_map() -> TokenStream {
    quote! {
        & *_dump_decoded_private::MAP
    }
    .into()
}
