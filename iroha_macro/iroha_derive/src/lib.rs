extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(Io)]
pub fn io_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_io(&ast)
}

#[proc_macro_derive(IntoContract)]
pub fn into_contract_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_into_contract(&ast)
}

#[proc_macro_derive(IntoQuery)]
pub fn into_query_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_into_query(&ast)
}

fn impl_io(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {

        impl std::convert::From<#name> for Vec<u8> {
            fn from(origin: #name) -> Self {
                origin.encode()
            }
        }

        impl std::convert::From<&#name> for Vec<u8> {
            fn from(origin: &#name) -> Self {
                origin.encode()
            }
        }

        impl std::convert::TryFrom<Vec<u8>> for #name {
            type Error = String;

            fn try_from(vector: Vec<u8>) -> Result<Self, Self::Error> {
                #name::decode(&mut vector.as_slice())
                    .map_err(|e| format!(
                            "Failed to deserialize vector {:?} into {}, because: {}.",
                            &vector,
                            stringify!(#name),
                            e
                        )
                    )
            }
        }
    };
    gen.into()
}

fn impl_into_contract(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {

        impl std::convert::From<#name> for Contract {
            fn from(origin: #name) -> Self {
                Contract::#name(origin)
            }
        }
    };
    gen.into()
}

fn impl_into_query(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {

        impl std::convert::From<#name> for IrohaQuery {
            fn from(origin: #name) -> Self {
                IrohaQuery::#name(origin)
            }
        }
    };
    gen.into()
}
