extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn::{
    spanned::Spanned, FieldPat, FnArg, Ident, ItemFn, Pat, PatIdent, PatReference, PatStruct,
    PatTuple, PatTupleStruct, PatType, Signature,
};

#[proc_macro_attribute]
pub fn log(_attr: TokenStream, item: TokenStream) -> TokenStream {
    if cfg!(debug_assertions) {
        impl_log(item)
    } else {
        item
    }
}

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

fn impl_log(item: TokenStream) -> TokenStream {
    let input: ItemFn = syn::parse_macro_input!(item as ItemFn);
    let ItemFn {
        attrs,
        vis,
        block,
        sig,
        ..
    } = input;
    let Signature {
        output: return_type,
        inputs: params,
        unsafety,
        asyncness,
        constness,
        abi,
        ident,
        generics:
            syn::Generics {
                params: gen_params,
                where_clause,
                ..
            },
        ..
    } = sig;
    let param_names: Vec<_> = params
        .clone()
        .into_iter()
        .flat_map(|param| match param {
            FnArg::Typed(PatType { pat, .. }) => param_names(*pat),
            FnArg::Receiver(_) => Box::new(std::iter::once(Ident::new("self", param.span()))),
        })
        .map(|item| quote!(print!("{} = {:?}, ", stringify!(#item), &#item);))
        .collect();
    let arguments = quote!(#(#param_names)*);
    let ident_str = ident.to_string();
    quote!(
        #(#attrs) *
        #vis #constness #unsafety #asyncness #abi fn #ident<#gen_params>(#params) #return_type
        #where_clause
        {
            print!("{} {}[start]: ",
                std::time::SystemTime::now().duration_since(
                    std::time::SystemTime::UNIX_EPOCH
                    ).expect("SystemTime befor UNIX EPOCH.").as_millis(),
                #ident_str,
            );
            #arguments
            println!("");
            let result = #block;
            println!("{} {}[end]: {:?}",
                std::time::SystemTime::now().duration_since(
                    std::time::SystemTime::UNIX_EPOCH
                    ).expect("SystemTime befor UNIX EPOCH.").as_millis(),
                #ident_str,
                &result
            );
            result
        }
    )
    .into()
}

fn param_names(pat: Pat) -> Box<dyn Iterator<Item = Ident>> {
    match pat {
        Pat::Ident(PatIdent { ident, .. }) => Box::new(std::iter::once(ident)),
        Pat::Reference(PatReference { pat, .. }) => param_names(*pat),
        Pat::Struct(PatStruct { fields, .. }) => Box::new(
            fields
                .into_iter()
                .flat_map(|FieldPat { pat, .. }| param_names(*pat)),
        ),
        Pat::Tuple(PatTuple { elems, .. }) => Box::new(elems.into_iter().flat_map(param_names)),
        Pat::TupleStruct(PatTupleStruct {
            pat: PatTuple { elems, .. },
            ..
        }) => Box::new(elems.into_iter().flat_map(param_names)),
        _ => Box::new(std::iter::empty()),
    }
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
