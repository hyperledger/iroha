extern crate proc_macro;

use crate::proc_macro::TokenStream;
use log::Level;
use proc_macro_error::{abort, abort_call_site, proc_macro_error};
use quote::quote;
use std::str::FromStr;
use syn::{
    spanned::Spanned, AttributeArgs, FieldPat, FnArg, Ident, ItemFn, Lit, NestedMeta, Pat,
    PatIdent, PatReference, PatStruct, PatTuple, PatTupleStruct, PatType, Signature,
};

#[proc_macro_error]
#[proc_macro_attribute]
pub fn log(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input: ItemFn = syn::parse_macro_input!(item as ItemFn);
    let args = syn::parse_macro_input!(attr as AttributeArgs);
    if args.len() > 1 {
        abort_call_site!(format!(
            "Unexpected number of arguments: 1 or 0 arguments expected, got {}",
            args.len()
        ))
    }
    let log_level = args
        .first()
        .map(|nested_meta| {
            if let NestedMeta::Lit(Lit::Str(lit_str)) = nested_meta {
                Level::from_str(&lit_str.value()).expect("Failed to parse log level.")
            } else {
                abort!(nested_meta, "Invalid argument. String expected.")
            }
        })
        .unwrap_or(Level::Debug);
    let log_level = format!("{}", log_level);
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
        .map(|item| quote!(log::log!(log_level, "{} = {:?}, ", stringify!(#item), &#item);))
        .collect();
    let arguments = quote!(#(#param_names)*);
    let ident_str = ident.to_string();
    quote!(
        #(#attrs) *
        #vis #constness #unsafety #asyncness #abi fn #ident<#gen_params>(#params) #return_type
        #where_clause
        {
            let log_level = <log::Level as std::str::FromStr>::from_str(#log_level).expect("Failed to parse log level.");
            log::log!(log_level, "{}[start]: ",
                #ident_str,
            );
            #arguments
            let result = #block;
            log::log!(log_level, "{}[end]: {:?}",
                #ident_str,
                &result
            );
            result
        }
    )
    .into()
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

#[proc_macro_derive(FromVariant)]
pub fn from_variant_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    impl_from_variant(&ast)
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

const CONTAINERS: &[&str] = &["Box", "RefCell", "Cell", "Rc", "Arc", "Mutex", "RwLock"];

fn get_type_argument<'a, 'b>(
    s: &'a str,
    ty: &'b syn::TypePath,
) -> Option<&'b syn::GenericArgument> {
    let segments = &ty.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let syn::PathArguments::AngleBracketed(ref bracketed_arguments) = segments[0].arguments {
        assert_eq!(bracketed_arguments.args.len(), 1);
        Some(&bracketed_arguments.args[0])
    } else {
        unreachable!("No other arguments for types in enum variants possible")
    }
}

fn from_container_variant_internal(
    into_ty: &syn::Ident,
    from_variant: &syn::Ident,
    from_ty: &syn::GenericArgument,
    container_ty: &syn::TypePath,
) -> proc_macro2::TokenStream {
    quote! {
        impl std::convert::From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #from_variant (#container_ty :: new(origin))
            }
        }
    }
}

fn from_variant_internal(
    into_ty: &syn::Ident,
    from_variant: &syn::Ident,
    from_ty: &syn::Type,
) -> proc_macro2::TokenStream {
    quote! {
        impl std::convert::From<#from_ty> for #into_ty {
            fn from(origin: #from_ty) -> Self {
                #into_ty :: #from_variant (origin)
            }
        }
    }
}

fn from_variant(
    into_ty: &syn::Ident,
    from_variant: &syn::Ident,
    from_ty: &syn::Type,
) -> proc_macro2::TokenStream {
    let from_orig = from_variant_internal(into_ty, from_variant, from_ty);

    if let syn::Type::Path(path) = from_ty {
        let mut code = from_orig;

        for container in CONTAINERS {
            if let Some(inner) = get_type_argument(container, path) {
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| {
                        let mut segment = segment.clone();
                        segment.arguments = Default::default();
                        segment
                    })
                    .collect::<syn::punctuated::Punctuated<_, syn::token::Colon2>>();
                let path = syn::Path {
                    segments,
                    leading_colon: None,
                };
                let path = &syn::TypePath { path, qself: None };

                let from_inner =
                    from_container_variant_internal(into_ty, from_variant, inner, path);
                code = quote! {
                    #code
                    #from_inner
                };
            }
        }

        return code;
    }

    from_orig
}

fn impl_from_variant(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let froms = if let syn::Data::Enum(ref data_enum) = ast.data {
        &data_enum.variants
    } else {
        panic!("Only enums are supported")
    }
    .iter()
    .filter_map(|variant| {
        if let syn::Fields::Unnamed(ref unnamed) = variant.fields {
            if unnamed.unnamed.len() == 1 {
                let variant_type = &unnamed
                    .unnamed
                    .first()
                    .expect("Won't fail as we have more than  one argument for variant")
                    .ty;
                return Some((&variant.ident, variant_type));
            }
        }
        None
    })
    .map(|(ident, ty)| from_variant(name, ident, ty));

    let gen = quote! {
        #(#froms)*
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
