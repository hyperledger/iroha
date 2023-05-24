//! This crate provides [`wrap`] attribute macro to wrap a host-defined function into another
//! function which signature will be compatible with `wasmtime` crate to be successfully exported.

use std::ops::Deref;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, diagnostic, proc_macro_error, Diagnostic, Level, OptionExt as _};
use quote::quote;
use syn::{parse_quote, punctuated::Punctuated};

/// Macro to wrap function with normal parameters and return value to another one which will
/// meet `wasmtime` specifications.
///
/// Describing all possible input and output signatures would be a very big table,
/// so see detailed signature by expanding generated code (i.e. with `cargo expand`).
///
/// # Key notes
///
/// 1. If there is something to encode or decode (input or output) generated signature will always
/// return `Result<..., Trap>`.
/// 2. If your function returns `T` on success, then generated function will return
/// `Result<WasmUsize, Trap>`, where `WasmUsize` is the offset of encoded `T` prefixed with length
/// 3. If your function returns [`Result`] with `Trap` on [`Err`], generated function will pop it up
/// 4. If your function returns [`Result`] with custom error, then it will be encoded into memory (as in 2)
/// 5. You can receive `&State` or `&mut State` as the second parameter of your function
/// 6. You can have only two function parameters, where second is reserved for `State`,
/// if you need more -- use tuple as a first parameter
#[proc_macro_error]
#[proc_macro_attribute]
pub fn wrap(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let fn_item = syn::parse_macro_input!(item as syn::ItemFn);
    let ident = &fn_item.sig.ident;
    let fn_attrs = &fn_item.attrs;

    let mut inner_fn_item = fn_item.clone();
    let inner_fn_ident = syn::Ident::new(&format!("__{}_inner", ident), ident.span());
    inner_fn_item.sig.ident = inner_fn_ident.clone();
    inner_fn_item.attrs.clear();

    let fn_class = classify_fn(&fn_item);
    let params = gen_params(&fn_class);
    let output = gen_output(&fn_class);
    let body = gen_body(&inner_fn_ident, &fn_class);

    quote! {
        #(#fn_attrs)*
        fn #ident(#params) -> #output {
            #inner_fn_item

            #body
        }

    }
    .into()
}

fn gen_params(
    FnClass {
        param,
        state,
        return_type,
    }: &FnClass,
) -> Punctuated<syn::FnArg, syn::Token![,]> {
    let mut params = Punctuated::new();
    if *state || param.is_some() || return_type.is_some() {
        params.push(parse_quote! {
            mut caller: ::wasmtime::Caller<crate::smartcontracts::wasm::State>
        });
    }

    if param.is_some() {
        params.push(parse_quote! {
            offset: ::iroha_wasm_codec::WasmUsize
        });
        params.push(parse_quote! {
            len: ::iroha_wasm_codec::WasmUsize
        });
    }

    params
}

fn gen_output(
    FnClass {
        param, return_type, ..
    }: &FnClass,
) -> syn::Type {
    let trap_type = quote! {::wasmtime::Trap};

    match (param, return_type) {
        (None, None) => parse_quote! { () },
        (Some(_), None | Some(ReturnType::Result(None, ErrType::Trap))) => parse_quote! {
            ::core::result::Result<(), #trap_type>
        },
        (_, _) => parse_quote! {
            ::core::result::Result<iroha_wasm_codec::WasmUsize, #trap_type>
        },
    }
}

fn gen_body(
    inner_fn_ident: &syn::Ident,
    FnClass {
        param,
        state,
        return_type,
    }: &FnClass,
) -> TokenStream2 {
    let decode_param = param.as_ref().map_or_else(
        || quote! {},
        |param_ty| quote! {
            let param: #param_ty = ::iroha_wasm_codec::decode_from_memory(&memory, &caller, offset, len)?;
        }
    );

    let pass_state = if *state {
        quote! {caller.data_mut()}
    } else {
        quote! {}
    };

    let get_memory = quote! {
        let memory = Runtime::get_memory(&mut caller).expect("Checked at instantiation step");
    };

    let get_alloc = quote! {
        let alloc_fn = Runtime::get_alloc_fn(&mut caller).expect("Checked at instantiation step");
    };

    match (param, return_type) {
        // foo() =>
        // foo()
        //
        // foo() -> Result<(), Trap> =>
        // foo() -> Result<(), Trap>
        (None, None | Some(ReturnType::Result(None, ErrType::Trap))) => quote! {
            #inner_fn_ident(#pass_state)
        },
        // foo() -> RetType
        // | foo() -> Result<(), ErrType>
        // | foo() -> Result<OkType, ErrType> =>
        // foo() -> Result<WasmUsize, Trap>
        (None, Some(ReturnType::Other(_) | ReturnType::Result(_, ErrType::Other(_)))) => quote! {
            let value = #inner_fn_ident(#pass_state);
            #get_memory
            #get_alloc
            crate::smartcontracts::wasm::codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo() -> Result<OkType, Trap> =>
        // foo() -> Result<WasmUsize, Trap>
        (None, Some(ReturnType::Result(Some(ok_type), ErrType::Trap))) => quote! {
            let value: #ok_type = #inner_fn_ident(#pass_state)?;
            #get_memory
            #get_alloc
            crate::smartcontracts::wasm::codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo(Param) =>
        // foo(WasmUsize, WasmUsize) -> Result<(), Trap>
        (Some(_param_ty), None) => quote! {
            #get_memory
            #decode_param

            #inner_fn_ident(param, #pass_state);
            Ok(())
        },
        // foo(Param) -> Result<(), Trap> =>
        // foo(WasmUsize, WasmUsize) -> Result<(), Trap>
        (Some(_param_ty), Some(ReturnType::Result(None, ErrType::Trap))) => quote! {
            #get_memory
            #decode_param

            #inner_fn_ident(param, #pass_state)
        },
        // foo(Param) -> RetType
        // | foo(Param) -> Result<(), ErrType>
        // | foo(Param) -> Result<OkType, ErrType> =>
        // foo(WasmUsize, WasmUsize) -> Result<WasmUsize, Trap>
        (
            Some(_param_ty),
            Some(ReturnType::Other(_) | ReturnType::Result(_, ErrType::Other(_))),
        ) => quote! {
            #get_memory
            #get_alloc
            #decode_param

            let value = #inner_fn_ident(param, #pass_state);
            crate::smartcontracts::wasm::codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo(Param) -> Result<OkType, Trap> =>
        // foo(WasmUsize, WasmUsize) -> Result<WasmUsize, Trap>
        (Some(_param_ty), Some(ReturnType::Result(Some(ok_type), ErrType::Trap))) => quote! {
            #get_memory
            #get_alloc
            #decode_param

            let value: #ok_type = #inner_fn_ident(param, #pass_state)?;
            crate::smartcontracts::wasm::codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
    }
}

/// Classified function
struct FnClass {
    /// Input parameter
    param: Option<syn::Type>,
    /// Does function require state?
    state: bool,
    /// Return type.
    /// [`None`] means `()`
    return_type: Option<ReturnType>,
}

/// Classified return type
enum ReturnType {
    /// [`Result`] type with [`Ok`] and [`Err`]  types respectively
    Result(Option<syn::Type>, ErrType),
    /// Something other than [`Result`]
    #[allow(unused_tuple_struct_fields)] // May be used in future
    Other(syn::Type),
}

/// Classified error type
enum ErrType {
    /// `wasmtime::Trap` error type
    Trap,
    /// Something other than `wasmtime::Trap`
    #[allow(unused_tuple_struct_fields)] // May be used in future
    Other(syn::Type),
}

fn classify_fn(fn_item: &syn::ItemFn) -> FnClass {
    let params = &fn_item.sig.inputs;
    let (param, state) = classify_params_and_state(params);

    let output = &fn_item.sig.output;

    let output_ty = match output {
        syn::ReturnType::Default => {
            return FnClass {
                param,
                state,
                return_type: None,
            }
        }
        syn::ReturnType::Type(_, ref ty) => ty,
    };

    let output_type_path = unwrap_path(output_ty);
    let output_last_segment = last_segment(output_type_path);
    if output_last_segment.ident != "Result" {
        return FnClass {
            param,
            state,
            return_type: Some(ReturnType::Other(*output_ty.clone())),
        };
    }

    let syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments { args: generics, ..}) = &output_last_segment.arguments else {
        abort!(output_last_segment.arguments, "`Result` return type should have generic arguments");
    };

    let ok_type = classify_ok_type(generics);
    let err_type = extract_err_type(generics);

    let err_type_path = unwrap_path(err_type);
    let err_type_last_segment = last_segment(err_type_path);
    let err_type = if err_type_last_segment.ident == "Trap" {
        ErrType::Trap
    } else {
        ErrType::Other(err_type.clone())
    };

    FnClass {
        param,
        state,
        return_type: Some(ReturnType::Result(ok_type, err_type)),
    }
}

fn extract_type_from_fn_arg(fn_arg: syn::FnArg) -> syn::PatType {
    let syn::FnArg::Typed(pat_type) = fn_arg else {
        abort!(fn_arg, "`self` arguments are forbidden");
    };

    pat_type
}

fn classify_params_and_state(
    params: &Punctuated<syn::FnArg, syn::Token![,]>,
) -> (Option<syn::Type>, bool) {
    match params.len() {
        0 => (None, false),
        1 => {
            let mut params_iter = params.iter();
            let first_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());

            if let Ok(()) = is_valid_state_param(&first_param.ty) {
                (None, true)
            } else {
                (Some(first_param.ty.deref().clone()), false)
            }
        }
        2 => {
            let mut params_iter = params.iter();
            let first_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());

            let second_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());
            if let Err(diagnostic) = is_valid_state_param(&second_param.ty) {
                diagnostic.abort()
            }

            (Some(first_param.ty.deref().clone()), true)
        }
        _ => abort!(params, "No more than 2 parameters are allowed"),
    }
}

fn is_valid_state_param(ty: &syn::Type) -> Result<(), Diagnostic> {
    let syn::Type::Reference(state_ty_ref) = ty else {
        return Err(diagnostic!(ty, Level::Error, "State type should be reference to `State`"));
    };
    let syn::Type::Path(ref state_ty_path) = *state_ty_ref.elem else {
        return Err(diagnostic!(state_ty_ref, Level::Error, "State type should be reference to `State`"));
    };

    let last_segment = state_ty_path
        .path
        .segments
        .last()
        .expect_or_abort("Path segment expected in state parameter type");
    if last_segment.ident != "State" {
        return Err(diagnostic!(
            last_segment,
            Level::Error,
            "State parameter type should be `State`"
        ));
    }

    Ok(())
}

fn classify_ok_type(
    generics: &Punctuated<syn::GenericArgument, syn::Token![,]>,
) -> Option<syn::Type> {
    let ok_generic = generics
        .first()
        .expect_or_abort("First generic argument expected in `Result` return type");
    let syn::GenericArgument::Type(ok_type) = ok_generic else {
        abort!(ok_generic, "First generic of `Result` return type expected to be a type");
    };

    if let syn::Type::Tuple(syn::TypeTuple { elems, .. }) = ok_type {
        (!elems.is_empty()).then_some(ok_type.clone())
    } else {
        Some(ok_type.clone())
    }
}

fn extract_err_type(generics: &Punctuated<syn::GenericArgument, syn::Token![,]>) -> &syn::Type {
    let err_generic = generics
        .iter()
        .nth(1)
        .expect_or_abort("Second generic argument expected in `Result` return type");
    let syn::GenericArgument::Type(err_type) = err_generic else
    {
        abort!(err_generic, "Second generic of `Result` return type expected to be a type");
    };
    err_type
}

fn unwrap_path(ty: &syn::Type) -> &syn::Path {
    let syn::Type::Path(syn::TypePath {ref path, ..}) = *ty else {
        abort!(ty, "Expected path");
    };

    path
}

fn last_segment(path: &syn::Path) -> &syn::PathSegment {
    path.segments
        .last()
        .expect_or_abort("At least one path segment expected")
}
