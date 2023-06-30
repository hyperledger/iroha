//! This crate provides [`wrap`] and [`wrap_signature`] attribute macros to wrap a host-defined
//! function into another function which signature will be compatible with `wasmtime` crate to be
//! successfully exported.

use std::ops::Deref;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, diagnostic, proc_macro_error, Diagnostic, Level, OptionExt as _};
use quote::quote;
use syn::{parse_quote, punctuated::Punctuated};

mod kw {
    syn::custom_keyword!(state);
}

struct StateAttr {
    _state: kw::state,
    _equal: syn::Token![=],
    ty: syn::Type,
}

impl syn::parse::Parse for StateAttr {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let state = input.parse()?;
        let equal = input.parse()?;
        let type_str: syn::LitStr = input.parse()?;
        let ty = syn::parse_str(&type_str.value())?;
        Ok(Self {
            _state: state,
            _equal: equal,
            ty,
        })
    }
}

/// Macro to wrap function with normal parameters and return value to another one which will
/// meet `wasmtime` specifications.
///
/// Describing all possible input and output signatures would be a very big table,
/// so see detailed signature by expanding generated code (i.e. with `cargo expand`).
///
/// # Key notes
///
/// 1. If there is something to encode or decode (input or output) generated signature will always
/// return `Result<..., wasmtime::Error>`
/// 2. If your function returns `T` on success, then generated function will return
/// `Result<WasmUsize, wasmtime::Error>`, where `WasmUsize` is the offset of encoded `T` prefixed with length
/// 3. If your function returns [`Result`] with `wasmtime::Error` on [`Err`], generated function will pop it up
/// 4. If your function returns [`Result`] with custom error, then it will be encoded into memory (as in 2)
/// 5. You can receive constant or mutable reference to *state* as the second parameter of your function
/// 6. You can have only two function parameters, where second is reserved for *state*,
/// if you need more -- use tuple as a first parameter
///
/// # `state` attribute
///
/// You can pass an attribute in the form of `#[wrap(state = "YourStateType")]`.
/// This is needed in cases when it's impossible to infer the state type from the function signature.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn wrap(attr: TokenStream, item: TokenStream) -> TokenStream {
    let state_attr_opt = if attr.is_empty() {
        None
    } else {
        Some(syn::parse_macro_input!(attr as StateAttr))
    };
    let mut fn_item = syn::parse_macro_input!(item as syn::ItemFn);
    let ident = &fn_item.sig.ident;

    let mut inner_fn_item = fn_item.clone();
    let inner_fn_ident = syn::Ident::new(&format!("__{}_inner", ident), ident.span());
    inner_fn_item.sig.ident = inner_fn_ident.clone();

    let fn_class = classify_fn(&fn_item.sig);

    fn_item.sig.inputs = gen_params(
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
        true,
    );

    let output = gen_output(&fn_class);
    fn_item.sig.output = parse_quote! {-> #output};

    let body = gen_body(
        &inner_fn_ident,
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
    );
    fn_item.block = parse_quote!({#body});

    quote! {
        #inner_fn_item

        #fn_item
    }
    .into()
}

/// Macro to wrap trait function signature with normal parameters and return value
/// to another one which will meet `wasmtime` specifications.
///
/// See [`wrap`] for more details.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn wrap_trait_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    let state_attr_opt = if attr.is_empty() {
        None
    } else {
        Some(syn::parse_macro_input!(attr as StateAttr))
    };
    let mut fn_item = syn::parse_macro_input!(item as syn::TraitItemMethod);
    let ident = &fn_item.sig.ident;

    let mut inner_fn_item = fn_item.clone();
    let inner_fn_ident = syn::Ident::new(&format!("__{}_inner", ident), ident.span());
    inner_fn_item.sig.ident = inner_fn_ident;

    let fn_class = classify_fn(&fn_item.sig);

    fn_item.sig.inputs = gen_params(
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
        false,
    );

    let output = gen_output(&fn_class);
    fn_item.sig.output = parse_quote! {-> #output};

    quote! {
        #inner_fn_item

        #fn_item
    }
    .into()
}

/// `with_body` parameter specifies if end function will have a body or not.
/// Depending on this `gen_params()` will either insert `mut` or not.
/// This is required because
/// [patterns are not allowed in functions without body ](https://github.com/rust-lang/rust/issues/35203).
fn gen_params(
    FnClass {
        param,
        state: state_ty_from_fn_sig,
        return_type,
    }: &FnClass,
    state_ty_from_attr: Option<&syn::Type>,
    with_body: bool,
) -> Punctuated<syn::FnArg, syn::Token![,]> {
    let mut params = Punctuated::new();
    if state_ty_from_fn_sig.is_some() || param.is_some() || return_type.is_some() {
        let state_ty = retrieve_state_ty(state_ty_from_attr, state_ty_from_fn_sig.as_ref());
        let mutability = if with_body {
            quote! {mut}
        } else {
            quote! {}
        };
        params.push(parse_quote! {
            #mutability caller: ::wasmtime::Caller<#state_ty>
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
    match (param, return_type) {
        (None, None) => parse_quote! { () },
        (Some(_), None | Some(ReturnType::Result(None, ErrType::WasmtimeError))) => parse_quote! {
            ::wasmtime::Result<()>
        },
        (_, _) => parse_quote! {
            ::wasmtime::Result<iroha_wasm_codec::WasmUsize>
        },
    }
}

/// [`TokenStream2`] wrapper which will be lazily evaluated
///
/// Implements [`quote::ToTokens`] trait
struct LazyTokenStream<F>(once_cell::unsync::Lazy<TokenStream2, F>);

impl<F: FnOnce() -> TokenStream2> LazyTokenStream<F> {
    pub fn new(f: F) -> Self {
        Self(once_cell::unsync::Lazy::new(f))
    }
}

impl<F: FnOnce() -> TokenStream2> quote::ToTokens for LazyTokenStream<F> {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let inner = &*self.0;
        inner.to_tokens(tokens)
    }
}

fn gen_body(
    inner_fn_ident: &syn::Ident,
    FnClass {
        param,
        state: state_ty_from_fn_sig,
        return_type,
    }: &FnClass,
    state_ty_from_attr: Option<&syn::Type>,
) -> TokenStream2 {
    let decode_param = param.as_ref().map_or_else(
        || quote! {},
        |param_ty| quote! {
            let param: #param_ty = ::iroha_wasm_codec::decode_from_memory(&memory, &caller, offset, len)?;
        }
    );

    let pass_state = if state_ty_from_fn_sig.is_some() {
        quote! {caller.data_mut()}
    } else {
        quote! {}
    };

    let get_memory = LazyTokenStream::new(|| {
        let state_ty = retrieve_state_ty(state_ty_from_attr, state_ty_from_fn_sig.as_ref());
        quote! {
            let memory = Runtime::<#state_ty>::get_memory(&mut caller).expect("Checked at instantiation step");
        }
    });

    let get_alloc = LazyTokenStream::new(|| {
        let state_ty = retrieve_state_ty(state_ty_from_attr, state_ty_from_fn_sig.as_ref());
        quote! {
            let alloc_fn = Runtime::<#state_ty>::get_alloc_fn(&mut caller).expect("Checked at instantiation step");
        }
    });

    match (param, return_type) {
        // foo() =>
        // foo()
        //
        // foo() -> Result<(), wasmtime::Error> =>
        // foo() -> Result<(), wasmtime::Error>
        (None, None | Some(ReturnType::Result(None, ErrType::WasmtimeError))) => quote! {
            Self::#inner_fn_ident(#pass_state)
        },
        // foo() -> RetType
        // | foo() -> Result<(), ErrType>
        // | foo() -> Result<OkType, ErrType> =>
        // foo() -> Result<WasmUsize, wasmtime::Error>
        (None, Some(ReturnType::Other(_) | ReturnType::Result(_, ErrType::Other(_)))) => quote! {
            let value = Self::#inner_fn_ident(#pass_state);
            #get_memory
            #get_alloc
            ::iroha_wasm_codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo() -> Result<OkType, wasmtime::Error> =>
        // foo() -> Result<WasmUsize, wasmtime::Error>
        (None, Some(ReturnType::Result(Some(ok_type), ErrType::WasmtimeError))) => quote! {
            let value: #ok_type = Self::#inner_fn_ident(#pass_state)?;
            #get_memory
            #get_alloc
            ::iroha_wasm_codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo(Param) =>
        // foo(WasmUsize, WasmUsize) -> Result<(), wasmtime::Error>
        (Some(_param_ty), None) => quote! {
            #get_memory
            #decode_param

            Self::#inner_fn_ident(param, #pass_state);
            Ok(())
        },
        // foo(Param) -> Result<(), wasmtime::Error> =>
        // foo(WasmUsize, WasmUsize) -> Result<(), wasmtime::Error>
        (Some(_param_ty), Some(ReturnType::Result(None, ErrType::WasmtimeError))) => quote! {
            #get_memory
            #decode_param

            Self::#inner_fn_ident(param, #pass_state)
        },
        // foo(Param) -> RetType
        // | foo(Param) -> Result<(), ErrType>
        // | foo(Param) -> Result<OkType, ErrType> =>
        // foo(WasmUsize, WasmUsize) -> Result<WasmUsize, WasmtimeError>
        (
            Some(_param_ty),
            Some(ReturnType::Other(_) | ReturnType::Result(_, ErrType::Other(_))),
        ) => quote! {
            #get_memory
            #get_alloc
            #decode_param

            let value = Self::#inner_fn_ident(param, #pass_state);
            ::iroha_wasm_codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
        },
        // foo(Param) -> Result<OkType, wasmtime::Error> =>
        // foo(WasmUsize, WasmUsize) -> Result<WasmUsize, wasmtime::Error>
        (Some(_param_ty), Some(ReturnType::Result(Some(ok_type), ErrType::WasmtimeError))) => {
            quote! {
                #get_memory
                #get_alloc
                #decode_param

                let value: #ok_type = Self::#inner_fn_ident(param, #pass_state)?;
                ::iroha_wasm_codec::encode_into_memory(&value, &memory, &alloc_fn, &mut caller)
            }
        }
    }
}

/// Classified function
struct FnClass {
    /// Input parameter
    param: Option<syn::Type>,
    /// Does function require state explicitly?
    state: Option<syn::Type>,
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
    /// `wasmtime::Error` error type
    WasmtimeError,
    /// Something other than `wasmtime::Error`
    #[allow(unused_tuple_struct_fields)] // May be used in future
    Other(syn::Type),
}

fn classify_fn(fn_sig: &syn::Signature) -> FnClass {
    let params = &fn_sig.inputs;
    let (param, state) = classify_params_and_state(params);

    let output = &fn_sig.output;

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

    let syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
        args: generics,
        ..
    }) = &output_last_segment.arguments
    else {
        abort!(
            output_last_segment.arguments,
            "`Result` return type should have generic arguments"
        );
    };

    let ok_type = classify_ok_type(generics);
    let err_type = extract_err_type(generics);

    let err_type_path = unwrap_path(err_type);
    let err_type_last_segment = last_segment(err_type_path);
    let err_type = if err_type_last_segment.ident == "WasmtimeError" {
        ErrType::WasmtimeError
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
) -> (Option<syn::Type>, Option<syn::Type>) {
    match params.len() {
        0 => (None, None),
        1 => {
            let mut params_iter = params.iter();
            let first_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());

            if let Ok(state_ty) = parse_state_param(&first_param) {
                (None, Some(state_ty.clone()))
            } else {
                (Some(first_param.ty.deref().clone()), None)
            }
        }
        2 => {
            let mut params_iter = params.iter();
            let first_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());

            let second_param = extract_type_from_fn_arg(params_iter.next().unwrap().clone());
            match parse_state_param(&second_param) {
                Ok(state_ty) => (Some(first_param.ty.deref().clone()), Some(state_ty.clone())),
                Err(diagnostic) => diagnostic.abort(),
            }
        }
        _ => abort!(params, "No more than 2 parameters are allowed"),
    }
}

fn parse_state_param(param: &syn::PatType) -> Result<&syn::Type, Diagnostic> {
    let syn::Pat::Ident(pat_ident) = &*param.pat else {
        return Err(diagnostic!(
            param,
            Level::Error,
            "State parameter should be an ident"
        ));
    };
    if !["state", "_state"].contains(&&*pat_ident.ident.to_string()) {
        return Err(diagnostic!(
            param,
            Level::Error,
            "State parameter should be named `state` or `_state`"
        ));
    }

    let syn::Type::Reference(ty_ref) = &*param.ty else {
        return Err(diagnostic!(
            param.ty,
            Level::Error,
            "State parameter should be either reference or mutable reference"
        ));
    };

    Ok(&*ty_ref.elem)
}

fn classify_ok_type(
    generics: &Punctuated<syn::GenericArgument, syn::Token![,]>,
) -> Option<syn::Type> {
    let ok_generic = generics
        .first()
        .expect_or_abort("First generic argument expected in `Result` return type");
    let syn::GenericArgument::Type(ok_type) = ok_generic else {
        abort!(
            ok_generic,
            "First generic of `Result` return type expected to be a type"
        );
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
    let syn::GenericArgument::Type(err_type) = err_generic else {
        abort!(
            err_generic,
            "Second generic of `Result` return type expected to be a type"
        );
    };
    err_type
}

fn unwrap_path(ty: &syn::Type) -> &syn::Path {
    let syn::Type::Path(syn::TypePath { ref path, .. }) = *ty else {
        abort!(ty, "Expected path");
    };

    path
}

fn last_segment(path: &syn::Path) -> &syn::PathSegment {
    path.segments
        .last()
        .expect_or_abort("At least one path segment expected")
}

fn retrieve_state_ty<'ty>(
    state_ty_from_attr: Option<&'ty syn::Type>,
    state_ty_from_fn_sig: Option<&'ty syn::Type>,
) -> &'ty syn::Type {
    state_ty_from_attr
        .or(state_ty_from_fn_sig)
        .expect_or_abort("`state` attribute is required")
}
