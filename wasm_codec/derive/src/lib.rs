//! This crate provides [`wrap`] and [`wrap_signature`] attribute macros to wrap a host-defined
//! function into another function which signature will be compatible with `wasmtime` crate to be
//! successfully exported.

use std::ops::Deref;

use iroha_macro_utils::Emitter;
use manyhow::{bail, emit, manyhow, Result};
use proc_macro2::TokenStream;
use quote::quote;
use syn2::{parse_quote, punctuated::Punctuated};

mod kw {
    syn2::custom_keyword!(state);
}

struct StateAttr {
    _state: kw::state,
    _equal: syn2::Token![=],
    ty: syn2::Type,
}

impl syn2::parse::Parse for StateAttr {
    fn parse(input: syn2::parse::ParseStream) -> syn2::Result<Self> {
        let state = input.parse()?;
        let equal = input.parse()?;
        let type_str: syn2::LitStr = input.parse()?;
        let ty = syn2::parse_str(&type_str.value())?;
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
#[manyhow]
#[proc_macro_attribute]
pub fn wrap(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let state_attr_opt: Option<StateAttr> = if attr.is_empty() {
        None
    } else if let Some(v) = emitter.handle(syn2::parse2(attr)) {
        Some(v)
    } else {
        return emitter.finish_token_stream();
    };

    let Some(fn_item): Option<syn2::ItemFn> = emitter.handle(syn2::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let parsing_result = impl_wrap_fn(&mut emitter, &state_attr_opt, fn_item);

    if let Some(result) = parsing_result {
        emitter.finish_token_stream_with(result)
    } else {
        emitter.finish_token_stream()
    }
}

fn impl_wrap_fn(
    emitter: &mut Emitter,
    state_attr_opt: &Option<StateAttr>,
    mut fn_item: syn2::ItemFn,
) -> Option<TokenStream> {
    let ident = &fn_item.sig.ident;

    let mut inner_fn_item = fn_item.clone();
    let inner_fn_ident = syn2::Ident::new(&format!("__{ident}_inner"), ident.span());
    inner_fn_item.sig.ident = inner_fn_ident.clone();

    let fn_class = classify_fn(emitter, &fn_item.sig)?;

    fn_item.sig.inputs = gen_params(
        emitter,
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
        true,
    )?;

    let output = gen_output(&fn_class);
    fn_item.sig.output = parse_quote! {-> #output};

    let body = gen_body(
        emitter,
        &inner_fn_ident,
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
    )?;
    fn_item.block = parse_quote!({#body});

    Some(quote! {
        #inner_fn_item

        #fn_item
    })
}

/// Macro to wrap trait function signature with normal parameters and return value
/// to another one which will meet `wasmtime` specifications.
///
/// See [`wrap`] for more details.
#[manyhow]
#[proc_macro_attribute]
pub fn wrap_trait_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut emitter = Emitter::new();

    let state_attr_opt: Option<StateAttr> = if attr.is_empty() {
        None
    } else if let Some(v) = emitter.handle(syn2::parse2(attr)) {
        Some(v)
    } else {
        return emitter.finish_token_stream();
    };

    let Some(fn_item): Option<syn2::TraitItemFn> = emitter.handle(syn2::parse2(item)) else {
        return emitter.finish_token_stream();
    };

    let parsing_result = impl_wrap_trait_fn(&mut emitter, &state_attr_opt, fn_item);

    if let Some(result) = parsing_result {
        emitter.finish_token_stream_with(result)
    } else {
        emitter.finish_token_stream()
    }
}

fn impl_wrap_trait_fn(
    emitter: &mut Emitter,
    state_attr_opt: &Option<StateAttr>,
    mut fn_item: syn2::TraitItemFn,
) -> Option<TokenStream> {
    let ident = &fn_item.sig.ident;

    let mut inner_fn_item = fn_item.clone();
    let inner_fn_ident = syn2::Ident::new(&format!("__{ident}_inner"), ident.span());
    inner_fn_item.sig.ident = inner_fn_ident;

    let fn_class = classify_fn(emitter, &fn_item.sig)?;

    fn_item.sig.inputs = gen_params(
        emitter,
        &fn_class,
        state_attr_opt.as_ref().map(|state_attr| &state_attr.ty),
        false,
    )?;

    let output = gen_output(&fn_class);
    fn_item.sig.output = parse_quote! {-> #output};

    Some(quote! {
        #inner_fn_item

        #fn_item
    })
}

/// `with_body` parameter specifies if end function will have a body or not.
/// Depending on this `gen_params()` will either insert `mut` or not.
/// This is required because
/// [patterns are not allowed in functions without body ](https://github.com/rust-lang/rust/issues/35203).
fn gen_params(
    emitter: &mut Emitter,
    FnClass {
        param,
        state: state_ty_from_fn_sig,
        return_type,
    }: &FnClass,
    state_ty_from_attr: Option<&syn2::Type>,
    with_body: bool,
) -> Option<Punctuated<syn2::FnArg, syn2::Token![,]>> {
    let mut params = Punctuated::new();
    if state_ty_from_fn_sig.is_some() || param.is_some() || return_type.is_some() {
        let state_ty =
            retrieve_state_ty(emitter, state_ty_from_attr, state_ty_from_fn_sig.as_ref())?;
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

    Some(params)
}

fn gen_output(
    FnClass {
        param, return_type, ..
    }: &FnClass,
) -> syn2::Type {
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

/// [`TokenStream`] wrapper which will be lazily evaluated
///
/// Implements [`quote::ToTokens`] trait
struct LazyTokenStream<F>(once_cell::unsync::Lazy<TokenStream, F>);

impl<F: FnOnce() -> TokenStream> LazyTokenStream<F> {
    pub fn new(f: F) -> Self {
        Self(once_cell::unsync::Lazy::new(f))
    }
}

impl<F: FnOnce() -> TokenStream> quote::ToTokens for LazyTokenStream<F> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let inner = &*self.0;
        inner.to_tokens(tokens);
    }
}

fn gen_body(
    emitter: &mut Emitter,
    inner_fn_ident: &syn2::Ident,
    FnClass {
        param,
        state: state_ty_from_fn_sig,
        return_type,
    }: &FnClass,
    state_ty_from_attr: Option<&syn2::Type>,
) -> Option<TokenStream> {
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

    let memory_state_ty =
        retrieve_state_ty(emitter, state_ty_from_attr, state_ty_from_fn_sig.as_ref())?;
    let get_memory = LazyTokenStream::new(|| {
        quote! {
            let memory = Runtime::<#memory_state_ty>::get_memory(&mut caller).expect("Checked at instantiation step");
        }
    });

    let alloc_state_ty =
        retrieve_state_ty(emitter, state_ty_from_attr, state_ty_from_fn_sig.as_ref())?;
    let get_alloc = LazyTokenStream::new(|| {
        quote! {
            let alloc_fn = Runtime::<#alloc_state_ty>::get_alloc_fn(&mut caller).expect("Checked at instantiation step");
        }
    });

    let output = match (param, return_type) {
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
    };

    Some(output)
}

/// Classified function
struct FnClass {
    /// Input parameter
    param: Option<syn2::Type>,
    /// Does function require state explicitly?
    state: Option<syn2::Type>,
    /// Return type.
    /// [`None`] means `()`
    return_type: Option<ReturnType>,
}

/// Classified return type
enum ReturnType {
    /// [`Result`] type with [`Ok`] and [`Err`]  types respectively
    Result(Option<syn2::Type>, ErrType),
    /// Something other than [`Result`]
    #[allow(unused_tuple_struct_fields)] // May be used in future
    Other(syn2::Type),
}

/// Classified error type
enum ErrType {
    /// `wasmtime::Error` error type
    WasmtimeError,
    /// Something other than `wasmtime::Error`
    #[allow(unused_tuple_struct_fields)] // May be used in future
    Other(syn2::Type),
}

fn classify_fn(emitter: &mut Emitter, fn_sig: &syn2::Signature) -> Option<FnClass> {
    let params = &fn_sig.inputs;
    let (param, state) = classify_params_and_state(emitter, params)?;

    let output = &fn_sig.output;

    let output_ty = match output {
        syn2::ReturnType::Default => {
            return Some(FnClass {
                param,
                state,
                return_type: None,
            })
        }
        syn2::ReturnType::Type(_, ref ty) => ty,
    };

    let output_type_path = unwrap_path(emitter, output_ty)?;
    let output_last_segment = last_segment(emitter, output_type_path)?;
    if output_last_segment.ident != "Result" {
        return Some(FnClass {
            param,
            state,
            return_type: Some(ReturnType::Other(*output_ty.clone())),
        });
    }

    let syn2::PathArguments::AngleBracketed(syn2::AngleBracketedGenericArguments {
        args: generics,
        ..
    }) = &output_last_segment.arguments
    else {
        emit!(
            emitter,
            output_last_segment.arguments,
            "`Result` return type should have generic arguments"
        );
        return None;
    };

    let ok_type = emitter.handle(classify_ok_type(generics))?;
    let err_type = extract_err_type(emitter, generics)?;

    let err_type_path = unwrap_path(emitter, err_type)?;
    let err_type_last_segment = last_segment(emitter, err_type_path)?;
    let err_type = if err_type_last_segment.ident == "WasmtimeError" {
        ErrType::WasmtimeError
    } else {
        ErrType::Other(err_type.clone())
    };

    Some(FnClass {
        param,
        state,
        return_type: Some(ReturnType::Result(ok_type, err_type)),
    })
}

fn extract_type_from_fn_arg(emitter: &mut Emitter, fn_arg: syn2::FnArg) -> Option<syn2::PatType> {
    if let syn2::FnArg::Typed(pat_type) = fn_arg {
        Some(pat_type)
    } else {
        emit!(emitter, fn_arg, "`self` arguments are forbidden");
        None
    }
}

fn classify_params_and_state(
    emitter: &mut Emitter,
    params: &Punctuated<syn2::FnArg, syn2::Token![,]>,
) -> Option<(Option<syn2::Type>, Option<syn2::Type>)> {
    match params.len() {
        0 => Some((None, None)),
        1 => {
            let mut params_iter = params.iter();
            let first_param =
                extract_type_from_fn_arg(emitter, params_iter.next().unwrap().clone())?;

            if let Ok(state_ty) = parse_state_param(&first_param) {
                Some((None, Some(state_ty.clone())))
            } else {
                Some((Some(first_param.ty.deref().clone()), None))
            }
        }
        2 => {
            let mut params_iter = params.iter();
            let first_param =
                extract_type_from_fn_arg(emitter, params_iter.next().unwrap().clone())?;

            let second_param =
                extract_type_from_fn_arg(emitter, params_iter.next().unwrap().clone())?;

            let Some(state_ty) = emitter.handle(parse_state_param(&second_param)) else {
                return None;
            };
            Some((Some(first_param.ty.deref().clone()), Some(state_ty.clone())))
        }
        _ => {
            emit!(emitter, params, "No more than 2 parameters are allowed");
            None
        }
    }
}

fn parse_state_param(param: &syn2::PatType) -> Result<&syn2::Type> {
    let syn2::Pat::Ident(pat_ident) = &*param.pat else {
        bail!(param, "State parameter should be an ident");
    };
    if !["state", "_state"].contains(&&*pat_ident.ident.to_string()) {
        bail!(param, "State parameter should be named `state` or `_state`");
    }

    let syn2::Type::Reference(ty_ref) = &*param.ty else {
        bail!(param.ty, "State parameter should be either reference or mutable reference");
    };

    Ok(&*ty_ref.elem)
}

fn classify_ok_type(
    generics: &Punctuated<syn2::GenericArgument, syn2::Token![,]>,
) -> Result<Option<syn2::Type>> {
    let Some(ok_generic) = generics
        .first() else {
            bail!("First generic argument expected in `Result` return type");
        };
    let syn2::GenericArgument::Type(ok_type) = ok_generic else {
        bail!(ok_generic, "First generic of `Result` return type expected to be a type");
    };

    if let syn2::Type::Tuple(syn2::TypeTuple { elems, .. }) = ok_type {
        Ok((!elems.is_empty()).then_some(ok_type.clone()))
    } else {
        Ok(Some(ok_type.clone()))
    }
}

fn extract_err_type<'arg>(
    emitter: &mut Emitter,
    generics: &'arg Punctuated<syn2::GenericArgument, syn2::Token![,]>,
) -> Option<&'arg syn2::Type> {
    let Some(err_generic) = generics
        .iter()
        .nth(1) else {
            emit!(emitter, "Second generic of `Result` return type expected to be a type");
            return None;
        };

    if let syn2::GenericArgument::Type(err_type) = err_generic {
        Some(err_type)
    } else {
        emit!(
            emitter,
            err_generic,
            "Second generic of `Result` return type expected to be a type"
        );
        None
    }
}

fn unwrap_path<'ty>(emitter: &mut Emitter, ty: &'ty syn2::Type) -> Option<&'ty syn2::Path> {
    if let syn2::Type::Path(syn2::TypePath { ref path, .. }) = ty {
        Some(path)
    } else {
        emit!(emitter, ty, "Expected path");
        None
    }
}

fn last_segment<'path>(
    emitter: &mut Emitter,
    path: &'path syn2::Path,
) -> Option<&'path syn2::PathSegment> {
    path.segments.last().or_else(|| {
        emit!(emitter, "At least one path segment expected");
        None
    })
}

fn retrieve_state_ty<'ty>(
    emitter: &mut Emitter,
    state_ty_from_attr: Option<&'ty syn2::Type>,
    state_ty_from_fn_sig: Option<&'ty syn2::Type>,
) -> Option<&'ty syn2::Type> {
    state_ty_from_attr.or(state_ty_from_fn_sig).or_else(|| {
        emit!(emitter, "`state` attribute is required");
        None
    })
}
