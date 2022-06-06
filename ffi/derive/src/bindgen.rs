use proc_macro2::{Span, TokenStream};
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, Type};

use crate::{arg::Arg, impl_visitor::FnDescriptor};

pub fn gen_ffi_fn(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_ffi_fn_name(fn_descriptor);

    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_ffi_fn_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor
        .input_args
        .iter()
        .map(gen_ffi_fn_arg)
        .collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(|arg| {
        let mut arg = arg.clone();

        if !arg.is_iter_or_slice_ref(true) {
            let ffi_type = &arg.ffi_type;
            arg.ffi_type = parse_quote! {*mut #ffi_type};
        }

        gen_ffi_fn_arg(&arg)
    });
    let ffi_fn_body = gen_fn_body(fn_descriptor);

    let ffi_fn_doc = format!(
        " FFI function equivalent of [`{}::{}`]\n \
          \n \
          # Safety\n \
          \n \
          All of the given pointers must be valid",
        fn_descriptor.self_ty.get_ident().expect_or_abort("Defined"),
        fn_descriptor.method_name
    );

    quote! {
        #[doc = #ffi_fn_doc]
        #[no_mangle]
        pub unsafe extern "C" fn #ffi_fn_name(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiResult {
            let res = std::panic::catch_unwind(|| {
                #ffi_fn_body
            });

            match res {
                Ok(res) => res,
                Err(_) => {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    iroha_ffi::FfiResult::UnrecoverableError
                },
            }
        }
    }
}

fn gen_ffi_fn_name(fn_descriptor: &FnDescriptor) -> Ident {
    let self_ty_name = fn_descriptor.self_ty_name();

    Ident::new(
        &format!("{}__{}", self_ty_name, fn_descriptor.method_name),
        Span::call_site(),
    )
}

fn gen_fn_body(fn_descriptor: &FnDescriptor) -> syn::Block {
    let checks = gen_type_check_stmts(fn_descriptor);
    let input_conversions = gen_ffi_to_src_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor);
    let output_conversion = gen_src_to_ffi_stmts(fn_descriptor);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    parse_quote! {{
        #( #checks )*
        #( #input_conversions )*

        #method_call_stmt

        #output_conversion
        #( #output_assignment )*

        iroha_ffi::FfiResult::Ok
    }}
}

fn gen_type_check_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = gen_dangling_ptr_assignments(fn_descriptor);

    fn_descriptor
        .receiver
        .as_ref()
        .map(|self_arg| gen_ptr_null_check_stmt(self_arg).map(|stmt| stmts.push(stmt)));

    for arg in &fn_descriptor.input_args {
        if let Some(stmt) = gen_ptr_null_check_stmt(arg) {
            stmts.push(stmt);
        }
    }

    if let Some(output_arg) = ffi_output_arg(fn_descriptor) {
        let arg_name = &output_arg.name;

        stmts.push(parse_quote! {
            if #arg_name.is_null() {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                return iroha_ffi::FfiResult::ArgIsNull;
            }
        });

        if output_arg.is_iter_or_slice_ref(true) {
            let slice_elems_arg_name = gen_slice_elems_arg_name(output_arg);

            stmts.push(parse_quote! {
                if #slice_elems_arg_name.is_null() {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    return iroha_ffi::FfiResult::ArgIsNull;
                }
            });
        }
    }

    stmts
}

fn gen_ffi_to_src_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    if let Some(self_arg) = &fn_descriptor.receiver {
        let arg_name = &self_arg.name;

        match &self_arg.src_type {
            Type::Path(_) => stmts.push(parse_quote! {
                let __tmp_handle = #arg_name.read();
            }),
            Type::Reference(type_) => {
                stmts.push(if type_.mutability.is_some() {
                    parse_quote! { let #arg_name = &mut *#arg_name; }
                } else {
                    parse_quote! { let #arg_name = &*#arg_name; }
                });
            }
            _ => unreachable!("Self can only be taken by value or by reference"),
        }
    }

    for arg in &fn_descriptor.input_args {
        stmts.push(arg.ffi_to_src.clone());
    }

    stmts
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let method_name = fn_descriptor.method_name;
    let self_type = fn_descriptor.self_ty;

    let receiver = fn_descriptor.receiver.as_ref();
    let self_arg_name = receiver.map_or_else(Vec::new, |arg| {
        if matches!(arg.src_type, Type::Path(_)) {
            return vec![Ident::new("__tmp_handle", Span::call_site())];
        }

        vec![arg.name.clone()]
    });

    let fn_arg_names = fn_descriptor.input_args.iter().map(|arg| &arg.name);
    let method_call = quote! {#self_type::#method_name(#(#self_arg_name,)* #(#fn_arg_names),*)};

    fn_descriptor.output_arg.as_ref().map_or_else(
        || method_call.clone(),
        |output_arg| {
            let output_arg_name = &output_arg.name;

            quote! {
                let __output_ptr = #output_arg_name;
                let #output_arg_name = #method_call;
            }
        },
    )
}

fn gen_src_to_ffi_stmts<'ast>(fn_descriptor: &'ast FnDescriptor) -> Option<&'ast syn::Stmt> {
    if let Some(output_arg) = ffi_output_arg(fn_descriptor) {
        return Some(&output_arg.src_to_ffi);
    }

    None
}

fn ffi_output_arg<'tmp: 'ast, 'ast>(fn_descriptor: &'tmp FnDescriptor<'ast>) -> Option<&'ast Arg> {
    fn_descriptor.output_arg.as_ref().and_then(|output_arg| {
        if let Some(receiver) = &fn_descriptor.receiver {
            if receiver.name == output_arg.name {
                return None;
            }
        }

        Some(output_arg)
    })
}

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    if let Some(output_arg) = &fn_descriptor.output_arg {
        let output_arg_name = &output_arg.name;

        if output_arg.is_iter_or_slice_ref(true) {
            let (slice_len_arg_name, slice_elems_arg_name) = (
                gen_slice_len_arg_name(&output_arg.name),
                gen_slice_elems_arg_name(output_arg),
            );

            stmts.push(parse_quote! {{
                #slice_elems_arg_name.write(#output_arg_name.len());
                // NOTE: https://doc.rust-lang.org/std/primitive.pointer.html#method.offset)
                for (i, elem) in #output_arg_name.take(#slice_len_arg_name).enumerate() {
                    let offset = i.try_into().expect("allocation too large");
                    __output_ptr.offset(offset).write(elem);
                }
            }});
        } else {
            stmts.push(parse_quote! { __output_ptr.write(#output_arg_name); });
        }
    }

    stmts
}

fn gen_ffi_fn_arg(arg: &Arg) -> TokenStream {
    let ffi_name = &arg.name;
    let ffi_type = &arg.ffi_type;

    if arg.is_iter_or_slice_ref(false) || arg.is_iter_or_slice_ref(true) {
        let mut tokens = quote! { #ffi_name: #ffi_type, };
        slice_len_arg_to_tokens(arg, &mut tokens);
        tokens
    } else {
        quote! { #ffi_name: #ffi_type }
    }
}

fn gen_slice_elems_arg_name(arg: &Arg) -> Ident {
    Ident::new(&format!("{}_elems", arg.name), Span::call_site())
}

fn slice_len_arg_to_tokens(arg: &Arg, tokens: &mut TokenStream) {
    let mut slice_len_to_tokens = || {
        let slice_len_arg_name = gen_slice_len_arg_name(&arg.name);
        tokens.extend(quote! { #slice_len_arg_name: usize });
    };

    match &arg.src_type {
        Type::Reference(type_) => {
            if matches!(*type_.elem, Type::Slice(_)) {
                slice_len_to_tokens();
            }
        }
        Type::ImplTrait(type_) => {
            assert_eq!(type_.bounds.len(), 1);

            if let syn::TypeParamBound::Trait(trait_) = &type_.bounds[0] {
                let last_seg = &trait_.path.segments.last().expect_or_abort("Defined");

                if last_seg.ident == "IntoIterator" {
                    slice_len_to_tokens();
                } else if last_seg.ident == "ExactSizeIterator" {
                    slice_len_to_tokens();
                    let slice_elems_arg_name = gen_slice_elems_arg_name(arg);
                    tokens.extend(quote! {, #slice_elems_arg_name: *mut usize });
                } else {
                    abort!(arg.src_type, "Unsupported impl trait slice type")
                }
            }
        }
        _ => {}
    }
}

/// Returns a null check statement for this argument if it's FFI type is [`Type::Ptr`]
fn gen_ptr_null_check_stmt(arg: &Arg) -> Option<syn::Stmt> {
    let arg_name = &arg.name;

    if matches!(arg.ffi_type, Type::Ptr(_)) {
        return Some(parse_quote! {
            if #arg_name.is_null() {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                return iroha_ffi::FfiResult::ArgIsNull;
            }
        });
    }

    None
}

fn gen_dangling_ptr_assignments(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    for arg in &fn_descriptor.input_args {
        if arg.is_iter_or_slice_ref(false) {
            stmts.push(gen_dangling_ptr_assignment(arg));
        }
    }
    if let Some(output_arg) = ffi_output_arg(fn_descriptor) {
        if output_arg.is_iter_or_slice_ref(true) {
            stmts.push(gen_dangling_ptr_assignment(output_arg));
        }
    }

    stmts
}

fn gen_dangling_ptr_assignment(arg: &Arg) -> syn::Stmt {
    let (arg_name, slice_len_arg_name) = (&arg.name, gen_slice_len_arg_name(&arg.name));

    parse_quote! {
        // NOTE: `slice::from_raw_parts` takes a non-null aligned pointer
        let #arg_name = if #slice_len_arg_name == 0_usize {
            core::ptr::NonNull::dangling().as_ptr()
        } else { #arg_name };
    }
}

pub fn gen_slice_len_arg_name(arg_name: &Ident) -> Ident {
    Ident::new(&format!("{}_len", arg_name), Span::call_site())
}
