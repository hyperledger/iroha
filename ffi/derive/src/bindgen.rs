use proc_macro2::Span;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, Type};

use crate::{
    get_ident,
    impl_visitor::{FnArgDescriptor, FnDescriptor},
};

pub fn gen_ffi_fn(fn_descriptor: &FnDescriptor) -> proc_macro2::TokenStream {
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
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_ffi_fn_arg);
    let fn_body = gen_fn_body(fn_descriptor);

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
            #fn_body
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
    let input_conversions = gen_ffi_to_src_conversion_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor);
    let output_conversions = gen_src_to_ffi_conversion_stmts(fn_descriptor);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    parse_quote! {{
        #( #checks )*
        #( #input_conversions )*

        #method_call_stmt

        #( #output_conversions )*
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
        if let Some(stmt) = gen_ptr_null_check_stmt(output_arg) {
            stmts.push(stmt);
        }
        if output_arg.is_slice_ref_mut() {
            let slice_elems_arg_name = gen_slice_elems_arg_name(output_arg);

            stmts.push(parse_quote! {
                if #slice_elems_arg_name.is_null() {
                    return iroha_ffi::FfiResult::ArgIsNull;
                }
            });
        }
    }

    stmts
}

fn gen_ffi_to_src_conversion_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    if let Some(self_arg) = &fn_descriptor.receiver {
        let arg_name = &self_arg.ffi_name;

        match &self_arg.src_type {
            Type::Path(_) => stmts.push(parse_quote! {
                let _handle = #arg_name.read();
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
        stmts.extend(gen_ffi_to_src_arg_conversion_stmts(arg));
    }

    stmts
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor) -> syn::Stmt {
    let method_name = fn_descriptor.method_name;
    let self_type = fn_descriptor.self_ty;

    let receiver = fn_descriptor.receiver.as_ref();
    let self_arg_name = receiver.map_or_else(Vec::new, |arg| {
        if matches!(arg.src_type, Type::Path(_)) {
            return vec![Ident::new("_handle", Span::call_site())];
        }

        vec![arg.ffi_name.clone()]
    });

    let fn_arg_names = fn_descriptor.input_args.iter().map(|arg| &arg.ffi_name);
    parse_quote! { let method_res = #self_type::#method_name(#(#self_arg_name,)* #(#fn_arg_names),*); }
}

fn gen_src_to_ffi_conversion_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    if let Some(output_arg) = ffi_output_arg(fn_descriptor) {
        return gen_src_to_ffi_arg_conversion_stmts(output_arg);
    }

    vec![]
}

fn ffi_output_arg<'tmp: 'ast, 'ast>(
    fn_descriptor: &'tmp FnDescriptor<'ast>,
) -> Option<&'ast FnArgDescriptor> {
    fn_descriptor.output_arg.as_ref().and_then(|output_arg| {
        if let Some(receiver) = &fn_descriptor.receiver {
            if receiver.ffi_name == output_arg.ffi_name {
                return None;
            }
        }

        Some(output_arg)
    })
}

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    if let Some(output_arg) = &fn_descriptor.output_arg {
        let output_arg_name = &output_arg.ffi_name;

        if output_arg.is_slice_ref_mut() {
            let (slice_len_arg_name, slice_elems_arg_name) = (
                gen_slice_len_arg_name(output_arg),
                gen_slice_elems_arg_name(output_arg),
            );

            stmts.push(parse_quote! {{
                let #output_arg_name = core::slice::from_raw_parts_mut(#output_arg_name, #slice_len_arg_name);

                #slice_elems_arg_name.write(method_res.len());
                for (i, elem) in method_res.take(#slice_len_arg_name).enumerate() {
                    #output_arg_name[i] = elem;
                }
            }});
        } else {
            assert!(matches!(output_arg.ffi_type, Type::Ptr(_)));
            stmts.push(parse_quote! { #output_arg_name.write(method_res); });
        }
    }

    stmts
}

fn gen_ffi_fn_arg(fn_arg_descriptor: &FnArgDescriptor) -> proc_macro2::TokenStream {
    let ffi_name = &fn_arg_descriptor.ffi_name;
    let src_type = &fn_arg_descriptor.src_type;
    let ffi_type = &fn_arg_descriptor.ffi_type;

    if fn_arg_descriptor.is_slice_ref() || fn_arg_descriptor.is_slice_ref_mut() {
        let mut tokens = quote! { #ffi_name: #ffi_type, };
        slice_len_arg_to_tokens(src_type, fn_arg_descriptor, &mut tokens);
        tokens
    } else {
        quote! { #ffi_name: #ffi_type }
    }
}

fn gen_slice_elems_arg_name(fn_arg_descriptor: &FnArgDescriptor) -> Ident {
    Ident::new(
        &format!("{}_elems", fn_arg_descriptor.ffi_name),
        Span::call_site(),
    )
}

fn slice_len_arg_to_tokens(
    src_type: &Type,
    ffi_fn_arg: &FnArgDescriptor,
    tokens: &mut proc_macro2::TokenStream,
) {
    let mut slice_len_to_tokens = || {
        let slice_len_arg_name = gen_slice_len_arg_name(ffi_fn_arg);
        tokens.extend(quote! { #slice_len_arg_name: usize });
    };

    match &src_type {
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
                    let slice_elems_arg_name = gen_slice_elems_arg_name(ffi_fn_arg);
                    tokens.extend(quote! {, #slice_elems_arg_name: *mut usize });
                } else {
                    abort!(src_type, "Unsupported impl trait slice type")
                }
            }
        }
        _ => {}
    }
}

/// Returns a null check statement for this argument if it's FFI type is [`Type::Ptr`]
fn gen_ptr_null_check_stmt(fn_arg_descriptor: &FnArgDescriptor) -> Option<syn::Stmt> {
    let arg_name = &fn_arg_descriptor.ffi_name;

    if fn_arg_descriptor.is_ffi_ptr() {
        return Some(parse_quote! {
            if #arg_name.is_null() {
                return iroha_ffi::FfiResult::ArgIsNull;
            }
        });
    }

    None
}

fn gen_dangling_ptr_assignments(fn_descriptor: &FnDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    for arg in &fn_descriptor.input_args {
        if arg.is_slice_ref() {
            stmts.push(gen_dangling_ptr_assignment(arg));
        }
    }
    if let Some(output_arg) = ffi_output_arg(fn_descriptor) {
        if output_arg.is_slice_ref_mut() {
            stmts.push(gen_dangling_ptr_assignment(output_arg));
        }
    }

    stmts
}

// NOTE: `slice::from_raw_parts` takes a non-null aligned pointer
fn gen_dangling_ptr_assignment(fn_arg_descriptor: &FnArgDescriptor) -> syn::Stmt {
    let (arg_name, slice_len_arg_name) = (
        &fn_arg_descriptor.ffi_name,
        gen_slice_len_arg_name(fn_arg_descriptor),
    );

    parse_quote! {
        let #arg_name = if #slice_len_arg_name == 0_usize {
            core::ptr::NonNull::dangling().as_ptr()
        } else { #arg_name };
    }
}

fn gen_slice_len_arg_name(fn_arg_descriptor: &FnArgDescriptor) -> Ident {
    Ident::new(
        &format!("{}_len", fn_arg_descriptor.ffi_name),
        Span::call_site(),
    )
}

fn gen_ffi_to_src_impl_into_iterator_conversion_stmts(
    fn_arg_descriptor: &FnArgDescriptor,
    ffi_type: &syn::TypePtr,
) -> Vec<syn::Stmt> {
    let slice_len_arg_name = gen_slice_len_arg_name(fn_arg_descriptor);

    let arg_name = &fn_arg_descriptor.ffi_name;
    let mut stmts = vec![parse_quote! {
        let #arg_name = core::slice::from_raw_parts(#arg_name, #slice_len_arg_name).into_iter();
    }];

    match &*ffi_type.elem {
        Type::Path(type_) => {
            let last_seg = type_.path.segments.last().expect_or_abort("Defined");

            if last_seg.ident == "Pair" {
                stmts.push(parse_quote! {
                    let #arg_name = #arg_name.map(|&iroha_ffi::Pair(key, val)| {
                        (Clone::clone(&*key), Clone::clone(&*val))
                    });
                });
            } else {
                abort!(last_seg, "Collection item not supported in FFI")
            }
        }
        Type::Ptr(_) => {
            stmts.push(parse_quote! {
                let #arg_name = #arg_name.map(|&ptr| Clone::clone(&*ptr));
            });
        }
        _ => abort!(fn_arg_descriptor.src_type, "Unsupported FFI type"),
    }

    stmts
}

fn gen_ffi_to_src_arg_conversion_stmts(fn_arg_descriptor: &FnArgDescriptor) -> Vec<syn::Stmt> {
    let mut stmts = vec![];

    let arg_name = &fn_arg_descriptor.ffi_name;
    match (&fn_arg_descriptor.src_type, &fn_arg_descriptor.ffi_type) {
        (Type::Reference(src_ty), Type::Ptr(_)) => {
            if matches!(*src_ty.elem, Type::Slice(_)) {
                // TODO: slice is here
            } else {
                stmts.push(parse_quote! { let #arg_name = &*#arg_name; });
            }
        }
        (Type::ImplTrait(src_ty), Type::Ptr(ffi_ty)) => {
            if let syn::TypeParamBound::Trait(trait_) = &src_ty.bounds[0] {
                let last_seg = &trait_.path.segments.last().expect_or_abort("Defined");

                match last_seg.ident.to_string().as_ref() {
                    "IntoIterator" => {
                        stmts.extend(gen_ffi_to_src_impl_into_iterator_conversion_stmts(
                            fn_arg_descriptor,
                            ffi_ty,
                        ))
                    }
                    "Into" => stmts.push(parse_quote! {
                        let #arg_name = Clone::clone(&*#arg_name);
                    }),
                    _ => abort!(last_seg, "impl Trait type not supported"),
                }
            }
        }
        (Type::Path(_), Type::Ptr(_)) => {
            stmts.push(parse_quote! { let #arg_name = Clone::clone(&*#arg_name); });
        }
        (Type::Path(src_ty), Type::Path(_)) => {
            let last_seg = src_ty.path.segments.last().expect_or_abort("Defined");

            match last_seg.ident.to_string().as_ref() {
                "bool" => stmts.push(parse_quote! { let #arg_name = #arg_name != 0; }),
                // TODO: Wasm conversions?
                _ => unreachable!("Unsupported FFI conversion"),
            }
        }
        _ => abort!(fn_arg_descriptor.src_type, "Unsupported FFI type"),
    }

    stmts
}

fn gen_src_to_ffi_arg_conversion_stmts(fn_arg_descriptor: &FnArgDescriptor) -> Vec<syn::Stmt> {
    let ffi_type = if let Type::Ptr(ffi_type) = &fn_arg_descriptor.ffi_type {
        &*ffi_type.elem
    } else {
        unreachable!("Output must be an out-pointer")
    };

    let mut stmts = vec![];
    match (&fn_arg_descriptor.src_type, ffi_type) {
        (Type::Reference(src_ty), Type::Ptr(_)) => {
            stmts.push(if src_ty.mutability.is_some() {
                parse_quote! { let method_res: *mut _ = method_res; }
            } else {
                parse_quote! { let method_res: *const _ = method_res; }
            });
        }
        (Type::ImplTrait(_), Type::Path(ffi_ty)) => {
            if ffi_ty.path.segments.last().expect_or_abort("Defined").ident != "Pair" {
                abort!(fn_arg_descriptor.src_type, "Unsupported FFI type");
            }

            stmts.push(parse_quote! {
                let method_res = method_res.into_iter().map(|(key, val)| {
                    iroha_ffi::Pair(key as *const _, val as *const _)
                });
            });
        }
        (Type::ImplTrait(_), Type::Ptr(ffi_ty)) => {
            stmts.push(parse_quote! { let method_res = method_res.into_iter(); });

            if !matches!(*ffi_ty.elem, Type::Path(_)) {
                abort!(fn_arg_descriptor.src_type, "Unsupported FFI type");
            }

            stmts.push(if ffi_ty.mutability.is_some() {
                parse_quote! { let method_res = method_res.map(|arg| arg as *mut _); }
            } else {
                parse_quote! { let method_res = method_res.map(|arg| arg as *const _); }
            });
        }
        (Type::Path(src_ty), Type::Ptr(ffi_ty)) => {
            let is_option_type = get_ident(&src_ty.path) == "Option";

            stmts.push(if is_option_type && ffi_ty.mutability.is_some() {
                parse_quote! {
                    let method_res = method_res.map_or(core::ptr::null_mut(), |elem| elem as *mut _);
                }
            } else if is_option_type && ffi_ty.mutability.is_none() {
                parse_quote! {
                    let method_res = method_res.map_or(core::ptr::null(), |elem| elem as *const _);
                }
            } else {
                parse_quote! { let method_res = Box::into_raw(Box::new(method_res)); }
            });
        }
        (Type::Path(src_ty), Type::Path(_)) => {
            let last_seg = src_ty.path.segments.last().expect_or_abort("Defined");

            match last_seg.ident.to_string().as_ref() {
                "bool" => stmts.push(parse_quote! { let method_res = method_res as u8; }),
                "Result" => stmts.push(parse_quote! {
                    let method_res = match method_res {
                        Ok(method_res) => method_res,
                        Err(error) => {
                            return iroha_ffi::FfiResult::ExecutionFail;
                        }
                    };
                }),
                // TODO: Wasm conversions?
                _ => unreachable!("Unsupported FFI conversion"),
            }
        }
        _ => abort!(fn_arg_descriptor.src_type, "Unsupported FFI type"),
    }

    stmts
}
