use proc_macro2::{Span, TokenStream};
use proc_macro_error::OptionExt;
use quote::quote;
use syn::{parse_quote, visit_mut::VisitMut, Ident, Type};

use crate::{
    arg::{Arg, SelfResolver},
    impl_visitor::FnDescriptor,
};

pub fn gen_ffi_fn(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_ffi_fn_name(fn_descriptor);

    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(|arg| gen_ffi_fn_arg(fn_descriptor.self_ty, arg))
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor
        .input_args
        .iter()
        .map(|arg| gen_ffi_fn_arg(fn_descriptor.self_ty, arg))
        .collect();
    let output_arg =
        ffi_output_arg(fn_descriptor).map(|arg| gen_ffi_fn_out_ptr_arg(fn_descriptor.self_ty, arg));
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
        unsafe extern "C" fn #ffi_fn_name(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiResult {
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
    let input_conversions = gen_ffi_to_src_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    parse_quote! {{
        #input_conversions
        #method_call_stmt
        #output_assignment

        iroha_ffi::FfiResult::Ok
    }}
}

fn gen_ffi_to_src_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        let (arg_name, mut src_type) = (&arg.name, arg.src_type.clone());
        SelfResolver::new(fn_descriptor.self_ty).visit_type_mut(&mut src_type);

        stmts = if matches!(arg.src_type, Type::Path(_)) {
            quote! {let __tmp_handle = #arg_name.read();}
        } else {
            quote! {
                // TODO: Handle unwrap
                let #arg_name = <#src_type as iroha_ffi::TryFromFfi>::try_from_ffi(#arg_name).unwrap();
            }
        };
    }

    for arg in &fn_descriptor.input_args {
        let (arg_name, mut src_type) = (&arg.name, arg.src_type.clone());
        SelfResolver::new(fn_descriptor.self_ty).visit_type_mut(&mut src_type);

        stmts.extend(quote! {
            // TODO: Handle unwrap
            let #arg_name = <#src_type as iroha_ffi::TryFromFfi>::try_from_ffi(#arg_name).unwrap();
        });
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
                let __out_ptr = #output_arg_name;
                let #output_arg_name = #method_call;
            }
        },
    )
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

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    if let Some(output_arg) = &fn_descriptor.output_arg {
        let (arg_name, mut out_src_type) = (&output_arg.name, output_arg.src_type.clone());
        SelfResolver::new(fn_descriptor.self_ty).visit_type_mut(&mut out_src_type);

        if let Some(Arg { name, src_type, .. }) = &fn_descriptor.receiver {
            if matches!(src_type, Type::Path(_)) {
                return quote! {__out_ptr.write(#name);};
            }
        }

        return quote! {
            <#out_src_type as iroha_ffi::IntoFfi>::write_out(#arg_name, __out_ptr);
        };
    }

    quote! {}
}

fn gen_ffi_fn_arg(self_ty: &syn::Path, arg: &Arg) -> TokenStream {
    let (ffi_name, mut src_type) = (&arg.name, arg.src_type.clone());
    SelfResolver::new(self_ty).visit_type_mut(&mut src_type);

    quote! { #ffi_name: <#src_type as iroha_ffi::IntoFfi>::FfiType }
}

fn gen_ffi_fn_out_ptr_arg(self_ty: &syn::Path, arg: &Arg) -> TokenStream {
    let (ffi_name, mut src_type) = (&arg.name, arg.src_type.clone());
    SelfResolver::new(self_ty).visit_type_mut(&mut src_type);

    quote! { #ffi_name: <#src_type as iroha_ffi::IntoFfi>::OutFfiType }
}
