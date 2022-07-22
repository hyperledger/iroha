use proc_macro2::{Span, TokenStream};
use proc_macro_error::OptionExt;
use quote::quote;
use syn::{parse_quote, Ident, Type};

use crate::{
    impl_visitor::{ffi_output_arg, Arg, FnDescriptor},
    util,
};

pub fn generate(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_fn_name(fn_descriptor.self_ty_name(), &fn_descriptor.sig.ident);

    #[cfg(not(feature = "client"))]
    return crate::ffi_fn::gen_fn_definition(&ffi_fn_name, &fn_descriptor);
    #[cfg(feature = "client")]
    return crate::ffi_fn::gen_fn_declaration(&ffi_fn_name, &fn_descriptor);
}

#[cfg(feature = "client")]
fn gen_fn_declaration(ffi_fn_name: &Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_ty = fn_descriptor.self_ty.get_ident().expect_or_abort("Defined");
    let ffi_fn_doc = gen_doc(self_ty, &fn_descriptor.sig.ident);
    let fn_signature = gen_signature(&ffi_fn_name, fn_descriptor);

    quote! {
        extern {
            #[doc = #ffi_fn_doc]
            #fn_signature;
        }
    }
}

fn gen_fn_definition(ffi_fn_name: &Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_ty = fn_descriptor.self_ty.get_ident().expect_or_abort("Defined");

    let ffi_fn_doc = gen_doc(self_ty, &fn_descriptor.sig.ident);
    let fn_signature = gen_signature(&ffi_fn_name, fn_descriptor);
    let ffi_fn_body = gen_body(fn_descriptor);

    quote! {
        #[no_mangle]
        #[doc = #ffi_fn_doc]
        unsafe extern "C" #fn_signature {
            #[allow(clippy::shadow_unrelated)]
            let res = std::panic::catch_unwind(|| {
                let fn_body = || #ffi_fn_body;

                if let Err(err) = fn_body() {
                    return err;
                }

                iroha_ffi::FfiResult::Ok
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

pub fn gen_fn_name(self_ty: &Ident, method_name: &syn::Ident) -> syn::Ident {
    Ident::new(
        &format!("{}__{}", self_ty, method_name),
        proc_macro2::Span::call_site(),
    )
}

fn gen_doc(self_ty: &Ident, method_name: &Ident) -> String {
    // NOTE: [#docs = "some_doc"] expands to ///some_doc, therefore the leading space

    format!(
        " FFI function equivalent of [`{}::{}`]\n \
        \n \
        # Safety\n \
        \n \
        All of the given pointers must be valid",
        self_ty, method_name
    )
}

fn gen_signature(ffi_fn_name: &syn::Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_input_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor.input_args.iter().map(gen_input_arg).collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_out_ptr_arg);

    quote! {
        fn #ffi_fn_name<'itm>(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiResult
    }
}

fn gen_body(fn_descriptor: &FnDescriptor) -> syn::Block {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    parse_quote! {{
        #input_conversions
        #method_call_stmt
        #output_assignment

        Ok(())
    }}
}

fn gen_input_arg(arg: &impl Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved();

    quote! { #arg_name: #arg_type }
}

fn gen_out_ptr_arg(arg: &impl Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved();

    quote! { #arg_name: <#arg_type as iroha_ffi::Output>::OutPtr }
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        let arg_name = &arg.name();

        stmts = if matches!(arg.src_type(), Type::Path(_)) {
            quote! {let __tmp_handle = #arg_name.read();}
        } else {
            util::gen_arg_ffi_to_src(arg, false)
        };
    }

    for arg in &fn_descriptor.input_args {
        stmts.extend(util::gen_arg_ffi_to_src(arg, false));
    }

    stmts
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let method_name = &fn_descriptor.sig.ident;
    let self_type = &fn_descriptor.self_ty;

    let receiver = fn_descriptor.receiver.as_ref();
    let self_arg_name = receiver.map_or_else(Vec::new, |arg| {
        if matches!(arg.src_type(), Type::Path(_)) {
            return vec![Ident::new("__tmp_handle", Span::call_site())];
        }

        vec![arg.name().clone()]
    });

    let fn_arg_names = fn_descriptor.input_args.iter().map(Arg::name);
    let method_call = quote! {#self_type::#method_name(#(#self_arg_name,)* #(#fn_arg_names),*)};

    fn_descriptor.output_arg.as_ref().map_or_else(
        || quote! {#method_call;},
        |output_arg| {
            let output_arg_name = &output_arg.name();

            quote! {
                let __out_ptr = #output_arg_name;
                let #output_arg_name = #method_call;
            }
        },
    )
}

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    if let Some(output_arg) = &fn_descriptor.output_arg {
        if let Some(receiver) = &fn_descriptor.receiver {
            let arg_name = receiver.name();
            let src_type = receiver.src_type();

            if matches!(src_type, Type::Path(_)) {
                return quote! {
                    if __out_ptr.is_null() {
                        return Err(iroha_ffi::FfiResult::ArgIsNull);
                    }

                    __out_ptr.write(#arg_name);
                };
            }
        }

        let (arg_name, arg_type) = (output_arg.name(), output_arg.ffi_type_resolved());
        let output_arg_conversion = util::gen_arg_src_to_ffi(output_arg, true);

        return quote! {
            #output_arg_conversion
            iroha_ffi::OutPtrOf::<#arg_type>::write(__out_ptr, #arg_name)?;
        };
    }

    quote! {}
}
