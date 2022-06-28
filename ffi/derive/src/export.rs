use proc_macro2::{Span, TokenStream};
use proc_macro_error::OptionExt;
use quote::quote;
use syn::{parse_quote, Ident, Type};

use crate::impl_visitor::{Arg, FnDescriptor};

pub fn gen_ffi_fn(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_ffi_fn_name(fn_descriptor);

    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_ffi_fn_input_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor
        .input_args
        .iter()
        .map(gen_ffi_fn_input_arg)
        .collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_ffi_fn_out_ptr_arg);
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

        Ok(())
    }}
}

fn gen_ffi_to_src_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        let arg_name = &arg.name();

        stmts = if matches!(arg.src_type(), Type::Path(_)) {
            quote! {let __tmp_handle = #arg_name.read();}
        } else {
            gen_arg_ffi_to_src(arg)
        };
    }

    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_arg_ffi_to_src(arg));
    }

    stmts
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let method_name = fn_descriptor.method_name;
    let self_type = fn_descriptor.self_ty;

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
        || method_call.clone(),
        |output_arg| {
            let output_arg_name = &output_arg.name();

            quote! {
                let __out_ptr = #output_arg_name;
                let #output_arg_name = #method_call;
            }
        },
    )
}

fn ffi_output_arg<'tmp: 'ast, 'ast>(
    fn_descriptor: &'tmp FnDescriptor<'ast>,
) -> Option<&'ast crate::impl_visitor::ReturnArg<'ast>> {
    fn_descriptor.output_arg.as_ref().and_then(|output_arg| {
        if let Some(receiver) = &fn_descriptor.receiver {
            if receiver.name() == output_arg.name() {
                return None;
            }
        }

        Some(output_arg)
    })
}

pub fn gen_arg_ffi_to_src(arg: &impl crate::impl_visitor::Arg) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type_resolved());
    let store_name = Ident::new(&format!("{}_store", arg_name), Span::call_site());

    if let Type::Reference(ref_type) = &src_type {
        let elem = &ref_type.elem;

        return if ref_type.mutability.is_some() {
            quote! {
                let mut #store_name = Default::default();
                let #arg_name = <#elem as iroha_ffi::TryAsRust>::try_as_rust_mut(#arg_name, &mut #store_name)?;
            }
        } else {
            quote! {
                let mut #store_name = Default::default();
                let #arg_name = <#elem as iroha_ffi::TryAsRust>::try_as_rust_ref(#arg_name, &mut #store_name)?;
            }
        };
    }

    quote! { let #arg_name = <#src_type as iroha_ffi::TryFromFfi>::try_from_ffi(#arg_name)?; }
}

pub fn gen_arg_src_to_ffi(arg: &impl crate::impl_visitor::Arg) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type_resolved());
    let store_name = Ident::new(&format!("{}_store", arg_name), Span::call_site());

    if let Type::Reference(ref_type) = &src_type {
        let elem = &ref_type.elem;

        return if ref_type.mutability.is_some() {
            quote! {
                let mut #store_name = Default::default();
                let #arg_name = <#elem as iroha_ffi::AsFfi>::as_ffi_mut(#arg_name, &mut #store_name);
            }
        } else {
            quote! {
                let mut #store_name = Default::default();
                let #arg_name = <#elem as iroha_ffi::AsFfi>::as_ffi_ref(#arg_name, &mut #store_name);
            }
        };
    }

    quote! { let #arg_name = <#src_type as iroha_ffi::IntoFfi>::into_ffi(#arg_name); }
}

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    if let Some(output_arg) = &fn_descriptor.output_arg {
        if let Some(receiver) = &fn_descriptor.receiver {
            let arg_name = receiver.name();
            let src_type = receiver.src_type();

            if matches!(src_type, Type::Path(_)) {
                return quote! {__out_ptr.write(#arg_name);};
            }
        }

        let arg_name = output_arg.name();
        let arg_type = output_arg.ffi_type_resolved();
        let mut conversion = gen_arg_src_to_ffi(output_arg);
        conversion.extend(quote! {<#arg_type as iroha_ffi::ReprC>::write_out(#arg_name, __out_ptr)})
    }

    quote! {}
}

fn gen_ffi_fn_input_arg(arg: &impl crate::impl_visitor::Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved();

    quote! { #arg_name: #arg_type }
}

fn gen_ffi_fn_out_ptr_arg(arg: &impl crate::impl_visitor::Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved();

    quote! { #arg_name: <#arg_type as iroha_ffi::ReprC>::OutPtr }
}
