use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

use crate::impl_visitor::{ffi_output_arg, Arg, FnDescriptor};

pub fn gen_declaration(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_fn_name(fn_descriptor);
    let ffi_fn_doc = gen_doc(fn_descriptor);
    let fn_signature = gen_signature(&ffi_fn_name, fn_descriptor);

    quote! {
        extern {
            #[doc = #ffi_fn_doc]
            #fn_signature;
        }
    }
}

pub fn gen_definition(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = gen_fn_name(fn_descriptor);
    let ffi_fn_doc = gen_doc(fn_descriptor);
    let fn_signature = gen_signature(&ffi_fn_name, fn_descriptor);
    let ffi_fn_body = gen_body(fn_descriptor);

    quote! {
        #[no_mangle]
        #[doc = #ffi_fn_doc]
        pub unsafe extern "C" #fn_signature {
            #[allow(clippy::shadow_unrelated)]
            let res = std::panic::catch_unwind(|| {
                let fn_body = || #ffi_fn_body;

                if let Err(err) = fn_body() {
                    return err;
                }

                iroha_ffi::FfiReturn::Ok
            });

            match res {
                Ok(res) => res,
                Err(_) => {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    iroha_ffi::FfiReturn::UnrecoverableError
                },
            }
        }
    }
}

pub fn gen_fn_name(fn_descriptor: &FnDescriptor) -> Ident {
    let method_name = format!("__{}", &fn_descriptor.sig.ident);
    let self_ty_name = fn_descriptor
        .self_ty_name()
        .map_or_else(Default::default, ToString::to_string);
    let trait_name = fn_descriptor
        .trait_name()
        .map_or_else(Default::default, |trait_name| format!("__{trait_name}"));

    Ident::new(
        &format!("{}{}{}", self_ty_name, trait_name, method_name),
        proc_macro2::Span::call_site(),
    )
}

fn gen_doc(fn_descriptor: &FnDescriptor) -> String {
    // NOTE: [#docs = "some_doc"] expands to ///some_doc, therefore the leading space
    let method_name = &fn_descriptor.sig.ident;
    let self_type = fn_descriptor
        .self_ty
        .as_ref()
        .and_then(syn::Path::get_ident);
    let trait_name = fn_descriptor
        .trait_name
        .as_ref()
        .and_then(syn::Path::get_ident);

    let path = self_type.map_or_else(
        || method_name.to_string(),
        |self_ty| {
            trait_name.map_or_else(
                || format!("{}::{}", self_ty, method_name),
                // NOTE: Fully-qualified syntax currently not supported
                |trait_| format!("{}::{}", trait_, method_name),
            )
        },
    );

    format!(
        " FFI function equivalent of [`{}`]\n \
          \n \
          # Safety\n \
          \n \
          All of the given pointers must be valid",
        path
    )
}

fn gen_signature(ffi_fn_name: &Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_input_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor.input_args.iter().map(gen_input_arg).collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_out_ptr_arg);

    quote! {
        fn #ffi_fn_name<'__iroha_ffi_itm>(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiReturn
    }
}

fn gen_input_arg(arg: &Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved(false);

    quote! { #arg_name: #arg_type }
}

fn gen_out_ptr_arg(arg: &Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved(true);

    quote! { #arg_name: <#arg_type as iroha_ffi::Output>::OutPtr }
}

fn gen_body(fn_descriptor: &FnDescriptor) -> syn::Block {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    syn::parse_quote! {{
        #input_conversions
        #method_call_stmt
        #output_assignment

        Ok(())
    }}
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        stmts = crate::util::gen_arg_ffi_to_src(arg, false)
    }

    for arg in &fn_descriptor.input_args {
        stmts.extend(crate::util::gen_arg_ffi_to_src(arg, false));
    }

    stmts
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ident = &fn_descriptor.sig.ident;
    let self_type = &fn_descriptor.self_ty;
    let trait_name = &fn_descriptor.trait_name;

    let receiver = fn_descriptor.receiver.as_ref();
    let self_arg_name = receiver.map_or_else(Vec::new, |arg| vec![arg.name().clone()]);

    let fn_arg_names = fn_descriptor.input_args.iter().map(Arg::name);
    let self_ty = self_type.as_ref().map_or_else(
        || quote!(),
        |self_ty| {
            trait_name.as_ref().map_or_else(
                || quote! {#self_ty::},
                |trait_| quote! {<#self_ty as #trait_>::},
            )
        },
    );
    let method_call = quote! {#self_ty #ident(#(#self_arg_name,)* #(#fn_arg_names),*)};

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
    match &fn_descriptor.output_arg {
        Some(output_arg) => {
            let (arg_name, arg_type) = (output_arg.name(), output_arg.ffi_type_resolved(true));
            let output_arg_conversion = crate::util::gen_arg_src_to_ffi(output_arg, true);
            quote! {
                #output_arg_conversion
                iroha_ffi::OutPtrOf::<#arg_type>::write(__out_ptr, #arg_name)?;
            }
        }
        None => quote! {},
    }
}
