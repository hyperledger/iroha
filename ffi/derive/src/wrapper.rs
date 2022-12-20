use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;

use crate::{
    ffi_fn,
    impl_visitor::{unwrap_result_type, FnDescriptor},
    util::gen_arg_src_to_ffi,
};

pub fn wrap_as_opaque(input: &syn::DeriveInput) -> TokenStream {
    let attrs = &input.attrs;
    let vis = &input.vis;
    let ident = &input.ident;

    let item_type = match input.data {
        syn::Data::Enum(_) => quote! {enum},
        syn::Data::Struct(_) => quote! {struct},
        syn::Data::Union(_) => quote! {union},
    };

    match &input.data {
        syn::Data::Enum(_) | syn::Data::Struct(_) => {
            quote! {
                #(#attrs)*
                #[repr(transparent)]
                #vis #item_type #ident {
                    __opaque_ptr: *mut iroha_ffi::Extern
                }

                unsafe impl iroha_ffi::ReprC for #ident {}
            }
        }
        syn::Data::Union(_) => {
            abort!(ident, "Unions are not supported")
        }
    }
}

pub fn wrap_impl_item(fns: &[FnDescriptor]) -> TokenStream {
    if fns.is_empty() {
        return quote! {};
    }

    let self_ty_name = fns[0].self_ty_name();
    let methods = fns.iter().map(wrap_method);

    quote! {
        impl #self_ty_name {
            #(#methods)*
        }
    }
}

pub fn wrap_method(fn_descriptor: &FnDescriptor) -> TokenStream {
    let (method_doc, mut signature) = (&fn_descriptor.doc, fn_descriptor.sig.clone());

    let method_body = gen_wrapper_method_body(fn_descriptor);
    if let syn::ReturnType::Type(_, output) = &mut signature.output {
        // Patch the return type to facilitate returning types referencing local store
        **output = syn::parse_quote! {<#output as iroha_ffi::FfiWrapperOutput>::ReturnType};
    }

    quote! {
        #method_doc
        pub #signature {
            #method_body
        }
    }
}

fn gen_wrapper_method_body(fn_descriptor: &FnDescriptor) -> TokenStream {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let ffi_fn_call_stmt = gen_ffi_fn_call_stmt(fn_descriptor);
    let return_stmt = gen_return_stmt(fn_descriptor);

    quote! {
        #input_conversions

        // SAFETY:
        // 1. call to FFI function is safe, i.e. it's implementation is free from UBs.
        // 2. out-pointer is initialized, i.e. MaybeUninit::assume_init() is not UB
        unsafe {
            #ffi_fn_call_stmt
            #return_stmt
        }
    }
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        stmts.extend(gen_arg_src_to_ffi(arg, false));
    }
    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_arg_src_to_ffi(arg, false));
    }
    if let Some(arg) = &fn_descriptor.output_arg {
        let name = &arg.name();

        stmts.extend(quote! {
            let mut #name = core::mem::MaybeUninit::uninit();
        });
    }

    stmts
}

fn gen_ffi_fn_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = ffi_fn::gen_fn_name(fn_descriptor);

    let mut arg_names = quote! {};
    if let Some(arg) = &fn_descriptor.receiver {
        let arg_name = &arg.name();

        arg_names.extend(quote! {
            #arg_name,
        });
    }
    for arg in &fn_descriptor.input_args {
        let arg_name = &arg.name();

        arg_names.extend(quote! {
            #arg_name,
        });
    }
    if let Some(arg) = &fn_descriptor.output_arg {
        let arg_name = &arg.name();

        arg_names.extend(quote! {
            #arg_name.as_mut_ptr()
        });
    }

    let execution_fail_arm = fn_descriptor.output_arg.as_ref().map_or_else(
        || quote! {},
        |output| {
            if unwrap_result_type(output.src_type()).is_some() {
                quote! { iroha_ffi::FfiReturn::ExecutionFail => {return Err(());} }
            } else {
                quote! {}
            }
        },
    );

    quote! {
        let __ffi_return = #ffi_fn_name(#arg_names);

        match __ffi_return {
            iroha_ffi::FfiReturn::Ok => {},
            #execution_fail_arm
            _ => panic!(concat!(stringify!(#ffi_fn_name), " returned {:?}"), __ffi_return)
        }
    }
}

fn gen_return_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    fn_descriptor.output_arg.as_ref().map_or_else(|| quote! {}, |output| {
        let arg_name = &output.name();

        let return_stmt = unwrap_result_type(output.src_type())
            .map_or_else(|| (quote! {#arg_name}), |_| (quote! { Ok(#arg_name) }));

        quote! {
            let #arg_name = #arg_name.assume_init();
            let #arg_name = iroha_ffi::FfiOutPtrRead::try_read_out(#arg_name).expect("Invalid out-pointer value returned");
            #return_stmt
        }
    })
}
