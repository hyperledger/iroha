use proc_macro2::TokenStream;
use proc_macro_error::abort;
use quote::quote;

use crate::{
    ffi_fn,
    impl_visitor::{Arg, FnDescriptor, ReturnArg},
    util::{gen_arg_ffi_to_src, gen_arg_src_to_ffi},
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
                    __opaque_ptr: *mut iroha_ffi::Opaque
                };
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

fn wrap_method(fn_descriptor: &FnDescriptor) -> TokenStream {
    let (method_doc, signature) = (&fn_descriptor.doc, &fn_descriptor.sig);
    let method_body = gen_wrapper_method_body(fn_descriptor);

    quote! {
        #[doc = #method_doc]
        pub #signature {
            #method_body
        }
    }
}

fn gen_wrapper_method_body(fn_descriptor: &FnDescriptor) -> TokenStream {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let ffi_fn_call_stmt = gen_ffi_fn_call_stmt(fn_descriptor);
    let return_stmt = fn_descriptor.output_arg.as_ref().map(gen_return_stmt);

    quote! {
        #input_conversions
        #ffi_fn_call_stmt
        #return_stmt
    }
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    if let Some(arg) = &fn_descriptor.receiver {
        return gen_arg_ffi_to_src(arg, false);
    }

    let mut stmts = quote! {};
    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_arg_src_to_ffi(arg, false));
    }

    stmts
}

fn gen_ffi_fn_call_stmt(fn_descriptor: &FnDescriptor) -> TokenStream {
    let ffi_fn_name = ffi_fn::gen_fn_name(fn_descriptor.self_ty_name(), &fn_descriptor.sig.ident);
    let arg_names: Vec<_> = fn_descriptor.input_args.iter().map(Arg::name).collect();

    quote! {
        let __output = #ffi_fn_name(#(#arg_names),*);
    }
}

fn gen_return_stmt(arg: &ReturnArg) -> TokenStream {
    let (arg_name, output_arg_conversion) = (arg.name(), gen_arg_ffi_to_src(arg, true));

    quote! {
        #output_arg_conversion

        if __output == iroha_ffi::FfiReturn::Ok {
            TryFromReprC::try_from_repr_c(#arg_name).expect("Must not fail");
        } else {
            panic!("{} returned {}", ffi_fn_name, __output);
        }
    }
}
