use proc_macro2::TokenStream;
use quote::quote;
use syn::{visit_mut::VisitMut, Ident};

use crate::{
    getset_gen::{gen_resolve_type, gen_store_name},
    impl_visitor::{Arg, FnDescriptor},
};

fn prune_fn_declaration_attributes<'a>(attrs: &[&'a syn::Attribute]) -> Vec<&'a syn::Attribute> {
    let mut pruned = Vec::new();

    for attr in attrs {
        if **attr == syn::parse_quote! {#[inline]} {
            continue;
        }

        pruned.push(*attr);
    }

    pruned
}

pub fn gen_declaration(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let ffi_fn_attrs = prune_fn_declaration_attributes(&fn_descriptor.attrs);
    let ffi_fn_name = gen_fn_name(fn_descriptor, trait_name);
    let ffi_fn_doc = gen_doc(fn_descriptor, trait_name);
    let fn_signature = gen_decl_signature(&ffi_fn_name, fn_descriptor);

    quote! {
        extern {
            #[doc = #ffi_fn_doc]
            #(#ffi_fn_attrs)*
            #fn_signature;
        }
    }
}

pub fn gen_definition(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let ffi_fn_attrs = &fn_descriptor.attrs;
    let ffi_fn_name = gen_fn_name(fn_descriptor, trait_name);
    let ffi_fn_doc = gen_doc(fn_descriptor, trait_name);
    let fn_signature = gen_def_signature(&ffi_fn_name, fn_descriptor);
    let ffi_fn_body = gen_body(fn_descriptor, trait_name);

    quote! {
        #[no_mangle]
        #(#ffi_fn_attrs)*
        #[doc = #ffi_fn_doc]
        unsafe extern "C" #fn_signature {
            let fn_ = || {
                let fn_body = || #ffi_fn_body;

                if let Err(err) = fn_body() {
                    return err;
                }

                iroha_ffi::FfiReturn::Ok
            };

            match std::panic::catch_unwind(fn_) {
                Ok(res) => res,
                Err(_) => {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    iroha_ffi::FfiReturn::UnrecoverableError
                },
            }
        }
    }
}

pub fn gen_fn_name(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> Ident {
    let method_name = format!("__{}", &fn_descriptor.sig.ident);
    let self_ty_name = fn_descriptor
        .self_ty_name()
        .map_or_else(Default::default, ToString::to_string);
    let trait_name =
        trait_name.map_or_else(Default::default, |trait_name| format!("__{trait_name}"));

    Ident::new(
        &format!("{self_ty_name}{trait_name}{method_name}"),
        proc_macro2::Span::call_site(),
    )
}

fn gen_doc(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> String {
    let method_name = &fn_descriptor.sig.ident;
    let self_type = fn_descriptor
        .self_ty
        .as_ref()
        .and_then(syn::Path::get_ident);

    let path = self_type.map_or_else(
        || method_name.to_string(),
        |self_ty| {
            trait_name.map_or_else(
                || format!("{self_ty}::{method_name}"),
                // NOTE: Fully-qualified syntax currently not supported
                |trait_| format!("{trait_}::{method_name}"),
            )
        },
    );

    // NOTE: [#docs = "some_doc"] expands to ///some_doc, therefore the leading space
    format!(
        " FFI function equivalent of [`{path}`]\n \
          \n \
          # Safety\n \
          \n \
          All of the given pointers must be valid"
    )
}

fn gen_decl_signature(ffi_fn_name: &Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_decl_input_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor
        .input_args
        .iter()
        .map(gen_decl_input_arg)
        .collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_decl_out_ptr_arg);

    quote! {
        fn #ffi_fn_name(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiReturn
    }
}

fn gen_def_signature(ffi_fn_name: &Ident, fn_descriptor: &FnDescriptor) -> TokenStream {
    let self_arg = fn_descriptor
        .receiver
        .as_ref()
        .map(gen_def_input_arg)
        .map_or_else(Vec::new, |self_arg| vec![self_arg]);
    let fn_args: Vec<_> = fn_descriptor
        .input_args
        .iter()
        .map(gen_def_input_arg)
        .collect();
    let output_arg = ffi_output_arg(fn_descriptor).map(gen_def_out_ptr_arg);

    quote! {
        fn #ffi_fn_name(#(#self_arg,)* #(#fn_args,)* #output_arg) -> iroha_ffi::FfiReturn
    }
}

fn gen_def_input_arg(arg: &Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.ffi_type_resolved();

    quote! { #arg_name: #arg_type }
}

fn gen_def_out_ptr_arg(arg: &Arg) -> TokenStream {
    let (arg_name, arg_type) = (arg.name(), arg.src_type_resolved());
    quote! { #arg_name: *mut <#arg_type as iroha_ffi::FfiOutPtr>::OutPtr }
}

fn gen_decl_input_arg(arg: &Arg) -> TokenStream {
    let arg_name = arg.name();
    let arg_type = arg.wrapper_ffi_type_resolved();

    quote! { #arg_name: #arg_type }
}

fn gen_decl_out_ptr_arg(arg: &Arg) -> TokenStream {
    let (arg_name, arg_type) = (arg.name(), arg.src_type_resolved());
    quote! { #arg_name: *mut <<#arg_type as iroha_ffi::FfiWrapperType>::ReturnType as iroha_ffi::FfiOutPtr>::OutPtr }
}

fn gen_body(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let input_conversions = gen_input_conversion_stmts(fn_descriptor);
    let method_call_stmt = gen_method_call_stmt(fn_descriptor, trait_name);
    let output_assignment = gen_output_assignment_stmts(fn_descriptor);

    quote! {{
        #input_conversions
        #method_call_stmt
        #output_assignment

        Ok(())
    }}
}

fn gen_input_conversion_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    let mut stmts = quote! {};

    if let Some(arg) = &fn_descriptor.receiver {
        stmts = gen_arg_ffi_to_src(arg);
    }

    for arg in &fn_descriptor.input_args {
        stmts.extend(gen_arg_ffi_to_src(arg));
    }

    stmts
}

pub fn gen_arg_ffi_to_src(arg: &Arg) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type_resolved());
    let store_name = gen_store_name(arg_name);

    quote! {
        let mut #store_name = Default::default();
        let #arg_name: #src_type = iroha_ffi::FfiConvert::try_from_ffi(#arg_name, &mut #store_name)?;
    }
}

pub struct InjectColon;
impl VisitMut for InjectColon {
    fn visit_angle_bracketed_generic_arguments_mut(
        &mut self,
        i: &mut syn::AngleBracketedGenericArguments,
    ) {
        i.colon2_token = Some(syn::parse_quote!(::));
    }
}

fn gen_method_call_stmt(fn_descriptor: &FnDescriptor, trait_name: Option<&Ident>) -> TokenStream {
    let ident = &fn_descriptor.sig.ident;
    let self_type = &fn_descriptor.self_ty;

    let receiver = fn_descriptor.receiver.as_ref();
    let self_arg_name = receiver.map_or_else(Vec::new, |arg| vec![arg.name().clone()]);

    let fn_arg_names = fn_descriptor.input_args.iter().map(Arg::name);
    let self_ty = self_type.clone().map_or_else(
        || quote!(),
        |mut self_ty| {
            let mut inject_colon = InjectColon;
            inject_colon.visit_path_mut(&mut self_ty);

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

            if output_arg.src_type_is_empty_tuple() {
                return quote! { let #output_arg_name = #method_call; };
            }

            quote! {
                let __out_ptr = #output_arg_name;
                let #output_arg_name = #method_call;
            }
        },
    )
}

fn gen_output_assignment_stmts(fn_descriptor: &FnDescriptor) -> TokenStream {
    fn_descriptor.output_arg.as_ref().map_or_else(
        || quote! {},
        |out_arg| {
            let (arg_name, arg_type) = (out_arg.name(), out_arg.src_type_resolved());
            let resolve_impl_trait = gen_resolve_type(out_arg);

            if out_arg.src_type_is_empty_tuple() {
                return quote! { #resolve_impl_trait };
            }

            quote! {
                #resolve_impl_trait
                <#arg_type as iroha_ffi::FfiOutPtrWrite>::write_out(#arg_name, __out_ptr);
            }
        },
    )
}

fn ffi_output_arg<'ast>(fn_descriptor: &'ast FnDescriptor<'ast>) -> Option<&'ast Arg> {
    fn_descriptor.output_arg.as_ref().and_then(|output_arg| {
        if output_arg.src_type_is_empty_tuple() {
            return None;
        }

        if let Some(receiver) = &fn_descriptor.receiver {
            if receiver.name() == output_arg.name() {
                return None;
            }
        }

        Some(output_arg)
    })
}
