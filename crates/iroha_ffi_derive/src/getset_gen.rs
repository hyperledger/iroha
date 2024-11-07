use std::default::Default;

use darling::ast::Style;
use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::quote;
use rustc_hash::FxHashMap;
use syn::{parse_quote, visit::Visit, Ident};

use crate::{
    attr_parse::{
        derive::DeriveAttrs,
        getset::{GetSetGenMode, GetSetStructAttrs},
    },
    convert::{FfiTypeField, FfiTypeFields},
    impl_visitor::{unwrap_result_type, Arg, FnDescriptor},
};

/// Generate FFI function equivalents of getset-derived methods
pub fn gen_derived_methods<'a>(
    emitter: &mut Emitter,
    name: &Ident,
    derives: &DeriveAttrs,
    getset_struct_attrs: &GetSetStructAttrs,
    fields: &'a FfiTypeFields,
) -> impl Iterator<Item = FnDescriptor<'a>> {
    let mut ffi_derives = FxHashMap::default();

    match fields.style {
        Style::Struct => {}
        Style::Tuple | Style::Unit => {
            emit!(emitter, "Only named structs supported");
            return ffi_derives.into_values();
        }
    }

    for field in fields.iter() {
        for (mode, options) in field
            .getset_attr
            .get_field_accessors(derives, getset_struct_attrs)
        {
            if options.with_prefix {
                emit!(
                    emitter,
                    "with_prefix option of getset crate is not supported by iroha_ffi_derive"
                );
            }
            if options.visibility != Some(parse_quote!(pub)) {
                // ignore non-public accessors
                continue;
            }

            let fn_ = gen_derived_method(name, field, mode);
            ffi_derives.insert(fn_.sig.ident.clone(), fn_);
        }
    }

    ffi_derives.into_values()
}

pub fn gen_resolve_type(arg: &Arg) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type());

    if unwrap_result_type(src_type).is_some() {
        return quote! {
            let #arg_name = if let Ok(ok) = #arg_name {
                ok
            } else {
                // TODO: Implement error handling (https://github.com/hyperledger-iroha/iroha/issues/2252)
                return Err(iroha_ffi::FfiReturn::ExecutionFail);
            };
        };
    }

    let mut type_resolver = FfiTypeResolver(arg_name, quote! {});
    type_resolver.visit_type(src_type);
    type_resolver.1
}

fn gen_derived_method<'ast>(
    item_name: &Ident,
    field: &'ast FfiTypeField,
    mode: GetSetGenMode,
) -> FnDescriptor<'ast> {
    let handle_name = Ident::new("__handle", proc_macro2::Span::call_site());
    let field_name = field
        .ident
        .as_ref()
        .expect("BUG: Field name not defined")
        .clone();
    let sig = gen_derived_method_sig(field, mode);
    let self_ty = Some(parse_quote! {#item_name});

    let doc = field.doc_attrs.attrs.iter().collect();

    let field_ty = &field.ty;
    let (receiver, input_args, output_arg) = match mode {
        GetSetGenMode::Set => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&mut Self}),
            vec![Arg::new(self_ty.clone(), field_name, field_ty.clone())],
            None,
        ),
        GetSetGenMode::Get => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&Self}),
            Vec::new(),
            Some(Arg::new(
                self_ty.clone(),
                field_name,
                parse_quote!(& #field_ty),
            )),
        ),
        GetSetGenMode::GetCopy => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&Self}),
            Vec::new(),
            Some(Arg::new(
                self_ty.clone(),
                field_name,
                parse_quote!(#field_ty),
            )),
        ),
        GetSetGenMode::GetMut => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&mut Self}),
            Vec::new(),
            Some(Arg::new(
                self_ty.clone(),
                field_name,
                parse_quote!(&mut #field_ty),
            )),
        ),
    };

    FnDescriptor {
        attrs: Vec::new(),
        self_ty,
        doc,
        sig,
        receiver: Some(receiver),
        input_args,
        output_arg,
    }
}

fn gen_derived_method_sig(field: &FfiTypeField, mode: GetSetGenMode) -> syn::Signature {
    let field_name = field.ident.as_ref().expect("BUG: Field name not defined");
    let field_ty = &field.ty;

    let method_name = Ident::new(
        &match mode {
            GetSetGenMode::Set => format!("set_{field_name}"),
            GetSetGenMode::Get | GetSetGenMode::GetCopy => format!("{field_name}"),
            GetSetGenMode::GetMut => format!("{field_name}_mut"),
        },
        proc_macro2::Span::call_site(),
    );

    match mode {
        GetSetGenMode::Set => parse_quote! {
            fn #method_name(&mut self, #field_name: #field_ty)
        },
        GetSetGenMode::Get => parse_quote! {
            fn #method_name(&self) -> &#field_ty
        },
        GetSetGenMode::GetCopy => parse_quote! {
            fn #method_name(&self) -> #field_ty
        },
        GetSetGenMode::GetMut => parse_quote! {
            fn #method_name(&mut self) -> &mut #field_ty
        },
    }
}

pub fn gen_store_name(arg_name: &Ident) -> Ident {
    Ident::new(&format!("{arg_name}_store"), proc_macro2::Span::call_site())
}

struct FfiTypeResolver<'itm>(&'itm Ident, TokenStream);
impl<'itm> Visit<'itm> for FfiTypeResolver<'itm> {
    fn visit_trait_bound(&mut self, i: &'itm syn::TraitBound) {
        let trait_ = i.path.segments.last().expect("Defined");

        let arg_name = self.0;
        if trait_.ident == "IntoIterator" || trait_.ident == "ExactSizeIterator" {
            self.1 = quote! { let #arg_name: Vec<_> = #arg_name.into_iter().collect(); };
        } else if trait_.ident == "Into" {
            self.1 = quote! { let #arg_name = #arg_name.into(); };
        } else if trait_.ident == "AsRef" {
            self.1 = quote! { let #arg_name = #arg_name.as_ref(); };
        }
    }
}
