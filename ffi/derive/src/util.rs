use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, visit::Visit, Ident};

use crate::impl_visitor::{is_doc_attr, unwrap_result_type, Arg, FnDescriptor};

/// Type of accessor method derived for a structure
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Derive {
    Setter,
    Getter,
    MutGetter,
}

/// Generate FFI function equivalents of derived methods
pub fn gen_derived_methods(item: &syn::ItemStruct) -> Vec<FnDescriptor> {
    let struct_derives = parse_derives(&item.attrs).unwrap_or_default();

    let mut ffi_derives = Vec::new();
    match &item.fields {
        syn::Fields::Named(syn::FieldsNamed { named, .. }) => named.iter().for_each(|field| {
            if let Some(mut field_derives) = parse_derives(&field.attrs) {
                field_derives.extend(struct_derives.clone());

                for derive in field_derives {
                    ffi_derives.push(gen_derived_method(&item.ident, field, derive));
                }
            }
        }),
        syn::Fields::Unnamed(_) | syn::Fields::Unit => {
            abort!(item, "Only named structs supported")
        }
    }

    ffi_derives
}

pub fn gen_resolve_type(arg: &Arg) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type());

    if unwrap_result_type(src_type).is_some() {
        return quote! {
            let #arg_name = if let Ok(ok) = #arg_name {
                ok
            } else {
                // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                return Err(iroha_ffi::FfiReturn::ExecutionFail);
            };
        };
    }

    let mut type_resolver = FfiTypeResolver(arg_name, quote! {});
    type_resolver.visit_type(src_type);
    type_resolver.1
}

/// Parse `getset` attributes to find out which methods it derives
fn parse_derives(attrs: &[syn::Attribute]) -> Option<HashSet<Derive>> {
    attrs
        .iter()
        .filter_map(|attr| {
            if let Ok(syn::Meta::List(meta_list)) = attr.parse_meta() {
                return meta_list
                    .path
                    .is_ident("getset")
                    .then_some(meta_list.nested);
            }

            None
        })
        .flatten()
        .try_fold(HashSet::new(), |mut acc, nested| {
            if let syn::NestedMeta::Meta(item) = nested {
                match item {
                    syn::Meta::NameValue(item) => {
                        if item.lit == parse_quote! {"pub"} {
                            if item.path.is_ident("set") {
                                acc.insert(Derive::Setter);
                            } else if item.path.is_ident("get") {
                                acc.insert(Derive::Getter);
                            } else if item.path.is_ident("get_mut") {
                                acc.insert(Derive::MutGetter);
                            }
                        }
                    }
                    syn::Meta::Path(path) => {
                        if path.is_ident("skip") {
                            return None;
                        }
                    }
                    _ => abort!(item, "Unsupported getset attribute"),
                }
            }

            Some(acc)
        })
}

fn gen_derived_method<'ast>(
    item_name: &Ident,
    field: &'ast syn::Field,
    derive: Derive,
) -> FnDescriptor<'ast> {
    let handle_name = Ident::new("__handle", proc_macro2::Span::call_site());
    let field_name = field.ident.as_ref().expect_or_abort("Defined").clone();
    let sig = gen_derived_method_sig(field, derive);
    let self_ty = Some(parse_quote! {#item_name});

    let mut doc = Vec::new();
    for attr in &field.attrs {
        if is_doc_attr(attr) {
            doc.push(attr);
        }
    }

    let field_ty = &field.ty;
    let field_ty = match derive {
        Derive::Setter => field_ty.clone(),
        Derive::Getter => parse_quote! {&#field_ty},
        Derive::MutGetter => parse_quote! {&mut #field_ty},
    };

    let (receiver, input_args, output_arg) = match derive {
        Derive::Setter => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&mut Self}),
            vec![Arg::new(self_ty.clone(), field_name, field_ty)],
            None,
        ),
        Derive::Getter => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&Self}),
            Vec::new(),
            Some(Arg::new(self_ty.clone(), field_name, field_ty)),
        ),
        Derive::MutGetter => (
            Arg::new(self_ty.clone(), handle_name, parse_quote! {&mut Self}),
            Vec::new(),
            Some(Arg::new(self_ty.clone(), field_name, field_ty)),
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

fn gen_derived_method_sig(field: &syn::Field, derive: Derive) -> syn::Signature {
    let field_name = field.ident.as_ref().expect("Field name not defined");
    let field_ty = &field.ty;

    let method_name = Ident::new(
        &match derive {
            Derive::Setter => format!("set_{field_name}"),
            Derive::Getter => format!("{field_name}"),
            Derive::MutGetter => format!("{field_name}_mut"),
        },
        proc_macro2::Span::call_site(),
    );

    match derive {
        Derive::Setter => parse_quote! {
            fn #method_name(&mut self, #field)
        },
        Derive::Getter => parse_quote! {
            fn #method_name(&self) -> & #field_ty
        },
        Derive::MutGetter => parse_quote! {
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
        let trait_ = i.path.segments.last().expect_or_abort("Defined");

        let arg_name = self.0;
        if trait_.ident == "IntoIterator" || trait_.ident == "ExactSizeIterator" {
            self.1 = quote! { let #arg_name: Vec<_> = #arg_name.into_iter().collect(); };
        } else if trait_.ident == "Into" {
            self.1 = quote! { let #arg_name = #arg_name.into(); };
        }
    }
}
