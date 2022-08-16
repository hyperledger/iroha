use std::collections::HashSet;

use proc_macro2::TokenStream;
use proc_macro_error::{abort, OptionExt};
use quote::quote;
use syn::{parse_quote, Ident, Type};

use crate::impl_visitor::{find_doc_attr, unwrap_result_type, Arg, FnDescriptor};

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

pub fn gen_arg_ffi_to_src(arg: &Arg, is_output: bool) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type_resolved());

    if is_output {
        let mut stmt = quote! {
            let mut store = ();
            let #arg_name: #src_type = iroha_ffi::TryFromReprC::try_from_repr_c(#arg_name, &mut store)?;
        };

        if let Type::Reference(ref_type) = &src_type {
            let elem = &ref_type.elem;

            stmt.extend(if ref_type.mutability.is_some() {
                quote! {
                    // NOTE: Type having `type TryFromReprC::Store = ()` will never reference
                    // local context, i.e. it's lifetime can be attached to that of the wrapping fn
                    unsafe { &mut *(#arg_name as *mut #elem) }
                }
            } else {
                quote! {
                    unsafe { &*(#arg_name as *const #elem) }
                }
            });
        }

        return stmt;
    }

    quote! {
        let mut store = Default::default();
        let #arg_name: #src_type = iroha_ffi::TryFromReprC::try_from_repr_c(#arg_name, &mut store)?;
    }
}

#[allow(clippy::expect_used)]
pub fn gen_arg_src_to_ffi(arg: &Arg, is_output: bool) -> TokenStream {
    let (arg_name, src_type) = (arg.name(), arg.src_type());

    let mut resolve_impl_trait = None;
    if let Type::ImplTrait(type_) = &src_type {
        for bound in &type_.bounds {
            if let syn::TypeParamBound::Trait(trait_) = bound {
                let trait_ = trait_.path.segments.last().expect_or_abort("Defined");

                if trait_.ident == "IntoIterator" || trait_.ident == "ExactSizeIterator" {
                    resolve_impl_trait = Some(quote! {
                        let #arg_name: Vec<_> = #arg_name.into_iter().collect();
                    });
                } else if trait_.ident == "Into" {
                    resolve_impl_trait = Some(quote! {
                        let #arg_name = #arg_name.into();
                    });
                }
            }
        }
    }

    let ffi_conversion = quote! {
        #resolve_impl_trait
        let #arg_name = iroha_ffi::IntoFfi::into_ffi(#arg_name);
    };

    if is_output {
        if unwrap_result_type(src_type).is_some() {
            return quote! {
                let #arg_name = if let Ok(ok) = #arg_name {
                    iroha_ffi::IntoFfi::into_ffi(ok)
                } else {
                    // TODO: Implement error handling (https://github.com/hyperledger/iroha/issues/2252)
                    return Err(iroha_ffi::FfiReturn::ExecutionFail);
                };
            };
        }

        return ffi_conversion;
    }

    if let Type::Reference(ref_type) = &src_type {
        if ref_type.mutability.is_some() {
            return ffi_conversion;
        }
    }

    quote! {
        #ffi_conversion
        // NOTE: `AsReprCRef` prevents ownerhip transfer over FFI
        let #arg_name = iroha_ffi::AsReprCRef::as_ref(&#arg_name);
    }
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

#[allow(clippy::expect_used)]
fn gen_derived_method(item_name: &Ident, field: &syn::Field, derive: Derive) -> FnDescriptor {
    let handle_name = Ident::new("__handle", proc_macro2::Span::call_site());
    let field_name = field.ident.as_ref().expect_or_abort("Defined").clone();
    let self_ty = Some(parse_quote! {#item_name});

    let sig = gen_derived_method_sig(field, derive);
    let doc = find_doc_attr(&field.attrs).cloned();

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
        self_ty,
        trait_name: None,
        doc,
        sig,
        receiver: Some(receiver),
        input_args,
        output_arg,
    }
}

#[allow(clippy::expect_used)]
fn gen_derived_method_sig(field: &syn::Field, derive: Derive) -> syn::Signature {
    let field_name = field.ident.as_ref().expect("Field name not defined");
    let field_ty = &field.ty;

    let method_name = Ident::new(
        &match derive {
            Derive::Setter => format!("set_{}", field_name),
            Derive::Getter => format!("{}", field_name),
            Derive::MutGetter => format!("{}_mut", field_name),
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
