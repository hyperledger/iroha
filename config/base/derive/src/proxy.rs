use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_quote, Type, TypePath};

use super::utils::{get_inner_type, StructWithFields};
use crate::utils;

pub fn impl_proxy(ast: StructWithFields) -> TokenStream {
    // somewhat awkward conversion, could it be better?
    let parent_name = &ast.ident;
    let parent_ty: Type = parse_quote! { #parent_name };
    let proxy_struct = gen_proxy_struct(ast);
    let loadenv_derive = quote! { ::iroha_config_base::derive::LoadFromEnv };
    let disk_derive = quote! { ::iroha_config_base::derive::LoadFromDisk };
    let builder_derive = quote! { ::iroha_config_base::derive::Builder };
    let combine_derive = quote! { ::iroha_config_base::derive::Combine };
    let documented_derive = quote! { ::iroha_config_base::derive::Documented };
    quote! {
        /// Proxy configuration structure to be used as an intermediate
        /// for config loading
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize,
                 #builder_derive,
                 #loadenv_derive,
                 #disk_derive,
                 #combine_derive,
                 #documented_derive
        )]
        #[builder(parent = #parent_ty)]
        #proxy_struct

    }
    .into()
}

pub fn impl_combine(ast: &StructWithFields) -> TokenStream {
    let combine_trait = quote! { ::iroha_config_base::proxy::Combine };
    let name = &ast.ident;
    let fields = utils::extract_field_idents(&ast.fields);

    quote! {
        impl #combine_trait for #name {
            fn combine(mut self, other: Self) -> Self {
                #(if let Some(other_field) = other.#fields {
                    self.#fields = Some(other_field)
                })*
                self
            }
        }
    }
    .into()
}

pub fn impl_load_from_env(ast: &StructWithFields) -> TokenStream {
    let set_field = ast.fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let l_value = &field.lvalue_write;
            let as_str_attr = field.has_as_str;
            let ident = &field.ident;
            let field_env = &field.env_str;
            let is_string = if let Type::Path(TypePath { path, .. }) = ty {
                path.is_ident("String")
            } else {
                false
            };

            let set_field = if is_string {
                quote! { #l_value = var }
            } else if as_str_attr {
                quote! {
                    #l_value = serde_json::from_value(var.into())
                        .map_err(|e| ::iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
            } else if field.has_option {
                quote! {
                    #l_value = Some(serde_json::from_value(var.into())
                        .map_err(|e| ::iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?)
                }
            }
            else {
                quote! {
                    #l_value = serde_json::from_str(&var)
                        .map_err(|e| ::iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
            };

            let inner_thing2 = if field.has_inner && field.has_option {
                let inner_ty = get_inner_type("Option", ty);
                let loadenv_trait = quote! { ::iroha_config_base::proxy::LoadFromEnv };
                let err_variant = quote! { ::iroha_config_base::derive::Error::ProxyBuildError };
                quote! {
                    <#inner_ty as #loadenv_trait>::load_environment(#l_value.as_mut().ok_or(#err_variant(stringify!(#ident).to_owned()))?)?;
                }
            } else if field.has_inner {
                quote! {
                    #l_value.load_environment()?;
                }
            }
            else {
                quote! {}
            };

            quote! {
                if let Ok(var) = std::env::var(#field_env) {
                    #set_field;
                }
                #inner_thing2
            }
        });

    let name = &ast.ident;
    quote! {
        impl ::iroha_config_base::proxy::LoadFromEnv for #name {
            type Error = ::iroha_config_base::derive::Error;
            fn load_environment(
                &'_ mut self
            ) -> core::result::Result<(), ::iroha_config_base::derive::Error> {
                #(#set_field)*
                Ok(())
            }
        }
    }
    .into()
}

pub fn impl_load_from_disk(ast: &StructWithFields) -> TokenStream {
    let proxy_name = &ast.ident;
    let disk_trait = quote! { ::iroha_config_base::proxy::LoadFromDisk };
    let error_ty = quote! { ::iroha_config_base::derive::Error };
    quote! {
        impl #disk_trait for #proxy_name {
            type Error = #error_ty;
            fn from_path<P: AsRef<std::path::Path> + std::fmt::Debug + Clone>(path: P) -> Result<Self, Self::Error> {
                let mut file = std::fs::File::open(path)?;
                // String has better parsing speed, see [issue](https://github.com/serde-rs/json/issues/160#issuecomment-253446892)
                let mut s = String::new();
                std::io::Read::read_to_string(&mut file, &mut s)?;
                let res: Self = serde_json::from_str(&s)?;
                Ok(res)
            }
        }
    }.into()
}

fn gen_proxy_struct(mut ast: StructWithFields) -> StructWithFields {
    // As this changes the field types of the AST, `lvalue_read`
    // and `lvalue_write` of its `StructField`s may get desynchronized
    ast.fields.iter_mut().for_each(|field| {
        // For fields of `Configuration` that have an inner config, the corresponding
        // proxy field should have a `..Proxy` type there as well
        if field.has_inner {
            #[allow(clippy::expect_used)]
            if let Type::Path(path) = &mut field.ty {
                let old_ident = &path.path.segments.last().expect("Can't be empty").ident;
                let new_ident = format_ident!("{}Proxy", old_ident);
                path.path.segments.last_mut().expect("Can't be empty").ident = new_ident;
            }
        }
        let ty = &field.ty;
        field.ty = parse_quote! {
            Option<#ty>
        };
        // Fields that already wrap an option should have a
        // custom deserializer so that json `null` becomes
        // `Some(None)` and not just `None`
        if field.has_option {
            let de_helper = stringify! { ::iroha_config_base::proxy::some_option };
            let serde_attr: syn::Attribute =
                parse_quote! { #[serde(default, deserialize_with = #de_helper)] };
            field.attrs.push(serde_attr);
        }
        field.has_option = true;
    });
    ast.ident = format_ident!("{}Proxy", ast.ident);
    // Removing struct-level docs as `..Proxy` has its own doc,
    // but not the field documentation as they stay the same
    utils::remove_attr(&mut ast.attrs, "doc");
    ast
}

pub fn impl_build(ast: &StructWithFields) -> TokenStream {
    let checked_fields = gen_none_fields_check(ast);
    let proxy_name = &ast.ident;
    let parent_ty = utils::get_parent_ty(ast);
    let builder_trait = quote! { ::iroha_config_base::proxy::Builder };
    let error_ty = quote! { ::iroha_config_base::derive::Error };

    quote! {
        impl #builder_trait for #proxy_name {
            type ReturnValue = Result<#parent_ty, #error_ty>;
            fn build(self) -> Self::ReturnValue {
                Ok(#parent_ty {
                    #checked_fields
                })
            }
        }
    }
    .into()
}

/// Helper function to be used in [`impl Builder`]. Verifies that all fields have
/// been initialized.
fn gen_none_fields_check(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let checked_fields = ast.fields.iter().map(|field| {
        let ident = &field.ident;
        let err_variant = quote! { ::iroha_config_base::derive::Error::ProxyBuildError };
        if field.has_inner {
            let inner_ty = get_inner_type("Option", &field.ty).clone();
            let builder_trait = quote! { ::iroha_config_base::proxy::Builder };
            quote! {
                #ident: <#inner_ty as #builder_trait>::build(
                    self.#ident.ok_or(
                        #err_variant(stringify!(#ident).to_owned())
                    )?
                )?
            }
        } else {
            quote! {
                #ident: self.#ident.ok_or(
                    #err_variant(stringify!(#ident).to_owned()))?
            }
        }
    });
    quote! {
        #(#checked_fields),*
    }
}
