use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_quote, Type, TypePath};

use super::utils::{get_inner_type, StructWithFields};
use crate::utils;

pub fn impl_combine(ast: StructWithFields) -> TokenStream {
    let parent_load_env_impl = impl_load_env(&ast);
    let parent_name = &ast.ident.clone();

    let proxy_struct = gen_proxy_struct(ast);
    let build_impl = impl_build(parent_name, &proxy_struct);
    let disk_impl = impl_load_from_disk(&proxy_struct);
    let proxy_load_env_impl = impl_load_env(&proxy_struct);

    quote! {
        /// Proxy configuration structure to be used as an intermediate
        /// for config loading
        #[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
        #proxy_struct

        #parent_load_env_impl
        #proxy_load_env_impl
        #disk_impl
        #build_impl
    }
    .into()
}

fn impl_load_env(ast: &StructWithFields) -> proc_macro2::TokenStream {
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
                        .map_err(|e| iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
            } else if field.has_option {
                quote! {
                    #l_value = Some(serde_json::from_value(var.into())
                        .map_err(|e| iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?)
                }
            }
            else {
                quote! {
                    #l_value = serde_json::from_str(&var)
                        .map_err(|e| iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
            };

            let inner_thing2 = if field.has_inner && field.has_option {
                let inner_ty = get_inner_type("Option", ty);
                let loadenv_trait = quote! { iroha_config_base::proxy::LoadFromEnv };
                let err_variant = quote! { iroha_config_base::derive::Error::ProxyBuildError };
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
        impl iroha_config_base::proxy::LoadFromEnv for #name {
            type Error = iroha_config_base::derive::Error;
            fn load_environment(
                &'_ mut self
            ) -> core::result::Result<(), iroha_config_base::derive::Error> {
                #(#set_field)*
                Ok(())
            }
        }
    }
}

fn impl_load_from_disk(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let proxy_name = &ast.ident;
    let disk_trait = quote! { iroha_config_base::proxy::LoadFromDisk };
    let error_ty = quote! { iroha_config_base::derive::Error };
    quote! {
        impl #disk_trait for #proxy_name {
            type Error = #error_ty;
            fn from_path<P: AsRef<std::path::Path> + std::fmt::Debug + Clone>(path: P) -> Result<Self, Self::Error> {
                let file = std::fs::File::open(path)?;
                let reader = std::io::BufReader::new(file);
                serde_json::from_reader(reader)?
            }
        }
    }
}

fn gen_proxy_struct(mut ast: StructWithFields) -> StructWithFields {
    // Make mut, parse quote and modify ast for proxy
    ast.fields.iter_mut().for_each(|field| {
        // For fields of `Configuration` that have an inner config, the corresponding
        // proxy field should have a proxy there as well
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
        field.has_option = true;
        // Also remove `#[serde(default = ..)]` if present
        // as it breaks proxy deserialization
        utils::remove_attr(&mut field.attrs, "serde");
    });
    ast.ident = format_ident!("{}Proxy", ast.ident);
    utils::remove_attr_struct(&mut ast, "config");
    ast
}

// REVIEW: need lvalue here as well?
fn impl_build(parent_name: &syn::Ident, ast: &StructWithFields) -> proc_macro2::TokenStream {
    let checked_fields = gen_none_fields_check(ast);
    let proxy_name = &ast.ident;
    let builder_trait = quote! { iroha_config_base::proxy::Builder };
    let error_ty = quote! { iroha_config_base::derive::Error };

    quote! {
        impl #builder_trait for #proxy_name {
            type ReturnValue = Result<#parent_name, #error_ty>;
            fn build(self) -> Self::ReturnValue {
                Ok(#parent_name {
                    #checked_fields
                })
            }
        }
    }
}

/// Helper function to be used in [`impl Builder`]. Verifies that all fields have
/// been initialized.
fn gen_none_fields_check(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let checked_fields = ast.fields.iter().map(|field| {
        let ident = &field.ident;
        let err_variant = quote! { iroha_config_base::derive::Error::ProxyBuildError };
        if field.has_inner {
            let inner_ty = get_inner_type("Option", &field.ty);
            let builder_trait = quote! { iroha_config_base::proxy::Builder };
            quote! {
                #ident: <#inner_ty as #builder_trait>::build(self.#ident.ok_or(#err_variant(stringify!(#ident).to_owned()))?)?
            }
        } else {
            quote! {
                #ident: self.#ident.ok_or(#err_variant(stringify!(#ident).to_owned()))?
            }
        }
    });
    quote! {
        #(#checked_fields),*
    }
}
