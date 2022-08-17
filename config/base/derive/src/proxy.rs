use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Type, TypePath};

use super::utils::{get_inner_type, StructWithFields};

pub fn impl_combine(ast: &StructWithFields) -> TokenStream {
    let StructWithFields {
        ident: parent_name,
        vis,
        generics,
        ..
    } = ast;

    let proxy_name = format_ident!("{}Proxy", parent_name);

    let load_env_impl = impl_load_env(parent_name, ast);
    let disk_impl = impl_load_from_disk(&proxy_name);
    let proxy_fields = gen_proxy_struct_fields(ast);
    let build_impl = impl_build(&proxy_name, ast);

    quote! {
        /// Proxy configuration structure to be used as an intermediate
        /// for config loading
        #[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
        #vis struct #proxy_name #generics {
            #proxy_fields
        }

        #load_env_impl
        #disk_impl
        #build_impl
    }
    .into()
}

fn impl_load_env(struct_name: &Ident, ast: &StructWithFields) -> proc_macro2::TokenStream {
    let set_field = ast.fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let l_value = &field.lvalue_write;
            let as_str_attr = field.has_as_str;
            let is_option = field.has_option;
            let inner_thing = field.has_inner;
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
            } else if is_option {
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

            let inner_thing2 = if inner_thing && is_option {
                let inner_ty = get_inner_type("Option", ty);
                quote! {
                    <#inner_ty as iroha_config_base::LoadFromEnv>::load_environment()?;
                }
            } else if inner_thing {
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

    quote! {
        impl iroha_config_base::proxy::LoadFromEnv for #struct_name {
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

fn impl_build(proxy_name: &Ident, ast: &StructWithFields) -> proc_macro2::TokenStream {
    let checked_fields = gen_none_fields_check(ast);
    let parent_name = &ast.ident;
    let builder_trait = quote! { iroha_config_base::proxy::Builder };
    let error_ty = quote! { iroha_config_base::derive::Error };

    quote! {
        impl #builder_trait for #proxy_name {
            type Target = #parent_name;
            type Error = #error_ty;
            fn build(self) -> Result<Self::Target, Self::Error> {
                Ok(Self::Target {
                    #checked_fields
                })
            }
        }
    }
}

fn impl_load_from_disk(proxy_name: &Ident) -> proc_macro2::TokenStream {
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

fn gen_proxy_struct_fields(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let combined_fields = ast.fields.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            #ident: Option<#ty>
        }
    });
    quote! {
        #(#combined_fields),*
    }
}

/// Helper function to be used in [`impl Builder`]. Verifies that all fields have
/// been initialized.
fn gen_none_fields_check(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let checked_fields = ast.fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            quote! {
                #ident: self.#ident.ok_or(iroha_config_base::derive::Error::ProxyBuildError(stringify!(#ident).to_owned()))?
            }
        });
    quote! {
        #(#checked_fields),*
    }
}
