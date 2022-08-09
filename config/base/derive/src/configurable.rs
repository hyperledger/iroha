use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Ident, Type, TypePath};

use super::utils::{
    extract_field_attrs, extract_field_idents, extract_field_types, field_has_as_str_attr,
    field_has_inner_attr, field_has_option_type, gen_field_env, gen_lvalues, get_env_prefix,
    get_inner_type, StructWithFields,
};

pub(super) fn impl_configurable(ast: &StructWithFields) -> TokenStream {
    let StructWithFields {
        ident: parent_name,
        vis,
        generics,
        ..
    } = ast;
    let proxy_name = format_ident!("{}Proxy", parent_name);

    let prefix = get_env_prefix(ast);

    let field_idents = extract_field_idents(&ast.fields);

    let field_attrs = extract_field_attrs(&ast.fields);

    let field_ty = extract_field_types(&ast.fields);

    // Doing for parent struct right now instead of the proxy
    // TODO: when generating for proxy, replace types and option with proxy's values
    let load_env_impl = impl_load_env(parent_name, &field_idents, &field_attrs, &prefix, &field_ty);

    let disk_impl = impl_load_from_disk(&proxy_name);
    let proxy_fields = gen_proxy_struct_fields(&field_idents, &field_attrs, &field_ty);
    let build_impl = impl_build(parent_name, &proxy_name, &field_idents, &field_attrs);

    // TODO: decide if attrs are needed here too
    quote! {
        /// Proxy configuration structure to be used as an intermediate
        /// for config loading
        #[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
        // #(#attrs)*
        #vis struct #proxy_name #generics {
            #proxy_fields
        }

        #load_env_impl
        #disk_impl
        #build_impl
    }
    .into()
}

fn impl_load_env(
    struct_name: &Ident,
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
    prefix: &str,
    field_ty: &[Type],
) -> proc_macro2::TokenStream {
    let inner = field_has_inner_attr(field_attrs);

    let field_environment = gen_field_env(field_idents, prefix);

    let as_str = field_has_as_str_attr(field_attrs);
    let option = field_has_option_type(field_ty);

    let (_lvalue_read, lvalue) = gen_lvalues(field_ty, field_idents);

    let set_field = field_ty
        .iter()
        .zip(field_idents.iter())
        .zip(as_str.iter())
        .zip(lvalue.iter())
        .zip(option.iter())
        .map(|((((ty, ident), &as_str_attr), l_value), &is_option)| {
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
            (set_field, l_value, ty)
        })
        .zip(field_environment.iter())
        .zip(inner.iter())
        .zip(option.iter())
        .map(|((((set_field, l_value, ty), field_env), &inner_thing), &is_option)| {
            // let inner_thing2 = quote! {};
            let inner_thing2 = if inner_thing && is_option {
                let inner_ty = get_inner_type("Option", ty);
                quote! {
                    // #l_value = <#inner as iroha_config_base::LoadFromEnv>::load_environment().ok();
                    // let inner_config = #inner::new();
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

fn impl_build(
    parent_name: &Ident,
    proxy_name: &Ident,
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
) -> proc_macro2::TokenStream {
    let checked_fields = gen_none_fields_check(field_idents, field_attrs);

    quote! {
        impl iroha_config_base::proxy::Builder for #proxy_name {
            type Target = #parent_name;
            type Error = iroha_config_base::derive::Error;
            fn build(self) -> Result<Self::Target, iroha_config_base::derive::Error> {
                Ok(Self::Target {
                    #checked_fields
                })
            }
        }
    }
}

fn impl_load_from_disk(proxy_name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        impl iroha_config_base::proxy::LoadFromDisk for #proxy_name {
            type Error = iroha_config_base::derive::Error;
            fn from_path<P: AsRef<std::path::Path> + std::fmt::Debug + Clone>(path: P) -> Result<Self, Self::Error> {
                let file = std::fs::File::open(path.clone())?;
                let reader = std::io::BufReader::new(file);
                serde_json::from_reader(reader)?
            }
        }
    }
}

fn gen_proxy_struct_fields(
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
    field_ty: &[Type],
) -> proc_macro2::TokenStream {
    // TODO: decide if attrs are needed
    let combined_fields = field_idents
        .iter()
        .zip(field_attrs.iter())
        .zip(field_ty.iter())
        .map(|((ident, _attrs), ty)| {
            quote! {
                // #(#attrs)*
                #ident: Option<#ty>
            }
        });
    quote! {
        #(#combined_fields),*
    }
}

/// Helper function to be used in [`impl Builder`]. Verifies that all fields have
/// been initialized.
fn gen_none_fields_check(
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
) -> proc_macro2::TokenStream {
    // TODO: attrs here too
    let checked_fields = field_idents
        .iter()
        .zip(field_attrs.iter())
        .map(|(ident, _attrs)| {
            let ident_str = ident.to_string();
            quote! {
                #ident: self.#ident.ok_or(iroha_config_base::derive::Error::ProxyBuildError(#ident_str.to_owned()))?
            }
        });
    quote! {
        #(#checked_fields),*
    }
}
