use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::{parse_quote, Type, TypePath};

use super::utils::{get_inner_type, StructWithFields};
use crate::utils;

pub fn impl_proxy(ast: StructWithFields) -> TokenStream {
    let parent_name = &ast.ident;
    let parent_ty: Type = parse_quote! { #parent_name };
    let proxy_struct = gen_proxy_struct(ast);
    let loadenv_derive = quote! { ::iroha_config_base::derive::LoadFromEnv };
    let disk_derive = quote! { ::iroha_config_base::derive::LoadFromDisk };
    let builder_derive = quote! { ::iroha_config_base::derive::Builder };
    let override_derive = quote! { ::iroha_config_base::derive::Override };
    let documented_derive = quote! { ::iroha_config_base::derive::Documented };
    quote! {
        /// Proxy configuration structure to be used as an intermediate
        /// for configuration loading. Both loading from disk and
        /// from env should only be done via this struct, which then
        /// builds into its parent [`struct@Configuration`].
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize,
                 #builder_derive,
                 #loadenv_derive,
                 #disk_derive,
                 #override_derive,
                 #documented_derive
        )]
        #[builder(parent = #parent_ty)]
        #proxy_struct

    }
    .into()
}

pub fn impl_override(ast: &StructWithFields) -> TokenStream {
    let override_trait = quote! { ::iroha_config_base::proxy::Override };
    let name = &ast.ident;
    let clauses = ast.fields.iter().map(|field| {
        let field_name = &field.ident;
        if field.has_inner {
            let inner_ty = get_inner_type("Option", &field.ty);
            quote! {
                self.#field_name = match (self.#field_name, other.#field_name) {
                    (Some(this_field), Some(other_field)) => Some(<#inner_ty as #override_trait>::override_with(this_field, other_field)),
                    (this_field, None) => this_field,
                    (None, other_field) => other_field,
                };
            }
        } else {
            quote! {
                if let Some(other_field) = other.#field_name {
                    self.#field_name = Some(other_field)
                }
            }
        }
    });

    quote! {
        impl #override_trait for #name {
            fn override_with(mut self, other: Self) -> Self {
                #(#clauses)*
                self
            }
        }
    }
    .into()
}

#[allow(clippy::str_to_string)]
pub fn impl_load_from_env(ast: &StructWithFields) -> TokenStream {
    let env_fetcher_ident = quote! { env_fetcher };
    let fetch_env_trait = quote! { ::iroha_config_base::proxy::FetchEnv };
    let env_trait = quote! { ::iroha_config_base::proxy::LoadFromEnv };

    let set_field = ast.fields
        .iter()
        .map(|field| {
            let ty = &field.ty;
            let as_str_attr = field.has_as_str;
            let ident = &field.ident;
            let field_env = &field.env_str;

            let inner_ty = if field.has_option {
                get_inner_type("Option", ty)
            } else {
                abort!(ast, "This macro should only be used on `ConfigurationProxy` types, \
                                i.e. the types which represent a partially finalised configuration \
                                (with some required fields omitted and to be read from other sources). \
                                These types' fields have the `Option` type wrapped around each of them.")
            };
            let is_string = if let Type::Path(TypePath { path, .. }) = inner_ty {
                path.is_ident("String")
            } else {
                false
            };
            let inner = if is_string {
                quote! { Ok(var) }
            } else if as_str_attr {
                quote! {{
                    let value: ::serde_json::Value = var.into();
                    ::json5::from_str(&value.to_string())
                }}
            } else {
                quote! { ::json5::from_str(&var) }
            };
            let mut set_field = quote! {
                let #ident = #env_fetcher_ident.fetch(#field_env)
                    // treating unicode errors the same as variable absence
                    .ok()
                    .map(|var| {
                        #inner.map_err(|err| {
                            ::iroha_config_base::derive::Error::field_deserialization_from_json5(
                                // FIXME: specify location precisely
                                //        https://github.com/hyperledger/iroha/issues/3470
                                #field_env,
                                err
                            )
                        })
                    })
                    .transpose()?;
            };
            if field.has_inner {
                set_field.extend(quote! {
                    let inner_proxy = <#inner_ty as #env_trait>::from_env(#env_fetcher_ident)?;
                    let #ident = if let Some(old_inner) = #ident {
                        Some(<#inner_ty as ::iroha_config_base::proxy::Override>::override_with(old_inner, inner_proxy))
                    } else {
                        Some(inner_proxy)
                    };
                });
            }
            set_field
        });

    let name = &ast.ident;
    let fields = ast
        .fields
        .iter()
        .map(|field| {
            let ident = &field.ident;
            quote! { #ident }
        })
        .collect::<Vec<_>>();
    quote! {
        impl #env_trait for #name {
            type ReturnValue = Result<Self, ::iroha_config_base::derive::Error>;
            fn from_env<F: #fetch_env_trait>(#env_fetcher_ident: &F) -> Self::ReturnValue {
                #(#set_field)*
                let proxy = #name {
                    #(#fields),*
                };
                Ok(proxy)
            }
        }
    }
    .into()
}

pub fn impl_load_from_disk(ast: &StructWithFields) -> TokenStream {
    let proxy_name = &ast.ident;
    let disk_trait = quote! { ::iroha_config_base::proxy::LoadFromDisk };
    let error_ty = quote! { ::iroha_config_base::derive::Error };
    let disk_err_variant = quote! { ::iroha_config_base::derive::Error::Disk };
    let serde_err_variant = quote! { ::iroha_config_base::derive::Error::Json5 };
    let none_proxy = gen_none_fields_proxy(ast);
    quote! {
        impl #disk_trait for #proxy_name {
            type ReturnValue = Self;
            fn from_path<P: AsRef<::std::path::Path> + ::std::fmt::Debug + Clone>(path: P) -> Self::ReturnValue {
                let mut file = ::std::fs::File::open(path).map_err(#disk_err_variant);
                // String has better parsing speed, see [issue](https://github.com/serde-rs/json/issues/160#issuecomment-253446892)
                let mut s = String::new();
                let res = file
                    .and_then(|mut f| {
                        ::std::io::Read::read_to_string(&mut f, &mut s).map(move |_| s).map_err(#disk_err_variant)
                    })
                    .and_then(
                        |s| -> ::core::result::Result<Self, #error_ty> {
                            json5::from_str(&s).map_err(#serde_err_variant)
                        },
                    )
                    .map_or(#none_proxy, ::std::convert::identity);
                res
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
        //
        field
            .attrs
            .retain(|attr| attr.path.is_ident("doc") || attr.path.is_ident("config"));
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
    // The only needed struct-level attributes are these
    ast.attrs.retain(|attr| {
        attr.path.is_ident("config") || attr.path.is_ident("serde") || attr.path.is_ident("cfg")
    });
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
        let missing_field = quote! { ::iroha_config_base::derive::Error::MissingField };
        if field.has_inner {
            let inner_ty = get_inner_type("Option", &field.ty);
            let builder_trait = quote! { ::iroha_config_base::proxy::Builder };
            quote! {
                #ident: <#inner_ty as #builder_trait>::build(
                    self.#ident.ok_or(
                        #missing_field{field: stringify!(#ident), message: ""}
                    )?
                )?
            }
        } else {
            quote! {
                #ident: self.#ident.ok_or(
                    #missing_field{field: stringify!(#ident), message: ""}
                )?
            }
        }
    });
    quote! {
        #(#checked_fields),*
    }
}

/// Helper function to be used as an empty fallback for [`impl LoadFromEnv`] or [`impl LoadFromDisk`].
/// Only meant for proxy types usage.
fn gen_none_fields_proxy(ast: &StructWithFields) -> proc_macro2::TokenStream {
    let proxy_name = &ast.ident;
    let none_fields = ast.fields.iter().map(|field| {
        let ident = &field.ident;
        quote! {
            #ident: None
        }
    });
    quote! {
        #proxy_name {
            #(#none_fields),*
        }
    }
}
