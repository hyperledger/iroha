use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{Lit, LitStr, Meta};

use super::utils::StructWithFields;

pub fn impl_documented(ast: &StructWithFields) -> TokenStream {
    let name = &ast.ident;
    let docs = gen_docs(ast);

    let get_docs = impl_get_docs(docs.clone(), ast);
    let get_inner_docs = impl_get_inner_docs(docs.clone(), ast);
    let get_doc_recursive = impl_get_doc_recursive(docs, ast);

    let get_recursive = impl_get_recursive(ast);

    let out = quote! {
        impl ::iroha_config_base::proxy::Documented for #name {
            type Error = ::iroha_config_base::derive::Error;

            #get_recursive
            #get_doc_recursive
            #get_docs
            #get_inner_docs
        }
    };
    out.into()
}

fn impl_get_doc_recursive(docs: Vec<LitStr>, ast: &StructWithFields) -> proc_macro2::TokenStream {
    if ast.fields.is_empty() {
        return quote! {
            fn get_doc_recursive<'a>(
                inner_field: impl AsRef<[&'a str]>,
            ) -> core::result::Result<std::option::Option<String>, ::iroha_config_base::derive::Error>
            {
                Err(::iroha_config_base::derive::Error::UnknownField(
                    inner_field.as_ref().iter().map(ToString::to_string).collect()
                ))
            }
        };
    }

    let variants = ast.fields
        .iter()
        .zip(docs)
        .map(|(field, documentation)| {
            let inner_thing = field.has_inner;
            let ty = &field.ty;
            let ident = &field.ident;
            if inner_thing {
                quote! {
                    [stringify!(#ident)] => {
                        let curr_doc = #documentation;
                        let inner_docs = <#ty as ::iroha_config_base::proxy::Documented>::get_inner_docs();
                        let total_docs = format!("{}\n\nHas following fields:\n\n{}\n", curr_doc, inner_docs);
                        Some(total_docs)
                    },
                    [stringify!(#ident), rest @ ..] => <#ty as ::iroha_config_base::proxy::Documented>::get_doc_recursive(rest)?,
                }
            } else {
                quote! { [stringify!(#ident)] => Some(#documentation.to_owned()), }
            }
        });

    quote! {
        fn get_doc_recursive<'a>(
            inner_field: impl AsRef<[&'a str]>,
        ) -> core::result::Result<std::option::Option<String>, ::iroha_config_base::derive::Error>
        {
            let inner_field = inner_field.as_ref();
            let doc = match inner_field {
                #(#variants)*
                field => return Err(::iroha_config_base::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(doc)
        }
    }
}

fn impl_get_inner_docs(docs: Vec<LitStr>, ast: &StructWithFields) -> proc_macro2::TokenStream {
    let inserts = ast.fields.iter().zip(docs).map(|(field, documentation)| {
        let inner_thing = field.has_inner;
        let ty = &field.ty;
        let ident = &field.ident;
        let doc = if inner_thing {
            quote! { <#ty as ::iroha_config_base::proxy::Documented>::get_inner_docs().as_str() }
        } else {
            quote! { #documentation.into() }
        };

        quote! {
            inner_docs.push_str(stringify!(#ident));
            inner_docs.push_str(": ");
            inner_docs.push_str(#doc);
            inner_docs.push_str("\n\n");
        }
    });

    quote! {
        fn get_inner_docs() -> String {
            let mut inner_docs = String::new();
            #(#inserts)*
            inner_docs
        }
    }
}

fn impl_get_docs(docs: Vec<LitStr>, ast: &StructWithFields) -> proc_macro2::TokenStream {
    let inserts = ast.fields.iter().zip(docs).map(|(field, documentation)| {
        let ident = &field.ident;
        let ty = &field.ty;
        let inner_thing = field.has_inner;
        let doc = if inner_thing {
            quote! { <#ty as ::iroha_config_base::proxy::Documented>::get_docs().into() }
        } else {
            quote! { #documentation.into() }
        };

        quote! { map.insert(stringify!(#ident).to_owned(), #doc); }
    });

    quote! {
        fn get_docs() -> serde_json::Value {
            let mut map = serde_json::Map::new();
            #(#inserts)*
            map.into()
        }
    }
}

fn impl_get_recursive(ast: &StructWithFields) -> proc_macro2::TokenStream {
    if ast.fields.is_empty() {
        return quote! {
            fn get_recursive<'a, T>(
                &self,
                inner_field: T,
            ) -> ::iroha_config_base::BoxedFuture<'a, core::result::Result<serde_json::Value, Self::Error>>
            where
                T: AsRef<[&'a str]> + Send + 'a,
            {
                Err(::iroha_config_base::derive::Error::UnknownField(
                    inner_field.as_ref().iter().map(ToString::to_string).collect()
                ))
            }
        };
    }

    let variants = ast.fields
        .iter()
        .map(|field | {
            let inner_thing = field.has_inner;
            let ident = &field.ident;
            let l_value = &field.lvalue_read;
            let inner_thing2 = if inner_thing {
                quote! {
                    [stringify!(#ident), rest @ ..] => {
                        #l_value.get_recursive(rest)?
                    },
                }
            } else {
                quote! {}
            };
            quote! {
                [stringify!(#ident)] => {
                    serde_json::to_value(&#l_value)
                        .map_err(|e| ::iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
                #inner_thing2
            }
        });

    quote! {
        fn get_recursive<'a, T>(
            &self,
            inner_field: T,
        ) -> core::result::Result<serde_json::Value, Self::Error>
        where
            T: AsRef<[&'a str]> + Send + 'a,
        {
            let inner_field = inner_field.as_ref();
            let value = match inner_field {
                #(#variants)*
                field => return Err(::iroha_config_base::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(value)
        }
    }
}

/// Generate documentation for all fields based on their type and already existing documentation
pub fn gen_docs(ast: &StructWithFields) -> Vec<LitStr> {
    ast.fields
        .iter()
        .map(|field| {
            let field_ty = &field.ty;
            let env = &field.env_str;
            let real_doc = field
                .attrs
                .iter()
                .filter_map(|attr| attr.parse_meta().ok())
                .find_map(|metadata| {
                    if let Meta::NameValue(meta) = metadata {
                        if meta.path.is_ident("doc") {
                            if let Lit::Str(s) = meta.lit {
                                return Some(s);
                            }
                        }
                    }
                    None
                });
            let real_doc = real_doc.map(|doc| doc.value() + "\n\n").unwrap_or_default();
            let docs = format!(
                "{}Has type `{}`. Can be configured via environment variable `{}`",
                real_doc,
                quote! { #field_ty }.to_string().replace(' ', ""),
                env
            );
            LitStr::new(&docs, Span::mixed_site())
        })
        .collect::<Vec<_>>()
}
