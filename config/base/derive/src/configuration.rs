use proc_macro::TokenStream;
use quote::quote;
use syn::{Ident, LitStr, Type};

use super::utils::{
    extract_field_attrs, extract_field_idents, extract_field_types, field_has_inner_attr, gen_docs,
    gen_field_env, gen_lvalues, get_env_prefix, StructWithFields,
};

pub(super) fn impl_configuration(ast: &StructWithFields) -> TokenStream {
    let name = &ast.ident;

    let prefix = get_env_prefix(ast);

    let field_idents = extract_field_idents(&ast.fields);

    let field_attrs = extract_field_attrs(&ast.fields);

    let field_ty = extract_field_types(&ast.fields);
    let inner = field_has_inner_attr(&field_attrs);

    let field_env = gen_field_env(&field_idents, &prefix);

    let docs = gen_docs(&field_attrs, &field_env, &field_ty);

    let (lvalue_read, _lvalue_write) = gen_lvalues(&field_ty, &field_idents);

    let get_recursive = impl_get_recursive(&field_idents, &inner, &lvalue_read);
    let get_doc_recursive =
        impl_get_doc_recursive(&field_ty, &field_idents, inner.clone(), docs.clone());
    let get_inner_docs = impl_get_inner_docs(&field_ty, &field_idents, inner.clone(), docs.clone());
    let get_docs = impl_get_docs(&field_ty, &field_idents, inner, docs);

    let out = quote! {
        impl iroha_config_base::proxy::Configuration for #name {
            type Error = iroha_config_base::derive::Error;

            #get_recursive
            #get_doc_recursive
            #get_docs
            #get_inner_docs
        }
    };
    out.into()
}

fn impl_get_doc_recursive(
    field_ty: &[Type],
    field_idents: &[&Ident],
    inner: Vec<bool>,
    docs: Vec<LitStr>,
) -> proc_macro2::TokenStream {
    if field_idents.is_empty() {
        return quote! {
            fn get_doc_recursive<'a>(
                inner_field: impl AsRef<[&'a str]>,
            ) -> core::result::Result<std::option::Option<String>, iroha_config_base::derive::Error>
            {
                Err(iroha_config_base::derive::Error::UnknownField(
                    inner_field.as_ref().iter().map(ToString::to_string).collect()
                ))
            }
        };
    }
    let variants = field_idents
        .iter()
        .zip(inner)
        .zip(docs)
        .zip(field_ty)
        .map(|(((ident, inner_thing), documentation), ty)| {
            if inner_thing {
                quote! {
                    [stringify!(#ident)] => {
                        let curr_doc = #documentation;
                        let inner_docs = <#ty as iroha_config_base::proxy::Configuration>::get_inner_docs();
                        let total_docs = format!("{}\n\nHas following fields:\n\n{}\n", curr_doc, inner_docs);
                        Some(total_docs)
                    },
                    [stringify!(#ident), rest @ ..] => <#ty as iroha_config_base::proxy::Configuration>::get_doc_recursive(rest)?,
                }
            } else {
                quote! { [stringify!(#ident)] => Some(#documentation.to_owned()), }
            }
        });

    quote! {
        fn get_doc_recursive<'a>(
            inner_field: impl AsRef<[&'a str]>,
        ) -> core::result::Result<std::option::Option<String>, iroha_config_base::derive::Error>
        {
            let inner_field = inner_field.as_ref();
            let doc = match inner_field {
                #(#variants)*
                field => return Err(iroha_config_base::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(doc)
        }
    }
}

fn impl_get_inner_docs(
    field_ty: &[Type],
    field_idents: &[&Ident],
    inner: Vec<bool>,
    docs: Vec<LitStr>,
) -> proc_macro2::TokenStream {
    let inserts = field_idents.iter().zip(inner).zip(docs).zip(field_ty).map(
        |(((ident, inner_thing), documentation), ty)| {
            let doc = if inner_thing {
                quote! { <#ty as iroha_config_base::proxy::Configuration>::get_inner_docs().as_str() }
            } else {
                quote! { #documentation.into() }
            };

            quote! {
                inner_docs.push_str(stringify!(#ident));
                inner_docs.push_str(": ");
                inner_docs.push_str(#doc);
                inner_docs.push_str("\n\n");
            }
        },
    );

    quote! {
        fn get_inner_docs() -> String {
            let mut inner_docs = String::new();
            #(#inserts)*
            inner_docs
        }
    }
}

fn impl_get_docs(
    field_ty: &[Type],
    field_idents: &[&Ident],
    inner: Vec<bool>,
    docs: Vec<LitStr>,
) -> proc_macro2::TokenStream {
    let inserts = field_idents.iter().zip(inner).zip(docs).zip(field_ty).map(
        |(((ident, inner_thing), documentation), ty)| {
            let doc = if inner_thing {
                quote! { <#ty as iroha_config_base::proxy::Configuration>::get_docs().into() }
            } else {
                quote! { #documentation.into() }
            };

            quote! { map.insert(stringify!(#ident).to_owned(), #doc); }
        },
    );

    quote! {
        fn get_docs() -> serde_json::Value {
            let mut map = serde_json::Map::new();
            #(#inserts)*
            map.into()
        }
    }
}

fn impl_get_recursive(
    field_idents: &[&Ident],
    inner: &[bool],
    lvalue: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    if field_idents.is_empty() {
        return quote! {
            fn get_recursive<'a, T>(
                &self,
                inner_field: T,
            ) -> iroha_config_base::BoxedFuture<'a, core::result::Result<serde_json::Value, Self::Error>>
            where
                T: AsRef<[&'a str]> + Send + 'a,
            {
                Err(iroha_config_base::derive::Error::UnknownField(
                    inner_field.as_ref().iter().map(ToString::to_string).collect()
                ))
            }
        };
    }
    let variants = field_idents
        .iter()
        .zip(inner)
        .zip(lvalue.iter())
        .map(|((ident, &inner_thing), l_value)| {
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
                        .map_err(|e| iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
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
                field => return Err(iroha_config_base::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(value)
        }
    }
}
