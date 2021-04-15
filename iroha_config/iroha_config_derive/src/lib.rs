#![allow(clippy::string_add, clippy::str_to_string)]

//! Module with Configurable derive macro

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_error::{abort, abort_call_site};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    Data, DataStruct, DeriveInput, Fields, GenericArgument, Ident, Lit, LitStr, Meta,
    PathArguments, Token, Type, TypePath,
};

struct EnvPrefix {
    _ident: Ident,
    _eq: Token![=],
    prefix: LitStr,
}

mod attrs {
    pub const ENV_PREFIX: &str = "env_prefix";
    pub const SERDE_AS_STR: &str = "serde_as_str";
    pub const INNER: &str = "inner";
}

fn get_type_argument<'a, 'b>(s: &'a str, ty: &'b Type) -> Option<&'b GenericArgument> {
    let path = if let Type::Path(ty) = ty {
        ty
    } else {
        return None;
    };
    let segments = &path.path.segments;
    if segments.len() != 1 || segments[0].ident != s {
        return None;
    }

    if let PathArguments::AngleBracketed(bracketed_arguments) = &segments[0].arguments {
        if bracketed_arguments.args.len() == 1 {
            return Some(&bracketed_arguments.args[0]);
        }
    }
    None
}

fn is_arc_rwlock(ty: &Type) -> bool {
    let dearced_ty = get_type_argument("Arc", ty)
        .and_then(|ty| {
            if let GenericArgument::Type(ty) = ty {
                Some(ty)
            } else {
                None
            }
        })
        .unwrap_or(ty);
    get_type_argument("RwLock", dearced_ty).is_some()
}

// TODO: make it const generic type once it will be stabilized
fn parse_const_ident(input: ParseStream, ident: &'static str) -> syn::Result<Ident> {
    let parse_ident: Ident = input.parse()?;
    if parse_ident == ident {
        Ok(parse_ident)
    } else {
        Err(syn::Error::new_spanned(parse_ident, "Unknown ident"))
    }
}

impl Parse for EnvPrefix {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _ident: parse_const_ident(input, attrs::ENV_PREFIX)?,
            _eq: input.parse()?,
            prefix: input.parse()?,
        })
    }
}

struct Inner {
    _ident: Ident,
}

impl Parse for Inner {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _ident: parse_const_ident(input, attrs::INNER)?,
        })
    }
}

struct SerdeAsStr {
    _ident: Ident,
}

impl Parse for SerdeAsStr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _ident: parse_const_ident(input, attrs::SERDE_AS_STR)?,
        })
    }
}

/// Derive for config. Check other doc in `iroha_config` reexport
#[proc_macro_derive(Configurable, attributes(config))]
pub fn configurable_derive(input: TokenStream) -> TokenStream {
    let ast = match syn::parse(input) {
        Ok(ast) => ast,
        Err(err) => {
            abort_call_site!("Failed to parse input Token Stream: {}", err)
        }
    };
    impl_configurable(&ast)
}

fn impl_load_env(
    ty: &Ident,
    field_idents: &[&Ident],
    inner: &[bool],
    lvalue: &[proc_macro2::TokenStream],
    as_str: &[bool],
    field_ty: &[Type],
    field_environment: &[String],
) -> proc_macro2::TokenStream {
    let set_field = field_ty
        .iter()
        .zip(field_idents.iter())
        .zip(as_str.iter())
        .zip(lvalue.iter())
        .map(|(((ty, ident), &as_str), lvalue)| {
            let is_string = if let Type::Path(TypePath { path, .. }) = ty {
                path.is_ident("String")
            } else {
                false
            };
            let set_field = if is_string {
                quote! { #lvalue = var }
            } else if as_str {
                quote! {
                    #lvalue = serde_json::from_value(var.into())
                        .map_err(|e| iroha_config::derive::Error::field_error(stringify!(#ident), e))?
                }
            } else {
                quote! {
                    #lvalue = serde_json::from_str(&var)
                        .map_err(|e| iroha_config::derive::Error::field_error(stringify!(#ident), e))?
                }
            };
            (set_field, lvalue)
        })
        .zip(field_environment.iter())
        .zip(inner.iter())
        .map(|(((set_field, lvalue), field_environment), &inner)| {
            let inner = if inner {
                quote! {
                    #lvalue.load_environment().await?;
                }
            } else {
                quote! {}
            };
            quote! {
                if let Ok(var) = std::env::var(#field_environment) {
                    #set_field;
                }
                #inner
            }
        });

    quote! {
        fn load_environment(
            &'_ mut self
        ) -> iroha_config::BoxedFuture<'_, std::result::Result<(), iroha_config::derive::Error>> {
            async fn load_environment(_self: &mut #ty) -> std::result::Result<(), iroha_config::derive::Error> {
                #(#set_field)*
                Ok(())
            }
            Box::pin(load_environment(self))
        }
    }
}

fn impl_get_doc_recursive(
    field_ty: &[Type],
    field_idents: &[&Ident],
    inner: Vec<bool>,
    docs: Vec<LitStr>,
) -> proc_macro2::TokenStream {
    let variants = field_idents
        .iter()
        .zip(inner)
        .zip(docs)
        .zip(field_ty)
        .map(|(((ident, inner), docs), ty)| {
            if inner {
                quote! {
                    [stringify!(#ident)] => Some(#docs),
                    [stringify!(#ident), rest @ ..] => <#ty as iroha_config::Configurable>::get_doc_recursive(rest)?,
                }
            } else {
                quote! { [stringify!(#ident)] => Some(#docs), }
            }
        })
        // XXX: Workaround
        //Decription of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

    quote! {
        fn get_doc_recursive<'a>(
            inner_field: impl AsRef<[&'a str]>,
        ) -> std::result::Result<std::option::Option<&'static str>, iroha_config::derive::Error>
        {
            let inner_field = inner_field.as_ref();
            let doc = match inner_field {
                #variants
                field => return Err(iroha_config::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(doc)
        }
    }
}

fn impl_get_docs(
    field_ty: &[Type],
    field_idents: &[&Ident],
    inner: Vec<bool>,
    docs: Vec<LitStr>,
) -> proc_macro2::TokenStream {
    let inserts = field_idents
        .iter()
        .zip(inner)
        .zip(docs)
        .zip(field_ty)
        .map(|(((ident, inner), docs), ty)| {
            let docs = if inner {
                quote!{ <#ty as iroha_config::Configurable>::get_docs().into() }
            } else {
                quote!{ #docs.into() }
            };

            quote! { map.insert(stringify!(#ident).to_owned(), #docs); }
        })
        // XXX: Workaround
        //Decription of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

    quote! {
        fn get_docs() -> serde_json::Value {
            let mut map = serde_json::Map::new();
            #inserts
            map.into()
        }
    }
}

fn impl_get_recursive(
    ty: &Ident,
    field_idents: &[&Ident],
    inner: Vec<bool>,
    lvalue: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    let variants = field_idents
        .iter()
        .zip(inner)
        .zip(lvalue.iter())
        .map(|((ident, inner), lvalue)| {
            let inner = if inner {
                quote! {
                    [stringify!(#ident), rest @ ..] => {
                        #lvalue.get_recursive(rest).await?
                    },
                }
            } else {
                quote! {}
            };
            quote! {
                [stringify!(#ident)] => {
                    serde_json::to_value(&#lvalue)
                        .map_err(|e| iroha_config::derive::Error::field_error(stringify!(#ident), e))?
                }
                #inner
            }
        })
        // XXX: Workaround
        //Decription of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

    quote! {
        fn get_recursive<'a, 'b, T>(
            &'a self,
            inner_field: T,
        ) -> iroha_config::BoxedFuture<'a, Result<serde_json::Value, Self::Error>>
        where
            'b: 'a,
            T: AsRef<[&'b str]> + Send + 'b,
        {
            async fn get_recursive<'a>(
                _self: &#ty,
                inner_field: impl AsRef<[&'a str]> + Send,
            ) -> std::result::Result<serde_json::Value, iroha_config::derive::Error> {
                let inner_field = inner_field.as_ref();
                let value = match inner_field {
                    #variants
                    field => return Err(iroha_config::derive::Error::UnknownField(
                        field.iter().map(ToString::to_string).collect()
                    )),
                };
                Ok(value)
            }
            Box::pin(get_recursive(self, inner_field))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn impl_configurable(ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let prefix = ast
        .attrs
        .iter()
        .find_map(|attr| attr.parse_args::<EnvPrefix>().ok())
        .map(|pref| pref.prefix.value())
        .unwrap_or_default();

    let fields = if let Data::Struct(DataStruct {
        fields: Fields::Named(fields),
        ..
    }) = &ast.data
    {
        &fields.named
    } else {
        abort!(ast, "Only structs are supported")
    };
    let field_idents = fields
        .iter()
        .map(|field| {
            #[allow(clippy::expect_used)]
            field
                .ident
                .as_ref()
                .expect("Should always be set for named structures")
        })
        .collect::<Vec<_>>();
    let field_attrs = fields.iter().map(|field| &field.attrs).collect::<Vec<_>>();
    let field_ty = fields
        .iter()
        .map(|field| field.ty.clone())
        .collect::<Vec<_>>();

    let inner = field_attrs
        .iter()
        .map(|attrs| attrs.iter().any(|attr| attr.parse_args::<Inner>().is_ok()))
        .collect::<Vec<_>>();

    let as_str = field_attrs
        .iter()
        .map(|attrs| {
            attrs
                .iter()
                .any(|attr| attr.parse_args::<SerdeAsStr>().is_ok())
        })
        .collect::<Vec<_>>();

    let field_environment = field_idents
        .iter()
        .into_iter()
        .map(|ident| prefix.clone() + &ident.to_string().to_uppercase())
        .collect::<Vec<_>>();
    let docs = field_attrs
        .iter()
        .zip(field_environment.iter())
        .zip(field_ty.iter())
        .map(|((attrs, env), field_ty)| {
            let real_doc = attrs
                .iter()
                .filter_map(|attr| attr.parse_meta().ok())
                .find_map(|meta| {
                    if let Meta::NameValue(meta) = meta {
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
        .collect::<Vec<_>>();
    let lvalue = field_ty.iter().map(is_arc_rwlock).zip(field_idents.iter());
    let lvalue_read = lvalue
        .clone()
        .map(|(is_arc_rwlock, ident)| {
            if is_arc_rwlock {
                quote! { _self.#ident.read().await }
            } else {
                quote! { _self.#ident }
            }
        })
        .collect::<Vec<_>>();
    let lvalue_write = lvalue
        .clone()
        .map(|(is_arc_rwlock, ident)| {
            if is_arc_rwlock {
                quote! { _self.#ident.write().await }
            } else {
                quote! { _self.#ident }
            }
        })
        .collect::<Vec<_>>();

    let load_environment = impl_load_env(
        name,
        &field_idents,
        &inner,
        &lvalue_write,
        &as_str,
        &field_ty,
        &field_environment,
    );
    let get_recursive = impl_get_recursive(name, &field_idents, inner.clone(), &lvalue_read);
    let get_doc_recursive =
        impl_get_doc_recursive(&field_ty, &field_idents, inner.clone(), docs.clone());
    let get_docs = impl_get_docs(&field_ty, &field_idents, inner, docs);

    let out = quote! {
        impl iroha_config::Configurable for #name {
            type Error = iroha_config::derive::Error;

            #get_recursive
            #get_doc_recursive
            #get_docs
            #load_environment
        }
    };
    out.into()
}
