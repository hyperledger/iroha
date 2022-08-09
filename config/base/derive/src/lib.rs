//! Contains the `#[derive(Configurable)]` macro definition.

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_error::{abort, abort_call_site};
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Attribute, Data, DataStruct, DeriveInput, Field, Fields, GenericArgument, Ident, Lit, LitStr,
    Meta, NestedMeta, PathArguments, Token, Type, TypePath,
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

fn get_type_argument<'sl, 'tl>(s: &'sl str, ty: &'tl Type) -> Option<&'tl GenericArgument> {
    let path = if let Type::Path(r#type) = ty {
        r#type
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
    #[allow(clippy::shadow_unrelated)]
    let dearced_ty = get_type_argument("Arc", ty)
        .and_then(|ty| {
            if let GenericArgument::Type(r#type) = ty {
                Some(r#type)
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

/// Derive for config. More details in `iroha_config_base` reexport
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
        .map(|(((ty, ident), &as_str_attr), l_value)| {
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
            } else {
                quote! {
                    #l_value = serde_json::from_str(&var)
                        .map_err(|e| iroha_config_base::derive::Error::field_error(stringify!(#ident), e))?
                }
            };
            (set_field, l_value)
        })
        .zip(field_environment.iter())
        .zip(inner.iter())
        .map(|(((set_field, l_value), field_env), &inner_thing)| {
            let inner_thing2 = if inner_thing {
                quote! {
                    #l_value.load_environment()?;
                }
            } else {
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
        fn load_environment(
            &'_ mut self
        ) -> core::result::Result<(), iroha_config_base::derive::Error> {
            #(#set_field)*
            Ok(())
        }
    }
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
                        let inner_docs = <#ty as iroha_config_base::Configurable>::get_inner_docs();
                        let total_docs = format!("{}\n\nHas following fields:\n\n{}\n", curr_doc, inner_docs);
                        Some(total_docs)
                    },
                    [stringify!(#ident), rest @ ..] => <#ty as iroha_config_base::Configurable>::get_doc_recursive(rest)?,
                }
            } else {
                quote! { [stringify!(#ident)] => Some(#documentation.to_owned()), }
            }
        })
        // XXX: Workaround
        //Decription of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

    quote! {
        fn get_doc_recursive<'a>(
            inner_field: impl AsRef<[&'a str]>,
        ) -> core::result::Result<std::option::Option<String>, iroha_config_base::derive::Error>
        {
            let inner_field = inner_field.as_ref();
            let doc = match inner_field {
                #variants
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
    let inserts = field_idents
        .iter()
        .zip(inner)
        .zip(docs)
        .zip(field_ty)
        .map(|(((ident, inner_thing), documentation), ty)| {
            let doc = if inner_thing {
                quote!{ <#ty as iroha_config_base::Configurable>::get_inner_docs().as_str() }
            } else {
                quote!{ #documentation.into() }
            };

            quote! {
                inner_docs.push_str(stringify!(#ident));
                inner_docs.push_str(": ");
                inner_docs.push_str(#doc);
                inner_docs.push_str("\n\n");
            }
        })
        // XXX: Workaround
        //Description of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

    quote! {
        fn get_inner_docs() -> String {
            let mut inner_docs = String::new();
            #inserts
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
    let inserts = field_idents
        .iter()
        .zip(inner)
        .zip(docs)
        .zip(field_ty)
        .map(|(((ident, inner_thing), documentation), ty)| {
            let doc = if inner_thing {
                quote!{ <#ty as iroha_config_base::Configurable>::get_docs().into() }
            } else {
                quote!{ #documentation.into() }
            };

            quote! { map.insert(stringify!(#ident).to_owned(), #doc); }
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
    field_idents: &[&Ident],
    inner: Vec<bool>,
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
        .map(|((ident, inner_thing), l_value)| {
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
        })
        // XXX: Workaround
        //Decription of issue is here https://stackoverflow.com/a/65353489
        .fold(quote! {}, |acc, new| quote! { #acc #new });

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
                #variants
                field => return Err(iroha_config_base::derive::Error::UnknownField(
                    field.iter().map(ToString::to_string).collect()
                )),
            };
            Ok(value)
        }
    }
}

#[allow(clippy::too_many_lines, clippy::str_to_string)]
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
        .map(|((attrs, env), field_type)| {
            let real_doc = attrs
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
                quote! { #field_type }.to_string().replace(' ', ""),
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
                quote! { self.#ident.read().await }
            } else {
                quote! { self.#ident }
            }
        })
        .collect::<Vec<_>>();
    let lvalue_write = lvalue
        .clone()
        .map(|(is_arc_rwlock, ident)| {
            if is_arc_rwlock {
                quote! { self.#ident.write().await }
            } else {
                quote! { self.#ident }
            }
        })
        .collect::<Vec<_>>();

    let load_environment = impl_load_env(
        &field_idents,
        &inner,
        &lvalue_write,
        &as_str,
        &field_ty,
        &field_environment,
    );
    let get_recursive = impl_get_recursive(&field_idents, inner.clone(), &lvalue_read);
    let get_doc_recursive =
        impl_get_doc_recursive(&field_ty, &field_idents, inner.clone(), docs.clone());
    let get_inner_docs = impl_get_inner_docs(&field_ty, &field_idents, inner.clone(), docs.clone());
    let get_docs = impl_get_docs(&field_ty, &field_idents, inner, docs);

    let out = quote! {
        impl iroha_config_base::Configurable for #name {
            type Error = iroha_config_base::derive::Error;

            #get_recursive
            #get_doc_recursive
            #get_docs
            #get_inner_docs
            #load_environment
        }
    };
    out.into()
}

// Take struct with named fields as input
#[derive(Debug, Clone)]
struct ViewInput {
    attrs: Vec<Attribute>,
    vis: syn::Visibility,
    _struct_token: Token![struct],
    ident: Ident,
    generics: syn::Generics,
    fields: Vec<Field>,
    _semi_token: Option<Token![;]>,
}

impl Parse for ViewInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            attrs: input.call(Attribute::parse_outer)?,
            vis: input.parse()?,
            _struct_token: input.parse()?,
            ident: input.parse()?,
            generics: input.parse()?,
            fields: input
                .parse::<syn::FieldsNamed>()?
                .named
                .into_iter()
                .collect(),
            _semi_token: input.parse()?,
        })
    }
}

// Recreate struct
impl ToTokens for ViewInput {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let ViewInput {
            attrs,
            vis,
            ident,
            generics,
            fields,
            ..
        } = self;
        let stream = quote! {
            #(#attrs)*
            #vis struct #ident #generics {
                #(#fields),*
            }
        };
        tokens.extend(stream);
    }
}

/// Keywords used inside `#[view(...)]`
mod kw {
    syn::custom_keyword!(ignore);
    syn::custom_keyword!(into);
}

/// Structure to parse `#[view(...)]` attributes
/// [`Inner`] is responsible for parsing attribute arguments
struct View<Inner: Parse>(std::marker::PhantomData<Inner>);

impl<Inner: Parse> View<Inner> {
    fn parse(attr: &Attribute) -> syn::Result<Inner> {
        attr.path
            .is_ident("view")
            .then(|| attr.parse_args::<Inner>())
            .map_or_else(
                || {
                    Err(syn::Error::new_spanned(
                        attr,
                        "Attribute must be in form #[view...]",
                    ))
                },
                |inner| inner,
            )
    }
}

struct ViewIgnore {
    _kw: kw::ignore,
}

impl Parse for ViewIgnore {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _kw: input.parse()?,
        })
    }
}

struct ViewFieldType {
    _kw: kw::into,
    _eq: Token![=],
    ty: Type,
}

impl Parse for ViewFieldType {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _kw: input.parse()?,
            _eq: input.parse()?,
            ty: input.parse()?,
        })
    }
}

impl From<ViewFieldType> for Type {
    fn from(value: ViewFieldType) -> Self {
        value.ty
    }
}

/// Generate view for given struct and convert from type to its view.
/// More details in `iroha_config_base` reexport.
#[proc_macro]
pub fn view(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as ViewInput);
    let original = gen_original_struct(ast.clone());
    let view = gen_view_struct(ast);
    let impl_from = gen_impl_from(&original, &view);
    let impl_default = gen_impl_default(&original, &view);
    let impl_has_view = gen_impl_has_view(&original);
    let assertions = gen_assertions(&view);
    let out = quote! {
        #original
        #impl_has_view
        #view
        #impl_from
        #impl_default
        #assertions
    };
    out.into()
}

fn gen_original_struct(mut ast: ViewInput) -> ViewInput {
    remove_attr_struct(&mut ast, "view");
    ast
}

#[allow(clippy::str_to_string, clippy::expect_used)]
fn gen_view_struct(mut ast: ViewInput) -> ViewInput {
    // Remove fields with #[view(ignore)]
    ast.fields.retain(is_view_field_ignored);
    // Change field type to `Type` if it has attribute #[view(into = Type)]
    ast.fields.iter_mut().for_each(view_field_change_type);
    // Replace doc-string for view
    remove_attr(&mut ast.attrs, "doc");
    let view_doc = format!("View for {}", ast.ident);
    ast.attrs.push(syn::parse_quote!(
        #[doc = #view_doc]
    ));
    // Remove `Default` from #[derive(..., Default, ...)] or #[derive(Default)] because we implement `Default` inside macro
    ast.attrs
        .iter_mut()
        .filter(|attr| attr.path.is_ident("derive"))
        .for_each(|attr| {
            let meta = attr
                .parse_meta()
                .expect("derive macro must be in one of the meta forms");
            match meta {
                Meta::List(list) => {
                    let items: Vec<syn::NestedMeta> = list
                        .nested
                        .into_iter()
                        .filter(|nested| {
                            if let NestedMeta::Meta(Meta::Path(path)) = nested {
                                if path.is_ident("Default") {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();
                    *attr = syn::parse_quote!(
                        #[derive(#(#items),*)]
                    )
                }
                Meta::Path(path) if path.is_ident("Default") => {
                    *attr = syn::parse_quote!(
                        #[derive()]
                    )
                }
                _ => {}
            }
        });
    remove_attr_struct(&mut ast, "view");
    ast.ident = format_ident!("{}View", ast.ident);
    ast
}

fn gen_impl_from(original: &ViewInput, view: &ViewInput) -> proc_macro2::TokenStream {
    let ViewInput {
        ident: original_ident,
        ..
    } = original;
    let ViewInput {
        generics,
        ident: view_ident,
        fields,
        ..
    } = view;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let field_idents = extract_field_idents(fields);

    quote! {
        impl #impl_generics core::convert::From<#original_ident> for #view_ident #ty_generics #where_clause {
            fn from(config: #original_ident) -> Self {
                let #original_ident {
                    #(
                        #field_idents,
                    )*
                    ..
                } =  config;
                Self {
                    #(
                        #field_idents: core::convert::From::<_>::from(#field_idents),
                    )*
                }
            }
        }
    }
}

fn gen_impl_default(original: &ViewInput, view: &ViewInput) -> proc_macro2::TokenStream {
    let ViewInput {
        ident: original_ident,
        ..
    } = original;
    let ViewInput {
        generics,
        ident: view_ident,
        ..
    } = view;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics core::default::Default for #view_ident #ty_generics #where_clause {
            fn default() -> Self {
                core::convert::From::<_>::from(<#original_ident as core::default::Default>::default())
            }
        }
    }
}

fn gen_impl_has_view(original: &ViewInput) -> proc_macro2::TokenStream {
    let ViewInput {
        generics,
        ident: view_ident,
        ..
    } = original;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics iroha_config_base::view::HasView for #view_ident #ty_generics #where_clause {}
    }
}

fn gen_assertions(view: &ViewInput) -> proc_macro2::TokenStream {
    let ViewInput { fields, .. } = view;
    let field_types = extract_field_types(fields);
    let messages: Vec<String> = extract_field_idents(fields)
        .iter()
        .map(|ident| {
            format!("Field `{ident}` has it's own view, consider adding attribute #[view(into = ViewType)]")
        })
        .collect();
    quote! {
        /// Assert that every field of 'View' doesn't implement `HasView` trait
        const _: () = {
            use iroha_config_base::view::NoView;
            #(
                const _: () = assert!(!iroha_config_base::view::IsHasView::<#field_types>::IS_HAS_VIEW, #messages);
            )*
        };
    }
}

/// Change [`Field`] type to `Type` if `#[view(type = Type)]` is present
fn view_field_change_type(field: &mut Field) {
    if let Some(ty) = field
        .attrs
        .iter()
        .map(View::<ViewFieldType>::parse)
        .find_map(Result::ok)
        .map(ViewFieldType::into)
    {
        field.ty = ty;
    }
}

/// Check if [`Field`] has `#[view(ignore)]`
fn is_view_field_ignored(field: &Field) -> bool {
    field
        .attrs
        .iter()
        .map(View::<ViewIgnore>::parse)
        .find_map(Result::ok)
        .is_none()
}

/// Remove attributes with ident [`attr_ident`] from struct attributes and field attributes
fn remove_attr_struct(ast: &mut ViewInput, attr_ident: &str) {
    let ViewInput { attrs, fields, .. } = ast;
    for field in fields {
        remove_attr(&mut field.attrs, attr_ident)
    }
    remove_attr(attrs, attr_ident);
}

/// Remove attributes with ident [`attr_ident`] from attributes
fn remove_attr(attrs: &mut Vec<Attribute>, attr_ident: &str) {
    attrs.retain(|attr| !attr.path.is_ident(attr_ident));
}

/// Return [`Vec`] of fields idents
fn extract_field_idents(fields: &[Field]) -> Vec<&Ident> {
    fields
        .iter()
        .map(|field| {
            #[allow(clippy::expect_used)]
            field
                .ident
                .as_ref()
                .expect("Should always be set for named structures")
        })
        .collect::<Vec<_>>()
}

/// Return [`Vec`] of fields types
fn extract_field_types(fields: &[Field]) -> Vec<&Type> {
    fields.iter().map(|field| &field.ty).collect::<Vec<_>>()
}
