use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Attribute, Field, GenericArgument, Ident, Lit, LitStr, Meta, PathArguments, Token, Type,
};

/// Keywords used inside `#[view(...)]` and `#[config(...)]`
mod kw {
    // config keywords
    syn::custom_keyword!(serde_as_str);
    syn::custom_keyword!(inner);
    syn::custom_keyword!(env_prefix);
    // view keywords
    syn::custom_keyword!(ignore);
    syn::custom_keyword!(into);
}

/// Trait for attribute parsing generalization
pub trait AttrParser<Inner: Parse> {
    const IDENT: &'static str;

    fn parse(attr: &syn::Attribute) -> syn::Result<Inner> {
        attr.path
            .is_ident(<Self as AttrParser<_>>::IDENT)
            .then(|| attr.parse_args::<Inner>())
            .map_or_else(
                || {
                    Err(syn::Error::new_spanned(
                        attr,
                        format!(
                            "Attribute must be in form #[{}...]",
                            <Self as AttrParser<_>>::IDENT
                        ),
                    ))
                },
                |inner| inner,
            )
    }
}

// Macro for automatic [`syn::parse::Parse`] impl generation for keyword
// attribute structs in derive macros. Put in parent crate as
// `#[macro_export]` is disallowed from proc macro crates.
macro_rules! attr_struct {
    // Matching struct with named fields
    (
        $( #[$meta:meta] )*
    //  ^~~~attributes~~~~^
        $vis:vis struct $name:ident {
            $(
                $( #[$field_meta:meta] )*
    //          ^~~~field attributes~~~!^
                $field_vis:vis $field_name:ident : $field_ty:ty
    //          ^~~~~~~~~~~~~~~~~a single field~~~~~~~~~~~~~~~^
            ),*
        $(,)? }
    ) => {
        $( #[$meta] )*
        $vis struct $name {
            $(
                $( #[$field_meta] )*
                $field_vis $field_name : $field_ty
            ),*
        }

        impl syn::parse::Parse for $name {
            fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
                Ok(Self {
                    $(
                        $field_name: input.parse()?,
                    )*
                })
            }
        }
    };
}

/// Structure to parse `#[view(...)]` attributes.
/// [`Inner`] is responsible for parsing attribute arguments
pub struct View<Inner: Parse>(std::marker::PhantomData<Inner>);

/// Structure to parse `#[config(...)]` attributes.
/// [`Inner`] is responsible for parsing attribute arguments
struct Config<Inner: Parse>(std::marker::PhantomData<Inner>);

impl<Inner: Parse> AttrParser<Inner> for Config<Inner> {
    const IDENT: &'static str = "config";
}

impl<Inner: Parse> AttrParser<Inner> for View<Inner> {
    const IDENT: &'static str = "view";
}

attr_struct! {
    pub struct ViewIgnore {
        _kw: kw::ignore,
    }
}

attr_struct! {
    pub struct ViewFieldType {
        _kw: kw::into,
        _eq: Token![=],
        ty: Type,
    }
}

attr_struct! {
    pub struct ConfigInner {
        _kw: kw::inner,
    }
}

attr_struct! {
    pub struct ConfigAsStr {
        _kw: kw::serde_as_str,
    }
}

attr_struct! {
    pub struct ConfigEnvPrefix {
        _kw: kw::env_prefix,
        _eq: Token![=],
        pub prefix: LitStr,
    }
}

impl From<ViewFieldType> for Type {
    fn from(value: ViewFieldType) -> Self {
        value.ty
    }
}

/// Parsed struct with named fields used in proc macros of this crate
#[derive(Clone)]
pub struct StructWithFields {
    pub attrs: Vec<Attribute>,
    pub vis: syn::Visibility,
    _struct_token: Token![struct],
    pub ident: Ident,
    pub generics: syn::Generics,
    pub fields: Vec<Field>,
    _semi_token: Option<Token![;]>,
}

impl Parse for StructWithFields {
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

impl ToTokens for StructWithFields {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let StructWithFields {
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

/// Remove attributes with ident [`attr_ident`] from attributes
pub fn remove_attr(attrs: &mut Vec<Attribute>, attr_ident: &str) {
    attrs.retain(|attr| !attr.path.is_ident(attr_ident));
}

pub fn extract_field_idents(fields: &[Field]) -> Vec<&Ident> {
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

pub fn extract_field_types(fields: &[Field]) -> Vec<Type> {
    fields
        .iter()
        .map(|field| field.ty.clone())
        .collect::<Vec<_>>()
}
pub fn extract_field_attrs(fields: &[Field]) -> Vec<&[Attribute]> {
    fields
        .iter()
        .map(|field| field.attrs.as_slice())
        .collect::<Vec<_>>()
}

pub fn get_type_argument<'sl, 'tl>(s: &'sl str, ty: &'tl Type) -> Option<&'tl GenericArgument> {
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

pub fn get_inner_type<'tl, 'sl>(outer_ty_ident: &'sl str, ty: &'tl Type) -> &'tl Type {
    #[allow(clippy::shadow_unrelated)]
    get_type_argument(outer_ty_ident, ty)
        .and_then(|ty| {
            if let GenericArgument::Type(r#type) = ty {
                Some(r#type)
            } else {
                None
            }
        })
        .unwrap_or(ty)
}

pub fn is_arc_rwlock(ty: &Type) -> bool {
    let dearced_ty = get_inner_type("Arc", ty);
    get_type_argument("RwLock", dearced_ty).is_some()
}

/// Receives a [`Vec`] with all the attributes on fields, returns a [`Vec<bool>`]
/// showing if any of them had a [`#[config(inner)]`].
pub fn field_has_inner_attr(field_attrs: &[&[Attribute]]) -> Vec<bool> {
    field_attrs
        .iter()
        .map(|attrs| {
            attrs
                .iter()
                .any(|attr| Config::<ConfigInner>::parse(attr).is_ok())
        })
        .collect::<Vec<_>>()
}

/// Receives a [`Vec`] with all the attributes on fields, returns a [`Vec<bool>`]
/// showing if any of them had a [`#[config(serde_as_str)]`].
pub fn field_has_as_str_attr(field_attrs: &[&[Attribute]]) -> Vec<bool> {
    field_attrs
        .iter()
        .map(|attrs| {
            attrs
                .iter()
                .any(|attr| Config::<ConfigAsStr>::parse(attr).is_ok())
        })
        .collect::<Vec<_>>()
}

/// Receives a [`Vec`] with all the attributes on fields, returns a [`Vec<bool>`]
/// showing if any of them are wrapped in [`Option<..>`].
pub fn field_has_option_type(field_ty: &[Type]) -> Vec<bool> {
    field_ty.iter().map(is_option_type).collect::<Vec<_>>()
}

/// Check if the provided type is of the form [`Option<..>`]
pub fn is_option_type(ty: &Type) -> bool {
    get_type_argument("Option", ty).is_some()
}

/// Remove attributes with ident [`attr_ident`] from struct attributes and field attributes
pub fn remove_attr_struct(ast: &mut StructWithFields, attr_ident: &str) {
    let StructWithFields { attrs, fields, .. } = ast;
    for field in fields {
        remove_attr(&mut field.attrs, attr_ident)
    }
    remove_attr(attrs, attr_ident);
}

pub fn get_env_prefix(ast: &StructWithFields) -> String {
    ast.attrs
        .iter()
        .map(Config::<ConfigEnvPrefix>::parse)
        .find_map(Result::ok)
        .map(|pref| pref.prefix.value())
        .unwrap_or_default()
}

/// Generate documentation for all fields based on their type and already existing documentation
pub fn gen_docs(
    field_attrs: &[&[Attribute]],
    field_env: &[String],
    field_ty: &[Type],
) -> Vec<LitStr> {
    field_attrs
        .iter()
        .zip(field_env.iter())
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
        .collect::<Vec<_>>()
}

/// Generate lvalue forms for all struct fields, taking [`Arc<RwLock<..>>`] types
/// into account as well. Returns a 2-tuple of read and write forms.
pub fn gen_lvalues(
    field_ty: &[Type],
    field_idents: &[&Ident],
) -> (Vec<TokenStream>, Vec<TokenStream>) {
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
    (lvalue_read, lvalue_write)
}

pub fn gen_field_env(field_idents: &[&Ident], prefix: &str) -> Vec<String> {
    field_idents
        .iter()
        .map(|ident| prefix.to_owned() + &ident.to_string().to_uppercase())
        .collect::<Vec<_>>()
}
