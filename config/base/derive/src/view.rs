use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Attribute, Field, Ident, Meta, NestedMeta, Token, Type,
};

use super::utils;

// Take struct with named fields as input
#[derive(Debug, Clone)]
pub(crate) struct ViewInput {
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
pub(crate) struct View<Inner: Parse>(std::marker::PhantomData<Inner>);

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

pub(crate) struct ViewIgnore {
    _kw: kw::ignore,
}

impl Parse for ViewIgnore {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            _kw: input.parse()?,
        })
    }
}

pub(crate) struct ViewFieldType {
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

pub(crate) fn gen_original_struct(mut ast: ViewInput) -> ViewInput {
    remove_attr_struct(&mut ast, "view");
    ast
}

#[allow(clippy::str_to_string, clippy::expect_used)]
pub(crate) fn gen_view_struct(mut ast: ViewInput) -> ViewInput {
    // Remove fields with #[view(ignore)]
    ast.fields.retain(is_view_field_ignored);
    // Change field type to `Type` if it has attribute #[view(into = Type)]
    ast.fields.iter_mut().for_each(view_field_change_type);
    // Replace doc-string for view
    utils::remove_attr(&mut ast.attrs, "doc");
    let view_doc = format!("View for {}", ast.ident);
    ast.attrs.push(syn::parse_quote!(
        #[doc = #view_doc]
    ));
    // Remove `Default` from #[derive(..., Default, ...)] or #[derive(Default)] because we implement `Default` inside macro
    // TODO: also add info with remove proxy
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
                                if path.is_ident("Default") || path.is_ident("Proxy") {
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

pub(crate) fn gen_impl_from(original: &ViewInput, view: &ViewInput) -> proc_macro2::TokenStream {
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
    let field_idents = utils::extract_field_idents(fields);

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

pub(crate) fn gen_impl_default(original: &ViewInput, view: &ViewInput) -> proc_macro2::TokenStream {
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

pub(crate) fn gen_impl_has_view(original: &ViewInput) -> proc_macro2::TokenStream {
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

pub(crate) fn gen_assertions(view: &ViewInput) -> proc_macro2::TokenStream {
    let ViewInput { fields, .. } = view;
    let field_types = utils::extract_field_types(fields);
    let messages: Vec<String> = utils::extract_field_idents(fields)
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

/// Check if [`Field`] has `#[view(ignore)]`
pub(crate) fn is_view_field_ignored(field: &Field) -> bool {
    field
        .attrs
        .iter()
        .map(View::<ViewIgnore>::parse)
        .find_map(Result::ok)
        .is_none()
}

/// Remove attributes with ident [`attr_ident`] from struct attributes and field attributes
pub(crate) fn remove_attr_struct(ast: &mut ViewInput, attr_ident: &str) {
    let ViewInput { attrs, fields, .. } = ast;
    for field in fields {
        utils::remove_attr(&mut field.attrs, attr_ident)
    }
    utils::remove_attr(attrs, attr_ident);
}

/// Change [`Field`] type to `Type` if `#[view(type = Type)]` is present
pub(crate) fn view_field_change_type(field: &mut Field) {
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
