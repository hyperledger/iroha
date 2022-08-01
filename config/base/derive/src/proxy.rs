use proc_macro::TokenStream;
use proc_macro_error::abort;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote, Attribute, Data, DataStruct, DeriveInput, Field, Fields, Ident, Token, Type,
};

use super::{config, utils};

// Take struct with named fields as input
#[derive(Debug, Clone)]
struct ProxyInput {
    attrs: Vec<Attribute>,
    vis: syn::Visibility,
    _struct_token: Token![struct],
    ident: Ident,
    generics: syn::Generics,
    fields: Vec<Field>,
    _semi_token: Option<Token![;]>,
}

impl Parse for ProxyInput {
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
impl ProxyInput {}

pub(super) fn impl_proxy(ast: &DeriveInput) -> TokenStream {
    let DeriveInput {
        attrs,
        vis,
        ident: parent_name,
        generics,
        data,
    } = ast;

    let prefix = ast
        .attrs
        .iter()
        .find_map(|attr| attr.parse_args::<config::EnvPrefix>().ok())
        .map(|pref| pref.prefix.value())
        .unwrap_or_default();

    let proxy_name = format_ident!("{}Proxy", parent_name);

    let fields = if let Data::Struct(DataStruct {
        fields: Fields::Named(fields),
        ..
    }) = &data
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
    // dbg!(&field_idents);
    let field_attrs = fields
        .iter()
        .map(|field| field.attrs.as_slice())
        .collect::<Vec<_>>();
    let field_ty = fields
        .iter()
        .map(|field| field.ty.clone())
        .collect::<Vec<_>>();

    let inner = utils::field_has_inner_attr(&field_attrs);

    let field_environment = field_idents
        .iter()
        .map(|ident| prefix.clone() + &ident.to_string().to_uppercase())
        .collect::<Vec<_>>();

    let lvalue = field_ty
        .iter()
        .map(utils::is_arc_rwlock)
        .zip(field_idents.iter());

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

    let as_str = field_attrs
        .iter()
        .map(|attrs| {
            attrs
                .iter()
                .any(|attr| attr.parse_args::<config::SerdeAsStr>().is_ok())
        })
        .collect::<Vec<_>>();

    println!("GETTING PROXY LOADENV");
    // dbg!(&field_ty);
    // dbg!(&field_idents);
    let proxy_ty = field_ty
        .iter()
        .map(|ty| {
            let new_ty: Type = parse_quote! {
                // #(#attrs)*
                Option<#ty>
            };
            new_ty
        })
        .collect::<Vec<_>>();

    // let load_env_fn = config::impl_load_env(
    //     &field_idents,
    //     &inner,
    //     &lvalue_write,
    //     &as_str,
    //     &proxy_ty,
    //     &field_environment,
    // );

    let proxy_fields = gen_proxy_struct_fields(&field_idents, &field_attrs, &field_ty);
    let build_fn = impl_build(&field_idents, &field_attrs);

    quote! {
        // #[derive(Debug, Clone, Serialize, Deserialize)]
        // // #(#attrs)*
        // #vis struct #proxy_name #generics {
        //     #proxy_fields
        // }
        // impl iroha_config_base::proxy::Combine for #proxy_name {
        //     type Target = #parent_name;
        //     #load_env_fn
        //     #build_fn

        // }
    }
    .into()
}

fn impl_build(field_idents: &[&Ident], field_attrs: &[&[Attribute]]) -> proc_macro2::TokenStream {
    let checked_fields = gen_none_fields_check(field_idents, field_attrs);

    quote! {
        fn build(self) -> Result<Self::Target, iroha_config_base::derive::Error> {
            Ok(Self::Target {
                #checked_fields
            })
        }
    }
}

fn gen_proxy_struct_fields(
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
    field_ty: &[Type],
) -> proc_macro2::TokenStream {
    let combined_fields = field_idents
        .iter()
        .zip(field_attrs.iter())
        .zip(field_ty.iter())
        .map(|((ident, attrs), ty)| {
            if utils::is_option_type(ty) {
                quote! { #ident: #ty }
            } else {
                quote! {
                    // #(#attrs)*
                    #ident: Option<#ty>
                }
            }
        });
    quote! {
        #(#combined_fields),*
    }
}

/// Helper function for checking inner
fn gen_none_fields_check(
    field_idents: &[&Ident],
    field_attrs: &[&[Attribute]],
) -> proc_macro2::TokenStream {
    let checked_fields = field_idents
        .iter()
        .zip(field_attrs.iter())
        .map(|(ident, attrs)| {
            quote! {
                // #(#attrs)*
                #ident: self.#ident.ok_or(iroha_config_base::derive::Error::ProxyError(ident.to_string()))?
            }
        });
    quote! {
        #(#checked_fields),*
    }
}
