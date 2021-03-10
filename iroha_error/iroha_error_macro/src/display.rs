extern crate proc_macro;

use proc_macro_error::abort;
use quote::quote;

fn get_attr_str(attrs: &[syn::Attribute]) -> Option<syn::LitStr> {
    attrs
        .iter()
        .filter(|attr| attr.path.is_ident("error"))
        .filter_map(|attr| match attr.parse_meta().ok()? {
            syn::Meta::List(syn::MetaList { ref nested, .. }) if nested.len() == 1 => {
                Some(nested[0].clone())
            }
            syn::Meta::List(list) => {
                abort!(list, "error attribute should have only 1 argument string")
            }
            _ => abort!(attr, "Only function like attributes supported"),
        })
        .map(|nested_meta| match nested_meta {
            syn::NestedMeta::Lit(syn::Lit::Str(s)) => s,
            _ => abort!(nested_meta, "Argument for error attribute should be string"),
        })
        .next()
}

pub fn impl_fmt(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &ast.ident;

    let variants = if let syn::Data::Enum(ref data_enum) = ast.data {
        &data_enum.variants
    } else {
        abort!(ast, "Only enums are supported")
    }
    .iter()
    .map(|variant| {
        let fmt = get_attr_str(&variant.attrs)
            .expect("Enum variants should have error attribute with display format");
        match variant.fields {
            syn::Fields::Unnamed(_) => (&variant.ident, true, fmt),
            syn::Fields::Unit => (&variant.ident, false, fmt),
            syn::Fields::Named(_) => abort!(
                variant,
                "Invalid variant. Only unnamed fields supported or units. Check out iroha2 style-guide"
            ),
        }
    })
    .map(|(variant, field, fmt)| {
        if field {
            quote! { Self:: #variant (_) => write!(f, #fmt) }
        } else {
            quote! { Self:: #variant => write!(f, #fmt) }
        }
    });

    quote! {
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
                match self {
                    #(#variants,)*
                }
            }
        }
    }
}
