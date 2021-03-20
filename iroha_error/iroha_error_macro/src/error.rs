use proc_macro_error::abort;
use quote::quote;

const SOURCE_ATTR: &str = "source";

fn attrs_have_ident(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs.iter().any(|attr| attr.path.is_ident(ident))
}

pub fn impl_source(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &ast.ident;

    let variants = if let syn::Data::Enum(ref data_enum) = ast.data {
        &data_enum.variants
    } else {
        abort!(ast, "Only enums are supported")
    }
    .iter()
    .map(|variant| {
        let ident = &variant.ident;
        match variant.fields {
            syn::Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 && attrs_have_ident(&fields.unnamed[0].attrs, SOURCE_ATTR) => {
                quote! { Self:: #ident (var) => std::error::Error::source(var) }
            },
            syn::Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                quote! { Self:: #ident (_) => None }
            },
            syn::Fields::Unit => quote! { Self:: #ident => None },

            syn::Fields::Unnamed(_) => abort!(
                variant,
                "Unnamed variant should have exactly one arguments. Check out iroha2 style-guide."
            ),
            syn::Fields::Named(_) => abort!(
                variant,
                "Invalid variant. Named structures inside enum are not supported. Check out iroha2 style-guide."
            ),
        }
    });

    quote! {
        impl std::error::Error for #name {
            fn source(&self) -> std::option::Option<&(dyn std::error::Error + 'static)> {
                match self {
                    #(#variants,)*
                }
            }
        }
    }
}
