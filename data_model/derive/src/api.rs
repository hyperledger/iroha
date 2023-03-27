use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, Attribute};

pub fn process_item(mut input: syn::DeriveInput) -> TokenStream {
    let vis = &input.vis;

    if matches!(vis, syn::Visibility::Public(_)) {
        return process_pub_item(input);
    }

    let non_transparent_item = quote! {
        #[cfg(not(feature = "transparent_api"))]
        #input
    };

    input.vis = parse_quote! {pub};
    let transparent_item = quote! {
        #[cfg(feature = "transparent_api")]
        #input
    };

    quote! {
        #non_transparent_item
        #transparent_item
    }
}

fn process_pub_item(input: syn::DeriveInput) -> TokenStream {
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();

    let attrs = input.attrs;
    let ident = input.ident;

    match input.data {
        syn::Data::Struct(item) => match &item.fields {
            syn::Fields::Named(fields) => {
                let fields = fields.named.iter().map(|field| {
                    let field_attrs = &field.attrs;
                    let field_name = &field.ident;
                    let field_ty = &field.ty;

                    if !matches!(field.vis, syn::Visibility::Public(_)) {
                        return quote! {#field,};
                    }

                    quote! {
                        #[cfg(feature = "transparent_api")]
                        #(#field_attrs)*
                        pub #field_name: #field_ty,

                        #[cfg(not(feature = "transparent_api"))]
                        #(#field_attrs)*
                        pub(crate) #field_name: #field_ty,
                    }
                });

                let item = quote! {
                    pub struct #ident #impl_generics #where_clause {
                        #(#fields)*
                    }
                };

                expose_ffi(attrs, &item)
            }
            syn::Fields::Unnamed(fields) => {
                let fields = fields.unnamed.iter().map(|field| {
                    let field_attrs = &field.attrs;
                    let field_ty = &field.ty;

                    if !matches!(field.vis, syn::Visibility::Public(_)) {
                        return quote! {#field,};
                    }

                    quote! {
                        #[cfg(feature = "transparent_api")]
                        #(#field_attrs)*
                        pub #field_ty,

                        #[cfg(not(feature = "transparent_api"))]
                        #(#field_attrs)*
                        pub(crate) #field_ty,
                    }
                });

                let item = quote! {
                    pub struct #ident #impl_generics( #(#fields)* ) #where_clause;
                };

                expose_ffi(attrs, &item)
            }
            syn::Fields::Unit => {
                let item = quote! {
                    pub struct #ident #impl_generics #where_clause;
                };

                expose_ffi(attrs, &item)
            }
        },
        syn::Data::Enum(item) => {
            let variants = &item.variants;

            let item = quote! {
                pub enum #ident #impl_generics #where_clause {
                    #variants
                }
            };

            expose_ffi(attrs, &item)
        }
        // Triggers in `quote!` side, see https://github.com/rust-lang/rust-clippy/issues/10417
        #[allow(clippy::arithmetic_side_effects)]
        syn::Data::Union(item) => {
            let fields = item.fields.named.iter().map(|field| {
                let field_attrs = &field.attrs;
                let field_name = &field.ident;
                let field_ty = &field.ty;

                if !matches!(field.vis, syn::Visibility::Public(_)) {
                    return quote! {#field,};
                }

                quote! {
                    #(#field_attrs)*
                    #[cfg(feature = "transparent_api")]
                    pub #field_name: #field_ty,

                    #(#field_attrs)*
                    #[cfg(not(feature = "transparent_api"))]
                    pub(crate) #field_name: #field_ty,
                }
            });

            let item = quote! {
                pub union #ident #impl_generics #where_clause {
                    #(#fields),*
                }
            };

            expose_ffi(attrs, &item)
        }
    }
}

fn expose_ffi(mut attrs: Vec<Attribute>, item: &TokenStream) -> TokenStream {
    let mut ffi_attrs = attrs.iter().filter(|&attr| attr.path.is_ident("ffi_type"));

    if ffi_attrs.next().is_none() {
        return quote! {
            #(#attrs)*
            #item
        };
    }

    attrs.retain(|attr| *attr != parse_quote! (#[ffi_type]));
    let no_ffi_attrs: Vec<_> = attrs
        .iter()
        .filter(|&attr| !attr.path.is_ident("ffi_type"))
        .collect();

    quote! {
        #[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
        #(#no_ffi_attrs)*
        #item

        #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
        #[derive(iroha_ffi::FfiType)]
        #(#attrs)*
        #item

        #[cfg(feature = "ffi_import")]
        iroha_ffi::ffi! {
            #(#attrs)*
            #item
        }
    }
}
