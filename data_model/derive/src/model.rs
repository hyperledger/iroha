use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn2::{parse_quote, Attribute};

pub fn impl_model(emitter: &mut Emitter, input: &syn2::ItemMod) -> TokenStream {
    let syn2::ItemMod {
        attrs,
        vis,
        mod_token,
        ident,
        content,
        semi,
        ..
    } = input;

    let syn2::Visibility::Public(vis_public) = vis else {
        emit!(
            emitter,
            input,
            "The `model` attribute can only be used on public modules"
        );
        return quote!();
    };
    if ident != "model" {
        emit!(
            emitter,
            input,
            "The `model` attribute can only be used on the `model` module"
        );
    }

    let items_code = content.as_ref().map_or_else(Vec::new, |(_, items)| {
        items.iter().cloned().map(process_item).collect()
    });

    quote! {
        #(#attrs)*
        #[allow(missing_docs)]
        #vis_public #mod_token #ident {
            #(#items_code)*
        }#semi
    }
}

pub fn process_item(item: syn2::Item) -> TokenStream {
    let mut input: syn2::DeriveInput = match item {
        syn2::Item::Struct(item_struct) => item_struct.into(),
        syn2::Item::Enum(item_enum) => item_enum.into(),
        syn2::Item::Union(item_union) => item_union.into(),
        other => return other.into_token_stream(),
    };
    let vis = &input.vis;

    if matches!(vis, syn2::Visibility::Public(_)) {
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

fn process_pub_item(input: syn2::DeriveInput) -> TokenStream {
    let (impl_generics, _, where_clause) = input.generics.split_for_impl();

    let attrs = input.attrs;
    let ident = input.ident;

    match input.data {
        syn2::Data::Struct(item) => match &item.fields {
            syn2::Fields::Named(fields) => {
                let fields = fields.named.iter().map(|field| {
                    let field_attrs = &field.attrs;
                    let field_name = &field.ident;
                    let field_ty = &field.ty;

                    if !matches!(field.vis, syn2::Visibility::Public(_)) {
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
            syn2::Fields::Unnamed(fields) => {
                let fields = fields.unnamed.iter().map(|field| {
                    let field_attrs = &field.attrs;
                    let field_ty = &field.ty;

                    if !matches!(field.vis, syn2::Visibility::Public(_)) {
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
            syn2::Fields::Unit => {
                let item = quote! {
                    pub struct #ident #impl_generics #where_clause;
                };

                expose_ffi(attrs, &item)
            }
        },
        syn2::Data::Enum(item) => {
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
        syn2::Data::Union(item) => {
            let fields = item.fields.named.iter().map(|field| {
                let field_attrs = &field.attrs;
                let field_name = &field.ident;
                let field_ty = &field.ty;

                if !matches!(field.vis, syn2::Visibility::Public(_)) {
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

            // See https://github.com/rust-lang/rust-clippy/issues/10417
            #[allow(clippy::arithmetic_side_effects)]
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
    let mut ffi_attrs = attrs
        .iter()
        .filter(|&attr| attr.path().is_ident("ffi_type"));

    if ffi_attrs.next().is_none() {
        return quote! {
            #(#attrs)*
            #item
        };
    }

    attrs.retain(|attr| *attr != parse_quote! (#[ffi_type]));
    let no_ffi_attrs: Vec<_> = attrs
        .iter()
        .filter(|&attr| !attr.path().is_ident("ffi_type"))
        .collect();

    quote! {
        #[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
        #(#no_ffi_attrs)*
        #item

        #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
        #[derive(iroha_ffi::FfiType)]
        #[iroha_ffi::ffi_export]
        #(#attrs)*
        #item

        #[cfg(feature = "ffi_import")]
        iroha_ffi::ffi! {
            #[iroha_ffi::ffi_import]
            #(#attrs)*
            #item
        }
    }
}
