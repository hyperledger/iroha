#![allow(clippy::str_to_string, clippy::mixed_read_write_in_expression)]

use manyhow::{bail, Result};
use proc_macro2::TokenStream;
use quote::quote;
use syn2::parse_quote;

pub fn impl_id(input: &syn2::ItemStruct) -> Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let identifiable_derive = derive_identifiable(input)?;

    Ok(quote! {
        #identifiable_derive

        impl #impl_generics ::core::cmp::PartialOrd for #name #ty_generics #where_clause where Self: Identifiable {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl #impl_generics ::core::cmp::Ord for #name #ty_generics #where_clause where Self: Identifiable {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                self.id().cmp(other.id())
            }
        }

        impl #impl_generics ::core::cmp::Eq for #name #ty_generics #where_clause where Self: Identifiable  {}
        impl #impl_generics ::core::cmp::PartialEq for #name #ty_generics #where_clause  where Self: Identifiable {
            fn eq(&self, other: &Self) -> bool {
                self.id() == other.id()
            }
        }

        impl #impl_generics ::core::hash::Hash for #name #ty_generics #where_clause  where Self: Identifiable {
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                self.id().hash(state);
            }
        }
    })
}

fn derive_identifiable(input: &syn2::ItemStruct) -> Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let (id_type, id_expr) = get_id_type(input)?;

    Ok(quote! {
        impl #impl_generics Identifiable for #name #ty_generics #where_clause {
            type Id = #id_type;

            #[inline]
            fn id(&self) -> &Self::Id {
                #id_expr
            }
        }
    })
}

fn get_id_type(input: &syn2::ItemStruct) -> Result<(TokenStream, TokenStream)> {
    match &input.fields {
        syn2::Fields::Named(fields) => {
            for field in &fields.named {
                let (field_name, field_ty) = (&field.ident, &field.ty);

                if is_identifier(&field.attrs) {
                    return Ok((quote! {#field_ty}, quote! {&self.#field_name}));
                }
                if is_transparent(&field.attrs) {
                    return Ok((
                        quote! {<#field_ty as Identifiable>::Id},
                        quote! {Identifiable::id(&self.#field_name)},
                    ));
                }
            }
        }
        syn2::Fields::Unnamed(fields) => {
            for (i, field) in fields.unnamed.iter().enumerate() {
                let (field_id, field_ty): (syn2::Index, _) = (i.into(), &field.ty);

                if is_identifier(&field.attrs) {
                    return Ok((quote! {#field_ty}, quote! {&self.#field_id}));
                }
                if is_transparent(&field.attrs) {
                    return Ok((
                        quote! {<#field_ty as Identifiable>::Id},
                        quote! {Identifiable::id(&self.#field_id)},
                    ));
                }
            }
        }
        syn2::Fields::Unit => {}
    }

    match &input.fields {
        syn2::Fields::Named(named) => {
            for field in &named.named {
                let field_ty = &field.ty;

                if field.ident.as_ref().expect("Field must be named") == "id" {
                    return Ok((quote! {#field_ty}, quote! {&self.id}));
                }
            }
        }
        syn2::Fields::Unnamed(_) | syn2::Fields::Unit => {}
    }

    bail!(input, "Identifier not found")
}

fn is_identifier(attrs: &[syn2::Attribute]) -> bool {
    attrs.iter().any(|attr| attr == &parse_quote! {#[id]})
}

fn is_transparent(attrs: &[syn2::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr == &parse_quote! {#[id(transparent)]})
}
