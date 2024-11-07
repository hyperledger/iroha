use darling::{FromAttributes, FromDeriveInput, FromField};
use iroha_macro_utils::{find_single_attr_opt, Emitter};
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse_quote;

mod kw {
    syn::custom_keyword!(transparent);
}

enum IdAttr {
    Missing,
    Normal,
    Transparent,
}

impl FromAttributes for IdAttr {
    fn from_attributes(attrs: &[syn::Attribute]) -> darling::Result<Self> {
        let mut accumulator = darling::error::Accumulator::default();
        let Some(attr) = find_single_attr_opt(&mut accumulator, "id", attrs) else {
            return accumulator.finish_with(IdAttr::Missing);
        };

        let result = match &attr.meta {
            syn::Meta::Path(_) => IdAttr::Normal,
            syn::Meta::List(list) if list.parse_args::<kw::transparent>().is_ok() => {
                IdAttr::Transparent
            }
            _ => {
                accumulator.push(
                    darling::Error::custom("Expected `#[id]` or `#[id(transparent)]`")
                        .with_span(&attr),
                );
                IdAttr::Normal
            }
        };

        accumulator.finish_with(result)
    }
}

#[derive(FromDeriveInput)]
#[darling(supports(struct_any))]
struct IdDeriveInput {
    ident: syn::Ident,
    generics: syn::Generics,
    data: darling::ast::Data<darling::util::Ignored, IdField>,
}

struct IdField {
    ident: Option<syn::Ident>,
    ty: syn::Type,
    id_attr: IdAttr,
}

impl FromField for IdField {
    fn from_field(field: &syn::Field) -> darling::Result<Self> {
        let ident = field.ident.clone();
        let ty = field.ty.clone();
        let id_attr = IdAttr::from_attributes(&field.attrs)?;

        Ok(Self { ident, ty, id_attr })
    }
}

impl IdDeriveInput {
    fn fields(&self) -> &darling::ast::Fields<IdField> {
        match &self.data {
            darling::ast::Data::Struct(fields) => fields,
            _ => unreachable!(),
        }
    }
}

pub fn impl_id_eq_ord_hash(emitter: &mut Emitter, input: &syn::DeriveInput) -> TokenStream {
    let Some(input) = emitter.handle(IdDeriveInput::from_derive_input(input)) else {
        return quote!();
    };

    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let identifiable_derive = derive_identifiable(emitter, &input);

    quote! {
        #identifiable_derive

        impl #impl_generics ::core::cmp::PartialOrd for #name #ty_generics #where_clause where Self: Identifiable {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl #impl_generics ::core::cmp::Ord for #name #ty_generics #where_clause where Self: Identifiable {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                <Self as Identifiable>::id(self).cmp(<Self as Identifiable>::id(other))
            }
        }

        impl #impl_generics ::core::cmp::Eq for #name #ty_generics #where_clause where Self: Identifiable  {}
        impl #impl_generics ::core::cmp::PartialEq for #name #ty_generics #where_clause  where Self: Identifiable {
            fn eq(&self, other: &Self) -> bool {
                <Self as Identifiable>::id(self) == <Self as Identifiable>::id(other)
            }
        }

        impl #impl_generics ::core::hash::Hash for #name #ty_generics #where_clause  where Self: Identifiable {
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                <Self as Identifiable>::id(self).hash(state)
            }
        }

        impl #impl_generics core::borrow::Borrow<<Self as Identifiable>::Id> for #name #ty_generics #where_clause where Self: Identifiable {
            fn borrow(&self) -> &<Self as Identifiable>::Id {
                <Self as Identifiable>::id(self)
            }
        }
    }
}

fn derive_identifiable(emitter: &mut Emitter, input: &IdDeriveInput) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let (id_type, id_expr) = get_id_type(emitter, input);

    quote! {
        impl #impl_generics Identifiable for #name #ty_generics #where_clause {
            type Id = #id_type;

            #[inline]
            fn id(&self) -> &Self::Id {
                #id_expr
            }
        }
    }
}

fn get_id_type(emitter: &mut Emitter, input: &IdDeriveInput) -> (syn::Type, syn::Expr) {
    for (field_index, IdField { ty, ident, id_attr }) in input.fields().iter().enumerate() {
        let field_name = ident.as_ref().map_or_else(
            || syn::Index::from(field_index).to_token_stream(),
            ToTokens::to_token_stream,
        );
        match id_attr {
            IdAttr::Normal => {
                return (ty.clone(), parse_quote! {&self.#field_name});
            }
            IdAttr::Transparent => {
                return (
                    parse_quote! {<#ty as Identifiable>::Id},
                    parse_quote! {Identifiable::id(&self.#field_name)},
                );
            }
            IdAttr::Missing => {
                // nothing here
            }
        }
    }

    for field in input.fields().iter() {
        if field.ident.as_ref().is_some_and(|i| i == "id") {
            return (field.ty.clone(), parse_quote! {&self.id});
        }
    }

    emit!(
        emitter,
        "Could not find the identifier field. Either mark it with `#[id]` or have it named `id`"
    );

    // return dummy types
    (parse_quote! {()}, parse_quote! {()})
}
