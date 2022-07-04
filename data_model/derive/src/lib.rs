//! Crate with `Filter` and `EventFilter` derive macro
#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};

/// [`Filter`] is used for code generation of `...Filter` structs and `...EventFilter` enums, as well as
/// implementing the `Filter` trait for both of them.
/// This macro should only be attributed to `Event` enums. E.g. if the event is called `AccountEvent`,
/// then the macro will produce `AccountEventFilter` and `AccountFilter`. The latter will have `new` and
/// field getters defined, and both will have their respective `Filter` trait impls generated.
/// Due to name scoping, the macro currently properly
/// expands only from within the `iroha_data_model` crate as it relies on a few of `crate::prelude`
/// imports. This macro also depends on the naming conventions adopted so far, such as that
/// `Event` enums always have tuple variants with either some sort of `Id` or another `Event` inside
/// of them, as well as that all `Event` inner fields precede `Id` fields in the enum definition.
#[proc_macro_derive(Filter)]
pub fn filter_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input TokenStream.");
    impl_from_filter(&ast)
}

fn impl_from_filter(ast: &syn::DeriveInput) -> TokenStream {
    // Omitting attributes as they don't need to be inherited for filters
    let syn::DeriveInput {
        vis,
        ident: event_ident,
        generics,
        data,
        ..
    } = ast;

    let event_filter_ident = format_ident!("{}Filter", event_ident);

    let filter_ident = format_ident!(
        "{}Filter",
        event_ident
            .to_string()
            .strip_suffix("Event")
            .expect("Events should follow the naming format")
    );

    let event_variants = if let syn::Data::Enum(syn::DataEnum { variants, .. }) = data {
        variants.iter().collect::<Vec<_>>()
    } else {
        panic!("Only `...Event` enums are supported")
    };

    let mut filter_variants_idents_id_fields = Vec::<syn::Ident>::new();
    let mut filter_variants_idents_event_fields = Vec::<syn::Ident>::new();

    let import_path = quote! { crate::prelude };

    let filter_variants_event_fields = event_variants
        .iter()
        .filter_map(|variant| {
            let event_filter_variant_ident = format_ident!("By{}", variant.ident);
            if let syn::Fields::Unnamed(ref unnamed) = variant.fields {
                let variant_type = &unnamed
                    .unnamed
                    .first()
                    .expect("Should have at least one type")
                    .ty;
                process_event_variant(
                    variant_type,
                    &event_filter_variant_ident,
                    &mut filter_variants_idents_id_fields,
                    &mut filter_variants_idents_event_fields,
                )
                .map(|inner_filter_ident| {
                    Some(quote! {
                        #event_filter_variant_ident (#import_path::FilterOpt<#inner_filter_ident>)
                    })
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let filter_impl_variant_pairs_event_fields = filter_variants_idents_event_fields
        .iter()
        .zip(event_variants.iter())
        .map(|(filter_variant_ident, event_var)| {
            let event_var_ident = event_var.ident.clone();
            quote! {
                (Self::#filter_variant_ident(filter_opt), #import_path::#event_ident::#event_var_ident(event)) => {
                    filter_opt.matches(event)
                }
            }
        })
        .collect::<Vec<_>>();

    let filter_impl_variant_pairs_id_fields = filter_variants_idents_id_fields
        .iter()
        .zip(
            event_variants
                .iter()
                .skip(filter_impl_variant_pairs_event_fields.len()),
        )
        .map(|(filter_var, event_var)| {
            let event_var_ident = format_ident!("{}", &event_var.ident);
            quote! {
                (Self::#filter_var, #import_path::#event_ident::#event_var_ident (_))
            }
        })
        .collect::<Vec<_>>();

    let filter_doc = format!("Filter for {} entity", filter_ident);
    let new_doc = format!("Construct new {}", filter_ident);

    quote! {
        #[derive(
            Clone,
            PartialEq,
            PartialOrd,
            Ord,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        #[doc = #filter_doc]
        #vis struct #filter_ident #generics {
            id_filter: #import_path::FilterOpt<#import_path::IdFilter<<#import_path::#event_ident as Identifiable>::Id>>,
            event_filter: #import_path::FilterOpt<#event_filter_ident>
        }

        impl #filter_ident {
            #[doc = #new_doc]
            pub const fn new(
                id_filter: #import_path::FilterOpt<#import_path::IdFilter<<#import_path::#event_ident as Identifiable>::Id>>,
                event_filter: #import_path::FilterOpt<#event_filter_ident>,
            ) -> Self {
                Self {
                    id_filter,
                    event_filter,
                }
            }

            /// Get `id_filter`
            #[inline]
            pub const fn id_filter(&self) -> &#import_path::FilterOpt<#import_path::IdFilter<<#import_path::#event_ident as Identifiable>::Id>> {
                &self.id_filter
            }

            /// Get `event_filter`
            #[inline]
            pub const fn event_filter(&self) -> &#import_path::FilterOpt<#event_filter_ident> {
                &self.event_filter
            }
        }

        impl Filter for #filter_ident {
            type EventType = #import_path::#event_ident;
            fn matches(&self, entity: &Self::EventType) -> bool {
                self.id_filter.matches(entity.id()) && self.event_filter.matches(entity)
            }
        }

        #[derive(
            Clone,
            PartialEq,
            PartialOrd,
            Ord,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        #[allow(clippy::enum_variant_names, missing_docs)]
        #vis enum #event_filter_ident #generics {
            #(#filter_variants_idents_id_fields),*,
            #(#filter_variants_event_fields),*
        }

        impl Filter for #event_filter_ident {
            type EventType = #import_path::#event_ident;
            fn matches(&self, event: &#import_path::#event_ident) -> bool {
                match (self, event) {
                    #(#filter_impl_variant_pairs_id_fields)|* => true,
                    #(#filter_impl_variant_pairs_event_fields),*
                    _ => false,
                }
            }
        }

    }
    .into()
}

fn process_event_variant(
    variant_type: &syn::Type,
    event_filter_variant_ident: &syn::Ident,
    variants_with_id_fields: &mut Vec<syn::Ident>,
    variants_with_event_fields: &mut Vec<syn::Ident>,
) -> Option<syn::Ident> {
    if let syn::Type::Path(path) = variant_type {
        let var_ty_ident = &path.path.segments[0].ident;

        var_ty_ident
            .to_string()
            .ends_with("Event")
            .then(|| {
                variants_with_event_fields.push(event_filter_variant_ident.clone());
                format_ident!(
                    "{}Filter",
                    var_ty_ident
                        .to_string()
                        .strip_suffix("Event")
                        .expect("Variant name should have suffix `Event`"),
                )
            })
            .or_else(|| {
                variants_with_id_fields.push(event_filter_variant_ident.clone());
                None
            })
    } else {
        None
    }
}
