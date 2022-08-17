#![allow(
    clippy::expect_used,
    clippy::mixed_read_write_in_expression,
    clippy::unwrap_in_result,
    clippy::arithmetic
)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Attribute, Generics, Ident, Token, Variant, Visibility,
};

pub struct EventEnum {
    vis: Visibility,
    ident: Ident,
    generics: Generics,
    variants: Punctuated<EventVariant, Token![,]>,
}

pub enum EventVariant {
    EventField { variant: Ident, field: Ident },
    IdField(Ident),
}

impl EventEnum {
    /// Used to produce fields like `ByAccount(crate::prelude::FilterOpt<AccountFilter>)` in `DomainEventFilter`.
    fn generate_filter_variants_with_event_fields(&self) -> Vec<proc_macro2::TokenStream> {
        self.variants
            .iter()
            .filter_map(|variant| match variant {
                EventVariant::IdField(_) => None,
                EventVariant::EventField {
                    variant: variant_ident,
                    field: field_ident,
                } => {
                    // E.g. `Account` field in the event => `ByAccount` in the event filter
                    let filter_variant_ident = format_ident!("By{}", variant_ident);
                    // E.g. `AccountEvent` inner field from `Account` variant in event =>
                    // `AccountFilter` inside the event filter
                    let inner_filter_ident = format_ident!(
                        "{}Filter",
                        field_ident
                            .to_string()
                            .strip_suffix("Event")
                            .expect("Variant name should have suffix `Event`"),
                    );
                    let import_path = quote! {crate::prelude};
                    Some(quote! {
                    #filter_variant_ident(#import_path::FilterOpt<#inner_filter_ident>) })
                }
            })
            .collect()
    }

    /// Used to produce fields like `ByCreated` in `DomainEventFilter`.
    fn generate_filter_variants_with_id_fields(&self) -> Vec<Ident> {
        self.variants
            .iter()
            .filter_map(|variant| match variant {
                EventVariant::IdField(event_variant_ident) => {
                    // Event fields such as `MetadataRemoved` get mapped to `ByMetadataRemoved`
                    let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                    Some(filter_variant_ident)
                }
                EventVariant::EventField { .. } => None,
            })
            .collect()
    }

    /// Match arms for `Filter` impls of event filters of the form
    /// `(Self::ByAccount(filter_opt), crate::prelude::DomainEvent::Account(event)) => {filter_opt.matches(event)}`.
    fn generate_filter_impls_with_event_fields(&self) -> Vec<proc_macro2::TokenStream> {
        self.variants
            .iter()
            .filter_map(|variant| match variant {
                EventVariant::IdField(_) => None,
                EventVariant::EventField {
                    variant: event_variant_ident,
                    ..
                } => {
                    let event_ident = &self.ident;
                    let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                    let import_path = quote! {crate::prelude};
                    Some(quote! {
                        (Self::#filter_variant_ident(filter_opt), #import_path::#event_ident::#event_variant_ident(event)) => {
                            filter_opt.matches(event)
                        }})

                }}).collect()
    }

    /// Match arms for `Filter` impls of event filters of the form
    /// `(Self::ByCreated, crate::prelude::DomainEvent::Created(_))`.
    fn generate_filter_impls_with_id_fields(&self) -> Vec<proc_macro2::TokenStream> {
        self.variants
            .iter()
            .filter_map(|variant| match variant {
                EventVariant::IdField(event_variant_ident) => {
                    let event_ident = &self.ident;
                    let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                    let import_path = quote! {crate::prelude};
                    Some(
                        quote! {
                            (Self::#filter_variant_ident, #import_path::#event_ident::#event_variant_ident(_))
                        })
                },
                EventVariant::EventField { .. } => None,
            })
            .collect()
    }
}

impl Parse for EventEnum {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let _attrs = input.call(Attribute::parse_outer)?;
        let vis = input.parse()?;
        let _enum_token = input.parse::<Token![enum]>()?;
        let ident = input.parse::<Ident>()?;
        let generics = input.parse::<Generics>()?;
        let content;
        let _brace_token = syn::braced!(content in input);
        let variants = content.parse_terminated(EventVariant::parse)?;
        if ident.to_string().ends_with("Event") {
            Ok(EventEnum {
                vis,
                ident,
                generics,
                variants,
            })
        } else {
            Err(syn::Error::new_spanned(
                ident,
                "Bad ident: only derivable for `...Event` enums",
            ))
        }
    }
}

impl Parse for EventVariant {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let variant = input.parse::<Variant>()?;
        let variant_ident = variant.ident;
        let field_type = variant
            .fields
            .into_iter()
            .next()
            .expect("Should have at least one unnamed field")
            .ty;
        if let syn::Type::Path(path) = field_type {
            let field_ident = path
                .path
                .get_ident()
                .expect("Should be an ident-convertible path");

            if field_ident.to_string().ends_with("Event") {
                Ok(EventVariant::EventField {
                    variant: variant_ident,
                    field: field_ident.clone(),
                })
            } else {
                Ok(EventVariant::IdField(variant_ident))
            }
        } else {
            Err(syn::Error::new_spanned(
                field_type,
                "Unexpected AST type variant",
            ))
        }
    }
}

/// Generates the filter for the event. E.g. for `AccountEvent`, `AccountFilter`
/// and its `impl Filter` are generated.
pub fn impl_filter(event: &EventEnum) -> TokenStream {
    let EventEnum {
        vis,
        ident: event_ident,
        generics,
        ..
    } = event;

    let event_filter_and_impl = impl_event_filter(event);

    let filter_ident = format_ident!(
        "{}Filter",
        event_ident
            .to_string()
            .strip_suffix("Event")
            .expect("Events should follow the naming format")
    );
    let event_filter_ident = format_ident!("{}Filter", event_ident);

    let import_path = quote! { crate::prelude };
    let fil_opt = quote! { #import_path::FilterOpt };
    let orig_fil = quote! { #import_path::OriginFilter };
    let imp_event = quote! { #import_path::#event_ident };

    let filter_doc = format!(" Filter for {} entity", event_ident);
    let new_doc = format!(" Construct new {}", filter_ident);

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
            iroha_ffi::FfiType,
            IntoSchema,
            Hash,
        )]
        #[doc = #filter_doc]
        #vis struct #filter_ident #generics {
            origin_filter: #fil_opt<#orig_fil<#imp_event>>,
            event_filter: #fil_opt<#event_filter_ident>
        }

        impl #filter_ident {
            #[doc = #new_doc]
            pub const fn new(
                origin_filter: #fil_opt<#orig_fil<#imp_event>>,
                event_filter: #fil_opt<#event_filter_ident>,
            ) -> Self {
                Self {
                    origin_filter,
                    event_filter,
                }
            }

            /// Get `origin_filter`
            #[inline]
            pub const fn origin_filter(&self) -> &#fil_opt<#orig_fil<#imp_event>> {
                &self.origin_filter
            }

            /// Get `event_filter`
            #[inline]
            pub const fn event_filter(&self) -> &#fil_opt<#event_filter_ident> {
                &self.event_filter
            }
        }

        impl #import_path::Filter for #filter_ident {
            type Event = #imp_event;
            fn matches(&self, event: &Self::Event) -> bool {
                self.origin_filter.matches(event) && self.event_filter.matches(event)
            }
        }

        #event_filter_and_impl
    }
    .into()
}

/// Generates the event filter for the event. E.g. for `AccountEvent`, `AccountEventFilter`
/// and its `impl Filter` are generated.
fn impl_event_filter(event: &EventEnum) -> proc_macro2::TokenStream {
    let EventEnum {
        vis,
        ident: event_ident,
        generics,
        ..
    } = event;

    let id_variants = event.generate_filter_variants_with_id_fields();
    let event_variants = event.generate_filter_variants_with_event_fields();

    let id_impls = event.generate_filter_impls_with_id_fields();
    let event_impls = event.generate_filter_impls_with_event_fields();

    let event_filter_ident = format_ident!("{}Filter", event_ident);
    let import_path = quote! { crate::prelude };
    let imp_event = quote! { #import_path::#event_ident };

    let event_filter_doc = format!(" Event filter for {} entity", event_ident);

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
        #[allow(clippy::enum_variant_names, missing_docs)]
        #[doc = #event_filter_doc]
        #vis enum #event_filter_ident #generics {
            #(#id_variants),*,
            #(#event_variants),*
        }

        impl #import_path::Filter for #event_filter_ident {
            type Event = #imp_event;

            fn matches(&self, event: &#imp_event) -> bool {
                match (self, event) {
                    #(#id_impls)|* => true,
                    #(#event_impls),*
                    _ => false,
                }
            }
        }
    }
}
