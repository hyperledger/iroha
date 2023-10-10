#![allow(
    clippy::mixed_read_write_in_expression,
    clippy::arithmetic_side_effects
)]

use darling::{FromDeriveInput, FromVariant};
use iroha_macro_utils::Emitter;
use manyhow::emit;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn2::{Generics, Ident, Variant, Visibility};

#[derive(FromDeriveInput)]
#[darling(supports(enum_tuple))]
struct EventEnum {
    vis: Visibility,
    ident: Ident,
    generics: Generics,
    data: darling::ast::Data<EventVariant, darling::util::Ignored>,
}

enum EventVariant {
    /// A variant of event that delegates to some other event. Identified by conventional naming of the event types: ending with `Event`.
    /// Delegates all the filterting to the corresponding event's filter.
    Delegating {
        variant_name: Ident,
        /// A name of the event this variant delegates to, without the the `Event` suffix
        delegated_event_name_base: String,
    },
    /// An actual event. Has either an Id or an identifiable object as a payload
    /// The presense of the Id field is not required by this macro per se, but will be enfored by `OriginFilter` requiring a `HasOrigin` impl.
    Direct(Ident),
}

impl FromVariant for EventVariant {
    fn from_variant(variant: &Variant) -> darling::Result<Self> {
        let syn2::Fields::Unnamed(fields) = &variant.fields else {
            return Err(
                darling::Error::custom("Expected an enum with unnamed fields")
                    .with_span(&variant.fields),
            );
        };
        // note: actually, we have only one field in the event variants
        // this is not enforced by this macro, but by `IntoSchema`
        let Some(first_field_ty) = fields.unnamed.first().map(|v| &v.ty) else {
            return Err(darling::Error::custom("Expected at least one field").with_span(&fields));
        };
        let syn2::Type::Path(path) = first_field_ty else {
            return Err(
                darling::Error::custom("Only identifiers supported as event types")
                    .with_span(first_field_ty),
            );
        };
        let Some(first_field_ty_name) = path.path.get_ident() else {
            return Err(
                darling::Error::custom("Only identifiers supported as event types")
                    .with_span(first_field_ty),
            );
        };

        // What clippy suggests is much less readable in this case
        #[allow(clippy::option_if_let_else)]
        if let Some(delegated_event_name_base) =
            first_field_ty_name.to_string().strip_suffix("Event")
        {
            Ok(EventVariant::Delegating {
                variant_name: variant.ident.clone(),
                delegated_event_name_base: delegated_event_name_base.to_string(),
            })
        } else {
            Ok(EventVariant::Direct(variant.ident.clone()))
        }
    }
}

impl EventEnum {
    fn variants(&self) -> &[EventVariant] {
        match &self.data {
            darling::ast::Data::Enum(variants) => variants,
            _ => unreachable!("BUG: only enums should be here"),
        }
    }

    fn filter_map_variants<T, F: Fn(&EventVariant) -> Option<T>>(&self, fun: F) -> Vec<T> {
        self.variants().iter().filter_map(fun).collect()
    }

    /// Used to produce fields like `ByAccount(crate::prelude::FilterOpt<AccountFilter>)` in `DomainEventFilter`.
    fn generate_filter_variants_for_delegating_events(&self) -> Vec<TokenStream> {
        self.filter_map_variants(|variant| {
            if let EventVariant::Delegating {
                variant_name,
                delegated_event_name_base,
            } = variant
            {
                // E.g. `Account` field in the event => `ByAccount` in the event filter
                let filter_variant_ident = format_ident!("By{}", variant_name);
                // E.g. `AccountEvent` inner field from `Account` variant in event =>
                // `AccountFilter` inside the event filter
                let inner_filter_ident = format_ident!("{}Filter", delegated_event_name_base);
                let import_path = quote! {crate::prelude};
                Some(quote! {
                    #filter_variant_ident(#import_path::FilterOpt<#inner_filter_ident>)
                })
            } else {
                None
            }
        })
    }

    /// Used to produce fields like `ByCreated` in `DomainEventFilter`.
    fn generate_filter_variants_for_direct_events(&self) -> Vec<Ident> {
        self.filter_map_variants(|variant| {
            if let EventVariant::Direct(event_variant_ident) = variant {
                // Event fields such as `MetadataRemoved` get mapped to `ByMetadataRemoved`
                let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                Some(filter_variant_ident)
            } else {
                None
            }
        })
    }

    /// Match arms for `Filter` impls of event filters of the form
    /// `(Self::ByAccount(filter_opt), crate::prelude::DomainEvent::Account(event)) => {filter_opt.matches(event)}`.
    fn generate_filter_arms_for_delegating_events(&self) -> Vec<TokenStream> {
        self.filter_map_variants(|variant| {
            if let EventVariant::Delegating { variant_name, .. } = variant {
                let event_ident = &self.ident;
                let filter_variant_ident = format_ident!("By{}", variant_name);
                let import_path = quote! {crate::prelude};
                Some(quote! {
                    (
                        Self::#filter_variant_ident(filter_opt),
                        #import_path::#event_ident::#variant_name(event)
                    ) => {
                        filter_opt.matches(event)
                    }
                })
            } else {
                None
            }
        })
    }

    /// Match arms for `Filter` impls of event filters of the form
    /// `(Self::ByCreated, crate::prelude::DomainEvent::Created(_))`.
    fn generate_filter_patterns_for_direct_events(&self) -> Vec<proc_macro2::TokenStream> {
        self.filter_map_variants(|variant| {
            if let EventVariant::Direct(event_variant_ident) = variant {
                let event_ident = &self.ident;
                let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                let import_path = quote! {crate::prelude};
                Some(quote! {
                    (
                        Self::#filter_variant_ident,
                        #import_path::#event_ident::#event_variant_ident(_)
                    )
                })
            } else {
                None
            }
        })
    }
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

    let id_variants = event.generate_filter_variants_for_direct_events();
    let event_variants = event.generate_filter_variants_for_delegating_events();

    let id_patterns = event.generate_filter_patterns_for_direct_events();
    let event_arms = event.generate_filter_arms_for_delegating_events();

    let event_filter_ident = format_ident!("{}Filter", event_ident);
    let import_path = quote! { crate::prelude };
    let imp_event = quote! { #import_path::#event_ident };

    let event_filter_doc = format!(" Event filter for {event_ident} entity");

    quote! {
        iroha_data_model_derive::model_single! {
            #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
            #[allow(clippy::enum_variant_names, missing_docs)]
            #[doc = #event_filter_doc]
            #vis enum #event_filter_ident #generics {
                #(#id_variants),*,
                #(#event_variants),*
            }
        }

        #[cfg(feature = "transparent_api")]
        impl #import_path::Filter for #event_filter_ident {
            type Event = #imp_event;

            fn matches(&self, event: &#imp_event) -> bool {
                match (self, event) {
                    #(#id_patterns)|* => true,
                    #(#event_arms),*
                    _ => false,
                }
            }
        }
    }
}

/// Generates the filter for the event. E.g. for `AccountEvent`, `AccountFilter`
/// and its `impl Filter` are generated.
pub fn impl_filter(emitter: &mut Emitter, input: &syn2::DeriveInput) -> TokenStream {
    let Some(event) = emitter.handle(EventEnum::from_derive_input(input)) else {
        return quote!();
    };

    let EventEnum {
        vis,
        ident: event_ident,
        generics,
        ..
    } = &event;

    let event_filter_and_impl = impl_event_filter(&event);

    let event_base = event_ident.to_string().strip_suffix("Event").map_or_else(
        || {
            emit!(emitter, event_ident, "Event name should end with `Event`");
            event_ident.to_string()
        },
        ToString::to_string,
    );

    let filter_ident = format_ident!("{}Filter", event_base);
    let event_filter_ident = format_ident!("{}Filter", event_ident);

    let import_path = quote! { crate::prelude };
    let fil_opt = quote! { #import_path::FilterOpt };
    let orig_fil = quote! { #import_path::OriginFilter };
    let imp_event = quote! { #import_path::#event_ident };

    let filter_doc = format!(" Filter for {event_ident} entity");

    quote! {
        iroha_data_model_derive::model_single! {
            #[derive(Debug, Clone, PartialEq, Eq, derive_more::Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
            #[doc = #filter_doc]
            #vis struct #filter_ident #generics {
                origin_filter: #fil_opt<#orig_fil<#imp_event>>,
                event_filter: #fil_opt<#event_filter_ident>
            }
        }

        #[cfg(feature = "transparent_api")]
        impl #import_path::Filter for #filter_ident {
            type Event = #imp_event;

            fn matches(&self, event: &Self::Event) -> bool {
                self.origin_filter.matches(event) && self.event_filter.matches(event)
            }
        }

        #event_filter_and_impl
    }
}
