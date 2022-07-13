//! A crate containing various derive macros for `data_model`

#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::eval_order_dependence,
    clippy::unwrap_in_result
)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    token::Brace,
    Attribute, Field, Generics, Ident, Token, TypePath, Variant, Visibility,
};

/// A derive macro for `Identifiable` trait. Currently supports derivations only for
/// `IdBox`, `Event` enums, and structs from the `data_model` crate (with the exception of `NewRole` due
/// to its unconventional trait implementation).
///
/// As such, the macro introduces a new
/// outer attribute `id` for the entities it is derived from. This attribute should
/// be supplied with the associated type to be used in `impl Identifiable`. The type
/// should be supplied as a string literal that constitutes a
/// legal Rust type path.
///
/// Example:
/// ```rust
///
/// // For a struct decorated like this
/// #[derive(Identifiable)]
/// #[id(type = "<Domain as Identifiable>::Id")]
/// pub struct NewDomain {
///    /// The identification associated with the domain builder.
///    id: <Domain as Identifiable>::Id,
///    /// The (IPFS) link to the logo of this domain.
///    logo: Option<IpfsPath>,
///    /// Metadata associated with the domain builder.
///    metadata: Metadata,
/// }
///
/// // The following impl will be derived
/// impl Identifiable for NewDomain {
///    type Id = <Domain as Identifiable>::Id;
///
///    fn id(&self) -> &Self::Id {
///        &self.id
///    }
/// }
/// ```
#[proc_macro_derive(Identifiable, attributes(id))]
pub fn id_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as id::IdInput);
    id::impl_id(&ast)
}

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
    let event = parse_macro_input!(input as filter::EventEnum);
    filter::impl_filter(&event)
}

/// An implementation of `Ord`, `PartialOrd`, `Eq`, `PartialEq` and `Hash` traits that always
/// conforms to the same implementation principles based on ids of the entities.
/// Thus, this derive should only be used for types that also implement
/// `Identifiable`.
#[proc_macro_derive(OrdEqHash)]
pub fn ordeqhash_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input TokenStream.");
    id::impl_ordeqhash(&ast)
}

mod id {
    use super::*;

    pub(super) struct IdInput {
        _attrs: Vec<Attribute>,
        _vis: Visibility,
        _enum_token: Option<Token![enum]>,
        _struct_token: Option<Token![struct]>,
        ident: Ident,
        _generics: Generics,
        _brace_token: Brace,
        _enum_variants: Option<Punctuated<Variant, Token![,]>>,
        struct_fields: Option<Punctuated<Field, Token![,]>>,
        event_variants: Option<Punctuated<filter::EventVariant, Token![,]>>,
        id_type: TypePath,
    }
    impl IdInput {
        fn generate_identifiable_impls_with_event_fields(
            &self,
            id_type: &TypePath,
        ) -> Vec<proc_macro2::TokenStream> {
            self.event_variants
                .as_ref()
                .expect("Should not be called for enums/structs besides `Event`")
                .iter()
                .filter_map(|variant| match variant {
                    filter::EventVariant::IdField(_) => None,
                    filter::EventVariant::EventField {
                        variant: event_variant_ident,
                        ..
                    } => {
                        let inner_event_field_ident = format_ident!(
                            "{}_id",
                            id_type
                                .path
                                .get_ident()
                                .expect("Supplied `id_type` should be an ident convertible type path")
                                .to_string()
                                .strip_suffix("Id")
                                .expect("Associated type for `Event`s should have `Id` suffix")
                                .to_ascii_lowercase()
                        );
                        Some(quote! {
                            Self::#event_variant_ident(event) => &event.id().#inner_event_field_ident
                        })
                    }
                })
                .collect()
        }

        fn generate_identifiable_impls_with_id_fields(&self) -> Vec<proc_macro2::TokenStream> {
            self.event_variants
                .as_ref()
                .expect("Should not be called for enums/structs besides `Event`")
                .iter()
                .filter_map(|variant| match variant {
                    filter::EventVariant::IdField(event_variant_ident) => Some(quote! {
                        Self::#event_variant_ident(id)
                    }),
                    filter::EventVariant::EventField { .. } => None,
                })
                .collect()
        }
    }
    impl Parse for IdInput {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let attrs = input.call(Attribute::parse_outer)?;
            let id_type = parse_id_attribute(&attrs);
            let vis = input.parse::<Visibility>()?;
            if input.peek(Token![struct]) {
                let struct_token = Some(input.parse::<Token![struct]>()?);
                let content;
                Ok(IdInput {
                    _attrs: attrs,
                    _vis: vis,
                    _enum_token: None,
                    _struct_token: struct_token,
                    ident: input.parse()?,
                    _generics: input.parse()?,
                    _brace_token: syn::braced!(content in input),
                    struct_fields: Some(content.parse_terminated(Field::parse_named)?),
                    _enum_variants: None,
                    event_variants: None,
                    id_type,
                })
            } else {
                let enum_token = Some(input.parse::<Token![enum]>()?);
                let ident = input.parse::<Ident>()?;
                let content;
                if ident.to_string().ends_with("Event") {
                    Ok(IdInput {
                        _attrs: attrs,
                        _vis: vis,
                        _enum_token: enum_token,
                        _struct_token: None,
                        ident,
                        _generics: input.parse()?,
                        _brace_token: syn::braced!(content in input),
                        _enum_variants: None,
                        struct_fields: None,
                        event_variants: Some(
                            content.parse_terminated(filter::EventVariant::parse)?,
                        ),
                        id_type,
                    })
                } else {
                    // Box case
                    Ok(IdInput {
                        _attrs: attrs,
                        _vis: vis,
                        _enum_token: enum_token,
                        _struct_token: None,
                        ident,
                        _generics: input.parse()?,
                        _brace_token: syn::braced!(content in input),
                        _enum_variants: Some(content.parse_terminated(syn::Variant::parse)?),
                        struct_fields: None,
                        event_variants: None,
                        id_type,
                    })
                }
            }
        }
    }

    pub(super) fn impl_ordeqhash(ast: &syn::DeriveInput) -> TokenStream {
        let name = ast.ident.clone();

        quote! {
            impl core::cmp::PartialOrd for #name {
                #[inline]
                fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }

            impl core::cmp::Ord for #name {
                fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                    self.id().cmp(other.id())
                }
            }

            impl core::cmp::PartialEq for #name {
                fn eq(&self, other: &Self) -> bool {
                    self.id() == other.id()
                }
            }

            impl core::cmp::Eq for #name {}

            impl core::hash::Hash for #name {
                fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                    self.id().hash(state);
                }
            }
        }
        .into()
    }

    pub(super) fn impl_id(ast: &IdInput) -> TokenStream {
        let id = ast.id_type.clone();
        let name = ast.ident.clone();

        if ast.event_variants.is_some() {
            let event_fields = ast.generate_identifiable_impls_with_event_fields(&ast.id_type);
            let id_fields = ast.generate_identifiable_impls_with_id_fields();

            quote! {
                impl Identifiable for #name {
                    type Id = #id;

                    fn id(&self) -> &Self::Id {
                        match self {
                            #(#id_fields)|* => id,
                            #(#event_fields),*
                        }
                    }
                }
            }
            .into()
        } else if ast.struct_fields.is_some() {
            quote! {
                impl Identifiable for #name {
                    type Id = #id;

                    fn id(&self) -> &Self::Id {
                        &self.id
                    }
                }
            }
            .into()
        } else {
            quote! {
                impl Identifiable for #name {
                    type Id = #id;

                    fn id(&self) -> &Self::Id {
                        self
                    }
                }
            }
            .into()
        }
    }

    fn parse_id_attribute(attrs: &[Attribute]) -> TypePath {
        attrs
            .iter()
            .find_map(|attr| {
                attr.path.is_ident("id").then(|| match attr.parse_meta() {
                    Ok(syn::Meta::List(syn::MetaList { nested, .. })) => {
                        nested.iter().find_map(|m| match m {
                            syn::NestedMeta::Meta(syn::Meta::NameValue(syn::MetaNameValue {
                                lit: syn::Lit::Str(inner),
                                ..
                            })) => {
                                let path =
                                    inner.parse::<syn::TypePath>().expect("Failed parse lit?");
                                Some(path)
                            }
                            _ => None,
                        })
                    }
                    _ => None,
                })
            })
            .flatten()
            .expect("Should provide a valid type as an attribute to derive `Identifiable`")
    }
}

mod filter {
    use super::*;

    pub(super) struct EventEnum {
        _attrs: Vec<Attribute>,
        vis: Visibility,
        _enum_token: Token![enum],
        ident: Ident,
        generics: Generics,
        _brace_token: Brace,
        variants: Punctuated<EventVariant, Token![,]>,
    }

    pub(super) enum EventVariant {
        EventField { variant: Ident, field: Ident },
        IdField(Ident),
    }

    impl EventEnum {
        fn generate_filter_variants_with_event_fields(&self) -> Vec<proc_macro2::TokenStream> {
            self.variants
                .iter()
                .filter_map(|variant| match variant {
                    EventVariant::IdField(_) => None,
                    EventVariant::EventField {
                        variant: variant_ident,
                        field: field_ident,
                    } => {
                        let filter_variant_ident = format_ident!("By{}", variant_ident);
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

        fn generate_filter_variants_with_id_fields(&self) -> Vec<Ident> {
            self.variants
                .iter()
                .filter_map(|variant| match variant {
                    EventVariant::IdField(event_variant_ident) => {
                        let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                        Some(filter_variant_ident)
                    }
                    EventVariant::EventField { .. } => None,
                })
                .collect()
        }

        fn generate_filter_impls_with_event_fields(&self) -> Vec<proc_macro2::TokenStream> {
            self.variants
                .iter()
                .filter_map(|variant| match variant {
                    EventVariant::IdField(_) => None,
                    EventVariant::EventField {
                        variant: event_variant_ident,
                        ..
                    } => {
                        let event_ident = self.ident.clone();
                        let filter_variant_ident = format_ident!("By{}", event_variant_ident);
                        let import_path = quote! {crate::prelude};
                        Some(quote! {
                            (Self::#filter_variant_ident(filter_opt), #import_path::#event_ident::#event_variant_ident(event)) => {
                                filter_opt.matches(event)
                            }})

                    }}).collect()
        }

        fn generate_filter_impls_with_id_fields(&self) -> Vec<proc_macro2::TokenStream> {
            self.variants
                .iter()
                .filter_map(|variant| match variant {
                    EventVariant::IdField(event_variant_ident) => {
                        let event_ident = self.ident.clone();
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
            let content;
            let event = EventEnum {
                _attrs: input.call(Attribute::parse_outer)?,
                vis: input.parse()?,
                _enum_token: input.parse()?,
                ident: input.parse()?,
                generics: input.parse()?,
                _brace_token: syn::braced!(content in input),
                variants: content.parse_terminated(EventVariant::parse)?,
            };
            if event.ident.to_string().ends_with("Event") {
                Ok(event)
            } else {
                Err(syn::Error::new_spanned(
                    event.ident,
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
                Err(syn::Error::new_spanned(field_type, "Wrong type path"))
            }
        }
    }

    pub(super) fn impl_filter(event: &EventEnum) -> TokenStream {
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
        let id_fil = quote! { #import_path::IdFilter };
        let imp_event = quote! { #import_path::#event_ident };

        let filter_doc = format!("{}", filter_ident);
        let new_doc = format!("{}", filter_ident);

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
                id_filter: #fil_opt<#id_fil<<#imp_event as Identifiable>::Id>>,
                event_filter: #fil_opt<#event_filter_ident>
            }

            impl #filter_ident {
                #[doc = #new_doc]
                pub const fn new(
                    id_filter: #fil_opt<#id_fil<<#imp_event as Identifiable>::Id>>,
                    event_filter: #fil_opt<#event_filter_ident>,
                ) -> Self {
                    Self {
                        id_filter,
                        event_filter,
                    }
                }

                /// Get `id_filter`
                #[inline]
                pub const fn id_filter(&self) -> &#fil_opt<#id_fil<<#imp_event as Identifiable>::Id>> {
                    &self.id_filter
                }

                /// Get `event_filter`
                #[inline]
                pub const fn event_filter(&self) -> &#fil_opt<#event_filter_ident> {
                    &self.event_filter
                }
            }

            impl Filter for #filter_ident {
                type EventType = #imp_event;
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
                #(#id_variants),*,
                #(#event_variants),*
            }

            impl Filter for #event_filter_ident {
                type EventType = #imp_event;
                fn matches(&self, event: &#imp_event) -> bool {
                    match (self, event) {
                        #(#id_impls)|* => true,
                        #(#event_impls),*
                        _ => false,
                    }
                }
            }

        }
        .into()
    }
}
