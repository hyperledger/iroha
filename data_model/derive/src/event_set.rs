#![allow(unused)]

use darling::{FromDeriveInput, FromVariant};
use iroha_macro_utils::Emitter;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DeriveInput, Variant};

enum FieldsStyle {
    Unit,
    Unnamed,
    Named,
}

/// Converts the `FieldStyle` to an ignoring pattern (to be put after the variant name)
impl ToTokens for FieldsStyle {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            FieldsStyle::Unit => {}
            FieldsStyle::Unnamed => tokens.extend(quote!((..))),
            FieldsStyle::Named => tokens.extend(quote!({ .. })),
        }
    }
}

struct EventSetVariant {
    event_ident: syn::Ident,
    flag_ident: syn::Ident,
    fields_style: FieldsStyle,
}

impl FromVariant for EventSetVariant {
    fn from_variant(variant: &Variant) -> darling::Result<Self> {
        let syn::Variant {
            attrs: _,
            ident: event_ident,
            fields,
            discriminant: _,
        } = variant;

        // a nested event is an event within an event (like `AccountEvent::Asset`, which bears an `AssetEvent`)
        // we detect those by checking whether the payload type (if any) ends with `Event`
        let is_nested = match fields {
            syn::Fields::Unnamed(fields) => {
                fields.unnamed.len() == 1
                    && matches!(&fields.unnamed[0].ty, syn::Type::Path(p) if p.path.segments.last().unwrap().ident.to_string().ends_with("Event"))
            }
            syn::Fields::Unit |
            // just a fail-safe, we don't use named fields in events
            syn::Fields::Named(_) => false,
        };

        // we have a different naming convention for nested events
        // to signify that there are actually multiple types of events inside
        let flag_ident = if is_nested {
            syn::Ident::new(&format!("Any{event_ident}"), event_ident.span())
        } else {
            event_ident.clone()
        };

        let fields_style = match fields {
            syn::Fields::Unnamed(_) => FieldsStyle::Unnamed,
            syn::Fields::Named(_) => FieldsStyle::Named,
            syn::Fields::Unit => FieldsStyle::Unit,
        };

        Ok(Self {
            event_ident: event_ident.clone(),
            flag_ident,
            fields_style,
        })
    }
}

struct EventSetEnum {
    vis: syn::Visibility,
    event_enum_ident: syn::Ident,
    set_ident: syn::Ident,
    variants: Vec<EventSetVariant>,
}

impl FromDeriveInput for EventSetEnum {
    fn from_derive_input(input: &DeriveInput) -> darling::Result<Self> {
        let syn::DeriveInput {
            attrs: _,
            vis,
            ident: event_ident,
            generics,
            data,
        } = &input;

        let mut accumulator = darling::error::Accumulator::default();

        if !generics.params.is_empty() {
            accumulator.push(darling::Error::custom(
                "EventSet cannot be derived on generic enums",
            ));
        }

        let Some(variants) = darling::ast::Data::<EventSetVariant, ()>::try_from(data)?.take_enum()
        else {
            accumulator.push(darling::Error::custom(
                "EventSet can be derived only on enums",
            ));

            return Err(accumulator.finish().unwrap_err());
        };

        if variants.len() > 32 {
            accumulator.push(darling::Error::custom(
                "EventSet can be derived only on enums with up to 32 variants",
            ));
        }

        accumulator.finish_with(Self {
            vis: vis.clone(),
            event_enum_ident: event_ident.clone(),
            set_ident: syn::Ident::new(&format!("{event_ident}Set"), event_ident.span()),
            variants,
        })
    }
}

impl ToTokens for EventSetEnum {
    #[allow(clippy::too_many_lines)] // splitting it is not really feasible, it's all tightly coupled =(
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            vis,
            event_enum_ident,
            set_ident,
            variants,
        } = self;

        let flag_raw_values = variants
            .iter()
            .zip(0u32..)
            .map(|(_, i)| quote!(1 << #i))
            .collect::<Vec<_>>();

        // definitions of consts for each event
        let flag_defs = variants.iter().zip(flag_raw_values.iter()).map(
            |(
                EventSetVariant {
                    flag_ident,
                    event_ident,
                    ..
                },
                raw_value,
            )| {
                let doc = format!(" Matches [`{event_enum_ident}::{event_ident}`]");
                quote! {
                    #[doc = #doc]
                    #vis const #flag_ident: Self = Self(#raw_value);
                }
            },
        );
        // identifiers of all the flag constants to use in impls
        let flag_idents = variants
            .iter()
            .map(|EventSetVariant { flag_ident, .. }| quote!(#set_ident::#flag_ident))
            .collect::<Vec<_>>();
        // names of all the flag (as string literals) to use in debug impl
        let flag_names = variants
            .iter()
            .map(|EventSetVariant { flag_ident, .. }| {
                let flag_name = flag_ident.to_string();
                quote! {
                    #flag_name
                }
            })
            .collect::<Vec<_>>();
        // names of all the flags in `quotes` to use in error message
        let flag_names_str = variants
            .iter()
            .map(|EventSetVariant { flag_ident, .. }| format!("`{flag_ident}`"))
            .collect::<Vec<_>>()
            .join(", ");
        // patterns for matching events in the `matches` method
        let event_patterns = variants.iter().map(
            |EventSetVariant {
                 event_ident,
                 fields_style,
                 ..
             }| {
                quote! {
                    #event_enum_ident::#event_ident #fields_style
                }
            },
        );

        let doc = format!(" An event set for [`{event_enum_ident}`]s\n\nEvent sets of the same type can be combined with a custom `|` operator");

        tokens.extend(quote! {
            #[derive(
                Copy,
                Clone,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Hash,
                // this introduces tight coupling with these crates
                // but it's the easiest way to make sure those traits are implemented
                parity_scale_codec::Decode,
                parity_scale_codec::Encode,
                iroha_schema::TypeId,
            )]
            #[repr(transparent)]
            #[doc = #doc]
            #vis struct #set_ident(u32);

            // we want to imitate an enum here, so not using the SCREAMING_SNAKE_CASE here
            #[allow(non_upper_case_globals)]
            impl #set_ident {
                #( #flag_defs )*
            }

            impl #set_ident {
                /// Creates an empty event set
                pub const fn empty() -> Self {
                    Self(0)
                }

                /// Creates an event set containing all events
                pub const fn all() -> Self {
                    Self(
                        #(
                            #flag_idents.0
                        )|*
                    )
                }

                /// Combines two event sets by computing a union of two sets
                ///
                /// A const method version of the `|` operator
                pub const fn or(self, other: Self) -> Self {
                    Self(self.0 | other.0)
                }

                /// Checks whether an event set is a superset of another event set
                ///
                /// That is, whether `self` will match all events that `other` contains
                const fn contains(&self, other: Self) -> bool {
                    (self.0 & other.0) == other.0
                }

                /// Decomposes an `EventSet` into a vector of basis `EventSet`s, each containing a single event
                ///
                /// Each of the event set in the vector will be equal to some of the associated constants for the `EventSet`
                fn decompose(&self) -> Vec<Self> {
                    let mut result = Vec::new();

                    #(if self.contains(#flag_idents) {
                        result.push(#flag_idents);
                    })*

                    result
                }

                /// Checks whether an event set contains a specific event
                pub const fn matches(&self, event: &#event_enum_ident) -> bool {
                    match event {
                        #(
                            #event_patterns => self.contains(#flag_idents),
                        )*
                    }
                }
            }

            impl core::fmt::Debug for #set_ident {
                fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    write!(f, "{}[", stringify!(#set_ident))?;

                    let mut need_comma = false;

                    #(if self.contains(#flag_idents) {
                        if need_comma {
                            write!(f, ", ")?;
                        } else {
                            need_comma = true;
                        }
                        write!(f, "{}", #flag_names)?
                    })*

                    write!(f, "]")
                }
            }

            impl core::ops::BitOr for #set_ident {
                type Output = Self;

                fn bitor(self, rhs: Self) -> Self {
                    self.or(rhs)
                }
            }

            impl core::ops::BitOrAssign for #set_ident {
                fn bitor_assign(&mut self, rhs: Self) {
                    *self = self.or(rhs);
                }
            }

            impl serde::Serialize for #set_ident {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    use serde::ser::*;

                    let basis = self.decompose();
                    let mut seq = serializer.serialize_seq(Some(basis.len()))?;
                    for event in basis {
                        let str = match event {
                            #(#flag_idents => #flag_names,)*
                            _ => unreachable!(),
                        };

                        seq.serialize_element(&str)?;
                    }
                    seq.end()
                }
            }

            impl<'de> serde::Deserialize<'de> for #set_ident {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    struct Visitor;

                    impl<'de> serde::de::Visitor<'de> for Visitor {
                        type Value = #set_ident;

                        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                            formatter.write_str("a sequence of strings")
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                        where
                            A: serde::de::SeqAccess<'de>,
                        {
                            let mut result = #set_ident::empty();

                            struct SingleEvent(#set_ident);
                            impl<'de> serde::Deserialize<'de> for SingleEvent {
                                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                                where
                                    D: serde::Deserializer<'de>,
                                {
                                    struct Visitor;

                                    impl<'de> serde::de::Visitor<'de> for Visitor {
                                        type Value = SingleEvent;

                                        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                                            formatter.write_str("a string")
                                        }

                                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                                        where
                                            E: serde::de::Error,
                                        {
                                            let event = match v {
                                                #(
                                                    #flag_names => #flag_idents,
                                                )*
                                                _ => return Err(serde::de::Error::custom(format!("unknown event variant `{}`, expected one of {}", v, #flag_names_str))),
                                            };

                                            Ok(SingleEvent(event))
                                        }
                                    }

                                    deserializer.deserialize_str(Visitor)
                                }
                            }
                            while let Some(SingleEvent(event)) = seq.next_element::<SingleEvent>()? {
                                result |= event;
                            }

                            Ok(result)
                        }
                    }

                    deserializer.deserialize_seq(Visitor)
                }
            }


            impl iroha_schema::IntoSchema for #set_ident {
                fn type_name() -> iroha_schema::Ident {
                    <Self as iroha_schema::TypeId>::id()
                }

                fn update_schema_map(metamap: &mut iroha_schema::MetaMap) {
                    if !metamap.contains_key::<Self>() {
                        if !metamap.contains_key::<u32>() {
                            <u32 as iroha_schema::IntoSchema>::update_schema_map(metamap);
                        }
                        metamap.insert::<Self>(iroha_schema::Metadata::Bitmap(iroha_schema::BitmapMeta {
                            repr: core::any::TypeId::of::<u32>(),
                            masks: vec![
                                #(
                                    iroha_schema::BitmapMask {
                                        name: String::from(#flag_names),
                                        mask: #flag_raw_values,
                                    },
                                )*
                            ],
                        }));
                    }
                }
            }
        })
    }
}

pub fn impl_event_set_derive(emitter: &mut Emitter, input: &syn::DeriveInput) -> TokenStream {
    let Some(enum_) = emitter.handle(EventSetEnum::from_derive_input(input)) else {
        return quote! {};
    };

    quote! {
        #enum_
    }
}
