use crate::{EmitterExt, utils::darling_result};
use darling::{FromDeriveInput, FromVariant};
use manyhow::Emitter;
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{DeriveInput, LitStr, Variant};
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
        // A nested event is an event within an event (for example `DomainEvent::Nft`).
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
    schema_name: LitStr,
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
        let schema_name =
            crate::utils::required_child_schema_name(input, "event_set", "EventSet", "event set")
                .map_err(darling::Error::from)?;
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
        if variants.len() > 64 {
            accumulator.push(darling::Error::custom(
                "EventSet can be derived only on enums with up to 64 variants",
            ));
        }
        accumulator.finish_with(Self {
            vis: vis.clone(),
            event_enum_ident: event_ident.clone(),
            set_ident: syn::Ident::new(&format!("{event_ident}Set"), event_ident.span()),
            schema_name,
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
            schema_name,
            variants,
        } = self;
        let repr = if variants.len() <= 32 {
            quote!(u32)
        } else {
            quote!(u64)
        };
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
        let doc = format!(
            " An event set for [`{event_enum_ident}`]s\n\nEvent sets of the same type can be combined with a custom `|` operator"
        );
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
                norito::codec::Decode,
                norito::codec::Encode,
                norito::NoritoSchema,
                iroha_schema::TypeId,
            )]
            #[repr(transparent)]
            #[norito_schema(name = #schema_name)]
            #[doc = #doc]
            #vis struct #set_ident(#repr);
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
            impl norito::json::FastJsonWrite for #set_ident {
                fn write_json(&self, out: &mut String) {
                    out.push('[');
                    let mut first = true;
                    for event in self.decompose() {
                        if !first {
                            out.push(',');
                        } else {
                            first = false;
                        }
                        let label = match event {
                            #(#flag_idents => #flag_names,)*
                            _ => unreachable!(),
                        };
                        norito::json::write_json_string(label, out);
                    }
                    out.push(']');
                }
            }
            impl norito::json::JsonDeserialize for #set_ident {
                fn json_deserialize(
                    parser: &mut norito::json::Parser<'_>,
                ) -> Result<Self, norito::json::Error> {
                    let value =
                        <norito::json::Value as norito::json::JsonDeserialize>::json_deserialize(
                            parser,
                        )?;
                    <Self as norito::json::JsonDeserialize>::json_from_value(&value)
                }
                fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
                    fn format_invalid_type(value: &norito::json::Value) -> String {
                        match value {
                            norito::json::Value::Null => String::from("unit value"),
                            norito::json::Value::Bool(value) => format!("boolean `{value}`"),
                            norito::json::Value::Number(number) => match number {
                                norito::json::Number::I64(value) => format!("integer `{value}`"),
                                norito::json::Number::U64(value) => format!("integer `{value}`"),
                                norito::json::Number::U128(value) => {
                                    format!("integer `{value}`")
                                }
                                norito::json::Number::F64(value) => {
                                    format!("floating point `{value}`")
                                }
                            },
                            norito::json::Value::String(value) => format!("string {value:?}"),
                            norito::json::Value::Array(_) => String::from("sequence"),
                            norito::json::Value::Object(_) => String::from("map"),
                        }
                    }
                    let values = match value {
                        norito::json::Value::Array(values) => values,
                        other => {
                            return Err(norito::json::Error::Message(format!(
                                "invalid type: {}, expected a sequence of strings",
                                format_invalid_type(other)
                            )));
                        }
                    };
                    let mut result = #set_ident::empty();
                    for value in values {
                        let name = match value {
                            norito::json::Value::String(name) => name,
                            other => {
                                return Err(norito::json::Error::Message(format!(
                                    "invalid type: {}, expected a string",
                                    format_invalid_type(other)
                                )));
                            }
                        };
                        let event = match name.as_str() {
                            #(#flag_names => #flag_idents,)*
                            other => {
                                return Err(norito::json::Error::Message(format!(
                                    "unknown event variant `{other}`, expected one of {}",
                                    #flag_names_str
                                )));
                            }
                        };
                        result |= event;
                    }
                    Ok(result)
                }
            }
            impl iroha_schema::IntoSchema for #set_ident {
                fn type_name() -> iroha_schema::Ident {
                    <Self as iroha_schema::TypeId>::id()
                }
                fn update_schema_map(metamap: &mut iroha_schema::MetaMap) {
                    if !metamap.contains_key::<Self>() {
                        if !metamap.contains_key::<#repr>() {
                            <#repr as iroha_schema::IntoSchema>::update_schema_map(metamap);
                        }
                        metamap.insert::<Self>(iroha_schema::Metadata::Bitmap(iroha_schema::BitmapMeta {
                            repr: core::any::TypeId::of::<#repr>(),
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
    let Some(enum_) = emitter.handle(darling_result(EventSetEnum::from_derive_input(input))) else {
        return quote! {};
    };
    quote! {
        #enum_
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn generated_set_declares_its_own_identity_once() {
        let input = parse_quote! {
            #[norito_schema(name = "fixture::Parent")]
            #[event_set(schema_name = "fixture::Child")]
            pub enum Parent { Unit, Nested(AnotherEvent), Named { value: u32 } }
        };
        let model = EventSetEnum::from_derive_input(&input).expect("event declaration");
        let file: syn::File = syn::parse2(model.into_token_stream()).expect("generated Rust");
        let child = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(child) if child.ident == "ParentSet" => Some(child),
                _ => None,
            })
            .expect("generated set");
        let identities: Vec<_> = child
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("norito_schema"))
            .collect();
        assert_eq!(identities.len(), 1);
        assert!(
            identities[0]
                .to_token_stream()
                .to_string()
                .contains("fixture::Child")
        );
        let generated = child.to_token_stream().to_string();
        assert!(!generated.contains("fixture::Parent"));
        assert_eq!(generated.matches("NoritoSchema").count(), 1);
        assert_eq!(generated.matches("codec :: Encode").count(), 1);
        assert_eq!(generated.matches("codec :: Decode").count(), 1);
    }

    #[test]
    fn set_generation_rejects_missing_child_identity() {
        let input = parse_quote! {
            #[norito_schema(name = "fixture::Parent")]
            enum Parent { Unit }
        };
        let error = EventSetEnum::from_derive_input(&input)
            .err()
            .expect("identity required");
        assert!(error.to_string().contains("EventSet requires #[event_set"));
    }

    #[test]
    fn bitmap_width_covers_32_and_64_events_and_rejects_65() {
        for count in [32, 33, 64, 65] {
            let variants = (0..count).map(|n| quote::format_ident!("Event{n}"));
            let input = syn::parse2(quote! {
                #[event_set(schema_name = "fixture::WideSet")]
                pub enum Wide { #(#variants),* }
            })
            .unwrap();
            let parsed = EventSetEnum::from_derive_input(&input);
            if count == 65 {
                assert!(
                    parsed
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("up to 64 variants")
                );
                continue;
            }
            let file: syn::File = syn::parse2(parsed.unwrap().into_token_stream()).unwrap();
            let child = file
                .items
                .iter()
                .find_map(|item| match item {
                    syn::Item::Struct(item) if item.ident == "WideSet" => Some(item),
                    _ => None,
                })
                .unwrap();
            let width = if count <= 32 { "u32" } else { "u64" };
            assert_eq!(
                child
                    .fields
                    .iter()
                    .next()
                    .unwrap()
                    .ty
                    .to_token_stream()
                    .to_string(),
                width
            );
        }
    }
}
