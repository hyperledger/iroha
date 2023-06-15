//! A crate containing various derive macros for `data_model`
#![allow(clippy::std_instead_of_core)]

mod filter;
mod has_origin;
mod id;
mod model;
mod partially_tagged;
mod variant_discriminant;

use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Macro which controls how to export item's API. The behaviour is controlled with `transparent_api`
/// feature flag. If the flag is active, item's public fields will be exposed as public, however, if
/// it's not active, item will be exposed as opaque, i.e. no fields will be visible. This enables
/// internal libraries of Iroha to see and destructure data model items. On the other hand,
/// client libraries will only see opaque items and can be dynamically linked.
///
/// Additionally, this macro will rewrite private items as public when `transparent_api` is active.
/// If an item should remain private regardless of consumer library, just don't wrap it in this macro.
///
/// Should be used only on public module named `model`.
/// Macro will modify only structs, enums and unions. Other items will be left as is.
///
/// # Example
///
/// ```rust
/// use iroha_data_model_derive::model;
///
/// #[model]
/// pub mod model {
///     pub struct DataModel1 {
///        pub item1: u32,
///        item2: u64
///     }
///
///     pub(crate) struct DataModel2 {
///        pub item1: u32,
///        item2: u64
///     }
/// }
///
/// /* will produce:
/// pub mod model {
///     pub struct DataModel1 {
///         #[cfg(feature = "transparent_api")]
///         pub item1: u32,
///         #[cfg(not(feature = "transparent_api"))]
///         pub(crate) item1: u32,
///         pub(super) item2: u64
///     }
///
///     #[cfg(not(feature = "transparent_api"))]
///     pub struct DataModel2 {
///         pub item1: u32,
///         pub(super) item2: u64
///     }
///
///     #[cfg(feature = "transparent_api")]
///     struct DataModel2 {
///         pub item1: u32,
///         pub(super) item2: u64
///     }
/// }
/// */
/// ```
#[proc_macro_attribute]
#[proc_macro_error::proc_macro_error]
pub fn model(_attr: TokenStream, input: TokenStream) -> TokenStream {
    model::impl_model(&parse_macro_input!(input)).into()
}

/// Same as [`model`] macro, but only processes a single item.
///
/// You should prefer using [`model`] macro over this one.
#[proc_macro]
#[proc_macro_error::proc_macro_error]
pub fn model_single(input: TokenStream) -> TokenStream {
    model::process_item(parse_macro_input!(input)).into()
}

/// Derive macro for `Identifiable` trait which also automatically implements [`Ord`], [`Eq`],
/// and [`Hash`] for the annotated struct by delegating to it's identifier field. Identifier
/// field for the struct can be selected by annotating the desired field with `#[id]` or
/// `#[id(transparent)]`. The use of `transparent` assumes that the field is also `Identifiable`,
/// and the macro takes the field identifier of the annotated structure. In the absence
/// of any helper attribute, the macro uses the field named `id` if there is such a field.
/// Otherwise, the macro expansion fails.
///
/// The macro should never be used on structs that aren't uniquely identifiable
///
/// # Examples
///
/// The common use-case:
///
/// ```rust
/// use iroha_data_model_derive::IdEqOrdHash;
/// use iroha_data_model::Identifiable;
///
/// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// struct Id {
///     name: u32,
/// }
///
/// #[derive(Debug, IdEqOrdHash)]
/// struct Struct {
///     id: Id,
/// }
///
/// /* which will expand into:
/// impl Identifiable for Struct {
///     type Id = Id;
///
///     #[inline]
///     fn id(&self) -> &Self::Id {
///         &self.id
///     }
/// }
///
/// impl core::cmp::PartialOrd for Struct {
///     #[inline]
///     fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
///         Some(self.cmp(other))
///     }
/// }
///
/// impl core::cmp::Ord for Struct {
///     fn cmp(&self, other: &Self) -> core::cmp::Ordering {
///         self.id().cmp(other.id())
///     }
/// }
///
/// impl core::cmp::PartialEq for Struct {
///     fn eq(&self, other: &Self) -> bool {
///         self.id() == other.id()
///     }
/// }
///
/// impl core::cmp::Eq for Struct {}
///
/// impl core::hash::Hash for Struct {
///     fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
///         self.id().hash(state);
///     }
/// }*/
/// ```
///
/// Manual selection of the identifier field:
///
/// ```rust
/// use iroha_data_model_derive::IdEqOrdHash;
/// use iroha_data_model::Identifiable;
///
/// #[derive(Debug, IdEqOrdHash)]
/// struct InnerStruct {
///     #[id]
///     field: Id,
/// }
///
/// #[derive(Debug, IdEqOrdHash)]
/// struct Struct {
///     #[id(transparent)]
///     inner: InnerStruct,
/// }
///
/// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// struct Id {
///     name: u32,
/// }
/// ```
///
#[proc_macro_error::proc_macro_error]
#[proc_macro_derive(IdEqOrdHash, attributes(id, opaque))]
pub fn id_eq_ord_hash(input: TokenStream) -> TokenStream {
    id::impl_id(&parse_macro_input!(input)).into()
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
///
/// # Examples
///
/// ```ignore
/// use iroha_data_model_derive::{Filter, IdEqOrdHash};
/// use iroha_data_model::prelude::{HasOrigin, Identifiable};
/// use serde::{Deserialize, Serialize};
///
///
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Filter, Deserialize, Serialize)]
/// pub enum LayerEvent {
///     SubLayer(SubLayerEvent),
///     Created(LayerId),
/// }
///
/// pub enum SubLayerEvent {
///     Created(SubLayerId),
/// }
///
/// pub struct LayerId {
///     name: u32,
/// }
///
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// pub struct SubLayerId {
///     name: u32,
///     parent_id: LayerId,
/// }
///
/// #[derive(Debug, Clone, IdEqOrdHash)]
/// pub struct Layer {
///     id: <Self as Identifiable>::Id,
/// }
///
/// #[derive(Debug, Clone, IdEqOrdHash)]
/// pub struct SubLayer {
///     id: <Self as Identifiable>::Id,
/// }
///
/// impl HasOrigin for LayerEvent {
///     type Origin = Layer;
///
///     fn origin_id(&self) -> &<Layer as Identifiable>::Id {
///         match self {
///             Self::SubLayer(sub_layer) => &sub_layer.origin_id().parent_id,
///             Self::Created(id) => id,
///         }
///     }
/// }
///
/// impl HasOrigin for SubLayerEvent {
///     type Origin = SubLayer;
///
///     fn origin_id(&self) -> &<SubLayer as Identifiable>::Id {
///         match self {
///             Self::Created(id) => id,
///         }
///     }
/// }
/// ```
///
/// Deriving [`Filter`] for `LayerEvent` expands into:
///
/// ```
/// /*
/// #[doc = " Filter for LayerEvent entity"]
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, derive_more::Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
/// pub struct LayerFilter {
///     origin_filter:
///         crate::prelude::FilterOpt<crate::prelude::OriginFilter<crate::prelude::LayerEvent>>,
///     event_filter: crate::prelude::FilterOpt<LayerEventFilter>,
/// }
/// impl LayerFilter {
///     #[doc = " Construct new LayerFilter"]
///     pub const fn new(
///         origin_filter: crate::prelude::FilterOpt<
///             crate::prelude::OriginFilter<crate::prelude::LayerEvent>,
///         >,
///         event_filter: crate::prelude::FilterOpt<LayerEventFilter>,
///     ) -> Self {
///         Self {
///             origin_filter,
///             event_filter,
///         }
///     }
///     #[doc = r" Get `origin_filter`"]
///     #[inline]
///     pub const fn origin_filter(
///         &self,
///     ) -> &crate::prelude::FilterOpt<crate::prelude::OriginFilter<crate::prelude::LayerEvent>> {
///         &self.origin_filter
///     }
///     #[doc = r" Get `event_filter`"]
///     #[inline]
///     pub const fn event_filter(&self) -> &crate::prelude::FilterOpt<LayerEventFilter> {
///         &self.event_filter
///     }
/// }
/// impl crate::prelude::Filter for LayerFilter {
///     type EventType = crate::prelude::LayerEvent;
///     fn matches(&self, event: &Self::EventType) -> bool {
///         self.origin_filter.matches(event) && self.event_filter.matches(event)
///     }
/// }
/// #[doc = " Event filter for LayerEvent entity"]
/// #[allow(clippy::enum_variant_names, missing_docs)]
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema)]
/// pub enum LayerEventFilter {
///     ByCreated,
///     BySubLayer(crate::prelude::FilterOpt<SubLayerFilter>),
/// }
/// impl crate::prelude::Filter for LayerEventFilter {
///     type EventType = crate::prelude::LayerEvent;
///     fn matches(&self, event: &crate::prelude::LayerEvent) -> bool {
///         match (self, event) {
///             (Self::ByCreated, crate::prelude::LayerEvent::Created(_)) => true,
///             (Self::BySubLayer(filter_opt), crate::prelude::LayerEvent::SubLayer(event)) => {
///                 filter_opt.matches(event)
///             }
///             _ => false,
///         }
///     }
/// } */
/// ```
#[proc_macro_derive(Filter)]
pub fn filter_derive(input: TokenStream) -> TokenStream {
    let event = parse_macro_input!(input as filter::EventEnum);
    filter::impl_filter(&event)
}

/// Derive `::serde::Serialize` trait for `enum` with possibility to avoid tags for selected variants
///
/// ```
/// use serde::Serialize;
/// use iroha_data_model_derive::PartiallyTaggedSerialize;
///
/// #[derive(PartiallyTaggedSerialize)]
/// enum Outer {
///     A(u64),
///     #[serde_partially_tagged(untagged)]
///     Inner(Inner),
/// }
///
/// #[derive(Serialize)]
/// enum Inner {
///     B(u32),
/// }
///
/// assert_eq!(
///     &serde_json::to_string(&Outer::Inner(Inner::B(42))).expect("Failed to serialize"), r#"{"B":42}"#
/// );
///
/// assert_eq!(
///     &serde_json::to_string(&Outer::A(42)).expect("Failed to serialize"), r#"{"A":42}"#
/// );
/// ```
#[proc_macro_error::proc_macro_error]
#[proc_macro_derive(PartiallyTaggedSerialize, attributes(serde_partially_tagged, serde))]
pub fn partially_tagged_serialize_derive(input: TokenStream) -> TokenStream {
    partially_tagged::impl_partially_tagged_serialize(&parse_macro_input!(input))
}

/// Derive `::serde::Deserialize` trait for `enum` with possibility to avoid tags for selected variants
///
/// ```
/// use serde::Deserialize;
/// use iroha_data_model_derive::PartiallyTaggedDeserialize;
/// use std::string::ToString;
///
/// #[derive(Debug, PartialEq, Eq, PartiallyTaggedDeserialize)]
/// enum Outer {
///     A(u64),
///     #[serde_partially_tagged(untagged)]
///     Inner(Inner),
/// }
///
/// #[derive(Debug, PartialEq, Eq, Deserialize)]
/// enum Inner {
///     B(u128),
/// }
///
/// assert_eq!(
///     serde_json::from_str::<Outer>(r#"{"B":42}"#).expect("Failed to deserialize B"), Outer::Inner(Inner::B(42))
/// );
///
/// assert_eq!(
///     serde_json::from_str::<Outer>(r#"{"A":42}"#).expect("Failed to deserialize A"), Outer::A(42)
/// );
/// ```
///
/// Deserialization of untagged variants happens in declaration order.
/// Should be used with care to avoid ambiguity.
///
/// ```
/// use serde::Deserialize;
/// use iroha_data_model_derive::PartiallyTaggedDeserialize;
///
/// #[derive(Debug, PartialEq, Eq, PartiallyTaggedDeserialize)]
/// enum Outer {
///     A(u64),
///     // Ambiguity is created here because without tag it is impossible to distinguish `Inner1` and `Inner2`.
///     // Due to deserialization order `Inner1` will be deserialized in case of ambiguity.
///     #[serde_partially_tagged(untagged)]
///     Inner1(Inner),
///     #[serde_partially_tagged(untagged)]
///     Inner2(Inner),
/// }
///
/// #[derive(Debug, PartialEq, Eq, Deserialize)]
/// enum Inner {
///     B(u32),
/// }
///
/// assert_eq!(
///     serde_json::from_str::<Outer>(r#"{"B":42}"#).expect("Failed to deserialize"), Outer::Inner1(Inner::B(42))
/// );
/// ```
#[proc_macro_error::proc_macro_error]
#[proc_macro_derive(PartiallyTaggedDeserialize, attributes(serde_partially_tagged, serde))]
pub fn partially_tagged_deserialize_derive(input: TokenStream) -> TokenStream {
    partially_tagged::impl_partially_tagged_deserialize(&parse_macro_input!(input))
}

/// Derive macro for `HasOrigin`.
///
/// Works only with enums containing single unnamed fields.
///
/// # Attributes
///
/// ## Container attributes
///
/// ### `#[has_origin(origin = Type)]`
///
/// Required attribute. Used to determine type of `Origin` in `HasOrigin` trait.
///
/// ## Field attributes
///
/// ### `#[has_origin(ident => expr)]`
///
/// This attribute is used to determine how to extract origin id from enum variant.
/// By default variant is assumed to by origin id.
///
/// # Examples
///
/// ```
/// use iroha_data_model_derive::{IdEqOrdHash, HasOrigin};
/// use iroha_data_model::prelude::{Identifiable, HasOrigin};
///
///
/// #[derive(Debug, Clone, HasOrigin)]
/// #[has_origin(origin = Layer)]
/// pub enum LayerEvent {
///     #[has_origin(sub_layer_event => &sub_layer_event.origin_id().parent_id)]
///     SubLayer(SubLayerEvent),
///     Created(LayerId),
/// }
///
/// #[derive(Debug, Clone, HasOrigin)]
/// #[has_origin(origin = SubLayer)]
/// pub enum SubLayerEvent {
///     Created(SubLayerId),
/// }
///
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// pub struct LayerId {
///     name: u32,
/// }
///
/// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// pub struct SubLayerId {
///     name: u32,
///     parent_id: LayerId,
/// }
///
/// #[derive(Debug, Clone, IdEqOrdHash)]
/// pub struct Layer {
///     id: LayerId,
/// }
///
/// #[derive(Debug, Clone, IdEqOrdHash)]
/// pub struct SubLayer {
///     id: SubLayerId,
/// }
///
/// let layer_id = LayerId { name: 42 };
/// let sub_layer_id = SubLayerId { name: 24, parent_id: layer_id.clone() };
/// let layer_created_event = LayerEvent::Created(layer_id.clone());
/// let sub_layer_created_event = SubLayerEvent::Created(sub_layer_id.clone());
/// let layer_sub_layer_event = LayerEvent::SubLayer(sub_layer_created_event.clone());
///
/// assert_eq!(&layer_id, layer_created_event.origin_id());
/// assert_eq!(&layer_id, layer_sub_layer_event.origin_id());
/// assert_eq!(&sub_layer_id, sub_layer_created_event.origin_id());
/// ```
#[proc_macro_error::proc_macro_error]
#[proc_macro_derive(HasOrigin, attributes(has_origin))]
pub fn has_origin_derive(input: TokenStream) -> TokenStream {
    has_origin::impl_has_origin(&parse_macro_input!(input))
}

/// Derive macro to implement `AssociatedConstant<T>` trait for enum variants where
/// `T` is the type of discriminant.
/// So perfectly this macro should be used together with `EnumDiscriminants` derive macro from `strum` crate.
///
/// It's the user responsibility to import `AssociatedConstant` trait.
///
/// # Attributes
///
/// `#[variant_discriminant(name(DiscriminantType))]` attribute is required.
///
/// # Examples
///
/// ```
/// use iroha_data_model_derive::VariantDiscriminant;
/// use iroha_data_model::AssociatedConstant;
///
/// #[derive(VariantDiscriminant)]
/// #[variant_discriminant(name(MyEnumKind))]
/// enum MyEnum {
///     Unsigned(u32),
///     String(String),
///     Boolean(bool),
/// }
///
/// #[derive(Debug, PartialEq, Eq)]
/// enum MyEnumKind {
///    Unsigned,
///    String,
///    Boolean,
/// }
///
/// assert_eq!(<u32 as AssociatedConstant<MyEnumKind>>::VALUE, MyEnumKind::Unsigned);
/// assert_eq!(<String as AssociatedConstant<MyEnumKind>>::VALUE, MyEnumKind::String);
/// assert_eq!(<bool as AssociatedConstant<MyEnumKind>>::VALUE, MyEnumKind::Boolean);
/// ```
#[proc_macro_error::proc_macro_error]
#[proc_macro_derive(VariantDiscriminant, attributes(variant_discriminant))]
pub fn variant_discriminant_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).expect("Failed to parse input Token Stream.");
    variant_discriminant::impl_variant_discriminant(&ast)
}
