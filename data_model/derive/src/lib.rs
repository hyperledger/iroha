//! A crate containing various derive macros for `data_model`

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod filter;
mod id;

/// A derive macro for `Identifiable` trait and id-based comparison traits. Currently supports derivations only for
/// `IdBox` and structs from the `data_model` crate that don't have generic parameters.
///
/// As such, the macro introduces a new
/// outer attribute `id` for the entities it is derived from. This attribute should
/// be supplied with the associated type to be used in `impl Identifiable`. The type
/// should be supplied as a string literal that constitutes a
/// legal Rust type path.
///
/// As this macro also derives an implementation of `Ord`, `PartialOrd`, `Eq`, `PartialEq` and `Hash` traits that always
/// conforms to the same implementation principles based on ids of the entities.
/// Thus none of the entities that derive this macro should derive neither of the aforementioned traits,
/// as they will be overridden.
///
/// As a rule of thumb, this derive should never be used on any structs that can't be uniquely identifiable,
/// as all the derived traits here rely on the fact of that uniqueness.
///
/// # Examples
///
/// ```rust
/// use iroha_data_model_derive::IdOrdEqHash;
/// use iroha_data_model::Identifiable;
///
/// #[derive(Debug, IdOrdEqHash)]
/// #[id(type = "Id")]
/// struct Struct {
///     id: <Self as Identifiable>::Id,
/// }
///
/// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// struct Id {
///     name: u32,
/// }
///
/// ```
///
/// Deriving [`IdOrdEqHash`] for `Struct` expands as follows:
///
/// ```rust
/// # use iroha_data_model::Identifiable;
/// #
/// # #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// # struct Id {
/// #     name: u32,
/// # }
/// #[derive(Debug)]
/// struct Struct {
///     id: <Self as Identifiable>::Id,
/// }
///
/// impl Identifiable for Struct {
///     type Id = Id;
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
/// }
///
/// ```
#[proc_macro_derive(IdOrdEqHash, attributes(id))]
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
///
/// # Examples
///
/// TODO Remove `ignore` #2604. Needs to be fixed
/// ```ignore
/// use iroha_data_model_derive::{Filter, IdOrdEqHash};
/// use iroha_data_model::prelude::{HasOrigin, Identifiable};
/// use iroha_schema::IntoSchema;
/// use parity_scale_codec::{Decode, Encode};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Filter, Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// pub enum LayerEvent {
///     SubLayer(SubLayerEvent),
///     Created(LayerId),
/// }
///
/// #[derive(Filter, Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// pub enum SubLayerEvent {
///     Created(SubLayerId),
/// }
///
/// #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// pub struct LayerId {
///     name: u32,
/// }
///
/// #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// pub struct SubLayerId {
///     name: u32,
///     parent_id: LayerId,
/// }
///
/// #[derive(Debug, Clone, IdOrdEqHash)]
/// #[id(type = "LayerId")]
/// pub struct Layer {
///     id: <Self as Identifiable>::Id,
/// }
///
/// #[derive(Debug, Clone, IdOrdEqHash)]
/// #[id(type = "SubLayerId")]
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
///
/// ```
///
/// Deriving [`Filter`] for `LayerEvent` expands as follows:
///  
/// TODO Remove `ignore` #2604. Needs to be fixed
/// ```ignore
/// # use iroha_data_model_derive::{Filter, IdOrdEqHash};
/// # use iroha_data_model::prelude::{HasOrigin, Identifiable};
/// # use iroha_schema::IntoSchema;
/// # use parity_scale_codec::{Decode, Encode};
/// # use serde::{Deserialize, Serialize};
/// #
/// # #[derive(Filter, Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// # pub enum LayerEvent {
/// #     SubLayer(SubLayerEvent),
/// #     Created(LayerId),
/// # }
/// #
/// # #[derive(Filter, Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// # pub enum SubLayerEvent {
/// #     Created(SubLayerId),
/// # }
/// #
/// # #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// # pub struct LayerId {
/// #     name: u32,
/// # }
/// #
/// # #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode, Serialize, Deserialize, IntoSchema)]
/// # pub struct SubLayerId {
/// #     name: u32,
/// #     parent_id: LayerId,
/// # }
/// #
/// # #[derive(Debug, Clone, IdOrdEqHash)]
/// # #[id(type = "LayerId")]
/// # pub struct Layer {
/// #     id: <Self as Identifiable>::Id,
/// # }
/// #
/// # #[derive(Debug, Clone, IdOrdEqHash)]
/// # #[id(type = "SubLayerId")]
/// # pub struct SubLayer {
/// #     id: <Self as Identifiable>::Id,
/// # }
/// #
/// # impl HasOrigin for LayerEvent {
/// #     type Origin = Layer;
/// #
/// #     fn origin_id(&self) -> &<Layer as Identifiable>::Id {
/// #         match self {
/// #             Self::SubLayer(sub_layer) => &sub_layer.origin_id().parent_id,
/// #             Self::Created(id) => id,
/// #         }
/// #     }
/// # }
/// #
/// # impl HasOrigin for SubLayerEvent {
/// #     type Origin = SubLayer;
/// #
/// #     fn origin_id(&self) -> &<SubLayer as Identifiable>::Id {
/// #         match self {
/// #             Self::Created(id) => id,
/// #         }
/// #     }
/// # }
/// #
/// #[derive(
///     Clone,
///     PartialEq,
///     PartialOrd,
///     Ord,
///     Eq,
///     Debug,
///     Decode,
///     Encode,
///     Deserialize,
///     Serialize,
///     IntoSchema,
///     Hash,
/// )]
/// #[doc = " Filter for LayerEvent entity"]
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
/// #[derive(
///     Clone,
///     PartialEq,
///     PartialOrd,
///     Ord,
///     Eq,
///     Debug,
///     Decode,
///     Encode,
///     Deserialize,
///     Serialize,
///     IntoSchema,
///     Hash,
/// )]
/// #[allow(clippy::enum_variant_names, missing_docs)]
/// #[doc = " Event filter for LayerEvent entity"]
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
/// }
///
/// ```
#[proc_macro_derive(Filter)]
pub fn filter_derive(input: TokenStream) -> TokenStream {
    let event = parse_macro_input!(input as filter::EventEnum);
    filter::impl_filter(&event)
}
