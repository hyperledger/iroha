//! A crate containing various derive macros for `data_model`

use proc_macro::TokenStream;
use syn::parse_macro_input;

mod filter;
mod id;

/// A derive macro for `Identifiable` trait and id-based comparison traits. Currently supports derivations only for
/// `IdBox`, `Event` enums, and structs from the `data_model` crate that don't have generic parameters.
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
/// Example:
/// ```rust
///
/// // For a struct decorated like this
/// #[derive(IdOrdEqHash)]
/// #[id(type = "Id")]
/// pub struct Domain {
///     /// Identification of this [`Domain`].
///     id: <Self as Identifiable>::Id,
///     /// [`Account`]s of the domain.
///     accounts: AccountsMap,
///     /// [`Asset`](AssetDefinition)s defined of the `Domain`.
///     asset_definitions: AssetDefinitionsMap,
///     /// IPFS link to the `Domain` logo
///     logo: Option<IpfsPath>,
///     /// [`Metadata`] of this `Domain` as a key-value store.
///     metadata: Metadata,
/// }
///
/// // The following impls will be derived
/// impl Identifiable for Domain {
///     type Id = Id;
///     #[inline]
///     fn id(&self) -> &Self::Id {
///         &self.id
///     }
/// }
/// impl core::cmp::PartialOrd for Domain {
///     #[inline]
///     fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
///         Some(self.cmp(other))
///     }
/// }
/// impl core::cmp::Ord for Domain {
///     fn cmp(&self, other: &Self) -> core::cmp::Ordering {
///         self.id().cmp(other.id())
///     }
/// }
/// impl core::cmp::PartialEq for Domain {
///     fn eq(&self, other: &Self) -> bool {
///         self.id() == other.id()
///     }
/// }
/// impl core::cmp::Eq for Domain {}
/// impl core::hash::Hash for Domain {
///     fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
///         self.id().hash(state);
///     }
/// }
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
/// Example:
/// ```rust
///    // For a struct decorated like this
///    #[derive(Filter)]
///    pub enum DomainEvent {
///        Account(AccountEvent),
///        AssetDefinition(AssetDefinitionEvent),
///        Created(DomainId),
///        Deleted(DomainId),
///        MetadataInserted(DomainId),
///        MetadataRemoved(DomainId),
///    }
///
///    // The following lengthy code will be derived
///    #[derive(
///        Clone,
///        PartialEq,
///        PartialOrd,
///        Ord,
///        Eq,
///        Debug,
///        Decode,
///        Encode,
///        Deserialize,
///        Serialize,
///        IntoSchema,
///        Hash,
///    )]
///    #[doc = " A filter for DomainFilter"]
///    pub struct DomainFilter {
///        origin_filter: crate::prelude::FilterOpt<
///                crate::prelude::OriginFilter<crate::prelude::DomainEvent>
///            >,
///        event_filter: crate::prelude::FilterOpt<DomainEventFilter>,
///    }
///    impl DomainFilter {
///        #[doc = "DomainFilter"]
///        pub const fn new(
///            origin_filter: crate::prelude::FilterOpt<
///                    crate::prelude::OriginFilter<<crate::prelude::DomainEvent>
///                >,
///            event_filter: crate::prelude::FilterOpt<DomainEventFilter>,
///        ) -> Self {
///            Self {
///                origin_filter,
///                event_filter,
///            }
///        }
///        #[doc = r" Get `origin_filter`"]
///        #[inline]
///        pub const fn origin_filter(
///            &self,
///        ) -> &crate::prelude::FilterOpt<
///                crate::prelude::OriginFilter<crate::prelude::DomainEvent>
///            > {
///            &self.origin_filter
///        }
///        #[doc = r" Get `event_filter`"]
///        #[inline]
///        pub const fn event_filter(&self) -> &crate::prelude::FilterOpt<DomainEventFilter> {
///            &self.event_filter
///        }
///    }
///    impl Filter for DomainFilter {
///        type EventType = crate::prelude::DomainEvent;
///        fn matches(&self, event: &Self::EventType) -> bool {
///            self.origin_filter.matches(event) && self.event_filter.matches(event)
///        }
///    }
///    #[derive(
///        Clone,
///        PartialEq,
///        PartialOrd,
///        Ord,
///        Eq,
///        Debug,
///        Decode,
///        Encode,
///        Deserialize,
///        Serialize,
///        IntoSchema,
///        Hash,
///    )]
///    #[allow(clippy::enum_variant_names, missing_docs)]
///    pub enum DomainEventFilter {
///        ByCreated,
///        ByDeleted,
///        ByMetadataInserted,
///        ByMetadataRemoved,
///        ByAccount(crate::prelude::FilterOpt<AccountFilter>),
///        ByAssetDefinition(crate::prelude::FilterOpt<AssetDefinitionFilter>),
///    }
///    impl Filter for DomainEventFilter {
///        type EventType = crate::prelude::DomainEvent;
///        fn matches(&self, event: &crate::prelude::DomainEvent) -> bool {
///            match (self, event) {
///                (Self::ByCreated, crate::prelude::DomainEvent::Created(_))
///                    | (Self::ByDeleted, crate::prelude::DomainEvent::Deleted(_))
///                    | (Self::ByMetadataInserted, crate::prelude::DomainEvent::MetadataInserted(_))
///                    | (Self::ByMetadataRemoved, crate::prelude::DomainEvent::MetadataRemoved(_)) => {
///                        true
///                    }
///                (Self::ByAccount(filter_opt), crate::prelude::DomainEvent::Account(event)) => {
///                    filter_opt.matches(event)
///                }
///                (
///                    Self::ByAssetDefinition(filter_opt),
///                    crate::prelude::DomainEvent::AssetDefinition(event),
///                ) => filter_opt.matches(event),
///                _ => false,
///            }
///        }
///    }
/// ```
#[proc_macro_derive(Filter)]
pub fn filter_derive(input: TokenStream) -> TokenStream {
    let event = parse_macro_input!(input as filter::EventEnum);
    filter::impl_filter(&event)
}
