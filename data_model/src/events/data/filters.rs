//! This module contains `EventFilter` and entities for filter

use super::*;

/// Create entity filter type. See usage below
///
/// This could be implemented with generic struct, but it's bad to have nested generics in filters
/// public API (especially for schemas)
macro_rules! entity_filter {
    ($(#[$meta:meta])* $vis:vis struct $name:ident { type EventType = $entity_type:ty; type EventFilter = $event_filter_type:ty; }) => {
        entity_filter! {
            @define_and_impl
            $(#[$meta])*,
            $vis,
            $name,
            $entity_type,
            $event_filter_type,
            concat!("Filter for ", stringify!($event_filter_type), " entity"),
            concat!("Construct new ", stringify!($name))
        }
    };
    (@define_and_impl  $(#[$meta:meta])*, $vis:vis, $name:ident, $entity_type:ty, $event_filter_type:ty, $struct_doc:expr, $new_doc:expr) => {
        $(#[$meta])*
        #[doc = $struct_doc]
        $vis struct $name {
            id_filter: FilterOpt<IdFilter<<$entity_type as IdTrait>::Id>>,
            event_filter: FilterOpt<$event_filter_type>,
        }

        impl $name {
            #[doc = $new_doc]
            pub const fn new(
                id_filter: FilterOpt<IdFilter<<$entity_type as IdTrait>::Id>>,
                event_filter: FilterOpt<$event_filter_type>,
            ) -> Self {
                Self {
                    id_filter,
                    event_filter,
                }
            }
        }

        impl Filter for $name {
            type EventType = $entity_type;

            fn matches(&self, entity: &Self::EventType) -> bool {
                self.id_filter.matches(entity.id()) && self.event_filter.matches(entity)
            }
        }
    };
}

#[cfg(feature = "roles")]
mod role {
    //! This module contains filters related to `RoleEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct RoleFilter {
            type EventType = RoleEvent;
            type EventFilter = RoleEventFilter;
        }
    );

    #[derive(
        Copy,
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
    #[allow(missing_docs)]
    pub enum RoleEventFilter {
        ByCreated,
        ByDeleted,
    }

    impl Filter for RoleEventFilter {
        type EventType = RoleEvent;

        fn matches(&self, event: &RoleEvent) -> bool {
            matches!(
                (self, event),
                (Self::ByCreated, RoleEvent::Created(_)) | (Self::ByDeleted, RoleEvent::Deleted(_))
            )
        }
    }
}

mod peer {
    //! This module contains filters related to `PeerEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct PeerFilter {
            type EventType = PeerEvent;
            type EventFilter = PeerEventFilter;
        }
    );

    #[derive(
        Copy,
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
    #[allow(missing_docs)]
    pub enum PeerEventFilter {
        ByAdded,
        ByRemoved,
    }

    impl Filter for PeerEventFilter {
        type EventType = PeerEvent;

        fn matches(&self, event: &PeerEvent) -> bool {
            matches!(
                (self, event),
                (Self::ByAdded, PeerEvent::Added(_)) | (Self::ByRemoved, PeerEvent::Removed(_))
            )
        }
    }
}

mod asset {
    //! This module contains filters related to `AssetEvent` and `AssetDefinitionEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct AssetFilter {
            type EventType = AssetEvent;
            type EventFilter = AssetEventFilter;
        }
    );

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct AssetDefinitionFilter {
            type EventType = AssetDefinitionEvent;
            type EventFilter = AssetDefinitionEventFilter;
        }
    );

    #[derive(
        Copy,
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
    #[allow(missing_docs, clippy::enum_variant_names)]
    pub enum AssetEventFilter {
        ByCreated,
        ByDeleted,
        ByAdded,
        ByRemoved,
        ByMetadataInserted,
        ByMetadataRemoved,
    }

    impl Filter for AssetEventFilter {
        type EventType = AssetEvent;

        fn matches(&self, event: &AssetEvent) -> bool {
            matches!(
                (self, event),
                (Self::ByCreated, AssetEvent::Created(_))
                    | (Self::ByDeleted, AssetEvent::Deleted(_))
                    | (Self::ByAdded, AssetEvent::Added(_))
                    | (Self::ByRemoved, AssetEvent::Removed(_))
                    | (Self::ByMetadataInserted, AssetEvent::MetadataInserted(_))
                    | (Self::ByMetadataRemoved, AssetEvent::MetadataRemoved(_))
            )
        }
    }

    #[derive(
        Copy,
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
    #[allow(missing_docs, clippy::enum_variant_names)]
    pub enum AssetDefinitionEventFilter {
        ByCreated,
        ByDeleted,
        ByMintabilityChanged,
        ByMetadataInserted,
        ByMetadataRemoved,
    }

    impl Filter for AssetDefinitionEventFilter {
        type EventType = AssetDefinitionEvent;

        fn matches(&self, event: &AssetDefinitionEvent) -> bool {
            matches!(
                (self, event),
                (Self::ByCreated, AssetDefinitionEvent::Created(_))
                    | (Self::ByDeleted, AssetDefinitionEvent::Deleted(_))
                    | (
                        Self::ByMetadataInserted,
                        AssetDefinitionEvent::MetadataInserted(_)
                    )
                    | (
                        Self::ByMetadataRemoved,
                        AssetDefinitionEvent::MetadataRemoved(_)
                    )
                    | (
                        Self::ByMintabilityChanged,
                        AssetDefinitionEvent::MintabilityChanged(_)
                    )
            )
        }
    }
}

mod domain {
    //! This module contains filters related to `DomainEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct DomainFilter {
            type EventType = DomainEvent;
            type EventFilter = DomainEventFilter;
        }
    );

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
        FromVariant,
        IntoSchema,
        Hash,
    )]
    #[allow(clippy::enum_variant_names)]
    /// Filter for Domain events
    pub enum DomainEventFilter {
        /// Filter by Account event.
        /// `AcceptAll` value will accept all `Account` events that are related to Domain
        ByAccount(FilterOpt<AccountFilter>),
        /// Filter by AssetDefinition event.
        /// `AcceptAll` value will accept all `AssetDefinition` events that are related to Domain
        ByAssetDefinition(FilterOpt<AssetDefinitionFilter>),
        /// Filter by Created event
        ByCreated,
        /// Filter by Deleted event
        ByDeleted,
        /// Filter by MetadataInserted event
        ByMetadataInserted,
        /// Filter by MetadataRemoved event
        ByMetadataRemoved,
    }

    impl Filter for DomainEventFilter {
        type EventType = DomainEvent;

        fn matches(&self, event: &DomainEvent) -> bool {
            match (self, event) {
                (Self::ByAccount(filter_opt), DomainEvent::Account(account)) => {
                    filter_opt.matches(account)
                }
                (
                    Self::ByAssetDefinition(filter_opt),
                    DomainEvent::AssetDefinition(asset_definition),
                ) => filter_opt.matches(asset_definition),
                (Self::ByCreated, DomainEvent::Created(_))
                | (Self::ByDeleted, DomainEvent::Deleted(_))
                | (Self::ByMetadataInserted, DomainEvent::MetadataInserted(_))
                | (Self::ByMetadataRemoved, DomainEvent::MetadataRemoved(_)) => true,
                _ => false,
            }
        }
    }
}

mod account {
    //! This module contains filters related to `AccountEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct AccountFilter {
            type EventType = AccountEvent;
            type EventFilter = AccountEventFilter;
        }
    );

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
        FromVariant,
        IntoSchema,
        Hash,
    )]
    #[allow(clippy::enum_variant_names)]
    /// Filter for Account events
    pub enum AccountEventFilter {
        /// Filter by Asset event.
        /// `AcceptAll` value will accept all `Asset` events that are related to Account
        ByAsset(FilterOpt<AssetFilter>),
        /// Filter by Created event
        ByCreated,
        /// Filter by Deleted event
        ByDeleted,
        /// Filter by AuthenticationAdded event
        ByAuthenticationAdded,
        /// Filter by AuthenticationRemoved event
        ByAuthenticationRemoved,
        /// Filter by PermissionAdded event
        ByPermissionAdded,
        /// Filter by PermissionRemoved event
        ByPermissionRemoved,
        /// Filter by MetadataInserted event
        ByMetadataInserted,
        /// Filter by MetadataRemoved event
        ByMetadataRemoved,
    }

    impl Filter for AccountEventFilter {
        type EventType = AccountEvent;

        fn matches(&self, event: &AccountEvent) -> bool {
            match (self, event) {
                (Self::ByAsset(filter_opt), AccountEvent::Asset(asset)) => {
                    filter_opt.matches(asset)
                }
                (Self::ByCreated, AccountEvent::Created(_))
                | (Self::ByDeleted, AccountEvent::Deleted(_))
                | (Self::ByAuthenticationAdded, AccountEvent::AuthenticationAdded(_))
                | (Self::ByAuthenticationRemoved, AccountEvent::AuthenticationRemoved(_))
                | (Self::ByPermissionAdded, AccountEvent::PermissionAdded(_))
                | (Self::ByPermissionRemoved, AccountEvent::PermissionRemoved(_))
                | (Self::ByMetadataInserted, AccountEvent::MetadataInserted(_))
                | (Self::ByMetadataRemoved, AccountEvent::MetadataRemoved(_)) => true,
                _ => false,
            }
        }
    }
}

mod trigger {
    //! This module contains filters related to `TriggerEvent`

    use super::*;

    entity_filter!(
        #[derive(
            Clone,
            PartialOrd,
            Ord,
            PartialEq,
            Eq,
            Debug,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
            Hash,
        )]
        pub struct TriggerFilter {
            type EventType = TriggerEvent;
            type EventFilter = TriggerEventFilter;
        }
    );

    #[derive(
        Copy,
        Clone,
        PartialOrd,
        Ord,
        PartialEq,
        Eq,
        Debug,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        FromVariant,
        IntoSchema,
        Hash,
    )]
    #[allow(missing_docs, clippy::enum_variant_names)]
    pub enum TriggerEventFilter {
        ByCreated,
        ByDeleted,
        ByExtended,
        ByShortened,
    }

    impl Filter for TriggerEventFilter {
        type EventType = TriggerEvent;

        fn matches(&self, event: &TriggerEvent) -> bool {
            matches!(
                (self, event),
                (Self::ByCreated, TriggerEvent::Created(_))
                    | (Self::ByDeleted, TriggerEvent::Deleted(_))
                    | (Self::ByExtended, TriggerEvent::Extended(_))
                    | (Self::ByShortened, TriggerEvent::Shortened(_))
            )
        }
    }
}

/// Filter for all events
pub type EventFilter = FilterOpt<EntityFilter>;

/// Trait for filters
pub trait Filter {
    /// Type of event that can be filtered
    type EventType;

    /// Check if `item` matches filter
    ///
    /// Returns `true`, if `item` matches filter and `false` if not
    fn matches(&self, item: &Self::EventType) -> bool;
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
/// Optional filter. May pass all items or may filter them by `F`
///
/// It's better than `Optional<F>` because `Optional` already has its own `filter` method and it
/// would be ugly to use fully qualified syntax to call `Filter::filter()` method on it.
/// Also `FilterOpt` variant names look better for filter needs
pub enum FilterOpt<F: Filter> {
    /// Accept all items that will be passed to `filter()` method
    AcceptAll,
    /// Use filter `F` to choose acceptable items passed to `filter()` method
    BySome(F),
}

impl<F: Filter> Filter for FilterOpt<F> {
    type EventType = F::EventType;

    fn matches(&self, item: &Self::EventType) -> bool {
        match self {
            Self::AcceptAll => true,
            Self::BySome(filter) => filter.matches(item),
        }
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
    FromVariant,
    IntoSchema,
    Hash,
)]
#[allow(clippy::enum_variant_names)]
/// Filters event by entity
pub enum EntityFilter {
    /// Filter by Peer entity. `AcceptAll` value will accept all `Peer` events
    ByPeer(FilterOpt<PeerFilter>),
    /// Filter by Domain entity. `AcceptAll` value will accept all `Domain` events
    ByDomain(FilterOpt<DomainFilter>),
    /// Filter by Account entity. `AcceptAll` value will accept all `Account` events
    ByAccount(FilterOpt<AccountFilter>),
    /// Filter by AssetDefinition entity. `AcceptAll` value will accept all `AssetDefinition` events
    ByAssetDefinition(FilterOpt<AssetDefinitionFilter>),
    /// Filter by Asset entity. `AcceptAll` value will accept all `Asset` events
    ByAsset(FilterOpt<AssetFilter>),
    /// Filter by Trigger entity. `AcceptAll` value will accept all `Trigger` events
    ByTrigger(FilterOpt<TriggerFilter>),
    /// Filter by Role entity. `AcceptAll` value will accept all `Role` events
    #[cfg(feature = "roles")]
    ByRole(FilterOpt<RoleFilter>),
}

impl Filter for EntityFilter {
    type EventType = Event;

    fn matches(&self, event: &Event) -> bool {
        match (self, event) {
            (Self::ByPeer(filter_opt), Event::Peer(peer)) => filter_opt.matches(peer),
            (Self::ByDomain(filter_opt), Event::Domain(domain)) => filter_opt.matches(domain),
            (Self::ByAccount(filter_opt), Event::Account(account)) => filter_opt.matches(account),
            (Self::ByAssetDefinition(filter_opt), Event::AssetDefinition(asset_definition)) => {
                filter_opt.matches(asset_definition)
            }
            (Self::ByAsset(filter_opt), Event::Asset(asset)) => filter_opt.matches(asset),
            #[cfg(feature = "roles")]
            (Self::ByRole(filter_opt), Event::Role(role)) => filter_opt.matches(role),
            _ => false,
        }
    }
}

#[derive(
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    Hash,
)]
/// Filter for identifiers
///
/// Passes id trough filter, if it equals to the one provided in construction
pub struct IdFilter<Id: Eq>(Id);

impl<Id: Eq> IdFilter<Id> {
    /// Construct new `IdFilter`
    pub fn new(id: Id) -> Self {
        Self(id)
    }
}

impl<Id: Eq> Filter for IdFilter<Id> {
    type EventType = Id;

    fn matches(&self, id: &Id) -> bool {
        id == &self.0
    }
}

pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::role::{RoleEventFilter, RoleFilter};
    pub use super::{
        account::{AccountEventFilter, AccountFilter},
        asset::{AssetDefinitionEventFilter, AssetDefinitionFilter, AssetEventFilter, AssetFilter},
        domain::{DomainEventFilter, DomainFilter},
        peer::{PeerEventFilter, PeerFilter},
        trigger::{TriggerEventFilter, TriggerFilter},
        EntityFilter as DataEntityFilter, EventFilter as DataEventFilter,
        FilterOpt::{self, *},
        IdFilter,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn entity_scope() {
        let domain_name = "wonderland".parse().expect("Valid");
        let account_name = "alice".parse().expect("Valid");
        let asset_name = "rose".parse().expect("Valid");

        let domain_id = DomainId::new(domain_name);
        let account_id = AccountId::new(account_name, domain_id.clone());
        let asset_id = AssetId::new(
            AssetDefinitionId::new(asset_name, domain_id.clone()),
            account_id.clone(),
        );

        let domain_created = DomainEvent::Created(domain_id);
        let account_created = AccountEvent::Created(account_id.clone());
        let asset_created = AssetEvent::Created(asset_id);
        let account_asset_created = AccountEvent::Asset(asset_created.clone());
        let account_filter = BySome(EntityFilter::ByAccount(BySome(AccountFilter::new(
            BySome(IdFilter(account_id)),
            AcceptAll,
        ))));
        assert!(!account_filter.matches(&domain_created.into()));
        assert!(!account_filter.matches(&asset_created.into()));
        assert!(account_filter.matches(&account_created.into()));
        assert!(account_filter.matches(&account_asset_created.into()));
    }
}
