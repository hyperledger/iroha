//! This module contains `EventFilter` and entities for filter

use super::*;

/// Create entity filter type. See usage below
///
/// This could be implemented with generic struct, but it's bad to have nested generics in filters
/// public API (especially for schemas)
macro_rules! entity_filter {
    (pub struct $name:ident { event: $entity_type:ty, filter: $event_filter_type:ty, }) => {
        entity_filter! {
            $name,
            $entity_type,
            $event_filter_type,
            concat!("Filter for ", stringify!($event_filter_type), " entity"),
            concat!("Construct new ", stringify!($name))
        }
    };
    ($name:ident, $entity_type:ty, $event_filter_type:ty, $struct_doc:expr, $new_doc:expr) => {
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
        #[doc = $struct_doc]
        pub struct $name {
            id_filter: FilterOpt<IdFilter<<$entity_type as Identifiable>::Id>>,
            event_filter: FilterOpt<$event_filter_type>,
        }

        impl $name {
            #[doc = $new_doc]
            pub fn new(
                id_filter: FilterOpt<IdFilter<<$entity_type as Identifiable>::Id>>,
                event_filter: FilterOpt<$event_filter_type>,
            ) -> Self {
                Self {
                    id_filter,
                    event_filter,
                }
            }
        }

        impl Filter for $name {
            type Item = $entity_type;

            fn filter(&self, entity: &Self::Item) -> bool {
                self.id_filter.filter(entity.id()) && self.event_filter.filter(entity)
            }
        }
    };
}

#[cfg(feature = "roles")]
entity_filter!(
    pub struct RoleFilter {
        event: RoleEvent,
        filter: RoleEventFilter,
    }
);
entity_filter!(
    pub struct PeerFilter {
        event: PeerEvent,
        filter: PeerEventFilter,
    }
);
entity_filter!(
    pub struct AssetFilter {
        event: AssetEvent,
        filter: AssetEventFilter,
    }
);
entity_filter!(
    pub struct AssetDefinitionFilter {
        event: AssetDefinitionEvent,
        filter: AssetDefinitionEventFilter,
    }
);
entity_filter!(
    pub struct DomainFilter {
        event: DomainEvent,
        filter: DomainEventFilter,
    }
);
entity_filter!(
    pub struct AccountFilter {
        event: AccountEvent,
        filter: AccountEventFilter,
    }
);

/// Filter for all events
pub type EventFilter = FilterOpt<EntityFilter>;

/// Trait for filters
pub trait Filter {
    /// Type of item that can be filtered
    type Item;

    /// Check if `item` passes filter
    ///
    /// Returns `true`, if `item` passes filter and `false` if not
    fn filter(&self, item: &Self::Item) -> bool;
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
    type Item = F::Item;

    fn filter(&self, item: &Self::Item) -> bool {
        match self {
            Self::AcceptAll => true,
            Self::BySome(filter) => filter.filter(item),
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
    /// Filter by Domain entity. `AcceptAll` value will accept all `Domain` events
    ByDomain(FilterOpt<DomainFilter>),
    /// Filter by Peer entity. `AcceptAll` value will accept all `Peer` events
    ByPeer(FilterOpt<PeerFilter>),
    /// Filter by Role entity. `AcceptAll` value will accept all `Role` events
    #[cfg(feature = "roles")]
    ByRole(FilterOpt<RoleFilter>),
    /// Filter by Account entity. `AcceptAll` value will accept all `Account` events
    ByAccount(FilterOpt<AccountFilter>),
    /// Filter by AssetDefinition entity. `AcceptAll` value will accept all `AssetDefinition` events
    ByAssetDefinition(FilterOpt<AssetDefinitionFilter>),
    /// Filter by Asset entity. `AcceptAll` value will accept all `Asset` events
    ByAsset(FilterOpt<AssetFilter>),
    /// Filter by Trigger entity. `AcceptAll` value will accept all `Trigger` events
    ByTrigger(FilterOpt<TriggerFilter>),
}

impl Filter for EntityFilter {
    type Item = Event;

    fn filter(&self, event: &Event) -> bool {
        match (self, event) {
            (Self::ByDomain(filter_opt), Event::Domain(domain)) => filter_opt.filter(domain),
            (Self::ByPeer(filter_opt), Event::Peer(peer)) => filter_opt.filter(peer),
            #[cfg(feature = "roles")]
            (Self::ByRole(filter_opt), Event::Role(role)) => filter_opt.filter(role),
            (Self::ByAccount(filter_opt), Event::Account(account)) => filter_opt.filter(account),
            (Self::ByAssetDefinition(filter_opt), Event::AssetDefinition(asset_definition)) => {
                filter_opt.filter(asset_definition)
            }
            (Self::ByAsset(filter_opt), Event::Asset(asset)) => filter_opt.filter(asset),
            _ => false,
        }
    }
}

#[cfg(feature = "roles")]
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
#[allow(missing_docs)]
pub enum RoleEventFilter {
    ByCreated,
    ByDeleted,
}

#[cfg(feature = "roles")]
impl Filter for RoleEventFilter {
    type Item = RoleEvent;

    fn filter(&self, event: &RoleEvent) -> bool {
        match (self, event) {
            (Self::ByCreated, RoleEvent::Created(_)) | (Self::ByDeleted, RoleEvent::Deleted(_)) => {
                true
            }
            _ => false,
        }
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
#[allow(missing_docs)]
pub enum PeerEventFilter {
    ByCreated,
    ByDeleted,
}

impl Filter for PeerEventFilter {
    type Item = PeerEvent;

    fn filter(&self, event: &PeerEvent) -> bool {
        matches!(
            (self, event),
            (Self::ByCreated, PeerEvent::Created(_)) | (Self::ByDeleted, PeerEvent::Deleted(_))
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
pub enum AssetEventFilter {
    ByCreated,
    ByDeleted,
    ByIncreased,
    ByDecreased,
    ByMetadataInserted,
    ByMetadataRemoved,
}

impl Filter for AssetEventFilter {
    type Item = AssetEvent;

    fn filter(&self, event: &AssetEvent) -> bool {
        matches!(
            (self, event),
            (Self::ByCreated, AssetEvent::Created(_))
                | (Self::ByDeleted, AssetEvent::Deleted(_))
                | (Self::ByIncreased, AssetEvent::Increased(_))
                | (Self::ByDecreased, AssetEvent::Decreased(_))
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
    ByMetadataInserted,
    ByMetadataRemoved,
}

impl Filter for AssetDefinitionEventFilter {
    type Item = AssetDefinitionEvent;

    fn filter(&self, event: &AssetDefinitionEvent) -> bool {
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
        )
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
    type Item = DomainEvent;

    fn filter(&self, event: &DomainEvent) -> bool {
        match (self, event) {
            (Self::ByAccount(filter_opt), DomainEvent::Account(account)) => {
                filter_opt.filter(account)
            }
            (
                Self::ByAssetDefinition(filter_opt),
                DomainEvent::AssetDefinition(asset_definition),
            ) => filter_opt.filter(asset_definition),
            (Self::ByCreated, DomainEvent::Created(_))
            | (Self::ByDeleted, DomainEvent::Deleted(_))
            | (Self::ByMetadataInserted, DomainEvent::MetadataInserted(_))
            | (Self::ByMetadataRemoved, DomainEvent::MetadataRemoved(_)) => true,
            _ => false,
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
/// Filter for Account events
pub enum AccountEventFilter {
    /// Filter by Asset event.
    /// `AcceptAll` value will accept all `Asset` events that are related to Account
    ByAsset(FilterOpt<AssetFilter>),
    /// Filter by Created event
    ByCreated,
    /// Filter by Deleted event
    ByDeleted,
    /// Filter by Authentication event
    ByAuthentication,
    /// Filter by Permission event
    ByPermission,
    /// Filter by MetadataInserted event
    ByMetadataInserted,
    /// Filter by MetadataRemoved event
    ByMetadataRemoved,
}

impl Filter for AccountEventFilter {
    type Item = AccountEvent;

    fn filter(&self, event: &AccountEvent) -> bool {
        match (self, event) {
            (Self::ByAsset(filter_opt), AccountEvent::Asset(asset)) => filter_opt.filter(asset),
            (Self::ByCreated, AccountEvent::Created(_))
            | (Self::ByDeleted, AccountEvent::Deleted(_))
            | (Self::ByAuthentication, AccountEvent::Authentication(_))
            | (Self::ByPermission, AccountEvent::Permission(_))
            | (Self::ByMetadataInserted, AccountEvent::MetadataInserted(_))
            | (Self::ByMetadataRemoved, AccountEvent::MetadataRemoved(_)) => true,
            _ => false,
        }
    }
}

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
pub enum TriggerFilter {
    ByCreated,
    ByDeleted,
    ByExtended,
    ByShortened,
}

impl Filter for TriggerFilter {
    type Item = TriggerEvent;

    fn filter(&self, event: &TriggerEvent) -> bool {
        matches!(
            (self, event),
            (Self::ByCreated, TriggerEvent::Created(_))
                | (Self::ByDeleted, TriggerEvent::Deleted(_))
                | (Self::ByExtended, TriggerEvent::Extended(_))
                | (Self::ByShortened, TriggerEvent::Shortened(_))
        )
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

impl<Id: Eq> Filter for IdFilter<Id> {
    type Item = Id;

    fn filter(&self, id: &Id) -> bool {
        id == &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_scope() {
        const DOMAIN: &str = "wonderland";
        const ACCOUNT: &str = "alice";
        const ASSET: &str = "rose";
        let domain_id = DomainId::test(DOMAIN);
        let account_id = AccountId::test(ACCOUNT, DOMAIN);
        let asset_id = AssetId::test(ASSET, DOMAIN, ACCOUNT, DOMAIN);

        let domain_created = DomainEvent::Created(domain_id);
        let account_created = AccountEvent::Created(account_id.clone());
        let asset_created = AssetEvent::Created(asset_id);
        let account_asset_created = AccountEvent::Asset(asset_created.clone());
        let account_filter = BySome(EntityFilter::ByAccount(BySome(AccountFilter::new(
            BySome(IdFilter(account_id)),
            AcceptAll,
        ))));
        assert!(!account_filter.filter(&domain_created.into()));
        assert!(!account_filter.filter(&asset_created.into()));
        assert!(account_filter.filter(&account_created.into()));
        assert!(account_filter.filter(&account_asset_created.into()));
    }
}
