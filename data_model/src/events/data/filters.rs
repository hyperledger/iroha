//! This module contains `EventFilter` and entities for filter

use super::*;

macro_rules! entity_filter {
    (pub struct $name: ident { event: $entity_type:ty, filter: $event_filter_type:ty, }) => {
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
        pub struct $name {
            id_filter: FilterOpt<IdFilter<<$entity_type as Identifiable>::Id>>,
            event_filter: FilterOpt<$event_filter_type>,
        }

        impl $name {
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
pub type EventFilter = FilterOpt<EntityFilter>;

pub trait Filter {
    type Item;

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
pub enum FilterOpt<F: Filter> {
    AcceptAll,
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

/// EntityFilter for `EventFilter`
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
pub enum EntityFilter {
    /// Domain entity. `None` value will accept all `Domain` events
    ByDomain(FilterOpt<DomainFilter>),
    /// Peer entity. `None` value will accept all `Domain` events
    ByPeer(FilterOpt<PeerFilter>),
    /// Role entity. `None` value will accept all `Role` events
    #[cfg(feature = "roles")]
    ByRole(FilterOpt<RoleFilter>),
    /// Account entity. `None` value will accept all `Account` events
    ByAccount(FilterOpt<AccountFilter>),
    /// Asset entity. `None` value will accept all `AssetDefinition` events
    ByAssetDefinition(FilterOpt<AssetDefinitionFilter>),
    /// Asset entity. `None` value will accept all `Asset` events
    ByAsset(FilterOpt<AssetFilter>),
    ByTrigger(FilterOpt<TriggerFilter>),
}

impl Filter for EntityFilter {
    type Item = Event;

    fn filter(&self, event: &Event) -> bool {
        match (self, event) {
            (&Self::ByDomain(ref filter_opt), &Event::Domain(ref domain)) => {
                filter_opt.filter(domain)
            }
            (&Self::ByPeer(ref filter_opt), &Event::Peer(ref peer)) => filter_opt.filter(peer),
            #[cfg(feature = "roles")]
            (&Self::ByRole(ref filter_opt), &Event::Role(ref role)) => filter_opt.filter(role),
            (&Self::ByAccount(ref filter_opt), &Event::Account(ref account)) => {
                filter_opt.filter(account)
            }
            (
                &Self::ByAssetDefinition(ref filter_opt),
                &Event::AssetDefinition(ref asset_definition),
            ) => filter_opt.filter(asset_definition),
            (&Self::ByAsset(ref filter_opt), &Event::Asset(ref asset)) => filter_opt.filter(asset),
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
pub enum RoleEventFilter {
    ByCreated,
    ByDeleted,
}

#[cfg(feature = "roles")]
impl Filter for RoleEventFilter {
    type Item = RoleEvent;

    fn filter(&self, event: &RoleEvent) -> bool {
        match (self, event) {
            (Self::ByCreated, RoleEvent::Created(_)) => true,
            (Self::ByDeleted, RoleEvent::Deleted(_)) => true,
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
    IntoSchema,
    Hash,
)]
pub enum PeerEventFilter {
    ByCreated,
    ByDeleted,
}

impl Filter for PeerEventFilter {
    type Item = PeerEvent;

    fn filter(&self, event: &PeerEvent) -> bool {
        match (self, event) {
            (Self::ByCreated, PeerEvent::Created(_)) => true,
            (Self::ByDeleted, PeerEvent::Deleted(_)) => true,
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
    IntoSchema,
    Hash,
)]
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
        match (self, event) {
            (Self::ByCreated, AssetEvent::Created(_)) => true,
            (Self::ByDeleted, AssetEvent::Deleted(_)) => true,
            (Self::ByIncreased, AssetEvent::Increased(_)) => true,
            (Self::ByDecreased, AssetEvent::Decreased(_)) => true,
            (Self::ByMetadataInserted, AssetEvent::MetadataInserted(_)) => true,
            (Self::ByMetadataRemoved, AssetEvent::MetadataRemoved(_)) => true,
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
    IntoSchema,
    Hash,
)]
pub enum AssetDefinitionEventFilter {
    ByCreated,
    ByDeleted,
    ByMetadataInserted,
    ByMetadataRemoved,
}

impl Filter for AssetDefinitionEventFilter {
    type Item = AssetDefinitionEvent;

    fn filter(&self, event: &AssetDefinitionEvent) -> bool {
        match (self, event) {
            (Self::ByCreated, AssetDefinitionEvent::Created(_)) => true,
            (Self::ByDeleted, AssetDefinitionEvent::Deleted(_)) => true,
            (Self::ByMetadataInserted, AssetDefinitionEvent::MetadataInserted(_)) => true,
            (Self::ByMetadataRemoved, AssetDefinitionEvent::MetadataRemoved(_)) => true,
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
pub enum DomainEventFilter {
    ByAccount(FilterOpt<AccountFilter>),
    ByAssetDefinition(FilterOpt<AssetDefinitionFilter>),
    ByCreated,
    ByDeleted,
    ByMetadataInserted,
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
            (Self::ByCreated, DomainEvent::Created(_)) => true,
            (Self::ByDeleted, DomainEvent::Deleted(_)) => true,
            (Self::ByMetadataInserted, DomainEvent::MetadataInserted(_)) => true,
            (Self::ByMetadataRemoved, DomainEvent::MetadataRemoved(_)) => true,
            _ => false,
        }
    }
}

/// AccountFilter for `EntityFilter`
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
pub enum AccountEventFilter {
    ByAsset(FilterOpt<AssetFilter>),
    ByCreated,
    ByDeleted,
    ByAuthentication,
    ByPermission,
    ByMetadataInserted,
    ByMetadataRemoved,
}

impl Filter for AccountEventFilter {
    type Item = AccountEvent;

    fn filter(&self, event: &AccountEvent) -> bool {
        match (self, event) {
            (Self::ByAsset(filter_opt), AccountEvent::Asset(asset)) => filter_opt.filter(asset),
            (Self::ByCreated, AccountEvent::Created(_)) => true,
            (Self::ByDeleted, AccountEvent::Deleted(_)) => true,
            (Self::ByAuthentication, AccountEvent::Authentication(_)) => true,
            (Self::ByPermission, AccountEvent::Permission(_)) => true,
            (Self::ByMetadataInserted, AccountEvent::MetadataInserted(_)) => true,
            (Self::ByMetadataRemoved, AccountEvent::MetadataRemoved(_)) => true,
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
    FromVariant,
    IntoSchema,
    Hash,
)]
pub enum TriggerFilter {
    ByCreated,
    ByDeleted,
    ByExtended,
    ByShortened,
}

impl Filter for TriggerFilter {
    type Item = TriggerEvent;

    fn filter(&self, event: &TriggerEvent) -> bool {
        match (self, event) {
            (Self::ByCreated, TriggerEvent::Created(_)) => true,
            (Self::ByDeleted, TriggerEvent::Deleted(_)) => true,
            (Self::ByExtended, TriggerEvent::Extended(_)) => true,
            (Self::ByShortened, TriggerEvent::Shortened(_)) => true,
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
