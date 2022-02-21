//! This module contains `EventFilter` and entities for filter

use detail::Filter;

use super::*;

#[cfg(feature = "roles")]
pub type RoleEntityFilter = SimpleEntityFilter<RoleId>;
pub type PeerEntityFilter = detail::SimpleEntityFilter<PeerId>;
pub type AssetEntityFilter = detail::SimpleEntityFilter<AssetId>;
pub type AssetDefinitionEntityFilter = detail::SimpleEntityFilter<AssetDefinitionId>;
pub type OtherDomainChangeFilter = detail::SimpleEntityFilter<DomainId>;
pub type OtherAccountChangeFilter = detail::SimpleEntityFilter<AccountId>;
pub type DomainEntityFilter = detail::ComplexEntityFilter<DomainEvent, DomainEventFilter>;
pub type AccountEntityFilter = detail::ComplexEntityFilter<AccountEvent, AccountEventFilter>;

mod detail {
    //! This module contains *sealed* structs, that is used in public API, but should
    //! not be accessed from nowhere except parent module

    use super::*;

    pub trait Filter {
        type Item;

        fn filter(&self, item: &Self::Item) -> bool;
    }

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct SimpleEntityFilter<Id: Eq> {
        id_filter: IdFilter<Id>,
        status_filter: StatusFilter,
    }

    impl<Id: Eq> SimpleEntityFilter<Id> {
        pub fn new(id_filter: IdFilter<Id>, status_filter: StatusFilter) -> Self {
            Self {
                id_filter,
                status_filter,
            }
        }
    }

    impl<Id: Into<IdBox> + Debug + Clone + Eq + Ord> Filter for SimpleEntityFilter<Id> {
        type Item = SimpleEvent<Id>;

        fn filter(&self, entity: &SimpleEvent<Id>) -> bool {
            self.id_filter.filter(entity.id()) && self.status_filter.filter(entity.status())
        }
    }

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct ComplexEntityFilter<Entity, EventFilter>
    where
        Entity: IdTrait,
        EventFilter: Filter<Item = Entity>,
        for<'a> <Entity as Identifiable>::Id: IntoSchema + Deserialize<'a> + Serialize,
    {
        id_filter: IdFilter<<Entity as Identifiable>::Id>,
        event_filter: Option<EventFilter>,
    }

    impl<Entity, EventFilter> ComplexEntityFilter<Entity, EventFilter>
    where
        Entity: IdTrait,
        EventFilter: Filter<Item = Entity>,
        for<'a> <Entity as Identifiable>::Id: IntoSchema + Deserialize<'a> + Serialize,
    {
        pub fn new(
            id_filter: IdFilter<<Entity as Identifiable>::Id>,
            event_filter: Option<EventFilter>,
        ) -> Self {
            Self {
                id_filter,
                event_filter,
            }
        }
    }

    impl<Entity, EventFilter> Filter for ComplexEntityFilter<Entity, EventFilter>
    where
        Entity: IdTrait,
        EventFilter: Filter<Item = Entity>,
        for<'a> <Entity as Identifiable>::Id: IntoSchema + Deserialize<'a> + Serialize,
    {
        type Item = Entity;

        fn filter(&self, entity: &Entity) -> bool {
            self.id_filter.filter(entity.id())
                && self
                    .event_filter
                    .as_ref()
                    .map_or(true, |filter| filter.filter(entity))
        }
    }
}

/// Event filter
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum EventFilter {
    /// Accept all events
    AcceptAll,
    /// Accept events if they matches entity
    ByEntity(EntityFilter),
}

impl EventFilter {
    pub fn filter(&self, event: &Event) -> bool {
        match self {
            Self::AcceptAll => true,
            Self::ByEntity(filter) => filter.filter(event),
        }
    }
}

/// EntityFilter for `EventFilter`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum EntityFilter {
    /// Domain entity. `None` value will accept all `Domain` events
    ByDomain(Option<DomainEntityFilter>),
    /// Peer entity. `None` value will accept all `Domain` events
    ByPeer(Option<PeerEntityFilter>),
    /// Role entity. `None` value will accept all `Role` events
    #[cfg(feature = "roles")]
    ByRole(Option<RoleEntityFilter>),
    /// Account entity. `None` value will accept all `Account` events
    ByAccount(Option<AccountEntityFilter>),
    /// Asset entity. `None` value will accept all `AssetDefinition` events
    ByAssetDefinition(Option<AssetDefinitionEntityFilter>),
    /// Asset entity. `None` value will accept all `Asset` events
    ByAsset(Option<AssetEntityFilter>),
}

impl EntityFilter {
    fn filter(&self, event: &Event) -> bool {
        match (self, event) {
            (&Self::ByDomain(ref filter_opt), &Event::Domain(ref domain)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(domain)),
            (&Self::ByPeer(ref filter_opt), &Event::Peer(ref peer)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(peer)),
            #[cfg(feature = "roles")]
            (&Self::ByRole(ref filter_opt), &Event::Role(ref role)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(role)),
            (&Self::ByAccount(ref filter_opt), &Event::Account(ref account)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(account)),
            (
                &Self::ByAssetDefinition(ref filter_opt),
                &Event::AssetDefinition(ref asset_definition),
            ) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(asset_definition)),
            (&Self::ByAsset(ref filter_opt), &Event::Asset(ref asset)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(asset)),
            _ => false,
        }
    }
}

/// DomainFilter for `EntityFilter`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum DomainEventFilter {
    ByAccount(Option<AccountEntityFilter>),
    ByAssetDefinition(Option<AssetDefinitionEntityFilter>),
    ByOtherDomainChange(Option<OtherDomainChangeFilter>),
}

impl Filter for DomainEventFilter {
    type Item = DomainEvent;

    fn filter(&self, event: &DomainEvent) -> bool {
        match (self, event) {
            (&Self::ByAccount(ref filter_opt), &DomainEvent::Account(ref account)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(account)),
            (
                &Self::ByAssetDefinition(ref filter_opt),
                &DomainEvent::AssetDefinition(ref asset_definition),
            ) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(asset_definition)),
            (
                &Self::ByOtherDomainChange(ref filter_opt),
                &DomainEvent::OtherDomainChange(ref change),
            ) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(change)),
            _ => false,
        }
    }
}

/// AccountFilter for `EntityFilter`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum AccountEventFilter {
    ByAsset(Option<AssetEntityFilter>),
    ByOtherAccountChange(Option<OtherAccountChangeFilter>),
}

impl Filter for AccountEventFilter {
    type Item = AccountEvent;

    fn filter(&self, event: &AccountEvent) -> bool {
        match (self, event) {
            (&Self::ByAsset(ref filter_opt), &AccountEvent::Asset(ref asset)) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(asset)),
            (
                &Self::ByOtherAccountChange(ref filter_opt),
                &AccountEvent::OtherAccountChange(ref change),
            ) => filter_opt
                .as_ref()
                .map_or(true, |filter| filter.filter(change)),
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct IdFilter<Id: Eq>(Id);

impl<Id: Eq> Filter for IdFilter<Id> {
    type Item = Id;

    fn filter(&self, id: &Id) -> bool {
        id == &self.0
    }
}

/// Filter to select a status.
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum StatusFilter {
    /// Select [`Status::Created`].
    Created,
    /// Select [`Status::Updated`] or more detailed status in option.
    Updated(Option<Updated>),
    /// Select [`Status::Deleted`].
    Deleted,
}

impl Filter for StatusFilter {
    type Item = Status;

    fn filter(&self, status: &Status) -> bool {
        match (self, status) {
            (Self::Created, Status::Created) | (Self::Deleted, Status::Deleted) => true,
            (Self::Updated(opt), Status::Updated(detail)) => {
                opt.map_or(true, |filter_detail| detail == &filter_detail)
            }
            _ => false,
        }
    }
}
