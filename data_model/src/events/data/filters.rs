//! This module contains `EventFilter` and entities for filter

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
pub type EventFilter = FilterOpt<EntityFilter>;

mod detail {
    //! This module contains *sealed* structs, that is used in public API, but should
    //! not be accessed from nowhere except parent module

    use super::*;

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
        id_filter: FilterOpt<IdFilter<<Entity as Identifiable>::Id>>,
        event_filter: FilterOpt<EventFilter>,
    }

    impl<Entity, EventFilter> ComplexEntityFilter<Entity, EventFilter>
    where
        Entity: IdTrait,
        EventFilter: Filter<Item = Entity>,
        for<'a> <Entity as Identifiable>::Id: IntoSchema + Deserialize<'a> + Serialize,
    {
        pub fn new(
            id_filter: FilterOpt<IdFilter<<Entity as Identifiable>::Id>>,
            event_filter: FilterOpt<EventFilter>,
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
            self.id_filter.filter(entity.id()) && self.event_filter.filter(entity)
        }
    }
}

pub trait Filter {
    type Item;

    fn filter(&self, item: &Self::Item) -> bool;
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
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
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum EntityFilter {
    /// Domain entity. `None` value will accept all `Domain` events
    ByDomain(FilterOpt<DomainEntityFilter>),
    /// Peer entity. `None` value will accept all `Domain` events
    ByPeer(FilterOpt<PeerEntityFilter>),
    /// Role entity. `None` value will accept all `Role` events
    #[cfg(feature = "roles")]
    ByRole(FilterOpt<RoleEntityFilter>),
    /// Account entity. `None` value will accept all `Account` events
    ByAccount(FilterOpt<AccountEntityFilter>),
    /// Asset entity. `None` value will accept all `AssetDefinition` events
    ByAssetDefinition(FilterOpt<AssetDefinitionEntityFilter>),
    /// Asset entity. `None` value will accept all `Asset` events
    ByAsset(FilterOpt<AssetEntityFilter>),
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

#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum DomainEventFilter {
    ByAccount(FilterOpt<AccountEntityFilter>),
    ByAssetDefinition(FilterOpt<AssetDefinitionEntityFilter>),
    ByOtherDomainChange(FilterOpt<OtherDomainChangeFilter>),
}

impl Filter for DomainEventFilter {
    type Item = DomainEvent;

    fn filter(&self, event: &DomainEvent) -> bool {
        match (self, event) {
            (&Self::ByAccount(ref filter_opt), &DomainEvent::Account(ref account)) => {
                filter_opt.filter(account)
            }
            (
                &Self::ByAssetDefinition(ref filter_opt),
                &DomainEvent::AssetDefinition(ref asset_definition),
            ) => filter_opt.filter(asset_definition),
            (
                &Self::ByOtherDomainChange(ref filter_opt),
                &DomainEvent::OtherDomainChange(ref change),
            ) => filter_opt.filter(change),
            _ => false,
        }
    }
}

/// AccountFilter for `EntityFilter`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum AccountEventFilter {
    ByAsset(FilterOpt<AssetEntityFilter>),
    ByOtherAccountChange(FilterOpt<OtherAccountChangeFilter>),
}

impl Filter for AccountEventFilter {
    type Item = AccountEvent;

    fn filter(&self, event: &AccountEvent) -> bool {
        match (self, event) {
            (&Self::ByAsset(ref filter_opt), &AccountEvent::Asset(ref asset)) => {
                filter_opt.filter(asset)
            }
            (
                &Self::ByOtherAccountChange(ref filter_opt),
                &AccountEvent::OtherAccountChange(ref change),
            ) => filter_opt.filter(change),
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
    Created,
    Updated(FilterOpt<UpdatedFilter>),
    Deleted,
}

impl Filter for StatusFilter {
    type Item = Status;

    fn filter(&self, status: &Status) -> bool {
        match (self, status) {
            (Self::Created, Status::Created) | (Self::Deleted, Status::Deleted) => true,
            (Self::Updated(filter_opt), Status::Updated(detail)) => filter_opt.filter(detail),
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct UpdatedFilter(Updated);

impl Filter for UpdatedFilter {
    type Item = Updated;

    fn filter(&self, item: &Updated) -> bool {
        item == &self.0
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

        let domain_created =
            DomainEvent::OtherDomainChange(OtherDomainChangeEvent::new(domain_id, Status::Created));
        let account_created = AccountEvent::OtherAccountChange(OtherAccountChangeEvent::new(
            account_id.clone(),
            Status::Created,
        ));
        let asset_created = AssetEvent::new(asset_id, Status::Created);
        let account_asset_created = AccountEvent::Asset(asset_created.clone());

        let account_filter = BySome(EntityFilter::ByAccount(BySome(AccountEntityFilter::new(
            BySome(IdFilter(account_id)),
            AcceptAll,
        ))));
        assert!(!account_filter.filter(&domain_created.into()));
        assert!(!account_filter.filter(&asset_created.into()));
        assert!(account_filter.filter(&account_created.into()));
        assert!(account_filter.filter(&account_asset_created.into()));
    }
}
