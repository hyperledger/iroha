//! This module contains `EventFilter` and entities for filter

use super::*;

/// Filter for all events
pub type EventFilter = FilterOpt<EntityFilter>;

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

    /// Get `id`
    pub fn id(&self) -> &Id {
        &self.0
    }
}

impl<Id: Eq> Filter for IdFilter<Id> {
    type EventType = Id;

    fn matches(&self, id: &Id) -> bool {
        id == &self.0
    }
}

pub mod prelude {
    pub use super::{
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
