//! This module contains `EventFilter` and entities for filter

use core::{fmt::Debug, hash::Hash};

use super::*;

/// Filter for all events
pub type EventFilter = FilterOpt<EntityFilter>;

/// Optional filter. May pass all items or may filter them by `F`
///
/// It's better than `Optional<F>` because `Optional` already has its own `filter` method and it
/// would be ugly to use fully qualified syntax to call `Filter::filter()` method on it.
/// Also `FilterOpt` variant names look better for filter needs
#[derive(
    Clone,
    PartialEq,
    PartialOrd,
    Ord,
    Eq,
    Debug,
    Decode,
    Encode,
    Serialize,
    Deserialize,
    IntoSchema,
    Hash,
)]
#[serde(untagged)]
pub enum FilterOpt<F: Filter> {
    /// Accept all items that will be passed to `filter()` method
    #[serde(with = "accept_all_as_string")]
    AcceptAll,
    /// Use filter `F` to choose acceptable items passed to `filter()` method
    BySome(F),
}

mod accept_all_as_string {
    //! Module to (de-)serialize `FilterOpt::AcceptAll` variant as string

    #[cfg(not(feature = "std"))]
    use alloc::format;

    use serde::{Deserializer, Serializer};

    /// Serialize bytes using `base64`
    pub fn serialize<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("AcceptAll")
    }

    /// Deserialize bytes using `base64`
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = ();

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an AcceptAll string")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if s == "AcceptAll" {
                    Ok(())
                } else {
                    Err(E::custom(format!("expected AcceptAll, got {}", s)))
                }
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

impl<F: Filter> Filter for FilterOpt<F> {
    type Event = F::Event;

    fn matches(&self, item: &Self::Event) -> bool {
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
    type Event = Event;

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

#[derive(Clone, PartialOrd, Ord, Eq, Debug, Decode, Encode, Serialize, IntoSchema)]
/// Filter that accepts a data event with the matching origin.
pub struct OriginFilter<T: HasOrigin>(<T::Origin as Identifiable>::Id)
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema;

impl<T: HasOrigin> OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema,
{
    /// Construct [`OriginFilter`].
    pub fn new(origin_id: <T::Origin as Identifiable>::Id) -> Self {
        Self(origin_id)
    }

    /// Get the id of the origin of the data event that this filter accepts.
    pub fn origin_id(&self) -> &<T::Origin as Identifiable>::Id {
        &self.0
    }
}

impl<T: HasOrigin> Filter for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema,
{
    type Event = T;

    fn matches(&self, event: &T) -> bool {
        event.origin_id() == self.origin_id()
    }
}

impl<T: HasOrigin> PartialEq for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: HasOrigin> Hash for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema,
{
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<'de, T: HasOrigin> Deserialize<'de> for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Hash + Decode + Encode + Serialize + IntoSchema,
    <<T as HasOrigin>::Origin as Identifiable>::Id: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let origin_id = <T::Origin as Identifiable>::Id::deserialize(deserializer)?;
        Ok(Self::new(origin_id))
    }
}

pub mod prelude {
    pub use super::{
        EntityFilter as DataEntityFilter, EventFilter as DataEventFilter,
        FilterOpt::{self, *},
        OriginFilter,
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
            BySome(OriginFilter(account_id)),
            AcceptAll,
        ))));
        assert!(!account_filter.matches(&domain_created.into()));
        assert!(!account_filter.matches(&asset_created.into()));
        assert!(account_filter.matches(&account_created.into()));
        assert!(account_filter.matches(&account_asset_created.into()));
    }
}
