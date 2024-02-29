//! This module contains `EventFilter` and entities for filter

use core::fmt::Debug;

use derive_more::Constructor;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

/// Filter for all events
pub type DataEventFilter = FilterOpt<DataEntityFilter>;

#[model]
pub mod model {
    use super::*;

    /// Optional filter. May pass all items or may filter them by `F`
    ///
    /// It's better than `Optional<F>` because `Optional` already has its own `filter` method and it
    /// would be ugly to use fully qualified syntax to call `Filter::filter()` method on it.
    /// Also `FilterOpt` variant names look better for filter needs
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[serde(untagged)] // Unaffected by #3330
    pub enum FilterOpt<F> {
        /// Accept all items that will be passed to `filter()` method
        #[serde(with = "accept_all_as_string")]
        AcceptAll,
        /// Use filter `F` to choose acceptable items passed to `filter()` method
        BySome(F),
    }

    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[allow(clippy::enum_variant_names)]
    /// Filters event by entity
    pub enum DataEntityFilter {
        /// Filter by Peer entity. `AcceptAll` value will accept all `Peer` events
        ByPeer(FilterOpt<PeerFilter>),
        /// Filter by Domain entity. `AcceptAll` value will accept all `Domain` events
        ByDomain(FilterOpt<DomainFilter>),
        /// Filter by Trigger entity. `AcceptAll` value will accept all `Trigger` events
        ByTrigger(FilterOpt<TriggerFilter>),
        /// Filter by Role entity. `AcceptAll` value will accept all `Role` events
        ByRole(FilterOpt<RoleFilter>),
    }

    /// Filter that accepts a data event with the matching origin.
    #[derive(
        Clone,
        PartialOrd,
        Ord,
        Eq,
        Debug,
        Constructor,
        Decode,
        Encode,
        Serialize,
        Deserialize,
        IntoSchema,
    )]
    #[serde(bound(
        deserialize = "<<T as HasOrigin>::Origin as Identifiable>::Id: Deserialize<'de>"
    ))]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct OriginFilter<T: HasOrigin>(pub(super) <T::Origin as Identifiable>::Id)
    where
        <T::Origin as Identifiable>::Id:
            Debug + Clone + Eq + Ord + Decode + Encode + Serialize + IntoSchema;
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
                    Err(E::custom(format!("expected AcceptAll, got {s}")))
                }
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

#[cfg(feature = "transparent_api")]
impl<F: Filter> Filter for FilterOpt<F> {
    type Event = F::Event;

    fn matches(&self, item: &Self::Event) -> bool {
        match self {
            Self::AcceptAll => true,
            Self::BySome(filter) => filter.matches(item),
        }
    }
}

#[cfg(feature = "transparent_api")]
impl Filter for DataEntityFilter {
    type Event = DataEvent;

    fn matches(&self, event: &DataEvent) -> bool {
        match (self, event) {
            (Self::ByPeer(filter_opt), DataEvent::Peer(peer)) => filter_opt.matches(peer),
            (Self::ByDomain(filter_opt), DataEvent::Domain(domain)) => filter_opt.matches(domain),
            (Self::ByTrigger(filter_opt), DataEvent::Trigger(trigger)) => {
                filter_opt.matches(trigger)
            }
            (Self::ByRole(filter_opt), DataEvent::Role(role)) => filter_opt.matches(role),
            _ => false,
        }
    }
}

impl<T: HasOrigin> OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Decode + Encode + Serialize + IntoSchema,
{
    /// Get the id of the origin of the data event that this filter accepts.
    pub fn origin_id(&self) -> &<T::Origin as Identifiable>::Id {
        &self.0
    }
}

#[cfg(feature = "transparent_api")]
impl<T: HasOrigin> Filter for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Decode + Encode + Serialize + IntoSchema,
{
    type Event = T;

    fn matches(&self, event: &T) -> bool {
        event.origin_id() == self.origin_id()
    }
}

impl<T: HasOrigin> PartialEq for OriginFilter<T>
where
    <T::Origin as Identifiable>::Id:
        Debug + Clone + Eq + Ord + Decode + Encode + Serialize + IntoSchema,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub mod prelude {
    pub use super::{
        DataEntityFilter, DataEventFilter,
        FilterOpt::{self, *},
        OriginFilter,
    };
}

#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    use super::*;
    use crate::{
        account::AccountsMap,
        asset::{AssetDefinitionsMap, AssetTotalQuantityMap},
    };

    #[test]
    #[cfg(feature = "transparent_api")]
    fn entity_scope() {
        let domain_name = "wonderland".parse().expect("Valid");
        let account_name = "alice".parse().expect("Valid");
        let asset_name = "rose".parse().expect("Valid");
        let domain_owner_id = "genesis@genesis".parse().expect("Valid");

        let domain_id = DomainId::new(domain_name);
        let domain = Domain {
            id: domain_id.clone(),
            accounts: AccountsMap::default(),
            asset_definitions: AssetDefinitionsMap::default(),
            asset_total_quantities: AssetTotalQuantityMap::default(),
            logo: None,
            metadata: Metadata::default(),
            owned_by: domain_owner_id,
        };
        let account_id = AccountId::new(domain_id.clone(), account_name);
        let account = Account::new(
            account_id.clone(),
            iroha_crypto::KeyPair::generate().into_raw_parts().0,
        )
        .into_account();
        let asset_id = AssetId::new(
            AssetDefinitionId::new(domain_id.clone(), asset_name),
            account_id.clone(),
        );
        let asset = Asset::new(asset_id.clone(), 0_u32);

        // Create three events with three levels of nesting
        // the first one is just a domain event
        // the second one is an account event with a domain event inside
        // the third one is an asset event with an account event with a domain event inside
        let domain_created = DomainEvent::Created(domain).into();
        let account_created = DomainEvent::Account(AccountEvent::Created(account)).into();
        let asset_created =
            DomainEvent::Account(AccountEvent::Asset(AssetEvent::Created(asset))).into();

        // test how the differently nested filters with with the events
        // FIXME: rewrite the filters using the builder DSL https://github.com/hyperledger/iroha/issues/3068
        let domain_filter = BySome(DataEntityFilter::ByDomain(BySome(DomainFilter::new(
            BySome(OriginFilter(domain_id)),
            AcceptAll,
        ))));
        let account_filter = BySome(DataEntityFilter::ByDomain(BySome(DomainFilter::new(
            // kind of unfortunately, we have to specify the domain id filter,
            // even though we will filter it with the account id filter (account id contains domain id with and account name)
            // FIXME: maybe make this more orthogonal by introducing a partial id (in account event filter only by account name)
            AcceptAll,
            BySome(DomainEventFilter::ByAccount(BySome(AccountFilter::new(
                BySome(OriginFilter(account_id)),
                AcceptAll,
            )))),
        ))));
        let asset_filter = BySome(DataEntityFilter::ByDomain(BySome(DomainFilter::new(
            AcceptAll,
            BySome(DomainEventFilter::ByAccount(BySome(AccountFilter::new(
                AcceptAll,
                BySome(AccountEventFilter::ByAsset(BySome(AssetFilter::new(
                    BySome(OriginFilter(asset_id)),
                    AcceptAll,
                )))),
            )))),
        ))));

        // domain filter matches all of those, because all of those events happened in the same domain
        assert!(domain_filter.matches(&domain_created));
        assert!(domain_filter.matches(&account_created));
        assert!(domain_filter.matches(&asset_created));

        // account event does not match the domain created event, as it is not an account event
        assert!(!account_filter.matches(&domain_created));
        assert!(account_filter.matches(&account_created));
        assert!(account_filter.matches(&asset_created));

        // asset event matches only the domain->account->asset event
        assert!(!asset_filter.matches(&domain_created));
        assert!(!asset_filter.matches(&account_created));
        assert!(asset_filter.matches(&asset_created));
    }
}
