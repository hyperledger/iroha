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
            (Self::ByAccount(filter_opt), DataEvent::Account(account)) => {
                filter_opt.matches(account)
            }
            (Self::ByAssetDefinition(filter_opt), DataEvent::AssetDefinition(asset_definition)) => {
                filter_opt.matches(asset_definition)
            }
            (Self::ByAsset(filter_opt), DataEvent::Asset(asset)) => filter_opt.matches(asset),
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
    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;
    #[cfg(feature = "std")]
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        account::AccountsMap,
        asset::{AssetDefinitionsMap, AssetTotalQuantityMap, AssetsMap},
        role::RoleIds,
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
        let account_id = AccountId::new(account_name, domain_id.clone());
        let account = Account {
            id: account_id.clone(),
            assets: AssetsMap::default(),
            signatories: BTreeSet::default(),
            signature_check_condition: SignatureCheckCondition::default(),
            metadata: Metadata::default(),
            roles: RoleIds::default(),
        };
        let asset_id = AssetId::new(
            AssetDefinitionId::new(asset_name, domain_id),
            account_id.clone(),
        );
        let asset = Asset::new(asset_id, 0u32);

        let domain_created = DomainEvent::Created(domain);
        let account_created = AccountEvent::Created(account);
        let asset_created = AssetEvent::Created(asset);
        let account_asset_created = AccountEvent::Asset(asset_created.clone());
        let account_filter = BySome(DataEntityFilter::ByAccount(BySome(AccountFilter::new(
            BySome(OriginFilter(account_id)),
            AcceptAll,
        ))));
        assert!(!account_filter.matches(&domain_created.into()));
        assert!(!account_filter.matches(&asset_created.into()));
        assert!(account_filter.matches(&account_created.into()));
        assert!(account_filter.matches(&account_asset_created.into()));
    }
}
