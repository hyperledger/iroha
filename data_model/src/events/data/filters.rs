//! This module contains `EventFilter` and entities for filter

// TODO write code documentation
// - possible topics to cover: EventFilter vs EventMatcher
// - how this maps to event hierarchy (events are hierarchical, but event filters are flat)
// - how to construct event filters (should be done with builder API when they are implemented)

use core::fmt::Debug;

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
    pub enum DataEntityFilter {
        ByPeer(PeerEventFilter),
        ByDomain(DomainEventFilter),
        ByAccount(AccountEventFilter),
        ByAsset(AssetEventFilter),
        ByAssetDefinition(AssetDefinitionEventFilter),
        ByTrigger(TriggerEventFilter),
        ByRole(RoleEventFilter),
        // We didn't have filters for these events before the refactor. Should we?
        // Configuration(ConfigurationEventFilter),
        // Executor(ExecutorEventFilter),
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct PeerEventFilter {
        pub id_matcher: Option<super::PeerId>,
        pub event_matcher: Option<PeerEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum PeerEventMatcher {
        ByAdded,
        ByRemoved,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct DomainEventFilter {
        pub id_matcher: Option<super::DomainId>,
        pub event_matcher: Option<DomainEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum DomainEventMatcher {
        ByCreated,
        ByDeleted,
        ByMetadataInserted,
        ByMetadataRemoved,
        ByOwnerChanged,
        // we allow filtering for nested events, but if you need to specify an id matcher for, for example, AccountId, you need to use AccountFilter
        // nested events
        ByAccount,
        ByAssetDefinition,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AccountEventFilter {
        pub id_matcher: Option<super::AccountId>,
        pub event_matcher: Option<AccountEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AccountEventMatcher {
        ByCreated,
        ByDeleted,
        ByAuthenticationAdded,
        ByAuthenticationRemoved,
        ByPermissionAdded,
        ByPermissionRemoved,
        ByRoleRevoked,
        ByRoleGranted,
        ByMetadataInserted,
        ByMetadataRemoved,
        // nested events
        ByAsset,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AssetEventFilter {
        pub id_matcher: Option<super::AssetId>,
        pub event_matcher: Option<AssetEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AssetEventMatcher {
        ByCreated,
        ByDeleted,
        ByAdded,
        ByRemoved,
        ByMetadataInserted,
        ByMetadataRemoved,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AssetDefinitionEventFilter {
        pub id_matcher: Option<super::AssetDefinitionId>,
        pub event_matcher: Option<AssetDefinitionEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AssetDefinitionEventMatcher {
        ByCreated,
        ByMintabilityChanged,
        ByOwnerChanged,
        ByDeleted,
        ByMetadataInserted,
        ByMetadataRemoved,
        ByTotalQuantityChanged,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct TriggerEventFilter {
        pub id_matcher: Option<super::TriggerId>,
        pub event_matcher: Option<TriggerEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum TriggerEventMatcher {
        ByCreated,
        ByDeleted,
        ByExtended,
        ByShortened,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct RoleEventFilter {
        pub id_matcher: Option<super::RoleId>,
        pub event_matcher: Option<RoleEventMatcher>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum RoleEventMatcher {
        ByCreated,
        ByDeleted,
        ByPermissionRemoved,
    }
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
impl<F: EventFilter> EventFilter for FilterOpt<F> {
    type Event = F::Event;

    fn matches(&self, item: &Self::Event) -> bool {
        match self {
            Self::AcceptAll => true,
            Self::BySome(filter) => filter.matches(item),
        }
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for PeerEventFilter {
    type Event = super::PeerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use PeerEventMatcher::*;

        use super::PeerEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByAdded, Added(_)) => true,
                (ByRemoved, Removed(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for DomainEventFilter {
    type Event = super::DomainEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use DomainEventMatcher::*;

        use super::DomainEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByMetadataInserted, MetadataInserted(_)) => true,
                (ByMetadataRemoved, MetadataRemoved(_)) => true,
                (ByOwnerChanged, OwnerChanged(_)) => true,
                (ByAccount, Account(_)) => true,
                (ByAssetDefinition, AssetDefinition(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AccountEventFilter {
    type Event = super::AccountEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AccountEventMatcher::*;

        use super::AccountEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByAuthenticationAdded, AuthenticationAdded(_)) => true,
                (ByAuthenticationRemoved, AuthenticationRemoved(_)) => true,
                (ByPermissionAdded, PermissionAdded(_)) => true,
                (ByPermissionRemoved, PermissionRemoved(_)) => true,
                (ByRoleRevoked, RoleRevoked(_)) => true,
                (ByRoleGranted, RoleGranted(_)) => true,
                (ByMetadataInserted, MetadataInserted(_)) => true,
                (ByMetadataRemoved, MetadataRemoved(_)) => true,
                (ByAsset, Asset(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetEventFilter {
    type Event = super::AssetEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AssetEventMatcher::*;

        use super::AssetEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByAdded, Added(_)) => true,
                (ByRemoved, Removed(_)) => true,
                (ByMetadataInserted, MetadataInserted(_)) => true,
                (ByMetadataRemoved, MetadataRemoved(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetDefinitionEventFilter {
    type Event = super::AssetDefinitionEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AssetDefinitionEventMatcher::*;

        use super::AssetDefinitionEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByMintabilityChanged, MintabilityChanged(_)) => true,
                (ByOwnerChanged, OwnerChanged(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByMetadataInserted, MetadataInserted(_)) => true,
                (ByMetadataRemoved, MetadataRemoved(_)) => true,
                (ByTotalQuantityChanged, TotalQuantityChanged(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for TriggerEventFilter {
    type Event = super::TriggerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use TriggerEventMatcher::*;

        use super::TriggerEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByExtended, Extended(_)) => true,
                (ByShortened, Shortened(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for RoleEventFilter {
    type Event = super::RoleEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use RoleEventMatcher::*;

        use super::RoleEvent::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (ByCreated, Created(_)) => true,
                (ByDeleted, Deleted(_)) => true,
                (ByPermissionRemoved, PermissionRemoved(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for DataEntityFilter {
    type Event = DataEvent;

    fn matches(&self, event: &DataEvent) -> bool {
        use DataEntityFilter::*;
        use DataEvent::*;

        match (self, event) {
            (ByPeer(filter), Peer(event)) => filter.matches(event),
            (ByDomain(filter), Domain(event)) => filter.matches(event),
            (ByAccount(filter), Domain(DomainEvent::Account(event))) => filter.matches(event),
            (ByAsset(filter), Domain(DomainEvent::Account(AccountEvent::Asset(event)))) => {
                filter.matches(event)
            }
            (ByAssetDefinition(filter), Domain(DomainEvent::AssetDefinition(event))) => {
                filter.matches(event)
            }
            (ByTrigger(filter), Trigger(event)) => filter.matches(event),
            (ByRole(filter), Role(event)) => filter.matches(event),
            _ => false,
        }
    }
}

pub mod prelude {
    pub use super::{
        AccountEventFilter, AccountEventMatcher, AssetDefinitionEventFilter,
        AssetDefinitionEventMatcher, AssetEventFilter, AssetEventMatcher, DataEntityFilter,
        DataEventFilter, DomainEventFilter, DomainEventMatcher,
        FilterOpt::{self, *},
        PeerEventFilter, PeerEventMatcher, RoleEventFilter, RoleEventMatcher, TriggerEventFilter,
        TriggerEventMatcher,
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
            iroha_crypto::KeyPair::random().into_parts().0,
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
        let domain_filter = BySome(DataEntityFilter::ByDomain(DomainEventFilter {
            id_matcher: Some(domain_id),
            event_matcher: None,
        }));
        let account_filter = BySome(DataEntityFilter::ByAccount(AccountEventFilter {
            id_matcher: Some(account_id),
            event_matcher: None,
        }));
        let asset_filter = BySome(DataEntityFilter::ByAsset(AssetEventFilter {
            id_matcher: Some(asset_id),
            event_matcher: None,
        }));

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
