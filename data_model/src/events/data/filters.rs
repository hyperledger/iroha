//! This module contains filters for data events.
//!
//! (almost) Each event in [`super::events`], there's two corresponding types in this module:
//! - `*EventMatcher` - matches one event kind (e.g. [`super::events::AccountEvent::Created`] with [`AccountEventMatcher::ByCreated`])
//! - `*EventFilter` - struct combining an optional id matcher and an optional event matcher
//!
//! The ones not having a filter are [`super::events::ConfigurationEvent`] and [`super::events::ExecutorEvent`] (TODO: why?).

use core::fmt::Debug;

use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

#[model]
pub mod model {
    use super::*;

    #[derive(
        Debug, Clone, PartialEq, Eq, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    pub enum DataEventFilter {
        /// Matches any data events ([`DataEvent`])
        ByAny,
        /// Matches only [`PeerEvent`]s
        ByPeer(PeerEventFilter),
        /// Matches only [`DomainEvent`]s
        ByDomain(DomainEventFilter),
        /// Matches only [`AccountEvent`]s
        ByAccount(AccountEventFilter),
        /// Matches only [`AssetEvent`]s
        ByAsset(AssetEventFilter),
        /// Matches only [`AssetDefinitionEvent`]s
        ByAssetDefinition(AssetDefinitionEventFilter),
        /// Matches only [`TriggerEvent`]s
        ByTrigger(TriggerEventFilter),
        /// Matches only [`RoleEvent`]s
        ByRole(RoleEventFilter),
        // We didn't have filters for these events before the refactor. Should we?
        // Configuration(ConfigurationEventFilter),
        // Executor(ExecutorEventFilter),
    }

    /// An event filter for [`PeerEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct PeerEventFilter {
        pub id_matcher: Option<super::PeerId>,
        pub event_matcher: Option<PeerEventMatcher>,
    }

    /// An event matcher for [`PeerEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum PeerEventMatcher {
        /// Matches only [`PeerEvent::Added`]
        ByAdded,
        /// Matches only [`PeerEvent::Removed`]
        ByRemoved,
    }

    /// An event filter for [`DomainEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct DomainEventFilter {
        /// If specified matches only events originating from this domain
        pub id_matcher: Option<super::DomainId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<DomainEventMatcher>,
    }

    /// An event matcher for [`DomainEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum DomainEventMatcher {
        /// Matches only [`DomainEvent::Created`]
        ByCreated,
        /// Matches only [`DomainEvent::Deleted`]
        ByDeleted,
        /// Matches only [`DomainEvent::MetadataInserted`]
        ByMetadataInserted,
        /// Matches only [`DomainEvent::MetadataRemoved`]
        ByMetadataRemoved,
        /// Matches only [`DomainEvent::OwnerChanged`]
        ByOwnerChanged,
        // we allow filtering for nested events, but if you need to specify an id matcher for, for example, AccountId, you need to use AccountFilter
        /// Matches only [`DomainEvent::Account`]
        ByAccountAny,
        /// Matches only [`DomainEvent::AssetDefinition`]
        ByAssetDefinitionAny,
    }

    /// An event filter for [`AccountEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AccountEventFilter {
        /// If specified matches only events originating from this account
        pub id_matcher: Option<super::AccountId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<AccountEventMatcher>,
    }

    /// An event matcher for [`AccountEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AccountEventMatcher {
        /// Matches only [`AccountEvent::Created`]
        ByCreated,
        /// Matches only [`AccountEvent::Deleted`]
        ByDeleted,
        /// Matches only [`AccountEvent::AuthenticationAdded`]
        ByAuthenticationAdded,
        /// Matches only [`AccountEvent::AuthenticationRemoved`]
        ByAuthenticationRemoved,
        /// Matches only [`AccountEvent::PermissionAdded`]
        ByPermissionAdded,
        /// Matches only [`AccountEvent::PermissionRemoved`]
        ByPermissionRemoved,
        /// Matches only [`AccountEvent::RoleRevoked`]
        ByRoleRevoked,
        /// Matches only [`AccountEvent::RoleGranted`]
        ByRoleGranted,
        /// Matches only [`AccountEvent::MetadataInserted`]
        ByMetadataInserted,
        /// Matches only [`AccountEvent::MetadataRemoved`]
        ByMetadataRemoved,
        // nested events
        /// Matches only [`AccountEvent::Asset`]
        ByAssetAny,
    }

    /// An event filter for [`AssetEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AssetEventFilter {
        /// If specified matches only events originating from this asset
        pub id_matcher: Option<super::AssetId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<AssetEventMatcher>,
    }

    /// An event matcher for [`AssetEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AssetEventMatcher {
        /// Matches only [`AssetEvent::Created`]
        ByCreated,
        /// Matches only [`AssetEvent::Deleted`]
        ByDeleted,
        /// Matches only [`AssetEvent::Added`]
        ByAdded,
        /// Matches only [`AssetEvent::Removed`]
        ByRemoved,
        /// Matches only [`AssetEvent::MetadataInserted`]
        ByMetadataInserted,
        /// Matches only [`AssetEvent::MetadataRemoved`]
        ByMetadataRemoved,
    }

    /// An event filter for [`AssetDefinitionEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AssetDefinitionEventFilter {
        /// If specified matches only events originating from this asset definition
        pub id_matcher: Option<super::AssetDefinitionId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<AssetDefinitionEventMatcher>,
    }

    /// An event matcher for [`AssetDefinitionEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum AssetDefinitionEventMatcher {
        /// Matches only [`AssetDefinitionEvent::Created`]
        ByCreated,
        /// Matches only [`AssetDefinitionEvent::MintabilityChanged`]
        ByMintabilityChanged,
        /// Matches only [`AssetDefinitionEvent::OwnerChanged`]
        ByOwnerChanged,
        /// Matches only [`AssetDefinitionEvent::Deleted`]
        ByDeleted,
        /// Matches only [`AssetDefinitionEvent::MetadataInserted`]
        ByMetadataInserted,
        /// Matches only [`AssetDefinitionEvent::MetadataRemoved`]
        ByMetadataRemoved,
        /// Matches only [`AssetDefinitionEvent::TotalQuantityChanged`]
        ByTotalQuantityChanged,
    }

    /// An event filter for [`TriggerEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct TriggerEventFilter {
        /// If specified matches only events originating from this trigger
        pub id_matcher: Option<super::TriggerId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<TriggerEventMatcher>,
    }

    /// An event matcher for [`TriggerEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum TriggerEventMatcher {
        /// Matches only [`TriggerEvent::Created`]
        ByCreated,
        /// Matches only [`TriggerEvent::Deleted`]
        ByDeleted,
        /// Matches only [`TriggerEvent::Extended`]
        ByExtended,
        /// Matches only [`TriggerEvent::Shortened`]
        ByShortened,
    }

    /// An event filter for [`RoleEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct RoleEventFilter {
        /// If specified matches only events originating from this role
        pub id_matcher: Option<super::RoleId>,
        /// If specified matches only events of this type
        pub event_matcher: Option<RoleEventMatcher>,
    }

    /// An event matcher for [`RoleEvent`]s
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum RoleEventMatcher {
        /// Matches only [`RoleEvent::Created`]
        ByCreated,
        /// Matches only [`RoleEvent::Deleted`]
        ByDeleted,
        /// Matches only [`RoleEvent::PermissionRemoved`]
        ByPermissionRemoved,
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
                (ByAccountAny, Account(_)) => true,
                (ByAssetDefinitionAny, AssetDefinition(_)) => true,
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
                (ByAssetAny, Asset(_)) => true,
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
impl EventFilter for DataEventFilter {
    type Event = DataEvent;

    fn matches(&self, event: &DataEvent) -> bool {
        use DataEvent::*;
        use DataEventFilter::*;

        match (self, event) {
            (ByAny, _) => true,
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
        AssetDefinitionEventMatcher, AssetEventFilter, AssetEventMatcher, DataEventFilter,
        DomainEventFilter, DomainEventMatcher, PeerEventFilter, PeerEventMatcher, RoleEventFilter,
        RoleEventMatcher, TriggerEventFilter, TriggerEventMatcher,
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
        let domain_filter = DataEventFilter::ByDomain(DomainEventFilter {
            id_matcher: Some(domain_id),
            event_matcher: None,
        });
        let account_filter = DataEventFilter::ByAccount(AccountEventFilter {
            id_matcher: Some(account_id),
            event_matcher: None,
        });
        let asset_filter = DataEventFilter::ByAsset(AssetEventFilter {
            id_matcher: Some(asset_id),
            event_matcher: None,
        });

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
