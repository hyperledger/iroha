//! This module contains filters for data events.
//!
//! (almost) Each event in [`super::events`], there's two corresponding types in this module:
//! - `*EventMatcher` - matches one event kind (e.g. [`super::events::AccountEvent::Created`] with [`AccountEventMatcher::Created`])
//! - `*EventFilter` - struct combining an optional id matcher and an optional event matcher

use core::fmt::Debug;

use getset::Getters;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

#[model]
pub mod model {
    use super::*;

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub enum DataEventFilter {
        /// Matches any data events ([`DataEvent`])
        Any,
        /// Matches [`PeerEvent`]s
        Peer(PeerEventFilter),
        /// Matches [`DomainEvent`]s
        Domain(DomainEventFilter),
        /// Matches [`AccountEvent`]s
        Account(AccountEventFilter),
        /// Matches [`AssetEvent`]s
        Asset(AssetEventFilter),
        /// Matches [`AssetDefinitionEvent`]s
        AssetDefinition(AssetDefinitionEventFilter),
        /// Matches [`TriggerEvent`]s
        Trigger(TriggerEventFilter),
        /// Matches [`RoleEvent`]s
        Role(RoleEventFilter),
        // We didn't have filters for these events before the refactor. Should we?
        // Configuration(ConfigurationEventFilter),
        // Executor(ExecutorEventFilter),
    }

    /// An event filter for [`PeerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct PeerEventFilter {
        /// If specified matches only events originating from this peer
        pub(super) id_matcher: Option<super::PeerId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<PeerEventMatcher>,
    }

    /// An event matcher for [`PeerEvent`]s
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
    pub enum PeerEventMatcher {
        /// Matches [`PeerEvent::Added`]
        Added,
        /// Matches [`PeerEvent::Removed`]
        Removed,
    }

    /// An event filter for [`DomainEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct DomainEventFilter {
        /// If specified matches only events originating from this domain
        pub(super) id_matcher: Option<super::DomainId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<DomainEventMatcher>,
    }

    /// An event matcher for [`DomainEvent`]s
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
    pub enum DomainEventMatcher {
        /// Matches [`DomainEvent::Created`]
        Created,
        /// Matches [`DomainEvent::Deleted`]
        Deleted,
        /// Matches [`DomainEvent::MetadataInserted`]
        MetadataInserted,
        /// Matches [`DomainEvent::MetadataRemoved`]
        MetadataRemoved,
        /// Matches [`DomainEvent::OwnerChanged`]
        OwnerChanged,
        // we allow filtering for nested events, but if you need to specify an id matcher for, for example, AccountId, you need to use AccountFilter
        /// Matches any [`DomainEvent::Account`]. To further filter by account events, use [`AccountEventFilter`]
        AnyAccount,
        /// Matches any [`DomainEvent::AssetDefinition`]. To further filter by asset definition events, use [`AssetDefinitionEventFilter`]
        AnyAssetDefinition,
    }

    /// An event filter for [`AccountEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct AccountEventFilter {
        /// If specified matches only events originating from this account
        pub(super) id_matcher: Option<super::AccountId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<AccountEventMatcher>,
    }

    /// An event matcher for [`AccountEvent`]s
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
    pub enum AccountEventMatcher {
        /// Matches [`AccountEvent::Created`]
        Created,
        /// Matches [`AccountEvent::Deleted`]
        Deleted,
        /// Matches [`AccountEvent::AuthenticationAdded`]
        AuthenticationAdded,
        /// Matches [`AccountEvent::AuthenticationRemoved`]
        AuthenticationRemoved,
        /// Matches [`AccountEvent::PermissionAdded`]
        PermissionAdded,
        /// Matches [`AccountEvent::PermissionRemoved`]
        PermissionRemoved,
        /// Matches [`AccountEvent::RoleRevoked`]
        RoleRevoked,
        /// Matches [`AccountEvent::RoleGranted`]
        RoleGranted,
        /// Matches [`AccountEvent::MetadataInserted`]
        MetadataInserted,
        /// Matches [`AccountEvent::MetadataRemoved`]
        MetadataRemoved,
        // nested events
        /// Matches any [`AccountEvent::Asset`]. To further filter by asset events, use [`AssetEventFilter`]
        AnyAsset,
    }

    /// An event filter for [`AssetEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct AssetEventFilter {
        /// If specified matches only events originating from this asset
        pub(super) id_matcher: Option<super::AssetId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<AssetEventMatcher>,
    }

    /// An event matcher for [`AssetEvent`]s
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
    pub enum AssetEventMatcher {
        /// Matches [`AssetEvent::Created`]
        Created,
        /// Matches [`AssetEvent::Deleted`]
        Deleted,
        /// Matches [`AssetEvent::Added`]
        Added,
        /// Matches [`AssetEvent::Removed`]
        Removed,
        /// Matches [`AssetEvent::MetadataInserted`]
        MetadataInserted,
        /// Matches [`AssetEvent::MetadataRemoved`]
        MetadataRemoved,
    }

    /// An event filter for [`AssetDefinitionEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct AssetDefinitionEventFilter {
        /// If specified matches only events originating from this asset definition
        pub(super) id_matcher: Option<super::AssetDefinitionId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<AssetDefinitionEventMatcher>,
    }

    /// An event matcher for [`AssetDefinitionEvent`]s
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
    pub enum AssetDefinitionEventMatcher {
        /// Matches [`AssetDefinitionEvent::Created`]
        Created,
        /// Matches [`AssetDefinitionEvent::MintabilityChanged`]
        MintabilityChanged,
        /// Matches [`AssetDefinitionEvent::OwnerChanged`]
        OwnerChanged,
        /// Matches [`AssetDefinitionEvent::Deleted`]
        Deleted,
        /// Matches [`AssetDefinitionEvent::MetadataInserted`]
        MetadataInserted,
        /// Matches [`AssetDefinitionEvent::MetadataRemoved`]
        MetadataRemoved,
        /// Matches [`AssetDefinitionEvent::TotalQuantityChanged`]
        TotalQuantityChanged,
    }

    /// An event filter for [`TriggerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct TriggerEventFilter {
        /// If specified matches only events originating from this trigger
        pub(super) id_matcher: Option<super::TriggerId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<TriggerEventMatcher>,
    }

    /// An event matcher for [`TriggerEvent`]s
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
    pub enum TriggerEventMatcher {
        /// Matches [`TriggerEvent::Created`]
        Created,
        /// Matches [`TriggerEvent::Deleted`]
        Deleted,
        /// Matches [`TriggerEvent::Extended`]
        Extended,
        /// Matches [`TriggerEvent::Shortened`]
        Shortened,
    }

    /// An event filter for [`RoleEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Default,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct RoleEventFilter {
        /// If specified matches only events originating from this role
        pub(super) id_matcher: Option<super::RoleId>,
        /// If specified matches only events of this type
        pub(super) event_matcher: Option<RoleEventMatcher>,
    }

    /// An event matcher for [`RoleEvent`]s
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
    pub enum RoleEventMatcher {
        /// Matches [`RoleEvent::Created`]
        Created,
        /// Matches [`RoleEvent::Deleted`]
        Deleted,
        /// Matches [`RoleEvent::PermissionRemoved`]
        PermissionRemoved,
    }
}

impl PeerEventFilter {
    /// Creates a new [`PeerEventFilter`] accepting all [`PeerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_id(mut self, id_matcher: PeerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: PeerEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for PeerEventFilter {
    type Event = super::PeerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use PeerEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Added, PeerEvent::Added(_)) => true,
                (Removed, PeerEvent::Removed(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl DomainEventFilter {
    /// Creates a new [`DomainEventFilter`] accepting all [`DomainEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_id(mut self, id_matcher: DomainId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: DomainEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for DomainEventFilter {
    type Event = super::DomainEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use DomainEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, DomainEvent::Created(_)) => true,
                (Deleted, DomainEvent::Deleted(_)) => true,
                (MetadataInserted, DomainEvent::MetadataInserted(_)) => true,
                (MetadataRemoved, DomainEvent::MetadataRemoved(_)) => true,
                (OwnerChanged, DomainEvent::OwnerChanged(_)) => true,
                (AnyAccount, DomainEvent::Account(_)) => true,
                (AnyAssetDefinition, DomainEvent::AssetDefinition(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl AccountEventFilter {
    /// Creates a new [`AccountEventFilter`] accepting all [`AccountEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_id(mut self, id_matcher: AccountId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: AccountEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AccountEventFilter {
    type Event = super::AccountEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AccountEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, AccountEvent::Created(_)) => true,
                (Deleted, AccountEvent::Deleted(_)) => true,
                (AuthenticationAdded, AccountEvent::AuthenticationAdded(_)) => true,
                (AuthenticationRemoved, AccountEvent::AuthenticationRemoved(_)) => true,
                (PermissionAdded, AccountEvent::PermissionAdded(_)) => true,
                (PermissionRemoved, AccountEvent::PermissionRemoved(_)) => true,
                (RoleRevoked, AccountEvent::RoleRevoked(_)) => true,
                (RoleGranted, AccountEvent::RoleGranted(_)) => true,
                (MetadataInserted, AccountEvent::MetadataInserted(_)) => true,
                (MetadataRemoved, AccountEvent::MetadataRemoved(_)) => true,
                (AnyAsset, AccountEvent::Asset(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl AssetEventFilter {
    /// Creates a new [`AssetEventFilter`] accepting all [`AssetEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_from(mut self, id_matcher: AssetId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: AssetEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetEventFilter {
    type Event = super::AssetEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AssetEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, AssetEvent::Created(_)) => true,
                (Deleted, AssetEvent::Deleted(_)) => true,
                (Added, AssetEvent::Added(_)) => true,
                (Removed, AssetEvent::Removed(_)) => true,
                (MetadataInserted, AssetEvent::MetadataInserted(_)) => true,
                (MetadataRemoved, AssetEvent::MetadataRemoved(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl AssetDefinitionEventFilter {
    /// Creates a new [`AssetDefinitionEventFilter`] accepting all [`AssetDefinitionEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_from(mut self, id_matcher: AssetDefinitionId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: AssetDefinitionEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetDefinitionEventFilter {
    type Event = super::AssetDefinitionEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use AssetDefinitionEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, AssetDefinitionEvent::Created(_)) => true,
                (MintabilityChanged, AssetDefinitionEvent::MintabilityChanged(_)) => true,
                (OwnerChanged, AssetDefinitionEvent::OwnerChanged(_)) => true,
                (Deleted, AssetDefinitionEvent::Deleted(_)) => true,
                (MetadataInserted, AssetDefinitionEvent::MetadataInserted(_)) => true,
                (MetadataRemoved, AssetDefinitionEvent::MetadataRemoved(_)) => true,
                (TotalQuantityChanged, AssetDefinitionEvent::TotalQuantityChanged(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl TriggerEventFilter {
    /// Creates a new [`TriggerEventFilter`] accepting all [`TriggerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_from(mut self, id_matcher: TriggerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: TriggerEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for TriggerEventFilter {
    type Event = super::TriggerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use TriggerEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, TriggerEvent::Created(_)) => true,
                (Deleted, TriggerEvent::Deleted(_)) => true,
                (Extended, TriggerEvent::Extended(_)) => true,
                (Shortened, TriggerEvent::Shortened(_)) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

impl RoleEventFilter {
    /// Creates a new [`RoleEventFilter`] accepting all [`RoleEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_matcher: None,
        }
    }

    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn only_from(mut self, id_matcher: RoleId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s of types matching `event_matcher`.
    #[must_use]
    pub const fn only_events(mut self, event_matcher: RoleEventMatcher) -> Self {
        self.event_matcher = Some(event_matcher);
        self
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for RoleEventFilter {
    type Event = super::RoleEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        use RoleEventMatcher::*;

        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }
        if let Some(event_matcher) = &self.event_matcher {
            match (event_matcher, event) {
                (Created, RoleEvent::Created(_)) => true,
                (Deleted, RoleEvent::Deleted(_)) => true,
                (PermissionRemoved, RoleEvent::PermissionRemoved(_)) => true,
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
        use DataEventFilter::*;

        match (self, event) {
            (Any, _) => true,
            (Peer(filter), DataEvent::Peer(event)) => filter.matches(event),
            (Domain(filter), DataEvent::Domain(event)) => filter.matches(event),
            (Account(filter), DataEvent::Domain(DomainEvent::Account(event))) => {
                filter.matches(event)
            }
            (
                Asset(filter),
                DataEvent::Domain(DomainEvent::Account(AccountEvent::Asset(event))),
            ) => filter.matches(event),
            (AssetDefinition(filter), DataEvent::Domain(DomainEvent::AssetDefinition(event))) => {
                filter.matches(event)
            }
            (Trigger(filter), DataEvent::Trigger(event)) => filter.matches(event),
            (Role(filter), DataEvent::Role(event)) => filter.matches(event),
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
        let domain_filter = DataEventFilter::Domain(DomainEventFilter {
            id_matcher: Some(domain_id),
            event_matcher: None,
        });
        let account_filter = DataEventFilter::Account(AccountEventFilter {
            id_matcher: Some(account_id),
            event_matcher: None,
        });
        let asset_filter = DataEventFilter::Asset(AssetEventFilter {
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
