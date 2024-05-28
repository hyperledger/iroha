//! This module contains filters for data events.
//!
//! For each event in [`super::events`], there's a corresponding filter type in this module. It can filter the events by origin id and event type.
//!
//! Event types are filtered with an `EventSet` type, allowing to filter for multiple event types at once.

use core::fmt::Debug;

use getset::Getters;
use iroha_data_model_derive::model;

pub use self::model::*;
use super::*;

#[model]
mod model {
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
        /// Matches [`ConfigurationEvent`]s
        Configuration(ConfigurationEventFilter),
        /// Matches [`ExecutorEvent`]s
        Executor(ExecutorEventFilter),
    }

    /// An event filter for [`PeerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: PeerEventSet,
    }

    /// An event filter for [`DomainEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: DomainEventSet,
    }

    /// An event filter for [`AccountEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: AccountEventSet,
    }

    /// An event filter for [`AssetEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: AssetEventSet,
    }

    /// An event filter for [`AssetDefinitionEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: AssetDefinitionEventSet,
    }

    /// An event filter for [`TriggerEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: TriggerEventSet,
    }

    /// An event filter for [`RoleEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
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
        /// Matches only event from this set
        pub(super) event_set: RoleEventSet,
    }

    /// An event filter for [`ConfigurationEvent`]s
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct ConfigurationEventFilter {
        /// If specified matches only events originating from this configuration
        pub(super) id_matcher: Option<super::ParameterId>,
        /// Matches only event from this set
        pub(super) event_set: ConfigurationEventSet,
    }

    /// An event filter for [`ExecutorEvent`].
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub struct ExecutorEventFilter {
        // executor is a global entity, so no id here
        /// Matches only event from this set
        pub(super) event_set: ExecutorEventSet,
    }
}

impl PeerEventFilter {
    /// Creates a new [`PeerEventFilter`] accepting all [`PeerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: PeerEventSet::all(),
        }
    }

    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_peer(mut self, id_matcher: PeerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`PeerEventFilter`] to accept only [`PeerEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: PeerEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for PeerEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for PeerEventFilter {
    type Event = super::PeerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl DomainEventFilter {
    /// Creates a new [`DomainEventFilter`] accepting all [`DomainEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: DomainEventSet::all(),
        }
    }

    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_domain(mut self, id_matcher: DomainId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`DomainEventFilter`] to accept only [`DomainEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: DomainEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for DomainEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for DomainEventFilter {
    type Event = super::DomainEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl AccountEventFilter {
    /// Creates a new [`AccountEventFilter`] accepting all [`AccountEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: AccountEventSet::all(),
        }
    }

    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_account(mut self, id_matcher: AccountId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AccountEventFilter`] to accept only [`AccountEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AccountEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for AccountEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AccountEventFilter {
    type Event = super::AccountEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl AssetEventFilter {
    /// Creates a new [`AssetEventFilter`] accepting all [`AssetEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: AssetEventSet::all(),
        }
    }

    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_asset(mut self, id_matcher: AssetId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AssetEventFilter`] to accept only [`AssetEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AssetEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for AssetEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetEventFilter {
    type Event = super::AssetEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl AssetDefinitionEventFilter {
    /// Creates a new [`AssetDefinitionEventFilter`] accepting all [`AssetDefinitionEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: AssetDefinitionEventSet::all(),
        }
    }

    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_asset_definition(mut self, id_matcher: AssetDefinitionId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`AssetDefinitionEventFilter`] to accept only [`AssetDefinitionEvent`]s of types contained in `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: AssetDefinitionEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for AssetDefinitionEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for AssetDefinitionEventFilter {
    type Event = super::AssetDefinitionEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl TriggerEventFilter {
    /// Creates a new [`TriggerEventFilter`] accepting all [`TriggerEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: TriggerEventSet::all(),
        }
    }

    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_trigger(mut self, id_matcher: TriggerId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`TriggerEventFilter`] to accept only [`TriggerEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: TriggerEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for TriggerEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for TriggerEventFilter {
    type Event = super::TriggerEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl RoleEventFilter {
    /// Creates a new [`RoleEventFilter`] accepting all [`RoleEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: RoleEventSet::all(),
        }
    }

    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_role(mut self, id_matcher: RoleId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`RoleEventFilter`] to accept only [`RoleEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: RoleEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for RoleEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for RoleEventFilter {
    type Event = super::RoleEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl ConfigurationEventFilter {
    /// Creates a new [`ConfigurationEventFilter`] accepting all [`ConfigurationEvent`]s.
    pub const fn new() -> Self {
        Self {
            id_matcher: None,
            event_set: ConfigurationEventSet::all(),
        }
    }

    /// Modifies a [`ConfigurationEventFilter`] to accept only [`ConfigurationEvent`]s originating from ids matching `id_matcher`.
    #[must_use]
    pub fn for_parameter(mut self, id_matcher: ParameterId) -> Self {
        self.id_matcher = Some(id_matcher);
        self
    }

    /// Modifies a [`ConfigurationEventFilter`] to accept only [`ConfigurationEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: ConfigurationEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for ConfigurationEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for ConfigurationEventFilter {
    type Event = super::ConfigurationEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if let Some(id_matcher) = &self.id_matcher {
            if id_matcher != event.origin_id() {
                return false;
            }
        }

        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

impl ExecutorEventFilter {
    /// Creates a new [`ExecutorEventFilter`] accepting all [`ExecutorEvent`]s.
    pub const fn new() -> Self {
        Self {
            event_set: ExecutorEventSet::all(),
        }
    }

    /// Modifies a [`ExecutorEventFilter`] to accept only [`ExecutorEvent`]s of types matching `event_set`.
    #[must_use]
    pub const fn for_events(mut self, event_set: ExecutorEventSet) -> Self {
        self.event_set = event_set;
        self
    }
}

impl Default for ExecutorEventFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "transparent_api")]
impl super::EventFilter for ExecutorEventFilter {
    type Event = super::ExecutorEvent;

    fn matches(&self, event: &Self::Event) -> bool {
        if !self.event_set.matches(event) {
            return false;
        }

        true
    }
}

#[cfg(feature = "transparent_api")]
impl EventFilter for DataEventFilter {
    type Event = DataEvent;

    fn matches(&self, event: &DataEvent) -> bool {
        use DataEventFilter::*;

        #[allow(clippy::match_same_arms)]
        match (event, self) {
            (
                DataEvent::Domain(DomainEvent::Account(AccountEvent::Asset(event))),
                Asset(filter),
            ) => filter.matches(event),
            (DataEvent::Domain(DomainEvent::Account(event)), Account(filter)) => {
                filter.matches(event)
            }
            (DataEvent::Domain(DomainEvent::AssetDefinition(event)), AssetDefinition(filter)) => {
                filter.matches(event)
            }
            (DataEvent::Domain(event), Domain(filter)) => filter.matches(event),

            (DataEvent::Peer(event), Peer(filter)) => filter.matches(event),
            (DataEvent::Trigger(event), Trigger(filter)) => filter.matches(event),
            (DataEvent::Role(event), Role(filter)) => filter.matches(event),
            (DataEvent::Configuration(event), Configuration(filter)) => filter.matches(event),
            (DataEvent::Executor(event), Executor(filter)) => filter.matches(event),

            (
                DataEvent::Peer(_)
                | DataEvent::Domain(_)
                | DataEvent::Trigger(_)
                | DataEvent::Role(_)
                | DataEvent::Configuration(_)
                | DataEvent::Executor(_),
                Any,
            ) => true,
            (
                DataEvent::Peer(_)
                | DataEvent::Domain(_)
                | DataEvent::Trigger(_)
                | DataEvent::Role(_)
                | DataEvent::Configuration(_)
                | DataEvent::Executor(_),
                _,
            ) => false,
        }
    }
}

pub mod prelude {
    pub use super::{
        AccountEventFilter, AssetDefinitionEventFilter, AssetEventFilter, ConfigurationEventFilter,
        DataEventFilter, DomainEventFilter, ExecutorEventFilter, PeerEventFilter, RoleEventFilter,
        TriggerEventFilter,
    };
}
#[cfg(test)]
#[cfg(feature = "transparent_api")]
mod tests {
    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{
        account::AccountsMap,
        asset::{AssetDefinitionsMap, AssetTotalQuantityMap},
    };

    #[test]
    #[cfg(feature = "transparent_api")]
    fn entity_scope() {
        let domain_id: DomainId = "wonderland".parse().unwrap();
        let account_id = AccountId::new(domain_id.clone(), KeyPair::random().into_parts().0);
        let asset_id: AssetId = format!("rose##{account_id}").parse().unwrap();
        let domain_owner_id = AccountId::new(domain_id.clone(), KeyPair::random().into_parts().0);

        let domain = Domain {
            id: domain_id.clone(),
            accounts: AccountsMap::default(),
            asset_definitions: AssetDefinitionsMap::default(),
            asset_total_quantities: AssetTotalQuantityMap::default(),
            logo: None,
            metadata: Metadata::default(),
            owned_by: domain_owner_id,
        };
        let account = Account::new(account_id.clone()).into_account();
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
        let domain_filter = DataEventFilter::Domain(DomainEventFilter::new().for_domain(domain_id));
        let account_filter =
            DataEventFilter::Account(AccountEventFilter::new().for_account(account_id));
        let asset_filter = DataEventFilter::Asset(AssetEventFilter::new().for_asset(asset_id));

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
