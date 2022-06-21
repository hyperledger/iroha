//! This module contains data events

use iroha_data_primitives::small::SmallVec;

use super::*;

mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetEvent<const HASH_LENGTH: usize> {
        Created(AssetId<{ HASH_LENGTH }>),
        Deleted(AssetId<{ HASH_LENGTH }>),
        Added(AssetId<{ HASH_LENGTH }>),
        Removed(AssetId<{ HASH_LENGTH }>),
        MetadataInserted(AssetId<{ HASH_LENGTH }>),
        MetadataRemoved(AssetId<{ HASH_LENGTH }>),
    }

    impl<const HASH_LENGTH: usize> Identifiable for AssetEvent<HASH_LENGTH> {
        type Id = AssetId<HASH_LENGTH>;

        fn id(&self) -> &AssetId<HASH_LENGTH> {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Added(id)
                | Self::Removed(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetDefinitionEvent<const HASH_LENGTH: usize> {
        Created(AssetDefinitionId<{ HASH_LENGTH }>),
        MintabilityChanged(AssetDefinitionId<{ HASH_LENGTH }>),
        Deleted(AssetDefinitionId<{ HASH_LENGTH }>),
        MetadataInserted(AssetDefinitionId<{ HASH_LENGTH }>),
        MetadataRemoved(AssetDefinitionId<{ HASH_LENGTH }>),
    }
    // NOTE: Whenever you add a new event here, please also update the
    // AssetDefinitionEventFilter enum and its `impl Filter for
    // AssetDefinitionEventFilter`.

    impl<const HASH_LENGTH: usize> Identifiable for AssetDefinitionEvent<HASH_LENGTH> {
        type Id = AssetDefinitionId<HASH_LENGTH>;

        fn id(&self) -> &AssetDefinitionId<HASH_LENGTH> {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MintabilityChanged(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod peer {
    //! This module contains `PeerEvent` and its impls

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum PeerEvent {
        Added(PeerId),
        Removed(PeerId),
    }

    impl Identifiable for PeerEvent {
        type Id = PeerId;

        fn id(&self) -> &PeerId {
            match self {
                Self::Added(id) | Self::Removed(id) => id,
            }
        }
    }
}

mod role {
    //! This module contains `RoleEvent` and its impls

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum RoleEvent {
        Created(RoleId),
        Deleted(RoleId),
    }

    impl Identifiable for RoleEvent {
        type Id = RoleId;

        fn id(&self) -> &RoleId {
            match self {
                Self::Created(id) | Self::Deleted(id) => id,
            }
        }
    }
}

mod account {
    //! This module contains `AccountEvent` and its impls

    use super::*;

    /// Account event
    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AccountEvent<const HASH_LENGTH: usize> {
        Asset(AssetEvent<{ HASH_LENGTH }>),
        Created(AccountId),
        Deleted(AccountId),
        AuthenticationAdded(AccountId),
        AuthenticationRemoved(AccountId),
        PermissionAdded(AccountId),
        PermissionRemoved(AccountId),
        RoleRevoked(AccountId),
        RoleGranted(AccountId),
        MetadataInserted(AccountId),
        MetadataRemoved(AccountId),
    }

    impl<const HASH_LENGTH: usize> Identifiable for AccountEvent<HASH_LENGTH> {
        type Id = AccountId;

        fn id(&self) -> &AccountId {
            match self {
                Self::Asset(asset) => &asset.id().account_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::AuthenticationAdded(id)
                | Self::AuthenticationRemoved(id)
                | Self::PermissionAdded(id)
                | Self::PermissionRemoved(id)
                | Self::RoleRevoked(id)
                | Self::RoleGranted(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod domain {
    //! This module contains `DomainEvent` and its impls

    use super::*;

    /// Domain Event
    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum DomainEvent<const HASH_LENGTH: usize> {
        Account(AccountEvent<{ HASH_LENGTH }>),
        AssetDefinition(AssetDefinitionEvent<{ HASH_LENGTH }>),
        Created(DomainId),
        Deleted(DomainId),
        MetadataInserted(DomainId),
        MetadataRemoved(DomainId),
    }

    impl<const HASH_LENGTH: usize> Identifiable for DomainEvent<HASH_LENGTH> {
        type Id = DomainId;

        fn id(&self) -> &DomainId {
            match self {
                Self::Account(account) => &account.id().domain_id,
                Self::AssetDefinition(asset_definition) => &asset_definition.id().domain_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::MetadataInserted(id)
                | Self::MetadataRemoved(id) => id,
            }
        }
    }
}

mod trigger {
    //! This module contains `TriggerEvent` and its impls

    use super::*;

    /// Trigger Event
    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum TriggerEvent {
        Created(TriggerId),
        Deleted(TriggerId),
        Extended(TriggerId),
        Shortened(TriggerId),
    }

    impl Identifiable for TriggerEvent {
        type Id = TriggerId;

        fn id(&self) -> &TriggerId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Extended(id)
                | Self::Shortened(id) => id,
            }
        }
    }
}

/// World event
///
/// Does not participate in `Event`, but useful for events warranties when modifying `wsv`
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
#[allow(missing_docs)]
pub enum WorldEvent<const HASH_LENGTH: usize> {
    Peer(peer::PeerEvent),
    Domain(domain::DomainEvent<{ HASH_LENGTH }>),
    Role(role::RoleEvent),
    Trigger(trigger::TriggerEvent),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event<const HASH_LENGTH: usize> {
    /// Peer event
    Peer(peer::PeerEvent),
    /// Domain event
    Domain(domain::DomainEvent<{ HASH_LENGTH }>),
    /// Account event
    Account(account::AccountEvent<{ HASH_LENGTH }>),
    /// Asset definition event
    AssetDefinition(asset::AssetDefinitionEvent<{ HASH_LENGTH }>),
    /// Asset event
    Asset(asset::AssetEvent<{ HASH_LENGTH }>),
    /// Trigger event
    Trigger(trigger::TriggerEvent),
    /// Role event
    Role(role::RoleEvent),
}

impl<const HASH_LENGTH: usize> From<WorldEvent<HASH_LENGTH>> for SmallVec<[Event<HASH_LENGTH>; 3]> {
    fn from(world_event: WorldEvent<HASH_LENGTH>) -> Self {
        let mut events = SmallVec::new();

        match world_event {
            WorldEvent::Domain(domain_event) => {
                match &domain_event {
                    DomainEvent::Account(account_event) => {
                        if let AccountEvent::Asset(asset_event) = account_event {
                            events.push(DataEvent::Asset(asset_event.clone()));
                        }
                        events.push(DataEvent::Account(account_event.clone()));
                    }
                    DomainEvent::AssetDefinition(asset_definition_event) => {
                        events.push(DataEvent::AssetDefinition(asset_definition_event.clone()));
                    }
                    _ => (),
                }
                events.push(DataEvent::Domain(domain_event));
            }
            WorldEvent::Peer(peer_event) => {
                events.push(DataEvent::Peer(peer_event));
            }
            WorldEvent::Role(role_event) => {
                events.push(DataEvent::Role(role_event));
            }
            WorldEvent::Trigger(trigger_event) => {
                events.push(DataEvent::Trigger(trigger_event));
            }
        }

        events
    }
}

pub mod prelude {
    pub use super::{
        account::AccountEvent,
        asset::{AssetDefinitionEvent, AssetEvent},
        domain::DomainEvent,
        peer::PeerEvent,
        role::RoleEvent,
        trigger::TriggerEvent,
        Event as DataEvent, WorldEvent,
    };
}
