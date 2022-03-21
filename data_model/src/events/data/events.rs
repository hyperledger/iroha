//! This module contains data events

use super::*;

/// Trait for retrieving id from events
pub trait IdTrait {
    type Id;

    fn id(&self) -> &Self::Id;
}

mod asset {
    //! This module contains `AssetEvent`, `AssetDefinitionEvent` and its impls

    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[non_exhaustive]
    #[allow(missing_docs)]
    pub enum AssetEvent {
        Created(AssetId),
        Deleted(AssetId),
        Added(AssetId),
        Removed(AssetId),
        MetadataInserted(AssetId),
        MetadataRemoved(AssetId),
    }

    impl IdTrait for AssetEvent {
        type Id = AssetId;

        fn id(&self) -> &AssetId {
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
    pub enum AssetDefinitionEvent {
        Created(AssetDefinitionId),
        Deleted(AssetDefinitionId),
        MetadataInserted(AssetDefinitionId),
        MetadataRemoved(AssetDefinitionId),
    }

    impl IdTrait for AssetDefinitionEvent {
        type Id = AssetDefinitionId;

        fn id(&self) -> &AssetDefinitionId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
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

    impl IdTrait for PeerEvent {
        type Id = PeerId;

        fn id(&self) -> &PeerId {
            match self {
                Self::Added(id) | Self::Removed(id) => id,
            }
        }
    }
}

#[cfg(feature = "roles")]
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

    impl IdTrait for RoleEvent {
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
    pub enum AccountEvent {
        Asset(AssetEvent),
        Created(AccountId),
        Deleted(AccountId),
        AuthenticationAdded(AccountId),
        AuthenticationRemoved(AccountId),
        PermissionAdded(AccountId),
        PermissionRemoved(AccountId),
        MetadataInserted(AccountId),
        MetadataRemoved(AccountId),
    }

    impl IdTrait for AccountEvent {
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
    pub enum DomainEvent {
        Account(AccountEvent),
        AssetDefinition(AssetDefinitionEvent),
        Created(DomainId),
        Deleted(DomainId),
        MetadataInserted(DomainId),
        MetadataRemoved(DomainId),
    }

    impl IdTrait for DomainEvent {
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

    impl IdTrait for TriggerEvent {
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
pub enum WorldEvent {
    Peer(peer::PeerEvent),
    Domain(domain::DomainEvent),
    #[cfg(feature = "roles")]
    Role(role::RoleEvent),
    Trigger(trigger::TriggerEvent),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Peer event
    Peer(peer::PeerEvent),
    /// Domain event
    Domain(domain::DomainEvent),
    /// Account event
    Account(account::AccountEvent),
    /// Asset definition event
    AssetDefinition(asset::AssetDefinitionEvent),
    /// Asset event
    Asset(asset::AssetEvent),
    /// Trigger event
    Trigger(trigger::TriggerEvent),
    /// Role event
    #[cfg(feature = "roles")]
    Role(role::RoleEvent),
}

pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::role::RoleEvent;
    pub use super::{
        account::AccountEvent,
        asset::{AssetDefinitionEvent, AssetEvent},
        domain::DomainEvent,
        peer::PeerEvent,
        trigger::TriggerEvent,
        Event as DataEvent, WorldEvent,
    };
}
