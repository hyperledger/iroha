//! This module contains data events

use super::*;

/// Trait for retrieving id from events
pub trait IdTrait: Identifiable {
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
        Increased(AssetId),
        Decreased(AssetId),
        MetadataInserted(AssetId),
        MetadataRemoved(AssetId),
    }

    impl Identifiable for AssetEvent {
        type Id = AssetId;
    }

    impl IdTrait for AssetEvent {
        fn id(&self) -> &AssetId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Increased(id)
                | Self::Decreased(id)
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

    impl Identifiable for AssetDefinitionEvent {
        type Id = AssetDefinitionId;
    }

    impl IdTrait for AssetDefinitionEvent {
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
        Trusted(PeerId),
        Untrusted(PeerId),
    }

    impl Identifiable for PeerEvent {
        type Id = PeerId;
    }

    impl IdTrait for PeerEvent {
        fn id(&self) -> &PeerId {
            match self {
                Self::Trusted(id) | Self::Untrusted(id) => id,
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

    impl Identifiable for RoleEvent {
        type Id = RoleId;
    }

    impl IdTrait for RoleEvent {
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
        Authentication(AccountId),
        Permission(AccountId),
        MetadataInserted(AccountId),
        MetadataRemoved(AccountId),
    }

    impl Identifiable for AccountEvent {
        type Id = AccountId;
    }

    impl IdTrait for AccountEvent {
        fn id(&self) -> &AccountId {
            match self {
                Self::Asset(asset) => &asset.id().account_id,
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Authentication(id)
                | Self::Permission(id)
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

    impl Identifiable for DomainEvent {
        type Id = DomainId;
    }

    impl IdTrait for DomainEvent {
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
    }

    impl IdTrait for TriggerEvent {
        fn id(&self) -> &TriggerId {
            match self {
                Self::Created(id)
                | Self::Deleted(id)
                | Self::Extended(id)
                | Self::Shortened(id) => id,
            }
        }
    }

    impl From<Register<Trigger>> for DataEvent {
        fn from(src: Register<Trigger>) -> Self {
            Self::Trigger(TriggerEvent::Created(src.object.id))
        }
    }

    impl From<Unregister<Trigger>> for DataEvent {
        fn from(src: Unregister<Trigger>) -> Self {
            Self::Trigger(TriggerEvent::Deleted(src.object_id))
        }
    }

    impl From<Mint<Trigger, u32>> for DataEvent {
        fn from(src: Mint<Trigger, u32>) -> Self {
            Self::Trigger(TriggerEvent::Extended(src.destination_id))
        }
    }

    impl From<Burn<Trigger, u32>> for DataEvent {
        fn from(src: Burn<Trigger, u32>) -> Self {
            Self::Trigger(TriggerEvent::Shortened(src.destination_id))
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
    Domain(domain::DomainEvent),
    Peer(peer::PeerEvent),

    #[cfg(feature = "roles")]
    Role(role::RoleEvent),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Domain event
    Domain(domain::DomainEvent),
    /// Peer event
    Peer(peer::PeerEvent),
    /// Role event
    #[cfg(feature = "roles")]
    Role(role::RoleEvent),
    /// Account event
    Account(account::AccountEvent),
    /// Asset definition event
    AssetDefinition(asset::AssetDefinitionEvent),
    /// Asset event
    Asset(asset::AssetEvent),
    /// Trigger event
    Trigger(trigger::TriggerEvent),
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
