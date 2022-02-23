//! This module contains data events

use super::*;

pub trait IdTrait: Identifiable {
    fn id(&self) -> &Self::Id;
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
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
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
            Self::Increased(id) => &id,
            Self::Decreased(id) => &id,
            Self::MetadataInserted(id) => &id,
            Self::MetadataRemoved(id) => &id,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
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
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
            Self::MetadataInserted(id) => &id,
            Self::MetadataRemoved(id) => &id,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
pub enum PeerEvent {
    Created(PeerId),
    Deleted(PeerId),
}

impl Identifiable for PeerEvent {
    type Id = PeerId;
}

impl IdTrait for PeerEvent {
    fn id(&self) -> &PeerId {
        match self {
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
        }
    }
}

#[cfg(feature = "roles")]
#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
pub enum RoleEvent {
    Created(RoleId),
    Deleted(RoleId),
}

#[cfg(feature = "roles")]
impl Identifiable for RoleEvent {
    type Id = RoleId;
}

#[cfg(feature = "roles")]
impl IdTrait for RoleEvent {
    fn id(&self) -> &RoleId {
        match self {
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
        }
    }
}

/// Account event
#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
pub enum AccountEvent {
    /// Asset change
    Asset(AssetEvent),
    /// Account registration
    Created(AccountId),
    /// Account deleting
    Deleted(AccountId),
    /// Authentication event
    Authentication(AccountId),
    /// Permission update
    Permission(AccountId),
    /// Metadata was inserted
    MetadataInserted(AccountId),
    /// Metadata was removed
    MetadataRemoved(AccountId),
}

impl Identifiable for AccountEvent {
    type Id = AccountId;
}

impl IdTrait for AccountEvent {
    fn id(&self) -> &AccountId {
        match self {
            Self::Asset(asset) => &asset.id().account_id,
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
            Self::Authentication(id) => &id,
            Self::Permission(id) => &id,
            Self::MetadataInserted(id) => &id,
            Self::MetadataRemoved(id) => &id,
        }
    }
}

/// Domain Event
#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
#[non_exhaustive]
pub enum DomainEvent {
    /// Account change
    Account(AccountEvent),
    /// Asset definition change
    AssetDefinition(AssetDefinitionEvent),
    /// Domain registration
    Created(DomainId),
    /// Domain deleting
    Deleted(DomainId),
    /// Metadata was inserted
    MetadataInserted(DomainId),
    /// Metadata was removed
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
            Self::Created(id) => &id,
            Self::Deleted(id) => &id,
            Self::MetadataInserted(id) => &id,
            Self::MetadataRemoved(id) => &id,
        }
    }
}

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

/// World event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
#[allow(missing_docs)]
pub enum WorldEvent {
    Domain(DomainEvent),
    Peer(PeerEvent),

    #[cfg(feature = "roles")]
    Role(Role),
}

/// Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Event {
    /// Domain event
    Domain(DomainEvent),
    /// Peer event
    Peer(PeerEvent),
    /// Role event
    #[cfg(feature = "roles")]
    Role(Role),
    /// Account event
    Account(AccountEvent),
    /// Asset definition event
    AssetDefinition(AssetDefinitionEvent),
    /// Asset event
    Asset(AssetEvent),
    /// Trigger event
    Trigger(TriggerEvent),
}

mod trigger {
    use crate::prelude::*;

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
