//! This module contains data events

use super::*;

pub type AssetEvent = SimpleEvent<AssetId>;
pub type AssetDefinitionEvent = SimpleEvent<AssetDefinitionId>;
pub type PeerEvent = SimpleEvent<PeerId>;
#[cfg(feature = "roles")]
pub type Role = SimpleEvent<RoleId>;

pub trait IdTrait: Identifiable {
    fn id(&self) -> &Self::Id;
}

#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct SimpleEvent<Id> {
    id: Id,
    status: Status,
}

impl<Id: Into<IdBox> + Debug + Clone + Eq + Ord> SimpleEvent<Id> {
    pub fn new(id: Id, status: impl Into<Status>) -> Self {
        Self {
            id,
            status: status.into(),
        }
    }

    pub fn status(&self) -> &Status {
        &self.status
    }
}

impl<Id: Into<IdBox> + Debug + Clone + Eq + Ord> Identifiable for SimpleEvent<Id> {
    type Id = Id;
}

impl<Id: Into<IdBox> + Debug + Clone + Eq + Ord> IdTrait for SimpleEvent<Id> {
    fn id(&self) -> &Id {
        &self.id
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

/// Entity status.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
pub enum Status {
    /// Entity was added, registered or another action was made to make entity appear on
    /// the blockchain for the first time.
    Created,
    /// Entity's state was minted, burned, changed, any parameter updated it's value.
    Updated(Updated),
    /// Entity was archived or by any other way was put into state that guarantees absence of
    /// [`Updated`](`Status::Updated`) events for this entity.
    Deleted,
}

/// Description for [`Status::Updated`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    Hash,
)]
#[allow(missing_docs)]
pub enum Updated {
    Metadata(MetadataUpdated),
    Authentication,
    Permission,
    Asset(AssetUpdated),
}

/// Description for [`Updated::Metadata`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    Hash,
)]
#[allow(missing_docs)]
pub enum MetadataUpdated {
    Inserted,
    Removed,
}

/// Description for [`Updated::Asset`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    Hash,
)]
#[allow(missing_docs)]
pub enum AssetUpdated {
    Received,
    Sent,
    Minted,
    Burned,
}

impl From<MetadataUpdated> for Status {
    fn from(src: MetadataUpdated) -> Self {
        Self::Updated(src.into())
    }
}

impl From<AssetUpdated> for Status {
    fn from(src: AssetUpdated) -> Self {
        Self::Updated(src.into())
    }
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
