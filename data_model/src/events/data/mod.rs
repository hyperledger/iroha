//! Data events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
use std::fmt::Debug;

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

pub mod filters;

pub type AssetEvent = detail::SimpleEvent<AssetId>;
pub type AssetDefinitionEvent = detail::SimpleEvent<AssetDefinitionId>;
pub type PeerEvent = detail::SimpleEvent<PeerId>;
pub type OtherAccountChangeEvent = detail::SimpleEvent<AccountId>;
pub type OtherDomainChangeEvent = detail::SimpleEvent<DomainId>;
#[cfg(feature = "roles")]
pub type Role = SimpleEvent<RoleId>;

mod detail {
    use super::*;

    pub trait IdTrait: Identifiable {
        fn id(&self) -> &Self::Id;
    }

    #[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct SimpleEvent<Id> {
        id: Id,
        status: Status,
    }

    impl<Id> SimpleEvent<Id> {
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
}

/// Account event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum AccountEvent {
    /// Account change without asset changing
    OtherAccountChange(OtherAccountChangeEvent),
    /// Asset change
    Asset(AssetEvent),
}

impl Identifiable for AccountEvent {
    type Id = AccountId;
}

impl detail::IdTrait for AccountEvent {
    fn id(&self) -> &AccountId {
        match self {
            Self::OtherAccountChange(change) => change.id(),
            Self::Asset(asset) => &asset.id().account_id,
        }
    }
}

/// Domain Event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum DomainEvent {
    /// Domain change without account or asset definition change
    OtherDomainChange(OtherDomainChangeEvent),
    /// Account change
    Account(AccountEvent),
    /// Asset definition change
    AssetDefinition(AssetDefinitionEvent),
}

impl Identifiable for DomainEvent {
    type Id = DomainId;
}

impl detail::IdTrait for DomainEvent {
    fn id(&self) -> &DomainId {
        match self {
            Self::OtherDomainChange(change) => change.id(),
            Self::Account(account) => &account.id().domain_id,
            Self::AssetDefinition(asset_definition) => &asset_definition.id().domain_id,
        }
    }
}

/// World event
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum WorldEvent {
    /// Domain change
    Domain(DomainEvent),
    /// Peer change
    Peer(PeerEvent),
    /// Role change
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
    /// Entity was added, registered, minted or another action was made to make entity appear on
    /// the blockchain for the first time.
    Created,
    /// Entity's state was changed, any parameter updated it's value.
    Updated(Updated),
    /// Entity was archived or by any other way was put into state that guarantees absence of
    /// [`Updated`](`Status::Updated`) events for this entity.
    Deleted,
}

/// Description for [`Status::Updated`].
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
#[allow(missing_docs)]
pub enum MetadataUpdated {
    Inserted,
    Removed,
}

/// Description for [`Updated::Asset`].
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
#[allow(missing_docs)]
pub enum AssetUpdated {
    Received,
    Sent,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_scope() {
        const DOMAIN: &str = "wonderland";
        const ACCOUNT: &str = "alice";
        const ASSET: &str = "rose";
        let domain = DomainId::test(DOMAIN);
        let account = AccountId::test(ACCOUNT, DOMAIN);
        let asset = AssetId::test(ASSET, DOMAIN, ACCOUNT, DOMAIN);

        let entity_created = |entity: Entity| Event::new(entity, Status::Created);
        let domain_created = entity_created(Entity::Domain(domain));
        let account_created = entity_created(Entity::Account(account.clone()));
        let asset_created = entity_created(Entity::Asset(asset));

        let account_filter = EventFilter::new(Some(EntityFilter::Account(Some(account))), None);
        assert!(!account_filter.apply(&domain_created));
        assert!(account_filter.apply(&account_created));
        assert!(account_filter.apply(&asset_created));
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::RoleEvent;
    pub use super::{
        filters::{EventFilter as DataEventFilter, *},
        AccountEvent, AssetDefinitionEvent, AssetEvent, AssetUpdated, DomainEvent,
        Event as DataEvent, MetadataUpdated, OtherAccountChangeEvent, OtherDomainChangeEvent,
        PeerEvent, Status as DataStatus, Updated, WorldEvent,
    };
}
