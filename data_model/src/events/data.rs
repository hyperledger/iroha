//! Data events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

pub mod typed {
    //! This module contains typed events

    use super::*;

    macro_rules! typed_event_struct_definition {
        ($i:ident, id: $id_type:ty) => {
            typed_event_struct_definition! {
                $i,
                $id_type,
                concat!(" ", stringify!($i), " event"),
                concat!(" Create new ", stringify!($i), " event")
            }
        };
        ($i:ident, $id_type:ty, $struct_doc:expr, $new_doc:expr) => {
            #[doc = $struct_doc]
            #[derive(
                Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema,
            )]
            pub struct $i {
                id: $id_type,
                status: Status,
            }

            impl $i {
                #[doc = $new_doc]
                pub fn new(id: $id_type, status: impl Into<Status>) -> Self {
                    $i {
                        id,
                        status: status.into(),
                    }
                }
            }
        };
    }

    typed_event_struct_definition!(Asset, id: AssetId);
    typed_event_struct_definition!(AssetDefinition, id: AssetDefinitionId);
    typed_event_struct_definition!(Peer, id: PeerId);
    typed_event_struct_definition!(OtherAccountChange, id: AccountId);
    typed_event_struct_definition!(OtherDomainChange, id: DomainId);
    #[cfg(feature = "roles")]
    typed_event_struct_definition!(Role, id: RoleId);

    /// Account event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
    )]
    pub enum Account {
        /// Account change without asset changing
        OtherAccountChange(OtherAccountChange),
        /// Asset change
        Asset(Asset),
    }

    /// Domain Event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
    )]
    pub enum Domain {
        /// Domain change without account or asset definition change
        OtherDomainChange(OtherDomainChange),
        /// Account change
        Account(Account),
        /// Asset definition change
        AssetDefinition(AssetDefinition),
    }

    /// World event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
    )]
    pub enum World {
        /// Domain change
        Domain(Domain),
        /// Peer change
        Peer(Peer),
        /// Role change
        #[cfg(feature = "roles")]
        Role(Role),
    }

    /// New Event
    #[derive(
        Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
    )]
    pub enum Event {
        /// World event
        World(World),
        /// Domain event
        Domain(Domain),
        /// Peer event
        Peer(Peer),
        /// Role event
        #[cfg(feature = "roles")]
        Role(Role),
        /// Account event
        Account(Account),
        /// Asset definition event
        AssetDefinition(AssetDefinition),
        /// Asset event
        Asset(Asset),
    }

    pub mod prelude {
        //! Exports common structs and enums from this module.

        #[cfg(feature = "roles")]
        pub use super::Role as RoleEvent;
        pub use super::{
            Account as AccountEvent, Asset as AssetEvent, AssetDefinition as AssetDefinitionEvent,
            Domain as DomainEvent, OtherAccountChange as OtherAccountChangeEvent,
            OtherDomainChange as OtherDomainChangeEvent, Peer as PeerEvent, World as WorldEvent,
        };
    }
}

/// Event.
#[derive(Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Event {
    entity: Entity,
    status: Status,
}

/// Enumeration of all possible Iroha data entities.
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum Entity {
    /// [`Account`].
    Account(AccountId),
    /// [`AssetDefinition`].
    AssetDefinition(AssetDefinitionId),
    /// [`Asset`].
    Asset(AssetId),
    /// [`Domain`].
    Domain(DomainId),
    /// [`Peer`].
    Peer(PeerId),
    #[cfg(feature = "roles")]
    /// [`Role`].
    Role(RoleId),
    /// [`Trigger`]
    Trigger(TriggerId),
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
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
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
    Trigger(TriggerUpdated),
}

/// Description for [`Updated::Metadata`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
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

/// Description for [`Updated::Metadata`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
#[allow(missing_docs)]
pub enum TriggerUpdated {
    Extended,
    Shortened,
}

/// Description for [`Updated::Asset`].
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
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

/// Filter to select [`Event`]s which match the `entity` and `status` conditions.
#[derive(
    Default,
    Debug,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
pub struct EventFilter {
    /// Optional filter by [`Entity`]. [`None`] accepts any entities.
    entity: Option<EntityFilter>,
    /// Optional filter by [`Status`]. [`None`] accepts any statuses.
    status: Option<StatusFilter>,
}

/// Filter to select entities under the [`Entity`] of the optional id,
/// or all the entities of the [`Entity`] type.
#[derive(
    Debug,
    Decode,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Encode,
    Deserialize,
    Serialize,
    Clone,
    IntoSchema,
)]
pub enum EntityFilter {
    /// Filter by [`Entity::Account`].
    Account(Option<AccountId>),
    /// Filter by [`Entity::AssetDefinition`].
    AssetDefinition(Option<AssetDefinitionId>),
    /// Filter by [`Entity::Asset`].
    Asset(Option<AssetId>),
    /// Filter by [`Entity::Domain`].
    Domain(Option<DomainId>),
    /// Filter by [`Entity::Peer`].
    Peer(Option<PeerId>),
}

/// Filter to select a status.
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
pub enum StatusFilter {
    /// Select [`Status::Created`].
    Created,
    /// Select [`Status::Updated`] or more detailed status in option.
    Updated(Option<Updated>),
    /// Select [`Status::Deleted`].
    Deleted,
}

impl Event {
    /// Construct [`Event`].
    pub fn new(entity: impl Into<Entity>, status: impl Into<Status>) -> Self {
        Self {
            entity: entity.into(),
            status: status.into(),
        }
    }
}

impl EventFilter {
    /// Construct [`EventFilter`].
    pub const fn new(entity: Option<EntityFilter>, status: Option<StatusFilter>) -> Self {
        Self { entity, status }
    }

    /// Check if `event` is accepted.
    pub fn apply(&self, event: &Event) -> bool {
        let entity_check = self
            .entity
            .as_ref()
            .map_or(true, |entity| entity.apply(&event.entity));
        let status_check = self
            .status
            .map_or(true, |status| status.apply(event.status));
        entity_check && status_check
    }
}

impl EntityFilter {
    fn apply(&self, entity: &Entity) -> bool {
        match self {
            Self::Account(opt) => match entity {
                Entity::Account(account_id) => opt
                    .as_ref()
                    .map_or(true, |filter_id| account_id == filter_id),
                Entity::Asset(asset_id) => opt
                    .as_ref()
                    .map_or(false, |filter_id| asset_id.account_id == *filter_id),
                _ => false,
            },
            Self::AssetDefinition(opt) => match entity {
                Entity::AssetDefinition(asset_definition_id) => opt
                    .as_ref()
                    .map_or(true, |filter_id| asset_definition_id == filter_id),
                Entity::Asset(asset_id) => opt
                    .as_ref()
                    .map_or(false, |filter_id| asset_id.definition_id == *filter_id),
                _ => false,
            },
            Self::Asset(opt) => match entity {
                Entity::Asset(asset_id) => {
                    opt.as_ref().map_or(true, |filter_id| asset_id == filter_id)
                }
                _ => false,
            },
            Self::Domain(opt) => match entity {
                Entity::Account(account_id) => opt
                    .as_ref()
                    .map_or(false, |filter_id| account_id.domain_id == *filter_id),
                Entity::AssetDefinition(asset_definition_id) => {
                    opt.as_ref().map_or(false, |filter_id| {
                        asset_definition_id.domain_id == *filter_id
                    })
                }
                Entity::Asset(asset_id) => opt.as_ref().map_or(false, |filter_id| {
                    asset_id.account_id.domain_id == *filter_id
                        || asset_id.definition_id.domain_id == *filter_id
                }),
                Entity::Domain(id) => opt.as_ref().map_or(true, |filter_id| id == filter_id),
                _ => false,
            },
            Self::Peer(opt) => match entity {
                Entity::Peer(peer_id) => {
                    opt.as_ref().map_or(true, |filter_id| peer_id == filter_id)
                }
                _ => false,
            },
        }
    }
}

impl StatusFilter {
    fn apply(self, status: Status) -> bool {
        match self {
            Self::Created => Status::Created == status,
            Self::Updated(opt) => match status {
                Status::Updated(detail) => {
                    opt.map_or(true, |filter_detail| detail == filter_detail)
                }
                _ => false,
            },
            Self::Deleted => Status::Deleted == status,
        }
    }
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
    use super::TriggerUpdated;
    use crate::prelude::*;

    impl From<Register<Trigger>> for DataEvent {
        fn from(src: Register<Trigger>) -> Self {
            Self::new(src.object.id, DataStatus::Created)
        }
    }

    impl From<Unregister<Trigger>> for DataEvent {
        fn from(src: Unregister<Trigger>) -> Self {
            Self::new(src.object_id, DataStatus::Deleted)
        }
    }

    impl From<Mint<Trigger, u32>> for DataEvent {
        fn from(src: Mint<Trigger, u32>) -> Self {
            Self::new(
                src.destination_id,
                DataStatus::Updated(Updated::Trigger(TriggerUpdated::Extended)),
            )
        }
    }

    impl From<Burn<Trigger, u32>> for DataEvent {
        fn from(src: Burn<Trigger, u32>) -> Self {
            Self::new(
                src.destination_id,
                DataStatus::Updated(Updated::Trigger(TriggerUpdated::Shortened)),
            )
        }
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
    pub use super::{
        typed::prelude::*, AssetUpdated, Entity as DataEntity, Event as DataEvent,
        EventFilter as DataEventFilter, MetadataUpdated, Status as DataStatus, Updated,
    };
}
