//! Data events.

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

/// Event.
#[derive(Debug, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, Clone, IntoSchema)]
pub struct Event {
    entity: Entity,
    status: Status,
}

/// Enumeration of all possible Iroha data entities.
#[derive(
    Clone, PartialEq, Eq, Debug, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
// SATO How detailed should `DataEntity` be?
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
}

/// Entity status.
#[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone, IntoSchema)]
// SATO How detailed should `DataStatus` be?
pub enum Status {
    /// Entity was added, registered, minted or another action was made to make entity appear on
    /// the blockchain for the first time.
    Created,
    /// Entity's state was changed, any parameter updated it's value.
    // Updated(Updated),
    Updated,
    /// Entity was archived or by any other way was put into state that guarantees absence of
    /// [`Updated`](`Status::Updated`) events for this entity.
    Deleted,
}

// #[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone, IntoSchema)]
// enum Updated {
//     Authentication,
//     Metadata(Metadata),
//     Permission,
// }

// #[derive(Debug, Decode, Encode, Deserialize, Serialize, Eq, PartialEq, Copy, Clone, IntoSchema)]
// enum Metadata {
//     Inserted,
//     Removed,
// }

/// Filter to select [`Event`]s which match the `entity` and `status` conditions.
#[derive(Default, Debug, Decode, Encode, Deserialize, Serialize, Clone, IntoSchema)]
pub struct EventFilter {
    /// Optional filter by [`Entity`]. [`None`] accepts any entities.
    entity: Option<EntityFilter>,
    /// Optional filter by [`Status`]. [`None`] accepts any statuses.
    status: Option<StatusFilter>,
}

/// Filter to select entities under the [`Entity`] of the optional id,
/// or all the entities of the [`Entity`] type.
#[derive(Debug, Decode, Encode, Deserialize, Serialize, Clone, IntoSchema)]
pub enum EntityFilter {
    /// Filter by [`Account`].
    Account(Option<AccountId>),
    /// Filter by [`AssetDefinition`].
    AssetDefinition(Option<AssetDefinitionId>),
    /// Filter by [`Asset`].
    Asset(Option<AssetId>),
    /// Filter by [`Domain`].
    Domain(Option<DomainId>),
    /// Filter by [`Peer`].
    Peer(Option<PeerId>),
}

/// Filter to select a status.
pub type StatusFilter = Status;

impl Event {
    /// Construct [`Event`].
    pub const fn new(entity: Entity, status: Status) -> Self {
        Self { entity, status }
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
        self == status
    }
}

impl From<Event> for Vec<Event> {
    fn from(src: Event) -> Self {
        vec![src]
    }
}

mod world {
    use crate::prelude::*;

    impl From<Register<Peer>> for DataEvent {
        fn from(src: Register<Peer>) -> Self {
            Self::new(DataEntity::Peer(src.object.id), DataStatus::Created)
        }
    }

    impl From<Unregister<Peer>> for DataEvent {
        fn from(src: Unregister<Peer>) -> Self {
            Self::new(DataEntity::Peer(src.object_id), DataStatus::Deleted)
        }
    }

    impl From<Register<Domain>> for DataEvent {
        fn from(src: Register<Domain>) -> Self {
            Self::new(DataEntity::Domain(src.object.id), DataStatus::Created)
        }
    }

    impl From<Unregister<Domain>> for DataEvent {
        fn from(src: Unregister<Domain>) -> Self {
            Self::new(DataEntity::Domain(src.object_id), DataStatus::Deleted)
        }
    }

    #[cfg(feature = "roles")]
    impl From<Register<Role>> for DataEvent {
        fn from(src: Register<Role>) -> Self {
            Self::new(DataEntity::Role(src.object.id), DataStatus::Created)
        }
    }

    #[cfg(feature = "roles")]
    impl From<Unregister<Role>> for DataEvent {
        fn from(src: Unregister<Role>) -> Self {
            Self::new(DataEntity::Role(src.object_id), DataStatus::Deleted)
        }
    }
}

mod domain {
    use crate::prelude::*;

    impl From<Register<NewAccount>> for DataEvent {
        fn from(src: Register<NewAccount>) -> Self {
            Self::new(DataEntity::Account(src.object.id), DataStatus::Created)
        }
    }

    impl From<Unregister<Account>> for DataEvent {
        fn from(src: Unregister<Account>) -> Self {
            Self::new(DataEntity::Account(src.object_id), DataStatus::Deleted)
        }
    }

    impl From<Register<AssetDefinition>> for DataEvent {
        fn from(src: Register<AssetDefinition>) -> Self {
            Self::new(
                DataEntity::AssetDefinition(src.object.id),
                DataStatus::Created,
            )
        }
    }

    impl From<Unregister<AssetDefinition>> for DataEvent {
        fn from(src: Unregister<AssetDefinition>) -> Self {
            Self::new(
                DataEntity::AssetDefinition(src.object_id),
                DataStatus::Deleted,
            )
        }
    }

    impl From<SetKeyValue<AssetDefinition, Name, Value>> for DataEvent {
        fn from(src: SetKeyValue<AssetDefinition, Name, Value>) -> Self {
            Self::new(
                DataEntity::AssetDefinition(src.object_id),
                // SATO Inserted
                DataStatus::Updated,
            )
        }
    }

    impl From<RemoveKeyValue<AssetDefinition, Name>> for DataEvent {
        fn from(src: RemoveKeyValue<AssetDefinition, Name>) -> Self {
            Self::new(
                DataEntity::AssetDefinition(src.object_id),
                // SATO Removed
                DataStatus::Updated,
            )
        }
    }

    impl From<SetKeyValue<Domain, Name, Value>> for DataEvent {
        fn from(src: SetKeyValue<Domain, Name, Value>) -> Self {
            Self::new(
                DataEntity::Domain(src.object_id),
                // SATO Inserted
                DataStatus::Updated,
            )
        }
    }

    impl From<RemoveKeyValue<Domain, Name>> for DataEvent {
        fn from(src: RemoveKeyValue<Domain, Name>) -> Self {
            Self::new(
                DataEntity::Domain(src.object_id),
                // SATO Removed
                DataStatus::Updated,
            )
        }
    }
}

mod account {
    use iroha_crypto::PublicKey;

    use crate::prelude::*;

    // SATO DataStatus::Updated(...)

    impl From<Mint<Account, PublicKey>> for DataEvent {
        fn from(src: Mint<Account, PublicKey>) -> Self {
            Self::new(DataEntity::Account(src.destination_id), DataStatus::Updated)
        }
    }

    impl From<Mint<Account, SignatureCheckCondition>> for DataEvent {
        fn from(src: Mint<Account, SignatureCheckCondition>) -> Self {
            Self::new(DataEntity::Account(src.destination_id), DataStatus::Updated)
        }
    }

    impl From<Burn<Account, PublicKey>> for DataEvent {
        fn from(src: Burn<Account, PublicKey>) -> Self {
            Self::new(DataEntity::Account(src.destination_id), DataStatus::Updated)
        }
    }

    impl From<SetKeyValue<Account, Name, Value>> for DataEvent {
        fn from(src: SetKeyValue<Account, Name, Value>) -> Self {
            Self::new(DataEntity::Account(src.object_id), DataStatus::Updated)
        }
    }

    impl From<RemoveKeyValue<Account, Name>> for DataEvent {
        fn from(src: RemoveKeyValue<Account, Name>) -> Self {
            Self::new(DataEntity::Account(src.object_id), DataStatus::Updated)
        }
    }

    impl From<Grant<Account, PermissionToken>> for DataEvent {
        fn from(src: Grant<Account, PermissionToken>) -> Self {
            Self::new(DataEntity::Account(src.destination_id), DataStatus::Updated)
        }
    }

    #[cfg(feature = "roles")]
    impl From<Grant<Account, RoleId>> for DataEvent {
        fn from(src: Grant<Account, RoleId>) -> Self {
            Self::new(DataEntity::Account(src.destination_id), DataStatus::Updated)
        }
    }
}

mod asset {
    use crate::{prelude::*, ValueMarker};

    // SATO DataStatus::Updated(...)

    impl<O: ValueMarker> From<Mint<Asset, O>> for DataEvent {
        fn from(src: Mint<Asset, O>) -> Self {
            Self::new(DataEntity::Asset(src.destination_id), DataStatus::Created)
        }
    }

    impl From<SetKeyValue<Asset, Name, Value>> for DataEvent {
        fn from(src: SetKeyValue<Asset, Name, Value>) -> Self {
            Self::new(DataEntity::Asset(src.object_id), DataStatus::Updated)
        }
    }

    impl<O: ValueMarker> From<Burn<Asset, O>> for DataEvent {
        fn from(src: Burn<Asset, O>) -> Self {
            Self::new(DataEntity::Asset(src.destination_id), DataStatus::Deleted)
        }
    }

    impl From<RemoveKeyValue<Asset, Name>> for DataEvent {
        fn from(src: RemoveKeyValue<Asset, Name>) -> Self {
            Self::new(DataEntity::Asset(src.object_id), DataStatus::Updated)
        }
    }

    impl From<Transfer<Asset, u32, Asset>> for Vec<DataEvent> {
        fn from(src: Transfer<Asset, u32, Asset>) -> Self {
            vec![
                DataEvent::new(DataEntity::Asset(src.source_id), DataStatus::Updated),
                DataEvent::new(DataEntity::Asset(src.destination_id), DataStatus::Updated),
            ]
        }
    }
}

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Entity as DataEntity, Event as DataEvent, EventFilter as DataEventFilter,
        Status as DataStatus,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_filter_scope() {
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
