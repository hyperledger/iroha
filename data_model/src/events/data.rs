//! Events of data entities.

use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};

use crate::prelude::*;

/// Entity type to filter events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub enum EntityType {
    /// Account.
    Account,
    /// AssetDefinition.
    AssetDefinition,
    /// Asset.
    Asset,
    /// Domain.
    Domain,
    /// Peer.
    Peer,
}

/// Entity type to filter events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode)]
pub enum Status {
    /// Entity was added, registered, minted or another action was made to make entity appear on
    /// the blockchain for the first time.
    Created,
    /// Entity's state was changed, any parameter updated it's value.
    Updated,
    /// Entity was archived or by any other way was put into state that guarantees absense of
    /// [`Updated`](`Status::Updated`) events for this entity.
    Deleted,
}

/// Enumeration of all possible Iroha data entities.
#[derive(Debug, Clone, Decode, Encode, FromVariant)]
pub enum Entity {
    /// Account.
    Account(Box<Account>),
    /// AssetDefinition.
    AssetDefinition(AssetDefinition),
    /// Asset.
    Asset(Asset),
    /// Domain.
    Domain(Domain),
    /// Peer.
    Peer(Peer),
}

impl From<Entity> for EntityType {
    fn from(entity: Entity) -> Self {
        match entity {
            Entity::Account(_) => EntityType::Account,
            Entity::AssetDefinition(_) => EntityType::AssetDefinition,
            Entity::Asset(_) => EntityType::Asset,
            Entity::Domain(_) => EntityType::Domain,
            Entity::Peer(_) => EntityType::Peer,
        }
    }
}

//TODO: implement filter for data entities
/// Event filter.
#[derive(Debug, Clone, Copy, Decode, Encode, IntoSchema)]
pub struct EventFilter;

impl EventFilter {
    /// Apply filter to event.
    #[allow(clippy::unused_self)]
    pub const fn apply(self, _event: Event) -> bool {
        false
    }
}

//TODO: implement event for data entities
/// Event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema)]
pub struct Event;

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        Entity as DataEntity, EntityType as DataEntityType, Event as DataEvent,
        EventFilter as DataEventFilter, Status as DataStatus,
    };
}
