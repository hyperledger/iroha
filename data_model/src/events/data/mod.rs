//! Data events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
use std::fmt::Debug;

pub use events::Event;
use events::{IdTrait, SimpleEvent, Status};
pub use filters::EventFilter;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

mod events;
mod filters;

/// Exports common structs and enums from this module.
pub mod prelude {
    #[cfg(feature = "roles")]
    pub use super::RoleEvent;
    pub use super::{
        events::{
            AccountEvent, AssetDefinitionEvent, AssetEvent, AssetUpdated, DomainEvent,
            Event as DataEvent, MetadataUpdated, OtherAccountChangeEvent, OtherDomainChangeEvent,
            PeerEvent, Status as DataStatus, Updated, WorldEvent,
        },
        filters::{EventFilter as DataEventFilter, *},
    };
}
