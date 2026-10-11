//! Data events.
pub use crate::Registered;
use crate::prelude::*;
pub use events::DataEvent;
pub use filters::{DataEventFilter, EscrowEventFilter};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::{format, string::String, vec, vec::Vec};
pub mod escrow;
mod events;
mod filters;
/// Generic game session transition events.
pub mod game;
#[cfg(feature = "governance")]
pub mod governance;
pub mod kagemusha;
pub mod musubi;
pub mod oracle;
pub mod proof;
pub mod runtime_upgrade;
pub mod smart_contract;
pub mod social;
pub mod soradns;
pub mod sorafs;
pub mod space_directory;
pub mod verifying_keys;
/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{
        escrow::prelude::*,
        events::prelude::*,
        filters::prelude::*,
        kagemusha::KagemushaLoadCommittedV1,
        musubi::prelude::*,
        oracle::prelude::*,
        social::prelude::*,
        soradns::{SoradnsDirectoryEvent, SoradnsDirectoryEventSet},
        sorafs::prelude::*,
        space_directory::prelude::*,
    };
}
