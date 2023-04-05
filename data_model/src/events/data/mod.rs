//! Data events.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

pub use events::DataEvent;
pub use filters::DataEventFilter;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[cfg(feature = "_transparent-api")]
use super::Filter;
use crate::prelude::*;
pub use crate::Registered;

mod events;
mod filters;

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{events::prelude::*, filters::prelude::*};
}
