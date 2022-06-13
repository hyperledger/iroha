//! Data events.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

pub use events::Event;
pub use filters::EventFilter;
use iroha_macro::FromVariant;
use iroha_schema::prelude::*;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
pub use crate::Registered;

mod events;
mod filters;

/// Exports common structs and enums from this module.
pub mod prelude {
    pub use super::{events::prelude::*, filters::prelude::*};
}
