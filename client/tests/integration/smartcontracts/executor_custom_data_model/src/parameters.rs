//! Module with custom parameters
use alloc::{format, string::String, vec::Vec};

use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use iroha_executor::prelude::*;

/// Parameter that controls domain limits
#[derive(PartialEq, Eq, Parameter, Decode, Encode, Serialize, Deserialize, IntoSchema)]
pub struct DomainLimits {
    /// Length of domain id in bytes
    pub id_len: u32,
}

impl Default for DomainLimits {
    fn default() -> Self {
        Self {
            id_len: 2_u32.pow(4),
        }
    }
}
