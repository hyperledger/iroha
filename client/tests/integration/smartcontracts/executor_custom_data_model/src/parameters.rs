//! Module with custom parameters
use alloc::{format, string::String, vec::Vec};

use iroha_executor_data_model::parameter::Parameter;
use iroha_schema::IntoSchema;
use serde::{Deserialize, Serialize};

/// Parameter that controls domain limits
#[derive(PartialEq, Eq, Parameter, Deserialize, Serialize, IntoSchema)]
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
