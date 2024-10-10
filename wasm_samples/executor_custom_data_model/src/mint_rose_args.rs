//! Arguments to mint rose with args trigger

use iroha_data_model::prelude::JsonValue;
use serde::{Deserialize, Serialize};

/// Arguments to mint rose with args trigger
#[derive(Serialize, Deserialize)]
pub struct MintRoseArgs {
    // Amount to mint
    pub val: u32,
}

impl From<MintRoseArgs> for JsonValue {
    fn from(details: MintRoseArgs) -> Self {
        JsonValue::new(details)
    }
}

impl TryFrom<&JsonValue> for MintRoseArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &JsonValue) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
