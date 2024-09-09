//! Arguments to mint rose with args trigger

use iroha_data_model::prelude::JsonString;
use serde::{Deserialize, Serialize};

/// Arguments to mint rose with args trigger
#[derive(Serialize, Deserialize)]
pub struct MintRoseArgs {
    // Amount to mint
    pub val: u32,
}

impl From<MintRoseArgs> for JsonString {
    fn from(details: MintRoseArgs) -> Self {
        JsonString::new(details)
    }
}

impl TryFrom<&JsonString> for MintRoseArgs {
    type Error = serde_json::Error;

    fn try_from(payload: &JsonString) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
