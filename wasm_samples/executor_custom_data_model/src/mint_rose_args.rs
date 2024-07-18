//! Arguments to mint rose with args trigger

use serde::{Deserialize, Serialize};

/// Arguments to mint rose with args trigger
#[derive(Serialize, Deserialize)]
pub struct MintRoseArgs {
    // Amount to mint
    pub val: u32,
}
