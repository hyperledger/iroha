//! Example of one custom instruction.
//! See `smartcontracts/executor_custom_instructions_simple`.

use alloc::{format, string::String, vec::Vec};

use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::{Custom, InstructionBox},
    prelude::Numeric,
    JsonString,
};
use iroha_schema::IntoSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, IntoSchema)]
pub enum CustomInstructionBox {
    MintAssetForAllAccounts(MintAssetForAllAccounts),
    // Other custom instructions
}

#[derive(Debug, Deserialize, Serialize, IntoSchema)]
pub struct MintAssetForAllAccounts {
    pub asset_definition_id: AssetDefinitionId,
    pub quantity: Numeric,
}

impl From<CustomInstructionBox> for Custom {
    fn from(isi: CustomInstructionBox) -> Self {
        let payload = serde_json::to_value(&isi)
            .expect("INTERNAL BUG: Couldn't serialize custom instruction");

        Self::new(payload)
    }
}

impl CustomInstructionBox {
    pub fn into_instruction(self) -> InstructionBox {
        InstructionBox::Custom(self.into())
    }
}

impl TryFrom<&JsonString> for CustomInstructionBox {
    type Error = serde_json::Error;

    fn try_from(payload: &JsonString) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
