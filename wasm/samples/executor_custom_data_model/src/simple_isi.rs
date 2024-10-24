//! Example of one custom instruction.
//! See `wasm/samples/executor_custom_instructions_simple`.

use alloc::{format, string::String, vec::Vec};

use iroha_data_model::{
    asset::AssetDefinitionId,
    isi::{CustomInstruction, Instruction, InstructionBox},
    prelude::{Json, Numeric},
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
    pub asset_definition: AssetDefinitionId,
    pub quantity: Numeric,
}

impl From<MintAssetForAllAccounts> for CustomInstructionBox {
    fn from(isi: MintAssetForAllAccounts) -> Self {
        Self::MintAssetForAllAccounts(isi)
    }
}

impl Instruction for CustomInstructionBox {}
impl Instruction for MintAssetForAllAccounts {}

impl From<CustomInstructionBox> for CustomInstruction {
    fn from(isi: CustomInstructionBox) -> Self {
        let payload = serde_json::to_value(&isi)
            .expect("INTERNAL BUG: Couldn't serialize custom instruction");

        Self::new(payload)
    }
}

impl From<MintAssetForAllAccounts> for InstructionBox {
    fn from(isi: MintAssetForAllAccounts) -> Self {
        Self::Custom(CustomInstructionBox::from(isi).into())
    }
}

impl From<CustomInstructionBox> for InstructionBox {
    fn from(isi: CustomInstructionBox) -> Self {
        Self::Custom(isi.into())
    }
}

impl TryFrom<&Json> for CustomInstructionBox {
    type Error = serde_json::Error;

    fn try_from(payload: &Json) -> serde_json::Result<Self> {
        serde_json::from_str::<Self>(payload.as_ref())
    }
}
