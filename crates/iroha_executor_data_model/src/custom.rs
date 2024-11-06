//! Types for custom instructions

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};

use derive_more::{Constructor, From};
use iroha_data_model::{
    isi::{CustomInstruction, Instruction, InstructionBox},
    prelude::{Json, *},
};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::*;

// TODO #5221 #[proc_macro_derive(CustomInstruction)]
macro_rules! impl_custom_instruction {
    ($box:ty, $($instruction:ty)|+) => {
        impl Instruction for $box {}

        impl From<$box> for InstructionBox {
            fn from(value: $box) -> Self {
                Self::Custom(value.into())
            }
        }

        impl From<$box> for CustomInstruction {
            fn from(value: $box) -> Self {
                let payload = serde_json::to_value(&value)
                    .expect(concat!("INTERNAL BUG: Couldn't serialize ", stringify!($box)));

                Self::new(payload)
            }
        }

        impl TryFrom<&Json> for $box {
            type Error = serde_json::Error;

            fn try_from(payload: &Json) -> serde_json::Result<Self> {
                serde_json::from_str::<Self>(payload.as_ref())
            }
        } $(

        impl Instruction for $instruction {}

        impl From<$instruction> for InstructionBox {
            fn from(value: $instruction) -> Self {
                Self::Custom(<$box>::from(value).into())
            }
        })+
    };
}

/// Types for multisig instructions
pub mod multisig {
    use super::*;

    /// Multisig-related instructions
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, IntoSchema, From)]
    pub enum MultisigInstructionBox {
        /// Register a multisig account, which is a prerequisite of multisig transactions
        Register(MultisigRegister),
        /// Propose a multisig transaction and initialize approvals with the proposer's one
        Propose(MultisigPropose),
        /// Approve a certain multisig transaction
        Approve(MultisigApprove),
    }

    /// Register a multisig account, which is a prerequisite of multisig transactions
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, IntoSchema, Constructor)]
    pub struct MultisigRegister {
        /// Multisig account to be registered
        /// <div class="warning">
        ///
        /// Any corresponding private key allows the owner to manipulate this account as a ordinary personal account
        ///
        /// </div>
        // FIXME #5022 prevent multisig monopoly
        // FIXME #5022 stop accepting user input: otherwise, after #4426 pre-registration account will be hijacked as a multisig account
        pub account: AccountId,
        /// List of signatories and their relative weights of responsibility for the multisig account
        pub signatories: BTreeMap<AccountId, Weight>,
        /// Threshold of total weight at which the multisig account is considered authenticated
        pub quorum: u16,
        /// Multisig transaction time-to-live in milliseconds based on block timestamps. Defaults to [`DEFAULT_MULTISIG_TTL_MS`]
        pub transaction_ttl_ms: u64,
    }

    type Weight = u8;

    /// Default multisig transaction time-to-live in milliseconds based on block timestamps
    pub const DEFAULT_MULTISIG_TTL_MS: u64 = 60 * 60 * 1_000; // 1 hour

    /// Propose a multisig transaction and initialize approvals with the proposer's one
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, IntoSchema, Constructor)]
    pub struct MultisigPropose {
        /// Multisig account to propose
        pub account: AccountId,
        /// Proposal contents
        pub instructions: Vec<InstructionBox>,
    }

    /// Approve a certain multisig transaction
    #[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize, IntoSchema, Constructor)]
    pub struct MultisigApprove {
        /// Multisig account to approve
        pub account: AccountId,
        /// Proposal to approve
        pub instructions_hash: HashOf<Vec<InstructionBox>>,
    }

    // TODO #5221 #[derive(CustomInstruction)]
    impl_custom_instruction!(
        MultisigInstructionBox,
        MultisigRegister | MultisigPropose | MultisigApprove
    );
}
