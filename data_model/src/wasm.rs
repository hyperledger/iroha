//! This module contains data and structures related only to WASM execution

pub mod export {
    //! Data which is exported from WASM to Iroha

    /// Name of the exported memory
    pub const WASM_MEMORY: &str = "memory";

    pub mod fn_names {
        //! Names of the functions which are exported from Iroha to WASM

        /// Exported function to allocate memory
        pub const WASM_ALLOC: &str = "_iroha_wasm_alloc";
        /// Exported function to deallocate memory
        pub const WASM_DEALLOC: &str = "_iroha_wasm_dealloc";
        /// Name of the exported entry for smart contract execution
        pub const SMART_CONTRACT_MAIN: &str = "_iroha_smart_contract_main";
        /// Name of the exported entry for trigger execution
        pub const TRIGGER_MAIN: &str = "_iroha_trigger_main";
        /// Name of the exported entry for validator to validate transaction
        pub const VALIDATOR_VALIDATE_TRANSACTION: &str = "_iroha_validator_validate_transaction";
        /// Name of the exported entry for validator to validate instruction
        pub const VALIDATOR_VALIDATE_INSTRUCTION: &str = "_iroha_validator_validate_instruction";
        /// Name of the exported entry for validator to validate query
        pub const VALIDATOR_VALIDATE_QUERY: &str = "_iroha_validator_validate_query";
        /// Name of the exported entry for validator to perform migration
        pub const VALIDATOR_MIGRATE: &str = "_iroha_validator_migrate";
    }
}

pub mod import {
    //! Data which is imported from Iroha to WASM

    /// Name of the linked wasm module
    pub const MODULE: &str = "iroha";

    pub mod fn_names {
        //! Names of the functions which are imported from Iroha to WASM

        /// Name of the imported function to execute instructions
        pub const EXECUTE_ISI: &str = "execute_instruction";
        /// Name of the imported function to execute queries
        pub const EXECUTE_QUERY: &str = "execute_query";
        /// Name of the imported function to get payload for smart contract
        /// [`main()`](super::super::export::fn_names::SMART_CONTRACT_MAIN) entrypoint
        pub const GET_SMART_CONTRACT_PAYLOAD: &str = "get_smart_contract_payload";
        /// Name of the imported function to get payload for trigger
        /// [`main()`](super::super::export::fn_names::TRIGGER_MAIN) entrypoint
        pub const GET_TRIGGER_PAYLOAD: &str = "get_trigger_payload";
        /// Name of the imported function to get payload for
        /// [`migrate()`](super::super::export::fn_names::VALIDATOR_MIGRATE) entrypoint
        pub const GET_MIGRATE_PAYLOAD: &str = "get_migrate_payload";
        /// Name of the imported function to get payload for
        /// [`validate_transaction()`](super::super::export::fn_names::VALIDATOR_VALIDATE_TRANSACTION) entrypoint
        pub const GET_VALIDATE_TRANSACTION_PAYLOAD: &str = "get_validate_transaction_payload";
        /// Name of the imported function to get payload for
        /// [`validate_instruction()`](super::super::export::fn_names::VALIDATOR_VALIDATE_INSTRUCTION) entrypoint
        pub const GET_VALIDATE_INSTRUCTION_PAYLOAD: &str = "get_validate_instruction_payload";
        /// Name of the imported function to get payload for
        /// [`validate_query()`](super::super::export::fn_names::VALIDATOR_VALIDATE_QUERY) entrypoint
        pub const GET_VALIDATE_QUERY_PAYLOAD: &str = "get_validate_query_payload";
        /// Name of the imported function to debug print objects
        pub const DBG: &str = "dbg";
        /// Name of the imported function to log objects
        pub const LOG: &str = "log";
        /// Name of the imported function to set new [`PermissionTokenSchema`](crate::permission::PermissionTokenSchema)
        pub const SET_PERMISSION_TOKEN_SCHEMA: &str = "set_permission_token_schema";
    }
}

pub mod payloads {
    //! Payloads with function arguments for different entrypoints

    use parity_scale_codec::{Decode, Encode};

    use crate::prelude::*;

    /// Payload for smart contract [`main()`](super::export::fn_names::SMART_CONTRACT_MAIN) entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct SmartContract {
        /// Smart contract owner who submitted transaction with it
        pub owner: AccountId,
    }

    /// Payload for trigger [`main()`](super::export::fn_names::TRIGGER_MAIN) entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Trigger {
        /// Trigger owner who registered the trigger
        pub owner: AccountId,
        /// Event which triggered the execution
        pub event: Event,
    }

    /// Payload for [`migrate()`](super::export::fn_names::VALIDATOR_MIGRATE) entrypoint
    #[derive(Debug, Clone, Copy, Encode, Decode)]
    pub struct Migrate {
        /// Height of the latest block in the blockchain
        pub block_height: u64,
    }

    /// Payload for [`validate_transaction()`](super::export::fn_names::VALIDATOR_VALIDATE_TRANSACTION) entrypoint
    pub type ValidateTransaction = Validate<SignedTransaction>;

    /// Payload for [`validate_instruction()`](super::export::fn_names::VALIDATOR_VALIDATE_INSTRUCTION) entrypoint
    pub type ValidateInstruction = Validate<InstructionExpr>;

    /// Payload for [`validate_query()`](super::export::fn_names::VALIDATOR_VALIDATE_QUERY) entrypoint
    pub type ValidateQuery = Validate<QueryBox>;

    /// Generic payload for `validate_*()` entrypoints of validator.
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Validate<T> {
        /// Authority which executed the operation to be validated
        pub authority: AccountId,
        /// Height of the latest block in the blockchain
        pub block_height: u64,
        /// Operation to be validated
        pub to_validate: T,
    }
}
