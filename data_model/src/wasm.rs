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
        /// Name of the exported entry for smart contract or trigger execution
        pub const WASM_MAIN: &str = "_iroha_wasm_main";
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
        /// Name of the imported function to query trigger authority
        pub const GET_AUTHORITY: &str = "get_authority";
        /// Name of the imported function to query event that triggered the smart contract execution
        pub const GET_TRIGGERING_EVENT: &str = "get_triggering_event";
        /// Name of the imported function to get transaction that is to be verified
        pub const GET_TRANSACTION_TO_VALIDATE: &str = "get_transaction_to_validate";
        /// Name of the imported function to get instruction that is to be verified
        pub const GET_INSTRUCTION_TO_VALIDATE: &str = "get_instruction_to_validate";
        /// Name of the imported function to get query that is to be verified
        pub const GET_QUERY_TO_VALIDATE: &str = "get_query_to_validate";
        /// Name of the imported function to get current block height
        pub const GET_BLOCK_HEIGHT: &str = "get_block_height";
        /// Name of the imported function to debug print objects
        pub const DBG: &str = "dbg";
        /// Name of the imported function to log objects
        pub const LOG: &str = "log";
        /// Name of the imported function to set new [`PermissionTokenSchema`](crate::permission::PermissionTokenSchema)
        pub const SET_PERMISSION_TOKEN_SCHEMA: &str = "set_permission_token_schema";
    }
}
